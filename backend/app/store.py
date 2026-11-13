"""Single-host durable queue. Use one shared private volume, not ephemeral pods."""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from .models import AIResult, utcnow

TERMINAL = ("completed", "partial", "failed", "cancelled")
ACTIVE = ("queued", "parsing", "awaiting_ai", "generating")


class StoreError(Exception):
    def __init__(self, code: str, status: int = 409):
        self.code, self.status = code, status
        super().__init__(code)


class Store:
    def __init__(self, root: Path, *, queue_limit=8, storage_max_bytes=1024**3, storage_max_captures=100):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.captures_dir = self.root / "captures"
        self.captures_dir.mkdir(exist_ok=True, mode=0o700)
        self.path = self.root / "metadata.sqlite3"
        self.queue_limit = queue_limit
        self.storage_max_bytes = storage_max_bytes
        self.storage_max_captures = storage_max_captures
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
            CREATE TABLE IF NOT EXISTS captures (
              id TEXT PRIMARY KEY, sha256 TEXT, size INTEGER NOT NULL,
              created REAL NOT NULL, ready INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY, capture_id TEXT NOT NULL REFERENCES captures(id),
              state TEXT NOT NULL, ai_enabled INTEGER NOT NULL, consent INTEGER NOT NULL,
              policy_hash TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              heartbeat REAL NOT NULL DEFAULT 0, lease TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0,
              evidence TEXT, ai_result TEXT, error_code TEXT, idempotency_key TEXT UNIQUE);
            CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state, created_at);
            """)
        os.chmod(self.path, 0o600)

    @contextmanager
    def connection(self, *, write=False):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def capture_path(self, capture_id: str) -> Path:
        if len(capture_id) != 32 or any(c not in "0123456789abcdef" for c in capture_id):
            raise StoreError("invalid_capture_id", 400)
        return self.captures_dir / (capture_id + ".pcap")

    def reserve_capture(self, reserve_bytes: int) -> str:
        with self.connection(write=True) as db:
            count, total = db.execute("SELECT COUNT(*), COALESCE(SUM(size),0) FROM captures").fetchone()
            if count >= self.storage_max_captures or total + reserve_bytes > self.storage_max_bytes:
                raise StoreError("capture_storage_quota", 507)
            cid = uuid.uuid4().hex
            db.execute("INSERT INTO captures(id,size,created) VALUES(?,?,?)", (cid, reserve_bytes, time.time()))
        return cid

    def finish_capture(self, cid: str, size: int, sha256: str):
        with self.connection(write=True) as db:
            db.execute("UPDATE captures SET size=?, sha256=?, ready=1 WHERE id=?", (size, sha256, cid))

    def abort_capture(self, cid: str):
        self.capture_path(cid).unlink(missing_ok=True)
        with self.connection(write=True) as db:
            db.execute("DELETE FROM captures WHERE id=? AND ready=0", (cid,))

    def capture(self, cid: str) -> dict:
        with self.connection() as db:
            row = db.execute("SELECT * FROM captures WHERE id=? AND ready=1", (cid,)).fetchone()
        if row is None:
            raise StoreError("capture_not_found", 404)
        return dict(row)

    def create_job(self, request, policy_hash: str, key: str | None = None) -> dict:
        with self.connection(write=True) as db:
            if key:
                row = db.execute("SELECT * FROM jobs WHERE idempotency_key=?", (key,)).fetchone()
                if row:
                    if (row["capture_id"] != request.capture_id or bool(row["ai_enabled"]) != request.ai_enabled
                            or bool(row["consent"]) != request.ai_consent or row["policy_hash"] != policy_hash):
                        raise StoreError("idempotency_conflict")
                    return self._public(row)
            if not db.execute("SELECT id FROM captures WHERE id=? AND ready=1", (request.capture_id,)).fetchone():
                raise StoreError("capture_not_found", 404)
            count = db.execute("SELECT COUNT(*) FROM jobs WHERE state IN ('queued','parsing','awaiting_ai','generating')").fetchone()[0]
            if count >= self.queue_limit:
                raise StoreError("queue_full", 429)
            if db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] >= 500:
                raise StoreError("job_history_quota", 507)
            jid, now = uuid.uuid4().hex, utcnow()
            db.execute("""INSERT INTO jobs(id,capture_id,state,ai_enabled,consent,policy_hash,created_at,updated_at,idempotency_key)
              VALUES(?,?,'queued',?,?,?,?,?,?)""",
              (jid, request.capture_id, request.ai_enabled, request.ai_consent, policy_hash, now, now, key))
        return self.job(jid)

    def job(self, jid: str, *, internal=False) -> dict:
        with self.connection() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        if not row:
            raise StoreError("job_not_found", 404)
        return dict(row) if internal else self._public(row)

    def jobs(self, limit=50) -> list[dict]:
        with self.connection() as db:
            return [self._public(r) for r in db.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,))]

    @staticmethod
    def _public(row) -> dict:
        result = {k: row[k] for k in ("id", "capture_id", "state", "created_at", "updated_at", "error_code", "policy_hash")}
        result.update(ai_enabled=bool(row["ai_enabled"]), cancel_requested=bool(row["cancel_requested"]),
                      evidence_available=bool(row["evidence"]), ai_state=json.loads(row["ai_result"])["state"] if row["ai_result"] else None)
        return result

    def claim(self, phase: str) -> dict | None:
        before, after = ("queued", "parsing") if phase == "parser" else ("awaiting_ai", "generating")
        with self.connection(write=True) as db:
            row = db.execute("SELECT id FROM jobs WHERE state=? AND cancel_requested=0 ORDER BY created_at LIMIT 1", (before,)).fetchone()
            if not row:
                return None
            db.execute("UPDATE jobs SET state=?, lease=?, heartbeat=?, updated_at=? WHERE id=?",
                       (after, uuid.uuid4().hex, time.time(), utcnow(), row["id"]))
            return dict(db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone())

    def cancelled(self, job: dict) -> bool:
        with self.connection(write=True) as db:
            row = db.execute("SELECT cancel_requested,lease,state FROM jobs WHERE id=?", (job["id"],)).fetchone()
            if not row or row["lease"] != job["lease"] or row["state"] in TERMINAL:
                return True
            db.execute("UPDATE jobs SET heartbeat=? WHERE id=? AND lease=?", (time.time(), job["id"], job["lease"]))
            return bool(row["cancel_requested"])

    def finish(self, job: dict, state: str, *, evidence: str | None = None, ai_result: str | None = None, error_code: str | None = None) -> bool:
        with self.connection(write=True) as db:
            row = db.execute("SELECT lease,cancel_requested,state FROM jobs WHERE id=?", (job["id"],)).fetchone()
            if not row or row["lease"] != job["lease"] or row["state"] in TERMINAL:
                return False
            state = "cancelled" if row["cancel_requested"] else state
            if row["cancel_requested"]:
                ai_result = AIResult(state="cancelled", provider="unknown", warnings=["Cancelled before final result was committed"]).model_dump_json()
            db.execute("""UPDATE jobs SET state=?, evidence=COALESCE(?,evidence), ai_result=COALESCE(?,ai_result),
              error_code=?, lease=NULL, heartbeat=0, updated_at=? WHERE id=? AND lease=?""",
              (state, evidence, ai_result, error_code, utcnow(), job["id"], job["lease"]))
            return True

    def cancel(self, jid: str) -> dict:
        with self.connection(write=True) as db:
            row = db.execute("SELECT state FROM jobs WHERE id=?", (jid,)).fetchone()
            if not row:
                raise StoreError("job_not_found", 404)
            if row["state"] not in TERMINAL:
                state = "cancelled" if row["state"] in ("queued", "awaiting_ai") else row["state"]
                result = AIResult(state="cancelled", provider="unknown").model_dump_json() if state == "cancelled" else None
                db.execute("UPDATE jobs SET cancel_requested=1, state=?, ai_result=COALESCE(?,ai_result), updated_at=? WHERE id=?", (state, result, utcnow(), jid))
        return self.job(jid)

    def recover_stale(self, stale_seconds=600) -> int:
        cutoff = time.time() - stale_seconds
        timestamp = datetime.fromtimestamp(cutoff, timezone.utc).isoformat().replace("+00:00", "Z")
        with self.connection(write=True) as db:
            rows = db.execute("""SELECT * FROM jobs WHERE
              (state IN ('parsing','generating') AND heartbeat<?) OR
              (state IN ('queued','awaiting_ai') AND updated_at<?)""", (cutoff, timestamp)).fetchall()
            for row in rows:
                cancelled = bool(row["cancel_requested"])
                state = "cancelled" if cancelled else ("partial" if row["evidence"] else "failed")
                code = "cancelled" if cancelled else ("ai_worker_unavailable" if row["state"] == "awaiting_ai" else
                       "parser_worker_unavailable" if row["state"] == "queued" else "worker_interrupted")
                result = AIResult(state="cancelled" if cancelled else "unavailable", provider="unknown",
                    error_code=code, warnings=["Worker unavailable/interrupted; available deterministic evidence retained"]).model_dump_json()
                db.execute("UPDATE jobs SET state=?, error_code=?, lease=NULL, heartbeat=0, ai_result=?, updated_at=? WHERE id=?",
                           (state, code, result, utcnow(), row["id"]))
            return len(rows)

    def purge_expired(self, retention_hours: int) -> int:
        cutoff, count = time.time() - retention_hours * 3600, 0
        with self.connection(write=True) as db:
            # Incomplete uploads older than an hour are crash leftovers; active jobs are never purged.
            rows = db.execute("""SELECT c.id FROM captures c WHERE ((c.ready=1 AND c.created<?) OR (c.ready=0 AND c.created<?))
              AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.capture_id=c.id AND j.state IN ('queued','parsing','awaiting_ai','generating'))""",
              (cutoff, time.time() - 3600)).fetchall()
            for row in rows:
                self.capture_path(row["id"]).unlink(missing_ok=True)
                db.execute("DELETE FROM jobs WHERE capture_id=?", (row["id"],))
                db.execute("DELETE FROM captures WHERE id=?", (row["id"],))
                count += 1
            db.execute("PRAGMA incremental_vacuum(100)")
        return count
