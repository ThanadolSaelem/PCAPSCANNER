"""Single-host durable queue. Use one shared private volume, not ephemeral pods."""
from __future__ import annotations

import json
import os
import shutil
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
    def __init__(
        self,
        root: Path,
        *,
        queue_limit: int = 8,
        storage_max_bytes: int = 0,
        storage_max_captures: int = 500,
        disk_reserve_bytes: int = 256 * 1024 * 1024,
    ):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.captures_dir = self.root / "captures"
        self.captures_dir.mkdir(exist_ok=True, mode=0o700)
        self.path = self.root / "metadata.sqlite3"
        self.queue_limit = queue_limit
        self.storage_max_bytes = storage_max_bytes
        self.storage_max_captures = storage_max_captures
        self.disk_reserve_bytes = disk_reserve_bytes
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
            CREATE TABLE IF NOT EXISTS captures (
              id TEXT PRIMARY KEY,
              sha256 TEXT,
              size INTEGER NOT NULL,
              created REAL NOT NULL,
              ready INTEGER NOT NULL DEFAULT 0,
              filename TEXT,
              format TEXT NOT NULL DEFAULT 'pcap',
              source_kind TEXT NOT NULL DEFAULT 'upload',
              local_path TEXT,
              bytes_received INTEGER NOT NULL DEFAULT 0,
              expected_bytes INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY,
              capture_id TEXT NOT NULL REFERENCES captures(id),
              state TEXT NOT NULL,
              ai_enabled INTEGER NOT NULL,
              consent INTEGER NOT NULL,
              policy_hash TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              heartbeat REAL NOT NULL DEFAULT 0,
              lease TEXT,
              cancel_requested INTEGER NOT NULL DEFAULT 0,
              evidence TEXT,
              ai_result TEXT,
              error_code TEXT,
              idempotency_key TEXT UNIQUE,
              resource_mode TEXT NOT NULL DEFAULT 'auto',
              triage_enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state, created_at);
            """)
            self._migrate_columns(db)
        os.chmod(self.path, 0o600)

    @staticmethod
    def _migrate_columns(db: sqlite3.Connection) -> None:
        cap_cols = {r[1] for r in db.execute("PRAGMA table_info(captures)").fetchall()}
        cap_migrations = {
            "filename": "TEXT",
            "format": "TEXT NOT NULL DEFAULT 'pcap'",
            "source_kind": "TEXT NOT NULL DEFAULT 'upload'",
            "local_path": "TEXT",
            "bytes_received": "INTEGER NOT NULL DEFAULT 0",
            "expected_bytes": "INTEGER NOT NULL DEFAULT 0",
        }
        for col, ddl in cap_migrations.items():
            if col not in cap_cols:
                db.execute(f"ALTER TABLE captures ADD COLUMN {col} {ddl}")

        job_cols = {r[1] for r in db.execute("PRAGMA table_info(jobs)").fetchall()}
        job_migrations = {
            "resource_mode": "TEXT NOT NULL DEFAULT 'auto'",
            "triage_enabled": "INTEGER NOT NULL DEFAULT 1",
        }
        for col, ddl in job_migrations.items():
            if col not in job_cols:
                db.execute(f"ALTER TABLE jobs ADD COLUMN {col} {ddl}")

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

    @staticmethod
    def _validate_id(capture_id: str) -> None:
        if len(capture_id) != 32 or any(c not in "0123456789abcdef" for c in capture_id):
            raise StoreError("invalid_capture_id", 400)

    def capture_path(self, capture_id: str, ext: str = "pcap") -> Path:
        self._validate_id(capture_id)
        safe_ext = ext if ext in ("pcap", "csv", "part") else "pcap"
        return self.captures_dir / f"{capture_id}.{safe_ext}"

    def upload_part_path(self, capture_id: str) -> Path:
        return self.capture_path(capture_id, "part")

    def resolve_capture_path(self, capture_id: str) -> Path:
        row = self.capture(capture_id)
        if row.get("source_kind") == "local" and row.get("local_path"):
            return Path(str(row["local_path"]))
        fmt = str(row.get("format") or "pcap")
        ext = "csv" if fmt in ("csv", "tsv") else "pcap"
        candidate = self.capture_path(capture_id, ext)
        if candidate.exists():
            return candidate
        return self.capture_path(capture_id, "pcap")

    def _check_storage_capacity(self, db: sqlite3.Connection, reserve_bytes: int, *, local_reference: bool = False) -> None:
        count, total = db.execute(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN source_kind != 'local' THEN size ELSE 0 END), 0) FROM captures"
        ).fetchone()
        if count >= self.storage_max_captures:
            raise StoreError("capture_storage_quota", 507)
        if local_reference:
            return
        if self.storage_max_bytes > 0:
            if total + reserve_bytes > self.storage_max_bytes:
                raise StoreError("capture_storage_quota", 507)
        else:
            try:
                free_bytes = shutil.disk_usage(self.captures_dir).free
            except OSError:
                free_bytes = 0
            if free_bytes > 0 and free_bytes - reserve_bytes < self.disk_reserve_bytes:
                raise StoreError("insufficient_disk_space", 507)

    def reserve_capture(self, reserve_bytes: int, *, filename: str | None = None, fmt: str = "pcap") -> str:
        with self.connection(write=True) as db:
            self._check_storage_capacity(db, max(0, reserve_bytes))
            cid = uuid.uuid4().hex
            db.execute(
                """INSERT INTO captures(id,size,created,ready,filename,format,source_kind,expected_bytes)
                   VALUES(?,?,?,0,?,?,'upload',?)""",
                (cid, max(0, reserve_bytes), time.time(), filename, fmt, max(0, reserve_bytes)),
            )
        return cid

    def finish_capture(self, cid: str, size: int, sha256: str, *, fmt: str = "pcap"):
        with self.connection(write=True) as db:
            db.execute(
                "UPDATE captures SET size=?, bytes_received=?, sha256=?, format=?, ready=1 WHERE id=?",
                (size, size, sha256, fmt, cid),
            )

    def abort_capture(self, cid: str):
        for ext in ("pcap", "csv", "part"):
            self.capture_path(cid, ext).unlink(missing_ok=True)
        with self.connection(write=True) as db:
            db.execute("DELETE FROM captures WHERE id=? AND ready=0", (cid,))

    def init_chunk_upload(self, filename: str, expected_bytes: int, fmt: str = "pcap") -> str:
        clean_name = Path(filename).name[:255] or "capture.pcap"
        with self.connection(write=True) as db:
            self._check_storage_capacity(db, expected_bytes)
            cid = uuid.uuid4().hex
            db.execute(
                """INSERT INTO captures(id,size,created,ready,filename,format,source_kind,bytes_received,expected_bytes)
                   VALUES(?,?,?,0,?,?,'chunked',0,?)""",
                (cid, expected_bytes, time.time(), clean_name, fmt, expected_bytes),
            )
        part = self.upload_part_path(cid)
        with open(part, "wb") as _:
            pass
        os.chmod(part, 0o600)
        return cid

    def pending_upload(self, upload_id: str) -> dict:
        self._validate_id(upload_id)
        with self.connection() as db:
            row = db.execute("SELECT * FROM captures WHERE id=? AND ready=0", (upload_id,)).fetchone()
        if row is None:
            raise StoreError("upload_not_found", 404)
        return dict(row)

    def append_upload_chunk(self, upload_id: str, offset: int, chunk: bytes) -> int:
        self._validate_id(upload_id)
        part = self.upload_part_path(upload_id)
        with self.connection(write=True) as db:
            row = db.execute("SELECT bytes_received, expected_bytes, size FROM captures WHERE id=? AND ready=0", (upload_id,)).fetchone()
            if row is None:
                raise StoreError("upload_not_found", 404)
            received = int(row["bytes_received"])
            if offset != received:
                raise StoreError("chunk_offset_mismatch", 409)
            expected = int(row["expected_bytes"])
            new_total = received + len(chunk)
            if expected > 0 and new_total > expected:
                raise StoreError("chunk_exceeds_declared_size", 413)
            if self.storage_max_bytes == 0:
                try:
                    free_bytes = shutil.disk_usage(self.captures_dir).free
                except OSError:
                    free_bytes = 0
                if free_bytes > 0 and free_bytes - len(chunk) < self.disk_reserve_bytes:
                    raise StoreError("insufficient_disk_space", 507)
            with open(part, "r+b" if part.exists() else "wb") as fh:
                fh.seek(offset)
                fh.write(chunk)
            db.execute("UPDATE captures SET bytes_received=? WHERE id=?", (new_total, upload_id))
            return new_total

    def complete_chunk_upload(self, upload_id: str, total_size: int, sha256: str, fmt: str) -> dict:
        self._validate_id(upload_id)
        part = self.upload_part_path(upload_id)
        ext = "csv" if fmt in ("csv", "tsv") else "pcap"
        dest = self.capture_path(upload_id, ext)
        os.replace(part, dest)
        os.chmod(dest, 0o600)
        with self.connection(write=True) as db:
            db.execute(
                "UPDATE captures SET size=?, bytes_received=?, sha256=?, format=?, ready=1 WHERE id=?",
                (total_size, total_size, sha256, fmt, upload_id),
            )
            row = db.execute("SELECT * FROM captures WHERE id=?", (upload_id,)).fetchone()
        return dict(row)

    def register_local_capture(self, local_path: Path, filename: str, fmt: str, size: int, sha256: str) -> dict:
        cid = uuid.uuid4().hex
        with self.connection(write=True) as db:
            self._check_storage_capacity(db, 0, local_reference=True)
            db.execute(
                """INSERT INTO captures(id,sha256,size,created,ready,filename,format,source_kind,local_path,bytes_received,expected_bytes)
                   VALUES(?,?,?,?,1,?,?,'local',?,?,?)""",
                (cid, sha256, size, time.time(), filename[:255], fmt, str(local_path), size, size),
            )
            row = db.execute("SELECT * FROM captures WHERE id=?", (cid,)).fetchone()
        return dict(row)

    def capture(self, cid: str) -> dict:
        with self.connection() as db:
            row = db.execute("SELECT * FROM captures WHERE id=? AND ready=1", (cid,)).fetchone()
        if row is None:
            raise StoreError("capture_not_found", 404)
        return dict(row)

    def create_job(self, request, policy_hash: str, key: str | None = None) -> dict:
        res_mode = getattr(request, "resource_mode", "auto") or "auto"
        triage_on = bool(getattr(request, "triage_enabled", True))
        with self.connection(write=True) as db:
            if key:
                row = db.execute("SELECT * FROM jobs WHERE idempotency_key=?", (key,)).fetchone()
                if row:
                    if (
                        row["capture_id"] != request.capture_id
                        or bool(row["ai_enabled"]) != request.ai_enabled
                        or bool(row["consent"]) != request.ai_consent
                        or row["policy_hash"] != policy_hash
                    ):
                        raise StoreError("idempotency_conflict")
                    return self.job(row["id"])
            if not db.execute("SELECT id FROM captures WHERE id=? AND ready=1", (request.capture_id,)).fetchone():
                raise StoreError("capture_not_found", 404)
            count = db.execute("SELECT COUNT(*) FROM jobs WHERE state IN ('queued','parsing','awaiting_ai','generating')").fetchone()[0]
            if count >= self.queue_limit:
                raise StoreError("queue_full", 429)
            if db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] >= 500:
                raise StoreError("job_history_quota", 507)
            jid, now = uuid.uuid4().hex, utcnow()
            db.execute(
                """INSERT INTO jobs(id,capture_id,state,ai_enabled,consent,policy_hash,created_at,updated_at,idempotency_key,resource_mode,triage_enabled)
                   VALUES(?,?,'queued',?,?,?,?,?,?,?,?)""",
                (jid, request.capture_id, request.ai_enabled, request.ai_consent, policy_hash, now, now, key, res_mode, 1 if triage_on else 0),
            )
        return self.job(jid)

    def job(self, jid: str, *, internal=False) -> dict:
        with self.connection() as db:
            if internal:
                row = db.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
            else:
                row = db.execute(
                    """SELECT j.*, c.filename AS capture_filename, c.size AS capture_size_bytes,
                              c.format AS capture_format, c.source_kind AS capture_source_kind
                       FROM jobs j LEFT JOIN captures c ON c.id = j.capture_id WHERE j.id=?""",
                    (jid,),
                ).fetchone()
        if not row:
            raise StoreError("job_not_found", 404)
        return dict(row) if internal else self._public(row)

    def jobs(self, limit=50) -> list[dict]:
        with self.connection() as db:
            rows = db.execute(
                """SELECT j.*, c.filename AS capture_filename, c.size AS capture_size_bytes,
                          c.format AS capture_format, c.source_kind AS capture_source_kind
                   FROM jobs j LEFT JOIN captures c ON c.id = j.capture_id
                   ORDER BY j.created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [self._public(r) for r in rows]

    @staticmethod
    def _public(row) -> dict:
        keys = set(row.keys())
        result = {k: row[k] for k in ("id", "capture_id", "state", "created_at", "updated_at", "error_code", "policy_hash")}
        ai_obj = json.loads(row["ai_result"]) if row["ai_result"] else None
        ev_obj = json.loads(row["evidence"]) if row["evidence"] else None
        coverage_summary = None
        finding_count = None
        triage_summary = None
        if ev_obj:
            cov = ev_obj.get("coverage") or {}
            coverage_summary = {
                "packets_seen": cov.get("packets_seen", 0),
                "packets_analyzed": cov.get("packets_analyzed", 0),
                "truncated": bool(cov.get("truncated", False)),
                "parser": cov.get("parser", ""),
            }
            finding_count = len(ev_obj.get("findings") or [])
            triage_summary = ev_obj.get("triage")
        result.update(
            ai_enabled=bool(row["ai_enabled"]),
            cancel_requested=bool(row["cancel_requested"]),
            evidence_available=bool(row["evidence"]),
            ai_state=ai_obj["state"] if ai_obj else None,
            resource_mode=row["resource_mode"] if "resource_mode" in keys else "auto",
            triage_enabled=bool(row["triage_enabled"]) if "triage_enabled" in keys else True,
            capture_filename=row["capture_filename"] if "capture_filename" in keys else None,
            capture_size_bytes=row["capture_size_bytes"] if "capture_size_bytes" in keys else None,
            capture_format=row["capture_format"] if "capture_format" in keys else None,
            capture_source_kind=row["capture_source_kind"] if "capture_source_kind" in keys else None,
            finding_count=finding_count,
            coverage_summary=coverage_summary,
            triage_summary=triage_summary,
        )
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
            rows = db.execute("""SELECT c.id, c.source_kind FROM captures c WHERE ((c.ready=1 AND c.created<?) OR (c.ready=0 AND c.created<?))
              AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.capture_id=c.id AND j.state IN ('queued','parsing','awaiting_ai','generating'))""",
              (cutoff, time.time() - 3600)).fetchall()
            for row in rows:
                # Never unlink user-owned files referenced via local_ingest_roots
                if row["source_kind"] != "local":
                    for ext in ("pcap", "csv", "part"):
                        self.capture_path(row["id"], ext).unlink(missing_ok=True)
                db.execute("DELETE FROM jobs WHERE capture_id=?", (row["id"],))
                db.execute("DELETE FROM captures WHERE id=?", (row["id"],))
                count += 1
            db.execute("PRAGMA incremental_vacuum(100)")
        return count
