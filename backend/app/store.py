"""Single-host durable queue. Use one shared private volume, not ephemeral pods."""
from __future__ import annotations

import json
import hashlib
import errno
import os
import re
import shutil
import sqlite3
import stat
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
        batch_admission_concurrency: int = 2,
    ):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.captures_dir = self.root / "captures"
        self.captures_dir.mkdir(exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        os.chmod(self.captures_dir, 0o700)
        self.batch_staging_dir = self.root / "batch-staging"
        self.batch_staging_dir.mkdir(exist_ok=True, mode=0o700)
        os.chmod(self.batch_staging_dir, 0o700)
        self.batch_lock_dir = self.root / ".locks"
        self.batch_lock_dir.mkdir(exist_ok=True, mode=0o700)
        self.disk_capacity_lock_path = self.batch_lock_dir / "disk-capacity-write.lock"
        self.worker_scratch_dir = self.root / "worker-scratch"
        self.worker_scratch_dir.mkdir(exist_ok=True, mode=0o700)
        for private_dir in (self.batch_lock_dir, self.worker_scratch_dir):
            os.chmod(private_dir, 0o700)
        self.path = self.root / "metadata.sqlite3"
        self.queue_limit = queue_limit
        self.storage_max_bytes = storage_max_bytes
        self.storage_max_captures = storage_max_captures
        self.disk_reserve_bytes = disk_reserve_bytes
        self.batch_admission_concurrency = max(1, min(int(batch_admission_concurrency), 8))
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
              triage_enabled INTEGER NOT NULL DEFAULT 1,
              triage_endpoint_consent INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state, created_at);
            CREATE TABLE IF NOT EXISTS batches (
              id TEXT PRIMARY KEY,
              request_sha256 TEXT NOT NULL,
              item_count INTEGER NOT NULL,
              total_bytes INTEGER NOT NULL,
              idempotency_key TEXT UNIQUE,
              created REAL NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS batch_items (
              batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
              item_index INTEGER NOT NULL,
              capture_id TEXT NOT NULL,
              job_id TEXT NOT NULL,
              sha256 TEXT NOT NULL,
              size_bytes INTEGER NOT NULL,
              format TEXT NOT NULL,
              PRIMARY KEY(batch_id, item_index)
            );
            CREATE INDEX IF NOT EXISTS batch_items_job ON batch_items(job_id);
            """)
            self._migrate_columns(db)
        os.chmod(self.path, 0o600)
        self._recover_interrupted_batch_files()
        self._recover_interrupted_chunk_uploads()

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
            "triage_endpoint_consent": "INTEGER NOT NULL DEFAULT 0",
        }
        for col, ddl in job_migrations.items():
            if col not in job_cols:
                db.execute(f"ALTER TABLE jobs ADD COLUMN {col} {ddl}")

    @contextmanager
    def _file_lock(self, path: Path, *, blocking: bool = True):
        """Acquire a private advisory lock shared by processes using this data directory."""
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        acquired = False
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
                try:
                    msvcrt.locking(fd, mode, 1)
                except OSError as exc:
                    if not blocking:
                        raise StoreError("batch_admission_busy", 429) from exc
                    raise
            else:
                import fcntl

                mode = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
                try:
                    fcntl.flock(fd, mode)
                except BlockingIOError as exc:
                    raise StoreError("batch_admission_busy", 429) from exc
            acquired = True
            yield
        finally:
            if acquired:
                try:
                    if os.name == "nt":
                        import msvcrt

                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
            else:
                os.close(fd)

    @contextmanager
    def upload_lock(self, upload_id: str, *, blocking: bool = True):
        """Fence mutations and finalization of one upload across processes."""
        self._validate_id(upload_id)
        with self._file_lock(self.batch_lock_dir / f"upload-{upload_id}.lock", blocking=blocking):
            yield

    def _check_disk_headroom_unlocked(self, directory: Path, upcoming_bytes: int) -> None:
        try:
            free_bytes = shutil.disk_usage(directory).free
        except OSError as exc:
            raise StoreError("disk_capacity_unavailable", 507) from exc
        if free_bytes - max(0, int(upcoming_bytes)) < self.disk_reserve_bytes:
            raise StoreError("insufficient_disk_space", 507)

    @staticmethod
    def _write_reserved_handle_unlocked(handle, data: bytes, error_code: str) -> None:
        try:
            written = handle.write(data)
            if written != len(data):
                raise StoreError(error_code, 507)
            handle.flush()
            # Force delayed allocation to become visible before the shared lock is released.
            os.fsync(handle.fileno())
        except OSError as exc:
            if exc.errno in (errno.ENOSPC, getattr(errno, "EDQUOT", -1)):
                raise StoreError("insufficient_disk_space", 507) from exc
            raise StoreError(error_code, 507) from exc

    def write_capture_chunk(self, handle, data: bytes) -> None:
        """Atomically check headroom and persist one ordinary capture upload block."""
        with self._file_lock(self.disk_capacity_lock_path):
            self._check_disk_headroom_unlocked(self.captures_dir, len(data))
            self._write_reserved_handle_unlocked(handle, data, "capture_upload_write_failed")

    def write_unreserved_capture_chunk(self, capture_id: str, handle, data: bytes) -> None:
        """Charge actual bytes against storage quota before persisting a streamed block."""
        self._validate_id(capture_id)
        with self._file_lock(self.batch_lock_dir / "capture-storage-capacity.lock"):
            # Keep the reservation and write in one process-shared critical section.
            with self.connection(write=True) as db:
                row = db.execute(
                    "SELECT size,ready,source_kind FROM captures WHERE id=?", (capture_id,)
                ).fetchone()
                if row is None or row["ready"] or row["source_kind"] != "upload":
                    raise StoreError("upload_not_found", 404)
                _, total = db.execute(
                    "SELECT COUNT(*), COALESCE(SUM(CASE WHEN source_kind != 'local' THEN size ELSE 0 END),0) FROM captures"
                ).fetchone()
                if self.storage_max_bytes > 0 and int(total) + len(data) > self.storage_max_bytes:
                    raise StoreError("capture_storage_quota", 507)
                db.execute(
                    "UPDATE captures SET size=size+?,bytes_received=bytes_received+? WHERE id=? AND ready=0",
                    (len(data), len(data), capture_id),
                )
                with self._file_lock(self.disk_capacity_lock_path):
                    self._check_disk_headroom_unlocked(self.captures_dir, len(data))
                    self._write_reserved_handle_unlocked(handle, data, "capture_upload_write_failed")

    def write_worker_snapshot_chunk(self, handle, data: bytes) -> None:
        """Atomically check headroom and persist one private local-capture snapshot block."""
        with self._file_lock(self.disk_capacity_lock_path):
            self._check_disk_headroom_unlocked(self.worker_scratch_dir, len(data))
            self._write_reserved_handle_unlocked(handle, data, "worker_scratch_unavailable")

    @contextmanager
    def batch_upload_slot(self, slot_count: int):
        """Enforce a process-shared limit on simultaneous multipart staging requests."""
        limit = max(1, min(int(slot_count), self.batch_admission_concurrency, 8))
        lock = None
        for index in range(limit):
            candidate = self._file_lock(self.batch_lock_dir / f"batch-upload-{index}.lock", blocking=False)
            try:
                candidate.__enter__()
            except StoreError:
                continue
            lock = candidate
            break
        if lock is None:
            raise StoreError("batch_admission_busy", 429)
        try:
            yield
        finally:
            lock.__exit__(None, None, None)

    @contextmanager
    def _batch_upload_maintenance_lock(self):
        locks = []
        try:
            for index in range(self.batch_admission_concurrency):
                lock = self._file_lock(self.batch_lock_dir / f"batch-upload-{index}.lock", blocking=False)
                lock.__enter__()
                locks.append(lock)
        except StoreError:
            for lock in reversed(locks):
                lock.__exit__(None, None, None)
            raise
        try:
            yield
        finally:
            for lock in reversed(locks):
                lock.__exit__(None, None, None)

    def write_batch_staging_chunk(self, handle, data: bytes, max_staging_bytes: int) -> None:
        """Check aggregate staging and real disk headroom atomically before each write."""
        with self._file_lock(self.disk_capacity_lock_path):
            current_bytes = 0
            try:
                for entry in self.batch_staging_dir.glob("*.upload"):
                    info = entry.lstat()
                    if stat.S_ISREG(info.st_mode):
                        current_bytes += info.st_size
            except OSError as exc:
                raise StoreError("disk_capacity_unavailable", 507) from exc
            if current_bytes + len(data) > max_staging_bytes:
                raise StoreError("batch_staging_quota", 507)
            self._check_disk_headroom_unlocked(self.batch_staging_dir, len(data))
            self._write_reserved_handle_unlocked(handle, data, "batch_staging_unavailable")

    def _recover_interrupted_batch_files(self) -> None:
        """Clean crash remnants only when no active uploader or batch commit owns them."""
        try:
            with self._batch_upload_maintenance_lock():
                for entry in self.batch_staging_dir.iterdir():
                    if not re.fullmatch(r"[a-f0-9]{32}\.upload", entry.name):
                        continue
                    try:
                        info = entry.lstat()
                        if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                            entry.unlink(missing_ok=True)
                    except OSError:
                        continue
        except StoreError:
            pass
        try:
            with self._file_lock(self.batch_lock_dir / "batch-commit.lock", blocking=False):
                with self.connection() as db:
                    referenced = {str(row[0]) for row in db.execute("SELECT id FROM captures").fetchall()}
                for entry in self.captures_dir.iterdir():
                    match = re.fullmatch(r"([a-f0-9]{32})\.(?:pcap|csv|part)", entry.name)
                    if not match or match.group(1) in referenced:
                        continue
                    try:
                        info = entry.lstat()
                        if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                            entry.unlink(missing_ok=True)
                    except OSError:
                        continue
        except (StoreError, OSError, sqlite3.Error):
            pass

    def _recover_interrupted_chunk_uploads(self) -> None:
        """Return unready chunk uploads to a deterministic resumable partial state."""
        try:
            with self.connection() as db:
                ids = [str(row[0]) for row in db.execute(
                    "SELECT id FROM captures WHERE source_kind='chunked' AND ready=0"
                ).fetchall()]
        except sqlite3.Error:
            return
        for upload_id in ids:
            try:
                with self.upload_lock(upload_id, blocking=False):
                    with self.connection() as db:
                        row = db.execute(
                            "SELECT bytes_received,expected_bytes,format,ready FROM captures "
                            "WHERE id=? AND source_kind='chunked'", (upload_id,)
                        ).fetchone()
                    if row is None or row["ready"]:
                        continue
                    part = self.upload_part_path(upload_id)
                    ext = "csv" if row["format"] in ("csv", "tsv") else "pcap"
                    finalized = self.capture_path(upload_id, ext)
                    if not part.exists() and finalized.exists():
                        os.replace(finalized, part)
                    elif part.exists() and finalized.exists():
                        finalized.unlink(missing_ok=True)
                    if part.exists():
                        info = part.lstat()
                        if not stat.S_ISREG(info.st_mode):
                            part.unlink(missing_ok=True)
                            actual = 0
                        else:
                            actual = min(info.st_size, max(0, int(row["expected_bytes"])))
                            with part.open("r+b") as handle:
                                handle.truncate(actual)
                                handle.flush()
                                os.fsync(handle.fileno())
                            os.chmod(part, 0o600)
                    else:
                        actual = 0
                        with part.open("wb") as handle:
                            handle.flush()
                            os.fsync(handle.fileno())
                        os.chmod(part, 0o600)
                    with self.connection(write=True) as db:
                        db.execute(
                            "UPDATE captures SET bytes_received=? WHERE id=? AND ready=0 AND source_kind='chunked'",
                            (actual, upload_id),
                        )
            except (StoreError, OSError, sqlite3.Error):
                # A live process may still own the upload; never disturb its files.
                continue

    @contextmanager
    def worker_scratch_session(self):
        """Provide a private per-job scratch directory and reclaim orphaned crash remnants."""
        token = f"{os.getpid()}-{uuid.uuid4().hex}"
        lock_path = self.worker_scratch_dir / f"{token}.lock"
        scratch = self.worker_scratch_dir / token
        lock = self._file_lock(lock_path)
        lock.__enter__()
        try:
            for entry in self.worker_scratch_dir.iterdir():
                if not entry.is_dir() or entry == scratch or not re.fullmatch(r"\d+-[a-f0-9]{32}", entry.name):
                    continue
                stale_lock = self.worker_scratch_dir / f"{entry.name}.lock"
                try:
                    with self._file_lock(stale_lock, blocking=False):
                        shutil.rmtree(entry, ignore_errors=True)
                    stale_lock.unlink(missing_ok=True)
                except StoreError:
                    continue
            scratch.mkdir(mode=0o700)
            os.chmod(scratch, 0o700)
            yield scratch
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
            lock.__exit__(None, None, None)
            lock_path.unlink(missing_ok=True)

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
            try:
                free_bytes = shutil.disk_usage(self.worker_scratch_dir).free
            except OSError as exc:
                raise StoreError("disk_capacity_unavailable", 507) from exc
            if free_bytes - reserve_bytes < self.disk_reserve_bytes:
                raise StoreError("insufficient_disk_space", 507)
            return
        if self.storage_max_bytes > 0:
            if total + reserve_bytes > self.storage_max_bytes:
                raise StoreError("capture_storage_quota", 507)
        try:
            free_bytes = shutil.disk_usage(self.captures_dir).free
        except OSError as exc:
            raise StoreError("disk_capacity_unavailable", 507) from exc
        if free_bytes - reserve_bytes < self.disk_reserve_bytes:
            raise StoreError("insufficient_disk_space", 507)

    def ensure_worker_scratch_capacity(self, reserve_bytes: int) -> None:
        try:
            free_bytes = shutil.disk_usage(self.worker_scratch_dir).free
        except OSError as exc:
            raise StoreError("disk_capacity_unavailable", 507) from exc
        if free_bytes - max(0, int(reserve_bytes)) < self.disk_reserve_bytes:
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

    def abort_capture(self, cid: str, *, lock_held: bool = False):
        self._validate_id(cid)
        if not lock_held:
            with self.upload_lock(cid):
                return self.abort_capture(cid, lock_held=True)
        with self.connection(write=True) as db:
            row = db.execute("SELECT ready FROM captures WHERE id=?", (cid,)).fetchone()
            if row is None or row["ready"]:
                return
            db.execute("DELETE FROM captures WHERE id=? AND ready=0", (cid,))
        for ext in ("pcap", "csv", "part"):
            self.capture_path(cid, ext).unlink(missing_ok=True)

    def init_chunk_upload(self, filename: str, expected_bytes: int, fmt: str = "pcap") -> str:
        clean_name = Path(filename).name[:255] or "capture.pcap"
        cid = uuid.uuid4().hex
        with self.upload_lock(cid):
            with self.connection(write=True) as db:
                self._check_storage_capacity(db, expected_bytes)
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

    def append_upload_chunk(self, upload_id: str, offset: int, chunk: bytes, *, lock_held: bool = False) -> int:
        self._validate_id(upload_id)
        if not lock_held:
            with self.upload_lock(upload_id):
                return self.append_upload_chunk(upload_id, offset, chunk, lock_held=True)
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
            with self._file_lock(self.disk_capacity_lock_path):
                self._check_disk_headroom_unlocked(self.captures_dir, len(chunk))
                try:
                    with open(part, "r+b" if part.exists() else "wb") as fh:
                        fh.seek(offset)
                        self._write_reserved_handle_unlocked(fh, chunk, "capture_upload_write_failed")
                except OSError as exc:
                    if exc.errno in (errno.ENOSPC, getattr(errno, "EDQUOT", -1)):
                        raise StoreError("insufficient_disk_space", 507) from exc
                    raise StoreError("capture_upload_write_failed", 507) from exc
            db.execute("UPDATE captures SET bytes_received=? WHERE id=?", (new_total, upload_id))
            return new_total

    def complete_chunk_upload(
        self, upload_id: str, total_size: int, sha256: str, fmt: str, *, lock_held: bool = False
    ) -> dict:
        self._validate_id(upload_id)
        if not lock_held:
            with self.upload_lock(upload_id):
                return self.complete_chunk_upload(upload_id, total_size, sha256, fmt, lock_held=True)
        part = self.upload_part_path(upload_id)
        ext = "csv" if fmt in ("csv", "tsv") else "pcap"
        dest = self.capture_path(upload_id, ext)
        moved = False
        try:
            with self.connection(write=True) as db:
                row = db.execute(
                    "SELECT * FROM captures WHERE id=? AND ready=0 AND source_kind='chunked'", (upload_id,)
                ).fetchone()
                if row is None:
                    raise StoreError("upload_not_found", 404)
                try:
                    actual_size = part.stat().st_size
                except OSError as exc:
                    raise StoreError("upload_not_found", 404) from exc
                received, expected = int(row["bytes_received"]), int(row["expected_bytes"])
                if received != expected or actual_size != expected or total_size != expected:
                    raise StoreError("chunked_upload_incomplete", 409)
                os.replace(part, dest)
                moved = True
                os.chmod(dest, 0o600)
                updated = db.execute(
                    "UPDATE captures SET size=?,bytes_received=?,sha256=?,format=?,ready=1 "
                    "WHERE id=? AND ready=0 AND bytes_received=? AND expected_bytes=?",
                    (total_size, total_size, sha256, fmt, upload_id, expected, expected),
                )
                if updated.rowcount != 1:
                    raise StoreError("upload_not_found", 404)
                result = db.execute("SELECT * FROM captures WHERE id=?", (upload_id,)).fetchone()
            return dict(result)
        except BaseException:
            if moved and dest.exists() and not part.exists():
                os.replace(dest, part)
            raise

    def register_local_capture(self, local_path: Path, filename: str, fmt: str, size: int, sha256: str) -> dict:
        cid = uuid.uuid4().hex
        with self.connection(write=True) as db:
            self._check_storage_capacity(db, size, local_reference=True)
            db.execute(
                """INSERT INTO captures(id,sha256,size,created,ready,filename,format,source_kind,local_path,bytes_received,expected_bytes)
                   VALUES(?,?,?,?,1,?,?,'local',?,?,?)""",
                (cid, sha256, size, time.time(), filename[:255], fmt, str(local_path), size, size),
            )
            row = db.execute("SELECT * FROM captures WHERE id=?", (cid,)).fetchone()
        return dict(row)

    def create_batch(
        self,
        staged: list[dict],
        *,
        request_sha256: str,
        policy_hash: str,
        idempotency_key: str | None = None,
    ) -> dict:
        with self._file_lock(self.batch_lock_dir / "batch-commit.lock"):
            return self._create_batch_locked(
                staged,
                request_sha256=request_sha256,
                policy_hash=policy_hash,
                idempotency_key=idempotency_key,
            )

    def _create_batch_locked(
        self,
        staged: list[dict],
        *,
        request_sha256: str,
        policy_hash: str,
        idempotency_key: str | None = None,
    ) -> dict:
        """Atomically move staged PCAPs and create a batch manifest plus queued jobs."""
        if not staged or len(staged) > 64:
            raise StoreError("batch_file_count_invalid", 400)
        staging_root = self.batch_staging_dir.resolve()
        normalized: list[dict] = []
        total_bytes = 0
        for item in staged:
            try:
                path = Path(item["path"]).resolve(strict=True)
                info = path.lstat()
                size_bytes = int(item["size_bytes"])
                sha256 = str(item["sha256"])
                fmt = str(item["format"])
            except (OSError, KeyError, TypeError, ValueError) as exc:
                raise StoreError("batch_staging_unavailable", 507) from exc
            if not path.is_relative_to(staging_root) or not stat.S_ISREG(info.st_mode):
                raise StoreError("batch_staging_unavailable", 507)
            if size_bytes < 1 or info.st_size != size_bytes or fmt not in ("pcap", "pcapng"):
                raise StoreError("batch_staging_integrity_error", 400)
            digest = hashlib.sha256()
            try:
                with path.open("rb") as fh:
                    for block in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                        digest.update(block)
            except OSError as exc:
                raise StoreError("batch_staging_unavailable", 507) from exc
            if digest.hexdigest() != sha256:
                raise StoreError("batch_staging_integrity_error", 400)
            normalized.append({"path": path, "size_bytes": size_bytes, "sha256": sha256, "format": fmt})
            total_bytes += size_bytes

        batch_id = uuid.uuid4().hex
        created_at = utcnow()
        moved_paths: list[Path] = []
        existing_batch_id: str | None = None
        try:
            with self.connection(write=True) as db:
                if idempotency_key:
                    old = db.execute(
                        "SELECT id,request_sha256 FROM batches WHERE idempotency_key=?",
                        (idempotency_key,),
                    ).fetchone()
                    if old:
                        if old["request_sha256"] != request_sha256:
                            raise StoreError("idempotency_conflict", 409)
                        existing_batch_id = old["id"]

                if existing_batch_id is None:
                    active_count = db.execute(
                        "SELECT COUNT(*) FROM jobs WHERE state IN ('queued','parsing','awaiting_ai','generating')"
                    ).fetchone()[0]
                    if active_count + len(normalized) > self.queue_limit:
                        raise StoreError("queue_full", 429)
                    history_count = db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
                    if history_count + len(normalized) > 500:
                        raise StoreError("job_history_quota", 507)
                    capture_count, existing_bytes = db.execute(
                        "SELECT COUNT(*), COALESCE(SUM(CASE WHEN source_kind != 'local' THEN size ELSE 0 END),0) FROM captures"
                    ).fetchone()
                    if capture_count + len(normalized) > self.storage_max_captures:
                        raise StoreError("capture_storage_quota", 507)
                    if self.storage_max_bytes > 0:
                        if existing_bytes + total_bytes > self.storage_max_bytes:
                            raise StoreError("capture_storage_quota", 507)
                    try:
                        free_bytes = shutil.disk_usage(self.captures_dir).free
                    except OSError as exc:
                        raise StoreError("disk_capacity_unavailable", 507) from exc
                    # Staging and captures share this data-directory filesystem; rename
                    # does not consume the already-staged bytes a second time.
                    if free_bytes < self.disk_reserve_bytes:
                        raise StoreError("insufficient_disk_space", 507)

                    db.execute(
                        "INSERT INTO batches(id,request_sha256,item_count,total_bytes,idempotency_key,created,created_at) VALUES(?,?,?,?,?,?,?)",
                        (batch_id, request_sha256, len(normalized), total_bytes, idempotency_key, time.time(), created_at),
                    )
                    for index, item in enumerate(normalized):
                        capture_id, job_id = uuid.uuid4().hex, uuid.uuid4().hex
                        destination = self.capture_path(capture_id, "pcap")
                        if destination.exists():
                            raise StoreError("batch_id_collision", 503)
                        os.replace(item["path"], destination)
                        os.chmod(destination, 0o600)
                        moved_paths.append(destination)
                        safe_filename = f"batch-{batch_id[:8]}-{index + 1}.{item['format']}"
                        db.execute(
                            """INSERT INTO captures(id,sha256,size,created,ready,filename,format,source_kind,bytes_received,expected_bytes)
                               VALUES(?,?,?,?,1,?,?,'upload',?,?)""",
                            (capture_id, item["sha256"], item["size_bytes"], time.time(), safe_filename,
                             item["format"], item["size_bytes"], item["size_bytes"]),
                        )
                        now = utcnow()
                        db.execute(
                            """INSERT INTO jobs(id,capture_id,state,ai_enabled,consent,policy_hash,created_at,updated_at,
                               idempotency_key,resource_mode,triage_enabled,triage_endpoint_consent)
                               VALUES(?,?,'queued',0,0,?,?,?,?,'auto',1,0)""",
                            (job_id, capture_id, policy_hash, now, now, f"batch:{batch_id}:{index}"),
                        )
                        db.execute(
                            "INSERT INTO batch_items(batch_id,item_index,capture_id,job_id,sha256,size_bytes,format) VALUES(?,?,?,?,?,?,?)",
                            (batch_id, index, capture_id, job_id, item["sha256"], item["size_bytes"], item["format"]),
                        )
        except BaseException:
            for path in moved_paths:
                path.unlink(missing_ok=True)
            raise
        return self.batch(existing_batch_id or batch_id)

    def batch(self, batch_id: str) -> dict:
        if len(batch_id) != 32 or any(char not in "0123456789abcdef" for char in batch_id):
            raise StoreError("batch_not_found", 404)
        with self.connection() as db:
            batch_row = db.execute("SELECT * FROM batches WHERE id=?", (batch_id,)).fetchone()
            if not batch_row:
                raise StoreError("batch_not_found", 404)
            rows = db.execute(
                """SELECT bi.item_index,bi.capture_id,bi.job_id,bi.sha256,bi.size_bytes,bi.format,
                          j.state,j.error_code,j.evidence
                   FROM batch_items bi LEFT JOIN jobs j ON j.id=bi.job_id
                   WHERE bi.batch_id=? ORDER BY bi.item_index""",
                (batch_id,),
            ).fetchall()
        items = []
        for row in rows:
            items.append({
                "index": row["item_index"],
                "capture_id": row["capture_id"],
                "analysis_id": row["job_id"],
                "sha256": row["sha256"],
                "size_bytes": row["size_bytes"],
                "format": row["format"],
                "state": row["state"] or "failed",
                "error_code": row["error_code"] or ("job_history_expired" if row["state"] is None else None),
                "evidence_available": bool(row["evidence"]),
            })
        states = [item["state"] for item in items]
        active = {"queued", "parsing", "awaiting_ai", "generating"}
        if any(state in active for state in states):
            batch_state = "queued" if all(state == "queued" for state in states) else "running"
        elif states and all(state == "completed" for state in states):
            batch_state = "completed"
        elif states and all(state == "cancelled" for state in states):
            batch_state = "cancelled"
        elif states and all(state == "failed" for state in states):
            batch_state = "failed"
        else:
            batch_state = "partial"
        return {
            "batch_id": batch_row["id"],
            "created_at": batch_row["created_at"],
            "state": batch_state,
            "total_items": batch_row["item_count"],
            "completed_items": sum(state == "completed" for state in states),
            "failed_items": sum(state == "failed" for state in states),
            "partial_items": sum(state == "partial" for state in states),
            "cancelled_items": sum(state == "cancelled" for state in states),
            "items": items,
        }

    def batches(self, limit: int = 20) -> list[dict]:
        bounded_limit = max(1, min(int(limit), 100))
        with self.connection() as db:
            rows = db.execute(
                "SELECT id FROM batches ORDER BY created DESC,id DESC LIMIT ?",
                (bounded_limit,),
            ).fetchall()
        return [self.batch(str(row["id"])) for row in rows]

    def cancel_batch(self, batch_id: str) -> dict:
        if len(batch_id) != 32 or any(char not in "0123456789abcdef" for char in batch_id):
            raise StoreError("batch_not_found", 404)
        with self.connection(write=True) as db:
            if not db.execute("SELECT id FROM batches WHERE id=?", (batch_id,)).fetchone():
                raise StoreError("batch_not_found", 404)
            rows = db.execute(
                "SELECT j.id,j.state FROM batch_items bi JOIN jobs j ON j.id=bi.job_id WHERE bi.batch_id=?",
                (batch_id,),
            ).fetchall()
            for row in rows:
                if row["state"] in TERMINAL:
                    continue
                next_state = "cancelled" if row["state"] in ("queued", "awaiting_ai") else row["state"]
                ai_json = AIResult(state="cancelled", provider="unknown").model_dump_json() if next_state == "cancelled" else None
                db.execute(
                    "UPDATE jobs SET cancel_requested=1,state=?,ai_result=COALESCE(?,ai_result),updated_at=? WHERE id=?",
                    (next_state, ai_json, utcnow(), row["id"]),
                )
        return self.batch(batch_id)

    def capture(self, cid: str) -> dict:
        with self.connection() as db:
            row = db.execute("SELECT * FROM captures WHERE id=? AND ready=1", (cid,)).fetchone()
        if row is None:
            raise StoreError("capture_not_found", 404)
        return dict(row)

    def create_job(self, request, policy_hash: str, key: str | None = None) -> dict:
        res_mode = getattr(request, "resource_mode", "auto") or "auto"
        triage_on = bool(getattr(request, "triage_enabled", True))
        triage_endpoint_consent = bool(getattr(request, "triage_endpoint_consent", False))
        with self.connection(write=True) as db:
            if key:
                row = db.execute("SELECT * FROM jobs WHERE idempotency_key=?", (key,)).fetchone()
                if row:
                    if (
                        row["capture_id"] != request.capture_id
                        or bool(row["ai_enabled"]) != request.ai_enabled
                        or bool(row["consent"]) != request.ai_consent
                        or row["policy_hash"] != policy_hash
                        or row["resource_mode"] != res_mode
                        or bool(row["triage_enabled"]) != triage_on
                        or bool(row["triage_endpoint_consent"]) != triage_endpoint_consent
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
                """INSERT INTO jobs(id,capture_id,state,ai_enabled,consent,policy_hash,created_at,updated_at,idempotency_key,resource_mode,triage_enabled,triage_endpoint_consent)
                   VALUES(?,?,'queued',?,?,?,?,?,?,?,?,?)""",
                (jid, request.capture_id, request.ai_enabled, request.ai_consent, policy_hash, now, now, key, res_mode, 1 if triage_on else 0, 1 if triage_endpoint_consent else 0),
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
            triage_endpoint_consent=bool(row["triage_endpoint_consent"]) if "triage_endpoint_consent" in keys else False,
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
            db.execute(
                """DELETE FROM batches WHERE created<? AND NOT EXISTS (
                     SELECT 1 FROM batch_items bi JOIN jobs j ON j.id=bi.job_id
                     WHERE bi.batch_id=batches.id AND j.state IN ('queued','parsing','awaiting_ai','generating')
                   )""",
                (cutoff,),
            )
            db.execute("PRAGMA incremental_vacuum(100)")
        return count
