"""Run offline: python -m backend.app.worker. No AI/OSINT network calls."""
from __future__ import annotations

import signal
import time
import hashlib
import os
import stat
from pathlib import Path
from .config import load_settings
from .models import AIResult
from .pipeline import analyze_capture, PipelineError
from .store import Store, StoreError

_HASH_BLOCK_BYTES = 4 * 1024 * 1024
_HASH_CANCEL_CHECK_BYTES = 64 * 1024 * 1024


class LocalCaptureSnapshotError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _snapshot_local_capture(
    store: Store,
    source_path: Path,
    scratch_dir: Path,
    expected_sha256: str,
    expected_size: int,
    is_cancelled,
) -> Path | None:
    """Copy a local capture into private storage and validate identity/content before parsing."""
    snapshot_path = scratch_dir / f"local-{os.urandom(16).hex()}.{source_path.suffix.lstrip('.') or 'pcap'}"
    succeeded = False
    try:
        try:
            store.ensure_worker_scratch_capacity(expected_size)
        except StoreError as exc:
            raise LocalCaptureSnapshotError(exc.code) from exc
        if expected_size <= 0:
            raise LocalCaptureSnapshotError("capture_integrity_mismatch")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            source_fd = os.open(source_path, flags)
        except OSError as exc:
            raise LocalCaptureSnapshotError("local_capture_unavailable") from exc
        with os.fdopen(source_fd, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
                raise LocalCaptureSnapshotError("capture_integrity_mismatch")
            try:
                snapshot_fd = os.open(
                    snapshot_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
                    0o600,
                )
            except OSError as exc:
                raise LocalCaptureSnapshotError("worker_scratch_unavailable") from exc
            digest = hashlib.sha256()
            total = 0
            try:
                with os.fdopen(snapshot_fd, "wb") as snapshot:
                    while True:
                        if is_cancelled():
                            return None
                        block = source.read(min(_HASH_BLOCK_BYTES, expected_size - total + 1))
                        if not block:
                            break
                        total += len(block)
                        if total > expected_size:
                            raise LocalCaptureSnapshotError("capture_integrity_mismatch")
                        digest.update(block)
                        store.write_worker_snapshot_chunk(snapshot, block)
                    snapshot.flush()
                    os.fsync(snapshot.fileno())
                    os.fchmod(snapshot.fileno(), 0o400)
            except OSError as exc:
                raise LocalCaptureSnapshotError("worker_scratch_unavailable") from exc
            after = os.fstat(source.fileno())
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or total != expected_size
                or digest.hexdigest() != expected_sha256
            ):
                raise LocalCaptureSnapshotError("capture_integrity_mismatch")
        succeeded = True
        return snapshot_path
    finally:
        if not succeeded:
            snapshot_path.unlink(missing_ok=True)


def _hash_local_capture(path: Path, is_cancelled) -> tuple[str, int] | None:
    """Retained for small integrity tests; production parsing uses the immutable snapshot above."""
    digest = hashlib.sha256()
    total = 0
    next_cancel_check = _HASH_CANCEL_CHECK_BYTES
    with path.open("rb") as capture_file:
        while True:
            block = capture_file.read(_HASH_BLOCK_BYTES)
            if not block:
                return digest.hexdigest(), total
            digest.update(block)
            total += len(block)
            if total >= next_cancel_check:
                if is_cancelled():
                    return None
                next_cancel_check = total + _HASH_CANCEL_CHECK_BYTES


def make_store(settings):
    return Store(
        settings.data_dir,
        queue_limit=settings.queue_limit,
        storage_max_bytes=settings.storage_max_bytes,
        storage_max_captures=settings.storage_max_captures,
        disk_reserve_bytes=getattr(settings, "disk_reserve_bytes", 256 * 1024 * 1024),
        batch_admission_concurrency=settings.batch_admission_concurrency,
    )


def run_once(store: Store, settings) -> bool:
    job = store.claim("parser")
    if not job:
        return False
    try:
        with store.worker_scratch_session() as scratch_dir:
            capture = store.capture(job["capture_id"])
            capture_path = store.resolve_capture_path(job["capture_id"])
            if capture.get("source_kind") == "local":
                try:
                    capture_path = _snapshot_local_capture(
                        store,
                        capture_path,
                        scratch_dir,
                        str(capture.get("sha256") or ""),
                        int(capture.get("size") or 0),
                        lambda: store.cancelled(job),
                    )
                except LocalCaptureSnapshotError as exc:
                    store.finish(job, "failed", error_code=exc.code)
                    return True
                if capture_path is None:
                    store.finish(job, "cancelled", error_code="cancelled")
                    return True
            bundle = analyze_capture(
                capture_path,
                capture["sha256"],
                settings,
                is_cancelled=lambda: store.cancelled(job),
                resource_mode=job.get("resource_mode", getattr(settings, "resource_mode", "auto")),
                triage_enabled=bool(job.get("triage_enabled", True)),
                triage_endpoint_consent=bool(job.get("triage_endpoint_consent", False)),
            )
            if store.cancelled(job):
                store.finish(job, "cancelled", error_code="cancelled")
                return True
            evidence = bundle.model_dump_json()
            partial = bundle.coverage.truncated or any(s.state in ("failed", "partial", "unavailable") for s in bundle.coverage.stages)
            if job["ai_enabled"]:
                store.finish(job, "awaiting_ai", evidence=evidence)
            else:
                ai = AIResult(state="disabled", provider=settings.ai.provider, model=settings.ai.model)
                store.finish(job, "partial" if partial else "completed", evidence=evidence, ai_result=ai.model_dump_json())
    except StoreError as exc:
        store.finish(job, "failed", error_code=exc.code)
    except PipelineError as exc:
        store.finish(job, "failed", error_code=exc.code)
    except Exception:
        store.finish(job, "failed", error_code="parser_internal_error")
    return True


def _workspace_stamp(ws_path) -> tuple[int, int] | None:
    if ws_path is None:
        return None
    try:
        st = ws_path.stat()
        return (int(st.st_mtime_ns), int(st.st_size))
    except OSError:
        return None


def main():
    from .picker import resolve_workspace_config_path

    settings = load_settings()
    store = make_store(settings)
    with store.worker_scratch_session():
        pass
    ws_path = resolve_workspace_config_path()
    ws_stamp = _workspace_stamp(ws_path)

    def stop(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    cleaned_at = 0.0
    try:
        while True:
            current_stamp = _workspace_stamp(ws_path)
            if current_stamp != ws_stamp:
                ws_stamp = current_stamp
                try:
                    new_settings = load_settings()
                    settings = new_settings
                    new_store = make_store(new_settings)
                    if new_store.root != store.root:
                        store = new_store
                        cleaned_at = 0.0
                        with store.worker_scratch_session():
                            pass
                except Exception:
                    pass
            if time.monotonic() - cleaned_at > 60:
                store.recover_stale(max(600, settings.parser_timeout_seconds * 3))
                store.purge_expired(settings.retention_hours)
                cleaned_at = time.monotonic()
            if not run_once(store, settings):
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
