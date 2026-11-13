"""Run offline: python -m backend.app.worker. No AI/OSINT network calls."""
from __future__ import annotations

import signal
import time
from .config import load_settings
from .models import AIResult
from .pipeline import analyze_capture, PipelineError
from .store import Store


def make_store(settings):
    return Store(settings.data_dir, queue_limit=settings.queue_limit, storage_max_bytes=settings.storage_max_bytes,
                 storage_max_captures=settings.storage_max_captures)


def run_once(store: Store, settings) -> bool:
    job = store.claim("parser")
    if not job:
        return False
    try:
        capture = store.capture(job["capture_id"])
        bundle = analyze_capture(store.capture_path(job["capture_id"]), capture["sha256"], settings,
                                 is_cancelled=lambda: store.cancelled(job))
        evidence = bundle.model_dump_json()
        partial = bundle.coverage.truncated or any(s.state in ("failed", "partial", "unavailable") for s in bundle.coverage.stages)
        if job["ai_enabled"]:
            store.finish(job, "awaiting_ai", evidence=evidence)
        else:
            ai = AIResult(state="disabled", provider=settings.ai.provider, model=settings.ai.model)
            store.finish(job, "partial" if partial else "completed", evidence=evidence, ai_result=ai.model_dump_json())
    except PipelineError as exc:
        store.finish(job, "failed", error_code=exc.code)
    except Exception:
        store.finish(job, "failed", error_code="parser_internal_error")
    return True


def main():
    settings = load_settings()
    store = make_store(settings)
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    cleaned_at = 0.0
    try:
        while True:
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
