"""Network-capable narrator consumes only already-generated structured evidence."""
from __future__ import annotations

import asyncio
from .config import load_settings
from .models import EvidenceBundle, AIResult
from .main import profile_hash
from .llm import generate_summary
from .picker import resolve_workspace_config_path
from .worker import _workspace_stamp, make_store


async def run_once(store, settings) -> bool:
    job = store.claim("ai")
    if not job:
        return False
    try:
        bundle = EvidenceBundle.model_validate_json(job["evidence"])
        if not job["consent"] or job["policy_hash"] != profile_hash(settings):
            result = AIResult(state="unavailable", provider=settings.ai.provider, model=settings.ai.model,
                              error_code="ai_consent_or_policy_changed")
        else:
            task = asyncio.create_task(generate_summary(bundle, settings))
            try:
                while not task.done():
                    if store.cancelled(job):
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                        result = AIResult(state="cancelled", provider=settings.ai.provider, model=settings.ai.model)
                        break
                    await asyncio.wait({task}, timeout=0.2)
                else:
                    result = await task
            finally:
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
        partial = bundle.coverage.truncated or any(s.state in ("failed", "partial", "unavailable") for s in bundle.coverage.stages)
        partial = partial or result.state not in ("completed", "disabled")
        store.finish(job, "partial" if partial else "completed", ai_result=result.model_dump_json(),
                     error_code=result.error_code)
    except asyncio.CancelledError:
        store.finish(job, "partial", error_code="ai_worker_interrupted")
        raise
    except Exception:
        result = AIResult(state="unavailable", provider=settings.ai.provider, model=settings.ai.model, error_code="ai_internal_error")
        store.finish(job, "partial", ai_result=result.model_dump_json(), error_code=result.error_code)
    return True


async def main():
    settings = load_settings()
    store = make_store(settings)
    ws_path = resolve_workspace_config_path()
    ws_stamp = _workspace_stamp(ws_path)
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
            except Exception:
                pass
        store.recover_stale(600)
        if not await run_once(store, settings):
            await asyncio.sleep(0.5)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
