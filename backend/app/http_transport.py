"""Bounded, non-redirecting HTTP transport for explicitly consented local services.

This helper deliberately ignores ambient proxy configuration, does not follow
redirects, limits request/response sizes, and returns no upstream error body.
Endpoint URL validation and per-analysis consent remain the caller's job.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable

import httpx

MAX_JSON_REQUEST_BYTES = 512 * 1024
MAX_JSON_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_OPERATION_SECONDS = 60.0


def _is_cancelled(check: Callable[[], bool] | None) -> bool:
    if check is None:
        return False
    try:
        return bool(check())
    except Exception:
        # A broken cancellation callback must fail closed, not permit more I/O.
        return True


def post_json_bounded(
    url: str,
    payload: Any,
    *,
    timeout_seconds: float,
    transport: httpx.BaseTransport | None = None,
    deadline_monotonic: float | None = None,
    cancellation_check: Callable[[], bool] | None = None,
) -> Any | None:
    """POST bounded JSON, with a hard total deadline and cooperative cancellation.

    HTTPX's synchronous read timeout is an idle timeout, so a peer that drips
    bytes can otherwise keep a request alive indefinitely. The request therefore
    runs on a daemon worker while this caller watches the absolute deadline and
    cancellation callback. On either condition, the active response/client is
    closed from a separate daemon thread to interrupt streaming without waiting
    for a potentially blocked read.
    """
    try:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_JSON_REQUEST_BYTES:
            return None
        now = time.monotonic()
        timeout = max(1.0, min(float(timeout_seconds), MAX_OPERATION_SECONDS))
        local_deadline = now + timeout
        deadline = min(local_deadline, deadline_monotonic) if deadline_monotonic is not None else local_deadline
        if deadline <= now or _is_cancelled(cancellation_check):
            return None

        limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)
        state_lock = threading.Lock()
        active: dict[str, Any] = {"client": None, "response": None}
        cancelled = threading.Event()
        completed = threading.Event()
        result: list[Any] = [None]

        def close_active() -> None:
            cancelled.set()
            with state_lock:
                response = active.get("response")
                client = active.get("client")

            def _close() -> None:
                for obj in (response, client):
                    if obj is not None:
                        try:
                            obj.close()
                        except Exception:
                            pass

            threading.Thread(target=_close, name="bounded-http-cancel", daemon=True).start()

        def request_worker() -> None:
            client: httpx.Client | None = None
            try:
                remaining = max(0.001, deadline - time.monotonic())
                client = httpx.Client(
                    follow_redirects=False,
                    trust_env=False,
                    timeout=httpx.Timeout(remaining, connect=min(remaining, 5.0)),
                    limits=limits,
                    transport=transport,
                )
                with state_lock:
                    active["client"] = client
                if cancelled.is_set() or _is_cancelled(cancellation_check):
                    return
                with client.stream(
                    "POST",
                    url,
                    content=body,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                ) as response:
                    with state_lock:
                        active["response"] = response
                    if cancelled.is_set() or time.monotonic() >= deadline:
                        return
                    if response.status_code != 200:
                        return
                    raw = bytearray()
                    for chunk in response.iter_bytes():
                        if cancelled.is_set() or time.monotonic() >= deadline or _is_cancelled(cancellation_check):
                            return
                        if len(raw) + len(chunk) > MAX_JSON_RESPONSE_BYTES:
                            return
                        raw.extend(chunk)
                    if not cancelled.is_set() and time.monotonic() < deadline:
                        result[0] = json.loads(raw.decode("utf-8"))
            except Exception:
                result[0] = None
            finally:
                with state_lock:
                    active["response"] = None
                    active["client"] = None
                if client is not None:
                    try:
                        client.close()
                    except Exception:
                        pass
                completed.set()

        threading.Thread(target=request_worker, name="bounded-http-request", daemon=True).start()
        while not completed.is_set():
            if _is_cancelled(cancellation_check) or time.monotonic() >= deadline:
                close_active()
                return None
            completed.wait(min(0.01, max(0.001, deadline - time.monotonic())))
        if time.monotonic() >= deadline or _is_cancelled(cancellation_check):
            close_active()
            return None
        return result[0]
    except (httpx.HTTPError, OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
