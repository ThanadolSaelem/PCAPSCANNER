"""Authenticated REST API; capture parsing and AI run in separate workers."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from contextlib import asynccontextmanager
from typing import Annotated
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from .config import AppSettings, load_settings
from .models import AnalysisRequest, EvidenceBundle, AIResult, ProblemDetails
from .store import Store, StoreError

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}


def profile_hash(settings: AppSettings) -> str:
    return hashlib.sha256(settings.ai.model_dump_json().encode()).hexdigest()


def problem(status: int, code: str, request_id: str | None = None, headers=None):
    return JSONResponse(status_code=status, media_type="application/problem+json", headers=headers,
        content={"type": "urn:pcapscanner:problem:" + code, "title": code.replace("_", " "),
                 "status": status, "code": code, "request_id": request_id or uuid.uuid4().hex})


class BoundaryMiddleware:
    """Authenticate before reading bodies; bound JSON even without Content-Length."""
    def __init__(self, app, settings: AppSettings):
        self.app, self.settings = app, settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        rid = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = rid
        headers = dict(scope.get("headers", []))
        if scope["path"].startswith("/api/"):
            token = self.settings.api_token.get_secret_value() if self.settings.api_token else None
            if not token:
                return await problem(503, "api_credentials_not_configured", rid)(scope, receive, send)
            try:
                scheme, supplied = headers.get(b"authorization", b"").decode("ascii").split(" ", 1)
                authorized = scheme.lower() == "bearer" and hmac.compare_digest(supplied, token)
            except (ValueError, UnicodeError):
                authorized = False
            if not authorized:
                return await problem(401, "unauthorized", rid, {"WWW-Authenticate": "Bearer"})(scope, receive, send)
        if scope["method"] in ("POST", "PUT", "PATCH") and scope["path"] != "/api/v1/captures":
            data = bytearray()
            while True:
                msg = await receive()
                if msg["type"] == "http.disconnect":
                    return
                data.extend(msg.get("body", b""))
                if len(data) > self.settings.api_json_max_bytes:
                    return await problem(413, "json_body_too_large", rid)(scope, receive, send)
                if not msg.get("more_body", False):
                    break
            consumed = False
            original_receive = receive
            async def final_receive():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": bytes(data), "more_body": False}
                return await original_receive()
            receive = final_receive
        async def secured_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + [
                    (b"x-request-id", rid.encode()), (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff")]
            await send(message)
        await self.app(scope, receive, secured_send)


def create_app(settings: AppSettings | None = None) -> FastAPI:
    cfg = settings or load_settings()
    store = Store(cfg.data_dir, queue_limit=cfg.queue_limit, storage_max_bytes=cfg.storage_max_bytes,
                  storage_max_captures=cfg.storage_max_captures)
    app = FastAPI(title="PCAPSCANNER Backend", version="1.0.0",
        description="Single-tenant evidence-first offline capture API. Bearer token required for /api/v1/*. AI is optional and advisory.")
    app.openapi_version = "3.1.0"
    app.state.settings, app.state.store = cfg, store
    app.add_middleware(BoundaryMiddleware, settings=cfg)

    @app.exception_handler(StoreError)
    async def store_error(request, exc):
        return problem(exc.status, exc.code, request.state.request_id,
                       {"Retry-After": "5"} if exc.status == 429 else None)

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return problem(exc.status_code, str(exc.detail), request.state.request_id)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Never echo request input (it may contain secrets or captured identifiers).
        return problem(422, "invalid_request", request.state.request_id)

    @app.get("/health", tags=["Health"])
    def health():
        return {"status": "ok", "api_version": "1.0", "authentication_configured": bool(cfg.api_token)}

    @app.post("/api/v1/captures", status_code=201, tags=["Captures"], openapi_extra={"requestBody": {
        "required": True, "content": {"application/vnd.tcpdump.pcap": {"schema": {"type": "string", "format": "binary"}}}}})
    async def upload(request: Request):
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip()
        if content_type not in ("application/vnd.tcpdump.pcap", "application/x-pcap", "application/x-pcapng", "application/octet-stream"):
            raise HTTPException(415, "unsupported_capture_content_type")
        length = request.headers.get("content-length")
        if length:
            try:
                size = int(length)
                if size < 0:
                    raise ValueError()
            except ValueError:
                raise HTTPException(400, "invalid_content_length")
            if size > cfg.upload_max_bytes:
                raise HTTPException(413, "capture_too_large")
        cid = store.reserve_capture(cfg.upload_max_bytes)
        path, digest, total, prefix = store.capture_path(cid), hashlib.sha256(), 0, bytearray()
        try:
            with open(path, "xb") as f:
                os.chmod(path, 0o600)
                async for chunk in request.stream():
                    total += len(chunk)
                    if total > cfg.upload_max_bytes:
                        raise HTTPException(413, "capture_too_large")
                    if len(prefix) < 28:
                        prefix.extend(chunk[:28 - len(prefix)])
                    if len(prefix) >= 4 and bytes(prefix[:4]) not in PCAP_MAGIC:
                        raise HTTPException(400, "invalid_capture_magic")
                    digest.update(chunk)
                    f.write(chunk)
            minimum = 28 if bytes(prefix[:4]) == b"\x0a\x0d\x0d\x0a" else 24
            if total < minimum or bytes(prefix[:4]) not in PCAP_MAGIC:
                raise HTTPException(400, "invalid_capture_header")
            store.finish_capture(cid, total, digest.hexdigest())
        except BaseException:
            store.abort_capture(cid)
            raise
        return {"capture_id": cid, "sha256": digest.hexdigest(), "size_bytes": total,
                "validation": "header_only_full_validation_in_worker"}

    @app.post("/api/v1/analyses", status_code=202, tags=["Analyses"])
    def analyze(body: AnalysisRequest, idempotency_key: Annotated[str | None, Header(max_length=128)] = None):
        if body.ai_enabled and not cfg.ai.enabled:
            raise HTTPException(409, "ai_disabled_by_operator")
        if body.ai_enabled and not cfg.ai.model:
            raise HTTPException(409, "ai_model_not_configured")
        return store.create_job(body, profile_hash(cfg), idempotency_key)

    @app.get("/api/v1/analyses", tags=["Analyses"])
    def list_jobs(limit: Annotated[int, Query(ge=1, le=100)] = 50):
        return {"items": store.jobs(limit)}

    @app.get("/api/v1/analyses/{analysis_id}", tags=["Analyses"])
    def job(analysis_id: str):
        return store.job(analysis_id)

    @app.post("/api/v1/analyses/{analysis_id}/cancel", tags=["Analyses"])
    def cancel(analysis_id: str):
        return store.cancel(analysis_id)

    @app.get("/api/v1/analyses/{analysis_id}/evidence", tags=["Evidence"], response_model=EvidenceBundle)
    def evidence(analysis_id: str):
        row = store.job(analysis_id, internal=True)
        if not row["evidence"]:
            raise HTTPException(409, "evidence_not_ready")
        return EvidenceBundle.model_validate_json(row["evidence"])

    @app.get("/api/v1/analyses/{analysis_id}/report", tags=["Reports"])
    def report(analysis_id: str):
        row = store.job(analysis_id, internal=True)
        if not row["evidence"]:
            raise HTTPException(409, "evidence_not_ready")
        bundle = EvidenceBundle.model_validate_json(row["evidence"])
        return {"analysis_id": analysis_id, "status": row["state"], "evidence": bundle.model_dump(mode="json"),
                "ai": json.loads(row["ai_result"]) if row["ai_result"] else {"state": "pending"},
                "disclaimer": "Detector findings are candidates. AI is advisory; missing findings do not certify safety."}

    @app.get("/api/v1/ai/config", tags=["AI"])
    def ai_config():
        # AIConfig stores only secret ENV references, never values.
        return {"configuration": cfg.ai.model_dump(mode="json"), "policy_hash": profile_hash(cfg),
                "editable": "server_config_file_and_environment_only"}

    @app.get("/api/v1/ai/config/schema", tags=["AI"])
    def ai_schema():
        result = cfg.ai.__class__.model_json_schema()
        result["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        return result

    @app.get("/api/v1/ai/models", tags=["AI"])
    async def ai_models():
        from .llm import list_models
        try:
            items = await list_models(cfg)
            return {"state": "disabled" if not cfg.ai.enabled else ("completed" if items else "unavailable_or_empty"),
                    "items": items, "warning": None if items else "No catalog returned; this does not prove the provider has no models"}
        except Exception:
            raise HTTPException(502, "ai_model_discovery_unavailable")

    original_openapi = app.openapi
    def secured_openapi():
        schema = original_openapi()
        schema.setdefault("components", {}).setdefault("securitySchemes", {})["OperatorBearer"] = {"type": "http", "scheme": "bearer"}
        schema["components"].setdefault("schemas", {})["ProblemDetails"] = ProblemDetails.model_json_schema()
        for path, methods in schema["paths"].items():
            if path.startswith("/api/"):
                for method, operation in methods.items():
                    if method in ("get", "post", "put", "delete", "patch"):
                        operation["security"] = [{"OperatorBearer": []}]
                        for status in (400, 401, 404, 409, 413, 415, 422, 429, 502, 503, 507):
                            operation["responses"][str(status)] = {"description": "Stable Problem Details error code; no sensitive input echo",
                                "content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/ProblemDetails"}}}}
        return schema
    app.openapi = secured_openapi
    return app
