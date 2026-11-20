"""Authenticated REST API; capture parsing and AI run in separate workers."""
from __future__ import annotations

import hashlib
import hmac
import asyncio
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Body, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from .config import AIConfig, AppSettings, load_settings
from .batch_upload import BatchUploadError, stage_batch_upload
from .models import (
    AIConfigUpdateRequest,
    AICredentialUpdateRequest,
    AIModelProbeRequest,
    AIResult,
    BatchResponse,
    AnalysisRequest,
    CaseAnalysisLinkRequest,
    CaseCreateRequest,
    CaseDetail,
    CaseIOCCreateRequest,
    CaseListResponse,
    CaseNoteCreateRequest,
    CasePatchRequest,
    ChunkUploadInitRequest,
    EvidenceBundle,
    GroundedChatRequest,
    JobsPruneRequest,
    OSINTKeyRotateRequest,
    OSINTLookupRequest,
    LocalCaptureRequest,
    NativePickRequest,
    ProblemDetails,
    ScopedKeyCreateRequest,
    WorkspaceUpdateRequest,
)
from .picker import (
    ALLOWED_MODEL_EXTENSIONS,
    PickerError,
    detect_picker_backend,
    is_loopback_client,
    is_native_picker_enabled,
    pick_native_path,
    resolve_workspace_config_path,
    truthy_env,
    update_workspace_config,
)
from .store import ACTIVE, Store, StoreError
from .system import build_capabilities_payload, probe_capabilities, recommended_chunk_size_bytes
from .triage import bundle_to_triage_jsonl
from .etbert_bridge import inspect_etbert_checkpoint, is_etbert_effectively_enabled
from .yara import default_rules_dir, inspect_yara_rules
from .geoip import build_world_map_flows
from .exporters.csv_json import export_findings_and_evidence_csv
from .exporters.cef import export_findings_cef
from .exporters.navigator import export_attack_navigator_layer
from .exporters.pdf_report import export_snapshot_pdf
from .llm import (
    clear_runtime_api_key,
    credential_slot_for,
    credential_slot_names,
    generate_chat_completion,
    generate_summary,
    infer_preset,
    list_presets,
    probe_models,
    runtime_api_key_status,
    set_runtime_api_key,
)
from .llm.chat import ChatLimits, answer_question
from .stix_export import export_stix_bundle
from .osint_service import OSINTService, extract_ioc_candidates, MAX_IOCS_PER_OPERATION

mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/svg+xml", ".svg")

REPO_ROOT = Path(__file__).resolve().parents[2]

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}
ALLOWED_CAPTURE_CONTENT_TYPES = {
    "application/vnd.tcpdump.pcap",
    "application/x-pcap",
    "application/x-pcapng",
    "application/octet-stream",
    "text/csv",
    "application/csv",
    "text/tab-separated-values",
}
LOCAL_CAPTURE_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".csv", ".tsv"}
MAX_SINGLE_CHUNK_BYTES = 64 * 1024 * 1024
HASH_STREAM_BLOCK_BYTES = 4 * 1024 * 1024


def _looks_like_csv_header(prefix: bytes) -> bool:
    sample = prefix[:512].lstrip(b"\xef\xbb\xbf")
    if not sample or b"\x00" in sample:
        return False
    text = sample.decode("utf-8", errors="ignore").lower()
    first_line = text.splitlines()[0] if text else ""
    has_time = "time" in first_line
    has_src = ("source" in first_line) or ("src" in first_line)
    has_dst = ("destination" in first_line) or ("dst" in first_line)
    return has_time and has_src and has_dst


def _detect_capture_format(prefix: bytes) -> str | None:
    if len(prefix) >= 4 and bytes(prefix[:4]) in PCAP_MAGIC:
        return "pcapng" if bytes(prefix[:4]) == b"\x0a\x0d\x0d\x0a" else "pcap"
    if _looks_like_csv_header(prefix):
        first = prefix[:512].decode("utf-8", errors="ignore").splitlines()[0]
        return "tsv" if first.count("\t") >= first.count(",") else "csv"
    return None


def _hash_and_peek_file(path: Path) -> tuple[str, int, bytes]:
    digest = hashlib.sha256()
    total = 0
    prefix = bytearray()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(HASH_STREAM_BLOCK_BYTES)
            if not block:
                break
            if len(prefix) < 512:
                prefix.extend(block[: 512 - len(prefix)])
            digest.update(block)
            total += len(block)
    return digest.hexdigest(), total, bytes(prefix)


def _finalize_chunked_upload(store: Store, upload_id: str) -> tuple[dict, str, str]:
    """Serialize completeness checks, hashing, format validation, and publication."""
    with store.upload_lock(upload_id):
        pending = store.pending_upload(upload_id)
        part = store.upload_part_path(upload_id)
        expected = int(pending["expected_bytes"])
        received = int(pending["bytes_received"])
        try:
            actual_size = part.stat().st_size
        except OSError as exc:
            raise HTTPException(409, "chunked_upload_incomplete") from exc
        if received != expected or actual_size != expected:
            raise HTTPException(409, "chunked_upload_incomplete")
        sha256, total, prefix = _hash_and_peek_file(part)
        if total != expected:
            raise HTTPException(409, "chunked_upload_incomplete")
        fmt = _detect_capture_format(prefix)
        minimum = 28 if fmt == "pcapng" else (24 if fmt == "pcap" else 12)
        if fmt is None or total < minimum:
            store.abort_capture(upload_id, lock_held=True)
            raise HTTPException(400, "invalid_capture_header")
        row = store.complete_chunk_upload(upload_id, total, sha256, fmt, lock_held=True)
        return row, sha256, fmt


def _allowed_roots(cfg: AppSettings) -> list[Path]:
    roots: list[Path] = []
    for raw in getattr(cfg, "local_ingest_roots", []) or []:
        if not raw or "\x00" in raw:
            continue
        resolved = Path(raw).expanduser().resolve()
        if resolved.is_dir():
            roots.append(resolved)
    return roots


def _resolve_local_file(raw_path: str, roots: list[Path]) -> Path:
    if not roots:
        raise HTTPException(403, "local_ingest_disabled")
    if not raw_path or "\x00" in raw_path:
        raise HTTPException(400, "invalid_local_path")
    target = Path(raw_path).expanduser().resolve()
    if not any(target.is_relative_to(root) for root in roots):
        raise HTTPException(403, "local_path_not_allowlisted")
    if not target.is_file():
        raise HTTPException(404, "local_file_not_found")
    if target.suffix.lower() not in LOCAL_CAPTURE_EXTENSIONS:
        raise HTTPException(415, "unsupported_capture_extension")
    return target


def profile_hash(settings: AppSettings) -> str:
    policy = settings.ai.model_dump_json() + "\0" + settings.triage.model_dump_json()
    return hashlib.sha256(policy.encode()).hexdigest()


def problem(status: int, code: str, request_id: str | None = None, headers=None):
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        headers=headers,
        content={
            "type": "urn:pcapscanner:problem:" + code,
            "title": code.replace("_", " "),
            "status": status,
            "code": code,
            "request_id": request_id or uuid.uuid4().hex,
        },
    )


def _required_scope_for_request(method: str, path: str) -> tuple[str, ...]:
    if path.startswith("/api/v1/auth/keys"):
        return ("admin:keys",)
    if path.endswith((".csv", ".cef", ".navigator.json", ".pdf", ".stix.json", ".jsonl")):
        return ("export:reports",)
    if path.endswith("/snapshot"):
        if method == "GET":
            return ("read:manifest", "export:reports", "read:analyses")
        return ("export:reports",)
    if path.endswith("/report"):
        return ("read:report", "read:analyses")
    if path.endswith(("/evidence", "/artifacts", "/geoip")) or "/artifacts/" in path:
        return ("read:evidence", "read:analyses")
    if "/osint" in path or path.startswith("/api/v1/iocs"):
        return ("read:osint", "read:analyses") if method == "GET" else ("write:osint",)
    if path.startswith("/api/v1/cases"):
        return ("read:cases",) if method == "GET" else ("write:cases",)
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return ("write:analyses",)
    if path.startswith("/api/v1/analyses"):
        return ("read:status", "read:analyses")
    return ("read:analyses", "read:status")


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
            except (ValueError, UnicodeError):
                scheme, supplied = "", ""
            if scheme.lower() != "bearer" or not supplied:
                return await problem(401, "unauthorized", rid, {"WWW-Authenticate": "Bearer"})(scope, receive, send)
            if hmac.compare_digest(supplied, token):
                authorized = True
            elif supplied.startswith("phk_"):
                app_obj = scope.get("app")
                store_obj = getattr(getattr(app_obj, "state", None), "store", None)
                if store_obj is None:
                    return await problem(401, "unauthorized", rid, {"WWW-Authenticate": "Bearer"})(scope, receive, send)
                req_scope = _required_scope_for_request(scope.get("method", "GET"), scope["path"])
                try:
                    store_obj.verify_scoped_api_key(supplied, required_scope=req_scope, endpoint=scope["path"])
                    authorized = True
                except StoreError as exc:
                    hdrs = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else ({"Retry-After": "60"} if exc.status == 429 else None)
                    return await problem(exc.status, exc.code, rid, hdrs)(scope, receive, send)
            else:
                authorized = False
            if not authorized:
                return await problem(401, "unauthorized", rid, {"WWW-Authenticate": "Bearer"})(scope, receive, send)

        is_binary_upload = scope["path"] in {"/api/v1/captures", "/api/v1/batches"} or (
            scope["path"].startswith("/api/v1/captures/uploads/") and scope["path"].endswith("/chunk")
        )
        if scope["method"] in ("POST", "PUT", "PATCH") and not is_binary_upload:
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
                    (b"x-request-id", rid.encode()),
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    (
                        b"content-security-policy",
                        b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                        b"img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:; "
                        b"object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
                    ),
                ]
            await send(message)

        await self.app(scope, receive, secured_send)


def create_app(settings: AppSettings | None = None) -> FastAPI:
    initial_cfg = settings or load_settings()
    initial_store = Store(
        initial_cfg.data_dir,
        queue_limit=initial_cfg.queue_limit,
        storage_max_bytes=initial_cfg.storage_max_bytes,
        storage_max_captures=initial_cfg.storage_max_captures,
        disk_reserve_bytes=getattr(initial_cfg, "disk_reserve_bytes", 256 * 1024 * 1024),
        batch_admission_concurrency=initial_cfg.batch_admission_concurrency,
    )
    app = FastAPI(
        title="PCAPSCANNER Backend",
        version="1.1.0",
        description="Single-tenant evidence-first offline capture API. Bearer token required for /api/v1/*. AI is optional and advisory.",
    )
    app.openapi_version = "3.1.0"
    app.state.settings, app.state.store = initial_cfg, initial_store
    app.state.local_file_grants = {}
    app.state.osint_service = OSINTService()
    app.state.local_file_grants_lock = threading.Lock()
    app.state.batch_admission = threading.BoundedSemaphore(initial_cfg.batch_admission_concurrency)
    app.state.batch_admission_active = 0
    app.state.batch_admission_state_lock = threading.Lock()
    app.state.chat_semaphore = asyncio.Semaphore(2)
    app.add_middleware(BoundaryMiddleware, settings=initial_cfg)

    def _cfg() -> AppSettings:
        return app.state.settings

    def _store() -> Store:
        return app.state.store

    def _issue_local_file_grant(path: Path, sha256: str, size: int, st: os.stat_result) -> str:
        now = time.monotonic()
        with app.state.local_file_grants_lock:
            grants = app.state.local_file_grants
            for token, grant in list(grants.items()):
                if grant["expires_at"] <= now:
                    grants.pop(token, None)
            if len(grants) >= LOCAL_FILE_GRANT_MAX_ENTRIES:
                raise HTTPException(429, "local_file_grant_capacity")
            token = secrets.token_urlsafe(32)
            grants[token] = {
                "path": str(path),
                "sha256": sha256,
                "size": size,
                "device": st.st_dev,
                "inode": st.st_ino,
                "mtime_ns": st.st_mtime_ns,
                "expires_at": now + LOCAL_FILE_GRANT_TTL_SECONDS,
            }
        return token

    def _consume_local_file_grant(token: str) -> dict[str, object]:
        with app.state.local_file_grants_lock:
            grant = app.state.local_file_grants.pop(token, None)
        if not grant or float(grant["expires_at"]) <= time.monotonic():
            raise HTTPException(409, "local_file_grant_expired_or_used")
        return grant

    def _workspace_state() -> dict[str, object]:
        cfg_now = _cfg()
        ws_path = resolve_workspace_config_path()
        picker_backend = detect_picker_backend() if is_native_picker_enabled() else None
        ckpt_path = getattr(cfg_now.triage, "etbert_checkpoint_path", None)
        ckpt_info = inspect_etbert_checkpoint(ckpt_path)
        return {
            "data_dir": str(Path(cfg_now.data_dir).expanduser().resolve()),
            "local_ingest_roots": [str(r) for r in _allowed_roots(cfg_now)],
            "resource_mode": str(getattr(cfg_now, "resource_mode", "auto")),
            "etbert_checkpoint_path": ckpt_path,
            "etbert_checkpoint_configured": bool(ckpt_path),
            "etbert_enabled": is_etbert_effectively_enabled(
                cfg_now.triage, ckpt_ready=bool(ckpt_info.get("ready"))
            ),
            "etbert_checkpoint_info": ckpt_info,
            "etbert_checkpoint_status": ckpt_info,
            "native_picker_available": bool(picker_backend is not None),
            "picker_backend": picker_backend,
            "persisted": bool(ws_path is not None),
            "workspace_config_path": str(ws_path) if ws_path else None,
        }

    def _normalize_existing_roots(raw_roots: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw in raw_roots:
            if not raw or "\x00" in raw:
                raise HTTPException(400, "invalid_local_path")
            resolved = Path(raw).expanduser().resolve()
            if not resolved.is_dir():
                raise HTTPException(400, "local_root_not_found")
            key = str(resolved)
            if key not in seen:
                seen.add(key)
                normalized.append(key)
            if len(normalized) > 20:
                raise HTTPException(400, "too_many_local_roots")
        return normalized

    def _apply_workspace_mutation(
        *,
        new_data_dir: str | None = None,
        new_roots: list[str] | None = None,
        new_resource_mode: str | None = None,
        new_etbert_checkpoint_path: str | None = None,
        new_etbert_enabled: bool | None = None,
        clear_etbert_checkpoint: bool = False,
    ) -> dict[str, object]:
        cfg_now = _cfg()
        store_now = _store()
        update_fields: dict[str, object] = {}
        next_store = store_now

        if new_data_dir is not None:
            if not new_data_dir or "\x00" in new_data_dir:
                raise HTTPException(400, "invalid_data_dir")
            target_dir = Path(new_data_dir).expanduser().resolve()
            if target_dir.exists() and not target_dir.is_dir():
                raise HTTPException(400, "invalid_data_dir")
            if target_dir != store_now.root:
                with app.state.batch_admission_state_lock:
                    if app.state.batch_admission_active:
                        raise HTTPException(409, "batch_admission_in_progress")
                active_jobs = [j for j in store_now.jobs(50) if j.get("state") in ACTIVE]
                if active_jobs:
                    raise HTTPException(409, "active_jobs_in_progress")
                try:
                    next_store = Store(
                        target_dir,
                        queue_limit=cfg_now.queue_limit,
                        storage_max_bytes=cfg_now.storage_max_bytes,
                        storage_max_captures=cfg_now.storage_max_captures,
                        disk_reserve_bytes=getattr(cfg_now, "disk_reserve_bytes", 256 * 1024 * 1024),
                        batch_admission_concurrency=cfg_now.batch_admission_concurrency,
                    )
                except (OSError, sqlite3.Error) as exc:
                    raise HTTPException(400, "invalid_data_dir") from exc
            update_fields["data_dir"] = target_dir

        if new_roots is not None:
            update_fields["local_ingest_roots"] = _normalize_existing_roots(new_roots)

        if new_resource_mode is not None:
            update_fields["resource_mode"] = new_resource_mode

        triage_updates: dict[str, object] = {}
        clearing_etbert = False
        if clear_etbert_checkpoint:
            clearing_etbert = True
            triage_updates["etbert_checkpoint_path"] = None
            if new_etbert_enabled is None:
                triage_updates["etbert_enabled"] = False
        elif new_etbert_checkpoint_path is not None:
            cleaned_ckpt = new_etbert_checkpoint_path.strip()
            if cleaned_ckpt:
                if "\x00" in cleaned_ckpt:
                    raise HTTPException(400, "invalid_etbert_checkpoint_path")
                resolved_ckpt = Path(cleaned_ckpt).expanduser().resolve()
                if not resolved_ckpt.is_file() or resolved_ckpt.suffix.lower() not in ALLOWED_MODEL_EXTENSIONS:
                    raise HTTPException(400, "invalid_etbert_checkpoint_path")
                triage_updates["etbert_checkpoint_path"] = str(resolved_ckpt)
                if new_etbert_enabled is None:
                    triage_updates["etbert_enabled"] = True
            else:
                clearing_etbert = True
                triage_updates["etbert_checkpoint_path"] = None
                if new_etbert_enabled is None:
                    triage_updates["etbert_enabled"] = False
        if new_etbert_enabled is not None:
            triage_updates["etbert_enabled"] = bool(new_etbert_enabled)
        if triage_updates:
            update_fields["triage"] = cfg_now.triage.model_copy(update=triage_updates)

        if update_fields:
            updated_cfg = cfg_now.model_copy(update=update_fields)
            app.state.settings = updated_cfg
            app.state.store = next_store
            ws_path = resolve_workspace_config_path()
            if ws_path is not None:
                explicit_etbert = (
                    bool(updated_cfg.triage.etbert_enabled)
                    if "etbert_enabled" in updated_cfg.triage.model_fields_set
                    else None
                )
                persisted_ckpt = "" if clearing_etbert else updated_cfg.triage.etbert_checkpoint_path
                update_workspace_config(
                    path=ws_path,
                    data_dir=str(updated_cfg.data_dir),
                    local_ingest_roots=list(updated_cfg.local_ingest_roots),
                    resource_mode=str(updated_cfg.resource_mode),
                    etbert_checkpoint_path=persisted_ckpt,
                    etbert_enabled=explicit_etbert,
                    prefer_workspace=True,
                )

        return _workspace_state()

    @app.exception_handler(StoreError)
    async def store_error(request, exc):
        return problem(
            exc.status,
            exc.code,
            request.state.request_id,
            {"Retry-After": "5"} if exc.status == 429 else None,
        )

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return problem(exc.status_code, str(exc.detail), request.state.request_id, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Never echo request input (it may contain secrets or captured identifiers).
        return problem(422, "invalid_request", request.state.request_id)

    @app.get("/health", tags=["Health"])
    def health():
        return {"status": "ok", "api_version": "1.1", "authentication_configured": bool(_cfg().api_token)}

    @app.get("/api/v1/system/capabilities", tags=["System"])
    def capabilities():
        return build_capabilities_payload(_cfg())

    @app.get("/api/v1/system/etbert", tags=["System"])
    def etbert_status():
        cfg_now = _cfg()
        status = inspect_etbert_checkpoint(cfg_now.triage.etbert_checkpoint_path)
        return {
            **status,
            "etbert_enabled": is_etbert_effectively_enabled(
                cfg_now.triage, ckpt_ready=bool(status.get("ready"))
            ),
            "mode": str(cfg_now.triage.mode),
        }

    @app.get("/api/v1/yara/rules", tags=["System"])
    def yara_rules_inventory():
        cfg_now = _cfg()
        return inspect_yara_rules(cfg_now.yara_rules_dir or default_rules_dir())

    @app.get("/api/v1/system/workspace", tags=["System"])
    def get_workspace():
        return _workspace_state()

    @app.put("/api/v1/system/workspace", tags=["System"])
    def update_workspace(body: WorkspaceUpdateRequest, request: Request):
        client_host = request.client.host if request.client else None
        if not is_loopback_client(client_host) and not truthy_env(os.environ.get("PCAP_ALLOW_REMOTE_WORKSPACE")):
            raise HTTPException(403, "workspace_mutation_loopback_only")

        cfg_now = _cfg()
        next_roots: list[str] | None = None
        if body.local_ingest_roots is not None:
            next_roots = list(body.local_ingest_roots)
        elif body.add_local_ingest_root is not None or body.remove_local_ingest_root is not None:
            current_roots = list(cfg_now.local_ingest_roots or [])
            if body.add_local_ingest_root is not None:
                current_roots.append(body.add_local_ingest_root)
            if body.remove_local_ingest_root is not None:
                rm_resolved = str(Path(body.remove_local_ingest_root).expanduser().resolve())
                current_roots = [
                    r for r in current_roots if str(Path(r).expanduser().resolve()) != rm_resolved
                ]
            next_roots = current_roots

        return _apply_workspace_mutation(
            new_data_dir=body.data_dir,
            new_roots=next_roots,
            new_resource_mode=body.resource_mode,
            new_etbert_checkpoint_path=body.etbert_checkpoint_path,
            new_etbert_enabled=body.etbert_enabled,
            clear_etbert_checkpoint=body.clear_etbert_checkpoint,
        )

    @app.post("/api/v1/system/pick-path", tags=["System"])
    async def pick_path_native(body: NativePickRequest, request: Request):
        client_host = request.client.host if request.client else None
        if not is_loopback_client(client_host):
            raise HTTPException(403, "picker_loopback_only")

        cfg_now = _cfg()
        existing_roots = _allowed_roots(cfg_now)
        if body.purpose == "data_dir":
            init_dir = Path(cfg_now.data_dir).expanduser()
            if not init_dir.is_dir():
                init_dir = Path.home()
        else:
            init_dir = existing_roots[0] if existing_roots else (Path.home() / "Downloads")
            if not init_dir.is_dir():
                init_dir = Path.home()

        try:
            picked = await run_in_threadpool(pick_native_path, body.purpose, initial_dir=init_dir)
        except PickerError as exc:
            raise HTTPException(exc.status, exc.code) from exc

        if picked is None:
            return {
                "cancelled": True,
                "purpose": body.purpose,
                "selected_path": None,
                "workspace": _workspace_state(),
            }

        if body.purpose == "data_dir":
            ws_state = _apply_workspace_mutation(new_data_dir=str(picked))
            return {
                "cancelled": False,
                "purpose": "data_dir",
                "selected_path": str(picked),
                "workspace": ws_state,
            }

        if body.purpose == "capture_root":
            merged_roots = list(cfg_now.local_ingest_roots or []) + [str(picked)]
            ws_state = _apply_workspace_mutation(new_roots=merged_roots)
            return {
                "cancelled": False,
                "purpose": "capture_root",
                "selected_path": str(picked),
                "workspace": ws_state,
            }

        if body.purpose == "model_file":
            if not picked.is_file() or picked.suffix.lower() not in ALLOWED_MODEL_EXTENSIONS:
                raise HTTPException(415, "unsupported_model_extension")
            resolved_model = str(picked.resolve(strict=True))
            ws_state = _apply_workspace_mutation(
                new_etbert_checkpoint_path=resolved_model,
                new_etbert_enabled=True,
            )
            ckpt_info = inspect_etbert_checkpoint(resolved_model)
            return {
                "cancelled": False,
                "purpose": "model_file",
                "selected_path": resolved_model,
                "etbert_checkpoint": ckpt_info,
                "etbert_status": ckpt_info,
                "workspace": ws_state,
            }

        # A file selection grants one exact path once; it never authorizes the parent folder.
        if not picked.is_file():
            raise HTTPException(404, "local_file_not_found")
        if picked.suffix.lower() not in LOCAL_CAPTURE_EXTENSIONS:
            raise HTTPException(415, "unsupported_capture_extension")
        resolved = picked.resolve(strict=True)
        before = resolved.stat()
        if cfg_now.upload_max_bytes > 0 and before.st_size > cfg_now.upload_max_bytes:
            raise HTTPException(413, "capture_too_large")
        sha256, total, prefix = await run_in_threadpool(_hash_and_peek_file, resolved)
        after = resolved.stat()
        fmt = _detect_capture_format(prefix)
        minimum = 28 if fmt == "pcapng" else (24 if fmt == "pcap" else 12)
        if fmt is None or total < minimum:
            raise HTTPException(400, "invalid_capture_header")
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ) or total != after.st_size:
            raise HTTPException(409, "local_file_changed_during_selection")
        grant_token = _issue_local_file_grant(resolved, sha256, total, after)
        return {
            "cancelled": False,
            "purpose": "capture_file",
            "selected_path": None,
            "file_grant_token": grant_token,
            "filename": resolved.name,
            "size_bytes": total,
            "sha256": sha256,
            "grant_expires_in_seconds": LOCAL_FILE_GRANT_TTL_SECONDS,
            "workspace": _workspace_state(),
        }

    @app.post(
        "/api/v1/captures",
        status_code=201,
        tags=["Captures"],
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/vnd.tcpdump.pcap": {"schema": {"type": "string", "format": "binary"}}},
            }
        },
    )
    async def upload(request: Request):
        cfg_now, store_now = _cfg(), _store()
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type not in ALLOWED_CAPTURE_CONTENT_TYPES:
            raise HTTPException(415, "unsupported_capture_content_type")
        length = request.headers.get("content-length")
        declared_size: int | None = None
        upload_limit = cfg_now.upload_max_bytes
        if length is not None:
            try:
                declared_size = int(length)
                if declared_size < 0:
                    raise ValueError()
            except ValueError:
                raise HTTPException(400, "invalid_content_length")
            if upload_limit > 0 and declared_size > upload_limit:
                raise HTTPException(413, "capture_too_large")

        raw_name = request.headers.get("x-capture-filename", "").strip()
        clean_name = Path(raw_name).name[:255] if raw_name else None
        reserve_bytes = declared_size if declared_size is not None else (upload_limit if upload_limit > 0 else 0)
        charge_actual_bytes = declared_size is None and upload_limit == 0
        cid = store_now.reserve_capture(reserve_bytes, filename=clean_name)
        path, digest, total, prefix = store_now.capture_path(cid, "pcap"), hashlib.sha256(), 0, bytearray()
        write_buffer = bytearray()
        write_block_bytes = 1024 * 1024
        try:
            with open(path, "xb") as f:
                os.chmod(path, 0o600)
                async for chunk in request.stream():
                    total += len(chunk)
                    if declared_size is not None and total > declared_size:
                        raise HTTPException(400, "content_length_mismatch")
                    if upload_limit > 0 and total > upload_limit:
                        raise HTTPException(413, "capture_too_large")
                    if len(prefix) < 512:
                        prefix.extend(chunk[: 512 - len(prefix)])
                    if len(prefix) >= 4:
                        head4 = bytes(prefix[:4])
                        if head4 not in PCAP_MAGIC and not _looks_like_csv_header(bytes(prefix)):
                            if b"\n" in prefix or len(prefix) >= 256:
                                raise HTTPException(400, "invalid_capture_magic")
                    digest.update(chunk)
                    for offset in range(0, len(chunk), write_block_bytes):
                        write_buffer.extend(chunk[offset:offset + write_block_bytes])
                        if len(write_buffer) == write_block_bytes:
                            block = bytes(write_buffer)
                            write_buffer.clear()
                            if charge_actual_bytes:
                                await run_in_threadpool(store_now.write_unreserved_capture_chunk, cid, f, block)
                            else:
                                await run_in_threadpool(store_now.write_capture_chunk, f, block)
                if write_buffer:
                    if charge_actual_bytes:
                        await run_in_threadpool(store_now.write_unreserved_capture_chunk, cid, f, bytes(write_buffer))
                    else:
                        await run_in_threadpool(store_now.write_capture_chunk, f, bytes(write_buffer))
                if declared_size is not None and total != declared_size:
                    raise HTTPException(400, "content_length_mismatch")
            fmt = _detect_capture_format(bytes(prefix))
            if fmt is None:
                raise HTTPException(400, "invalid_capture_header")
            if fmt in ("pcap", "pcapng"):
                minimum = 28 if fmt == "pcapng" else 24
                if total < minimum:
                    raise HTTPException(400, "invalid_capture_header")
            else:
                if total < 12:
                    raise HTTPException(400, "invalid_capture_header")
                csv_dest = store_now.capture_path(cid, "csv")
                os.replace(path, csv_dest)
                os.chmod(csv_dest, 0o600)
            store_now.finish_capture(cid, total, digest.hexdigest(), fmt=fmt)
        except BaseException:
            store_now.abort_capture(cid)
            raise
        return {
            "capture_id": cid,
            "sha256": digest.hexdigest(),
            "size_bytes": total,
            "format": fmt,
            "filename": clean_name,
            "validation": "header_only_full_validation_in_worker",
        }

    @app.post(
        "/api/v1/batches",
        status_code=202,
        tags=["Batches"],
        response_model=BatchResponse,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "required": ["files"],
                            "properties": {"files": {"type": "array", "items": {"type": "string", "format": "binary"}}},
                        }
                    }
                },
            }
        },
    )
    async def create_batch(
        request: Request,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=128)] = None,
    ):
        if idempotency_key is not None and not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", idempotency_key):
            raise HTTPException(400, "invalid_idempotency_key")
        if not app.state.batch_admission.acquire(blocking=False):
            raise HTTPException(429, "batch_admission_busy", headers={"Retry-After": "2"})
        with app.state.batch_admission_state_lock:
            app.state.batch_admission_active += 1
        store_now, cfg_now = _store(), _cfg()
        staged = []
        try:
            with store_now.batch_upload_slot(cfg_now.batch_admission_concurrency):
                total_limit = cfg_now.batch_max_total_bytes
                per_file_limit = min(cfg_now.upload_max_bytes, total_limit) if cfg_now.upload_max_bytes > 0 else total_limit
                try:
                    staged = await stage_batch_upload(
                        request,
                        store_now.batch_staging_dir,
                        max_files=cfg_now.batch_max_files,
                        max_file_bytes=per_file_limit,
                        max_total_bytes=total_limit,
                        max_staging_bytes=total_limit * cfg_now.batch_admission_concurrency,
                        staging_writer=store_now.write_batch_staging_chunk,
                    )
                except BatchUploadError as exc:
                    raise HTTPException(exc.status, exc.code) from exc

                policy = profile_hash(cfg_now)
                manifest = {
                    "items": [
                        {"sha256": item.sha256, "size_bytes": item.size_bytes, "format": item.format}
                        for item in staged
                    ],
                    "policy_hash": policy,
                    "ai_enabled": False,
                    "triage_enabled": True,
                    "triage_endpoint_consent": False,
                    "resource_mode": "auto",
                }
                request_digest = hashlib.sha256(
                    json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                staged_payload = [
                    {"path": item.path, "size_bytes": item.size_bytes, "sha256": item.sha256, "format": item.format}
                    for item in staged
                ]
                return await run_in_threadpool(
                    store_now.create_batch,
                    staged_payload,
                    request_sha256=request_digest,
                    policy_hash=policy,
                    idempotency_key=idempotency_key,
                )
        finally:
            for item in staged:
                try:
                    item.path.unlink(missing_ok=True)
                except OSError:
                    pass
            with app.state.batch_admission_state_lock:
                app.state.batch_admission_active -= 1
            app.state.batch_admission.release()

    @app.get("/api/v1/batches", tags=["Batches"], response_model=list[BatchResponse])
    def list_batches(limit: Annotated[int, Query(ge=1, le=100)] = 20):
        return _store().batches(limit)

    @app.get("/api/v1/batches/{batch_id}", tags=["Batches"], response_model=BatchResponse)
    def get_batch(batch_id: str):
        return _store().batch(batch_id)

    @app.post("/api/v1/batches/{batch_id}/cancel", tags=["Batches"], response_model=BatchResponse)
    def cancel_batch(batch_id: str):
        return _store().cancel_batch(batch_id)

    @app.post("/api/v1/captures/uploads", status_code=201, tags=["Captures"])
    def init_chunked_upload(body: ChunkUploadInitRequest):
        cfg_now, store_now = _cfg(), _store()
        if cfg_now.upload_max_bytes > 0 and body.total_bytes > cfg_now.upload_max_bytes:
            raise HTTPException(413, "capture_too_large")
        caps = probe_capabilities(cfg_now.data_dir)
        chunk_size = recommended_chunk_size_bytes(caps)
        ext = Path(body.filename).suffix.lower().lstrip(".")
        fmt = ext if ext in ("pcap", "pcapng", "cap", "csv", "tsv") else (
            body.format_hint if body.format_hint != "auto" else "pcap"
        )
        cid = store_now.init_chunk_upload(body.filename, body.total_bytes, fmt=fmt)
        return {
            "upload_id": cid,
            "capture_id": cid,
            "chunk_size_bytes": chunk_size,
            "offset": 0,
            "unlimited": cfg_now.upload_max_bytes == 0,
        }

    @app.get("/api/v1/captures/uploads/{upload_id}", tags=["Captures"])
    def upload_status(upload_id: str):
        row = _store().pending_upload(upload_id)
        return {
            "upload_id": upload_id,
            "capture_id": upload_id,
            "offset": row["bytes_received"],
            "expected_bytes": row["expected_bytes"],
            "filename": row["filename"],
        }

    @app.put("/api/v1/captures/uploads/{upload_id}/chunk", tags=["Captures"])
    async def put_upload_chunk(upload_id: str, request: Request, offset: Annotated[int, Query(ge=0)] = 0):
        cfg_now, store_now = _cfg(), _store()
        pending = store_now.pending_upload(upload_id)
        buf = bytearray()
        async for part in request.stream():
            buf.extend(part)
            if len(buf) > MAX_SINGLE_CHUNK_BYTES:
                raise HTTPException(413, "chunk_too_large")
        if not buf:
            raise HTTPException(400, "empty_chunk")
        if cfg_now.upload_max_bytes > 0 and offset + len(buf) > cfg_now.upload_max_bytes:
            raise HTTPException(413, "capture_too_large")
        if offset == 0 and len(buf) >= 4:
            head4 = bytes(buf[:4])
            if head4 not in PCAP_MAGIC and not _looks_like_csv_header(bytes(buf[:512])):
                if b"\n" in buf[:512] or len(buf) >= 256:
                    raise HTTPException(400, "invalid_capture_magic")
        received = await run_in_threadpool(store_now.append_upload_chunk, upload_id, offset, bytes(buf))
        return {
            "upload_id": upload_id,
            "offset": received,
            "received_bytes": received,
            "expected_bytes": pending["expected_bytes"],
        }

    @app.post("/api/v1/captures/uploads/{upload_id}/complete", tags=["Captures"])
    async def finish_chunked_upload(upload_id: str):
        store_now = _store()
        row, sha256, fmt = await run_in_threadpool(_finalize_chunked_upload, store_now, upload_id)
        return {
            "capture_id": row["id"],
            "sha256": sha256,
            "size_bytes": row["size"],
            "format": fmt,
            "filename": row["filename"],
            "validation": "header_only_full_validation_in_worker",
        }

    @app.delete("/api/v1/captures/uploads/{upload_id}", status_code=204, tags=["Captures"])
    def abort_chunked_upload(upload_id: str):
        _store().abort_capture(upload_id)
        return JSONResponse(status_code=204, content=None)

    @app.get("/api/v1/captures/local/browse", tags=["Captures"])
    def browse_local_captures():
        roots = _allowed_roots(_cfg())
        files: list[dict[str, object]] = []
        if roots:
            for root in roots:
                try:
                    entries = sorted(root.iterdir(), key=lambda p: p.name.lower())
                except OSError:
                    continue
                for entry in entries:
                    if len(files) >= 200:
                        break
                    if entry.is_file() and entry.suffix.lower() in LOCAL_CAPTURE_EXTENSIONS:
                        try:
                            st = entry.stat()
                        except OSError:
                            continue
                        files.append(
                            {
                                "name": entry.name,
                                "path": str(entry),
                                "size_bytes": st.st_size,
                                "format": entry.suffix.lower().lstrip("."),
                                "modified_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
                            }
                        )
        return {
            "enabled": len(roots) > 0,
            "roots": [str(r) for r in roots],
            "files": files,
        }

    @app.post("/api/v1/captures/local", status_code=201, tags=["Captures"])
    async def register_local_capture(body: LocalCaptureRequest):
        cfg_now = _cfg()
        if body.file_grant_token:
            grant = _consume_local_file_grant(body.file_grant_token)
            try:
                target = Path(str(grant["path"])).resolve(strict=True)
                current = target.stat()
            except OSError as exc:
                raise HTTPException(409, "local_file_changed_after_selection") from exc
            if not target.is_file() or (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
            ) != (grant["device"], grant["inode"], grant["size"], grant["mtime_ns"]):
                raise HTTPException(409, "local_file_changed_after_selection")
        else:
            roots = _allowed_roots(cfg_now)
            target = _resolve_local_file(body.path or "", roots)
        sha256, total, prefix = await run_in_threadpool(_hash_and_peek_file, target)
        if cfg_now.upload_max_bytes > 0 and total > cfg_now.upload_max_bytes:
            raise HTTPException(413, "capture_too_large")
        if body.file_grant_token and (sha256 != grant["sha256"] or total != grant["size"]):
            raise HTTPException(409, "local_file_changed_after_selection")
        fmt = _detect_capture_format(prefix)
        if fmt is None:
            raise HTTPException(400, "invalid_capture_header")
        minimum = 28 if fmt == "pcapng" else (24 if fmt == "pcap" else 12)
        if total < minimum:
            raise HTTPException(400, "invalid_capture_header")
        row = _store().register_local_capture(target, target.name, fmt, total, sha256)
        return {
            "capture_id": row["id"],
            "sha256": sha256,
            "size_bytes": total,
            "format": fmt,
            "filename": row["filename"],
            "source_kind": "local",
            "validation": "zero_copy_local_reference",
        }

    @app.get("/api/v1/cases", tags=["Cases"], response_model=CaseListResponse)
    def list_cases(
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
        search: Annotated[str, Query(max_length=120)] = "",
    ):
        return _store().cases(limit=limit, offset=offset, search=search)

    @app.post("/api/v1/cases", status_code=201, tags=["Cases"], response_model=CaseDetail)
    def create_case(body: CaseCreateRequest):
        return _store().create_case(body.model_dump())

    @app.get("/api/v1/cases/{case_id}", tags=["Cases"], response_model=CaseDetail)
    def get_case(case_id: str):
        return _store().case(case_id)

    @app.patch("/api/v1/cases/{case_id}", tags=["Cases"], response_model=CaseDetail)
    def patch_case(case_id: str, body: CasePatchRequest):
        return _store().update_case(case_id, body.model_dump(exclude_unset=True))

    @app.delete("/api/v1/cases/{case_id}", status_code=204, tags=["Cases"])
    def delete_case(case_id: str):
        _store().delete_case(case_id)
        return Response(status_code=204)

    @app.post("/api/v1/cases/{case_id}/analyses", tags=["Cases"], response_model=CaseDetail)
    def link_case_analysis(case_id: str, body: CaseAnalysisLinkRequest):
        return _store().link_case_analysis(case_id, body.analysis_id)

    @app.delete("/api/v1/cases/{case_id}/analyses/{analysis_id}", status_code=204, tags=["Cases"])
    def unlink_case_analysis(case_id: str, analysis_id: str):
        _store().unlink_case_analysis(case_id, analysis_id)
        return Response(status_code=204)

    @app.post("/api/v1/cases/{case_id}/notes", tags=["Cases"], response_model=CaseDetail)
    def create_case_note(case_id: str, body: CaseNoteCreateRequest):
        return _store().create_case_note(case_id, body.note)

    @app.delete("/api/v1/cases/{case_id}/notes/{note_id}", status_code=204, tags=["Cases"])
    def delete_case_note(case_id: str, note_id: str):
        _store().delete_case_note(case_id, note_id)
        return Response(status_code=204)

    @app.get("/api/v1/cases/{case_id}/iocs", tags=["Cases"])
    def list_case_iocs(case_id: str):
        return {"items": _store().list_case_iocs(case_id)}

    @app.post("/api/v1/cases/{case_id}/iocs", status_code=201, tags=["Cases"])
    def create_case_ioc(case_id: str, body: CaseIOCCreateRequest):
        return _store().add_case_ioc(case_id, body.model_dump())

    @app.delete("/api/v1/cases/{case_id}/iocs/{ioc_id}", status_code=204, tags=["Cases"])
    def delete_case_ioc(case_id: str, ioc_id: str):
        _store().delete_case_ioc(case_id, ioc_id)
        return Response(status_code=204)

    @app.get("/api/v1/iocs/search", tags=["OSINT"])
    def search_iocs(
        query: Annotated[str, Query(max_length=256)] = "",
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ):
        return _store().search_local_iocs(query=query, limit=limit)

    @app.post("/api/v1/analyses", status_code=202, tags=["Analyses"])
    def analyze(body: AnalysisRequest, idempotency_key: Annotated[str | None, Header(max_length=128)] = None):
        cfg_now = _cfg()
        if body.ai_enabled and not cfg_now.ai.enabled:
            raise HTTPException(409, "ai_disabled_by_operator")
        if body.ai_enabled and not cfg_now.ai.model:
            raise HTTPException(409, "ai_model_not_configured")
        return _store().create_job(body, profile_hash(cfg_now), idempotency_key)

    def _require_loopback_workspace_mutation(request: Request, error_code: str) -> None:
        client_host = request.client.host if request.client else None
        if not is_loopback_client(client_host) and not truthy_env(os.environ.get("PCAP_ALLOW_REMOTE_WORKSPACE")):
            raise HTTPException(403, error_code)

    @app.get("/api/v1/analyses", tags=["Analyses"])
    def list_jobs(
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        store_now = _store()
        return {
            "items": store_now.jobs(limit=limit, offset=offset),
            "total": store_now.jobs_count(),
            "limit": limit,
            "offset": offset,
        }

    @app.post("/api/v1/analyses/prune", tags=["Analyses"])
    def prune_jobs_endpoint(
        keep_latest: Annotated[int, Query(ge=0, le=500)] = 20,
        max_age_hours: Annotated[int | None, Query(ge=1, le=8760)] = None,
        body: JobsPruneRequest | None = Body(default=None),
    ):
        eff_keep = body.keep_latest if body is not None else keep_latest
        eff_age = body.max_age_hours if body is not None else max_age_hours
        return _store().prune_jobs(keep_latest=eff_keep, max_age_hours=eff_age)

    @app.get("/api/v1/analyses/{analysis_id}", tags=["Analyses"])
    def job(analysis_id: str):
        return _store().job(analysis_id)

    @app.delete("/api/v1/analyses/{analysis_id}", tags=["Analyses"])
    def delete_job_endpoint(analysis_id: str):
        return _store().delete_job(analysis_id)

    @app.post("/api/v1/analyses/{analysis_id}/cancel", tags=["Analyses"])
    def cancel(analysis_id: str):
        return _store().cancel(analysis_id)

    @app.get("/api/v1/analyses/{analysis_id}/evidence", tags=["Evidence"], response_model=EvidenceBundle)
    def evidence(analysis_id: str):
        row = _store().job(analysis_id, internal=True)
        if not row["evidence"]:
            raise HTTPException(409, "evidence_not_ready")
        return EvidenceBundle.model_validate_json(row["evidence"])

    @app.get("/api/v1/analyses/{analysis_id}/triage.jsonl", tags=["Evidence"])
    def triage_jsonl(analysis_id: str):
        row = _store().job(analysis_id, internal=True)
        if not row["evidence"]:
            raise HTTPException(409, "evidence_not_ready")
        bundle = EvidenceBundle.model_validate_json(row["evidence"])
        payload = bundle_to_triage_jsonl(bundle, _cfg().triage)
        return PlainTextResponse(
            content=payload,
            media_type="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="triage-{analysis_id[:8]}.jsonl"'},
        )

    @app.post("/api/v1/analyses/{analysis_id}/snapshot", status_code=201, tags=["Reports"])
    def create_analysis_snapshot(analysis_id: str):
        return _store().create_snapshot(analysis_id)

    @app.get("/api/v1/analyses/{analysis_id}/snapshot", tags=["Reports"])
    def get_analysis_snapshot(analysis_id: str, snapshot_id: Annotated[str | None, Query(max_length=64)] = None):
        snap = _store().get_or_create_snapshot(analysis_id, snapshot_id=snapshot_id)
        return {k: v for k, v in snap.items() if not k.startswith("_")}

    @app.get("/api/v1/analyses/{analysis_id}/artifacts", tags=["Evidence"])
    def list_analysis_artifacts(analysis_id: str):
        items = _store().list_artifacts(analysis_id)
        return {"analysis_id": analysis_id, "items": items, "total": len(items)}

    @app.get("/api/v1/analyses/{analysis_id}/artifacts/{artifact_id}", tags=["Evidence"])
    def get_analysis_artifact(
        analysis_id: str,
        artifact_id: str,
        download: Annotated[bool, Query()] = False,
    ):
        item = _store().get_artifact(analysis_id, artifact_id)
        if download:
            safe_meta = json.dumps(
                {
                    "artifact": item,
                    "safety_notice": "Raw carved binary bytes are not served directly; verify SHA-256 and YARA rule metadata offline.",
                },
                indent=2,
            )
            return Response(
                content=safe_meta.encode("utf-8"),
                media_type="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="{artifact_id}-metadata.json"',
                },
            )
        return item

    @app.get("/api/v1/analyses/{analysis_id}/geoip", tags=["Evidence"])
    def get_analysis_geoip(analysis_id: str):
        row = _store().job(analysis_id, internal=True)
        if not row["evidence"]:
            raise HTTPException(409, "evidence_not_ready")
        bundle = EvidenceBundle.model_validate_json(row["evidence"])
        if bundle.geoip:
            return bundle.geoip
        return build_world_map_flows(bundle.evidence)

    @app.get("/api/v1/analyses/{analysis_id}/report", tags=["Reports"])
    def report(analysis_id: str):
        store_now = _store()
        row = store_now.job(analysis_id, internal=True)
        if not row["evidence"]:
            raise HTTPException(409, "evidence_not_ready")
        bundle = EvidenceBundle.model_validate_json(row["evidence"])
        meta = store_now.job(analysis_id)
        return {
            "analysis_id": analysis_id,
            "status": row["state"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "resource_mode": meta.get("resource_mode", "auto"),
            "capture_filename": meta.get("capture_filename"),
            "capture_size_bytes": meta.get("capture_size_bytes"),
            "capture_format": meta.get("capture_format"),
            "evidence": bundle.model_dump(mode="json"),
            "ai": json.loads(row["ai_result"]) if row["ai_result"] else {"state": "pending"},
            "osint": json.loads(row["osint_result"]) if row.get("osint_result") else {"state": "not_requested", "results": []},
            "disclaimer": "Detector findings are candidates. AI is advisory; missing findings do not certify safety.",
        }

    @app.get("/api/v1/osint/capabilities", tags=["OSINT"])
    def osint_capabilities():
        return app.state.osint_service.capabilities(enabled=bool(_cfg().osint_enabled))

    @app.get("/api/v1/osint/cache", tags=["OSINT"])
    def list_osint_cache_entries(limit: Annotated[int, Query(ge=1, le=200)] = 100):
        items = _store().list_osint_cache(limit=limit)
        return {"items": items, "total": len(items)}

    @app.post("/api/v1/osint/cache/clear", tags=["OSINT"])
    def clear_osint_cache_entries(
        request: Request,
        provider: Annotated[str | None, Query(max_length=32)] = None,
    ):
        _require_loopback_workspace_mutation(request, "osint_cache_mutation_loopback_only")
        deleted = _store().clear_osint_cache(provider=provider)
        return {"deleted": deleted, "deleted_count": deleted, "provider": provider}

    @app.delete("/api/v1/osint/cache", tags=["OSINT"])
    def delete_all_osint_cache_entries(
        request: Request,
        provider: Annotated[str | None, Query(max_length=32)] = None,
    ):
        _require_loopback_workspace_mutation(request, "osint_cache_mutation_loopback_only")
        deleted = _store().clear_osint_cache(provider=provider)
        return {"deleted": deleted, "deleted_count": deleted, "provider": provider}

    @app.delete("/api/v1/osint/cache/{cache_id}", status_code=204, tags=["OSINT"])
    def delete_osint_cache_entry(cache_id: str, request: Request):
        _require_loopback_workspace_mutation(request, "osint_cache_mutation_loopback_only")
        _store().delete_osint_cache_entry(cache_id)
        return Response(status_code=204)

    @app.post("/api/v1/osint/keys/rotate", tags=["OSINT"])
    def rotate_osint_key(body: OSINTKeyRotateRequest, request: Request):
        _require_loopback_workspace_mutation(request, "osint_key_rotation_loopback_only")
        try:
            result = app.state.osint_service.rotate_key(body.provider, body.api_key)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        cleared = _store().clear_osint_cache(provider=body.provider) if body.invalidate_cache else 0
        return {
            **result,
            "cache_invalidated": bool(body.invalidate_cache),
            "deleted_cache_entries": cleared,
        }

    @app.get("/api/v1/analyses/{analysis_id}/osint/candidates", tags=["OSINT"])
    def osint_candidates(analysis_id: str):
        store_now = _store()
        row = store_now.job(analysis_id, internal=True)
        if not row["evidence"]:
            raise HTTPException(409, "evidence_not_ready")
        pending_operation = store_now.unresolved_osint_operation(analysis_id)
        bundle = EvidenceBundle.model_validate_json(row["evidence"])
        if not bundle.evidence:
            return {
                "analysis_id": analysis_id,
                "candidates": [],
                "candidate_count": 0,
                "truncated": False,
                "max_iocs_per_operation": MAX_IOCS_PER_OPERATION,
                "lookup_is_external": True,
                "consent_required_for_lookup": True,
                "pending_operation": pending_operation,
            }
        candidates, truncated = extract_ioc_candidates(
            bundle, [item.evidence_id for item in bundle.evidence]
        )
        return {
            "analysis_id": analysis_id,
            "candidates": [candidate.public_dict() for candidate in candidates],
            "candidate_count": len(candidates),
            "truncated": truncated,
            "max_iocs_per_operation": MAX_IOCS_PER_OPERATION,
            "lookup_is_external": True,
            "consent_required_for_lookup": True,
            "pending_operation": pending_operation,
        }

    @app.post("/api/v1/analyses/{analysis_id}/osint", tags=["OSINT"])
    async def osint_lookup(analysis_id: str, body: OSINTLookupRequest):
        store_now = _store()
        row = store_now.job(analysis_id, internal=True)
        if not row["evidence"]:
            raise HTTPException(409, "evidence_not_ready")
        if not body.consent:
            store_now.record_osint_audit(
                analysis_id,
                requested_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                providers=list(body.providers),
                indicator_count=0,
                outcome="consent_denied",
                consent=False,
            )
            raise HTTPException(428, "osint_consent_required")
        fingerprint_payload = json.dumps(
            {"candidate_ids": sorted(body.candidate_ids), "providers": sorted(body.providers)},
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        request_fingerprint = hmac.new(
            _cfg().api_token.get_secret_value().encode("utf-8"),
            b"PCAPSCANNER-OSINT-OP-v1\0" + analysis_id.encode("ascii") + b"\0" + fingerprint_payload,
            hashlib.sha256,
        ).hexdigest()
        attempted = store_now.osint_audit_operation(analysis_id, body.operation_id)
        if attempted is not None:
            if not hmac.compare_digest(attempted.get("request_fingerprint") or "", request_fingerprint):
                raise HTTPException(409, "osint_operation_id_conflict")
            previous = json.loads(row["osint_result"]) if row.get("osint_result") else None
            if isinstance(previous, dict) and previous.get("operation_id") == body.operation_id:
                return previous
            raise HTTPException(409, "osint_operation_already_attempted")
        previous = json.loads(row["osint_result"]) if row.get("osint_result") else None
        if isinstance(previous, dict) and previous.get("operation_id") == body.operation_id:
            raise HTTPException(409, "osint_operation_state_inconsistent")
        bundle = EvidenceBundle.model_validate_json(row["evidence"])
        all_candidates, _ = extract_ioc_candidates(
            bundle, [item.evidence_id for item in bundle.evidence]
        )
        by_id = {candidate.candidate_id: candidate for candidate in all_candidates}
        if any(candidate_id not in by_id for candidate_id in body.candidate_ids):
            raise HTTPException(422, "unknown_osint_candidate")
        selected = [by_id[candidate_id] for candidate_id in body.candidate_ids]
        try:
            with store_now.osint_operation_lock(analysis_id):
                # Re-read after acquiring the process-shared lock to prevent duplicate API-credit use.
                current = store_now.job(analysis_id, internal=True)
                attempted = store_now.osint_audit_operation(analysis_id, body.operation_id)
                if attempted is not None:
                    if not hmac.compare_digest(attempted.get("request_fingerprint") or "", request_fingerprint):
                        raise HTTPException(409, "osint_operation_id_conflict")
                    prior = json.loads(current["osint_result"]) if current.get("osint_result") else None
                    if isinstance(prior, dict) and prior.get("operation_id") == body.operation_id:
                        return prior
                    raise HTTPException(409, "osint_operation_already_attempted")
                unresolved = store_now.unresolved_osint_operation(analysis_id)
                if unresolved is not None:
                    if not body.accept_uncertain_retry_risk:
                        raise HTTPException(409, "osint_previous_operation_unresolved")
                    store_now.resolve_uncertain_osint_operation(analysis_id, unresolved["operation_id"])
                requested_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                # Persist consent and operation metadata before any external request.
                # If the process dies after a provider call but before saving its result,
                # a retry with this ID must not silently spend credits twice.
                store_now.record_osint_audit(
                    analysis_id,
                    requested_at=requested_at,
                    providers=list(body.providers),
                    indicator_count=len(selected),
                    outcome="started",
                    consent=True,
                    operation_id=body.operation_id,
                    request_fingerprint=request_fingerprint,
                )
                result = await app.state.osint_service.enrich(
                    selected,
                    body.providers,
                    consent=True,
                    enabled=bool(_cfg().osint_enabled),
                )
                result["operation_id"] = body.operation_id
                for item in result.get("results", []):
                    if isinstance(item, dict) and item.get("state") in {"completed", "partial", "not_found"}:
                        cand_obj = by_id.get(str(item.get("candidate_id")))
                        if cand_obj is not None:
                            store_now.put_osint_cache(
                                str(item.get("provider")),
                                cand_obj.indicator_type,
                                cand_obj.indicator,
                                str(item.get("state")),
                                dict(item.get("summary") or {}),
                            )
                store_now.save_osint_result(
                    analysis_id,
                    json.dumps(result, separators=(",", ":"), ensure_ascii=True),
                )
                uncertain_states = {
                    "provider_timeout", "operation_timeout", "provider_error",
                    "invalid_provider_response", "response_too_large", "redirect_blocked",
                }
                has_uncertain_provider_attempt = any(
                    item.get("state") in uncertain_states
                    for item in result.get("results", [])
                    if isinstance(item, dict)
                )
                store_now.finish_osint_audit(
                    analysis_id,
                    body.operation_id,
                    "uncertain" if has_uncertain_provider_attempt else str(result.get("state", "unknown")),
                )
                return result
        except ValueError as exc:
            code = str(exc)
            if code not in {
                "ioc_count_limit_exceeded", "provider_selection_invalid", "unsupported_provider",
                "lookup_count_limit_exceeded", "invalid_ioc_candidate", "duplicate_ioc_candidate",
            }:
                code = "invalid_osint_request"
            raise HTTPException(422, code) from exc

    @app.post("/api/v1/analyses/{analysis_id}/summary", tags=["AI"])
    async def generate_analysis_summary(analysis_id: str):
        if not re.fullmatch(r"[a-f0-9]{32}", analysis_id):
            raise HTTPException(404, "analysis_not_found")
        row = _store().job(analysis_id, internal=True)
        if not row["evidence"]:
            raise HTTPException(409, "evidence_not_ready")
        bundle = EvidenceBundle.model_validate_json(row["evidence"])
        cfg_now = _cfg()
        if not cfg_now.ai.enabled:
            raise HTTPException(409, "ai_disabled_by_operator")
        if not cfg_now.ai.model and str(cfg_now.ai.provider) != "manus":
            raise HTTPException(409, "ai_model_not_configured")
        result = await generate_summary(bundle, cfg_now)
        _store().save_ai_result(analysis_id, result.model_dump_json())
        return result.model_dump(mode="json")

    @app.post("/api/v1/analyses/{analysis_id}/chat", tags=["AI"])
    async def grounded_chat(analysis_id: str, body: GroundedChatRequest):
        row = _store().job(analysis_id, internal=True)
        if not row["evidence"]:
            raise HTTPException(409, "evidence_not_ready")
        bundle = EvidenceBundle.model_validate_json(row["evidence"])
        if not body.consent:
            result = await answer_question(bundle, body.question, consent=False)
        else:
            cfg_now = _cfg()
            if not cfg_now.ai.enabled:
                raise HTTPException(409, "ai_disabled_by_operator")
            if not cfg_now.ai.model:
                raise HTTPException(409, "ai_model_not_configured")
            if cfg_now.ai.context_window_tokens <= 513:
                raise HTTPException(409, "ai_context_window_too_small")

            async def provider_call(prompt: str) -> str:
                return await generate_chat_completion(prompt, cfg_now)

            max_output_tokens = min(1_200, cfg_now.ai.max_output_tokens, cfg_now.ai.context_window_tokens - 513)
            limits = ChatLimits(
                max_question_bytes=min(2_000, cfg_now.ai.input_max_bytes),
                max_context_bytes=min(24_000, cfg_now.ai.input_max_bytes),
                max_prompt_bytes=min(32_000, cfg_now.ai.input_max_bytes),
                max_output_bytes=min(8_000, max_output_tokens * 4),
                context_window_tokens=cfg_now.ai.context_window_tokens,
                max_output_tokens=max_output_tokens,
                timeout_seconds=min(20.0, cfg_now.ai.timeout_seconds),
                max_claims=20,
            )
            async with app.state.chat_semaphore:
                result = await answer_question(
                    bundle,
                    body.question,
                    consent=True,
                    provider=provider_call,
                    limits=limits,
                )
        return {
            "state": result.state,
            "claims": [claim.model_dump(mode="json") for claim in result.claims],
            "prompt_sha256": result.prompt_sha256,
            "error_code": result.error_code,
            "usage": result.usage,
            "transcript_persisted": False,
        }

    def _resolve_snapshot_and_bundle(
        analysis_id: str, snapshot_id: str | None = None
    ) -> tuple[dict, EvidenceBundle]:
        if not re.fullmatch(r"[a-f0-9]{32}", analysis_id):
            raise HTTPException(404, "analysis_not_found")
        snap = _store().get_or_create_snapshot(analysis_id, snapshot_id=snapshot_id)
        bundle = EvidenceBundle.model_validate_json(snap["_bundle_json"])
        manifest = {k: v for k, v in snap.items() if not k.startswith("_")}
        return manifest, bundle

    @app.get("/api/v1/analyses/{analysis_id}/export.stix.json", tags=["Reports"])
    def export_stix(
        analysis_id: str,
        snapshot_id: Annotated[str | None, Query(max_length=64)] = None,
        redact: Annotated[bool, Query()] = False,
    ):
        manifest, bundle = _resolve_snapshot_and_bundle(analysis_id, snapshot_id=snapshot_id)
        payload = export_stix_bundle(bundle, redact=redact)
        payload["x_pcapscanner_snapshot_id"] = manifest["snapshot_id"]
        return JSONResponse(
            content=payload,
            media_type="application/stix+json",
            headers={
                "Content-Disposition": f'attachment; filename="pcap-stix-{analysis_id[:8]}.json"',
                "X-Snapshot-Id": str(manifest["snapshot_id"]),
            },
        )

    @app.get("/api/v1/analyses/{analysis_id}/export.csv", tags=["Reports"])
    def export_csv(
        analysis_id: str,
        snapshot_id: Annotated[str | None, Query(max_length=64)] = None,
        redact: Annotated[bool, Query()] = False,
    ):
        manifest, bundle = _resolve_snapshot_and_bundle(analysis_id, snapshot_id=snapshot_id)
        csv_text = export_findings_and_evidence_csv(bundle, snapshot_id=manifest["snapshot_id"], redact=redact)
        return Response(
            content=csv_text.encode("utf-8"),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="pcap-findings-{analysis_id[:8]}.csv"',
                "X-Snapshot-Id": str(manifest["snapshot_id"]),
            },
        )

    @app.get("/api/v1/analyses/{analysis_id}/export.cef", tags=["Reports"])
    def export_cef(
        analysis_id: str,
        snapshot_id: Annotated[str | None, Query(max_length=64)] = None,
        redact: Annotated[bool, Query()] = False,
    ):
        manifest, bundle = _resolve_snapshot_and_bundle(analysis_id, snapshot_id=snapshot_id)
        cef_text = export_findings_cef(bundle, snapshot_id=manifest["snapshot_id"], redact=redact)
        return PlainTextResponse(
            content=cef_text,
            media_type="text/plain; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="pcap-siem-{analysis_id[:8]}.cef"',
                "X-Snapshot-Id": str(manifest["snapshot_id"]),
            },
        )

    @app.get("/api/v1/analyses/{analysis_id}/export.navigator.json", tags=["Reports"])
    def export_navigator(
        analysis_id: str,
        snapshot_id: Annotated[str | None, Query(max_length=64)] = None,
        redact: Annotated[bool, Query()] = False,
    ):
        manifest, bundle = _resolve_snapshot_and_bundle(analysis_id, snapshot_id=snapshot_id)
        layer = export_attack_navigator_layer(
            bundle,
            snapshot_id=manifest["snapshot_id"],
            analysis_id=analysis_id,
            redact=redact,
        )
        return JSONResponse(
            content=layer,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="pcap-attack-navigator-{analysis_id[:8]}.json"',
                "X-Snapshot-Id": str(manifest["snapshot_id"]),
            },
        )

    @app.get("/api/v1/analyses/{analysis_id}/export.pdf", tags=["Reports"])
    def export_pdf(
        analysis_id: str,
        snapshot_id: Annotated[str | None, Query(max_length=64)] = None,
        redact: Annotated[bool, Query()] = False,
    ):
        manifest, bundle = _resolve_snapshot_and_bundle(analysis_id, snapshot_id=snapshot_id)
        store_now = _store()
        job_meta = store_now.job(analysis_id)
        internal_row = store_now.job(analysis_id, internal=True)
        ai_result = json.loads(internal_row["ai_result"]) if internal_row.get("ai_result") else None
        pdf_bytes = export_snapshot_pdf(
            bundle,
            snapshot=manifest,
            job=job_meta,
            ai_result=ai_result,
            redact=redact,
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="pcap-forensic-report-{analysis_id[:8]}.pdf"',
                "X-Snapshot-Id": str(manifest["snapshot_id"]),
            },
        )

    @app.post("/api/v1/auth/keys", status_code=201, tags=["Auth"])
    def create_scoped_key(body: ScopedKeyCreateRequest):
        return _store().create_scoped_api_key(
            label=body.name,
            scopes=list(body.scopes),
            expires_in_days=body.expires_in_days,
            rate_limit_per_minute=body.rate_limit_rpm,
            quota_limit=body.quota_limit,
        )

    @app.get("/api/v1/auth/keys", tags=["Auth"])
    def list_scoped_keys():
        items = _store().list_scoped_api_keys()
        return {"items": items, "total": len(items)}

    @app.delete("/api/v1/auth/keys/{key_id}", tags=["Auth"])
    def revoke_scoped_key(key_id: str):
        return _store().revoke_scoped_api_key(key_id)

    @app.get("/api/v1/auth/keys/audit", tags=["Auth"])
    def list_scoped_key_audit(limit: Annotated[int, Query(ge=1, le=500)] = 100):
        items = _store().list_api_key_audit(limit=limit)
        return {"items": items, "total": len(items)}

    def _ai_config_payload(cfg_now: AppSettings) -> dict[str, object]:
        api_key_env = cfg_now.ai.api_key_env
        rt_status = runtime_api_key_status()
        cur_provider = cfg_now.ai.provider.value if hasattr(cfg_now.ai.provider, "value") else str(cfg_now.ai.provider)
        cur_slot = credential_slot_for(cfg_now.ai)
        cur_rt = rt_status.get(cur_slot, {"configured": False, "key_fingerprint": None})
        manus_env_set = bool(os.environ.get("MANUS_API_KEY"))
        manus_ready = bool(rt_status.get("manus", {}).get("configured") or os.environ.get("MANUS_API_KEY"))
        return {
            "configuration": cfg_now.ai.model_dump(mode="json"),
            "triage": cfg_now.triage.model_dump(mode="json"),
            "policy_hash": profile_hash(cfg_now),
            "editable": "loopback_nonsecret_runtime_and_env",
            "api_key_env_set": bool(api_key_env and os.environ.get(api_key_env)),
            "manus_env_set": manus_env_set,
            "manus_ready": manus_ready,
            # Catalog card that best describes the active route (explicit preset,
            # else inferred from provider + base_url origin for legacy configs).
            "active_preset": cfg_now.ai.preset or infer_preset(cur_provider, cfg_now.ai.base_url),
            "credential_slot": cur_slot,
            "runtime_key_set": bool(cur_rt["configured"]),
            "runtime_key_fingerprint": cur_rt["key_fingerprint"],
            "runtime_keys": {k: bool(v["configured"]) for k, v in rt_status.items()},
            "runtime_key_fingerprints": {k: v["key_fingerprint"] for k, v in rt_status.items()},
        }

    def _drop_mismatched_preset(data: dict[str, object], fields_set: set[str]) -> None:
        """Keep a catalog preset (and therefore its RAM key slot) only while it still describes the route.

        A preset is dropped when the wire protocol changes, or when a vendor preset with a fixed
        endpoint is re-pointed at another origin, so a vendor's key is never replayed elsewhere.
        """
        if "preset" in fields_set or not data.get("preset"):
            return
        from .llm import get_preset

        meta = get_preset(str(data.get("preset")))
        provider_value = data.get("provider")
        provider_text = getattr(provider_value, "value", provider_value)
        if meta is None or meta["protocol"] != str(provider_text):
            data["preset"] = None
            return
        base_url = data.get("base_url")
        if (
            not meta.get("base_url_editable")
            and meta.get("base_url")
            and isinstance(base_url, str)
            and base_url.strip()
        ):
            from .config import _origin

            try:
                if _origin(base_url.strip().rstrip("/")) != _origin(str(meta["base_url"])):
                    data["preset"] = None
            except ValueError:
                data["preset"] = None

    @app.get("/api/v1/ai/config", tags=["AI"])
    def ai_config():
        # AIConfig stores only secret ENV references, never values.
        return _ai_config_payload(_cfg())

    @app.get("/api/v1/ai/providers", tags=["AI"])
    def ai_providers():
        """Non-secret provider catalog used by the Model Settings UI (LiteLLM-style registry)."""
        rt_status = runtime_api_key_status()
        items = []
        for preset in list_presets():
            slot = rt_status.get(preset["id"], {"configured": False, "key_fingerprint": None})
            env_name = preset.get("api_key_env")
            items.append(
                {
                    **preset,
                    "runtime_key_set": bool(slot["configured"]),
                    "runtime_key_fingerprint": slot["key_fingerprint"],
                    "env_key_set": bool(env_name and os.environ.get(env_name))
                    or (preset["id"] == "manus" and bool(os.environ.get("MANUS_API_KEY"))),
                }
            )
        return {"schema_version": "1.0", "items": items}

    @app.put("/api/v1/ai/credentials", tags=["AI"])
    def set_ai_credentials(body: AICredentialUpdateRequest, request: Request):
        client_host = request.client.host if request.client else None
        if not is_loopback_client(client_host) and not truthy_env(os.environ.get("PCAP_ALLOW_REMOTE_WORKSPACE")):
            raise HTTPException(403, "ai_credentials_loopback_only")
        try:
            meta = set_runtime_api_key(body.provider, body.api_key)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return {**meta, **_ai_config_payload(_cfg())}

    @app.delete("/api/v1/ai/credentials", tags=["AI"])
    def delete_ai_credentials(
        request: Request,
        provider: Annotated[str, Query(min_length=1, max_length=48, pattern=r"^[a-z0-9][a-z0-9_-]{0,47}$")],
    ):
        client_host = request.client.host if request.client else None
        if not is_loopback_client(client_host) and not truthy_env(os.environ.get("PCAP_ALLOW_REMOTE_WORKSPACE")):
            raise HTTPException(403, "ai_credentials_loopback_only")
        if provider not in credential_slot_names():
            raise HTTPException(422, "unsupported_ai_provider")
        cleared = clear_runtime_api_key(provider)
        return {"provider": provider, "cleared": cleared, **_ai_config_payload(_cfg())}

    @app.put("/api/v1/ai/config", tags=["AI"])
    def update_ai_config(body: AIConfigUpdateRequest, request: Request):
        client_host = request.client.host if request.client else None
        if not is_loopback_client(client_host) and not truthy_env(os.environ.get("PCAP_ALLOW_REMOTE_WORKSPACE")):
            raise HTTPException(403, "ai_config_mutation_loopback_only")

        cfg_now = _cfg()
        next_ai_data = cfg_now.ai.model_dump(mode="python")
        for field_name in body.model_fields_set:
            val = getattr(body, field_name)
            if field_name in {"base_url", "model", "api_key_env", "preset"} and isinstance(val, str):
                val = val.strip() or None
            next_ai_data[field_name] = val
        # Switching wire protocol without naming a new preset drops a stale card.
        _drop_mismatched_preset(next_ai_data, body.model_fields_set)
        if (
            next_ai_data.get("enabled")
            and str(next_ai_data.get("provider")) == "openai_compatible"
            and next_ai_data.get("base_url") is None
            and "base_url" not in body.model_fields_set
            and "data_boundary" not in body.model_fields_set
            and "allowed_origins" not in body.model_fields_set
            and not next_ai_data.get("allowed_origins")
        ):
            next_ai_data["data_boundary"] = "local"
            next_ai_data["allowed_origins"] = ["http://127.0.0.1:11434"]
        if str(next_ai_data.get("provider")) == "manus":
            if next_ai_data.get("base_url") is None and not next_ai_data.get("allowed_origins"):
                next_ai_data["base_url"] = "https://api.manus.ai"
                next_ai_data["data_boundary"] = "remote"
                next_ai_data["allowed_origins"] = ["https://api.manus.ai"]
            if not next_ai_data.get("model"):
                next_ai_data["model"] = "standard"
            if "timeout_seconds" not in body.model_fields_set and int(next_ai_data.get("timeout_seconds") or 30) < 90:
                next_ai_data["timeout_seconds"] = 120
        try:
            updated_ai = AIConfig.model_validate(next_ai_data)
        except ValidationError:
            raise HTTPException(422, "invalid_ai_configuration") from None

        updated_cfg = cfg_now.model_copy(update={"ai": updated_ai})
        app.state.settings = updated_cfg
        ws_path = resolve_workspace_config_path()
        if ws_path is not None:
            update_workspace_config(
                path=ws_path,
                ai=updated_ai.model_dump(mode="json"),
                prefer_workspace=True,
            )
        return _ai_config_payload(updated_cfg)

    @app.get("/api/v1/ai/config/schema", tags=["AI"])
    def ai_schema():
        result = _cfg().ai.__class__.model_json_schema()
        result["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        return result

    @app.get("/api/v1/ai/models", tags=["AI"])
    async def ai_models():
        from .llm import list_models

        cfg_now = _cfg()
        try:
            discovery_cfg = cfg_now.model_copy(
                update={"ai": cfg_now.ai.model_copy(update={"timeout_seconds": min(cfg_now.ai.timeout_seconds, 5)})}
            )
            items = await list_models(discovery_cfg)
            return {
                "state": "disabled" if not cfg_now.ai.enabled else ("completed" if items else "unavailable_or_empty"),
                "items": items,
                "warning": None if items else "No catalog returned; this does not prove the provider has no models",
            }
        except Exception:
            raise HTTPException(502, "ai_model_discovery_unavailable")

    @app.post("/api/v1/ai/models/probe", tags=["AI"])
    async def ai_models_probe(body: AIModelProbeRequest, request: Request):
        client_host = request.client.host if request.client else None
        if not is_loopback_client(client_host) and not truthy_env(os.environ.get("PCAP_ALLOW_REMOTE_WORKSPACE")):
            raise HTTPException(403, "ai_probe_loopback_only")

        cfg_now = _cfg()
        probe_data = cfg_now.ai.model_dump(mode="python")
        for field_name in body.model_fields_set:
            val = getattr(body, field_name)
            if field_name in {"base_url", "api_key_env", "preset"} and isinstance(val, str):
                val = val.strip() or None
            probe_data[field_name] = val
        _drop_mismatched_preset(probe_data, body.model_fields_set)
        if str(probe_data.get("provider")) == "manus":
            if probe_data.get("base_url") is None and not probe_data.get("allowed_origins"):
                probe_data["base_url"] = "https://api.manus.ai"
                probe_data["data_boundary"] = "remote"
                probe_data["allowed_origins"] = ["https://api.manus.ai"]
        probe_data["enabled"] = False
        try:
            probe_cfg = AIConfig.model_validate(probe_data)
        except ValidationError:
            raise HTTPException(422, "invalid_ai_configuration") from None
        try:
            items, warning = await probe_models(probe_cfg)
            return {
                "state": "completed" if items else "unavailable_or_empty",
                "items": items,
                "warning": warning,
            }
        except Exception:
            raise HTTPException(502, "ai_model_discovery_unavailable")

    ui_dist_dir = (REPO_ROOT / "dist").resolve()
    ui_index_file = ui_dist_dir / "index.html"
    if truthy_env(os.environ.get("PCAP_SERVE_UI")) and ui_index_file.is_file():

        @app.get("/", include_in_schema=False)
        def serve_ui_root():
            return FileResponse(ui_index_file)

        @app.get("/{full_path:path}", include_in_schema=False)
        def serve_ui_spa(full_path: str):
            clean = full_path.lstrip("/")
            if clean == "api" or clean.startswith("api/"):
                raise HTTPException(404, "not_found")
            if clean:
                candidate = (ui_dist_dir / clean).resolve()
                if not candidate.is_relative_to(ui_dist_dir):
                    raise HTTPException(404, "not_found")
                if candidate.is_file():
                    return FileResponse(candidate)
                if clean.startswith("assets/"):
                    raise HTTPException(404, "asset_not_found")
            return FileResponse(ui_index_file)

    original_openapi = app.openapi

    def secured_openapi():
        schema = original_openapi()
        schema.setdefault("components", {}).setdefault("securitySchemes", {})["OperatorBearer"] = {
            "type": "http",
            "scheme": "bearer",
        }
        schema["components"].setdefault("schemas", {})["ProblemDetails"] = ProblemDetails.model_json_schema()
        for path, methods in schema["paths"].items():
            if path.startswith("/api/"):
                for method, operation in methods.items():
                    if method in ("get", "post", "put", "delete", "patch"):
                        operation["security"] = [{"OperatorBearer": []}]
                        for status in (400, 401, 403, 404, 409, 413, 415, 422, 429, 502, 503, 507):
                            operation["responses"][str(status)] = {
                                "description": "Stable Problem Details error code; no sensitive input echo",
                                "content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/ProblemDetails"}}},
                            }
        return schema

    app.openapi = secured_openapi
    return app
LOCAL_FILE_GRANT_TTL_SECONDS = 300
LOCAL_FILE_GRANT_MAX_ENTRIES = 128
