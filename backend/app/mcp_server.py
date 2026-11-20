"""Read-only stdio MCP server with per-call scoped API credential reauthorization and signed cursors."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
from typing import Any

_DEFAULT_CURSOR_SECRET = secrets.token_hex(32)


READ_ONLY_MCP_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "list_analyses",
        "description": "List recent analysis jobs with bounded summary metadata.",
        "required_scope": ("read:status", "read:analyses"),
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
            "additionalProperties": False,
        },
    },
    {
        "name": "get_analysis_status",
        "description": "Read bounded status and coverage for an analysis job.",
        "required_scope": ("read:status", "read:analyses"),
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {"analysis_id": {"type": "string"}},
            "required": ["analysis_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_snapshot_manifest",
        "description": "Read the immutable versioned snapshot manifest for an analysis.",
        "required_scope": ("read:manifest", "read:analyses", "export:reports"),
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "analysis_id": {"type": "string"},
                "snapshot_id": {"type": "string"},
            },
            "required": ["analysis_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_evidence",
        "description": "List bounded evidence items from an immutable snapshot using signed cursor pagination.",
        "required_scope": ("read:evidence", "read:analyses"),
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "analysis_id": {"type": "string"},
                "snapshot_id": {"type": "string"},
                "kind": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "cursor": {"type": "string"},
            },
            "required": ["analysis_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_report",
        "description": "Read the structured forensic & AI report for an analysis.",
        "required_scope": ("read:report", "read:analyses"),
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {
                "analysis_id": {"type": "string"},
                "snapshot_id": {"type": "string"},
            },
            "required": ["analysis_id"],
            "additionalProperties": False,
        },
    },
)


def encode_signed_cursor(
    *,
    analysis_id: str,
    snapshot_id: str,
    offset: int,
    kind: str | None = None,
    secret: str | None = None,
) -> str:
    effective_secret = secret or _DEFAULT_CURSOR_SECRET
    payload = {
        "a": str(analysis_id),
        "s": str(snapshot_id),
        "o": int(max(0, offset)),
        "k": str(kind or ""),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(effective_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()[:24]
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{token}.{sig}"


def decode_signed_cursor(
    cursor: str,
    *,
    expected_analysis_id: str,
    expected_snapshot_id: str,
    expected_kind: str | None = None,
    secret: str | None = None,
) -> int:
    effective_secret = secret or _DEFAULT_CURSOR_SECRET
    if not cursor or "." not in cursor:
        raise ValueError("invalid_cursor")
    token, sig = cursor.rsplit(".", 1)
    pad = "=" * ((4 - len(token) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode((token + pad).encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("invalid_cursor") from exc
    expected_sig = hmac.new(effective_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()[:24]
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("invalid_cursor_signature")
    if str(payload.get("a") or "") != str(expected_analysis_id):
        raise ValueError("cursor_analysis_mismatch")
    if str(payload.get("s") or "") != str(expected_snapshot_id):
        raise ValueError("cursor_snapshot_mismatch")
    if str(payload.get("k") or "") != str(expected_kind or ""):
        raise ValueError("cursor_filter_mismatch")
    offset = int(payload.get("o", -1))
    if offset < 0:
        raise ValueError("invalid_cursor_offset")
    return offset


class ReadOnlyMCPServer:
    """Strictly read-only MCP server bound to Store with per-call token reauthorization."""

    def __init__(
        self,
        store: Any,
        *,
        operator_token: str | None = None,
        default_token: str | None = None,
        cursor_secret: str | None = None,
    ) -> None:
        self.store = store
        self.operator_token = operator_token or os.environ.get("PCAP_API_TOKEN") or ""
        self.default_token = default_token or ""
        self.cursor_secret = cursor_secret or self.operator_token or _DEFAULT_CURSOR_SECRET

    def list_tools(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for t in READ_ONLY_MCP_TOOLS:
            item = dict(t)
            req = item.get("required_scope")
            if isinstance(req, (tuple, list)):
                item["required_scope"] = req[0] if req else "read:analyses"
            out.append(item)
        return out

    def _authorize_call(self, token: str | None, required_scope: str | tuple[str, ...], tool_name: str) -> None:
        supplied = (token or self.default_token or "").strip()
        if not supplied:
            raise PermissionError("unauthorized")
        if self.operator_token and hmac.compare_digest(supplied, self.operator_token):
            return
        try:
            res = self.store.verify_scoped_api_key(
                supplied,
                required_scope=required_scope,
                endpoint=f"mcp:{tool_name}",
            )
            if isinstance(res, dict) and "ok" in res and not res.get("ok"):
                raise PermissionError(str(res.get("error") or "unauthorized"))
        except Exception as exc:
            code = getattr(exc, "code", None) or str(exc) or "unauthorized"
            raise PermissionError(str(code)) from exc

    def _resolve_snapshot(self, analysis_id: str, snapshot_id: str | None) -> dict[str, Any]:
        try:
            snap = self.store.get_or_create_snapshot(analysis_id, snapshot_id=snapshot_id)
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code in {"job_not_found", "snapshot_not_found", "evidence_not_ready"}:
                raise LookupError(code) from exc
            raise
        if snap is None:
            raise LookupError("snapshot_not_found")
        return snap

    @staticmethod
    def _extract_bundle_dict(snap: dict[str, Any]) -> dict[str, Any]:
        raw = snap.get("bundle")
        if isinstance(raw, dict):
            return raw
        raw_json = snap.get("_bundle_json")
        if isinstance(raw_json, str) and raw_json:
            return json.loads(raw_json)
        return {}

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> dict[str, Any]:
        args = dict(arguments or {})
        tool_spec = next((t for t in READ_ONLY_MCP_TOOLS if t["name"] == tool_name), None)
        if tool_spec is None:
            raise KeyError(f"unsupported_mcp_tool:{tool_name}")

        self._authorize_call(token, tool_spec["required_scope"], tool_name)

        if tool_name == "list_analyses":
            limit = max(1, min(int(args.get("limit") or 20), 100))
            items = self.store.jobs(limit)
            return {"items": items, "total": len(items)}

        analysis_id = str(args.get("analysis_id") or "").strip()
        if not analysis_id:
            raise ValueError("missing_analysis_id")

        if tool_name == "get_analysis_status":
            try:
                status = self.store.job(analysis_id)
            except Exception as exc:
                if getattr(exc, "code", None) == "job_not_found":
                    raise LookupError("analysis_not_found") from exc
                raise
            return dict(status)

        if tool_name == "get_snapshot_manifest":
            snap = self._resolve_snapshot(analysis_id, args.get("snapshot_id"))
            return {k: v for k, v in snap.items() if k != "bundle" and not k.startswith("_")}

        if tool_name == "list_evidence":
            snap = self._resolve_snapshot(analysis_id, args.get("snapshot_id"))
            snap_id = str(snap["snapshot_id"])
            kind = str(args.get("kind") or "").strip() or None
            limit = max(1, min(int(args.get("limit") or 50), 100))
            cursor_str = str(args.get("cursor") or "").strip()
            offset = (
                decode_signed_cursor(
                    cursor_str,
                    expected_analysis_id=analysis_id,
                    expected_snapshot_id=snap_id,
                    expected_kind=kind,
                    secret=self.cursor_secret,
                )
                if cursor_str
                else 0
            )
            bundle_dict = self._extract_bundle_dict(snap)
            all_ev = list(bundle_dict.get("evidence") or [])
            if kind:
                all_ev = [e for e in all_ev if e.get("kind") == kind]
            page = all_ev[offset : offset + limit]
            next_offset = offset + len(page)
            next_cursor = (
                encode_signed_cursor(
                    analysis_id=analysis_id,
                    snapshot_id=snap_id,
                    offset=next_offset,
                    kind=kind,
                    secret=self.cursor_secret,
                )
                if next_offset < len(all_ev)
                else None
            )
            return {
                "analysis_id": analysis_id,
                "snapshot_id": snap_id,
                "capture_sha256": snap.get("capture_sha256"),
                "total": len(all_ev),
                "limit": limit,
                "items": page,
                "next_cursor": next_cursor,
            }

        if tool_name == "get_report":
            try:
                row = self.store.job(analysis_id, internal=True)
            except Exception as exc:
                if getattr(exc, "code", None) == "job_not_found":
                    raise LookupError("analysis_not_found") from exc
                raise
            if not row.get("evidence"):
                raise LookupError("evidence_not_ready")
            meta = self.store.job(analysis_id)
            snap = self._resolve_snapshot(analysis_id, args.get("snapshot_id"))
            payload = {
                "analysis_id": analysis_id,
                "snapshot_id": snap["snapshot_id"],
                "status": row["state"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "resource_mode": meta.get("resource_mode", "auto"),
                "capture_filename": meta.get("capture_filename"),
                "capture_size_bytes": meta.get("capture_size_bytes"),
                "capture_format": meta.get("capture_format"),
                "evidence": json.loads(row["evidence"]),
                "ai": json.loads(row["ai_result"]) if row.get("ai_result") else {"state": "pending"},
                "osint": (
                    json.loads(row["osint_result"])
                    if row.get("osint_result")
                    else {"state": "not_requested", "results": []}
                ),
                "disclaimer": "Detector findings are candidates. AI is advisory; missing findings do not certify safety.",
            }
            return payload

        raise KeyError(f"unsupported_mcp_tool:{tool_name}")

    def handle_jsonrpc(self, request: dict[str, Any], *, token: str | None = None) -> dict[str, Any]:
        req_id = request.get("id")
        method = str(request.get("method") or "")
        params = dict(request.get("params") or {})
        effective_token = token or params.get("_token") or self.default_token or None

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.list_tools()}}
        if method == "tools/call" or method.startswith("pcap."):
            if method.startswith("pcap."):
                alias_map = {
                    "pcap.list_analyses": "list_analyses",
                    "pcap.get_status": "get_analysis_status",
                    "pcap.get_manifest": "get_snapshot_manifest",
                    "pcap.list_evidence": "list_evidence",
                    "pcap.get_report": "get_report",
                }
                name = alias_map.get(method, method.removeprefix("pcap."))
                arguments = {k: v for k, v in params.items() if k != "_token"}
            else:
                name = str(params.get("name") or "")
                raw_arguments = dict(params.get("arguments") or {})
                if not effective_token and isinstance(raw_arguments.get("_token"), str):
                    effective_token = raw_arguments.get("_token")
                arguments = {k: v for k, v in raw_arguments.items() if k != "_token"}
            try:
                output = self.call_tool(name, arguments, token=effective_token)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(output, ensure_ascii=False)}],
                        "structuredContent": output,
                        "isError": False,
                    },
                }
            except PermissionError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32001, "message": str(exc), "data": {"code": str(exc)}},
                }
            except (ValueError, KeyError, LookupError) as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": str(exc), "data": {"code": str(exc)}},
                }
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

    handle_request = handle_jsonrpc


def main() -> int:
    from .config import load_settings
    from .store import Store

    settings = load_settings()
    store = Store(
        settings.data_dir,
        queue_limit=settings.queue_limit,
        storage_max_bytes=settings.storage_max_bytes,
    )
    op_token = settings.api_token.get_secret_value() if settings.api_token else None
    cli_default_token = (os.environ.get("PCAP_MCP_TOKEN") or "").strip() or None
    server = ReadOnlyMCPServer(store, operator_token=op_token, default_token=cli_default_token)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = server.handle_jsonrpc(req)
        except Exception as exc:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
        sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    return 0


__all__ = [
    "READ_ONLY_MCP_TOOLS",
    "ReadOnlyMCPServer",
    "decode_signed_cursor",
    "encode_signed_cursor",
]

if __name__ == "__main__":
    raise SystemExit(main())
