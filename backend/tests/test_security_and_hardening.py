from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import struct
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import etbert_bridge, mcp_server, triage  # noqa: E402
from backend.app.config import (  # noqa: E402
    AIConfig,
    AppSettings,
    DEFAULT_ETBERT_MODEL_CANDIDATES,
    _validate_endpoint,
)
from backend.app.exporters.pdf_report import _ascii_safe  # noqa: E402
from backend.app.exporters.redaction import redact_text  # noqa: E402
from backend.app.http_transport import post_json_bounded  # noqa: E402
from backend.app.llm.providers import (  # noqa: E402
    _RequestFailure,
    _build_prompt,
    _ensure_resolved_host_allowed,
)
from backend.app.main import create_app  # noqa: E402
from backend.app.models import (  # noqa: E402
    AnalysisRequest,
    Coverage,
    Evidence,
    EvidenceBundle,
    Finding,
)
from backend.app.store import Store  # noqa: E402
from backend.app.yara import inspect_yara_rules  # noqa: E402

TOKEN = "security-hardening-operator-token-32ch"
PCAP_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
CSV_FIXTURE = (
    b'"No.","Time","Source","Destination","Protocol","Length","Info"\n'
    b'"1","0.000000","192.0.2.10","198.51.100.20","TCP","74","54321 -> 443 [SYN] Seq=0"\n'
)
TSV_FIXTURE = (
    b"No.\tTime\tSource\tDestination\tProtocol\tLength\tInfo\n"
    b"1\t0.000000\t192.0.2.10\t198.51.100.20\tUDP\t88\t53000 -> 53 Standard query\n"
)


def _make_app(tmp_path: Path):
    settings = AppSettings(
        data_dir=tmp_path,
        api_token=SecretStr(TOKEN),
        upload_max_bytes=1024 * 1024,
        storage_max_bytes=16 * 1024 * 1024,
        queue_limit=32,
    )
    app = create_app(settings)
    client = TestClient(app, client=("127.0.0.1", 50000), headers={"Authorization": f"Bearer {TOKEN}"})
    return app, client


def test_tier1_bearer_token_only_sent_to_loopback_and_attached_by_http_transport(monkeypatch):
    monkeypatch.setenv("PCAP_TIER1_API_TOKEN", "tier1-secret-token-xyz")
    monkeypatch.delenv("TIER1_API_TOKEN", raising=False)

    assert triage._loopback_tier1_token("http://127.0.0.1:8787/classify") == "tier1-secret-token-xyz"
    assert triage._loopback_tier1_token("http://localhost:8787/v1/systemone") == "tier1-secret-token-xyz"
    assert triage._loopback_tier1_token("https://remote-sidecar.example/classify") is None

    assert etbert_bridge._loopback_tier1_token("http://127.0.0.1:8787/etbert/score") == "tier1-secret-token-xyz"
    assert etbert_bridge._loopback_tier1_token("https://evil.example/etbert/score") is None

    captured_headers: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.append(dict(request.headers))
        return httpx.Response(200, json={"ok": True})

    res = post_json_bounded(
        "http://127.0.0.1:8787/classify",
        {"items": []},
        timeout_seconds=5.0,
        transport=httpx.MockTransport(handler),
        bearer_token="tier1-secret-token-xyz",
    )
    assert res == {"ok": True}
    assert captured_headers and captured_headers[0].get("authorization") == "Bearer tier1-secret-token-xyz"


def test_mcp_server_cursor_secret_token_enforcement_and_stripping(tmp_path: Path, monkeypatch):
    assert mcp_server._DEFAULT_CURSOR_SECRET != "pcapscanner-cursor-secret"
    assert len(mcp_server._DEFAULT_CURSOR_SECRET) >= 32

    store = Store(tmp_path)
    monkeypatch.setenv("PCAP_API_TOKEN", "ambient-env-operator-token-should-not-autofallback")
    server = mcp_server.ReadOnlyMCPServer(store, operator_token="op-explicit-token")

    # Missing token must be rejected even when PCAP_API_TOKEN is set in process env.
    unauth = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_analyses", "arguments": {}}})
    assert "error" in unauth
    assert unauth["error"]["code"] == -32001

    # Capture arguments passed into call_tool to confirm `_token` is stripped from both params and params.arguments.
    observed_calls: list[tuple[str, dict, str | None]] = []
    orig_call_tool = server.call_tool

    def spy_call_tool(tool_name, arguments=None, *, token=None):
        observed_calls.append((tool_name, dict(arguments or {}), token))
        return orig_call_tool(tool_name, arguments, token=token)

    monkeypatch.setattr(server, "call_tool", spy_call_tool)

    ok_params = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "list_analyses", "_token": "op-explicit-token", "arguments": {"limit": 5, "_token": "nested-ignored"}},
        }
    )
    assert "result" in ok_params
    assert observed_calls[-1] == ("list_analyses", {"limit": 5}, "op-explicit-token")

    ok_nested = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "list_analyses", "arguments": {"limit": 3, "_token": "op-explicit-token"}},
        }
    )
    assert "result" in ok_nested
    assert observed_calls[-1] == ("list_analyses", {"limit": 3}, "op-explicit-token")


def test_config_endpoint_validation_rejects_ipv4_mapped_ipv6_and_has_no_personal_paths():
    for bad_remote in (
        "https://[::ffff:169.254.169.254]/v1",
        "https://[::ffff:10.0.0.1]/v1",
        "https://[::ffff:127.0.0.1]/v1",
        "https://[::ffff:192.168.1.5]/v1",
    ):
        with pytest.raises(ValueError):
            _validate_endpoint(bad_remote, data_boundary="remote")

    for bad_local in (
        "http://[::ffff:169.254.169.254]/v1",
        "http://[::ffff:10.0.0.1]/v1",
    ):
        with pytest.raises(ValueError):
            _validate_endpoint(bad_local, data_boundary="local")

    # Loopback IPv4-mapped IPv6 is permitted only under local boundary.
    assert _validate_endpoint("http://[::ffff:127.0.0.1]:11434/v1", data_boundary="local")

    config_src = (ROOT / "backend" / "app" / "config.py").read_text(encoding="utf-8")
    assert "/Users/thanadol" not in config_src
    assert all("/Users/thanadol" not in str(p) for p in DEFAULT_ETBERT_MODEL_CANDIDATES)


def test_llm_dns_resolution_ssrf_guard_and_utf8_prompt_budget(monkeypatch):
    async def _run_dns_check(resolved_ip: str, url: str, boundary: str) -> None:
        loop = asyncio.get_running_loop()

        async def fake_getaddrinfo(_host, port, **_kw):
            family = socket.AF_INET6 if ":" in resolved_ip else socket.AF_INET
            sockaddr = (resolved_ip, port, 0, 0) if family == socket.AF_INET6 else (resolved_ip, port)
            return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]

        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
        await _ensure_resolved_host_allowed(url, boundary)

    for blocked_ip in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::ffff:169.254.169.254", "::ffff:10.1.2.3"):
        with pytest.raises(_RequestFailure) as exc:
            asyncio.run(_run_dns_check(blocked_ip, "https://rebinding.example/v1", "remote"))
        assert exc.value.code in {"remote_private_endpoint", "forbidden_endpoint"}

    # Public IP is allowed for remote boundary, rejected for local boundary.
    asyncio.run(_run_dns_check("93.184.216.34", "https://api.example/v1", "remote"))
    with pytest.raises(_RequestFailure) as exc_local:
        asyncio.run(_run_dns_check("93.184.216.34", "http://localhost-spoof.example/v1", "local"))
    assert exc_local.value.code == "forbidden_endpoint"

    # Prompt budget uses 3 * (context_window_tokens - max_output_tokens - 512) UTF-8 bytes.
    bundle = EvidenceBundle(
        capture_sha256="b" * 64,
        coverage=Coverage(packets_seen=10, packets_analyzed=10, truncated=False, parser="fixture"),
        evidence=[
            Evidence(
                evidence_id=f"EV-{i:06d}",
                kind="flow",
                summary="flow",
                packet_refs=[i],
                attributes={"protocol": "TCP", "src": f"192.0.2.{i % 250}", "dst": "198.51.100.2", "packets": 5, "bytes": 400},
            )
            for i in range(1, 25)
        ],
        findings=[],
    )
    # First measure prompt size with generous window.
    large_cfg = AIConfig(
        enabled=True,
        provider="openai_compatible",
        base_url="http://127.0.0.1:11434",
        allowed_origins=("http://127.0.0.1:11434",),
        model="local-model",
        data_boundary="local",
        context_window_tokens=16384,
        max_output_tokens=512,
        input_max_bytes=100_000,
    )
    _prompt, _sha, prompt_bytes = _build_prompt(bundle, large_cfg)
    # Choose context_window_tokens such that input_token_budget < prompt_bytes < input_token_budget * 3.
    # For example, input_token_budget = prompt_bytes // 2 -> 3x budget is ~1.5 * prompt_bytes (MUST PASS).
    half_tokens = max(600, prompt_bytes // 2)
    passing_cfg = large_cfg.model_copy(
        update={
            "max_output_tokens": 256,
            "context_window_tokens": half_tokens + 256 + 512,
            "input_max_bytes": min(100_000, prompt_bytes + 4096),
        }
    )
    _, _, measured = _build_prompt(bundle, passing_cfg)
    assert measured > half_tokens
    assert measured <= half_tokens * 3

    # Now tighten context_window_tokens so 3 * input_token_budget < prompt_bytes (MUST FAIL).
    tight_tokens = max(1, (prompt_bytes // 3) - 100)
    failing_cfg = large_cfg.model_copy(
        update={
            "max_output_tokens": 256,
            "context_window_tokens": tight_tokens + 256 + 512,
            "input_max_bytes": min(100_000, prompt_bytes + 4096),
        }
    )
    with pytest.raises(_RequestFailure) as exc_budget:
        _build_prompt(bundle, failing_cfg)
    assert exc_budget.value.code == "budget_exceeded"


def test_admin_keys_scope_is_restricted_to_auth_keys_only(tmp_path: Path):
    app, client = _make_app(tmp_path)
    created = client.post(
        "/api/v1/auth/keys",
        json={"name": "key-admin-only", "scopes": ["admin:keys"]},
    )
    assert created.status_code == 201, created.text
    scoped_secret = created.json()["token"]
    assert scoped_secret

    scoped_client = TestClient(app, client=("127.0.0.1", 50000), headers={"Authorization": f"Bearer {scoped_secret}"})
    assert scoped_client.get("/api/v1/auth/keys").status_code == 200
    assert scoped_client.get("/api/v1/analyses").status_code == 403
    assert scoped_client.get("/api/v1/cases").status_code == 403
    assert scoped_client.get("/api/v1/osint/capabilities").status_code == 403


def test_osint_cache_mutation_and_key_rotation_require_loopback(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("PCAP_ALLOW_REMOTE_WORKSPACE", raising=False)
    app, loopback_client = _make_app(tmp_path)
    remote_client = TestClient(
        app,
        client=("198.51.100.10", 50000),
        headers={"Authorization": f"Bearer {TOKEN}"},
    )

    r_clear_post = remote_client.post("/api/v1/osint/cache/clear")
    assert r_clear_post.status_code == 403
    assert r_clear_post.json()["code"] == "osint_cache_mutation_loopback_only"

    r_clear_del = remote_client.delete("/api/v1/osint/cache")
    assert r_clear_del.status_code == 403
    assert r_clear_del.json()["code"] == "osint_cache_mutation_loopback_only"

    r_item_del = remote_client.delete("/api/v1/osint/cache/cache-entry-1")
    assert r_item_del.status_code == 403
    assert r_item_del.json()["code"] == "osint_cache_mutation_loopback_only"

    r_rotate = remote_client.post(
        "/api/v1/osint/keys/rotate",
        json={"provider": "virustotal", "api_key": "vt-test-key-1234", "invalidate_cache": True},
    )
    assert r_rotate.status_code == 403
    assert r_rotate.json()["code"] == "osint_key_rotation_loopback_only"

    # Same operations succeed on loopback.
    assert loopback_client.post("/api/v1/osint/cache/clear").status_code == 200
    assert loopback_client.delete("/api/v1/osint/cache").status_code == 200
    ok_rotate = loopback_client.post(
        "/api/v1/osint/keys/rotate",
        json={"provider": "virustotal", "api_key": "vt-test-key-1234", "invalidate_cache": True},
    )
    assert ok_rotate.status_code == 200
    assert ok_rotate.json()["provider"] == "virustotal"


def test_security_headers_include_csp(tmp_path: Path):
    _app, client = _make_app(tmp_path)
    for path in ("/health", "/api/v1/analyses"):
        resp = client.get(path)
        assert resp.status_code == 200
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp


def test_yara_inspect_skips_symlinks_and_falls_back_to_bundled_rules(tmp_path: Path):
    rules_dir = tmp_path / "custom_rules"
    rules_dir.mkdir()
    (rules_dir / "valid_rule.yar").write_text(
        'rule Detect_Test_Beacon { strings: $a = "beacon" condition: $a }\n',
        encoding="utf-8",
    )
    outside_secret = tmp_path / "outside.yar"
    outside_secret.write_text(
        'rule Secret_Symlink_Rule { strings: $a = "secret" condition: $a }\n',
        encoding="utf-8",
    )
    (rules_dir / "symlinked.yar").symlink_to(outside_secret)

    info = inspect_yara_rules(rules_dir)
    assert info["available"] is True
    assert info["rule_file_count"] == 1
    assert info["rule_names"] == ["Detect_Test_Beacon"]

    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()
    fallback_info = inspect_yara_rules(empty_dir)
    assert fallback_info["available"] is True
    assert int(fallback_info["rule_count"]) > 0


def test_batch_upload_accepts_csv_and_tsv_alongside_pcap(tmp_path: Path):
    _app, client = _make_app(tmp_path)
    files = [
        ("files", ("capture_a.csv", CSV_FIXTURE, "text/csv")),
        ("files", ("capture_b.tsv", TSV_FIXTURE, "text/tab-separated-values")),
        ("files", ("capture_c.pcap", PCAP_HEADER, "application/vnd.tcpdump.pcap")),
    ]
    resp = client.post("/api/v1/batches", files=files)
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["total_items"] == 3
    assert [item["format"] for item in body["items"]] == ["csv", "tsv", "pcap"]


def test_analyses_pagination_delete_and_prune_preserves_active_and_case_linked_jobs(tmp_path: Path):
    app, client = _make_app(tmp_path)
    store: Store = app.state.store

    def _upload_and_create(name: str, *, complete: bool) -> tuple[str, str]:
        up = client.post(
            "/api/v1/captures",
            content=PCAP_HEADER,
            headers={"Content-Type": "application/vnd.tcpdump.pcap", "X-Capture-Filename": name},
        )
        assert up.status_code == 201, up.text
        cid = up.json()["capture_id"]
        job = store.create_job(AnalysisRequest(capture_id=cid), "hardening-policy")
        jid = job["id"]
        if complete:
            lease = store.claim("parser")
            assert lease is not None and lease["id"] == jid
            bundle = EvidenceBundle(
                capture_sha256=store.capture(cid)["sha256"],
                coverage=Coverage(packets_seen=1, packets_analyzed=1, truncated=False, parser="fixture"),
                evidence=[],
                findings=[],
            )
            assert store.finish(lease, "completed", evidence=bundle.model_dump_json())
        return cid, jid

    cid_1, jid_old_1 = _upload_and_create("old_1.pcap", complete=True)
    cid_2, jid_old_2 = _upload_and_create("old_2.pcap", complete=True)
    cid_case, jid_case = _upload_and_create("case_linked.pcap", complete=True)
    _cid_active, jid_active = _upload_and_create("still_active.pcap", complete=False)
    active_lease = store.claim("parser")
    assert active_lease is not None and active_lease["id"] == jid_active
    _cid_newest, jid_newest = _upload_and_create("newest.pcap", complete=True)

    # Link jid_case to an investigation case so prune MUST preserve it.
    case_resp = client.post("/api/v1/cases", json={"title": "Protected Case"})
    assert case_resp.status_code == 201
    case_id = case_resp.json()["id"]
    link_resp = client.post(f"/api/v1/cases/{case_id}/analyses", json={"analysis_id": jid_case})
    assert link_resp.status_code == 200

    # Pagination check
    page = client.get("/api/v1/analyses?limit=2&offset=1")
    assert page.status_code == 200
    pdata = page.json()
    assert pdata["total"] == 5
    assert pdata["limit"] == 2
    assert pdata["offset"] == 1
    assert len(pdata["items"]) == 2

    # Active job cannot be deleted -> 409
    del_active = client.delete(f"/api/v1/analyses/{jid_active}")
    assert del_active.status_code == 409
    assert del_active.json()["code"] == "job_active_cannot_delete"

    # Terminal job delete unlinks orphaned capture file
    cap1_path = store.capture_path(cid_1, "pcap")
    assert cap1_path.exists()
    del_ok = client.delete(f"/api/v1/analyses/{jid_old_1}")
    assert del_ok.status_code == 200
    assert del_ok.json() == {"deleted": True, "analysis_id": jid_old_1, "capture_deleted": True}
    assert not cap1_path.exists()

    # Prune keep_latest=1 removes jid_old_2, keeps jid_newest, jid_active, and jid_case
    cap2_path = store.capture_path(cid_2, "pcap")
    assert cap2_path.exists()
    prune_resp = client.post("/api/v1/analyses/prune", json={"keep_latest": 1})
    assert prune_resp.status_code == 200
    prune_data = prune_resp.json()
    assert prune_data["deleted_ids"] == [jid_old_2]
    assert prune_data["deleted_count"] == 1
    assert prune_data["captures_deleted"] == 1
    assert prune_data["remaining_count"] == 3
    assert not cap2_path.exists()
    assert store.capture_path(cid_case, "pcap").exists()

    remaining_ids = {item["id"] for item in client.get("/api/v1/analyses?limit=20&offset=0").json()["items"]}
    assert remaining_ids == {jid_newest, jid_active, jid_case}


def test_exports_redact_query_and_pdf_thai_transliteration(tmp_path: Path):
    app, client = _make_app(tmp_path)
    store: Store = app.state.store

    up = client.post(
        "/api/v1/captures",
        content=PCAP_HEADER,
        headers={"Content-Type": "application/vnd.tcpdump.pcap", "X-Capture-Filename": "corp-payroll-2026.pcapng"},
    )
    assert up.status_code == 201
    cid = up.json()["capture_id"]
    job = store.create_job(AnalysisRequest(capture_id=cid), "export-redact-policy")
    jid = job["id"]
    lease = store.claim("parser")
    assert lease is not None

    ev = Evidence(
        evidence_id="EV-000001",
        kind="http",
        summary=(
            "Beacon from 203.0.113.77 / 2001:db8:cafe::42 mac aa:bb:cc:dd:ee:ff "
            "to https://c2-secret.evilcorp.net/beacon?id=1 by analyst@secretcorp.org "
            "using api_key=sk_live_SUPERSECRET12345 from /Users/alice/secret/corp-payroll-2026.pcapng "
            "(rule file malware_rules.yar) ตรวจพบความผิดปกติในการเชื่อมต่อ"
        ),
        packet_refs=[1, 2],
        attributes={
            "protocol": "HTTP",
            "src": "203.0.113.77",
            "dst": "2001:db8:cafe::42",
            "query": "c2-secret.evilcorp.net",
            "url": "https://c2-secret.evilcorp.net/beacon?id=1",
            "email": "analyst@secretcorp.org",
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "path": "/Users/alice/secret/corp-payroll-2026.pcapng",
        },
    )
    finding = Finding(
        finding_id="F-0001",
        detector="http_beacon_detector",
        title="ตรวจพบความผิดปกติ: C2 to c2-secret.evilcorp.net from 203.0.113.77",
        severity="high",
        confidence="high",
        evidence_ids=["EV-000001"],
        limitations=["Observed in /Users/alice/secret/corp-payroll-2026.pcapng with malware_rules.yar"],
    )
    bundle = EvidenceBundle(
        capture_sha256=hashlib.sha256(PCAP_HEADER).hexdigest(),
        coverage=Coverage(
            packets_seen=42,
            packets_analyzed=42,
            truncated=False,
            parser="tshark",
            warnings=["Captured from /Users/alice/secret/corp-payroll-2026.pcapng"],
        ),
        evidence=[ev],
        findings=[finding],
    )
    ai_payload = {
        "state": "completed",
        "provider": "openai_compatible",
        "model": "qwen2.5:7b",
        "report": {
            "summary": [
                {
                    "claim": "ตรวจพบความผิดปกติของโฮสต์ 203.0.113.77 ติดต่อ c2-secret.evilcorp.net",
                    "evidence_ids": ["EV-000001"],
                }
            ],
            "assessments": [
                {
                    "finding_id": "F-0001",
                    "assessment": "ส่งข้อมูลไปที่ https://c2-secret.evilcorp.net/beacon?id=1 โดย analyst@secretcorp.org",
                    "evidence_ids": ["EV-000001"],
                }
            ],
            "limitations": [],
            "recommended_actions": [
                {
                    "action": "แยกเครื่อง 203.0.113.77 ออกจากเครือข่ายและตรวจสอบ malware_rules.yar",
                    "evidence_ids": ["EV-000001"],
                }
            ],
        },
    }
    assert store.finish(
        lease,
        "completed",
        evidence=bundle.model_dump_json(),
        ai_result=json.dumps(ai_payload, ensure_ascii=False),
    )

    # Direct redaction helper preserves non-domain rule filenames while masking sensitive tokens.
    sample_redacted = redact_text(
        "Rule malware_rules.yar matched 203.0.113.77 and c2-secret.evilcorp.net with token=supersecret99"
    )
    assert "malware_rules.yar" in sample_redacted
    assert "203.0.113.77" not in sample_redacted
    assert "c2-secret.evilcorp.net" not in sample_redacted
    assert "supersecret99" not in sample_redacted

    # Thai RTGS transliteration helper produces clean Latin ASCII instead of "????".
    translit = _ascii_safe("ตรวจพบความผิดปกติในการเชื่อมต่อ")
    assert translit.strip()
    assert "?" not in translit
    assert all(ord(ch) < 128 for ch in translit)

    sensitive_needles = (
        "203.0.113.77",
        "2001:db8:cafe::42",
        "c2-secret.evilcorp.net",
        "analyst@secretcorp.org",
        "aa:bb:cc:dd:ee:ff",
        "sk_live_SUPERSECRET12345",
        "/Users/alice/secret",
        "corp-payroll-2026.pcapng",
    )

    # 1. STIX
    stix_resp = client.get(f"/api/v1/analyses/{jid}/export.stix.json?redact=true")
    assert stix_resp.status_code == 200
    stix_text = stix_resp.text
    for needle in sensitive_needles:
        assert needle not in stix_text, f"STIX leaked {needle}"
    assert "EV-000001" in stix_text or "F-0001" in stix_text

    # 2. CSV
    csv_resp = client.get(f"/api/v1/analyses/{jid}/export.csv?redact=true")
    assert csv_resp.status_code == 200
    csv_text = csv_resp.text
    for needle in sensitive_needles:
        assert needle not in csv_text, f"CSV leaked {needle}"
    assert "F-0001" in csv_text
    assert "EV-000001" in csv_text
    assert "malware_rules.yar" in csv_text

    # 3. CEF
    cef_resp = client.get(f"/api/v1/analyses/{jid}/export.cef?redact=true")
    assert cef_resp.status_code == 200
    cef_text = cef_resp.text
    for needle in sensitive_needles:
        assert needle not in cef_text, f"CEF leaked {needle}"
    assert "F-0001" in cef_text

    # 4. ATT&CK Navigator
    nav_resp = client.get(f"/api/v1/analyses/{jid}/export.navigator.json?redact=true")
    assert nav_resp.status_code == 200
    nav_text = nav_resp.text
    for needle in sensitive_needles:
        assert needle not in nav_text, f"Navigator leaked {needle}"

    # 5. PDF
    pdf_resp = client.get(f"/api/v1/analyses/{jid}/export.pdf?redact=true")
    assert pdf_resp.status_code == 200
    pdf_bytes = pdf_resp.content
    assert pdf_bytes.startswith(b"%PDF-")
    pdf_latin = pdf_bytes.decode("latin-1", errors="ignore")
    for needle in sensitive_needles:
        assert needle not in pdf_latin, f"PDF leaked {needle}"
    assert "????" not in pdf_latin
