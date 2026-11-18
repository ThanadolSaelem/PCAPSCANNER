from __future__ import annotations

import hashlib
import io
import json
import pickle
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from backend.app.agents.mcp import MCPServer
from backend.app.config import AppSettings
from backend.app.correlation import (
    build_ioc_inventory,
    correlate_bundle_findings,
    correlate_zeek_and_tshark_evidence,
)
from backend.app.dns_analysis import DNSObservation, analyze_dns_candidates
from backend.app.etbert_bridge import (
    inspect_etbert_checkpoint,
    resolve_etbert_checkpoint_path,
    score_flows_with_local_etbert_checkpoint,
)
from backend.app.exporters.cef import export_findings_cef
from backend.app.exporters.csv_json import export_findings_and_evidence_csv
from backend.app.exporters.navigator import export_attack_navigator_layer
from backend.app.exporters.pdf_report import export_analysis_pdf, export_snapshot_pdf
from backend.app.flow_intel import build_flow_analytics
from backend.app.geoip import GeoIP, build_world_map_flows
from backend.app.llm.chat import answer_question
from backend.app.main import create_app, profile_hash
from backend.app.mitre import ATTACKMapper
from backend.app.models import AnalysisRequest, Coverage, Evidence, EvidenceBundle, Finding
from backend.app.osint_service import IOCCandidate, OSINTService


def _sample_bundle(*, include_yara: bool = False) -> EvidenceBundle:
    ev_flow = Evidence(
        evidence_id="EV-000001",
        kind="flow",
        summary="TCP 10.0.0.5:51234 -> 8.8.8.8:443 (12 pkts, 1800 bytes)",
        packet_refs=[1, 2, 3],
        attributes={
            "src": "10.0.0.5",
            "dst": "8.8.8.8",
            "src_port": 51234,
            "dst_port": 443,
            "protocol": "TCP",
            "packets": 12,
            "bytes": 1800,
            "first_seen": 1700000000.0,
            "last_seen": 1700000010.0,
            "intervals": "1.0,1.0,1.0",
        },
    )
    ev_zeek = Evidence(
        evidence_id="EV-000002",
        kind="zeek",
        summary="Zeek conn.log row 1: tcp 10.0.0.5:51234 -> 8.8.8.8:443",
        packet_refs=[],
        attributes={
            "source_log": "conn.log",
            "source_row": 1,
            "uid": "C123456",
            "id_orig_h": "10.0.0.5",
            "id_orig_p": 51234,
            "id_resp_h": "8.8.8.8",
            "id_resp_p": 443,
            "proto": "tcp",
        },
    )
    ev_dns = Evidence(
        evidence_id="EV-000003",
        kind="dns",
        summary="DNS query beacon.bad-c2.example",
        packet_refs=[4],
        attributes={
            "src": "10.0.0.5",
            "query": "beacon.bad-c2.example",
            "rcode": 0,
            "qtype": 1,
        },
    )
    ev_list: list[Evidence] = [ev_flow, ev_zeek, ev_dns]
    if include_yara:
        sample_sha = hashlib.sha256(b"MZ_FAKE_PAYLOAD").hexdigest()
        ev_list.append(
            Evidence(
                evidence_id="EV-000004",
                kind="yara",
                summary="YARA rule Suspicious_Dropper matched carved object",
                packet_refs=[5, 6],
                attributes={
                    "rule_id": "Suspicious_Dropper",
                    "object_sha256": sample_sha,
                    "object_size_bytes": 4096,
                    "filename": "payload.exe",
                    "content_type": "application/x-dosexec",
                },
            )
        )
    finding = Finding(
        finding_id="F-0001",
        detector="flow_periodic_beacon",
        title="=cmd|'/c calc'!A0 Periodic connection candidate",
        severity="medium",
        confidence="low",
        summary="=SUM(1,2) periodic flow to 8.8.8.8:443",
        evidence_ids=["EV-000001"],
        limitations=["Candidate only."],
    )
    mitre = ATTACKMapper().map_analysis(findings=[finding]).to_dict()
    iocs = build_ioc_inventory(ev_list, [finding])
    return EvidenceBundle(
        capture_sha256="a" * 64,
        coverage=Coverage(
            packets_seen=12,
            packets_analyzed=12,
            truncated=False,
            parser="tshark-test",
            warnings=[],
            stages=[],
        ),
        evidence=ev_list,
        findings=[finding],
        mitre_attack=mitre,
        flow_analytics=build_flow_analytics(ev_list),
        geoip=build_world_map_flows(ev_list),
        iocs=iocs,
    )


def _seed_completed_analysis(app, tmp_path: Path, bundle: EvidenceBundle) -> str:
    store = app.state.store
    sample_file = tmp_path / "seed.pcap"
    sample_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    cap = store.register_local_capture(
        sample_file,
        "seed.pcap",
        "pcap",
        sample_file.stat().st_size,
        hashlib.sha256(sample_file.read_bytes()).hexdigest(),
    )
    req = AnalysisRequest(capture_id=cap["id"], ai_enabled=False, ai_consent=False)
    job = store.create_job(req, profile_hash(app.state.settings))
    claimed = store.claim("parser")
    assert claimed is not None and claimed["id"] == job["id"]
    ok = store.finish(claimed, "completed", evidence=bundle.model_dump_json())
    assert ok is True
    return str(job["id"])


def test_m2_fast_flux_nxdomain_zeek_correlation_and_mitre():
    obs = [
        DNSObservation(
            evidence_id=f"EV-{i:06d}",
            query="flux.bad-actor.example",
            response_code=0,
            source="10.0.0.9",
            answers=(f"198.51.100.{i}", f"203.0.113.{i}"),
            min_ttl=30,
        )
        for i in range(1, 7)
    ] + [
        DNSObservation(
            evidence_id=f"EV-{1000 + i:06d}",
            query=f"nx{i}.dga.example",
            response_code=3,
            source="10.0.0.99",
        )
        for i in range(1, 14)
    ]
    res = analyze_dns_candidates(obs)
    detectors = {c.detector for c in res.candidates}
    assert "dns_fast_flux_heuristic" in detectors
    assert "dns_origin_nxdomain_ratio" in detectors

    bundle = _sample_bundle()
    zeek_corrs = correlate_zeek_and_tshark_evidence(bundle.evidence)
    assert zeek_corrs == 1
    assert bundle.evidence[1].attributes["correlated_evidence_id"] == "EV-000001"
    assert bundle.evidence[0].attributes["correlated_zeek_evidence_id"] == "EV-000002"
    assert bundle.evidence[0].attributes["zeek_uid_hash"] == "C123456"

    bundle_corrs = correlate_bundle_findings(bundle.evidence, bundle.findings)
    assert len(bundle_corrs) >= 1
    assert bundle.mitre_attack is not None
    assert bundle.mitre_attack["attack_version"] == "19.1"
    assert len(bundle.mitre_attack["techniques"]) >= 1


def test_m3_geoip_and_world_map_offline():
    geo = GeoIP.lookup("8.8.8.8")
    assert geo is not None
    assert geo["country"] == "United States"

    wm = build_world_map_flows([{"src": "10.0.0.5", "dst": "8.8.8.8", "packets": 10, "bytes": 1200}])
    assert wm["mapped_public_ips"] == 1
    assert wm["mapped_ip_count"] == 1
    assert len(wm["countries"]) == 1
    assert wm["countries"][0]["unique_ips"] == 1
    assert len(wm["arcs"]) == 1
    assert wm["arcs"][0]["src_id"] == "HOME"
    assert wm["arcs"][0]["dst_id"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_m3_osint_7_providers_rdns_and_rdap():
    def handler(request: httpx.Request) -> httpx.Response:
        if "rdap.arin.net" in str(request.url):
            return httpx.Response(
                200,
                json={"handle": "NET-8-8-8-0-1", "name": "LVLT-GOGL-8-8-8", "country": "US", "status": ["active"]},
            )
        return httpx.Response(404, json={})

    svc = OSINTService(
        transport=httpx.MockTransport(handler),
        env={
            "PCAP_OSINT_RDNS_ACK": "1",
            "PCAP_OSINT_RDAP_ACK": "1",
        },
        minimum_interval_seconds=0.0,
        rdns_resolver=lambda ip: ("dns.google", [], [ip]),
    )
    caps = svc.capabilities(enabled=True)
    provider_ids = {p["id"] for p in caps["providers"]}
    assert {"virustotal", "abuseipdb", "greynoise", "shodan", "otx", "rdns", "rdap"}.issubset(provider_ids)

    cand = IOCCandidate("IOC-0001", "ipv4", "8.8.8.8", ("EV-0001",))
    res = await svc.enrich([cand], ["rdns", "rdap"], consent=True, enabled=True)
    assert res["state"] == "completed"
    by_prov = {item["provider"]: item for item in res["results"]}
    assert by_prov["rdns"]["summary"]["ptr_hostname"] == "dns.google"
    assert by_prov["rdap"]["summary"]["country"] == "US"


def test_m3_m4_m5_m6_api_routes_iocs_yara_charts_snapshots_and_exporters(tmp_path: Path):
    settings = AppSettings(
        data_dir=tmp_path / "data",
        api_token=SecretStr("operator-master-token"),
        yara_rules_dir=Path(__file__).resolve().parent.parent / "rules",
    )
    app = create_app(settings)
    client = TestClient(app)
    headers = {"Authorization": "Bearer operator-master-token"}

    bundle = _sample_bundle(include_yara=True)
    analysis_id = _seed_completed_analysis(app, tmp_path, bundle)

    # M4: YARA rules inventory + Artifact inventory synthesized from YARA evidence
    rules_res = client.get("/api/v1/yara/rules", headers=headers)
    assert rules_res.status_code == 200
    assert rules_res.json()["available"] is True
    assert rules_res.json()["rule_count"] >= 1

    art_list = client.get(f"/api/v1/analyses/{analysis_id}/artifacts", headers=headers)
    assert art_list.status_code == 200
    items = art_list.json()["items"]
    assert len(items) == 1
    assert items[0]["size_bytes"] == 4096
    assert items[0]["matched_rules"] == ["Suspicious_Dropper"]

    art_dl = client.get(
        f"/api/v1/analyses/{analysis_id}/artifacts/{items[0]['artifact_id']}?download=true",
        headers=headers,
    )
    assert art_dl.status_code == 200
    assert "Suspicious_Dropper" in art_dl.text

    # M5: Bounded dashboard flow analytics & GeoIP endpoint
    geo_res = client.get(f"/api/v1/analyses/{analysis_id}/geoip", headers=headers)
    assert geo_res.status_code == 200
    assert geo_res.json()["mapped_public_ips"] == 1
    assert bundle.flow_analytics is not None
    assert len(bundle.flow_analytics["packet_size_histogram"]) >= 1
    assert len(bundle.flow_analytics["top_protos"]) >= 1

    # M3: OSINT cache list / delete / bulk clear & key rotation invalidation
    cached = app.state.store.put_osint_cache("virustotal", "ipv4", "8.8.8.8", "completed", {"malicious": 0})
    app.state.store.put_osint_cache("abuseipdb", "ipv4", "1.1.1.1", "completed", {"abuse_confidence": 0})
    cache_list = client.get("/api/v1/osint/cache", headers=headers)
    assert cache_list.status_code == 200
    assert cache_list.json()["total"] == 2

    rot_res = client.post(
        "/api/v1/osint/keys/rotate",
        headers=headers,
        json={"provider": "virustotal", "api_key": "vt-new-secret-key-value", "invalidate_cache": True},
    )
    assert rot_res.status_code == 200
    assert rot_res.json()["cache_invalidated"] is True
    assert rot_res.json()["deleted_cache_entries"] == 1

    del_cache = client.delete("/api/v1/osint/cache", headers=headers)
    assert del_cache.status_code == 200
    assert del_cache.json()["deleted_count"] == 1
    assert client.get("/api/v1/osint/cache", headers=headers).json()["total"] == 0

    # Re-add and test single delete
    cached2 = app.state.store.put_osint_cache("otx", "domain", "bad.example", "completed", {"pulse_count": 3})
    assert cached2["cache_id"] != cached["cache_id"]
    assert client.delete(f"/api/v1/osint/cache/{cached2['cache_id']}", headers=headers).status_code == 204

    # M3: Case IOC CRUD + cross-case & bundle IOC search
    case_res = client.post(
        "/api/v1/cases",
        headers=headers,
        json={"title": "C2 Triage", "severity": "high", "status": "open"},
    )
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]
    assert client.post(
        f"/api/v1/cases/{case_id}/analyses",
        headers=headers,
        json={"analysis_id": analysis_id},
    ).status_code == 200

    bad_ioc = client.post(
        f"/api/v1/cases/{case_id}/iocs",
        headers=headers,
        json={"ioc_type": "ip", "value": "not-an-ip"},
    )
    assert bad_ioc.status_code == 400

    good_ioc = client.post(
        f"/api/v1/cases/{case_id}/iocs",
        headers=headers,
        json={"ioc_type": "ip", "value": "198.51.100.42", "severity": "high", "tags": ["c2"], "note": "observed callback"},
    )
    assert good_ioc.status_code == 201
    ioc_data = good_ioc.json()
    assert ioc_data["indicator_type"] == "ipv4"
    assert ioc_data["ioc_type"] == "ipv4"
    assert ioc_data["indicator"] == "198.51.100.42"

    search_case = client.get("/api/v1/iocs/search?query=198.51.100.42", headers=headers)
    assert search_case.status_code == 200
    assert search_case.json()["total"] == 1
    assert "case_ioc" in search_case.json()["items"][0]["sources"]

    search_bundle = client.get("/api/v1/iocs/search?query=8.8.8.8", headers=headers)
    assert search_bundle.status_code == 200
    assert search_bundle.json()["total"] == 1
    assert analysis_id in search_bundle.json()["items"][0]["analysis_ids"]
    assert case_id in search_bundle.json()["items"][0]["case_ids"]

    assert client.delete(f"/api/v1/cases/{case_id}/iocs/{ioc_data['ioc_id']}", headers=headers).status_code == 204

    # M6: Immutable snapshots + CSV / CEF / Navigator / PDF exports
    snap_create = client.post(f"/api/v1/analyses/{analysis_id}/snapshot", headers=headers)
    assert snap_create.status_code == 201
    snap_id = snap_create.json()["snapshot_id"]
    assert snap_create.json()["immutable"] is True

    snap_get = client.get(f"/api/v1/analyses/{analysis_id}/snapshot", headers=headers)
    assert snap_get.status_code == 200
    assert snap_get.json()["snapshot_id"] == snap_id
    assert "_bundle_json" not in snap_get.json()

    csv_res = client.get(f"/api/v1/analyses/{analysis_id}/export.csv", headers=headers)
    assert csv_res.status_code == 200
    assert csv_res.headers.get("X-Snapshot-Id") == snap_id
    assert "'=cmd" in csv_res.text

    cef_res = client.get(f"/api/v1/analyses/{analysis_id}/export.cef", headers=headers)
    assert cef_res.status_code == 200
    assert "CEF:0|PCAPSCANNER|" in cef_res.text
    assert snap_id in cef_res.text

    nav_res = client.get(f"/api/v1/analyses/{analysis_id}/export.navigator.json", headers=headers)
    assert nav_res.status_code == 200
    assert nav_res.json()["versions"]["layer"] == "4.5"
    assert len(nav_res.json()["techniques"]) >= 1

    pdf_res = client.get(f"/api/v1/analyses/{analysis_id}/export.pdf", headers=headers)
    assert pdf_res.status_code == 200
    assert pdf_res.content.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_res.content

    # PDF regression guard when report.summary is a structured claim list instead of str
    pdf_with_ai_list = export_analysis_pdf(
        {"id": analysis_id, "capture_filename": "seed.pcap"},
        bundle.model_dump(mode="json"),
        ai_result={
            "state": "completed",
            "report": {
                "summary": [{"claim": "Periodic traffic observed to 8.8.8.8", "evidence_ids": ["EV-000001"]}],
                "recommended_actions": [{"action": "Inspect host 10.0.0.5"}],
            },
        },
        options={"force_pure_pdf": True},
    )
    assert pdf_with_ai_list.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_with_ai_list


def test_m6_unit_exporters_direct():
    bundle = _sample_bundle()
    snapshot = {
        "snapshot_id": "SNAP-0123456789abcdef",
        "analysis_id": "a" * 32,
        "created_at": "2026-04-17T00:00:00Z",
        "capture_sha256": bundle.capture_sha256,
        "parser_version": "1.0",
        "rule_set_version": "1.0",
        "policy_hash": "b" * 64,
    }
    csv_text = export_findings_and_evidence_csv(bundle, snapshot=snapshot)
    assert "'=SUM(1,2)" in csv_text or "'=cmd" in csv_text

    cef_text = export_findings_cef(bundle, snapshot=snapshot)
    assert "CEF:0|PCAPSCANNER|" in cef_text
    assert "SNAP-0123456789abcdef" in cef_text

    nav_layer = export_attack_navigator_layer(bundle, snapshot=snapshot)
    assert nav_layer["versions"]["layer"] == "4.5"
    assert len(nav_layer["techniques"]) >= 1

    pdf_bytes = export_snapshot_pdf(bundle, snapshot=snapshot)
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes


def test_m7_scoped_api_keys_quotas_ratelimits_and_mcp_cursor(tmp_path: Path):
    settings = AppSettings(
        data_dir=tmp_path / "data",
        api_token=SecretStr("operator-master-token"),
    )
    app = create_app(settings)
    client = TestClient(app)
    headers = {"Authorization": "Bearer operator-master-token"}
    analysis_id = _seed_completed_analysis(app, tmp_path, _sample_bundle())

    create_res = client.post(
        "/api/v1/auth/keys",
        headers=headers,
        json={
            "name": "mcp-reader",
            "scopes": ["read:status", "read:manifest", "read:evidence", "read:report"],
            "rate_limit_rpm": 5,
            "quota_limit": 4,
        },
    )
    assert create_res.status_code == 201
    key_data = create_res.json()
    raw_token = key_data["token"]
    key_id = key_data["key_id"]
    assert raw_token.startswith("phk_")
    assert key_data["name"] == "mcp-reader"
    assert key_data["quota_limit"] == 4

    list_res = client.get("/api/v1/auth/keys", headers=headers)
    assert list_res.status_code == 200
    assert all("token" not in item for item in list_res.json()["items"])

    # Insufficient scope over HTTP middleware -> 403
    scoped_headers = {"Authorization": f"Bearer {raw_token}"}
    denied_res = client.get("/api/v1/cases", headers=scoped_headers)
    assert denied_res.status_code == 403
    assert denied_res.json()["code"] == "insufficient_scope"

    mcp = MCPServer(app.state.store, default_token=raw_token)
    r_tools = mcp.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert "result" in r_tools
    assert len(r_tools["result"]["tools"]) == 5

    # Call 1: get_manifest (must not leak _bundle_json or bundle)
    r_man = mcp.handle_request(
        {"jsonrpc": "2.0", "id": 2, "method": "pcap.get_manifest", "params": {"analysis_id": analysis_id}}
    )
    man_content = r_man["result"]["structuredContent"]
    assert man_content["immutable"] is True
    assert "_bundle_json" not in man_content
    assert "bundle" not in man_content

    # Call 2 & Call 3: list_evidence with signed cursor pagination
    r_ev1 = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "pcap.list_evidence",
            "params": {"analysis_id": analysis_id, "limit": 2},
        }
    )
    ev1 = r_ev1["result"]["structuredContent"]
    assert len(ev1["items"]) == 2
    assert ev1["next_cursor"]

    # Tampered cursor fails cleanly without executing bad offset
    r_bad_cursor = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "pcap.list_evidence",
            "params": {"analysis_id": analysis_id, "limit": 2, "cursor": ev1["next_cursor"] + "tamper"},
        }
    )
    assert "error" in r_bad_cursor

    # Authorized call 4 reaches quota_limit=4 and succeeds; authorized call 5 must fail with api_key_quota_exceeded
    r_fourth = mcp.handle_request({"jsonrpc": "2.0", "id": 5, "method": "pcap.list_analyses", "params": {}})
    assert "result" in r_fourth

    r_quota = mcp.handle_request({"jsonrpc": "2.0", "id": 6, "method": "pcap.list_analyses", "params": {}})
    assert "error" in r_quota
    assert r_quota["error"]["data"]["code"] == "api_key_quota_exceeded"

    # Also test RPM limit via HTTP endpoint with a separate low-RPM key
    rpm_key = client.post(
        "/api/v1/auth/keys",
        headers=headers,
        json={"name": "rpm-capped", "scopes": ["read:status"], "rate_limit_rpm": 2, "quota_limit": 100},
    ).json()
    rpm_hdr = {"Authorization": f"Bearer {rpm_key['token']}"}
    assert client.get(f"/api/v1/analyses/{analysis_id}", headers=rpm_hdr).status_code == 200
    assert client.get(f"/api/v1/analyses/{analysis_id}", headers=rpm_hdr).status_code == 200
    rate_limited = client.get(f"/api/v1/analyses/{analysis_id}", headers=rpm_hdr)
    assert rate_limited.status_code == 429
    assert rate_limited.json()["code"] == "api_key_rate_limited"

    # Revoke first key -> api_key_revoked on MCP
    rev_res = client.delete(f"/api/v1/auth/keys/{key_id}", headers=headers)
    assert rev_res.status_code == 200
    r_rev = mcp.handle_request({"jsonrpc": "2.0", "id": 7, "method": "pcap.list_analyses", "params": {}})
    assert "error" in r_rev
    assert r_rev["error"]["data"]["code"] == "api_key_revoked"

    audit_res = client.get("/api/v1/auth/keys/audit", headers=headers)
    assert audit_res.status_code == 200
    actions = {row["action"] for row in audit_res.json()["items"]}
    assert {"created", "authorized", "quota_exceeded", "rate_limited", "revoked"}.issubset(actions)


@pytest.mark.asyncio
async def test_m8_grounded_chat_consent_and_citations():
    bundle = _sample_bundle()
    denied = await answer_question(bundle, "What flows were observed?", consent=False)
    assert denied.state == "consent_required"

    async def fake_provider(prompt: str) -> str:
        assert "SAFE_ANALYSIS_JSON" in prompt
        return json.dumps({"claims": [{"claim": "One periodic flow candidate exists.", "evidence_ids": ["EV-000001"]}]})

    ok = await answer_question(
        bundle,
        "Did any flow exhibit periodic behavior?",
        consent=True,
        provider=fake_provider,
    )
    assert ok.state == "completed"
    assert len(ok.claims) == 1
    assert ok.claims[0].evidence_ids == ["EV-000001"]


def test_etbert_bin_checkpoint_inspection_scoring_and_workspace_endpoints(tmp_path: Path, monkeypatch):
    ckpt_path = tmp_path / "pre-trained_model.bin"
    fake_state = {
        "embedding.word_embedding.weight": b"\x00" * 1024,
        "encoder.transformer.0.self_attn.linear_layers.0.weight": b"\x01" * 1024,
        "encoder.transformer.11.feed_forward.linear_1.weight": b"\x02" * 1024,
        "target.mlm_linear_1.weight": b"\x03" * 256,
    }
    with zipfile.ZipFile(ckpt_path, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(fake_state))

    resolved = resolve_etbert_checkpoint_path(str(ckpt_path))
    assert resolved == ckpt_path.resolve()

    info = inspect_etbert_checkpoint(ckpt_path)
    assert info["exists"] is True
    assert info["valid"] is True
    assert info["architecture"] == "uer-etbert-mlm"
    assert info["num_layers"] == 12
    assert info["ready"] is True

    # Also inspect raw pickle format with HuggingFace-style keys
    bert_ckpt = tmp_path / "bert_model.pt"
    bert_ckpt.write_bytes(
        pickle.dumps(
            {
                "embeddings.word_embeddings.weight": b"\x00" * 64,
                "encoder.layer.0.attention.self.query.weight": b"\x01" * 64,
                "encoder.layer.5.output.dense.weight": b"\x02" * 64,
                "classifier.weight": b"\x03" * 32,
            }
        )
    )
    bert_info = inspect_etbert_checkpoint(bert_ckpt)
    assert bert_info["valid"] is True
    assert bert_info["num_layers"] == 6
    assert bert_info["has_classification_head"] is True

    scores = score_flows_with_local_etbert_checkpoint(
        [
            ("EV-000001", {"protocol": "TLS", "dst_port": 443, "tls_handshake_types": "1,2", "bytes": 1800, "packets": 12}),
            ("EV-000002", {"protocol": "HTTP", "dst_port": 80, "http_sqli_hits": 2, "http_uri_max_entropy": 4.9}),
        ],
        ckpt_path,
    )
    assert "EV-000001" in scores
    assert "EV-000002" in scores
    assert scores["EV-000002"].predicted_class == "Web_Injection_Or_Tunnel"
    assert scores["EV-000002"].confidence >= 0.80

    # FastAPI endpoints for ET-BERT & Workspace
    settings = AppSettings(data_dir=tmp_path / "data", api_token=SecretStr("operator-master-token"))
    app = create_app(settings)
    client = TestClient(app)
    headers = {"Authorization": "Bearer operator-master-token"}

    ws_upd = client.put(
        "/api/v1/system/workspace",
        headers=headers,
        json={"etbert_checkpoint_path": str(ckpt_path)},
    )
    assert ws_upd.status_code == 200
    ws_json = ws_upd.json()
    assert ws_json["etbert_enabled"] is True
    assert ws_json["etbert_checkpoint_configured"] is True
    assert ws_json["etbert_checkpoint_info"]["num_layers"] == 12

    et_res = client.get("/api/v1/system/etbert", headers=headers)
    assert et_res.status_code == 200
    assert et_res.json()["etbert_enabled"] is True
    assert et_res.json()["ready"] is True

    ws_clear = client.put(
        "/api/v1/system/workspace",
        headers=headers,
        json={"clear_etbert_checkpoint": True},
    )
    assert ws_clear.status_code == 200
    cleared = ws_clear.json()
    assert cleared["etbert_checkpoint_configured"] is False
    assert cleared["etbert_checkpoint_path"] is None
    assert cleared["etbert_enabled"] is False
    assert cleared["etbert_checkpoint_info"]["ready"] is False

    # Verify explicit unbind persists across server restarts even if a default .bin exists on disk
    from backend.app import config as app_config

    ws_file = tmp_path / "workspace.json"
    monkeypatch.setenv("PCAP_WORKSPACE_CONFIG", str(ws_file))
    monkeypatch.setenv("PCAP_USE_WORKSPACE_CONFIG", "1")
    settings_re = AppSettings(data_dir=tmp_path / "data", api_token=SecretStr("operator-master-token"))
    app_re = create_app(settings_re)
    client_re = TestClient(app_re)
    assert client_re.put(
        "/api/v1/system/workspace", headers=headers, json={"etbert_checkpoint_path": str(ckpt_path)}
    ).status_code == 200
    assert client_re.put(
        "/api/v1/system/workspace", headers=headers, json={"clear_etbert_checkpoint": True}
    ).status_code == 200

    monkeypatch.setattr(app_config, "DEFAULT_ETBERT_MODEL_CANDIDATES", (str(ckpt_path),))
    reloaded = app_config.load_settings()
    assert reloaded.triage.etbert_checkpoint_path is None
    assert reloaded.triage.etbert_enabled is False
