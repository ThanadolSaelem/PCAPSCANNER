from __future__ import annotations

import json
import zipfile
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from backend.app import main as main_module
from backend.app import triage
from backend.app.config import AIConfig, AppSettings, TriageConfig, load_settings
from backend.app.flow_intel import build_flow_analytics
from backend.app.llm import probe_models
from backend.app.main import create_app, profile_hash
from backend.app.models import Coverage, Evidence, EvidenceBundle, Stage
from backend.app.pipeline import _Accumulator, _Packet, _build_bundle


TOKEN = "test-only-operator-token-32-characters"


def _make_dummy_etbert_bin(tmp_path) -> str:
    ckpt = tmp_path / "synthetic_etbert.bin"
    with zipfile.ZipFile(ckpt, "w") as zf:
        zf.writestr(
            "archive/data.pkl",
            b"embedding.word_embedding.weight encoder.transformer.0.self_attn.in_proj_weight",
        )
        zf.writestr("archive/data/0", b"\x01\x02\x03\x04" * 256)
    return str(ckpt)


def test_build_flow_analytics_includes_non_flow_kinds_and_omits_na_ports():
    evidence = [
        Evidence(
            evidence_id="EV-000001",
            kind="wlan",
            summary="WLAN deauth burst",
            packet_refs=[1, 2],
            attributes={
                "protocol": "WLAN",
                "src": "aa:bb:cc:11:22:33",
                "dst": "ff:ff:ff:ff:ff:ff",
                "packets": 24,
                "bytes": 0,
                "time_epoch": 1700000001.0,
            },
        ),
        Evidence(
            evidence_id="EV-000002",
            kind="icmp",
            summary="ICMP ping sweep",
            packet_refs=[3, 4],
            attributes={
                "protocol": "ICMP",
                "src": "192.0.2.10",
                "dst": "198.51.100.5",
                "packets": 12,
                "bytes": 1008,
                "first_seen": 1700000002.0,
                "dst_port": "N/A",
            },
        ),
        Evidence(
            evidence_id="EV-000003",
            kind="http",
            summary="HTTP GET",
            packet_refs=[5],
            attributes={
                "protocol": "HTTP",
                "src": "192.0.2.10",
                "dst": "203.0.113.80",
                "dst_port": 8080,
                "packets": 6,
                "bytes": 2400,
                "first_seen": 1700000003.0,
            },
        ),
    ]
    analytics = build_flow_analytics(
        evidence,
        packet_lengths=[56, 56, 84, 420],
        inter_arrival_seconds=[0.0005, 0.004, 0.05, 0.4, 2.5],
    )
    assert any(row["ip"] == "aa:bb:cc:11:22:33" and row["packets"] == 24 for row in analytics["top_src_ips"])
    assert any(row["protocol"] == "WLAN" for row in analytics["top_protos"])
    assert all(row["port"] != "N/A" for row in analytics["top_dst_ports"])
    assert analytics["top_dst_ports"] == [{"port": "8080", "packets": 6}]
    assert sum(row["count"] for row in analytics["packet_size_histogram"]) == 4
    assert sum(row["count"] for row in analytics["iat_histogram"]) == 5
    # Zero-byte WLAN edge still survives via packet-count tie-breaker
    assert any(link["source"] == "aa:bb:cc:11:22:33" and link["packets"] == 24 for link in analytics["sankey_links"])
    assert any(node["id"] == "aa:bb:cc:11:22:33" for node in analytics["network_graph"]["nodes"])
    assert len(analytics["traffic_heatmap"]) >= 2


def test_pipeline_detects_wlan_deauth_flood_and_populates_histograms():
    acc = _Accumulator(packet_limit=5000, flow_limit=1000)
    for idx in range(1, 21):
        pkt = _Packet(
            frame=idx,
            timestamp=1700000000.0 + idx * 0.02,
            frame_len=64,
            proto="WLAN",
            src="aa:bb:cc:dd:ee:01",
            dst="ff:ff:ff:ff:ff:ff",
            tcp_srcport=None,
            tcp_dstport=None,
            udp_srcport=None,
            udp_dstport=None,
            dns_query=None,
            dns_rcode=None,
            tls_type=None,
            tcp_syn=None,
            eth_src="aa:bb:cc:dd:ee:01",
            eth_dst="ff:ff:ff:ff:ff:ff",
            protocol_label="WLAN",
            wlan_type_subtype=0x0C,
            wlan_bssid="aa:bb:cc:dd:ee:01",
        )
        acc.rows_seen += 1
        acc.rows_analyzed += 1
        acc.ingest_packet(pkt)

    bundle = _build_bundle(
        acc,
        capture_sha256="a" * 64,
        parser_state="completed",
        parser_detail="fixture",
        zeek_stage=Stage(name="zeek", state="skipped", detail="fixture"),
        parser_name="tshark-offline",
        triage_cfg=TriageConfig(etbert_checkpoint_path=None),
    )
    assert any(f.detector == "wlan_deauth_flood" for f in bundle.findings)
    assert bundle.triage is not None
    assert any(c.label == "WiFi_Attack" for c in bundle.triage.top_classes)
    assert bundle.flow_analytics is not None
    assert sum(row["count"] for row in bundle.flow_analytics["packet_size_histogram"]) == 20
    assert sum(row["count"] for row in bundle.flow_analytics["iat_histogram"]) == 19
    assert bundle.flow_analytics["top_src_ips"][0]["ip"] == "aa:bb:cc:dd:ee:01"
    assert bundle.flow_analytics["top_dst_ports"] == []


def test_pipeline_no_timestamp_capture_does_not_fabricate_iat_from_frame_numbers():
    acc = _Accumulator(packet_limit=5000, flow_limit=1000)
    for idx in range(1, 10):
        pkt = _Packet(
            frame=idx,
            timestamp=None,
            frame_len=128,
            proto="WLAN",
            src="aa:bb:cc:dd:ee:02",
            dst="ff:ff:ff:ff:ff:ff",
            tcp_srcport=None,
            tcp_dstport=None,
            udp_srcport=None,
            udp_dstport=None,
            dns_query=None,
            dns_rcode=None,
            tls_type=None,
            tcp_syn=None,
            protocol_label="WLAN",
            wlan_type_subtype=0x08,
        )
        acc.rows_seen += 1
        acc.rows_analyzed += 1
        acc.ingest_packet(pkt)

    bundle = _build_bundle(
        acc,
        capture_sha256="b" * 64,
        parser_state="completed",
        parser_detail="fixture",
        zeek_stage=Stage(name="zeek", state="skipped", detail="fixture"),
        parser_name="wireshark-csv-offline",
        triage_cfg=TriageConfig(etbert_checkpoint_path=None),
    )
    assert bundle.flow_analytics is not None
    assert sum(row["count"] for row in bundle.flow_analytics["packet_size_histogram"]) == 9
    assert sum(row["count"] for row in bundle.flow_analytics["iat_histogram"]) == 0


def test_triage_auto_runs_local_etbert_bin_unless_explicitly_disabled(tmp_path):
    ckpt = _make_dummy_etbert_bin(tmp_path)
    bundle = EvidenceBundle(
        capture_sha256="c" * 64,
        coverage=Coverage(packets_seen=4, packets_analyzed=4, truncated=False, parser="fixture"),
        evidence=[
            Evidence(
                evidence_id="EV-000001",
                kind="flow",
                summary="TLS flow",
                packet_refs=[1],
                attributes={
                    "protocol": "TLS",
                    "src": "192.0.2.10",
                    "dst": "198.51.100.20",
                    "src_port": 51000,
                    "dst_port": 443,
                    "packets": 6,
                    "bytes": 4200,
                    "data_len_sum": 3600,
                    "tls_handshake_types": "1,2",
                },
            ),
            Evidence(
                evidence_id="EV-000002",
                kind="wlan",
                summary="WLAN deauth flood",
                packet_refs=[2, 3],
                attributes={
                    "protocol": "WLAN",
                    "src": "aa:bb:cc:11:22:33",
                    "dst": "ff:ff:ff:ff:ff:ff",
                    "packets": 20,
                    "bytes": 1200,
                    "wlan_deauth_count": 20,
                },
            ),
        ],
        findings=[],
    )

    # Default etbert_enabled=False (not in model_fields_set) should auto-run local .bin
    auto_cfg = TriageConfig(etbert_checkpoint_path=ckpt)
    report_auto = triage.classify_bundle(bundle, auto_cfg)
    assert report_auto.etbert_scored_count == 1
    assert report_auto.decisions[0].etbert_label is not None
    assert report_auto.decisions[1].predicted_class == "WiFi_Attack"
    assert report_auto.decisions[1].decision == "escalate_attack"

    # Explicit opt-out disables local .bin scoring
    disabled_cfg = TriageConfig(etbert_checkpoint_path=ckpt, etbert_enabled=False)
    report_off = triage.classify_bundle(bundle, disabled_cfg)
    assert report_off.etbert_scored_count == 0


@pytest.mark.asyncio
async def test_probe_models_supports_ollama_tags_fallback():
    seen_paths: list[str] = []

    async def ollama_handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        if request.url.path == "/v1/models":
            return httpx.Response(404, json={"error": "not found"})
        if request.url.path == "/api/tags":
            return httpx.Response(
                200,
                json={
                    "models": [
                        {
                            "name": "qwen2.5:7b",
                            "model": "qwen2.5:7b",
                            "details": {"family": "qwen2", "parameter_size": "7.6B"},
                        }
                    ]
                },
            )
        return httpx.Response(404)

    cfg = AIConfig(
        enabled=False,
        provider="openai_compatible",
        base_url="http://127.0.0.1:11434/v1",
        allowed_origins=["http://127.0.0.1:11434"],
        data_boundary="local",
    )
    items, warning = await probe_models(cfg, transport=httpx.MockTransport(ollama_handler))
    assert warning is None
    assert items == [
        {
            "id": "qwen2.5:7b",
            "owned_by": "ollama",
            "type": "qwen2",
            "display_name": "qwen2.5:7b (7.6B)",
        }
    ]
    assert seen_paths == ["/v1/models", "/api/tags"]


def test_runtime_ai_config_and_probe_endpoints_with_workspace_persistence(tmp_path, monkeypatch):
    ws_file = tmp_path / "workspace.json"
    monkeypatch.setenv("PCAP_WORKSPACE_CONFIG", str(ws_file))
    monkeypatch.setenv("PCAP_USE_WORKSPACE_CONFIG", "1")
    monkeypatch.delenv("PCAP_ALLOW_REMOTE_WORKSPACE", raising=False)

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    settings = AppSettings(
        data_dir=data_dir,
        api_token=SecretStr(TOKEN),
        triage=TriageConfig(etbert_checkpoint_path=_make_dummy_etbert_bin(tmp_path)),
    )
    app = create_app(settings)
    client = TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"})

    # Initial GET reports editable runtime mode and effective ET-BERT activation
    initial = client.get("/api/v1/ai/config")
    assert initial.status_code == 200
    assert initial.json()["editable"] == "loopback_nonsecret_runtime_and_env"
    old_hash = initial.json()["policy_hash"]

    assert client.get("/api/v1/system/etbert").json()["etbert_enabled"] is True

    # Saving unrelated workspace field does not accidentally persist etbert_enabled=False
    other_dir = tmp_path / "data2"
    other_dir.mkdir()
    ws_upd = client.put("/api/v1/system/workspace", json={"data_dir": str(other_dir)})
    assert ws_upd.status_code == 200
    ws_saved = json.loads(ws_file.read_text(encoding="utf-8"))
    assert "etbert_enabled" not in ws_saved

    # Reject secret-bearing payload cleanly with 422 and no echo
    secret_bad = client.put(
        "/api/v1/ai/config",
        json={"api_key": "sk-secret-must-never-persist", "enabled": True},
    )
    assert secret_bad.status_code == 422
    assert "sk-secret" not in secret_bad.text

    # Reject enabled provider without matching allowed_origins
    origin_bad = client.put(
        "/api/v1/ai/config",
        json={
            "enabled": True,
            "provider": "openai_compatible",
            "base_url": "http://127.0.0.1:11434",
            "allowed_origins": [],
            "data_boundary": "local",
        },
    )
    assert origin_bad.status_code == 422

    # Valid loopback AI configuration succeeds and persists to workspace.json
    ok = client.put(
        "/api/v1/ai/config",
        json={
            "enabled": True,
            "provider": "openai_compatible",
            "base_url": "http://127.0.0.1:11434",
            "allowed_origins": ["http://127.0.0.1:11434"],
            "data_boundary": "local",
            "model": "qwen2.5:7b",
        },
    )
    assert ok.status_code == 200, ok.text
    payload = ok.json()
    assert payload["configuration"]["enabled"] is True
    assert payload["configuration"]["model"] == "qwen2.5:7b"
    assert payload["policy_hash"] != old_hash
    assert payload["policy_hash"] == profile_hash(app.state.settings)

    # Probe endpoint delegates cleanly through loopback guard
    async def fake_probe(_cfg):
        return ([{"id": "qwen2.5:7b", "owned_by": "ollama"}], None)

    monkeypatch.setattr(main_module, "probe_models", fake_probe)
    probed = client.post(
        "/api/v1/ai/models/probe",
        json={
            "provider": "openai_compatible",
            "base_url": "http://127.0.0.1:11434",
            "allowed_origins": ["http://127.0.0.1:11434"],
            "data_boundary": "local",
        },
    )
    assert probed.status_code == 200
    assert probed.json()["state"] == "completed"
    assert probed.json()["items"][0]["id"] == "qwen2.5:7b"

    # Reload via load_settings() recovers persisted non-secret AI settings cleanly
    monkeypatch.setenv("PCAP_DATA_DIR", str(other_dir))
    reloaded = load_settings()
    assert reloaded.ai.enabled is True
    assert reloaded.ai.model == "qwen2.5:7b"
    assert reloaded.ai.base_url == "http://127.0.0.1:11434"

    # Remote non-loopback caller is blocked cleanly
    monkeypatch.setattr(main_module, "is_loopback_client", lambda _host: False)
    denied_cfg = client.put("/api/v1/ai/config", json={"enabled": False})
    denied_probe = client.post("/api/v1/ai/models/probe", json={})
    assert denied_cfg.status_code == 403
    assert denied_cfg.json()["code"] == "ai_config_mutation_loopback_only"
    assert denied_probe.status_code == 403
    assert denied_probe.json()["code"] == "ai_probe_loopback_only"


def test_triage_falls_back_to_local_bin_when_etbert_http_returns_empty(tmp_path, monkeypatch):
    ckpt = _make_dummy_etbert_bin(tmp_path)
    bundle = EvidenceBundle(
        capture_sha256="d" * 64,
        coverage=Coverage(packets_seen=2, packets_analyzed=2, truncated=False, parser="fixture"),
        evidence=[
            Evidence(
                evidence_id="EV-000010",
                kind="flow",
                summary="TLS flow",
                packet_refs=[1],
                attributes={
                    "protocol": "TLS",
                    "src": "192.0.2.10",
                    "dst": "198.51.100.20",
                    "src_port": 51000,
                    "dst_port": 443,
                    "packets": 6,
                    "bytes": 4200,
                    "data_len_sum": 3600,
                    "tls_handshake_types": "1,2",
                },
            ),
        ],
        findings=[],
    )

    monkeypatch.setattr(triage, "score_with_etbert_http", lambda *_args, **_kwargs: {})
    cfg = TriageConfig(
        etbert_enabled=True,
        etbert_endpoint_url="http://127.0.0.1:9000/etbert/score",
        allowed_origins=["http://127.0.0.1:9000"],
        etbert_checkpoint_path=ckpt,
    )
    report = triage.classify_bundle(bundle, cfg, allow_network=True)
    assert report.etbert_scored_count == 1
    assert report.decisions[0].etbert_label is not None


def test_ai_runtime_credentials_are_memory_only_loopback_and_wired_to_provider(tmp_path, monkeypatch):
    from backend.app.llm import providers as llm_providers

    ws_file = tmp_path / "workspace.json"
    monkeypatch.setenv("PCAP_WORKSPACE_CONFIG", str(ws_file))
    monkeypatch.delenv("MANUS_API_URL", raising=False)
    monkeypatch.delenv("MANUS_API_KEY", raising=False)

    settings = AppSettings(
        data_dir=tmp_path / "data",
        api_token=TOKEN,
        ai=AIConfig(enabled=False),
    )
    app = create_app(settings)
    client = TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"})

    secret = "sk-manus-unit-test-secret-998877"
    try:
        # Store runtime API key strictly in RAM via loopback endpoint
        put_res = client.put(
            "/api/v1/ai/credentials",
            json={"provider": "manus", "api_key": secret},
        )
        assert put_res.status_code == 200, put_res.text
        put_body = put_res.json()
        assert put_body["configured"] is True
        assert put_body["provider"] == "manus"
        assert len(put_body["key_fingerprint"]) == 12
        assert put_body["runtime_keys"]["manus"] is True
        # Secret must NEVER be echoed back in response or written to workspace.json
        assert secret not in put_res.text

        # Configure Manus via non-secret /api/v1/ai/config without needing an explicit model name
        cfg_res = client.put(
            "/api/v1/ai/config",
            json={
                "enabled": True,
                "provider": "manus",
                "base_url": "https://api.manus.ai",
                "allowed_origins": ["https://api.manus.ai"],
                "data_boundary": "remote",
            },
        )
        assert cfg_res.status_code == 200, cfg_res.text
        cfg_body = cfg_res.json()
        assert cfg_body["manus_ready"] is True
        assert cfg_body["runtime_key_set"] is True
        assert cfg_body["configuration"]["model"] == "standard"
        assert cfg_body["configuration"]["timeout_seconds"] == 120
        assert secret not in cfg_res.text
        assert not ws_file.exists() or secret not in ws_file.read_text(encoding="utf-8")

        # Provider runtime resolves Manus API v2 task.create + x-manus-api-key (no Authorization header)
        rt = llm_providers._runtime(app.state.settings)
        assert rt.route == "manus_v2"
        assert rt.endpoint == "https://api.manus.ai/v2/task.create"
        assert rt.headers["x-manus-api-key"] == secret
        assert "authorization" not in rt.headers
        assert rt.model == "standard"

        # Clear key removes it from RAM cleanly
        del_res = client.delete("/api/v1/ai/credentials", params={"provider": "manus"})
        assert del_res.status_code == 200
        assert del_res.json()["cleared"] is True
        assert del_res.json()["runtime_keys"]["manus"] is False

        # Non-loopback caller is blocked on both PUT and DELETE
        monkeypatch.setattr(main_module, "is_loopback_client", lambda _host: False)
        denied_put = client.put("/api/v1/ai/credentials", json={"provider": "manus", "api_key": secret})
        denied_del = client.delete("/api/v1/ai/credentials", params={"provider": "manus"})
        assert denied_put.status_code == 403
        assert denied_put.json()["code"] == "ai_credentials_loopback_only"
        assert denied_del.status_code == 403
        assert denied_del.json()["code"] == "ai_credentials_loopback_only"
    finally:
        llm_providers.clear_runtime_api_key("manus")


