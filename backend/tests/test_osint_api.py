from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import struct
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.config import AppSettings
from backend.app.main import create_app
from backend.app.models import AnalysisRequest, Coverage, Evidence, EvidenceBundle
from backend.app.osint_service import OSINTService
from backend.app.store import Store, StoreError


TOKEN = "test-osint-operator-token-32-characters"
HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _make_app(tmp_path: Path):
    settings = AppSettings(data_dir=tmp_path, api_token=SecretStr(TOKEN), upload_max_bytes=1024, storage_max_bytes=8192)
    app = create_app(settings)
    client = TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"})
    return app, client


def _persist_public_ip_job(app, client):
    capture_response = client.post("/api/v1/captures", content=HEADER, headers={"Content-Type": "application/vnd.tcpdump.pcap"})
    assert capture_response.status_code == 201
    capture_id = capture_response.json()["capture_id"]
    store = app.state.store
    job = store.create_job(AnalysisRequest(capture_id=capture_id), "osint-test-profile")
    lease = store.claim("parser")
    bundle = EvidenceBundle(
        capture_sha256=store.capture(capture_id)["sha256"],
        coverage=Coverage(packets_seen=1, packets_analyzed=1, truncated=False, parser="fixture"),
        evidence=[Evidence(
            evidence_id="EV-000001",
            kind="flow",
            summary="Synthetic public endpoint",
            packet_refs=[1],
            attributes={"src_ip": "8.8.8.8", "dst_ip": "10.2.3.4"},
        )],
        findings=[],
    )
    assert store.finish(lease, "awaiting_ai", evidence=bundle.model_dump_json())
    candidate_id = "IOC-" + hashlib.sha256(b"ipv4:8.8.8.8").hexdigest()[:16]
    return job["id"], candidate_id


def _payload(
    candidate_id: str,
    operation_id: str = "a" * 32,
    *,
    consent: bool = True,
    accept_uncertain_retry_risk: bool = False,
):
    return {
        "operation_id": operation_id,
        "candidate_ids": [candidate_id],
        "providers": ["virustotal"],
        "consent": consent,
        "accept_uncertain_retry_risk": accept_uncertain_retry_risk,
    }


def test_osint_routes_require_auth_and_capabilities_hide_credentials(tmp_path: Path):
    app, client = _make_app(tmp_path)
    unauthenticated = TestClient(app)
    assert unauthenticated.get("/api/v1/osint/capabilities").status_code == 401
    app.state.osint_service = OSINTService(env={"PCAP_OSINT_VIRUSTOTAL_API_KEY": "should-never-appear"})
    response = client.get("/api/v1/osint/capabilities")
    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert response.json()["available"] is False
    assert "should-never-appear" not in response.text


def test_existing_osint_audit_schema_migrates_without_losing_rows(tmp_path: Path):
    root = tmp_path / "existing-data"
    root.mkdir()
    db_path = root / "metadata.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.execute("""CREATE TABLE osint_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            providers TEXT NOT NULL,
            indicator_count INTEGER NOT NULL,
            outcome TEXT NOT NULL,
            consent INTEGER NOT NULL
        )""")
        db.execute("INSERT INTO osint_audit(analysis_id,requested_at,providers,indicator_count,outcome,consent) VALUES(?,?,?,?,?,?)",
                   ("a" * 32, "2026-01-01T00:00:00Z", '["virustotal"]', 1, "completed", 1))

    Store(root)

    with sqlite3.connect(db_path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(osint_audit)")}
        row = db.execute("SELECT analysis_id,operation_id,outcome FROM osint_audit").fetchone()
        indexes = {item[1] for item in db.execute("PRAGMA index_list(osint_audit)")}
    assert "operation_id" in columns
    assert "request_fingerprint" in columns
    assert row == ("a" * 32, None, "completed")
    assert "osint_audit_operation" in indexes


def test_candidate_preview_is_local_and_contains_only_structured_evidence_indicators(tmp_path: Path):
    app, client = _make_app(tmp_path)
    analysis_id, _ = _persist_public_ip_job(app, client)

    response = client.get(f"/api/v1/analyses/{analysis_id}/osint/candidates")

    assert response.status_code == 200
    data = response.json()
    assert data["lookup_is_external"] is True
    assert data["consent_required_for_lookup"] is True
    assert data["candidate_count"] == 1
    assert data["candidates"][0]["indicator"] == "8.8.8.8"
    assert data["candidates"][0]["evidence_ids"] == ["EV-000001"]


def test_lookup_denied_without_per_operation_consent_and_audits_no_indicator(tmp_path: Path):
    app, client = _make_app(tmp_path)
    analysis_id, candidate_id = _persist_public_ip_job(app, client)

    response = client.post(f"/api/v1/analyses/{analysis_id}/osint", json=_payload(candidate_id, consent=False))

    assert response.status_code == 428
    assert response.json()["code"] == "osint_consent_required"
    with app.state.store.connection() as db:
        row = db.execute("SELECT * FROM osint_audit WHERE analysis_id=?", (analysis_id,)).fetchone()
    assert row is not None
    stored = json.dumps(dict(row))
    assert "8.8.8.8" not in stored
    assert "should-never-appear" not in stored
    assert row["consent"] == 0
    assert row["outcome"] == "consent_denied"


@pytest.mark.parametrize("malformed", [
    {"candidate_ids": ["IOC-0000000000000000"], "providers": ["virustotal"], "consent": True},
    {"operation_id": "b" * 32, "candidate_ids": ["IOC-0000000000000000"], "providers": ["virustotal"], "consent": "true"},
])
def test_lookup_request_schema_fails_closed(tmp_path: Path, malformed: dict[str, object]):
    app, client = _make_app(tmp_path)
    analysis_id, _ = _persist_public_ip_job(app, client)
    response = client.post(f"/api/v1/analyses/{analysis_id}/osint", json=malformed)
    assert response.status_code == 422


def test_admin_switch_off_never_calls_provider_and_result_is_retained(tmp_path: Path):
    app, client = _make_app(tmp_path)
    analysis_id, candidate_id = _persist_public_ip_job(app, client)
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": {"attributes": {"reputation": 1}}})

    app.state.osint_service = OSINTService(
        transport=httpx.MockTransport(handler),
        env={"PCAP_OSINT_VIRUSTOTAL_API_KEY": "test-api-key-12345", "PCAP_OSINT_VIRUSTOTAL_PREMIUM_LICENSE_ACK": "1"},
        minimum_interval_seconds=0,
    )
    response = client.post(f"/api/v1/analyses/{analysis_id}/osint", json=_payload(candidate_id))

    assert response.status_code == 200
    assert response.json()["state"] == "disabled"
    assert response.json()["error_code"] == "osint_disabled_by_operator"
    assert calls == 0
    report = client.get(f"/api/v1/analyses/{analysis_id}/report")
    assert report.status_code == 200
    assert report.json()["osint"]["state"] == "disabled"


@pytest.mark.asyncio
async def test_operation_id_is_idempotent_and_audit_stores_no_raw_indicator(tmp_path: Path):
    app, client = _make_app(tmp_path)
    analysis_id, candidate_id = _persist_public_ip_job(app, client)
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 4, "undetected": 10},
            "reputation": 0,
        }}})

    app.state.settings.osint_enabled = True
    app.state.osint_service = OSINTService(
        transport=httpx.MockTransport(handler),
        env={"PCAP_OSINT_VIRUSTOTAL_API_KEY": "test-api-key-12345", "PCAP_OSINT_VIRUSTOTAL_PREMIUM_LICENSE_ACK": "1"},
        minimum_interval_seconds=0,
    )
    payload = _payload(candidate_id, operation_id="c" * 32)
    first = client.post(f"/api/v1/analyses/{analysis_id}/osint", json=payload)
    second = client.post(f"/api/v1/analyses/{analysis_id}/osint", json=payload)

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert first.json()["state"] == "completed"
    assert first.json()["results"][0]["summary"]["malicious"] == 1
    assert calls == 1
    report = client.get(f"/api/v1/analyses/{analysis_id}/report").json()
    assert report["osint"]["operation_id"] == "c" * 32
    with app.state.store.connection() as db:
        row = db.execute("SELECT * FROM osint_audit WHERE analysis_id=?", (analysis_id,)).fetchone()
    assert row is not None
    stored = json.dumps(dict(row))
    assert "8.8.8.8" not in stored
    assert "test-api-key-12345" not in stored
    assert row["consent"] == 1
    assert row["indicator_count"] == 1
    assert len(row["request_fingerprint"]) == 64
    assert "8.8.8.8" not in row["request_fingerprint"]


def test_operation_id_cannot_be_reused_for_a_different_request(tmp_path: Path):
    app, client = _make_app(tmp_path)
    analysis_id, candidate_id = _persist_public_ip_job(app, client)
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": {"attributes": {"reputation": 0}}})

    app.state.settings.osint_enabled = True
    app.state.osint_service = OSINTService(
        transport=httpx.MockTransport(handler),
        env={"PCAP_OSINT_VIRUSTOTAL_API_KEY": "test-api-key-12345", "PCAP_OSINT_VIRUSTOTAL_PREMIUM_LICENSE_ACK": "1"},
        minimum_interval_seconds=0,
    )
    operation_id = "d" * 32
    first = client.post(f"/api/v1/analyses/{analysis_id}/osint", json=_payload(candidate_id, operation_id))
    changed = client.post(
        f"/api/v1/analyses/{analysis_id}/osint",
        json=_payload("IOC-" + "0" * 16, operation_id),
    )

    assert first.status_code == 200
    assert changed.status_code == 409
    assert changed.json()["code"] == "osint_operation_id_conflict"
    assert calls == 1


def test_unresolved_operation_is_surfaced_without_indicators_and_blocks_new_lookups(tmp_path: Path):
    app, client = _make_app(tmp_path)
    analysis_id, candidate_id = _persist_public_ip_job(app, client)
    app.state.store.record_osint_audit(
        analysis_id,
        requested_at="2026-11-17T00:00:00Z",
        providers=["virustotal"],
        indicator_count=1,
        outcome="started",
        consent=True,
        operation_id="e" * 32,
        request_fingerprint="f" * 64,
    )
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": {"attributes": {"reputation": 0}}})

    app.state.settings.osint_enabled = True
    app.state.osint_service = OSINTService(
        transport=httpx.MockTransport(handler),
        env={"PCAP_OSINT_VIRUSTOTAL_API_KEY": "test-api-key-12345", "PCAP_OSINT_VIRUSTOTAL_PREMIUM_LICENSE_ACK": "1"},
        minimum_interval_seconds=0,
    )
    preview = client.get(f"/api/v1/analyses/{analysis_id}/osint/candidates")
    blocked = client.post(
        f"/api/v1/analyses/{analysis_id}/osint",
        json=_payload(candidate_id, operation_id="9" * 32),
    )

    assert preview.status_code == 200
    pending = preview.json()["pending_operation"]
    assert pending == {
        "operation_id": "e" * 32,
        "requested_at": "2026-11-17T00:00:00Z",
        "providers": ["virustotal"],
        "indicator_count": 1,
        "state": "uncertain",
    }
    assert "8.8.8.8" not in json.dumps(pending)
    assert "request_fingerprint" not in pending
    assert blocked.status_code == 409
    assert blocked.json()["code"] == "osint_previous_operation_unresolved"
    assert calls == 0


def test_provider_timeout_stays_uncertain_until_explicit_duplicate_charge_override(tmp_path: Path):
    app, client = _make_app(tmp_path)
    analysis_id, candidate_id = _persist_public_ip_job(app, client)
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ReadTimeout("synthetic provider timeout")
        return httpx.Response(200, json={"data": {"attributes": {"reputation": 0}}})

    app.state.settings.osint_enabled = True
    app.state.osint_service = OSINTService(
        transport=httpx.MockTransport(handler),
        env={"PCAP_OSINT_VIRUSTOTAL_API_KEY": "test-api-key-12345", "PCAP_OSINT_VIRUSTOTAL_PREMIUM_LICENSE_ACK": "1"},
        minimum_interval_seconds=0,
    )
    first = client.post(
        f"/api/v1/analyses/{analysis_id}/osint",
        json=_payload(candidate_id, operation_id="a" * 32),
    )
    preview = client.get(f"/api/v1/analyses/{analysis_id}/osint/candidates")
    blocked = client.post(
        f"/api/v1/analyses/{analysis_id}/osint",
        json=_payload(candidate_id, operation_id="b" * 32),
    )

    assert first.status_code == 200
    assert first.json()["results"][0]["state"] == "provider_timeout"
    assert preview.json()["pending_operation"]["operation_id"] == "a" * 32
    assert blocked.status_code == 409
    assert blocked.json()["code"] == "osint_previous_operation_unresolved"
    assert calls == 1

    override = client.post(
        f"/api/v1/analyses/{analysis_id}/osint",
        json=_payload(candidate_id, operation_id="c" * 32, accept_uncertain_retry_risk=True),
    )
    assert override.status_code == 200
    assert override.json()["results"][0]["state"] == "completed"
    assert calls == 2
    with app.state.store.connection() as db:
        audit_states = [row["outcome"] for row in db.execute(
            "SELECT outcome FROM osint_audit WHERE analysis_id=?", (analysis_id,)
        ).fetchall()]
    assert "operator_override" in audit_states
    assert "completed" in audit_states
    assert client.get(f"/api/v1/analyses/{analysis_id}/osint/candidates").json()["pending_operation"] is None


def test_osint_operation_tombstones_are_capped_per_analysis(tmp_path: Path):
    app, client = _make_app(tmp_path)
    analysis_id, _ = _persist_public_ip_job(app, client)
    store = app.state.store
    for index in range(100):
        store.record_osint_audit(
            analysis_id,
            requested_at="2026-11-17T00:00:00Z",
            providers=["virustotal"],
            indicator_count=1,
            outcome="completed",
            consent=True,
            operation_id=f"{index:032x}",
            request_fingerprint=f"{index:064x}",
        )
    with pytest.raises(StoreError) as error:
        store.record_osint_audit(
            analysis_id,
            requested_at="2026-11-17T00:00:00Z",
            providers=["virustotal"],
            indicator_count=1,
            outcome="completed",
            consent=True,
            operation_id=f"{100:032x}",
            request_fingerprint=f"{100:064x}",
        )

    assert error.value.status == 429
    with store.connection() as db:
        count = db.execute(
            "SELECT COUNT(*) FROM osint_audit WHERE analysis_id=? AND operation_id IS NOT NULL", (analysis_id,)
        ).fetchone()[0]
    assert count == 100
