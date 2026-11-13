from __future__ import annotations

import hashlib
import json
import struct
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from backend.app.config import AppSettings
from backend.app.main import create_app, profile_hash
from backend.app.models import AnalysisRequest, Coverage, EvidenceBundle, AIResult
from backend.app.store import Store, StoreError

TOKEN = "test-only-operator-token-32-characters"
HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


@pytest.fixture
def app(tmp_path):
    settings = AppSettings(data_dir=tmp_path, api_token=SecretStr(TOKEN), upload_max_bytes=1024,
                           storage_max_bytes=8192, storage_max_captures=4, queue_limit=1, api_json_max_bytes=2048)
    return create_app(settings)


@pytest.fixture
def client(app):
    return TestClient(app, headers={"Authorization": "Bearer " + TOKEN})


def upload(client):
    response = client.post("/api/v1/captures", content=HEADER, headers={"Content-Type": "application/vnd.tcpdump.pcap"})
    assert response.status_code == 201, response.text
    return response.json()["capture_id"]


def test_auth_and_openapi(app):
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    denied = client.get("/api/v1/analyses")
    assert denied.status_code == 401
    assert denied.headers["content-type"].startswith("application/problem+json")
    schema = client.get("/openapi.json").json()
    assert schema["openapi"].startswith("3.1")
    assert schema["paths"]["/api/v1/analyses"]["post"]["security"] == [{"OperatorBearer": []}]
    assert TOKEN not in json.dumps(schema)


def test_missing_credentials_fail_closed(tmp_path):
    cfg = AppSettings(data_dir=tmp_path, api_token=None)
    c = TestClient(create_app(cfg))
    assert c.get("/api/v1/ai/config").status_code == 503


def test_streaming_header_size_and_hash(client, app):
    assert client.post("/api/v1/captures", content=b"not a pcap", headers={"Content-Type": "application/octet-stream"}).status_code == 400
    assert client.post("/api/v1/captures", content=HEADER, headers={"Content-Type": "text/plain"}).status_code == 415
    assert client.post("/api/v1/captures", content=HEADER + b"a" * 1025, headers={"Content-Type": "application/octet-stream"}).status_code == 413
    assert not list(app.state.store.captures_dir.iterdir())
    cid = upload(client)
    capture = app.state.store.capture(cid)
    assert capture["sha256"] == hashlib.sha256(HEADER).hexdigest()
    assert app.state.store.capture_path(cid).stat().st_mode & 0o777 == 0o600


def test_json_cap_chunked_and_no_error_input_echo(client):
    response = client.post("/api/v1/analyses", content=(b"x" * 1500 for _ in range(2)), headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    r = client.post("/api/v1/analyses", json={"capture_id": "secret-password-to-not-echo"})
    assert r.status_code == 422
    assert "secret-password" not in r.text


def test_queue_idempotency_and_cancel(client):
    cid = upload(client)
    body = {"capture_id": cid}
    first = client.post("/api/v1/analyses", json=body, headers={"Idempotency-Key": "request-one"})
    assert first.status_code == 202
    repeat = client.post("/api/v1/analyses", json=body, headers={"Idempotency-Key": "request-one"})
    assert repeat.json()["id"] == first.json()["id"]
    assert client.post("/api/v1/analyses", json=body).status_code == 429
    cancelled = client.post("/api/v1/analyses/" + first.json()["id"] + "/cancel")
    assert cancelled.json()["state"] == "cancelled"
    assert client.post("/api/v1/analyses", json=body).status_code == 202


def test_ai_opt_in_operator_and_config(client):
    cid = upload(client)
    assert client.post("/api/v1/analyses", json={"capture_id": cid, "ai_enabled": True}).status_code == 422
    assert client.post("/api/v1/analyses", json={"capture_id": cid, "ai_enabled": True, "ai_consent": True}).status_code == 409
    assert TOKEN not in client.get("/api/v1/ai/config").text
    assert client.get("/api/v1/ai/config/schema").json()["$schema"].endswith("2020-12/schema")


def test_storage_reservations(client):
    for _ in range(4):
        upload(client)
    assert client.post("/api/v1/captures", content=HEADER, headers={"Content-Type": "application/octet-stream"}).status_code == 507


def test_atomic_queue_admission_and_fencing(app, client):
    cid = upload(client)
    store = app.state.store
    request = AnalysisRequest(capture_id=cid)
    def admit(_):
        try:
            return store.create_job(request, "profile")
        except StoreError:
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(admit, range(8)))
    assert len([r for r in results if r]) == 1
    job = store.claim("parser")
    assert store.claim("parser") is None
    with store.connection(write=True) as db:
        db.execute("UPDATE jobs SET heartbeat=? WHERE id=?", (time.time() - 1000, job["id"]))
    assert store.recover_stale() == 1
    assert store.cancelled(job)
    assert not store.finish(job, "completed")
    assert store.job(job["id"])["state"] == "failed"


def test_evidence_survives_ai_failure_and_retention(app, client):
    cid = upload(client)
    store = app.state.store
    jid = store.create_job(AnalysisRequest(capture_id=cid), "profile")["id"]
    job = store.claim("parser")
    bundle = EvidenceBundle(capture_sha256=store.capture(cid)["sha256"], coverage=Coverage(packets_seen=0, packets_analyzed=0, truncated=False, parser="fixture"), evidence=[], findings=[])
    store.finish(job, "awaiting_ai", evidence=bundle.model_dump_json())
    ai_job = store.claim("ai")
    ai = AIResult(state="unavailable", provider="manus", error_code="upstream_timeout")
    store.finish(ai_job, "partial", ai_result=ai.model_dump_json())
    report = client.get(f"/api/v1/analyses/{jid}/report").json()
    assert report["ai"]["state"] == "unavailable"
    assert report["evidence"]["capture_sha256"] == bundle.capture_sha256
    with store.connection(write=True) as db:
        db.execute("UPDATE captures SET created=? WHERE id=?", (time.time() - 48*3600, cid))
    assert store.purge_expired(24) == 1
    assert not store.capture_path(cid).exists()
    assert client.get(f"/api/v1/analyses/{jid}").status_code == 404


def test_stale_ai_handoff_and_interrupted_narrator(app, client):
    cid = upload(client)
    store = app.state.store
    jid = store.create_job(AnalysisRequest(capture_id=cid), "profile")["id"]
    bundle = EvidenceBundle(capture_sha256=store.capture(cid)["sha256"], coverage=Coverage(packets_seen=0, packets_analyzed=0, truncated=False, parser="fixture"), evidence=[], findings=[])
    job = store.claim("parser")
    store.finish(job, "awaiting_ai", evidence=bundle.model_dump_json())
    with store.connection(write=True) as db:
        db.execute("UPDATE jobs SET updated_at='2000-01-01T00:00:00Z' WHERE id=?", (jid,))
    assert store.recover_stale() == 1
    r = client.get(f"/api/v1/analyses/{jid}/report").json()
    assert r["status"] == "partial" and r["ai"]["state"] == "unavailable"
    assert r["ai"]["error_code"] == "ai_worker_unavailable"
    jid2 = store.create_job(AnalysisRequest(capture_id=cid), "profile")["id"]
    job2 = store.claim("parser")
    store.finish(job2, "awaiting_ai", evidence=bundle.model_dump_json())
    ai_job = store.claim("ai")
    with store.connection(write=True) as db:
        db.execute("UPDATE jobs SET heartbeat=? WHERE id=?", (time.time()-1000, jid2))
    store.recover_stale()
    assert store.job(jid2)["ai_state"] == "unavailable"
    assert not store.finish(ai_job, "completed")


def test_cancel_handoff_and_lost_worker_state(app, client):
    cid = upload(client)
    store = app.state.store
    jid = store.create_job(AnalysisRequest(capture_id=cid), "profile")["id"]
    bundle = EvidenceBundle(capture_sha256=store.capture(cid)["sha256"], coverage=Coverage(packets_seen=0, packets_analyzed=0, truncated=False, parser="fixture"), evidence=[], findings=[])
    job = store.claim("parser")
    store.finish(job, "awaiting_ai", evidence=bundle.model_dump_json())
    store.cancel(jid)
    r = client.get(f"/api/v1/analyses/{jid}/report").json()
    assert r["status"] == "cancelled" and r["ai"]["state"] == "cancelled"
    jid2 = store.create_job(AnalysisRequest(capture_id=cid), "profile")["id"]
    job2 = store.claim("parser")
    store.cancel(jid2)
    with store.connection(write=True) as db:
        db.execute("UPDATE jobs SET heartbeat=? WHERE id=?", (time.time()-1000, jid2))
    store.recover_stale()
    assert store.job(jid2)["state"] == "cancelled"
    assert store.job(jid2)["ai_state"] == "cancelled"
    assert not store.finish(job2, "completed")


def test_cancel_race_does_not_publish_completed_ai_result(app, client):
    cid = upload(client)
    store = app.state.store
    jid = store.create_job(AnalysisRequest(capture_id=cid), "profile")["id"]
    job = store.claim("parser")
    store.cancel(jid)
    result = AIResult(state="completed", provider="manus")
    store.finish(job, "completed", ai_result=result.model_dump_json())
    assert store.job(jid)["state"] == "cancelled"
    assert store.job(jid)["ai_state"] == "cancelled"
