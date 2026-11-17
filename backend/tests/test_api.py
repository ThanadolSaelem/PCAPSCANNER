from __future__ import annotations

import hashlib
import json
import struct
import errno
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from backend.app import store as store_module
from backend.app import worker as worker_module
from backend.app.config import AIConfig, AppSettings
from backend.app import main as main_module
from backend.app.main import create_app, profile_hash
from backend.app.models import AnalysisRequest, Coverage, Evidence, EvidenceBundle, AIResult
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


def persist_evidence_job(app, client):
    capture_id = upload(client)
    store = app.state.store
    analysis_id = store.create_job(AnalysisRequest(capture_id=capture_id), "profile")["id"]
    lease = store.claim("parser")
    bundle = EvidenceBundle(
        capture_sha256=store.capture(capture_id)["sha256"],
        coverage=Coverage(packets_seen=1, packets_analyzed=1, truncated=False, parser="fixture"),
        evidence=[
            Evidence(
                evidence_id="EV-000001",
                kind="dns",
                summary="DNS request for private.example from 192.0.2.44",
                packet_refs=[1],
                attributes={"protocol": "DNS", "src": "192.0.2.44", "query": "private.example", "dns_qry_type": 1},
            )
        ],
        findings=[],
    )
    assert store.finish(lease, "awaiting_ai", evidence=bundle.model_dump_json())
    return analysis_id, bundle


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


def test_batch_limits_are_exposed_from_runtime_settings(client, app):
    app.state.settings.batch_max_files = 3
    app.state.settings.batch_max_total_bytes = 4096
    app.state.settings.batch_admission_concurrency = 1
    limits = client.get("/api/v1/system/capabilities").json()["limits"]
    assert limits["batch_max_files"] == 3
    assert limits["batch_max_total_bytes"] == 4096
    assert limits["batch_admission_concurrency"] == 1


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


def test_physical_disk_reserve_serializes_all_service_managed_writers(app, monkeypatch):
    store = app.state.store
    store.disk_reserve_bytes = 64
    state_lock = threading.Lock()
    remaining = [120]

    def fake_disk_usage(_path):
        with state_lock:
            return SimpleNamespace(free=remaining[0])

    monkeypatch.setattr(store_module.shutil, "disk_usage", fake_disk_usage)

    class _TrackedWriter:
        def __init__(self, path: Path):
            self.handle = path.open("wb")

        def write(self, data: bytes) -> int:
            written = self.handle.write(data)
            with state_lock:
                remaining[0] -= written
            return written

        def flush(self):
            return self.handle.flush()

        def fileno(self) -> int:
            return self.handle.fileno()

        def close(self) -> None:
            self.handle.close()

    writers = {
        "upload": _TrackedWriter(store.captures_dir / ("a" * 32 + ".pcap")),
        "batch": _TrackedWriter(store.batch_staging_dir / ("b" * 32 + ".upload")),
        "snapshot": _TrackedWriter(store.worker_scratch_dir / "reserve-test.bin"),
    }
    data = b"x" * 40

    def write_one(item):
        name, writer = item
        try:
            if name == "upload":
                store.write_capture_chunk(writer, data)
            elif name == "batch":
                store.write_batch_staging_chunk(writer, data, 1024)
            else:
                store.write_worker_snapshot_chunk(writer, data)
            return "ok"
        except StoreError as exc:
            return exc.code
        finally:
            writer.close()

    with ThreadPoolExecutor(max_workers=3) as pool:
        outcomes = list(pool.map(write_one, writers.items()))
    assert outcomes.count("ok") == 1
    assert outcomes.count("insufficient_disk_space") == 2


def test_capture_write_maps_fsync_enospc_to_fail_closed_storage_error(app, monkeypatch):
    path = app.state.store.captures_dir / ("c" * 32 + ".pcap")
    handle = path.open("wb")

    def fail_fsync(_fd):
        raise OSError(errno.ENOSPC, "synthetic disk full")

    monkeypatch.setattr(store_module.os, "fsync", fail_fsync)
    try:
        with pytest.raises(StoreError) as exc_info:
            app.state.store.write_capture_chunk(handle, b"bounded")
    finally:
        handle.close()
    assert exc_info.value.code == "insufficient_disk_space"


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


def test_grounded_chat_requires_per_turn_consent_and_cites_privacy_safe_evidence(app, client, monkeypatch):
    analysis_id, _bundle = persist_evidence_job(app, client)
    calls = []

    async def fake_chat(prompt, _settings):
        calls.append(prompt)
        return json.dumps({"claims": [{"claim": "The retained evidence records one DNS request.", "evidence_ids": ["EV-000001"]}]})

    monkeypatch.setattr(main_module, "generate_chat_completion", fake_chat)
    denied = client.post(
        f"/api/v1/analyses/{analysis_id}/chat",
        json={"question": "What happened?", "consent": False},
    )
    assert denied.status_code == 200
    assert denied.json()["state"] == "consent_required"
    assert calls == []

    app.state.settings = app.state.settings.model_copy(
        update={
            "ai": AIConfig(
                enabled=True,
                provider="openai_compatible",
                base_url="http://127.0.0.1:11434",
                allowed_origins=["http://127.0.0.1:11434"],
                data_boundary="local",
                model="test-model",
            )
        }
    )
    sent = client.post(
        f"/api/v1/analyses/{analysis_id}/chat",
        json={"question": "Explain http://203.0.113.9/private/path and private.example", "consent": True},
    )
    assert sent.status_code == 200, sent.text
    payload = sent.json()
    assert payload["state"] == "completed"
    assert payload["claims"][0]["evidence_ids"] == ["EV-000001"]
    assert payload["transcript_persisted"] is False
    assert len(calls) == 1
    assert "192.0.2.44" not in calls[0]
    assert "private.example" not in calls[0]
    assert "203.0.113.9" not in calls[0]
    assert "/private/path" not in calls[0]
    assert "EV-000001" in calls[0]
    assert "chat" not in app.state.store.job(analysis_id)

    app.state.settings = app.state.settings.model_copy(
        update={"ai": app.state.settings.ai.model_copy(update={"context_window_tokens": 513})}
    )
    too_small = client.post(
        f"/api/v1/analyses/{analysis_id}/chat",
        json={"question": "Explain the evidence", "consent": True},
    )
    assert too_small.status_code == 409
    assert too_small.json()["code"] == "ai_context_window_too_small"
    assert len(calls) == 1

    malformed_consent = client.post(
        f"/api/v1/analyses/{analysis_id}/chat",
        json={"question": "test", "consent": "true"},
    )
    assert malformed_consent.status_code == 422


def test_stix_export_endpoint_is_authenticated_and_metadata_only(app, client):
    analysis_id, _bundle = persist_evidence_job(app, client)
    response = client.get(f"/api/v1/analyses/{analysis_id}/export.stix.json")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/stix+json")
    payload = response.json()
    assert payload["type"] == "bundle"
    assert payload["objects"] and all(obj["spec_version"] == "2.1" for obj in payload["objects"])
    serialized = response.text
    assert "private.example" in serialized
    assert "192.0.2.44" in serialized
    assert "RAW PAYLOAD" not in serialized
    assert "/private/path" not in serialized
    unauthenticated = TestClient(app).get(f"/api/v1/analyses/{analysis_id}/export.stix.json")
    assert unauthenticated.status_code == 401


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


def test_batch_intake_is_atomic_idempotent_and_uses_opaque_paths(client, app):
    files = [("files", ("../../operator-secret.pcap", HEADER, "application/octet-stream"))]
    first = client.post("/api/v1/batches", files=files, headers={"Idempotency-Key": "batch-once"})
    assert first.status_code == 202, first.text
    manifest = first.json()
    assert manifest["state"] == "queued"
    assert manifest["total_items"] == 1
    item = manifest["items"][0]
    assert item["format"] == "pcap"
    assert item["sha256"] == hashlib.sha256(HEADER).hexdigest()
    assert "filename" not in item
    assert "operator-secret" not in first.text
    capture = app.state.store.capture(item["capture_id"])
    assert capture["filename"].startswith("batch-")
    assert "operator-secret" not in capture["filename"]
    assert app.state.store.capture_path(item["capture_id"]).stat().st_mode & 0o777 == 0o600

    repeated = client.post("/api/v1/batches", files=files, headers={"Idempotency-Key": "batch-once"})
    assert repeated.status_code == 202, repeated.text
    assert repeated.json()["batch_id"] == manifest["batch_id"]
    with app.state.store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 1

    changed = client.post(
        "/api/v1/batches",
        files=[("files", ("other.pcap", HEADER + b"x", "application/octet-stream"))],
        headers={"Idempotency-Key": "batch-once"},
    )
    assert changed.status_code == 409
    assert changed.json()["code"] == "idempotency_conflict"
    assert client.get(f"/api/v1/batches/{manifest['batch_id']}").json()["items"][0]["analysis_id"] == item["analysis_id"]

    too_many_for_queue = client.post(
        "/api/v1/batches",
        files=[
            ("files", ("one.pcap", HEADER, "application/octet-stream")),
            ("files", ("two.pcap", HEADER, "application/octet-stream")),
        ],
    )
    assert too_many_for_queue.status_code == 429
    assert too_many_for_queue.headers["retry-after"] == "5"
    with app.state.store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 1
    assert list(app.state.store.batch_staging_dir.iterdir()) == []


def test_batch_auth_precedes_body_and_invalid_uploads_leave_no_staging_files(app):
    unauthenticated = TestClient(app)
    denied = unauthenticated.post(
        "/api/v1/batches",
        files=[("files", ("cap.pcap", HEADER, "application/octet-stream"))],
    )
    assert denied.status_code == 401
    assert list(app.state.store.batch_staging_dir.iterdir()) == []

    client = TestClient(app, headers={"Authorization": "Bearer " + TOKEN})
    bad_suffix = client.post(
        "/api/v1/batches",
        files=[("files", ("cap.txt", HEADER, "application/octet-stream"))],
    )
    assert bad_suffix.status_code == 400
    assert bad_suffix.json()["code"] == "invalid_capture_suffix"

    bad_magic = client.post(
        "/api/v1/batches",
        files=[("files", ("cap.pcap", b"not-a-capture", "application/octet-stream"))],
    )
    assert bad_magic.status_code == 400
    assert bad_magic.json()["code"] == "invalid_capture_magic"

    too_large = client.post(
        "/api/v1/batches",
        files=[("files", ("large.pcap", HEADER + b"x" * 1025, "application/octet-stream"))],
    )
    assert too_large.status_code == 413
    assert list(app.state.store.batch_staging_dir.iterdir()) == []
    with app.state.store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 0


def test_batch_cancel_obeys_running_worker_fence(client, app):
    created = client.post(
        "/api/v1/batches",
        files=[("files", ("cap.pcap", HEADER, "application/octet-stream"))],
    )
    assert created.status_code == 202, created.text
    batch_id = created.json()["batch_id"]
    worker_claim = app.state.store.claim("parser")
    assert worker_claim is not None

    cancel_response = client.post(f"/api/v1/batches/{batch_id}/cancel")
    assert cancel_response.status_code == 200
    assert cancel_response.json()["items"][0]["state"] == "parsing"
    assert app.state.store.job(worker_claim["id"])["cancel_requested"] is True

    assert app.state.store.finish(worker_claim, "completed")
    final = client.get(f"/api/v1/batches/{batch_id}")
    assert final.status_code == 200
    assert final.json()["state"] == "cancelled"
    assert final.json()["items"][0]["state"] == "cancelled"


def test_batch_partial_count_is_not_reported_as_failed(client, app):
    created = client.post(
        "/api/v1/batches",
        files=[("files", ("cap.pcap", HEADER, "application/octet-stream"))],
    )
    assert created.status_code == 202, created.text
    batch_id = created.json()["batch_id"]
    item = created.json()["items"][0]
    store = app.state.store
    job = store.claim("parser")
    assert job is not None
    bundle = EvidenceBundle(
        capture_sha256=item["sha256"],
        coverage=Coverage(packets_seen=0, packets_analyzed=0, truncated=True, parser="test"),
        evidence=[],
        findings=[],
    )
    assert store.finish(job, "partial", evidence=bundle.model_dump_json())

    result = client.get(f"/api/v1/batches/{batch_id}")
    assert result.status_code == 200
    assert result.json()["state"] == "partial"
    assert result.json()["partial_items"] == 1
    assert result.json()["failed_items"] == 0
    listed = client.get("/api/v1/batches?limit=5")
    assert listed.status_code == 200
    assert listed.json()[0]["batch_id"] == batch_id


def test_batch_restart_cleanup_preserves_live_files_and_removes_crash_orphans(client, app):
    created = client.post(
        "/api/v1/batches",
        files=[("files", ("cap.pcap", HEADER, "application/octet-stream"))],
    )
    assert created.status_code == 202, created.text
    live_id = created.json()["items"][0]["capture_id"]
    store = app.state.store
    live_path = store.capture_path(live_id)
    assert live_path.exists()

    orphan_id = "f" * 32
    orphan_path = store.capture_path(orphan_id)
    orphan_path.write_bytes(b"orphaned rename before SQLite commit")
    stale_stage = store.batch_staging_dir / ("e" * 32 + ".upload")
    active_stage = store.batch_staging_dir / ("d" * 32 + ".upload")
    stale_stage.write_bytes(b"staged before process crash")
    active_stage.write_bytes(b"belongs to an uploader holding a slot")
    settings = app.state.settings

    def reopen_store():
        return Store(
            settings.data_dir,
            queue_limit=settings.queue_limit,
            storage_max_bytes=settings.storage_max_bytes,
            storage_max_captures=settings.storage_max_captures,
            disk_reserve_bytes=settings.disk_reserve_bytes,
            batch_admission_concurrency=settings.batch_admission_concurrency,
        )

    with store.batch_upload_slot(settings.batch_admission_concurrency):
        reopen_store()
        assert stale_stage.exists() and active_stage.exists()
    recovered = reopen_store()
    assert live_path.exists()
    assert not orphan_path.exists()
    assert not stale_stage.exists()
    assert not active_stage.exists()
    assert recovered.capture(live_id)["sha256"] == created.json()["items"][0]["sha256"]


def test_batch_staging_writer_enforces_global_quota_and_disk_reserve(monkeypatch, app):
    store = app.state.store
    staged = store.batch_staging_dir / ("a" * 32 + ".upload")
    monkeypatch.setattr(
        store_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=store.disk_reserve_bytes + 1),
    )
    with pytest.raises(StoreError) as capture_error:
        store.reserve_capture(2)
    assert capture_error.value.code == "insufficient_disk_space"
    with store.batch_upload_slot(app.state.settings.batch_admission_concurrency):
        with staged.open("wb") as handle:
            with pytest.raises(StoreError) as disk_error:
                store.write_batch_staging_chunk(handle, b"two", 16)
        assert disk_error.value.code == "insufficient_disk_space"
        assert staged.stat().st_size == 0

        monkeypatch.setattr(
            store_module.shutil,
            "disk_usage",
            lambda _path: SimpleNamespace(free=store.disk_reserve_bytes + 1024),
        )
        with staged.open("wb") as handle:
            with pytest.raises(StoreError) as quota_error:
                store.write_batch_staging_chunk(handle, b"two", 1)
        assert quota_error.value.code == "batch_staging_quota"
        assert staged.stat().st_size == 0


def test_chunked_upload_preserves_physical_disk_reserve_with_storage_quota(monkeypatch, app):
    store = app.state.store
    upload_id = store.init_chunk_upload("chunked.pcap", 2, "pcap")
    monkeypatch.setattr(
        store_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=store.disk_reserve_bytes),
    )
    with pytest.raises(StoreError) as error:
        store.append_upload_chunk(upload_id, 0, b"x")
    assert error.value.code == "insufficient_disk_space"
    assert store.pending_upload(upload_id)["bytes_received"] == 0


def test_local_capture_worker_parses_verified_snapshot_not_mutable_source(app, tmp_path, monkeypatch):
    settings = app.state.settings
    store = app.state.store
    source_path = tmp_path / "local-source.pcap"
    source_path.write_bytes(HEADER)
    digest = hashlib.sha256(HEADER).hexdigest()
    capture = store.register_local_capture(source_path, source_path.name, "pcap", len(HEADER), digest)
    job_id = store.create_job(AnalysisRequest(capture_id=capture["id"]), "profile")["id"]
    parsed_bytes: list[bytes] = []
    parsed_paths: list[Path] = []
    bundle = EvidenceBundle(
        capture_sha256=digest,
        coverage=Coverage(packets_seen=1, packets_analyzed=1, truncated=False, parser="snapshot-test"),
        evidence=[],
        findings=[],
    )

    def fake_analyze_capture(path, _digest, _settings, **_kwargs):
        parsed_path = Path(path)
        parsed_paths.append(parsed_path)
        source_path.write_bytes(b"tampered while parser is opening input")
        parsed_bytes.append(parsed_path.read_bytes())
        source_path.write_bytes(HEADER)
        return bundle

    monkeypatch.setattr(worker_module, "analyze_capture", fake_analyze_capture)
    assert worker_module.run_once(store, settings)
    assert parsed_bytes == [HEADER]
    assert parsed_paths[0] != source_path
    assert store.job(job_id)["state"] == "completed"
    assert list(store.worker_scratch_dir.iterdir()) == []


def test_unknown_length_direct_upload_charges_actual_bytes_against_storage_quota(client, app):
    app.state.settings.upload_max_bytes = 0
    app.state.store.storage_max_bytes = len(HEADER) + 2
    response = client.post(
        "/api/v1/captures",
        content=iter((HEADER, b"over")),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 507, response.text
    assert response.json()["code"] == "capture_storage_quota"
    with app.state.store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 0
    assert list(app.state.store.captures_dir.iterdir()) == []


def test_direct_upload_enforces_declared_content_length(client, app):
    response = client.post(
        "/api/v1/captures",
        content=HEADER,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(HEADER) + 1),
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "content_length_mismatch"
    with app.state.store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 0


def _init_chunk_upload(client, expected_bytes: int):
    response = client.post(
        "/api/v1/captures/uploads",
        json={"filename": "chunked.pcap", "total_bytes": expected_bytes},
    )
    assert response.status_code == 201, response.text
    return response.json()["upload_id"]


def test_incomplete_chunk_upload_cannot_be_marked_ready(client, app):
    upload_id = _init_chunk_upload(client, len(HEADER))
    appended = client.put(
        f"/api/v1/captures/uploads/{upload_id}/chunk?offset=0",
        content=HEADER[:-1],
        headers={"Content-Type": "application/octet-stream"},
    )
    assert appended.status_code == 200, appended.text
    incomplete = client.post(f"/api/v1/captures/uploads/{upload_id}/complete")
    assert incomplete.status_code == 409
    assert incomplete.json()["code"] == "chunked_upload_incomplete"
    assert client.get(f"/api/v1/captures/uploads/{upload_id}").json()["offset"] == len(HEADER) - 1
    with pytest.raises(StoreError):
        app.state.store.capture(upload_id)


def test_restart_restores_chunked_file_moved_before_ready_transition(app):
    store = app.state.store
    upload_id = store.init_chunk_upload("crash-window.pcap", len(HEADER), "pcap")
    assert store.append_upload_chunk(upload_id, 0, HEADER) == len(HEADER)
    part = store.upload_part_path(upload_id)
    finalized = store.capture_path(upload_id, "pcap")
    with store.upload_lock(upload_id):
        part.replace(finalized)

    recovered = Store(
        store.root,
        storage_max_bytes=store.storage_max_bytes,
        storage_max_captures=store.storage_max_captures,
        disk_reserve_bytes=store.disk_reserve_bytes,
    )
    assert not finalized.exists()
    assert recovered.upload_part_path(upload_id).read_bytes() == HEADER
    assert recovered.pending_upload(upload_id)["bytes_received"] == len(HEADER)
    with pytest.raises(StoreError):
        recovered.capture(upload_id)


def test_chunked_completion_serializes_against_concurrent_append(client, app, monkeypatch):
    upload_id = _init_chunk_upload(client, len(HEADER))
    appended = client.put(
        f"/api/v1/captures/uploads/{upload_id}/chunk?offset=0",
        content=HEADER,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert appended.status_code == 200, appended.text

    hashing_started = threading.Event()
    allow_hash = threading.Event()
    append_lock_attempted = threading.Event()
    real_hash = main_module._hash_and_peek_file
    real_upload_lock = app.state.store.upload_lock
    lock_call_count = 0
    lock_call_guard = threading.Lock()

    @store_module.contextmanager
    def tracked_upload_lock(lock_upload_id, *, blocking=True):
        nonlocal lock_call_count
        with lock_call_guard:
            lock_call_count += 1
            if lock_call_count == 2:
                append_lock_attempted.set()
        with real_upload_lock(lock_upload_id, blocking=blocking):
            yield

    def pause_hash(path):
        hashing_started.set()
        assert allow_hash.wait(5), "test did not release the finalizer"
        return real_hash(path)

    monkeypatch.setattr(main_module, "_hash_and_peek_file", pause_hash)
    monkeypatch.setattr(app.state.store, "upload_lock", tracked_upload_lock)
    with ThreadPoolExecutor(max_workers=2) as pool:
        completion = pool.submit(client.post, f"/api/v1/captures/uploads/{upload_id}/complete")
        assert hashing_started.wait(3)
        append_during_hash = pool.submit(
            client.put,
            f"/api/v1/captures/uploads/{upload_id}/chunk?offset={len(HEADER)}",
            content=b"x",
            headers={"Content-Type": "application/octet-stream"},
        )
        assert append_lock_attempted.wait(3)
        assert not append_during_hash.done()
        allow_hash.set()
        complete_response = completion.result(timeout=5)
        append_response = append_during_hash.result(timeout=5)
    assert complete_response.status_code == 200, complete_response.text
    assert append_response.status_code == 404
    capture_path = app.state.store.capture_path(upload_id)
    assert capture_path.read_bytes() == HEADER
    assert app.state.store.capture(upload_id)["ready"] == 1


def test_abort_after_ready_preserves_capture_file(client, app):
    upload_id = _init_chunk_upload(client, len(HEADER))
    assert client.put(
        f"/api/v1/captures/uploads/{upload_id}/chunk?offset=0",
        content=HEADER,
        headers={"Content-Type": "application/octet-stream"},
    ).status_code == 200
    completed = client.post(f"/api/v1/captures/uploads/{upload_id}/complete")
    assert completed.status_code == 200, completed.text
    capture_path = app.state.store.capture_path(upload_id)
    original = capture_path.read_bytes()
    aborted = client.delete(f"/api/v1/captures/uploads/{upload_id}")
    assert aborted.status_code == 204
    assert capture_path.read_bytes() == original == HEADER
    assert app.state.store.capture(upload_id)["ready"] == 1
