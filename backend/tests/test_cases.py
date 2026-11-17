from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from backend.app.config import AppSettings
from backend.app.main import create_app
from backend.app.models import AnalysisRequest
from backend.app.store import Store, StoreError

TOKEN = "case-test-operator-token-32-characters"


@pytest.fixture
def cases_app(tmp_path):
    settings = AppSettings(data_dir=tmp_path, api_token=SecretStr(TOKEN), queue_limit=8, api_json_max_bytes=8192)
    app = create_app(settings)
    return app


@pytest.fixture
def cases_client(cases_app):
    return TestClient(cases_app, headers={"Authorization": "Bearer " + TOKEN})


def seed_job(store: Store) -> str:
    capture_id = uuid.uuid4().hex
    with store.connection(write=True) as db:
        db.execute(
            """INSERT INTO captures(id,sha256,size,created,ready,filename,format,source_kind,bytes_received,expected_bytes)
               VALUES(?,?,?,?,1,?,'pcap','upload',0,0)""",
            (capture_id, "a" * 64, 24, time.time(), "fixture.pcap"),
        )
    return store.create_job(AnalysisRequest(capture_id=capture_id), "case-test-policy")["id"]


def create_case(client: TestClient, **override):
    body = {"title": "Incident review"}
    body.update(override)
    response = client.post("/api/v1/cases", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def test_case_crud_list_shape_and_auth(cases_client):
    unauthorized = TestClient(cases_client.app).get("/api/v1/cases")
    assert unauthorized.status_code == 401

    created = create_case(
        cases_client,
        description="  Review suspicious activity  ",
        status="in_progress",
        severity="high",
        tags=[" endpoint ", "triage"],
    )
    assert set(created) == {
        "id", "title", "description", "status", "severity", "tags", "created_at", "updated_at",
        "analysis_count", "note_count", "analyses", "notes",
    }
    assert created["title"] == "Incident review"
    assert created["description"] == "Review suspicious activity"
    assert created["tags"] == ["endpoint", "triage"]
    assert created["analysis_count"] == created["note_count"] == 0

    listed = cases_client.get("/api/v1/cases").json()
    assert listed["total"] == 1
    assert listed["items"] == [{k: v for k, v in created.items() if k not in ("analyses", "notes")}]
    assert cases_client.get(f"/api/v1/cases/{created['id']}").json() == created

    updated = cases_client.patch(
        f"/api/v1/cases/{created['id']}", json={"title": "Updated review", "status": "resolved"}
    )
    assert updated.status_code == 200
    assert updated.json()["title"] == "Updated review"
    assert updated.json()["status"] == "resolved"
    deleted_case = cases_client.delete(f"/api/v1/cases/{created['id']}")
    assert deleted_case.status_code == 204
    assert deleted_case.content == b""
    assert cases_client.get(f"/api/v1/cases/{created['id']}").status_code == 404


def test_case_search_and_total_storage_cap(cases_client, monkeypatch):
    create_case(cases_client, title="DNS tunnel review", description="high entropy", tags=["dns"])
    create_case(cases_client, title="TLS certificate", description="issuer review", tags=["certificate"])

    by_title = cases_client.get("/api/v1/cases?search=tunnel").json()
    assert by_title["total"] == 1
    assert by_title["items"][0]["title"] == "DNS tunnel review"
    by_tag = cases_client.get("/api/v1/cases?search=CERTIFICATE").json()
    assert by_tag["total"] == 1
    assert by_tag["items"][0]["title"] == "TLS certificate"
    assert cases_client.get("/api/v1/cases?search=" + "x" * 121).status_code == 422

    monkeypatch.setattr(Store, "CASE_TOTAL_LIMIT", 2)
    assert cases_client.post("/api/v1/cases", json={"title": "third"}).status_code == 429


def test_case_rejects_malformed_ids_fields_and_pagination(cases_client):
    for bad_id in ("bad", "A" * 32, "g" * 32, "a" * 31):
        assert cases_client.get(f"/api/v1/cases/{bad_id}").status_code == 400
        assert cases_client.delete(f"/api/v1/cases/{bad_id}").status_code == 400

    invalid_bodies = [
        {"title": "   "},
        {"title": "x" * 161},
        {"title": "valid", "description": "x" * 4001},
        {"title": "valid", "status": "active"},
        {"title": "valid", "severity": "urgent"},
        {"title": "valid", "tags": ["x"] * 21},
        {"title": "valid", "tags": ["x" * 65]},
        {"title": "valid", "tags": ["Tag", " tag "]},
        {"title": "valid", "unexpected": "value"},
    ]
    for body in invalid_bodies:
        response = cases_client.post("/api/v1/cases", json=body)
        assert response.status_code == 422, (body, response.text)
        assert "unexpected" not in response.text
        assert "x" * 65 not in response.text

    case_id = create_case(cases_client)["id"]
    assert cases_client.patch(f"/api/v1/cases/{case_id}", json={}).status_code == 422
    assert cases_client.patch(f"/api/v1/cases/{case_id}", json={"description": None}).status_code == 422
    assert cases_client.get("/api/v1/cases?limit=101").status_code == 422
    assert cases_client.get("/api/v1/cases?offset=-1").status_code == 422


def test_analysis_association_exists_caps_and_cascades(cases_app, cases_client, monkeypatch):
    store = cases_app.state.store
    case_data = create_case(cases_client)
    case_id = case_data["id"]
    analysis_id = seed_job(store)
    missing_id = uuid.uuid4().hex

    assert cases_client.post(
        f"/api/v1/cases/{case_id}/analyses", json={"analysis_id": missing_id}
    ).status_code == 404
    assert cases_client.post(
        f"/api/v1/cases/{case_id}/analyses", json={"analysis_id": "oops"}
    ).status_code == 422
    linked = cases_client.post(
        f"/api/v1/cases/{case_id}/analyses", json={"analysis_id": analysis_id}
    )
    assert linked.status_code == 200
    assert linked.json()["analyses"] == [{
        "analysis_id": analysis_id,
        "capture_filename": "fixture.pcap",
        "state": "queued",
        "linked_at": linked.json()["analyses"][0]["linked_at"],
    }]
    assert cases_client.post(
        f"/api/v1/cases/{case_id}/analyses", json={"analysis_id": analysis_id}
    ).status_code == 409

    second_id = seed_job(store)
    monkeypatch.setattr(Store, "CASE_ANALYSIS_LIMIT", 1)
    over_cap = cases_client.post(
        f"/api/v1/cases/{case_id}/analyses", json={"analysis_id": second_id}
    )
    assert over_cap.status_code == 429
    assert over_cap.json()["code"] == "case_analysis_limit"
    monkeypatch.setattr(Store, "CASE_ANALYSIS_LIMIT", 100)

    unlinked = cases_client.delete(f"/api/v1/cases/{case_id}/analyses/{analysis_id}")
    assert unlinked.status_code == 204
    assert unlinked.content == b""
    assert cases_client.delete(f"/api/v1/cases/{case_id}/analyses/{analysis_id}").status_code == 404
    assert cases_client.post(
        f"/api/v1/cases/{case_id}/analyses", json={"analysis_id": analysis_id}
    ).status_code == 200
    # Job retention deletes only the link; the case and its independent metadata remain.
    with store.connection(write=True) as db:
        db.execute("DELETE FROM jobs WHERE id=?", (analysis_id,))
    retained = cases_client.get(f"/api/v1/cases/{case_id}").json()
    assert retained["analyses"] == []
    assert retained["title"] == "Incident review"

    assert cases_client.delete(f"/api/v1/cases/{case_id}").status_code == 204
    with store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM case_analyses WHERE case_id=?", (case_id,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM case_notes WHERE case_id=?", (case_id,)).fetchone()[0] == 0


def test_case_notes_bounds_limit_deletion_and_cascade(cases_app, cases_client, monkeypatch):
    store = cases_app.state.store
    case_id = create_case(cases_client)["id"]
    for payload in ({"note": ""}, {"note": "   "}, {"note": "x" * 4001}, {"note": "hello", "extra": 1}):
        assert cases_client.post(f"/api/v1/cases/{case_id}/notes", json=payload).status_code == 422

    first = cases_client.post(f"/api/v1/cases/{case_id}/notes", json={"note": "  Investigated  "})
    assert first.status_code == 200
    assert first.json()["notes"][0]["note"] == "Investigated"
    note_id = first.json()["notes"][0]["id"]
    assert cases_client.delete(f"/api/v1/cases/{case_id}/notes/{'f' * 32}").status_code == 404
    assert cases_client.delete(f"/api/v1/cases/{case_id}/notes/not-an-id").status_code == 400

    monkeypatch.setattr(Store, "CASE_NOTE_LIMIT", 1)
    over_cap = cases_client.post(f"/api/v1/cases/{case_id}/notes", json={"note": "second"})
    assert over_cap.status_code == 429
    assert over_cap.json()["code"] == "case_note_limit"
    monkeypatch.setattr(Store, "CASE_NOTE_LIMIT", 100)
    deleted_note = cases_client.delete(f"/api/v1/cases/{case_id}/notes/{note_id}")
    assert deleted_note.status_code == 204
    assert deleted_note.content == b""
    assert cases_client.delete(f"/api/v1/cases/{case_id}/notes/{note_id}").status_code == 404

    another = cases_client.post(f"/api/v1/cases/{case_id}/notes", json={"note": "remove with case"}).json()
    assert cases_client.delete(f"/api/v1/cases/{case_id}").status_code == 204
    with store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM case_notes WHERE id=?", (another["notes"][0]["id"],)).fetchone()[0] == 0


def test_additive_cases_tables_initialize_on_pre_cases_database(tmp_path):
    # Build the current base schema, then remove only the additive Cases tables to
    # simulate a database produced before Cases existed.
    first = Store(tmp_path)
    with first.connection(write=True) as db:
        db.execute("DROP TABLE case_notes")
        db.execute("DROP TABLE case_analyses")
        db.execute("DROP TABLE cases")

    reopened = Store(tmp_path)
    with reopened.connection() as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"cases", "case_analyses", "case_notes"}.issubset(tables)
        foreign_keys = {row[2]: row[6] for row in db.execute("PRAGMA foreign_key_list(case_analyses)")}
        assert foreign_keys == {"cases": "CASCADE", "jobs": "CASCADE"}
        note_fk = list(db.execute("PRAGMA foreign_key_list(case_notes)"))
        assert any(row[2] == "cases" and row[6] == "CASCADE" for row in note_fk)
