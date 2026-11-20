"""Focused tests for deterministic metadata-only STIX export."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from backend.app.models import Coverage, Evidence, EvidenceBundle, Finding
from backend.app.stix_export import export_stix_bundle


CAPTURE_SHA256 = "a" * 64
CREATED_AT = "2026-11-17T08:00:00Z"


def _bundle(*, evidence_count: int = 1) -> EvidenceBundle:
    evidence = [
        Evidence(
            evidence_id=f"EV-{index:06d}",
            kind="dns" if index == 1 else "flow",
            summary=(
                "DNS query suspicious.example; URI https://example.test/private/file.pcap "
                "local path /home/analyst/captures/private.pcap"
            ),
            packet_refs=[index],
            attributes={
                "query": "suspicious.example",
                "src": "192.0.2.44",
                "packets": 7,
                "payload": "RAW_PAYLOAD_SENTINEL",
                "filepath": "/private/local/capture.pcap",
                "request_uri": "https://example.test/private?q=secret",
                "pseudonymization_salt": "PSEUDONYM_SECRET_SENTINEL",
                "custom_note": "not in string allowlist",
            },
        )
        for index in range(1, evidence_count + 1)
    ]
    return EvidenceBundle(
        capture_sha256=CAPTURE_SHA256,
        created_at=CREATED_AT,
        coverage=Coverage(
            packets_seen=evidence_count,
            packets_analyzed=evidence_count,
            truncated=False,
            parser="synthetic-test",
        ),
        evidence=evidence,
        findings=[
            Finding(
                finding_id="F-0001",
                detector="dns_metadata_test",
                title="DNS metadata candidate",
                severity="low",
                confidence="low",
                evidence_ids=["EV-000001"],
                limitations=["Heuristic only; validate with the cited evidence."],
                summary="Review the cited DNS evidence.",
            )
        ],
    )


def _content(note: dict) -> dict:
    return json.loads(note["content"])


def test_export_is_deterministic_valid_shaped_and_preserves_citations() -> None:
    bundle = _bundle()
    exported = export_stix_bundle(bundle)
    assert exported == export_stix_bundle(bundle)
    assert exported["type"] == "bundle"
    assert exported["id"].startswith("bundle--")
    assert len(exported["objects"]) == 3

    objects = exported["objects"]
    by_id = {obj["id"]: obj for obj in objects}
    assert len(by_id) == len(objects)
    identity = next(obj for obj in objects if obj["type"] == "identity")
    assert identity["spec_version"] == "2.1"
    assert identity["identity_class"] == "organization"
    evidence_note = next(obj for obj in objects if obj["type"] == "note" and _content(obj)["record_type"] == "evidence")
    finding_note = next(obj for obj in objects if obj["type"] == "note" and _content(obj)["record_type"] == "finding")

    for obj in (evidence_note, finding_note):
        assert obj["spec_version"] == "2.1"
        assert obj["created"].endswith("Z") and obj["modified"] == obj["created"]
        assert all(ref in by_id for ref in obj["object_refs"])
        assert obj["external_references"][0]["source_name"] == "pcapscanner-local-evidence"
    assert evidence_note["external_references"][0]["external_id"] == "EV-000001"
    assert finding_note["external_references"][0]["external_id"] == "F-0001"
    finding_content = _content(finding_note)
    assert finding_content["evidence_ids"] == ["EV-000001"]
    assert evidence_note["id"] in finding_note["object_refs"]


def test_export_excludes_payload_paths_uri_values_and_pseudonym_secrets() -> None:
    encoded = json.dumps(export_stix_bundle(_bundle()), sort_keys=True)
    for forbidden in (
        "RAW_PAYLOAD_SENTINEL",
        "/private/local/capture.pcap",
        "/home/analyst/captures/private.pcap",
        "https://example.test/private",
        "PSEUDONYM_SECRET_SENTINEL",
        "PSEUDONYM_SECRET_SENTINEL",
        "custom_note",
    ):
        assert forbidden not in encoded
    # Safe local evidence metadata and the citation identifier survive filtering.
    assert "suspicious.example" in encoded
    assert "EV-000001" in encoded


def test_export_drops_narratives_with_common_credential_markers() -> None:
    bundle = _bundle()
    unsafe_finding = bundle.findings[0].model_copy(
        update={"summary": "Authorization: Bearer BEARER-SENTINEL token=TOKEN-SENTINEL password=PASSWORD-SENTINEL"}
    )
    bundle = bundle.model_copy(update={"findings": [unsafe_finding]})

    encoded = json.dumps(export_stix_bundle(bundle), sort_keys=True)
    for forbidden in ("BEARER-SENTINEL", "TOKEN-SENTINEL", "PASSWORD-SENTINEL", "Authorization"):
        assert forbidden not in encoded


def test_object_cap_never_leaves_a_finding_with_dangling_evidence_refs() -> None:
    exported = export_stix_bundle(_bundle(evidence_count=2), max_objects=2)
    assert len(exported["objects"]) == 2
    assert [obj["type"] for obj in exported["objects"]] == ["identity", "note"]
    note = exported["objects"][1]
    assert _content(note)["record_type"] == "evidence"
    assert _content(note)["evidence_id"] == "EV-000001"


def test_size_cap_is_enforced_and_rejects_less_than_minimum_bundle() -> None:
    bundle = _bundle()
    with pytest.raises(ValueError, match="too small"):
        export_stix_bundle(bundle, max_bytes=20)

    full = export_stix_bundle(bundle)
    one_evidence = export_stix_bundle(bundle, max_objects=2)
    encoded_size = len(json.dumps(one_evidence, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    bounded = export_stix_bundle(bundle, max_bytes=encoded_size)
    assert len(json.dumps(bounded, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= encoded_size
    assert len(bounded["objects"]) <= len(full["objects"])


def test_input_is_validated_including_cross_references() -> None:
    invalid = _bundle().model_dump(mode="python")
    invalid["findings"][0]["evidence_ids"] = ["EV-999999"]
    with pytest.raises(ValidationError):
        export_stix_bundle(invalid)

    valid = _bundle()
    invalid_finding = valid.findings[0].model_copy(update={"evidence_ids": ["EV-999999"]})
    bypassed = EvidenceBundle.model_construct(
        schema_version=valid.schema_version,
        capture_sha256=valid.capture_sha256,
        created_at=valid.created_at,
        coverage=valid.coverage,
        evidence=valid.evidence,
        findings=[invalid_finding],
    )
    with pytest.raises(ValidationError):
        export_stix_bundle(bypassed)


def test_invalid_cap_arguments_fail_closed() -> None:
    bundle = _bundle()
    with pytest.raises(ValueError):
        export_stix_bundle(bundle, max_objects=0)
    with pytest.raises(ValueError):
        export_stix_bundle(bundle, max_bytes=0)
