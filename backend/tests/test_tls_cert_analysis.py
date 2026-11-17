from __future__ import annotations

from backend.app import tls_cert_analysis
from backend.app.tls_cert_analysis import (
    TLSCertificateObservation,
    analyze_tls_certificate_metadata,
)


def _observation(
    evidence_id: str,
    source_log: str,
    attributes: dict[str, object],
) -> TLSCertificateObservation:
    return TLSCertificateObservation(
        evidence_id=evidence_id,
        source_log=source_log,
        attributes=attributes,
    )


def test_explicit_zeek_validation_statuses_create_low_confidence_cited_candidates() -> None:
    rows = [
        _observation("EV-000003", "ssl.log", {"tls_validation_status": "certificate has expired"}),
        _observation("EV-000002", "ssl.log", {"tls_validation_status": "certificate is not yet valid"}),
        _observation("EV-000001", "ssl.log", {"tls_validation_status": "self signed certificate"}),
    ]

    result = analyze_tls_certificate_metadata(rows)

    assert [(item.detector, item.evidence_ids) for item in result.candidates] == [
        ("tls_certificate_expired", ("EV-000003",)),
        ("tls_certificate_not_yet_valid", ("EV-000002",)),
        ("tls_certificate_self_signed", ("EV-000001",)),
    ]
    assert all(item.confidence == "low" for item in result.candidates)
    assert all(item.limitations for item in result.candidates)
    assert result.records_examined == 3
    assert result.truncated is False


def test_normalized_x509_key_metadata_flags_only_explicit_weak_rsa_or_ec_sizes() -> None:
    rows = [
        _observation(
            "EV-000001",
            "x509.log",
            {"certificate_key_type": "rsa", "certificate_key_length": 1024},
        ),
        _observation(
            "EV-000002",
            "x509.log",
            {"certificate_key_type": "ECDSA", "certificate_key_length": "224"},
        ),
        _observation(
            "EV-000003",
            "x509.log",
            {"certificate_key_type": "RSA", "certificate_key_length": 2048},
        ),
        _observation(
            "EV-000004",
            "x509.log",
            {"certificate_key_type": "EC", "certificate_key_length": 256},
        ),
        _observation(
            "EV-000005",
            "x509.log",
            {"certificate_key_type": "Ed25519", "certificate_key_length": 256},
        ),
    ]

    result = analyze_tls_certificate_metadata(rows)

    assert [(item.detector, item.evidence_ids) for item in result.candidates] == [
        ("tls_certificate_weak_key", ("EV-000001",)),
        ("tls_certificate_weak_key", ("EV-000002",)),
    ]


def test_missing_or_invalid_required_fields_and_invalid_evidence_ids_make_no_candidate() -> None:
    rows = [
        _observation("EV-000001", "ssl.log", {}),
        _observation("EV-000002", "x509.log", {"certificate_key_type": "RSA"}),
        _observation("EV-000003", "x509.log", {"certificate_key_length": 512}),
        _observation("EV-000004", "x509.log", {"certificate_key_type": "RSA", "certificate_key_length": True}),
        _observation("bad-id", "ssl.log", {"tls_validation_status": "certificate expired"}),
        _observation("EV-000005", "ssl.log", {"tls_validation_status": "not expired"}),
        _observation("EV-000006", "ssl.log", {"tls_validation_status": "certificate valid"}),
    ]

    assert analyze_tls_certificate_metadata(rows).candidates == ()


def test_common_issuer_and_subject_names_are_never_used_as_indicators() -> None:
    row = _observation(
        "EV-000001",
        "x509.log",
        {
            "issuer": "DigiCert Global Root G2",
            "subject": "example.test",
            "certificate_sha256": "a" * 64,
            "certificate_signature_algorithm": "sha1WithRSAEncryption",
        },
    )

    assert analyze_tls_certificate_metadata([row]).candidates == ()


def test_only_expected_zeek_logs_and_expected_metadata_fields_are_considered() -> None:
    rows = [
        _observation("EV-000001", "conn.log", {"tls_validation_status": "certificate expired"}),
        _observation("EV-000002", "x509.log", {"tls_validation_status": "self signed certificate"}),
        _observation("EV-000003", "ssl.log", {"certificate_key_type": "RSA", "certificate_key_length": 512}),
    ]

    assert analyze_tls_certificate_metadata(rows).candidates == ()


def test_results_are_deterministic_and_do_not_echo_capture_values() -> None:
    secret_value = "CN=private.example, O=Private Organization"
    rows = [
        _observation(
            "EV-000002",
            "x509.log",
            {"certificate_key_type": "RSA", "certificate_key_length": 1024, "subject": secret_value},
        ),
        _observation(
            "EV-000001",
            "ssl.log",
            {"tls_validation_status": "certificate has expired", "issuer": secret_value},
        ),
    ]

    forward = analyze_tls_certificate_metadata(rows).candidates
    reverse = analyze_tls_certificate_metadata(list(reversed(rows))).candidates

    assert forward == reverse
    assert all(secret_value not in item.title + item.summary for item in forward)
    assert all("EV-" not in item.title + item.summary for item in forward)


def test_non_metadata_payload_values_are_ignored() -> None:
    # A bytes-like certificate payload is not parsed, hashed, retained, or echoed.
    row = _observation(
        "EV-000001",
        "x509.log",
        {
            "certificate": b"not a certificate",
            "certificate_key_type": "RSA",
            "certificate_key_length": 1024,
        },
    )

    result = analyze_tls_certificate_metadata([row])

    assert len(result.candidates) == 1
    assert result.candidates[0].summary == tls_cert_analysis._DETECTOR_TEXT["tls_certificate_weak_key"][1]


def test_record_and_candidate_caps_are_reported(monkeypatch) -> None:
    rows = [
        _observation(f"EV-{index:06d}", "ssl.log", {"tls_validation_status": "certificate expired"})
        for index in range(1, 5)
    ]
    monkeypatch.setattr(tls_cert_analysis, "MAX_TLS_CERT_RECORDS", 2)
    result = analyze_tls_certificate_metadata(rows)
    assert result.records_examined == 2
    assert result.truncated is True
    assert len(result.candidates) == 2

    monkeypatch.setattr(tls_cert_analysis, "MAX_TLS_CERT_RECORDS", 10)
    monkeypatch.setattr(tls_cert_analysis, "MAX_TLS_CERT_CANDIDATES", 1)
    capped = analyze_tls_certificate_metadata(rows)
    assert len(capped.candidates) == 1
    assert capped.truncated is True
