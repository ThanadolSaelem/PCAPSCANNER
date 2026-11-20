from __future__ import annotations

import pytest

from backend.app.ja3_analysis import (
    MAX_TLS_COMPONENTS,
    build_ja3_fingerprint,
    build_ja3s_fingerprint,
    calculate_ja3,
    calculate_ja3s,
    fingerprints_from_zeek_attributes,
    validate_ja3_hash,
    validate_ja3s_hash,
)


def test_ja3_hash_uses_canonical_order_and_known_vector() -> None:
    result = build_ja3_fingerprint(
        771,
        [4865, 4866],
        [0, 10, 11],
        [29, 23],
        [0],
    )
    assert result.kind == "ja3"
    assert result.digest == "38eaca597c62da4c9db8cfad482f14ad"
    assert result.tls_version == 771
    assert result.cipher_count == 2
    assert result.extension_count == 3
    assert result.curve_count == 2
    assert result.point_format_count == 1
    assert calculate_ja3(771, [4865, 4866], [0, 10, 11], [29, 23], [0]) == result.digest
    # JA3 is order-sensitive; list order is not sorted or otherwise rewritten.
    reordered = build_ja3_fingerprint(771, [4866, 4865], [0, 10, 11], [29, 23], [0])
    assert reordered.digest != result.digest


def test_grease_is_removed_from_ja3_components() -> None:
    ordinary = build_ja3_fingerprint(771, [4865, 4866], [0, 10, 11], [29, 23], [0])
    with_grease = build_ja3_fingerprint(
        "771",
        [0x0A0A, 4865, 0x2A2A, 4866],
        [0, 0x1A1A, 10, 11],
        [29, 0x3A3A, 23],
        [0x4A4A, 0],
    )
    assert with_grease.digest == ordinary.digest
    assert with_grease.cipher_count == 2


def test_ja3s_hash_uses_server_hello_components_and_drops_grease() -> None:
    result = build_ja3s_fingerprint(771, 4865, [0, 43])
    assert result.kind == "ja3s"
    assert result.digest == "32c243fff40e548be0e9d43d09174766"
    assert result.cipher_count == 1
    assert result.extension_count == 2
    assert calculate_ja3s(771, 4865, [0, 43]) == result.digest
    grease_extension = build_ja3s_fingerprint(771, 4865, [0, 0x1A1A, 43])
    assert grease_extension.extension_count == 2
    assert grease_extension.digest == result.digest
    grease_cipher = build_ja3s_fingerprint(771, 0x0A0A, [0, 43])
    assert grease_cipher.cipher_count == 0


def test_component_normalization_rejects_ambiguous_or_unbounded_input() -> None:
    with pytest.raises(ValueError):
        build_ja3_fingerprint("TLSv13", [4865], [], [], [])
    with pytest.raises(ValueError):
        build_ja3_fingerprint(True, [4865], [], [], [])
    with pytest.raises(ValueError):
        build_ja3_fingerprint(771, [4865, "0x1302"], [], [], [])
    with pytest.raises(ValueError):
        build_ja3s_fingerprint(771, -1, [])
    with pytest.raises(ValueError):
        build_ja3_fingerprint(771, [4865] * (MAX_TLS_COMPONENTS + 1), [], [], [])
    with pytest.raises(ValueError):
        build_ja3_fingerprint(771, "4865", [], [], [])


def test_hash_validators_accept_only_32_hex_digits() -> None:
    assert validate_ja3_hash("ABCDEF0123456789abcdef0123456789") == "abcdef0123456789abcdef0123456789"
    assert validate_ja3s_hash("0123456789abcdef0123456789abcdef") == "0123456789abcdef0123456789abcdef"
    for invalid in (None, 123, "", "0" * 31, "0" * 33, "g" * 32, "0" * 32 + "\n"):
        assert validate_ja3_hash(invalid) is None
        assert validate_ja3s_hash(invalid) is None


def test_zeek_adapter_retains_only_valid_hash_and_protocol_metadata() -> None:
    records = fingerprints_from_zeek_attributes(
        {
            "tls_ja3": "ABCDEF0123456789abcdef0123456789",
            "tls_ja3s": "not-a-hash",
            "tls_version": "TLSv13",
            "tls_cipher": "TLS_AES_128_GCM_SHA256",
            "tls_server_name": "private.example",
            "zeek_uid_hash": "sensitive-row-id",
        }
    )
    assert len(records) == 1
    assert records[0].kind == "ja3"
    assert records[0].to_metadata() == {
        "ja3_hash": "abcdef0123456789abcdef0123456789",
        "tls_version": "TLSv13",
        "tls_cipher": "TLS_AES_128_GCM_SHA256",
    }
    assert "private.example" not in repr(records)
    assert "sensitive-row-id" not in repr(records)
    assert fingerprints_from_zeek_attributes({"tls_ja3": "invalid"}) == ()


def test_computed_result_never_exposes_canonical_component_string() -> None:
    result = build_ja3_fingerprint(771, [4865, 4866], [0, 10], [29], [0])
    assert "4865" not in repr(result)
    assert "771,4865" not in repr(result)
    assert set(result.to_metadata()).issubset(
        {
            "ja3_hash",
            "tls_version",
            "tls_cipher",
            "cipher_count",
            "extension_count",
            "curve_count",
            "point_format_count",
        }
    )
