"""Bounded, metadata-only JA3/JA3S fingerprint normalization and validation.

JA3/JA3S component serialization follows the conventions used by
ninedter/pcap-hunter (MIT License); no upstream fingerprint or reputation data
is included. Hashes identify protocol handshakes, not malware or an actor.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal, Mapping

MAX_TLS_COMPONENTS = 256
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_DECIMAL_RE = re.compile(r"^[0-9]{1,5}$")
_PROTOCOL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,120}$")
FingerprintKind = Literal["ja3", "ja3s"]


@dataclass(frozen=True)
class TLSFingerprint:
    """A fingerprint digest and bounded protocol metadata, never raw components."""

    kind: FingerprintKind
    digest: str
    tls_version: int | str | None = None
    cipher: str | None = None
    cipher_count: int | None = None
    extension_count: int | None = None
    curve_count: int | None = None
    point_format_count: int | None = None

    def to_metadata(self) -> dict[str, str | int]:
        """Return safe metadata for a finding; never expose the canonical input."""
        metadata: dict[str, str | int] = {f"{self.kind}_hash": self.digest}
        if self.tls_version is not None:
            metadata["tls_version"] = self.tls_version
        if self.cipher is not None:
            metadata["tls_cipher"] = self.cipher
        for key in ("cipher_count", "extension_count", "curve_count", "point_format_count"):
            value = getattr(self, key)
            if value is not None:
                metadata[key] = value
        return metadata


def _number(value: object, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an unsigned 16-bit identifier")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and _DECIMAL_RE.fullmatch(value):
        number = int(value, 10)
    else:
        raise ValueError(f"{name} must be an unsigned 16-bit identifier")
    if not 0 <= number <= 65535:
        raise ValueError(f"{name} must be an unsigned 16-bit identifier")
    return number


def _version(value: object) -> int:
    return _number(value, "TLS version")


def _is_grease(value: int) -> bool:
    """Return whether an extension/cipher/group is an RFC 8701 GREASE value."""
    return value & 0x0F0F == 0x0A0A


def _identifier_list(values: object, name: str) -> tuple[int, ...]:
    if not isinstance(values, (list, tuple)):
        raise ValueError(f"{name} must be a bounded list or tuple")
    if len(values) > MAX_TLS_COMPONENTS:
        raise ValueError(f"{name} exceeds the {MAX_TLS_COMPONENTS}-item limit")
    normalized: list[int] = []
    for value in values:
        number = _number(value, name)
        if not _is_grease(number):
            normalized.append(number)
    return tuple(normalized)


def _md5_ja3(canonical: str) -> str:
    # JA3 specifies MD5 for interoperability; it is not used as a security hash.
    return hashlib.md5(canonical.encode("ascii"), usedforsecurity=False).hexdigest()


def build_ja3_fingerprint(
    version: object,
    ciphers: object,
    extensions: object,
    elliptic_curves: object,
    point_formats: object,
) -> TLSFingerprint:
    """Build a JA3 digest from structured ClientHello metadata.

    Component order is retained, GREASE identifiers are removed, and all input
    sequences are capped. Only the digest and component counts are returned.
    """
    tls_version = _version(version)
    cipher_ids = _identifier_list(ciphers, "ciphers")
    extension_ids = _identifier_list(extensions, "extensions")
    curve_ids = _identifier_list(elliptic_curves, "elliptic_curves")
    point_format_ids = _identifier_list(point_formats, "point_formats")
    canonical = ",".join(
        (
            str(tls_version),
            "-".join(map(str, cipher_ids)),
            "-".join(map(str, extension_ids)),
            "-".join(map(str, curve_ids)),
            "-".join(map(str, point_format_ids)),
        )
    )
    return TLSFingerprint(
        kind="ja3",
        digest=_md5_ja3(canonical),
        tls_version=tls_version,
        cipher_count=len(cipher_ids),
        extension_count=len(extension_ids),
        curve_count=len(curve_ids),
        point_format_count=len(point_format_ids),
    )


def build_ja3s_fingerprint(version: object, cipher: object, extensions: object) -> TLSFingerprint:
    """Build a JA3S digest from structured ServerHello metadata."""
    tls_version = _version(version)
    cipher_id = _number(cipher, "cipher")
    extension_ids = _identifier_list(extensions, "extensions")
    cipher_value = "" if _is_grease(cipher_id) else str(cipher_id)
    cipher_count = 0 if _is_grease(cipher_id) else 1
    canonical = ",".join((str(tls_version), cipher_value, "-".join(map(str, extension_ids))))
    return TLSFingerprint(
        kind="ja3s",
        digest=_md5_ja3(canonical),
        tls_version=tls_version,
        cipher_count=cipher_count,
        extension_count=len(extension_ids),
    )


def calculate_ja3(
    version: object,
    ciphers: object,
    extensions: object,
    curves: object,
    point_formats: object,
) -> str:
    """Return only a JA3 hash (compatibility-style functional entry point)."""
    return build_ja3_fingerprint(version, ciphers, extensions, curves, point_formats).digest


def calculate_ja3s(version: object, cipher: object, extensions: object) -> str:
    """Return only a JA3S hash from a ServerHello's version, cipher and extensions."""
    return build_ja3s_fingerprint(version, cipher, extensions).digest


def validate_ja3_hash(value: object) -> str | None:
    """Normalize a 32-hex-character JA3 digest, or return ``None`` if invalid."""
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        return None
    return value.lower()


def validate_ja3s_hash(value: object) -> str | None:
    """Normalize a 32-hex-character JA3S digest, or return ``None`` if invalid."""
    return validate_ja3_hash(value)


def _protocol_token(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    token = value.strip()
    return token if _PROTOCOL_TOKEN_RE.fullmatch(token) else None


def fingerprints_from_zeek_attributes(
    attributes: Mapping[str, object],
) -> tuple[TLSFingerprint, ...]:
    """Validate existing Zeek-normalized hashes without retaining row identifiers.

    Consumes the target normalizer's ``tls_ja3``, ``tls_ja3s``, ``tls_version``
    and ``tls_cipher`` keys. Zeek's version/cipher labels are protocol metadata;
    they are not used to recompute a JA3 hash because negotiated values do not
    reconstruct the original ClientHello/ServerHello component lists.
    """
    version_value = attributes.get("tls_version")
    version: int | str | None
    if isinstance(version_value, int) and not isinstance(version_value, bool) and 0 <= version_value <= 65535:
        version = version_value
    else:
        version = _protocol_token(version_value)
    cipher = _protocol_token(attributes.get("tls_cipher"))
    records: list[TLSFingerprint] = []
    for kind, key, validator in (
        ("ja3", "tls_ja3", validate_ja3_hash),
        ("ja3s", "tls_ja3s", validate_ja3s_hash),
    ):
        digest = validator(attributes.get(key))
        if digest is not None:
            records.append(TLSFingerprint(kind=kind, digest=digest, tls_version=version, cipher=cipher))
    return tuple(records)
