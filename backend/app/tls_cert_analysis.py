"""Bounded, low-confidence TLS certificate metadata checks for Zeek evidence.

This is an independently rewritten, metadata-only adaptation of selected TLS
certificate checks in ``ninedter/pcap-hunter`` (``app/pipeline/tls_certs.py``,
reviewed at commit ``cf839a43f6747e3f8d8ad021889d74e0cdbd10a6``). It does not
parse or retain certificate bytes and does not infer risk from issuer names.
All returned candidates cite the retained Zeek evidence row that supplied the
explicit indicator; these candidates are investigative leads, not verdicts.

Original upstream work is Copyright (c) 2025 ninedter and is made available
under the MIT License. Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated documentation files
to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions: The above copyright notice and this
permission notice shall be included in all copies or substantial portions of
the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping

MAX_TLS_CERT_RECORDS = 2_000
MAX_TLS_CERT_CANDIDATES = 100
MAX_TLS_VALIDATION_TEXT = 120
MAX_TLS_KEY_TYPE_TEXT = 64
MAX_TLS_EVIDENCE_ID_TEXT = 16
WEAK_RSA_KEY_BITS = 2_048
WEAK_EC_KEY_BITS = 256

_EVIDENCE_ID_RE = re.compile(r"^EV-[0-9]{6}$")
_DIGITS_RE = re.compile(r"^[0-9]{1,7}$")


@dataclass(frozen=True)
class TLSCertificateObservation:
    """One retained normalized Zeek row; values are metadata, never cert bytes."""

    evidence_id: str
    source_log: str
    attributes: Mapping[str, object]


@dataclass(frozen=True)
class TLSCertificateCandidate:
    """A single explicit, low-confidence indicator linked to local evidence."""

    detector: str
    title: str
    summary: str
    confidence: str
    evidence_ids: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class TLSCertificateAnalysisResult:
    candidates: tuple[TLSCertificateCandidate, ...]
    records_examined: int
    truncated: bool


_LIMITATIONS = (
    "This is a low-confidence metadata indicator, not proof of compromise or malicious activity.",
    "Only retained Zeek TLS/X.509 metadata was evaluated; a missing indicator does not establish validity or benignness.",
    "Certificate bytes, issuer reputation, chain building, revocation, and live network checks are not used.",
)

# Fixed output strings avoid echoing certificate fields, peer identifiers, or
# arbitrary text from a capture into a finding summary.
_DETECTOR_TEXT = {
    "tls_certificate_expired": (
        "Certificate reported expired",
        "Retained Zeek TLS validation metadata explicitly reports an expired certificate.",
    ),
    "tls_certificate_not_yet_valid": (
        "Certificate reported not yet valid",
        "Retained Zeek TLS validation metadata explicitly reports a certificate that is not yet valid.",
    ),
    "tls_certificate_self_signed": (
        "Self-signed certificate reported",
        "Retained Zeek TLS validation metadata explicitly reports a self-signed certificate.",
    ),
    "tls_certificate_weak_key": (
        "Weak certificate public-key parameters",
        "Retained Zeek X.509 key metadata is below the local RSA or EC size threshold.",
    ),
}


def _bounded_text(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text in {"-", "(empty)"} or len(text) > limit or not text.isascii():
        return None
    return text


def _validation_indicators(value: object) -> tuple[str, ...]:
    """Recognize explicit validation-status phrases; do not infer from names."""
    text = _bounded_text(value, MAX_TLS_VALIDATION_TEXT)
    if text is None:
        return ()
    normalized = re.sub(r"[_-]+", " ", text.lower())
    indicators: list[str] = []
    if re.search(r"\bexpired\b", normalized) and not re.search(
        r"\b(?:not|never) expired\b", normalized
    ):
        indicators.append("tls_certificate_expired")
    if re.search(r"\bnot yet valid\b|\bnot currently valid\b", normalized):
        indicators.append("tls_certificate_not_yet_valid")
    if re.search(r"\bself signed\b|\bselfsigned\b", normalized):
        indicators.append("tls_certificate_self_signed")
    return tuple(indicators)


def _bounded_key_length(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 1_000_000 else None
    if isinstance(value, str) and len(value) <= 7 and _DIGITS_RE.fullmatch(value.strip()):
        try:
            parsed = int(value.strip(), 10)
        except ValueError:  # pragma: no cover - guarded by the regular expression
            return None
        return parsed if 1 <= parsed <= 1_000_000 else None
    return None


def _weak_key_indicator(attributes: Mapping[str, object]) -> bool:
    key_type = _bounded_text(attributes.get("certificate_key_type"), MAX_TLS_KEY_TYPE_TEXT)
    key_length = _bounded_key_length(attributes.get("certificate_key_length"))
    if key_type is None or key_length is None:
        return False
    normalized_type = key_type.lower()
    if normalized_type == "rsa":
        return key_length < WEAK_RSA_KEY_BITS
    if normalized_type in {"ec", "ecdsa", "ecdh"}:
        return key_length < WEAK_EC_KEY_BITS
    return False


def analyze_tls_certificate_metadata(
    observations: Iterable[TLSCertificateObservation],
) -> TLSCertificateAnalysisResult:
    """Return bounded candidates from normalized ``ssl.log``/``x509.log`` rows.

    Required normalized attributes are ``tls_validation_status`` from
    ``ssl.log`` and ``certificate_key_type`` plus ``certificate_key_length``
    from ``x509.log``. The current normalizer does not retain certificate
    validity dates, so this function does not calculate date-based expiry or
    long-lived-certificate findings; it uses only explicit validation status.
    Evidence identifiers are validated locally before any candidate is emitted.
    """
    rows: list[TLSCertificateObservation] = []
    truncated = False
    for observation in observations:
        if len(rows) >= MAX_TLS_CERT_RECORDS:
            truncated = True
            break
        rows.append(observation)

    candidates: dict[tuple[str, str], TLSCertificateCandidate] = {}
    for observation in rows:
        evidence_id = observation.evidence_id
        if (
            not isinstance(evidence_id, str)
            or len(evidence_id) > MAX_TLS_EVIDENCE_ID_TEXT
            or not _EVIDENCE_ID_RE.fullmatch(evidence_id)
        ):
            continue
        if not isinstance(observation.attributes, Mapping):
            continue

        indicators: tuple[str, ...] = ()
        if observation.source_log == "ssl.log":
            indicators = _validation_indicators(
                observation.attributes.get("tls_validation_status")
            )
        elif observation.source_log == "x509.log" and _weak_key_indicator(observation.attributes):
            indicators = ("tls_certificate_weak_key",)
        else:
            continue

        for detector in indicators:
            key = detector, evidence_id
            if key in candidates:
                continue
            title, summary = _DETECTOR_TEXT[detector]
            if len(candidates) >= MAX_TLS_CERT_CANDIDATES:
                truncated = True
                continue
            candidates[key] = TLSCertificateCandidate(
                detector=detector,
                title=title,
                summary=summary,
                confidence="low",
                evidence_ids=(evidence_id,),
                limitations=_LIMITATIONS,
            )

    ordered = tuple(candidates[key] for key in sorted(candidates))
    return TLSCertificateAnalysisResult(
        candidates=ordered,
        records_examined=len(rows),
        truncated=truncated,
    )
