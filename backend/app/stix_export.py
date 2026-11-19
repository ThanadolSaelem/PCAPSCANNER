"""Deterministic, metadata-only STIX 2.1 export for validated evidence bundles.

This module intentionally creates STIX Note and Identity objects only.  It does
not export packet payloads, filesystem paths, URI values, or pseudonymization
secrets, and it performs no network or provider operations.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from .exporters.redaction import redact_value
from .models import Evidence, EvidenceBundle, Finding

DEFAULT_MAX_OBJECTS = 2_000
HARD_MAX_OBJECTS = 5_000
DEFAULT_MAX_BYTES = 1_000_000
HARD_MAX_BYTES = 4_000_000

# Even summaries and titles are untrusted text. Remove URI/path-like fragments
# rather than exporting them, and drop strings that appear to carry credentials.
_URI_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{0,31}://[^\s\]\[<>{}\"']+")
_WWW_RE = re.compile(r"(?i)\bwww\.[^\s\]\[<>{}\"']+")
_WINDOWS_PATH_RE = re.compile(r"(?i)\b[a-z]:\\[^\s\]\[<>{}\"']*")
_ABSOLUTE_PATH_RE = re.compile(r"(?<![\w.])/(?:[^\s/]+/)+[^\s,;)}\]]*")
_RELATIVE_PATH_RE = re.compile(r"(?<![\w.-])(?:\.\.?/)(?:[^\s/]+/)*[^\s,;)}\]]*")
_SLASH_PATH_RE = re.compile(r"(?<![\w])(?:[A-Za-z0-9_.-]+/)+[^\s,;)}\]]*")
_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:authorization|bearer|api[_ -]?key|access[_ -]?token|token|password|passwd|secret|salt|credential)\b"
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:payload|raw|body|cookie|authorization|credential|password|secret|salt|"
    r"token|api.?key|uri|url|path|filename|user.?agent|header|pseudonym|anon)"
)
_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
_DOMAINISH_RE = re.compile(r"^[A-Za-z0-9_.-]{1,253}$")
_SAFE_TEXT_ATTRIBUTE_KEYS = frozenset(
    {
        "protocol", "src", "dst", "source", "destination", "src_ip", "dst_ip",
        "source_ip", "destination_ip", "src_mac", "dst_mac", "mac",
        "query", "qname", "domain", "hostname", "rule_id", "state", "method",
        "http_method", "http_status", "status", "dns_qry_name", "dns_query",
    }
)


def _uuid(kind: str, capture_sha256: str, source_id: str = "") -> str:
    return str(uuid5(NAMESPACE_URL, f"pcapscanner:stix:2.1:{capture_sha256}:{kind}:{source_id}"))


def _timestamp(value: str) -> str:
    """Convert an input time to a valid, deterministic STIX timestamp."""
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed = parsed.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        parsed = datetime(1970, 1, 1, tzinfo=timezone.utc)
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_narrative(value: str | None, *, limit: int) -> str | None:
    if not value:
        return None
    # Drop text with credential markers altogether: partial redaction can leave
    # secret fragments, and none are needed to preserve evidence provenance.
    if _CREDENTIAL_RE.search(value):
        return None
    cleaned = _URI_RE.sub("[URI omitted]", value)
    cleaned = _WWW_RE.sub("[URI omitted]", cleaned)
    cleaned = _WINDOWS_PATH_RE.sub("[path omitted]", cleaned)
    cleaned = _ABSOLUTE_PATH_RE.sub("[path omitted]", cleaned)
    cleaned = _RELATIVE_PATH_RE.sub("[path omitted]", cleaned)
    cleaned = _SLASH_PATH_RE.sub("[path omitted]", cleaned)
    # Do not let an overlong untrusted field defeat the export byte cap.
    cleaned = cleaned[:limit].strip()
    return cleaned or None


def _safe_string_attribute(key: str, value: str) -> str | None:
    if _SENSITIVE_KEY_RE.search(key) or key.lower() not in _SAFE_TEXT_ATTRIBUTE_KEYS:
        return None
    if not value or len(value) > 256 or _CREDENTIAL_RE.search(value):
        return None
    if any(token in value for token in ("://", "\\", "/")) or "?" in value:
        return None
    lowered = key.lower()
    if lowered in {"src", "dst", "source", "destination", "src_ip", "dst_ip", "source_ip", "destination_ip"}:
        if value.lower() == "broadcast":
            return value
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            if not _DOMAINISH_RE.fullmatch(value):
                return None
            return value
    if lowered in {"mac", "src_mac", "dst_mac"}:
        return value if _MAC_RE.fullmatch(value) else None
    if lowered in {"query", "qname", "domain", "hostname", "dns_qry_name", "dns_query"}:
        return value if _DOMAINISH_RE.fullmatch(value) else None
    if not value.isprintable():
        return None
    return value


def _safe_attributes(evidence: Evidence) -> dict[str, str | int | float | bool]:
    result: dict[str, str | int | float | bool] = {}
    for raw_key, raw_value in sorted(evidence.attributes.items(), key=lambda row: str(row[0])):
        key = str(raw_key)
        if _SENSITIVE_KEY_RE.search(key):
            continue
        if isinstance(raw_value, str):
            value = _safe_string_attribute(key, raw_value)
            if value is not None:
                result[key] = value
        elif isinstance(raw_value, bool):
            result[key] = raw_value
        elif isinstance(raw_value, int):
            result[key] = raw_value
        elif isinstance(raw_value, float):
            # Pydantic rejects non-finite numbers, but retain this boundary check
            # for EvidenceBundle instances created through unsafe model APIs.
            if raw_value == raw_value and abs(raw_value) != float("inf"):
                result[key] = raw_value
    return result


def _note(
    *,
    object_id: str,
    created: str,
    content: dict[str, Any],
    refs: list[str],
    source_id: str,
    citation_type: str,
) -> dict[str, Any]:
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": object_id,
        "created": created,
        "modified": created,
        "content": json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        "object_refs": refs,
        "external_references": [
            {
                "source_name": "pcapscanner-local-evidence",
                "external_id": source_id,
                "description": citation_type,
            }
        ],
    }


def _json_size(objects: list[dict[str, Any]], bundle_id: str) -> int:
    prefix = json.dumps(
        {"type": "bundle", "id": bundle_id, "objects": []},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    empty_size = len(prefix.encode("utf-8"))
    if not objects:
        return empty_size
    return empty_size + sum(
        len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        for obj in objects
    ) + len(objects) - 1


def export_stix_bundle(
    bundle: EvidenceBundle | dict[str, Any] | str | bytes,
    *,
    max_objects: int = DEFAULT_MAX_OBJECTS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    redact: bool = False,
) -> dict[str, Any]:
    """Export a validated ``EvidenceBundle`` as a deterministic STIX 2.1 bundle.

    ``max_objects`` includes the Identity object. Evidence Notes are emitted in
    evidence-ID order; a Finding Note is included only when every cited evidence
    object was retained. All citations are preserved as local STIX object
    references and ``external_references``. Both limits are hard bounded even
    when callers request larger values.
    """
    if isinstance(max_objects, bool) or not isinstance(max_objects, int) or max_objects < 1:
        raise ValueError("max_objects must be a positive integer")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    max_objects = min(max_objects, HARD_MAX_OBJECTS)
    max_bytes = min(max_bytes, HARD_MAX_BYTES)

    if isinstance(bundle, EvidenceBundle):
        # Revalidation closes the model_construct/bypassed-validator edge case.
        validated = EvidenceBundle.model_validate(bundle.model_dump(mode="python"))
    else:
        validated = EvidenceBundle.model_validate(bundle)

    created = _timestamp(validated.created_at)
    capture_sha = validated.capture_sha256
    identity_id = f"identity--{_uuid('identity', capture_sha)}"
    bundle_id = f"bundle--{_uuid('bundle', capture_sha)}"
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": created,
        "modified": created,
        "name": "PCAP Scanner local evidence exporter",
        "identity_class": "organization",
    }
    objects: list[dict[str, Any]] = [identity]
    evidence_object_ids: dict[str, str] = {}
    current_size = _json_size([], bundle_id)
    current_size += len(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    if current_size > max_bytes:
        raise ValueError("max_bytes is too small for the minimum STIX bundle")

    for evidence in sorted(validated.evidence, key=lambda item: item.evidence_id):
        if len(objects) >= max_objects:
            break
        object_id = f"note--{_uuid('evidence', capture_sha, evidence.evidence_id)}"
        summary = _safe_narrative(evidence.summary, limit=1_000)
        content: dict[str, Any] = {
            "record_type": "evidence",
            "evidence_id": evidence.evidence_id,
            "kind": evidence.kind,
            "packet_refs": list(evidence.packet_refs[:50]),
            "attributes": _safe_attributes(evidence),
        }
        if summary:
            content["summary"] = summary
        if redact:
            content = redact_value(content)
        note = _note(
            object_id=object_id,
            created=created,
            content=content,
            refs=[identity_id],
            source_id=evidence.evidence_id,
            citation_type="Validated local evidence identifier",
        )
        note_size = len(json.dumps(note, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        if current_size + 1 + note_size > max_bytes:
            continue
        objects.append(note)
        current_size += 1 + note_size
        evidence_object_ids[evidence.evidence_id] = object_id

    for finding in sorted(validated.findings, key=lambda item: item.finding_id):
        if len(objects) >= max_objects:
            break
        # Never output an incomplete citation or invent a substitute reference.
        if not all(evidence_id in evidence_object_ids for evidence_id in finding.evidence_ids):
            continue
        note = _finding_note(finding, capture_sha, created, identity_id, evidence_object_ids, redact=redact)
        note_size = len(json.dumps(note, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        if current_size + 1 + note_size > max_bytes:
            continue
        objects.append(note)
        current_size += 1 + note_size

    return {"type": "bundle", "id": bundle_id, "objects": objects}


def _finding_note(
    finding: Finding,
    capture_sha: str,
    created: str,
    identity_id: str,
    evidence_object_ids: dict[str, str],
    *,
    redact: bool = False,
) -> dict[str, Any]:
    content: dict[str, Any] = {
        "record_type": "finding",
        "finding_id": finding.finding_id,
        "detector": _safe_narrative(finding.detector, limit=100),
        "title": _safe_narrative(finding.title, limit=300),
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence_ids": list(finding.evidence_ids),
        "limitations": [
            safe for item in finding.limitations
            if (safe := _safe_narrative(item, limit=500)) is not None
        ],
    }
    summary = _safe_narrative(finding.summary, limit=600)
    if summary:
        content["summary"] = summary
    triage_class = _safe_narrative(finding.triage_class, limit=64)
    if triage_class:
        content["triage_class"] = triage_class
    if finding.triage_confidence is not None:
        content["triage_confidence"] = finding.triage_confidence
    if redact:
        content = redact_value(content)
    refs = [identity_id, *(evidence_object_ids[eid] for eid in finding.evidence_ids)]
    return _note(
        object_id=f"note--{_uuid('finding', capture_sha, finding.finding_id)}",
        created=created,
        content=content,
        refs=list(dict.fromkeys(refs)),
        source_id=finding.finding_id,
        citation_type="Validated local finding identifier",
    )


# Convenient explicit alias for call sites that prefer the STIX-first name.
to_stix_bundle = export_stix_bundle
