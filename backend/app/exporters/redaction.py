"""Shared deterministic PII / identifier / path / secret redaction helpers for exports."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

_SECRET_RE = re.compile(
    r"(?ix)\b(?:bearer\s+[A-Za-z0-9._~+/=-]{4,}|"
    r"(?:api[_ -]?key|access[_ -]?token|auth(?:orization)?|password|passwd|secret|token)\s*[:=]\s*[^\s,;]+)"
)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>()\"']+", re.I)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_IPV4_RE = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])"
)
_IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_WINDOWS_PATH_RE = re.compile(r"(?i)\b[a-z]:\\(?:[^\s<>()'\"|,;\\]+\\)*[^\s<>()'\"|,;\\]*")
_POSIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.:/-])/(?:(?:Users|home|var|tmp|etc|opt|mnt|Volumes|private|root|srv|usr|Downloads|Desktop|Documents|data\d*)/[^\s\"'<>()|,;]+|(?:[A-Za-z0-9_~.-]+/)+[A-Za-z0-9_~.-]+)"
)
_CAPTURE_FILE_RE = re.compile(r"(?i)\b[A-Za-z0-9_.-]+\.(?:pcapng|pcap|cap|csv|tsv)\b")
_DOMAIN_RE = re.compile(
    r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-])"
)

_NON_DOMAIN_SUFFIXES = frozenset(
    {
        "yar",
        "yara",
        "json",
        "jsonl",
        "bin",
        "pt",
        "pdf",
        "csv",
        "tsv",
        "cef",
        "pcap",
        "pcapng",
        "cap",
        "py",
        "ts",
        "tsx",
        "js",
        "mjs",
        "css",
        "html",
        "md",
        "txt",
        "log",
        "sqlite",
        "sqlite3",
        "stix",
    }
)

_PRESERVE_DICT_KEYS = frozenset(
    {
        "finding_id",
        "evidence_id",
        "analysis_id",
        "snapshot_id",
        "capture_id",
        "capture_sha256",
        "sha256",
        "md5",
        "sha1",
        "ja3",
        "ja3s",
        "ja3_hash",
        "ja3s_hash",
        "technique_id",
        "techniqueID",
        "tactic",
        "record_type",
        "severity",
        "confidence",
        "created_at",
        "updated_at",
        "modified",
        "created",
        "id",
        "spec_version",
        "type",
        "state",
        "detector",
        "rule_id",
        "ruleset_sha256",
        "packet_refs",
        "evidence_ids",
        "object_refs",
        "external_id",
    }
)


def _sub_ipv6(match: re.Match[str]) -> str:
    candidate = match.group(0)
    if "::" not in candidate and candidate.count(":") < 4:
        return candidate
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    return "[REDACTED_IP]"


def _sub_domain(match: re.Match[str]) -> str:
    candidate = match.group(0)
    tld = candidate.rsplit(".", 1)[-1].lower()
    if tld in _NON_DOMAIN_SUFFIXES:
        return candidate
    return "[REDACTED_HOST]"


def redact_text(value: str | None) -> str:
    """Deterministically mask secrets, URLs, emails, MACs, IPs, paths, capture filenames, and domains."""
    if not value:
        return "" if value is None else str(value)
    text = str(value)
    text = _SECRET_RE.sub("[REDACTED_SECRET]", text)
    text = _URL_RE.sub("[REDACTED_URL]", text)
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = _MAC_RE.sub("[REDACTED_MAC]", text)
    text = _IPV4_RE.sub("[REDACTED_IP]", text)
    text = _IPV6_CANDIDATE_RE.sub(_sub_ipv6, text)
    text = _WINDOWS_PATH_RE.sub("[REDACTED_PATH]", text)
    text = _POSIX_PATH_RE.sub("[REDACTED_PATH]", text)
    text = _CAPTURE_FILE_RE.sub("[REDACTED_FILE]", text)
    text = _DOMAIN_RE.sub(_sub_domain, text)
    return text


def redact_value(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact nested JSON-like structures while preserving stable IDs and hashes."""
    if key in _PRESERVE_DICT_KEYS:
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {k: redact_value(v, key=str(k)) for k, v in value.items()}
    return value


__all__ = ["redact_text", "redact_value"]
