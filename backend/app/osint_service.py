"""Bounded, per-operation-consented read-only OSINT lookups.

Only normalized indicators extracted from selected Evidence IDs are sent. The
service never accepts a capture, URL, URI path, payload, packet text, or raw log.
Provider origins and routes are fixed; responses are reduced to small allowlisted
summaries and are never forwarded to the AI narrator/chat context.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Mapping, Sequence
from urllib.parse import quote

import httpx

from .models import EvidenceBundle

MAX_IOCS_PER_OPERATION = 12
MAX_PROVIDERS_PER_OPERATION = 7
MAX_TOTAL_LOOKUPS = MAX_IOCS_PER_OPERATION * MAX_PROVIDERS_PER_OPERATION
MAX_REQUEST_BYTES = 4 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_OPERATION_SECONDS = 35.0
PER_REQUEST_TIMEOUT_SECONDS = 6.0
MAX_CANDIDATES_PER_REPORT = 200
MAX_PROVIDER_RESULT_TEXT = 120
MAX_RATE_RETRY_AFTER_SECONDS = 300

ProviderId = Literal["virustotal", "abuseipdb", "greynoise", "shodan", "otx", "rdns", "rdap"]
IndicatorType = Literal["ipv4", "ipv6", "domain", "md5", "sha1", "sha256"]

_PROVIDER_NAMES: dict[str, str] = {
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "greynoise": "GreyNoise",
    "shodan": "Shodan",
    "otx": "AlienVault OTX",
    "rdns": "Reverse DNS (PTR)",
    "rdap": "RDAP / WHOIS",
}
_KEY_ENV = {
    "virustotal": "PCAP_OSINT_VIRUSTOTAL_API_KEY",
    "abuseipdb": "PCAP_OSINT_ABUSEIPDB_API_KEY",
    "greynoise": "PCAP_OSINT_GREYNOISE_API_KEY",
    "shodan": "PCAP_OSINT_SHODAN_API_KEY",
    "otx": "PCAP_OSINT_OTX_API_KEY",
}
_ACK_ENV = {
    "virustotal": "PCAP_OSINT_VIRUSTOTAL_PREMIUM_LICENSE_ACK",
    "abuseipdb": "PCAP_OSINT_ABUSEIPDB_TERMS_ACK",
    "greynoise": "PCAP_OSINT_GREYNOISE_LICENSE_ACK",
    "shodan": "PCAP_OSINT_SHODAN_AUTOMATION_ACK",
    "otx": "PCAP_OSINT_OTX_AUTHORIZED_USE_ACK",
    "rdns": "PCAP_OSINT_RDNS_ACK",
    "rdap": "PCAP_OSINT_RDAP_ACK",
}
_SHODAN_LOG_REDACTION_ACK_ENV = "PCAP_OSINT_SHODAN_QUERY_LOG_REDACTION_ACK"
_PRIVATE_DOMAIN_SUFFIXES = {
    "alt", "arpa", "corp", "example", "home", "internal", "intranet", "invalid",
    "lan", "local", "localhost", "localdomain", "onion", "private", "test",
    "example.com", "example.net", "example.org",
}
_PRIVATE_DOMAIN_NAMES = {"example.com", "example.net", "example.org", "home.arpa"}
_PRIVATE_DOMAIN_LABELS = {
    "corp", "home", "internal", "intranet", "lan", "local", "localhost", "onion", "private",
}
_PROCESS_RATE_LOCK = threading.Lock()
_PROCESS_LAST_REQUEST_AT: dict[str, float] = {}
_QUERY_SECRET_RE = re.compile(r"(?i)([?&](?:key|api_key)=)[^&\s'\"<>]+")


class _QuerySecretLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        redacted = _QUERY_SECRET_RE.sub(r"\1[REDACTED]", message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


for _http_log_name in ("httpx", "httpcore", "httpcore.http11", "httpcore.http2", "httpcore.connection"):
    _http_log = logging.getLogger(_http_log_name)
    if not any(isinstance(item, _QuerySecretLogFilter) for item in _http_log.filters):
        _http_log.addFilter(_QuerySecretLogFilter())
_REFERENCE_DOCS = {
    "virustotal": "https://docs.virustotal.com/reference/overview",
    "abuseipdb": "https://docs.abuseipdb.com/",
    "greynoise": "https://docs.greynoise.io/reference/getcommunityip",
    "shodan": "https://developer.shodan.io/api",
    "otx": "https://otx.alienvault.com/api",
    "rdns": "https://www.rfc-editor.org/rfc/rfc1035",
    "rdap": "https://www.rfc-editor.org/rfc/rfc9083",
}
_MIN_REQUEST_INTERVAL_SECONDS = {
    "virustotal": 1.0,
    "abuseipdb": 1.0,
    "greynoise": 1.0,
    "shodan": 1.0,
    "otx": 1.0,
    "rdns": 0.25,
    "rdap": 0.5,
}
_SUPPORTED_TYPES: dict[str, set[str]] = {
    "virustotal": {"ipv4", "ipv6", "domain", "md5", "sha1", "sha256"},
    "abuseipdb": {"ipv4", "ipv6"},
    "greynoise": {"ipv4", "ipv6"},
    "shodan": {"ipv4", "domain"},
    "otx": {"ipv4", "ipv6", "domain", "md5", "sha1", "sha256"},
    "rdns": {"ipv4", "ipv6"},
    "rdap": {"ipv4", "ipv6", "domain"},
}
_IP_ATTRIBUTE_KEYS = {"src", "dst", "src_ip", "dst_ip", "source_ip", "destination_ip", "id_orig_h", "id_resp_h"}
_DOMAIN_ATTRIBUTE_KEYS = {"query", "tls_server_name", "server_name", "hostname", "domain", "dns_qry_name"}
_HASH_ATTRIBUTE_KEYS = {"artifact_sha256", "object_sha256", "artifact_sha1", "artifact_md5"}
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
_HEX_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


@dataclass(frozen=True, slots=True)
class IOCCandidate:
    candidate_id: str
    indicator_type: IndicatorType
    indicator: str
    evidence_ids: tuple[str, ...]

    def public_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "indicator_type": self.indicator_type,
            "indicator": self.indicator,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True, slots=True)
class _ProviderConfig:
    key: str | None
    ready: bool
    state: str


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _canonical_indicator(value: object, hint: str | None = None) -> tuple[IndicatorType, str] | None:
    if not isinstance(value, str) or not value or len(value) > 253 or value != value.strip():
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value) or any(ch in value for ch in "/\\?#@%"):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        if not address.is_global or address.is_multicast or address.is_reserved:
            return None
        kind: IndicatorType = "ipv4" if address.version == 4 else "ipv6"
        if hint and hint not in {"ip", kind, "address"}:
            return None
        return kind, address.compressed
    if hint in {"md5", "sha1", "sha256"}:
        if len(value) == _HEX_LENGTHS[hint] and re.fullmatch(r"[a-fA-F0-9]+", value):
            return hint, value.lower()  # type: ignore[return-value]
        return None
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    if not _DOMAIN_RE.fullmatch(domain):
        return None
    labels = domain.split(".")
    if (
        domain in _PRIVATE_DOMAIN_NAMES
        or any(domain == suffix or domain.endswith("." + suffix) for suffix in _PRIVATE_DOMAIN_SUFFIXES)
        or any(label in _PRIVATE_DOMAIN_LABELS for label in labels[:-1])
    ):
        return None
    if hint and hint not in {"domain", "hostname", "dns"}:
        return None
    return "domain", domain


def extract_ioc_candidates(bundle: EvidenceBundle, evidence_ids: Sequence[str]) -> tuple[list[IOCCandidate], bool]:
    """Extract deduplicated public indicators from selected structured evidence only."""
    if isinstance(evidence_ids, (str, bytes)) or not isinstance(evidence_ids, Sequence):
        raise ValueError("evidence_id_list_required")
    if not 1 <= len(evidence_ids) <= 5_000 or len(set(evidence_ids)) != len(evidence_ids):
        raise ValueError("evidence_id_selection_invalid")
    by_id = {ev.evidence_id: ev for ev in bundle.evidence}
    if any(evidence_id not in by_id for evidence_id in evidence_ids):
        raise ValueError("unknown_evidence_id")
    collected: dict[tuple[str, str], set[str]] = {}
    for evidence_id in evidence_ids:
        ev = by_id[evidence_id]
        attrs = ev.attributes
        for key, value in attrs.items():
            normalized_key = key.lower()
            hint: str | None = None
            if normalized_key in _IP_ATTRIBUTE_KEYS:
                hint = "ip"
            elif normalized_key in _DOMAIN_ATTRIBUTE_KEYS:
                hint = "domain"
            elif normalized_key in _HASH_ATTRIBUTE_KEYS and ev.kind == "yara":
                hint = "sha256" if normalized_key.endswith("sha256") else "sha1" if normalized_key.endswith("sha1") else "md5"
            if hint is None or not isinstance(value, str):
                continue
            normalized = _canonical_indicator(value, hint)
            if normalized is None:
                continue
            kind, indicator = normalized
            collected.setdefault((kind, indicator), set()).add(evidence_id)
    sorted_items = sorted(collected.items(), key=lambda item: (item[0][0], item[0][1]))
    truncated = len(sorted_items) > MAX_CANDIDATES_PER_REPORT
    candidates: list[IOCCandidate] = []
    for (kind, indicator), refs in sorted_items[:MAX_CANDIDATES_PER_REPORT]:
        candidate_id = "IOC-" + hashlib.sha256(f"{kind}:{indicator}".encode("utf-8")).hexdigest()[:16]
        candidates.append(IOCCandidate(candidate_id, kind, indicator, tuple(sorted(refs))))
    return candidates, truncated


def _clean_key(raw: str | None) -> str | None:
    if not raw:
        return None
    key = raw.strip()
    if not 8 <= len(key) <= 512 or any(ord(ch) < 33 or ord(ch) == 127 for ch in key):
        return None
    return key


def _safe_string(value: object, maximum: int = MAX_PROVIDER_RESULT_TEXT) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > maximum or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None
    # Never persist provider-returned URLs, URI fragments, paths or credentials.
    if any(token in text.lower() for token in ("http://", "https://", "www.", "bearer ", "authorization", "cookie", "token=")):
        return None
    if any(ch in text for ch in "/\\?#@"):
        return None
    return text


def _safe_int(value: object, minimum: int = -10_000_000, maximum: int = 10_000_000) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        result = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None
    return result if minimum <= result <= maximum else None


def _safe_bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _safe_timestamp(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:T[0-9:.+-]+Z?)?", value):
        return None
    return value


def _allowlisted_summary(provider: str, payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    # Shodan host responses place scalar metadata beside a `data` banner list;
    # other providers commonly wrap the indicator in `data.attributes`.
    data = payload if provider == "shodan" else payload.get("data", payload)
    if not isinstance(data, dict):
        return {}
    attrs = data.get("attributes", data)
    if not isinstance(attrs, dict):
        attrs = data
    summary: dict[str, Any] = {}
    if provider == "virustotal":
        stats = attrs.get("last_analysis_stats")
        if isinstance(stats, dict):
            for key in ("malicious", "suspicious", "harmless", "undetected", "timeout"):
                number = _safe_int(stats.get(key), 0, 1_000_000)
                if number is not None:
                    summary[key] = number
        reputation = _safe_int(attrs.get("reputation"), -1_000_000, 1_000_000)
        if reputation is not None:
            summary["reputation"] = reputation
        for key in ("country", "as_owner"):
            value = _safe_string(attrs.get(key))
            if value:
                summary[key] = value
        asn = _safe_int(attrs.get("asn"), 0, 4_294_967_295)
        if asn is not None:
            summary["asn"] = asn
        timestamp = _safe_int(attrs.get("last_analysis_date"), 0, 4_102_444_800)
        if timestamp is not None:
            summary["last_analysis_epoch"] = timestamp
    elif provider == "abuseipdb":
        for key, low, high in (("abuseConfidenceScore", 0, 100), ("totalReports", 0, 10_000_000), ("numDistinctUsers", 0, 10_000_000)):
            number = _safe_int(attrs.get(key), low, high)
            if number is not None:
                summary[{"abuseConfidenceScore": "abuse_confidence", "totalReports": "total_reports", "numDistinctUsers": "distinct_reporters"}[key]] = number
        for key, out in (("countryCode", "country_code"), ("usageType", "usage_type")):
            value = _safe_string(attrs.get(key), 64)
            if value:
                summary[out] = value
        tor = _safe_bool(attrs.get("isTor"))
        if tor is not None:
            summary["is_tor"] = tor
        last_reported = _safe_timestamp(attrs.get("lastReportedAt"))
        if last_reported:
            summary["last_reported_at"] = last_reported
    elif provider == "greynoise":
        classification = attrs.get("classification")
        if classification in {"benign", "malicious", "unknown"}:
            summary["classification"] = classification
        for key in ("noise", "riot"):
            value = _safe_bool(attrs.get(key))
            if value is not None:
                summary[key] = value
        for key in ("first_seen", "last_seen"):
            value = _safe_timestamp(attrs.get(key))
            if value:
                summary[key] = value
    elif provider == "shodan":
        ports = attrs.get("ports")
        if isinstance(ports, list):
            safe_ports = sorted({p for x in ports if (p := _safe_int(x, 1, 65535))})[:32]
            if safe_ports:
                summary["ports"] = safe_ports
        asn_raw = attrs.get("asn")
        asn_text = _safe_string(asn_raw, 24)
        if asn_text and re.fullmatch(r"AS[0-9]{1,10}", asn_text.upper()):
            summary["asn"] = asn_text.upper()
        country = _safe_string(attrs.get("country_code"), 2)
        if country and re.fullmatch(r"[A-Za-z]{2}", country):
            summary["country_code"] = country.upper()
        for key in ("org", "isp"):
            value = _safe_string(attrs.get(key), 80)
            if value:
                summary[key] = value
        last_update = _safe_timestamp(attrs.get("last_update"))
        if last_update:
            summary["last_update"] = last_update
        records = attrs.get("data")
        if isinstance(records, list):
            summary["service_count"] = min(len(records), 10_000)
        subdomains = attrs.get("subdomains")
        if isinstance(subdomains, list):
            summary["subdomain_count"] = min(len(subdomains), 10_000)
    elif provider == "otx":
        pulse_info = attrs.get("pulse_info", payload.get("pulse_info"))
        if isinstance(pulse_info, dict):
            count = _safe_int(pulse_info.get("count"), 0, 10_000_000)
            if count is not None:
                summary["pulse_count"] = count
        reputation = _safe_int(attrs.get("reputation", payload.get("reputation")), -1_000_000, 1_000_000)
        if reputation is not None:
            summary["reputation"] = reputation
        validation = attrs.get("validation", payload.get("validation"))
        if isinstance(validation, bool):
            summary["validated"] = validation
    elif provider == "rdns":
        ptr_host = _safe_string(attrs.get("ptr_hostname"), 253)
        if ptr_host:
            summary["ptr_hostname"] = ptr_host
        alias_count = _safe_int(attrs.get("aliases_count"), 0, 100)
        if alias_count is not None:
            summary["aliases_count"] = alias_count
    elif provider == "rdap":
        for key, out_key in (
            ("handle", "handle"),
            ("name", "network_name"),
            ("country", "country"),
            ("ldhName", "ldh_name"),
            ("startAddress", "start_address"),
            ("endAddress", "end_address"),
        ):
            val = _safe_string(attrs.get(key, payload.get(key)), 120)
            if val:
                summary[out_key] = val
        statuses = attrs.get("status", payload.get("status"))
        if isinstance(statuses, list):
            clean_statuses = [s for x in statuses if (s := _safe_string(x, 64))]
            if clean_statuses:
                summary["status"] = clean_statuses[:8]
    return summary


class OSINTService:
    """Read-only fixed-origin provider broker with fresh consent per operation."""

    def __init__(
        self,
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        env: Mapping[str, str] | None = None,
        minimum_interval_seconds: float = 1.0,
        rdns_resolver: Callable[[str], tuple[str, list[str], list[str]]] | None = None,
    ) -> None:
        self._transport = transport
        self._env = env if env is not None else os.environ
        self._minimum_interval_seconds = max(0.0, min(float(minimum_interval_seconds), 60.0))
        self._rdns_resolver = rdns_resolver
        self._rotated_keys: dict[str, str] = {}

    def rotate_key(self, provider: str, api_key: str) -> dict[str, Any]:
        """Rotate an in-memory provider API key without exposing secret material."""
        if provider not in _KEY_ENV:
            raise ValueError("unsupported_provider_key_rotation")
        cleaned = _clean_key(api_key)
        if cleaned is None:
            raise ValueError("invalid_api_key_format")
        self._rotated_keys[provider] = cleaned
        return {
            "provider": provider,
            "state": "rotated",
            "key_fingerprint": hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:12],
            "rotated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    def _provider_config(self, provider: str) -> _ProviderConfig:
        ack = _truthy(self._env.get(_ACK_ENV[provider]))
        raw_key = self._rotated_keys.get(provider) or (self._env.get(_KEY_ENV[provider]) if provider in _KEY_ENV else None)
        key = _clean_key(raw_key)
        if provider == "shodan" and not _truthy(self._env.get(_SHODAN_LOG_REDACTION_ACK_ENV)):
            return _ProviderConfig(key, False, "query_log_redaction_ack_required")
        if not ack:
            return _ProviderConfig(key, False, "terms_ack_required")
        if provider in {"rdns", "rdap"}:
            return _ProviderConfig(None, True, "ready")
        if provider == "greynoise" and key is None:
            return _ProviderConfig(None, True, "community")
        if key is None:
            return _ProviderConfig(None, False, "api_key_missing")
        return _ProviderConfig(key, True, "ready")

    def capabilities(self, *, enabled: bool) -> dict[str, Any]:
        providers = []
        for provider, name in _PROVIDER_NAMES.items():
            config = self._provider_config(provider)
            ready = bool(enabled and config.ready)
            state = "ready" if ready else "disabled_by_operator" if not enabled else config.state
            providers.append({
                "id": provider,
                "name": name,
                "ready": ready,
                "state": state,
                "supports": sorted(_SUPPORTED_TYPES[provider]),
                "reference": _REFERENCE_DOCS[provider],
            })
        return {
            "enabled": bool(enabled),
            "available": any(item["ready"] for item in providers),
            "providers": providers,
            "max_iocs_per_operation": MAX_IOCS_PER_OPERATION,
            "max_providers_per_operation": MAX_PROVIDERS_PER_OPERATION,
            "max_total_lookups": MAX_TOTAL_LOOKUPS,
            "max_response_bytes_per_lookup": MAX_RESPONSE_BYTES,
            "max_operation_seconds": MAX_OPERATION_SECONDS,
            "read_only": True,
            "accepted_inputs": ["public IPv4/IPv6", "public FQDN", "operator-selected artifact MD5/SHA-1/SHA-256"],
            "excluded_inputs": ["capture", "packet payload", "URI/path", "credentials", "raw logs"],
        }

    async def enrich(self, candidates: Sequence[IOCCandidate], providers: Sequence[str], *, consent: bool, enabled: bool) -> dict[str, Any]:
        if not consent:
            return {"state": "consent_required", "error_code": "osint_consent_required", "results": []}
        if not enabled:
            return {"state": "disabled", "error_code": "osint_disabled_by_operator", "results": []}
        if not 1 <= len(candidates) <= MAX_IOCS_PER_OPERATION:
            raise ValueError("ioc_count_limit_exceeded")
        if isinstance(providers, (str, bytes)) or not isinstance(providers, Sequence):
            raise ValueError("provider_list_required")
        selected = list(providers)
        if not 1 <= len(selected) <= MAX_PROVIDERS_PER_OPERATION or len(set(selected)) != len(selected):
            raise ValueError("provider_selection_invalid")
        if any(provider not in _PROVIDER_NAMES for provider in selected):
            raise ValueError("unsupported_provider")
        if len(candidates) * len(selected) > MAX_TOTAL_LOOKUPS:
            raise ValueError("lookup_count_limit_exceeded")
        if len({candidate.candidate_id for candidate in candidates}) != len(candidates):
            raise ValueError("duplicate_ioc_candidate")
        for candidate in candidates:
            normalized = _canonical_indicator(candidate.indicator, candidate.indicator_type)
            if normalized is None or normalized[0] != candidate.indicator_type or normalized[1] != candidate.indicator:
                raise ValueError("invalid_ioc_candidate")

        configs = {provider: self._provider_config(provider) for provider in selected}
        semaphore = asyncio.Semaphore(8)
        client_limits = httpx.Limits(max_connections=8, max_keepalive_connections=4)
        results: list[dict[str, Any]] = []
        tasks: list[tuple[IOCCandidate, str, asyncio.Task[dict[str, Any]]]] = []
        started = time.monotonic()
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(PER_REQUEST_TIMEOUT_SECONDS),
            limits=client_limits,
            trust_env=False,
            follow_redirects=False,
            transport=self._transport,
            headers={"Accept": "application/json", "User-Agent": "PCAPSCANNER-OSINT/1.0"},
        ) as client:
            for provider in selected:
                config = configs[provider]
                for candidate in candidates:
                    if candidate.indicator_type not in _SUPPORTED_TYPES[provider]:
                        results.append(self._result(candidate, provider, "unsupported_indicator_type"))
                    elif not config.ready:
                        results.append(self._result(candidate, provider, config.state))
                    else:
                        task = asyncio.create_task(self._lookup_guarded(client, semaphore, provider, candidate, config.key))
                        tasks.append((candidate, provider, task))
            if tasks:
                done, pending = await asyncio.wait([task for _, _, task in tasks], timeout=MAX_OPERATION_SECONDS)
                for candidate, provider, task in tasks:
                    if task in done:
                        try:
                            results.append(task.result())
                        except Exception:
                            results.append(self._result(candidate, provider, "provider_error"))
                    else:
                        task.cancel()
                        results.append(self._result(candidate, provider, "operation_timeout"))
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
        results.sort(key=lambda item: (item["provider"], item["candidate_id"]))
        success_count = sum(item["state"] in {"completed", "partial", "not_found"} for item in results)
        attempted = sum(item["state"] not in {"unsupported_indicator_type", "terms_ack_required", "api_key_missing"} for item in results)
        state = "completed" if results and success_count == len(results) else "partial" if success_count else "unavailable"
        return {
            "state": state,
            "error_code": None if success_count else "no_provider_lookup_completed",
            "requested_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "consent": True,
            "provider_ids": selected,
            "indicator_count": len(candidates),
            "lookup_count": len(results),
            "attempted_count": attempted,
            "elapsed_ms": min(MAX_OPERATION_SECONDS * 1000, int((time.monotonic() - started) * 1000)),
            "results": results,
        }

    async def _lookup_guarded(self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, provider: str, candidate: IOCCandidate, key: str | None) -> dict[str, Any]:
        async with semaphore:
            while True:
                with _PROCESS_RATE_LOCK:
                    now = time.monotonic()
                    delay = self._minimum_interval_seconds - (now - _PROCESS_LAST_REQUEST_AT.get(provider, 0.0))
                    if delay <= 0:
                        _PROCESS_LAST_REQUEST_AT[provider] = now
                        break
                await asyncio.sleep(delay)
            return await self._request_one(client, provider, candidate, key)

    @staticmethod
    def _result(candidate: IOCCandidate, provider: str, state: str, summary: dict[str, Any] | None = None, retry_after: int | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "candidate_id": candidate.candidate_id,
            "indicator_type": candidate.indicator_type,
            "provider": provider,
            "state": state,
            "summary": summary or {},
            "source_reference": _REFERENCE_DOCS[provider],
        }
        if retry_after is not None:
            result["retry_after_seconds"] = retry_after
        return result

    async def _request_one(self, client: httpx.AsyncClient, provider: str, candidate: IOCCandidate, key: str | None) -> dict[str, Any]:
        indicator = candidate.indicator
        if provider == "rdns":
            resolver = self._rdns_resolver or socket.gethostbyaddr
            try:
                host_tuple = await asyncio.wait_for(
                    asyncio.to_thread(resolver, indicator),
                    timeout=PER_REQUEST_TIMEOUT_SECONDS,
                )
            except (socket.herror, socket.gaierror):
                return self._result(candidate, provider, "not_found")
            except (asyncio.TimeoutError, TimeoutError):
                return self._result(candidate, provider, "provider_timeout")
            except OSError:
                return self._result(candidate, provider, "provider_error")
            hostname = str(host_tuple[0] or "").rstrip(".").lower() if host_tuple else ""
            aliases = host_tuple[1] if len(host_tuple) > 1 and isinstance(host_tuple[1], list) else []
            return self._result(
                candidate,
                provider,
                "completed" if hostname else "not_found",
                _allowlisted_summary("rdns", {"ptr_hostname": hostname, "aliases_count": len(aliases)}),
            )

        encoded = quote(indicator, safe=".-")
        headers: dict[str, str] = {}
        params: dict[str, str] = {}
        if provider == "virustotal":
            resource = "ip_addresses" if candidate.indicator_type in {"ipv4", "ipv6"} else "domains" if candidate.indicator_type == "domain" else "files"
            url = f"https://www.virustotal.com/api/v3/{resource}/{encoded}"
            headers["x-apikey"] = key or ""
        elif provider == "abuseipdb":
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": indicator, "maxAgeInDays": "90"}
            headers.update({"Key": key or "", "Accept": "application/json"})
        elif provider == "greynoise":
            if key:
                url = f"https://api.greynoise.io/v3/ip/{encoded}"
                params = {"quick": "true"}
                headers["key"] = key
            else:
                if candidate.indicator_type != "ipv4":
                    return self._result(candidate, provider, "api_key_required_for_indicator")
                url = f"https://api.greynoise.io/v3/community/{encoded}"
        elif provider == "shodan":
            if candidate.indicator_type == "domain":
                url = f"https://api.shodan.io/dns/domain/{encoded}"
            else:
                url = f"https://api.shodan.io/shodan/host/{encoded}"
                params["minify"] = "true"
            # Shodan's documented REST API places the key in a query parameter.
            # Do not log request URLs or propagate HTTP exceptions.
            params["key"] = key or ""
        elif provider == "rdap":
            if candidate.indicator_type == "domain":
                url = f"https://rdap.org/domain/{encoded}"
            else:
                url = f"https://rdap.arin.net/registry/ip/{encoded}"
            headers["Accept"] = "application/rdap+json, application/json"
        else:
            kind = "IPv4" if candidate.indicator_type == "ipv4" else "IPv6" if candidate.indicator_type == "ipv6" else "domain" if candidate.indicator_type == "domain" else "file"
            url = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{encoded}/general"
            headers["X-OTX-API-KEY"] = key or ""

        try:
            async with client.stream("GET", url, params=params, headers=headers) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    return self._result(candidate, provider, "redirect_blocked")
                if response.status_code == 404:
                    return self._result(candidate, provider, "not_found")
                if response.status_code == 429:
                    retry_after = _safe_int(response.headers.get("Retry-After"), 0, MAX_RATE_RETRY_AFTER_SECONDS)
                    return self._result(candidate, provider, "rate_limited", retry_after=retry_after)
                if response.status_code in {401, 403}:
                    return self._result(candidate, provider, "provider_auth_or_plan_error")
                if response.status_code not in {200, 206}:
                    return self._result(candidate, provider, "provider_error")
                content_length = _safe_int(response.headers.get("Content-Length"), 0, MAX_RESPONSE_BYTES)
                if response.headers.get("Content-Length") and content_length is None:
                    return self._result(candidate, provider, "response_too_large")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                        return self._result(candidate, provider, "response_too_large")
                    body.extend(chunk)
        except (httpx.TimeoutException, asyncio.TimeoutError):
            return self._result(candidate, provider, "provider_timeout")
        except (httpx.HTTPError, OSError, ValueError):
            return self._result(candidate, provider, "provider_error")
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._result(candidate, provider, "invalid_provider_response")
        state = "partial" if response.status_code == 206 else "completed"
        return self._result(candidate, provider, state, _allowlisted_summary(provider, payload))
