from __future__ import annotations

import sys
import asyncio
import logging
import time
from pathlib import Path

import httpx
import pytest
import backend.app.osint_service as osint_module

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.models import Coverage, Evidence, EvidenceBundle
from backend.app.osint_service import (
    MAX_IOCS_PER_OPERATION,
    MAX_OPERATION_SECONDS,
    MAX_PROVIDERS_PER_OPERATION,
    MAX_RESPONSE_BYTES,
    IOCCandidate,
    OSINTService,
    extract_ioc_candidates,
)


def _candidate(indicator: str = "8.8.8.8", indicator_type: str = "ipv4") -> IOCCandidate:
    return IOCCandidate("IOC-0123456789abcdef", indicator_type, indicator, ("EV-000001",))  # type: ignore[arg-type]


def _env(provider: str = "virustotal") -> dict[str, str]:
    env = {
        f"PCAP_OSINT_{provider.upper()}_API_KEY": "test-api-key-12345",
        f"PCAP_OSINT_{provider.upper()}_" + {
            "virustotal": "PREMIUM_LICENSE_ACK",
            "abuseipdb": "TERMS_ACK",
            "greynoise": "LICENSE_ACK",
            "shodan": "AUTOMATION_ACK",
            "otx": "AUTHORIZED_USE_ACK",
        }[provider]: "1",
    }
    if provider == "shodan":
        env["PCAP_OSINT_SHODAN_QUERY_LOG_REDACTION_ACK"] = "1"
    return env


def _bundle() -> EvidenceBundle:
    return EvidenceBundle(
        capture_sha256="a" * 64,
        coverage=Coverage(packets_seen=3, packets_analyzed=3, truncated=False, parser="test"),
        evidence=[
            Evidence(evidence_id="EV-000001", kind="flow", summary="flow", packet_refs=[1], attributes={"src_ip": "8.8.8.8", "dst_ip": "10.0.0.4"}),
            Evidence(evidence_id="EV-000002", kind="dns", summary="dns", packet_refs=[2], attributes={"query": "edge.google.com", "src_ip": "8.8.8.8"}),
            Evidence(evidence_id="EV-000003", kind="yara", summary="hash only", packet_refs=[3], attributes={"object_sha256": "b" * 64, "uri": "/private/path"}),
        ],
        findings=[],
    )


@pytest.mark.asyncio
async def test_requires_fresh_consent_and_admin_switch_before_any_request() -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": {"attributes": {"reputation": 0}}})

    service = OSINTService(transport=httpx.MockTransport(handler), env=_env(), minimum_interval_seconds=0)
    denied = await service.enrich([_candidate()], ["virustotal"], consent=False, enabled=True)
    disabled = await service.enrich([_candidate()], ["virustotal"], consent=True, enabled=False)

    assert denied == {"state": "consent_required", "error_code": "osint_consent_required", "results": []}
    assert disabled["state"] == "disabled"
    assert calls == 0


@pytest.mark.asyncio
async def test_virustotal_uses_fixed_https_origin_header_auth_and_allowlisted_summary() -> None:
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 12, "undetected": 30},
            "reputation": -2,
            "country": "US",
            "asn": 15169,
            "last_analysis_date": 1_700_000_000,
            "last_analysis_results": {"engine": {"result": "raw provider detail must not persist"}},
        }}})

    service = OSINTService(transport=httpx.MockTransport(handler), env=_env(), minimum_interval_seconds=0)
    response = await service.enrich([_candidate()], ["virustotal"], consent=True, enabled=True)

    assert response["state"] == "completed"
    assert len(seen) == 1
    request = seen[0]
    assert request.url.scheme == "https"
    assert request.url.host == "www.virustotal.com"
    assert request.url.path == "/api/v3/ip_addresses/8.8.8.8"
    assert request.headers["x-apikey"] == "test-api-key-12345"
    assert "key" not in request.url.params
    summary = response["results"][0]["summary"]
    assert summary == {
        "malicious": 3, "suspicious": 1, "harmless": 12, "undetected": 30,
        "reputation": -2, "country": "US", "asn": 15169, "last_analysis_epoch": 1_700_000_000,
    }
    assert "raw provider detail" not in str(response)
    assert "8.8.8.8" not in str(response)


def test_candidate_extraction_is_structured_deduplicated_and_excludes_private_or_path_data() -> None:
    candidates, truncated = extract_ioc_candidates(_bundle(), ["EV-000001", "EV-000002", "EV-000003"])

    assert not truncated
    assert [(item.indicator_type, item.indicator) for item in candidates] == [
        ("domain", "edge.google.com"),
        ("ipv4", "8.8.8.8"),
        ("sha256", "b" * 64),
    ]
    ip_candidate = next(item for item in candidates if item.indicator_type == "ipv4")
    assert ip_candidate.evidence_ids == ("EV-000001", "EV-000002")
    assert all("/private/path" not in item.indicator for item in candidates)


def test_candidate_extraction_excludes_iana_special_use_and_private_domain_names() -> None:
    base = _bundle()
    extra = [
        Evidence(evidence_id=f"EV-{index:06d}", kind="dns", summary="dns", packet_refs=[index], attributes={"query": name})
        for index, name in enumerate(("db.corp", "host.onion", "router.home.arpa", "node.example.com", "cache.internal.google.com"), start=4)
    ]
    bundle = base.model_copy(update={"evidence": [*base.evidence, *extra]})

    candidates, _ = extract_ioc_candidates(bundle, [item.evidence_id for item in bundle.evidence])

    domains = {item.indicator for item in candidates if item.indicator_type == "domain"}
    assert domains == {"edge.google.com"}


@pytest.mark.asyncio
async def test_provider_429_is_reported_without_automatic_retry() -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": "12"})

    service = OSINTService(transport=httpx.MockTransport(handler), env=_env(), minimum_interval_seconds=0)
    response = await service.enrich([_candidate()], ["virustotal"], consent=True, enabled=True)

    assert calls == 1
    assert response["state"] == "unavailable"
    assert response["results"][0]["state"] == "rate_limited"
    assert response["results"][0]["retry_after_seconds"] == 12


@pytest.mark.asyncio
async def test_provider_rate_limit_is_shared_across_service_instances_in_process() -> None:
    with osint_module._PROCESS_RATE_LOCK:
        osint_module._PROCESS_LAST_REQUEST_AT.pop("virustotal", None)
    started: list[float] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        started.append(time.monotonic())
        return httpx.Response(200, json={"data": {"attributes": {"reputation": 0}}})

    first = OSINTService(transport=httpx.MockTransport(handler), env=_env(), minimum_interval_seconds=0.04)
    second = OSINTService(transport=httpx.MockTransport(handler), env=_env(), minimum_interval_seconds=0.04)
    await asyncio.gather(
        first.enrich([_candidate()], ["virustotal"], consent=True, enabled=True),
        second.enrich([_candidate("1.1.1.1", "ipv4")], ["virustotal"], consent=True, enabled=True),
    )

    assert len(started) == 2
    assert started[1] - started[0] >= 0.035


@pytest.mark.asyncio
async def test_redirects_are_not_followed_and_response_body_is_bounded() -> None:
    calls: list[str] = []

    async def redirect_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://attacker.invalid/collect"})

    service = OSINTService(transport=httpx.MockTransport(redirect_handler), env=_env(), minimum_interval_seconds=0)
    redirected = await service.enrich([_candidate()], ["virustotal"], consent=True, enabled=True)
    assert redirected["results"][0]["state"] == "redirect_blocked"
    assert len(calls) == 1
    assert "attacker.invalid" not in str(calls)

    async def large_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))

    large_service = OSINTService(transport=httpx.MockTransport(large_handler), env=_env(), minimum_interval_seconds=0)
    oversized = await large_service.enrich([_candidate()], ["virustotal"], consent=True, enabled=True)
    assert oversized["results"][0]["state"] == "response_too_large"
    assert "x" * 200 not in str(oversized)


@pytest.mark.asyncio
async def test_shodan_key_is_sent_only_to_its_fixed_origin_and_summary_omits_banners() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.scheme == "https"
        assert request.url.host == "api.shodan.io"
        assert request.url.path == "/shodan/host/8.8.8.8"
        assert request.url.params["key"] == "test-api-key-12345"
        return httpx.Response(200, json={
            "ports": [80, 443, 80],
            "asn": "AS15169",
            "country_code": "US",
            "org": "Example Org",
            "last_update": "2026-11-17T12:00:00Z",
            "data": [{"data": "raw banner content"}],
            "opts": {"raw": "raw packet-like data"},
        })

    service = OSINTService(transport=httpx.MockTransport(handler), env=_env("shodan"), minimum_interval_seconds=0)
    response = await service.enrich([_candidate()], ["shodan"], consent=True, enabled=True)

    assert response["state"] == "completed"
    assert response["results"][0]["summary"] == {
        "ports": [80, 443], "asn": "AS15169", "country_code": "US", "org": "Example Org", "last_update": "2026-11-17T12:00:00Z", "service_count": 1,
    }
    assert "raw banner content" not in str(response)
    assert "raw packet-like data" not in str(response)
    assert "test-api-key-12345" not in str(response)


@pytest.mark.asyncio
async def test_shodan_is_unavailable_without_query_log_redaction_ack() -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"ports": [80]})

    env = _env("shodan")
    env.pop("PCAP_OSINT_SHODAN_QUERY_LOG_REDACTION_ACK")
    service = OSINTService(transport=httpx.MockTransport(handler), env=env, minimum_interval_seconds=0)
    caps = service.capabilities(enabled=True)
    result = await service.enrich([_candidate()], ["shodan"], consent=True, enabled=True)

    shodan = next(item for item in caps["providers"] if item["id"] == "shodan")
    assert shodan["state"] == "query_log_redaction_ack_required"
    assert result["results"][0]["state"] == "query_log_redaction_ack_required"
    assert calls == 0


@pytest.mark.asyncio
async def test_shodan_query_key_is_redacted_from_builtin_http_logs(caplog) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["key"] == "test-api-key-12345"
        return httpx.Response(200, json={"subdomains": [], "data": []})

    service = OSINTService(transport=httpx.MockTransport(handler), env=_env("shodan"), minimum_interval_seconds=0)
    caplog.set_level(logging.DEBUG, logger="httpx")
    caplog.set_level(logging.DEBUG, logger="httpcore.http11")
    result = await service.enrich(
        [_candidate("scan-test.google.com", "domain")], ["shodan"], consent=True, enabled=True
    )

    assert result["state"] == "completed"
    assert "test-api-key-12345" not in caplog.text


@pytest.mark.asyncio
async def test_greynoise_community_requires_ack_and_is_ipv4_only() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"ip": "8.8.8.8", "classification": "unknown", "noise": False, "riot": True, "raw_data": {"uri": "/sensitive"}})

    env = {"PCAP_OSINT_GREYNOISE_LICENSE_ACK": "1"}
    service = OSINTService(transport=httpx.MockTransport(handler), env=env, minimum_interval_seconds=0)
    ipv4 = await service.enrich([_candidate()], ["greynoise"], consent=True, enabled=True)
    ipv6_candidate = _candidate("2001:4860:4860::8888", "ipv6")
    ipv6 = await service.enrich([ipv6_candidate], ["greynoise"], consent=True, enabled=True)

    assert ipv4["state"] == "completed"
    assert ipv4["results"][0]["summary"] == {"classification": "unknown", "noise": False, "riot": True}
    assert ipv6["results"][0]["state"] == "api_key_required_for_indicator"
    assert len(calls) == 1
    assert "/sensitive" not in str(ipv4)


@pytest.mark.asyncio
async def test_abuseipdb_uses_key_header_and_fixed_query_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.abuseipdb.com"
        assert request.url.path == "/api/v2/check"
        assert request.headers["Key"] == "test-api-key-12345"
        assert request.url.params["ipAddress"] == "8.8.8.8"
        assert request.url.params["maxAgeInDays"] == "90"
        return httpx.Response(200, json={"data": {
            "abuseConfidenceScore": 12,
            "totalReports": 9,
            "numDistinctUsers": 5,
            "countryCode": "US",
            "usageType": "Data Center",
            "isTor": False,
            "lastReportedAt": "2026-11-16T00:00:00Z",
            "reports": [{"comment": "raw comment must not persist"}],
        }})

    service = OSINTService(transport=httpx.MockTransport(handler), env=_env("abuseipdb"), minimum_interval_seconds=0)
    response = await service.enrich([_candidate()], ["abuseipdb"], consent=True, enabled=True)

    assert response["state"] == "completed"
    summary = response["results"][0]["summary"]
    assert summary["abuse_confidence"] == 12
    assert summary["distinct_reporters"] == 5
    assert summary["is_tor"] is False
    assert "raw comment" not in str(response)
    assert "8.8.8.8" not in str(response)


@pytest.mark.asyncio
async def test_paid_greynoise_uses_quick_mode_and_never_retains_raw_data() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.greynoise.io"
        assert request.url.path == "/v3/ip/8.8.8.8"
        assert request.url.params["quick"] == "true"
        assert request.headers["key"] == "test-api-key-12345"
        return httpx.Response(200, json={"classification": "benign", "noise": True, "riot": False,
                                        "first_seen": "2026-01-01T00:00:00Z", "tags": ["scanner", "bot"],
                                        "raw_data": [{"uri": "/secret", "authorization": "hidden"}]})

    service = OSINTService(transport=httpx.MockTransport(handler), env=_env("greynoise"), minimum_interval_seconds=0)
    response = await service.enrich([_candidate()], ["greynoise"], consent=True, enabled=True)

    assert response["state"] == "completed"
    assert response["results"][0]["summary"]["classification"] == "benign"
    assert "tags" not in response["results"][0]["summary"]
    assert "/secret" not in str(response)
    assert "authorization" not in str(response)


@pytest.mark.asyncio
async def test_otx_uses_fixed_indicator_path_and_header_auth() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "otx.alienvault.com"
        assert request.url.path == "/api/v1/indicators/IPv4/8.8.8.8/general"
        assert request.headers["X-OTX-API-KEY"] == "test-api-key-12345"
        return httpx.Response(200, json={"pulse_info": {"count": 4, "pulses": [{"name": "omit"}]},
                                        "validation": True, "reputation": 3, "raw": "omit"})

    service = OSINTService(transport=httpx.MockTransport(handler), env=_env("otx"), minimum_interval_seconds=0)
    response = await service.enrich([_candidate()], ["otx"], consent=True, enabled=True)

    assert response["state"] == "completed"
    assert response["results"][0]["summary"] == {"pulse_count": 4, "reputation": 3, "validated": True}
    assert "omit" not in str(response)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("candidate", "expected_path"),
    [
        (_candidate("scan-test.google.com", "domain"), "/api/v3/domains/scan-test.google.com"),
        (_candidate("b" * 64, "sha256"), "/api/v3/files/" + "b" * 64),
    ],
)
async def test_virustotal_uses_fixed_domain_and_hash_routes(candidate: IOCCandidate, expected_path: str) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "www.virustotal.com"
        assert request.url.path == expected_path
        assert request.headers["x-apikey"] == "test-api-key-12345"
        return httpx.Response(200, json={"data": {"attributes": {"reputation": 0}}})

    service = OSINTService(transport=httpx.MockTransport(handler), env=_env(), minimum_interval_seconds=0)
    response = await service.enrich([candidate], ["virustotal"], consent=True, enabled=True)
    assert response["state"] == "completed"


@pytest.mark.asyncio
async def test_shodan_domain_route_uses_key_query_and_only_retains_count() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.shodan.io"
        assert request.url.path == "/dns/domain/scan-test.google.com"
        assert request.url.params["key"] == "test-api-key-12345"
        return httpx.Response(200, json={"subdomains": ["www", "mail"], "data": [{"value": "secret"}]})

    service = OSINTService(transport=httpx.MockTransport(handler), env=_env("shodan"), minimum_interval_seconds=0)
    response = await service.enrich([_candidate("scan-test.google.com", "domain")], ["shodan"], consent=True, enabled=True)
    assert response["results"][0]["summary"] == {"service_count": 1, "subdomain_count": 2}
    assert "secret" not in str(response)


def test_capability_summary_exposes_readiness_but_never_credentials() -> None:
    caps = OSINTService(env=_env()).capabilities(enabled=True)

    assert caps["enabled"] is True
    assert caps["available"] is True
    assert caps["max_iocs_per_operation"] == MAX_IOCS_PER_OPERATION
    assert caps["max_providers_per_operation"] == MAX_PROVIDERS_PER_OPERATION
    assert caps["max_operation_seconds"] == MAX_OPERATION_SECONDS
    assert "test-api-key-12345" not in str(caps)
    assert all(set(item).isdisjoint({"key", "api_key", "secret"}) for item in caps["providers"])
