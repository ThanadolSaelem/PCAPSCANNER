from __future__ import annotations

import json

import pytest

from backend.app.llm.chat import ChatLimits, answer_question
from backend.app.models import Coverage, Evidence, EvidenceBundle, Finding, Stage


def make_bundle() -> EvidenceBundle:
    return EvidenceBundle(
        capture_sha256="a" * 64,
        coverage=Coverage(
            packets_seen=2,
            packets_analyzed=2,
            truncated=False,
            parser="fixture",
            warnings=[],
            stages=[Stage(name="parse", state="completed", detail="ok")],
        ),
        evidence=[
            Evidence(
                evidence_id="EV-000001",
                kind="http",
                summary="RAW PACKET PAYLOAD: payload-secret",
                packet_refs=[1],
                attributes={
                    "src_ip": "10.20.30.40",
                    "dst_ip": "8.8.8.8",
                    "protocol": "TCP",
                    "dst_port": 443,
                    "http_path": "/admin/reset?token=uri-path-secret",
                    "filename": "private-capture.pcap",
                },
            ),
        ],
        findings=[
            Finding(
                finding_id="F-0001",
                detector="fixture",
                title="Observed flow",
                severity="low",
                confidence="low",
                evidence_ids=["EV-000001"],
            )
        ],
    )


def claim_response(evidence_id: str = "EV-000001") -> str:
    return json.dumps(
        {"claims": [{"claim": "The evidence records one observed flow.", "evidence_ids": [evidence_id]}]}
    )


@pytest.mark.asyncio
async def test_requires_consent_for_each_turn_and_never_calls_provider_without_it():
    called = False

    async def provider(prompt: str) -> str:
        nonlocal called
        called = True
        return claim_response()

    result = await answer_question(make_bundle(), "Summarize this analysis", consent=False, provider=provider)
    assert result.state == "consent_required"
    assert result.error_code == "per_turn_consent_required"
    assert not called


@pytest.mark.asyncio
async def test_provider_receives_only_safe_projection_and_claim_is_returned():
    observed: list[str] = []

    async def provider(prompt: str) -> str:
        observed.append(prompt)
        return claim_response()

    result = await answer_question(
        make_bundle(),
        "What does this flow show? /admin/reset?token=question-secret https://host.example/private/path private.example "
        "Authorization: Bearer BEARER-SENTINEL token=TOKEN-SENTINEL password=PASSWORD-SENTINEL "
        "Authorization: Basic BASIC-SENTINEL api_key=APIKEY-SENTINEL 00:11:22:33:44:55 0011.2233.4455",
        consent=True,
        provider=provider,
    )

    assert result.state == "completed"
    assert result.claims[0].evidence_ids == ["EV-000001"]
    assert result.prompt_sha256 and len(observed) == 1
    prompt = observed[0]
    for forbidden in (
        "RAW PACKET PAYLOAD",
        "payload-secret",
        "10.20.30.40",
        "8.8.8.8",
        "uri-path-secret",
        "private-capture.pcap",
        "/admin/reset",
        "question-secret",
        "https://host.example/private/path",
        "private.example",
        "BEARER-SENTINEL",
        "BASIC-SENTINEL",
        "TOKEN-SENTINEL",
        "PASSWORD-SENTINEL",
        "APIKEY-SENTINEL",
        "00:11:22:33:44:55",
        "0011.2233.4455",
        "a" * 64,
    ):
        assert forbidden not in prompt
    assert "id_" in prompt
    assert "EV-000001" in prompt


@pytest.mark.asyncio
async def test_unknown_citation_is_rejected():
    async def provider(prompt: str) -> str:
        return claim_response("EV-999999")

    result = await answer_question(make_bundle(), "Which evidence is relevant?", consent=True, provider=provider)
    assert result.state == "invalid_output"
    assert result.error_code == "unknown_citation"
    assert result.claims == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("output", ['{"claims": []}', '{"claims": [{"claim": "", "evidence_ids": ["EV-000001"]}]}'])
async def test_empty_claim_lists_or_empty_claim_text_are_rejected(output: str):
    async def provider(prompt: str) -> str:
        return output

    result = await answer_question(make_bundle(), "What was observed?", consent=True, provider=provider)
    assert result.state == "invalid_output"
    assert result.claims == ()


@pytest.mark.asyncio
async def test_input_budget_prevents_provider_call():
    called = False

    async def provider(prompt: str) -> str:
        nonlocal called
        called = True
        return claim_response()

    limits = ChatLimits(max_context_bytes=32)
    result = await answer_question(make_bundle(), "Explain", consent=True, provider=provider, limits=limits)
    assert result.state == "budget_exceeded"
    assert result.error_code == "context_budget_exceeded"
    assert not called


@pytest.mark.asyncio
async def test_output_budget_and_timeout_fail_closed():
    async def oversized(prompt: str) -> str:
        return json.dumps({"claims": [{"claim": "x" * 200, "evidence_ids": ["EV-000001"]}]})

    limited = await answer_question(
        make_bundle(), "Explain", consent=True, provider=oversized,
        limits=ChatLimits(max_output_bytes=100),
    )
    assert limited.state == "budget_exceeded"
    assert limited.error_code == "output_budget_exceeded"

    async def hanging(prompt: str) -> str:
        import asyncio
        await asyncio.sleep(1)
        return claim_response()

    timed_out = await answer_question(
        make_bundle(), "Explain", consent=True, provider=hanging,
        limits=ChatLimits(timeout_seconds=0.01),
    )
    assert timed_out.state == "unavailable"
    assert timed_out.error_code == "provider_timeout"
    assert timed_out.claims == ()


@pytest.mark.asyncio
async def test_reasoning_tags_and_markdown_fences_parsed_cleanly():
    raw_with_think = (
        "<think>\n"
        "1. The user asks about flows in the capture.\n"
        "2. Evidence EV-000001 has HTTP flow data.\n"
        "</think>\n"
        "```json\n"
        '{"claims": [{"claim": "Observed one HTTP flow in EV-000001", "evidence_ids": ["ev_1"]}]}\n'
        "```\n"
    )

    async def reasoning_provider(prompt: str) -> str:
        return raw_with_think

    result = await answer_question(make_bundle(), "Explain flow", consent=True, provider=reasoning_provider)
    assert result.state == "completed"
    assert len(result.claims) == 1
    assert result.claims[0].claim == "Observed one HTTP flow in EV-000001"
    assert result.claims[0].evidence_ids == ["EV-000001"]


@pytest.mark.asyncio
async def test_direct_claim_list_shape_accepted():
    raw_list = '[{"claim": "Direct list format", "evidence_ids": ["EV-000001"]}]'

    async def list_provider(prompt: str) -> str:
        return raw_list

    result = await answer_question(make_bundle(), "Explain flow", consent=True, provider=list_provider)
    assert result.state == "completed"
    assert len(result.claims) == 1
    assert result.claims[0].claim == "Direct list format"


@pytest.mark.asyncio
async def test_provider_output_length_is_not_masked_as_provider_error():
    from backend.app.llm.providers import _RequestFailure

    async def truncated_provider(prompt: str) -> str:
        raise _RequestFailure("output_length")

    result = await answer_question(make_bundle(), "Explain flow", consent=True, provider=truncated_provider)
    assert result.state == "invalid_output"
    assert result.error_code == "output_length"


