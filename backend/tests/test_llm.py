from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from backend.app.config import AIConfig, AppSettings, load_settings
from backend.app.llm import generate_chat_completion, generate_summary, list_models
from backend.app.models import (
    AISummary,
    Confidence,
    Coverage,
    Evidence,
    EvidenceBundle,
    Finding,
    Stage,
)


ORIGIN = "http://127.0.0.1:11434"


def bundle(*, confidence: Confidence = "high") -> EvidenceBundle:
    return EvidenceBundle(
        capture_sha256="a" * 64,
        coverage=Coverage(
            packets_seen=10,
            packets_analyzed=10,
            truncated=False,
            parser="tshark",
            warnings=["untrusted warning"],
            stages=[Stage(name="parse", state="completed", detail="not sent")],
        ),
        evidence=[
            Evidence(
                evidence_id="EV-000001",
                kind="flow",
                summary="RAW PAYLOAD bearer totally-secret; this must never be sent",
                packet_refs=[1, 2],
                attributes={
                    "src_ip": "10.1.2.3",
                    "dst_ip": "8.8.8.8",
                    "protocol": "TCP",
                    "src_port": 1234,
                    "dst_port": 443,
                    "packet_count": 2,
                    "filename": "capture-secret.pcap",
                    "cookie": "session=secret",
                },
            ),
            Evidence(
                evidence_id="EV-000002",
                kind="dns",
                summary="free text should not leave process",
                packet_refs=[3],
                attributes={"domain": "secret.example", "query": "credentials"},
            ),
        ],
        findings=[
            Finding(
                finding_id="F-0001",
                detector="detector-one",
                title="Suspicious flow",
                severity="high",
                confidence=confidence,
                evidence_ids=["EV-000001"],
                limitations=["Only deterministic parser fields were used"],
            )
        ],
    )


def settings(**kwargs) -> AppSettings:
    values = {
        "enabled": True,
        "provider": "openai_compatible",
        "base_url": ORIGIN,
        "allowed_origins": [ORIGIN],
        "data_boundary": "local",
        "model": "test-model",
        "timeout_seconds": 2,
        "retries": 0,
    }
    values.update(kwargs)
    config = AIConfig(**values)
    return AppSettings(ai=config)


def summary_payload(*, confidence: str = "low", evidence_id: str = "EV-000001") -> dict:
    return {
        "summary": [{"claim": "Evidence-only summary", "evidence_ids": [evidence_id]}],
        "assessments": [
            {
                "finding_id": "F-0001",
                "interpretation": "The deterministic finding is retained.",
                "confidence": confidence,
                "evidence_ids": [evidence_id],
            }
        ],
        "limitations": [
            {"claim": "AI interpretation is not proof of compromise", "evidence_ids": [evidence_id]}
        ],
        "recommended_actions": [{"action": "Review the cited flow", "evidence_ids": [evidence_id]}],
    }


@pytest.mark.asyncio
async def test_disabled_never_calls_transport():
    called = False

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    disabled = AppSettings(ai=AIConfig(enabled=False))
    result = await generate_summary(bundle(), disabled, transport=httpx.MockTransport(handler))
    assert result.state == "disabled"
    assert result.report is None
    assert called is False


def test_ai_enabled_by_default_with_local_ollama_defaults_and_opt_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg = AIConfig()
    assert cfg.enabled is True
    assert cfg.provider == "openai_compatible"
    assert cfg.data_boundary == "local"
    assert cfg.allowed_origins == [ORIGIN]
    assert cfg.model is None

    with_model = AIConfig(model="qwen2.5:7b")
    assert with_model.enabled is True
    assert with_model.data_boundary == "local"
    assert with_model.allowed_origins == [ORIGIN]

    monkeypatch.delenv("PCAP_AI_CONFIG", raising=False)
    monkeypatch.delenv("PCAP_AI_ENABLED", raising=False)
    monkeypatch.delenv("PCAP_WORKSPACE_CONFIG", raising=False)
    monkeypatch.delenv("PCAP_ENABLE_NATIVE_PICKER", raising=False)
    monkeypatch.delenv("PCAP_USE_WORKSPACE_CONFIG", raising=False)
    monkeypatch.setenv("PCAP_DATA_DIR", str(tmp_path / "data"))
    loaded_default = load_settings()
    assert loaded_default.ai.enabled is True
    assert loaded_default.ai.data_boundary == "local"
    assert loaded_default.ai.allowed_origins == [ORIGIN]

    monkeypatch.setenv("PCAP_AI_ENABLED", "0")
    loaded_opt_out = load_settings()
    assert loaded_opt_out.ai.enabled is False

    # Custom endpoint still fails closed without explicit allowed_origins.
    with pytest.raises(ValidationError):
        AIConfig(base_url="https://api.example/v1")


@pytest.mark.asyncio
async def test_grounded_chat_completion_uses_strict_schema_and_bounded_output():
    requests = []
    answer = {"claims": [{"claim": "The cited flow is present.", "evidence_ids": ["EV-000001"]}]}

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(answer)}, "finish_reason": "stop"}]},
        )

    raw = await generate_chat_completion(
        "Return one evidence-cited claim.",
        settings(max_output_tokens=8_000),
        transport=httpx.MockTransport(handler),
    )
    assert json.loads(raw) == answer
    assert len(requests) == 1
    request = requests[0]
    assert request["max_tokens"] == 1_200
    assert request["response_format"]["json_schema"]["strict"] is True
    assert request["response_format"]["json_schema"]["schema"]["additionalProperties"] is False
    assert request["messages"][-1]["content"] == "Return one evidence-cited claim."


def test_settings_defaults_secret_and_nonsecret_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    config_path = tmp_path / "ai.yaml"
    config_path.write_text(
        """
ai:
  enabled: false
  provider: openai_compatible
  api_key_env: PCAP_AI_API_KEY
  timeout_seconds: 12
storage_max_captures: 7
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("PCAP_AI_CONFIG", str(config_path))
    monkeypatch.setenv("PCAP_API_TOKEN", "top-secret")
    loaded = load_settings()
    assert loaded.storage_max_captures == 7
    assert loaded.api_token == SecretStr("top-secret")
    assert "top-secret" not in loaded.model_dump_json()
    assert "api_key_env" in loaded.model_dump_json()

    config_path.write_text("ai:\n  api_key: leaked\n", encoding="utf-8")
    with pytest.raises(ValueError, match="secret_config_value_forbidden"):
        load_settings()


def test_endpoint_and_origin_policy():
    with pytest.raises(ValidationError):
        AIConfig(
            enabled=True,
            provider="openai_compatible",
            base_url="http://127.0.0.1:11434",
            data_boundary="local",
            model="m",
        )
    with pytest.raises(ValidationError):
        AIConfig(
            enabled=True,
            provider="openai_compatible",
            base_url="http://10.0.0.1:11434",
            data_boundary="remote",
            allowed_origins=["http://10.0.0.1:11434"],
            model="m",
        )
    with pytest.raises(ValidationError):
        AIConfig(
            enabled=True,
            provider="openai_compatible",
            base_url="https://169.254.169.254/v1",
            allowed_origins=["https://169.254.169.254"],
            model="m",
        )
    with pytest.raises(ValidationError):
        AIConfig(
            enabled=True,
            provider="openai_compatible",
            base_url="https://api.example/v1?key=secret",
            allowed_origins=["https://api.example"],
            model="m",
        )


@pytest.mark.asyncio
async def test_redaction_pseudonymization_and_no_raw_capture():
    seen: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(summary_payload())}, "finish_reason": "stop"}]})

    result = await generate_summary(bundle(), settings(), transport=httpx.MockTransport(handler))
    assert result.state == "completed"
    assert result.prompt_version == "2.0"
    prompt = json.dumps(seen[0])
    assert "RAW PAYLOAD" not in prompt
    assert "bearer totally-secret" not in prompt
    assert "capture-secret.pcap" not in prompt
    assert "session=secret" not in prompt
    assert "10.1.2.3" not in prompt
    assert "secret.example" not in prompt
    assert "id_" in prompt
    assert "F-0001" in prompt and "EV-000001" in prompt

@pytest.mark.asyncio
async def test_uri_paths_and_uri_derived_metrics_are_not_sent_to_ai():
    seen: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(summary_payload())}, "finish_reason": "stop"}]})

    evidence_bundle = bundle()
    evidence_bundle.evidence[0].attributes.update(
        {
            "http_path": "/admin/reset?token=AI-URI-SENTINEL",
            "http_uri_max_len": 987654,
            "http_uri_max_entropy": 7.125,
            "http_xss_hits": 11,
            "http_crlf_hits": 12,
            "http_sqli_hits": 13,
            "http_shell_hits": 14,
            "http_host_ip_hits": 15,
        }
    )
    evidence_bundle.coverage.warnings = ["diagnostic at /private/capture.pcap for sensor.example"]
    evidence_bundle.coverage.stages[0].detail = "input /Users/operator/secret.pcap from host.example"
    result = await generate_summary(evidence_bundle, settings(), transport=httpx.MockTransport(handler))
    assert result.state == "completed"
    prompt = json.dumps(seen[0])
    assert "AI-URI-SENTINEL" not in prompt
    assert "/private/capture.pcap" not in prompt
    assert "/Users/operator/secret.pcap" not in prompt
    assert "sensor.example" not in prompt
    assert "host.example" not in prompt
    assert "http_uri_max_len" not in prompt
    assert "http_uri_max_entropy" not in prompt
    for marker in (
        "http_xss_hits",
        "http_crlf_hits",
        "http_sqli_hits",
        "http_shell_hits",
        "http_host_ip_hits",
    ):
        assert marker not in prompt
    # Filtering applies only to the provider context; local deterministic evidence remains intact.
    assert evidence_bundle.evidence[0].attributes["http_xss_hits"] == 11
    assert evidence_bundle.findings[0].finding_id == "F-0001"


@pytest.mark.asyncio
async def test_budget_exceeded_has_no_transport_call():
    called = False

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    result = await generate_summary(
        bundle(),
        settings(input_max_bytes=100),
        transport=httpx.MockTransport(handler),
    )
    assert result.state == "budget_exceeded"
    assert result.error_code == "budget_exceeded"
    assert called is False


@pytest.mark.asyncio
async def test_fabricated_refs_and_excess_confidence_are_invalid():
    async def fabricated(request: httpx.Request) -> httpx.Response:
        payload = summary_payload(evidence_id="EV-999999")
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(payload)}}]})

    result = await generate_summary(bundle(), settings(), transport=httpx.MockTransport(fabricated))
    assert result.state == "invalid_output"
    assert result.error_code == "invalid_refs"

    async def excessive(request: httpx.Request) -> httpx.Response:
        payload = summary_payload(confidence="high")
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(payload)}}]})

    result = await generate_summary(
        bundle(confidence="low"), settings(), transport=httpx.MockTransport(excessive)
    )
    assert result.state == "invalid_output"
    assert result.error_code == "confidence_exceeded"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutate, expected_error",
    [
        (lambda payload: payload["summary"][0].pop("evidence_ids"), "invalid_output"),
        (lambda payload: payload["limitations"][0].pop("evidence_ids"), "invalid_output"),
        (lambda payload: payload["recommended_actions"][0].pop("evidence_ids"), "invalid_output"),
        (lambda payload: payload["summary"][0].update(evidence_ids=["EV-999999"]), "invalid_refs"),
        (lambda payload: payload["limitations"][0].update(evidence_ids=["EV-999999"]), "invalid_refs"),
        (lambda payload: payload["recommended_actions"][0].update(evidence_ids=["EV-999999"]), "invalid_refs"),
        (lambda payload: payload["assessments"][0].update(evidence_ids=["EV-000002"]), "invalid_refs"),
    ],
)
async def test_uncited_unknown_and_mismatched_citations_fail_closed(mutate, expected_error):
    payload = summary_payload()
    mutate(payload)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(payload)}}]})

    original = bundle()
    result = await generate_summary(original, settings(), transport=httpx.MockTransport(handler))
    assert result.state == "invalid_output"
    assert result.report is None
    assert result.error_code == expected_error
    assert original.findings[0].finding_id == "F-0001"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response, state, error",
    [
        ({"error": {"message": "do not expose"}}, "unavailable", "provider_error"),
        ({"choices": [{"message": {"refusal": "no"}, "finish_reason": "stop"}]}, "refused", "refused"),
        ({"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}, "invalid_output", "output_length"),
    ],
)
async def test_200_error_refusal_and_length(response, state, error):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response)

    result = await generate_summary(bundle(), settings(), transport=httpx.MockTransport(handler))
    assert result.state == state
    assert result.error_code == error
    assert result.report is None
    assert "do not expose" not in json.dumps(result.model_dump())


@pytest.mark.asyncio
async def test_retry_only_429_and_native_chat_shape():
    attempts = 0
    requests: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        requests.append(json.loads(request.content))
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "0"}, json={"error": "rate"})
        return httpx.Response(200, json={"usage": {"total_tokens": 3}, "choices": [{"message": {"content": json.dumps(summary_payload())}, "finish_reason": "stop"}]})

    result = await generate_summary(bundle(), settings(retries=1, token_parameter="max_completion_tokens"), transport=httpx.MockTransport(handler))
    assert result.state == "completed"
    assert attempts == 2
    assert requests[0]["max_completion_tokens"] == 2048
    assert requests[0]["stream"] is False
    assert "tools" not in requests[0]
    assert requests[0]["response_format"]["json_schema"]["schema"]["additionalProperties"] is False


@pytest.mark.asyncio
async def test_anthropic_native_messages_shape_and_discovery():
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "claude-test", "display_name": "Test"}]})
        return httpx.Response(200, json={"usage": {"input_tokens": 1}, "stop_reason": "end_turn", "content": [{"type": "text", "text": json.dumps(summary_payload())}]})

    cfg = AIConfig(
        enabled=True,
        provider="anthropic",
        base_url="https://api.anthropic.example",
        allowed_origins=["https://api.anthropic.example"],
        model="claude-test",
        api_key_env="PCAP_AI_KEY_TEST",
        timeout_seconds=2,
    )
    # The key is an environment value, never config-file data.
    import os

    old = os.environ.get("PCAP_AI_KEY_TEST")
    os.environ["PCAP_AI_KEY_TEST"] = "test-key"
    try:
        app_settings = AppSettings(ai=cfg)
        result = await generate_summary(bundle(), app_settings, transport=httpx.MockTransport(handler))
        assert result.state == "completed"
        discovered = await list_models(app_settings, transport=httpx.MockTransport(handler))
    finally:
        if old is None:
            os.environ.pop("PCAP_AI_KEY_TEST", None)
        else:
            os.environ["PCAP_AI_KEY_TEST"] = old
    assert discovered == [{"id": "claude-test", "display_name": "Test"}]
    post = next(request for request in requests if request.method == "POST")
    assert post.url.path == "/v1/messages"
    assert post.headers["x-api-key"] == "test-key"
    assert post.headers["anthropic-version"] == "2023-06-01"
    body = json.loads(post.content)
    assert body["max_tokens"] == 2048
    assert "tools" not in body and "stream" not in body
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert body["output_config"]["format"]["schema"]["additionalProperties"] is False


@pytest.mark.asyncio
async def test_no_retry_on_fatal_200_error():
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(200, json={"error": {"message": "fatal"}})

    result = await generate_summary(bundle(), settings(retries=2), transport=httpx.MockTransport(handler))
    assert result.state == "unavailable"
    assert result.error_code == "provider_error"
    assert attempts == 1


@pytest.mark.asyncio
async def test_real_parser_attribute_names_and_v1_paths():
    from backend.app.llm.providers import _safe_context
    b = bundle()
    b.evidence[0].attributes = {"src": "192.0.2.1", "dst": "192.0.2.2", "protocol": "TCP", "packets": 3, "bytes": 240, "dst_port": 443}
    context = _safe_context(b, b"fixed-test-salt")
    attrs = context["evidence"][0]["attributes"]
    assert attrs["packets"] == 3 and attrs["bytes"] == 240
    assert attrs["src"].startswith("id_") and "192.0.2.1" not in json.dumps(context)
    assert context["capture_ref"].startswith("id_")
    assert b.capture_sha256 not in json.dumps(context)
    assert context["coverage"]["warnings"] == ["untrusted warning"]
    paths = []
    async def handler(request):
        paths.append(request.url.path)
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "test-model"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(summary_payload())}}]})
    assert (await generate_summary(b, settings(), transport=httpx.MockTransport(handler))).state == "completed"
    await list_models(settings(), transport=httpx.MockTransport(handler))
    assert paths == ["/v1/chat/completions", "/v1/models"]


@pytest.mark.asyncio
async def test_total_deadline_cancels_slow_transport():
    import asyncio
    async def handler(request):
        await asyncio.sleep(3)
        return httpx.Response(200, json={})
    result = await generate_summary(bundle(), settings(timeout_seconds=1), transport=httpx.MockTransport(handler))
    assert result.state == "unavailable" and result.error_code == "timeout"


@pytest.mark.asyncio
async def test_output_reserve_prevents_context_overflow():
    called = False
    async def handler(request):
        nonlocal called
        called = True
        return httpx.Response(200, json={})
    result = await generate_summary(bundle(), settings(context_window_tokens=2048, max_output_tokens=2048), transport=httpx.MockTransport(handler))
    assert result.state == "budget_exceeded" and not called


@pytest.mark.asyncio
async def test_manus_v2_probe_summary_and_chat_lifecycle(monkeypatch: pytest.MonkeyPatch):
    from backend.app.llm import clear_runtime_api_key, probe_models, set_runtime_api_key

    monkeypatch.delenv("MANUS_API_URL", raising=False)
    monkeypatch.delenv("MANUS_API_KEY", raising=False)
    set_runtime_api_key("manus", "sk-manus-v2-key-123456")

    seen: list[tuple[str, str, dict]] = []
    detail_polls = 0
    chat_answer = {"claims": [{"claim": "Observed suspicious TCP flow.", "evidence_ids": ["EV-000001"]}]}

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal detail_polls
        assert request.headers.get("x-manus-api-key") == "sk-manus-v2-key-123456"
        assert "authorization" not in request.headers
        body = json.loads(request.content) if request.content else {}
        seen.append((request.method, f"{request.url.path}?{request.url.query.decode()}" if request.url.query else request.url.path, body))

        if request.url.path == "/v2/task.list":
            return httpx.Response(200, json={"ok": True, "data": [], "has_more": False})
        if request.url.path == "/v2/task.create":
            # Verify Manus v2 strict schema rules: no unsupported keywords like pattern/minLength/maxItems/title
            schema_text = json.dumps(body.get("structured_output_schema", {}))
            for forbidden in ('"pattern"', '"minLength"', '"maxLength"', '"minItems"', '"maxItems"', '"title"'):
                assert forbidden not in schema_text
            assert body.get("hide_in_task_list") is True
            assert body.get("interactive_mode") is False
            assert body.get("clear_connectors") is True
            task_id = "task_chat_01" if "Return one evidence-cited claim" in body["message"]["content"] else "task_sum_01"
            return httpx.Response(200, json={"ok": True, "task_id": task_id})
        if request.url.path == "/v2/task.detail":
            task_id = request.url.params.get("task_id")
            if task_id == "task_sum_01" and detail_polls == 0:
                detail_polls += 1
                return httpx.Response(200, json={"ok": True, "task": {"id": task_id, "status": "running"}})
            return httpx.Response(200, json={"ok": True, "task": {"id": task_id, "status": "stopped"}})
        if request.url.path == "/v2/task.listMessages":
            task_id = request.url.params.get("task_id")
            if task_id == "task_sum_01":
                return httpx.Response(
                    200,
                    json={
                        "ok": True,
                        "task_id": task_id,
                        "messages": [
                            {"id": "m1", "type": "assistant_message", "assistant_message": {"content": "Summary ready."}},
                            {
                                "id": "m2",
                                "type": "structured_output_result",
                                "structured_output_result": {"success": True, "value": summary_payload()},
                            },
                        ],
                        "has_more": False,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "task_id": task_id,
                    "messages": [
                        {
                            "id": "m3",
                            "type": "assistant_message",
                            "assistant_message": {"content": f"Here is the grounded answer:\n```json\n{json.dumps(chat_answer)}\n```"},
                        }
                    ],
                    "has_more": False,
                },
            )
        return httpx.Response(404, json={"ok": False})

    try:
        # Note: user can paste https://api.manus.ai/v2/task.create or https://api.manus.ai, and omit model!
        manus_cfg = AIConfig(
            enabled=True,
            provider="manus",
            base_url="https://api.manus.ai/v2/task.create",
            allowed_origins=["https://api.manus.ai"],
            data_boundary="remote",
            model=None,
            timeout_seconds=5,
        )
        items, warning = await probe_models(manus_cfg, transport=httpx.MockTransport(handler))
        assert warning is None
        assert any(item["id"] == "standard" for item in items)
        assert any(item["id"] == "max" for item in items)

        manus_settings = AppSettings(ai=manus_cfg)
        result = await generate_summary(bundle(), manus_settings, transport=httpx.MockTransport(handler))
        assert result.state == "completed", result
        assert result.model == "standard"
        assert result.report is not None
        assert result.report.assessments[0].finding_id == "F-0001"

        raw_chat = await generate_chat_completion(
            "Return one evidence-cited claim.",
            manus_settings,
            transport=httpx.MockTransport(handler),
        )
        assert json.loads(raw_chat) == chat_answer
    finally:
        clear_runtime_api_key("manus")

