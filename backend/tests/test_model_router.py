"""Tests for the catalog-driven Layer-2 model router (presets, credential slots, path routing)."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.app import main as main_module
from backend.app.config import AIConfig, AppSettings
from backend.app.llm import catalog, probe_models
from backend.app.llm import providers as llm_providers
from backend.app.main import create_app

TOKEN = "router-test-token-0123456789abcdef"


def _preset_config(preset: dict, **overrides) -> AIConfig:
    data = {
        "enabled": True,
        "preset": preset["id"],
        "provider": preset["protocol"],
        "base_url": preset["base_url"],
        "allowed_origins": list(preset["allowed_origins"]),
        "data_boundary": preset["data_boundary"],
        "model": preset["default_model"] or (preset["model_suggestions"] or ["test-model"])[0],
        "api_key_env": preset["api_key_env"],
        "token_parameter": preset["token_parameter"],
        "response_mode": preset["response_mode"],
        "timeout_seconds": preset["timeout_seconds"],
    }
    data.update(overrides)
    return AIConfig.model_validate(data)


@pytest.fixture(autouse=True)
def _clear_slots():
    yield
    for slot in llm_providers.credential_slot_names():
        llm_providers.clear_runtime_api_key(slot)


def test_catalog_entries_are_unique_complete_and_map_to_supported_protocols():
    items = catalog.list_presets()
    ids = [item["id"] for item in items]
    assert len(ids) == len(set(ids))
    assert {"ollama", "openai", "anthropic", "gemini", "openrouter", "groq", "manus", "custom"} <= set(ids)
    for item in items:
        assert catalog.PRESET_ID_RE.fullmatch(item["id"])
        assert item["protocol"] in {"openai_compatible", "anthropic", "manus"}
        assert item["category"] in {"local", "cloud", "agent", "custom"}
        assert item["data_boundary"] in {"local", "remote"}
        # The catalog never carries secret values, only env var *names*.
        assert "api_key" not in item
        if item["base_url"]:
            if item["data_boundary"] == "remote":
                assert item["base_url"].startswith("https://")
            assert item["allowed_origins"] and item["base_url"].startswith(item["allowed_origins"][0])


@pytest.mark.parametrize("preset", [p for p in catalog.list_presets() if p["base_url"]], ids=lambda p: p["id"])
def test_every_catalog_preset_builds_a_policy_valid_ai_config(preset):
    cfg = _preset_config(preset)
    assert cfg.preset == preset["id"]


def test_preset_must_be_known_and_match_wire_protocol():
    with pytest.raises(ValueError):
        AIConfig(enabled=False, preset="does-not-exist")
    with pytest.raises(ValueError):
        AIConfig(
            enabled=True,
            preset="anthropic",
            provider="openai_compatible",
            base_url="https://api.anthropic.com",
            allowed_origins=["https://api.anthropic.com"],
            data_boundary="remote",
            model="x",
        )


@pytest.mark.parametrize(
    ("preset_id", "expected"),
    [
        ("ollama", "http://127.0.0.1:11434/v1/chat/completions"),
        ("openai", "https://api.openai.com/v1/chat/completions"),
        ("gemini", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
        ("openrouter", "https://openrouter.ai/api/v1/chat/completions"),
        ("groq", "https://api.groq.com/openai/v1/chat/completions"),
        ("deepseek", "https://api.deepseek.com/v1/chat/completions"),
        ("anthropic", "https://api.anthropic.com/v1/messages"),
        ("manus", "https://api.manus.ai/v2/task.create"),
    ],
)
def test_router_resolves_vendor_specific_endpoints(preset_id, expected):
    preset = catalog.get_preset(preset_id)
    row = next(p for p in catalog.list_presets() if p["id"] == preset_id)
    if preset["key_required"]:
        llm_providers.set_runtime_api_key(preset_id, f"key-for-{preset_id}-123")
    rt = llm_providers._runtime(AppSettings.model_construct(ai=_preset_config(row)))
    assert rt.endpoint == expected


def test_credential_slots_isolate_vendors_sharing_the_openai_protocol(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    rows = {p["id"]: p for p in catalog.list_presets()}
    llm_providers.set_runtime_api_key("openai", "sk-openai-only-secret")
    llm_providers.set_runtime_api_key("openai_compatible", "sk-legacy-generic-secret")

    rt_openai = llm_providers._runtime(AppSettings.model_construct(ai=_preset_config(rows["openai"])))
    assert rt_openai.headers["authorization"] == "Bearer sk-openai-only-secret"

    # Groq has no key of its own: the OpenAI or generic key must NOT leak to api.groq.com.
    with pytest.raises(llm_providers._RequestFailure) as excinfo:
        llm_providers._runtime(AppSettings.model_construct(ai=_preset_config(rows["groq"])))
    assert excinfo.value.code == "provider_credentials_missing"

    llm_providers.set_runtime_api_key("groq", "gsk_groq_secret")
    rt_groq = llm_providers._runtime(AppSettings.model_construct(ai=_preset_config(rows["groq"])))
    assert rt_groq.headers["authorization"] == "Bearer gsk_groq_secret"

    # Legacy preset-less configs keep using the wire-protocol slot.
    legacy = AIConfig(
        enabled=True,
        provider="openai_compatible",
        base_url="https://api.openai.com/v1",
        allowed_origins=["https://api.openai.com"],
        data_boundary="remote",
        model="gpt-4.1-mini",
    )
    rt_legacy = llm_providers._runtime(AppSettings.model_construct(ai=legacy))
    assert rt_legacy.headers["authorization"] == "Bearer sk-legacy-generic-secret"


def test_catalog_does_not_relax_origin_allowlist():
    rows = {p["id"]: p for p in catalog.list_presets()}
    with pytest.raises(ValueError):
        _preset_config(rows["openai"], allowed_origins=["https://evil.example"])
    with pytest.raises(ValueError):
        _preset_config(rows["custom"], base_url="http://10.0.0.5:8000/v1", allowed_origins=["http://10.0.0.5:8000"])


@pytest.mark.asyncio
async def test_probe_uses_preset_slot_and_versioned_models_path():
    rows = {p["id"]: p for p in catalog.list_presets()}
    llm_providers.set_runtime_api_key("gemini", "AIza-test-gemini")
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization", "")
        return httpx.Response(200, json={"data": [{"id": "gemini-2.5-flash", "owned_by": "google"}]})

    async def _allow(_url, _boundary):
        return None

    import backend.app.llm.providers as mod

    original = mod._ensure_resolved_host_allowed
    mod._ensure_resolved_host_allowed = _allow
    try:
        items, warning = await probe_models(
            _preset_config(rows["gemini"], enabled=False), transport=httpx.MockTransport(handler)
        )
    finally:
        mod._ensure_resolved_host_allowed = original
    assert warning is None
    assert [item["id"] for item in items] == ["gemini-2.5-flash"]
    assert seen["url"] == "https://generativelanguage.googleapis.com/v1beta/openai/models"
    assert seen["auth"] == "Bearer AIza-test-gemini"


def test_providers_endpoint_and_preset_credentials_round_trip(tmp_path, monkeypatch):
    ws_file = tmp_path / "workspace.json"
    monkeypatch.setenv("PCAP_WORKSPACE_CONFIG", str(ws_file))
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    app = create_app(AppSettings(data_dir=tmp_path / "data", api_token=TOKEN, ai=AIConfig(enabled=False)))
    client = TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"})

    catalog_res = client.get("/api/v1/ai/providers")
    assert catalog_res.status_code == 200
    groq = next(item for item in catalog_res.json()["items"] if item["id"] == "groq")
    assert groq["runtime_key_set"] is False and groq["protocol"] == "openai_compatible"

    secret = "gsk_router_endpoint_secret_42"
    put_res = client.put("/api/v1/ai/credentials", json={"provider": "groq", "api_key": secret})
    assert put_res.status_code == 200, put_res.text
    assert secret not in put_res.text
    assert put_res.json()["runtime_keys"]["groq"] is True

    cfg_res = client.put(
        "/api/v1/ai/config",
        json={
            "enabled": True,
            "preset": "groq",
            "provider": "openai_compatible",
            "base_url": "https://api.groq.com/openai/v1",
            "allowed_origins": ["https://api.groq.com"],
            "data_boundary": "remote",
            "model": "llama-3.3-70b-versatile",
            "api_key_env": "GROQ_API_KEY",
            "response_mode": "json_object",
        },
    )
    assert cfg_res.status_code == 200, cfg_res.text
    body = cfg_res.json()
    assert body["configuration"]["preset"] == "groq"
    assert body["active_preset"] == "groq"
    assert body["credential_slot"] == "groq"
    assert body["runtime_key_set"] is True
    assert secret not in cfg_res.text
    assert not ws_file.exists() or secret not in ws_file.read_text(encoding="utf-8")

    # Secrets are still rejected on the non-secret config endpoint.
    leak = client.put("/api/v1/ai/config", json={"preset": "groq", "api_key": secret})
    assert leak.status_code == 422
    assert secret not in leak.text

    # Unknown slots / presets are rejected.
    assert client.put("/api/v1/ai/credentials", json={"provider": "nope", "api_key": "abcd1234"}).status_code == 422
    assert client.delete("/api/v1/ai/credentials", params={"provider": "nope"}).status_code == 422
    assert client.put("/api/v1/ai/config", json={"preset": "nope"}).status_code == 422

    # Switching protocol without naming a preset drops the stale card instead of failing.
    switch = client.put(
        "/api/v1/ai/config",
        json={
            "provider": "anthropic",
            "base_url": "https://api.anthropic.com",
            "allowed_origins": ["https://api.anthropic.com"],
            "model": "claude-sonnet-4-5",
        },
    )
    assert switch.status_code == 200, switch.text
    assert switch.json()["configuration"]["preset"] is None
    assert switch.json()["active_preset"] == "anthropic"

    del_res = client.delete("/api/v1/ai/credentials", params={"provider": "groq"})
    assert del_res.status_code == 200 and del_res.json()["cleared"] is True

    monkeypatch.setattr(main_module, "is_loopback_client", lambda _host: False)
    assert client.put("/api/v1/ai/credentials", json={"provider": "groq", "api_key": secret}).status_code == 403


def test_infer_preset_for_legacy_configs():
    assert catalog.infer_preset("manus", None) == "manus"
    assert catalog.infer_preset("openai_compatible", None) == "ollama"
    assert catalog.infer_preset("openai_compatible", "https://api.groq.com/openai/v1") == "groq"
    assert catalog.infer_preset("openai_compatible", "https://llm.internal.example/v1") == "custom"
    assert catalog.infer_preset("anthropic", "https://api.anthropic.com") == "anthropic"


def test_repointing_a_fixed_endpoint_preset_drops_its_key_slot(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAP_WORKSPACE_CONFIG", str(tmp_path / "workspace.json"))
    app = create_app(AppSettings(data_dir=tmp_path / "data", api_token=TOKEN, ai=AIConfig(enabled=False)))
    client = TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"})
    client.put("/api/v1/ai/credentials", json={"provider": "openai", "api_key": "sk-openai-secret-1"})
    ok = client.put(
        "/api/v1/ai/config",
        json={
            "enabled": True,
            "preset": "openai",
            "provider": "openai_compatible",
            "base_url": "https://api.openai.com/v1",
            "allowed_origins": ["https://api.openai.com"],
            "data_boundary": "remote",
            "model": "gpt-4.1-mini",
        },
    )
    assert ok.status_code == 200 and ok.json()["credential_slot"] == "openai"
    moved = client.put(
        "/api/v1/ai/config",
        json={"base_url": "https://llm.other.example/v1", "allowed_origins": ["https://llm.other.example"]},
    )
    assert moved.status_code == 200, moved.text
    body = moved.json()
    assert body["configuration"]["preset"] is None
    assert body["credential_slot"] == "openai_compatible"
    assert body["runtime_key_set"] is False
