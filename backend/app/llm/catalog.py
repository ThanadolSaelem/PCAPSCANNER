"""Declarative provider catalog for the Layer-2 model router.

Inspired by LiteLLM's ``provider_create_fields.json`` registry: every provider the
UI can offer is described once, as *data*, and mapped onto one of the three wire
protocols PCAPSCANNER actually implements (``openai_compatible``, ``anthropic``
and ``manus``).  Adding a new OpenAI-compatible vendor therefore needs no new
transport code — only a catalog entry.

Security notes
--------------
* The catalog is advisory UI metadata.  It is **not** a security boundary: the
  persisted :class:`~backend.app.config.AIConfig` still enforces the exact origin
  allowlist, the ``local``/``remote`` data boundary, HTTPS for remote endpoints
  and the SSRF/DNS checks in ``providers.py``.
* No secrets live here.  ``api_key_env`` is only a suggested environment
  variable *name*; API key values stay RAM-only via ``/api/v1/ai/credentials``.
* Each preset id is also a dedicated in-memory credential slot, so a key typed
  for one vendor is never sent to another vendor that shares the same protocol.

This module intentionally has no imports from ``..config`` to avoid cycles.
"""

from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import urlsplit

PresetCategory = Literal["local", "cloud", "agent", "custom"]
Protocol = Literal["openai_compatible", "anthropic", "manus"]

PRESET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
CUSTOM_PRESET_ID = "custom"

_PRESETS: tuple[dict[str, Any], ...] = (
    # ------------------------------------------------------------------ local
    {
        "id": "ollama",
        "label": "Ollama",
        "initials": "OL",
        "accent": "#4b5563",
        "category": "local",
        "protocol": "openai_compatible",
        "tagline": "รันโมเดลบนเครื่องตัวเอง — ข้อมูลไม่ออกจากเครื่อง",
        "base_url": "http://127.0.0.1:11434",
        "data_boundary": "local",
        "api_key_env": None,
        "key_required": False,
        "key_placeholder": "ไม่ต้องใช้ API Key",
        "model_label": "Model",
        "default_model": None,
        "model_suggestions": ["qwen2.5:7b", "llama3.1:8b", "gemma2:9b", "mistral-nemo"],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_schema",
        "timeout_seconds": 60,
        "base_url_editable": True,
        "docs_url": "https://github.com/ollama/ollama/blob/main/docs/openai.md",
    },
    {
        "id": "lmstudio",
        "label": "LM Studio",
        "initials": "LM",
        "accent": "#4f46e5",
        "category": "local",
        "protocol": "openai_compatible",
        "tagline": "Local server ของ LM Studio (OpenAI-compatible)",
        "base_url": "http://127.0.0.1:1234/v1",
        "data_boundary": "local",
        "api_key_env": None,
        "key_required": False,
        "key_placeholder": "ไม่ต้องใช้ API Key",
        "model_label": "Model",
        "default_model": None,
        "model_suggestions": [],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_schema",
        "timeout_seconds": 60,
        "base_url_editable": True,
        "docs_url": "https://lmstudio.ai/docs/app/api/endpoints/openai",
    },
    {
        "id": "vllm",
        "label": "vLLM / llama.cpp",
        "initials": "vL",
        "accent": "#0f766e",
        "category": "local",
        "protocol": "openai_compatible",
        "tagline": "Self-hosted inference server บน loopback",
        "base_url": "http://127.0.0.1:8000/v1",
        "data_boundary": "local",
        "api_key_env": None,
        "key_required": False,
        "key_placeholder": "ใส่ได้หาก server ตั้ง --api-key ไว้",
        "model_label": "Model",
        "default_model": None,
        "model_suggestions": [],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_schema",
        "timeout_seconds": 60,
        "base_url_editable": True,
        "docs_url": "https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html",
    },
    # ------------------------------------------------------------------ cloud
    {
        "id": "openai",
        "label": "OpenAI",
        "initials": "AI",
        "accent": "#10a37f",
        "category": "cloud",
        "protocol": "openai_compatible",
        "tagline": "GPT-4.1 / o-series ผ่าน OpenAI API",
        "base_url": "https://api.openai.com/v1",
        "data_boundary": "remote",
        "api_key_env": "OPENAI_API_KEY",
        "key_required": True,
        "key_placeholder": "sk-...",
        "model_label": "Model",
        "default_model": "gpt-4.1-mini",
        "model_suggestions": ["gpt-4.1-mini", "gpt-4.1", "gpt-4o-mini", "o4-mini"],
        "supports_discovery": True,
        "token_parameter": "max_completion_tokens",
        "response_mode": "json_schema",
        "timeout_seconds": 60,
        "base_url_editable": False,
        "docs_url": "https://platform.openai.com/docs/api-reference/chat",
    },
    {
        "id": "anthropic",
        "label": "Anthropic Claude",
        "initials": "A\\",
        "accent": "#c96442",
        "category": "cloud",
        "protocol": "anthropic",
        "tagline": "Claude ผ่าน Messages API (x-api-key)",
        "base_url": "https://api.anthropic.com",
        "data_boundary": "remote",
        "api_key_env": "ANTHROPIC_API_KEY",
        "key_required": True,
        "key_placeholder": "sk-ant-...",
        "model_label": "Model",
        "default_model": "claude-sonnet-4-5",
        "model_suggestions": ["claude-sonnet-4-5", "claude-haiku-4-5", "claude-opus-4-1"],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_schema",
        "timeout_seconds": 60,
        "base_url_editable": False,
        "docs_url": "https://docs.anthropic.com/en/api/messages",
    },
    {
        "id": "gemini",
        "label": "Google Gemini",
        "initials": "G",
        "accent": "#3b82f6",
        "category": "cloud",
        "protocol": "openai_compatible",
        "tagline": "Gemini ผ่าน OpenAI-compatible endpoint ของ Google AI Studio",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "data_boundary": "remote",
        "api_key_env": "GEMINI_API_KEY",
        "key_required": True,
        "key_placeholder": "AIza...",
        "model_label": "Model",
        "default_model": "gemini-2.5-flash",
        "model_suggestions": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_schema",
        "timeout_seconds": 60,
        "base_url_editable": False,
        "docs_url": "https://ai.google.dev/gemini-api/docs/openai",
    },
    {
        "id": "openrouter",
        "label": "OpenRouter",
        "initials": "OR",
        "accent": "#6366f1",
        "category": "cloud",
        "protocol": "openai_compatible",
        "tagline": "Router รวมหลายร้อยโมเดลด้วย Key เดียว",
        "base_url": "https://openrouter.ai/api/v1",
        "data_boundary": "remote",
        "api_key_env": "OPENROUTER_API_KEY",
        "key_required": True,
        "key_placeholder": "sk-or-...",
        "model_label": "Model",
        "default_model": "openai/gpt-4.1-mini",
        "model_suggestions": [
            "openai/gpt-4.1-mini",
            "anthropic/claude-sonnet-4.5",
            "google/gemini-2.5-flash",
            "meta-llama/llama-3.3-70b-instruct",
        ],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_object",
        "timeout_seconds": 60,
        "base_url_editable": False,
        "docs_url": "https://openrouter.ai/docs/quickstart",
    },
    {
        "id": "groq",
        "label": "Groq",
        "initials": "GQ",
        "accent": "#f55036",
        "category": "cloud",
        "protocol": "openai_compatible",
        "tagline": "Inference ความเร็วสูงบน LPU",
        "base_url": "https://api.groq.com/openai/v1",
        "data_boundary": "remote",
        "api_key_env": "GROQ_API_KEY",
        "key_required": True,
        "key_placeholder": "gsk_...",
        "model_label": "Model",
        "default_model": "llama-3.3-70b-versatile",
        "model_suggestions": ["llama-3.3-70b-versatile", "openai/gpt-oss-120b", "qwen/qwen3-32b"],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_object",
        "timeout_seconds": 45,
        "base_url_editable": False,
        "docs_url": "https://console.groq.com/docs/openai",
    },
    {
        "id": "deepseek",
        "label": "DeepSeek",
        "initials": "DS",
        "accent": "#4d6bfe",
        "category": "cloud",
        "protocol": "openai_compatible",
        "tagline": "deepseek-chat / deepseek-reasoner",
        "base_url": "https://api.deepseek.com/v1",
        "data_boundary": "remote",
        "api_key_env": "DEEPSEEK_API_KEY",
        "key_required": True,
        "key_placeholder": "sk-...",
        "model_label": "Model",
        "default_model": "deepseek-chat",
        "model_suggestions": ["deepseek-chat", "deepseek-reasoner"],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_object",
        "timeout_seconds": 90,
        "base_url_editable": False,
        "docs_url": "https://api-docs.deepseek.com/",
    },
    {
        "id": "mistral",
        "label": "Mistral AI",
        "initials": "M",
        "accent": "#fa520f",
        "category": "cloud",
        "protocol": "openai_compatible",
        "tagline": "Mistral Large / Small (EU hosted)",
        "base_url": "https://api.mistral.ai/v1",
        "data_boundary": "remote",
        "api_key_env": "MISTRAL_API_KEY",
        "key_required": True,
        "key_placeholder": "Mistral API Key",
        "model_label": "Model",
        "default_model": "mistral-small-latest",
        "model_suggestions": ["mistral-small-latest", "mistral-large-latest", "magistral-medium-latest"],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_object",
        "timeout_seconds": 60,
        "base_url_editable": False,
        "docs_url": "https://docs.mistral.ai/api/",
    },
    {
        "id": "xai",
        "label": "xAI Grok",
        "initials": "xA",
        "accent": "#111827",
        "category": "cloud",
        "protocol": "openai_compatible",
        "tagline": "Grok ผ่าน OpenAI-compatible API",
        "base_url": "https://api.x.ai/v1",
        "data_boundary": "remote",
        "api_key_env": "XAI_API_KEY",
        "key_required": True,
        "key_placeholder": "xai-...",
        "model_label": "Model",
        "default_model": "grok-3-mini",
        "model_suggestions": ["grok-3-mini", "grok-4"],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_schema",
        "timeout_seconds": 60,
        "base_url_editable": False,
        "docs_url": "https://docs.x.ai/docs/api-reference",
    },
    {
        "id": "together",
        "label": "Together AI",
        "initials": "TG",
        "accent": "#0f6fff",
        "category": "cloud",
        "protocol": "openai_compatible",
        "tagline": "Open-weight models แบบ serverless",
        "base_url": "https://api.together.xyz/v1",
        "data_boundary": "remote",
        "api_key_env": "TOGETHER_API_KEY",
        "key_required": True,
        "key_placeholder": "Together API Key",
        "model_label": "Model",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "model_suggestions": ["meta-llama/Llama-3.3-70B-Instruct-Turbo", "Qwen/Qwen2.5-72B-Instruct-Turbo"],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_object",
        "timeout_seconds": 60,
        "base_url_editable": False,
        "docs_url": "https://docs.together.ai/docs/openai-api-compatibility",
    },
    # ------------------------------------------------------------------ agent
    {
        "id": "manus",
        "label": "Manus Agent",
        "initials": "MA",
        "accent": "#1f2937",
        "category": "agent",
        "protocol": "manus",
        "tagline": "Manus API v2 (task.create) — เลือก Agent Profile แทนชื่อโมเดล",
        "base_url": "https://api.manus.ai",
        "data_boundary": "remote",
        "api_key_env": None,
        "key_required": True,
        "key_placeholder": "Manus API Key (ส่งผ่าน x-manus-api-key)",
        "model_label": "Agent profile",
        "default_model": "standard",
        "model_suggestions": ["standard", "lite", "max", "max-medium", "max-high", "max-extra", "max-ultra"],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_schema",
        "timeout_seconds": 120,
        "base_url_editable": False,
        "docs_url": "https://open.manus.ai/docs",
    },
    # ----------------------------------------------------------------- custom
    {
        "id": CUSTOM_PRESET_ID,
        "label": "Custom endpoint",
        "initials": "{ }",
        "accent": "#64748b",
        "category": "custom",
        "protocol": "openai_compatible",
        "tagline": "OpenAI-compatible endpoint อื่นๆ (Azure gateway, LiteLLM proxy, ฯลฯ)",
        "base_url": None,
        "data_boundary": "remote",
        "api_key_env": None,
        "key_required": False,
        "key_placeholder": "API Key (ถ้า endpoint ต้องการ)",
        "model_label": "Model",
        "default_model": None,
        "model_suggestions": [],
        "supports_discovery": True,
        "token_parameter": "max_tokens",
        "response_mode": "json_object",
        "timeout_seconds": 60,
        "base_url_editable": True,
        "docs_url": None,
    },
)

_BY_ID: dict[str, dict[str, Any]] = {item["id"]: item for item in _PRESETS}


def _origin_of(url: str | None) -> str | None:
    if not url:
        return None
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return None
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme.lower()}://{parts.hostname.lower()}{port}"


def list_presets() -> list[dict[str, Any]]:
    """Return a deep-enough copy of the catalog (safe for JSON responses)."""
    out: list[dict[str, Any]] = []
    for item in _PRESETS:
        row = dict(item)
        row["model_suggestions"] = list(item["model_suggestions"])
        row["allowed_origins"] = [o for o in [_origin_of(item["base_url"])] if o]
        out.append(row)
    return out


def get_preset(preset_id: str | None) -> dict[str, Any] | None:
    if not preset_id:
        return None
    return _BY_ID.get(preset_id)


def is_known_preset(preset_id: str | None) -> bool:
    return bool(preset_id) and preset_id in _BY_ID


def preset_ids() -> frozenset[str]:
    return frozenset(_BY_ID)


def infer_preset(provider: str, base_url: str | None) -> str | None:
    """Best-effort mapping of a legacy (preset-less) configuration onto a catalog card."""
    if provider == "manus":
        return "manus"
    origin = _origin_of(base_url)
    if provider == "anthropic":
        return "anthropic" if origin in (None, "https://api.anthropic.com") else CUSTOM_PRESET_ID
    if origin is None:
        return "ollama"
    for item in _PRESETS:
        if item["protocol"] == provider and _origin_of(item["base_url"]) == origin:
            return item["id"]
    return CUSTOM_PRESET_ID


__all__ = [
    "CUSTOM_PRESET_ID",
    "PRESET_ID_RE",
    "get_preset",
    "infer_preset",
    "is_known_preset",
    "list_presets",
    "preset_ids",
]
