"""Validated runtime configuration for PCAPSCANNER.

Secrets are deliberately sourced from the process environment only.  The config
file named by ``PCAP_AI_CONFIG`` is a non-secret YAML/JSON overlay.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


class ProviderName(str, Enum):
    MANUS = "manus"
    OPENAI_COMPATIBLE = "openai_compatible"
    ANTHROPIC = "anthropic"


ResponseMode = Literal["json_schema", "json_object", "text"]
TokenParameter = Literal["max_tokens", "max_completion_tokens"]
DataBoundary = Literal["local", "remote"]


def _origin(url: str) -> str:
    """Return an exact, normalized origin for an already validated URL."""
    parts = urlsplit(url)
    host = parts.hostname
    if not parts.scheme or not host:
        raise ValueError("invalid_endpoint")
    host_text = host.lower()
    if ":" in host_text and not host_text.startswith("["):
        host_text = f"[{host_text}]"
    # urlsplit.port raises a useful ValueError for malformed ports.
    port = parts.port
    if port is not None:
        return f"{parts.scheme.lower()}://{host_text}:{port}"
    return f"{parts.scheme.lower()}://{host_text}"


def _validate_endpoint(value: str, *, data_boundary: str, require_https_remote: bool = True) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("invalid_endpoint")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("endpoint_control_characters_forbidden")
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("invalid_endpoint")
    if parts.username is not None or parts.password is not None:
        raise ValueError("endpoint_credentials_forbidden")
    if parts.query or parts.fragment:
        raise ValueError("endpoint_query_forbidden")
    # A path is permitted because OpenAI-compatible deployments commonly use /v1.
    if "\\" in parts.path:
        raise ValueError("invalid_endpoint")
    try:
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid_endpoint") from exc
    lowered_host = host.lower().rstrip(".")
    if lowered_host in {
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "localhost.localdomain",
    }:
        raise ValueError("forbidden_endpoint")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        # Metadata, link-local, multicast, unspecified and reserved destinations
        # are never valid provider endpoints.  Loopback/private are allowed only
        # for an explicitly local data boundary.
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise ValueError("forbidden_endpoint")
        if data_boundary == "remote" and (ip.is_loopback or ip.is_private):
            raise ValueError("remote_private_endpoint")
    elif data_boundary == "remote" and lowered_host in {"localhost", "ip6-localhost"}:
        raise ValueError("remote_private_endpoint")
    if require_https_remote and data_boundary == "remote" and parts.scheme.lower() != "https":
        raise ValueError("remote_requires_https")
    if parts.scheme.lower() == "http" and data_boundary != "local":
        raise ValueError("http_requires_local_boundary")
    # Touch the port to ensure malformed numeric ports fail above; no default is
    # inserted into the stored value, preserving exact origin matching.
    _ = port
    return value


def _validate_origin(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("invalid_origin")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("origin_control_characters_forbidden")
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("invalid_origin")
    if parts.username is not None or parts.password is not None:
        raise ValueError("origin_credentials_forbidden")
    if parts.path or parts.query or parts.fragment:
        raise ValueError("origin_must_not_have_path")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError("invalid_origin") from exc
    # Origins are exact allowlist entries.  Reject a trailing slash rather than
    # silently making it equivalent to another entry.
    expected = _origin(value)
    if value != expected:
        raise ValueError("origin_must_be_exact")
    host = parts.hostname.lower().rstrip(".")
    if host in {"metadata", "metadata.google.internal", "instance-data"}:
        raise ValueError("forbidden_origin")
    try:
        ip = ipaddress.ip_address(parts.hostname)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved):
        raise ValueError("forbidden_origin")
    return value


class AIConfig(BaseModel):
    """Non-secret AI provider configuration."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True, validate_assignment=True)

    schema_version: Literal["1.0"] = "1.0"
    enabled: bool = False
    provider: ProviderName = ProviderName.OPENAI_COMPATIBLE
    # None means the safe local Ollama-compatible default for the compatible
    # provider, or the runtime MANUS_API_URL for the Manus adapter.
    base_url: str | None = None
    allowed_origins: list[str] = Field(default_factory=list, max_length=20)
    model: str | None = Field(default=None, max_length=200)
    # This is an environment variable *name*, never a key value.
    api_key_env: str | None = Field(default=None, max_length=128)
    data_boundary: DataBoundary = "remote"
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    retries: int = Field(default=0, ge=0, le=2)
    input_max_bytes: int = Field(default=100_000, ge=1, le=100_000)
    max_output_tokens: int = Field(default=2048, ge=1, le=8192)
    context_window_tokens: int = Field(default=16_384, ge=1, le=2_000_000)
    token_parameter: TokenParameter = "max_tokens"
    response_mode: ResponseMode = "json_schema"
    temperature: float | None = Field(default=None, ge=0, le=2)
    anthropic_version: str = Field(default="2023-06-01", min_length=1, max_length=64)

    @field_validator("allowed_origins")
    @classmethod
    def exact_origins(cls, origins: list[str]) -> list[str]:
        checked = [_validate_origin(item) for item in origins]
        if len(set(checked)) != len(checked):
            raise ValueError("duplicate_origin")
        return checked

    @field_validator("api_key_env")
    @classmethod
    def environment_name(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("api_key_env_must_be_environment_name")
        return value

    @field_validator("model")
    @classmethod
    def explicit_model(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("model_must_not_be_empty")
        return value

    @model_validator(mode="after")
    def validate_provider_policy(self) -> "AIConfig":
        if self.base_url is not None:
            _validate_endpoint(self.base_url, data_boundary=self.data_boundary)
        if not self.enabled:
            return self

        if self.provider == ProviderName.MANUS:
            # The actual URL and key are obtained at runtime from MANUS_*.
            # A configured URL is still validated and must be allowlisted.
            if self.base_url is not None and _origin(self.base_url) not in self.allowed_origins:
                raise ValueError("endpoint_origin_not_allowed")
            return self

        effective = self.base_url
        if effective is None and self.provider == ProviderName.OPENAI_COMPATIBLE:
            effective = "http://127.0.0.1:11434"
            if self.data_boundary != "local":
                raise ValueError("local_default_requires_local_boundary")
        if effective is None:
            raise ValueError("base_url_required")
        if _origin(effective) not in self.allowed_origins:
            raise ValueError("endpoint_origin_not_allowed")
        return self


class AppSettings(BaseModel):
    """Application settings used by the backend and AI layer."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    data_dir: Path = Path("./data/pcapscanner")
    api_token: SecretStr | None = None
    upload_max_bytes: int = Field(default=100 * 1024 * 1024, ge=1)
    storage_max_bytes: int = Field(default=1024 * 1024 * 1024, ge=1)
    storage_max_captures: int = Field(default=100, ge=1)
    api_json_max_bytes: int = Field(default=1024 * 1024, ge=1)
    queue_limit: int = Field(default=8, ge=1)
    packet_limit: int = Field(default=20_000, ge=1)
    flow_limit: int = Field(default=5_000, ge=1)
    parser_timeout_seconds: int = Field(default=120, ge=1)
    parser_memory_mb: int = Field(default=512, ge=1)
    zeek_enabled: bool = False
    retention_hours: int = Field(default=24, ge=1)
    ai: AIConfig = Field(default_factory=AIConfig)


_SECRET_CONFIG_KEYS = {
    "api_key",
    "api_token",
    "secret",
    "password",
    "authorization",
    "bearer",
    "credential",
    "credentials",
}


def _assert_nonsecret(value: Any, path: str = "config") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in _SECRET_CONFIG_KEYS or key_text.endswith("_secret") or key_text.endswith("_password"):
                raise ValueError("secret_config_value_forbidden")
            # api_key_env is explicitly a variable-name reference, not a secret.
            _assert_nonsecret(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_nonsecret(child, f"{path}[{index}]")


def _load_config_file(path_text: str) -> dict[str, Any]:
    try:
        path = Path(path_text).expanduser()
        raw = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            data = json.loads(raw)
        else:
            data = yaml.safe_load(raw)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ValueError("config_file_unavailable") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("config_file_must_be_mapping")
    _assert_nonsecret(data)
    return data


def _parse_bool(value: str, field: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid_{field}")


def _parse_list(value: str, field: str) -> list[str]:
    text = value.strip()
    if text.startswith("["):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid_{field}") from exc
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            raise ValueError(f"invalid_{field}")
        return parsed
    return [item.strip() for item in text.split(",") if item.strip()]


def _env_overlay(env: dict[str, str]) -> dict[str, Any]:
    top: dict[str, Any] = {}
    ai: dict[str, Any] = {}
    top_map: dict[str, tuple[str, str]] = {
        "PCAP_DATA_DIR": ("data_dir", "str"),
        "PCAP_UPLOAD_MAX_BYTES": ("upload_max_bytes", "int"),
        "PCAP_STORAGE_MAX_BYTES": ("storage_max_bytes", "int"),
        "PCAP_STORAGE_MAX_CAPTURES": ("storage_max_captures", "int"),
        "PCAP_API_JSON_MAX_BYTES": ("api_json_max_bytes", "int"),
        "PCAP_QUEUE_LIMIT": ("queue_limit", "int"),
        "PCAP_PACKET_LIMIT": ("packet_limit", "int"),
        "PCAP_FLOW_LIMIT": ("flow_limit", "int"),
        "PCAP_PARSER_TIMEOUT_SECONDS": ("parser_timeout_seconds", "int"),
        "PCAP_PARSER_MEMORY_MB": ("parser_memory_mb", "int"),
        "PCAP_ZEEK_ENABLED": ("zeek_enabled", "bool"),
        "PCAP_RETENTION_HOURS": ("retention_hours", "int"),
    }
    for env_name, (field_name, kind) in top_map.items():
        if env_name not in env:
            continue
        raw = env[env_name]
        if kind == "int":
            try:
                top[field_name] = int(raw)
            except ValueError as exc:
                raise ValueError(f"invalid_{field_name}") from exc
        elif kind == "bool":
            top[field_name] = _parse_bool(raw, field_name)
        else:
            top[field_name] = raw

    ai_map: dict[str, tuple[str, str]] = {
        "PCAP_AI_ENABLED": ("enabled", "bool"),
        "PCAP_AI_PROVIDER": ("provider", "str"),
        "PCAP_AI_BASE_URL": ("base_url", "str"),
        "PCAP_AI_ALLOWED_ORIGINS": ("allowed_origins", "list"),
        "PCAP_AI_MODEL": ("model", "str"),
        "PCAP_AI_API_KEY_ENV": ("api_key_env", "str"),
        "PCAP_AI_DATA_BOUNDARY": ("data_boundary", "str"),
        "PCAP_AI_TIMEOUT_SECONDS": ("timeout_seconds", "int"),
        "PCAP_AI_RETRIES": ("retries", "int"),
        "PCAP_AI_INPUT_MAX_BYTES": ("input_max_bytes", "int"),
        "PCAP_AI_MAX_OUTPUT_TOKENS": ("max_output_tokens", "int"),
        "PCAP_AI_CONTEXT_WINDOW_TOKENS": ("context_window_tokens", "int"),
        "PCAP_AI_TOKEN_PARAMETER": ("token_parameter", "str"),
        "PCAP_AI_RESPONSE_MODE": ("response_mode", "str"),
        "PCAP_AI_TEMPERATURE": ("temperature", "float"),
        "PCAP_AI_ANTHROPIC_VERSION": ("anthropic_version", "str"),
    }
    # Double-underscore names are accepted as a conventional nested alias too.
    for env_name, (field_name, kind) in ai_map.items():
        candidates = (env_name, env_name.replace("PCAP_AI_", "PCAP_AI__", 1))
        selected = next((name for name in candidates if name in env), None)
        if selected is None:
            continue
        raw = env[selected]
        if kind == "int":
            try:
                ai[field_name] = int(raw)
            except ValueError as exc:
                raise ValueError(f"invalid_ai_{field_name}") from exc
        elif kind == "float":
            try:
                ai[field_name] = float(raw)
            except ValueError as exc:
                raise ValueError(f"invalid_ai_{field_name}") from exc
        elif kind == "bool":
            ai[field_name] = _parse_bool(raw, f"ai_{field_name}")
        elif kind == "list":
            ai[field_name] = _parse_list(raw, f"ai_{field_name}")
        else:
            ai[field_name] = raw
    # Explicitly omit a blank optional temperature so it remains None.
    if "PCAP_AI_TEMPERATURE" in env and not env["PCAP_AI_TEMPERATURE"].strip():
        ai["temperature"] = None
    if ai:
        top["ai"] = ai
    return top


def _merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_settings() -> AppSettings:
    """Load non-secret YAML/JSON config and environment overrides.

    ``PCAP_API_TOKEN`` is intentionally read only from the environment.  The
    AI API key itself is likewise looked up at request time through the
    configured environment-variable *name* and is never placed in this model.
    """
    env = dict(os.environ)
    file_overlay: dict[str, Any] = {}
    config_path = env.get("PCAP_AI_CONFIG")
    if config_path:
        file_overlay = _load_config_file(config_path)
        # Permit a concise AI-only file while retaining the full settings form.
        if "ai" not in file_overlay and any(key in AIConfig.model_fields for key in file_overlay):
            file_overlay = {"ai": file_overlay}
    merged = _merge(file_overlay, _env_overlay(env))
    if env.get("PCAP_API_TOKEN", ""):
        merged["api_token"] = SecretStr(env["PCAP_API_TOKEN"])
    else:
        merged.pop("api_token", None)
    return AppSettings.model_validate(merged)


__all__ = ["AIConfig", "AppSettings", "ProviderName", "load_settings"]
