"""PCAPSCANNER AI service public API."""

from .catalog import get_preset, infer_preset, list_presets
from .providers import (
    clear_runtime_api_key,
    credential_slot_for,
    credential_slot_names,
    generate_chat_completion,
    generate_summary,
    get_runtime_api_key,
    list_models,
    probe_models,
    runtime_api_key_status,
    set_runtime_api_key,
)

__all__ = [
    "clear_runtime_api_key",
    "credential_slot_for",
    "credential_slot_names",
    "get_preset",
    "infer_preset",
    "list_presets",
    "generate_chat_completion",
    "generate_summary",
    "get_runtime_api_key",
    "list_models",
    "probe_models",
    "runtime_api_key_status",
    "set_runtime_api_key",
]
