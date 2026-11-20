"""Prompt templates and choice-token resolution extracted for OpenJev inference."""
from __future__ import annotations

from typing import Any

from .schema import OPENJEV_CLASS_CRITERIA, TRAFFIC_CLASSES

CHOICE_LETTERS: tuple[str, ...] = tuple("ABCDEFGHIJ")


def to_single_token_choice_prompt(state_text: str) -> str:
    """Format a classification prompt ending cleanly at a single A-J choice letter."""
    lines = [
        f"{CHOICE_LETTERS[idx]}. {item['label']} — {item['description']}"
        for idx, item in enumerate(OPENJEV_CLASS_CRITERIA)
    ]
    options = "\n".join(lines)
    return (
        "You are a calibrated Tier-1 network traffic classifier.\n"
        "Inspect the anonymized L2-L7 telemetry and reply with ONLY one option letter (A-J).\n\n"
        f"State: {state_text}\n\n"
        f"Options:\n{options}\n\n"
        "Answer letter:"
    )


def to_choice_prompt(state_text: str, *, include_criteria: bool = True) -> str:
    """Render a compact classification prompt ending in \\boxed{CLASS_NAME}."""
    if include_criteria:
        choices = "\n".join(
            f"{idx + 1}. {item['label']} — {item['description']}"
            for idx, item in enumerate(OPENJEV_CLASS_CRITERIA)
        )
    else:
        choices = "\n".join(f"{idx + 1}. {cls}" for idx, cls in enumerate(TRAFFIC_CLASSES))
    return (
        "You are a calibrated Tier-1 network traffic classifier.\n"
        "Inspect the anonymized L2-L7 flow telemetry below and select the single best class.\n\n"
        f"State: {state_text}\n\n"
        f"Classes:\n{choices}\n\n"
        "Respond ONLY with \\boxed{CLASS_NAME} (no extra text).\nAnswer: \\boxed{"
    )


def resolve_choice_token_ids(tokenizer: Any) -> list[int]:
    """Resolve 10 distinct single-token vocabulary IDs corresponding to `A`..`J`."""
    ids: list[int] = []
    seen: set[int] = set()
    for ch in CHOICE_LETTERS:
        toks_sp = tokenizer.encode(" " + ch, add_special_tokens=False)
        toks_bare = tokenizer.encode(ch, add_special_tokens=False)
        cand = toks_sp[-1] if toks_sp else toks_bare[-1]
        if cand in seen and toks_bare:
            cand = toks_bare[-1]
        seen.add(cand)
        ids.append(int(cand))
    if len(set(ids)) != len(TRAFFIC_CLASSES):
        raise ValueError(f"Tokenizer did not yield 10 distinct choice token IDs for A-J: {ids}")
    return ids


__all__ = [
    "CHOICE_LETTERS",
    "resolve_choice_token_ids",
    "to_choice_prompt",
    "to_single_token_choice_prompt",
]
