"""Standalone Tier-1 Traffic Inference package (ET-BERT + OpenJev LoRA)."""
from .etbert_scorer import (
    ETBertDatagramScorer,
    bytes_to_etbert_bigram_tokens,
    format_etbert_input_text,
    inspect_etbert_checkpoint,
    is_data_bearing_flow,
)
from .openjev_scorer import OpenJevTier1Scorer, score_state_calibrated_fallback
from .prompts import CHOICE_LETTERS, resolve_choice_token_ids, to_choice_prompt, to_single_token_choice_prompt
from .schema import (
    CLASS_TO_INDEX,
    DEFAULT_HIGH_THRESHOLD,
    DEFAULT_LOW_THRESHOLD,
    OPENJEV_CLASS_CRITERIA,
    TRAFFIC_CLASSES,
    resolve_device,
    resolve_torch_dtype,
)
from .server import create_app

__version__ = "1.0.0"


def convert_uer_checkpoint(*args, **kwargs):
    """Lazily delegate to `tier1_inference.convert_uer.convert_uer_checkpoint`."""
    from .convert_uer import convert_uer_checkpoint as _impl

    return _impl(*args, **kwargs)


__all__ = [
    "CHOICE_LETTERS",
    "CLASS_TO_INDEX",
    "DEFAULT_HIGH_THRESHOLD",
    "DEFAULT_LOW_THRESHOLD",
    "ETBertDatagramScorer",
    "OPENJEV_CLASS_CRITERIA",
    "OpenJevTier1Scorer",
    "TRAFFIC_CLASSES",
    "__version__",
    "bytes_to_etbert_bigram_tokens",
    "convert_uer_checkpoint",
    "create_app",
    "format_etbert_input_text",
    "inspect_etbert_checkpoint",
    "is_data_bearing_flow",
    "resolve_choice_token_ids",
    "resolve_device",
    "resolve_torch_dtype",
    "score_state_calibrated_fallback",
    "to_choice_prompt",
    "to_single_token_choice_prompt",
]
