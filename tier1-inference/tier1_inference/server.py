"""Standalone FastAPI inference server (`/health`, `/etbert/score`, `/classify`, `/v1/systemone`)."""
from __future__ import annotations

import hmac
import platform
import sys
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from .etbert_scorer import ETBertDatagramScorer
from .openjev_scorer import OpenJevTier1Scorer
from .schema import (
    DEFAULT_HIGH_THRESHOLD,
    DEFAULT_LOW_THRESHOLD,
    OPENJEV_CLASS_CRITERIA,
    TRAFFIC_CLASSES,
    resolve_device,
)

MAX_STATE_CHARS = 16_384
MAX_QUESTIONS = 16
DEFAULT_MAX_ITEMS = 512


class ETBertItemModel(BaseModel):
    model_config = ConfigDict(extra="ignore")

    item_id: str | None = Field(default=None, max_length=256)
    kind: str = Field(default="flow", max_length=32)
    state: str = Field(default="", max_length=MAX_STATE_CHARS)
    features: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    bigram_tokens: list[Any] = Field(default_factory=list, max_length=512)
    protocol: str | None = Field(default=None, max_length=32)
    src_port: int | None = None
    dst_port: int | None = None
    packets: int | None = None
    bytes: int | None = None


class ETBertScoreRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    model: str | None = Field(default=None, max_length=128)
    items: list[ETBertItemModel] = Field(default_factory=list)


class ClassifyItemModel(BaseModel):
    model_config = ConfigDict(extra="ignore")

    evidence_id: str | None = Field(default=None, max_length=256)
    item_id: str | None = Field(default=None, max_length=256)
    kind: str | None = Field(default="flow", max_length=32)
    state: str | None = Field(default=None, max_length=MAX_STATE_CHARS)
    compact_text: str | None = Field(default=None, max_length=MAX_STATE_CHARS)


class ClassifyRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    model: str | None = Field(default=None, max_length=128)
    items: list[ClassifyItemModel] = Field(default_factory=list)


class SystemOneRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    model: str | None = Field(default=None, max_length=128)
    state: str = Field(default="", max_length=MAX_STATE_CHARS)
    questions: dict[str, Any] = Field(default_factory=lambda: {"traffic_class": {"type": "choice"}})


def create_app(
    *,
    openjev_checkpoint: str | None = None,
    etbert_checkpoint: str | None = None,
    base_model: str | None = None,
    device: str = "auto",
    high_threshold: float = DEFAULT_HIGH_THRESHOLD,
    low_threshold: float = DEFAULT_LOW_THRESHOLD,
    max_items: int = DEFAULT_MAX_ITEMS,
    api_token: str | None = None,
    require_weights: bool = False,
    openjev_model_name: str = "openjev-cal-tier1",
    etbert_model_name: str = "etbert-l7-datagram",
) -> FastAPI:
    """Create FastAPI service exposing ET-BERT and OpenJev Tier-1 inference endpoints."""
    resolved_dev = resolve_device(device)
    normalized_token = (api_token or "").strip() or None
    capped_max_items = max(1, min(int(max_items), 4096))

    etbert_scorer = ETBertDatagramScorer(
        checkpoint_path=etbert_checkpoint,
        device=resolved_dev,
        model_name=etbert_model_name,
        require_weights=bool(require_weights and etbert_checkpoint),
    )
    openjev_scorer = OpenJevTier1Scorer(
        checkpoint_path=openjev_checkpoint,
        base_model=base_model,
        device=resolved_dev,
        model_name=openjev_model_name,
        require_weights=bool(require_weights and openjev_checkpoint),
    )

    if require_weights and not (openjev_scorer.loaded_weights or etbert_scorer.loaded_weights):
        raise RuntimeError(
            "require_weights=True was specified, but neither OpenJev nor ET-BERT loaded neural HF weights."
        )

    app = FastAPI(
        title="PCAPSCANNER Tier-1 Inference API",
        version="1.0.0",
        description=(
            "Standalone inference-only ET-BERT (L7 datagram) + OpenJev LoRA/HF "
            "Tier-1 traffic classifier API (no training dependencies)."
        ),
    )
    app.state.etbert_scorer = etbert_scorer
    app.state.openjev_scorer = openjev_scorer
    app.state.max_items = capped_max_items
    app.state.auth_required = normalized_token is not None

    def verify_bearer(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> None:
        _ = request
        if normalized_token is None:
            return
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing_or_invalid_bearer_token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        presented = authorization[7:].strip()
        if not hmac.compare_digest(presented.encode("utf-8"), normalized_token.encode("utf-8")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_bearer_token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @app.get("/health")
    def health() -> dict[str, Any]:
        safe_etb_info = {
            key: value
            for key, value in etbert_scorer.checkpoint_info.items()
            if key in {"configured", "exists", "format", "architecture", "checkpoint_type", "has_classification_head"}
        }
        return {
            "status": "ok",
            "service": "pcapscanner-tier1-inference",
            "version": "1.0.0",
            "device": resolved_dev,
            "platform": sys.platform,
            "machine": platform.machine(),
            "openjev_loaded": openjev_scorer.loaded_weights,
            "openjev_mode": openjev_scorer.checkpoint_mode if openjev_scorer.loaded_weights else "state_fallback",
            "etbert_loaded": etbert_scorer.loaded_weights,
            "etbert_mode": "neural_hf" if etbert_scorer.loaded_weights else "feature_fallback",
            "etbert_checkpoint_info": safe_etb_info,
            "auth_required": normalized_token is not None,
            "max_items": capped_max_items,
            "classes": list(TRAFFIC_CLASSES),
            "criteria_count": len(OPENJEV_CLASS_CRITERIA),
        }

    @app.post("/etbert/score", dependencies=[Depends(verify_bearer)])
    def etbert_score(payload: ETBertScoreRequest) -> dict[str, Any]:
        if len(payload.items) > capped_max_items:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"batch_too_large: max_items={capped_max_items}",
            )
        raw_items = [item.model_dump(exclude_none=True) for item in payload.items]
        results = etbert_scorer.score_batch(raw_items)
        return {
            "model": payload.model or etbert_scorer.model_name,
            "count": len(results),
            "results": results,
        }

    @app.post("/classify", dependencies=[Depends(verify_bearer)])
    def classify_batch(payload: ClassifyRequest) -> dict[str, Any]:
        if len(payload.items) > capped_max_items:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"batch_too_large: max_items={capped_max_items}",
            )
        states = [str(item.state or item.compact_text or "") for item in payload.items]
        scored = openjev_scorer.score_states(
            states,
            high_threshold=high_threshold,
            low_threshold=low_threshold,
        )
        results = [
            {"evidence_id": item.evidence_id or item.item_id, **res}
            for item, res in zip(payload.items, scored)
        ]
        return {
            "model": payload.model or openjev_scorer.model_name,
            "count": len(results),
            "results": results,
        }

    @app.post("/v1/systemone", dependencies=[Depends(verify_bearer)])
    def systemone(payload: SystemOneRequest) -> dict[str, Any]:
        if len(payload.questions) > MAX_QUESTIONS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"too_many_questions: max={MAX_QUESTIONS}",
            )
        questions = payload.questions or {"traffic_class": {"type": "choice"}}
        res = openjev_scorer.score_states(
            [payload.state],
            high_threshold=high_threshold,
            low_threshold=low_threshold,
        )[0]
        answers: dict[str, Any] = {}
        for q_name in questions:
            answers[q_name] = {
                "prediction": res["predicted_class"],
                "label": res["label"],
                "confidence": res["confidence"],
                "ppl": res["ppl"],
                "decision": res["decision"],
                "probabilities": res["probabilities"],
            }
        return {
            "model": payload.model or res["model"],
            "device": resolved_dev,
            "answers": answers,
        }

    return app


__all__ = [
    "ClassifyRequest",
    "ETBertScoreRequest",
    "SystemOneRequest",
    "create_app",
]
