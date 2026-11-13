"""Evidence-first contracts; AI never mutates deterministic findings."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


EvidenceId = Annotated[str, Field(pattern=r"^EV-[0-9]{6}$")]
Confidence = Literal["low", "medium", "high"]
Severity = Literal["info", "low", "medium", "high"]


class Stage(Contract):
    name: str = Field(max_length=80)
    state: Literal["completed", "partial", "failed", "skipped", "unavailable"]
    detail: str = Field(max_length=500)


class Coverage(Contract):
    packets_seen: int = Field(ge=0)
    packets_analyzed: int = Field(ge=0)
    truncated: bool
    parser: str = Field(max_length=100)
    warnings: list[str] = Field(default_factory=list, max_length=100)
    stages: list[Stage] = Field(default_factory=list, max_length=30)


class Evidence(Contract):
    evidence_id: EvidenceId
    kind: Literal["flow", "dns", "tls", "packet"]
    summary: str = Field(max_length=1000)
    packet_refs: list[int] = Field(max_length=50)
    attributes: dict[str, str | int | float | bool] = Field(default_factory=dict, max_length=30)

    @model_validator(mode="after")
    def positive_refs(self):
        if any(n < 1 for n in self.packet_refs):
            raise ValueError("Packet references must be positive")
        return self


class Finding(Contract):
    finding_id: str = Field(pattern=r"^F-[0-9]{4}$")
    detector: str = Field(max_length=100)
    title: str = Field(max_length=300)
    severity: Severity
    confidence: Confidence
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=100)
    limitations: list[str] = Field(default_factory=list, max_length=20)


class EvidenceBundle(Contract):
    schema_version: Literal["1.0"] = "1.0"
    capture_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: str = Field(default_factory=utcnow)
    coverage: Coverage
    evidence: list[Evidence] = Field(max_length=5000)
    findings: list[Finding] = Field(max_length=1000)

    @model_validator(mode="after")
    def cross_references(self):
        ids = [e.evidence_id for e in self.evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate evidence IDs")
        fids = [f.finding_id for f in self.findings]
        if len(fids) != len(set(fids)):
            raise ValueError("Duplicate finding IDs")
        known = set(ids)
        if any(not set(f.evidence_ids).issubset(known) for f in self.findings):
            raise ValueError("Finding cites unknown evidence")
        if self.coverage.packets_analyzed > self.coverage.packets_seen:
            raise ValueError("Invalid packet coverage")
        return self


class Assessment(Contract):
    finding_id: str
    interpretation: str = Field(min_length=1, max_length=4000)
    confidence: Confidence
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=100)


class Recommendation(Contract):
    action: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[EvidenceId] = Field(max_length=100)


class AISummary(Contract):
    summary: str = Field(min_length=1, max_length=6000)
    assessments: list[Assessment] = Field(max_length=1000)
    limitations: list[str] = Field(max_length=30)
    recommended_actions: list[Recommendation] = Field(max_length=20)


class AIResult(Contract):
    state: Literal["disabled", "completed", "unavailable", "refused", "invalid_output", "budget_exceeded", "cancelled"]
    provider: str
    model: str | None = None
    prompt_sha256: str | None = None
    prompt_version: str = "1.0"
    redaction_policy: str = "identifiers-v1"
    usage: dict[str, int] = Field(default_factory=dict)
    report: AISummary | None = None
    warnings: list[str] = Field(default_factory=list)
    error_code: str | None = None


class AnalysisRequest(Contract):
    capture_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    ai_enabled: bool = False
    ai_consent: bool = False

    @model_validator(mode="after")
    def consent(self):
        if self.ai_enabled and not self.ai_consent:
            raise ValueError("AI processing requires explicit consent")
        return self


class ProblemDetails(Contract):
    type: str
    title: str
    status: int = Field(ge=400, le=599)
    code: str
    request_id: str = Field(pattern=r"^[a-f0-9]{32}$")
