"""Evidence-first contracts; AI never mutates deterministic findings."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator


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
    kind: Literal["flow", "dns", "tls", "packet", "arp", "http", "icmp", "wlan", "zeek", "yara"]
    summary: str = Field(max_length=1000)
    packet_refs: list[int] = Field(max_length=50)
    attributes: dict[str, str | int | float | bool] = Field(default_factory=dict, max_length=40)

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
    summary: str | None = Field(default=None, max_length=600)
    triage_class: str | None = Field(default=None, max_length=64)
    triage_confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class Tier1ClassStat(Contract):
    label: str = Field(max_length=64)
    count: int = Field(ge=0)
    avg_confidence: float = Field(ge=0.0, le=1.0)
    escalated: int = Field(ge=0)


class Tier1Summary(Contract):
    enabled: bool = True
    model: str = Field(default="openjev-cal-tier1", max_length=120)
    mode: str = Field(default="heuristic_calibrated", max_length=64)
    total_evaluated: int = Field(ge=0)
    benign_filtered: int = Field(ge=0)
    escalated_count: int = Field(ge=0)
    uncertain_count: int = Field(ge=0)
    reduction_ratio: float = Field(ge=0.0, le=1.0)
    mean_confidence: float = Field(ge=0.0, le=1.0)
    mean_ppl: float = Field(ge=0.0)
    etbert_scored_count: int = Field(default=0, ge=0)
    top_classes: list[Tier1ClassStat] = Field(default_factory=list, max_length=30)
    escalated_evidence_ids: list[EvidenceId] = Field(default_factory=list, max_length=500)


class TimelineBucket(Contract):
    index: int = Field(ge=0)
    label: str = Field(max_length=40)
    packets: int = Field(ge=0)
    bytes: int = Field(ge=0)
    anomalies: int = Field(default=0, ge=0)


class SamplePacket(Contract):
    no: int = Field(ge=1)
    time: str = Field(max_length=40)
    source: str = Field(max_length=100)
    destination: str = Field(max_length=100)
    protocol: str = Field(max_length=32)
    length: int = Field(ge=0)
    info: str = Field(max_length=400)
    evidence_id: EvidenceId | None = None
    triage_label: str | None = Field(default=None, max_length=64)


class CaptureMetrics(Contract):
    duration_seconds: float = Field(default=0.0, ge=0.0)
    start_epoch: float | None = None
    end_epoch: float | None = None
    total_bytes: int = Field(default=0, ge=0)
    protocol_counts: dict[str, int] = Field(default_factory=dict, max_length=50)
    timeline: list[TimelineBucket] = Field(default_factory=list, max_length=72)
    sample_packets: list[SamplePacket] = Field(default_factory=list, max_length=250)


class EvidenceBundle(Contract):
    schema_version: Literal["1.0"] = "1.0"
    capture_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: str = Field(default_factory=utcnow)
    coverage: Coverage
    evidence: list[Evidence] = Field(max_length=5000)
    findings: list[Finding] = Field(max_length=1000)
    triage: Tier1Summary | None = None
    telemetry: CaptureMetrics | None = None

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


class GroundedClaim(Contract):
    claim: str = Field(min_length=1, max_length=4000)
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=100)


class Recommendation(Contract):
    action: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=100)


class AISummary(Contract):
    summary: list[GroundedClaim] = Field(min_length=1, max_length=30)
    assessments: list[Assessment] = Field(max_length=1000)
    limitations: list[GroundedClaim] = Field(max_length=30)
    recommended_actions: list[Recommendation] = Field(max_length=20)


class AIResult(Contract):
    state: Literal["disabled", "completed", "unavailable", "refused", "invalid_output", "budget_exceeded", "cancelled"]
    provider: str
    model: str | None = None
    prompt_sha256: str | None = None
    prompt_version: str = "2.0"
    redaction_policy: str = "identifiers-v1"
    usage: dict[str, int] = Field(default_factory=dict)
    report: AISummary | None = None
    warnings: list[str] = Field(default_factory=list)
    error_code: str | None = None
    context_reduction: dict[str, int | float] | None = None


class AnalysisRequest(Contract):
    capture_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    ai_enabled: bool = False
    ai_consent: bool = False
    resource_mode: Literal["auto", "fast", "deep", "unlimited"] = "auto"
    triage_enabled: bool = True
    triage_endpoint_consent: bool = False

    @model_validator(mode="after")
    def consent(self):
        if self.ai_enabled and not self.ai_consent:
            raise ValueError("AI processing requires explicit consent")
        if self.triage_endpoint_consent and not self.triage_enabled:
            raise ValueError("Tier-1 endpoint consent requires Tier-1 to be enabled")
        return self


class GroundedChatRequest(Contract):
    question: str = Field(min_length=1, max_length=8_000)
    consent: StrictBool


class OSINTLookupRequest(Contract):
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    candidate_ids: list[Annotated[str, Field(pattern=r"^IOC-[a-f0-9]{16}$")]] = Field(min_length=1, max_length=12)
    providers: list[Literal["virustotal", "abuseipdb", "greynoise", "shodan", "otx"]] = Field(min_length=1, max_length=5)
    consent: StrictBool
    accept_uncertain_retry_risk: StrictBool = False

    @model_validator(mode="after")
    def unique_selection(self):
        if len(set(self.candidate_ids)) != len(self.candidate_ids):
            raise ValueError("duplicate_osint_candidate")
        if len(set(self.providers)) != len(self.providers):
            raise ValueError("duplicate_osint_provider")
        return self


class ChunkUploadInitRequest(Contract):
    filename: str = Field(min_length=1, max_length=255)
    total_bytes: int = Field(ge=1)
    format_hint: Literal["auto", "pcap", "pcapng", "cap", "csv", "tsv"] = "auto"


class LocalCaptureRequest(Contract):
    path: str | None = Field(default=None, min_length=1, max_length=1024)
    file_grant_token: str | None = Field(default=None, min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")

    @model_validator(mode="after")
    def exactly_one_source(self):
        if bool(self.path) == bool(self.file_grant_token):
            raise ValueError("provide exactly one local path or file grant")
        return self


class WorkspaceUpdateRequest(Contract):
    data_dir: str | None = Field(default=None, min_length=1, max_length=1024)
    local_ingest_roots: list[str] | None = Field(default=None, max_length=20)
    add_local_ingest_root: str | None = Field(default=None, min_length=1, max_length=1024)
    remove_local_ingest_root: str | None = Field(default=None, min_length=1, max_length=1024)
    resource_mode: Literal["auto", "fast", "deep", "unlimited"] | None = None


class NativePickRequest(Contract):
    purpose: Literal["data_dir", "capture_root", "capture_file"]


class BatchItemResponse(Contract):
    index: int = Field(ge=0)
    capture_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    analysis_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=1)
    format: Literal["pcap", "pcapng"]
    state: Literal["queued", "parsing", "awaiting_ai", "generating", "completed", "partial", "failed", "cancelled"]
    error_code: str | None = None
    evidence_available: bool = False


class BatchResponse(Contract):
    batch_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    created_at: str
    state: Literal["queued", "running", "partial", "completed", "failed", "cancelled"]
    total_items: int = Field(ge=1, le=64)
    completed_items: int = Field(ge=0)
    failed_items: int = Field(ge=0)
    partial_items: int = Field(ge=0)
    cancelled_items: int = Field(ge=0)
    items: list[BatchItemResponse] = Field(min_length=1, max_length=64)


class ProblemDetails(Contract):
    type: str
    title: str
    status: int = Field(ge=400, le=599)
    code: str
    request_id: str = Field(pattern=r"^[a-f0-9]{32}$")
