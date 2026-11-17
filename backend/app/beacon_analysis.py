"""Bounded, metadata-only interval and jitter heuristics for beacon candidates.

Adapted from the periodicity and modal-interval/jitter scoring in
``ninedter/pcap-hunter/app/pipeline/beacon.py``. Results are low-confidence
candidates, not verdicts. This module intentionally accepts no endpoint
addresses and never includes identifiers or payload data in summaries.

MIT License
Copyright (c) 2025 ninedter

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from statistics import fmean, pstdev
from typing import Iterable


MAX_BEACON_OBSERVATIONS = 2_048
MAX_TIMESTAMPS_PER_OBSERVATION = 50
MAX_BEACON_CANDIDATES = 50
MAX_BEACON_EVIDENCE_IDS = 100
MIN_BEACON_TIMESTAMPS = 4
MIN_BEACON_SCORE = 0.35
_EVIDENCE_ID_RE = re.compile(r"^EV-[0-9]{6}$")

# Adapted from upstream's benign periodic service penalties; no IP allowlist is
# used here so the analyzer need not inspect or expose raw endpoint addresses.
_BENIGN_SERVICE_MULTIPLIERS = {
    53: 0.15,
    123: 0.15,
    443: 0.15,
    80: 0.30,
    993: 0.15,
    995: 0.15,
    5223: 0.15,
    5228: 0.15,
    1883: 0.20,
    8883: 0.20,
    5060: 0.20,
    5061: 0.20,
    5353: 0.15,
}
_BENIGN_PERIODIC_PROTOCOLS = frozenset({"icmp", "ntp", "ssdp", "mdns", "igmp"})


@dataclass(frozen=True, slots=True)
class BeaconObservation:
    """One locally retained flow sample; evidence_id must name retained Evidence."""

    evidence_id: str
    timestamps: Iterable[float]
    protocol: str | None = None
    destination_port: int | None = None
    timestamps_truncated: bool = False


@dataclass(frozen=True, slots=True)
class BeaconCandidate:
    detector: str
    title: str
    summary: str
    confidence: str
    score: float
    packet_count: int
    mean_interval: float | None
    interval_cv: float | None
    dominant_interval: float | None
    jitter_pct: float | None
    evidence_ids: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BeaconAnalysisResult:
    candidates: tuple[BeaconCandidate, ...]
    observations_examined: int
    partial: bool
    truncated: bool


def _bounded_sorted_timestamps(values: Iterable[float]) -> tuple[list[float], bool]:
    """Read at most cap+1 values, discard non-finite/unparseable values, sort."""
    timestamps: list[float] = []
    truncated = False
    try:
        iterator = iter(values)
    except TypeError:
        return timestamps, False
    for raw in iterator:
        if len(timestamps) >= MAX_TIMESTAMPS_PER_OBSERVATION:
            truncated = True
            break
        if isinstance(raw, bool):
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError, OverflowError):
            continue
        if math.isfinite(value):
            timestamps.append(value)
    timestamps.sort()
    return timestamps, truncated


def _histogram_entropy(values: list[float], bins: int) -> float:
    if not values:
        return 0.0
    low, high = min(values), max(values)
    if high <= low:
        return 0.0
    width = (high - low) / bins
    counts = [0] * bins
    for value in values:
        index = min(bins - 1, int((value - low) / width))
        counts[index] += 1
    total = len(values)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def periodicity_score(timestamps: Iterable[float]) -> dict[str, int | float | None]:
    """Return bounded interval regularity metrics, adapting upstream's score."""
    times, _ = _bounded_sorted_timestamps(timestamps)
    count = len(times)
    if count < 3:
        return {"count": count, "mean_interval": None, "std_interval": None,
                "cv": None, "entropy": None, "score": 0.0}

    gaps = [times[index] - times[index - 1] for index in range(1, count)]
    mean_gap = fmean(gaps)
    std_gap = pstdev(gaps)
    cv = std_gap / mean_gap if mean_gap > 0 else None
    bins = min(20, max(5, len(gaps) // 3))
    entropy = _histogram_entropy(gaps, bins)
    raw_score = (1.0 - min(cv if cv is not None else 1.0, 1.0)) * 0.6
    raw_score += (1.0 - min(entropy / 4.0, 1.0)) * 0.4
    volume_scale = min(count / 20.0, 1.0) * 0.7 + 0.3
    score = raw_score * volume_scale if mean_gap > 0 else 0.0
    return {
        "count": count,
        "mean_interval": mean_gap,
        "std_interval": std_gap,
        "cv": cv,
        "entropy": entropy,
        "score": min(1.0, max(0.0, score)),
    }


def jitter_score(timestamps: Iterable[float]) -> dict[str, int | float | None]:
    """Score the fraction of bounded gaps near a deterministic modal interval."""
    times, _ = _bounded_sorted_timestamps(timestamps)
    if len(times) < 5:
        return {"jitter_score": 0.0, "dominant_interval": None,
                "jitter_pct": None, "consistent_ratio": None}
    gaps = [times[index] - times[index - 1] for index in range(1, len(times))]
    high = max(gaps, default=0.0)
    if high <= 0:
        return {"jitter_score": 0.0, "dominant_interval": 0.0,
                "jitter_pct": 0.0, "consistent_ratio": 0.0}

    low = min(gaps)
    n_bins = min(50, max(10, len(gaps) // 3))
    if high == low:
        dominant = high
    else:
        width = (high - low) / n_bins
        counts = [0] * n_bins
        for gap in gaps:
            counts[min(n_bins - 1, int((gap - low) / width))] += 1
        peak = max(range(n_bins), key=lambda index: counts[index])
        dominant = low + (peak + 0.5) * width
    if dominant <= 0:
        return {"jitter_score": 0.0, "dominant_interval": 0.0,
                "jitter_pct": 0.0, "consistent_ratio": 0.0}

    tolerance = dominant * 0.2
    consistent_gaps = [gap for gap in gaps if dominant - tolerance <= gap <= dominant + tolerance]
    ratio = len(consistent_gaps) / len(gaps)
    jitter_pct = (pstdev(consistent_gaps) / dominant * 100.0) if len(consistent_gaps) > 1 else 0.0
    raw_score = ratio * 0.7 + (1.0 - min(jitter_pct / 30.0, 1.0)) * 0.3
    volume_scale = min(len(times) / 20.0, 1.0) * 0.7 + 0.3
    return {
        "jitter_score": min(1.0, max(0.0, raw_score * volume_scale)),
        "dominant_interval": round(dominant, 2),
        "jitter_pct": round(jitter_pct, 1),
        "consistent_ratio": round(ratio, 3),
    }


def _valid_evidence_id(value: object) -> bool:
    return isinstance(value, str) and bool(_EVIDENCE_ID_RE.fullmatch(value))


def _metadata_penalty(protocol: str | None, port: int | None) -> float:
    penalty = _BENIGN_SERVICE_MULTIPLIERS.get(port, 1.0) if port is not None else 1.0
    if isinstance(protocol, str) and protocol.strip().lower() in _BENIGN_PERIODIC_PROTOCOLS:
        penalty *= 0.15
    return penalty


def analyze_beacon_candidates(
    observations: Iterable[BeaconObservation],
    *,
    input_truncated: bool = False,
) -> BeaconAnalysisResult:
    """Rank low-confidence candidates over bounded retained flow metadata.

    `input_truncated` should reflect upstream packet/flow sampling limits. IDs
    are shape-checked here; integration must ensure each ID exists in the
    retained Evidence collection. Output ordering and citations are stable.
    """
    examined: list[tuple[BeaconObservation, list[float], bool]] = []
    truncated = bool(input_truncated)
    observations_examined = 0
    iterator = iter(observations)
    for observation in iterator:
        if observations_examined >= MAX_BEACON_OBSERVATIONS:
            truncated = True
            break
        observations_examined += 1
        if not isinstance(observation, BeaconObservation):
            continue
        times, time_cap_hit = _bounded_sorted_timestamps(observation.timestamps)
        local_truncated = bool(observation.timestamps_truncated or time_cap_hit)
        truncated = truncated or local_truncated
        examined.append((observation, times, local_truncated))

    scored: list[BeaconCandidate] = []
    for observation, times, local_truncated in examined:
        if not _valid_evidence_id(observation.evidence_id) or len(times) < MIN_BEACON_TIMESTAMPS:
            continue
        periodic = periodicity_score(times)
        jitter = jitter_score(times)
        raw_score = max(float(periodic["score"] or 0.0), float(jitter["jitter_score"] or 0.0))
        port = observation.destination_port
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            port = None
        score = raw_score * _metadata_penalty(observation.protocol, port)
        if score < MIN_BEACON_SCORE:
            continue

        evidence_ids = (observation.evidence_id,)[:MAX_BEACON_EVIDENCE_IDS]
        mean_gap = periodic["mean_interval"]
        cv = periodic["cv"]
        dominant = jitter["dominant_interval"]
        jitter_pct = jitter["jitter_pct"]
        scored.append(
            BeaconCandidate(
                detector="periodic_flow_beacon_heuristic",
                title="Periodic flow timing candidate (low confidence)",
                summary=(
                    f"A retained flow sample with {len(times)} timestamps showed locally scored periodic timing "
                    f"(score {score:.2f}; mean interval "
                    f"{float(mean_gap):.2f}s" if mean_gap is not None else
                    f"A retained flow sample with {len(times)} timestamps showed locally scored periodic timing "
                    f"(score {score:.2f})"
                ) + ("; the bounded timestamp sample was incomplete." if local_truncated else "."),
                confidence="low",
                score=round(score, 4),
                packet_count=len(times),
                mean_interval=round(float(mean_gap), 3) if mean_gap is not None else None,
                interval_cv=round(float(cv), 4) if cv is not None else None,
                dominant_interval=float(dominant) if dominant is not None else None,
                jitter_pct=float(jitter_pct) if jitter_pct is not None else None,
                evidence_ids=evidence_ids,
                limitations=(
                    "Low-confidence timing heuristic only; periodic traffic is not proof of command-and-control or compromise.",
                    "Legitimate scheduled jobs, keep-alives, retries, and capture sampling can produce similar intervals.",
                    "Only retained timestamp metadata was scored; absent candidates do not establish benignness.",
                ),
            )
        )

    scored.sort(key=lambda candidate: (-candidate.score, candidate.evidence_ids))
    if len(scored) > MAX_BEACON_CANDIDATES:
        scored = scored[:MAX_BEACON_CANDIDATES]
        truncated = True
    return BeaconAnalysisResult(
        candidates=tuple(scored),
        observations_examined=observations_examined,
        partial=truncated,
        truncated=truncated,
    )
