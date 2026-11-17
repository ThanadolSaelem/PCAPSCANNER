from __future__ import annotations

from dataclasses import replace

from backend.app import beacon_analysis
from backend.app.beacon_analysis import (
    BeaconObservation,
    analyze_beacon_candidates,
    jitter_score,
    periodicity_score,
)


def _observation(index: int, timestamps: tuple[float, ...], **kwargs) -> BeaconObservation:
    return BeaconObservation(evidence_id=f"EV-{index:06d}", timestamps=timestamps, **kwargs)


def test_periodicity_score_is_deterministic_and_finite() -> None:
    result = periodicity_score([6.0, 0.0, 4.0, 2.0, 8.0])
    assert result["count"] == 5
    assert result["mean_interval"] == 2.0
    assert result["std_interval"] == 0.0
    assert result["cv"] == 0.0
    assert result["score"] == 0.475
    assert periodicity_score([0.0, 2.0, 4.0, 6.0, 8.0]) == result
    assert periodicity_score([0.0, float("nan"), float("inf")])["count"] == 1


def test_jitter_score_tolerates_interval_jitter_and_caps_sample() -> None:
    regular = jitter_score([0, 10, 20, 30, 40, 50])
    jittered = jitter_score([0, 9.5, 20.2, 29.8, 40.1, 50])
    assert regular["jitter_score"] > 0.0
    assert jittered["jitter_score"] >= 0.0
    assert jitter_score([0, 10, 20, 30])["dominant_interval"] is None


def test_candidate_is_low_confidence_cited_and_summary_omits_raw_endpoints() -> None:
    item = _observation(7, (0, 60, 120, 180, 240), protocol="tcp", destination_port=8443)
    candidate = analyze_beacon_candidates([item]).candidates[0]
    assert candidate.detector == "periodic_flow_beacon_heuristic"
    assert candidate.confidence == "low"
    assert candidate.evidence_ids == ("EV-000007",)
    assert "192.0.2.44" not in candidate.summary
    assert "198.51.100.8" not in candidate.summary
    assert candidate.limitations


def test_candidate_ranking_and_citations_are_permutation_stable() -> None:
    rows = [
        _observation(2, (0, 20, 40, 60, 80)),
        _observation(1, (0, 20, 40, 60, 80)),
        _observation(3, (0, 20, 40, 60, 80), destination_port=443),
    ]
    forward = analyze_beacon_candidates(rows).candidates
    reverse = analyze_beacon_candidates(list(reversed(rows))).candidates
    assert forward == reverse
    assert [candidate.evidence_ids for candidate in forward] == [("EV-000001",), ("EV-000002",)]


def test_benign_port_penalty_can_suppress_candidate_and_bad_evidence_is_rejected() -> None:
    periodic = (0, 60, 120, 180, 240)
    benign = _observation(1, periodic, destination_port=443)
    invalid_id = BeaconObservation("not-an-evidence-id", periodic)
    assert analyze_beacon_candidates([benign, invalid_id]).candidates == ()


def test_timestamp_cap_and_upstream_sampling_are_reported_partial() -> None:
    many = _observation(1, tuple(range(100)))
    sampled = replace(_observation(2, (0, 60, 120, 180, 240)), timestamps_truncated=True)
    result = analyze_beacon_candidates([many, sampled])
    assert result.truncated is True
    assert result.partial is True
    assert result.candidates[0].packet_count == beacon_analysis.MAX_TIMESTAMPS_PER_OBSERVATION
    assert any("sample was incomplete" in item.summary for item in result.candidates)


def test_observation_and_candidate_caps_are_strict_and_reported(monkeypatch) -> None:
    monkeypatch.setattr(beacon_analysis, "MAX_BEACON_OBSERVATIONS", 2)
    rows = [_observation(i, (0, 10, 20, 30, 40)) for i in range(1, 5)]
    capped = analyze_beacon_candidates(rows)
    assert capped.observations_examined == 2
    assert capped.truncated is True

    monkeypatch.setattr(beacon_analysis, "MAX_BEACON_OBSERVATIONS", 100)
    monkeypatch.setattr(beacon_analysis, "MAX_BEACON_CANDIDATES", 1)
    candidate_capped = analyze_beacon_candidates(rows[:3])
    assert len(candidate_capped.candidates) == 1
    assert candidate_capped.truncated is True


def test_upstream_partial_coverage_propagates_even_when_no_candidate() -> None:
    result = analyze_beacon_candidates([], input_truncated=True)
    assert result.candidates == ()
    assert result.partial is True
    assert result.truncated is True
