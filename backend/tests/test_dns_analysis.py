from __future__ import annotations

from backend.app import dns_analysis
from backend.app.dns_analysis import DNSObservation, analyze_dns_candidates, normalize_domain


def _row(index: int, query: str, *, source: str = "192.0.2.10", qtype: int = 1, rcode: int | None = None):
    return DNSObservation(
        query=query,
        evidence_id=f"EV-{index:06d}",
        source=source,
        response_code=rcode,
        qtype=qtype,
    )


def test_normalizer_rejects_malformed_oversized_and_non_dns_values() -> None:
    assert normalize_domain("WWW.Example.COM.") == "www.example.com"
    assert normalize_domain("host.example.co.uk") == "host.example.co.uk"
    assert normalize_domain("") is None
    assert normalize_domain("localhost") is None
    assert normalize_domain("bad..example") is None
    assert normalize_domain("-bad.example") is None
    assert normalize_domain("x" * 64 + ".example") is None
    assert normalize_domain("a" * 250 + ".com") is None
    assert normalize_domain("192.0.2.1") is None
    assert normalize_domain("tést.example") is None


def test_dga_like_domain_produces_low_confidence_candidate_without_raw_identifiers() -> None:
    query = "xk7m2p9q4v8n3z2a.example.net"
    result = analyze_dns_candidates([_row(1, query)])

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.detector == "dns_dga_heuristic"
    assert candidate.evidence_ids == ("EV-000001",)
    assert "192.0.2.10" not in candidate.summary
    assert query not in candidate.summary
    assert "xk7m2p9q4v8n3z2a" not in candidate.title + candidate.summary
    assert candidate.limitations
    assert result.truncated is False


def test_tunneling_candidate_requires_diverse_long_subdomains_and_cites_rows() -> None:
    rows = [
        _row(i + 1, f"{'a' * 31}{i:02d}.tunnel.example", qtype=16)
        for i in range(24)
    ]
    result = analyze_dns_candidates(rows)

    candidates = [item for item in result.candidates if item.detector == "dns_tunneling_heuristic"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert len(candidate.evidence_ids) == 24
    assert candidate.evidence_ids == tuple(f"EV-{i:06d}" for i in range(1, 25))
    assert "192.0.2.10" not in candidate.summary
    assert "tunnel.example" not in candidate.summary
    assert "24 distinct subdomain names" in candidate.summary


def test_repeated_benign_or_response_rows_do_not_create_dga_or_tunnel_candidate() -> None:
    rows = [_row(i + 1, "www.example.com") for i in range(100)]
    rows.extend(_row(200 + i, "xk7m2p9q4v8n3z2a.example.net", rcode=3) for i in range(5))
    result = analyze_dns_candidates(rows)
    assert result.candidates == ()


def test_candidates_are_stable_under_input_permutation() -> None:
    rows = [_row(i + 1, f"{'b' * 31}{i:02d}.tunnel.example", qtype=16) for i in range(24)]
    forward = analyze_dns_candidates(rows).candidates
    reverse = analyze_dns_candidates(list(reversed(rows))).candidates
    assert forward == reverse


def test_citation_cap_is_permutation_invariant_after_100_ids() -> None:
    dga_rows = [_row(i + 1, "xk7m2p9q4v8n3z2a.example.net") for i in range(125)]
    forward_dga = analyze_dns_candidates(dga_rows).candidates
    reverse_dga = analyze_dns_candidates(list(reversed(dga_rows))).candidates
    assert forward_dga == reverse_dga
    assert forward_dga[0].evidence_ids == tuple(f"EV-{i:06d}" for i in range(1, 101))

    tunnel_rows = []
    for index in range(144):
        name_index = index % 24
        tunnel_rows.append(_row(index + 1, f"{'c' * 31}{name_index:02d}.tunnel.example", qtype=16))
    forward_tunnel = analyze_dns_candidates(tunnel_rows).candidates
    reverse_tunnel = analyze_dns_candidates(list(reversed(tunnel_rows))).candidates
    assert forward_tunnel == reverse_tunnel
    candidate = next(item for item in forward_tunnel if item.detector == "dns_tunneling_heuristic")
    assert candidate.evidence_ids == tuple(f"EV-{i:06d}" for i in range(1, 101))


def test_nested_short_labels_do_not_fake_a_long_encoded_label() -> None:
    rows = [
        _row(
            index + 1,
            f"{'.'.join(['a'] * 11)}.{index % 24:02d}.tunnel.example",
            qtype=16,
        )
        for index in range(501)
    ]
    result = analyze_dns_candidates(rows)
    assert not any(item.detector == "dns_tunneling_heuristic" for item in result.candidates)


def test_analysis_record_group_and_candidate_caps_are_reported(monkeypatch) -> None:
    rows = []
    evidence_index = 1
    for source, suffix in (("192.0.2.10", "tunnel.example"), ("192.0.2.11", "other.example")):
        for index in range(24):
            rows.append(_row(evidence_index, f"{'a' * 31}{index:02d}.{suffix}", source=source, qtype=16))
            evidence_index += 1
    monkeypatch.setattr(dns_analysis, "MAX_DNS_GROUPS", 1)
    monkeypatch.setattr(dns_analysis, "MAX_DNS_CANDIDATES", 1)
    capped = analyze_dns_candidates(rows)
    assert capped.truncated is True
    assert len(capped.candidates) <= 1

    monkeypatch.setattr(dns_analysis, "MAX_DNS_ANALYZED_RECORDS", 1)
    record_capped = analyze_dns_candidates(rows)
    assert record_capped.records_examined == 1
    assert record_capped.truncated is True
