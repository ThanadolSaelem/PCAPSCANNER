"""Bounded DNS anomaly heuristics adapted from PCAP-Hunter's DNS analyzer.

This module ports selected DGA/tunneling scoring ideas from
ninedter/pcap-hunter (MIT; see THIRD_PARTY_NOTICES.md) into a dependency-free,
metadata-only contract. Results are low-confidence candidates, never verdicts.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable


MAX_DNS_ANALYZED_RECORDS = 5_000
MAX_DNS_GROUPS = 256
MAX_DNS_CANDIDATES = 50
MAX_DNS_EVIDENCE_IDS = 100
MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
DGA_SCORE_THRESHOLD = 0.5
TUNNEL_SCORE_THRESHOLD = 0.5
TUNNEL_MIN_UNIQUE_SUBDOMAINS = 20

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9-]+$")
_MULTI_LABEL_PUBLIC_SUFFIXES = frozenset(
    {
        "ac.uk", "co.uk", "gov.uk", "org.uk", "com.au", "net.au", "org.au",
        "co.jp", "ne.jp", "or.jp", "com.br", "net.br", "com.cn", "net.cn",
        "com.hk", "com.sg", "co.nz", "co.kr", "co.in", "com.mx", "com.tr",
    }
)
_ENTROPY_WHITELIST_SUFFIXES = frozenset(
    {
        "cloudfront.net", "amazonaws.com", "akamaiedge.net", "akadns.net",
        "googleusercontent.com", "1e100.net", "cloudflare.com",
    }
)
_BENIGN_SERVICE_LABELS = frozenset(
    {"www", "mail", "smtp", "imap", "pop", "api", "cdn", "static", "autodiscover", "selector1", "selector2"}
)


@dataclass(frozen=True)
class DNSObservation:
    query: str
    evidence_id: str
    source: str | None = None
    response_code: int | None = None
    qtype: int | None = None


@dataclass(frozen=True)
class DNSCandidate:
    detector: str
    title: str
    summary: str
    evidence_ids: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class DNSAnalysisResult:
    candidates: tuple[DNSCandidate, ...]
    truncated: bool
    records_examined: int


@dataclass
class _TunnelGroup:
    evidence_ids: list[str] = field(default_factory=list)
    subdomains: set[str] = field(default_factory=set)
    query_count: int = 0
    txt_count: int = 0


def normalize_domain(value: str) -> str | None:
    """Accept only bounded ASCII DNS names suitable for local heuristics."""
    if not isinstance(value, str) or not value or len(value) > MAX_DOMAIN_LENGTH:
        return None
    domain = value.rstrip(".").lower()
    if not domain or len(domain) > MAX_DOMAIN_LENGTH or not domain.isascii():
        return None
    labels = domain.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > MAX_LABEL_LENGTH
        or not _DOMAIN_LABEL_RE.fullmatch(label)
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        return None
    if all(label.isdigit() for label in labels):
        return None
    return domain


def _registrable_parts(domain: str) -> tuple[str, str] | None:
    """Return (registrable label, subdomain) using a conservative suffix list."""
    labels = domain.split(".")
    if len(labels) < 2:
        return None
    suffix2 = ".".join(labels[-2:])
    index = len(labels) - 3 if suffix2 in _MULTI_LABEL_PUBLIC_SUFFIXES else len(labels) - 2
    if index < 0:
        return None
    root = ".".join(labels[index:])
    subdomain = ".".join(labels[:index])
    return root, subdomain


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _dga_score(label: str, domain: str) -> float:
    """Adapt upstream entropy/character-ratio signals as a weak candidate score."""
    if len(label) < 8 or label in _BENIGN_SERVICE_LABELS:
        return 0.0
    alpha = [char for char in label if "a" <= char <= "z"]
    consonants = sum(char not in "aeiou" for char in alpha)
    consonant_ratio = consonants / len(alpha) if alpha else 0.0
    digit_ratio = sum(char.isdigit() for char in label) / len(label)
    entropy = _entropy(label)

    score = 0.0
    if entropy > 4.0:
        score += 0.3
    elif entropy > 3.5:
        score += 0.15
    if consonant_ratio > 0.75:
        score += 0.2
    elif alpha and consonant_ratio < 0.35 and len(label) > 8:
        score += 0.1
    if digit_ratio > 0.3:
        score += 0.25
    elif digit_ratio > 0.15:
        score += 0.1
    if len(label) > 15:
        score += 0.15
    elif len(label) > 12:
        score += 0.05
    if alpha and consonant_ratio == 1.0 and len(label) > 5:
        score += 0.15
    if any(domain == suffix or domain.endswith(f".{suffix}") for suffix in _ENTROPY_WHITELIST_SUFFIXES):
        score *= 0.3
    return min(score, 1.0)


def _candidate_evidence(ids: list[str]) -> tuple[str, ...]:
    # Evidence IDs are already validated by the target EvidenceBundle builder.
    return tuple(sorted(set(ids))[:MAX_DNS_EVIDENCE_IDS])


def _retain_bounded_evidence_id(ids: list[str], evidence_id: str) -> None:
    """Keep the lexicographically smallest bounded ID set, independent of row order."""
    if evidence_id in ids:
        return
    if len(ids) < MAX_DNS_EVIDENCE_IDS:
        ids.append(evidence_id)
        ids.sort()
        return
    if ids and evidence_id < ids[-1]:
        ids[-1] = evidence_id
        ids.sort()


def analyze_dns_candidates(observations: Iterable[DNSObservation]) -> DNSAnalysisResult:
    """Analyze only bounded request metadata and return sanitized, cited candidates."""
    rows: list[DNSObservation] = []
    truncated = False
    for observation in observations:
        if len(rows) >= MAX_DNS_ANALYZED_RECORDS:
            truncated = True
            break
        rows.append(observation)

    request_rows: list[tuple[DNSObservation, str, str, str]] = []
    for observation in rows:
        if observation.response_code is not None:
            continue
        domain = normalize_domain(observation.query)
        if domain is None:
            continue
        parts = _registrable_parts(domain)
        if parts is None:
            continue
        root, subdomain = parts
        request_rows.append((observation, domain, root, subdomain))

    # Aggregate by normalized query, not source address. The emitted finding does
    # not contain the query/domain; it links to the local DNS evidence rows only.
    dga_rows: dict[str, list[str]] = {}
    dga_scores: dict[str, float] = {}
    tunnel_groups: dict[tuple[str, str], _TunnelGroup] = {}

    for observation, domain, root, subdomain in request_rows:
        source = observation.source or ""
        parts = _registrable_parts(domain)
        if parts is None:
            continue
        registrable_label = root.split(".", 1)[0]
        analyzed_label = subdomain.rsplit(".", 1)[-1] if subdomain else registrable_label
        score = _dga_score(analyzed_label, domain)
        if score >= DGA_SCORE_THRESHOLD:
            if domain not in dga_rows:
                if len(dga_rows) >= MAX_DNS_CANDIDATES:
                    truncated = True
                else:
                    dga_rows[domain] = []
                    dga_scores[domain] = score
            if domain in dga_rows:
                _retain_bounded_evidence_id(dga_rows[domain], observation.evidence_id)

        if not source or len(source) > 64 or not subdomain:
            continue
        group_key = (source, root)
        group = tunnel_groups.get(group_key)
        if group is None:
            if len(tunnel_groups) >= MAX_DNS_GROUPS:
                truncated = True
                continue
            group = _TunnelGroup()
            tunnel_groups[group_key] = group
        group.query_count += 1
        group.subdomains.add(subdomain)
        if observation.qtype == 16:
            group.txt_count += 1
        _retain_bounded_evidence_id(group.evidence_ids, observation.evidence_id)

    candidates: list[DNSCandidate] = []
    dga_limits = (
        "Character-distribution scores are weak heuristics and are not a malware verdict.",
        "Legitimate generated identifiers, CDN labels, tracking domains, and software updates may look random.",
        "Only retained DNS query metadata was evaluated; a no-finding result does not establish benignness.",
    )
    tunnel_limits = (
        "DNS tunneling indicators are low-confidence heuristics, not proof of exfiltration or compromise.",
        "The public-suffix grouping uses a small fixed list and may group some multi-label domains imperfectly.",
        "Only retained query names and query types were evaluated; answer IPs and TTLs are not inferred.",
    )

    for domain in sorted(dga_rows):
        ids = _candidate_evidence(dga_rows[domain])
        if ids:
            candidates.append(
                DNSCandidate(
                    detector="dns_dga_heuristic",
                    title="DGA-like DNS label candidate",
                    summary=(
                        "A retained DNS query label exceeded the local character-distribution heuristic "
                        f"threshold (score {dga_scores[domain]:.2f}); domain and label values are in cited local evidence."
                    ),
                    evidence_ids=ids,
                    limitations=dga_limits,
                )
            )

    for (source, root), group in sorted(tunnel_groups.items()):
        unique_subdomains = len(group.subdomains)
        if unique_subdomains < TUNNEL_MIN_UNIQUE_SUBDOMAINS or not group.subdomains:
            continue
        # Score the longest individual label within each unique subdomain name.
        # Dots between short labels must not inflate the encoded-label signal.
        label_lengths = [max(len(label) for label in value.split(".")) for value in group.subdomains]
        average_length = sum(label_lengths) / unique_subdomains
        max_length = max(label_lengths)
        txt_ratio = group.txt_count / group.query_count if group.query_count else 0.0
        score = 0.0
        if unique_subdomains > 100:
            score += 0.3
        elif unique_subdomains > 50:
            score += 0.2
        else:
            score += 0.1
        if average_length > 30:
            score += 0.25
        elif average_length > 20:
            score += 0.15
        if max_length > 50:
            score += 0.15
        if txt_ratio > 0.5:
            score += 0.2
        elif txt_ratio > 0.2:
            score += 0.1
        if group.query_count > 500:
            score += 0.1
        if score < TUNNEL_SCORE_THRESHOLD:
            continue
        ids = _candidate_evidence(group.evidence_ids)
        if ids:
            candidates.append(
                DNSCandidate(
                    detector="dns_tunneling_heuristic",
                    title="DNS tunneling-pattern candidate",
                    summary=(
                        f"A retained query group had {unique_subdomains} distinct subdomain names, "
                        f"{group.query_count} requests, average label length {average_length:.1f}, "
                        f"and TXT ratio {txt_ratio:.2f} (heuristic score {min(score, 1.0):.2f}). "
                        "Identifiers are available only in cited local evidence."
                    ),
                    evidence_ids=ids,
                    limitations=tunnel_limits,
                )
            )

    if len(candidates) > MAX_DNS_CANDIDATES:
        candidates = candidates[:MAX_DNS_CANDIDATES]
        truncated = True
    return DNSAnalysisResult(
        candidates=tuple(candidates),
        truncated=truncated,
        records_examined=len(rows),
    )
