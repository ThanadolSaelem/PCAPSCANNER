"""Flow intelligence, jitter-tolerant beaconing, exfiltration asymmetry, port anomalies & chart analytics."""
from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Literal

try:
    import numpy as np  # type: ignore[import-not-found]
except ImportError:
    np = None  # type: ignore[assignment]


def _pure_diff(values: list[float]) -> list[float]:
    return [values[i + 1] - values[i] for i in range(len(values) - 1)]


def _pure_mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _pure_std(values: list[float]) -> float:
    if not values:
        return 0.0
    m = _pure_mean(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / len(values))


def _pure_histogram(values: list[float], n_bins: int) -> tuple[list[int], list[float]]:
    n_bins = max(1, int(n_bins))
    if not values:
        return [0] * n_bins, [float(i) for i in range(n_bins + 1)]
    lo = min(values)
    hi = max(values)
    if hi <= lo:
        edges = [lo + (i / n_bins) for i in range(n_bins + 1)]
        counts = [len(values)] + [0] * (n_bins - 1)
        return counts, edges
    span = hi - lo
    step = span / n_bins
    edges = [lo + i * step for i in range(n_bins)] + [hi]
    counts = [0] * n_bins
    for v in values:
        if v >= hi:
            idx = n_bins - 1
        else:
            idx = min(n_bins - 1, max(0, int((v - lo) / step)))
        counts[idx] += 1
    return counts, edges


INFRA_ALLOWLIST = frozenset(
    {
        "1.1.1.1", "1.0.0.1",
        "8.8.8.8", "8.8.4.4",
        "208.67.222.222", "208.67.220.220",
        "9.9.9.9", "149.112.112.112",
        "168.95.1.1", "168.95.192.1",
        "129.6.15.28", "129.6.15.29",
        "132.163.97.1", "132.163.96.1",
    }
)

BENIGN_PERIODIC_PROTOS = frozenset({"icmp", "ntp", "ssdp", "mdns", "igmp"})

BENIGN_SERVICE_PORTS: dict[str, float] = {
    "53": 0.15,
    "123": 0.15,
    "443": 0.15,
    "80": 0.3,
    "993": 0.15,
    "995": 0.15,
    "5223": 0.15,
    "5228": 0.15,
    "1883": 0.2,
    "8883": 0.2,
    "5060": 0.2,
    "5061": 0.2,
    "5353": 0.15,
}

KNOWN_SERVICES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 8080: "http-alt", 8443: "https-alt",
}

C2_COMMON_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337}
ASYMMETRY_MIN_BYTES = 1_000_000
ASYMMETRY_RATIO_THRESHOLD = 10.0
HIGH_PORT_THRESHOLD = 10_000


def is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value).strip())
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_global
    except (ValueError, TypeError):
        return False


def periodicity_score(ts: list[float]) -> dict[str, Any]:
    if not ts or len(ts) < 3:
        return {"count": len(ts), "mean_gap": None, "std_gap": None, "cv": None, "entropy": None, "score": 0.0}
    if np is not None:
        gaps_arr = np.diff(ts)
        if len(gaps_arr) == 0:
            return {"count": len(ts), "mean_gap": 0.0, "std_gap": 0.0, "cv": 0.0, "entropy": 0.0, "score": 0.0}
        mean_gap = float(np.mean(gaps_arr))
        std_gap = float(np.std(gaps_arr))
        n_bins = min(20, max(5, int(len(gaps_arr) / 3)))
        bins = [int(x) for x in np.histogram(gaps_arr, bins=n_bins)[0]]
    else:
        gaps = _pure_diff(ts)
        if not gaps:
            return {"count": len(ts), "mean_gap": 0.0, "std_gap": 0.0, "cv": 0.0, "entropy": 0.0, "score": 0.0}
        mean_gap = _pure_mean(gaps)
        std_gap = _pure_std(gaps)
        n_bins = min(20, max(5, int(len(gaps) / 3)))
        bins, _ = _pure_histogram(gaps, n_bins)

    cv = float(std_gap / mean_gap) if mean_gap > 0 else None
    bin_sum = sum(bins)
    probs = [b / bin_sum for b in bins if b > 0] if bin_sum > 0 else [1.0]
    entropy = float(-sum(p * math.log2(p) for p in probs if p > 0))
    score = (1.0 - min(cv if cv is not None else 1.0, 1.0)) * 0.6 + (1.0 - min(entropy / 4.0, 1.0)) * 0.4
    score *= min(len(ts) / 20.0, 1.0) * 0.7 + 0.3
    return {
        "count": len(ts),
        "mean_gap": round(mean_gap, 4),
        "std_gap": round(std_gap, 4),
        "cv": round(cv, 4) if cv is not None else None,
        "entropy": round(entropy, 4),
        "score": float(score),
    }


def jitter_score(ts: list[float]) -> dict[str, Any]:
    if not ts or len(ts) < 5:
        return {"jitter_score": 0.0, "dominant_interval": None, "jitter_pct": None, "consistent_ratio": None}
    gaps_list = _pure_diff(ts)
    if not gaps_list or max(gaps_list) == 0:
        return {"jitter_score": 0.0, "dominant_interval": 0.0, "jitter_pct": 0.0, "consistent_ratio": 0.0}
    n_bins = min(50, max(10, len(gaps_list) // 3))
    if np is not None:
        gaps_arr = np.asarray(gaps_list, dtype=float)
        counts_arr, edges_arr = np.histogram(gaps_arr, bins=n_bins)
        peak_bin = int(np.argmax(counts_arr))
        dominant_interval = float((edges_arr[peak_bin] + edges_arr[peak_bin + 1]) / 2.0)
    else:
        counts, edges = _pure_histogram(gaps_list, n_bins)
        peak_bin = max(range(len(counts)), key=lambda i: counts[i])
        dominant_interval = float((edges[peak_bin] + edges[peak_bin + 1]) / 2.0)
    if dominant_interval <= 0:
        return {"jitter_score": 0.0, "dominant_interval": 0.0, "jitter_pct": 0.0, "consistent_ratio": 0.0}
    tol = dominant_interval * 0.2
    lo, hi = dominant_interval - tol, dominant_interval + tol
    consistent_gaps = [g for g in gaps_list if lo <= g <= hi]
    consistent_ratio = len(consistent_gaps) / len(gaps_list)
    jitter_pct = (_pure_std(consistent_gaps) / dominant_interval * 100.0) if len(consistent_gaps) > 1 else 0.0
    score = consistent_ratio * 0.7 + (1.0 - min(jitter_pct / 30.0, 1.0)) * 0.3
    score *= min(len(ts) / 20.0, 1.0) * 0.7 + 0.3
    return {
        "jitter_score": float(score),
        "dominant_interval": round(dominant_interval, 2),
        "jitter_pct": round(jitter_pct, 1),
        "consistent_ratio": round(consistent_ratio, 3),
    }


def rank_beaconing(flows: list[dict[str, Any]], top_n: int = 20) -> list[dict[str, Any]]:
    """Score and rank flows by jitter-tolerant periodicity with FP reduction multipliers."""
    rows: list[dict[str, Any]] = []
    for f in flows:
        raw_times = f.get("pkt_times") or f.get("times") or []
        ts = sorted(float(t) for t in raw_times if t is not None and math.isfinite(float(t)))
        if len(ts) < 4:
            continue
        stats = periodicity_score(ts)
        jitter = jitter_score(ts)
        final_score = max(float(stats["score"]), float(jitter["jitter_score"]))

        dst = str(f.get("dst", "") or "")
        src = str(f.get("src", "") or "")
        proto = str(f.get("proto") or f.get("protocol") or "").lower()
        dport = str(f.get("dport", f.get("dst_port", "")) or "")

        if dport in BENIGN_SERVICE_PORTS:
            final_score *= BENIGN_SERVICE_PORTS[dport]
        if dst in INFRA_ALLOWLIST or src in INFRA_ALLOWLIST:
            final_score *= 0.1
        if proto in BENIGN_PERIODIC_PROTOS:
            final_score *= 0.15

        pkt_lens = f.get("pkt_lens") or []
        count_val = int(f.get("count", f.get("packets", len(ts))) or len(ts))
        if pkt_lens and count_val > 200:
            avg_pkt_size = sum(pkt_lens) / len(pkt_lens)
            if avg_pkt_size > 500:
                final_score *= 0.25
        elif count_val > 200 and f.get("bytes"):
            avg_pkt_size = float(f["bytes"]) / max(1, count_val)
            if avg_pkt_size > 500:
                final_score *= 0.25

        rows.append(
            {
                "src": src,
                "dst": dst,
                "sport": f.get("sport", f.get("src_port")),
                "dport": dport,
                "proto": f.get("proto", f.get("protocol")),
                "pkts": count_val,
                "mean_gap": stats["mean_gap"],
                "std_gap": stats["std_gap"],
                "cv": stats["cv"],
                "entropy": stats["entropy"],
                "score": round(final_score, 4),
                "dominant_interval": jitter["dominant_interval"],
                "jitter_pct": jitter["jitter_pct"],
                "consistent_ratio": jitter["consistent_ratio"],
            }
        )
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows[:top_n]


@dataclass
class FlowAsymmetryResult:
    src: str
    dst: str
    outbound_bytes: int
    inbound_bytes: int
    ratio: float
    total_packets: int
    score: float
    is_suspicious: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "outbound_bytes": self.outbound_bytes,
            "inbound_bytes": self.inbound_bytes,
            "ratio": round(self.ratio, 2),
            "total_packets": self.total_packets,
            "score": round(self.score, 3),
            "is_suspicious": self.is_suspicious,
            "reason": self.reason,
        }


@dataclass
class PortAnomalyResult:
    src: str
    dst: str
    port: int
    proto: str
    anomaly_type: str
    expected_service: str
    score: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "port": self.port,
            "proto": self.proto,
            "anomaly_type": self.anomaly_type,
            "expected_service": self.expected_service,
            "score": round(self.score, 3),
            "reason": self.reason,
        }


def detect_flow_asymmetry(flows: list[dict[str, Any]]) -> list[FlowAsymmetryResult]:
    pair_stats: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"outbound_bytes": 0, "inbound_bytes": 0, "total_packets": 0}
    )
    for flow in flows:
        src = str(flow.get("src", "") or "")
        dst = str(flow.get("dst", "") or "")
        if not src or not dst:
            continue
        pkt_lens = flow.get("pkt_lens") or []
        count = int(flow.get("count", flow.get("packets", 0)) or 0)
        flow_bytes = flow.get("bytes")
        total_bytes = int(flow_bytes) if flow_bytes else (sum(pkt_lens) if pkt_lens else count * 800)
        pair_stats[(src, dst)]["outbound_bytes"] += total_bytes
        pair_stats[(src, dst)]["total_packets"] += count
        pair_stats[(dst, src)]["inbound_bytes"] += total_bytes

    results: list[FlowAsymmetryResult] = []
    checked: set[tuple[str, str]] = set()
    for (src, dst), stats in list(pair_stats.items()):
        if (src, dst) in checked or (dst, src) in checked:
            continue
        checked.add((src, dst))
        outbound = stats["outbound_bytes"]
        inbound = pair_stats[(dst, src)].get("outbound_bytes", 0)
        total_packets = stats["total_packets"] + pair_stats[(dst, src)].get("total_packets", 0)
        if outbound < ASYMMETRY_MIN_BYTES:
            continue
        ratio = outbound / max(inbound, 1)
        score = 0.0
        reasons: list[str] = []
        if ratio >= 100:
            score += 0.5
            reasons.append(f"extreme ratio ({ratio:.0f}:1)")
        elif ratio >= ASYMMETRY_RATIO_THRESHOLD:
            score += 0.3
            reasons.append(f"high ratio ({ratio:.1f}:1)")
        elif ratio >= 5:
            score += 0.15
            reasons.append(f"elevated ratio ({ratio:.1f}:1)")
        else:
            continue
        if outbound > 100_000_000:
            score += 0.3
            reasons.append(f"large volume ({outbound / 1_000_000:.1f} MB)")
        elif outbound > 10_000_000:
            score += 0.15
            reasons.append(f"notable volume ({outbound / 1_000_000:.1f} MB)")
        final_s = min(score, 1.0)
        results.append(
            FlowAsymmetryResult(
                src=src,
                dst=dst,
                outbound_bytes=outbound,
                inbound_bytes=inbound,
                ratio=ratio,
                total_packets=total_packets,
                score=final_s,
                is_suspicious=final_s >= 0.4,
                reason="; ".join(reasons),
            )
        )
    results.sort(key=lambda r: r.score, reverse=True)
    return results


def detect_port_anomalies(flows: list[dict[str, Any]]) -> list[PortAnomalyResult]:
    results: list[PortAnomalyResult] = []
    seen: set[tuple[str, str, int]] = set()
    for flow in flows:
        src = str(flow.get("src", "") or "")
        dst = str(flow.get("dst", "") or "")
        proto = str(flow.get("proto", flow.get("protocol", "")) or "").lower()
        try:
            dport = int(flow.get("dport", flow.get("dst_port", 0)) or 0)
            sport = int(flow.get("sport", flow.get("src_port", 0)) or 0)
        except (ValueError, TypeError):
            continue
        if not src or not dst or not dport:
            continue
        key = (dst, src, dport)
        if key in seen:
            continue
        seen.add(key)

        if dport in C2_COMMON_PORTS:
            results.append(
                PortAnomalyResult(
                    src=src, dst=dst, port=dport, proto=proto, anomaly_type="c2_port",
                    expected_service="n/a", score=0.7, reason=f"Port {dport} commonly used by C2 frameworks",
                )
            )
            continue
        count = int(flow.get("count", flow.get("packets", 0)) or 0)
        if sport > HIGH_PORT_THRESHOLD and dport > HIGH_PORT_THRESHOLD and count > 10:
            results.append(
                PortAnomalyResult(
                    src=src, dst=dst, port=dport, proto=proto, anomaly_type="high_port_pair",
                    expected_service="n/a", score=0.4, reason=f"High-port-to-high-port ({sport}->{dport}, {count} packets)",
                )
            )
        if dport in KNOWN_SERVICES:
            expected = KNOWN_SERVICES[dport]
            if dport == 53 and proto == "tcp" and count > 20:
                results.append(
                    PortAnomalyResult(
                        src=src, dst=dst, port=dport, proto=proto, anomaly_type="non_standard",
                        expected_service=expected, score=0.5, reason=f"TCP traffic on DNS port 53 ({count} packets) - possible DNS-over-TCP tunneling",
                    )
                )
            elif dport == 80 and proto == "udp":
                results.append(
                    PortAnomalyResult(
                        src=src, dst=dst, port=dport, proto=proto, anomaly_type="non_standard",
                        expected_service=expected, score=0.5, reason="UDP traffic on HTTP port 80 - unexpected protocol",
                    )
                )
    results.sort(key=lambda r: r.score, reverse=True)
    return results[:50]


def compute_flow_aggregates(
    flows: list[dict[str, Any]] | None,
    top_n: int = 10,
    weight: Literal["packets", "flows"] = "packets",
    exclude_private: bool = False,
) -> dict[str, Any]:
    src: Counter[str] = Counter()
    dst: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    protos: Counter[str] = Counter()

    for f in flows or []:
        n = int(f.get("count", f.get("packets", 0)) or 0) if weight == "packets" else 1
        s = f.get("src")
        d = f.get("dst")
        dp = f.get("dport", f.get("dst_port", "N/A"))
        dport = str(dp) if dp is not None else "N/A"
        proto = f.get("proto", f.get("protocol", "Unknown"))
        if s and (not exclude_private or is_public_ipv4(str(s))):
            src[str(s)] += n
        if d and (not exclude_private or is_public_ipv4(str(d))):
            dst[str(d)] += n
        if dport:
            ports[dport] += n
        if proto:
            protos[str(proto)] += n

    return {
        "top_src_ips": src.most_common(top_n),
        "top_dst_ips": dst.most_common(top_n),
        "top_dst_ports": ports.most_common(top_n),
        "top_protos": protos.most_common(top_n),
    }


def build_flow_analytics(
    flows_or_evidence: list[Any],
    *,
    packet_lengths: list[int] | None = None,
    inter_arrival_seconds: list[float] | None = None,
    heatmap_samples: list[tuple[float, str]] | None = None,
    dns_queries: list[str] | None = None,
    findings: list[Any] | None = None,
    duration_seconds: float | None = None,
    total_packets: int | None = None,
    total_bytes: int | None = None,
    **_extra: Any,
) -> dict[str, Any]:
    """Compute dashboard chart datasets (histograms, talkers, Sankey, topology graph, heatmap)."""
    flows: list[dict[str, Any]] = []
    inferred_dns: list[str] = list(dns_queries or [])
    inferred_hm: list[tuple[float, str]] = list(heatmap_samples or [])
    for item in flows_or_evidence or []:
        if isinstance(item, dict) and "kind" not in item:
            flows.append(item)
            continue
        kind = getattr(item, "kind", item.get("kind") if isinstance(item, dict) else None)
        attrs = getattr(item, "attributes", item.get("attributes") if isinstance(item, dict) else None) or {}
        if not isinstance(attrs, dict):
            continue
        if kind == "flow":
            flows.append(attrs)
            dst_ip = str(attrs.get("dst") or "")
            t0 = attrs.get("first_seen")
            if dst_ip and isinstance(t0, (int, float)):
                inferred_hm.append((float(t0), dst_ip))
        elif kind == "dns":
            q = str(attrs.get("query") or "").strip()
            if q:
                inferred_dns.append(q)
    dns_queries = inferred_dns
    if not heatmap_samples and inferred_hm:
        heatmap_samples = inferred_hm

    size_bins = [
        ("0-64", 0, 64),
        ("65-128", 65, 128),
        ("129-256", 129, 256),
        ("257-512", 257, 512),
        ("513-1024", 513, 1024),
        ("1025-1500", 1025, 1500),
        ("1500+", 1501, 10**9),
    ]
    size_counts = {label: 0 for label, _, _ in size_bins}
    for length in packet_lengths or []:
        for label, lo, hi in size_bins:
            if lo <= length <= hi:
                size_counts[label] += 1
                break
    if not packet_lengths:
        for f in flows:
            cnt = int(f.get("count", f.get("packets", 0)) or 0)
            avg_l = int(float(f.get("bytes", 0) or 0) / max(1, cnt)) if cnt else 0
            if avg_l > 0:
                for label, lo, hi in size_bins:
                    if lo <= avg_l <= hi:
                        size_counts[label] += cnt
                        break

    iat_bins = [
        ("<1ms", 0.0, 0.001),
        ("1-10ms", 0.001, 0.01),
        ("10-100ms", 0.01, 0.1),
        ("0.1-1s", 0.1, 1.0),
        ("1-10s", 1.0, 10.0),
        (">10s", 10.0, float("inf")),
    ]
    iat_counts = {label: 0 for label, _, _ in iat_bins}
    iat_values = list(inter_arrival_seconds or [])
    if not iat_values:
        for f in flows:
            raw_iv = f.get("intervals") or []
            if isinstance(raw_iv, str):
                parts = [p.strip() for p in raw_iv.split(",") if p.strip()]
                parsed_iv: list[float] = []
                for p in parts:
                    try:
                        parsed_iv.append(float(p))
                    except ValueError:
                        pass
                raw_iv = parsed_iv
            for iv in raw_iv:
                if isinstance(iv, (int, float)) and math.isfinite(iv) and iv >= 0:
                    iat_values.append(float(iv))
    for iv in iat_values:
        for label, lo, hi in iat_bins:
            if lo <= iv < hi or (hi == float("inf") and iv >= lo):
                iat_counts[label] += 1
                break

    agg = compute_flow_aggregates(flows, top_n=10, weight="packets", exclude_private=False)
    agg_public = compute_flow_aggregates(flows, top_n=10, weight="packets", exclude_private=True)
    top_domains = Counter(dns_queries or []).most_common(10)

    pair_bytes: Counter[tuple[str, str]] = Counter()
    pair_pkts: Counter[tuple[str, str]] = Counter()
    pair_proto: dict[tuple[str, str], str] = {}
    node_bytes: Counter[str] = Counter()
    for f in flows:
        src = str(f.get("src", "") or "")
        dst = str(f.get("dst", "") or "")
        if not src or not dst:
            continue
        b = int(f.get("bytes", 0) or 0)
        p = int(f.get("count", f.get("packets", 0)) or 0)
        dp = f.get("dport", f.get("dst_port"))
        pr = str(f.get("proto", f.get("protocol", "IP")))
        svc = f"{pr}:{dp}" if dp is not None else pr
        pair_bytes[(src, dst)] += b
        pair_pkts[(src, dst)] += p
        pair_proto[(src, dst)] = svc
        node_bytes[src] += b
        node_bytes[dst] += b

    top_edges = pair_bytes.most_common(24)
    sankey_links = [
        {
            "source": s,
            "target": d,
            "service": pair_proto.get((s, d), "IP"),
            "bytes": b,
            "packets": pair_pkts[(s, d)],
        }
        for (s, d), b in top_edges
    ]

    graph_node_ids = [ip for ip, _ in node_bytes.most_common(25)]
    graph_set = set(graph_node_ids)
    graph_nodes = [
        {
            "id": ip,
            "bytes": node_bytes[ip],
            "is_public": is_public_ipv4(ip),
        }
        for ip in graph_node_ids
    ]
    graph_edges = [
        {
            "source": s,
            "target": d,
            "bytes": b,
            "packets": pair_pkts[(s, d)],
            "label": pair_proto.get((s, d), ""),
        }
        for (s, d), b in top_edges
        if s in graph_set and d in graph_set
    ]

    heatmap_rows: list[dict[str, Any]] = []
    if heatmap_samples:
        top_hm_dsts = [ip for ip, _ in agg["top_dst_ips"][:8]]
        top_hm_set = set(top_hm_dsts)
        ts_vals = [t for t, _ in heatmap_samples]
        t_min, t_max = min(ts_vals), max(ts_vals)
        span = max(1e-6, t_max - t_min)
        n_slices = 12
        matrix: dict[str, list[int]] = {dst_ip: [0] * n_slices for dst_ip in top_hm_dsts}
        for ts_v, dst_ip in heatmap_samples:
            if dst_ip in top_hm_set:
                slot = min(n_slices - 1, max(0, int(((ts_v - t_min) / span) * (n_slices - 1))))
                matrix[dst_ip][slot] += 1
        heatmap_rows = [{"ip": dst_ip, "buckets": matrix[dst_ip]} for dst_ip in top_hm_dsts]

    return {
        "packet_size_histogram": [{"bucket": label, "count": size_counts[label]} for label, _, _ in size_bins],
        "iat_histogram": [{"bucket": label, "count": iat_counts[label]} for label, _, _ in iat_bins],
        "top_src_ips": [{"ip": ip, "packets": c} for ip, c in agg["top_src_ips"]],
        "top_dst_ips": [{"ip": ip, "packets": c} for ip, c in agg["top_dst_ips"]],
        "top_public_dst_ips": [{"ip": ip, "packets": c} for ip, c in agg_public["top_dst_ips"]],
        "top_dst_ports": [{"port": port, "packets": c} for port, c in agg["top_dst_ports"]],
        "top_protos": [{"protocol": proto, "packets": c} for proto, c in agg["top_protos"]],
        "top_domains": [{"domain": dom, "count": c} for dom, c in top_domains],
        "sankey_links": sankey_links,
        "network_graph": {"nodes": graph_nodes, "edges": graph_edges},
        "traffic_heatmap": heatmap_rows,
    }


__all__ = [
    "ASYMMETRY_MIN_BYTES",
    "ASYMMETRY_RATIO_THRESHOLD",
    "BENIGN_PERIODIC_PROTOS",
    "BENIGN_SERVICE_PORTS",
    "C2_COMMON_PORTS",
    "FlowAsymmetryResult",
    "INFRA_ALLOWLIST",
    "KNOWN_SERVICES",
    "PortAnomalyResult",
    "build_flow_analytics",
    "compute_flow_aggregates",
    "detect_flow_asymmetry",
    "detect_port_anomalies",
    "is_public_ipv4",
    "jitter_score",
    "periodicity_score",
    "rank_beaconing",
]
