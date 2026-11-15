"""Tier-1 fast calibrated classifier, Jev compact flow JSONL, and Pre-AI context compactor.

This module sits between deterministic PCAP/CSV parsing and the optional Big AI
Narrator:
  1. It extracts compact L2-L7 flow states compatible with OpenJev / Trainer-Pipeline
     evaluation and RL+LoRA+GRPO calibration workflows (`triage.jsonl`).
  2. It runs a fast calibrated classifier (deterministic multi-layer scoring baseline
     with optional local OpenJev HTTP classifier integration) to score each evidence
     item into traffic classes with calibrated confidence p in [0, 1] and an
     entropy/perplexity uncertainty proxy.
  3. Before invoking the Big AI Narrator (`providers.py`), `pack_evidence_for_ai`
     filters redundant high-confidence Benign flows and packs high-signal escalated
     findings & evidence within the LLM's byte/token budget so user-connected
     LLMs avoid out-of-context (`budget_exceeded`) failures.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen

from .etbert_bridge import score_with_etbert_http


TRAFFIC_CLASSES: tuple[str, ...] = (
    "Benign",
    "ARP_Spoofing",
    "Port_Scan_Recon",
    "DoS_Flood",
    "DNS_Tunnel_DGA",
    "C2_Beaconing",
    "TLS_Anomaly",
    "Web_Injection_Or_Tunnel",
    "WiFi_Attack",
    "Protocol_Tunnel",
)

OPENJEV_CLASS_CRITERIA: list[dict[str, str]] = [
    {"label": "Benign", "description": "Normal, non-malicious background traffic."},
    {"label": "ARP_Spoofing", "description": "Layer-2 MAC/IP conflicts or spoofed ARP replies."},
    {"label": "Port_Scan_Recon", "description": "Host/port enumeration, SYN/NULL/Xmas/ARP sweep probing."},
    {"label": "DoS_Flood", "description": "High-rate SYN, RST, ACK, UDP, or ICMP flooding/amplification."},
    {"label": "DNS_Tunnel_DGA", "description": "High-entropy DGA labels, TXT/NULL tunneling, or NXDOMAIN bursts."},
    {"label": "C2_Beaconing", "description": "Periodic low-jitter callbacks or sustained C2 channel patterns."},
    {"label": "TLS_Anomaly", "description": "Repeated ClientHello handshakes, downgrade, or suspicious TLS flows."},
    {"label": "Web_Injection_Or_Tunnel", "description": "XSS, SQLi, CRLF, path/shell markers, or anomalous HTTP datagrams."},
    {"label": "WiFi_Attack", "description": "802.11 management frame attacks such as deauth or disassociation bursts."},
    {"label": "Protocol_Tunnel", "description": "Data-bearing ICMP/Telnet/non-standard port tunnels or SSH brute/tunnel activity."},
]

SEVERITY_RANK: dict[str, int] = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class TriageDecision:
    evidence_id: str
    kind: str
    predicted_class: str
    confidence: float
    uncertainty_ppl: float
    decision: str  # "fast_benign" | "escalate_attack" | "escalate_uncertain"
    compact_text: str
    signals: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    etbert_label: str | None = None
    etbert_confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ClassStat:
    label: str
    count: int
    avg_confidence: float
    escalated: int


@dataclass(frozen=True)
class TriageReport:
    enabled: bool
    model: str
    mode: str
    total_evaluated: int
    benign_filtered: int
    escalated_count: int
    uncertain_count: int
    reduction_ratio: float
    mean_confidence: float
    mean_ppl: float
    top_classes: list[ClassStat]
    escalated_evidence_ids: list[str]
    decisions: list[TriageDecision] = field(default_factory=list)
    etbert_scored_count: int = 0

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "model": self.model,
            "mode": self.mode,
            "total_evaluated": self.total_evaluated,
            "benign_filtered": self.benign_filtered,
            "escalated_count": self.escalated_count,
            "uncertain_count": self.uncertain_count,
            "reduction_ratio": round(self.reduction_ratio, 4),
            "mean_confidence": round(self.mean_confidence, 4),
            "mean_ppl": round(self.mean_ppl, 4),
            "etbert_scored_count": self.etbert_scored_count,
            "top_classes": [asdict(item) for item in self.top_classes],
            "escalated_evidence_ids": list(self.escalated_evidence_ids[:200]),
        }


def _attr_float(attrs: dict[str, Any], key: str, default: float = 0.0) -> float:
    raw = attrs.get(key)
    if isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(float(raw)):
        return float(raw)
    if isinstance(raw, str):
        try:
            val = float(raw)
            return val if math.isfinite(val) else default
        except ValueError:
            return default
    return default


def _attr_int(attrs: dict[str, Any], key: str, default: int = 0) -> int:
    raw = attrs.get(key)
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    if isinstance(raw, float) and math.isfinite(raw):
        return int(raw)
    if isinstance(raw, str) and raw.strip().lstrip("-").isdigit():
        return int(raw.strip())
    return default


def _attr_str(attrs: dict[str, Any], key: str, default: str = "") -> str:
    raw = attrs.get(key)
    return str(raw) if raw is not None else default


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _softmax(logits: dict[str, float]) -> dict[str, float]:
    max_logit = max(logits.values())
    exps = {k: math.exp(min(40.0, max(-40.0, v - max_logit))) for k, v in logits.items()}
    total = sum(exps.values()) or 1.0
    return {k: v / total for k, v in exps.items()}


def _shannon_ppl(probs: dict[str, float]) -> float:
    entropy = 0.0
    for p in probs.values():
        if p > 1e-12:
            entropy -= p * math.log2(p)
    return round(2.0 ** entropy, 4)


def _compact_flow_state(
    evidence: Any,
    finding_hints: Sequence[Any],
    etbert_result: dict[str, Any] | None = None,
) -> str:
    """Format an Evidence object into a compact token-efficient L2-L7 + ET-BERT state string."""
    ev_id = str(getattr(evidence, "evidence_id", evidence.get("evidence_id") if isinstance(evidence, dict) else ""))
    kind = str(getattr(evidence, "kind", evidence.get("kind") if isinstance(evidence, dict) else "flow"))
    attrs = getattr(evidence, "attributes", None)
    if attrs is None and isinstance(evidence, dict):
        attrs = evidence.get("attributes", {})
    attrs = dict(attrs or {})

    proto = _attr_str(attrs, "protocol", kind.upper())
    src = _attr_str(attrs, "src", _attr_str(attrs, "src_ip", "?"))
    dst = _attr_str(attrs, "dst", _attr_str(attrs, "dst_ip", "?"))
    sp = attrs.get("src_port")
    dp = attrs.get("dst_port")
    src_ep = f"{src}:{sp}" if sp is not None else src
    dst_ep = f"{dst}:{dp}" if dp is not None else dst
    pkts = _attr_int(attrs, "packets", len(getattr(evidence, "packet_refs", []) or []))
    nbytes = _attr_int(attrs, "bytes", 0)

    extras: list[str] = []
    if _attr_float(attrs, "duration", 0.0) > 0:
        extras.append(f"dur={_attr_float(attrs, 'duration'):.3f}")
    if _attr_float(attrs, "pkt_rate", 0.0) > 0:
        extras.append(f"rate={_attr_float(attrs, 'pkt_rate'):.1f}")
    if "rev_packets" in attrs or "rev_bytes" in attrs:
        extras.append(f"rev={_attr_int(attrs, 'rev_packets')}/{_attr_int(attrs, 'rev_bytes')}")
    if "io_byte_ratio" in attrs:
        extras.append(f"io={_attr_float(attrs, 'io_byte_ratio'):.2f}")

    # L3 / topology context
    if "ttl_min" in attrs:
        ttl_min = _attr_int(attrs, "ttl_min")
        ttl_max = _attr_int(attrs, "ttl_max", ttl_min)
        extras.append(f"ttl={ttl_min}" if ttl_min == ttl_max else f"ttl={ttl_min}-{ttl_max}")
    if _attr_int(attrs, "ttl_distinct_count", 0) > 1:
        extras.append(f"ttl_cnt={_attr_int(attrs, 'ttl_distinct_count')}")
    if _attr_int(attrs, "ip_frag_count", 0) > 0:
        extras.append(f"frags={_attr_int(attrs, 'ip_frag_count')}")
    if _attr_int(attrs, "same_src_dst_count", 0) > 0:
        extras.append(f"same_sd={_attr_int(attrs, 'same_src_dst_count')}")
    if _attr_int(attrs, "dst_unique_srcs", 0) > 1:
        extras.append(f"dst_fanin={_attr_int(attrs, 'dst_unique_srcs')}")
    if _attr_int(attrs, "src_unique_dst_ports", 0) > 1:
        extras.append(f"src_ports={_attr_int(attrs, 'src_unique_dst_ports')}")
    if _attr_int(attrs, "src_unique_dsts", 0) > 1:
        extras.append(f"src_dsts={_attr_int(attrs, 'src_unique_dsts')}")

    # L4 TCP flags & seq
    if "tcp_flags_mask" in attrs:
        extras.append(f"flags=0x{_attr_int(attrs, 'tcp_flags_mask'):02x}")
    for key, tag in (
        ("syn_count", "syn"),
        ("ack_count", "ack"),
        ("fin_count", "fin"),
        ("rst_count", "rst"),
        ("null_flag_count", "null_f"),
        ("xmas_flag_count", "xmas_f"),
        ("retrans_count", "retrans"),
        ("seq_jump_count", "seq_jmp"),
        ("data_len_sum", "dlen"),
    ):
        val = _attr_int(attrs, key, 0)
        if val > 0:
            extras.append(f"{tag}={val}")

    # ICMP
    if "icmp_type" in attrs or "icmp_code" in attrs:
        extras.append(f"icmp_tc={_attr_int(attrs, 'icmp_type', 0)}/{_attr_int(attrs, 'icmp_code', 0)}")
    if _attr_int(attrs, "icmp_data_len_sum", 0) > 0:
        extras.append(f"icmp_dlen={_attr_int(attrs, 'icmp_data_len_sum')}")

    # DNS
    if kind == "dns" or attrs.get("query"):
        q = _attr_str(attrs, "query")
        label = q.rstrip(".").split(".", 1)[0]
        extras.append(f"q_len={len(label)} q_ent={_entropy(label):.2f}")
        if "dns_qry_type" in attrs:
            extras.append(f"qtype={attrs['dns_qry_type']}")
        if "rcode" in attrs:
            extras.append(f"rcode={attrs['rcode']}")

    # ARP & ARP scans
    if kind == "arp" or attrs.get("arp_conflicts") or attrs.get("arp_scan_targets"):
        if "arp_conflicts" in attrs:
            extras.append(f"arp_conflicts={attrs['arp_conflicts']}")
        if "arp_replies" in attrs:
            extras.append(f"arp_replies={attrs['arp_replies']}")
        if _attr_int(attrs, "arp_scan_targets", 0) > 0:
            extras.append(f"arp_scan={attrs['arp_scan_targets']}")

    # TLS & timing
    if attrs.get("tls_handshake_types"):
        extras.append(f"tls_hs={attrs['tls_handshake_types']}")
    if _attr_int(attrs, "tls_client_hello_count", 0) > 0:
        extras.append(f"tls_ch={attrs['tls_client_hello_count']}")
    if attrs.get("intervals"):
        extras.append(f"intervals={str(attrs['intervals'])[:48]}")

    # Sanitized HTTP & Telnet
    if attrs.get("http_method") or attrs.get("http_path"):
        extras.append(f"http={_attr_str(attrs, 'http_method')} {_attr_str(attrs, 'http_path')[:48]}".strip())
    if attrs.get("http_status_codes"):
        extras.append(f"http_code={attrs['http_status_codes']}")
    if _attr_int(attrs, "http_uri_max_len", 0) > 0:
        extras.append(f"uri_len={_attr_int(attrs, 'http_uri_max_len')}")
    if _attr_float(attrs, "http_uri_max_entropy", 0.0) > 0:
        extras.append(f"uri_ent={_attr_float(attrs, 'http_uri_max_entropy'):.2f}")
    for key, tag in (
        ("http_xss_hits", "xss"),
        ("http_crlf_hits", "crlf"),
        ("http_sqli_hits", "sqli"),
        ("http_shell_hits", "shell"),
        ("http_host_ip_hits", "host_ip"),
        ("telnet_cmd_count", "telnet_cmds"),
    ):
        val = _attr_int(attrs, key, 0)
        if val > 0:
            extras.append(f"{tag}={val}")

    # L2 WiFi / 802.11 WLAN
    for key, tag in (
        ("wlan_deauth_count", "wlan_deauth"),
        ("wlan_beacon_count", "wlan_beacon"),
        ("wlan_auth_count", "wlan_auth"),
        ("wlan_bssid_count", "wlan_bssids"),
    ):
        val = _attr_int(attrs, key, 0)
        if val > 0:
            extras.append(f"{tag}={val}")

    # ET-BERT L7 sidecar features
    etb = etbert_result or {}
    et_lbl = etb.get("label") or attrs.get("etbert_label")
    et_score = etb.get("score") if "score" in etb else attrs.get("etbert_score")
    et_conf = etb.get("confidence") if "confidence" in etb else attrs.get("etbert_confidence")
    et_ent = etb.get("entropy") if "entropy" in etb else attrs.get("etbert_entropy")
    if et_lbl:
        extras.append(f"etbert_lbl={et_lbl}")
    if isinstance(et_score, (int, float)) and not isinstance(et_score, bool):
        extras.append(f"etbert_score={float(et_score):.2f}")
    if isinstance(et_conf, (int, float)) and not isinstance(et_conf, bool):
        extras.append(f"etbert_conf={float(et_conf):.2f}")
    if isinstance(et_ent, (int, float)) and not isinstance(et_ent, bool) and float(et_ent) > 0:
        extras.append(f"etbert_ent={float(et_ent):.2f}")

    if finding_hints:
        detectors = sorted({str(getattr(f, "detector", "")) for f in finding_hints if getattr(f, "detector", None)})
        if detectors:
            extras.append("det=" + ",".join(detectors))

    tail = (" " + " ".join(extras)) if extras else ""
    return f"[{ev_id}] {kind.upper()} {proto} {src_ep}->{dst_ep} pkts={pkts} bytes={nbytes}{tail}"


def score_evidence_deterministic(
    evidence: Any,
    linked_findings: Sequence[Any],
    *,
    peer_port_fanout: int = 0,
    high_threshold: float = 0.90,
    low_threshold: float = 0.35,
    etbert_result: dict[str, Any] | None = None,
) -> TriageDecision:
    """Compute baseline multi-class logits for a single normalized evidence item.

    Honors strict separation: only uses existing deterministic detector baseline,
    sanitized HTTP markers from existing web scorer, and optional ET-BERT model
    outputs — delegating nuanced L2-L7 classification to fine-tuned OpenJev.
    """
    ev_id = str(getattr(evidence, "evidence_id", ""))
    kind = str(getattr(evidence, "kind", "flow"))
    attrs = dict(getattr(evidence, "attributes", {}) or {})
    summary = str(getattr(evidence, "summary", ""))

    # Baseline calibrated logits across all 10 classes (non-Benign prior kept low at -3.0)
    logits: dict[str, float] = {cls: -3.0 for cls in TRAFFIC_CLASSES}
    logits["Benign"] = 1.6  # Benign prior for normal background flows
    signals: list[str] = []

    pkts = _attr_int(attrs, "packets", 1)
    nbytes = _attr_int(attrs, "bytes", 0)
    dst_port = _attr_int(attrs, "dst_port", -1)
    proto = _attr_str(attrs, "protocol", "").upper()

    detectors = {str(getattr(f, "detector", "")) for f in linked_findings}
    f_ids = [str(getattr(f, "finding_id", "")) for f in linked_findings if getattr(f, "finding_id", None)]

    # 1. L2 ARP Spoofing / Recon signals (existing detector + attributes)
    arp_conflicts = _attr_int(attrs, "arp_conflicts", 0)
    arp_replies = _attr_int(attrs, "arp_replies", 0)
    if kind == "arp" or proto == "ARP" or "arp_spoofing_conflict" in detectors or "arp_scan_burst" in detectors:
        if arp_conflicts > 0 or "arp_spoofing_conflict" in detectors:
            logits["ARP_Spoofing"] += 6.2
            logits["Benign"] -= 2.4
            signals.append(f"mac_ip_conflict={max(1, arp_conflicts)}")
        elif arp_replies >= 15 or "arp_scan_burst" in detectors:
            logits["Port_Scan_Recon"] += 4.2
            logits["ARP_Spoofing"] += 2.6
            logits["Benign"] -= 1.2
            signals.append("arp_discovery_burst")

    # 2. Port Scan / Recon signals (existing detector / fanout)
    if "tcp_destination_port_spread" in detectors or peer_port_fanout >= 20:
        fan = max(peer_port_fanout, 20)
        logits["Port_Scan_Recon"] += 4.8 + min(1.5, math.log2(max(2, fan)) * 0.25)
        logits["Benign"] -= 2.0
        signals.append(f"port_fanout={fan}")
    elif "port_scan" in " ".join(detectors).lower():
        logits["Port_Scan_Recon"] += 4.9
        logits["Benign"] -= 1.8
        signals.append("detector_port_scan")

    # 3. DoS / Flood signals (existing burst rules)
    icmp_flood = kind == "icmp" and pkts >= 50
    rst_flood = "tcp_flood_or_rst_storm" in detectors or _attr_int(attrs, "rst_count", 0) >= 20
    syn_flood = pkts >= 100 and nbytes <= pkts * 74 and dst_port >= 0 and "tcp" in proto.lower()
    if "icmp_smurf_or_flood" in detectors or icmp_flood or rst_flood or syn_flood:
        logits["DoS_Flood"] += 5.3
        logits["Benign"] -= 2.1
        signals.append(f"burst_pkts={pkts}")

    # 4. DNS Tunnel / DGA signals (existing NXDOMAIN / label entropy)
    if kind == "dns" or attrs.get("query") or "dns_nxdomain_entropy" in detectors:
        query = _attr_str(attrs, "query")
        label = query.rstrip(".").split(".", 1)[0]
        ent = _entropy(label)
        rcode = _attr_int(attrs, "rcode", 0)
        if "dns_nxdomain_entropy" in detectors or (len(label) >= 20 and ent >= 3.5):
            logits["DNS_Tunnel_DGA"] += 5.2 + min(1.0, max(0.0, ent - 3.5))
            logits["Benign"] -= 1.8
            signals.append(f"dns_entropy={ent:.2f},len={len(label)}")
        elif rcode == 3:
            logits["DNS_Tunnel_DGA"] += 3.1
            logits["Benign"] -= 0.4
            signals.append("dns_nxdomain")

    # 5. C2 Beaconing / Periodic callback signals
    intervals_raw = _attr_str(attrs, "intervals")
    if "periodic_tcp_connection_starts" in detectors:
        logits["C2_Beaconing"] += 5.4
        logits["Benign"] -= 1.9
        signals.append("periodic_syn_intervals")
    elif intervals_raw:
        vals = []
        for item in intervals_raw.split(","):
            try:
                v = float(item)
                if math.isfinite(v) and v > 0:
                    vals.append(v)
            except ValueError:
                pass
        if len(vals) >= 3:
            mean_v = sum(vals) / len(vals)
            std_v = math.sqrt(sum((x - mean_v) ** 2 for x in vals) / len(vals))
            cv = std_v / max(mean_v, 1e-6)
            if cv <= 0.20:
                logits["C2_Beaconing"] += 4.3
                logits["Benign"] -= 1.0
                signals.append(f"low_jitter_cv={cv:.2f}")

    # 6. TLS Renegotiation / Anomaly signals
    tls_hs = _attr_str(attrs, "tls_handshake_types")
    client_hellos = _attr_int(attrs, "tls_client_hello_count", 0)
    if "tls_renegotiation_anomaly" in detectors or client_hellos >= 3 or (tls_hs.count("1") >= 2):
        logits["TLS_Anomaly"] += 5.1
        logits["Benign"] -= 1.6
        signals.append("repeated_tls_handshake")

    # 7. HTTP XSS / Web Injection / Outbound Tunneling (supports both stub http_path and sanitized pipeline markers)
    http_path = _attr_str(attrs, "http_path").lower()
    sanitized_web_hits = (
        _attr_int(attrs, "http_xss_hits", 0)
        + _attr_int(attrs, "http_crlf_hits", 0)
        + _attr_int(attrs, "http_sqli_hits", 0)
        + _attr_int(attrs, "http_shell_hits", 0)
    )
    if (
        "http_suspicious_uri" in detectors
        or sanitized_web_hits > 0
        or any(tok in http_path for tok in ("<script", "cookie=", "union+select", "../", "cmd=", "uname"))
    ):
        logits["Web_Injection_Or_Tunnel"] += 5.6
        logits["Benign"] -= 2.2
        signals.append("suspicious_http_uri_marker")
    elif pkts >= 20 and nbytes >= 500_000 and dst_port not in (80, 443):
        logits["Web_Injection_Or_Tunnel"] += 3.6
        logits["Benign"] -= 0.7
        signals.append(f"nonstd_port_bulk={dst_port}")

    # 8. Optional ET-BERT L7 sidecar prediction fusion (when ET-BERT microservice scored this item)
    etbert_label: str | None = None
    etbert_conf: float | None = None
    if etbert_result:
        raw_lbl = str(etbert_result.get("label") or "")
        raw_conf = etbert_result.get("confidence")
        if raw_lbl:
            etbert_label = raw_lbl
        if isinstance(raw_conf, (int, float)) and math.isfinite(float(raw_conf)):
            etbert_conf = round(min(1.0, max(0.0, float(raw_conf))), 4)
        if etbert_label in logits and etbert_conf is not None and etbert_conf > 0.50:
            delta = 2.0 + 4.0 * (etbert_conf - 0.50)
            if etbert_label == "Benign":
                logits["Benign"] += delta * 0.6
            else:
                logits[etbert_label] += delta
                logits["Benign"] -= delta * 0.5
            signals.append("etbert_l7")

    # Normalize into calibrated probabilities
    probs = _softmax(logits)
    predicted_class = max(probs, key=lambda key: probs[key])
    confidence = round(probs[predicted_class], 4)
    uncertainty_ppl = _shannon_ppl(probs)

    if predicted_class == "Benign":
        if confidence >= high_threshold:
            decision = "fast_benign"
        else:
            decision = "escalate_uncertain"
    else:
        if confidence >= low_threshold:
            decision = "escalate_attack"
        else:
            decision = "escalate_uncertain"

    if not signals and summary and predicted_class != "Benign":
        signals.append("heuristic_pattern")

    return TriageDecision(
        evidence_id=ev_id,
        kind=kind,
        predicted_class=predicted_class,
        confidence=confidence,
        uncertainty_ppl=uncertainty_ppl,
        decision=decision,
        compact_text=_compact_flow_state(evidence, linked_findings, etbert_result=etbert_result),
        signals=signals,
        finding_ids=f_ids,
        etbert_label=etbert_label,
        etbert_confidence=etbert_conf,
    )


_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>()]+", re.I)
_SECRET_RE = re.compile(
    r"(?ix)\b(?:bearer\s+[A-Za-z0-9._~+/=-]+|"
    r"(?:api[_ -]?key|access[_ -]?token|auth(?:orization)?|password|passwd|secret|token)\s*[:=]\s*[^\s,;]+)"
)


def _anonymize_compact_state(text: str, salt: str) -> str:
    """Replace concrete network identifiers and secrets with per-call pseudonyms."""
    body = text.split(" ", 1)[-1] if " " in text else text

    def _tag(prefix: str, value: str) -> str:
        digest = hashlib.sha256(f"{salt}:{value.lower()}".encode("utf-8")).hexdigest()[:8]
        return f"{prefix}_{digest}"

    body = _SECRET_RE.sub("[REDACTED]", body)
    body = _URL_RE.sub("[REDACTED_URL]", body)
    body = _MAC_RE.sub(lambda m: _tag("mac", m.group(0)), body)
    body = _IPV4_RE.sub(lambda m: _tag("ip", m.group(0)), body)
    body = _IPV6_RE.sub(lambda m: _tag("ip6", m.group(0)), body)
    return body


def _decision_from_label_conf(label: str, conf: float, high_threshold: float, low_threshold: float) -> str:
    if label == "Benign":
        return "fast_benign" if conf >= high_threshold else "escalate_uncertain"
    return "escalate_attack" if conf >= low_threshold else "escalate_uncertain"


def _call_openjev_systemone_http(
    decisions: list[TriageDecision],
    endpoint_url: str,
    model_name: str,
    timeout_seconds: float,
    *,
    high_threshold: float = 0.90,
    low_threshold: float = 0.35,
) -> list[TriageDecision] | None:
    """Upstream OpenJev `/v1/systemone` state-question endpoint client."""
    ephemeral_salt = secrets.token_hex(16)
    updated: list[TriageDecision] = list(decisions)
    per_req_timeout = max(1.0, min(timeout_seconds, 5.0))
    succeeded = 0
    for idx, prev in enumerate(decisions[:128]):
        pseudo_id = hashlib.sha256(f"{ephemeral_salt}:{prev.evidence_id}".encode()).hexdigest()[:12]
        anon_state = pseudo_id + " " + _anonymize_compact_state(prev.compact_text, ephemeral_salt)
        body = {
            "model": model_name,
            "state": anon_state,
            "questions": {
                "traffic_class": {
                    "instructions": "Classify the network traffic state into one label from TRAFFIC_CLASSES.",
                    "type": "choice",
                    "criteria": OPENJEV_CLASS_CRITERIA,
                }
            },
        }
        request = Request(
            endpoint_url,
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=per_req_timeout) as resp:
                if getattr(resp, "status", 200) != 200:
                    if idx == 0:
                        return None
                    break
                raw = resp.read(512 * 1024)
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
            answers = parsed.get("answers", {}) if isinstance(parsed, dict) else {}
            tc = answers.get("traffic_class")
            if isinstance(tc, str):
                label = tc
                conf = prev.confidence
                ppl = prev.uncertainty_ppl
            elif isinstance(tc, dict):
                label = str(tc.get("label") or tc.get("prediction") or tc.get("value") or prev.predicted_class)
                try:
                    conf = min(1.0, max(0.0, float(tc.get("confidence", prev.confidence))))
                except (TypeError, ValueError):
                    conf = prev.confidence
                if isinstance(tc.get("probabilities"), dict) and tc["probabilities"]:
                    probs = {
                        str(k): max(0.0, float(v))
                        for k, v in tc["probabilities"].items()
                        if isinstance(v, (int, float))
                    }
                    ppl = _shannon_ppl(probs) if probs else prev.uncertainty_ppl
                else:
                    try:
                        ppl = float(tc.get("ppl", prev.uncertainty_ppl))
                    except (TypeError, ValueError):
                        ppl = prev.uncertainty_ppl
            else:
                if idx == 0:
                    return None
                continue
            succeeded += 1
            updated[idx] = TriageDecision(
                evidence_id=prev.evidence_id,
                kind=prev.kind,
                predicted_class=label,
                confidence=round(conf, 4),
                uncertainty_ppl=round(max(1.0, ppl), 4),
                decision=_decision_from_label_conf(label, conf, high_threshold, low_threshold),
                compact_text=prev.compact_text,
                signals=prev.signals + ["openjev_systemone"],
                finding_ids=prev.finding_ids,
                etbert_label=prev.etbert_label,
                etbert_confidence=prev.etbert_confidence,
            )
        except (OSError, TimeoutError, URLError, ValueError, TypeError, json.JSONDecodeError):
            if succeeded == 0:
                return None
            break
    return updated if succeeded > 0 else None


def _call_openjev_http(
    decisions: list[TriageDecision],
    endpoint_url: str,
    model_name: str,
    timeout_seconds: float,
    *,
    high_threshold: float = 0.90,
    low_threshold: float = 0.35,
) -> list[TriageDecision] | None:
    """Optional call to a user-hosted OpenJev /v1/systemone or batch `/classify` server.

    Sends ONLY compact anonymized flow states (no raw IPs/MACs/payloads/secrets).
    Returns updated decisions on valid JSON response, or None to fall back cleanly.
    """
    if endpoint_url.rstrip("/").endswith("/v1/systemone"):
        return _call_openjev_systemone_http(
            decisions,
            endpoint_url,
            model_name,
            timeout_seconds,
            high_threshold=high_threshold,
            low_threshold=low_threshold,
        )

    ephemeral_salt = secrets.token_hex(16)
    payload_items = [
        {
            "evidence_id": d.evidence_id,
            "kind": d.kind,
            "state": (
                hashlib.sha256(f"{ephemeral_salt}:{d.evidence_id}".encode()).hexdigest()[:12]
                + " "
                + _anonymize_compact_state(d.compact_text, ephemeral_salt)
            ),
        }
        for d in decisions[:256]
    ]
    req_body = json.dumps({"model": model_name, "items": payload_items}).encode("utf-8")
    request = Request(
        endpoint_url,
        data=req_body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=max(1.0, timeout_seconds)) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            raw = resp.read(2 * 1024 * 1024)
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
        rows = parsed.get("results") if isinstance(parsed, dict) else parsed
        if not isinstance(rows, list) or len(rows) != len(payload_items):
            return None
        updated: list[TriageDecision] = list(decisions)
        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            label = str(row.get("label") or row.get("predicted_class") or updated[idx].predicted_class)
            try:
                conf = float(row.get("confidence", updated[idx].confidence))
                conf = min(1.0, max(0.0, conf))
            except (TypeError, ValueError):
                conf = updated[idx].confidence
            try:
                ppl = float(row.get("ppl", updated[idx].uncertainty_ppl))
            except (TypeError, ValueError):
                ppl = updated[idx].uncertainty_ppl
            decision = _decision_from_label_conf(label, conf, high_threshold, low_threshold)
            prev = updated[idx]
            updated[idx] = TriageDecision(
                evidence_id=prev.evidence_id,
                kind=prev.kind,
                predicted_class=label,
                confidence=round(conf, 4),
                uncertainty_ppl=round(max(1.0, ppl), 4),
                decision=decision,
                compact_text=prev.compact_text,
                signals=prev.signals + ["openjev_http"],
                finding_ids=prev.finding_ids,
                etbert_label=prev.etbert_label,
                etbert_confidence=prev.etbert_confidence,
            )
        return updated
    except (OSError, TimeoutError, URLError, ValueError, TypeError, json.JSONDecodeError):
        return None


def classify_bundle(bundle: Any, triage_cfg: Any = None) -> TriageReport:
    """Classify all evidence records in an EvidenceBundle with Tier-1 gating."""
    enabled = bool(getattr(triage_cfg, "enabled", True)) if triage_cfg is not None else True
    mode = str(getattr(triage_cfg, "mode", "heuristic_calibrated")) if triage_cfg is not None else "heuristic_calibrated"
    model_name = str(getattr(triage_cfg, "model_name", "openjev-cal-tier1")) if triage_cfg is not None else "openjev-cal-tier1"
    high_t = float(getattr(triage_cfg, "high_confidence_threshold", 0.90)) if triage_cfg is not None else 0.90
    low_t = float(getattr(triage_cfg, "low_confidence_threshold", 0.35)) if triage_cfg is not None else 0.35
    endpoint_url = getattr(triage_cfg, "endpoint_url", None) if triage_cfg is not None else None
    timeout_s = float(getattr(triage_cfg, "timeout_seconds", 10.0)) if triage_cfg is not None else 10.0
    etbert_enabled = bool(getattr(triage_cfg, "etbert_enabled", False)) if triage_cfg is not None else False
    etbert_url = getattr(triage_cfg, "etbert_endpoint_url", None) if triage_cfg is not None else None
    etbert_model = str(getattr(triage_cfg, "etbert_model_name", "etbert-l7-datagram")) if triage_cfg is not None else "etbert-l7-datagram"
    etbert_timeout = float(getattr(triage_cfg, "etbert_timeout_seconds", 8.0)) if triage_cfg is not None else 8.0

    evidence_list = list(getattr(bundle, "evidence", []) or [])
    findings_list = list(getattr(bundle, "findings", []) or [])

    findings_by_ev: dict[str, list[Any]] = {}
    for finding in findings_list:
        for ev_id in getattr(finding, "evidence_ids", []) or []:
            findings_by_ev.setdefault(str(ev_id), []).append(finding)

    # Pre-compute distinct dst ports per src for flow fanout context
    ports_by_src: dict[str, set[int]] = {}
    for item in evidence_list:
        attrs = dict(getattr(item, "attributes", {}) or {})
        src = attrs.get("src") or attrs.get("src_ip")
        dp = _attr_int(attrs, "dst_port", -1)
        if src and dp >= 0:
            ports_by_src.setdefault(str(src), set()).add(dp)

    etbert_scores: dict[str, dict[str, Any]] = {}
    if enabled and etbert_enabled and etbert_url and evidence_list:
        etbert_scores = score_with_etbert_http(
            evidence_list,
            endpoint_url=str(etbert_url),
            model_name=etbert_model,
            timeout_seconds=etbert_timeout,
        )

    decisions: list[TriageDecision] = []
    if enabled:
        for item in evidence_list:
            ev_id = str(getattr(item, "evidence_id", ""))
            attrs = dict(getattr(item, "attributes", {}) or {})
            src = str(attrs.get("src") or attrs.get("src_ip") or "")
            fanout = len(ports_by_src.get(src, ()))
            decisions.append(
                score_evidence_deterministic(
                    item,
                    findings_by_ev.get(ev_id, ()),
                    peer_port_fanout=fanout,
                    high_threshold=high_t,
                    low_threshold=low_t,
                    etbert_result=etbert_scores.get(ev_id),
                )
            )

        if endpoint_url and mode in ("http_openjev", "hybrid", "etbert_openjev") and decisions:
            http_updated = _call_openjev_http(
                decisions,
                str(endpoint_url),
                model_name,
                timeout_s,
                high_threshold=high_t,
                low_threshold=low_t,
            )
            if http_updated is not None:
                decisions = http_updated
            elif mode == "http_openjev":
                mode = "http_openjev(fallback_heuristic)"
            elif mode == "etbert_openjev":
                mode = "etbert_openjev(fallback_etbert)" if etbert_scores else "etbert_openjev(fallback_heuristic)"

    benign_filtered = sum(1 for d in decisions if d.decision == "fast_benign")
    escalated_attack = sum(1 for d in decisions if d.decision == "escalate_attack")
    uncertain = sum(1 for d in decisions if d.decision == "escalate_uncertain")
    escalated_ids = [d.evidence_id for d in decisions if d.decision != "fast_benign"]
    total = len(decisions)
    reduction_ratio = (benign_filtered / total) if total > 0 else 0.0
    mean_conf = (sum(d.confidence for d in decisions) / total) if total > 0 else 0.0
    mean_ppl = (sum(d.uncertainty_ppl for d in decisions) / total) if total > 0 else 1.0

    grouped: dict[str, list[TriageDecision]] = {}
    for d in decisions:
        grouped.setdefault(d.predicted_class, []).append(d)
    top_classes = [
        ClassStat(
            label=label,
            count=len(rows),
            avg_confidence=round(sum(r.confidence for r in rows) / len(rows), 4),
            escalated=sum(1 for r in rows if r.decision != "fast_benign"),
        )
        for label, rows in sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    ]

    return TriageReport(
        enabled=enabled,
        model=model_name,
        mode=mode,
        total_evaluated=total,
        benign_filtered=benign_filtered,
        escalated_count=escalated_attack + uncertain,
        uncertain_count=uncertain,
        reduction_ratio=reduction_ratio,
        mean_confidence=mean_conf,
        mean_ppl=mean_ppl,
        top_classes=top_classes,
        escalated_evidence_ids=escalated_ids,
        decisions=decisions,
        etbert_scored_count=len(etbert_scores),
    )


def pack_evidence_for_ai(
    bundle: Any,
    *,
    max_bytes: int,
    triage_cfg: Any = None,
    max_findings: int = 80,
) -> tuple[Any, dict[str, int | float]]:
    """Select high-signal Tier-1 escalated evidence & cited findings within `max_bytes`.

    Preserves finding <-> evidence cross-reference integrity so LLM grounding checks
    never fail `invalid_refs` or `missing_finding`, while pruning repetitive
    `fast_benign` background records that cause out-of-context failures.
    """
    evidence_list = list(getattr(bundle, "evidence", []) or [])
    findings_list = list(getattr(bundle, "findings", []) or [])
    report = classify_bundle(bundle, triage_cfg)
    decision_by_id = {d.evidence_id: d for d in report.decisions}

    raw_size_est = len(
        json.dumps(
            {
                "evidence": [getattr(e, "attributes", {}) for e in evidence_list],
                "findings": [getattr(f, "title", "") for f in findings_list],
            },
            ensure_ascii=False,
        ).encode("utf-8")
    )

    # Trim repetitive parser warnings only in the ephemeral AI copy when budget is tight
    raw_warnings = list(getattr(getattr(bundle, "coverage", None), "warnings", []) or [])
    warning_limit = 8 if max_bytes <= 16_000 else (20 if max_bytes <= 40_000 else 60)
    trimmed_warnings = raw_warnings[:warning_limit]
    if len(raw_warnings) > warning_limit:
        trimmed_warnings.append(f"... {len(raw_warnings) - warning_limit} additional parser warning(s) omitted for LLM budget.")

    try:
        from .models import AISummary

        schema_bytes = len(
            json.dumps(AISummary.model_json_schema(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
    except Exception:
        schema_bytes = 2200

    stages_obj = getattr(getattr(bundle, "coverage", None), "stages", []) or []
    stages_bytes = sum(
        48 + len(str(getattr(s, "name", "")).encode("utf-8")) + len(str(getattr(s, "detail", "")).encode("utf-8"))
        for s in stages_obj
    )
    warnings_bytes = sum(len(str(w).encode("utf-8")) + 4 for w in trimmed_warnings) + 180
    triage_bytes = (
        len(json.dumps(report.to_summary_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")) + 40
        if getattr(bundle, "triage", None) is not None
        else 0
    )
    # Prompt instructions (~460) + tokenizer note (~210) + JSON wrapper keys (~320)
    fixed_reserve = schema_bytes + stages_bytes + warnings_bytes + triage_bytes + 1000
    evidence_budget = max(256, max_bytes - fixed_reserve)

    # Sort findings by severity desc, then Tier-1 max confidence desc
    def finding_priority(finding: Any) -> tuple[int, float, str]:
        sev = SEVERITY_RANK.get(str(getattr(finding, "severity", "low")), 0)
        ev_confs = [
            decision_by_id[eid].confidence
            for eid in getattr(finding, "evidence_ids", [])
            if eid in decision_by_id and decision_by_id[eid].decision != "fast_benign"
        ]
        max_conf = max(ev_confs) if ev_confs else 0.0
        return (-sev, -max_conf, str(getattr(finding, "finding_id", "")))

    sorted_findings = sorted(findings_list, key=finding_priority)

    selected_findings: list[Any] = []
    required_ev_ids: set[str] = set()
    ev_by_id = {str(getattr(e, "evidence_id", "")): e for e in evidence_list}

    running_bytes = 0
    for finding in sorted_findings[:max_findings]:
        f_ev_ids = [str(eid) for eid in getattr(finding, "evidence_ids", []) if str(eid) in ev_by_id]
        if not f_ev_ids:
            continue
        lim_bytes = sum(len(str(x).encode("utf-8")) + 4 for x in (getattr(finding, "limitations", []) or []))
        est = 170 + len(str(getattr(finding, "title", "")).encode("utf-8")) + lim_bytes + (len(f_ev_ids) * 14)
        for eid in f_ev_ids:
            if eid not in required_ev_ids:
                ev = ev_by_id[eid]
                refs_bytes = len(getattr(ev, "packet_refs", []) or []) * 7
                est += len(json.dumps(getattr(ev, "attributes", {}), ensure_ascii=False).encode("utf-8")) + 145 + refs_bytes
        if running_bytes + est > evidence_budget:
            if selected_findings:
                continue
            # First finding alone exceeds tight evidence_budget: try smaller findings unless none exist
            if len(sorted_findings) > 1:
                continue
            break
        selected_findings.append(finding)
        required_ev_ids.update(f_ev_ids)
        running_bytes += est

    # Add non-finding escalated / uncertain evidence prioritized by Tier-1 score
    def ev_priority(item: Any) -> tuple[int, float, str]:
        eid = str(getattr(item, "evidence_id", ""))
        d = decision_by_id.get(eid)
        if not d:
            return (2, 0.0, eid)
        tier = 0 if d.decision == "escalate_attack" else (1 if d.decision == "escalate_uncertain" else 3)
        return (tier, -d.confidence, eid)

    selected_evidence: list[Any] = [ev_by_id[eid] for eid in ev_by_id if eid in required_ev_ids]
    selected_ev_ids = {str(getattr(e, "evidence_id", "")) for e in selected_evidence}

    for item in sorted(evidence_list, key=ev_priority):
        eid = str(getattr(item, "evidence_id", ""))
        if eid in selected_ev_ids:
            continue
        d = decision_by_id.get(eid)
        # Skip fast_benign flows once we have any findings or non-trivial flow volume
        if d and d.decision == "fast_benign" and (selected_findings or len(evidence_list) > 20):
            continue
        refs_bytes = len(getattr(item, "packet_refs", []) or []) * 7
        est = len(json.dumps(getattr(item, "attributes", {}), ensure_ascii=False).encode("utf-8")) + 145 + refs_bytes
        if selected_evidence and running_bytes + est > evidence_budget:
            break
        selected_evidence.append(item)
        selected_ev_ids.add(eid)
        running_bytes += est

    # Ensure at least one evidence item if possible, keeping finding references consistent
    if not selected_evidence and evidence_list:
        first = sorted(evidence_list, key=ev_priority)[0]
        selected_evidence = [first]
        selected_ev_ids = {str(getattr(first, "evidence_id", ""))}
        selected_findings = [
            f for f in selected_findings if set(getattr(f, "evidence_ids", [])).issubset(selected_ev_ids)
        ]

    # Build shallow clone using same Pydantic model class if available
    warnings = list(trimmed_warnings)
    filtered_ev_count = max(0, len(evidence_list) - len(selected_evidence))
    filtered_f_count = max(0, len(findings_list) - len(selected_findings))
    if filtered_ev_count > 0 or filtered_f_count > 0:
        savings = round((1.0 - (running_bytes / max(1, raw_size_est))) * 100.0, 1)
        warnings.append(
            f"Tier-1 context compactor filtered {filtered_ev_count} benign/low-priority evidence records "
            f"and {filtered_f_count} excess findings (~{max(0.0, savings):.1f}% context reduction) before LLM."
        )

    packed_stats: dict[str, int | float] = {
        "raw_evidence_count": len(evidence_list),
        "sent_evidence_count": len(selected_evidence),
        "raw_findings_count": len(findings_list),
        "sent_findings_count": len(selected_findings),
        "benign_filtered_count": report.benign_filtered,
        "raw_bytes_est": raw_size_est,
        "sent_bytes_est": running_bytes,
        "reduction_pct": round((1.0 - (len(selected_evidence) / max(1, len(evidence_list)))) * 100.0, 2),
    }

    if hasattr(bundle, "model_copy"):
        cov = bundle.coverage.model_copy(update={"warnings": warnings[:100]})
        compacted = bundle.model_copy(
            update={
                "coverage": cov,
                "evidence": selected_evidence,
                "findings": selected_findings,
            }
        )
        return compacted, packed_stats
    return bundle, packed_stats


_JSONL_METRIC_KEYS: tuple[str, ...] = (
    "protocol",
    "src_port",
    "dst_port",
    "packets",
    "bytes",
    "rev_packets",
    "rev_bytes",
    "io_byte_ratio",
    "duration",
    "pkt_rate",
    "ttl_min",
    "ttl_max",
    "ttl_distinct_count",
    "ip_frag_count",
    "same_src_dst_count",
    "dst_unique_srcs",
    "src_unique_dst_ports",
    "src_unique_dsts",
    "tcp_flags_mask",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "null_flag_count",
    "xmas_flag_count",
    "retrans_count",
    "data_len_sum",
    "icmp_type",
    "icmp_code",
    "icmp_data_len_sum",
    "rcode",
    "dns_qry_type",
    "http_uri_max_len",
    "http_uri_max_entropy",
    "http_xss_hits",
    "http_crlf_hits",
    "http_sqli_hits",
    "http_shell_hits",
    "telnet_cmd_count",
    "wlan_deauth_count",
    "wlan_beacon_count",
    "wlan_auth_count",
    "wlan_bssid_count",
    "arp_conflicts",
    "arp_replies",
    "arp_scan_targets",
)


def bundle_to_triage_jsonl(bundle: Any, triage_cfg: Any = None) -> str:
    """Export per-flow compact JSONL compatible with Trainer-Pipeline / OpenJev."""
    report = classify_bundle(bundle, triage_cfg)
    ev_map = {str(getattr(e, "evidence_id", "")): e for e in getattr(bundle, "evidence", []) or []}
    lines: list[str] = []
    for dec in report.decisions:
        ev = ev_map.get(dec.evidence_id)
        attrs = dict(getattr(ev, "attributes", {}) or {}) if ev is not None else {}
        record: dict[str, Any] = {
            "evidence_id": dec.evidence_id,
            "kind": dec.kind,
            "text": dec.compact_text,
            "predicted_class": dec.predicted_class,
            "confidence": dec.confidence,
            "uncertainty_ppl": dec.uncertainty_ppl,
            "triage_decision": dec.decision,
            "signals": dec.signals,
            "finding_ids": dec.finding_ids,
            "packet_refs": list(getattr(ev, "packet_refs", []) or []) if ev is not None else [],
            "metrics": {k: attrs[k] for k in _JSONL_METRIC_KEYS if k in attrs},
        }
        if dec.etbert_label is not None or dec.etbert_confidence is not None:
            record["etbert"] = {
                "label": dec.etbert_label,
                "confidence": dec.etbert_confidence,
            }
        lines.append(json.dumps(record, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


__all__ = [
    "OPENJEV_CLASS_CRITERIA",
    "TRAFFIC_CLASSES",
    "ClassStat",
    "TriageDecision",
    "TriageReport",
    "bundle_to_triage_jsonl",
    "classify_bundle",
    "pack_evidence_for_ai",
    "score_evidence_deterministic",
]
