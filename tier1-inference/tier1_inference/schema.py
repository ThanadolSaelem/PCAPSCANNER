"""Inference-only schema, constants, device resolution, and calibration math."""
from __future__ import annotations

import math
from typing import Any, Mapping

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

CLASS_TO_INDEX: dict[str, int] = {cls: idx for idx, cls in enumerate(TRAFFIC_CLASSES)}

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

DEFAULT_HIGH_THRESHOLD: float = 0.90
DEFAULT_LOW_THRESHOLD: float = 0.35


def shannon_ppl_from_probs(probs: Mapping[str, float]) -> float:
    """Compute perplexity proxy $2^{H(p)}$ from calibrated class probabilities."""
    entropy = 0.0
    for p in probs.values():
        fp = float(p)
        if fp > 1e-12:
            entropy -= fp * math.log2(fp)
    return round(2.0**entropy, 4)


def decision_from_label_conf(
    label: str,
    conf: float,
    high_threshold: float = DEFAULT_HIGH_THRESHOLD,
    low_threshold: float = DEFAULT_LOW_THRESHOLD,
) -> str:
    """Map predicted label and confidence into Tier-1 triage gating decisions."""
    if label == "Benign":
        return "fast_benign" if conf >= high_threshold else "escalate_uncertain"
    return "escalate_attack" if conf >= low_threshold else "escalate_uncertain"


def softmax_logits(logits: Mapping[str, float]) -> dict[str, float]:
    """Numerically stable softmax over class logit dict."""
    if not logits:
        return {}
    max_l = max(logits.values())
    exps = {k: math.exp(min(40.0, max(-40.0, v - max_l))) for k, v in logits.items()}
    total = sum(exps.values()) or 1.0
    return {k: round(v / total, 6) for k, v in exps.items()}


def resolve_device(preferred: str = "auto") -> str:
    """Resolve PyTorch compute device (`cuda` -> Apple Silicon `mps` -> `cpu`)."""
    req = (preferred or "auto").strip().lower()
    if req in {"cuda", "mps", "cpu"}:
        return req
    try:
        import torch

        if torch.cuda.is_available():
            return "cuda"
        mps = getattr(torch.backends, "mps", None)
        if mps is not None and mps.is_available():
            return "mps"
    except ImportError:
        pass
    return "cpu"


def resolve_torch_dtype(device: str) -> Any:
    """Choose a safe tensor dtype per device (`float16` on MPS/CUDA, `float32` on CPU)."""
    import torch

    if device in {"cuda", "mps"}:
        return torch.float16
    return torch.float32


__all__ = [
    "CLASS_TO_INDEX",
    "DEFAULT_HIGH_THRESHOLD",
    "DEFAULT_LOW_THRESHOLD",
    "OPENJEV_CLASS_CRITERIA",
    "TRAFFIC_CLASSES",
    "decision_from_label_conf",
    "resolve_device",
    "resolve_torch_dtype",
    "shannon_ppl_from_probs",
    "softmax_logits",
]
