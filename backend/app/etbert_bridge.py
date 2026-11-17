"""Safe data-bearing L7 HTTP bridge to an ET-BERT datagram scorer service.

ET-BERT excels at encrypted/data-bearing Application Layer (L7) datagram bursts
(e.g., TLS handshakes, HTTP tunnels, DNS payloads), whereas control/L2/L3-only
traffic (ARP, ICMP, 802.11 management/deauth, pure SYN/RST header floods) should
be handled natively via L2-L4 dissector telemetry and OpenJev rather than fed
as empty padding to ET-BERT.

This module strictly enforces:
  1. Data-bearing gating (`is_data_bearing_evidence`).
  2. Ephemeral per-call anonymization of all IPs, MACs, queries, and URLs before
     leaving the PCAPSCANNER backend.
  3. Fail-closed behavior: network/parse failures yield an empty dict `{}` so
     OpenJev / deterministic Tier-1 classification continues uninterrupted.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
from typing import Any, Callable, Sequence
from .http_transport import post_json_bounded

DATA_BEARING_KINDS = frozenset({"flow", "tls", "http", "dns", "packet"})
NON_L7_KINDS = frozenset({"arp", "icmp", "wlan"})
NON_L7_PROTOS = frozenset({"ARP", "ICMP", "ICMPV6", "WLAN"})
COMMON_L7_PORTS = frozenset({21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443})
STANDARD_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"})

_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>()]+", re.I)
_SECRET_RE = re.compile(
    r"(?ix)\b(?:bearer\s+[A-Za-z0-9._~+/=-]+|"
    r"(?:api[_ -]?key|access[_ -]?token|auth(?:orization)?|password|passwd|secret|token)\s*[:=]\s*[^\s,;]+)"
)

_SAFE_ETBERT_FEATURE_KEYS: tuple[str, ...] = (
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
    "data_len_sum",
    "data_len_max",
    "tls_handshake_types",
    "tls_client_hello_count",
    "http_method",
    "http_status_codes",
    "dns_qry_type",
    "rcode",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "retrans_count",
)


def _get_attr(evidence: Any, key: str, default: Any = None) -> Any:
    if isinstance(evidence, dict):
        return evidence.get(key, default)
    return getattr(evidence, key, default)


def _num_int(attrs: dict[str, Any], key: str, default: int = 0) -> int:
    raw = attrs.get(key)
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    if isinstance(raw, float) and math.isfinite(raw):
        return int(raw)
    if isinstance(raw, str) and raw.strip().lstrip("-").isdigit():
        return int(raw.strip())
    return default


def _num_float(attrs: dict[str, Any], key: str, default: float = 0.0) -> float:
    raw = attrs.get(key)
    if isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(float(raw)):
        return float(raw)
    return default


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def anonymize_identifier(value: str, salt: str, prefix: str = "id") -> str:
    digest = hashlib.sha256(f"{salt}:{value.lower()}".encode("utf-8", "replace")).hexdigest()[:10]
    return f"{prefix}_{digest}"


def _anonymize_text(text: str, salt: str) -> str:
    clean = _SECRET_RE.sub("[REDACTED]", text)
    clean = _URL_RE.sub("[REDACTED_URL]", clean)
    clean = _MAC_RE.sub(lambda m: anonymize_identifier(m.group(0), salt, "mac"), clean)
    clean = _IPV4_RE.sub(lambda m: anonymize_identifier(m.group(0), salt, "ip"), clean)
    clean = _IPV6_RE.sub(lambda m: anonymize_identifier(m.group(0), salt, "ip6"), clean)
    return clean


def is_data_bearing_evidence(evidence: Any) -> bool:
    """Return True only when the evidence represents data-bearing L7/transport traffic."""
    kind = str(_get_attr(evidence, "kind", "flow") or "flow").lower()
    if kind in NON_L7_KINDS or kind not in DATA_BEARING_KINDS:
        return False

    attrs = dict(_get_attr(evidence, "attributes", {}) or {})
    proto = str(attrs.get("protocol", "") or "").upper()
    if proto in NON_L7_PROTOS:
        return False

    if kind in {"tls", "http", "dns"}:
        return True

    if (
        attrs.get("tls_handshake_types")
        or _num_int(attrs, "tls_client_hello_count", 0) > 0
        or attrs.get("http_method")
        or attrs.get("http_status_codes")
        or _num_int(attrs, "http_uri_max_len", 0) > 0
        or attrs.get("query")
        or _num_int(attrs, "telnet_cmd_count", 0) > 0
        or _num_int(attrs, "data_len_sum", 0) > 0
        or _num_int(attrs, "data_len_max", 0) > 0
    ):
        return True

    pkts = max(1, _num_int(attrs, "packets", 1))
    nbytes = _num_int(attrs, "bytes", 0)
    dst_port = _num_int(attrs, "dst_port", -1)
    src_port = _num_int(attrs, "src_port", -1)
    avg_pkt_bytes = nbytes / pkts

    # Exclude pure L3/L4 header floods (e.g., empty SYN/RST/ACK floods <= ~74B/pkt)
    if (dst_port in COMMON_L7_PORTS or src_port in COMMON_L7_PORTS) and avg_pkt_bytes > 74.0:
        return True
    if proto in {"TCP", "UDP"} and pkts >= 2 and avg_pkt_bytes > 90.0:
        return True
    return False


def build_etbert_request_items(
    evidence_list: Sequence[Any],
    *,
    max_items: int = 256,
    salt: str | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Build anonymized JSON-serializable payloads for data-bearing evidence only."""
    ephemeral_salt = salt or secrets.token_hex(16)
    items: list[dict[str, Any]] = []
    evidence_ids: list[str] = []

    for evidence in evidence_list:
        if len(items) >= max_items:
            break
        if not is_data_bearing_evidence(evidence):
            continue
        ev_id = str(_get_attr(evidence, "evidence_id", "") or "")
        kind = str(_get_attr(evidence, "kind", "flow") or "flow").lower()
        attrs = dict(_get_attr(evidence, "attributes", {}) or {})

        features: dict[str, Any] = {}
        for key in _SAFE_ETBERT_FEATURE_KEYS:
            if key in attrs and attrs[key] is not None and not isinstance(attrs[key], bool):
                val = attrs[key]
                if isinstance(val, float) and not math.isfinite(val):
                    continue
                features[key] = val

        # A method is packet-controlled input. Keep only a fixed, standard
        # category in both the structured feature map and the human-readable state.
        if "http_method" in features:
            method = str(features["http_method"]).upper()
            features["http_method"] = method if method in STANDARD_HTTP_METHODS else "OTHER"

        src_raw = str(attrs.get("src") or attrs.get("src_ip") or "")
        dst_raw = str(attrs.get("dst") or attrs.get("dst_ip") or "")
        if src_raw:
            features["src_pseudo"] = anonymize_identifier(src_raw, ephemeral_salt, "host")
        if dst_raw:
            features["dst_pseudo"] = anonymize_identifier(dst_raw, ephemeral_salt, "host")

        query_raw = str(attrs.get("query") or "")
        if query_raw:
            first_label = query_raw.rstrip(".").split(".", 1)[0]
            features["q_len"] = len(first_label)
            features["q_ent"] = round(_entropy(first_label), 3)
            features["q_pseudo"] = anonymize_identifier(query_raw, ephemeral_salt, "dom")

        # Include intervals summary without raw timestamps or raw URIs
        if attrs.get("intervals"):
            features["intervals"] = str(attrs["intervals"])[:64]

        item_id = anonymize_identifier(ev_id or str(len(items)), ephemeral_salt, "ev")
        items.append(
            {
                "item_id": item_id,
                "kind": kind,
                "state": _anonymize_text(
                    f"{kind.upper()} {features.get('protocol', kind.upper())} "
                    f"sp={features.get('src_port', '-')} dp={features.get('dst_port', '-')} "
                    f"pkts={features.get('packets', 0)} bytes={features.get('bytes', 0)} "
                    f"dlen={features.get('data_len_sum', 0)} "
                    f"tls={features.get('tls_handshake_types', '-')} "
                    f"http={features.get('http_method', '-')}",
                    ephemeral_salt,
                ),
                "features": features,
            }
        )
        evidence_ids.append(ev_id)

    return items, evidence_ids


def score_with_etbert_http(
    evidence_list: Sequence[Any],
    *,
    endpoint_url: str,
    model_name: str = "etbert-l7-datagram",
    timeout_seconds: float = 8.0,
    max_items: int = 256,
    allow_network: bool = False,
    deadline_monotonic: float | None = None,
    cancellation_check: Callable[[], bool] | None = None,
) -> dict[str, dict[str, Any]]:
    """Query user-hosted ET-BERT HTTP endpoint for data-bearing L7 flows.

    Returns `{evidence_id: {"label": str, "score": float, "confidence": float, "entropy": float, "model": str}}`
    or `{}` cleanly on network/timeout/malformed-response failures.
    """
    if not allow_network or not endpoint_url or not evidence_list:
        return {}

    items, ev_ids = build_etbert_request_items(evidence_list, max_items=max_items)
    if not items:
        return {}

    try:
        parsed = post_json_bounded(
            endpoint_url,
            {"model": model_name, "items": items},
            timeout_seconds=max(1.0, float(timeout_seconds)),
            deadline_monotonic=deadline_monotonic,
            cancellation_check=cancellation_check,
        )
        if not isinstance(parsed, (dict, list)):
            return {}
        rows = parsed.get("results") if isinstance(parsed, dict) else parsed
        if not isinstance(rows, list):
            return {}

        id_map = {item["item_id"]: ev_id for item, ev_id in zip(items, ev_ids)}
        out: dict[str, dict[str, Any]] = {}

        if len(rows) == len(ev_ids):
            pairs = list(zip(ev_ids, rows))
        else:
            pairs = []
            for row in rows:
                if isinstance(row, dict) and str(row.get("item_id", "")) in id_map:
                    pairs.append((id_map[str(row["item_id"])], row))

        for ev_id, row in pairs:
            if not ev_id or not isinstance(row, dict):
                continue
            label = str(row.get("label") or row.get("predicted_class") or "Benign")[:64]
            try:
                conf = float(row.get("confidence", 0.5))
                if not math.isfinite(conf):
                    conf = 0.5
                conf = round(min(1.0, max(0.0, conf)), 4)
            except (TypeError, ValueError):
                conf = 0.5
            try:
                raw_score = row.get("score", row.get("anomaly_score", 0.0 if label == "Benign" else conf))
                score = float(raw_score)
                if not math.isfinite(score):
                    score = 0.0
                score = round(min(1.0, max(0.0, score)), 4)
            except (TypeError, ValueError):
                score = 0.0
            try:
                ent = float(row.get("entropy", 0.0))
                if not math.isfinite(ent):
                    ent = 0.0
                ent = round(max(0.0, ent), 4)
            except (TypeError, ValueError):
                ent = 0.0
            out[ev_id] = {
                "label": label,
                "score": score,
                "confidence": conf,
                "entropy": ent,
                "model": str(row.get("model") or model_name)[:80],
            }
        return out
    except (ValueError, TypeError, KeyError):
        return {}


__all__ = [
    "anonymize_identifier",
    "build_etbert_request_items",
    "is_data_bearing_evidence",
    "score_with_etbert_http",
]
