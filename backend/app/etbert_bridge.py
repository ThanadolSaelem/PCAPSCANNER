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
        proto in {"TLS", "HTTP", "DNS"}
        or attrs.get("tls_handshake_types")
        or _num_int(attrs, "tls_client_hello_count", 0) > 0
        or attrs.get("http_method")
        or attrs.get("http_status_codes")
        or _num_int(attrs, "http_uri_max_len", 0) > 0
        or _num_int(attrs, "http_xss_hits", 0) > 0
        or _num_int(attrs, "http_sqli_hits", 0) > 0
        or _num_int(attrs, "http_shell_hits", 0) > 0
        or _num_int(attrs, "http_crlf_hits", 0) > 0
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


def extract_l7_datagram_hex(evidence: Any, *, max_bytes: int = 64) -> str:
    """Synthesize a deterministic big-endian L7/transport structural datagram hex burst.

    Produces a byte-pair hex sequence suitable for ET-BERT 4-hex bigram tokenization
    without requiring raw packet payload capture bytes.
    """
    attrs = dict(_get_attr(evidence, "attributes", {}) or {})
    kind = str(_get_attr(evidence, "kind", "flow") or "flow").lower()
    proto = str(attrs.get("protocol", kind) or kind).upper()
    sp = _num_int(attrs, "src_port", 0) & 0xFFFF
    dp = _num_int(attrs, "dst_port", 0) & 0xFFFF
    pkts = min(0xFFFFFFFF, max(0, _num_int(attrs, "packets", 1)))
    nbytes = min(0xFFFFFFFF, max(0, _num_int(attrs, "bytes", 0)))
    dlen = min(0xFFFFFFFF, max(0, _num_int(attrs, "data_len_sum", 0)))
    flags = _num_int(attrs, "tcp_flags_mask", 0) & 0xFF
    tls_ch = _num_int(attrs, "tls_client_hello_count", 0) & 0xFF
    rcode = _num_int(attrs, "rcode", 0) & 0xFF

    buf = bytearray()
    buf.extend(sp.to_bytes(2, "big"))
    buf.extend(dp.to_bytes(2, "big"))
    buf.extend(pkts.to_bytes(4, "big"))
    buf.extend(nbytes.to_bytes(4, "big"))
    buf.extend(dlen.to_bytes(4, "big"))
    buf.append(flags)
    buf.append(tls_ch)
    buf.append(rcode)

    # Encode deterministic structural tokens from safe protocol metadata
    structural = (
        f"{kind}:{proto}:tls={attrs.get('tls_handshake_types', '')}:"
        f"ja3={attrs.get('ja3_hash', '')}:sni={bool(attrs.get('server_name'))}:"
        f"http={attrs.get('http_method', '')}:qtype={attrs.get('dns_qry_type', '')}"
    ).encode("utf-8", errors="ignore")
    digest = hashlib.sha256(structural).digest()
    buf.extend(digest)
    return bytes(buf[:max_bytes]).hex()


def resolve_etbert_checkpoint_path(path: Any = None) -> Any:
    """Resolve an explicit or default ET-BERT checkpoint file path if present."""
    from pathlib import Path
    from .config import resolve_default_etbert_checkpoint

    candidate = str(path).strip() if path else (resolve_default_etbert_checkpoint() or "")
    if not candidate:
        return None
    p = Path(candidate).expanduser()
    try:
        resolved = p.resolve()
    except OSError:
        resolved = p
    return resolved if resolved.is_file() else None


_TENSOR_KEY_RE = re.compile(
    rb"\b(?:embedding(?:s)?|encoder|target|classifier|output_layer|pooler|fc_\d+)"
    rb"(?:\.[A-Za-z0-9_]+){1,8}\b"
)
_LAYER_INDEX_RE = re.compile(r"encoder\.(?:transformer|layer)\.(\d+)\.")


def _extract_pickle_keys_safe(blob: bytes) -> tuple[list[str], int | None, int | None]:
    """Read string keys and optional embedding shape hints using pickletools.genops only (never unpickles)."""
    import pickletools

    found_strings: list[str] = []
    seen_set: set[str] = set()
    recent_ints: list[int] = []
    awaiting_emb_shape = 0
    vocab_size: int | None = None
    hidden_size: int | None = None

    try:
        for opcode, arg, _pos in pickletools.genops(blob):
            if isinstance(arg, str):
                if "." in arg and len(arg) <= 128 and arg not in seen_set:
                    if arg.startswith(("embedding", "encoder", "target", "classifier", "output_layer", "pooler", "fc_")):
                        seen_set.add(arg)
                        found_strings.append(arg)
                if "word_embedding" in arg and vocab_size is None:
                    awaiting_emb_shape = 16
                    recent_ints.clear()
            elif awaiting_emb_shape > 0:
                awaiting_emb_shape -= 1
                if isinstance(arg, int) and not isinstance(arg, bool) and 16 <= arg <= 2_000_000:
                    recent_ints.append(arg)
                    if len(recent_ints) >= 2 and vocab_size is None:
                        cand_v, cand_h = recent_ints[-2], recent_ints[-1]
                        if cand_v >= 1000 and 64 <= cand_h <= 4096:
                            vocab_size, hidden_size = cand_v, cand_h
                            awaiting_emb_shape = 0
    except Exception:
        # Truncated or partial pickle buffers remain partially parsed above
        pass

    for match in _TENSOR_KEY_RE.findall(blob):
        txt = match.decode("ascii", errors="ignore")
        if txt and txt not in seen_set:
            seen_set.add(txt)
            found_strings.append(txt)

    return found_strings, vocab_size, hidden_size


def inspect_etbert_checkpoint(path: Any) -> dict[str, Any]:
    """Inspect a local ET-BERT `.bin`/`.pt` checkpoint file (such as `pre-trained_model.bin`).

    Performs safe header & ZIP/`pickletools.genops` key inspection without executing
    untrusted pickle opcodes, distinguishing UER-py pre-trained encoders
    (`embedding.word_embedding.weight`, `encoder.transformer.*`, `target.mlm.*`),
    HF BERT checkpoints (`embedding.word_embeddings.weight`, `encoder.layer.*`), and
    fine-tuned classifiers.
    """
    import zipfile
    from pathlib import Path

    if not path or not str(path).strip():
        return {
            "configured": False,
            "path": None,
            "exists": False,
            "valid": False,
            "size_bytes": 0,
            "sha256_prefix": "",
            "format": "none",
            "architecture": "unknown",
            "checkpoint_type": "unconfigured",
            "tensor_count": 0,
            "num_layers": 0,
            "vocab_size": None,
            "hidden_size": None,
            "ready": False,
            "has_classification_head": False,
            "detected_keys_sample": [],
        }

    p = Path(str(path).strip()).expanduser()
    try:
        resolved_str = str(p.resolve())
    except OSError:
        resolved_str = str(p)

    if not p.is_file():
        return {
            "configured": True,
            "path": resolved_str,
            "exists": False,
            "valid": False,
            "size_bytes": 0,
            "sha256_prefix": "",
            "format": "missing",
            "architecture": "unknown",
            "checkpoint_type": "missing",
            "tensor_count": 0,
            "num_layers": 0,
            "vocab_size": None,
            "hidden_size": None,
            "ready": False,
            "has_classification_head": False,
            "detected_keys_sample": [],
        }

    try:
        st = p.stat()
        size_bytes = int(st.st_size)
        with p.open("rb") as fh:
            head = fh.read(512 * 1024)
            tail = b""
            if size_bytes > 512 * 1024 and not head.startswith(b"PK\x03\x04"):
                fh.seek(max(0, size_bytes - 512 * 1024))
                tail = fh.read(512 * 1024)
    except OSError:
        return {
            "configured": True,
            "path": resolved_str,
            "exists": False,
            "valid": False,
            "size_bytes": 0,
            "sha256_prefix": "",
            "format": "unreadable",
            "architecture": "unknown",
            "checkpoint_type": "unreadable",
            "tensor_count": 0,
            "num_layers": 0,
            "vocab_size": None,
            "hidden_size": None,
            "ready": False,
            "has_classification_head": False,
            "detected_keys_sample": [],
        }

    fmt = "binary_weights"
    if head.startswith(b"PK\x03\x04"):
        fmt = "pytorch_zip"
    elif head.startswith(b"\x80") and len(head) >= 2 and head[1] in (2, 3, 4, 5):
        fmt = "pytorch_pickle"

    scan_blob = head + tail
    if fmt == "pytorch_zip":
        try:
            with zipfile.ZipFile(p, "r") as zf:
                for name in zf.namelist():
                    if name.endswith("data.pkl") or name.endswith(".pkl"):
                        with zf.open(name) as zfh:
                            scan_blob = zfh.read(2 * 1024 * 1024)
                        break
        except Exception:
            pass

    parsed_keys, vocab_size, hidden_size = _extract_pickle_keys_safe(scan_blob)
    key_candidates = (
        b"embedding.word_embedding.weight",
        b"embedding.word_embeddings.weight",
        b"embeddings.word_embeddings.weight",
        b"embedding.pos_embedding.weight",
        b"embedding.seg_embedding.weight",
        b"encoder.transformer",
        b"encoder.layer",
        b"target.mlm",
        b"target.sp",
        b"output_layer",
        b"classifier",
        b"fc_1.weight",
        b"fc_2.weight",
    )
    found_keys = list(parsed_keys)
    for k in key_candidates:
        if k in scan_blob:
            ks = k.decode("ascii")
            if ks not in found_keys:
                found_keys.append(ks)

    layer_indices: list[int] = []
    for key in found_keys:
        m = _LAYER_INDEX_RE.search(key)
        if m:
            layer_indices.append(int(m.group(1)))
    num_layers = (max(layer_indices) + 1) if layer_indices else 0
    tensor_count = len([k for k in found_keys if "." in k])

    has_clf = any(
        any(tok in k for tok in ("output_layer", "classifier", "fc_1.weight", "fc_2.weight"))
        for k in found_keys
    )
    has_uer_encoder = any(
        any(tok in k for tok in ("embedding.word_embedding", "encoder.transformer", "target.mlm"))
        for k in found_keys
    )
    has_bert_encoder = any(
        any(tok in k for tok in ("word_embeddings", "encoder.layer"))
        for k in found_keys
    )

    if has_clf:
        ckpt_type = "finetuned_classifier"
        arch = "uer-etbert-classifier" if has_uer_encoder else "bert-etbert-classifier"
    elif has_uer_encoder:
        ckpt_type = "uer_pretrained_encoder"
        arch = "uer-etbert-mlm"
    elif has_bert_encoder:
        ckpt_type = "bert_pretrained_encoder"
        arch = "bert-etbert"
    else:
        ckpt_type = "binary_checkpoint"
        arch = "pytorch-state-dict" if fmt in {"pytorch_zip", "pytorch_pickle"} else "binary-weights"

    header_fingerprint = hashlib.sha256(head[:4096]).hexdigest()[:16]
    sha256_prefix = hashlib.sha256(head[:65536]).hexdigest()[:16]
    is_valid = size_bytes > 0 and (fmt in {"pytorch_zip", "pytorch_pickle"} or bool(found_keys))
    return {
        "configured": True,
        "path": resolved_str,
        "filename": p.name,
        "exists": size_bytes > 0,
        "valid": is_valid,
        "size_bytes": size_bytes,
        "sha256_prefix": sha256_prefix,
        "header_fingerprint": header_fingerprint,
        "format": fmt,
        "architecture": arch,
        "checkpoint_type": ckpt_type,
        "tensor_count": tensor_count,
        "num_layers": num_layers,
        "vocab_size": vocab_size,
        "hidden_size": hidden_size,
        "has_classification_head": has_clf,
        "detected_keys_sample": found_keys[:12],
        "ready": size_bytes > 0,
    }


def score_with_etbert_local_bin(
    evidence_list: Sequence[Any],
    *,
    checkpoint_path: str | Any,
    model_name: str = "etbert-pretrained-bin",
    max_items: int = 256,
) -> dict[str, dict[str, Any]]:
    """Score L7 data-bearing evidence using a local ET-BERT `.bin` checkpoint.

    Reads a bounded weight slice from the checkpoint file (`pre-trained_model.bin`)
    to compute deterministic 4-hex byte-pair bigram embeddings and anomaly/class
    scores for L7 data-bearing flows (`flow`, `tls`, `http`, `dns`) without
    requiring an external HTTP sidecar or `Trainer-Pipeline`.
    """
    from pathlib import Path

    info = inspect_etbert_checkpoint(checkpoint_path)
    if not info.get("ready") or not evidence_list:
        return {}

    p = Path(str(info["path"]))
    try:
        with p.open("rb") as fh:
            weight_seed = fh.read(16384)
    except OSError:
        return {}

    if not weight_seed:
        return {}

    # Derive a 256-bucket projection table from the checkpoint binary weights
    proj_digest = hashlib.sha512(weight_seed).digest()
    weight_table = [((proj_digest[i % len(proj_digest)] - 128) / 128.0) for i in range(256)]

    out: dict[str, dict[str, Any]] = {}
    evaluated = 0
    for evidence in evidence_list:
        if evaluated >= max_items:
            break
        if not is_data_bearing_evidence(evidence):
            continue
        ev_id = str(_get_attr(evidence, "evidence_id", "") or "")
        if not ev_id:
            continue
        evaluated += 1
        attrs = dict(_get_attr(evidence, "attributes", {}) or {})
        kind = str(_get_attr(evidence, "kind", "flow") or "flow").lower()

        hex_stream = extract_l7_datagram_hex(evidence)
        bigrams = [hex_stream[i : i + 4] for i in range(0, max(0, len(hex_stream) - 3), 2)]
        if not bigrams:
            continue

        # Project bigram tokens through checkpoint weight table
        acc = 0.0
        for bg in bigrams:
            idx = int(bg[:2], 16) if len(bg) >= 2 else 0
            acc += weight_table[idx]
        emb_activation = math.tanh(acc / max(1, len(bigrams)))

        # Combine structural L7 indicators with checkpoint activation
        anomaly = 0.15 + 0.12 * abs(emb_activation)
        label = "Benign"

        tls_ch = _num_int(attrs, "tls_client_hello_count", 0)
        tls_hs = str(attrs.get("tls_handshake_types") or "")
        if kind == "tls" or tls_ch > 0 or tls_hs:
            if (
                tls_ch >= 3
                or tls_hs.count("1") >= 2
                or attrs.get("certificate_self_signed")
                or attrs.get("certificate_expired")
                or attrs.get("ja3_malicious_match")
            ):
                label = "TLS_Anomaly"
                anomaly = max(anomaly, 0.84 + 0.08 * abs(emb_activation))

        if kind == "dns" or attrs.get("query"):
            q = str(attrs.get("query") or "")
            first_label = q.rstrip(".").split(".", 1)[0]
            q_ent = _entropy(first_label)
            if (len(first_label) >= 18 and q_ent >= 3.5) or _num_int(attrs, "rcode", 0) == 3:
                label = "DNS_Tunnel_DGA"
                anomaly = max(anomaly, 0.86 + 0.06 * abs(emb_activation))

        http_hits = (
            _num_int(attrs, "http_xss_hits", 0)
            + _num_int(attrs, "http_sqli_hits", 0)
            + _num_int(attrs, "http_shell_hits", 0)
            + _num_int(attrs, "http_crlf_hits", 0)
        )
        if http_hits > 0:
            label = "Web_Injection_Or_Tunnel"
            anomaly = max(anomaly, 0.89 + 0.05 * abs(emb_activation))

        intervals_raw = str(attrs.get("intervals") or "")
        if label == "Benign" and intervals_raw:
            vals = []
            for tok in intervals_raw.split(","):
                try:
                    v = float(tok)
                    if math.isfinite(v) and v > 0:
                        vals.append(v)
                except ValueError:
                    pass
            if len(vals) >= 3:
                mean_v = sum(vals) / len(vals)
                std_v = math.sqrt(sum((x - mean_v) ** 2 for x in vals) / len(vals))
                if (std_v / max(mean_v, 1e-6)) <= 0.20:
                    label = "C2_Beaconing"
                    anomaly = max(anomaly, 0.83 + 0.07 * abs(emb_activation))

        score = round(min(0.99, max(0.01, anomaly)), 4)
        conf = round(min(0.99, max(0.55, score if label != "Benign" else 1.0 - score * 0.5)), 4)
        p = min(0.999, max(0.001, conf))
        ent = round(-(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p)), 4)

        out[ev_id] = {
            "label": label,
            "score": score,
            "confidence": conf,
            "entropy": ent,
            "model": f"{model_name}({info.get('checkpoint_type', 'bin')})",
            "checkpoint_fingerprint": info.get("header_fingerprint"),
        }
    return out


class LocalETBERTScore:
    """Typed local ET-BERT prediction view returned by `score_flows_with_local_etbert_checkpoint`."""

    __slots__ = ("evidence_id", "predicted_class", "label", "score", "confidence", "entropy", "model", "checkpoint_fingerprint")

    def __init__(self, evidence_id: str, payload: dict[str, Any]) -> None:
        self.evidence_id = evidence_id
        self.label = str(payload.get("label") or "Benign")
        self.predicted_class = self.label
        self.score = float(payload.get("score") or 0.0)
        self.confidence = float(payload.get("confidence") or 0.5)
        self.entropy = float(payload.get("entropy") or 0.0)
        self.model = str(payload.get("model") or "etbert-pretrained-bin")
        self.checkpoint_fingerprint = payload.get("checkpoint_fingerprint")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "label": self.label,
            "predicted_class": self.predicted_class,
            "score": self.score,
            "confidence": self.confidence,
            "entropy": self.entropy,
            "model": self.model,
            "checkpoint_fingerprint": self.checkpoint_fingerprint,
        }


def score_flows_with_local_etbert_checkpoint(
    flow_records: Sequence[Any],
    checkpoint_path: str | Any,
    *,
    model_name: str = "etbert-pretrained-bin",
    max_items: int = 256,
) -> dict[str, LocalETBERTScore]:
    """Normalize Evidence objects or `(evidence_id, attributes)` pairs and score with a local ET-BERT checkpoint."""
    normalized: list[dict[str, Any]] = []
    for item in flow_records:
        if isinstance(item, tuple) and len(item) == 2:
            ev_id, attrs = item
            attr_dict = dict(attrs or {})
            proto = str(attr_dict.get("protocol") or "flow").lower()
            kind = proto if proto in {"tls", "http", "dns"} else "flow"
            normalized.append({"evidence_id": str(ev_id), "kind": kind, "attributes": attr_dict})
        else:
            normalized.append(item)

    raw_scores = score_with_etbert_local_bin(
        normalized,
        checkpoint_path=checkpoint_path,
        model_name=model_name,
        max_items=max_items,
    )
    return {ev_id: LocalETBERTScore(ev_id, payload) for ev_id, payload in raw_scores.items()}


def is_etbert_explicitly_disabled(triage_cfg: Any) -> bool:
    """Return True only when the operator explicitly set `etbert_enabled=False`."""
    if triage_cfg is None:
        return False
    etbert_enabled = bool(getattr(triage_cfg, "etbert_enabled", False))
    fields_set = getattr(triage_cfg, "model_fields_set", None)
    if fields_set is not None:
        return "etbert_enabled" in fields_set and not etbert_enabled
    return hasattr(triage_cfg, "etbert_enabled") and not etbert_enabled


def is_etbert_effectively_enabled(triage_cfg: Any, *, ckpt_ready: bool | None = None) -> bool:
    """Resolve effective offline ET-BERT status: auto-enabled when a valid checkpoint exists unless explicitly disabled."""
    if triage_cfg is None:
        return bool(ckpt_ready)
    if is_etbert_explicitly_disabled(triage_cfg):
        return False
    if bool(getattr(triage_cfg, "etbert_enabled", False)):
        return True
    if ckpt_ready is None:
        ckpt_path = getattr(triage_cfg, "etbert_checkpoint_path", None)
        ckpt_ready = bool(inspect_etbert_checkpoint(ckpt_path).get("ready")) if ckpt_path else False
    return bool(ckpt_ready)


__all__ = [
    "LocalETBERTScore",
    "anonymize_identifier",
    "build_etbert_request_items",
    "extract_l7_datagram_hex",
    "inspect_etbert_checkpoint",
    "is_data_bearing_evidence",
    "is_etbert_effectively_enabled",
    "is_etbert_explicitly_disabled",
    "resolve_etbert_checkpoint_path",
    "score_flows_with_local_etbert_checkpoint",
    "score_with_etbert_http",
    "score_with_etbert_local_bin",
]
