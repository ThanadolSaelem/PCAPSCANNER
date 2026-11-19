"""Inference-only ET-BERT L7 datagram scorer and safe checkpoint inspector.

Supports:
  1. Fine-tuned HuggingFace `AutoModelForSequenceClassification` checkpoint directories
     running cleanly on Apple Silicon (`mps`), NVIDIA (`cuda`), or `cpu`.
  2. Safe ZIP / `pickletools.genops` structural inspection of raw `.bin`/`.pt` checkpoints
     (such as UER `pre-trained_model.bin`) without executing arbitrary pickle opcodes.
  3. Zero-dependency calibrated L7 telemetry fallback when no fine-tuned HF weights
     are provided (or when only a raw un-fine-tuned MLM backbone is detected).
"""
from __future__ import annotations

import hashlib
import logging
import math
import pickletools
import re
import zipfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from .schema import TRAFFIC_CLASSES, resolve_device, resolve_torch_dtype

logger = logging.getLogger(__name__)

DATA_BEARING_KINDS = frozenset({"flow", "tls", "http", "dns", "packet"})
NON_L7_KINDS = frozenset({"arp", "icmp", "wlan"})
NON_L7_PROTOS = frozenset({"ARP", "ICMP", "ICMPV6", "WLAN"})
COMMON_L7_PORTS = frozenset({21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443})

_TENSOR_KEY_RE = re.compile(
    rb"\b(?:embedding(?:s)?|encoder|target|classifier|output_layer|pooler|fc_\d+)"
    rb"(?:\.[A-Za-z0-9_]+){1,8}\b"
)
_LAYER_INDEX_RE = re.compile(r"encoder\.(?:transformer|layer)\.(\d+)\.")


def _to_int(val: Any, default: int = 0) -> int:
    if isinstance(val, int) and not isinstance(val, bool):
        return val
    if isinstance(val, float) and math.isfinite(val):
        return int(val)
    if isinstance(val, str):
        stripped = val.strip()
        if stripped.lstrip("-").isdigit():
            return int(stripped)
    return default


def _to_float(val: Any, default: float = 0.0) -> float:
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        fv = float(val)
        return fv if math.isfinite(fv) else default
    if isinstance(val, str):
        try:
            fv = float(val.strip())
            return fv if math.isfinite(fv) else default
        except ValueError:
            return default
    return default


def is_data_bearing_flow(item: Mapping[str, Any]) -> bool:
    """Filter strictly for data-bearing L7/transport traffic (exclude pure L2/header floods)."""
    kind = str(item.get("kind") or "flow").lower()
    attrs = dict(item.get("features") or item.get("metrics") or item.get("attributes") or item)
    proto = str(attrs.get("protocol") or item.get("protocol") or "").upper()
    pkts = max(1, _to_int(attrs.get("packets", item.get("packets", 1)), 1))
    nbytes = _to_int(attrs.get("bytes", item.get("bytes", 0)), 0)
    sp = _to_int(attrs.get("src_port", item.get("src_port", -1)), -1)
    dp = _to_int(attrs.get("dst_port", item.get("dst_port", -1)), -1)

    if kind in NON_L7_KINDS or kind not in DATA_BEARING_KINDS:
        return False
    if proto in NON_L7_PROTOS:
        return False
    if kind in {"tls", "http", "dns"}:
        return True

    if (
        proto in {"TLS", "HTTP", "DNS"}
        or attrs.get("tls_handshake_types")
        or _to_int(attrs.get("tls_client_hello_count"), 0) > 0
        or attrs.get("http_method")
        or attrs.get("http_status_codes")
        or _to_int(attrs.get("http_uri_max_len"), 0) > 0
        or attrs.get("query")
        or _to_int(attrs.get("q_len"), 0) > 0
        or _to_int(attrs.get("telnet_cmd_count"), 0) > 0
        or _to_int(attrs.get("data_len_sum"), 0) > 0
        or _to_int(attrs.get("data_len_max"), 0) > 0
    ):
        return True

    avg_pkt_bytes = nbytes / pkts
    if (dp in COMMON_L7_PORTS or sp in COMMON_L7_PORTS) and avg_pkt_bytes > 74.0:
        return True
    if proto in {"TCP", "UDP"} and pkts >= 2 and avg_pkt_bytes > 90.0:
        return True
    return False


def bytes_to_etbert_bigram_tokens(datagram: bytes | Sequence[int], *, max_len: int = 512) -> list[str]:
    """Convert raw payload bytes / ints into ET-BERT hex-bigram tokens (`ab12`, `12ff`, ...)."""
    seq = list(datagram[: max_len + 1])
    if len(seq) < 2:
        return [f"{int(b) & 0xFF:02x}" for b in seq]
    return [f"{int(seq[i]) & 0xFF:02x}{int(seq[i + 1]) & 0xFF:02x}" for i in range(len(seq) - 1)][:max_len]


def format_etbert_input_text(item: Mapping[str, Any], *, bigram_only: bool = False) -> str:
    """Format datagram/telemetry item into compact input text for ET-BERT Transformer."""
    if item.get("bigram_tokens"):
        toks = " ".join(str(t) for t in list(item["bigram_tokens"])[:256])
        if bigram_only or not str(item.get("state") or "").strip():
            return toks
        return f"{item.get('state', '')} | BURST {toks}".strip()
    feats = dict(item.get("features") or {})
    if feats:
        parts = [f"{k}={v}" for k, v in sorted(feats.items()) if k not in {"src_pseudo", "dst_pseudo"}]
        prefix = "" if bigram_only else "[CLS] "
        return f"{prefix}{item.get('kind', 'flow')} " + " ".join(parts)
    return str(item.get("state") or "")


def _extract_pickle_keys_safe(blob: bytes) -> tuple[list[str], int | None, int | None]:
    """Inspect tensor key names and embedding shape hints via pickletools.genops without unpickling."""
    found_strings: list[str] = []
    seen_set: set[str] = set()
    recent_ints: list[int] = []
    awaiting_emb_shape = 0
    vocab_size: int | None = None
    hidden_size: int | None = None

    try:
        for _opcode, arg, _pos in pickletools.genops(blob):
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
        pass

    for match in _TENSOR_KEY_RE.findall(blob):
        txt = match.decode("ascii", errors="ignore")
        if txt and txt not in seen_set:
            seen_set.add(txt)
            found_strings.append(txt)

    return found_strings, vocab_size, hidden_size


def inspect_etbert_checkpoint(path: str | Path | None) -> dict[str, Any]:
    """Safely classify a checkpoint path into HF classifier dir, UER MLM `.bin`, or invalid."""
    if not path or not str(path).strip():
        return {
            "configured": False,
            "exists": False,
            "format": "none",
            "architecture": "unknown",
            "checkpoint_type": "unconfigured",
            "has_classification_head": False,
            "is_hf_dir": False,
        }

    p = Path(str(path).strip()).expanduser()
    try:
        resolved = p.resolve()
    except OSError:
        resolved = p

    if resolved.is_dir():
        has_cfg = (resolved / "config.json").is_file()
        has_weights = any(
            (resolved / name).is_file()
            for name in ("model.safetensors", "pytorch_model.bin", "adapter_config.json")
        )
        return {
            "configured": True,
            "exists": True,
            "filename": resolved.name,
            "format": "huggingface_dir",
            "architecture": "hf-sequence-classifier" if has_cfg else "unknown_dir",
            "checkpoint_type": "hf_finetuned_classifier" if (has_cfg and has_weights) else "incomplete_dir",
            "has_classification_head": bool(has_cfg and has_weights),
            "is_hf_dir": bool(has_cfg and has_weights),
        }

    if not resolved.is_file():
        return {
            "configured": True,
            "exists": False,
            "filename": resolved.name,
            "format": "missing",
            "architecture": "unknown",
            "checkpoint_type": "missing",
            "has_classification_head": False,
            "is_hf_dir": False,
        }

    try:
        size_bytes = int(resolved.stat().st_size)
        with resolved.open("rb") as fh:
            head = fh.read(512 * 1024)
            tail = b""
            if size_bytes > 512 * 1024 and not head.startswith(b"PK\x03\x04"):
                fh.seek(max(0, size_bytes - 512 * 1024))
                tail = fh.read(512 * 1024)
    except OSError:
        return {
            "configured": True,
            "exists": False,
            "filename": resolved.name,
            "format": "unreadable",
            "architecture": "unknown",
            "checkpoint_type": "unreadable",
            "has_classification_head": False,
            "is_hf_dir": False,
        }

    fmt = "binary_weights"
    if head.startswith(b"PK\x03\x04"):
        fmt = "pytorch_zip"
    elif head.startswith(b"\x80") and len(head) >= 2 and head[1] in (2, 3, 4, 5):
        fmt = "pytorch_pickle"

    scan_blob = head + tail
    if fmt == "pytorch_zip":
        try:
            with zipfile.ZipFile(resolved, "r") as zf:
                for name in zf.namelist():
                    if name.endswith("data.pkl") or name.endswith(".pkl"):
                        with zf.open(name) as zfh:
                            scan_blob = zfh.read(2 * 1024 * 1024)
                        break
        except Exception:
            pass

    parsed_keys, vocab_size, hidden_size = _extract_pickle_keys_safe(scan_blob)
    layer_indices = [int(m.group(1)) for key in parsed_keys if (m := _LAYER_INDEX_RE.search(key))]
    num_layers = (max(layer_indices) + 1) if layer_indices else 0
    has_clf = any(
        any(tok in k for tok in ("output_layer", "classifier", "fc_1.weight", "fc_2.weight"))
        for k in parsed_keys
    )
    has_uer_encoder = any(
        any(tok in k for tok in ("embedding.word_embedding", "encoder.transformer", "target.mlm"))
        for k in parsed_keys
    )
    has_bert_encoder = any(
        any(tok in k for tok in ("word_embeddings", "encoder.layer"))
        for k in parsed_keys
    )

    if has_clf:
        ckpt_type = "finetuned_binary_classifier"
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

    return {
        "configured": True,
        "exists": True,
        "filename": resolved.name,
        "size_bytes": size_bytes,
        "sha256_prefix": hashlib.sha256(head[:65536]).hexdigest()[:16],
        "format": fmt,
        "architecture": arch,
        "checkpoint_type": ckpt_type,
        "num_layers": num_layers,
        "vocab_size": vocab_size,
        "hidden_size": hidden_size,
        "has_classification_head": has_clf,
        "is_hf_dir": False,
    }


class ETBertDatagramScorer:
    """L7 ET-BERT inference scorer for `/etbert/score` (`cuda` / `mps` / `cpu` or fallback)."""

    def __init__(
        self,
        *,
        checkpoint_path: str | Path | None = None,
        device: str = "auto",
        model_name: str = "etbert-l7-datagram",
        id2label: Mapping[int, str] | None = None,
        require_weights: bool = False,
    ) -> None:
        self.checkpoint_path = str(checkpoint_path) if checkpoint_path else None
        self.device = resolve_device(device)
        self.model_name = model_name
        self.id2label = dict(id2label) if id2label else {i: cls for i, cls in enumerate(TRAFFIC_CLASSES)}
        self._tokenizer: Any = None
        self._model: Any = None
        self._bigram_only = False
        self.loaded_weights = False
        self.checkpoint_info: dict[str, Any] = inspect_etbert_checkpoint(self.checkpoint_path)

        if self.checkpoint_path:
            self._load_checkpoint(Path(self.checkpoint_path), require_weights=require_weights)
        elif require_weights:
            raise ValueError("ET-BERT checkpoint path is required when require_weights=True")

    def _load_checkpoint(self, path: Path, *, require_weights: bool = False) -> None:
        expanded = path.expanduser()
        if not expanded.exists():
            raise FileNotFoundError(f"ET-BERT checkpoint path not found: {expanded}")

        info = inspect_etbert_checkpoint(expanded)
        self.checkpoint_info = info

        if expanded.is_file():
            msg = (
                f"ET-BERT file '{expanded.name}' has type '{info.get('checkpoint_type')}' "
                f"(has_classification_head={info.get('has_classification_head')}); "
                "HuggingFace fine-tuned sequence-classification directory is required for neural head inference."
            )
            if require_weights:
                raise ValueError(msg)
            logger.warning("%s Falling back to calibrated L7 telemetry scoring.", msg)
            return

        if not info.get("is_hf_dir"):
            msg = f"ET-BERT directory '{expanded}' is missing HF config.json or model weights."
            if require_weights:
                raise ValueError(msg)
            logger.warning("%s Falling back to calibrated L7 telemetry scoring.", msg)
            return

        try:
            import torch  # noqa: F401
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "Loading neural ET-BERT HF weights requires 'torch' and 'transformers'. "
                "Install with: pip install -r requirements-neural.txt"
            ) from exc

        dtype = resolve_torch_dtype(self.device)
        self._tokenizer = AutoTokenizer.from_pretrained(str(expanded))
        try:
            self._model = AutoModelForSequenceClassification.from_pretrained(str(expanded), dtype=dtype)
        except TypeError as exc:
            if "dtype" not in str(exc):
                raise
            self._model = AutoModelForSequenceClassification.from_pretrained(str(expanded), torch_dtype=dtype)
        self._model.to(self.device)
        self._model.eval()
        cfg_map = getattr(self._model.config, "id2label", None)
        if isinstance(cfg_map, dict) and cfg_map:
            self.id2label = {int(k): str(v) for k, v in cfg_map.items()}
        self._bigram_only = getattr(self._model.config, "etbert_input_mode", None) == "bigram"
        self.loaded_weights = True

    def _fallback_score_item(self, item: Mapping[str, Any]) -> dict[str, Any]:
        """Calibrated L7 telemetry fallback when no fine-tuned ET-BERT HF head is loaded."""
        feats = dict(item.get("features") or item.get("metrics") or {})
        kind = str(item.get("kind") or "flow").lower()
        tls_ch = _to_int(feats.get("tls_client_hello_count"), 0)
        xss = _to_int(feats.get("http_xss_hits"), 0)
        crlf = _to_int(feats.get("http_crlf_hits"), 0)
        sqli = _to_int(feats.get("http_sqli_hits"), 0)
        shell = _to_int(feats.get("http_shell_hits"), 0)
        uri_ent = _to_float(feats.get("http_uri_max_entropy"), 0.0)
        uri_len = _to_int(feats.get("http_uri_max_len"), 0)
        q_ent = _to_float(feats.get("q_ent"), 0.0)
        q_len = _to_int(feats.get("q_len"), 0)
        rcode = _to_int(feats.get("rcode"), 0)
        io_ratio = _to_float(feats.get("io_byte_ratio"), 0.5)
        pkts = _to_int(feats.get("packets"), 1)
        dp = _to_int(feats.get("dst_port"), -1)
        telnet_cmds = _to_int(feats.get("telnet_cmd_count"), 0)

        attack_score = 0.08
        label = "Benign"
        if xss + crlf + sqli + shell > 0 or (uri_len >= 120 and uri_ent >= 4.2):
            label = "Web_Injection_Or_Tunnel"
            attack_score = 0.91
        elif tls_ch >= 3:
            label = "TLS_Anomaly"
            attack_score = 0.87
        elif kind == "dns" and ((q_len >= 20 and q_ent >= 3.5) or rcode == 3):
            label = "DNS_Tunnel_DGA"
            attack_score = 0.86 if q_ent >= 3.5 else 0.72
        elif telnet_cmds > 0 and dp not in (80, 443):
            label = "Protocol_Tunnel"
            attack_score = 0.78
        elif pkts >= 12 and (io_ratio >= 0.96 or io_ratio <= 0.04) and dp in {443, 8443, 4444, 8080}:
            label = "C2_Beaconing"
            attack_score = 0.68

        conf = round(attack_score if label != "Benign" else (1.0 - attack_score), 4)
        p_a = max(1e-6, min(1.0 - 1e-6, attack_score))
        ent = round(-(p_a * math.log2(p_a) + (1.0 - p_a) * math.log2(1.0 - p_a)), 4)
        suffix = (
            "feature-fallback;uer-mlm-unfinetuned"
            if self.checkpoint_info.get("checkpoint_type") == "uer_pretrained_encoder"
            else "feature-fallback"
        )
        return {
            "item_id": item.get("item_id"),
            "label": label,
            "score": round(attack_score, 4),
            "confidence": conf,
            "entropy": ent,
            "model": f"{self.model_name}({suffix})",
            "backend": "feature_fallback",
            "device": self.device,
        }

    def score_batch(
        self,
        items: Sequence[Mapping[str, Any]],
        *,
        max_length: int = 256,
        batch_size: int = 32,
    ) -> list[dict[str, Any]]:
        if not items:
            return []
        if not self.loaded_weights or self._model is None or self._tokenizer is None:
            return [self._fallback_score_item(item) for item in items]

        import torch

        results: list[dict[str, Any]] = []
        benign_idx = next((k for k, v in self.id2label.items() if str(v).lower() == "benign"), None)
        step = max(1, batch_size)
        for start in range(0, len(items), step):
            chunk = items[start : start + step]
            texts = [format_etbert_input_text(item, bigram_only=self._bigram_only) for item in chunk]
            enc = self._tokenizer(
                texts,
                padding=True,
                truncation=True,
                max_length=max_length,
                return_tensors="pt",
            )
            enc = {k: v.to(self.device) for k, v in enc.items()}
            with torch.inference_mode():
                logits = self._model(**enc).logits.float()
                probs = torch.softmax(logits, dim=-1).cpu().tolist()

            for item, p_row in zip(chunk, probs):
                pred_id = max(range(len(p_row)), key=lambda idx: p_row[idx])
                raw_lbl = self.id2label.get(pred_id, "Benign")
                conf = float(p_row[pred_id])
                if benign_idx is not None and benign_idx < len(p_row):
                    anomaly_score = float(1.0 - p_row[benign_idx])
                else:
                    anomaly_score = conf if raw_lbl != "Benign" else (1.0 - conf)
                ent = 0.0
                for pv in p_row:
                    clamped = min(1.0, max(1e-12, float(pv)))
                    ent -= clamped * math.log2(clamped)
                results.append(
                    {
                        "item_id": item.get("item_id"),
                        "label": raw_lbl,
                        "score": round(min(1.0, max(0.0, anomaly_score)), 4),
                        "confidence": round(min(1.0, max(0.0, conf)), 4),
                        "entropy": round(max(0.0, ent), 4),
                        "model": self.model_name,
                        "backend": "neural_hf",
                        "device": self.device,
                    }
                )
        return results


__all__ = [
    "ETBertDatagramScorer",
    "bytes_to_etbert_bigram_tokens",
    "format_etbert_input_text",
    "inspect_etbert_checkpoint",
    "is_data_bearing_flow",
]
