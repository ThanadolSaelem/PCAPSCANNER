"""Inference-only OpenJev LoRA / HF CausalLM scorer + calibrated state-token fallback."""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any, Sequence

from .prompts import resolve_choice_token_ids, to_single_token_choice_prompt
from .schema import (
    DEFAULT_HIGH_THRESHOLD,
    DEFAULT_LOW_THRESHOLD,
    TRAFFIC_CLASSES,
    decision_from_label_conf,
    resolve_device,
    resolve_torch_dtype,
    shannon_ppl_from_probs,
    softmax_logits,
)

_KV_RE = re.compile(r"([A-Za-z0-9_]+)=([^\s]+)")


def _parse_int_token(val: str | None, default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(float(val))
    except ValueError:
        return default


def _parse_float_token(val: str | None, default: float = 0.0) -> float:
    if val is None:
        return default
    try:
        v = float(val)
        return v if math.isfinite(v) else default
    except ValueError:
        return default


def score_state_calibrated_fallback(
    state_text: str,
    *,
    high_threshold: float = DEFAULT_HIGH_THRESHOLD,
    low_threshold: float = DEFAULT_LOW_THRESHOLD,
    model_name: str = "openjev-cal-tier1(state-fallback)",
) -> dict[str, Any]:
    """Calibrated 10-class scorer operating strictly on compact anonymized state tokens."""
    kv = dict(_KV_RE.findall(state_text or ""))
    upper_text = (state_text or "").upper()
    detectors = set(kv.get("det", "").split(",")) if kv.get("det") else set()

    logits: dict[str, float] = {cls: -3.0 for cls in TRAFFIC_CLASSES}
    logits["Benign"] = 1.6

    pkts = _parse_int_token(kv.get("pkts"), 1)
    nbytes = _parse_int_token(kv.get("bytes"), 0)

    # 1. ARP Spoofing / ARP Sweep
    arp_conflicts = _parse_int_token(kv.get("arp_conflicts"), 0)
    arp_replies = _parse_int_token(kv.get("arp_replies"), 0)
    arp_scan = _parse_int_token(kv.get("arp_scan"), 0)
    if arp_conflicts > 0 or "arp_spoofing_conflict" in detectors:
        logits["ARP_Spoofing"] += 6.2
        logits["Benign"] -= 2.4
    elif arp_scan >= 5 or arp_replies >= 15 or "arp_scan_burst" in detectors:
        logits["Port_Scan_Recon"] += 4.5
        logits["ARP_Spoofing"] += 2.2
        logits["Benign"] -= 1.4

    # 2. Port Scan / Recon
    src_ports = _parse_int_token(kv.get("src_ports"), 0)
    null_f = _parse_int_token(kv.get("null_f"), 0)
    xmas_f = _parse_int_token(kv.get("xmas_f"), 0)
    if "tcp_destination_port_spread" in detectors or src_ports >= 20 or null_f >= 3 or xmas_f >= 3:
        logits["Port_Scan_Recon"] += 5.0
        logits["Benign"] -= 2.0

    # 3. DoS Flood
    rst_cnt = _parse_int_token(kv.get("rst"), 0)
    syn_cnt = _parse_int_token(kv.get("syn"), 0)
    is_icmp = " ICMP " in upper_text
    if (
        "icmp_smurf_or_flood" in detectors
        or "tcp_flood_or_rst_storm" in detectors
        or rst_cnt >= 20
        or (is_icmp and pkts >= 50)
        or (syn_cnt >= 100 and nbytes <= pkts * 74)
    ):
        logits["DoS_Flood"] += 5.3
        logits["Benign"] -= 2.1

    # 4. DNS Tunnel / DGA
    q_len = _parse_int_token(kv.get("q_len"), 0)
    q_ent = _parse_float_token(kv.get("q_ent"), 0.0)
    rcode = _parse_int_token(kv.get("rcode"), 0)
    if "dns_nxdomain_entropy" in detectors or (q_len >= 20 and q_ent >= 3.5):
        logits["DNS_Tunnel_DGA"] += 5.4
        logits["Benign"] -= 1.9
    elif rcode == 3:
        logits["DNS_Tunnel_DGA"] += 3.1
        logits["Benign"] -= 0.4

    # 5. C2 Beaconing
    intervals_raw = kv.get("intervals", "")
    if "periodic_tcp_connection_starts" in detectors:
        logits["C2_Beaconing"] += 5.4
        logits["Benign"] -= 1.9
    elif intervals_raw:
        vals: list[float] = []
        for item in intervals_raw.split(","):
            try:
                fv = float(item)
                if math.isfinite(fv) and fv > 0:
                    vals.append(fv)
            except ValueError:
                pass
        if len(vals) >= 3:
            mean_v = sum(vals) / len(vals)
            std_v = math.sqrt(sum((v - mean_v) ** 2 for v in vals) / len(vals))
            if (std_v / max(mean_v, 1e-6)) <= 0.20:
                logits["C2_Beaconing"] += 4.3
                logits["Benign"] -= 1.0

    # 6. TLS Anomaly
    tls_ch = _parse_int_token(kv.get("tls_ch"), 0)
    tls_hs = kv.get("tls_hs", "")
    if "tls_renegotiation_anomaly" in detectors or tls_ch >= 3 or tls_hs.count("1") >= 2:
        logits["TLS_Anomaly"] += 5.1
        logits["Benign"] -= 1.6

    # 7. Web Injection / Tunnel
    web_hits = (
        _parse_int_token(kv.get("xss"), 0)
        + _parse_int_token(kv.get("crlf"), 0)
        + _parse_int_token(kv.get("sqli"), 0)
        + _parse_int_token(kv.get("shell"), 0)
    )
    uri_len = _parse_int_token(kv.get("uri_len"), 0)
    uri_ent = _parse_float_token(kv.get("uri_ent"), 0.0)
    if "http_suspicious_uri" in detectors or web_hits > 0 or (uri_len >= 120 and uri_ent >= 4.2):
        logits["Web_Injection_Or_Tunnel"] += 5.6
        logits["Benign"] -= 2.2

    # 8. WiFi / 802.11 Attacks
    wlan_deauth = _parse_int_token(kv.get("wlan_deauth"), 0)
    wlan_auth = _parse_int_token(kv.get("wlan_auth"), 0)
    if wlan_deauth >= 5 or wlan_auth >= 25 or (" WLAN " in upper_text and wlan_deauth > 0):
        logits["WiFi_Attack"] += 5.8
        logits["Benign"] -= 2.2

    # 9. Protocol Tunnel (Telnet / ICMP payload tunnel)
    telnet_cmds = _parse_int_token(kv.get("telnet_cmds"), 0)
    icmp_dlen = _parse_int_token(kv.get("icmp_dlen"), 0)
    if telnet_cmds > 0 or icmp_dlen >= 1024:
        logits["Protocol_Tunnel"] += 4.9
        logits["Benign"] -= 1.6

    # 10. Fuse upstream ET-BERT L7 tag when present in compact state
    et_lbl = kv.get("etbert_lbl", "")
    et_conf = _parse_float_token(kv.get("etbert_conf"), 0.0)
    if et_lbl in logits and et_conf > 0.50:
        delta = 2.0 + 4.0 * (et_conf - 0.50)
        if et_lbl == "Benign":
            logits["Benign"] += delta * 0.6
        else:
            logits[et_lbl] += delta
            logits["Benign"] -= delta * 0.5

    probs = softmax_logits(logits)
    pred_label = max(probs, key=lambda k: probs[k])
    conf = round(float(probs[pred_label]), 4)
    ppl = shannon_ppl_from_probs(probs)
    decision = decision_from_label_conf(pred_label, conf, high_threshold, low_threshold)
    return {
        "label": pred_label,
        "predicted_class": pred_label,
        "confidence": conf,
        "ppl": ppl,
        "decision": decision,
        "probabilities": probs,
        "model": model_name,
    }


class OpenJevTier1Scorer:
    """Calibrated 10-class OpenJev / RL-LoRA scorer for `/v1/systemone` and `/classify`."""

    def __init__(
        self,
        *,
        checkpoint_path: str | Path | None = None,
        base_model: str | None = None,
        device: str = "auto",
        model_name: str = "openjev-cal-tier1",
        require_weights: bool = False,
    ) -> None:
        self.checkpoint_path = str(checkpoint_path) if checkpoint_path else None
        self.base_model = base_model
        self.device = resolve_device(device)
        self.model_name = model_name
        self.loaded_weights = False
        self.checkpoint_mode = "state_fallback"
        self._model: Any = None
        self._tokenizer: Any = None
        self._choice_ids: list[int] = []

        if self.checkpoint_path:
            self._load_checkpoint(Path(self.checkpoint_path))
        elif require_weights:
            raise ValueError("OpenJev checkpoint directory is required when require_weights=True")

    def _load_checkpoint(self, ckpt_dir: Path) -> None:
        expanded = ckpt_dir.expanduser()
        if not expanded.is_dir():
            raise FileNotFoundError(f"OpenJev checkpoint directory not found: {expanded}")

        adapter_dir = expanded / "lora_adapter" if (expanded / "lora_adapter").is_dir() else expanded
        is_peft = (adapter_dir / "adapter_config.json").is_file()
        is_hf_full = (adapter_dir / "config.json").is_file()
        if not is_peft and not is_hf_full:
            raise ValueError(
                f"Directory '{expanded}' is missing both 'adapter_config.json' and 'config.json'."
            )

        try:
            import torch  # noqa: F401
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "Loading neural OpenJev weights requires 'torch' and 'transformers'. "
                "Install with: pip install -r requirements-neural.txt"
            ) from exc

        cfg_file = expanded / "tier1_config.json"
        tier1_meta = json.loads(cfg_file.read_text(encoding="utf-8")) if cfg_file.is_file() else {}
        base_name = self.base_model or tier1_meta.get("base_model")
        dtype = resolve_torch_dtype(self.device)

        def _load_causal_lm(pretrained_ref: str) -> Any:
            try:
                return AutoModelForCausalLM.from_pretrained(pretrained_ref, dtype=dtype)
            except TypeError as exc:
                if "dtype" not in str(exc):
                    raise
                return AutoModelForCausalLM.from_pretrained(pretrained_ref, torch_dtype=dtype)

        if is_peft:
            try:
                from peft import PeftConfig, PeftModel
            except ImportError as exc:
                raise RuntimeError(
                    "Loading a PEFT LoRA checkpoint requires 'peft'. "
                    "Install with: pip install -r requirements-neural.txt"
                ) from exc

            peft_cfg = PeftConfig.from_pretrained(str(adapter_dir))
            resolved_base = base_name or getattr(peft_cfg, "base_model_name_or_path", None)
            if not resolved_base:
                raise ValueError(
                    f"PEFT adapter '{adapter_dir}' does not specify base_model_name_or_path; pass --base-model."
                )
            self._tokenizer = AutoTokenizer.from_pretrained(str(adapter_dir))
            base = _load_causal_lm(resolved_base)
            self._model = PeftModel.from_pretrained(base, str(adapter_dir))
            self.checkpoint_mode = "neural_lora"
        else:
            self._tokenizer = AutoTokenizer.from_pretrained(str(adapter_dir))
            self._model = _load_causal_lm(str(adapter_dir))
            self.checkpoint_mode = "neural_hf"

        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token
        self._tokenizer.padding_side = "right"
        self._model.to(self.device)
        self._model.eval()

        raw_ids = tier1_meta.get("choice_token_ids") or resolve_choice_token_ids(self._tokenizer)
        choice_ids = [int(i) for i in raw_ids]
        if len(choice_ids) != len(TRAFFIC_CLASSES) or len(set(choice_ids)) != len(TRAFFIC_CLASSES):
            raise ValueError(f"Expected 10 distinct choice_token_ids, got: {choice_ids}")

        self._choice_ids = choice_ids
        self.loaded_weights = True

    def score_states(
        self,
        states: Sequence[str],
        *,
        high_threshold: float = DEFAULT_HIGH_THRESHOLD,
        low_threshold: float = DEFAULT_LOW_THRESHOLD,
        max_length: int = 384,
        batch_size: int = 16,
    ) -> list[dict[str, Any]]:
        if not states:
            return []
        if not self.loaded_weights or self._model is None or self._tokenizer is None:
            return [
                score_state_calibrated_fallback(
                    st,
                    high_threshold=high_threshold,
                    low_threshold=low_threshold,
                    model_name=f"{self.model_name}(state-fallback)",
                )
                for st in states
            ]

        import torch

        choice_tensor = torch.tensor(self._choice_ids, dtype=torch.long, device=self.device)
        results: list[dict[str, Any]] = []
        step = max(1, batch_size)
        for start in range(0, len(states), step):
            chunk = states[start : start + step]
            prompts = [to_single_token_choice_prompt(st) for st in chunk]
            enc = self._tokenizer(
                prompts,
                padding=True,
                truncation=True,
                max_length=max_length,
                return_tensors="pt",
            )
            enc = {k: v.to(self.device) for k, v in enc.items()}
            with torch.inference_mode():
                outputs = self._model(**enc)
                seq_pos = (enc["attention_mask"].sum(dim=-1) - 1).clamp(min=0)
                batch_idx = torch.arange(len(chunk), device=self.device)
                last_logits = outputs.logits[batch_idx, seq_pos]
                choice_logits = last_logits.index_select(dim=-1, index=choice_tensor).float()
                prob_rows = torch.softmax(choice_logits, dim=-1).cpu().tolist()

            for prow in prob_rows:
                probs = {cls: round(float(prow[i]), 6) for i, cls in enumerate(TRAFFIC_CLASSES)}
                best_idx = max(range(len(TRAFFIC_CLASSES)), key=lambda idx: prow[idx])
                pred_label = TRAFFIC_CLASSES[best_idx]
                conf = round(float(probs[pred_label]), 4)
                ppl = shannon_ppl_from_probs(probs)
                results.append(
                    {
                        "label": pred_label,
                        "predicted_class": pred_label,
                        "confidence": conf,
                        "ppl": ppl,
                        "decision": decision_from_label_conf(pred_label, conf, high_threshold, low_threshold),
                        "probabilities": probs,
                        "model": self.model_name,
                    }
                )
        return results


__all__ = [
    "OpenJevTier1Scorer",
    "score_state_calibrated_fallback",
]
