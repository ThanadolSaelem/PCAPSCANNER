"""Convert a fine-tuned UER / ET-BERT `.bin` checkpoint into a HuggingFace BERT directory.

Usage:
    python -m tier1_inference.convert_uer \
      --bin /path/to/finetuned_model_resumed.bin \
      --vocab /path/to/encryptd_vocab.txt \
      --uer-config /path/to/bert_base_config.json \
      --output ./models/etbert-l7
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


def _strip_prefix(key: str) -> str:
    for prefix in ("module.", "model."):
        if key.startswith(prefix):
            return key[len(prefix) :]
    return key


def _tensor_shape(tensor: Any) -> tuple[int, ...]:
    shape = getattr(tensor, "shape", None)
    if shape is None:
        return ()
    return tuple(int(dim) for dim in shape)


def _clone_tensor(tensor: Any) -> Any:
    if hasattr(tensor, "detach"):
        tensor = tensor.detach()
    if hasattr(tensor, "cpu"):
        tensor = tensor.cpu()
    if hasattr(tensor, "clone"):
        return tensor.clone()
    return tensor


def _slice_rows(tensor: Any, start: int, end: int) -> Any:
    sliced = tensor[start:end]
    return _clone_tensor(sliced)


def _pick_key(state: Mapping[str, Any], *candidates: str) -> tuple[str, Any] | None:
    for name in candidates:
        if name in state:
            return name, state[name]
    return None


def load_uer_config(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    cfg_path = Path(path).expanduser()
    if not cfg_path.is_file():
        raise FileNotFoundError(f"UER config file not found: {cfg_path}")
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"UER config must be a JSON object: {cfg_path}")
    return data


def load_labels(labels_path: str | Path | None, num_labels: int) -> tuple[dict[int, str], dict[str, int]]:
    if num_labels <= 0:
        raise ValueError(f"num_labels must be positive, got {num_labels}")

    if not labels_path:
        id2label = {idx: f"Label_{idx}" for idx in range(num_labels)}
        label2id = {name: idx for idx, name in id2label.items()}
        return id2label, label2id

    p = Path(labels_path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"Labels file not found: {p}")

    raw_text = p.read_text(encoding="utf-8").strip()
    id2label: dict[int, str] = {}

    if p.suffix.lower() == ".json":
        parsed = json.loads(raw_text)
        if isinstance(parsed, list):
            for idx, item in enumerate(parsed):
                id2label[idx] = str(item).strip()
        elif isinstance(parsed, dict):
            # Support either {"0": "Benign", ...} or {"Benign": 0, ...}
            keys_are_ints = all(str(k).lstrip("-").isdigit() for k in parsed)
            if keys_are_ints:
                for k, v in parsed.items():
                    id2label[int(k)] = str(v).strip()
            else:
                for k, v in parsed.items():
                    id2label[int(v)] = str(k).strip()
        else:
            raise ValueError(f"Unsupported JSON label structure in {p}")
    else:
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
        for idx, line in enumerate(lines):
            if "\t" in line:
                parts = [seg.strip() for seg in line.split("\t") if seg.strip()]
                if len(parts) >= 2 and parts[0].isdigit():
                    id2label[int(parts[0])] = parts[1]
                    continue
                if len(parts) >= 2 and parts[1].isdigit():
                    id2label[int(parts[1])] = parts[0]
                    continue
            id2label[idx] = line

    if len(id2label) != num_labels:
        raise ValueError(
            f"Label count mismatch: {p} defines {len(id2label)} labels, "
            f"but checkpoint head has {num_labels} output classes."
        )
    for idx in range(num_labels):
        if idx not in id2label or not id2label[idx]:
            raise ValueError(f"Missing label entry for class index {idx} in {p}")
    label2id = {name: idx for idx, name in id2label.items()}
    return id2label, label2id


def build_hf_bert_config_dict(
    *,
    vocab_size: int,
    hidden_size: int,
    num_hidden_layers: int,
    intermediate_size: int,
    max_position_embeddings: int,
    num_attention_heads: int,
    num_labels: int,
    id2label: Mapping[int, str],
    hidden_act: str = "gelu",
    dropout: float = 0.1,
    layer_norm_eps: float = 1e-6,
    type_vocab_size: int = 2,
    input_mode: str = "bigram",
) -> dict[str, Any]:
    return {
        "architectures": ["BertForSequenceClassification"],
        "model_type": "bert",
        "vocab_size": int(vocab_size),
        "hidden_size": int(hidden_size),
        "num_hidden_layers": int(num_hidden_layers),
        "num_attention_heads": int(num_attention_heads),
        "intermediate_size": int(intermediate_size),
        "hidden_act": str(hidden_act),
        "hidden_dropout_prob": float(dropout),
        "attention_probs_dropout_prob": float(dropout),
        "max_position_embeddings": int(max_position_embeddings),
        "type_vocab_size": int(type_vocab_size),
        "initializer_range": 0.02,
        "layer_norm_eps": float(layer_norm_eps),
        "pad_token_id": 0,
        "position_embedding_type": "absolute",
        "use_cache": True,
        "num_labels": int(num_labels),
        "id2label": {str(idx): id2label[idx] for idx in sorted(id2label)},
        "label2id": {id2label[idx]: int(idx) for idx in sorted(id2label)},
        "etbert_source_format": "uer",
        "etbert_input_mode": input_mode,
    }


def map_uer_state_dict_to_hf_bert(
    raw_state: Mapping[str, Any],
    *,
    uer_config: Mapping[str, Any] | None = None,
    allow_untrained_head: bool = False,
    fallback_num_labels: int = 10,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Map UER ET-BERT `state_dict` keys cleanly to HF `BertForSequenceClassification`."""
    state: dict[str, Any] = {_strip_prefix(str(k)): v for k, v in raw_state.items()}
    cfg = dict(uer_config or {})

    word_emb_hit = _pick_key(state, "embedding.word_embedding.weight", "embedding.word_embeddings.weight")
    pos_emb_hit = _pick_key(state, "embedding.position_embedding.weight", "embedding.pos_embedding.weight")
    seg_emb_hit = _pick_key(state, "embedding.segment_embedding.weight", "embedding.seg_embedding.weight")
    if word_emb_hit is None or pos_emb_hit is None:
        raise ValueError(
            "Checkpoint does not look like a UER ET-BERT model "
            "(missing 'embedding.word_embedding.weight' or 'embedding.position_embedding.weight')."
        )

    word_emb = word_emb_hit[1]
    pos_emb = pos_emb_hit[1]
    vocab_size, hidden_size = _tensor_shape(word_emb)
    max_pos = _tensor_shape(pos_emb)[0]

    layer_ids: set[int] = set()
    for key in state:
        if key.startswith("encoder.transformer."):
            parts = key.split(".")
            if len(parts) >= 3 and parts[2].isdigit():
                layer_ids.add(int(parts[2]))
    inferred_layers = (max(layer_ids) + 1) if layer_ids else 0
    num_layers = int(cfg.get("layers_num") or inferred_layers or 12)
    parameter_sharing = bool(cfg.get("parameter_sharing", False))

    if 0 not in layer_ids:
        raise ValueError("Checkpoint is missing 'encoder.transformer.0.*' layers.")

    ff_key = _pick_key(state, "encoder.transformer.0.feed_forward.linear_1.weight")
    inferred_ff = _tensor_shape(ff_key[1])[0] if ff_key is not None else (hidden_size * 4)
    intermediate_size = int(cfg.get("feedforward_size") or inferred_ff)
    num_heads = int(cfg.get("heads_num") or max(1, hidden_size // 64))

    hf_state: dict[str, Any] = {}
    hf_state["bert.embeddings.word_embeddings.weight"] = _clone_tensor(word_emb)
    hf_state["bert.embeddings.position_embeddings.weight"] = _clone_tensor(pos_emb)

    if seg_emb_hit is not None:
        seg_emb = seg_emb_hit[1]
        seg_rows = _tensor_shape(seg_emb)[0]
        if seg_rows >= 3:
            # UER seg_id 0 is PAD, 1 is segment A, 2 is segment B; HF uses 0=A, 1=B.
            hf_state["bert.embeddings.token_type_embeddings.weight"] = _slice_rows(seg_emb, 1, 3)
        elif seg_rows == 2:
            hf_state["bert.embeddings.token_type_embeddings.weight"] = _clone_tensor(seg_emb)
        else:
            raise ValueError(f"Unexpected segment_embedding row count: {seg_rows}")

    emb_ln_w = _pick_key(state, "embedding.layer_norm.gamma", "embedding.layer_norm.weight")
    emb_ln_b = _pick_key(state, "embedding.layer_norm.beta", "embedding.layer_norm.bias")
    if emb_ln_w is None or emb_ln_b is None:
        raise ValueError("Checkpoint is missing 'embedding.layer_norm.{gamma,beta}'.")
    hf_state["bert.embeddings.LayerNorm.weight"] = _clone_tensor(emb_ln_w[1])
    hf_state["bert.embeddings.LayerNorm.bias"] = _clone_tensor(emb_ln_b[1])

    for layer_idx in range(num_layers):
        src_idx = 0 if (parameter_sharing and f"encoder.transformer.{layer_idx}.self_attn.linear_layers.0.weight" not in state) else layer_idx
        u_prefix = f"encoder.transformer.{src_idx}"
        h_prefix = f"bert.encoder.layer.{layer_idx}"

        qkv_map = (
            ("0", "query"),
            ("1", "key"),
            ("2", "value"),
        )
        for qkv_idx, qkv_name in qkv_map:
            for suffix in ("weight", "bias"):
                k = f"{u_prefix}.self_attn.linear_layers.{qkv_idx}.{suffix}"
                if k in state:
                    hf_state[f"{h_prefix}.attention.self.{qkv_name}.{suffix}"] = _clone_tensor(state[k])

        for suffix in ("weight", "bias"):
            out_k = f"{u_prefix}.self_attn.final_linear.{suffix}"
            if out_k in state:
                hf_state[f"{h_prefix}.attention.output.dense.{suffix}"] = _clone_tensor(state[out_k])

        ln1_w = _pick_key(state, f"{u_prefix}.layer_norm_1.gamma", f"{u_prefix}.layer_norm_1.weight")
        ln1_b = _pick_key(state, f"{u_prefix}.layer_norm_1.beta", f"{u_prefix}.layer_norm_1.bias")
        if ln1_w is None or ln1_b is None:
            raise ValueError(f"Missing layer_norm_1 parameters in transformer layer {src_idx}")
        hf_state[f"{h_prefix}.attention.output.LayerNorm.weight"] = _clone_tensor(ln1_w[1])
        hf_state[f"{h_prefix}.attention.output.LayerNorm.bias"] = _clone_tensor(ln1_b[1])

        for suffix in ("weight", "bias"):
            ff1_k = f"{u_prefix}.feed_forward.linear_1.{suffix}"
            ff2_k = f"{u_prefix}.feed_forward.linear_2.{suffix}"
            if ff1_k in state:
                hf_state[f"{h_prefix}.intermediate.dense.{suffix}"] = _clone_tensor(state[ff1_k])
            if ff2_k in state:
                hf_state[f"{h_prefix}.output.dense.{suffix}"] = _clone_tensor(state[ff2_k])

        ln2_w = _pick_key(state, f"{u_prefix}.layer_norm_2.gamma", f"{u_prefix}.layer_norm_2.weight")
        ln2_b = _pick_key(state, f"{u_prefix}.layer_norm_2.beta", f"{u_prefix}.layer_norm_2.bias")
        if ln2_w is None or ln2_b is None:
            raise ValueError(f"Missing layer_norm_2 parameters in transformer layer {src_idx}")
        hf_state[f"{h_prefix}.output.LayerNorm.weight"] = _clone_tensor(ln2_w[1])
        hf_state[f"{h_prefix}.output.LayerNorm.bias"] = _clone_tensor(ln2_b[1])

    # Classifier head (`output_layer_1` = pooled dense [H, H], `output_layer_2` = logits [C, H])
    has_head = "output_layer_1.weight" in state and "output_layer_2.weight" in state
    if has_head:
        hf_state["bert.pooler.dense.weight"] = _clone_tensor(state["output_layer_1.weight"])
        if "output_layer_1.bias" in state:
            hf_state["bert.pooler.dense.bias"] = _clone_tensor(state["output_layer_1.bias"])
        clf_w = state["output_layer_2.weight"]
        num_labels = _tensor_shape(clf_w)[0]
        hf_state["classifier.weight"] = _clone_tensor(clf_w)
        if "output_layer_2.bias" in state:
            hf_state["classifier.bias"] = _clone_tensor(state["output_layer_2.bias"])
    else:
        if not allow_untrained_head:
            raise ValueError(
                "This UER checkpoint does not contain a fine-tuned classification head "
                "('output_layer_1.weight' / 'output_layer_2.weight'). It appears to be a pre-trained MLM encoder "
                "(e.g. pre-trained_model.bin). Convert your fine-tuned checkpoint (such as finetuned_model_resumed.bin) "
                "or pass --allow-untrained-head to export an un-tuned classification head."
            )
        num_labels = int(fallback_num_labels)
        if "target.sp.linear.weight" in state and _tensor_shape(state["target.sp.linear.weight"]) == (hidden_size, hidden_size):
            hf_state["bert.pooler.dense.weight"] = _clone_tensor(state["target.sp.linear.weight"])
            if "target.sp.linear.bias" in state:
                hf_state["bert.pooler.dense.bias"] = _clone_tensor(state["target.sp.linear.bias"])

    meta = {
        "vocab_size": vocab_size,
        "hidden_size": hidden_size,
        "num_hidden_layers": num_layers,
        "intermediate_size": intermediate_size,
        "max_position_embeddings": max_pos,
        "num_attention_heads": num_heads,
        "num_labels": num_labels,
        "has_classification_head": has_head,
        "hidden_act": str(cfg.get("hidden_act") or "gelu"),
        "dropout": float(cfg.get("dropout") if cfg.get("dropout") is not None else 0.1),
        "has_segment_embedding": seg_emb_hit is not None,
    }
    return hf_state, meta


def write_hf_tokenizer_files(
    vocab_path: str | Path,
    output_dir: str | Path,
    *,
    expected_vocab_size: int,
    max_position_embeddings: int = 512,
) -> Path:
    src = Path(vocab_path).expanduser()
    if not src.is_file():
        raise FileNotFoundError(f"Vocabulary file not found: {src}")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    dst_vocab = out_dir / "vocab.txt"

    raw_lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(raw_lines) == expected_vocab_size:
        shutil.copyfile(src, dst_vocab)
    elif len(raw_lines) < expected_vocab_size:
        padded = list(raw_lines)
        for idx in range(len(raw_lines), expected_vocab_size):
            padded.append(f"[unused_uer_{idx}]")
        dst_vocab.write_text("\n".join(padded) + "\n", encoding="utf-8")
    else:
        truncated = raw_lines[:expected_vocab_size]
        dst_vocab.write_text("\n".join(truncated) + "\n", encoding="utf-8")

    tok_cfg = {
        "do_lower_case": False,
        "do_basic_tokenize": True,
        "tokenize_chinese_chars": False,
        "strip_accents": None,
        "unk_token": "[UNK]",
        "sep_token": "[SEP]",
        "pad_token": "[PAD]",
        "cls_token": "[CLS]",
        "mask_token": "[MASK]",
        "model_max_length": int(max_position_embeddings),
        "tokenizer_class": "BertTokenizer",
    }
    (out_dir / "tokenizer_config.json").write_text(json.dumps(tok_cfg, indent=2) + "\n", encoding="utf-8")

    special_map = {
        "unk_token": "[UNK]",
        "sep_token": "[SEP]",
        "pad_token": "[PAD]",
        "cls_token": "[CLS]",
        "mask_token": "[MASK]",
    }
    (out_dir / "special_tokens_map.json").write_text(json.dumps(special_map, indent=2) + "\n", encoding="utf-8")
    return dst_vocab


def convert_uer_checkpoint(
    *,
    bin_path: str | Path,
    vocab_path: str | Path,
    output_dir: str | Path,
    uer_config_path: str | Path | None = None,
    labels_path: str | Path | None = None,
    input_mode: str = "bigram",
    allow_untrained_head: bool = False,
    fallback_num_labels: int = 10,
    unsafe_pickle: bool = False,
    verify: bool = True,
) -> dict[str, Any]:
    """Convert a UER ET-BERT `.bin` checkpoint to a self-contained HuggingFace directory."""
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, BertConfig, BertForSequenceClassification
    except ImportError as exc:
        raise RuntimeError(
            "Converting UER checkpoints requires 'torch' and 'transformers'. "
            "Install with: pip install -r requirements-neural.txt"
        ) from exc

    bin_file = Path(bin_path).expanduser()
    if not bin_file.is_file():
        raise FileNotFoundError(f"UER checkpoint file not found: {bin_file}")

    uer_cfg = load_uer_config(uer_config_path)

    load_kwargs: dict[str, Any] = {"map_location": "cpu"}
    if not unsafe_pickle:
        load_kwargs["weights_only"] = True
    else:
        load_kwargs["weights_only"] = False

    try:
        loaded = torch.load(str(bin_file), **load_kwargs)
    except TypeError:
        loaded = torch.load(str(bin_file), map_location="cpu")

    if isinstance(loaded, dict):
        if "state_dict" in loaded and isinstance(loaded["state_dict"], Mapping):
            raw_state = loaded["state_dict"]
        elif "model" in loaded and isinstance(loaded["model"], Mapping):
            raw_state = loaded["model"]
        else:
            raw_state = loaded
    else:
        raise ValueError(f"Expected state_dict mapping inside {bin_file}, got {type(loaded).__name__}")

    hf_state, meta = map_uer_state_dict_to_hf_bert(
        raw_state,
        uer_config=uer_cfg,
        allow_untrained_head=allow_untrained_head,
        fallback_num_labels=fallback_num_labels,
    )

    id2label, _label2id = load_labels(labels_path, meta["num_labels"])
    out_path = Path(output_dir).expanduser().resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    cfg_dict = build_hf_bert_config_dict(
        vocab_size=meta["vocab_size"],
        hidden_size=meta["hidden_size"],
        num_hidden_layers=meta["num_hidden_layers"],
        intermediate_size=meta["intermediate_size"],
        max_position_embeddings=meta["max_position_embeddings"],
        num_attention_heads=meta["num_attention_heads"],
        num_labels=meta["num_labels"],
        id2label=id2label,
        hidden_act=meta["hidden_act"],
        dropout=meta["dropout"],
        input_mode=input_mode,
    )

    hf_config = BertConfig.from_dict(cfg_dict)
    hf_model = BertForSequenceClassification(hf_config)
    missing, unexpected = hf_model.load_state_dict(hf_state, strict=bool(meta["has_classification_head"]))
    if meta["has_classification_head"] and (missing or unexpected):
        raise RuntimeError(
            f"State dict conversion mismatch (missing={missing}, unexpected={unexpected})"
        )

    hf_model.eval()
    hf_model.save_pretrained(str(out_path))
    # Persist custom metadata fields (`etbert_source_format`, `etbert_input_mode`) explicitly in config.json
    saved_cfg_path = out_path / "config.json"
    saved_cfg = json.loads(saved_cfg_path.read_text(encoding="utf-8"))
    saved_cfg["etbert_source_format"] = "uer"
    saved_cfg["etbert_input_mode"] = input_mode
    saved_cfg_path.write_text(json.dumps(saved_cfg, indent=2) + "\n", encoding="utf-8")

    write_hf_tokenizer_files(
        vocab_path,
        out_path,
        expected_vocab_size=meta["vocab_size"],
        max_position_embeddings=meta["max_position_embeddings"],
    )

    verified = False
    if verify:
        tok = AutoTokenizer.from_pretrained(str(out_path))
        reloaded = AutoModelForSequenceClassification.from_pretrained(str(out_path))
        reloaded.eval()
        sample = tok("1603 0301 0200 00f4", return_tensors="pt", truncation=True, max_length=32)
        with torch.inference_mode():
            logits = reloaded(**sample).logits
        if tuple(logits.shape) != (1, meta["num_labels"]):
            raise RuntimeError(f"Verification logits shape mismatch: {tuple(logits.shape)}")
        if not bool(torch.isfinite(logits).all()):
            raise RuntimeError("Verification logits contain non-finite values.")
        verified = True

    return {
        "output_dir": str(out_path),
        "num_labels": meta["num_labels"],
        "hidden_size": meta["hidden_size"],
        "num_hidden_layers": meta["num_hidden_layers"],
        "vocab_size": meta["vocab_size"],
        "has_classification_head": meta["has_classification_head"],
        "verified": verified,
        "input_mode": input_mode,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tier1_inference.convert_uer",
        description="Convert a UER / ET-BERT .bin checkpoint into a HuggingFace BertForSequenceClassification directory.",
    )
    p.add_argument("--bin", required=True, help="Path to UER .bin checkpoint (e.g. models/finetuned_model_resumed.bin)")
    p.add_argument("--vocab", required=True, help="Path to ET-BERT vocabulary file (e.g. models/encryptd_vocab.txt)")
    p.add_argument(
        "--uer-config",
        default=None,
        help="Optional path to UER JSON model config (e.g. bert_base_config.json)",
    )
    p.add_argument(
        "--labels",
        default=None,
        help="Optional JSON or newline label file mapping indices to human-readable class names",
    )
    p.add_argument("--output", required=True, help="Destination HuggingFace model directory (e.g. ./models/etbert-l7)")
    p.add_argument(
        "--input-mode",
        choices=["bigram", "text"],
        default="bigram",
        help="Input formatting preference stored in config.json for tier1_inference",
    )
    p.add_argument(
        "--allow-untrained-head",
        action="store_true",
        help="Allow exporting a pre-trained UER MLM encoder with an initialized (untrained) classifier head",
    )
    p.add_argument(
        "--fallback-num-labels",
        type=int,
        default=10,
        help="Number of labels if --allow-untrained-head is used",
    )
    p.add_argument(
        "--unsafe-pickle",
        action="store_true",
        help="Use torch.load(..., weights_only=False) only if weights_only=True fails on legacy checkpoints",
    )
    p.add_argument("--no-verify", action="store_true", help="Skip round-trip tokenizer + model forward-pass check")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        summary = convert_uer_checkpoint(
            bin_path=args.bin,
            vocab_path=args.vocab,
            output_dir=args.output,
            uer_config_path=args.uer_config,
            labels_path=args.labels,
            input_mode=args.input_mode,
            allow_untrained_head=args.allow_untrained_head,
            fallback_num_labels=args.fallback_num_labels,
            unsafe_pickle=args.unsafe_pickle,
            verify=not args.no_verify,
        )
    except Exception as exc:
        print(f"[tier1-convert-uer] ERROR: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "build_hf_bert_config_dict",
    "convert_uer_checkpoint",
    "load_labels",
    "load_uer_config",
    "map_uer_state_dict_to_hf_bert",
    "write_hf_tokenizer_files",
]
