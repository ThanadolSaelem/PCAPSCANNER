"""CLI entrypoint for standalone Tier-1 ET-BERT + OpenJev inference service."""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from typing import Sequence

from .schema import DEFAULT_HIGH_THRESHOLD, DEFAULT_LOW_THRESHOLD
from .server import DEFAULT_MAX_ITEMS, create_app


def _truthy(val: str | None) -> bool:
    if not val:
        return False
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _is_loopback_host(host: str) -> bool:
    cleaned = host.strip().lower()
    if cleaned in {"127.0.0.1", "localhost", "::1"}:
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tier1_inference",
        description="Serve standalone Tier-1 ET-BERT + OpenJev inference API (no training deps)",
    )
    p.add_argument("--host", default=os.environ.get("TIER1_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("TIER1_PORT", "9000")))
    p.add_argument(
        "--openjev-checkpoint",
        default=os.environ.get("TIER1_OPENJEV_CHECKPOINT") or None,
        help="Trained OpenJev LoRA/HF model directory (optional; runs calibrated fallback if omitted)",
    )
    p.add_argument(
        "--etbert-checkpoint",
        default=os.environ.get("TIER1_ETBERT_CHECKPOINT") or None,
        help="Fine-tuned ET-BERT HF sequence-classification directory (optional)",
    )
    p.add_argument(
        "--base-model",
        default=os.environ.get("TIER1_BASE_MODEL") or None,
        help="Optional base HF model override for PEFT LoRA adapter",
    )
    p.add_argument(
        "--device",
        choices=["auto", "mps", "cuda", "cpu"],
        default=os.environ.get("TIER1_DEVICE", "auto"),
    )
    p.add_argument(
        "--high-threshold",
        type=float,
        default=float(os.environ.get("TIER1_HIGH_THRESHOLD", str(DEFAULT_HIGH_THRESHOLD))),
    )
    p.add_argument(
        "--low-threshold",
        type=float,
        default=float(os.environ.get("TIER1_LOW_THRESHOLD", str(DEFAULT_LOW_THRESHOLD))),
    )
    p.add_argument(
        "--max-items",
        type=int,
        default=int(os.environ.get("TIER1_MAX_ITEMS", str(DEFAULT_MAX_ITEMS))),
    )
    p.add_argument(
        "--api-token",
        default=os.environ.get("TIER1_API_TOKEN") or None,
        help="Optional Bearer token protecting inference endpoints (recommended if binding beyond 127.0.0.1)",
    )
    p.add_argument(
        "--require-weights",
        action="store_true",
        default=_truthy(os.environ.get("TIER1_REQUIRE_WEIGHTS")),
        help="Fail startup unless at least one HF/LoRA neural checkpoint loads successfully",
    )
    return p


def main(argv: Sequence[str] | None = None) -> int:
    import uvicorn

    args = build_arg_parser().parse_args(argv)
    if not (0.01 <= args.low_threshold < args.high_threshold <= 0.999):
        print(
            f"[tier1-inference] ERROR: Invalid thresholds low={args.low_threshold}, high={args.high_threshold}",
            file=sys.stderr,
        )
        return 2

    if not _is_loopback_host(args.host) and not (args.api_token and args.api_token.strip()):
        print(
            f"[tier1-inference] WARN: Binding on non-loopback host '{args.host}' without --api-token / TIER1_API_TOKEN.",
            file=sys.stderr,
        )

    try:
        app = create_app(
            openjev_checkpoint=args.openjev_checkpoint,
            etbert_checkpoint=args.etbert_checkpoint,
            base_model=args.base_model,
            device=args.device,
            high_threshold=args.high_threshold,
            low_threshold=args.low_threshold,
            max_items=args.max_items,
            api_token=args.api_token,
            require_weights=args.require_weights,
        )
    except Exception as exc:
        print(f"[tier1-inference] ERROR: {exc}", file=sys.stderr)
        return 2

    oj = app.state.openjev_scorer
    et = app.state.etbert_scorer
    print(
        f"[tier1-inference] Listening on http://{args.host}:{args.port} | "
        f"device={oj.device} | openjev={'weights(' + oj.checkpoint_mode + ')' if oj.loaded_weights else 'state-fallback'} | "
        f"etbert={'weights' if et.loaded_weights else 'feature-fallback'} | "
        f"auth={'bearer' if app.state.auth_required else 'open-loopback'}"
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
