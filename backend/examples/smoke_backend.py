"""From project root: python -m backend.examples.smoke_backend [--live --model <catalog-id>]."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import struct
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from fastapi.testclient import TestClient
from pydantic import SecretStr
from backend.app.config import AppSettings, AIConfig
from backend.app.main import create_app
from backend.app.worker import run_once as parse_once
from backend.app.ai_worker import run_once as ai_once
from backend.tests.fixtures import write_synthetic_pcap


def smoke(live=False, model=None):
    if live and not model:
        raise ValueError("Explicit --model from the current provider catalog is required")
    with tempfile.TemporaryDirectory(prefix="pcapscanner-smoke-") as d:
        root = Path(d)
        original = write_synthetic_pcap(root / "seed.pcap").read_bytes()
        offset = 24
        records = []
        while offset < len(original):
            length = struct.unpack_from("<IIII", original, offset)[2]
            records.append(original[offset+16:offset+16+length])
            offset += 16 + length
        frame = records[1]  # harmless same-name NXDOMAIN response, repeated three times
        pcap = original[:24] + b"".join(struct.pack("<IIII", 1700000000+i, 0, len(frame), len(frame)) + frame for i in range(3))
        config = AIConfig()
        if live:
            base = os.environ.get("MANUS_API_URL", "")
            parts = urlsplit(base)
            if not base or not os.environ.get("MANUS_API_KEY"):
                raise ValueError("Live smoke requires the project MANUS_API_URL and MANUS_API_KEY")
            origin = parts.scheme + "://" + parts.netloc
            config = AIConfig(enabled=True, provider="manus", model=model, allowed_origins=[origin],
                              token_parameter="max_completion_tokens", timeout_seconds=60, retries=0,
                              context_window_tokens=32768, max_output_tokens=2048)
        token = secrets.token_urlsafe(32)
        settings = AppSettings(data_dir=root / "state", api_token=SecretStr(token), ai=config)
        app = create_app(settings)
        with TestClient(app, headers={"Authorization": "Bearer " + token}) as client:
            receipt = client.post("/api/v1/captures", content=pcap, headers={"Content-Type": "application/vnd.tcpdump.pcap"})
            assert receipt.status_code == 201, receipt.text
            accepted = client.post("/api/v1/analyses", json={"capture_id": receipt.json()["capture_id"], "ai_enabled": live, "ai_consent": live})
            assert accepted.status_code == 202, accepted.text
            jid = accepted.json()["id"]
        assert parse_once(app.state.store, settings)
        if live:
            assert asyncio.run(ai_once(app.state.store, settings))
        with TestClient(app, headers={"Authorization": "Bearer " + token}) as client:
            report = client.get(f"/api/v1/analyses/{jid}/report").json()
        evidence, ai = report["evidence"], report["ai"]
        result = {"job_state": report["status"], "packets_analyzed": evidence["coverage"]["packets_analyzed"],
                  "evidence_count": len(evidence["evidence"]), "finding_count": len(evidence["findings"]),
                  "ai_state": ai["state"], "ai_error_code": ai.get("error_code"), "model": model,
                  "usage": ai.get("usage", {}), "raw_capture_sent_to_ai": False,
                  "live": live, "source": "synthetic NXDOMAIN PCAP, no live traffic"}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        assert result["packets_analyzed"] == 3
        assert result["finding_count"] == 1
        if live:
            assert result["ai_state"] == "completed", "Live AI did not return a validated evidence-linked report"
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="Consumes provider credits; sends only pseudonymized synthetic evidence")
    parser.add_argument("--model", help="Exact ID obtained from the current model catalog")
    args = parser.parse_args()
    smoke(args.live, args.model)
