"""CEF (Common Event Format) and Syslog export for SIEM integration."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_CEF_VERSION = "0"
_VENDOR = "PCAPSCANNER"
_PRODUCT = "ForensicWorkbench"
_PRODUCT_VERSION = "3.1.0"

_SEVERITY_MAP = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
    "unknown": 0,
}


@dataclass
class CEFEvent:
    signature_id: str
    name: str
    severity: int
    extensions: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    def to_cef(self) -> str:
        ext_parts: list[str] = []
        for k, v in self.extensions.items():
            safe_v = str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")
            ext_parts.append(f"{k}={safe_v}")
        name_safe = self.name.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")
        sig_safe = self.signature_id.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")
        return f"CEF:{_CEF_VERSION}|{_VENDOR}|{_PRODUCT}|{_PRODUCT_VERSION}|{sig_safe}|{name_safe}|{self.severity}|{' '.join(ext_parts)}"


def format_syslog(event: CEFEvent, hostname: str = "pcapscanner") -> str:
    ts = event.timestamp.strftime("%b %d %H:%M:%S")
    return f"{ts} {hostname} {event.to_cef()}"


def generate_cef_events(bundle: dict[str, Any]) -> list[CEFEvent]:
    events: list[CEFEvent] = []
    snapshot_id = str(bundle.get("snapshot_id") or "")

    for c in bundle.get("correlations") or []:
        verdict = str(c.get("verdict") or "unknown").lower()
        sev = _SEVERITY_MAP.get(verdict, 0)
        signals = ", ".join(
            str(s.get("name") if isinstance(s, dict) else s)
            for s in (c.get("signals") or [])
        )
        ext = {
            "src": str(c.get("indicator") or ""),
            "cs1Label": "Verdict",
            "cs1": verdict,
            "cs2Label": "Signals",
            "cs2": signals,
            "cfp1Label": "Score",
            "cfp1": f"{float(c.get('composite_score', c.get('score')) or 0.0):.2f}",
        }
        if snapshot_id:
            ext["cs3Label"] = "SnapshotID"
            ext["cs3"] = snapshot_id
        events.append(
            CEFEvent(
                signature_id="CORR-001",
                name=f"Threat Correlation: {verdict}",
                severity=sev,
                extensions=ext,
            )
        )

    for b in bundle.get("beacons") or []:
        score = float(b.get("score") or 0.0)
        if score < 0.30:
            continue
        sev = 8 if score >= 0.65 else (5 if score >= 0.4 else 3)
        events.append(
            CEFEvent(
                signature_id="BEACON-001",
                name="C2 Beacon Candidate",
                severity=sev,
                extensions={
                    "src": str(b.get("src") or ""),
                    "dst": str(b.get("dst") or ""),
                    "dpt": str(b.get("dport") or ""),
                    "cnt": str(b.get("pkts", b.get("count") or "")),
                    "cfp1Label": "BeaconScore",
                    "cfp1": f"{score:.2f}",
                },
            )
        )

    dns = bundle.get("dns_analysis") or {}
    for d in dns.get("dga_detections") or []:
        events.append(
            CEFEvent(
                signature_id="DNS-DGA-001",
                name="DGA Domain Detected",
                severity=7,
                extensions={
                    "dhost": str(d.get("domain") or ""),
                    "cfp1Label": "EntropyScore",
                    "cfp1": f"{float(d.get('score') or 0.0):.2f}",
                    "cs1Label": "Reason",
                    "cs1": str(d.get("reason") or ""),
                },
            )
        )
    for t in (dns.get("tunneling_detections") or dns.get("tunneling_suspects") or []):
        dom = t if isinstance(t, str) else t.get("domain", "")
        events.append(CEFEvent(signature_id="DNS-TUNNEL-001", name="DNS Tunneling Suspect", severity=8, extensions={"dhost": str(dom)}))

    yara = bundle.get("yara_results") or {}
    for r in yara.get("results") or []:
        if not r.get("has_matches"):
            continue
        sev = _SEVERITY_MAP.get(str(r.get("severity") or "high").lower(), 8)
        rules = ", ".join(str(m.get("rule_name") or "") for m in (r.get("matches") or [])[:5])
        events.append(
            CEFEvent(
                signature_id="YARA-001",
                name=f"YARA Rule Match ({r.get('severity', 'high')})",
                severity=sev,
                extensions={
                    "fname": str(r.get("filename") or ""),
                    "fileHash": str(r.get("file_hash") or ""),
                    "cs1Label": "MatchedRules",
                    "cs1": rules,
                },
            )
        )

    for f in bundle.get("findings") or []:
        sev = _SEVERITY_MAP.get(str(f.get("severity") or "low").lower(), 3)
        ext = {
            "cs1Label": "Detector",
            "cs1": str(f.get("detector") or ""),
            "cs2Label": "Confidence",
            "cs2": str(f.get("confidence") or ""),
            "cs3Label": "EvidenceIDs",
            "cs3": ",".join(str(e) for e in (f.get("evidence_ids") or [])),
        }
        if snapshot_id:
            ext["cs4Label"] = "SnapshotID"
            ext["cs4"] = snapshot_id
        events.append(
            CEFEvent(
                signature_id=f"DET-{str(f.get('finding_id') or '0000')}",
                name=str(f.get("title") or f.get("detector") or "Finding"),
                severity=sev,
                extensions=ext,
            )
        )

    return events


def export_cef_text(bundle: dict[str, Any], *, hostname: str = "pcapscanner") -> str:
    events = generate_cef_events(bundle)
    return "\n".join(format_syslog(e, hostname=hostname) for e in events) + ("\n" if events else "")


def export_findings_cef(
    bundle: Any,
    *,
    snapshot: dict[str, Any] | None = None,
    snapshot_id: str | None = None,
    hostname: str = "pcapscanner",
) -> str:
    eff_snapshot_id = snapshot_id or (snapshot or {}).get("snapshot_id")
    bundle_dict = bundle.model_dump(mode="json") if hasattr(bundle, "model_dump") else dict(bundle)
    if eff_snapshot_id:
        bundle_dict["snapshot_id"] = eff_snapshot_id
    return export_cef_text(bundle_dict, hostname=hostname)


__all__ = ["CEFEvent", "export_cef_text", "export_findings_cef", "format_syslog", "generate_cef_events"]
