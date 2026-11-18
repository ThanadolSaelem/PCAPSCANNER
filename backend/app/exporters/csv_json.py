"""CSV, JSON, and IOC blocklist exporters with anti-formula injection sanitization."""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

# Spreadsheet formula injection characters (including ASCII & fullwidth equivalents)
_CSV_FORMULA = re.compile(r"^[\s\x00-\x1f\ufeff]*[=+\-@＝＋－＠]")
_MAX_EXPORT_ROWS = 100_000


def sanitize_csv_value(value: Any) -> str:
    """Neutralize leading spreadsheet formula characters by prefixing an apostrophe."""
    if value is None:
        return ""
    text = str(value)
    if text.startswith(("\t", "\r", "\n")) or _CSV_FORMULA.match(text):
        return f"'{text}"
    return text


def _flatten_dict(row: dict[str, Any], parent_key: str = "", sep: str = "_") -> dict[str, Any]:
    items: list[tuple[str, Any]] = []
    for k, v in row.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep).items())
        elif isinstance(v, list):
            items.append((new_key, "; ".join(str(x) for x in v) if v else ""))
        else:
            items.append((new_key, v))
    return dict(items)


def export_to_csv(data: list[dict[str, Any]]) -> bytes:
    """Serialize a list of dicts to UTF-8 CSV bytes with formula injection protection."""
    if not data:
        return b""
    if len(data) > _MAX_EXPORT_ROWS:
        raise ValueError(f"Export exceeds maximum row limit ({_MAX_EXPORT_ROWS})")

    flat = [_flatten_dict(r) for r in data]
    sanitized: list[dict[str, str]] = [{k: sanitize_csv_value(v) for k, v in row.items()} for row in flat]

    fieldnames: list[str] = []
    for row in sanitized:
        for k in row:
            if k not in fieldnames:
                fieldnames.append(k)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(sanitized)
    return buf.getvalue().encode("utf-8")


def export_to_json(data: Any, *, indent: int = 2) -> bytes:
    """Serialize analysis structures cleanly to UTF-8 JSON bytes."""
    return json.dumps(data, indent=indent, ensure_ascii=False, default=str).encode("utf-8")


def export_iocs_txt(bundle: dict[str, Any]) -> bytes:
    """Generate a deduplicated, categorized plain-text IOC blocklist from a bundle dict."""
    grouped: dict[str, list[str]] = {"ip": [], "domain": [], "hash": [], "ja3": [], "url": [], "other": []}
    seen: set[tuple[str, str]] = set()
    for item in bundle.get("iocs") or []:
        itype = str(item.get("type") or item.get("ioc_type") or "other").lower()
        val = str(item.get("value") or "").strip()
        if not val or (itype, val) in seen:
            continue
        seen.add((itype, val))
        bucket = grouped[itype if itype in grouped else "other"]
        prio = item.get("priority_label") or item.get("verdict") or "observed"
        ctx = str(item.get("context") or "").replace("\n", " ")[:120]
        bucket.append(f"{val}  # priority={prio}" + (f" ({ctx})" if ctx else ""))

    lines = [
        "# PCAPSCANNER Indicator of Compromise (IOC) Blocklist",
        f"# Capture SHA-256: {bundle.get('capture_sha256', '')}",
        "",
    ]
    for section, title in (
        ("ip", "IP Addresses"),
        ("domain", "Domains"),
        ("hash", "File Hashes (SHA-256 / SHA-1 / MD5)"),
        ("ja3", "TLS JA3 Fingerprints"),
        ("url", "URLs / Paths"),
        ("other", "Other Indicators"),
    ):
        entries = grouped[section]
        if entries:
            lines.append(f"## {title} ({len(entries)})")
            lines.extend(entries)
            lines.append("")
    if len(lines) <= 3:
        lines.append("# No high-signal IOCs extracted.")
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def export_findings_and_evidence_csv(
    bundle: Any,
    *,
    snapshot: dict[str, Any] | None = None,
    snapshot_id: str | None = None,
) -> str:
    """Export findings and evidence rows from an EvidenceBundle or dict to formula-safe CSV text."""
    eff_snapshot_id = snapshot_id or (snapshot or {}).get("snapshot_id")
    bundle_dict = bundle.model_dump(mode="json") if hasattr(bundle, "model_dump") else dict(bundle)
    rows: list[dict[str, Any]] = []
    for f in bundle_dict.get("findings") or []:
        rows.append(
            {
                "record_type": "finding",
                "snapshot_id": eff_snapshot_id or "",
                "id": f.get("finding_id", ""),
                "detector_or_kind": f.get("detector", ""),
                "severity": f.get("severity", ""),
                "confidence": f.get("confidence", ""),
                "title_or_summary": f.get("title", ""),
                "refs": ",".join(str(x) for x in (f.get("evidence_ids") or [])),
            }
        )
    for ev in bundle_dict.get("evidence") or []:
        rows.append(
            {
                "record_type": "evidence",
                "snapshot_id": eff_snapshot_id or "",
                "id": ev.get("evidence_id", ""),
                "detector_or_kind": ev.get("kind", ""),
                "severity": "",
                "confidence": "",
                "title_or_summary": ev.get("summary", ""),
                "refs": ",".join(str(x) for x in (ev.get("packet_refs") or [])),
            }
        )
    if not rows:
        rows.append(
            {
                "record_type": "summary",
                "snapshot_id": eff_snapshot_id or "",
                "id": bundle_dict.get("capture_sha256", "")[:16],
                "detector_or_kind": "coverage",
                "severity": "info",
                "confidence": "high",
                "title_or_summary": "No findings or evidence rows",
                "refs": "",
            }
        )
    return export_to_csv(rows).decode("utf-8")


__all__ = [
    "export_findings_and_evidence_csv",
    "export_iocs_txt",
    "export_to_csv",
    "export_to_json",
    "sanitize_csv_value",
]
