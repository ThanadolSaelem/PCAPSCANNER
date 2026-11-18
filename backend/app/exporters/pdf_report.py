"""Executive & technical PDF report generator with optional WeasyPrint and pure-Python PDF 1.4 fallback."""
from __future__ import annotations

import html
import re
import textwrap
from datetime import datetime, timezone
from typing import Any

try:
    from weasyprint import HTML as _WEASYPRINT_HTML  # type: ignore

    WEASYPRINT_AVAILABLE = True
except Exception:
    _WEASYPRINT_HTML = None
    WEASYPRINT_AVAILABLE = False

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|info|biz|ru|cn|xyz|top|dev|local|test)\b", re.I)


def _redact(text: str) -> str:
    text = _IPV4_RE.sub("[REDACTED_IP]", text)
    text = _DOMAIN_RE.sub("[REDACTED_HOST]", text)
    return text


def _ascii_safe(text: str) -> str:
    """Transliterate/replace non-Latin1 bytes cleanly for Type1 Helvetica PDF streams."""
    return text.encode("latin-1", "replace").decode("latin-1")


def _pdf_escape(text: str) -> str:
    return _ascii_safe(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class _PurePdfWriter:
    """Minimal dependency-free multi-page PDF 1.4 generator (US Letter, Type1 Helvetica)."""

    PAGE_W = 612
    PAGE_H = 792
    MARGIN_X = 48
    TOP_Y = 742
    BOTTOM_Y = 54

    def __init__(self, *, classification: str, title: str) -> None:
        self.classification = classification or "TLP:AMBER // INTERNAL"
        self.title = title or "PCAPSCANNER Forensic Report"
        self._pages: list[list[str]] = []
        self._cmds: list[str] = []
        self._y = self.TOP_Y
        self._start_page()

    def _start_page(self) -> None:
        self._cmds = []
        self._cmds.append("0.11 0.14 0.22 rg 0 766 612 26 re f")
        self._cmds.append(
            f"BT /F2 9 Tf 1 0.85 0.35 rg 48 775 Td ({_pdf_escape(self.classification[:80])}) Tj ET"
        )
        self._cmds.append("0.82 0.84 0.88 RG 0.5 w 48 42 m 564 42 l S")
        self._pages.append(self._cmds)
        self._y = self.TOP_Y

    def page_break(self) -> None:
        self._start_page()

    def ensure_space(self, needed: int) -> None:
        if self._y - needed < self.BOTTOM_Y:
            self._start_page()

    def heading(self, text: str, *, level: int = 1) -> None:
        size = 18 if level == 1 else (13 if level == 2 else 11)
        gap = 26 if level == 1 else (20 if level == 2 else 16)
        self.ensure_space(gap + 14)
        self._y -= 6
        if level == 2:
            self._cmds.append(f"0.86 0.88 0.92 RG 0.6 w 48 {self._y - 4} m 564 {self._y - 4} l S")
        color = "0.08 0.12 0.24" if level <= 2 else "0.18 0.22 0.32"
        self._cmds.append(f"BT /F2 {size} Tf {color} rg {self.MARGIN_X} {self._y} Td ({_pdf_escape(text[:95])}) Tj ET")
        self._y -= gap

    def paragraph(self, text: str, *, size: int = 9, color: str = "0.15 0.17 0.22") -> None:
        wrapped = textwrap.wrap(str(text), width=92 if size <= 9 else 80) or [""]
        for line in wrapped:
            self.ensure_space(size + 5)
            self._cmds.append(f"BT /F1 {size} Tf {color} rg {self.MARGIN_X} {self._y} Td ({_pdf_escape(line)}) Tj ET")
            self._y -= size + 4
        self._y -= 3

    def bullet(self, text: str) -> None:
        wrapped = textwrap.wrap(str(text), width=88) or [""]
        for idx, line in enumerate(wrapped):
            self.ensure_space(14)
            prefix = "- " if idx == 0 else "  "
            self._cmds.append(f"BT /F1 9 Tf 0.15 0.17 0.22 rg {self.MARGIN_X + 6} {self._y} Td ({_pdf_escape(prefix + line)}) Tj ET")
            self._y -= 13

    def table(self, headers: list[str], rows: list[list[str]], col_widths: list[int] | None = None) -> None:
        if not rows:
            self.paragraph("(No records recorded for this section.)")
            return
        n_cols = len(headers)
        usable = self.PAGE_W - 2 * self.MARGIN_X
        if not col_widths:
            col_widths = [usable // n_cols] * n_cols
        self.ensure_space(34)
        self._cmds.append(f"0.93 0.95 0.98 rg {self.MARGIN_X} {self._y - 4} {usable} 16 re f")
        x = self.MARGIN_X + 4
        for idx, h in enumerate(headers):
            max_chars = max(6, col_widths[idx] // 5)
            self._cmds.append(f"BT /F2 8 Tf 0.1 0.14 0.24 rg {x} {self._y} Td ({_pdf_escape(str(h)[:max_chars])}) Tj ET")
            x += col_widths[idx]
        self._y -= 18

        for r in rows[:40]:
            self.ensure_space(16)
            x = self.MARGIN_X + 4
            for idx, cell in enumerate(r[:n_cols]):
                max_chars = max(6, col_widths[idx] // 5)
                val = str(cell).replace("\n", " ")
                if len(val) > max_chars:
                    val = val[: max(1, max_chars - 2)] + ".."
                self._cmds.append(f"BT /F1 8 Tf 0.2 0.22 0.28 rg {x} {self._y} Td ({_pdf_escape(val)}) Tj ET")
                x += col_widths[idx]
            self._y -= 14
        self._y -= 6

    def to_bytes(self) -> bytes:
        total_pages = len(self._pages)
        for idx, cmds in enumerate(self._pages, start=1):
            footer = f"{self.title[:55]} | Page {idx} of {total_pages}"
            cmds.append(f"BT /F1 8 Tf 0.45 0.48 0.54 rg {self.MARGIN_X} 26 Td ({_pdf_escape(footer)}) Tj ET")

        objects: list[bytes] = []
        page_obj_nums = [5 + i * 2 for i in range(total_pages)]
        kids_ref = " ".join(f"{n} 0 R" for n in page_obj_nums)
        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        objects.append(f"<< /Type /Pages /Kids [{kids_ref}] /Count {total_pages} >>".encode("ascii"))
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")

        for idx, cmds in enumerate(self._pages):
            page_num = 5 + idx * 2
            content_num = page_num + 1
            stream_data = "\n".join(cmds).encode("latin-1", "replace")
            page_dict = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.PAGE_W} {self.PAGE_H}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_num} 0 R >>"
            ).encode("ascii")
            stream_obj = (
                f"<< /Length {len(stream_data)} >>\nstream\n".encode("ascii")
                + stream_data
                + b"\nendstream"
            )
            objects.append(page_dict)
            objects.append(stream_obj)

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: list[int] = [0]
        for obj_idx, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out.extend(f"{obj_idx} 0 obj\n".encode("ascii"))
            out.extend(body)
            out.extend(b"\nendobj\n")

        xref_pos = len(out)
        out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        out.extend(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
        out.extend(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
        )
        return bytes(out)


def _format_ai_summary(summary_val: Any) -> str:
    if not summary_val:
        return ""
    if isinstance(summary_val, str):
        return summary_val
    if isinstance(summary_val, list):
        parts: list[str] = []
        for item in summary_val[:20]:
            if isinstance(item, dict):
                claim = str(item.get("claim") or "").strip()
                refs = [str(r) for r in (item.get("evidence_ids") or []) if r]
                if claim:
                    parts.append(f"{claim} [{', '.join(refs)}]" if refs else claim)
            elif item:
                parts.append(str(item))
        return " ".join(parts)
    return str(summary_val)


def _render_html_report(
    *,
    job: dict[str, Any],
    bundle: dict[str, Any],
    ai_result: dict[str, Any] | None,
    options: dict[str, Any],
    tx: Any,
) -> str:
    title = html.escape(tx(str(options.get("title") or f"PCAPSCANNER Forensic Report — {job.get('capture_filename') or job.get('id', '')}")))
    classification = html.escape(str(options.get("classification") or "TLP:AMBER // INTERNAL"))
    analyst = html.escape(str(options.get("analyst_name") or "Security Analyst"))
    cov = bundle.get("coverage") or {}
    findings = bundle.get("findings") or []
    iocs = bundle.get("iocs") or []
    mitre = (bundle.get("mitre_attack") or {}).get("techniques") or []
    ai_rep = (ai_result or {}).get("report") or {}

    f_rows = "".join(
        f"<tr><td>{html.escape(str(f.get('finding_id')))}</td>"
        f"<td>{html.escape(str(f.get('severity')))}</td>"
        f"<td>{html.escape(tx(str(f.get('title'))))}</td></tr>"
        for f in findings[:40]
    ) or "<tr><td colspan='3'>No deterministic findings recorded.</td></tr>"
    i_rows = "".join(
        f"<tr><td>{html.escape(str(i.get('type')))}</td>"
        f"<td>{html.escape(tx(str(i.get('value'))))}</td>"
        f"<td>{html.escape(str(i.get('priority_label') or ''))}</td></tr>"
        for i in iocs[:40]
    ) or "<tr><td colspan='3'>No prioritized IOCs extracted.</td></tr>"
    m_rows = "".join(
        f"<tr><td>{html.escape(str(t.get('technique_id')))}</td>"
        f"<td>{html.escape(str(t.get('technique_name')))}</td>"
        f"<td>{html.escape(str(t.get('tactic')))}</td>"
        f"<td>{int(float(t.get('confidence') or 0) * 100)}%</td></tr>"
        for t in mitre[:40]
    ) or "<tr><td colspan='4'>No MITRE ATT&amp;CK hypotheses mapped.</td></tr>"
    summary_text = _format_ai_summary(ai_rep.get("summary")) or (
        "AI narrative was not executed or unavailable; deterministic forensic evidence follows."
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
  @page {{ size: letter; margin: 18mm; @top-center {{ content: "{classification}"; font-size: 9pt; color: #b45309; font-weight: bold; }} }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; color: #111827; font-size: 10pt; }}
  h1 {{ color: #0f172a; border-bottom: 2px solid #2563eb; padding-bottom: 6px; }}
  h2 {{ color: #1e293b; border-bottom: 1px solid #cbd5e1; margin-top: 18px; }}
  .banner {{ background: #0f172a; color: #f8fafc; padding: 10px 14px; font-weight: bold; border-radius: 4px; margin-bottom: 14px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 9pt; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 5px 7px; text-align: left; }}
  th {{ background: #f1f5f9; }}
</style></head><body>
  <div class="banner">{classification}</div>
  <h1>{title}</h1>
  <p><b>Capture SHA-256:</b> {html.escape(str(bundle.get('capture_sha256', '')))}<br/>
     <b>Snapshot ID:</b> {html.escape(str(bundle.get('snapshot_id', 'live')))}<br/>
     <b>Generated:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | <b>Analyst:</b> {analyst}<br/>
     <b>Packets Analyzed:</b> {cov.get('packets_analyzed', 0)} / {cov.get('packets_seen', 0)} (Parser: {html.escape(str(cov.get('parser', 'unknown')))})</p>
  <h2>1. Executive AI / Triage Summary</h2>
  <p>{html.escape(tx(summary_text))}</p>
  <h2>2. Deterministic Findings ({len(findings)})</h2>
  <table><tr><th>ID</th><th>Severity</th><th>Title</th></tr>{f_rows}</table>
  <h2>3. MITRE ATT&amp;CK v19.1 Hypotheses ({len(mitre)})</h2>
  <table><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Conf</th></tr>{m_rows}</table>
  <h2>4. Prioritized Indicators of Compromise ({len(iocs)})</h2>
  <table><tr><th>Type</th><th>Value</th><th>Priority</th></tr>{i_rows}</table>
</body></html>"""


def export_analysis_pdf(
    job: dict[str, Any],
    bundle: dict[str, Any],
    ai_result: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
) -> bytes:
    """Generate an executive & technical forensic PDF report (uses WeasyPrint when available, pure-Python PDF 1.4 otherwise)."""
    opts = dict(options or {})
    redact = bool(opts.get("redact_identifiers", False))
    tx = _redact if redact else (lambda s: s)
    title = tx(str(opts.get("title") or f"PCAPSCANNER Forensic Report - {job.get('capture_filename') or job.get('id', '')[:12]}"))
    classification = str(opts.get("classification") or "TLP:AMBER // INTERNAL")
    analyst = str(opts.get("analyst_name") or "Security Analyst")
    include = set(opts.get("include_sections") or [])

    def _want(sec: str) -> bool:
        return (not include) or (sec in include)

    if WEASYPRINT_AVAILABLE and _WEASYPRINT_HTML is not None and not opts.get("force_pure_pdf", True):
        try:
            html_doc = _render_html_report(job=job, bundle=bundle, ai_result=ai_result, options=opts, tx=tx)
            return bytes(_WEASYPRINT_HTML(string=html_doc).write_pdf())
        except Exception:
            pass

    pdf = _PurePdfWriter(classification=classification, title=title)
    cov = bundle.get("coverage") or {}
    tel = bundle.get("telemetry") or {}
    vis = bundle.get("visibility") or {}
    findings = list(bundle.get("findings") or [])
    beacons = list(bundle.get("beacons") or [])
    dns = bundle.get("dns_analysis") or {}
    tls = bundle.get("tls_analysis") or {}
    yara = bundle.get("yara_results") or {}
    carved = list(bundle.get("carved_files") or bundle.get("artifacts") or [])
    correlations = list(bundle.get("correlations") or [])
    iocs = list(bundle.get("iocs") or [])
    mitre = (bundle.get("mitre_attack") or {}).get("techniques") or []
    ai_rep = (ai_result or {}).get("report") or {}

    pdf.heading(title, level=1)
    pdf.paragraph(f"Classification: {classification}")
    pdf.paragraph(f"Prepared by: {analyst}   |   Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    pdf.paragraph(f"Analysis ID: {job.get('id', '')}   |   Snapshot ID: {bundle.get('snapshot_id', 'live')}   |   Capture File: {tx(str(job.get('capture_filename') or 'capture.pcap'))}")
    pdf.paragraph(f"Capture SHA-256: {bundle.get('capture_sha256', '')}")
    pdf.paragraph(f"Parser: {cov.get('parser', 'unknown')} | Packets Analyzed: {cov.get('packets_analyzed', 0)} / {cov.get('packets_seen', 0)} | Truncated: {cov.get('truncated', False)}")
    pdf.heading("Table of Contents", level=2)
    for item in (
        "1. Executive Summary & Two-Tier AI Assessment",
        "2. Capture Visibility & Quality Metrics",
        "3. Deterministic Findings",
        "4. Deep Forensics: DNS, TLS/JA3/Certs, Beacons, Carved Files & YARA",
        "5. Multi-Signal Threat Correlations & MITRE ATT&CK v19.1",
        "6. Prioritized IOC Appendix & Limitations",
    ):
        pdf.bullet(item)
    pdf.page_break()

    if _want("summary"):
        pdf.heading("1. Executive Summary & AI Assessment", level=1)
        ai_summary_text = _format_ai_summary(ai_rep.get("summary"))
        if ai_summary_text:
            pdf.paragraph(tx(ai_summary_text))
        else:
            pdf.paragraph(
                f"Capture processed {cov.get('packets_analyzed', 0)} packets across {tel.get('flow_count', 0)} flows. "
                f"Detected {len(findings)} deterministic findings, {len(correlations)} threat correlations, and {len(mitre)} ATT&CK technique hypotheses."
            )
        triage = bundle.get("triage")
        if triage:
            pdf.paragraph(
                f"Tier-1 Triage ({triage.get('model')} / {triage.get('mode')}): evaluated {triage.get('total_evaluated', 0)} items, "
                f"filtered {triage.get('benign_filtered', 0)} benign flows ({round(float(triage.get('reduction_ratio') or 0) * 100, 1)}% reduction), "
                f"escalated {triage.get('escalated_count', 0)} items (ET-BERT L7 scored: {triage.get('etbert_scored_count', 0)})."
            )
        if ai_rep.get("recommended_actions"):
            pdf.heading("Recommended Actions", level=3)
            for rec in ai_rep["recommended_actions"][:8]:
                pdf.bullet(tx(str(rec.get("action") or "")))

    if _want("visibility") and vis:
        pdf.heading("2. Capture Visibility & Detector Quality", level=2)
        pdf.paragraph(f"Quality Score: {vis.get('quality_score', 'N/A')}/100 | Parse Ratio: {vis.get('parse_ratio', 'N/A')} | Gaps: {', '.join(vis.get('visibility_gaps') or ['none'])}")
        for lim in (vis.get("limitations") or [])[:6]:
            pdf.bullet(tx(str(lim)))

    if _want("findings"):
        pdf.heading(f"3. Deterministic Findings ({len(findings)})", level=2)
        rows = [[f.get("finding_id", ""), f.get("severity", ""), f.get("confidence", ""), tx(str(f.get("title", "")))] for f in findings]
        pdf.table(["ID", "Severity", "Conf", "Title"], rows, [72, 68, 60, 316])

    if _want("forensics"):
        pdf.heading("4. Deep Forensics Summary", level=2)
        dns_alerts = dns.get("alerts") or {}
        pdf.paragraph(
            f"DNS Analysis: {dns.get('total_records', 0)} records | DGA: {dns_alerts.get('dga_count', 0)} | "
            f"Tunneling suspects: {dns_alerts.get('tunneling_count', 0)} | Fast-flux: {dns_alerts.get('fast_flux_count', 0)}"
        )
        if beacons:
            pdf.heading("Top C2 Beaconing Candidates", level=3)
            b_rows = [
                [
                    tx(str(b.get("src", ""))),
                    tx(str(b.get("dst", ""))),
                    str(b.get("dport", "")),
                    str(b.get("pkts", b.get("count", ""))),
                    f"{float(b.get('score') or 0):.2f}",
                ]
                for b in beacons[:12]
            ]
            pdf.table(["Source", "Destination", "Port", "Count", "Score"], b_rows, [120, 140, 65, 65, 126])
        if tls:
            ja3_obj = tls.get("ja3") or {}
            ja3_cnt = ja3_obj.get("unique_ja3") if ja3_obj.get("unique_ja3") is not None else len(ja3_obj.get("sessions") or ja3_obj.get("fingerprints") or [])
            certs_obj = tls.get("certificates") or {}
            cert_risks = (
                certs_obj.get("high_risk_count")
                if certs_obj.get("high_risk_count") is not None
                else (certs_obj.get("high_risk") or (certs_obj.get("alerts") or {}).get("high_risk_count") or 0)
            )
            pdf.paragraph(f"TLS/JA3 Analysis: {ja3_cnt} JA3 fingerprints inspected | High-risk certificates: {cert_risks}")
        if carved or yara:
            pdf.paragraph(f"HTTP Carved Files / Artifacts: {len(carved)} | YARA Scanned: {yara.get('scanned', 0)} | YARA Matched: {yara.get('matched', 0)}")

    if _want("mitre"):
        pdf.heading("5. Correlations & MITRE ATT&CK v19.1", level=2)
        if correlations:
            c_rows = [
                [
                    tx(str(c.get("indicator", ""))),
                    str(c.get("verdict", "")),
                    f"{float(c.get('composite_score', c.get('score')) or 0):.2f}",
                    ", ".join(str(s.get("name") if isinstance(s, dict) else s) for s in (c.get("signals") or [])[:4]),
                ]
                for c in correlations[:15]
            ]
            pdf.table(["Indicator", "Verdict", "Score", "Signals"], c_rows, [145, 75, 55, 241])
        if mitre:
            m_rows = [[str(t.get("technique_id", "")), str(t.get("tactic", "")), f"{int(float(t.get('confidence') or 0) * 100)}%", str(t.get("technique_name", ""))] for t in mitre[:20]]
            pdf.table(["Technique", "Tactic", "Conf", "Name"], m_rows, [75, 110, 50, 281])

    if _want("iocs"):
        pdf.heading(f"6. Prioritized Indicators of Compromise ({len(iocs)})", level=2)
        i_rows = [[str(i.get("type", "")), tx(str(i.get("value", ""))), str(i.get("priority_label", "")), tx(str(i.get("context", "")))] for i in iocs[:30]]
        pdf.table(["Type", "Value", "Priority", "Context"], i_rows, [58, 175, 75, 208])

    return pdf.to_bytes()


def export_snapshot_pdf(bundle: Any, *, snapshot: dict[str, Any] | None = None) -> bytes:
    bundle_dict = bundle.model_dump(mode="json") if hasattr(bundle, "model_dump") else dict(bundle)
    snap = dict(snapshot or {})
    if snap.get("snapshot_id"):
        bundle_dict["snapshot_id"] = snap["snapshot_id"]
    job_stub = {
        "id": snap.get("analysis_id", ""),
        "capture_filename": snap.get("capture_filename") or f"capture-{str(bundle_dict.get('capture_sha256', ''))[:8]}.pcap",
    }
    return export_analysis_pdf(job_stub, bundle_dict, options={"force_pure_pdf": True})


__all__ = ["WEASYPRINT_AVAILABLE", "export_analysis_pdf", "export_snapshot_pdf"]
