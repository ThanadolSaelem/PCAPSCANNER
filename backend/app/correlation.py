"""Cross-indicator Bayesian correlation engine, Zeek-to-TShark flow correlation & weighted IOC priority scorer."""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from typing import Any

# Correlation signal weights
SIGNAL_WEIGHTS: dict[str, float] = {
    "vt_detections": 0.20,
    "greynoise_malicious": 0.10,
    "abuseipdb": 0.08,
    "beacon_score": 0.18,
    "dga_domain": 0.12,
    "dns_tunneling": 0.10,
    "dns_fast_flux": 0.10,
    "self_signed_cert": 0.06,
    "expired_cert": 0.04,
    "yara_match": 0.08,
    "flow_asymmetry": 0.04,
    "shodan_vulns": 0.10,
    "shodan_exposure": 0.04,
}

VERDICT_THRESHOLDS: dict[str, float] = {
    "critical": 0.75,
    "high": 0.55,
    "medium": 0.35,
    "low": 0.0,
}

_TIER1_DEFINITIVE = {"vt_detections", "greynoise_malicious"}
_TIER2_BEHAVIOURAL = {"beacon_score", "flow_asymmetry", "dns_tunneling", "dga_domain", "dns_fast_flux"}
_TIER3_CONTEXTUAL = {"abuseipdb", "self_signed_cert", "expired_cert", "yara_match", "shodan_vulns", "shodan_exposure"}

_STRONG_SIGNAL_FLOORS = {
    "vt_detections": 0.55,
    "greynoise_malicious": 0.40,
}

VT_DEFAULT_TOTAL_ENGINES = 70
JA3_MALWARE_DEFAULT_DETECTIONS = 50

DEFAULT_WEIGHTS: dict[str, float] = {
    "vt_detections": 0.22,
    "greynoise_malicious": 0.13,
    "abuseipdb_score": 0.10,
    "beacon_score": 0.13,
    "connection_count": 0.08,
    "data_volume": 0.08,
    "flow_asymmetry": 0.06,
    "ja3_malware_match": 0.06,
    "dga_match": 0.04,
    "self_signed_cert": 0.03,
    "nxdomain_ratio": 0.04,
    "port_anomaly": 0.03,
}

DEFAULT_PRIORITY_THRESHOLDS: dict[str, float] = {
    "critical": 0.8,
    "high": 0.6,
    "medium": 0.4,
    "low": 0.0,
}
PRIORITY_THRESHOLDS = DEFAULT_PRIORITY_THRESHOLDS


def _finite(val: float, default: float = 0.0) -> float:
    return float(val) if math.isfinite(float(val)) else default


def _is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value).strip())
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_global
    except (ValueError, TypeError):
        return False


@dataclass
class CorrelationSignal:
    name: str
    value: Any
    score: float
    source: str


@dataclass
class CorrelationResult:
    indicator: str
    indicator_type: str
    signals: list[CorrelationSignal] = field(default_factory=list)
    composite_score: float = 0.0
    verdict: str = "low"
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "type": self.indicator_type,
            "composite_score": round(_finite(self.composite_score), 3),
            "verdict": self.verdict,
            "signal_count": len(self.signals),
            "evidence_ids": list(self.evidence_ids),
            "signals": [
                {
                    "name": s.name,
                    "value": s.value,
                    "score": round(_finite(s.score), 3),
                    "source": s.source,
                }
                for s in self.signals
            ],
        }


def _get_verdict(score: float) -> str:
    for label, threshold in sorted(VERDICT_THRESHOLDS.items(), key=lambda x: -x[1]):
        if score >= threshold:
            return label
    return "low"


def _attr_str(attrs: dict[str, Any], *keys: str) -> str:
    for k in keys:
        val = attrs.get(k)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _attr_port(attrs: dict[str, Any], *keys: str) -> int:
    for k in keys:
        val = attrs.get(k)
        if isinstance(val, int) and not isinstance(val, bool) and val >= 0:
            return val
        if isinstance(val, str) and val.strip().isdigit():
            return int(val.strip())
    return 0


def correlate_zeek_and_tshark_evidence(evidence_list: list[Any]) -> int:
    """Link Zeek evidence rows (`kind == 'zeek'`) with TShark `flow`/`dns`/`tls` evidence rows in place.

    Matches by 5-tuple (`src`, `dst`, `src_port`, `dst_port`, `protocol`) or (`src`, `dns_qname`/`query`)
    and annotates both sides with `correlated_evidence_id` and `zeek_uid_hash` (keeping <= 40 attributes).
    Returns the number of correlated Zeek rows.
    """
    tshark_by_5tuple: dict[tuple[str, str, int, int, str], Any] = {}
    tshark_by_pair_port: dict[tuple[str, str, int], Any] = {}
    tshark_by_dns: dict[tuple[str, str], Any] = {}

    for ev in evidence_list:
        kind = getattr(ev, "kind", None)
        if kind == "zeek":
            continue
        attrs = getattr(ev, "attributes", None)
        if not isinstance(attrs, dict):
            continue
        src = _attr_str(attrs, "src", "src_ip", "id_orig_h")
        dst = _attr_str(attrs, "dst", "dst_ip", "id_resp_h")
        sport = _attr_port(attrs, "src_port", "id_orig_p")
        dport = _attr_port(attrs, "dst_port", "id_resp_p")
        proto = _attr_str(attrs, "protocol", "proto").upper()
        if src and dst and dport:
            tshark_by_5tuple.setdefault((src, dst, sport, dport, proto), ev)
            tshark_by_pair_port.setdefault((src, dst, dport), ev)
        qname = _attr_str(attrs, "query", "dns_qname", "server_name", "tls_sni", "tls_server_name").lower()
        if src and qname:
            tshark_by_dns.setdefault((src, qname), ev)

    linked = 0
    for ev in evidence_list:
        if getattr(ev, "kind", None) != "zeek":
            continue
        attrs = getattr(ev, "attributes", None)
        if not isinstance(attrs, dict):
            continue
        src = _attr_str(attrs, "src", "src_ip", "id_orig_h")
        dst = _attr_str(attrs, "dst", "dst_ip", "id_resp_h")
        sport = _attr_port(attrs, "src_port", "id_orig_p")
        dport = _attr_port(attrs, "dst_port", "id_resp_p")
        proto = _attr_str(attrs, "protocol", "proto").upper()
        qname = _attr_str(attrs, "query", "dns_qname", "server_name", "tls_sni", "tls_server_name").lower()

        match = None
        if src and dst and dport:
            match = tshark_by_5tuple.get((src, dst, sport, dport, proto)) or tshark_by_pair_port.get((src, dst, dport))
        if match is None and src and qname:
            match = tshark_by_dns.get((src, qname))

        if match is not None:
            match_id = str(getattr(match, "evidence_id", "") or "")
            zeek_id = str(getattr(ev, "evidence_id", "") or "")
            uid_hash = attrs.get("zeek_uid_hash") or attrs.get("uid")
            if match_id and len(attrs) < 39:
                attrs["correlated_evidence_id"] = match_id
                linked += 1
            match_attrs = getattr(match, "attributes", None)
            if isinstance(match_attrs, dict):
                if zeek_id and "correlated_zeek_evidence_id" not in match_attrs and len(match_attrs) < 39:
                    match_attrs["correlated_zeek_evidence_id"] = zeek_id
                if isinstance(uid_hash, str) and uid_hash and "zeek_uid_hash" not in match_attrs and len(match_attrs) < 39:
                    match_attrs["zeek_uid_hash"] = uid_hash
    return linked


def correlate_bundle_findings(
    evidence_list: list[Any],
    findings: list[Any],
) -> list[CorrelationResult]:
    """Correlate multi-detector findings & evidence across shared endpoints or domains."""
    ev_by_id: dict[str, Any] = {str(getattr(e, "evidence_id", "")): e for e in evidence_list}
    by_indicator: dict[str, dict[str, Any]] = {}

    detector_weights: dict[str, tuple[str, float]] = {
        "flow_periodic_beacon": ("beacon_score", 0.78),
        "periodic_tcp_connection_starts": ("beacon_score", 0.78),
        "dns_query_label_entropy": ("dns_tunneling", 0.74),
        "dns_nxdomain_entropy": ("dga_domain", 0.74),
        "dns_nxdomain_burst": ("dga_domain", 0.72),
        "dns_tunneling_pattern": ("dns_tunneling", 0.76),
        "dns_query_velocity": ("dns_tunneling", 0.65),
        "dns_origin_nxdomain_ratio": ("dga_domain", 0.68),
        "dns_fast_flux_heuristic": ("dns_fast_flux", 0.75),
        "tls_certificate_self_signed": ("self_signed_cert", 0.65),
        "tls_certificate_expired": ("expired_cert", 0.55),
        "tls_certificate_weak_key": ("self_signed_cert", 0.65),
        "tls_certificate_long_validity": ("self_signed_cert", 0.50),
        "tls_certificate_weak_signature": ("self_signed_cert", 0.62),
        "tls_sni_certificate_mismatch": ("self_signed_cert", 0.68),
        "tls_ja3_known_signature": ("yara_match", 0.80),
        "tls_ja3_concentration": ("flow_asymmetry", 0.55),
        "yara_rule_match": ("yara_match", 0.85),
        "arp_spoofing_conflict": ("flow_asymmetry", 0.76),
        "http_suspicious_uri": ("yara_match", 0.72),
    }

    for f in findings:
        detector = str(getattr(f, "detector", f.get("detector", "") if isinstance(f, dict) else ""))
        ev_ids = list(getattr(f, "evidence_ids", f.get("evidence_ids", []) if isinstance(f, dict) else []) or [])
        sig_name, sig_score = detector_weights.get(detector, ("flow_asymmetry", 0.52))
        for eid in ev_ids:
            ev = ev_by_id.get(str(eid))
            if ev is None:
                continue
            attrs = getattr(ev, "attributes", {}) or {}
            candidates: list[tuple[str, str]] = []
            seen_cand: set[tuple[str, str]] = set()
            for k in ("dst", "dst_ip", "id_resp_h", "src", "src_ip", "id_orig_h"):
                v = str(attrs.get(k) or "").strip()
                if v and ("ip", v) not in seen_cand:
                    seen_cand.add(("ip", v))
                    candidates.append(("ip", v))
            qname = _attr_str(attrs, "query", "dns_qname", "server_name", "tls_sni", "tls_server_name").lower()
            if qname and ("domain", qname) not in seen_cand:
                seen_cand.add(("domain", qname))
                candidates.append(("domain", qname))
            for ind_type, ind_val in candidates:
                slot = by_indicator.setdefault(
                    ind_val,
                    {"type": ind_type, "signals": {}, "evidence_ids": []},
                )
                if eid not in slot["evidence_ids"] and len(slot["evidence_ids"]) < 16:
                    slot["evidence_ids"].append(str(eid))
                slot["signals"][detector] = CorrelationSignal(
                    name=sig_name,
                    value=detector,
                    score=sig_score,
                    source=detector,
                )

    results: list[CorrelationResult] = []
    for ind_val, info in by_indicator.items():
        sigs = list(info["signals"].values())
        if not sigs:
            continue
        comp = _compute_composite(sigs)
        if len(sigs) >= 2:
            comp = min(1.0, comp + 0.18 * (len(sigs) - 1))
        results.append(
            CorrelationResult(
                indicator=ind_val,
                indicator_type=info["type"],
                signals=sigs,
                composite_score=comp,
                verdict=_get_verdict(comp),
                evidence_ids=info["evidence_ids"],
            )
        )
    results.sort(key=lambda r: (len(r.signals), r.composite_score), reverse=True)
    return results[:50]


def _collect_ip_signals(
    ip: str,
    osint: dict[str, Any],
    beacon_lookup: dict[str, float],
    tls_lookup: dict[str, list[str]],
    yara_ips: set[str],
    asymmetry_lookup: dict[str, float],
) -> list[CorrelationSignal]:
    signals: list[CorrelationSignal] = []
    ip_osint = (osint.get("ips") or {}).get(ip, {})

    vt = ip_osint.get("vt", {})
    vt_attr = (vt.get("data") or {}).get("attributes", {}) if isinstance(vt, dict) else {}
    vt_rep = vt_attr.get("reputation", 0)
    if isinstance(vt_rep, (int, float)) and vt_rep < 0:
        normalised = min(abs(float(vt_rep)) / 100.0, 1.0)
        signals.append(CorrelationSignal("vt_detections", vt_rep, normalised, "virustotal"))
    else:
        last_stats = vt_attr.get("last_analysis_stats", {}) if isinstance(vt_attr, dict) else {}
        mal = int(last_stats.get("malicious", 0) or 0) if isinstance(last_stats, dict) else 0
        if mal > 0:
            total = sum(int(v or 0) for v in last_stats.values()) or VT_DEFAULT_TOTAL_ENGINES
            signals.append(CorrelationSignal("vt_detections", f"{mal}/{total}", min(mal / max(1, total), 1.0), "virustotal"))

    gn = ip_osint.get("greynoise", {})
    if isinstance(gn, dict) and gn.get("classification") == "malicious":
        signals.append(CorrelationSignal("greynoise_malicious", "malicious", 1.0, "greynoise"))

    abuse = ip_osint.get("abuseipdb", {})
    abuse_score = ((abuse.get("data") or {}).get("abuseConfidenceScore", 0)) if isinstance(abuse, dict) else 0
    if isinstance(abuse_score, (int, float)) and abuse_score > 0:
        signals.append(CorrelationSignal("abuseipdb", abuse_score, min(float(abuse_score) / 100.0, 1.0), "abuseipdb"))

    shodan = ip_osint.get("shodan", {})
    if isinstance(shodan, dict) and shodan and "error" not in shodan and "_error" not in shodan:
        vulns = shodan.get("vulns") or []
        ports = shodan.get("ports") or []
        if isinstance(vulns, (list, tuple)) and vulns:
            signals.append(CorrelationSignal("shodan_vulns", f"{len(vulns)} CVEs", min(0.3 + 0.1 * len(vulns), 1.0), "shodan"))
        if isinstance(ports, (list, tuple)) and len(ports) >= 10:
            signals.append(CorrelationSignal("shodan_exposure", f"{len(ports)} open ports", min(len(ports) / 30.0, 0.8), "shodan"))

    if ip in beacon_lookup and beacon_lookup[ip] > 0.5:
        bval = min(_finite(beacon_lookup[ip]), 1.0)
        signals.append(CorrelationSignal("beacon_score", round(bval, 2), bval, "beacon"))

    if ip in tls_lookup:
        for alert_type in tls_lookup[ip]:
            if alert_type == "self_signed":
                signals.append(CorrelationSignal("self_signed_cert", True, 1.0, "tls"))
            elif alert_type == "expired":
                signals.append(CorrelationSignal("expired_cert", True, 1.0, "tls"))

    if ip in yara_ips:
        signals.append(CorrelationSignal("yara_match", True, 1.0, "yara"))

    if ip in asymmetry_lookup and asymmetry_lookup[ip] > 0.3:
        aval = min(_finite(asymmetry_lookup[ip]), 1.0)
        signals.append(CorrelationSignal("flow_asymmetry", round(aval, 2), aval, "flow_analysis"))

    return signals


def _collect_domain_signals(
    domain: str,
    osint: dict[str, Any],
    dns_analysis: dict[str, Any],
) -> list[CorrelationSignal]:
    signals: list[CorrelationSignal] = []
    dom_osint = (osint.get("domains") or {}).get(domain, {})

    vt = dom_osint.get("vt", {}) if isinstance(dom_osint, dict) else {}
    vt_attr = (vt.get("data") or {}).get("attributes", {}) if isinstance(vt, dict) else {}
    last_analysis = vt_attr.get("last_analysis_stats", {}) if isinstance(vt_attr, dict) else {}
    malicious = int(last_analysis.get("malicious", 0) or 0) if isinstance(last_analysis, dict) else 0
    if malicious > 0:
        total = sum(int(v or 0) for v in last_analysis.values()) or 1
        signals.append(CorrelationSignal("vt_detections", f"{malicious}/{total}", min(malicious / total, 1.0), "virustotal"))

    for dga in dns_analysis.get("dga_detections", []):
        if isinstance(dga, dict) and dga.get("domain") == domain and dga.get("is_dga"):
            sc = min(_finite(dga.get("score", 0.0)), 1.0)
            signals.append(CorrelationSignal("dga_domain", sc, sc, "dns"))
            break

    for tunnel in dns_analysis.get("tunneling_detections", []):
        if isinstance(tunnel, dict) and tunnel.get("domain") == domain and tunnel.get("is_tunneling"):
            sc = min(_finite(tunnel.get("score", 0.0)), 1.0)
            signals.append(CorrelationSignal("dns_tunneling", sc, sc, "dns"))
            break

    return signals


def _compute_composite(signals: list[CorrelationSignal]) -> float:
    if not signals:
        return 0.0
    product = 1.0
    for sig in signals:
        weight = SIGNAL_WEIGHTS.get(sig.name, 0.05)
        p = min(max(0.0, _finite(sig.score)) * weight * 2.5, 0.95)
        product *= 1.0 - p
    composite = 1.0 - product

    for sig in signals:
        floor = _STRONG_SIGNAL_FLOORS.get(sig.name, 0.0)
        if floor > 0 and sig.score >= 0.5:
            composite = max(composite, floor)

    has_t1 = any(s.name in _TIER1_DEFINITIVE for s in signals)
    has_t2 = any(s.name in _TIER2_BEHAVIOURAL for s in signals)
    if not has_t1 and not has_t2:
        composite = min(composite, 0.45)

    return _finite(min(composite, 1.0))


def _extract_beacon_lookup(beacon_data: Any) -> dict[str, float]:
    lookup: dict[str, float] = {}
    if beacon_data is None:
        return lookup
    if isinstance(beacon_data, list):
        for row in beacon_data:
            if not isinstance(row, dict):
                continue
            dst = str(row.get("dst", "") or "")
            sc = _finite(row.get("score", 0.0))
            if dst and sc > 0:
                lookup[dst] = max(lookup.get(dst, 0.0), sc)
        return lookup
    with_rows = getattr(beacon_data, "to_dict", None)
    if callable(with_rows):
        for row in with_rows("records"):
            dst = str(row.get("dst", "") or "")
            sc = _finite(row.get("score", 0.0))
            if dst and sc > 0:
                lookup[dst] = max(lookup.get(dst, 0.0), sc)
    return lookup


def _extract_tls_lookup(tls_analysis: dict[str, Any]) -> dict[str, list[str]]:
    lookup: dict[str, list[str]] = {}
    for alert in tls_analysis.get("certificate_alerts", []) or []:
        if isinstance(alert, dict):
            dst_ip = str(alert.get("dst_ip", "") or "")
            atype = str(alert.get("type", "") or "")
            if dst_ip and atype:
                lookup.setdefault(dst_ip, []).append(atype)
    raw_alerts = tls_analysis.get("alerts")
    if isinstance(raw_alerts, list):
        for alert in raw_alerts:
            if isinstance(alert, dict):
                dst_ip = str(alert.get("dst_ip", "") or "")
                atype = str(alert.get("type", "") or "")
                if dst_ip and atype:
                    lookup.setdefault(dst_ip, []).append(atype)
    certs_block = tls_analysis.get("certificates") or {}
    cert_items = certs_block.get("certificates", []) if isinstance(certs_block, dict) else []
    for cert in cert_items:
        if not isinstance(cert, dict):
            continue
        dst_ip = str(cert.get("dst_ip", "") or "")
        if not dst_ip:
            continue
        if cert.get("is_self_signed"):
            lookup.setdefault(dst_ip, []).append("self_signed")
        if cert.get("is_expired"):
            lookup.setdefault(dst_ip, []).append("expired")
    return {k: list(dict.fromkeys(v)) for k, v in lookup.items()}


def correlate_indicators(
    features: dict[str, Any] | None = None,
    osint: dict[str, Any] | None = None,
    beacon_df: Any = None,
    dns_analysis: dict[str, Any] | None = None,
    tls_analysis: dict[str, Any] | None = None,
    yara_results: dict[str, Any] | None = None,
    asymmetry_results: list[Any] | None = None,
) -> list[CorrelationResult]:
    features = features or {}
    osint = osint or {}
    dns_analysis = dns_analysis or {}
    tls_analysis = tls_analysis or {}

    beacon_lookup = _extract_beacon_lookup(beacon_df)
    tls_lookup = _extract_tls_lookup(tls_analysis)

    yara_ips: set[str] = set()
    if yara_results and int(yara_results.get("matched", 0) or 0) > 0:
        for r in yara_results.get("results", []):
            if isinstance(r, dict) and r.get("has_matches"):
                for key in ("src_ip", "dst_ip", "src", "dst"):
                    val = str(r.get(key, "") or "")
                    if val:
                        yara_ips.add(val)

    asymmetry_lookup: dict[str, float] = {}
    for ar in asymmetry_results or []:
        if hasattr(ar, "dst") and hasattr(ar, "score"):
            asymmetry_lookup[str(ar.dst)] = max(asymmetry_lookup.get(str(ar.dst), 0.0), _finite(ar.score))
        elif isinstance(ar, dict):
            dst = str(ar.get("dst", "") or "")
            if dst:
                asymmetry_lookup[dst] = max(asymmetry_lookup.get(dst, 0.0), _finite(ar.get("score", 0.0)))

    results: list[CorrelationResult] = []
    seen_ips: set[str] = set()
    raw_ips = list((features.get("artifacts") or {}).get("ips", [])) + list((osint.get("ips") or {}).keys()) + list(beacon_lookup.keys())
    for ip in raw_ips:
        ip_s = str(ip or "").strip()
        if not ip_s or ip_s in seen_ips or not _is_public_ipv4(ip_s):
            continue
        seen_ips.add(ip_s)
        signals = _collect_ip_signals(ip_s, osint, beacon_lookup, tls_lookup, yara_ips, asymmetry_lookup)
        if not signals:
            continue
        comp = _compute_composite(signals)
        results.append(
            CorrelationResult(
                indicator=ip_s,
                indicator_type="ip",
                signals=signals,
                composite_score=comp,
                verdict=_get_verdict(comp),
            )
        )

    seen_doms: set[str] = set()
    raw_doms = list((features.get("artifacts") or {}).get("domains", [])) + list((osint.get("domains") or {}).keys())
    for d in raw_doms:
        d_s = str(d or "").strip()
        if not d_s or d_s in seen_doms:
            continue
        seen_doms.add(d_s)
        signals = _collect_domain_signals(d_s, osint, dns_analysis)
        if not signals:
            continue
        comp = _compute_composite(signals)
        results.append(
            CorrelationResult(
                indicator=d_s,
                indicator_type="domain",
                signals=signals,
                composite_score=comp,
                verdict=_get_verdict(comp),
            )
        )

    results.sort(key=lambda r: r.composite_score, reverse=True)
    return results


@dataclass
class ScoredIOC:
    ioc_type: str
    value: str
    priority_score: float
    priority_label: str
    factors: dict[str, dict[str, Any]]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.ioc_type,
            "value": self.value,
            "priority_score": round(_finite(self.priority_score), 3),
            "priority_label": self.priority_label,
            "factors": self.factors,
            "recommendation": self.recommendation,
        }


class IOCScorer:
    """Weighted IOC priority scorer combining OSINT, behavioral, and forensic context."""

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        thresholds: dict[str, float] | None = None,
    ):
        self.weights = (weights or DEFAULT_WEIGHTS).copy()
        self.thresholds = (thresholds or DEFAULT_PRIORITY_THRESHOLDS).copy()

    def score_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        osint_data: dict[str, Any] | None = None,
        behavioral_data: dict[str, Any] | None = None,
        context_data: dict[str, Any] | None = None,
    ) -> ScoredIOC:
        osint_data = osint_data or {}
        behavioral_data = behavioral_data or {}
        context_data = context_data or {}

        factors: dict[str, dict[str, Any]] = {}
        osint_score, osint_f = self._score_osint(osint_data)
        beh_score, beh_f = self._score_behavioral(behavioral_data)
        ctx_score, ctx_f = self._score_context(context_data)
        factors.update(osint_f)
        factors.update(beh_f)
        factors.update(ctx_f)

        total_score = _finite(min(max(osint_score + beh_score + ctx_score, 0.0), 1.0))
        label = self._get_priority_label(total_score)
        rec = self._generate_recommendation(total_score, factors)
        return ScoredIOC(
            ioc_type=ioc_type,
            value=ioc_value,
            priority_score=total_score,
            priority_label=label,
            factors=factors,
            recommendation=rec,
        )

    def _score_osint(self, osint_data: dict[str, Any]) -> tuple[float, dict[str, dict[str, Any]]]:
        score = 0.0
        factors: dict[str, dict[str, Any]] = {}

        vt_data = osint_data.get("virustotal") or {}
        if not vt_data and isinstance(osint_data.get("vt"), dict):
            attr = (osint_data["vt"].get("data") or {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {}) if isinstance(attr, dict) else {}
            mal = int(stats.get("malicious", 0) or 0) if isinstance(stats, dict) else 0
            tot = sum(int(v or 0) for v in stats.values()) if isinstance(stats, dict) else 0
            rep = attr.get("reputation", 0) if isinstance(attr, dict) else 0
            if mal > 0:
                vt_data = {"detections": mal, "total": tot or VT_DEFAULT_TOTAL_ENGINES}
            elif isinstance(rep, (int, float)) and rep < 0:
                vt_data = {"detections": min(VT_DEFAULT_TOTAL_ENGINES, abs(int(rep))), "total": VT_DEFAULT_TOTAL_ENGINES}

        if vt_data:
            detections = int(vt_data.get("detections", 0) or 0)
            total = int(vt_data.get("total", VT_DEFAULT_TOTAL_ENGINES) or VT_DEFAULT_TOTAL_ENGINES)
            if total > 0 and detections > 0:
                ratio = min(1.0, detections / total)
                contrib = ratio * self.weights.get("vt_detections", 0.22)
                score += contrib
                factors["vt_detections"] = {"value": f"{detections}/{total}", "contribution": round(contrib, 3)}

        gn = osint_data.get("greynoise") or {}
        if isinstance(gn, dict):
            cls_name = str(gn.get("classification", "") or "")
            if cls_name == "malicious":
                contrib = self.weights.get("greynoise_malicious", 0.13)
                score += contrib
                factors["greynoise"] = {"value": "malicious", "contribution": round(contrib, 3)}
            elif cls_name == "benign":
                factors["greynoise"] = {"value": "benign", "contribution": 0.0}

        abuse = osint_data.get("abuseipdb") or {}
        abuse_sc = 0.0
        if isinstance(abuse, dict):
            if "score" in abuse:
                abuse_sc = float(abuse.get("score") or 0)
            else:
                abuse_sc = float((abuse.get("data") or {}).get("abuseConfidenceScore") or 0)
        if abuse_sc > 0:
            contrib = min(1.0, abuse_sc / 100.0) * self.weights.get("abuseipdb_score", 0.10)
            score += contrib
            factors["abuseipdb"] = {"value": round(abuse_sc, 1), "contribution": round(contrib, 3)}

        return score, factors

    def _score_behavioral(self, behavioral_data: dict[str, Any]) -> tuple[float, dict[str, dict[str, Any]]]:
        score = 0.0
        factors: dict[str, dict[str, Any]] = {}

        b_score = _finite(behavioral_data.get("beacon_score", 0.0))
        if b_score > 0:
            contrib = min(1.0, b_score) * self.weights.get("beacon_score", 0.13)
            score += contrib
            factors["beacon_score"] = {"value": round(b_score, 2), "contribution": round(contrib, 3)}

        conn_count = int(behavioral_data.get("connection_count", 0) or 0)
        if conn_count > 0:
            contrib = min(conn_count / 100.0, 1.0) * self.weights.get("connection_count", 0.08)
            score += contrib
            factors["connection_count"] = {"value": conn_count, "contribution": round(contrib, 3)}

        vol = int(behavioral_data.get("data_volume", 0) or 0)
        if vol > 0:
            contrib = min(vol / 100_000_000.0, 1.0) * self.weights.get("data_volume", 0.08)
            score += contrib
            factors["data_volume"] = {"value": f"{vol / 1_000_000:.1f} MB", "contribution": round(contrib, 3)}

        return score, factors

    def _score_context(self, context_data: dict[str, Any]) -> tuple[float, dict[str, dict[str, Any]]]:
        score = 0.0
        factors: dict[str, dict[str, Any]] = {}

        ja3_match = context_data.get("ja3_malware_match")
        if ja3_match:
            contrib = self.weights.get("ja3_malware_match", 0.06)
            score += contrib
            factors["ja3_malware_match"] = {"value": ja3_match, "contribution": round(contrib, 3)}

        if context_data.get("dga_match"):
            contrib = self.weights.get("dga_match", 0.04)
            score += contrib
            factors["dga_match"] = {"value": True, "contribution": round(contrib, 3)}

        if context_data.get("self_signed_cert"):
            contrib = self.weights.get("self_signed_cert", 0.03)
            score += contrib
            factors["self_signed_cert"] = {"value": True, "contribution": round(contrib, 3)}

        nx_ratio = _finite(context_data.get("nxdomain_ratio", 0.0))
        if nx_ratio > 0.3:
            contrib = min(nx_ratio, 1.0) * self.weights.get("nxdomain_ratio", 0.04)
            score += contrib
            factors["nxdomain_ratio"] = {"value": f"{nx_ratio:.0%}", "contribution": round(contrib, 3)}

        asym = _finite(context_data.get("flow_asymmetry", 0.0))
        if asym > 0:
            contrib = min(1.0, asym) * self.weights.get("flow_asymmetry", 0.06)
            score += contrib
            factors["flow_asymmetry"] = {"value": round(asym, 2), "contribution": round(contrib, 3)}

        port_anom = _finite(context_data.get("port_anomaly", 0.0))
        if port_anom > 0:
            contrib = min(1.0, port_anom) * self.weights.get("port_anomaly", 0.03)
            score += contrib
            factors["port_anomaly"] = {"value": round(port_anom, 2), "contribution": round(contrib, 3)}

        return score, factors

    def _get_priority_label(self, score: float) -> str:
        if score >= self.thresholds["critical"]:
            return "critical"
        if score >= self.thresholds["high"]:
            return "high"
        if score >= self.thresholds["medium"]:
            return "medium"
        return "low"

    def _generate_recommendation(self, score: float, factors: dict[str, dict[str, Any]]) -> str:
        if score >= 0.8:
            action = "Immediate block recommended"
        elif score >= 0.6:
            action = "Block and investigate"
        elif score >= 0.4:
            action = "Monitor and investigate"
        else:
            action = "Continue monitoring"

        details: list[str] = []
        if "vt_detections" in factors and factors["vt_detections"]["contribution"] > 0.1:
            details.append("VirusTotal flagged")
        if "greynoise" in factors and factors["greynoise"]["value"] == "malicious":
            details.append("known malicious IP")
        if "beacon_score" in factors and factors["beacon_score"]["contribution"] > 0.06:
            details.append("C2 beaconing detected")
        if "ja3_malware_match" in factors:
            details.append(f"matches {factors['ja3_malware_match']['value']}")
        if "dga_match" in factors:
            details.append("DGA domain")
        return f"{action} ({', '.join(details)})" if details else action

    def rank_iocs(
        self,
        iocs: list[dict[str, Any]],
        osint: dict[str, Any] | None = None,
        beacon_results: list[dict[str, Any]] | None = None,
        *,
        dns_analysis: dict[str, Any] | None = None,
        tls_analysis: dict[str, Any] | None = None,
        asymmetry_results: list[Any] | None = None,
        port_anomalies: list[Any] | None = None,
        flow_stats_by_ip: dict[str, dict[str, int]] | None = None,
    ) -> list[ScoredIOC]:
        osint = osint or {}
        beacon_lookup = _extract_beacon_lookup(beacon_results)
        tls_lookup = _extract_tls_lookup(tls_analysis or {})
        dga_domains = {
            str(d.get("domain", "") or "")
            for d in (dns_analysis or {}).get("dga_detections", [])
            if isinstance(d, dict) and d.get("is_dga")
        }
        asym_lookup: dict[str, float] = {}
        for ar in asymmetry_results or []:
            dst = ar.dst if hasattr(ar, "dst") else (ar.get("dst", "") if isinstance(ar, dict) else "")
            sc = _finite(ar.score if hasattr(ar, "score") else (ar.get("score", 0.0) if isinstance(ar, dict) else 0.0))
            if dst:
                asym_lookup[str(dst)] = max(asym_lookup.get(str(dst), 0.0), sc)
        port_lookup: dict[str, float] = {}
        for pa in port_anomalies or []:
            dst = pa.dst if hasattr(pa, "dst") else (pa.get("dst", "") if isinstance(pa, dict) else "")
            sc = _finite(pa.score if hasattr(pa, "score") else (pa.get("score", 0.0) if isinstance(pa, dict) else 0.0))
            if dst:
                port_lookup[str(dst)] = max(port_lookup.get(str(dst), 0.0), sc)

        nx_block = (dns_analysis or {}).get("nxdomain_analysis") or (dns_analysis or {}).get("nxdomain") or {}
        nx_ratio = float(nx_block.get("nxdomain_ratio") or 0.0)
        scored: list[ScoredIOC] = []
        for ioc in iocs:
            ioc_type = str(ioc.get("type", "unknown"))
            ioc_value = str(ioc.get("value", "") or "")
            if not ioc_value:
                continue

            osint_data: dict[str, Any] = {}
            if ioc_type == "ip":
                osint_data = (osint.get("ips") or {}).get(ioc_value, {})
            elif ioc_type == "domain":
                osint_data = (osint.get("domains") or {}).get(ioc_value, {})
            elif ioc_type == "ja3":
                ja3_info = (osint.get("ja3") or {}).get(ioc_value, {}) or (ioc.get("meta") or {})
                if ja3_info.get("malware"):
                    osint_data = {"virustotal": {"detections": JA3_MALWARE_DEFAULT_DETECTIONS, "total": VT_DEFAULT_TOTAL_ENGINES}}

            ip_meta = (flow_stats_by_ip or {}).get(ioc_value, {})
            behavioral_data = {
                "beacon_score": beacon_lookup.get(ioc_value, 0.0),
                "connection_count": ip_meta.get("connections", 0),
                "data_volume": ip_meta.get("bytes", 0),
            }
            context_data: dict[str, Any] = {}
            if ioc_type == "ja3":
                ja3_info = (osint.get("ja3") or {}).get(ioc_value, {}) or (ioc.get("meta") or {})
                if ja3_info.get("malware"):
                    context_data["ja3_malware_match"] = ja3_info.get("client", "malware")
            elif ioc_type == "domain":
                if ioc_value in dga_domains:
                    context_data["dga_match"] = True
                if nx_ratio > 0.3:
                    context_data["nxdomain_ratio"] = nx_ratio
            elif ioc_type == "ip":
                if "self_signed" in tls_lookup.get(ioc_value, []):
                    context_data["self_signed_cert"] = True
                if ioc_value in asym_lookup:
                    context_data["flow_asymmetry"] = asym_lookup[ioc_value]
                if ioc_value in port_lookup:
                    context_data["port_anomaly"] = port_lookup[ioc_value]

            scored.append(
                self.score_ioc(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    osint_data=osint_data,
                    behavioral_data=behavioral_data,
                    context_data=context_data,
                )
            )

        scored.sort(key=lambda s: s.priority_score, reverse=True)
        return scored

    def explain_score(self, scored_ioc: ScoredIOC) -> str:
        lines = [
            f"IOC: {scored_ioc.value} ({scored_ioc.ioc_type})",
            f"Priority: {scored_ioc.priority_label.upper()} ({scored_ioc.priority_score:.1%})",
            "",
            "Contributing factors:",
        ]
        for fname, fdata in sorted(scored_ioc.factors.items(), key=lambda x: x[1].get("contribution", 0), reverse=True):
            contrib = fdata.get("contribution", 0)
            if contrib > 0:
                lines.append(f"  - {fname}: {fdata.get('value', '')} (+{contrib:.1%})")
        lines.append("")
        lines.append(f"Recommendation: {scored_ioc.recommendation}")
        return "\n".join(lines)


def build_ioc_inventory(
    evidence_or_flows: list[Any] | None = None,
    findings: list[Any] | None = None,
    *,
    flows: list[dict[str, Any]] | None = None,
    domains: list[str] | None = None,
    carved_files: list[dict[str, Any]] | None = None,
    tls_analysis: dict[str, Any] | None = None,
    osint: dict[str, Any] | None = None,
    beacon_results: list[dict[str, Any]] | None = None,
    dns_analysis: dict[str, Any] | None = None,
    asymmetry_results: list[Any] | None = None,
    port_anomalies: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Build normalized unified IOC inventory (`ip`, `domain`, `hash`, `ja3`) ranked by IOCScorer."""
    flows_list: list[dict[str, Any]] = list(flows or [])
    domains_list: list[str] = list(domains or [])
    carved_list: list[dict[str, Any]] = list(carved_files or [])
    tls_dict: dict[str, Any] = dict(tls_analysis or {})

    if evidence_or_flows:
        ja3_sessions: list[dict[str, Any]] = []
        for item in evidence_or_flows:
            if isinstance(item, dict) and "kind" not in item:
                flows_list.append(item)
                continue
            kind = getattr(item, "kind", item.get("kind") if isinstance(item, dict) else None)
            attrs = getattr(item, "attributes", item.get("attributes") if isinstance(item, dict) else None) or {}
            if not isinstance(attrs, dict):
                continue
            if kind == "flow":
                flows_list.append(attrs)
            elif kind == "dns":
                q = str(attrs.get("query") or "").strip()
                if q:
                    domains_list.append(q)
            elif kind == "yara":
                sha = str(attrs.get("object_sha256") or attrs.get("artifact_sha256") or "").strip()
                if sha:
                    carved_list.append({"sha256": sha})
            elif kind == "tls":
                jh = str(attrs.get("ja3") or attrs.get("ja3_hash") or "").strip()
                if jh:
                    ja3_sessions.append(
                        {
                            "ja3": jh,
                            "client": attrs.get("ja3_client") or attrs.get("matched_label") or "Unknown",
                            "is_malware": bool(attrs.get("ja3_malware")),
                        }
                    )
        if ja3_sessions and not tls_dict.get("ja3"):
            tls_dict["ja3"] = {"sessions": ja3_sessions}

    flows = flows_list
    domains = domains_list
    carved_files = carved_list
    tls_analysis = tls_dict
    ip_stats: dict[str, dict[str, int]] = {}
    raw_iocs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for f in flows or []:
        b = int(f.get("bytes", 0) or 0)
        for ep in (f.get("src"), f.get("dst")):
            ip_s = str(ep or "").strip()
            if not ip_s:
                continue
            st = ip_stats.setdefault(ip_s, {"connections": 0, "bytes": 0})
            st["connections"] += 1
            st["bytes"] += b
            if _is_public_ipv4(ip_s) and ("ip", ip_s) not in seen:
                seen.add(("ip", ip_s))
                raw_iocs.append({"type": "ip", "value": ip_s})

    for dom in domains or []:
        dom_s = str(dom or "").strip()
        if dom_s and ("domain", dom_s) not in seen:
            seen.add(("domain", dom_s))
            raw_iocs.append({"type": "domain", "value": dom_s})

    for item in carved_files or []:
        if not isinstance(item, dict):
            continue
        sha = str(item.get("sha256", "") or "").strip()
        if sha and ("hash", sha) not in seen:
            seen.add(("hash", sha))
            raw_iocs.append({"type": "hash", "value": sha})

    ja3_block = (tls_analysis or {}).get("ja3") or {}
    osint_ja3: dict[str, Any] = dict((osint or {}).get("ja3") or {})
    ja3_entries = (
        list(ja3_block.get("client_ja3") or []) + list(ja3_block.get("sessions") or [])
        if isinstance(ja3_block, dict)
        else []
    )
    for rec in ja3_entries:
        if not isinstance(rec, dict):
            continue
        jh = str(rec.get("ja3", "") or "").strip()
        if not jh:
            continue
        client_label = str(rec.get("client") or rec.get("ja3_client") or "Unknown")
        is_mal = bool(rec.get("is_malware") or rec.get("ja3_malware"))
        osint_ja3.setdefault(jh, {"client": client_label, "malware": is_mal})
        if ("ja3", jh) not in seen:
            seen.add(("ja3", jh))
            raw_iocs.append({"type": "ja3", "value": jh, "meta": {"client": client_label, "malware": is_mal}})

    enriched_osint = dict(osint or {})
    enriched_osint["ja3"] = osint_ja3
    scorer = IOCScorer()
    scored = scorer.rank_iocs(
        raw_iocs,
        osint=enriched_osint,
        beacon_results=beacon_results,
        dns_analysis=dns_analysis,
        tls_analysis=tls_analysis,
        asymmetry_results=asymmetry_results,
        port_anomalies=port_anomalies,
        flow_stats_by_ip=ip_stats,
    )
    return [item.to_dict() for item in scored[:500]]


__all__ = [
    "CorrelationResult",
    "CorrelationSignal",
    "DEFAULT_PRIORITY_THRESHOLDS",
    "DEFAULT_WEIGHTS",
    "IOCScorer",
    "JA3_MALWARE_DEFAULT_DETECTIONS",
    "PRIORITY_THRESHOLDS",
    "SIGNAL_WEIGHTS",
    "ScoredIOC",
    "VERDICT_THRESHOLDS",
    "VT_DEFAULT_TOTAL_ENGINES",
    "build_ioc_inventory",
    "correlate_bundle_findings",
    "correlate_indicators",
    "correlate_zeek_and_tshark_evidence",
]
