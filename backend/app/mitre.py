"""MITRE ATT&CK v19.1 mapping engine & kill-chain hypothesis generator."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

VALID_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "file", "ja3"}
MAX_BEACON_RESULTS = 20
MAX_YARA_RESULTS = 20
MAX_TLS_ALERTS = 20
MAX_JA3_FINGERPRINTS = 50
MAX_FLOWS = 1000
ATTACK_VERSION = "19.1"
MAPPING_SCHEMA_VERSION = 2
VALID_DISPOSITIONS = {"unreviewed", "confirmed", "dismissed", "false_positive"}
AVG_PACKET_SIZE_ESTIMATE = 800
C2_SUSPECT_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337}


@dataclass
class TechniqueMatch:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    analytic_id: str | None = None
    data_components: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    disposition: str = "unreviewed"
    analyst_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": round(float(self.confidence), 3),
            "evidence": self.evidence,
            "evidence_ids": self.evidence_ids,
            "analytic_id": self.analytic_id,
            "data_components": self.data_components,
            "limitations": self.limitations,
            "references": self.references,
            "disposition": self.disposition,
            "analyst_note": self.analyst_note,
        }


@dataclass
class AttackMapping:
    techniques: list[TechniqueMatch] = field(default_factory=list)
    tactics_summary: dict[str, int] = field(default_factory=dict)
    kill_chain_phase: str = "unknown"
    overall_severity: str = "low"
    attack_version: str = ATTACK_VERSION
    mapping_schema_version: int = MAPPING_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_version": self.attack_version,
            "mapping_schema_version": self.mapping_schema_version,
            "techniques": [t.to_dict() for t in self.techniques],
            "tactics_summary": self.tactics_summary,
            "kill_chain_phase": self.kill_chain_phase,
            "overall_severity": self.overall_severity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackMapping":
        techniques = [
            TechniqueMatch(
                technique_id=str(item.get("technique_id", "")),
                technique_name=str(item.get("technique_name", "")),
                tactic=str(item.get("tactic", "")),
                confidence=float(item.get("confidence", 0.0)),
                evidence=[str(v) for v in item.get("evidence", [])],
                evidence_ids=[str(v) for v in item.get("evidence_ids", [])],
                analytic_id=item.get("analytic_id") or None,
                data_components=[str(v) for v in item.get("data_components", [])],
                limitations=[str(v) for v in item.get("limitations", [])],
                references=[str(v) for v in item.get("references", [])],
                disposition=item.get("disposition", "unreviewed")
                if item.get("disposition", "unreviewed") in VALID_DISPOSITIONS
                else "unreviewed",
                analyst_note=str(item.get("analyst_note", "")),
            )
            for item in data.get("techniques", [])
            if isinstance(item, dict)
        ]
        return cls(
            techniques=techniques,
            tactics_summary={str(k): int(v) for k, v in (data.get("tactics_summary") or {}).items()},
            kill_chain_phase=str(data.get("kill_chain_phase", "unknown")),
            overall_severity=str(data.get("overall_severity", "low")),
            attack_version=str(data.get("attack_version", ATTACK_VERSION)),
            mapping_schema_version=int(data.get("mapping_schema_version", MAPPING_SCHEMA_VERSION)),
        )


KILL_CHAIN_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

DETECTION_RULES: dict[str, dict[str, Any]] = {
    "beacon_score": {
        "threshold": 0.7,
        "techniques": [
            {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "command-and-control"},
            {"id": "T1571", "name": "Non-Standard Port", "tactic": "command-and-control"},
            {"id": "T1573", "name": "Encrypted Channel", "tactic": "command-and-control"},
        ],
    },
    "dns_tunneling": {
        "threshold": 0.6,
        "techniques": [
            {"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "command-and-control"},
            {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Non-C2 Protocol", "tactic": "exfiltration"},
        ],
    },
    "dga_detected": {
        "threshold": 0.7,
        "techniques": [
            {"id": "T1568.002", "name": "Dynamic Resolution: Domain Generation Algorithms", "tactic": "command-and-control"},
        ],
    },
    "dns_fast_flux": {
        "threshold": 0.6,
        "techniques": [
            {"id": "T1568.001", "name": "Dynamic Resolution: Fast Flux DNS", "tactic": "command-and-control"},
        ],
    },
    "self_signed_cert": {
        "techniques": [
            {"id": "T1573.002", "name": "Encrypted Channel: Asymmetric Cryptography", "tactic": "command-and-control"},
        ],
    },
    "expired_cert": {
        "techniques": [
            {"id": "T1573.002", "name": "Encrypted Channel: Asymmetric Cryptography", "tactic": "command-and-control"},
        ],
    },
    "ja3_malware": {
        "techniques": [
            {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "command-and-control"},
            {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "command-and-control"},
        ],
    },
    "yara_critical": {
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
            {"id": "T1055", "name": "Process Injection", "tactic": "defense-evasion"},
        ],
    },
    "yara_high": {
        "techniques": [
            {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
        ],
    },
    "large_outbound": {
        "threshold": 10_000_000,
        "techniques": [
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
        ],
    },
    "non_standard_port": {
        "techniques": [
            {"id": "T1571", "name": "Non-Standard Port", "tactic": "command-and-control"},
        ],
    },
    "arp_spoofing_conflict": {
        "techniques": [
            {"id": "T1557.002", "name": "Adversary-in-the-Middle: ARP Cache Poisoning", "tactic": "credential-access"},
        ],
    },
    "port_scan": {
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "discovery"},
        ],
    },
    "dos_flood": {
        "techniques": [
            {"id": "T1498", "name": "Network Denial of Service", "tactic": "impact"},
        ],
    },
    "http_injection": {
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
        ],
    },
    "wifi_deauth": {
        "techniques": [
            {"id": "T1498.001", "name": "Network Denial of Service: Direct Network Flood", "tactic": "impact"},
        ],
    },
}

TECHNIQUE_METADATA: dict[str, dict[str, Any]] = {
    "T1071.001": {
        "data_components": ["Network Traffic: Web Protocols"],
        "analytic_id": "DET0027",
        "references": ["https://attack.mitre.org/detectionstrategies/DET0027/"],
        "limitations": ["Beacon periodicity alone does not prove HTTP or web-protocol C2."],
    },
    "T1573": {
        "data_components": ["Network Traffic Flow"],
        "limitations": ["Beacon periodicity alone does not prove an encrypted channel."],
    },
    "T1071.004": {
        "data_components": ["Network Traffic: DNS"],
        "limitations": ["DNS anomaly scoring does not establish operator intent or exfiltration."],
    },
    "T1568.001": {
        "data_components": ["Network Traffic: DNS"],
        "limitations": ["Fast-flux indicators require infrastructure corroboration to distinguish benign CDNs."],
    },
    "T1568.002": {
        "data_components": ["Network Traffic: DNS"],
        "limitations": ["DGA scoring is probabilistic and should be confirmed with domain-age or endpoint evidence."],
    },
    "T1571": {
        "analytic_id": "DET0227",
        "data_components": ["Network Traffic Flow"],
        "references": ["https://attack.mitre.org/detectionstrategies/DET0227/"],
        "limitations": ["A non-standard port is not malicious without protocol and asset context."],
    },
    "T1573.002": {
        "data_components": ["Network Traffic: SSL/TLS"],
        "limitations": ["Certificate anomalies do not prove encrypted C2 or attacker-controlled keys."],
    },
    "T1041": {
        "data_components": ["Network Traffic Flow"],
        "limitations": ["High outbound volume alone does not establish exfiltration or C2 use."],
    },
    "T1048": {
        "data_components": ["Network Traffic Flow"],
        "limitations": ["High outbound volume alone does not identify an alternative exfiltration protocol."],
    },
    "T1048.003": {
        "data_components": ["Network Traffic: DNS"],
        "limitations": ["High DNS label entropy or volume alone does not establish exfiltration."],
    },
    "T1027": {"limitations": ["YARA severity alone does not identify obfuscation; rule semantics and file context are required."]},
    "T1059": {"limitations": ["A carved-file YARA severity does not prove command or scripting execution."]},
    "T1055": {"limitations": ["A carved-file YARA severity does not prove process injection."]},
    "T1105": {"limitations": ["A YARA match does not prove tool transfer without transfer lineage and endpoint evidence."]},
    "T1095": {"limitations": ["JA3 reputation alone does not prove a non-application-layer protocol."]},
    "T1557.002": {
        "data_components": ["Network Traffic Flow"],
        "limitations": ["Duplicate ARP MAC announcements may reflect VRRP/HA failover rather than active poisoning."],
    },
    "T1046": {
        "data_components": ["Network Traffic Flow"],
        "limitations": ["Distinct port probing can reflect vulnerability scanning or service health checks."],
    },
    "T1498": {
        "data_components": ["Network Traffic Flow"],
        "limitations": ["High ICMP/RST/SYN packet rates require baseline capacity verification."],
    },
    "T1498.001": {
        "data_components": ["Network Traffic: Management Frames"],
        "limitations": ["802.11 deauthentication bursts can occur during AP channel roaming or maintenance."],
    },
    "T1190": {
        "data_components": ["Network Traffic: Web Protocols"],
        "limitations": ["Sanitized URI injection markers indicate probing and do not confirm exploitation succeeded."],
    },
}


class ATTACKMapper:
    """Maps analysis results to ATT&CK v19.1 technique hypotheses with analyst-reviewable state."""

    def __init__(self) -> None:
        self.detection_rules = DETECTION_RULES

    def map_analysis(
        self,
        features: dict[str, Any] | None = None,
        dns_analysis: dict[str, Any] | None = None,
        tls_analysis: dict[str, Any] | None = None,
        yara_results: dict[str, Any] | None = None,
        beacon_results: list[dict[str, Any]] | None = None,
        osint: dict[str, Any] | None = None,
        findings: list[Any] | None = None,
        dispositions: dict[str, dict[str, str]] | None = None,
    ) -> AttackMapping:
        techniques: list[TechniqueMatch] = []

        if beacon_results:
            techniques.extend(self._check_beaconing(beacon_results[:MAX_BEACON_RESULTS]))
        if dns_analysis:
            techniques.extend(self._check_dns(dns_analysis))
        if tls_analysis:
            techniques.extend(self._check_tls(tls_analysis))
        if yara_results:
            techniques.extend(self._check_yara(yara_results))
        if osint and osint.get("ja3"):
            techniques.extend(self._check_ja3(osint["ja3"]))
        elif features and (features.get("artifacts") or {}).get("ja3"):
            techniques.extend(self._check_ja3_from_features(features))
        if features:
            techniques.extend(self._check_data_transfer(features))
            techniques.extend(self._check_suspicious_ports(features))
        if findings:
            techniques.extend(self._check_detector_findings(findings))

        techniques = self._deduplicate_techniques(techniques)
        self._annotate_techniques(techniques)
        if dispositions:
            for t in techniques:
                key = f"{t.technique_id}:{t.tactic}"
                entry = dispositions.get(key) or dispositions.get(t.technique_id)
                if isinstance(entry, dict):
                    disp = entry.get("disposition", "unreviewed")
                    if disp in VALID_DISPOSITIONS:
                        t.disposition = disp
                    t.analyst_note = str(entry.get("analyst_note", "") or "")[:500]

        tactics_summary = self._calculate_tactics_summary(techniques)
        kill_chain_phase = self._determine_kill_chain_phase(tactics_summary)
        overall_severity = self._calculate_severity(techniques)
        return AttackMapping(
            techniques=techniques,
            tactics_summary=tactics_summary,
            kill_chain_phase=kill_chain_phase,
            overall_severity=overall_severity,
        )

    def _check_beaconing(self, beacon_results: list[dict[str, Any]]) -> list[TechniqueMatch]:
        techniques: list[TechniqueMatch] = []
        rule = self.detection_rules["beacon_score"]
        threshold = rule["threshold"]
        for beacon in beacon_results:
            score = float(beacon.get("score", 0) or 0) if isinstance(beacon, dict) else 0.0
            if score >= threshold:
                proto = beacon.get("proto") or beacon.get("protocol")
                protocol_note = f" over {proto}" if proto else ""
                ev = f"Beaconing detected with score {score:.2f} to {beacon.get('dst', 'unknown')}{protocol_note}"
                for tech in rule["techniques"]:
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=min(score, 1.0),
                            evidence=[ev],
                        )
                    )
        return techniques

    def _check_dns(self, dns_analysis: dict[str, Any]) -> list[TechniqueMatch]:
        techniques: list[TechniqueMatch] = []
        alerts = dns_analysis.get("alerts") or {}
        dga_count = int(alerts.get("dga_count", 0) or 0)
        if dga_count > 0:
            domains = [str(d.get("domain", "")) for d in dns_analysis.get("dga_detections", [])[:5] if isinstance(d, dict)]
            for tech in self.detection_rules["dga_detected"]["techniques"]:
                techniques.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=min(0.5 + dga_count * 0.1, 1.0),
                        evidence=[f"DGA domains detected: {', '.join(domains)}"],
                    )
                )

        tun_count = int(alerts.get("tunneling_count", 0) or 0)
        if tun_count > 0:
            for tech in self.detection_rules["dns_tunneling"]["techniques"]:
                techniques.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=min(0.6 + tun_count * 0.1, 1.0),
                        evidence=[f"DNS tunneling indicators: {tun_count} suspicious queries"],
                    )
                )

        ff_count = int(alerts.get("fast_flux_count", 0) or 0)
        if ff_count > 0:
            for tech in self.detection_rules["dns_fast_flux"]["techniques"]:
                techniques.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=min(0.5 + ff_count * 0.15, 1.0),
                        evidence=[f"Fast flux DNS detected for {ff_count} domains"],
                    )
                )
        return techniques

    def _check_tls(self, tls_analysis: dict[str, Any]) -> list[TechniqueMatch]:
        techniques: list[TechniqueMatch] = []
        alerts: list[dict[str, Any]] = []
        raw_alerts = tls_analysis.get("alerts", [])
        if isinstance(raw_alerts, list):
            alerts.extend(a for a in raw_alerts if isinstance(a, dict))
        cert_alerts = tls_analysis.get("certificate_alerts", [])
        if isinstance(cert_alerts, list):
            alerts.extend(a for a in cert_alerts if isinstance(a, dict))
        certs_block = tls_analysis.get("certificates") or {}
        if isinstance(certs_block, dict):
            for c in certs_block.get("certificates", [])[:MAX_TLS_ALERTS]:
                if not isinstance(c, dict):
                    continue
                subj = str(c.get("subject_cn") or c.get("dst_ip") or "unknown")
                if c.get("is_self_signed"):
                    alerts.append({"type": "self_signed", "cert": subj, "dst_ip": c.get("dst_ip", "")})
                if c.get("is_expired"):
                    alerts.append({"type": "expired", "cert": subj, "dst_ip": c.get("dst_ip", "")})

        for alert in alerts[:MAX_TLS_ALERTS]:
            atype = alert.get("type", "")
            cert = alert.get("cert", "unknown")
            if atype == "self_signed":
                for tech in self.detection_rules["self_signed_cert"]["techniques"]:
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=0.7,
                            evidence=[f"Self-signed certificate: {cert}"],
                        )
                    )
            elif atype == "expired":
                for tech in self.detection_rules["expired_cert"]["techniques"]:
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=0.5,
                            evidence=[f"Expired certificate: {cert}"],
                        )
                    )

        ja3_block = tls_analysis.get("ja3") or {}
        if isinstance(ja3_block, dict):
            ja3_candidates = (
                list(ja3_block.get("client_ja3") or [])
                + list(ja3_block.get("malware_ja3") or [])
                + list(ja3_block.get("sessions") or [])
            )
            seen_jh: set[str] = set()
            for entry in ja3_candidates[:MAX_JA3_FINGERPRINTS]:
                if not isinstance(entry, dict):
                    continue
                is_mal = bool(entry.get("is_malware") or entry.get("ja3_malware"))
                jh = str(entry.get("ja3", "") or "")
                if not is_mal or (jh and jh in seen_jh):
                    continue
                if jh:
                    seen_jh.add(jh)
                client = str(entry.get("client") or entry.get("ja3_client") or "Unknown malware")
                for tech in self.detection_rules["ja3_malware"]["techniques"]:
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=0.85,
                            evidence=[f"Malicious JA3 fingerprint: {client} ({jh[:16]}...)"],
                        )
                    )
        return techniques

    def _check_yara(self, yara_results: dict[str, Any]) -> list[TechniqueMatch]:
        techniques: list[TechniqueMatch] = []
        by_sev = yara_results.get("by_severity") or {}
        results = (yara_results.get("results") or [])[:MAX_YARA_RESULTS]

        if int(by_sev.get("critical", 0) or 0) > 0:
            files = [str(r.get("file_name") or r.get("filename") or "") for r in results if isinstance(r, dict) and r.get("severity") == "critical"]
            for tech in self.detection_rules["yara_critical"]["techniques"]:
                techniques.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=0.9,
                        evidence=[f"Critical YARA matches in: {', '.join(files[:3])}"],
                    )
                )
        if int(by_sev.get("high", 0) or 0) > 0:
            files = [str(r.get("file_name") or r.get("filename") or "") for r in results if isinstance(r, dict) and r.get("severity") == "high"]
            for tech in self.detection_rules["yara_high"]["techniques"]:
                techniques.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=0.75,
                        evidence=[f"High-severity YARA matches in: {', '.join(files[:3])}"],
                    )
                )
        return techniques

    def _check_ja3(self, ja3_data: dict[str, Any]) -> list[TechniqueMatch]:
        techniques: list[TechniqueMatch] = []
        for ja3_hash, info in ja3_data.items():
            if isinstance(info, dict) and info.get("malware"):
                client = info.get("client", "Unknown")
                for tech in self.detection_rules["ja3_malware"]["techniques"]:
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=0.85,
                            evidence=[f"Malicious JA3 fingerprint: {client} ({str(ja3_hash)[:16]}...)"],
                        )
                    )
        return techniques

    def _check_ja3_from_features(self, features: dict[str, Any]) -> list[TechniqueMatch]:
        techniques: list[TechniqueMatch] = []
        known_malware = {
            "72a589da586844d7f0818ce684948eea": "Emotet",
            "a0e9f5d64349fb13191bc781f81f42e1": "TrickBot",
            "51c64c77e60f3980eea90869b68c58a8": "Cobalt Strike",
        }
        for ja3 in (features.get("artifacts") or {}).get("ja3", [])[:MAX_JA3_FINGERPRINTS]:
            jh = ja3 if isinstance(ja3, str) else str((ja3 or {}).get("hash", "") or "")
            if jh in known_malware:
                techniques.append(
                    TechniqueMatch(
                        technique_id="T1071.001",
                        technique_name="Application Layer Protocol: Web Protocols",
                        tactic="command-and-control",
                        confidence=0.85,
                        evidence=[f"Known malware JA3 fingerprint detected: {known_malware[jh]}"],
                    )
                )
        return techniques

    def _check_data_transfer(self, features: dict[str, Any]) -> list[TechniqueMatch]:
        techniques: list[TechniqueMatch] = []
        threshold = int(self.detection_rules["large_outbound"]["threshold"])
        outbound_by_dst: dict[str, int] = {}
        for flow in (features.get("flows") or [])[:MAX_FLOWS]:
            dst = str(flow.get("dst", "") or "")
            cnt = int(flow.get("count", flow.get("packets", 0)) or 0)
            b = int(flow.get("bytes", 0) or 0) or cnt * AVG_PACKET_SIZE_ESTIMATE
            if dst:
                outbound_by_dst[dst] = outbound_by_dst.get(dst, 0) + b
        for dst, total_bytes in outbound_by_dst.items():
            if total_bytes >= threshold:
                for tech in self.detection_rules["large_outbound"]["techniques"]:
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=min(0.5 + (total_bytes / threshold) * 0.1, 0.9),
                            evidence=[f"Large data transfer to {dst}: {total_bytes / 1_000_000:.1f} MB"],
                        )
                    )
        return techniques

    def _check_suspicious_ports(self, features: dict[str, Any]) -> list[TechniqueMatch]:
        matches: list[TechniqueMatch] = []
        seen: set[tuple[str, int]] = set()
        for flow in (features.get("flows") or [])[:MAX_FLOWS]:
            try:
                port = int(flow.get("dport", flow.get("dst_port", 0)) or 0)
            except (TypeError, ValueError):
                continue
            dst = str(flow.get("dst") or "unknown")
            if port not in C2_SUSPECT_PORTS or (dst, port) in seen:
                continue
            seen.add((dst, port))
            for tech in self.detection_rules["non_standard_port"]["techniques"]:
                matches.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=0.7,
                        evidence=[f"C2-suspect destination port {port} observed to {dst}"],
                    )
                )
        return matches

    def _check_detector_findings(self, findings: list[Any]) -> list[TechniqueMatch]:
        matches: list[TechniqueMatch] = []
        for f in findings:
            detector = str(getattr(f, "detector", f.get("detector", "") if isinstance(f, dict) else ""))
            title = str(getattr(f, "title", f.get("title", "") if isinstance(f, dict) else ""))
            summary = str(getattr(f, "summary", f.get("summary", "") if isinstance(f, dict) else "")) or title
            raw_ev_ids = getattr(f, "evidence_ids", f.get("evidence_ids", []) if isinstance(f, dict) else []) or []
            ev_ids = [str(eid) for eid in raw_ev_ids if eid]
            rule_key: str | None = None
            conf = 0.6
            if detector == "arp_spoofing_conflict":
                rule_key, conf = "arp_spoofing_conflict", 0.78
            elif detector in ("tcp_destination_port_spread", "arp_scan_burst"):
                rule_key, conf = "port_scan", 0.55
            elif detector in ("icmp_smurf_or_flood", "tcp_flood_or_rst_storm"):
                rule_key, conf = "dos_flood", 0.65
            elif detector == "http_suspicious_uri":
                rule_key, conf = "http_injection", 0.72
            elif detector == "wlan_deauth_burst":
                rule_key, conf = "wifi_deauth", 0.75
            elif detector == "flow_periodic_beacon":
                rule_key, conf = "beacon_score", 0.68
            elif detector in ("dns_query_label_entropy",):
                rule_key, conf = "dns_tunneling", 0.64
            elif detector in ("dns_nxdomain_burst", "dns_origin_nxdomain_ratio"):
                rule_key, conf = "dga_detected", 0.62
            elif detector == "dns_fast_flux_heuristic":
                rule_key, conf = "dns_fast_flux", 0.66
            elif detector in (
                "tls_certificate_self_signed",
                "tls_certificate_weak_key",
                "tls_certificate_long_validity",
                "tls_certificate_weak_signature",
                "tls_sni_certificate_mismatch",
            ):
                rule_key, conf = "self_signed_cert", 0.58
            elif detector == "tls_certificate_expired":
                rule_key, conf = "expired_cert", 0.54
            elif detector in ("tls_ja3_known_signature", "tls_ja3_concentration"):
                rule_key, conf = "ja3_malware", 0.60 if detector == "tls_ja3_concentration" else 0.78
            elif detector == "yara_rule_match":
                rule_key, conf = "yara_high", 0.74
            if rule_key and rule_key in self.detection_rules:
                for tech in self.detection_rules[rule_key]["techniques"]:
                    matches.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=conf,
                            evidence=[summary[:240]],
                            evidence_ids=list(ev_ids[:8]),
                        )
                    )
        return matches

    def _deduplicate_techniques(self, techniques: list[TechniqueMatch]) -> list[TechniqueMatch]:
        seen: dict[str, TechniqueMatch] = {}
        for tech in techniques:
            key = f"{tech.technique_id}:{tech.tactic}"
            if key in seen:
                ex = seen[key]
                ex.confidence = max(ex.confidence, tech.confidence)
                for ev in tech.evidence:
                    if ev not in ex.evidence and len(ex.evidence) < 12:
                        ex.evidence.append(ev)
                for eid in tech.evidence_ids:
                    if eid not in ex.evidence_ids and len(ex.evidence_ids) < 16:
                        ex.evidence_ids.append(eid)
                ex.data_components.extend(tech.data_components)
                ex.limitations.extend(tech.limitations)
                ex.references.extend(tech.references)
            else:
                seen[key] = TechniqueMatch(
                    technique_id=tech.technique_id,
                    technique_name=tech.technique_name,
                    tactic=tech.tactic,
                    confidence=tech.confidence,
                    evidence=list(tech.evidence[:12]),
                    evidence_ids=list(tech.evidence_ids[:16]),
                    analytic_id=tech.analytic_id,
                    data_components=list(tech.data_components),
                    limitations=list(tech.limitations),
                    references=list(tech.references),
                    disposition=tech.disposition,
                    analyst_note=tech.analyst_note,
                )
        return list(seen.values())

    def _annotate_techniques(self, techniques: list[TechniqueMatch]) -> None:
        for tech in techniques:
            meta = TECHNIQUE_METADATA.get(tech.technique_id, {})
            analytic_id = meta.get("analytic_id")
            ev_text = " ".join(tech.evidence).lower()
            if tech.technique_id == "T1071.001" and not any(tok in ev_text for tok in ("http", "https", "web protocol")):
                analytic_id = None
            tech.analytic_id = tech.analytic_id or analytic_id
            meta_components = meta.get("data_components", [])
            if tech.technique_id == "T1071.001" and analytic_id is None:
                meta_components = ["Network Traffic Flow"]
            tech.data_components = list(dict.fromkeys(tech.data_components + list(meta_components)))
            tech.limitations = list(dict.fromkeys(tech.limitations + list(meta.get("limitations", []))))
            tech.references = list(dict.fromkeys(tech.references + list(meta.get("references", []))))
            tech.disposition = tech.disposition if tech.disposition in VALID_DISPOSITIONS else "unreviewed"

    def _calculate_tactics_summary(self, techniques: list[TechniqueMatch]) -> dict[str, int]:
        summary: dict[str, int] = {}
        for t in techniques:
            summary[t.tactic] = summary.get(t.tactic, 0) + 1
        return summary

    def _determine_kill_chain_phase(self, tactics_summary: dict[str, int]) -> str:
        if not tactics_summary:
            return "unknown"
        max_idx = -1
        adv = "unknown"
        for tactic in tactics_summary:
            if tactic in KILL_CHAIN_ORDER:
                idx = KILL_CHAIN_ORDER.index(tactic)
                if idx > max_idx:
                    max_idx = idx
                    adv = tactic
        return adv

    def _calculate_severity(self, techniques: list[TechniqueMatch]) -> str:
        if not techniques:
            return "low"
        high_impact = {"exfiltration", "impact", "command-and-control"}
        max_conf = max(t.confidence for t in techniques)
        has_high = any(t.tactic in high_impact for t in techniques)
        if has_high and max_conf >= 0.8:
            return "critical"
        if has_high or max_conf >= 0.7:
            return "high"
        if len(techniques) >= 3 or max_conf >= 0.5:
            return "medium"
        return "low"

    def to_json(self, mapping: AttackMapping) -> str:
        return json.dumps(mapping.to_dict(), indent=2)


def build_attack_timeline(bundle_or_mapping: Any) -> list[dict[str, Any]]:
    """Build a kill-chain ordered ATT&CK timeline from an EvidenceBundle or AttackMapping."""
    if bundle_or_mapping is None:
        return []
    if isinstance(bundle_or_mapping, AttackMapping):
        raw_mapping = bundle_or_mapping.to_dict()
        evidence_items: list[dict[str, Any]] = []
    elif isinstance(bundle_or_mapping, dict):
        if "mitre_attack" in bundle_or_mapping:
            raw_mapping = bundle_or_mapping.get("mitre_attack") or {}
            evidence_items = list(bundle_or_mapping.get("evidence") or [])
        else:
            raw_mapping = bundle_or_mapping
            evidence_items = []
    else:
        raw_mapping = getattr(bundle_or_mapping, "mitre_attack", None) or {}
        if isinstance(raw_mapping, AttackMapping):
            raw_mapping = raw_mapping.to_dict()
        raw_ev = getattr(bundle_or_mapping, "evidence", None) or []
        evidence_items = [
            ev.model_dump() if hasattr(ev, "model_dump") else (dict(ev) if isinstance(ev, dict) else {})
            for ev in raw_ev
        ]

    techniques = list((raw_mapping or {}).get("techniques") or [])
    if not techniques:
        return []

    global_first: float | None = None
    global_last: float | None = None
    ev_index: list[tuple[str, float | None, float | None, list[int]]] = []
    for ev in evidence_items:
        if not isinstance(ev, dict):
            continue
        attrs = ev.get("attributes") or {}
        summary = str(ev.get("summary") or "").lower()
        t0 = attrs.get("first_seen") or attrs.get("time_epoch")
        t1 = attrs.get("last_seen") or t0
        try:
            f0 = float(t0) if t0 is not None else None
        except (TypeError, ValueError):
            f0 = None
        try:
            f1 = float(t1) if t1 is not None else f0
        except (TypeError, ValueError):
            f1 = f0
        if f0 is not None:
            global_first = f0 if global_first is None else min(global_first, f0)
        if f1 is not None:
            global_last = f1 if global_last is None else max(global_last, f1)
        refs = [int(r) for r in (ev.get("packet_refs") or [])[:8] if isinstance(r, (int, float))]
        blob = summary + " " + " ".join(f"{k}={v}".lower() for k, v in attrs.items())
        ev_index.append((blob, f0, f1, refs))

    timeline: list[dict[str, Any]] = []
    for tech in techniques:
        if not isinstance(tech, dict):
            tech = tech.to_dict() if hasattr(tech, "to_dict") else {}
        tactic = str(tech.get("tactic") or "unknown")
        tactic_order = KILL_CHAIN_ORDER.index(tactic) if tactic in KILL_CHAIN_ORDER else len(KILL_CHAIN_ORDER)
        sample_ev = [str(x) for x in (tech.get("evidence") or [])[:6]]

        matched_first: float | None = None
        matched_last: float | None = None
        pkt_refs: list[int] = []
        tokens = [
            tok.lower()
            for line in sample_ev
            for tok in line.replace("=", " ").replace(":", " ").replace(",", " ").split()
            if len(tok) >= 4
        ][:12]
        for blob, f0, f1, refs in ev_index:
            if tokens and any(tok in blob for tok in tokens):
                if f0 is not None:
                    matched_first = f0 if matched_first is None else min(matched_first, f0)
                if f1 is not None:
                    matched_last = f1 if matched_last is None else max(matched_last, f1)
                for r in refs:
                    if r not in pkt_refs and len(pkt_refs) < 12:
                        pkt_refs.append(r)

        timeline.append(
            {
                "tactic": tactic,
                "tactic_order": tactic_order,
                "technique_id": str(tech.get("technique_id") or ""),
                "technique_name": str(tech.get("technique_name") or ""),
                "confidence": round(float(tech.get("confidence") or 0.0), 3),
                "disposition": str(tech.get("disposition") or "unreviewed"),
                "first_seen": matched_first if matched_first is not None else global_first,
                "last_seen": matched_last if matched_last is not None else global_last,
                "evidence_count": len(tech.get("evidence") or []),
                "sample_evidence": sample_ev,
                "evidence_ids": [str(x) for x in (tech.get("evidence_ids") or [])[:8]],
                "packet_refs": pkt_refs,
            }
        )

    timeline.sort(
        key=lambda item: (
            item["tactic_order"],
            float(item["first_seen"]) if item["first_seen"] is not None else float("inf"),
            -float(item["confidence"]),
            item["technique_id"],
        )
    )
    return timeline


__all__ = [
    "ATTACKMapper",
    "ATTACK_VERSION",
    "AttackMapping",
    "C2_SUSPECT_PORTS",
    "DETECTION_RULES",
    "KILL_CHAIN_ORDER",
    "MAPPING_SCHEMA_VERSION",
    "TECHNIQUE_METADATA",
    "TechniqueMatch",
    "VALID_DISPOSITIONS",
    "VALID_IOC_TYPES",
    "build_attack_timeline",
]
