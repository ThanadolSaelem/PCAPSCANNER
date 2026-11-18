from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import httpx

try:
    import pydantic

    HAS_PYDANTIC_V2 = int(getattr(pydantic, "__version__", "1").split(".")[0]) >= 2
except Exception:
    HAS_PYDANTIC_V2 = False

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import etbert_bridge, system, triage  # noqa: E402


@dataclass
class _StubEvidence:
    evidence_id: str
    kind: str
    summary: str
    packet_refs: list[int]
    attributes: dict[str, object]


@dataclass
class _StubFinding:
    finding_id: str
    detector: str
    title: str
    severity: str
    confidence: str
    evidence_ids: list[str]
    limitations: list[str] = field(default_factory=list)


@dataclass
class _StubCoverage:
    packets_seen: int = 100
    packets_analyzed: int = 100
    truncated: bool = False
    parser: str = "tshark-fields-offline"
    warnings: list[str] = field(default_factory=list)
    stages: list[object] = field(default_factory=list)

    def model_copy(self, update: dict[str, object]) -> "_StubCoverage":
        data = {
            "packets_seen": self.packets_seen,
            "packets_analyzed": self.packets_analyzed,
            "truncated": self.truncated,
            "parser": self.parser,
            "warnings": list(self.warnings),
            "stages": list(self.stages),
        }
        data.update(update)
        return _StubCoverage(**data)  # type: ignore[arg-type]


@dataclass
class _StubBundle:
    evidence: list[_StubEvidence]
    findings: list[_StubFinding]
    coverage: _StubCoverage = field(default_factory=_StubCoverage)

    def model_copy(self, update: dict[str, object]) -> "_StubBundle":
        return _StubBundle(
            evidence=list(update.get("evidence", self.evidence)),  # type: ignore[arg-type]
            findings=list(update.get("findings", self.findings)),  # type: ignore[arg-type]
            coverage=update.get("coverage", self.coverage),  # type: ignore[arg-type]
        )


class SystemAdaptiveProfileTests(unittest.TestCase):
    def test_adaptive_profiles_scale_with_device_ram_and_unlimited_stream(self) -> None:
        small_caps = system.HostCapabilities(
            cpu_count=2,
            host_memory_total_mb=1024,
            host_memory_available_mb=768,
            cgroup_memory_limit_mb=1024,
            effective_memory_mb=1024,
            disk_total_bytes=20 * 1024**3,
            disk_free_bytes=10 * 1024**3,
            tshark_available=True,
            tshark_version="TShark 4.2",
            zeek_available=False,
            zeek_version=None,
        )
        big_caps = system.HostCapabilities(
            cpu_count=16,
            host_memory_total_mb=32768,
            host_memory_available_mb=24000,
            cgroup_memory_limit_mb=None,
            effective_memory_mb=32768,
            disk_total_bytes=500 * 1024**3,
            disk_free_bytes=200 * 1024**3,
            tshark_available=True,
            tshark_version="TShark 4.2",
            zeek_available=True,
            zeek_version="Zeek 6.0",
        )

        self.assertEqual(system.recommended_chunk_size_bytes(small_caps), 2 * 1024 * 1024)
        self.assertEqual(system.recommended_chunk_size_bytes(big_caps), 16 * 1024 * 1024)

        auto_small = system.resolve_adaptive_profile("auto", small_caps)
        auto_big = system.resolve_adaptive_profile("auto", big_caps)
        self.assertLess(auto_small.packet_limit, auto_big.packet_limit)
        self.assertLess(auto_small.flow_limit, auto_big.flow_limit)
        self.assertTrue(auto_small.streaming_eviction)

        unlimited = system.resolve_adaptive_profile("unlimited", big_caps)
        self.assertEqual(unlimited.packet_limit, 0)
        self.assertEqual(unlimited.stdout_budget_bytes, 0)
        self.assertTrue(unlimited.streaming_eviction)

        legacy = system.resolve_adaptive_profile("legacy", small_caps, configured_packet_limit=20_000, configured_flow_limit=5_000)
        self.assertFalse(legacy.streaming_eviction)
        self.assertEqual(legacy.packet_limit, 20_000)

    def test_capabilities_payload_reports_unlimited_and_disk_headroom(self) -> None:
        settings = SimpleNamespace(
            data_dir=".",
            resource_mode="auto",
            upload_max_bytes=0,
            storage_max_bytes=0,
            disk_reserve_bytes=256 * 1024 * 1024,
            packet_limit=20_000,
            flow_limit=5_000,
            parser_memory_mb=512,
            parser_timeout_seconds=120,
            zeek_enabled=False,
            local_ingest_roots=["/tmp"],
            triage=SimpleNamespace(
                enabled=True,
                mode="heuristic_calibrated",
                model_name="openjev-cal-tier1",
                endpoint_url=None,
                high_confidence_threshold=0.90,
                low_confidence_threshold=0.35,
                compact_for_ai=True,
            ),
        )
        payload = system.build_capabilities_payload(settings)
        limits = payload["limits"]
        self.assertTrue(limits["unlimited_upload_enabled"])
        self.assertEqual(limits["upload_max_bytes"], 0)
        self.assertTrue(limits["local_ingest_enabled"])
        self.assertIn("unlimited", payload["profiles"])
        self.assertEqual(payload["profiles"]["unlimited"]["packet_limit"], 0)

    def test_darwin_macos_memory_probe_and_runtime_hint(self) -> None:
        settings = SimpleNamespace(
            data_dir=".",
            resource_mode="auto",
            upload_max_bytes=0,
            storage_max_bytes=0,
            disk_reserve_bytes=256 * 1024 * 1024,
            packet_limit=20_000,
            flow_limit=5_000,
            parser_memory_mb=512,
            parser_timeout_seconds=120,
            zeek_enabled=False,
            local_ingest_roots=[],
            triage=SimpleNamespace(
                enabled=True,
                mode="etbert_openjev",
                model_name="openjev-cal-tier1",
                endpoint_url="http://127.0.0.1:9000/v1/systemone",
                etbert_enabled=True,
                etbert_endpoint_url="http://127.0.0.1:9000/etbert/score",
                etbert_model_name="etbert-l7-datagram",
                high_confidence_threshold=0.90,
                low_confidence_threshold=0.35,
                compact_for_ai=True,
            ),
        )

        def _fake_run(cmd, **_kwargs):  # noqa: ANN001
            if cmd[:2] == ["sysctl", "-n"]:
                return SimpleNamespace(returncode=0, stdout=str(16 * 1024**3) + "\n", stderr="")
            if cmd[:1] == ["vm_stat"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
                        "Pages free:                              120000.\n"
                        "Pages inactive:                          180000.\n"
                        "Pages speculative:                        20000.\n"
                    ),
                    stderr="",
                )
            return SimpleNamespace(returncode=1, stdout="", stderr="")

        orig_platform = system.sys.platform
        orig_machine = system.platform.machine
        orig_run = system.subprocess.run
        system.sys.platform = "darwin"
        system.platform.machine = lambda: "arm64"  # type: ignore[assignment]
        system.subprocess.run = _fake_run  # type: ignore[assignment]
        try:
            total_mb, avail_mb = system._probe_memory_mb()
            payload = system.build_capabilities_payload(settings)
        finally:
            system.sys.platform = orig_platform
            system.platform.machine = orig_machine  # type: ignore[assignment]
            system.subprocess.run = orig_run  # type: ignore[assignment]

        self.assertEqual(total_mb, 16384)
        self.assertGreater(avail_mb, 4000)
        self.assertEqual(payload["runtime"], {"platform": "darwin", "machine": "arm64", "device_hint": "mps"})
        self.assertTrue(payload["triage"]["etbert_enabled"])
        self.assertEqual(payload["triage"]["etbert_model_name"], "etbert-l7-datagram")


class Tier1TriageAndCompactorTests(unittest.TestCase):
    def _build_mixed_bundle(self, benign_count: int = 250) -> _StubBundle:
        evidence: list[_StubEvidence] = []
        findings: list[_StubFinding] = []

        # 1. ARP spoofing item
        ev_arp = _StubEvidence(
            evidence_id="EV-000001",
            kind="arp",
            summary="ARP mapping IP 192.168.10.1 seen from 2 MAC(s)",
            packet_refs=[13, 520, 524],
            attributes={"protocol": "ARP", "src": "192.168.10.1", "dst": "2c:30:33:e2:d5:c3", "arp_conflicts": 1, "arp_replies": 62, "packets": 62},
        )
        evidence.append(ev_arp)
        findings.append(
            _StubFinding(
                finding_id="F-0001",
                detector="arp_spoofing_conflict",
                title="ARP spoofing conflict on 192.168.10.1",
                severity="high",
                confidence="medium",
                evidence_ids=["EV-000001"],
                limitations=["Verify gateway MAC table."],
            )
        )

        # 2. DGA / DNS Tunnel item
        ev_dns = _StubEvidence(
            evidence_id="EV-000002",
            kind="dns",
            summary="DNS query qx8z9v2m7p4w1r5t8n3k6b.bad.example",
            packet_refs=[88],
            attributes={
                "protocol": "DNS",
                "src": "192.0.2.10",
                "dst": "192.0.2.1",
                "query": "qx8z9v2m7p4w1r5t8n3k6b.bad.example",
                "rcode": 3,
                "packets": 18,
            },
        )
        evidence.append(ev_dns)
        findings.append(
            _StubFinding(
                finding_id="F-0002",
                detector="dns_nxdomain_entropy",
                title="High-entropy DNS NXDOMAIN bursts",
                severity="medium",
                confidence="medium",
                evidence_ids=["EV-000002"],
            )
        )

        # 3. C2 Beaconing item
        ev_c2 = _StubEvidence(
            evidence_id="EV-000003",
            kind="flow",
            summary="TCP flow 192.0.2.10 -> 198.51.100.14",
            packet_refs=[101, 202, 303, 404],
            attributes={
                "protocol": "TCP",
                "src": "192.0.2.10",
                "dst": "198.51.100.14",
                "src_port": 51200,
                "dst_port": 443,
                "packets": 20,
                "bytes": 6400,
                "intervals": "60.0,60.1,59.9,60.2,60.0",
            },
        )
        evidence.append(ev_c2)
        findings.append(
            _StubFinding(
                finding_id="F-0003",
                detector="periodic_tcp_connection_starts",
                title="Periodic outbound connections",
                severity="high",
                confidence="medium",
                evidence_ids=["EV-000003"],
            )
        )

        # 4. Web injection / XSS URI item
        ev_web = _StubEvidence(
            evidence_id="EV-000004",
            kind="http",
            summary="HTTP GET anomaly",
            packet_refs=[505],
            attributes={
                "protocol": "HTTP",
                "src": "192.0.2.50",
                "dst": "198.51.100.80",
                "dst_port": 80,
                "http_method": "GET",
                "http_path": "/aoidjw?cookie=<script>alert(1)</script>",
                "packets": 4,
                "bytes": 1200,
            },
        )
        evidence.append(ev_web)

        # 5. Many benign background flows
        for i in range(benign_count):
            evidence.append(
                _StubEvidence(
                    evidence_id=f"EV-{1000 + i:06d}",
                    kind="flow",
                    summary=f"TCP flow benign #{i}",
                    packet_refs=[2000 + i],
                    attributes={
                        "protocol": "TCP",
                        "src": "192.0.2.10",
                        "dst": f"203.0.113.{(i % 200) + 1}",
                        "src_port": 40000 + i,
                        "dst_port": 443 if i % 2 == 0 else 80,
                        "packets": 6,
                        "bytes": 2400,
                    },
                )
            )

        return _StubBundle(evidence=evidence, findings=findings)

    def test_multiclass_triage_and_benign_reduction(self) -> None:
        bundle = self._build_mixed_bundle(benign_count=120)
        report = triage.classify_bundle(bundle)
        self.assertTrue(report.enabled)
        self.assertEqual(report.total_evaluated, 124)
        self.assertGreaterEqual(report.benign_filtered, 115)
        self.assertGreater(report.reduction_ratio, 0.85)
        self.assertGreaterEqual(report.mean_ppl, 1.0)

        by_id = {d.evidence_id: d for d in report.decisions}
        self.assertEqual(by_id["EV-000001"].predicted_class, "ARP_Spoofing")
        self.assertEqual(by_id["EV-000001"].decision, "escalate_attack")
        self.assertEqual(by_id["EV-000002"].predicted_class, "DNS_Tunnel_DGA")
        self.assertEqual(by_id["EV-000003"].predicted_class, "C2_Beaconing")
        self.assertEqual(by_id["EV-000004"].predicted_class, "Web_Injection_Or_Tunnel")
        self.assertEqual(by_id["EV-001000"].predicted_class, "Benign")
        self.assertEqual(by_id["EV-001000"].decision, "fast_benign")

    def test_pack_evidence_for_ai_shrinks_huge_context_while_preserving_refs(self) -> None:
        bundle = self._build_mixed_bundle(benign_count=350)
        compacted, stats = triage.pack_evidence_for_ai(bundle, max_bytes=12_000)

        self.assertLess(len(compacted.evidence), 30)
        self.assertGreater(stats["benign_filtered_count"], 300)
        self.assertGreater(stats["reduction_pct"], 85.0)

        retained_ev_ids = {ev.evidence_id for ev in compacted.evidence}
        # All selected finding references MUST remain valid inside compacted evidence
        self.assertGreaterEqual(len(compacted.findings), 3)
        for finding in compacted.findings:
            self.assertTrue(set(finding.evidence_ids).issubset(retained_ev_ids))

    def test_triage_jsonl_export_structure(self) -> None:
        bundle = self._build_mixed_bundle(benign_count=10)
        jsonl = triage.bundle_to_triage_jsonl(bundle)
        lines = [line for line in jsonl.splitlines() if line.strip()]
        self.assertEqual(len(lines), 14)
        first = json.loads(lines[0])
        self.assertEqual(first["evidence_id"], "EV-000001")
        self.assertEqual(first["predicted_class"], "ARP_Spoofing")
        self.assertIn("uncertainty_ppl", first)
        self.assertIn("text", first)

    def test_openjev_http_anonymizes_ips_macs_and_urls(self) -> None:
        bundle = self._build_mixed_bundle(benign_count=2)
        secret_path = "/account/reset?access_token=PRIVATE-URI-SENTINEL"
        bundle.evidence[3].attributes["http_path"] = secret_path
        bundle.evidence[3].attributes.update(
            {
                "http_xss_hits": 1,
                "http_crlf_hits": 2,
                "http_sqli_hits": 3,
                "http_shell_hits": 4,
                "http_host_ip_hits": 5,
            }
        )
        report = triage.classify_bundle(bundle)
        local_decision = next(d for d in report.decisions if d.evidence_id == "EV-000004")
        local_state = local_decision.compact_text
        self.assertEqual(local_decision.predicted_class, "Web_Injection_Or_Tunnel")
        self.assertIn("suspicious_http_uri_marker", local_decision.signals)
        self.assertIn("xss=1", local_state)
        self.assertIn("crlf=2", local_state)
        self.assertIn("sqli=3", local_state)
        self.assertIn("shell=4", local_state)
        self.assertIn("host_ip=5", local_state)
        captured: list[dict[str, object]] = []

        class _FakeResp:
            status = 200

            def __init__(self, count: int) -> None:
                self._body = json.dumps(
                    {"results": [{"label": "Benign", "confidence": 0.99, "ppl": 1.02} for _ in range(count)]}
                ).encode("utf-8")

            def read(self, _limit: int = -1) -> bytes:
                return self._body

            def __enter__(self) -> "_FakeResp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

        def _fake_urlopen(req, timeout=10.0, **_kwargs):  # noqa: ANN001
            payload = json.loads(req.data.decode("utf-8"))
            captured.append(payload)
            return _FakeResp(len(payload["items"]))

        orig_urlopen = triage.urlopen
        triage.urlopen = _fake_urlopen  # type: ignore[assignment]
        try:
            updated = triage._call_openjev_http(
                report.decisions,
                "http://127.0.0.1:9000/classify",
                "openjev-cal-tier1",
                2.0,
                allow_network=True,
            )
        finally:
            triage.urlopen = orig_urlopen  # type: ignore[assignment]

        self.assertIsNotNone(updated)
        serialized = json.dumps(captured)
        self.assertNotIn("192.168.10.1", serialized)
        self.assertNotIn("2c:30:33:e2:d5:c3", serialized)
        self.assertNotIn("198.51.100.14", serialized)
        self.assertNotIn(secret_path, serialized)
        self.assertNotIn("PRIVATE-URI-SENTINEL", serialized)
        for token in ("xss=1", "crlf=2", "sqli=3", "shell=4", "host_ip=5"):
            self.assertNotIn(token, serialized)
        self.assertNotIn("uri_len", serialized)
        self.assertNotIn("uri_ent", serialized)
        self.assertIn("ip_", serialized)
        self.assertIn("mac_", serialized)

    def test_pack_evidence_for_ai_tight_budget_preserves_refs(self) -> None:
        bundle = self._build_mixed_bundle(benign_count=200)
        bundle.coverage.warnings = [f"Warning line {i}" for i in range(60)]
        compacted, stats = triage.pack_evidence_for_ai(bundle, max_bytes=5_500)
        self.assertLessEqual(len(compacted.coverage.warnings), 12)
        self.assertGreater(stats["benign_filtered_count"], 180)
        retained_ev_ids = {ev.evidence_id for ev in compacted.evidence}
        for finding in compacted.findings:
            self.assertTrue(set(finding.evidence_ids).issubset(retained_ev_ids))

    def test_etbert_bridge_filters_non_data_bearing_and_fail_closed(self) -> None:
        arp_ev = _StubEvidence("EV-000010", "arp", "ARP reply", [1], {"protocol": "ARP", "src": "192.0.2.1", "dst": "aa:bb:cc:dd:ee:ff", "packets": 10, "bytes": 600})
        icmp_ev = _StubEvidence("EV-000011", "icmp", "ICMP flood", [2], {"protocol": "ICMP", "src": "192.0.2.1", "dst": "192.0.2.2", "packets": 100, "bytes": 6400})
        wlan_ev = _StubEvidence("EV-000012", "wlan", "802.11 deauth", [3], {"protocol": "WLAN", "src": "aa:bb:cc:11:22:33", "dst": "Broadcast", "packets": 30, "bytes": 1200, "wlan_deauth_count": 30})
        syn_flood = _StubEvidence("EV-000013", "flow", "SYN flood", [4], {"protocol": "TCP", "src": "192.0.2.5", "dst": "198.51.100.2", "dst_port": 443, "packets": 500, "bytes": 30000, "syn_count": 500, "data_len_sum": 0})
        tls_ev = _StubEvidence("EV-000014", "flow", "TLS data flow", [5], {"protocol": "TLS", "src": "192.0.2.9", "dst": "198.51.100.99", "src_port": 51000, "dst_port": 443, "packets": 14, "bytes": 18400, "data_len_sum": 16000, "tls_handshake_types": "1,2"})

        self.assertFalse(etbert_bridge.is_data_bearing_evidence(arp_ev))
        self.assertFalse(etbert_bridge.is_data_bearing_evidence(icmp_ev))
        self.assertFalse(etbert_bridge.is_data_bearing_evidence(wlan_ev))
        self.assertFalse(etbert_bridge.is_data_bearing_evidence(syn_flood))
        self.assertTrue(etbert_bridge.is_data_bearing_evidence(tls_ev))

        items, ev_ids = etbert_bridge.build_etbert_request_items([arp_ev, icmp_ev, wlan_ev, syn_flood, tls_ev])
        self.assertEqual(ev_ids, ["EV-000014"])
        serialized = json.dumps(items)
        self.assertNotIn("192.0.2.9", serialized)
        self.assertNotIn("198.51.100.99", serialized)
        self.assertIn("host_", serialized)

        # Fail closed when endpoint raises URLError
        orig_post_json = etbert_bridge.post_json_bounded
        etbert_bridge.post_json_bounded = lambda *_args, **_kwargs: None  # type: ignore[assignment]
        try:
            res = etbert_bridge.score_with_etbert_http(
                [tls_ev],
                endpoint_url="http://127.0.0.1:9000/etbert/score",
                allow_network=True,
            )
        finally:
            etbert_bridge.post_json_bounded = orig_post_json  # type: ignore[assignment]
        self.assertEqual(res, {})

    def test_etbert_projection_excludes_uri_and_derived_metrics(self) -> None:
        secret_path = "/admin/reset?access_token=ETBERT-URI-SENTINEL"
        evidence = _StubEvidence(
            "EV-URI-001",
            "flow",
            "HTTP flow",
            [19],
            {
                "protocol": "HTTP",
                "src": "192.0.2.19",
                "dst": "198.51.100.19",
                "src_port": 52000,
                "dst_port": 80,
                "packets": 4,
                "bytes": 1200,
                "data_len_sum": 900,
                "http_method": "GET",
                "http_uri_max_len": len(secret_path),
                "http_uri_max_entropy": 6.75,
                "http_path": secret_path,
            },
        )
        items, _ = etbert_bridge.build_etbert_request_items([evidence], salt="unit-test")
        serialized = json.dumps(items)
        self.assertEqual(len(items), 1)
        self.assertNotIn(secret_path, serialized)
        self.assertNotIn("ETBERT-URI-SENTINEL", serialized)
        self.assertNotIn("http_uri_max_len", serialized)
        self.assertNotIn("http_uri_max_entropy", serialized)

        evidence.attributes["http_method"] = "PROPFIND-PCAP-METHOD-SENTINEL"
        items, _ = etbert_bridge.build_etbert_request_items([evidence], salt="unit-test")
        serialized = json.dumps(items)
        self.assertEqual(items[0]["features"]["http_method"], "OTHER")
        self.assertIn("http=OTHER", items[0]["state"])
        self.assertNotIn("PROPFIND-PCAP-METHOD-SENTINEL", serialized)

    def test_network_tier1_is_skipped_without_explicit_consent(self) -> None:
        bundle = self._build_mixed_bundle(benign_count=1)
        cfg = SimpleNamespace(
            enabled=True,
            mode="etbert_openjev",
            endpoint_url="http://127.0.0.1:9000/v1/systemone",
            etbert_enabled=True,
            etbert_endpoint_url="http://127.0.0.1:9000/etbert/score",
        )

        def _unexpected_call(*_args, **_kwargs):
            raise AssertionError("network classifier called without consent")

        original_post = etbert_bridge.post_json_bounded
        original_urlopen = triage.urlopen
        etbert_bridge.post_json_bounded = _unexpected_call  # type: ignore[assignment]
        triage.urlopen = _unexpected_call  # type: ignore[assignment]
        try:
            report = triage.classify_bundle(bundle, cfg)
        finally:
            etbert_bridge.post_json_bounded = original_post  # type: ignore[assignment]
            triage.urlopen = original_urlopen  # type: ignore[assignment]

        self.assertIn("consent_required", report.mode)
        self.assertEqual(report.etbert_scored_count, 0)

    def test_unified_10_class_etbert_plus_openjev_systemone_fusion(self) -> None:
        self.assertEqual(len(triage.TRAFFIC_CLASSES), 10)
        self.assertIn("WiFi_Attack", triage.TRAFFIC_CLASSES)
        self.assertIn("Protocol_Tunnel", triage.TRAFFIC_CLASSES)

        wlan_ev = _StubEvidence(
            "EV-000021",
            "wlan",
            "WLAN flow aa:bb:cc:00:00:01 to ff:ff:ff:ff:ff:ff",
            [10, 11],
            {"protocol": "WLAN", "src": "aa:bb:cc:00:00:01", "dst": "ff:ff:ff:ff:ff:ff", "packets": 40, "bytes": 2400, "wlan_deauth_count": 40, "wlan_bssid_count": 2},
        )
        tls_ev = _StubEvidence(
            "EV-000022",
            "flow",
            "TLS flow 192.0.2.15 to 203.0.113.55",
            [12, 13],
            {
                "protocol": "TLS",
                "src": "192.0.2.15",
                "dst": "203.0.113.55",
                "src_port": 54321,
                "dst_port": 443,
                "packets": 22,
                "bytes": 19500,
                "rev_packets": 18,
                "rev_bytes": 4200,
                "io_byte_ratio": 0.8228,
                "ttl_min": 64,
                "ttl_max": 128,
                "ttl_distinct_count": 2,
                "data_len_sum": 17200,
                "tls_handshake_types": "1",
            },
        )
        bundle = _StubBundle(evidence=[wlan_ev, tls_ev], findings=[])

        seen_systemone_reqs: list[dict[str, object]] = []

        class _JsonResp:
            status = 200

            def __init__(self, body: dict[str, object]) -> None:
                self._raw = json.dumps(body).encode("utf-8")

            def read(self, _limit: int = -1) -> bytes:
                return self._raw

            def __enter__(self) -> "_JsonResp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

        def _fake_etbert(url, payload, *, timeout_seconds, **_kwargs):  # noqa: ANN001
            self.assertEqual(len(payload["items"]), 1)  # Only TLS flow (not WLAN) sent to ET-BERT
            return {
                "results": [{"label": "C2_Beaconing", "score": 0.89, "confidence": 0.88, "entropy": 0.42}]
            }

        def _fake_systemone(req, timeout=10.0, **_kwargs):  # noqa: ANN001
            payload = json.loads(req.data.decode("utf-8"))
            seen_systemone_reqs.append(payload)
            state = payload["state"]
            if "WLAN" in state and "wlan_deauth=40" in state:
                pred = {"prediction": "WiFi_Attack", "confidence": 0.96, "ppl": 1.12}
            else:
                pred = {"prediction": "C2_Beaconing", "confidence": 0.91, "ppl": 1.24}
            return _JsonResp({"answers": {"traffic_class": pred}})

        cfg = SimpleNamespace(
            enabled=True,
            mode="etbert_openjev",
            model_name="openjev-cal-tier1",
            endpoint_url="http://127.0.0.1:9000/v1/systemone",
            etbert_enabled=True,
            etbert_endpoint_url="http://127.0.0.1:9000/etbert/score",
            etbert_model_name="etbert-l7-datagram",
            etbert_timeout_seconds=5,
            high_confidence_threshold=0.90,
            low_confidence_threshold=0.35,
            timeout_seconds=5,
        )

        orig_et_post_json = etbert_bridge.post_json_bounded
        orig_tr_urlopen = triage.urlopen
        etbert_bridge.post_json_bounded = _fake_etbert  # type: ignore[assignment]
        triage.urlopen = _fake_systemone  # type: ignore[assignment]
        try:
            report = triage.classify_bundle(bundle, cfg, allow_network=True)
        finally:
            etbert_bridge.post_json_bounded = orig_et_post_json  # type: ignore[assignment]
            triage.urlopen = orig_tr_urlopen  # type: ignore[assignment]

        self.assertEqual(report.etbert_scored_count, 1)
        self.assertEqual(report.decisions[0].predicted_class, "WiFi_Attack")
        self.assertEqual(report.decisions[0].decision, "escalate_attack")
        self.assertEqual(report.decisions[1].predicted_class, "C2_Beaconing")
        self.assertEqual(report.decisions[1].etbert_label, "C2_Beaconing")
        self.assertAlmostEqual(report.decisions[1].etbert_confidence or 0.0, 0.88)

        # Ensure raw IPs/MACs were stripped before /v1/systemone and ET-BERT score reached OpenJev
        serialized_reqs = json.dumps(seen_systemone_reqs)
        self.assertNotIn("192.0.2.15", serialized_reqs)
        self.assertNotIn("aa:bb:cc:00:00:01", serialized_reqs)
        self.assertIn("etbert_lbl=C2_Beaconing", serialized_reqs)
        self.assertIn("wlan_deauth=40", serialized_reqs)

        # JSONL export is deterministic and must not silently repeat a network call.
        jsonl = triage.bundle_to_triage_jsonl(bundle, cfg)
        rows = [json.loads(line) for line in jsonl.splitlines() if line.strip()]
        self.assertEqual(len(rows), 2)
        self.assertNotIn("etbert", rows[1])
        self.assertEqual(rows[1]["metrics"]["ttl_distinct_count"], 2)


class OptionalClassifierDeadlineTests(unittest.TestCase):
    def test_systemone_reuses_one_deadline_and_stops_between_requests_on_cancel(self) -> None:
        decisions = [
            triage.TriageDecision(
                evidence_id=f"EV-{idx}",
                kind="flow",
                predicted_class="Benign",
                confidence=0.99,
                uncertainty_ppl=1.0,
                decision="fast_benign",
                compact_text="TCP 192.0.2.1->198.51.100.1 pkts=1 bytes=64",
            )
            for idx in range(3)
        ]
        deadlines: list[float | None] = []

        class _JsonResp:
            status = 200

            def read(self, _limit: int = -1) -> bytes:
                return json.dumps({"answers": {"traffic_class": "Benign"}}).encode()

            def __enter__(self) -> "_JsonResp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

        def _fake_urlopen(_req, timeout=10.0, **kwargs):  # noqa: ANN001
            self.assertGreater(timeout, 0)
            deadlines.append(kwargs.get("deadline_monotonic"))
            return _JsonResp()

        orig_urlopen = triage.urlopen
        triage.urlopen = _fake_urlopen  # type: ignore[assignment]
        shared_deadline = time.monotonic() + 5.0
        try:
            updated = triage._call_openjev_systemone_http(
                decisions,
                "http://127.0.0.1:9000/v1/systemone",
                "openjev-cal-tier1",
                10.0,
                allow_network=True,
                deadline_monotonic=shared_deadline,
                cancellation_check=lambda: len(deadlines) >= 2,
            )
        finally:
            triage.urlopen = orig_urlopen  # type: ignore[assignment]

        self.assertIsNotNone(updated)
        self.assertEqual(len(deadlines), 2)
        self.assertEqual(deadlines, [shared_deadline, shared_deadline])

    def test_bounded_transport_cancels_slow_stream_at_total_deadline(self) -> None:
        started = threading.Event()
        closed = threading.Event()

        class _SlowStream(httpx.SyncByteStream):
            def __iter__(self):
                started.set()
                time.sleep(0.4)
                yield b"{}"

            def close(self) -> None:
                closed.set()

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, stream=_SlowStream(), request=request)

        transport = httpx.MockTransport(_handler)
        deadline = time.monotonic() + 0.06
        began = time.monotonic()
        result = triage.post_json_bounded(
            "http://classifier.invalid/score",
            {"items": [1]},
            timeout_seconds=2.0,
            transport=transport,
            deadline_monotonic=deadline,
        )
        elapsed = time.monotonic() - began

        self.assertIsNone(result)
        self.assertTrue(started.wait(0.2))
        self.assertTrue(closed.wait(0.5))
        self.assertLess(elapsed, 0.25)


@unittest.skipUnless(HAS_PYDANTIC_V2, "Requires Pydantic v2 + FastAPI backend environment")
class BackendPipelineAndChunkedUploadTests(unittest.TestCase):
    def test_csv_analysis_on_real_arp_poison_fixture(self) -> None:
        from backend.app.pipeline import analyze_capture

        zip_path = Path("/home/antigravity/folder.zip")
        if not zip_path.is_file():
            self.skipTest("/home/antigravity/folder.zip not present in this checkout")

        with zipfile.ZipFile(zip_path) as zf:
            csv_bytes = zf.read(zf.infolist()[0])

        sha = hashlib.sha256(csv_bytes).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            csv_file = Path(tmp) / "ARP_Poison.csv"
            csv_file.write_bytes(csv_bytes)
            settings = SimpleNamespace(resource_mode="auto", packet_limit=100_000, flow_limit=5_000, parser_timeout_seconds=30, parser_memory_mb=512, zeek_enabled=False, data_dir=tmp)
            bundle = analyze_capture(csv_file, sha, settings, resource_mode="auto", triage_enabled=True)

            self.assertEqual(bundle.coverage.parser, "wireshark-csv-offline")
            self.assertGreater(bundle.coverage.packets_analyzed, 900)
            self.assertIsNotNone(bundle.triage)
            self.assertGreaterEqual(bundle.triage.total_evaluated, 1)
            detectors = {f.detector for f in bundle.findings}
            self.assertIn("arp_spoofing_conflict", detectors)
            self.assertIsNotNone(bundle.telemetry)
            self.assertEqual(len(bundle.telemetry.timeline), 36)

    def test_pcapscanner_triage_connects_to_standalone_tier1_inference_asgi(self) -> None:
        from urllib.parse import urlsplit
        from fastapi.testclient import TestClient

        tier1_root = ROOT / "tier1-inference"
        if str(tier1_root) not in sys.path:
            sys.path.insert(0, str(tier1_root))
        from tier1_inference import create_app as create_tier1_app

        tier1_app = create_tier1_app(device="cpu")
        tier1_client = TestClient(tier1_app)

        ev_arp = _StubEvidence(
            "EV-INT-1",
            "arp",
            "ARP conflict",
            [1],
            {"protocol": "ARP", "src": "192.168.10.1", "dst": "aa:bb:cc:11:22:33", "arp_conflicts": 2, "packets": 10},
        )
        ev_dns = _StubEvidence(
            "EV-INT-2",
            "dns",
            "High entropy NXDOMAIN query",
            [2],
            {
                "protocol": "DNS",
                "src": "192.0.2.25",
                "dst": "198.51.100.40",
                "dst_port": 53,
                "query": "xk9q2m8z7p4v1w6n3c5b8r2t7y9k4m1q.evil.example",
                "rcode": 3,
                "packets": 6,
                "bytes": 780,
                "data_len_sum": 420,
            },
        )
        ev_benign = _StubEvidence(
            "EV-INT-3",
            "flow",
            "HTTPS normal flow",
            [3],
            {
                "protocol": "TCP",
                "src": "192.0.2.30",
                "dst": "203.0.113.80",
                "src_port": 51000,
                "dst_port": 443,
                "packets": 6,
                "bytes": 1800,
            },
        )
        bundle = _StubBundle(evidence=[ev_arp, ev_dns, ev_benign], findings=[])

        called_paths: list[str] = []
        sent_bodies: list[str] = []

        def _asgi_post(url: str, payload: object, **kwargs):  # noqa: ARG001
            path = urlsplit(url).path
            called_paths.append(path)
            sent_bodies.append(json.dumps(payload))
            resp = tier1_client.post(path, json=payload)
            return resp.json() if resp.status_code == 200 else None

        def _asgi_urlopen(req, **_kwargs):  # noqa: ANN001
            path = urlsplit(req.full_url).path
            payload = json.loads((req.data or b"{}").decode("utf-8"))
            called_paths.append(path)
            sent_bodies.append(json.dumps(payload))
            resp = tier1_client.post(path, json=payload)
            data = json.dumps(resp.json()).encode("utf-8")

            class _Resp:
                status = resp.status_code

                def read(self, _n: int = -1) -> bytes:
                    return data

                def __enter__(self) -> "_Resp":
                    return self

                def __exit__(self, *_a: object) -> None:
                    return None

            return _Resp()

        cfg = SimpleNamespace(
            enabled=True,
            mode="etbert_openjev",
            model_name="openjev-cal-tier1",
            endpoint_url="http://127.0.0.1:9000/v1/systemone",
            etbert_enabled=True,
            etbert_endpoint_url="http://127.0.0.1:9000/etbert/score",
            etbert_model_name="etbert-l7-datagram",
            etbert_timeout_seconds=5,
            high_confidence_threshold=0.90,
            low_confidence_threshold=0.35,
            timeout_seconds=5,
        )

        orig_et_post = etbert_bridge.post_json_bounded
        orig_tr_open = triage.urlopen
        etbert_bridge.post_json_bounded = _asgi_post  # type: ignore[assignment]
        triage.urlopen = _asgi_urlopen  # type: ignore[assignment]
        try:
            report = triage.classify_bundle(bundle, cfg, allow_network=True)
        finally:
            etbert_bridge.post_json_bounded = orig_et_post  # type: ignore[assignment]
            triage.urlopen = orig_tr_open  # type: ignore[assignment]

        self.assertIn("/etbert/score", called_paths)
        self.assertIn("/v1/systemone", called_paths)
        self.assertGreaterEqual(report.etbert_scored_count, 1)
        by_id = {d.evidence_id: d for d in report.decisions}
        self.assertEqual(by_id["EV-INT-1"].predicted_class, "ARP_Spoofing")
        self.assertEqual(by_id["EV-INT-2"].predicted_class, "DNS_Tunnel_DGA")
        self.assertEqual(by_id["EV-INT-2"].etbert_label, "DNS_Tunnel_DGA")
        self.assertEqual(by_id["EV-INT-3"].predicted_class, "Benign")
        self.assertEqual(by_id["EV-INT-3"].decision, "fast_benign")

        all_sent = "\n".join(sent_bodies)
        self.assertNotIn("192.168.10.1", all_sent)
        self.assertNotIn("aa:bb:cc:11:22:33", all_sent)
        self.assertNotIn("evil.example", all_sent)


if __name__ == "__main__":
    unittest.main()
