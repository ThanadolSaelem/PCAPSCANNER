from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import textwrap
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from backend.app import pipeline
from backend.app.config import AppSettings, _env_overlay
from backend.app.llm.providers import _safe_context
from backend.app.zeek import parse_zeek_logs
from backend.app.pipeline import PipelineError, analyze_capture
from backend.tests.fixtures import write_synthetic_pcap


HASH = "0" * 64


def settings(**overrides: object) -> SimpleNamespace:
    values = {
        "packet_limit": 20_000,
        "flow_limit": 5_000,
        "parser_timeout_seconds": 2,
        "parser_memory_mb": 512,
        "zeek_enabled": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def row(
    frame: int,
    *,
    timestamp: float = 1_700_000_000.0,
    src: str = "192.0.2.10",
    dst: str = "192.0.2.20",
    src_port: int | None = None,
    dst_port: int | None = None,
    proto: int | None = None,
    query: str = "",
    rcode: int | None = None,
    syn: str = "",
    tls: str = "",
) -> bytes:
    values = [
        str(frame),
        str(timestamp),
        "128",
        src,
        dst,
        "",
        "",
        str(src_port) if proto == 6 and src_port is not None else "",
        str(dst_port) if proto == 6 and dst_port is not None else "",
        str(src_port) if proto == 17 and src_port is not None else "",
        str(dst_port) if proto == 17 and dst_port is not None else "",
        str(proto) if proto is not None else "",
        query,
        str(rcode) if rcode is not None else "",
        tls,
        syn,
    ]
    return "\t".join(values).encode()


def test_malformed_rows_and_caps_are_explicit_and_bounded() -> None:
    accumulator = pipeline._Accumulator(packet_limit=3, flow_limit=1)
    accumulator.add_line(b"not-a-frame")
    accumulator.add_line(row(1, proto=17, src_port=53000, dst_port=53, query="one.test"))
    accumulator.add_line(row(2, proto=17, src_port=53001, dst_port=53, query="two.test"))
    accumulator.add_line(row(3, proto=17, src_port=53002, dst_port=53, query="three.test"))
    accumulator.add_line(row(4, proto=17, src_port=53003, dst_port=53, query="four.test"))

    bundle = pipeline._build_bundle(
        accumulator,
        capture_sha256=HASH,
        parser_state="partial",
        parser_detail="bounded test output",
        zeek_stage=pipeline._stage("zeek", "skipped", "disabled"),
    )

    assert accumulator.rows_seen == 5
    assert accumulator.rows_analyzed == 3
    assert bundle.coverage.packets_seen == 4  # packet_limit + sentinel, never fullcount
    assert bundle.coverage.packets_analyzed == 3
    assert bundle.coverage.truncated is True
    assert any("Malformed" in warning for warning in bundle.coverage.warnings)
    assert any("Packet cap" in warning for warning in bundle.coverage.warnings)
    assert len(accumulator.flows) == 1
    assert accumulator.flow_cap_hit is True
    assert all(ref > 0 for evidence in bundle.evidence for ref in evidence.packet_refs)
    assert all(len(evidence.packet_refs) <= 50 for evidence in bundle.evidence)


def test_detector_findings_have_valid_references_and_low_confidence() -> None:
    accumulator = pipeline._Accumulator(packet_limit=100, flow_limit=100)
    for index in range(20):
        accumulator.add_line(
            row(
                index + 1,
                timestamp=1_700_000_000 + index,
                src_port=40000 + index,
                dst_port=1000 + index,
                proto=6,
                syn="1",
            )
        )
    for index in range(3):
        accumulator.add_line(
            row(
                100 + index,
                timestamp=1_700_001_000 + index,
                src_port=53000 + index,
                dst_port=53,
                proto=17,
                query="missing.long.generated.label.test",
                rcode=3,
            )
        )
    bundle = pipeline._build_bundle(
        accumulator,
        capture_sha256=HASH,
        parser_state="completed",
        parser_detail="bounded test output",
        zeek_stage=pipeline._stage("zeek", "skipped", "disabled"),
    )

    assert bundle.findings
    assert any(f.detector == "tcp_destination_port_spread" for f in bundle.findings)
    assert any(f.detector == "dns_nxdomain_entropy" for f in bundle.findings)
    known = {e.evidence_id for e in bundle.evidence}
    for finding in bundle.findings:
        assert finding.severity in {"info", "low", "medium"}
        assert finding.confidence in {"low", "medium"}
        assert set(finding.evidence_ids) <= known
        assert finding.finding_id.startswith("F-")


def test_beacon_timing_stage_uses_retained_flow_times_and_cites_flow() -> None:
    accumulator = pipeline._Accumulator(packet_limit=100, flow_limit=100)
    for index in range(5):
        accumulator.add_line(
            row(
                index + 1,
                timestamp=1_700_000_000 + index * 60,
                src="192.0.2.10",
                dst="198.51.100.20",
                src_port=41000,
                dst_port=8443,
                proto=6,
            )
        )
    bundle = pipeline._build_bundle(
        accumulator,
        capture_sha256=HASH,
        parser_state="completed",
        parser_detail="synthetic periodic flow",
        zeek_stage=pipeline._stage("zeek", "skipped", "disabled"),
    )

    candidates = [item for item in bundle.findings if item.detector == "periodic_flow_beacon_heuristic"]
    assert candidates
    assert candidates[0].confidence == "low"
    assert len(candidates[0].evidence_ids) == 1
    assert candidates[0].evidence_ids[0] in {item.evidence_id for item in bundle.evidence}
    assert any(stage.name == "BEACON ANALYTICS" and stage.state == "completed" for stage in bundle.coverage.stages)
    assert "192.0.2.10" not in candidates[0].summary


def test_tls_analytics_adds_validated_fingerprints_and_cited_cert_candidates() -> None:
    rows = [
        pipeline.NormalizedZeekRow(
            log_name="ssl.log",
            source_row=1,
            summary="Zeek TLS metadata for private.example (TLSv13)",
            attributes={
                "source_engine": "Zeek",
                "source_log": "ssl.log",
                "source_row": 1,
                "src": "192.0.2.11",
                "tls_server_name": "private.example",
                "tls_version": "TLSv13",
                "tls_cipher": "TLS_AES_128_GCM_SHA256",
                "tls_ja3": "a" * 32,
                "tls_ja3s": "b" * 32,
                "tls_validation_status": "expired",
            },
        ),
        pipeline.NormalizedZeekRow(
            log_name="x509.log",
            source_row=2,
            summary="Zeek X.509 certificate metadata",
            attributes={
                "source_engine": "Zeek",
                "source_log": "x509.log",
                "source_row": 2,
                "certificate_key_type": "rsa",
                "certificate_key_length": 1024,
            },
        ),
    ]
    bundle = pipeline._build_bundle(
        pipeline._Accumulator(packet_limit=100, flow_limit=100),
        capture_sha256=HASH,
        parser_state="completed",
        parser_detail="synthetic Zeek TLS rows",
        zeek_stage=pipeline._stage("zeek", "completed", "normalized"),
        zeek_records=rows,
        triage_enabled=False,
    )

    fingerprints = [item for item in bundle.evidence if item.kind == "tls"]
    assert {item.attributes["fingerprint_kind"] for item in fingerprints} == {"ja3", "ja3s"}
    assert all(item.attributes["source_evidence_id"] in {row.evidence_id for row in bundle.evidence if row.kind == "zeek"} for item in fingerprints)
    assert {item.detector for item in bundle.findings} >= {"tls_certificate_expired", "tls_certificate_weak_key"}
    for finding in bundle.findings:
        assert set(finding.evidence_ids) <= {item.evidence_id for item in bundle.evidence}
    assert any(stage.name == "TLS ANALYTICS" and stage.state == "completed" for stage in bundle.coverage.stages)

    ai_context = json.dumps(_safe_context(bundle, b"unit-test-salt"), sort_keys=True)
    assert "private.example" not in ai_context
    assert "192.0.2.11" not in ai_context
    assert "ssl.log" not in ai_context
    assert "a" * 32 in ai_context and "b" * 32 in ai_context


def _dns_velocity_bundle(*, query_names: list[str], source: str = "192.0.2.10", start: float = 1_700_000_040.0):
    accumulator = pipeline._Accumulator(packet_limit=10_000, flow_limit=100)
    for index, query in enumerate(query_names):
        accumulator.dns_records.append(
            pipeline._DnsRecord(
                frame=index + 1,
                timestamp=start + index * 0.5,
                query=query,
                rcode=None,
                src=source,
                dst="192.0.2.53",
                qtype=1,
            )
        )
    return pipeline._build_bundle(
        accumulator,
        capture_sha256=HASH,
        parser_state="completed",
        parser_detail="synthetic bounded DNS records",
        zeek_stage=pipeline._stage("zeek", "skipped", "disabled"),
    )


def test_dns_query_velocity_flags_only_diverse_requests_and_cites_evidence() -> None:
    burst = _dns_velocity_bundle(
        query_names=[f"n{index}.telemetry.example" for index in range(60)]
    )
    findings = [item for item in burst.findings if item.detector == "dns_query_velocity_diversity"]
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].confidence == "low"
    assert len(findings[0].evidence_ids) == 60
    assert "192.0.2.10" not in (findings[0].summary or "")
    assert "telemetry.example" not in (findings[0].summary or "")
    dns_stage = next(stage for stage in burst.coverage.stages if stage.name == "DNS ANALYTICS")
    assert dns_stage.state == "completed"

    repeated = _dns_velocity_bundle(query_names=["resolver.example"] * 120)
    assert not any(item.detector == "dns_query_velocity_diversity" for item in repeated.findings)

    below_threshold = _dns_velocity_bundle(
        query_names=[f"n{index}.telemetry.example" for index in range(59)]
    )
    assert not any(item.detector == "dns_query_velocity_diversity" for item in below_threshold.findings)


def test_dns_query_velocity_group_cap_marks_coverage_partial(monkeypatch) -> None:
    monkeypatch.setattr(pipeline, "MAX_DNS_VELOCITY_GROUPS", 1)
    accumulator = pipeline._Accumulator(packet_limit=10_000, flow_limit=100)
    for source_index in range(2):
        for index in range(60):
            accumulator.dns_records.append(
                pipeline._DnsRecord(
                    frame=source_index * 60 + index + 1,
                    timestamp=1_700_000_040 + index * 0.5,
                    query=f"n{index}.s{source_index}.example",
                    rcode=None,
                    src=f"192.0.2.{10 + source_index}",
                    dst="192.0.2.53",
                    qtype=1,
                )
            )
    bundle = pipeline._build_bundle(
        accumulator,
        capture_sha256=HASH,
        parser_state="completed",
        parser_detail="synthetic capped DNS records",
        zeek_stage=pipeline._stage("zeek", "skipped", "disabled"),
    )

    dns_stage = next(stage for stage in bundle.coverage.stages if stage.name == "DNS ANALYTICS")
    assert dns_stage.state == "partial"
    assert bundle.coverage.truncated is True
    assert any("DNS query-rate analysis reached" in warning for warning in bundle.coverage.warnings)
    assert len([item for item in bundle.findings if item.detector == "dns_query_velocity_diversity"]) == 1


def test_adapted_dns_dga_and_tunneling_candidates_are_grounded_and_sanitized() -> None:
    accumulator = pipeline._Accumulator(packet_limit=10_000, flow_limit=100)
    observations = [("xk7m2p9q4v8n3z2a.example.net", 1)]
    observations.extend(
        (f"{'a' * 31}{index:02d}.tunnel.example", 16)
        for index in range(24)
    )
    for index, (query, qtype) in enumerate(observations, start=1):
        accumulator.dns_records.append(
            pipeline._DnsRecord(
                frame=index,
                timestamp=1_700_000_000 + index,
                query=query,
                rcode=None,
                src="192.0.2.10",
                dst="192.0.2.53",
                qtype=qtype,
            )
        )

    bundle = pipeline._build_bundle(
        accumulator,
        capture_sha256=HASH,
        parser_state="completed",
        parser_detail="synthetic bounded DNS records",
        zeek_stage=pipeline._stage("zeek", "skipped", "disabled"),
    )

    dga = [item for item in bundle.findings if item.detector == "dns_dga_heuristic"]
    tunnel = [item for item in bundle.findings if item.detector == "dns_tunneling_heuristic"]
    assert len(dga) == 1
    assert len(tunnel) == 1
    known = {item.evidence_id for item in bundle.evidence}
    assert set(dga[0].evidence_ids) <= known
    assert set(tunnel[0].evidence_ids) <= known
    for finding in dga + tunnel:
        assert finding.severity == "low"
        assert finding.confidence == "low"
        assert "192.0.2.10" not in (finding.summary or "")
        assert "xk7m2p9q4v8n3z2a" not in (finding.summary or "")
        assert "tunnel.example" not in (finding.summary or "")
    safe_context = json.dumps(_safe_context(bundle, b"dns-unit-test-salt"), sort_keys=True)
    assert "xk7m2p9q4v8n3z2a" not in safe_context
    assert "tunnel.example" not in safe_context
    assert "192.0.2.10" not in safe_context
    assert all(evidence_id in safe_context for finding in dga + tunnel for evidence_id in finding.evidence_ids)
    dns_stage = next(stage for stage in bundle.coverage.stages if stage.name == "DNS ANALYTICS")
    assert dns_stage.state == "completed"
    assert "DGA-like label" in dns_stage.detail
    assert "no network lookups" in dns_stage.detail


def test_command_is_offline_and_payload_fields_are_not_allowlisted(tmp_path) -> None:
    command = pipeline._build_command("/usr/bin/tshark", tmp_path / "capture.bin", 20)
    assert command[1:2] == ["-n"]
    assert "-r" in command
    assert str(tmp_path / "capture.bin") in command
    assert "-c" in command
    assert str(21) in command
    joined = " ".join(command)
    for forbidden in ("tcp.payload", "data.data", "http.cookie", "http.request.full_uri", "http.user_agent"):
        assert forbidden not in joined
    assert all(field in command for field in pipeline.FIELD_NAMES)


def test_missing_tshark_is_a_safe_error(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"not parsed here")
    monkeypatch.setattr(pipeline.shutil, "which", lambda name: None)
    with pytest.raises(PipelineError) as error:
        analyze_capture(capture, HASH, settings())
    assert error.value.code == "TSHARK_UNAVAILABLE"
    assert str(capture) not in str(error.value)


def test_csv_multiline_record_byte_limit_is_enforced_before_materializing_unbounded_input(tmp_path) -> None:
    capture = tmp_path / "large-record.csv"
    header = b"No,Time,Source,Destination,Protocol,Length,Info\n"
    segment = b"x" * (40 * 1024)
    row_bytes = (
        b'1,1.0,192.0.2.1,192.0.2.2,TCP,60,"' + segment + b"\n" + segment + b'","\n'
        + segment + b"\n" + segment + b'","\n' + segment + b"\n" + segment + b'","\n'
        + segment + b"\n" + segment + b'"\n'
    )
    capture.write_bytes(header + row_bytes)

    with pytest.raises(PipelineError, match="CSV record byte limit exceeded") as error:
        analyze_capture(capture, HASH, settings(packet_limit=10))
    assert error.value.code == "PARSER_FAILED"
    assert str(capture) not in str(error.value)


def test_csv_field_and_column_limits_are_enforced(tmp_path) -> None:
    oversized_field = tmp_path / "large-field.csv"
    header = b"No,Time,Source,Destination,Protocol,Length,Info\n"
    half = b"x" * (35 * 1024)
    oversized_field.write_bytes(
        header + b'1,1.0,192.0.2.1,192.0.2.2,TCP,60,"' + half + b"\n" + half + b'"\n'
    )
    with pytest.raises(PipelineError, match="CSV field byte limit exceeded"):
        analyze_capture(oversized_field, HASH, settings(packet_limit=10))

    too_many_columns = tmp_path / "wide-header.csv"
    columns = ["Time", "Source", "Destination"] + [f"field_{index}" for index in range(pipeline.MAX_CSV_COLUMNS)]
    too_many_columns.write_text(",".join(columns) + "\n", encoding="utf-8")
    with pytest.raises(PipelineError, match="CSV column limit exceeded"):
        analyze_capture(too_many_columns, HASH, settings(packet_limit=10))


def test_subprocess_cancellation_terminates_parser_tree(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"synthetic")
    tool = tmp_path / "fake-tshark"
    tool.write_text(
        "#!/usr/bin/env python3\n"
        "import time\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(pipeline.shutil, "which", lambda name: str(tool) if name == "tshark" else None)
    calls = 0

    def cancelled() -> bool:
        nonlocal calls
        calls += 1
        return calls > 1

    with pytest.raises(PipelineError) as error:
        analyze_capture(capture, HASH, settings(parser_timeout_seconds=10), is_cancelled=cancelled)
    assert error.value.code == "CANCELLED"
    assert calls > 1


def test_real_synthetic_capture_is_offline_and_normalized(tmp_path) -> None:
    if shutil.which("tshark") is None:
        pytest.skip("TShark is not installed in this environment")
    capture = write_synthetic_pcap(tmp_path / "tiny.pcap")
    bundle = analyze_capture(capture, HASH, settings(packet_limit=10, osint_enabled=True))
    assert bundle.coverage.packets_seen == 3
    assert bundle.coverage.packets_analyzed == 3
    assert bundle.coverage.truncated is False
    assert any(e.kind == "flow" for e in bundle.evidence)
    assert any(e.kind == "dns" for e in bundle.evidence)
    forbidden_keys = {"payload", "cookie", "url", "user-agent", "user_agent"}
    for evidence in bundle.evidence:
        assert not forbidden_keys.intersection(evidence.attributes)
    dns_stage = next(stage for stage in bundle.coverage.stages if stage.name == "DNS ANALYTICS")
    assert dns_stage.state == "completed"
    osint_stage = next(stage for stage in bundle.coverage.stages if stage.name == "osint")
    assert osint_stage.state == "awaiting_consent"
    assert "no external lookup is sent during parsing" in osint_stage.detail
    assert "confirm each operation" in osint_stage.detail
    yara_stage = next(stage for stage in bundle.coverage.stages if stage.name == "yara")
    assert yara_stage.state == "skipped"
    assert "PCAP_YARA_ENABLED" in yara_stage.detail

    disabled_bundle = analyze_capture(capture, HASH, settings(packet_limit=10, osint_enabled=False))
    disabled_osint = next(stage for stage in disabled_bundle.coverage.stages if stage.name == "osint")
    assert disabled_osint.state == "skipped"
    assert "PCAP_OSINT_ENABLED=0" in disabled_osint.detail


def test_capture_hash_is_supplied_not_recomputed(tmp_path, monkeypatch) -> None:
    if shutil.which("tshark") is None:
        pytest.skip("TShark is not installed in this environment")
    capture = write_synthetic_pcap(tmp_path / "tiny.pcap")
    supplied = "a" * 64
    bundle = analyze_capture(capture, supplied, settings(packet_limit=10))
    assert bundle.capture_sha256 == supplied
    # The implementation must not hash or upload the capture as part of parsing.
    assert hashlib.sha256(capture.read_bytes()).hexdigest() != supplied


def test_auto_tshark_extended_allowlist_runs_with_installed_cli(tmp_path) -> None:
    tshark = shutil.which("tshark")
    if tshark is None:
        pytest.skip("TShark is not installed in this environment")
    assert "icmp.data_len" not in pipeline.EXTENDED_FIELD_NAMES
    capture = write_synthetic_pcap(tmp_path / "auto-fields.pcap")
    limits = pipeline._get_limits(
        settings(resource_mode="auto", packet_limit=20, data_dir=str(tmp_path))
    )
    command = pipeline._build_streaming_command(tshark, capture, limits)
    result = subprocess.run(command, capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


def test_extended_icmp_mapping_uses_supported_data_len_field() -> None:
    parts = [""] * len(pipeline.EXTENDED_FIELD_NAMES)
    parts[0] = "1"
    parts[1] = "1700000000.001"
    parts[2] = "84"
    parts[11] = "1"
    parts[21] = "8"
    parts[30] = "16"
    parts[31] = "0"
    parts[32] = "1"
    parts[33] = "200"

    packet = pipeline._parse_packet(parts)

    assert packet is not None
    assert packet.proto == 1
    assert packet.icmp_type == 8
    assert packet.icmp_data_len == 16
    assert packet.icmp_code == 0
    assert packet.dns_qry_type == 1
    assert packet.http_response_code == 200


def test_extended_l2_l7_telemetry_sanitized_http_wlan_and_limits(monkeypatch) -> None:
    def ext_row(frame: int, overrides: dict[int, str]) -> bytes:
        cols = [""] * len(pipeline.EXTENDED_FIELD_NAMES)
        cols[0] = str(frame)
        cols[1] = f"1700000000.{frame:03d}"
        cols[2] = "180"
        for idx, val in overrides.items():
            cols[idx] = val
        return "\t".join(cols).encode()

    acc = pipeline._Accumulator(packet_limit=500, flow_limit=100, streaming_eviction=True)
    # 1. HTTP injection attempt with IP literal Host -> raw URI/Host MUST NEVER be stored
    acc.add_line(
        ext_row(
            1,
            {
                3: "192.0.2.50",
                4: "198.51.100.80",
                7: "51000",
                8: "80",
                11: "6",
                23: "GET",
                24: "64",
                27: "0x018",
                30: "96",
                33: "200",
                34: "/search?q=<script>alert(1)</script>",
                35: "198.51.100.80",
            },
        )
    )
    # Reverse TCP flow for bidirectional io_byte_ratio
    acc.add_line(
        ext_row(
            2,
            {
                2: "540",
                3: "198.51.100.80",
                4: "192.0.2.50",
                7: "80",
                8: "51000",
                11: "6",
                24: "128",
                27: "0x010",
                30: "480",
            },
        )
    )
    # 2. Same src==dst Land / Null / Xmas TCP probes + retransmission + fragmentation
    acc.add_line(
        ext_row(
            3,
            {
                3: "192.0.2.77",
                4: "192.0.2.77",
                7: "1234",
                8: "22",
                11: "6",
                24: "32",
                25: "1",
                27: "0x000",
                28: "1",
            },
        )
    )
    # 3. 802.11 WLAN deauth frame
    acc.add_line(
        ext_row(
            4,
            {
                2: "64",
                37: "0x0c",
                38: "aa:bb:cc:dd:ee:01",
                39: "11:22:33:44:55:66",
                40: "ff:ff:ff:ff:ff:ff",
            },
        )
    )
    # 4. ARP Who-Has sweep across 6 targets
    for i in range(6):
        acc.add_line(
            ext_row(
                10 + i,
                {
                    2: "60",
                    16: "10:20:30:40:50:60",
                    17: "ff:ff:ff:ff:ff:ff",
                    18: "1",
                    19: "192.0.2.99",
                    20: "10:20:30:40:50:60",
                    41: f"192.0.2.{10 + i}",
                },
            )
        )

    bundle = pipeline._build_bundle(
        acc,
        capture_sha256=HASH,
        parser_state="completed",
        parser_detail="extended metadata test",
        zeek_stage=pipeline._stage("zeek", "skipped", "disabled"),
    )

    serialized = bundle.model_dump_json()
    assert "<script>" not in serialized
    assert "http_path" not in serialized

    http_evs = [e for e in bundle.evidence if e.kind == "http"]
    assert len(http_evs) == 1
    assert http_evs[0].attributes["http_xss_hits"] == 1
    assert http_evs[0].attributes["http_host_ip_hits"] == 1
    assert http_evs[0].attributes["http_uri_max_len"] > 10
    assert http_evs[0].attributes["rev_packets"] == 1
    assert http_evs[0].attributes["rev_bytes"] == 540
    assert 0.2 <= float(http_evs[0].attributes["io_byte_ratio"]) <= 0.3

    wlan_evs = [e for e in bundle.evidence if e.kind == "wlan"]
    assert len(wlan_evs) == 1
    assert wlan_evs[0].attributes["wlan_deauth_count"] == 1
    assert wlan_evs[0].attributes["wlan_bssid_count"] == 1

    arp_evs = [e for e in bundle.evidence if e.kind == "arp" and e.attributes.get("arp_scan_targets") == 6]
    assert len(arp_evs) == 1

    for ev in bundle.evidence:
        assert len(ev.attributes) <= 40

    monkeypatch.setattr(pipeline.sys, "platform", "darwin")
    hook = pipeline._child_limits(512, 10.0)
    hook()


def test_zeek_ascii_normalization_is_allowlisted_and_provenanced(tmp_path) -> None:
    ascii_log = (
        r"#separator \x09" + "\n"
        "#set_separator ,\n"
        "#empty_field (empty)\n"
        "#unset_field -\n"
        "#path conn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tconn_state\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\turi\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tinterval\tcount\tcount\tcount\tcount\tstring\n"
        "1700000000.125\tCabc123\t192.0.2.10\t51515\t198.51.100.8\t443\ttcp\tssl\tSF\t1.5\t100\t900\t3\t4\t/secret/path?token=do-not-retain\n"
    )
    (tmp_path / "conn.log").write_text(ascii_log, encoding="utf-8")
    (tmp_path / "http.log").write_text(
        "GET /private/path?session=secret Cookie: do-not-retain\n",
        encoding="utf-8",
    )

    records, rows_seen, bytes_read, truncated = parse_zeek_logs(
        tmp_path,
        row_limit=10,
        byte_limit=1024 * 1024,
    )

    assert rows_seen == 1
    assert bytes_read == len(ascii_log.encode("utf-8"))
    assert truncated is False
    assert len(records) == 1
    record = records[0]
    assert record.log_name == "conn.log"
    assert record.source_row == 1
    assert record.attributes["src"] == "192.0.2.10"
    assert record.attributes["dst"] == "198.51.100.8"
    assert record.attributes["bytes"] == 1000
    assert record.attributes["packets"] == 7
    assert record.attributes["source_log"] == "conn.log"
    assert record.attributes["source_row"] == 1
    assert "uri" not in record.attributes
    assert "secret" not in record.summary
    assert "do-not-retain" not in str(record.attributes)


def test_zeek_jsonl_and_global_row_and_disk_bounds(tmp_path) -> None:
    (tmp_path / "dns.log").write_text(
        '{"ts":1700000000.5,"uid":"Dabc","id.orig_h":"192.0.2.9",'
        '"id.orig_p":53000,"id.resp_h":"198.51.100.53","id.resp_p":53,'
        '"proto":"udp","query":"exfil.example","qtype_name":"TXT",'
        '"rcode_name":"NOERROR","answers":["192.0.2.8"]}\n',
        encoding="utf-8",
    )
    (tmp_path / "ssl.log").write_text(
        '{"ts":1700000001,"uid":"Sabc","id.orig_h":"192.0.2.9",'
        '"id.resp_h":"198.51.100.8","proto":"tcp","version":"TLSv13",'
        '"cipher":"TLS_AES_128_GCM_SHA256","server_name":"api.example",'
        '"ja3":"0123456789abcdef0123456789abcdef"}\n',
        encoding="utf-8",
    )

    records, rows_seen, _, truncated = parse_zeek_logs(tmp_path, row_limit=1, byte_limit=1024 * 1024)
    assert rows_seen == 1
    assert len(records) == 1
    assert records[0].log_name == "dns.log"
    assert records[0].attributes["dns_answer_count"] == 1
    assert records[0].attributes["qtype_name"] == "TXT"
    assert truncated is True

    total, exceeded = pipeline.bounded_directory_size(tmp_path, 16)
    assert exceeded is True
    assert total > 16


def test_zeek_normalized_rows_enter_evidence_bundle_with_stable_ids(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "case capture.pcap"
    capture.write_bytes(b"synthetic")
    args_path = tmp_path / "argv.txt"
    log = (
        r"#separator \x09" + "\n"
        "#unset_field -\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\n"
        "1700000000\tCabc\t192.0.2.1\t12345\t198.51.100.2\t443\ttcp\tSF\n"
    )
    tool = tmp_path / "fake-zeek"
    tool.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        f"pathlib.Path('conn.log').write_text({log!r}, encoding='utf-8')\n"
        f"pathlib.Path({str(args_path)!r}).write_text(' '.join(sys.argv[1:]), encoding='utf-8')\n",
        encoding="utf-8",
    )
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(pipeline.shutil, "which", lambda name: str(tool) if name == "zeek" else None)

    limits = pipeline._get_limits(settings(zeek_enabled=True))
    stage, rows = pipeline._run_zeek(
        capture,
        limits=limits,
        deadline=time.monotonic() + 10,
        is_cancelled=lambda: False,
    )
    accumulator = pipeline._Accumulator(packet_limit=100, flow_limit=100)
    bundle = pipeline._build_bundle(
        accumulator,
        capture_sha256=HASH,
        parser_state="completed",
        parser_detail="bounded test",
        zeek_stage=stage,
        zeek_records=rows,
    )

    assert stage.state == "completed"
    assert "-r" in args_path.read_text(encoding="utf-8")
    zeek_evidence = [item for item in bundle.evidence if item.kind == "zeek"]
    assert len(zeek_evidence) == 1
    assert zeek_evidence[0].evidence_id == "EV-000001"
    assert zeek_evidence[0].attributes["source_log"] == "conn.log"
    assert "[conn.log row 1]" in zeek_evidence[0].summary
    assert bundle.coverage.truncated is False
    safe_context = json.dumps(_safe_context(bundle, b"unit-test-salt"), sort_keys=True)
    assert '"kind": "zeek"' in safe_context
    assert "192.0.2.1" not in safe_context
    assert "198.51.100.2" not in safe_context
    assert "conn.log" not in safe_context


def test_zeek_environment_bounds_are_validated() -> None:
    overlay = _env_overlay(
        {
            "PCAP_ZEEK_ENABLED": "1",
            "PCAP_ZEEK_MAX_ROWS": "321",
            "PCAP_ZEEK_MAX_OUTPUT_BYTES": "4194304",
            "PCAP_ZEEK_TIMEOUT_SECONDS": "30",
            "PCAP_ZEEK_MEMORY_MB": "192",
        }
    )
    config = AppSettings.model_validate(overlay)
    assert config.zeek_enabled is True
    assert config.zeek_max_rows == 321
    assert config.zeek_max_output_bytes == 4 * 1024 * 1024
    assert config.zeek_timeout_seconds == 30
    assert config.zeek_memory_mb == 192
    with pytest.raises(ValidationError):
        AppSettings(zeek_max_rows=10_001)


def test_sample_packets_cover_full_capture_chronologically() -> None:
    accumulator = pipeline._Accumulator(packet_limit=5_000, flow_limit=500)
    total_packets = 2_500
    base_ts = 1_700_000_000.0
    for i in range(1, total_packets + 1):
        accumulator.ingest_packet(
            pipeline._Packet(
                frame=i,
                timestamp=base_ts + i * 0.1,
                frame_len=128,
                src="192.0.2.10",
                dst="198.51.100.20",
                proto=6,
                tcp_srcport=50000 + (i % 10),
                tcp_dstport=443,
                udp_srcport=None,
                udp_dstport=None,
                dns_query=None,
                dns_rcode=None,
                tls_type=None,
                tcp_syn=(i == 1),
                tcp_rst=(i in (2100, 2300, 2450)),
            )
        )

    bundle = pipeline._build_bundle(
        accumulator,
        capture_sha256=HASH,
        parser_state="completed",
        parser_detail="reservoir sampling regression test",
        zeek_stage=pipeline._stage("zeek", "skipped", "test"),
    )
    samples = bundle.telemetry.sample_packets
    frame_nos = [s.no for s in samples]

    assert len(samples) == pipeline.MAX_SAMPLE_PACKETS
    assert frame_nos[0] == 1
    assert frame_nos == sorted(frame_nos), "sample_packets must be sorted chronologically by frame number"
    assert any(n <= 100 for n in frame_nos), "must include opening frames"
    assert any(800 <= n <= 1600 for n in frame_nos), "must sample middle of capture"
    assert any(n >= 2000 for n in frame_nos), "must sample late frames instead of stopping at frame 200"

