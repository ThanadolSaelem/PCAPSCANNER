from __future__ import annotations

import hashlib
import os
import shutil
import stat
import textwrap
from types import SimpleNamespace

import pytest

from backend.app import pipeline
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
    bundle = analyze_capture(capture, HASH, settings(packet_limit=10))
    assert bundle.coverage.packets_seen == 3
    assert bundle.coverage.packets_analyzed == 3
    assert bundle.coverage.truncated is False
    assert any(e.kind == "flow" for e in bundle.evidence)
    assert any(e.kind == "dns" for e in bundle.evidence)
    forbidden_keys = {"payload", "cookie", "url", "user-agent", "user_agent"}
    for evidence in bundle.evidence:
        assert not forbidden_keys.intersection(evidence.attributes)
    assert any(stage.name == "osint" and stage.state == "skipped" for stage in bundle.coverage.stages)
    assert any(stage.name == "yara" and stage.state == "skipped" for stage in bundle.coverage.stages)


def test_capture_hash_is_supplied_not_recomputed(tmp_path, monkeypatch) -> None:
    if shutil.which("tshark") is None:
        pytest.skip("TShark is not installed in this environment")
    capture = write_synthetic_pcap(tmp_path / "tiny.pcap")
    supplied = "a" * 64
    bundle = analyze_capture(capture, supplied, settings(packet_limit=10))
    assert bundle.capture_sha256 == supplied
    # The implementation must not hash or upload the capture as part of parsing.
    assert hashlib.sha256(capture.read_bytes()).hexdigest() != supplied


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
                34: "200",
                35: "/search?q=<script>alert(1)</script>",
                36: "198.51.100.80",
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
                38: "0x0c",
                39: "aa:bb:cc:dd:ee:01",
                40: "11:22:33:44:55:66",
                41: "ff:ff:ff:ff:ff:ff",
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
                    42: f"192.0.2.{10 + i}",
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

