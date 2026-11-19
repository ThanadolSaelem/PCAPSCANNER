"""Bounded, offline PCAP/PCAPNG & Wireshark CSV/TSV analysis engine.

This module deliberately exports only normalized flow/DNS/TLS/ARP/ICMP/HTTP
metadata. It never loads huge captures into memory, recomputes the capture hash,
or exports raw packet payloads, cookies, full query strings, or user-agent headers.
"""
from __future__ import annotations

import csv
import errno
import hashlib
import ipaddress
import math
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any, Callable, Iterable, Sequence

from .models import (
    ArtifactRecord,
    CaptureMetrics,
    Coverage,
    Evidence,
    EvidenceBundle,
    Finding,
    SamplePacket,
    Stage,
    Tier1ClassStat,
    Tier1Summary,
    TimelineBucket,
)
from .dns_analysis import DNSObservation, analyze_dns_candidates
from .beacon_analysis import BeaconObservation, analyze_beacon_candidates
from .ja3_analysis import fingerprints_from_zeek_attributes, match_known_ja3_threat
from .tls_cert_analysis import TLSCertificateObservation, analyze_tls_certificate_metadata
from .correlation import (
    build_ioc_inventory,
    correlate_bundle_findings,
    correlate_zeek_and_tshark_evidence,
)
from .flow_intel import build_flow_analytics
from .geoip import build_world_map_flows
from .mitre import ATTACKMapper
from .system import probe_capabilities, resolve_adaptive_profile
from .triage import classify_bundle
from .zeek import NormalizedZeekRow, bounded_directory_size, parse_zeek_logs
from .yara import (
    NormalizedYaraMatch,
    RuleSnapshot,
    YaraRulesError,
    default_rules_dir,
    detect_carved_content_type,
    snapshot_ruleset,
)


# Canonical 16-field TShark allowlist kept stable for unit tests and base builds.
FIELD_NAMES: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "ip.proto",
    "dns.qry.name",
    "dns.flags.rcode",
    "tls.handshake.type",
    "tcp.flags.syn",
)

# Extended safe L2-L7 metadata allowlist (never includes tcp.payload, data.data,
# http.cookie, http.request.full_uri, http.user_agent, or telnet.data).
# http.request.uri and http.host are distilled immediately in _parse_packet() into
# lengths/entropy/booleans and never stored on _Packet or Evidence.
EXTENDED_FIELD_NAMES: tuple[str, ...] = FIELD_NAMES + (
    "eth.src",
    "eth.dst",
    "arp.opcode",
    "arp.src.proto_ipv4",
    "arp.src.hw_mac",
    "icmp.type",
    "tcp.flags.reset",
    "http.request.method",
    "ip.ttl",
    "ip.flags.mf",
    "ip.frag_offset",
    "tcp.flags",
    "tcp.analysis.retransmission",
    "tcp.seq",
    "data.len",
    "icmp.code",
    "dns.qry.type",
    "http.response.code",
    "http.request.uri",
    "http.host",
    "telnet.cmd",
    "wlan.fc.type_subtype",
    "wlan.bssid",
    "wlan.sa",
    "wlan.da",
    "arp.dst.proto_ipv4",
)

MAX_EVIDENCE = 5000
MAX_PACKET_REFS = 50
MAX_NUMERIC_SERIES = 50
MAX_SAMPLE_PACKETS = 200
MAX_LINE_BYTES = 64 * 1024
MAX_CSV_PHYSICAL_LINE_BYTES = 64 * 1024
MAX_CSV_RECORD_BYTES = 256 * 1024
MAX_CSV_FIELD_BYTES = 64 * 1024
MAX_CSV_COLUMNS = 256
DEFAULT_MAX_STDOUT_BYTES = 64 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024
MAX_DNS_RECORDS = MAX_EVIDENCE
MAX_ARP_RECORDS = 1500
MAX_BEACON_FLOW_SAMPLES = 2_048
MAX_TLS_FINGERPRINT_EVIDENCE = 1_000
DEFAULT_ZEEK_MAX_ROWS = 2_000
DEFAULT_ZEEK_MAX_OUTPUT_BYTES = 32 * 1024 * 1024
DEFAULT_ZEEK_TIMEOUT_SECONDS = 45
DEFAULT_ZEEK_MEMORY_MB = 256
MAX_ZEEK_DIAGNOSTIC_BYTES = 1024 * 1024
DEFAULT_YARA_MAX_RULES_FILES = 64
DEFAULT_YARA_MAX_RULES_BYTES = 16 * 1024 * 1024
DEFAULT_YARA_MAX_OBJECTS = 100
DEFAULT_YARA_MAX_OBJECT_BYTES = 16 * 1024 * 1024
DEFAULT_YARA_MAX_TOTAL_BYTES = 64 * 1024 * 1024
DEFAULT_YARA_MAX_MATCHES = 200
DEFAULT_YARA_MAX_OUTPUT_BYTES = 1024 * 1024
DEFAULT_YARA_TIMEOUT_SECONDS = 30
DEFAULT_YARA_MEMORY_MB = 256
MAX_YARA_DIAGNOSTIC_BYTES = 64 * 1024
TCP_PORT_SPREAD_THRESHOLD = 20
DNS_NXDOMAIN_THRESHOLD = 3
DNS_HIGH_ENTROPY_THRESHOLD = 3.5
DNS_HIGH_ENTROPY_REPEAT_THRESHOLD = 3
DNS_QUERY_VELOCITY_WINDOW_SECONDS = 60
DNS_QUERY_VELOCITY_MIN_QUERIES = 60
DNS_QUERY_VELOCITY_MIN_UNIQUE_NAMES = 40
MAX_DNS_VELOCITY_GROUPS = 256
PERIODIC_MIN_STARTS = 4
PERIODIC_RELATIVE_TOLERANCE = 0.25
TIMELINE_BUCKETS = 36


class PipelineError(RuntimeError):
    """Safe, stable parser error; details never include tool stderr or capture data."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class _Limits:
    packet_limit: int  # 0 = unlimited stream
    flow_limit: int
    timeout_seconds: float
    memory_mb: int
    zeek_enabled: bool
    stdout_budget_bytes: int = DEFAULT_MAX_STDOUT_BYTES  # 0 = unlimited stream
    streaming_eviction: bool = False
    mode_label: str = "legacy"
    zeek_max_rows: int = DEFAULT_ZEEK_MAX_ROWS
    zeek_max_output_bytes: int = DEFAULT_ZEEK_MAX_OUTPUT_BYTES
    zeek_timeout_seconds: int = DEFAULT_ZEEK_TIMEOUT_SECONDS
    zeek_memory_mb: int = DEFAULT_ZEEK_MEMORY_MB
    osint_enabled: bool = False
    yara_enabled: bool = False
    yara_rules_dir: Path | None = None
    yara_max_rules_files: int = DEFAULT_YARA_MAX_RULES_FILES
    yara_max_rules_bytes: int = DEFAULT_YARA_MAX_RULES_BYTES
    yara_max_objects: int = DEFAULT_YARA_MAX_OBJECTS
    yara_max_object_bytes: int = DEFAULT_YARA_MAX_OBJECT_BYTES
    yara_max_total_bytes: int = DEFAULT_YARA_MAX_TOTAL_BYTES
    yara_max_matches: int = DEFAULT_YARA_MAX_MATCHES
    yara_max_output_bytes: int = DEFAULT_YARA_MAX_OUTPUT_BYTES
    yara_timeout_seconds: int = DEFAULT_YARA_TIMEOUT_SECONDS
    yara_memory_mb: int = DEFAULT_YARA_MEMORY_MB


@dataclass
class _Packet:
    frame: int
    timestamp: float | None
    frame_len: int | None
    src: str | None
    dst: str | None
    proto: int | str | None
    tcp_srcport: int | None
    tcp_dstport: int | None
    udp_srcport: int | None
    udp_dstport: int | None
    dns_query: str | None
    dns_rcode: int | None
    tls_type: str | None
    tcp_syn: bool | None
    eth_src: str | None = None
    eth_dst: str | None = None
    arp_opcode: int | None = None
    arp_src_ip: str | None = None
    arp_src_mac: str | None = None
    icmp_type: int | None = None
    tcp_rst: bool | None = None
    http_method: str | None = None
    ip_ttl: int | None = None
    ip_mf: bool | None = None
    ip_frag_offset: int | None = None
    tcp_flags: int | None = None
    tcp_retransmission: bool = False
    tcp_seq: int | None = None
    data_len: int | None = None
    icmp_data_len: int | None = None
    icmp_code: int | None = None
    dns_qry_type: int | None = None
    http_response_code: int | None = None
    http_uri_len: int = 0
    http_uri_entropy: float = 0.0
    http_xss_marker: bool = False
    http_crlf_marker: bool = False
    http_sqli_marker: bool = False
    http_shell_marker: bool = False
    http_host_is_ip: bool = False
    telnet_cmd_seen: bool = False
    wlan_type_subtype: int | None = None
    wlan_bssid: str | None = None
    wlan_sa: str | None = None
    wlan_da: str | None = None
    arp_dst_ip: str | None = None
    protocol_label: str | None = None
    info_summary: str | None = None


@dataclass
class _DnsRecord:
    frame: int
    timestamp: float | None
    query: str
    rcode: int | None
    src: str | None
    dst: str | None
    qtype: int | None = None


@dataclass
class _ArpConflictRecord:
    ip: str
    macs: list[str]
    packet_refs: list[int]
    reply_count: int


@dataclass
class _Flow:
    key: tuple[int | str, str, int | None, str, int | None]
    proto: int | str
    src: str
    dst: str
    src_port: int | None
    dst_port: int | None
    packets: int = 0
    bytes: int = 0
    first_time: float | None = None
    last_time: float | None = None
    times: list[float] = field(default_factory=list)
    intervals: list[float] = field(default_factory=list)
    refs: list[int] = field(default_factory=list)
    tls_types: list[str] = field(default_factory=list)
    tls_client_hello_count: int = 0
    syn_seen: bool = False
    syn_times: list[float] = field(default_factory=list)
    syn_refs: list[int] = field(default_factory=list)
    rst_count: int = 0
    http_methods: list[str] = field(default_factory=list)
    ip_ttl_min: int | None = None
    ip_ttl_max: int | None = None
    ip_ttl_set: set[int] = field(default_factory=set)
    ip_frag_count: int = 0
    same_src_dst_count: int = 0
    tcp_flags_mask: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    null_flag_count: int = 0
    xmas_flag_count: int = 0
    retrans_count: int = 0
    max_seq_seen: int | None = None
    seq_jump_count: int = 0
    data_len_sum: int = 0
    data_len_max: int = 0
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_data_len_sum: int = 0
    dns_qry_types: set[int] = field(default_factory=set)
    http_status_codes: list[int] = field(default_factory=list)
    http_uri_max_len: int = 0
    http_uri_max_entropy: float = 0.0
    http_xss_hits: int = 0
    http_crlf_hits: int = 0
    http_sqli_hits: int = 0
    http_shell_hits: int = 0
    http_host_ip_hits: int = 0
    telnet_cmd_count: int = 0
    wlan_subtypes: set[int] = field(default_factory=set)
    wlan_bssids: set[str] = field(default_factory=set)
    wlan_deauth_count: int = 0
    wlan_beacon_count: int = 0
    wlan_auth_count: int = 0


@dataclass
class _Accumulator:
    packet_limit: int
    flow_limit: int
    streaming_eviction: bool = False
    flows: dict[tuple[int | str, str, int | None, str, int | None], _Flow] = field(default_factory=dict)
    dns_records: list[_DnsRecord] = field(default_factory=list)
    rows_seen: int = 0
    rows_analyzed: int = 0
    malformed_rows: int = 0
    warnings: list[str] = field(default_factory=list)
    _warning_set: set[str] = field(default_factory=set)
    flow_cap_hit: bool = False
    flow_evictions: int = 0
    dns_cap_hit: bool = False
    dns_analysis_cap_hit: bool = False
    dns_velocity_cap_hit: bool = False
    beacon_analysis_cap_hit: bool = False
    beacon_observations_examined: int = 0
    syn_field_observed: bool = False
    stream_limited: bool = False

    # Streaming telemetry across all frames (even beyond flow eviction)
    total_bytes: int = 0
    first_epoch: float | None = None
    last_epoch: float | None = None
    protocol_counts: dict[str, int] = field(default_factory=dict)
    # Track distinct TCP dst ports and destination IPs per source globally
    source_tcp_ports: dict[str, set[int]] = field(default_factory=dict)
    source_scan_refs: dict[str, list[int]] = field(default_factory=dict)
    source_dsts: dict[str, set[str]] = field(default_factory=dict)
    # Track inbound unique sources & volume per destination globally (even when 1-pkt spoofed flows evict)
    dst_unique_srcs: dict[str, set[str]] = field(default_factory=dict)
    dst_inbound_pkts: dict[str, int] = field(default_factory=dict)
    dst_inbound_bytes: dict[str, int] = field(default_factory=dict)
    # Track ARP IP <-> MAC mappings and ARP request fanout for L2 spoofing & discovery
    arp_ip_macs: dict[str, set[str]] = field(default_factory=dict)
    arp_ip_refs: dict[str, list[int]] = field(default_factory=dict)
    arp_ip_replies: dict[str, int] = field(default_factory=dict)
    arp_scan_targets: dict[str, set[str]] = field(default_factory=dict)
    arp_scan_refs: dict[str, list[int]] = field(default_factory=dict)
    arp_scan_req_count: dict[str, int] = field(default_factory=dict)
    # Timeline coarse observations (bucketed dynamically on finalize)
    _packets_ingested: int = 0
    _time_samples: list[tuple[float, int, bool]] = field(default_factory=list)
    sample_packets: list[SamplePacket] = field(default_factory=list)

    def warn(self, message: str) -> None:
        if message not in self._warning_set and len(self.warnings) < 100:
            self._warning_set.add(message)
            self.warnings.append(message)

    def add_line(self, raw: bytes | str) -> None:
        """Parse one bounded TShark row and update bounded aggregates."""
        self.rows_seen += 1
        unlimited_packets = self.packet_limit <= 0
        if unlimited_packets or self.rows_seen <= self.packet_limit:
            self.rows_analyzed += 1
        else:
            # -c packet_limit+1 is the coverage sentinel; it is not analyzed.
            return

        parts, had_extra = _split_tshark_row(raw)
        if had_extra and len(parts or []) <= len(FIELD_NAMES):
            self.warn("A parser row contained extra columns and was truncated to the allowlist.")
        if parts is None:
            self.malformed_rows += 1
            self.warn("Malformed parser rows were skipped; coverage counts bounded records, not a full capture.")
            return
        packet = _parse_packet(parts)
        if packet is None:
            self.malformed_rows += 1
            self.warn("Malformed parser rows were skipped; coverage counts bounded records, not a full capture.")
            return
        if len(parts) > 15 and parts[15].strip():
            self.syn_field_observed = True
        self.ingest_packet(packet)

    def ingest_packet(self, packet: _Packet, *, is_flagged_hint: bool = False) -> None:
        """Consume one parsed packet metadata object in O(K) bounded memory."""
        self._packets_ingested += 1
        if packet.frame_len is not None:
            self.total_bytes += packet.frame_len

        ts = packet.timestamp
        if ts is not None and math.isfinite(ts):
            if self.first_epoch is None or ts < self.first_epoch:
                self.first_epoch = ts
            if self.last_epoch is None or ts > self.last_epoch:
                self.last_epoch = ts

        proto_label = packet.protocol_label or _infer_protocol_label(packet)
        self.protocol_counts[proto_label] = self.protocol_counts.get(proto_label, 0) + 1

        # Record global port-spread & fan-out/fan-in telemetry (bounded at 4096 hosts to cap RAM)
        if packet.proto == 6 and packet.src and packet.tcp_dstport is not None:
            if packet.src in self.source_tcp_ports or len(self.source_tcp_ports) < 4096:
                p_set = self.source_tcp_ports.setdefault(packet.src, set())
                if len(p_set) < 256:
                    p_set.add(packet.tcp_dstport)
                refs = self.source_scan_refs.setdefault(packet.src, [])
                if len(refs) < MAX_PACKET_REFS and (not refs or refs[-1] != packet.frame):
                    refs.append(packet.frame)

        if packet.src and packet.dst:
            if packet.src in self.source_dsts or len(self.source_dsts) < 4096:
                d_set = self.source_dsts.setdefault(packet.src, set())
                if len(d_set) < 256:
                    d_set.add(packet.dst)
            if packet.dst in self.dst_unique_srcs or len(self.dst_unique_srcs) < 4096:
                s_set = self.dst_unique_srcs.setdefault(packet.dst, set())
                if len(s_set) < 512:
                    s_set.add(packet.src)
                self.dst_inbound_pkts[packet.dst] = self.dst_inbound_pkts.get(packet.dst, 0) + 1
                self.dst_inbound_bytes[packet.dst] = self.dst_inbound_bytes.get(packet.dst, 0) + (packet.frame_len or 0)

        # Record ARP IP->MAC telemetry & ARP scan (opcode=1) discovery fanout
        if packet.arp_src_ip and packet.arp_src_mac and (packet.arp_opcode in (None, 2)):
            if packet.arp_src_ip in self.arp_ip_macs or len(self.arp_ip_macs) < 4096:
                self.arp_ip_macs.setdefault(packet.arp_src_ip, set()).add(packet.arp_src_mac)
                self.arp_ip_replies[packet.arp_src_ip] = self.arp_ip_replies.get(packet.arp_src_ip, 0) + 1
                refs = self.arp_ip_refs.setdefault(packet.arp_src_ip, [])
                if len(refs) < MAX_PACKET_REFS:
                    refs.append(packet.frame)

        if packet.arp_opcode == 1:
            scanner = packet.arp_src_ip or packet.src or packet.eth_src
            target = packet.arp_dst_ip or (packet.dst if packet.dst and packet.dst != "Broadcast" else None)
            if scanner and target:
                if scanner in self.arp_scan_targets or len(self.arp_scan_targets) < 2048:
                    t_set = self.arp_scan_targets.setdefault(scanner, set())
                    if len(t_set) < 512:
                        t_set.add(target)
                    self.arp_scan_req_count[scanner] = self.arp_scan_req_count.get(scanner, 0) + 1
                    refs = self.arp_scan_refs.setdefault(scanner, [])
                    if len(refs) < MAX_PACKET_REFS and (not refs or refs[-1] != packet.frame):
                        refs.append(packet.frame)

        # Flow aggregation with optional priority eviction for huge captures
        flow_key: tuple[int | str, str, int | None, str, int | None] | None = None
        if packet.src and packet.dst and packet.proto is not None:
            flow_key = (
                packet.proto,
                packet.src,
                _packet_source_port(packet),
                packet.dst,
                _packet_destination_port(packet),
            )
            flow = self.flows.get(flow_key)
            if flow is None:
                if len(self.flows) >= self.flow_limit:
                    if self.streaming_eviction:
                        if self._evict_low_value_flow():
                            flow = self._create_flow(flow_key, packet)
                            self.flows[flow_key] = flow
                        else:
                            flow = None
                    else:
                        if not self.flow_cap_hit:
                            self.warn("Flow aggregation cap reached; additional flows were not retained.")
                        self.flow_cap_hit = True
                        flow = None
                else:
                    flow = self._create_flow(flow_key, packet)
                    self.flows[flow_key] = flow
            if flow is not None:
                self._add_to_flow(flow, packet)

        if packet.dns_query:
            if len(self.dns_records) < MAX_DNS_RECORDS:
                self.dns_records.append(
                    _DnsRecord(
                        frame=packet.frame,
                        timestamp=packet.timestamp,
                        query=packet.dns_query,
                        rcode=packet.dns_rcode,
                        src=packet.src,
                        dst=packet.dst,
                        qtype=packet.dns_qry_type,
                    )
                )
            elif not self.dns_cap_hit:
                self.dns_cap_hit = True
                self.warn("DNS evidence cap reached; additional DNS records were not retained.")

        anomaly_tick = bool(
            is_flagged_hint
            or (packet.dns_rcode == 3)
            or (packet.tcp_rst)
            or (packet.http_method)
            or packet.http_xss_marker
            or packet.http_crlf_marker
            or packet.http_sqli_marker
            or packet.http_shell_marker
            or packet.telnet_cmd_seen
            or (packet.wlan_type_subtype in (0x0A, 0x0C))
            or (packet.src and packet.dst and packet.src == packet.dst)
            or (packet.tcp_flags is not None and (packet.tcp_flags == 0 or (packet.tcp_flags & 0x29) == 0x29))
            or (packet.tls_type and "1" in str(packet.tls_type))
            or (packet.arp_src_ip and len(self.arp_ip_macs.get(packet.arp_src_ip, ())) > 1)
        )

        seen_count = max(self.rows_analyzed, self._packets_ingested)

        # Bounded time series sample reservoir (max 3600 points -> bins into 36 timeline bars cleanly)
        if len(self._time_samples) < 3600:
            self._time_samples.append((ts if ts is not None else float(seen_count), packet.frame_len or 0, anomaly_tick))
        elif seen_count % max(2, seen_count // 1800) == 0:
            # Replace oldest non-anomaly or downsample proportionally
            idx = (seen_count * 2654435761) % 3600
            if not self._time_samples[idx][2] or anomaly_tick:
                self._time_samples[idx] = (ts if ts is not None else float(seen_count), packet.frame_len or 0, anomaly_tick)

        # Keep up to MAX_SAMPLE_PACKETS representative & flagged rows across the ENTIRE capture timeline
        if len(self.sample_packets) < MAX_SAMPLE_PACKETS:
            self.sample_packets.append(
                SamplePacket(
                    no=packet.frame,
                    time=_format_utc_time(ts, packet.frame),
                    source=packet.src or packet.eth_src or "Unknown",
                    destination=packet.dst or packet.eth_dst or "Unknown",
                    protocol=proto_label,
                    length=packet.frame_len or 0,
                    info=packet.info_summary or _default_packet_info(packet, proto_label),
                    triage_label="Flagged" if anomaly_tick else None,
                )
            )
        else:
            # Deterministic uniform reservoir slot spanning [0..seen_count-1] via 32-bit Murmur3 mix.
            # Anchor index 0 on the opening frame; reserve up to half the buffer (odd slots) for anomalies
            # while maintaining even temporal coverage from start to end of the capture.
            h = ((seen_count ^ 0x9E3779B9) * 0x85EBCA6B) & 0xFFFFFFFF
            h = ((h ^ (h >> 13)) * 0xC2B2AE35) & 0xFFFFFFFF
            h ^= h >> 16
            slot = h % seen_count
            if 0 < slot < MAX_SAMPLE_PACKETS:
                existing = self.sample_packets[slot]
                if anomaly_tick or existing.triage_label is None:
                    self.sample_packets[slot] = SamplePacket(
                        no=packet.frame,
                        time=_format_utc_time(ts, packet.frame),
                        source=packet.src or packet.eth_src or "Unknown",
                        destination=packet.dst or packet.eth_dst or "Unknown",
                        protocol=proto_label,
                        length=packet.frame_len or 0,
                        info=packet.info_summary or _default_packet_info(packet, proto_label),
                        triage_label="Flagged" if anomaly_tick else None,
                    )
            elif anomaly_tick:
                # Bounded anomaly replacement on odd slots only so even slots stay uniformly spread
                anom_slot = 1 + ((h % (MAX_SAMPLE_PACKETS // 2)) * 2)
                if anom_slot < MAX_SAMPLE_PACKETS and self.sample_packets[anom_slot].triage_label is None:
                    self.sample_packets[anom_slot] = SamplePacket(
                        no=packet.frame,
                        time=_format_utc_time(ts, packet.frame),
                        source=packet.src or packet.eth_src or "Unknown",
                        destination=packet.dst or packet.eth_dst or "Unknown",
                        protocol=proto_label,
                        length=packet.frame_len or 0,
                        info=packet.info_summary or _default_packet_info(packet, proto_label),
                        triage_label="Flagged",
                    )

    def _create_flow(
        self,
        key: tuple[int | str, str, int | None, str, int | None],
        packet: _Packet,
    ) -> _Flow:
        return _Flow(
            key=key,
            proto=packet.proto if packet.proto is not None else "UNK",
            src=packet.src or "",
            dst=packet.dst or "",
            src_port=key[2],
            dst_port=key[4],
        )

    def _evict_low_value_flow(self) -> bool:
        """Evict one single-packet benign ephemeral flow so heavy/anomalous flows survive."""
        victim_key = None
        for key, flow in self.flows.items():
            # Prefer evicting 1-packet benign ephemeral flows without TLS/RST/multiple refs/markers
            if (
                flow.packets <= 1
                and not flow.tls_types
                and flow.rst_count == 0
                and not flow.http_methods
                and flow.wlan_deauth_count == 0
                and flow.telnet_cmd_count == 0
                and flow.null_flag_count == 0
                and flow.xmas_flag_count == 0
            ):
                victim_key = key
                break
        if victim_key is None:
            # Fallback: oldest low-volume non-TLS flow among first 64 keys
            checked = 0
            best_score = None
            for key, flow in self.flows.items():
                score = (
                    (flow.packets * 10)
                    + (50 if flow.tls_types else 0)
                    + (80 if flow.rst_count else 0)
                    + (100 if flow.wlan_deauth_count or flow.http_xss_hits or flow.http_sqli_hits else 0)
                )
                if best_score is None or score < best_score:
                    best_score = score
                    victim_key = key
                checked += 1
                if checked >= 64:
                    break
        if victim_key is not None:
            self.flows.pop(victim_key, None)
            self.flow_evictions += 1
            return True
        return False

    def _add_to_flow(self, flow: _Flow, packet: _Packet) -> None:
        flow.packets += 1
        if packet.frame_len is not None:
            flow.bytes += packet.frame_len
        if packet.timestamp is not None:
            if flow.first_time is None:
                flow.first_time = packet.timestamp
            if flow.last_time is not None and len(flow.intervals) < MAX_NUMERIC_SERIES:
                interval = packet.timestamp - flow.last_time
                if math.isfinite(interval):
                    flow.intervals.append(max(0.0, interval))
            flow.last_time = packet.timestamp
            if len(flow.times) < MAX_NUMERIC_SERIES:
                flow.times.append(packet.timestamp)
        if packet.frame > 0 and len(flow.refs) < MAX_PACKET_REFS:
            flow.refs.append(packet.frame)
        if packet.tls_type:
            if packet.tls_type not in flow.tls_types and len(flow.tls_types) < 20:
                flow.tls_types.append(packet.tls_type)
            if "1" in packet.tls_type.split(","):
                flow.tls_client_hello_count += 1
        if packet.tcp_rst:
            flow.rst_count += 1
            flow.tcp_flags_mask |= 0x04
        if packet.http_method and packet.http_method not in flow.http_methods and len(flow.http_methods) < 8:
            flow.http_methods.append(packet.http_method)

        if packet.ip_ttl is not None:
            flow.ip_ttl_min = packet.ip_ttl if flow.ip_ttl_min is None else min(flow.ip_ttl_min, packet.ip_ttl)
            flow.ip_ttl_max = packet.ip_ttl if flow.ip_ttl_max is None else max(flow.ip_ttl_max, packet.ip_ttl)
            if len(flow.ip_ttl_set) < 16:
                flow.ip_ttl_set.add(packet.ip_ttl)
        if packet.ip_mf or (packet.ip_frag_offset is not None and packet.ip_frag_offset > 0):
            flow.ip_frag_count += 1
        if packet.src and packet.dst and packet.src == packet.dst:
            flow.same_src_dst_count += 1

        if packet.tcp_flags is not None:
            flow.tcp_flags_mask |= packet.tcp_flags
            if packet.tcp_flags & 0x02:
                flow.syn_count += 1
            if packet.tcp_flags & 0x10:
                flow.ack_count += 1
            if packet.tcp_flags & 0x01:
                flow.fin_count += 1
            if (packet.tcp_flags & 0x04) and not packet.tcp_rst:
                flow.rst_count += 1
            if packet.tcp_flags & 0x08:
                flow.psh_count += 1
            if packet.tcp_flags & 0x20:
                flow.urg_count += 1
            if packet.tcp_flags == 0:
                flow.null_flag_count += 1
            if (packet.tcp_flags & 0x29) == 0x29:
                flow.xmas_flag_count += 1
        elif packet.tcp_syn:
            flow.syn_count += 1
            flow.tcp_flags_mask |= 0x02

        if packet.tcp_retransmission:
            flow.retrans_count += 1
        if packet.tcp_seq is not None:
            if flow.max_seq_seen is not None and packet.tcp_seq < flow.max_seq_seen:
                if (flow.max_seq_seen - packet.tcp_seq) < 2_000_000_000:
                    flow.seq_jump_count += 1
            flow.max_seq_seen = packet.tcp_seq if flow.max_seq_seen is None else max(flow.max_seq_seen, packet.tcp_seq)

        if packet.data_len is not None and packet.data_len > 0:
            flow.data_len_sum += packet.data_len
            if packet.data_len > flow.data_len_max:
                flow.data_len_max = packet.data_len
        if packet.icmp_type is not None and flow.icmp_type is None:
            flow.icmp_type = packet.icmp_type
        if packet.icmp_code is not None and flow.icmp_code is None:
            flow.icmp_code = packet.icmp_code
        if packet.icmp_data_len is not None and packet.icmp_data_len > 0:
            flow.icmp_data_len_sum += packet.icmp_data_len

        if packet.dns_qry_type is not None and len(flow.dns_qry_types) < 8:
            flow.dns_qry_types.add(packet.dns_qry_type)
        if packet.http_response_code is not None and packet.http_response_code not in flow.http_status_codes and len(flow.http_status_codes) < 8:
            flow.http_status_codes.append(packet.http_response_code)
        if packet.http_uri_len > flow.http_uri_max_len:
            flow.http_uri_max_len = packet.http_uri_len
        if packet.http_uri_entropy > flow.http_uri_max_entropy:
            flow.http_uri_max_entropy = packet.http_uri_entropy
        if packet.http_xss_marker:
            flow.http_xss_hits += 1
        if packet.http_crlf_marker:
            flow.http_crlf_hits += 1
        if packet.http_sqli_marker:
            flow.http_sqli_hits += 1
        if packet.http_shell_marker:
            flow.http_shell_hits += 1
        if packet.http_host_is_ip:
            flow.http_host_ip_hits += 1
        if packet.telnet_cmd_seen:
            flow.telnet_cmd_count += 1

        if packet.wlan_type_subtype is not None:
            if len(flow.wlan_subtypes) < 12:
                flow.wlan_subtypes.add(packet.wlan_type_subtype)
            if packet.wlan_type_subtype in (0x0A, 0x0C):
                flow.wlan_deauth_count += 1
            elif packet.wlan_type_subtype == 0x08:
                flow.wlan_beacon_count += 1
            elif packet.wlan_type_subtype in (0x00, 0x0B):
                flow.wlan_auth_count += 1
        if packet.wlan_bssid and len(flow.wlan_bssids) < 16:
            flow.wlan_bssids.add(packet.wlan_bssid)

        if flow.proto == 6 and packet.tcp_syn:
            if not flow.syn_seen:
                flow.syn_seen = True
                if packet.timestamp is not None and len(flow.syn_times) < MAX_NUMERIC_SERIES:
                    flow.syn_times.append(packet.timestamp)
                if packet.frame > 0 and len(flow.syn_refs) < MAX_PACKET_REFS:
                    flow.syn_refs.append(packet.frame)


def _format_utc_time(ts: float | None, frame: int) -> str:
    if ts is None or not math.isfinite(ts):
        return f"frame #{frame}"
    # If small relative capture time (e.g., Wireshark CSV '0.000193'), show clean offset seconds
    if ts < 1_000_000_000:
        return f"+{ts:.6f}s"
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%H:%M:%S.") + f"{int(dt.microsecond / 1000):03d}"
    except (OSError, OverflowError, ValueError):
        return f"{ts:.3f}s"


def _infer_protocol_label(packet: _Packet) -> str:
    if packet.proto == "WLAN" or packet.wlan_type_subtype is not None:
        return "WLAN"
    if packet.arp_src_ip or packet.arp_opcode is not None:
        return "ARP"
    if packet.dns_query:
        return "DNS"
    if packet.tls_type:
        return "TLS"
    if packet.http_method or packet.http_response_code is not None:
        return "HTTP"
    if packet.telnet_cmd_seen:
        return "TELNET"
    if packet.icmp_type is not None or packet.proto == 1:
        return "ICMP"
    if packet.proto == 6:
        if packet.tcp_dstport == 443 or packet.tcp_srcport == 443:
            return "TLS"
        if packet.tcp_dstport in (80, 8080) or packet.tcp_srcport in (80, 8080):
            return "HTTP"
        if packet.tcp_dstport == 23 or packet.tcp_srcport == 23:
            return "TELNET"
        if packet.tcp_dstport == 22 or packet.tcp_srcport == 22:
            return "SSH"
        return "TCP"
    if packet.proto == 17:
        if packet.udp_dstport == 53 or packet.udp_srcport == 53:
            return "DNS"
        return "UDP"
    return f"PROTO-{packet.proto}" if packet.proto is not None else "OTHER"


def _default_packet_info(packet: _Packet, proto_label: str) -> str:
    if packet.proto == "WLAN" or packet.wlan_type_subtype is not None:
        sub = f"0x{packet.wlan_type_subtype:02x}" if packet.wlan_type_subtype is not None else "mgmt"
        return _safe_text(f"802.11 subtype={sub} Len={packet.frame_len or 0}", max_length=240)
    if packet.dns_query:
        rc = f" (rcode={packet.dns_rcode})" if packet.dns_rcode is not None else ""
        return _safe_text(f"DNS query {packet.dns_query}{rc}", max_length=240)
    if packet.http_method:
        return _safe_text(f"HTTP {packet.http_method} metadata (uri_len={packet.http_uri_len})", max_length=240)
    if packet.tls_type:
        return _safe_text(f"TLS handshake type={packet.tls_type}", max_length=240)
    if packet.arp_src_ip:
        op = "Request" if packet.arp_opcode == 1 else "Reply" if packet.arp_opcode == 2 else "ARP"
        return _safe_text(f"ARP {op} {packet.arp_src_ip} at {packet.arp_src_mac or ''}", max_length=240)
    sp = _packet_source_port(packet)
    dp = _packet_destination_port(packet)
    if sp is not None and dp is not None:
        flags = " [SYN]" if packet.tcp_syn else (" [RST]" if packet.tcp_rst else "")
        return f"{sp} → {dp}{flags} Len={packet.frame_len or 0}"
    return f"{proto_label} Len={packet.frame_len or 0}"


def _split_tshark_row(raw: bytes | str) -> tuple[list[str] | None, bool]:
    if isinstance(raw, bytes):
        if len(raw) > MAX_LINE_BYTES:
            return None, False
        text = raw.decode("utf-8", errors="replace")
    else:
        if len(raw.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
            return None, False
        text = raw
    text = text.rstrip("\r\n")
    if not text:
        return None, False
    columns = text.split("\t")
    max_cols = len(EXTENDED_FIELD_NAMES)
    had_extra = len(columns) > max_cols
    if len(columns) < len(FIELD_NAMES):
        columns.extend([""] * (len(FIELD_NAMES) - len(columns)))
    return columns[:max_cols], had_extra


def _safe_text(value: str, max_length: int = 253) -> str:
    value = "".join(ch for ch in value if ch.isprintable() and ch not in "\t\r\n")
    return value[:max_length]


def _parse_int(value: str, *, minimum: int | None = None, maximum: int | None = None) -> int | None:
    value = value.strip()
    if not value or not re.fullmatch(r"[0-9]+", value):
        return None
    try:
        number = int(value, 10)
    except (TypeError, ValueError):
        return None
    if minimum is not None and number < minimum:
        return None
    if maximum is not None and number > maximum:
        return None
    return number


def _parse_hex_or_int(value: str, *, minimum: int = 0, maximum: int | None = None) -> int | None:
    value = value.strip()
    if not value:
        return None
    token = value.split(",", 1)[0].strip()
    try:
        if token.lower().startswith("0x"):
            number = int(token, 16)
        elif re.fullmatch(r"[0-9]+", token):
            number = int(token, 10)
        else:
            return None
    except (TypeError, ValueError):
        return None
    if number < minimum:
        return None
    if maximum is not None and number > maximum:
        return None
    return number


def _sanitize_http_markers(uri_raw: str, host_raw: str) -> tuple[int, float, bool, bool, bool, bool, bool]:
    """Distill HTTP URI & Host into safe numeric/boolean markers; discard raw strings."""
    uri = uri_raw.strip()
    host = host_raw.strip()
    uri_len = min(65535, len(uri)) if uri else 0
    uri_ent = round(_entropy(uri[:512]), 3) if uri else 0.0
    low = uri.lower()
    xss = any(tok in low for tok in ("<script", "%3cscript", "onerror=", "onload=", "javascript:", "alert(", "document.cookie"))
    crlf = ("%0d%0a" in low) or ("%0d" in low) or ("%0a" in low) or ("\r" in uri) or ("\n" in uri)
    sqli = any(tok in low for tok in ("union select", "union+select", "union%20select", "' or 1=1", "%27%20or%201=1", "sleep(", "benchmark("))
    shell = any(tok in low for tok in ("../", "..%2f", "/bin/sh", "/bin/bash", "cmd=", "powershell", "wget ", "curl "))
    host_is_ip = False
    if host:
        host_only = host.split(":", 1)[0].strip("[]")
        host_is_ip = _parse_ip(host_only) is not None
    return uri_len, uri_ent, xss, crlf, sqli, shell, host_is_ip


def _parse_float(value: str) -> float | None:
    value = value.strip()
    if not value:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _parse_ip(value: str) -> str | None:
    value = value.strip()
    if not value or len(value) > 45:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _parse_bool(value: str) -> bool | None:
    value = value.strip().lower()
    if not value:
        return None
    if value in {"1", "true", "yes"}:
        return True
    if value in {"0", "false", "no"}:
        return False
    return None


def _parse_packet(parts: Sequence[str]) -> _Packet | None:
    frame = _parse_int(parts[0], minimum=1)
    if frame is None:
        return None
    src = _parse_ip(parts[3]) or _parse_ip(parts[5])
    dst = _parse_ip(parts[4]) or _parse_ip(parts[6])
    proto: int | str | None = _parse_int(parts[11], minimum=0, maximum=255)
    tcp_src = _parse_int(parts[7], minimum=0, maximum=65535)
    tcp_dst = _parse_int(parts[8], minimum=0, maximum=65535)
    udp_src = _parse_int(parts[9], minimum=0, maximum=65535)
    udp_dst = _parse_int(parts[10], minimum=0, maximum=65535)
    if proto is None:
        if tcp_src is not None or tcp_dst is not None:
            proto = 6
        elif udp_src is not None or udp_dst is not None:
            proto = 17
    frame_len = _parse_int(parts[2], minimum=0, maximum=1_000_000_000)
    query = _safe_text(parts[12].strip()) if parts[12].strip() else None
    rcode = _parse_int(parts[13], minimum=0, maximum=255)
    tls_type = _safe_text(parts[14].strip(), max_length=30) if parts[14].strip() else None
    tcp_syn = _parse_bool(parts[15])

    eth_src = _safe_text(parts[16].strip(), max_length=64) if len(parts) > 16 and parts[16].strip() else None
    eth_dst = _safe_text(parts[17].strip(), max_length=64) if len(parts) > 17 and parts[17].strip() else None
    arp_op = _parse_int(parts[18], minimum=0, maximum=65535) if len(parts) > 18 else None
    arp_ip = _parse_ip(parts[19]) if len(parts) > 19 else None
    arp_mac = _safe_text(parts[20].strip(), max_length=64) if len(parts) > 20 and parts[20].strip() else None
    icmp_type = _parse_int(parts[21], minimum=0, maximum=255) if len(parts) > 21 else None
    tcp_rst = _parse_bool(parts[22]) if len(parts) > 22 else None
    http_method = _safe_text(parts[23].strip(), max_length=16) if len(parts) > 23 and parts[23].strip() else None

    ip_ttl = _parse_int(parts[24], minimum=0, maximum=255) if len(parts) > 24 else None
    ip_mf = _parse_bool(parts[25]) if len(parts) > 25 else None
    ip_frag_offset = _parse_int(parts[26], minimum=0, maximum=65535) if len(parts) > 26 else None
    tcp_flags = _parse_hex_or_int(parts[27], minimum=0, maximum=4095) if len(parts) > 27 else None
    tcp_retrans = bool(_parse_bool(parts[28])) if len(parts) > 28 else False
    tcp_seq = _parse_int(parts[29], minimum=0, maximum=4_294_967_295) if len(parts) > 29 else None
    data_len = _parse_int(parts[30], minimum=0, maximum=1_000_000_000) if len(parts) > 30 else None
    icmp_code = _parse_int(parts[31], minimum=0, maximum=255) if len(parts) > 31 else None
    dns_qry_type = _parse_int(parts[32], minimum=0, maximum=65535) if len(parts) > 32 else None
    http_resp_code = _parse_int(parts[33], minimum=100, maximum=599) if len(parts) > 33 else None

    uri_raw = parts[34] if len(parts) > 34 else ""
    host_raw = parts[35] if len(parts) > 35 else ""
    uri_len, uri_ent, xss_m, crlf_m, sqli_m, shell_m, host_is_ip = _sanitize_http_markers(uri_raw, host_raw)

    telnet_cmd_seen = bool(len(parts) > 36 and parts[36].strip())
    wlan_subtype = _parse_hex_or_int(parts[37], minimum=0, maximum=255) if len(parts) > 37 else None
    wlan_bssid = _safe_text(parts[38].strip().lower(), max_length=64) if len(parts) > 38 and parts[38].strip() else None
    wlan_sa = _safe_text(parts[39].strip().lower(), max_length=64) if len(parts) > 39 and parts[39].strip() else None
    wlan_da = _safe_text(parts[40].strip().lower(), max_length=64) if len(parts) > 40 and parts[40].strip() else None
    arp_dst_ip = _parse_ip(parts[41]) if len(parts) > 41 else None

    if proto is None:
        if icmp_type is not None:
            proto = 1
        elif arp_op is not None or arp_ip is not None:
            proto = 0
            src = src or arp_ip or eth_src
            dst = dst or arp_dst_ip or eth_dst or "Broadcast"
        elif wlan_subtype is not None or wlan_sa or wlan_da or wlan_bssid:
            proto = "WLAN"
            src = src or wlan_sa or eth_src or wlan_bssid
            dst = dst or wlan_da or wlan_bssid or eth_dst or "Broadcast"

    # TShark has no portable icmp.data_len field. For ICMPv4, use the
    # supported generic data.len field when the ICMP dissector exposes it.
    icmp_data_len = data_len if proto == 1 else None

    return _Packet(
        frame=frame,
        timestamp=_parse_float(parts[1]),
        frame_len=frame_len,
        src=src,
        dst=dst,
        proto=proto,
        tcp_srcport=tcp_src,
        tcp_dstport=tcp_dst,
        udp_srcport=udp_src,
        udp_dstport=udp_dst,
        dns_query=query,
        dns_rcode=rcode,
        tls_type=tls_type,
        tcp_syn=tcp_syn,
        eth_src=eth_src,
        eth_dst=eth_dst,
        arp_opcode=arp_op,
        arp_src_ip=arp_ip,
        arp_src_mac=arp_mac,
        icmp_type=icmp_type,
        tcp_rst=tcp_rst,
        http_method=http_method,
        ip_ttl=ip_ttl,
        ip_mf=ip_mf,
        ip_frag_offset=ip_frag_offset,
        tcp_flags=tcp_flags,
        tcp_retransmission=tcp_retrans,
        tcp_seq=tcp_seq,
        data_len=data_len,
        icmp_data_len=icmp_data_len,
        icmp_code=icmp_code,
        dns_qry_type=dns_qry_type,
        http_response_code=http_resp_code,
        http_uri_len=uri_len,
        http_uri_entropy=uri_ent,
        http_xss_marker=xss_m,
        http_crlf_marker=crlf_m,
        http_sqli_marker=sqli_m,
        http_shell_marker=shell_m,
        http_host_is_ip=host_is_ip,
        telnet_cmd_seen=telnet_cmd_seen,
        wlan_type_subtype=wlan_subtype,
        wlan_bssid=wlan_bssid,
        wlan_sa=wlan_sa,
        wlan_da=wlan_da,
        arp_dst_ip=arp_dst_ip,
    )


def _packet_source_port(packet: _Packet) -> int | None:
    if packet.proto == 6:
        return packet.tcp_srcport
    if packet.proto == 17:
        return packet.udp_srcport
    return packet.tcp_srcport if packet.tcp_srcport is not None else packet.udp_srcport


def _packet_destination_port(packet: _Packet) -> int | None:
    if packet.proto == 6:
        return packet.tcp_dstport
    if packet.proto == 17:
        return packet.udp_dstport
    return packet.tcp_dstport if packet.tcp_dstport is not None else packet.udp_dstport


def _proto_name(proto: int | str) -> str:
    return {6: "TCP", 17: "UDP", 1: "ICMP", 0: "ARP"}.get(proto, str(proto))


def _flow_sort_key(flow: _Flow) -> tuple[str, ...]:
    return tuple("" if item is None else str(item) for item in flow.key)


def _format_number(value: float) -> str:
    return f"{value:.6g}"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _first_dns_label(query: str) -> str:
    return query.rstrip(".").split(".", 1)[0]


def _setting_int(settings: object, name: str, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    value = getattr(settings, name, default)
    if isinstance(value, bool):
        raise PipelineError("INVALID_SETTINGS", f"{name} must be a positive integer")
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise PipelineError("INVALID_SETTINGS", f"{name} must be a positive integer") from None
    if result < minimum:
        raise PipelineError("INVALID_SETTINGS", f"{name} must be >= {minimum}")
    if maximum is not None and result > maximum:
        return maximum
    return result


def _yara_limit_values(settings: object, parser_memory_mb: int) -> dict[str, object]:
    raw_rules_dir = getattr(settings, "yara_rules_dir", None)
    if raw_rules_dir is None or (isinstance(raw_rules_dir, str) and not raw_rules_dir.strip()):
        rules_dir = None
    elif isinstance(raw_rules_dir, (str, Path)):
        try:
            rules_dir = Path(raw_rules_dir).expanduser().resolve()
        except (OSError, RuntimeError):
            raise PipelineError("INVALID_SETTINGS", "yara_rules_dir is invalid") from None
    else:
        raise PipelineError("INVALID_SETTINGS", "yara_rules_dir is invalid")

    max_total = _setting_int(
        settings, "yara_max_total_bytes", DEFAULT_YARA_MAX_TOTAL_BYTES,
        minimum=1024 * 1024, maximum=256 * 1024 * 1024,
    )
    return {
        "osint_enabled": bool(getattr(settings, "osint_enabled", False)),
        "yara_enabled": bool(getattr(settings, "yara_enabled", False)),
        "yara_rules_dir": rules_dir,
        "yara_max_rules_files": _setting_int(settings, "yara_max_rules_files", DEFAULT_YARA_MAX_RULES_FILES, minimum=1, maximum=256),
        "yara_max_rules_bytes": _setting_int(settings, "yara_max_rules_bytes", DEFAULT_YARA_MAX_RULES_BYTES, minimum=1024, maximum=64 * 1024 * 1024),
        "yara_max_objects": _setting_int(settings, "yara_max_objects", DEFAULT_YARA_MAX_OBJECTS, minimum=1, maximum=500),
        "yara_max_object_bytes": min(
            _setting_int(settings, "yara_max_object_bytes", DEFAULT_YARA_MAX_OBJECT_BYTES, minimum=1024, maximum=128 * 1024 * 1024),
            max_total,
        ),
        "yara_max_total_bytes": max_total,
        "yara_max_matches": _setting_int(settings, "yara_max_matches", DEFAULT_YARA_MAX_MATCHES, minimum=1, maximum=2_000),
        "yara_max_output_bytes": _setting_int(settings, "yara_max_output_bytes", DEFAULT_YARA_MAX_OUTPUT_BYTES, minimum=64 * 1024, maximum=16 * 1024 * 1024),
        "yara_timeout_seconds": _setting_int(settings, "yara_timeout_seconds", DEFAULT_YARA_TIMEOUT_SECONDS, minimum=1, maximum=120),
        "yara_memory_mb": min(
            _setting_int(settings, "yara_memory_mb", DEFAULT_YARA_MEMORY_MB, minimum=128, maximum=512),
            max(128, parser_memory_mb // 2),
        ),
    }


def _setting_timeout(settings: object) -> float:
    value = getattr(settings, "parser_timeout_seconds", 120)
    if isinstance(value, bool):
        raise PipelineError("INVALID_SETTINGS", "parser_timeout_seconds must be positive")
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise PipelineError("INVALID_SETTINGS", "parser_timeout_seconds must be positive") from None
    if not math.isfinite(result) or result <= 0:
        raise PipelineError("INVALID_SETTINGS", "parser_timeout_seconds must be positive")
    return result


def _get_limits(settings: object, *, resource_mode: str | None = None) -> _Limits:
    requested_mode = resource_mode or getattr(settings, "resource_mode", None)
    # Preserve exact deterministic low caps when callers pass plain SimpleNamespace without resource_mode
    if not requested_mode or requested_mode == "legacy":
        parser_memory_mb = _setting_int(settings, "parser_memory_mb", 512, minimum=1, maximum=16_384)
        return _Limits(
            packet_limit=_setting_int(settings, "packet_limit", 20_000, minimum=1, maximum=10_000_000),
            flow_limit=_setting_int(settings, "flow_limit", 5_000, minimum=1, maximum=5_000),
            timeout_seconds=_setting_timeout(settings),
            memory_mb=parser_memory_mb,
            zeek_enabled=bool(getattr(settings, "zeek_enabled", False)),
            zeek_max_rows=_setting_int(settings, "zeek_max_rows", DEFAULT_ZEEK_MAX_ROWS, minimum=1, maximum=10_000),
            zeek_max_output_bytes=_setting_int(settings, "zeek_max_output_bytes", DEFAULT_ZEEK_MAX_OUTPUT_BYTES, minimum=1024 * 1024, maximum=256 * 1024 * 1024),
            zeek_timeout_seconds=_setting_int(settings, "zeek_timeout_seconds", DEFAULT_ZEEK_TIMEOUT_SECONDS, minimum=1, maximum=120),
            zeek_memory_mb=min(
                _setting_int(settings, "zeek_memory_mb", DEFAULT_ZEEK_MEMORY_MB, minimum=128, maximum=512),
                max(128, _setting_int(settings, "parser_memory_mb", 512, minimum=1, maximum=16_384) // 2),
            ),
            stdout_budget_bytes=DEFAULT_MAX_STDOUT_BYTES,
            streaming_eviction=False,
            mode_label="legacy",
            **_yara_limit_values(settings, parser_memory_mb),
        )

    caps = probe_capabilities(getattr(settings, "data_dir", "./data/pcapscanner"))
    profile = resolve_adaptive_profile(
        str(requested_mode),
        caps,
        configured_packet_limit=int(getattr(settings, "packet_limit", 20_000)),
        configured_flow_limit=int(getattr(settings, "flow_limit", 5_000)),
        configured_memory_mb=int(getattr(settings, "parser_memory_mb", 512)),
        configured_timeout_seconds=float(getattr(settings, "parser_timeout_seconds", 120)),
        zeek_enabled=bool(getattr(settings, "zeek_enabled", False)),
    )
    # If an explicit tiny packet_limit (e.g. 10 in tests) was passed with auto, honor it if smaller than 20,000
    raw_pkt = getattr(settings, "packet_limit", None)
    pkt_limit = profile.packet_limit
    if isinstance(raw_pkt, int) and 0 < raw_pkt < 20_000:
        pkt_limit = raw_pkt
    raw_flow = getattr(settings, "flow_limit", None)
    flow_limit = profile.flow_limit
    if isinstance(raw_flow, int) and 0 < raw_flow < 5_000:
        flow_limit = raw_flow

    return _Limits(
        packet_limit=pkt_limit,
        flow_limit=flow_limit,
        timeout_seconds=profile.timeout_seconds,
        memory_mb=profile.parser_memory_mb,
        zeek_enabled=profile.zeek_enabled,
        zeek_max_rows=_setting_int(settings, "zeek_max_rows", DEFAULT_ZEEK_MAX_ROWS, minimum=1, maximum=10_000),
        zeek_max_output_bytes=_setting_int(settings, "zeek_max_output_bytes", DEFAULT_ZEEK_MAX_OUTPUT_BYTES, minimum=1024 * 1024, maximum=256 * 1024 * 1024),
        zeek_timeout_seconds=_setting_int(settings, "zeek_timeout_seconds", DEFAULT_ZEEK_TIMEOUT_SECONDS, minimum=1, maximum=120),
        zeek_memory_mb=min(
            _setting_int(settings, "zeek_memory_mb", DEFAULT_ZEEK_MEMORY_MB, minimum=128, maximum=512),
            max(128, profile.parser_memory_mb // 2),
        ),
        stdout_budget_bytes=profile.stdout_budget_bytes,
        streaming_eviction=profile.streaming_eviction,
        mode_label=profile.mode,
        **_yara_limit_values(settings, profile.parser_memory_mb),
    )


def _child_limits(
    memory_mb: int,
    timeout_seconds: float,
    file_size_limit_bytes: int | None = None,
) -> Callable[[], None]:
    """Return a POSIX child setup hook with platform-aware memory and output limits."""
    def apply() -> None:
        if os.name != "posix":
            return
        try:
            import resource
        except ImportError:
            return

        def set_child_limit(which: int, value: int) -> None:
            try:
                current = resource.getrlimit(which)
                bounded = max(0, int(value))
                if current[1] != resource.RLIM_INFINITY:
                    bounded = min(bounded, current[1])
                resource.setrlimit(which, (bounded, bounded))
            except (OSError, ValueError, TypeError):
                return

        memory_limit = getattr(resource, "RLIMIT_AS", None)
        if sys.platform == "darwin":
            # RLIMIT_AS is unreliable under Mach VM; RLIMIT_DATA still bounds heap growth.
            memory_limit = getattr(resource, "RLIMIT_DATA", None)
        if memory_limit is not None:
            set_child_limit(memory_limit, memory_mb * 1024 * 1024)
        if file_size_limit_bytes is not None and hasattr(resource, "RLIMIT_FSIZE"):
            set_child_limit(resource.RLIMIT_FSIZE, max(1, int(file_size_limit_bytes)))
        if hasattr(resource, "RLIMIT_CORE"):
            set_child_limit(resource.RLIMIT_CORE, 0)
        if hasattr(resource, "RLIMIT_CPU"):
            set_child_limit(resource.RLIMIT_CPU, max(1, int(math.ceil(timeout_seconds))))

    return apply


def _spawn(
    command: Sequence[str],
    *,
    limits: _Limits,
    cwd: str | None = None,
    memory_mb: int | None = None,
    timeout_seconds: float | None = None,
    file_size_limit_bytes: int | None = None,
    stdout_target: object | None = None,
    stderr_target: object | None = None,
) -> subprocess.Popen[bytes]:
    kwargs: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": stdout_target if stdout_target is not None else subprocess.PIPE,
        "stderr": stderr_target if stderr_target is not None else subprocess.PIPE,
        "shell": False,
        "cwd": cwd,
        "start_new_session": True,
    }
    if os.name == "posix":
        kwargs["preexec_fn"] = _child_limits(
            memory_mb if memory_mb is not None else limits.memory_mb,
            timeout_seconds if timeout_seconds is not None else limits.timeout_seconds,
            file_size_limit_bytes,
        )
    try:
        return subprocess.Popen(list(command), **kwargs)  # type: ignore[arg-type]
    except FileNotFoundError:
        raise PipelineError("PARSER_START_FAILED", "The offline parser could not be started") from None
    except (OSError, ValueError):
        raise PipelineError("PARSER_START_FAILED", "The offline parser could not be started") from None


def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
    pid = getattr(process, "pid", None)
    if isinstance(pid, int) and pid > 0 and os.name == "posix":
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
    else:
        try:
            process.terminate()
        except (OSError, AttributeError):
            pass
    try:
        process.wait(timeout=0.35)
    except (subprocess.TimeoutExpired, OSError, AttributeError):
        pass
    if isinstance(pid, int) and pid > 0 and os.name == "posix":
        try:
            os.killpg(pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    else:
        try:
            process.kill()
        except (OSError, AttributeError):
            pass
    try:
        process.wait(timeout=0.35)
    except (subprocess.TimeoutExpired, OSError, AttributeError):
        pass


def _close_streams(process: subprocess.Popen[bytes]) -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(process, stream_name, None)
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


def _read_fd(stream: object, size: int = 64 * 1024) -> bytes:
    fileno = getattr(stream, "fileno", None)
    if not callable(fileno):
        return b""
    try:
        fd = fileno()
        if not isinstance(fd, int):
            return b""
        return os.read(fd, size)
    except BlockingIOError:
        return b""
    except OSError as exc:
        if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
            return b""
        return b""


def _stream_tshark(
    process: subprocess.Popen[bytes],
    accumulator: _Accumulator,
    *,
    deadline: float,
    is_cancelled: Callable[[], bool],
    stdout_budget_bytes: int = DEFAULT_MAX_STDOUT_BYTES,
) -> tuple[bool, int | None]:
    """Drain both child pipes with selectors and parse stdout one line at a time."""
    selector = selectors.DefaultSelector()
    streams: dict[int, tuple[object, str]] = {}
    stdout = getattr(process, "stdout", None)
    stderr = getattr(process, "stderr", None)
    for stream, label in ((stdout, "stdout"), (stderr, "stderr")):
        if stream is None:
            continue
        try:
            selector.register(stream, selectors.EVENT_READ, label)
            streams[stream.fileno()] = (stream, label)
        except (OSError, ValueError, AttributeError):
            continue

    line_buffer = bytearray()
    discard_long_line = False
    stdout_bytes = 0
    stderr_bytes = 0
    output_limited = False

    def consume_stdout(chunk: bytes) -> None:
        nonlocal line_buffer, discard_long_line
        pending = chunk
        while pending:
            if discard_long_line:
                newline = pending.find(b"\n")
                if newline < 0:
                    return
                pending = pending[newline + 1 :]
                discard_long_line = False
                continue
            newline = pending.find(b"\n")
            if newline < 0:
                if len(line_buffer) + len(pending) > MAX_LINE_BYTES:
                    line_buffer.clear()
                    discard_long_line = True
                    accumulator.stream_limited = True
                    accumulator.warn("An oversized parser line was discarded.")
                else:
                    line_buffer.extend(pending)
                return
            line = bytes(line_buffer) + pending[:newline]
            line_buffer.clear()
            pending = pending[newline + 1 :]
            if len(line) > MAX_LINE_BYTES:
                accumulator.stream_limited = True
                accumulator.warn("An oversized parser line was discarded.")
                continue
            if line.strip():
                accumulator.add_line(line)

    def flush_stdout() -> None:
        if line_buffer and not discard_long_line and len(line_buffer) <= MAX_LINE_BYTES:
            accumulator.add_line(bytes(line_buffer))
        line_buffer.clear()

    try:
        while streams:
            if is_cancelled():
                _terminate_tree(process)
                raise PipelineError("CANCELLED", "Offline parser cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_tree(process)
                raise PipelineError("PARSER_TIMEOUT", "Offline parser deadline exceeded")
            try:
                events = selector.select(timeout=min(0.25, remaining))
            except OSError:
                events = []
            if not events:
                continue
            for key, _ in events:
                stream = key.fileobj
                label = key.data
                data = _read_fd(stream)
                if not data:
                    try:
                        selector.unregister(stream)
                    except (OSError, KeyError, ValueError):
                        pass
                    streams.pop(key.fd, None)
                    if label == "stdout":
                        flush_stdout()
                    continue
                if label == "stderr":
                    stderr_bytes += len(data)
                    if stderr_bytes > MAX_STDERR_BYTES:
                        accumulator.warn("Parser diagnostics exceeded the bounded stderr drain and were discarded.")
                else:
                    stdout_bytes += len(data)
                    if stdout_budget_bytes > 0 and stdout_bytes > stdout_budget_bytes:
                        accumulator.stream_limited = True
                        accumulator.warn("Parser output exceeded its bounded byte budget; analysis is partial.")
                        output_limited = True
                        _terminate_tree(process)
                        for fd in list(streams):
                            try:
                                selector.unregister(fd)
                            except (OSError, KeyError, ValueError):
                                pass
                        streams.clear()
                        line_buffer.clear()
                        break
                    consume_stdout(data)
            if output_limited:
                break
    finally:
        selector.close()

    if not output_limited:
        flush_stdout()
    try:
        returncode = process.poll()
    except (OSError, AttributeError):
        returncode = None
    if returncode is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_tree(process)
            raise PipelineError("PARSER_TIMEOUT", "Offline parser deadline exceeded")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _terminate_tree(process)
            raise PipelineError("PARSER_TIMEOUT", "Offline parser deadline exceeded") from None
    return output_limited, returncode


def _drain_command(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    is_cancelled: Callable[[], bool],
    output_budget_bytes: int = DEFAULT_MAX_STDOUT_BYTES,
    output_directory: Path | None = None,
    disk_budget_bytes: int | None = None,
    output_entry_limit: int | None = None,
    watched_file: Path | None = None,
    watched_file_budget_bytes: int | None = None,
) -> str:
    """Drain an optional stage without retaining any tool output."""
    selector = selectors.DefaultSelector()
    streams: list[object] = []
    for stream_name in ("stdout", "stderr"):
        stream = getattr(process, stream_name, None)
        if stream is None:
            continue
        try:
            selector.register(stream, selectors.EVENT_READ)
            streams.append(stream)
        except (OSError, ValueError, AttributeError):
            continue
    total = 0
    limited = False
    try:
        while streams or process.poll() is None:
            if is_cancelled():
                _terminate_tree(process)
                raise PipelineError("CANCELLED", "Offline parser cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_tree(process)
                return "partial"
            wait_for = min(0.05, remaining)
            if streams:
                events = selector.select(timeout=wait_for)
            else:
                time.sleep(wait_for)
                events = []
            for key, _ in events:
                data = _read_fd(key.fileobj)
                if not data:
                    try:
                        selector.unregister(key.fileobj)
                    except (OSError, KeyError, ValueError):
                        pass
                    if key.fileobj in streams:
                        streams.remove(key.fileobj)
                    continue
                total += len(data)
                if total > output_budget_bytes:
                    limited = True
                    _terminate_tree(process)
                    streams.clear()
                    break
            if (
                not limited
                and output_directory is not None
                and disk_budget_bytes is not None
                and bounded_directory_size(
                    output_directory,
                    disk_budget_bytes,
                    max_entries=output_entry_limit or 128,
                )[1]
            ):
                limited = True
                _terminate_tree(process)
            if not limited and watched_file is not None and watched_file_budget_bytes is not None:
                try:
                    watched_size = watched_file.stat().st_size
                except OSError:
                    watched_size = 0
                if watched_size > watched_file_budget_bytes:
                    limited = True
                    _terminate_tree(process)
            if limited:
                break
    finally:
        selector.close()
    try:
        returncode = process.poll()
    except (OSError, AttributeError):
        returncode = None
    if returncode is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_tree(process)
            return "partial"
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _terminate_tree(process)
            return "partial"
    if limited:
        return "partial"
    return "completed" if returncode == 0 else "failed"


def _build_command(tshark: str, path: Path, packet_limit: int) -> list[str]:
    """Canonical command builder kept exact for bounded tests."""
    command = [
        tshark,
        "-n",
        "-r",
        str(path),
        "-c",
        str(packet_limit + 1),
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=/t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
    ]
    for field_name in FIELD_NAMES:
        command.extend(("-e", field_name))
    return command


def _build_streaming_command(tshark: str, path: Path, limits: _Limits) -> list[str]:
    """Command builder supporting unlimited stream mode and safe L2/L3/L4 fields."""
    command = [tshark, "-n", "-r", str(path)]
    if limits.packet_limit > 0:
        command.extend(["-c", str(limits.packet_limit + 1)])
    command.extend([
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=/t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
    ])
    for field_name in EXTENDED_FIELD_NAMES:
        command.extend(("-e", field_name))
    return command


def _flow_attributes(
    flow: _Flow,
    accumulator: _Accumulator | None = None,
) -> dict[str, str | int | float | bool]:
    attrs: dict[str, str | int | float | bool] = {
        "src": flow.src,
        "dst": flow.dst,
        "protocol": _proto_name(flow.proto),
        "packets": flow.packets,
        "bytes": flow.bytes,
    }
    if flow.src_port is not None:
        attrs["src_port"] = flow.src_port
    if flow.dst_port is not None:
        attrs["dst_port"] = flow.dst_port
    if flow.first_time is not None:
        attrs["first_seen"] = flow.first_time
    if flow.last_time is not None:
        attrs["last_seen"] = flow.last_time
        if flow.first_time is not None:
            dur = max(0.0, flow.last_time - flow.first_time)
            attrs["duration"] = round(dur, 6)
            if flow.packets >= 2 and dur > 0:
                attrs["pkt_rate"] = round(flow.packets / max(0.001, dur), 2)
    if flow.intervals:
        attrs["intervals"] = ",".join(_format_number(value) for value in flow.intervals[:MAX_NUMERIC_SERIES])
    if flow.tls_types:
        attrs["tls_handshake_types"] = ",".join(flow.tls_types[:20])
    if flow.tls_client_hello_count > 0:
        attrs["tls_client_hello_count"] = flow.tls_client_hello_count
    if flow.rst_count > 0:
        attrs["rst_count"] = flow.rst_count
    if flow.http_methods:
        attrs["http_method"] = ",".join(flow.http_methods[:5])

    # Bidirectional reverse-flow asymmetry & fan-in/fan-out window context
    if accumulator is not None and flow.proto in (6, 17, 1):
        rev_key = (flow.proto, flow.dst, flow.dst_port, flow.src, flow.src_port)
        rev_flow = accumulator.flows.get(rev_key)
        if rev_flow is not None:
            attrs["rev_packets"] = rev_flow.packets
            attrs["rev_bytes"] = rev_flow.bytes
            attrs["io_byte_ratio"] = round(flow.bytes / max(1, flow.bytes + rev_flow.bytes), 4)
        elif flow.packets >= 2:
            attrs["rev_packets"] = 0
            attrs["rev_bytes"] = 0
            attrs["io_byte_ratio"] = 1.0
        dst_fanin = len(accumulator.dst_unique_srcs.get(flow.dst, ()))
        if dst_fanin > 1:
            attrs["dst_unique_srcs"] = dst_fanin
            attrs["dst_inbound_pkts"] = accumulator.dst_inbound_pkts.get(flow.dst, flow.packets)
        src_ports_cnt = len(accumulator.source_tcp_ports.get(flow.src, ()))
        if src_ports_cnt > 1:
            attrs["src_unique_dst_ports"] = src_ports_cnt
        src_dsts_cnt = len(accumulator.source_dsts.get(flow.src, ()))
        if src_dsts_cnt > 1:
            attrs["src_unique_dsts"] = src_dsts_cnt

    # Selective L3/L4/L7/WLAN telemetry (omits zero values to preserve <= 40 Evidence limit)
    if flow.ip_ttl_min is not None:
        attrs["ttl_min"] = flow.ip_ttl_min
        attrs["ttl_max"] = flow.ip_ttl_max if flow.ip_ttl_max is not None else flow.ip_ttl_min
        if len(flow.ip_ttl_set) > 1:
            attrs["ttl_distinct_count"] = len(flow.ip_ttl_set)
    if flow.ip_frag_count > 0:
        attrs["ip_frag_count"] = flow.ip_frag_count
    if flow.same_src_dst_count > 0:
        attrs["same_src_dst_count"] = flow.same_src_dst_count
    if flow.tcp_flags_mask > 0:
        attrs["tcp_flags_mask"] = flow.tcp_flags_mask
    if flow.syn_count > 0:
        attrs["syn_count"] = flow.syn_count
    if flow.ack_count > 0:
        attrs["ack_count"] = flow.ack_count
    if flow.fin_count > 0:
        attrs["fin_count"] = flow.fin_count
    if flow.psh_count > 0:
        attrs["psh_count"] = flow.psh_count
    if flow.urg_count > 0:
        attrs["urg_count"] = flow.urg_count
    if flow.null_flag_count > 0:
        attrs["null_flag_count"] = flow.null_flag_count
    if flow.xmas_flag_count > 0:
        attrs["xmas_flag_count"] = flow.xmas_flag_count
    if flow.retrans_count > 0:
        attrs["retrans_count"] = flow.retrans_count
    if flow.seq_jump_count > 0:
        attrs["seq_jump_count"] = flow.seq_jump_count
    if flow.data_len_sum > 0:
        attrs["data_len_sum"] = flow.data_len_sum
        attrs["data_len_max"] = flow.data_len_max
    if flow.icmp_type is not None:
        attrs["icmp_type"] = flow.icmp_type
    if flow.icmp_code is not None:
        attrs["icmp_code"] = flow.icmp_code
    if flow.icmp_data_len_sum > 0:
        attrs["icmp_data_len_sum"] = flow.icmp_data_len_sum
    if flow.dns_qry_types:
        attrs["dns_qry_type"] = next(iter(sorted(flow.dns_qry_types)))
    if flow.http_status_codes:
        attrs["http_status_codes"] = ",".join(str(c) for c in flow.http_status_codes[:8])
    if flow.http_uri_max_len > 0:
        attrs["http_uri_max_len"] = flow.http_uri_max_len
    if flow.http_uri_max_entropy > 0.0:
        attrs["http_uri_max_entropy"] = flow.http_uri_max_entropy
    if flow.http_xss_hits > 0:
        attrs["http_xss_hits"] = flow.http_xss_hits
    if flow.http_crlf_hits > 0:
        attrs["http_crlf_hits"] = flow.http_crlf_hits
    if flow.http_sqli_hits > 0:
        attrs["http_sqli_hits"] = flow.http_sqli_hits
    if flow.http_shell_hits > 0:
        attrs["http_shell_hits"] = flow.http_shell_hits
    if flow.http_host_ip_hits > 0:
        attrs["http_host_ip_hits"] = flow.http_host_ip_hits
    if flow.telnet_cmd_count > 0:
        attrs["telnet_cmd_count"] = flow.telnet_cmd_count
    if flow.wlan_subtypes:
        attrs["wlan_subtypes"] = ",".join(f"0x{s:02x}" for s in sorted(flow.wlan_subtypes)[:8])
    if flow.wlan_bssids:
        attrs["wlan_bssid_count"] = len(flow.wlan_bssids)
    if flow.wlan_deauth_count > 0:
        attrs["wlan_deauth_count"] = flow.wlan_deauth_count
    if flow.wlan_beacon_count > 0:
        attrs["wlan_beacon_count"] = flow.wlan_beacon_count
    if flow.wlan_auth_count > 0:
        attrs["wlan_auth_count"] = flow.wlan_auth_count

    if len(attrs) > 38:
        # Preserve core identifiers + first 38 highest-priority attributes to satisfy <=40 contract.
        return dict(list(attrs.items())[:38])
    return attrs


def _dns_attributes(record: _DnsRecord) -> dict[str, str | int | float | bool]:
    attrs: dict[str, str | int | float | bool] = {"query": record.query}
    if record.rcode is not None:
        attrs["rcode"] = record.rcode
    if record.qtype is not None:
        attrs["dns_qry_type"] = record.qtype
    if record.src is not None:
        attrs["src"] = record.src
    if record.dst is not None:
        attrs["dst"] = record.dst
    if record.timestamp is not None:
        attrs["time_epoch"] = record.timestamp
    return attrs


def _finding(
    findings: list[Finding],
    *,
    detector: str,
    title: str,
    severity: str = "low",
    confidence: str = "low",
    summary: str | None = None,
    evidence_ids: Iterable[str],
    limitations: list[str],
) -> None:
    ids: list[str] = []
    for evidence_id in evidence_ids:
        if evidence_id not in ids and len(ids) < 100:
            ids.append(evidence_id)
    if not ids or len(findings) >= 1000:
        return
    findings.append(
        Finding(
            finding_id=f"F-{len(findings) + 1:04d}",
            detector=detector,
            title=title,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            evidence_ids=ids,
            limitations=limitations,
            summary=summary[:600] if summary else None,
        )
    )


def _detect_findings(
    accumulator: _Accumulator,
    flow_evidence: dict[tuple[int | str, str, int | None, str, int | None], str],
    dns_evidence: list[tuple[_DnsRecord, str]],
    arp_evidence: list[tuple[_ArpConflictRecord, str]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    # 1. ARP Spoofing (Conflicting MAC addresses claiming same IPv4) & ARP Scan Bursts
    if arp_evidence:
        for record, evidence_id in arp_evidence:
            if len(record.macs) > 1:
                _finding(
                    findings,
                    detector="arp_spoofing_conflict",
                    title=f"ARP spoofing candidate: IP {record.ip} claimed by {len(record.macs)} MAC addresses",
                    severity="high",
                    confidence="medium",
                    summary=f"Detected conflicting Layer-2 ARP announcements associating {record.ip} with multiple hardware MACs ({', '.join(record.macs[:4])}).",
                    evidence_ids=[evidence_id],
                    limitations=[
                        "Duplicate ARP announcements indicate potential poisoning or HA failover/VRRP.",
                        "Confirm expected gateway MAC address on the LAN segment before concluding incident.",
                    ],
                )

    # 2. TCP destination port spread (port scan)
    by_source: dict[str, dict[int, list[str]]] = {}
    for flow in accumulator.flows.values():
        if flow.proto != 6 or flow.dst_port is None:
            continue
        evidence_id = flow_evidence.get(flow.key)
        if evidence_id is None:
            continue
        by_source.setdefault(flow.src, {}).setdefault(flow.dst_port, []).append(evidence_id)
    for source in sorted(by_source):
        ports = by_source[source]
        global_count = max(len(ports), len(accumulator.source_tcp_ports.get(source, ())))
        if global_count < TCP_PORT_SPREAD_THRESHOLD:
            continue
        ids = [evidence_id for port in sorted(ports) for evidence_id in ports[port]]
        _finding(
            findings,
            detector="tcp_destination_port_spread",
            title="One source contacted many distinct TCP destination ports",
            severity="low",
            confidence="low",
            summary=f"Host {source} probed {global_count} distinct TCP destination ports inside the analyzed capture window.",
            evidence_ids=ids,
            limitations=[
                "Low-confidence threshold heuristic; scanning is not proof of malicious activity.",
                "Only bounded, normalized flow evidence is cited.",
            ],
        )

    # 3. Repeated NXDOMAINs and/or repeated long high-entropy labels (DNS tunnel / DGA)
    dns_by_query: dict[str, list[tuple[_DnsRecord, str]]] = {}
    for record, evidence_id in dns_evidence:
        dns_by_query.setdefault(record.query, []).append((record, evidence_id))
    for query in sorted(dns_by_query):
        records = dns_by_query[query]
        nxdomain = [item for item in records if item[0].rcode == 3]
        label = _first_dns_label(query)
        high_entropy = len(label) >= 20 and _entropy(label) >= DNS_HIGH_ENTROPY_THRESHOLD
        if len(nxdomain) >= DNS_NXDOMAIN_THRESHOLD or (high_entropy and len(records) >= DNS_HIGH_ENTROPY_REPEAT_THRESHOLD):
            _finding(
                findings,
                detector="dns_nxdomain_entropy",
                title="Repeated NXDOMAIN or high-entropy DNS query labels",
                severity="medium" if high_entropy else "low",
                confidence="low",
                summary=f"Query {query[:80]} triggered NXDOMAIN/high-entropy thresholds ({len(nxdomain)} NXDOMAINs across {len(records)} queries).",
                evidence_ids=[evidence_id for _, evidence_id in records],
                limitations=[
                    "DNS label entropy is a heuristic and is not evidence of maliciousness.",
                    "NXDOMAIN repetition can be benign and this detector is low confidence.",
                ],
            )

    # 3a. Adapted DGA/tunneling heuristics operate on bounded request metadata
    # only. They emit low-confidence candidates linked to the retained DNS rows.
    dns_analysis = analyze_dns_candidates(
        DNSObservation(
            query=record.query,
            evidence_id=evidence_id,
            source=record.src,
            response_code=record.rcode,
            qtype=record.qtype,
        )
        for record, evidence_id in dns_evidence
    )
    if dns_analysis.truncated:
        accumulator.dns_analysis_cap_hit = True
    for candidate in dns_analysis.candidates:
        _finding(
            findings,
            detector=candidate.detector,
            title=candidate.title,
            severity="low",
            confidence="low",
            summary=candidate.summary,
            evidence_ids=candidate.evidence_ids,
            limitations=list(candidate.limitations),
        )

    # 3b. High-volume, high-diversity DNS requests in fixed 60-second windows.
    # Keep only bounded aggregates; query names are used locally for counts and
    # are never copied into this finding's title or summary.
    velocity_groups: dict[tuple[str, int], dict[str, Any]] = {}
    for record, evidence_id in dns_evidence:
        if record.timestamp is None or record.src is None or record.rcode is not None:
            continue  # require a timestamped DNS request, not a response row
        if not math.isfinite(record.timestamp) or record.timestamp < 0:
            continue
        window = int(record.timestamp // DNS_QUERY_VELOCITY_WINDOW_SECONDS)
        key = (record.src, window)
        group = velocity_groups.get(key)
        if group is None:
            if len(velocity_groups) >= MAX_DNS_VELOCITY_GROUPS:
                accumulator.dns_velocity_cap_hit = True
                continue
            group = {"count": 0, "queries": set(), "evidence_ids": []}
            velocity_groups[key] = group
        group["count"] += 1
        query_key = record.query.rstrip(".").lower()
        if len(group["queries"]) < DNS_QUERY_VELOCITY_MIN_UNIQUE_NAMES:
            group["queries"].add(query_key)
        if len(group["evidence_ids"]) < 100:
            group["evidence_ids"].append(evidence_id)

    for (_source, _window), group in sorted(velocity_groups.items()):
        query_count = int(group["count"])
        unique_count = len(group["queries"])
        if query_count < DNS_QUERY_VELOCITY_MIN_QUERIES or unique_count < DNS_QUERY_VELOCITY_MIN_UNIQUE_NAMES:
            continue
        _finding(
            findings,
            detector="dns_query_velocity_diversity",
            title="High-volume, high-diversity DNS query burst",
            severity="low",
            confidence="low",
            summary=(
                f"A single source emitted {query_count} DNS requests for at least "
                f"{unique_count} distinct names in one fixed {DNS_QUERY_VELOCITY_WINDOW_SECONDS}-second window."
            ),
            evidence_ids=group["evidence_ids"],
            limitations=[
                "This low-confidence volume/diversity heuristic is not proof of DNS tunneling or compromise.",
                "Benign resolvers, software updates, service discovery, and capture duplication can produce bursts.",
                "Only timestamped DNS request rows retained within configured packet/evidence bounds are evaluated.",
            ],
        )

    # 4. Periodic SYN-based connection starts (candidate beacon)
    starts_by_target: dict[tuple[str, str, int | None], list[tuple[float, str]]] = {}
    periodic_cited_evidence: set[str] = set()
    total_starts = 0
    for flow in accumulator.flows.values():
        if flow.proto != 6 or not flow.syn_times:
            continue
        evidence_id = flow_evidence.get(flow.key)
        if evidence_id is None:
            continue
        total_starts += 1
        starts_by_target.setdefault((flow.src, flow.dst, flow.dst_port), []).append(
            (flow.syn_times[0], evidence_id)
        )
    if not accumulator.syn_field_observed:
        accumulator.warn(
            "Periodic TCP detector skipped: tcp.flags.syn was unavailable in the bounded field output; no connection-start coverage is claimed."
        )
    elif total_starts < PERIODIC_MIN_STARTS:
        accumulator.warn(
            f"Periodic TCP detector skipped: only {total_starts} SYN-based connection starts were available; at least {PERIODIC_MIN_STARTS} are required."
        )
    else:
        candidate_group = False
        for target in sorted(starts_by_target, key=lambda item: tuple(str(value) for value in item)):
            events = sorted(starts_by_target[target], key=lambda item: (item[0], item[1]))
            if len(events) < PERIODIC_MIN_STARTS:
                continue
            intervals = [events[index][0] - events[index - 1][0] for index in range(1, len(events))]
            intervals = [interval for interval in intervals if math.isfinite(interval) and interval > 0]
            if len(intervals) < PERIODIC_MIN_STARTS - 1:
                continue
            typical = median(intervals)
            if typical <= 0:
                continue
            if all(abs(interval - typical) / typical <= PERIODIC_RELATIVE_TOLERANCE for interval in intervals):
                candidate_group = True
                periodic_cited_evidence.update(evidence_id for _, evidence_id in events)
                _finding(
                    findings,
                    detector="periodic_tcp_connection_starts",
                    title="Periodic TCP connection starts (candidate beacon)",
                    severity="medium",
                    confidence="low",
                    summary=f"Target {target[1]}:{target[2] or '-'} received {len(events)} periodic connection starts (~{typical:.1f}s median interval).",
                    evidence_ids=[evidence_id for _, evidence_id in events],
                    limitations=[
                        "Candidate only; periodicity is not a definitive beacon determination.",
                        "Repeated SYNs on one five-tuple are counted once when tcp.flags.syn is present.",
                        "Timing patterns can be caused by benign software or scheduled jobs.",
                    ],
                )
        if not candidate_group:
            accumulator.warn(
                "Periodic TCP detector ran on SYN starts but found no sufficiently regular bounded interval group."
            )

    # 4a. Adapted PCAP-Hunter interval/jitter scoring over retained flow samples.
    # This complements the stricter SYN-start detector; already-cited groups are
    # suppressed to avoid emitting duplicate low-confidence findings.
    beacon_observations: list[BeaconObservation] = []
    for flow in accumulator.flows.values():
        evidence_id = flow_evidence.get(flow.key)
        if evidence_id is None or len(flow.times) < 4:
            continue
        if len(beacon_observations) >= MAX_BEACON_FLOW_SAMPLES:
            accumulator.beacon_analysis_cap_hit = True
            break
        protocol = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(flow.proto, "other")
        beacon_observations.append(
            BeaconObservation(
                evidence_id=evidence_id,
                timestamps=flow.times,
                protocol=protocol,
                destination_port=flow.dst_port,
                timestamps_truncated=flow.packets > len(flow.times),
            )
        )
    beacon_analysis = analyze_beacon_candidates(
        beacon_observations,
        input_truncated=accumulator.beacon_analysis_cap_hit,
    )
    accumulator.beacon_observations_examined = beacon_analysis.observations_examined
    accumulator.beacon_analysis_cap_hit = accumulator.beacon_analysis_cap_hit or beacon_analysis.truncated
    for candidate in beacon_analysis.candidates:
        if set(candidate.evidence_ids).issubset(periodic_cited_evidence):
            continue
        _finding(
            findings,
            detector=candidate.detector,
            title=candidate.title,
            severity="low",
            confidence="low",
            summary=candidate.summary,
            evidence_ids=list(candidate.evidence_ids),
            limitations=list(candidate.limitations),
        )
    if accumulator.beacon_analysis_cap_hit:
        accumulator.warn("Beacon timing analysis reached a configured observation or timestamp cap; candidate coverage is partial.")

    # 5. TLS repeated ClientHello / renegotiation anomaly
    for flow in accumulator.flows.values():
        if flow.tls_client_hello_count >= 3:
            eid = flow_evidence.get(flow.key)
            if eid:
                _finding(
                    findings,
                    detector="tls_renegotiation_anomaly",
                    title="Multiple TLS ClientHello handshakes inside one flow",
                    severity="medium",
                    confidence="low",
                    summary=f"Flow {flow.src}->{flow.dst}:{flow.dst_port or '-'} observed {flow.tls_client_hello_count} TLS ClientHello messages.",
                    evidence_ids=[eid],
                    limitations=[
                        "Repeated handshakes can indicate TLS renegotiation probes or multiplexed tunnels.",
                    ],
                )

    # 6. ICMP flood / burst traffic
    for flow in accumulator.flows.values():
        if flow.proto == 1 and flow.packets >= 50:
            eid = flow_evidence.get(flow.key)
            if eid:
                _finding(
                    findings,
                    detector="icmp_smurf_or_flood",
                    title="High-rate ICMP packet burst detected",
                    severity="medium" if flow.packets >= 200 else "low",
                    confidence="medium",
                    summary=f"ICMP flow {flow.src}->{flow.dst} logged {flow.packets} packets ({flow.bytes} bytes).",
                    evidence_ids=[eid],
                    limitations=[
                        "Verify whether ICMP burst corresponds to diagnostics/ping sweep or Smurf amplification.",
                    ],
                )

    # 7. 802.11 WLAN Deauthentication / Disassociation Flood
    for flow in accumulator.flows.values():
        if flow.proto == "WLAN" and flow.wlan_deauth_count >= 10:
            eid = flow_evidence.get(flow.key)
            if eid:
                _finding(
                    findings,
                    detector="wlan_deauth_flood",
                    title="802.11 WLAN deauthentication / disassociation flood",
                    severity="medium",
                    confidence="low",
                    summary=f"WLAN flow {flow.src}->{flow.dst} logged {flow.wlan_deauth_count} deauth/disassoc frames ({flow.packets} total frames).",
                    evidence_ids=[eid],
                    limitations=[
                        "IEEE 802.11 management frame flood heuristics are observational and can overlap roaming or AP resets.",
                        "Verify BSSID authorization and signal proximity before attributing interference.",
                    ],
                )

    if len(findings) >= 1000:
        accumulator.stream_limited = True
        accumulator.warn("Finding cap reached; additional candidates may not be retained.")
    return findings


def _stage(name: str, state: str, detail: str) -> Stage:
    return Stage(name=name, state=state, detail=detail[:500])  # type: ignore[arg-type]


def _build_timeline(accumulator: _Accumulator) -> list[TimelineBucket]:
    samples = accumulator._time_samples
    if not samples:
        return []
    t_min = min(item[0] for item in samples)
    t_max = max(item[0] for item in samples)
    span = max(1e-6, t_max - t_min)
    buckets_pkts = [0] * TIMELINE_BUCKETS
    buckets_bytes = [0] * TIMELINE_BUCKETS
    buckets_anom = [0] * TIMELINE_BUCKETS

    scale = max(1.0, accumulator.rows_analyzed / len(samples))
    for ts, nbytes, is_anom in samples:
        ratio = (ts - t_min) / span
        idx = min(TIMELINE_BUCKETS - 1, max(0, int(ratio * (TIMELINE_BUCKETS - 1))))
        buckets_pkts[idx] += max(1, int(round(scale)))
        buckets_bytes[idx] += nbytes
        if is_anom:
            buckets_anom[idx] += 1

    return [
        TimelineBucket(
            index=i,
            label=_format_utc_time(t_min + (span * i / max(1, TIMELINE_BUCKETS - 1)), i + 1),
            packets=buckets_pkts[i],
            bytes=buckets_bytes[i],
            anomalies=buckets_anom[i],
        )
        for i in range(TIMELINE_BUCKETS)
    ]


def _flow_priority_for_bundle(flow: _Flow) -> tuple[int, int, tuple[str, ...]]:
    # Prioritize suspicious/active flows when truncating evidence to MAX_EVIDENCE
    signal_rank = 0
    if (
        flow.tls_client_hello_count >= 3
        or flow.rst_count >= 5
        or (flow.proto == 1 and flow.packets >= 50)
        or flow.wlan_deauth_count > 0
        or flow.http_xss_hits > 0
        or flow.http_crlf_hits > 0
        or flow.http_sqli_hits > 0
        or flow.http_shell_hits > 0
        or flow.null_flag_count > 0
        or flow.xmas_flag_count > 0
        or flow.same_src_dst_count > 0
    ):
        signal_rank = 3
    elif (
        flow.syn_seen
        or flow.tls_types
        or flow.http_methods
        or flow.telnet_cmd_count > 0
        or flow.ip_frag_count > 0
        or flow.packets >= 5
    ):
        signal_rank = 2
    else:
        signal_rank = 1
    return (-signal_rank, -flow.packets, _flow_sort_key(flow))


def _build_bundle(
    accumulator: _Accumulator,
    *,
    capture_sha256: str,
    parser_state: str,
    parser_detail: str,
    zeek_stage: Stage,
    osint_enabled: bool = False,
    zeek_records: Sequence[NormalizedZeekRow] = (),
    yara_stage: Stage | None = None,
    yara_records: Sequence[NormalizedYaraMatch] = (),
    carved_artifacts: Sequence[dict[str, Any]] = (),
    parser_name: str = "tshark-fields-offline",
    triage_cfg: object | None = None,
    triage_enabled: bool = True,
    triage_endpoint_consent: bool = False,
) -> EvidenceBundle:
    if yara_stage is None:
        yara_stage = _stage(
            "yara",
            "skipped",
            "Disabled by PCAP_YARA_ENABLED; enable only with reviewed local .yar/.yara rules and TShark/YARA installed.",
        )
    evidence: list[Evidence] = []
    flow_evidence: dict[tuple[int | str, str, int | None, str, int | None], str] = {}
    dns_evidence: list[tuple[_DnsRecord, str]] = []
    arp_evidence: list[tuple[_ArpConflictRecord, str]] = []
    evidence_cap_hit = False
    zeek_evidence_cap_hit = False
    yara_evidence_cap_hit = False
    yara_evidence_ids: list[str] = []
    yara_ev_by_sha: dict[str, str] = {}
    retained_zeek_rows: list[tuple[NormalizedZeekRow, str]] = []

    # 1. Include conflicting/high-activity ARP IP->MAC claims first (never buried below huge flows)
    arp_candidates = [
        _ArpConflictRecord(
            ip=ip,
            macs=sorted(macs),
            packet_refs=accumulator.arp_ip_refs.get(ip, [1])[:MAX_PACKET_REFS],
            reply_count=accumulator.arp_ip_replies.get(ip, 1),
        )
        for ip, macs in sorted(accumulator.arp_ip_macs.items())
        if len(macs) > 1 or accumulator.arp_ip_replies.get(ip, 0) >= 15
    ]
    for arp_rec in arp_candidates[:MAX_ARP_RECORDS]:
        if len(evidence) >= MAX_EVIDENCE:
            evidence_cap_hit = True
            break
        evidence_id = f"EV-{len(evidence) + 1:06d}"
        conflict_count = max(0, len(arp_rec.macs) - 1)
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                kind="arp",
                summary=f"ARP mapping IP {arp_rec.ip} seen from {len(arp_rec.macs)} MAC(s) ({arp_rec.reply_count} replies)",
                packet_refs=[r for r in arp_rec.packet_refs if r > 0] or [1],
                attributes={
                    "protocol": "ARP",
                    "src": arp_rec.ip,
                    "dst": arp_rec.macs[0] if arp_rec.macs else "broadcast",
                    "arp_conflicts": conflict_count,
                    "arp_replies": arp_rec.reply_count,
                    "packets": arp_rec.reply_count,
                },
            )
        )
        arp_evidence.append((arp_rec, evidence_id))

    # 1b. Neutral ARP scan discovery candidates (Who-Has sweeps across distinct targets)
    for scanner, targets in sorted(accumulator.arp_scan_targets.items()):
        if len(targets) < 5:
            continue
        if len(evidence) >= MAX_EVIDENCE:
            evidence_cap_hit = True
            break
        evidence_id = f"EV-{len(evidence) + 1:06d}"
        req_count = accumulator.arp_scan_req_count.get(scanner, len(targets))
        refs = [r for r in accumulator.arp_scan_refs.get(scanner, [1]) if r > 0][:MAX_PACKET_REFS] or [1]
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                kind="arp",
                summary=f"ARP requests from {scanner} queried {len(targets)} target IPs ({req_count} requests)",
                packet_refs=refs,
                attributes={
                    "protocol": "ARP",
                    "src": scanner,
                    "dst": "Broadcast",
                    "arp_opcode": 1,
                    "arp_scan_targets": len(targets),
                    "arp_replies": 0,
                    "packets": req_count,
                },
            )
        )

    # 2. Flows (prioritize high-signal & active flows when streaming huge captures)
    flow_iter = (
        sorted(accumulator.flows.values(), key=_flow_priority_for_bundle)
        if accumulator.streaming_eviction
        else sorted(accumulator.flows.values(), key=_flow_sort_key)
    )
    for flow in flow_iter:
        if len(evidence) >= MAX_EVIDENCE:
            evidence_cap_hit = True
            break
        evidence_id = f"EV-{len(evidence) + 1:06d}"
        if flow.proto == "WLAN":
            ev_kind = "wlan"
        elif flow.proto == 1:
            ev_kind = "icmp"
        elif flow.http_methods or flow.http_status_codes:
            ev_kind = "http"
        else:
            ev_kind = "flow"
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                kind=ev_kind,
                summary=f"{_proto_name(flow.proto)} flow {flow.src} to {flow.dst}",
                packet_refs=flow.refs[:MAX_PACKET_REFS],
                attributes=_flow_attributes(flow, accumulator),
            )
        )
        flow_evidence[flow.key] = evidence_id

    # 3. DNS records
    for record in accumulator.dns_records:
        if len(evidence) >= MAX_EVIDENCE:
            evidence_cap_hit = True
            break
        evidence_id = f"EV-{len(evidence) + 1:06d}"
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                kind="dns",
                summary=f"DNS query {record.query}",
                packet_refs=[record.frame] if record.frame > 0 else [],
                attributes=_dns_attributes(record),
            )
        )
        dns_evidence.append((record, evidence_id))

    # 4. Allowlisted Zeek protocol metadata, with provenance embedded in attrs.
    for record in zeek_records:
        if len(evidence) >= MAX_EVIDENCE:
            evidence_cap_hit = True
            zeek_evidence_cap_hit = True
            break
        evidence_id = f"EV-{len(evidence) + 1:06d}"
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                kind="zeek",
                summary=record.summary,
                packet_refs=[],
                attributes=dict(record.attributes),
            )
        )
        retained_zeek_rows.append((record, evidence_id))
    if zeek_evidence_cap_hit and zeek_stage.state == "completed":
        zeek_stage = zeek_stage.model_copy(
            update={
                "state": "partial",
                "detail": "Zeek rows were normalized, but the global evidence cap prevented retaining every row.",
            }
        )

    # 5. YARA contributes only local rule IDs and hashes of temporary HTTP objects.
    for record in yara_records:
        if len(evidence) >= MAX_EVIDENCE:
            evidence_cap_hit = True
            yara_evidence_cap_hit = True
            break
        evidence_id = f"EV-{len(evidence) + 1:06d}"
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                kind="yara",
                summary=(
                    f"YARA rule {record.rule_id} matched a temporary HTTP object "
                    f"({record.object_size_bytes} bytes; SHA-256 {record.object_sha256[:16]}…)."
                ),
                packet_refs=[],
                attributes={
                    "protocol": "HTTP",
                    "match_count": 1,
                    "rule_id": record.rule_id,
                    "ruleset_sha256": record.ruleset_sha256,
                    "artifact_sha256": record.object_sha256,
                    "object_size_bytes": record.object_size_bytes,
                    "object_index": record.object_index,
                },
            )
        )
        yara_evidence_ids.append(evidence_id)
        yara_ev_by_sha.setdefault(record.object_sha256, evidence_id)
    if yara_evidence_cap_hit and yara_stage.state == "completed":
        yara_stage = yara_stage.model_copy(
            update={
                "state": "partial",
                "detail": "YARA matches were normalized, but the global evidence cap prevented retaining every match.",
            }
        )

    tls_fingerprint_count = 0
    tls_evidence_cap_hit = False
    ja3_threat_matches: list[tuple[str, str, str]] = []
    tls_observations = [
        TLSCertificateObservation(
            evidence_id=evidence_id,
            source_log=record.log_name,
            attributes=record.attributes,
        )
        for record, evidence_id in retained_zeek_rows
    ]
    for record, source_evidence_id in retained_zeek_rows:
        for fingerprint in fingerprints_from_zeek_attributes(record.attributes):
            if tls_fingerprint_count >= MAX_TLS_FINGERPRINT_EVIDENCE or len(evidence) >= MAX_EVIDENCE:
                tls_evidence_cap_hit = True
                evidence_cap_hit = True
                break
            fingerprint_evidence_id = f"EV-{len(evidence) + 1:06d}"
            metadata = {
                "protocol": "TLS",
                "fingerprint_kind": fingerprint.kind,
                **fingerprint.to_metadata(),
                "source_log": record.log_name,
                "source_row": record.source_row,
                "source_evidence_id": source_evidence_id,
            }
            if fingerprint.kind == "ja3":
                threat_profile = match_known_ja3_threat(fingerprint.digest)
                if threat_profile:
                    metadata["ja3_malicious_match"] = True
                    ja3_threat_matches.append((fingerprint_evidence_id, fingerprint.digest, threat_profile))
            evidence.append(
                Evidence(
                    evidence_id=fingerprint_evidence_id,
                    kind="tls",
                    summary=(
                        f"Validated Zeek {fingerprint.kind.upper()} TLS fingerprint metadata "
                        f"from {record.log_name} row {record.source_row}."
                    ),
                    packet_refs=[],
                    attributes=metadata,
                )
            )
            tls_fingerprint_count += 1
        if tls_evidence_cap_hit:
            break

    # Cross-link Zeek rows (conn.log, dns.log, ssl.log, x509.log) with TShark flow/dns/tls rows
    if retained_zeek_rows:
        correlate_zeek_and_tshark_evidence(evidence)

    tls_analysis = analyze_tls_certificate_metadata(tls_observations)
    tls_cap_hit = tls_analysis.truncated or tls_evidence_cap_hit
    tls_detail = (
        f"Offline TLS metadata analysis evaluated {tls_analysis.records_examined} retained Zeek rows; "
        f"retained {tls_fingerprint_count} validated JA3/JA3S fingerprints and "
        f"{len(tls_analysis.candidates)} low-confidence certificate metadata candidates. "
        "No certificate bytes, issuer reputation, or network lookups are used."
    )
    if not retained_zeek_rows and zeek_stage.state in {"skipped", "unavailable", "failed"}:
        tls_stage = _stage("TLS ANALYTICS", zeek_stage.state, f"Requires Zeek TLS/X.509 logs; {zeek_stage.detail}")
    else:
        tls_stage = _stage("TLS ANALYTICS", "partial" if tls_cap_hit or zeek_stage.state == "partial" else "completed", tls_detail)

    if evidence_cap_hit:
        accumulator.warn("Evidence cap reached; additional normalized flow/DNS/Zeek/YARA evidence was not retained.")
    if zeek_stage.state == "partial":
        accumulator.warn("Zeek stage coverage is partial; inspect the Zeek stage detail and configured bounds.")
    if yara_stage.state == "partial":
        accumulator.warn("YARA stage coverage is partial; inspect the stage detail and configured bounds.")
    if tls_stage.state == "partial":
        accumulator.warn("TLS metadata analysis coverage is partial; inspect the Zeek/TLS stage detail and configured caps.")
    if accumulator.flow_evictions > 0:
        accumulator.warn(
            f"Streaming flow table evicted {accumulator.flow_evictions} low-signal ephemeral flows to maintain bounded RAM."
        )

    findings = _detect_findings(accumulator, flow_evidence, dns_evidence, arp_evidence)

    # Evaluate Zeek dns.log answers/TTLs for fast-flux and per-origin NXDOMAIN ratio
    zeek_dns_obs: list[DNSObservation] = []
    for record, zeek_ev_id in retained_zeek_rows:
        if record.log_name != "dns.log":
            continue
        q = str(record.attributes.get("query") or "")
        if not q:
            continue
        ans_raw = str(record.attributes.get("dns_answers") or "")
        answers = tuple(a.strip() for a in ans_raw.split(",") if a.strip()) if ans_raw else ()
        min_ttl_raw = record.attributes.get("dns_ttl_min")
        min_ttl = int(min_ttl_raw) if isinstance(min_ttl_raw, int) and not isinstance(min_ttl_raw, bool) else None
        rcode_raw = record.attributes.get("rcode")
        rcode = int(rcode_raw) if isinstance(rcode_raw, int) and not isinstance(rcode_raw, bool) else None
        src_str = str(record.attributes.get("src") or "") or None
        zeek_dns_obs.append(
            DNSObservation(
                query=q,
                evidence_id=zeek_ev_id,
                source=src_str,
                response_code=rcode,
                answers=answers,
                min_ttl=min_ttl,
            )
        )
    if zeek_dns_obs:
        zeek_dns_res = analyze_dns_candidates(zeek_dns_obs)
        existing_det_ev = {(f.detector, tuple(f.evidence_ids)) for f in findings}
        for candidate in zeek_dns_res.candidates:
            if (candidate.detector, candidate.evidence_ids) not in existing_det_ev:
                _finding(
                    findings,
                    detector=candidate.detector,
                    title=candidate.title,
                    severity="medium" if candidate.detector == "dns_fast_flux_heuristic" else "low",
                    confidence="low",
                    summary=candidate.summary,
                    evidence_ids=list(candidate.evidence_ids),
                    limitations=list(candidate.limitations),
                )

    for candidate in tls_analysis.candidates:
        _finding(
            findings,
            detector=candidate.detector,
            title=candidate.title,
            severity="low",
            confidence=candidate.confidence,
            summary=candidate.summary,
            evidence_ids=list(candidate.evidence_ids),
            limitations=list(candidate.limitations),
        )
    for fp_ev_id, _digest, profile_label in ja3_threat_matches:
        _finding(
            findings,
            detector="tls_ja3_known_signature",
            title="JA3 client fingerprint matches known threat profile",
            severity="medium",
            confidence="low",
            summary=f"Retained Zeek TLS ClientHello JA3 digest matched local signature profile ({profile_label}).",
            evidence_ids=[fp_ev_id],
            limitations=[
                "JA3 digests fingerprint TLS client stacks and can be shared by benign HTTP libraries or OS runtimes.",
                "Corroborate with destination IP/SNI, certificate metadata, and periodic beacon timing before escalation.",
            ],
        )
    dns_analytics_partial = accumulator.dns_velocity_cap_hit or accumulator.dns_analysis_cap_hit
    dns_analysis_stage = _stage(
        "DNS ANALYTICS",
        "partial" if dns_analytics_partial else "completed",
        (
            "Offline DNS heuristic analysis reached a configured record/domain/source-window cap; "
            "some groups were not evaluated."
            if dns_analytics_partial
            else f"Offline DNS analysis evaluated {len(dns_evidence)} retained records for NXDOMAIN, DGA-like label, tunneling-pattern, and fixed {DNS_QUERY_VELOCITY_WINDOW_SECONDS}-second query-rate candidates; no network lookups were performed."
        ),
    )
    if accumulator.dns_velocity_cap_hit:
        accumulator.warn("DNS query-rate analysis reached its source/window group cap; some groups were not evaluated.")
    if accumulator.dns_analysis_cap_hit:
        accumulator.warn("DNS DGA/tunneling analysis reached its bounded record/group/candidate cap; some groups were not evaluated.")
    beacon_stage = _stage(
        "BEACON ANALYTICS",
        "partial" if accumulator.beacon_analysis_cap_hit else "completed",
        (
            "Offline beacon timing analysis reached an observation/timestamp cap; some retained flow samples were not evaluated."
            if accumulator.beacon_analysis_cap_hit
            else f"Offline interval/jitter analysis evaluated {accumulator.beacon_observations_examined} retained flow samples; candidates are low-confidence and do not establish C2 activity."
        ),
    )
    for evidence_id in yara_evidence_ids:
        _finding(
            findings,
            detector="yara_rule_match",
            title="YARA rule matched a carved HTTP object",
            severity="medium",
            confidence="medium",
            summary="An operator-managed local YARA rule matched a temporary carved HTTP object.",
            evidence_ids=[evidence_id],
            limitations=[
                "YARA match is a rule-based indicator and requires analyst validation against rule quality and surrounding traffic.",
                "The original object bytes are intentionally not retained as evidence or included in AI context.",
            ],
        )
    if evidence_cap_hit or accumulator.stream_limited:
        parser_state = "partial"

    warnings = list(accumulator.warnings)
    if accumulator.packet_limit > 0 and accumulator.rows_seen > accumulator.packet_limit:
        warnings.append(
            "Packet cap reached; packets_seen is capped at packet_limit+1 and is not the full capture count."
        )
    if parser_name == "wireshark-csv-offline":
        warnings.append("Analyzed exported Wireshark CSV/TSV columns offline; full binary packet payloads were not inspected.")
    else:
        warnings.append("Full capture coverage is not claimed; only bounded TShark field output was analyzed.")
    deduped_warnings: list[str] = []
    for warning in warnings:
        if warning not in deduped_warnings and len(deduped_warnings) < 100:
            deduped_warnings.append(warning)

    osint_stage = (
        _stage(
            "osint",
            "awaiting_consent",
            "Provider panel is available; no external lookup is sent during parsing. Select indicators/providers and confirm each operation in Reports.",
        )
        if osint_enabled
        else _stage("osint", "skipped", "OSINT provider capability is disabled by PCAP_OSINT_ENABLED=0.")
    )
    stages = [
        _stage("tshark", parser_state, parser_detail),
        dns_analysis_stage,
        zeek_stage,
        beacon_stage,
        tls_stage,
        yara_stage,
        osint_stage,
    ]
    packets_seen = (
        accumulator.rows_seen
        if accumulator.packet_limit <= 0
        else min(accumulator.rows_seen, accumulator.packet_limit + 1)
    )
    packets_analyzed = (
        accumulator.rows_analyzed
        if accumulator.packet_limit <= 0
        else min(accumulator.rows_analyzed, accumulator.packet_limit)
    )
    coverage = Coverage(
        packets_seen=packets_seen,
        packets_analyzed=packets_analyzed,
        truncated=bool(
            (accumulator.packet_limit > 0 and accumulator.rows_seen > accumulator.packet_limit)
            or accumulator.stream_limited
            or accumulator.flow_cap_hit
            or accumulator.dns_cap_hit
            or accumulator.dns_analysis_cap_hit
            or accumulator.dns_velocity_cap_hit
            or accumulator.beacon_analysis_cap_hit
            or evidence_cap_hit
            or zeek_stage.state == "partial"
            or tls_stage.state == "partial"
            or yara_stage.state == "partial"
        ),
        parser=parser_name,
        warnings=deduped_warnings,
        stages=stages,
    )

    duration_s = 0.0
    if accumulator.first_epoch is not None and accumulator.last_epoch is not None:
        duration_s = max(0.0, accumulator.last_epoch - accumulator.first_epoch)

    # Link sample packets to matching Evidence IDs by packet_ref (sorted chronologically by frame no.)
    ref_to_ev: dict[int, str] = {}
    for ev in evidence:
        for ref in ev.packet_refs:
            ref_to_ev.setdefault(ref, ev.evidence_id)
    sorted_samples = sorted(accumulator.sample_packets[:MAX_SAMPLE_PACKETS], key=lambda sp: sp.no)
    linked_samples: list[SamplePacket] = []
    for sp in sorted_samples:
        ev_id = ref_to_ev.get(sp.no)
        linked_samples.append(
            sp.model_copy(update={"evidence_id": ev_id}) if ev_id else sp
        )

    telemetry = CaptureMetrics(
        duration_seconds=round(duration_s, 3),
        start_epoch=accumulator.first_epoch,
        end_epoch=accumulator.last_epoch,
        total_bytes=accumulator.total_bytes,
        protocol_counts=dict(sorted(accumulator.protocol_counts.items(), key=lambda kv: -kv[1])[:40]),
        timeline=_build_timeline(accumulator),
        sample_packets=linked_samples,
    )

    triage_summary: Tier1Summary | None = None
    if triage_enabled and evidence:
        temp_bundle = type("_TempBundle", (), {"evidence": evidence, "findings": findings})()
        triage_report = classify_bundle(temp_bundle, triage_cfg, allow_network=triage_endpoint_consent)
        dec_by_ev = {d.evidence_id: d for d in triage_report.decisions}
        enriched_findings: list[Finding] = []
        for f in findings:
            decs = [dec_by_ev[eid] for eid in f.evidence_ids if eid in dec_by_ev]
            if decs:
                top_dec = max(decs, key=lambda d: d.confidence)
                enriched_findings.append(
                    f.model_copy(
                        update={
                            "triage_class": top_dec.predicted_class,
                            "triage_confidence": top_dec.confidence,
                        }
                    )
                )
            else:
                enriched_findings.append(f)
        findings = enriched_findings
        linked_samples = [
            sp.model_copy(
                update={
                    "triage_label": dec_by_ev[sp.evidence_id].predicted_class
                    if sp.evidence_id and sp.evidence_id in dec_by_ev
                    else sp.triage_label
                }
            )
            for sp in linked_samples
        ]
        telemetry = telemetry.model_copy(update={"sample_packets": linked_samples})
        triage_summary = Tier1Summary(
            enabled=triage_report.enabled,
            model=triage_report.model,
            mode=triage_report.mode,
            total_evaluated=triage_report.total_evaluated,
            benign_filtered=triage_report.benign_filtered,
            escalated_count=triage_report.escalated_count,
            uncertain_count=triage_report.uncertain_count,
            reduction_ratio=round(triage_report.reduction_ratio, 4),
            mean_confidence=round(triage_report.mean_confidence, 4),
            mean_ppl=round(triage_report.mean_ppl, 4),
            etbert_scored_count=getattr(triage_report, "etbert_scored_count", 0),
            etbert_backend=getattr(triage_report, "etbert_backend", None),
            etbert_device=getattr(triage_report, "etbert_device", None),
            etbert_model=getattr(triage_report, "etbert_model", None),
            etbert_top_classes=[
                Tier1ClassStat(
                    label=item.label,
                    count=item.count,
                    avg_confidence=item.avg_confidence,
                    escalated=item.escalated,
                )
                for item in getattr(triage_report, "etbert_top_classes", [])[:20]
            ],
            top_classes=[
                Tier1ClassStat(
                    label=item.label,
                    count=item.count,
                    avg_confidence=item.avg_confidence,
                    escalated=item.escalated,
                )
                for item in triage_report.top_classes[:30]
            ],
            escalated_evidence_ids=triage_report.escalated_evidence_ids[:500],
        )

    # Build opaque YARA / carved HTTP artifact metadata records (never sent to external AI)
    artifacts_by_sha: dict[str, ArtifactRecord] = {}
    for raw_art in carved_artifacts[:200]:
        sha = str(raw_art.get("sha256") or "")
        if not re.fullmatch(r"[a-f0-9]{64}", sha):
            continue
        artifacts_by_sha[sha] = ArtifactRecord(
            artifact_id=f"ART-{sha[:16]}",
            sha256=sha,
            size_bytes=max(1, int(raw_art.get("size_bytes") or 1)),
            content_type=str(raw_art.get("content_type") or "application/octet-stream")[:120],
            protocol="HTTP",
            object_index=max(1, int(raw_art.get("object_index") or 1)),
            matched_rules=[str(r)[:128] for r in (raw_art.get("matched_rules") or [])][:32],
            evidence_id=yara_ev_by_sha.get(sha),
            header_hex=str(raw_art.get("header_hex") or "")[:64],
        )
    for record in yara_records:
        sha = record.object_sha256
        existing_art = artifacts_by_sha.get(sha)
        if existing_art is None:
            artifacts_by_sha[sha] = ArtifactRecord(
                artifact_id=f"ART-{sha[:16]}",
                sha256=sha,
                size_bytes=max(1, record.object_size_bytes),
                content_type="application/octet-stream",
                protocol="HTTP",
                object_index=max(1, record.object_index),
                matched_rules=[record.rule_id],
                evidence_id=yara_ev_by_sha.get(sha),
                header_hex="",
            )
        elif record.rule_id not in existing_art.matched_rules and len(existing_art.matched_rules) < 32:
            artifacts_by_sha[sha] = existing_art.model_copy(
                update={
                    "matched_rules": [*existing_art.matched_rules, record.rule_id],
                    "evidence_id": existing_art.evidence_id or yara_ev_by_sha.get(sha),
                }
            )
    artifacts_list = list(artifacts_by_sha.values())[:200]

    pkt_lengths = [int(ln) for _, ln, _ in accumulator._time_samples if ln and ln > 0]
    iat_samples: list[float] = []
    for flow in accumulator.flows.values():
        for iv in flow.intervals:
            if math.isfinite(iv) and iv >= 0:
                iat_samples.append(float(iv))
                if len(iat_samples) >= 5000:
                    break
        if len(iat_samples) >= 5000:
            break
    if not iat_samples and accumulator.first_epoch is not None and len(accumulator._time_samples) >= 2:
        sorted_ts = sorted(ts for ts, _, _ in accumulator._time_samples if math.isfinite(ts))
        for prev_ts, cur_ts in zip(sorted_ts, sorted_ts[1:]):
            dt = cur_ts - prev_ts
            if math.isfinite(dt) and dt >= 0:
                iat_samples.append(dt)
                if len(iat_samples) >= 5000:
                    break

    flow_analytics = build_flow_analytics(
        evidence,
        packet_lengths=pkt_lengths or None,
        inter_arrival_seconds=iat_samples or None,
        findings=findings,
        duration_seconds=duration_s,
        total_packets=packets_analyzed,
        total_bytes=accumulator.total_bytes,
    )
    geoip_summary = build_world_map_flows(evidence)
    correlations_list = [item.to_dict() for item in correlate_bundle_findings(evidence, findings)]
    mitre_dict = ATTACKMapper().map_analysis(findings=findings).to_dict()
    ioc_inventory = build_ioc_inventory(evidence, findings)

    try:
        return EvidenceBundle(
            capture_sha256=capture_sha256,
            coverage=coverage,
            evidence=evidence,
            findings=findings,
            triage=triage_summary,
            telemetry=telemetry,
            mitre_attack=mitre_dict,
            correlations=correlations_list,
            artifacts=artifacts_list,
            flow_analytics=flow_analytics,
            geoip=geoip_summary,
            iocs=ioc_inventory,
        )
    except Exception:
        raise PipelineError("INTERNAL_CONTRACT_ERROR", "Parser output failed the evidence contract") from None


def _run_zeek(
    path: Path,
    *,
    limits: _Limits,
    deadline: float,
    is_cancelled: Callable[[], bool],
) -> tuple[Stage, list[NormalizedZeekRow]]:
    zeek = shutil.which("zeek")
    if not zeek:
        return _stage("zeek", "unavailable", "Zeek is not installed; TShark evidence was retained."), []
    zeek_deadline = min(deadline, time.monotonic() + limits.zeek_timeout_seconds)
    if zeek_deadline <= time.monotonic():
        return _stage("zeek", "partial", "No operation time remained for the bounded offline Zeek stage."), []
    records: list[NormalizedZeekRow] = []
    rows_seen = 0
    bytes_read = 0
    parse_truncated = False
    try:
        with tempfile.TemporaryDirectory(prefix="pcapscanner-zeek-") as run_dir:
            output_directory = Path(run_dir)
            process = _spawn(
                [zeek, "-r", str(path)],
                limits=limits,
                cwd=run_dir,
                memory_mb=limits.zeek_memory_mb,
                timeout_seconds=limits.zeek_timeout_seconds,
                file_size_limit_bytes=limits.zeek_max_output_bytes,
            )
            try:
                result = _drain_command(
                    process,
                    deadline=zeek_deadline,
                    is_cancelled=is_cancelled,
                    output_budget_bytes=MAX_ZEEK_DIAGNOSTIC_BYTES,
                    output_directory=output_directory,
                    disk_budget_bytes=limits.zeek_max_output_bytes,
                )
            finally:
                if process.poll() is None:
                    _terminate_tree(process)
                _close_streams(process)
            records, rows_seen, bytes_read, parse_truncated = parse_zeek_logs(
                output_directory,
                row_limit=limits.zeek_max_rows,
                byte_limit=limits.zeek_max_output_bytes,
                deadline=zeek_deadline,
                is_cancelled=is_cancelled,
            )
    except PipelineError:
        raise
    except (OSError, ValueError):
        return _stage("zeek", "failed", "Zeek could not be started; TShark evidence was retained."), []

    detail = (
        f"Offline Zeek normalized {len(records)} allowlisted rows (read {rows_seen}; "
        f"limits: {limits.zeek_max_rows} rows, {limits.zeek_max_output_bytes} log bytes, "
        f"{limits.zeek_timeout_seconds}s, {limits.zeek_memory_mb} MiB)."
    )
    if result == "failed" and not records:
        return _stage("zeek", "failed", "Zeek returned an error and no normalized rows; TShark evidence was retained."), []
    if result != "completed" or parse_truncated:
        return _stage("zeek", "partial", detail + " Output or normalization reached a configured bound."), records
    return _stage("zeek", "completed", detail), records


def _run_yara(
    path: Path,
    *,
    limits: _Limits,
    deadline: float,
    is_cancelled: Callable[[], bool],
    carved_artifacts_out: list[dict[str, Any]] | None = None,
) -> tuple[Stage, list[NormalizedYaraMatch]]:
    """Carve bounded HTTP objects and scan them locally; never retain object bytes."""
    if not limits.yara_enabled:
        return _stage(
            "yara",
            "skipped",
            "Disabled by PCAP_YARA_ENABLED; enable only with reviewed local .yar/.yara rules and TShark/YARA installed.",
        ), []
    if limits.yara_rules_dir is None:
        return _stage(
            "yara",
            "unavailable",
            "YARA is enabled but PCAP_YARA_RULES_DIR does not point to an operator rules directory.",
        ), []
    tshark = shutil.which("tshark")
    yara = shutil.which("yara")
    if not tshark or not yara:
        return _stage("yara", "unavailable", "TShark or the YARA CLI is not installed; no objects were scanned."), []

    stage_deadline = min(deadline, time.monotonic() + limits.yara_timeout_seconds)
    if stage_deadline <= time.monotonic():
        return _stage("yara", "partial", "No operation time remained for bounded HTTP carving/YARA."), []

    matches: list[NormalizedYaraMatch] = []
    objects_scanned = 0
    carved_bytes = 0
    partial = False
    carve_state = "failed"
    ruleset: RuleSnapshot | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="pcapscanner-yara-") as run_dir_text:
            run_dir = Path(run_dir_text)
            objects_dir = run_dir / "objects"
            rules_dir = run_dir / "rules"
            objects_dir.mkdir(mode=0o700)
            try:
                ruleset = snapshot_ruleset(
                    limits.yara_rules_dir,
                    rules_dir,
                    max_files=limits.yara_max_rules_files,
                    max_bytes=limits.yara_max_rules_bytes,
                )
            except YaraRulesError as exc:
                default_repo_yara = (Path(__file__).resolve().parents[2] / "yara-rules").resolve()
                bundled_yara = default_rules_dir()
                if (
                    str(exc) == "ruleset_empty"
                    and limits.yara_rules_dir == default_repo_yara
                    and bundled_yara is not None
                ):
                    ruleset = snapshot_ruleset(
                        bundled_yara,
                        rules_dir,
                        max_files=limits.yara_max_rules_files,
                        max_bytes=limits.yara_max_rules_bytes,
                    )
                else:
                    raise

            carve_process = _spawn(
                [tshark, "-n", "-r", str(path), "--export-objects", f"http,{objects_dir}"],
                limits=limits,
                cwd=str(run_dir),
                memory_mb=limits.memory_mb,
                timeout_seconds=max(1, stage_deadline - time.monotonic()),
                file_size_limit_bytes=limits.yara_max_object_bytes,
            )
            try:
                carve_state = _drain_command(
                    carve_process,
                    deadline=stage_deadline,
                    is_cancelled=is_cancelled,
                    output_budget_bytes=MAX_YARA_DIAGNOSTIC_BYTES,
                    output_directory=run_dir,
                    disk_budget_bytes=(
                        limits.yara_max_total_bytes
                        + limits.yara_max_rules_bytes
                        + limits.yara_max_output_bytes
                        + 4 * 1024 * 1024
                    ),
                    output_entry_limit=limits.yara_max_objects + limits.yara_max_rules_files + 16,
                )
            finally:
                if carve_process.poll() is None:
                    _terminate_tree(carve_process)
                _close_streams(carve_process)

            names: list[str] = []
            unsafe_entries = False
            with os.scandir(objects_dir) as entries:
                for entry in entries:
                    if is_cancelled():
                        raise PipelineError("CANCELLED", "Offline parser cancelled")
                    if time.monotonic() >= stage_deadline:
                        partial = True
                        break
                    try:
                        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                            unsafe_entries = True
                            continue
                    except OSError:
                        unsafe_entries = True
                        continue
                    names.append(entry.name)
                    if len(names) > limits.yara_max_objects:
                        partial = True
                        break
            names.sort()
            names = names[: limits.yara_max_objects]
            if unsafe_entries:
                partial = True
            if carve_state == "failed" and not names:
                return _stage("yara", "failed", "TShark HTTP object export failed; TShark and Zeek evidence were retained."), []

            object_meta: dict[int, tuple[str, int]] = {}
            object_headers: dict[int, tuple[str, str]] = {}
            for object_index, original_name in enumerate(names, start=1):
                if is_cancelled():
                    raise PipelineError("CANCELLED", "Offline parser cancelled")
                if time.monotonic() >= stage_deadline:
                    partial = True
                    break
                original = objects_dir / original_name
                safe_path = objects_dir / f"object-{object_index:06d}.bin"
                try:
                    info = original.stat(follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
                        partial = True
                        continue
                    if info.st_size > limits.yara_max_object_bytes or carved_bytes + info.st_size > limits.yara_max_total_bytes:
                        partial = True
                        continue
                    os.replace(original, safe_path)
                    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                    fd = os.open(safe_path, flags)
                    digest = hashlib.sha256()
                    size = 0
                    first_head = b""
                    with os.fdopen(fd, "rb") as object_file:
                        opened = os.fstat(object_file.fileno())
                        if not stat.S_ISREG(opened.st_mode) or opened.st_size != info.st_size:
                            partial = True
                            safe_path.unlink(missing_ok=True)
                            continue
                        while True:
                            if is_cancelled():
                                raise PipelineError("CANCELLED", "Offline parser cancelled")
                            if time.monotonic() >= stage_deadline:
                                partial = True
                                break
                            block = object_file.read(64 * 1024)
                            if not block:
                                break
                            if not first_head:
                                first_head = block[:256]
                            size += len(block)
                            if size > limits.yara_max_object_bytes or carved_bytes + size > limits.yara_max_total_bytes:
                                partial = True
                                break
                            digest.update(block)
                    if partial and time.monotonic() >= stage_deadline:
                        break
                    if size != info.st_size:
                        partial = True
                        safe_path.unlink(missing_ok=True)
                        continue
                    carved_bytes += size
                    object_meta[object_index] = (digest.hexdigest(), size)
                    object_headers[object_index] = (
                        detect_carved_content_type(first_head),
                        first_head[:32].hex(),
                    )
                except PipelineError:
                    raise
                except OSError:
                    partial = True

            objects_scanned = len(object_meta)
            if carve_state != "completed":
                partial = True

            if objects_scanned:
                remaining = stage_deadline - time.monotonic()
                if remaining <= 0:
                    partial = True
                else:
                    result_path = run_dir / "yara-results.txt"
                    scan_list = run_dir / "yara-scan-list.txt"
                    scan_list.write_text(
                        "".join(f"{(objects_dir / f'object-{index:06d}.bin').resolve()}\n" for index in object_meta),
                        encoding="utf-8",
                    )
                    yara_timeout = max(1, min(limits.yara_timeout_seconds, int(math.ceil(remaining))))
                    yara_command = [
                        yara,
                        f"--timeout={yara_timeout}",
                        "--threads=1",
                        "--no-follow-symlinks",
                        "--recursive",
                        f"--max-rules={limits.yara_max_matches + 1}",
                        *(str(rule_path) for rule_path in ruleset.files),
                        "--scan-list", str(scan_list),
                    ]
                    with result_path.open("wb") as result_file:
                        yara_process = _spawn(
                            yara_command,
                            limits=limits,
                            cwd=str(objects_dir),
                            memory_mb=limits.yara_memory_mb,
                            timeout_seconds=min(remaining, float(limits.yara_timeout_seconds)),
                            file_size_limit_bytes=limits.yara_max_output_bytes,
                            stdout_target=result_file,
                            stderr_target=subprocess.DEVNULL,
                        )
                        try:
                            yara_state = _drain_command(
                                yara_process,
                                deadline=stage_deadline,
                                is_cancelled=is_cancelled,
                                output_budget_bytes=limits.yara_max_output_bytes,
                                watched_file=result_path,
                                watched_file_budget_bytes=limits.yara_max_output_bytes,
                            )
                        finally:
                            if yara_process.poll() is None:
                                _terminate_tree(yara_process)
                            _close_streams(yara_process)
                    try:
                        result_bytes = result_path.stat().st_size
                    except OSError:
                        result_bytes = limits.yara_max_output_bytes + 1
                    if result_bytes > limits.yara_max_output_bytes:
                        partial = True
                    elif yara_state == "partial":
                        partial = True
                    elif yara_state == "failed":
                        partial = True

                    valid_objects = {f"object-{index:06d}.bin": (index, *meta) for index, meta in object_meta.items()}
                    parsed_results = 0
                    try:
                        with result_path.open("rb") as result_file:
                            for raw_line in result_file:
                                if is_cancelled():
                                    raise PipelineError("CANCELLED", "Offline parser cancelled")
                                if time.monotonic() >= stage_deadline:
                                    partial = True
                                    break
                                line = raw_line.decode("utf-8", errors="replace").strip()
                                if not line:
                                    continue
                                parts = line.split(maxsplit=1)
                                if len(parts) != 2 or parts[0] not in ruleset.rule_names:
                                    partial = True
                                    continue
                                basename = Path(parts[1]).name
                                meta = valid_objects.get(basename)
                                if meta is None:
                                    partial = True
                                    continue
                                object_index, object_hash, object_size = meta
                                matches.append(
                                    NormalizedYaraMatch(
                                        rule_id=parts[0],
                                        object_index=object_index,
                                        object_sha256=object_hash,
                                        object_size_bytes=object_size,
                                        ruleset_sha256=ruleset.sha256,
                                    )
                                )
                                parsed_results += 1
                                if parsed_results > limits.yara_max_matches:
                                    matches = matches[: limits.yara_max_matches]
                                    partial = True
                                    break
                    except OSError:
                        partial = True
                    if yara_state == "failed" and not matches:
                        return _stage("yara", "failed", "The local YARA scan failed; TShark and Zeek evidence were retained."), []

            if carved_artifacts_out is not None and object_meta:
                matched_by_idx: dict[int, list[str]] = {}
                for m in matches:
                    rules_for_obj = matched_by_idx.setdefault(m.object_index, [])
                    if m.rule_id not in rules_for_obj:
                        rules_for_obj.append(m.rule_id)
                for idx, (obj_sha, obj_size) in sorted(object_meta.items()):
                    ctype, hhex = object_headers.get(idx, ("application/octet-stream", ""))
                    carved_artifacts_out.append(
                        {
                            "object_index": idx,
                            "sha256": obj_sha,
                            "size_bytes": obj_size,
                            "content_type": ctype,
                            "header_hex": hhex,
                            "matched_rules": matched_by_idx.get(idx, []),
                        }
                    )

            detail = (
                f"Offline YARA scanned {objects_scanned} HTTP object(s), retained {len(matches)} rule match(es), "
                f"using the configured operator ruleset; limits: {limits.yara_max_objects} objects, "
                f"{limits.yara_max_total_bytes} object bytes, {limits.yara_max_matches} matches, "
                f"{limits.yara_timeout_seconds}s, {limits.yara_memory_mb} MiB. Raw objects were temporary and are not evidence."
            )
            if partial:
                return _stage("yara", "partial", detail + " One or more configured bounds or parser conditions limited coverage."), matches
            return _stage("yara", "completed", detail), matches
    except PipelineError:
        raise
    except YaraRulesError as exc:
        reason = str(exc)
        if reason == "ruleset_empty":
            return _stage(
                "yara",
                "skipped",
                "YARA is enabled, but no .yar/.yara signatures are present in the configured local rules directory.",
            ), []
        if reason == "rules_directory_unavailable":
            return _stage(
                "yara",
                "unavailable",
                "YARA is enabled, but the configured local rules directory is unavailable.",
            ), []
        return _stage("yara", "failed", "The operator YARA ruleset is invalid, unsafe, or exceeds its configured bounds."), []
    except (OSError, ValueError, subprocess.SubprocessError):
        return _stage("yara", "failed", "HTTP carving or local YARA scanning failed; TShark evidence was retained."), []


_ARP_IS_AT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\s+is at\s+([0-9A-Fa-f:]{11,17})", re.I)
_ARP_WHO_HAS_RE = re.compile(r"Who has\s+((?:\d{1,3}\.){3}\d{1,3})\?\s+Tell\s+((?:\d{1,3}\.){3}\d{1,3})", re.I)
_PORT_PAIR_RE = re.compile(r"(\d{1,5})\s*(?:->|→|>)\s*(\d{1,5})")
_DNS_QUERY_INFO_RE = re.compile(r"Standard query(?:\s+response)?[^A-Za-z0-9]*(?:A|AAAA|TXT|CNAME|PTR|MX|NS)?\s+([A-Za-z0-9._-]+)", re.I)
_HTTP_METHOD_RE = re.compile(r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]{1,160})", re.I)


def _looks_like_wireshark_csv(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(1024).lstrip(b"\xef\xbb\xbf")
    except OSError:
        return False
    # Check it is not binary PCAP/PCAPNG
    if b"\x00" in head or head[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}:
        return False
    text = head.decode("utf-8", errors="ignore").lower()
    first_line = text.splitlines()[0] if text else ""
    has_time = "time" in first_line
    has_src = ("source" in first_line) or ("src" in first_line)
    has_dst = ("destination" in first_line) or ("dst" in first_line)
    return has_time and has_src and has_dst


class _BoundedCSVLines:
    """Binary line source enforcing hard byte budgets while csv.reader consumes a record."""

    def __init__(self, handle: Any) -> None:
        self._handle = handle
        self._record_bytes = 0
        self._first_line = True

    def __iter__(self) -> _BoundedCSVLines:
        return self

    def __next__(self) -> str:
        raw = self._handle.readline(MAX_CSV_PHYSICAL_LINE_BYTES + 1)
        if not raw:
            raise StopIteration
        if len(raw) > MAX_CSV_PHYSICAL_LINE_BYTES:
            raise PipelineError("PARSER_FAILED", "CSV physical-line byte limit exceeded")
        self._record_bytes += len(raw)
        if self._record_bytes > MAX_CSV_RECORD_BYTES:
            raise PipelineError("PARSER_FAILED", "CSV record byte limit exceeded")
        encoding = "utf-8-sig" if self._first_line else "utf-8"
        self._first_line = False
        return raw.decode(encoding, errors="replace")

    def finish_record(self) -> None:
        self._record_bytes = 0


def _analyze_csv_capture(
    path: Path,
    *,
    capture_sha256: str,
    limits: _Limits,
    deadline: float,
    is_cancelled: Callable[[], bool],
    triage_cfg: object | None,
    triage_enabled: bool,
    triage_endpoint_consent: bool,
) -> EvidenceBundle:
    """Stream-parse a Wireshark CSV/TSV export line-by-line with bounded memory."""
    accumulator = _Accumulator(
        packet_limit=limits.packet_limit,
        flow_limit=limits.flow_limit,
        streaming_eviction=limits.streaming_eviction,
    )
    deadline_hit = False
    delimiter = "\t"
    with path.open("rb") as handle:
        first_line = handle.readline(MAX_CSV_PHYSICAL_LINE_BYTES + 1)
        if not first_line:
            raise PipelineError("PARSER_FAILED", "Capture CSV is empty")
        if len(first_line) > MAX_CSV_PHYSICAL_LINE_BYTES:
            raise PipelineError("PARSER_FAILED", "CSV header byte limit exceeded")
        first_line_text = first_line.decode("utf-8-sig", errors="replace")
        delimiter = "\t" if first_line_text.count("\t") >= first_line_text.count(",") else ","
        handle.seek(0)
        bounded_lines = _BoundedCSVLines(handle)
        reader = csv.reader(bounded_lines, delimiter=delimiter, strict=True)
        try:
            header = next(reader, None)
        except csv.Error as exc:
            raise PipelineError("PARSER_FAILED", "Malformed CSV header") from exc
        bounded_lines.finish_record()
        if not header:
            raise PipelineError("PARSER_FAILED", "Capture CSV missing header row")
        if len(header) > MAX_CSV_COLUMNS:
            raise PipelineError("PARSER_FAILED", "CSV column limit exceeded")
        if any(len(value.encode("utf-8", errors="replace")) > MAX_CSV_FIELD_BYTES for value in header):
            raise PipelineError("PARSER_FAILED", "CSV header field byte limit exceeded")
        col_map = {col.strip().lower().rstrip("."): idx for idx, col in enumerate(header)}

        def col(row: list[str], *names: str, default: str = "") -> str:
            for name in names:
                idx = col_map.get(name)
                if idx is not None and idx < len(row):
                    return row[idx].strip()
            return default

        while True:
            try:
                row = next(reader)
            except StopIteration:
                break
            except csv.Error as exc:
                detail = "CSV field byte limit exceeded" if "field larger than field limit" in str(exc).lower() else "Malformed CSV record"
                raise PipelineError("PARSER_FAILED", detail) from exc
            bounded_lines.finish_record()
            if len(row) > MAX_CSV_COLUMNS:
                raise PipelineError("PARSER_FAILED", "CSV column limit exceeded")
            if any(len(value.encode("utf-8", errors="replace")) > MAX_CSV_FIELD_BYTES for value in row):
                raise PipelineError("PARSER_FAILED", "CSV field byte limit exceeded")
            if is_cancelled():
                raise PipelineError("CANCELLED", "Offline parser cancelled")
            if accumulator.rows_seen % 500 == 0 and time.monotonic() >= deadline:
                deadline_hit = True
                accumulator.stream_limited = True
                accumulator.warn("CSV parser deadline exceeded; partial capture evidence returned.")
                break
            if not row:
                continue
            accumulator.rows_seen += 1
            if limits.packet_limit > 0 and accumulator.rows_seen > limits.packet_limit:
                break
            accumulator.rows_analyzed += 1

            frame_no = _parse_int(col(row, "no", "frame", default=str(accumulator.rows_analyzed)), minimum=1) or accumulator.rows_analyzed
            ts = _parse_float(col(row, "time", "time_epoch"))
            src = _safe_text(col(row, "source", "src"), max_length=80)
            dst = _safe_text(col(row, "destination", "dst"), max_length=80)
            proto_raw = _safe_text(col(row, "protocol", "proto"), max_length=24).upper()
            length = _parse_int(col(row, "length", "len"), minimum=0, maximum=1_000_000_000) or 60
            info = _safe_text(col(row, "info"), max_length=320)

            proto_num: int | str | None = None
            src_port: int | None = None
            dst_port: int | None = None
            syn_flag: bool | None = None
            rst_flag: bool | None = None
            dns_query: str | None = None
            dns_rcode: int | None = None
            arp_op: int | None = None
            arp_ip: str | None = None
            arp_mac: str | None = None
            arp_dst_ip: str | None = None
            tls_type: str | None = None
            http_method: str | None = None
            http_uri_len = 0
            http_uri_ent = 0.0
            http_xss_m = False
            http_crlf_m = False
            http_sqli_m = False
            http_shell_m = False
            telnet_cmd_seen = False
            wlan_subtype: int | None = None
            icmp_type: int | None = None
            flagged = False
            info_lower = info.lower()

            port_m = _PORT_PAIR_RE.search(info)
            if port_m:
                src_port = _parse_int(port_m.group(1), minimum=0, maximum=65535)
                dst_port = _parse_int(port_m.group(2), minimum=0, maximum=65535)

            if "ARP" in proto_raw:
                proto_num = 0
                is_at = _ARP_IS_AT_RE.search(info)
                who_has = _ARP_WHO_HAS_RE.search(info)
                if is_at:
                    arp_op = 2
                    arp_ip = _parse_ip(is_at.group(1))
                    arp_mac = is_at.group(2).lower()
                elif who_has:
                    arp_op = 1
                    arp_dst_ip = _parse_ip(who_has.group(1))
                    arp_ip = _parse_ip(who_has.group(2))
                    src = who_has.group(2)
                    dst = who_has.group(1)
                if "duplicate ip" in info_lower or "duplicate use of" in info_lower:
                    flagged = True
            elif "802.11" in proto_raw or "WLAN" in proto_raw or "802.11" in info_lower:
                proto_num = "WLAN"
                if "deauthentication" in info_lower:
                    wlan_subtype = 0x0C
                    flagged = True
                elif "disassociat" in info_lower:
                    wlan_subtype = 0x0A
                    flagged = True
                elif "beacon" in info_lower:
                    wlan_subtype = 0x08
                elif "authentication" in info_lower:
                    wlan_subtype = 0x0B
                elif "probe" in info_lower:
                    wlan_subtype = 0x04
            elif "DNS" in proto_raw or "MDNS" in proto_raw:
                proto_num = 17
                if src_port is None and dst_port is None:
                    dst_port = 53
                dq = _DNS_QUERY_INFO_RE.search(info)
                if dq:
                    dns_query = dq.group(1)
                if "no such name" in info_lower or "nxdomain" in info_lower:
                    dns_rcode = 3
                    flagged = True
            elif "TLS" in proto_raw or "SSL" in proto_raw:
                proto_num = 6
                if "client hello" in info_lower:
                    tls_type = "1"
            elif "HTTP" in proto_raw:
                proto_num = 6
                hm = _HTTP_METHOD_RE.search(info)
                if hm:
                    http_method = hm.group(1).upper()
                    http_uri_len, http_uri_ent, http_xss_m, http_crlf_m, http_sqli_m, http_shell_m, _ = _sanitize_http_markers(
                        hm.group(2), ""
                    )
                    if http_xss_m or http_crlf_m or http_sqli_m or http_shell_m:
                        flagged = True
            elif "TELNET" in proto_raw:
                proto_num = 6
                if src_port is None and dst_port is None:
                    dst_port = 23
                if any(tok in info_lower for tok in ("command", "suboption", "do ", "will ", "wont ", "data")):
                    telnet_cmd_seen = True
            elif "ICMP" in proto_raw:
                proto_num = 1
                icmp_type = 8 if "request" in info_lower else 0
            elif "TCP" in proto_raw:
                proto_num = 6
                if "[SYN]" in info:
                    syn_flag = True
                    accumulator.syn_field_observed = True
                if "[RST" in info:
                    rst_flag = True
                    flagged = True
            elif "UDP" in proto_raw:
                proto_num = 17

            pkt = _Packet(
                frame=frame_no,
                timestamp=ts,
                frame_len=length,
                src=src or "Unknown",
                dst=dst or "Unknown",
                proto=proto_num if proto_num is not None else 6,
                tcp_srcport=src_port if proto_num == 6 else None,
                tcp_dstport=dst_port if proto_num == 6 else None,
                udp_srcport=src_port if proto_num == 17 else None,
                udp_dstport=dst_port if proto_num == 17 else None,
                dns_query=dns_query,
                dns_rcode=dns_rcode,
                tls_type=tls_type,
                tcp_syn=syn_flag,
                arp_opcode=arp_op,
                arp_src_ip=arp_ip,
                arp_src_mac=arp_mac,
                icmp_type=icmp_type,
                tcp_rst=rst_flag,
                http_method=http_method,
                http_uri_len=http_uri_len,
                http_uri_entropy=http_uri_ent,
                http_xss_marker=http_xss_m,
                http_crlf_marker=http_crlf_m,
                http_sqli_marker=http_sqli_m,
                http_shell_marker=http_shell_m,
                telnet_cmd_seen=telnet_cmd_seen,
                wlan_type_subtype=wlan_subtype,
                arp_dst_ip=arp_dst_ip,
                protocol_label=proto_raw or ("WLAN" if proto_num == "WLAN" else "OTHER"),
                info_summary=info,
            )
            accumulator.ingest_packet(pkt, is_flagged_hint=flagged)

    parser_state = "partial" if deadline_hit or (limits.packet_limit > 0 and accumulator.rows_seen > limits.packet_limit) else "completed"
    parser_detail = f"Wireshark CSV/TSV export was parsed incrementally (mode={limits.mode_label}); full binary packet payloads unavailable."
    zeek_stage = _stage("zeek", "skipped", "Zeek offline parsing applies to binary PCAP/PCAPNG captures only.")
    yara_stage = _stage("yara", "skipped", "HTTP object carving/YARA applies to binary PCAP/PCAPNG captures only.")
    return _build_bundle(
        accumulator,
        capture_sha256=capture_sha256,
        parser_state=parser_state,
        parser_detail=parser_detail,
        zeek_stage=zeek_stage,
        osint_enabled=limits.osint_enabled,
        yara_stage=yara_stage,
        parser_name="wireshark-csv-offline",
        triage_cfg=triage_cfg,
        triage_enabled=triage_enabled,
        triage_endpoint_consent=triage_endpoint_consent,
    )


def analyze_capture(
    path: Path,
    capture_sha256: str,
    settings: object,
    is_cancelled: Callable[[], bool] = lambda: False,
    *,
    resource_mode: str | None = None,
    triage_enabled: bool = True,
    triage_endpoint_consent: bool = False,
) -> EvidenceBundle:
    """Analyze a PCAP/PCAPNG or Wireshark CSV/TSV capture offline with bounded memory."""
    if not isinstance(path, Path):
        path = Path(path)
    if not path.is_file():
        raise PipelineError("CAPTURE_NOT_FOUND", "Capture file is not available")
    if not re.fullmatch(r"[a-f0-9]{64}", capture_sha256):
        raise PipelineError("INVALID_CAPTURE_HASH", "Capture hash has an invalid format")
    limits = _get_limits(settings, resource_mode=resource_mode)
    if is_cancelled():
        raise PipelineError("CANCELLED", "Offline parser cancelled")

    triage_cfg = getattr(settings, "triage", None)
    deadline = time.monotonic() + limits.timeout_seconds

    if _looks_like_wireshark_csv(path):
        return _analyze_csv_capture(
            path,
            capture_sha256=capture_sha256,
            limits=limits,
            deadline=deadline,
            is_cancelled=is_cancelled,
            triage_cfg=triage_cfg,
            triage_enabled=triage_enabled,
            triage_endpoint_consent=triage_endpoint_consent,
        )

    tshark = shutil.which("tshark")
    if not tshark:
        raise PipelineError("TSHARK_UNAVAILABLE", "TShark is not installed")

    accumulator = _Accumulator(
        packet_limit=limits.packet_limit,
        flow_limit=limits.flow_limit,
        streaming_eviction=limits.streaming_eviction,
    )
    command = (
        _build_streaming_command(tshark, path, limits)
        if limits.streaming_eviction or limits.packet_limit == 0
        else _build_command(tshark, path, limits.packet_limit)
    )
    process = None
    try:
        process = _spawn(command, limits=limits)
        output_limited, returncode = _stream_tshark(
            process,
            accumulator,
            deadline=deadline,
            is_cancelled=is_cancelled,
            stdout_budget_bytes=limits.stdout_budget_bytes,
        )
    except PipelineError:
        raise
    except (OSError, ValueError):
        raise PipelineError("PARSER_FAILED", "Offline parser failed") from None
    finally:
        if process is not None:
            if process.poll() is None:
                _terminate_tree(process)
            _close_streams(process)

    if returncode not in (0, None) and not output_limited:
        raise PipelineError("PARSER_FAILED", "TShark returned a parser error")
    parser_state = "partial" if output_limited or (limits.packet_limit > 0 and accumulator.rows_seen > limits.packet_limit) else "completed"
    if accumulator.stream_limited or accumulator.malformed_rows or accumulator.flow_cap_hit or accumulator.dns_cap_hit:
        parser_state = "partial"
    parser_detail = (
        f"TShark fields were parsed incrementally with bounded output (mode={limits.mode_label}); full-capture coverage is not claimed."
        if parser_state == "partial"
        else f"TShark fields were parsed incrementally (mode={limits.mode_label}); full-capture coverage is not claimed."
    )

    zeek_records: list[NormalizedZeekRow] = []
    if limits.zeek_enabled:
        zeek_stage, zeek_records = _run_zeek(
            path,
            limits=limits,
            deadline=deadline,
            is_cancelled=is_cancelled,
        )
    else:
        zeek_stage = _stage(
            "zeek",
            "skipped",
            "Disabled by PCAP_ZEEK_ENABLED; set it to 1 to run offline Zeek (requires zeek on PATH).",
        )
    carved_artifacts: list[dict[str, Any]] = []
    yara_stage, yara_records = _run_yara(
        path,
        limits=limits,
        deadline=deadline,
        is_cancelled=is_cancelled,
        carved_artifacts_out=carved_artifacts,
    )
    return _build_bundle(
        accumulator,
        capture_sha256=capture_sha256,
        parser_state=parser_state,
        parser_detail=parser_detail,
        zeek_stage=zeek_stage,
        osint_enabled=limits.osint_enabled,
        zeek_records=zeek_records,
        yara_stage=yara_stage,
        yara_records=yara_records,
        carved_artifacts=carved_artifacts,
        triage_cfg=triage_cfg,
        triage_enabled=triage_enabled,
        triage_endpoint_consent=triage_endpoint_consent,
    )


__all__ = ["FIELD_NAMES", "EXTENDED_FIELD_NAMES", "PipelineError", "analyze_capture"]
