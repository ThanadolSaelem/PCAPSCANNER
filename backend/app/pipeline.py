"""Bounded, offline PCAP analysis using TShark field output.

This module deliberately exports only normalized flow/DNS/TLS metadata.  It never
reads the capture into Python memory, computes the capture hash, or exports packet
payloads, cookies, URLs, or user-agent strings.
"""
from __future__ import annotations

import errno
import ipaddress
import math
import os
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median
from typing import Callable, Iterable, Sequence

from .models import Coverage, Evidence, EvidenceBundle, Finding, Stage


# TShark's fields are an explicit allowlist.  tcp.flags.syn is included because
# the periodic-connection detector must use connection starts, not packet timing.
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

MAX_EVIDENCE = 5000
MAX_PACKET_REFS = 50
MAX_NUMERIC_SERIES = 50
MAX_LINE_BYTES = 64 * 1024
MAX_STDOUT_BYTES = 64 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024
MAX_DNS_RECORDS = MAX_EVIDENCE
TCP_PORT_SPREAD_THRESHOLD = 20
DNS_NXDOMAIN_THRESHOLD = 3
DNS_HIGH_ENTROPY_THRESHOLD = 3.5
DNS_HIGH_ENTROPY_REPEAT_THRESHOLD = 3
PERIODIC_MIN_STARTS = 4
PERIODIC_RELATIVE_TOLERANCE = 0.25


class PipelineError(RuntimeError):
    """Safe, stable parser error; details never include tool stderr or capture data."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class _Limits:
    packet_limit: int
    flow_limit: int
    timeout_seconds: float
    memory_mb: int
    zeek_enabled: bool


@dataclass
class _Packet:
    frame: int
    timestamp: float | None
    frame_len: int | None
    src: str | None
    dst: str | None
    proto: int | None
    tcp_srcport: int | None
    tcp_dstport: int | None
    udp_srcport: int | None
    udp_dstport: int | None
    dns_query: str | None
    dns_rcode: int | None
    tls_type: str | None
    tcp_syn: bool | None


@dataclass
class _DnsRecord:
    frame: int
    timestamp: float | None
    query: str
    rcode: int | None
    src: str | None
    dst: str | None


@dataclass
class _Flow:
    key: tuple[int, str, int | None, str, int | None]
    proto: int
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
    syn_seen: bool = False
    syn_times: list[float] = field(default_factory=list)
    syn_refs: list[int] = field(default_factory=list)


@dataclass
class _Accumulator:
    packet_limit: int
    flow_limit: int
    flows: dict[tuple[int, str, int | None, str, int | None], _Flow] = field(default_factory=dict)
    dns_records: list[_DnsRecord] = field(default_factory=list)
    rows_seen: int = 0
    rows_analyzed: int = 0
    malformed_rows: int = 0
    warnings: list[str] = field(default_factory=list)
    _warning_set: set[str] = field(default_factory=set)
    flow_cap_hit: bool = False
    dns_cap_hit: bool = False
    syn_field_observed: bool = False
    stream_limited: bool = False

    def warn(self, message: str) -> None:
        if message not in self._warning_set and len(self.warnings) < 100:
            self._warning_set.add(message)
            self.warnings.append(message)

    def add_line(self, raw: bytes | str) -> None:
        """Parse one bounded TShark row and update bounded aggregates."""
        self.rows_seen += 1
        if self.rows_seen <= self.packet_limit:
            self.rows_analyzed += 1
        else:
            # -c packet_limit+1 is the coverage sentinel; it is not analyzed.
            return

        parts, had_extra = _split_tshark_row(raw)
        if had_extra:
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
        if parts[15].strip():
            self.syn_field_observed = True

        if packet.src and packet.dst and packet.proto is not None:
            key = (
                packet.proto,
                packet.src,
                _packet_source_port(packet),
                packet.dst,
                _packet_destination_port(packet),
            )
            flow = self.flows.get(key)
            if flow is None:
                if len(self.flows) >= self.flow_limit:
                    if not self.flow_cap_hit:
                        self.warn("Flow aggregation cap reached; additional flows were not retained.")
                    self.flow_cap_hit = True
                    flow = None
                else:
                    flow = _Flow(
                        key=key,
                        proto=packet.proto,
                        src=packet.src,
                        dst=packet.dst,
                        src_port=key[2],
                        dst_port=key[4],
                    )
                    self.flows[key] = flow
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
                    )
                )
            elif not self.dns_cap_hit:
                self.dns_cap_hit = True
                self.warn("DNS evidence cap reached; additional DNS records were not retained.")

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
        if packet.tls_type and packet.tls_type not in flow.tls_types and len(flow.tls_types) < 20:
            flow.tls_types.append(packet.tls_type)

        # Count at most one SYN start per five-tuple.  This excludes repeated SYN
        # packets on a tuple (the common retransmission case) when the field exists.
        if flow.proto == 6 and packet.tcp_syn:
            if not flow.syn_seen:
                flow.syn_seen = True
                if packet.timestamp is not None and len(flow.syn_times) < MAX_NUMERIC_SERIES:
                    flow.syn_times.append(packet.timestamp)
                if packet.frame > 0 and len(flow.syn_refs) < MAX_PACKET_REFS:
                    flow.syn_refs.append(packet.frame)


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
    had_extra = len(columns) > len(FIELD_NAMES)
    if len(columns) < len(FIELD_NAMES):
        columns.extend([""] * (len(FIELD_NAMES) - len(columns)))
    return columns[: len(FIELD_NAMES)], had_extra


def _safe_text(value: str, max_length: int = 253) -> str:
    # TShark field mode is tab-delimited.  Remove control characters before the
    # value reaches a model or a finding, and bound names independently of rows.
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
    proto = _parse_int(parts[11], minimum=0, maximum=255)
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


def _proto_name(proto: int) -> str:
    return {6: "TCP", 17: "UDP"}.get(proto, str(proto))


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


def _setting_int(settings: object, name: str, default: int, *, maximum: int | None = None) -> int:
    value = getattr(settings, name, default)
    if isinstance(value, bool):
        raise PipelineError("INVALID_SETTINGS", f"{name} must be a positive integer")
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise PipelineError("INVALID_SETTINGS", f"{name} must be a positive integer") from None
    if result <= 0:
        raise PipelineError("INVALID_SETTINGS", f"{name} must be a positive integer")
    if maximum is not None and result > maximum:
        return maximum
    return result


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


def _get_limits(settings: object) -> _Limits:
    return _Limits(
        packet_limit=_setting_int(settings, "packet_limit", 20_000, maximum=10_000_000),
        flow_limit=_setting_int(settings, "flow_limit", 5_000, maximum=5_000),
        timeout_seconds=_setting_timeout(settings),
        memory_mb=_setting_int(settings, "parser_memory_mb", 512, maximum=16_384),
        zeek_enabled=bool(getattr(settings, "zeek_enabled", False)),
    )


def _child_limits(memory_mb: int, timeout_seconds: float) -> Callable[[], None]:
    """Return a Linux child setup hook; only used by this synchronous worker."""
    def apply() -> None:
        if os.name != "posix":
            return
        try:
            import resource

            memory = memory_mb * 1024 * 1024
            current_as = resource.getrlimit(resource.RLIMIT_AS)
            as_hard = current_as[1]
            if as_hard != resource.RLIM_INFINITY:
                memory = min(memory, as_hard)
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))

            cpu = max(1, int(math.ceil(timeout_seconds)))
            current_cpu = resource.getrlimit(resource.RLIMIT_CPU)
            cpu_hard = current_cpu[1]
            if cpu_hard != resource.RLIM_INFINITY:
                cpu = min(cpu, cpu_hard)
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        except (ImportError, OSError, ValueError):
            # Wall-clock enforcement in the parent remains authoritative.
            return

    return apply


def _spawn(
    command: Sequence[str],
    *,
    limits: _Limits,
    cwd: str | None = None,
) -> subprocess.Popen[bytes]:
    kwargs: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
        "cwd": cwd,
        "start_new_session": True,
    }
    if os.name == "posix":
        # This function is synchronous and is intended to run in the parser
        # worker.  A pre-exec resource hook avoids an unbounded child; no shell
        # or downloaded script is involved.
        kwargs["preexec_fn"] = _child_limits(limits.memory_mb, limits.timeout_seconds)
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
            # The session leader may already have exited while descendants live.
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
                    # stderr is intentionally drained but never returned or logged.
                    if stderr_bytes > MAX_STDERR_BYTES:
                        accumulator.warn("Parser diagnostics exceeded the bounded stderr drain and were discarded.")
                else:
                    stdout_bytes += len(data)
                    if stdout_bytes > MAX_STDOUT_BYTES:
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
        while streams:
            if is_cancelled():
                _terminate_tree(process)
                raise PipelineError("CANCELLED", "Offline parser cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_tree(process)
                return "partial"
            events = selector.select(timeout=min(0.25, remaining))
            if not events:
                continue
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
                if total > MAX_STDOUT_BYTES:
                    limited = True
                    _terminate_tree(process)
                    streams.clear()
                    break
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


def _flow_attributes(flow: _Flow) -> dict[str, str | int | float | bool]:
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
    if flow.intervals:
        attrs["intervals"] = ",".join(_format_number(value) for value in flow.intervals[:MAX_NUMERIC_SERIES])
    if flow.tls_types:
        attrs["tls_handshake_types"] = ",".join(flow.tls_types[:20])
    return attrs


def _dns_attributes(record: _DnsRecord) -> dict[str, str | int | float | bool]:
    attrs: dict[str, str | int | float | bool] = {"query": record.query}
    if record.rcode is not None:
        attrs["rcode"] = record.rcode
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
            severity="low",
            confidence="low",
            evidence_ids=ids,
            limitations=limitations,
        )
    )


def _detect_findings(
    accumulator: _Accumulator,
    flow_evidence: dict[tuple[int, str, int | None, str, int | None], str],
    dns_evidence: list[tuple[_DnsRecord, str]],
) -> list[Finding]:
    findings: list[Finding] = []

    # Candidate: one source contacts at least 20 distinct TCP destination ports.
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
        if len(ports) < TCP_PORT_SPREAD_THRESHOLD:
            continue
        ids = [evidence_id for port in sorted(ports) for evidence_id in ports[port]]
        _finding(
            findings,
            detector="tcp_destination_port_spread",
            title="One source contacted many distinct TCP destination ports",
            evidence_ids=ids,
            limitations=[
                "Low-confidence threshold heuristic; scanning is not proof of malicious activity.",
                "Only bounded, normalized flow evidence is cited.",
            ],
        )

    # Candidate: repeated NXDOMAINs and/or repeated long high-entropy labels.
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
                evidence_ids=[evidence_id for _, evidence_id in records],
                limitations=[
                    "DNS label entropy is a heuristic and is not evidence of maliciousness.",
                    "NXDOMAIN repetition can be benign and this detector is low confidence.",
                ],
            )

    # Candidate: regular SYN-based connection starts.  A single five-tuple can
    # produce many retransmitted SYN packets, so each flow contributes at most one.
    starts_by_target: dict[tuple[str, str, int | None], list[tuple[float, str]]] = {}
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
                _finding(
                    findings,
                    detector="periodic_tcp_connection_starts",
                    title="Periodic TCP connection starts (candidate beacon)",
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

    if len(findings) >= 1000:
        accumulator.stream_limited = True
        accumulator.warn("Finding cap reached; additional candidates may not be retained.")
    return findings


def _stage(name: str, state: str, detail: str) -> Stage:
    return Stage(name=name, state=state, detail=detail[:500])  # type: ignore[arg-type]


def _build_bundle(
    accumulator: _Accumulator,
    *,
    capture_sha256: str,
    parser_state: str,
    parser_detail: str,
    zeek_stage: Stage,
) -> EvidenceBundle:
    evidence: list[Evidence] = []
    flow_evidence: dict[tuple[int, str, int | None, str, int | None], str] = {}
    dns_evidence: list[tuple[_DnsRecord, str]] = []
    evidence_cap_hit = False

    for flow in sorted(accumulator.flows.values(), key=_flow_sort_key):
        if len(evidence) >= MAX_EVIDENCE:
            evidence_cap_hit = True
            break
        evidence_id = f"EV-{len(evidence) + 1:06d}"
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                kind="flow",
                summary=f"{_proto_name(flow.proto)} flow {flow.src} to {flow.dst}",
                packet_refs=flow.refs[:MAX_PACKET_REFS],
                attributes=_flow_attributes(flow),
            )
        )
        flow_evidence[flow.key] = evidence_id

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

    if evidence_cap_hit:
        accumulator.warn("Evidence cap reached; additional normalized flow/DNS evidence was not retained.")
    findings = _detect_findings(accumulator, flow_evidence, dns_evidence)
    if evidence_cap_hit or accumulator.stream_limited:
        parser_state = "partial"

    warnings = list(accumulator.warnings)
    if accumulator.rows_seen > accumulator.packet_limit:
        warnings.append(
            "Packet cap reached; packets_seen is capped at packet_limit+1 and is not the full capture count."
        )
    warnings.append("Full capture coverage is not claimed; only bounded TShark field output was analyzed.")
    # Preserve the contract's warning bound while keeping order deterministic.
    deduped_warnings: list[str] = []
    for warning in warnings:
        if warning not in deduped_warnings and len(deduped_warnings) < 100:
            deduped_warnings.append(warning)

    stages = [
        _stage("tshark", parser_state, parser_detail),
        zeek_stage,
        _stage("yara", "skipped", "YARA integration is unsupported in this offline parser."),
        _stage("osint", "skipped", "OSINT integration is unsupported and no network lookup was performed."),
    ]
    packets_seen = min(accumulator.rows_seen, accumulator.packet_limit + 1)
    coverage = Coverage(
        packets_seen=packets_seen,
        packets_analyzed=min(accumulator.rows_analyzed, accumulator.packet_limit),
        truncated=accumulator.rows_seen > accumulator.packet_limit or accumulator.stream_limited or accumulator.flow_cap_hit or accumulator.dns_cap_hit or evidence_cap_hit,
        parser="tshark-fields-offline",
        warnings=deduped_warnings,
        stages=stages,
    )
    try:
        return EvidenceBundle(
            capture_sha256=capture_sha256,
            coverage=coverage,
            evidence=evidence,
            findings=findings,
        )
    except Exception:
        # Do not leak a potentially sensitive value or tool diagnostic through an
        # implementation error.  This is an internal contract failure.
        raise PipelineError("INTERNAL_CONTRACT_ERROR", "Parser output failed the evidence contract") from None


def _run_zeek(
    path: Path,
    *,
    limits: _Limits,
    deadline: float,
    is_cancelled: Callable[[], bool],
) -> Stage:
    zeek = shutil.which("zeek")
    if not zeek:
        return _stage("zeek", "unavailable", "Zeek is not installed; TShark evidence was retained.")
    try:
        with tempfile.TemporaryDirectory(prefix="pcapscanner-zeek-") as run_dir:
            # Only Zeek's offline reader and the generated isolated directory are
            # used: no shell, downloaded scripts, or network input.
            process = _spawn([zeek, "-r", str(path)], limits=limits, cwd=run_dir)
            try:
                result = _drain_command(process, deadline=deadline, is_cancelled=is_cancelled)
            finally:
                if process.poll() is None:
                    _terminate_tree(process)
                _close_streams(process)
    except PipelineError:
        raise
    except (OSError, ValueError):
        return _stage("zeek", "failed", "Zeek could not be started; TShark evidence was retained.")
    if result == "completed":
        return _stage("zeek", "completed", "Zeek offline artifact stage completed; protocol output was not normalized into evidence.")
    if result == "partial":
        return _stage("zeek", "partial", "Zeek offline artifact stage exceeded its bounded deadline/output budget; TShark evidence was retained.")
    return _stage("zeek", "failed", "Zeek offline artifact stage failed; TShark evidence was retained.")


def analyze_capture(
    path: Path,
    capture_sha256: str,
    settings: object,
    is_cancelled: Callable[[], bool] = lambda: False,
) -> EvidenceBundle:
    """Analyze a capture synchronously with bounded, offline subprocess parsing.

    ``capture_sha256`` is supplied by the caller and is never recomputed here.
    ``PipelineError`` codes are stable and intentionally do not include paths or
    subprocess stderr.
    """
    if not isinstance(path, Path):
        path = Path(path)
    if not path.is_file():
        raise PipelineError("CAPTURE_NOT_FOUND", "Capture file is not available")
    if not re.fullmatch(r"[a-f0-9]{64}", capture_sha256):
        raise PipelineError("INVALID_CAPTURE_HASH", "Capture hash has an invalid format")
    limits = _get_limits(settings)
    if is_cancelled():
        raise PipelineError("CANCELLED", "Offline parser cancelled")
    tshark = shutil.which("tshark")
    if not tshark:
        raise PipelineError("TSHARK_UNAVAILABLE", "TShark is not installed")

    accumulator = _Accumulator(packet_limit=limits.packet_limit, flow_limit=limits.flow_limit)
    deadline = time.monotonic() + limits.timeout_seconds
    command = _build_command(tshark, path, limits.packet_limit)
    process = None
    try:
        process = _spawn(command, limits=limits)
        output_limited, returncode = _stream_tshark(
            process,
            accumulator,
            deadline=deadline,
            is_cancelled=is_cancelled,
        )
    except PipelineError:
        raise
    except (OSError, ValueError):
        raise PipelineError("PARSER_FAILED", "Offline parser failed") from None
    finally:
        # Real Popen streams are closed here; no full capture or stderr is kept.
        if process is not None:
            if process.poll() is None:
                _terminate_tree(process)
            _close_streams(process)

    if returncode not in (0, None) and not output_limited:
        raise PipelineError("PARSER_FAILED", "TShark returned a parser error")
    parser_state = "partial" if output_limited or accumulator.rows_seen > limits.packet_limit else "completed"
    if accumulator.stream_limited or accumulator.malformed_rows or accumulator.flow_cap_hit or accumulator.dns_cap_hit:
        parser_state = "partial"
    parser_detail = (
        "TShark fields were parsed incrementally with bounded output; full-capture coverage is not claimed."
        if parser_state == "partial"
        else "TShark fields were parsed incrementally; full-capture coverage is not claimed."
    )

    if limits.zeek_enabled:
        zeek_stage = _run_zeek(
            path,
            limits=limits,
            deadline=deadline,
            is_cancelled=is_cancelled,
        )
    else:
        zeek_stage = _stage("zeek", "skipped", "Optional Zeek stage is disabled by settings.")
    return _build_bundle(
        accumulator,
        capture_sha256=capture_sha256,
        parser_state=parser_state,
        parser_detail=parser_detail,
        zeek_stage=zeek_stage,
    )


__all__ = ["FIELD_NAMES", "PipelineError", "analyze_capture"]
