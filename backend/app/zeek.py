"""Bounded normalizer for offline Zeek ASCII and JSONL logs.

Only explicitly allowlisted metadata from conn.log, dns.log, ssl.log, and
x509.log is retained. HTTP paths, payload-like text, certificate subjects,
notices, and all other log families are deliberately ignored.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

MAX_ZEEK_LINE_BYTES = 64 * 1024
MAX_ZEEK_FIELDS = 128
MAX_ZEEK_OUTPUT_ENTRIES = 128
ALLOWED_ZEEK_LOGS = ("conn.log", "dns.log", "ssl.log", "x509.log")


@dataclass(frozen=True)
class NormalizedZeekRow:
    log_name: str
    source_row: int
    summary: str
    attributes: dict[str, str | int | float | bool]


def bounded_directory_size(
    directory: Path,
    byte_limit: int,
    *,
    max_entries: int = MAX_ZEEK_OUTPUT_ENTRIES,
) -> tuple[int, bool]:
    """Return recursive regular-file bytes, stopping at a fixed entry cap.

    Do not follow symlinks. Treat symlinks and special files as unsafe output so
    an exporter cannot hide data outside the monitored tree.
    """
    total = 0
    entries_seen = 0
    pending = [directory]
    try:
        while pending:
            current = pending.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    entries_seen += 1
                    if entries_seen > max_entries:
                        return byte_limit + 1, True
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        return byte_limit + 1, True
                    if stat.S_ISLNK(info.st_mode):
                        return byte_limit + 1, True
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(Path(entry.path))
                    elif stat.S_ISREG(info.st_mode):
                        total += max(0, info.st_size)
                        if total > byte_limit:
                            return total, True
                    else:
                        return byte_limit + 1, True
    except OSError:
        return byte_limit + 1, True
    return total, False


def _raw_text(row: dict[str, object], key: str, limit: int = 512) -> str | None:
    value = row.get(key)
    if isinstance(value, bool) or value is None or isinstance(value, (dict, list, tuple)):
        return None
    text = str(value).strip()
    if not text or text in {"-", "(empty)"}:
        return None
    text = "".join(ch for ch in text if ch.isprintable() and ch not in "\t\r\n")
    return text[:limit] if text else None


def _token(row: dict[str, object], key: str, limit: int = 120) -> str | None:
    text = _raw_text(row, key, limit)
    if text is None or not re.fullmatch(r"[A-Za-z0-9_.:+,-]{1,120}", text):
        return None
    return text


def _domain(row: dict[str, object], key: str) -> str | None:
    text = _raw_text(row, key, 253)
    if text is None or len(text) > 253 or not re.fullmatch(r"[A-Za-z0-9._-]+\.?", text):
        return None
    normalized = text.rstrip(".").lower()
    labels = normalized.split(".")
    if not normalized or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        return None
    return normalized


def _ip(row: dict[str, object], key: str) -> str | None:
    text = _raw_text(row, key, 45)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _integer(row: dict[str, object], key: str, maximum: int = (1 << 60)) -> int | None:
    value = row.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()):
        try:
            result = int(value.strip(), 10)
        except ValueError:
            return None
    else:
        return None
    return result if 0 <= result <= maximum else None


def _number(row: dict[str, object], key: str) -> float | None:
    value = row.get(key)
    if isinstance(value, bool) or value is None or isinstance(value, (dict, list, tuple)):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) and abs(result) <= 1_000_000_000_000 else None


def _boolean(row: dict[str, object], key: str) -> bool | None:
    value = row.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"t", "true", "1", "yes"}:
            return True
        if normalized in {"f", "false", "0", "no"}:
            return False
    return None


def _hex_digest(row: dict[str, object], key: str, lengths: set[int]) -> str | None:
    text = _raw_text(row, key, 128)
    if text is None:
        return None
    normalized = text.lower()
    if len(normalized) not in lengths or not re.fullmatch(r"[a-f0-9]+", normalized):
        return None
    return normalized


def _answer_count(value: object) -> int | None:
    if isinstance(value, (list, tuple)):
        return min(len(value), 100_000)
    if isinstance(value, str) and value not in {"", "-", "(empty)"}:
        return min(value.count(",") + 1, 100_000)
    return None


def _format_endpoint(ip: object, port: object) -> str:
    if not isinstance(ip, str):
        return "unknown"
    if isinstance(port, int):
        host = f"[{ip}]" if ":" in ip else ip
        return f"{host}:{port}"
    return ip


def _normalize_row(log_name: str, source_row: int, row: dict[str, object]) -> NormalizedZeekRow | None:
    attrs: dict[str, str | int | float | bool] = {
        "source_engine": "Zeek",
        "source_log": log_name,
        "source_row": source_row,
    }

    timestamp = _number(row, "ts")
    if timestamp is not None:
        attrs["timestamp_epoch"] = timestamp

    uid = _raw_text(row, "uid", 128)
    if uid is not None:
        attrs["zeek_uid_hash"] = hashlib.sha256(uid.encode("utf-8", errors="replace")).hexdigest()[:16]

    for target, key in (("src", "id.orig_h"), ("dst", "id.resp_h")):
        parsed = _ip(row, key)
        if parsed is not None:
            attrs[target] = parsed
    for target, key in (("src_port", "id.orig_p"), ("dst_port", "id.resp_p")):
        parsed = _integer(row, key, 65535)
        if parsed is not None:
            attrs[target] = parsed

    protocol = _token(row, "proto", 24)
    if protocol is not None:
        attrs["protocol"] = protocol.upper()
    service = _token(row, "service", 120)
    if service is not None:
        attrs["service"] = service.lower()
    state = _token(row, "conn_state", 32)
    if state is not None:
        attrs["connection_state"] = state
    duration = _number(row, "duration")
    if duration is not None and duration >= 0:
        attrs["duration"] = duration

    orig_bytes = _integer(row, "orig_bytes")
    resp_bytes = _integer(row, "resp_bytes")
    if orig_bytes is not None:
        attrs["origin_bytes"] = orig_bytes
    if resp_bytes is not None:
        attrs["response_bytes"] = resp_bytes
    if orig_bytes is not None or resp_bytes is not None:
        attrs["bytes"] = (orig_bytes or 0) + (resp_bytes or 0)

    orig_packets = _integer(row, "orig_pkts")
    resp_packets = _integer(row, "resp_pkts")
    if orig_packets is not None or resp_packets is not None:
        attrs["packets"] = (orig_packets or 0) + (resp_packets or 0)

    if log_name == "dns.log":
        query = _domain(row, "query")
        if query is not None:
            attrs["query"] = query
        for target, key in (("qtype_name", "qtype_name"), ("rcode_name", "rcode_name")):
            value = _token(row, key, 80)
            if value is not None:
                attrs[target] = value
        rcode = _integer(row, "rcode", 65535)
        if rcode is not None:
            attrs["rcode"] = rcode
        answer_count = _answer_count(row.get("answers"))
        if answer_count is not None:
            attrs["dns_answer_count"] = answer_count
        rejected = _boolean(row, "rejected")
        if rejected is not None:
            attrs["dns_rejected"] = rejected

    elif log_name == "ssl.log":
        for target, key in (("tls_version", "version"), ("tls_cipher", "cipher"), ("tls_validation_status", "validation_status")):
            value = _token(row, key, 120)
            if value is not None:
                attrs[target] = value
        server_name = _domain(row, "server_name")
        if server_name is not None:
            attrs["tls_server_name"] = server_name
        for target, key in (("tls_resumed", "resumed"), ("tls_established", "established")):
            value = _boolean(row, key)
            if value is not None:
                attrs[target] = value
        for target, key in (("tls_ja3", "ja3"), ("tls_ja3s", "ja3s")):
            value = _hex_digest(row, key, {32})
            if value is not None:
                attrs[target] = value

    elif log_name == "x509.log":
        for target, key, lengths in (
            ("certificate_sha1", "certificate.fingerprint.sha1", {40}),
            ("certificate_sha256", "certificate.fingerprint.sha256", {64}),
        ):
            value = _hex_digest(row, key, lengths)
            if value is not None:
                attrs[target] = value
        key_type = _token(row, "certificate.key_type", 64)
        if key_type is not None:
            attrs["certificate_key_type"] = key_type
        key_length = _integer(row, "certificate.key_length", 1_000_000)
        if key_length is not None:
            attrs["certificate_key_length"] = key_length
        signature = _token(row, "certificate.sig_alg", 96)
        if signature is not None:
            attrs["certificate_signature_algorithm"] = signature
        cert_version = _integer(row, "certificate.version", 10_000)
        if cert_version is not None:
            attrs["certificate_version"] = cert_version

    summary = f"{_summary(log_name, attrs)} [{log_name} row {source_row}]"
    return NormalizedZeekRow(log_name=log_name, source_row=source_row, summary=summary, attributes=attrs)


def _summary(log_name: str, attrs: dict[str, str | int | float | bool]) -> str:
    if log_name == "dns.log":
        query = str(attrs.get("query", "domain unavailable"))
        qtype = attrs.get("qtype_name")
        return f"Zeek DNS query {query}" + (f" ({qtype})" if qtype else "")
    if log_name == "ssl.log":
        name = attrs.get("tls_server_name", "server name unavailable")
        version = attrs.get("tls_version", "TLS version unavailable")
        return f"Zeek TLS metadata for {name} ({version})"
    if log_name == "x509.log":
        fingerprint = attrs.get("certificate_sha256")
        if isinstance(fingerprint, str):
            return f"Zeek X.509 certificate SHA-256 {fingerprint[:16]}…"
        return "Zeek X.509 certificate metadata"
    source = _format_endpoint(attrs.get("src"), attrs.get("src_port"))
    destination = _format_endpoint(attrs.get("dst"), attrs.get("dst_port"))
    protocol = attrs.get("protocol", "unknown")
    state = attrs.get("connection_state")
    suffix = f" state={state}" if state else ""
    return f"Zeek connection {protocol} {source} → {destination}{suffix}"


def _parse_log_file(
    path: Path,
    *,
    log_name: str,
    row_limit: int,
    byte_limit: int,
    deadline: float | None,
    is_cancelled: Callable[[], bool] | None,
) -> tuple[list[NormalizedZeekRow], int, int, bool]:
    rows: list[NormalizedZeekRow] = []
    data_rows = 0
    bytes_read = 0
    truncated = False
    try:
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            return rows, data_rows, bytes_read, True
        file_size = max(0, info.st_size)
        with path.open("rb") as source:
            fields: list[str] | None = None
            mode: str | None = None
            unset = "-"
            separator_supported = True
            discarding_long_line = False

            while bytes_read < byte_limit:
                if is_cancelled is not None and is_cancelled():
                    from .pipeline import PipelineError

                    raise PipelineError("CANCELLED", "Offline parser cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    truncated = True
                    break
                remaining = byte_limit - bytes_read
                raw = source.readline(min(MAX_ZEEK_LINE_BYTES + 1, remaining))
                if not raw:
                    break
                bytes_read += len(raw)
                if discarding_long_line:
                    if raw.endswith(b"\n"):
                        discarding_long_line = False
                    truncated = True
                    continue
                if len(raw) > MAX_ZEEK_LINE_BYTES:
                    truncated = True
                    discarding_long_line = not raw.endswith(b"\n")
                    data_rows += 1
                    if data_rows >= row_limit:
                        break
                    continue

                text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if not text:
                    continue
                if text.startswith("#separator "):
                    if text != r"#separator \x09":
                        separator_supported = False
                        truncated = True
                        break
                    continue
                if text.startswith("#unset_field "):
                    unset = text.partition(" ")[2][:32]
                    continue
                if text.startswith("#fields\t"):
                    candidate = text.split("\t")[1:]
                    if not candidate or len(candidate) > MAX_ZEEK_FIELDS or any(
                        len(field) > 128 or not re.fullmatch(r"[A-Za-z0-9_.]+", field) for field in candidate
                    ):
                        truncated = True
                        fields = None
                    else:
                        fields = candidate
                        mode = "ascii"
                    continue
                if text.startswith("#"):
                    continue

                if mode is None:
                    mode = "json" if text.lstrip().startswith("{") else "ascii"
                data_rows += 1
                if data_rows > row_limit:
                    truncated = True
                    break

                if mode == "json":
                    try:
                        decoded = json.loads(text)
                    except (json.JSONDecodeError, RecursionError):
                        truncated = True
                        continue
                    if not isinstance(decoded, dict):
                        truncated = True
                        continue
                    row: dict[str, object] = decoded
                else:
                    if not separator_supported or not fields:
                        truncated = True
                        continue
                    values = text.split("\t")
                    if len(values) != len(fields):
                        truncated = True
                        continue
                    row = {
                        name: (None if value == unset or value == "(empty)" else value)
                        for name, value in zip(fields, values)
                    }

                normalized = _normalize_row(log_name, data_rows, row)
                if normalized is not None:
                    rows.append(normalized)

                if data_rows >= row_limit:
                    try:
                        if source.tell() < min(file_size, byte_limit):
                            truncated = True
                    except OSError:
                        truncated = True
                    break

            if file_size > byte_limit or bytes_read >= byte_limit and file_size > bytes_read:
                truncated = True
            if discarding_long_line:
                truncated = True
    except OSError:
        return rows, data_rows, bytes_read, True
    return rows, data_rows, bytes_read, truncated


def parse_zeek_logs(
    directory: Path,
    *,
    row_limit: int,
    byte_limit: int,
    deadline: float | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> tuple[list[NormalizedZeekRow], int, int, bool]:
    """Read only safe Zeek logs within global row, byte, and wall-clock budgets."""
    rows: list[NormalizedZeekRow] = []
    rows_seen = 0
    bytes_read = 0
    truncated = False
    if row_limit < 1 or byte_limit < 1:
        return rows, rows_seen, bytes_read, True

    for log_name in ALLOWED_ZEEK_LOGS:
        if rows_seen >= row_limit:
            truncated = True
            break
        path = directory / log_name
        try:
            info = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            truncated = True
            continue
        if not stat.S_ISREG(info.st_mode):
            truncated = True
            continue
        remaining = byte_limit - bytes_read
        if remaining <= 0:
            truncated = True
            break
        parsed, seen, consumed, partial = _parse_log_file(
            path,
            log_name=log_name,
            row_limit=row_limit - rows_seen,
            byte_limit=remaining,
            deadline=deadline,
            is_cancelled=is_cancelled,
        )
        rows.extend(parsed)
        rows_seen += seen
        bytes_read += consumed
        truncated = truncated or partial
        if info.st_size > remaining:
            truncated = True
        if deadline is not None and time.monotonic() >= deadline:
            truncated = True
            break

    return rows, rows_seen, bytes_read, truncated


__all__ = ["ALLOWED_ZEEK_LOGS", "NormalizedZeekRow", "bounded_directory_size", "parse_zeek_logs"]
