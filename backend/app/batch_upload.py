"""Bounded, offline multipart intake for PCAP batch uploads."""
from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, BinaryIO, Callable

from python_multipart.exceptions import MultipartParseError
from python_multipart.multipart import MultipartParser, parse_options_header
from starlette.requests import Request

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
}
_READ_CHUNK_BYTES = 64 * 1024
_STAGING_WRITE_CHUNK_BYTES = 1024 * 1024
_HEADER_BYTES_PER_PART = 8192
_MULTIPART_FIXED_OVERHEAD_BYTES = 64 * 1024


@dataclass(frozen=True)
class StagedCapture:
    path: Path
    size_bytes: int
    sha256: str
    format: str


class BatchUploadError(Exception):
    def __init__(self, code: str, status: int = 400):
        self.code = code
        self.status = status
        super().__init__(code)


def multipart_body_limit(max_total_bytes: int, max_files: int) -> int:
    """Allow bounded file bytes plus a small fixed header budget per part."""
    return max_total_bytes + max_files * _HEADER_BYTES_PER_PART + _MULTIPART_FIXED_OVERHEAD_BYTES


class _BatchMultipartParser:
    """Stream file parts directly to private staging files under strict caps."""

    def __init__(self, boundary: bytes, staging_dir: Path, *, max_files: int,
                 max_file_bytes: int, max_total_bytes: int, max_body_bytes: int,
                 max_staging_bytes: int, staging_writer: Callable[[BinaryIO, bytes, int], None] | None):
        self.staging_dir = staging_dir
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_body_bytes = max_body_bytes
        self.max_staging_bytes = max_staging_bytes
        self.staging_writer = staging_writer
        self.received_body_bytes = 0
        self.received_file_bytes = 0
        self._header_name = bytearray()
        self._header_value = bytearray()
        self._header_bytes = 0
        self._headers: dict[bytes, bytes] = {}
        self._current: dict | None = None
        self._finished_pending: list[dict] = []
        self._created_paths: list[Path] = []
        self.staged: list[StagedCapture] = []
        self._file_count = 0
        self._ended = False
        callbacks = {
            "on_part_begin": self.on_part_begin,
            "on_part_data": self.on_part_data,
            "on_part_end": self.on_part_end,
            "on_header_field": self.on_header_field,
            "on_header_value": self.on_header_value,
            "on_header_end": self.on_header_end,
            "on_headers_finished": self.on_headers_finished,
            "on_end": self.on_end,
        }
        self.parser = MultipartParser(boundary, callbacks)

    def on_part_begin(self) -> None:
        if self._current is not None:
            raise BatchUploadError("invalid_multipart_body")
        self._headers = {}
        self._header_name.clear()
        self._header_value.clear()
        self._header_bytes = 0

    def on_header_field(self, data: bytes, start: int, end: int) -> None:
        self._header_bytes += end - start
        if self._header_bytes > _HEADER_BYTES_PER_PART:
            raise BatchUploadError("multipart_headers_too_large", 413)
        self._header_name.extend(data[start:end])

    def on_header_value(self, data: bytes, start: int, end: int) -> None:
        self._header_bytes += end - start
        if self._header_bytes > _HEADER_BYTES_PER_PART:
            raise BatchUploadError("multipart_headers_too_large", 413)
        self._header_value.extend(data[start:end])

    def on_header_end(self) -> None:
        name = bytes(self._header_name).strip().lower()
        if not name or name in self._headers:
            raise BatchUploadError("invalid_multipart_headers")
        self._headers[name] = bytes(self._header_value).strip()
        self._header_name.clear()
        self._header_value.clear()

    def on_headers_finished(self) -> None:
        try:
            disposition, options = parse_options_header(self._headers.get(b"content-disposition"))
        except Exception as exc:
            raise BatchUploadError("invalid_multipart_headers") from exc
        if disposition.lower() != b"form-data" or options.get(b"name") != b"files" or b"filename" not in options:
            raise BatchUploadError("batch_files_only")
        filename = options[b"filename"]
        if not filename or any(value < 32 or value == 127 for value in filename):
            raise BatchUploadError("invalid_capture_suffix")
        # Treat the supplied value as an untrusted display hint only; it is never
        # stored, returned, logged, or used to build a filesystem path.
        basename = filename.replace(b"\\", b"/").rsplit(b"/", 1)[-1]
        suffix = basename.rsplit(b".", 1)[-1].lower() if b"." in basename else b""
        if suffix not in {b"pcap", b"pcapng", b"cap"}:
            raise BatchUploadError("invalid_capture_suffix")
        self._file_count += 1
        if self._file_count > self.max_files:
            raise BatchUploadError("batch_file_count_exceeded", 413)
        path = self.staging_dir / (uuid.uuid4().hex + ".upload")
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            handle = os.fdopen(fd, "wb")
        except OSError as exc:
            raise BatchUploadError("batch_staging_unavailable", 507) from exc
        self._created_paths.append(path)
        self._current = {
            "path": path, "handle": handle, "size": 0, "digest": hashlib.sha256(),
            "prefix": bytearray(), "buffer": bytearray(), "complete": False,
        }

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        current = self._current
        if current is None:
            raise BatchUploadError("batch_files_only")
        size = end - start
        if size <= 0:
            return
        if current["size"] + size > self.max_file_bytes:
            raise BatchUploadError("capture_too_large", 413)
        if self.received_file_bytes + size > self.max_total_bytes:
            raise BatchUploadError("batch_total_size_exceeded", 413)
        view = memoryview(data)[start:end]
        current["digest"].update(view)
        if len(current["prefix"]) < 28:
            current["prefix"].extend(view[:28 - len(current["prefix"])])
        current["size"] += size
        self.received_file_bytes += size
        current["buffer"].extend(view)

    def on_part_end(self) -> None:
        current = self._current
        if current is None:
            raise BatchUploadError("invalid_multipart_body")
        prefix = bytes(current["prefix"])
        if len(prefix) < 4 or prefix[:4] not in PCAP_MAGIC:
            raise BatchUploadError("invalid_capture_magic")
        minimum = 28 if prefix[:4] == b"\x0a\x0d\x0d\x0a" else 24
        if current["size"] < minimum:
            raise BatchUploadError("invalid_capture_header")
        current["format"] = "pcapng" if prefix[:4] == b"\x0a\x0d\x0d\x0a" else "pcap"
        current["complete"] = True
        self._finished_pending.append(current)
        self._current = None

    def on_end(self) -> None:
        self._ended = True

    async def _flush(self) -> None:
        states = list(self._finished_pending)
        if self._current is not None:
            states.append(self._current)
        for state in states:
            buffered = state["buffer"]
            if buffered and (len(buffered) >= _STAGING_WRITE_CHUNK_BYTES or state["complete"]):
                data = bytes(buffered)
                buffered.clear()
                if self.staging_writer is None:
                    await asyncio.to_thread(state["handle"].write, data)
                else:
                    await asyncio.to_thread(self.staging_writer, state["handle"], data, self.max_staging_bytes)
        for state in self._finished_pending:
            def sync_and_close(handle):
                handle.flush()
                os.fsync(handle.fileno())
                handle.close()
            await asyncio.to_thread(sync_and_close, state["handle"])
            self.staged.append(StagedCapture(
                path=state["path"], size_bytes=state["size"], sha256=state["digest"].hexdigest(),
                format=state["format"],
            ))
        self._finished_pending.clear()

    async def parse(self, stream: AsyncIterator[bytes]) -> list[StagedCapture]:
        try:
            async for chunk in stream:
                if not isinstance(chunk, bytes):
                    raise BatchUploadError("invalid_multipart_body")
                self.received_body_bytes += len(chunk)
                if self.received_body_bytes > self.max_body_bytes:
                    raise BatchUploadError("batch_request_too_large", 413)
                for offset in range(0, len(chunk), _READ_CHUNK_BYTES):
                    self.parser.write(chunk[offset:offset + _READ_CHUNK_BYTES])
                    await self._flush()
            self.parser.finalize()
            await self._flush()
            if self._current is not None or self._finished_pending or not self._ended:
                raise BatchUploadError("invalid_multipart_body")
            if not self.staged:
                raise BatchUploadError("batch_files_required")
            return list(self.staged)
        except BatchUploadError:
            await self.cleanup()
            raise
        except MultipartParseError as exc:
            await self.cleanup()
            raise BatchUploadError("invalid_multipart_body") from exc
        except OSError as exc:
            await self.cleanup()
            raise BatchUploadError("batch_staging_unavailable", 507) from exc
        except BaseException:
            await self.cleanup()
            raise

    async def cleanup(self) -> None:
        handles: list[BinaryIO] = []
        if self._current is not None:
            handles.append(self._current["handle"])
        handles.extend(item["handle"] for item in self._finished_pending)
        for handle in handles:
            try:
                await asyncio.to_thread(handle.close)
            except Exception:
                pass
        for path in self._created_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        self.staged.clear()
        self._current = None
        self._finished_pending.clear()


async def stage_batch_upload(request: Request, staging_dir: Path, *, max_files: int,
                             max_file_bytes: int, max_total_bytes: int,
                             max_staging_bytes: int | None = None,
                             staging_writer: Callable[[BinaryIO, bytes, int], None] | None = None) -> list[StagedCapture]:
    content_type = request.headers.get("content-type", "")
    try:
        media_type, options = parse_options_header(content_type)
    except Exception as exc:
        raise BatchUploadError("invalid_multipart_content_type", 415) from exc
    if media_type.lower() != b"multipart/form-data":
        raise BatchUploadError("unsupported_batch_content_type", 415)
    boundary = options.get(b"boundary")
    if not boundary or len(boundary) > 70 or any(byte < 33 or byte > 126 for byte in boundary):
        raise BatchUploadError("invalid_multipart_boundary", 400)
    try:
        length = request.headers.get("content-length")
        if length is not None:
            declared = int(length)
            if declared < 0:
                raise ValueError
        else:
            declared = None
    except ValueError as exc:
        raise BatchUploadError("invalid_content_length", 400) from exc
    body_limit = multipart_body_limit(max_total_bytes, max_files)
    if declared is not None and declared > body_limit:
        raise BatchUploadError("batch_request_too_large", 413)
    parser = _BatchMultipartParser(
        boundary, staging_dir, max_files=max_files, max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes, max_body_bytes=body_limit,
        max_staging_bytes=max_staging_bytes if max_staging_bytes is not None else max_total_bytes,
        staging_writer=staging_writer,
    )
    return await parser.parse(request.stream())
