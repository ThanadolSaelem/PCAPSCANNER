"""Safe, offline YARA ruleset snapshotting and metadata-only match contracts."""
from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

_RULE_NAME_RE = re.compile(rb"\b(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]{0,127})\b")
_INCLUDE_RE = re.compile(rb"(?im)^\s*include\s+['\"]")
_SAFE_RULE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,96}\.(?:yar|yara)$", re.IGNORECASE)


class YaraRulesError(ValueError):
    """A ruleset is absent, unsafe, too large, or not a source ruleset."""


@dataclass(frozen=True)
class RuleSnapshot:
    files: tuple[Path, ...]
    sha256: str
    rule_names: frozenset[str]
    rule_count: int
    source_bytes: int


@dataclass(frozen=True)
class NormalizedYaraMatch:
    rule_id: str
    object_index: int
    object_sha256: str
    object_size_bytes: int
    ruleset_sha256: str


def snapshot_ruleset(
    source_dir: Path | str,
    destination: Path,
    *,
    max_files: int,
    max_bytes: int,
) -> RuleSnapshot:
    """Copy a flat, operator-managed source ruleset into private per-analysis storage.

    The snapshot removes source-path and symlink races for the scanner process. Includes
    are rejected so rule compilation cannot read files outside this snapshot.
    """
    source = Path(source_dir).expanduser()
    try:
        source_stat = source.lstat()
    except OSError as exc:
        raise YaraRulesError("rules_directory_unavailable") from exc
    if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISDIR(source_stat.st_mode):
        raise YaraRulesError("rules_directory_unavailable")

    try:
        entries = sorted(os.scandir(source), key=lambda entry: entry.name)
    except OSError as exc:
        raise YaraRulesError("rules_directory_unavailable") from exc

    candidates: list[Path] = []
    for entry in entries:
        suffix = Path(entry.name).suffix.lower()
        if suffix not in {".yar", ".yara"}:
            continue
        if not _SAFE_RULE_FILENAME_RE.fullmatch(entry.name) or entry.is_symlink():
            raise YaraRulesError("rules_filename_invalid")
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError as exc:
            raise YaraRulesError("rules_file_unavailable") from exc
        if not stat.S_ISREG(mode):
            raise YaraRulesError("rules_file_unavailable")
        candidates.append(Path(entry.path))
        if len(candidates) > max_files:
            raise YaraRulesError("rules_file_limit_exceeded")

    if not candidates:
        raise YaraRulesError("ruleset_empty")

    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest = hashlib.sha256()
    names: set[str] = set()
    snapshots: list[Path] = []
    total_bytes = 0
    rule_count = 0

    for index, source_path in enumerate(candidates, start=1):
        try:
            before = source_path.stat(follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > max_bytes:
                raise YaraRulesError("rules_file_limit_exceeded")
            if total_bytes + before.st_size > max_bytes:
                raise YaraRulesError("rules_byte_limit_exceeded")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(source_path, flags)
            with os.fdopen(fd, "rb") as source_file:
                opened = os.fstat(source_file.fileno())
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise YaraRulesError("rules_file_changed")
                content = source_file.read(max_bytes - total_bytes + 1)
                after = os.fstat(source_file.fileno())
            after_path = source_path.stat(follow_symlinks=False)
        except YaraRulesError:
            raise
        except OSError as exc:
            raise YaraRulesError("rules_file_unavailable") from exc

        if (
            len(content) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after_path.st_dev, after_path.st_ino, after_path.st_size, after_path.st_mtime_ns)
        ):
            raise YaraRulesError("rules_file_changed")
        if _INCLUDE_RE.search(content):
            raise YaraRulesError("rules_include_forbidden")

        found_names = [match.decode("ascii") for match in _RULE_NAME_RE.findall(content)]
        if not found_names or len(found_names) > 10_000 or names.intersection(found_names):
            raise YaraRulesError("rules_names_invalid")
        names.update(found_names)
        rule_count += len(found_names)
        total_bytes += len(content)
        digest.update(source_path.name.encode("ascii"))
        digest.update(b"\0")
        digest.update(content)

        snapshot_path = destination / f"rules-{index:04d}.yar"
        try:
            fd = os.open(snapshot_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o400)
            with os.fdopen(fd, "wb") as snapshot_file:
                snapshot_file.write(content)
                snapshot_file.flush()
                os.fsync(snapshot_file.fileno())
            os.chmod(snapshot_path, 0o400)
        except OSError as exc:
            raise YaraRulesError("rules_snapshot_failed") from exc
        snapshots.append(snapshot_path)

    return RuleSnapshot(
        files=tuple(snapshots),
        sha256=digest.hexdigest(),
        rule_names=frozenset(names),
        rule_count=rule_count,
        source_bytes=total_bytes,
    )


def default_rules_dir() -> Path | None:
    """Return bundled offline YARA rules directory (`backend/rules`) if present."""
    candidate = Path(__file__).resolve().parent.parent / "rules"
    if candidate.is_dir():
        return candidate
    return None


def detect_carved_content_type(head: bytes) -> str:
    """Classify a carved HTTP object's content type from magic bytes without executing it."""
    if not head:
        return "application/octet-stream"
    if head.startswith(b"MZ"):
        return "application/x-dosexec"
    if head.startswith(b"\x7fELF"):
        return "application/x-executable"
    if head.startswith(b"PK\x03\x04"):
        return "application/zip"
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return "image/gif"
    if head.startswith(b"\x1f\x8b"):
        return "application/gzip"
    lower = head[:256].lstrip().lower()
    if lower.startswith(b"<!doctype html") or lower.startswith(b"<html") or b"<script" in lower:
        return "text/html"
    if lower.startswith(b"{") or lower.startswith(b"["):
        return "application/json"
    if all(b in b"\t\r\n" or 32 <= b <= 126 for b in head[:128]):
        return "text/plain"
    return "application/octet-stream"


def inspect_yara_rules(
    source_dir: Path | str | None,
    *,
    max_files: int = 64,
    max_bytes: int = 16 * 1024 * 1024,
) -> dict[str, object]:
    """Return safe, metadata-only YARA ruleset status without exposing host paths."""
    candidates_dirs: list[Path] = []
    if source_dir:
        candidates_dirs.append(Path(source_dir).expanduser())
    bundled = default_rules_dir()
    if bundled is not None and bundled not in candidates_dirs:
        candidates_dirs.append(bundled)

    active_dir: Path | None = None
    for d in candidates_dirs:
        try:
            st = d.lstat()
            if not stat.S_ISLNK(st.st_mode) and stat.S_ISDIR(st.st_mode):
                has_yar = any(
                    Path(entry.name).suffix.lower() in {".yar", ".yara"}
                    for entry in os.scandir(d)
                )
                if has_yar:
                    active_dir = d
                    break
        except OSError:
            continue

    if active_dir is None:
        return {
            "configured": bool(source_dir),
            "available": False,
            "rule_file_count": 0,
            "rule_count": 0,
            "source_bytes": 0,
            "ruleset_sha256": None,
            "rule_names": [],
        }

    digest = hashlib.sha256()
    rule_names: list[str] = []
    file_count = 0
    total_bytes = 0
    try:
        for entry in sorted(os.scandir(active_dir), key=lambda e: e.name):
            if Path(entry.name).suffix.lower() not in {".yar", ".yara"}:
                continue
            if not _SAFE_RULE_FILENAME_RE.fullmatch(entry.name) or entry.is_symlink():
                continue
            p = Path(entry.path)
            raw = p.read_bytes()
            if len(raw) <= 0 or total_bytes + len(raw) > max_bytes or _INCLUDE_RE.search(raw):
                continue
            file_count += 1
            if file_count > max_files:
                break
            total_bytes += len(raw)
            digest.update(entry.name.encode("ascii") + b"\0" + raw)
            for match in _RULE_NAME_RE.findall(raw):
                name = match.decode("ascii", errors="ignore")
                if name and name not in rule_names and len(rule_names) < 200:
                    rule_names.append(name)
    except OSError:
        pass

    return {
        "configured": True,
        "available": file_count > 0 and len(rule_names) > 0,
        "rule_file_count": file_count,
        "rule_count": len(rule_names),
        "source_bytes": total_bytes,
        "ruleset_sha256": digest.hexdigest() if file_count > 0 else None,
        "rule_names": sorted(rule_names),
    }
