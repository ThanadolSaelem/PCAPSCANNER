"""Host hardware probing and device-adaptive resource planning.

Measures available CPU, RAM (respecting container cgroup limits when present),
disk headroom, and installed offline parsers (`tshark`, `zeek`) so PCAPSCANNER
can adapt upload chunk sizes and streaming parser budgets to the actual device
instead of enforcing rigid tiny static caps.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

ResourceMode = Literal["auto", "fast", "deep", "unlimited", "legacy"]

DEFAULT_MIN_CHUNK_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_CHUNK_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class HostCapabilities:
    cpu_count: int
    host_memory_total_mb: int
    host_memory_available_mb: int
    cgroup_memory_limit_mb: int | None
    effective_memory_mb: int
    disk_total_bytes: int
    disk_free_bytes: int
    tshark_available: bool
    tshark_version: str | None
    zeek_available: bool
    zeek_version: str | None
    yara_available: bool = False
    yara_version: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AdaptiveProfile:
    mode: str
    packet_limit: int  # 0 means unlimited streaming
    flow_limit: int
    parser_memory_mb: int
    timeout_seconds: float
    stdout_budget_bytes: int  # 0 means unlimited line-by-line streaming
    chunk_size_bytes: int
    streaming_eviction: bool
    zeek_enabled: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _read_first_line(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[0].strip()
    except (OSError, IndexError):
        return None


def _probe_cgroup_memory_mb() -> int | None:
    # cgroup v2
    raw = _read_first_line(Path("/sys/fs/cgroup/memory.max"))
    if raw and raw != "max":
        try:
            limit_bytes = int(raw)
            if 0 < limit_bytes < (1 << 58):
                return max(128, limit_bytes // (1024 * 1024))
        except ValueError:
            pass
    # cgroup v1
    raw_v1 = _read_first_line(Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"))
    if raw_v1:
        try:
            limit_bytes = int(raw_v1)
            if 0 < limit_bytes < (1 << 58):
                return max(128, limit_bytes // (1024 * 1024))
        except ValueError:
            pass
    return None


def _probe_macos_memory_mb() -> tuple[int, int]:
    """Query Apple Silicon / Intel macOS total & free/inactive unified memory."""
    total_mb = 0
    avail_mb = 0
    try:
        proc = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=2.0, shell=False)
        if proc.returncode == 0 and proc.stdout.strip().isdigit():
            total_mb = max(512, int(proc.stdout.strip()) // (1024 * 1024))
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        vm = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=2.0, shell=False)
        if vm.returncode == 0 and vm.stdout:
            page_match = re.search(r"page size of (\d+) bytes", vm.stdout)
            page_size = int(page_match.group(1)) if page_match else 16384
            free_pages = 0
            for key in ("Pages free", "Pages inactive", "Pages speculative"):
                m = re.search(rf"{re.escape(key)}:\s+(\d+)\.", vm.stdout)
                if m:
                    free_pages += int(m.group(1))
            if free_pages > 0:
                avail_mb = max(256, (free_pages * page_size) // (1024 * 1024))
    except (OSError, subprocess.SubprocessError):
        pass
    return total_mb, avail_mb


def _probe_memory_mb() -> tuple[int, int]:
    if sys.platform == "darwin":
        mac_total, mac_avail = _probe_macos_memory_mb()
        if mac_total > 0:
            avail = mac_avail if mac_avail > 0 else max(256, mac_total // 2)
            return mac_total, min(avail, mac_total)

    meminfo = Path("/proc/meminfo")
    total_kb = 0
    avail_kb = 0
    if meminfo.is_file():
        try:
            for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        total_kb = int(parts[1])
                elif line.startswith("MemAvailable:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        avail_kb = int(parts[1])
        except OSError:
            pass
    if total_kb <= 0:
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            phys_pages = os.sysconf("SC_PHYS_PAGES")
            if isinstance(page_size, int) and isinstance(phys_pages, int) and page_size > 0 and phys_pages > 0:
                total_kb = (page_size * phys_pages) // 1024
        except (ValueError, OSError, AttributeError):
            pass
    total_mb = max(512, total_kb // 1024) if total_kb > 0 else 2048
    avail_mb = max(256, avail_kb // 1024) if avail_kb > 0 else max(256, total_mb // 2)
    return total_mb, min(avail_mb, total_mb)


def _probe_disk(path: Path) -> tuple[int, int]:
    candidate = path.expanduser().resolve()
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    try:
        usage = shutil.disk_usage(candidate)
        return int(usage.total), int(usage.free)
    except OSError:
        return 0, 0


def _probe_tool_version(binary_name: str) -> tuple[bool, str | None]:
    binary = shutil.which(binary_name)
    if not binary:
        return False, None
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=2.5,
            shell=False,
        )
        first = (proc.stdout or proc.stderr or "").strip().splitlines()
        return True, first[0][:120] if first else "installed"
    except (OSError, subprocess.SubprocessError):
        return True, "installed"


def probe_capabilities(data_dir: Path | str = Path("./data/pcapscanner")) -> HostCapabilities:
    """Measure live hardware, disk space, and available offline parsers."""
    cpu_count = max(1, os.cpu_count() or 1)
    host_total_mb, host_avail_mb = _probe_memory_mb()
    cgroup_mb = _probe_cgroup_memory_mb()
    effective_mb = min(host_total_mb, cgroup_mb) if cgroup_mb is not None else host_total_mb
    effective_avail_mb = min(host_avail_mb, effective_mb)
    disk_total, disk_free = _probe_disk(Path(data_dir))
    tshark_ok, tshark_ver = _probe_tool_version("tshark")
    zeek_ok, zeek_ver = _probe_tool_version("zeek")
    yara_ok, yara_ver = _probe_tool_version("yara")
    return HostCapabilities(
        cpu_count=cpu_count,
        host_memory_total_mb=host_total_mb,
        host_memory_available_mb=effective_avail_mb,
        cgroup_memory_limit_mb=cgroup_mb,
        effective_memory_mb=effective_mb,
        disk_total_bytes=disk_total,
        disk_free_bytes=disk_free,
        tshark_available=tshark_ok,
        tshark_version=tshark_ver,
        zeek_available=zeek_ok,
        zeek_version=zeek_ver,
        yara_available=yara_ok,
        yara_version=yara_ver,
    )


def recommended_chunk_size_bytes(caps: HostCapabilities) -> int:
    """Pick a safe browser chunk size matched to device RAM."""
    if caps.effective_memory_mb >= 12_288:
        return 16 * 1024 * 1024
    if caps.effective_memory_mb >= 4_096:
        return 8 * 1024 * 1024
    if caps.effective_memory_mb >= 1_536:
        return 4 * 1024 * 1024
    return DEFAULT_MIN_CHUNK_BYTES


def resolve_adaptive_profile(
    mode: str,
    caps: HostCapabilities,
    *,
    configured_packet_limit: int = 0,
    configured_flow_limit: int = 0,
    configured_memory_mb: int = 512,
    configured_timeout_seconds: float = 120.0,
    zeek_enabled: bool = False,
) -> AdaptiveProfile:
    """Compute bounded execution budgets scaled dynamically to device resources."""
    normalized = (mode or "auto").strip().lower()
    chunk_bytes = recommended_chunk_size_bytes(caps)

    # Half of effective container/host RAM, clamped sensibly so OS stays responsive
    ram_budget_mb = max(512, min(16_384, int(caps.effective_memory_mb * 0.45)))

    if normalized == "legacy":
        return AdaptiveProfile(
            mode="legacy",
            packet_limit=configured_packet_limit if configured_packet_limit > 0 else 20_000,
            flow_limit=max(1, min(configured_flow_limit or 5_000, 5_000)),
            parser_memory_mb=max(256, min(configured_memory_mb, 16_384)),
            timeout_seconds=max(5.0, float(configured_timeout_seconds)),
            stdout_budget_bytes=64 * 1024 * 1024,
            chunk_size_bytes=chunk_bytes,
            streaming_eviction=False,
            zeek_enabled=zeek_enabled,
        )

    if normalized == "fast":
        return AdaptiveProfile(
            mode="fast",
            packet_limit=100_000,
            flow_limit=5_000,
            parser_memory_mb=max(512, min(ram_budget_mb, 2048)),
            timeout_seconds=max(float(configured_timeout_seconds), 120.0),
            stdout_budget_bytes=128 * 1024 * 1024,
            chunk_size_bytes=chunk_bytes,
            streaming_eviction=True,
            zeek_enabled=zeek_enabled,
        )

    if normalized == "deep":
        pkt_cap = 5_000_000 if caps.effective_memory_mb >= 4_096 else 1_000_000
        flow_cap = 20_000 if caps.effective_memory_mb >= 4_096 else 10_000
        return AdaptiveProfile(
            mode="deep",
            packet_limit=pkt_cap,
            flow_limit=flow_cap,
            parser_memory_mb=max(ram_budget_mb, 1024 if caps.effective_memory_mb >= 2048 else 512),
            timeout_seconds=max(float(configured_timeout_seconds), 600.0),
            stdout_budget_bytes=1024 * 1024 * 1024,
            chunk_size_bytes=chunk_bytes,
            streaming_eviction=True,
            zeek_enabled=zeek_enabled,
        )

    if normalized == "unlimited":
        return AdaptiveProfile(
            mode="unlimited",
            packet_limit=0,  # full capture stream, zero -c frame cutoff
            flow_limit=25_000 if caps.effective_memory_mb >= 4_096 else 10_000,
            parser_memory_mb=max(ram_budget_mb, configured_memory_mb),
            timeout_seconds=max(float(configured_timeout_seconds), 1800.0),
            stdout_budget_bytes=0,  # stream line-by-line without aborting stdout
            chunk_size_bytes=chunk_bytes,
            streaming_eviction=True,
            zeek_enabled=zeek_enabled,
        )

    # Default "auto": scales smoothly with RAM & CPU
    if caps.effective_memory_mb >= 16_384:
        auto_packets = 3_000_000
        auto_flows = 20_000
        auto_stdout = 1024 * 1024 * 1024
        auto_timeout = max(float(configured_timeout_seconds), 600.0)
    elif caps.effective_memory_mb >= 6_144:
        auto_packets = 1_000_000
        auto_flows = 12_000
        auto_stdout = 512 * 1024 * 1024
        auto_timeout = max(float(configured_timeout_seconds), 360.0)
    elif caps.effective_memory_mb >= 2_048:
        auto_packets = 300_000
        auto_flows = 8_000
        auto_stdout = 256 * 1024 * 1024
        auto_timeout = max(float(configured_timeout_seconds), 240.0)
    else:
        auto_packets = 100_000
        auto_flows = 5_000
        auto_stdout = 128 * 1024 * 1024
        auto_timeout = max(float(configured_timeout_seconds), 150.0)

    return AdaptiveProfile(
        mode="auto",
        packet_limit=auto_packets,
        flow_limit=auto_flows,
        parser_memory_mb=max(ram_budget_mb, configured_memory_mb),
        timeout_seconds=auto_timeout,
        stdout_budget_bytes=auto_stdout,
        chunk_size_bytes=chunk_bytes,
        streaming_eviction=True,
        zeek_enabled=zeek_enabled,
    )


def build_capabilities_payload(settings: object) -> dict[str, object]:
    """Serialize host capabilities, active resource settings, and adaptive profiles."""
    data_dir = Path(getattr(settings, "data_dir", "./data/pcapscanner"))
    caps = probe_capabilities(data_dir)
    disk_reserve = int(getattr(settings, "disk_reserve_bytes", 512 * 1024 * 1024))
    storage_max = int(getattr(settings, "storage_max_bytes", 0))
    upload_max = int(getattr(settings, "upload_max_bytes", 0))
    free_headroom = max(0, caps.disk_free_bytes - disk_reserve) if caps.disk_free_bytes > 0 else 0
    if storage_max > 0:
        effective_storage = min(storage_max, free_headroom) if free_headroom > 0 else storage_max
    else:
        effective_storage = free_headroom
    effective_upload = upload_max if upload_max > 0 else effective_storage

    profiles = {
        mode: resolve_adaptive_profile(
            mode,
            caps,
            configured_packet_limit=int(getattr(settings, "packet_limit", 20_000)),
            configured_flow_limit=int(getattr(settings, "flow_limit", 5_000)),
            configured_memory_mb=int(getattr(settings, "parser_memory_mb", 512)),
            configured_timeout_seconds=float(getattr(settings, "parser_timeout_seconds", 120)),
            zeek_enabled=bool(getattr(settings, "zeek_enabled", False)),
        ).to_dict()
        for mode in ("fast", "auto", "deep", "unlimited")
    }
    local_roots = list(getattr(settings, "local_ingest_roots", []) or [])
    try:
        from .picker import detect_picker_backend, is_native_picker_enabled

        native_picker_available = bool(is_native_picker_enabled() and detect_picker_backend() is not None)
    except Exception:
        native_picker_available = False
    resolved_data_dir = str(data_dir.expanduser().resolve())
    triage_cfg = getattr(settings, "triage", None)
    etbert_ckpt_path = getattr(triage_cfg, "etbert_checkpoint_path", None)
    try:
        from .etbert_bridge import inspect_etbert_checkpoint, is_etbert_effectively_enabled

        etbert_ckpt_status = inspect_etbert_checkpoint(etbert_ckpt_path)
        etbert_effective = is_etbert_effectively_enabled(
            triage_cfg, ckpt_ready=bool(etbert_ckpt_status.get("ready"))
        )
    except Exception:
        etbert_ckpt_status = {"configured": bool(etbert_ckpt_path), "ready": False}
        etbert_effective = bool(getattr(triage_cfg, "etbert_enabled", False))
    triage_info = {
        "enabled": bool(getattr(triage_cfg, "enabled", True)),
        "mode": str(getattr(triage_cfg, "mode", "heuristic_calibrated")),
        "model_name": str(getattr(triage_cfg, "model_name", "openjev-cal-tier1")),
        "endpoint_configured": bool(getattr(triage_cfg, "endpoint_url", None)),
        "etbert_enabled": etbert_effective,
        "etbert_endpoint_configured": bool(getattr(triage_cfg, "etbert_endpoint_url", None)),
        "etbert_checkpoint_configured": bool(etbert_ckpt_path),
        "etbert_checkpoint_path": str(etbert_ckpt_path) if etbert_ckpt_path else None,
        "etbert_checkpoint_info": etbert_ckpt_status,
        "etbert_checkpoint_status": etbert_ckpt_status,
        "etbert_model_name": str(getattr(triage_cfg, "etbert_model_name", "etbert-l7-datagram")),
        "high_confidence_threshold": float(getattr(triage_cfg, "high_confidence_threshold", 0.90)),
        "low_confidence_threshold": float(getattr(triage_cfg, "low_confidence_threshold", 0.35)),
        "compact_for_ai": bool(getattr(triage_cfg, "compact_for_ai", True)),
    }
    machine = (platform.machine() or "").lower()
    if sys.platform == "darwin":
        device_hint = "mps" if machine in {"arm64", "aarch64"} else "cpu"
    else:
        device_hint = "cuda_or_cpu"
    return {
        "host": caps.to_dict(),
        "runtime": {
            "platform": sys.platform,
            "machine": machine,
            "device_hint": device_hint,
        },
        "limits": {
            "resource_mode": str(getattr(settings, "resource_mode", "auto")),
            "data_dir": resolved_data_dir,
            "upload_max_bytes": upload_max,  # 0 means unlimited (disk-bounded)
            "storage_max_bytes": storage_max,  # 0 means dynamic free disk headroom
            "disk_reserve_bytes": disk_reserve,
            "effective_upload_max_bytes": effective_upload,
            "effective_storage_max_bytes": effective_storage,
            "unlimited_upload_enabled": upload_max == 0,
            "chunk_size_bytes": recommended_chunk_size_bytes(caps),
            "supported_formats": ["pcap", "pcapng", "cap", "csv", "tsv"],
            "local_ingest_enabled": len(local_roots) > 0,
            "local_ingest_roots": local_roots,
            "native_picker_available": native_picker_available,
            "batch_max_files": int(getattr(settings, "batch_max_files", 8)),
            "batch_max_total_bytes": int(getattr(settings, "batch_max_total_bytes", 2 * 1024 * 1024 * 1024)),
            "batch_admission_concurrency": int(getattr(settings, "batch_admission_concurrency", 2)),
            "zeek_enabled": bool(getattr(settings, "zeek_enabled", False)),
            "osint_enabled": bool(getattr(settings, "osint_enabled", False)),
            "zeek_max_rows": int(getattr(settings, "zeek_max_rows", 2_000)),
            "zeek_max_output_bytes": int(getattr(settings, "zeek_max_output_bytes", 32 * 1024 * 1024)),
            "zeek_timeout_seconds": int(getattr(settings, "zeek_timeout_seconds", 45)),
            "zeek_memory_mb": int(getattr(settings, "zeek_memory_mb", 256)),
            "yara_enabled": bool(getattr(settings, "yara_enabled", False)),
            # This reports only that a path is configured. The network-capable API
            # deliberately cannot inspect the parser's read-only rule mount.
            "yara_rules_configured": bool(getattr(settings, "yara_rules_dir", None)),
            "yara_max_rules_files": int(getattr(settings, "yara_max_rules_files", 64)),
            "yara_max_rules_bytes": int(getattr(settings, "yara_max_rules_bytes", 16 * 1024 * 1024)),
            "yara_max_objects": int(getattr(settings, "yara_max_objects", 100)),
            "yara_max_object_bytes": int(getattr(settings, "yara_max_object_bytes", 16 * 1024 * 1024)),
            "yara_max_total_bytes": int(getattr(settings, "yara_max_total_bytes", 64 * 1024 * 1024)),
            "yara_max_matches": int(getattr(settings, "yara_max_matches", 200)),
            "yara_max_output_bytes": int(getattr(settings, "yara_max_output_bytes", 1024 * 1024)),
            "yara_timeout_seconds": int(getattr(settings, "yara_timeout_seconds", 30)),
            "yara_memory_mb": int(getattr(settings, "yara_memory_mb", 256)),
        },
        "profiles": profiles,
        "triage": triage_info,
    }


__all__ = [
    "AdaptiveProfile",
    "HostCapabilities",
    "ResourceMode",
    "build_capabilities_payload",
    "probe_capabilities",
    "recommended_chunk_size_bytes",
    "resolve_adaptive_profile",
]
