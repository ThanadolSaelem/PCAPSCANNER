"""Native OS file/folder dialog picker and non-secret workspace configuration.

Enables macOS Finder (`osascript`) and Linux desktop (`zenity`/`kdialog`/`tkinter`)
folder & file selection directly from the local PCAPSCANNER Web UI while failing
closed on remote callers or headless servers and keeping bearer tokens separate
from non-secret workspace metadata.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Literal

PickerPurpose = Literal["data_dir", "capture_root", "capture_file"]

ALLOWED_RESOURCE_MODES = {"auto", "fast", "deep", "unlimited"}
ALLOWED_WORKSPACE_KEYS = {
    "schema_version",
    "data_dir",
    "local_ingest_roots",
    "resource_mode",
    "prefer_workspace",
}
_PURPOSE_PROMPTS: dict[PickerPurpose, str] = {
    "data_dir": "Select PCAPSCANNER Data Directory",
    "capture_root": "Select Local Capture Folder for Zero-Copy Scanning",
    "capture_file": "Select PCAP, PCAPNG, CAP, CSV, or TSV Capture File",
}

_OSASCRIPT_CHOOSE_DIR = (
    "on run argv\n"
    "    set promptText to item 1 of argv\n"
    "    set defaultDir to item 2 of argv\n"
    "    activate\n"
    '    if defaultDir is not "" then\n'
    "        return POSIX path of (choose folder with prompt promptText default location (POSIX file defaultDir))\n"
    "    else\n"
    "        return POSIX path of (choose folder with prompt promptText)\n"
    "    end if\n"
    "end run"
)

_OSASCRIPT_CHOOSE_FILE = (
    "on run argv\n"
    "    set promptText to item 1 of argv\n"
    "    set defaultDir to item 2 of argv\n"
    "    activate\n"
    '    if defaultDir is not "" then\n'
    "        return POSIX path of (choose file with prompt promptText default location (POSIX file defaultDir))\n"
    "    else\n"
    "        return POSIX path of (choose file with prompt promptText)\n"
    "    end if\n"
    "end run"
)

_TKINTER_PICK_SCRIPT = (
    "import sys, tkinter as tk\n"
    "from tkinter import filedialog\n"
    "mode, title, init_dir = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    "root = tk.Tk()\n"
    "root.withdraw()\n"
    "try:\n"
    "    root.attributes('-topmost', True)\n"
    "except Exception:\n"
    "    pass\n"
    "kw = {'title': title}\n"
    "if init_dir:\n"
    "    kw['initialdir'] = init_dir\n"
    "if mode == 'directory':\n"
    "    picked = filedialog.askdirectory(**kw)\n"
    "else:\n"
    "    kw['filetypes'] = [('Capture files', '*.pcap *.pcapng *.cap *.csv *.tsv'), ('All files', '*.*')]\n"
    "    picked = filedialog.askopenfilename(**kw)\n"
    "root.destroy()\n"
    "if not picked:\n"
    "    sys.exit(1)\n"
    "print(picked)\n"
)


class PickerError(RuntimeError):
    def __init__(self, status: int, code: str) -> None:
        self.status = status
        self.code = code
        super().__init__(code)


class PickerDisabledError(PickerError):
    def __init__(self, code: str = "native_picker_disabled") -> None:
        super().__init__(403, code)


class PickerUnavailableError(PickerError):
    def __init__(self, code: str = "desktop_picker_unavailable") -> None:
        super().__init__(503, code)


def truthy_env(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def falsy_env(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"0", "false", "no", "off"}


def default_pcapscanner_home() -> Path:
    return Path.home() / ".pcapscanner"


def resolve_default_workspace_config_path() -> Path:
    explicit = os.environ.get("PCAP_WORKSPACE_CONFIG", "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    return (default_pcapscanner_home() / "workspace.json").resolve()


def resolve_workspace_config_path() -> Path | None:
    """Return active workspace config path only when opted in or launched locally.

    Avoids polluting isolated unit tests that construct ``AppSettings`` or call
    ``load_settings()`` without opting into workspace persistence.
    """
    explicit = os.environ.get("PCAP_WORKSPACE_CONFIG", "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    if truthy_env(os.environ.get("PCAP_ENABLE_NATIVE_PICKER")) or truthy_env(
        os.environ.get("PCAP_USE_WORKSPACE_CONFIG")
    ):
        return (default_pcapscanner_home() / "workspace.json").resolve()
    return None


def is_loopback_client(host: str | None) -> bool:
    if not host:
        return False
    clean = host.strip().lower()
    if clean in {"localhost", "testclient"}:
        return True
    if clean.startswith("::ffff:"):
        clean = clean[7:]
    try:
        ip = ipaddress.ip_address(clean)
        return ip.is_loopback
    except ValueError:
        return False


def _has_tkinter() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("tkinter") is not None
    except Exception:
        return False


def detect_picker_backend() -> str | None:
    if sys.platform == "darwin":
        return "osascript" if shutil.which("osascript") else None
    if sys.platform.startswith("win"):
        return "tkinter" if _has_tkinter() else None
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return None
    for candidate in ("zenity", "kdialog"):
        if shutil.which(candidate):
            return candidate
    if _has_tkinter():
        return "tkinter"
    return None


def is_native_picker_enabled() -> bool:
    raw = os.environ.get("PCAP_ENABLE_NATIVE_PICKER")
    if raw is not None:
        return truthy_env(raw)
    return detect_picker_backend() is not None


def _normalize_roots(raw_roots: Any) -> list[str]:
    if not isinstance(raw_roots, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw_roots:
        if not isinstance(item, str):
            continue
        cleaned = item.strip()
        if not cleaned or "\x00" in cleaned:
            continue
        resolved = str(Path(cleaned).expanduser().resolve())
        if resolved not in seen:
            seen.add(resolved)
            out.append(resolved)
        if len(out) >= 20:
            break
    return out


def sanitize_workspace_data(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {"schema_version": "1.0", "local_ingest_roots": []}
    out: dict[str, Any] = {"schema_version": "1.0"}
    data_dir = raw.get("data_dir")
    if isinstance(data_dir, str) and data_dir.strip() and "\x00" not in data_dir:
        out["data_dir"] = str(Path(data_dir.strip()).expanduser().resolve())
    roots = _normalize_roots(raw.get("local_ingest_roots"))
    out["local_ingest_roots"] = roots
    rmode = raw.get("resource_mode")
    if isinstance(rmode, str) and rmode in ALLOWED_RESOURCE_MODES:
        out["resource_mode"] = rmode
    if isinstance(raw.get("prefer_workspace"), bool):
        out["prefer_workspace"] = raw["prefer_workspace"]
    return out


def load_workspace_config(path: Path | None = None) -> dict[str, Any]:
    target = path or resolve_workspace_config_path()
    if target is None or not target.is_file():
        return {"schema_version": "1.0", "local_ingest_roots": []}
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"schema_version": "1.0", "local_ingest_roots": []}
    return sanitize_workspace_data(raw)


def save_workspace_config(data: dict[str, Any], path: Path | None = None) -> Path:
    target = path or resolve_default_workspace_config_path()
    clean = sanitize_workspace_data(data)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(target.parent, 0o700)
    except OSError:
        pass
    fd, tmp_name = tempfile.mkstemp(prefix=".workspace-", suffix=".json", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(clean, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return target


def update_workspace_config(
    *,
    path: Path | None = None,
    data_dir: str | None = None,
    local_ingest_roots: list[str] | None = None,
    resource_mode: str | None = None,
    prefer_workspace: bool | None = None,
) -> dict[str, Any]:
    target = path or resolve_default_workspace_config_path()
    current = load_workspace_config(target)
    if data_dir is not None:
        current["data_dir"] = str(Path(data_dir).expanduser().resolve())
    if local_ingest_roots is not None:
        current["local_ingest_roots"] = _normalize_roots(local_ingest_roots)
    if resource_mode is not None and resource_mode in ALLOWED_RESOURCE_MODES:
        current["resource_mode"] = resource_mode
    if prefer_workspace is not None:
        current["prefer_workspace"] = bool(prefer_workspace)
    save_workspace_config(current, target)
    return current


def pick_native_path(
    purpose: PickerPurpose,
    *,
    initial_dir: Path | str | None = None,
    timeout_seconds: float = 180.0,
) -> Path | None:
    """Open the native OS file or folder chooser dialog and return selected path.

    Returns ``None`` if the user cancelled the dialog. Raises ``PickerError``
    when the picker is disabled, unsupported in a headless environment, or fails.
    """
    if purpose not in _PURPOSE_PROMPTS:
        raise PickerError(400, "invalid_picker_purpose")
    if not is_native_picker_enabled():
        raise PickerDisabledError()
    backend = detect_picker_backend()
    if backend is None:
        raise PickerUnavailableError()

    prompt = _PURPOSE_PROMPTS[purpose]
    is_dir = purpose in {"data_dir", "capture_root"}

    default_dir = ""
    if initial_dir:
        candidate = Path(initial_dir).expanduser().resolve()
        if candidate.is_dir():
            default_dir = str(candidate)

    if backend == "osascript":
        script = _OSASCRIPT_CHOOSE_DIR if is_dir else _OSASCRIPT_CHOOSE_FILE
        cmd = ["osascript", "-e", script, prompt, default_dir]
    elif backend == "zenity":
        cmd = ["zenity", "--file-selection", f"--title={prompt}"]
        if is_dir:
            cmd.append("--directory")
        else:
            cmd.extend(
                [
                    "--file-filter=Capture files | *.pcap *.pcapng *.cap *.csv *.tsv",
                    "--file-filter=All files | *",
                ]
            )
        if default_dir:
            cmd.append(f"--filename={default_dir.rstrip('/')}/")
    elif backend == "kdialog":
        start = default_dir or str(Path.home())
        if is_dir:
            cmd = ["kdialog", "--title", prompt, "--getexistingdirectory", start]
        else:
            cmd = [
                "kdialog",
                "--title",
                prompt,
                "--getopenfilename",
                start,
                "*.pcap *.pcapng *.cap *.csv *.tsv|Capture files",
            ]
    else:
        # Isolated subprocess avoids macOS AppKit / GUI main-thread violations in worker threads.
        mode_arg = "directory" if is_dir else "capture_file"
        cmd = [sys.executable, "-c", _TKINTER_PICK_SCRIPT, mode_arg, prompt, default_dir]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PickerError(504, "picker_timed_out") from exc
    except OSError as exc:
        raise PickerUnavailableError() from exc

    if proc.returncode != 0:
        err_text = (proc.stderr or "").lower()
        if backend == "osascript" and ("-128" in err_text or "user cancel" in err_text):
            return None
        if backend in {"zenity", "kdialog", "tkinter"} and proc.returncode in {1, 5}:
            return None
        if "no display" in err_text or "could not open display" in err_text:
            raise PickerUnavailableError()
        raise PickerError(500, "picker_failed")

    selected_text = (proc.stdout or "").strip()
    if not selected_text or "\x00" in selected_text:
        return None
    return Path(selected_text).expanduser().resolve()


__all__ = [
    "ALLOWED_RESOURCE_MODES",
    "ALLOWED_WORKSPACE_KEYS",
    "PickerDisabledError",
    "PickerError",
    "PickerPurpose",
    "PickerUnavailableError",
    "default_pcapscanner_home",
    "detect_picker_backend",
    "is_loopback_client",
    "is_native_picker_enabled",
    "load_workspace_config",
    "pick_native_path",
    "resolve_default_workspace_config_path",
    "resolve_workspace_config_path",
    "sanitize_workspace_data",
    "save_workspace_config",
    "truthy_env",
    "update_workspace_config",
]
