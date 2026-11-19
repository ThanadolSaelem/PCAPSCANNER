"""One-click unified supervisor for PCAPSCANNER Web UI, API, workers, and Tier-1 server.

Usage:
    python -m backend.app.launcher            # Production single-port mode (API + UI on 127.0.0.1:8000)
    python -m backend.app.launcher --dev      # Dev mode (API on 8000 + Vite HMR on 3000)
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Sequence
from urllib.error import URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .picker import (
    default_pcapscanner_home,
    is_loopback_client,
    load_workspace_config,
    save_workspace_config,
    truthy_env,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def ensure_local_token(token_path: Path) -> str:
    """Return process ``PCAP_API_TOKEN`` or create/reuse a private 0600 local token."""
    env_token = os.environ.get("PCAP_API_TOKEN", "").strip()
    if env_token:
        return env_token
    token_path = token_path.expanduser().resolve()
    token_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(token_path.parent, 0o700)
    except OSError:
        pass
    if token_path.is_file():
        existing = token_path.read_text(encoding="utf-8").strip()
        if len(existing) >= 16:
            try:
                os.chmod(token_path, 0o600)
            except OSError:
                pass
            return existing
    generated = secrets.token_urlsafe(32)
    fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(generated + "\n")
    finally:
        try:
            os.chmod(token_path, 0o600)
        except OSError:
            pass
    return generated


def ensure_workspace_initialized(
    workspace_path: Path,
    *,
    default_data_dir: Path | None = None,
    cli_data_dir: str | None = None,
) -> Path:
    """Create or normalize the local non-secret workspace config file."""
    ws_path = workspace_path.expanduser().resolve()
    current = load_workspace_config(ws_path)
    if cli_data_dir:
        current["data_dir"] = str(Path(cli_data_dir).expanduser().resolve())
        current["prefer_workspace"] = True
    elif not current.get("data_dir"):
        env_data_dir = os.environ.get("PCAP_DATA_DIR", "").strip()
        chosen = Path(env_data_dir) if env_data_dir else (default_data_dir or (ws_path.parent / "data"))
        current["data_dir"] = str(chosen.expanduser().resolve())
    save_workspace_config(current, ws_path)
    return ws_path


def probe_pcapscanner_health(port: int, *, host: str = "127.0.0.1", timeout: float = 0.8) -> bool:
    url = f"http://{host}:{port}/health"
    try:
        with urlopen(Request(url, headers={"Accept": "application/json"}), timeout=timeout) as resp:
            if resp.status != 200:
                return False
            data = json.loads(resp.read(4096).decode("utf-8"))
            return isinstance(data, dict) and data.get("status") == "ok" and "api_version" in data
    except (OSError, URLError, ValueError):
        return False


def discover_local_ollama_model(
    base_url: str = "http://127.0.0.1:11434",
    *,
    timeout: float = 0.4,
) -> str | None:
    """Inspect a loopback Ollama server (/api/tags or /v1/models) and pick a chat model if available."""
    parts = urlsplit(base_url.strip())
    if parts.scheme.lower() not in {"http", "https"} or not is_loopback_client(parts.hostname):
        return None
    clean_base = base_url.strip().rstrip("/")
    candidates: list[str] = []
    for path in ("/api/tags", "/v1/models"):
        try:
            with urlopen(Request(f"{clean_base}{path}", headers={"Accept": "application/json"}), timeout=timeout) as resp:
                if resp.status != 200:
                    continue
                payload = json.loads(resp.read(262_144).decode("utf-8"))
        except (OSError, URLError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        for key in ("models", "data"):
            rows = payload.get(key)
            if not isinstance(rows, list):
                continue
            for item in rows:
                if not isinstance(item, dict):
                    continue
                model_id = item.get("name") or item.get("model") or item.get("id")
                if isinstance(model_id, str) and model_id.strip():
                    candidates.append(model_id.strip())
        if candidates:
            break
    if not candidates:
        return None
    for model_id in candidates:
        if "embed" not in model_id.lower():
            return model_id
    return candidates[0]


def maybe_autoconfigure_local_ai(
    child_env: dict[str, str],
    ws_path: Path,
    *,
    timeout: float = 0.4,
) -> str | None:
    """Populate PCAP_AI_MODEL from local Ollama unless operator config/env disables or overrides AI."""
    ai_env_raw = child_env.get("PCAP_AI_ENABLED")
    if ai_env_raw is not None and not truthy_env(ai_env_raw):
        return None
    if child_env.get("PCAP_AI_CONFIG", "").strip():
        return None
    if child_env.get("PCAP_AI_MODEL", "").strip() or child_env.get("PCAP_AI_BASE_URL", "").strip():
        return None
    ws_cfg = load_workspace_config(ws_path)
    ws_ai = ws_cfg.get("ai") if isinstance(ws_cfg.get("ai"), dict) else {}
    if ws_ai.get("enabled") is False or ws_ai.get("model") or ws_ai.get("base_url"):
        return None
    provider = str(child_env.get("PCAP_AI_PROVIDER") or ws_ai.get("provider") or "openai_compatible")
    if provider != "openai_compatible":
        return None
    detected = discover_local_ollama_model(timeout=timeout)
    if not detected:
        return None
    child_env["PCAP_AI_MODEL"] = detected
    child_env.setdefault("PCAP_AI_ENABLED", "1")
    return detected


def is_port_free(port: int, *, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex((host, port)) != 0


def find_available_port(preferred: int, max_offset: int = 20, *, host: str = "127.0.0.1") -> int:
    for candidate in range(preferred, preferred + max_offset + 1):
        if is_port_free(candidate, host=host):
            return candidate
    raise RuntimeError(f"no_free_port_near_{preferred}")


def build_launch_url(port: int, token: str, *, backend_url: str = "") -> str:
    """Build loopback URL passing bearer credentials strictly in fragment (#), never query string."""
    return f"http://127.0.0.1:{port}/#token={quote(token, safe='')}&url={quote(backend_url, safe='/:')}"


def discover_tier1_inference_root(repo_root: Path = REPO_ROOT) -> Path | None:
    explicit = os.environ.get("PCAP_TIER1_MODULE_DIR", "").strip()
    candidates = [Path(explicit).expanduser()] if explicit else []
    candidates.extend([repo_root / "tier1-inference", repo_root.parent / "tier1-inference"])
    for cand in candidates:
        resolved = cand.resolve()
        if (resolved / "tier1_inference" / "server.py").is_file():
            return resolved
    return None


def discover_trainer_pipeline_root(repo_root: Path = REPO_ROOT) -> Path | None:
    explicit = os.environ.get("PCAP_TRAINER_PIPELINE_DIR", "").strip()
    candidates = [Path(explicit).expanduser()] if explicit else []
    candidates.extend([repo_root.parent / "Trainer-Pipeline", repo_root / "Trainer-Pipeline"])
    for cand in candidates:
        resolved = cand.resolve()
        if (resolved / "traffic_tier1" / "serve_tier1.py").is_file():
            return resolved
    return None


def _python_has_modules(py_exe: Path, modules: tuple[str, ...]) -> bool:
    if not py_exe.is_file():
        return False
    check = "; ".join(f"import {mod}" for mod in modules)
    try:
        proc = subprocess.run([str(py_exe), "-c", check], capture_output=True, timeout=6.0, shell=False)
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def find_tier1_python(
    service_root: Path,
    *,
    fallback_roots: Sequence[Path] = (),
    prefer_neural: bool = False,
    require_numpy: bool = False,
) -> Path | None:
    candidates: list[Path] = []
    explicit = os.environ.get("PCAP_TIER1_PYTHON", "").strip()
    if explicit:
        candidates.append(Path(explicit).expanduser())
    for root in (service_root, *fallback_roots):
        candidates.extend(
            [
                root / ".venv" / "bin" / "python",
                root / ".venv" / "Scripts" / "python.exe",
            ]
        )
    candidates.extend(
        [
            Path.home() / "venvs" / "tier1-inference" / "bin" / "python",
            Path.home() / "venvs" / "traffic-tier1" / "bin" / "python",
            REPO_ROOT / ".venv-backend" / "bin" / "python",
            Path(sys.executable),
        ]
    )
    if prefer_neural:
        for cand in candidates:
            if _python_has_modules(cand, ("fastapi", "uvicorn", "torch", "transformers")):
                return cand
    required = ("fastapi", "uvicorn", "numpy") if require_numpy else ("fastapi", "uvicorn")
    for cand in candidates:
        if _python_has_modules(cand, required):
            return cand
    return None


def _first_existing_dir(candidates: Sequence[Path]) -> Path | None:
    for cand in candidates:
        if cand.is_dir():
            return cand.resolve()
    return None


def _append_allowed_origin(raw: str | None, origin: str) -> str:
    items = [part.strip() for part in (raw or "").split(",") if part.strip()]
    if origin not in items:
        items.append(origin)
    return ",".join(items)


def open_browser_url(url: str) -> bool:
    try:
        if webbrowser.open(url, new=2):
            return True
    except Exception:
        pass
    if sys.platform == "darwin" and shutil.which("open"):
        try:
            subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except OSError:
            return False
    return False


def _wait_for_http_ok(url: str, *, timeout_seconds: float = 25.0, proc: subprocess.Popen | None = None) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            with urlopen(Request(url), timeout=0.8) as resp:
                if 200 <= resp.status < 400:
                    return True
        except (OSError, URLError):
            pass
        time.sleep(0.25)
    return False


def _terminate_children(children: list[tuple[str, subprocess.Popen]]) -> None:
    for _name, proc in reversed(children):
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
    deadline = time.monotonic() + 5.0
    for _name, proc in reversed(children):
        if proc.poll() is None:
            wait_left = max(0.2, deadline - time.monotonic())
            try:
                proc.wait(timeout=wait_left)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="One-click launcher for PCAPSCANNER Workbench")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PCAP_PORT", "8000")), help="Backend API / single-port Web UI port")
    parser.add_argument("--ui-port", type=int, default=3000, help="Vite dev server port when using --dev")
    parser.add_argument("--tier1-port", type=int, default=9000, help="Standalone Tier-1 inference server port")
    parser.add_argument("--dev", action="store_true", help="Launch Vite dev server alongside FastAPI backend")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the browser tab")
    parser.add_argument("--with-tier1", action="store_true", help="Force-start standalone Tier-1 HTTP server even without checkpoints")
    parser.add_argument("--no-tier1", action="store_true", help="Skip auto-starting Tier-1 inference HTTP server")
    parser.add_argument("--data-dir", default=None, help="Optional Data Directory override persisted into workspace config")
    parser.add_argument("--workspace-config", default=None, help="Optional workspace.json path (default: ~/.pcapscanner/workspace.json)")
    return parser


def resolve_tier1_launch_plan(
    *,
    repo_root: Path = REPO_ROOT,
    home_dir: Path | None = None,
    port: int = 9000,
    no_tier1: bool = False,
    with_tier1: bool = False,
) -> tuple[list[str], Path] | None:
    """Resolve standalone `tier1-inference` (or fallback `Trainer-Pipeline`) launch command."""
    if no_tier1:
        return None
    resolved_home = home_dir or default_pcapscanner_home()
    standalone_root = discover_tier1_inference_root(repo_root)
    trainer_root = discover_trainer_pipeline_root(repo_root)
    if standalone_root is None and trainer_root is None:
        return None

    openjev_candidates: list[Path] = []
    if os.environ.get("PCAP_OPENJEV_CHECKPOINT"):
        openjev_candidates.append(Path(os.environ["PCAP_OPENJEV_CHECKPOINT"]).expanduser())
    if standalone_root is not None:
        openjev_candidates.append(standalone_root / "models" / "openjev-tier1")
    openjev_candidates.extend(
        [
            repo_root / "models" / "openjev-tier1",
            resolved_home / "models" / "openjev-tier1",
        ]
    )
    if trainer_root is not None:
        openjev_candidates.append(trainer_root / "runs" / "tier1_rlcd")

    etbert_candidates: list[Path] = []
    if os.environ.get("PCAP_ETBERT_CHECKPOINT"):
        etbert_candidates.append(Path(os.environ["PCAP_ETBERT_CHECKPOINT"]).expanduser())
    if standalone_root is not None:
        etbert_candidates.append(standalone_root / "models" / "etbert-l7")
    etbert_candidates.extend(
        [
            repo_root / "models" / "etbert-l7",
            resolved_home / "models" / "etbert-l7",
        ]
    )
    if trainer_root is not None:
        etbert_candidates.append(trainer_root / "runs" / "etbert_l7")

    openjev_ckpt = _first_existing_dir(openjev_candidates)
    etbert_ckpt = _first_existing_dir(etbert_candidates)
    has_checkpoints = openjev_ckpt is not None or etbert_ckpt is not None
    autoserve = with_tier1 or truthy_env(os.environ.get("PCAP_TIER1_AUTOSERVE")) or trainer_root is not None

    if standalone_root is not None and (has_checkpoints or autoserve):
        service_root = standalone_root
        module_name = "tier1_inference"
        fallback_roots = (trainer_root,) if trainer_root is not None else ()
        require_numpy = False
    elif trainer_root is not None:
        service_root = trainer_root
        module_name = "traffic_tier1.serve_tier1"
        fallback_roots = ()
        require_numpy = True
    else:
        return None

    tier1_py = find_tier1_python(
        service_root,
        fallback_roots=fallback_roots,
        prefer_neural=has_checkpoints,
        require_numpy=require_numpy,
    )
    if tier1_py is None:
        return None

    cmd = [
        str(tier1_py),
        "-m",
        module_name,
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--device",
        "auto",
    ]
    if openjev_ckpt is not None:
        cmd.extend(["--openjev-checkpoint", str(openjev_ckpt)])
    if etbert_ckpt is not None:
        cmd.extend(["--etbert-checkpoint", str(etbert_ckpt)])
    return cmd, service_root


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    home_dir = default_pcapscanner_home()
    ws_path = ensure_workspace_initialized(
        Path(args.workspace_config) if args.workspace_config else (home_dir / "workspace.json"),
        default_data_dir=home_dir / "data",
        cli_data_dir=args.data_dir,
    )
    token = ensure_local_token(home_dir / "local_token.secret")

    # If PCAPSCANNER is already running cleanly on the requested port, just open the UI tab!
    if probe_pcapscanner_health(args.port):
        target_port = args.ui_port if args.dev and probe_pcapscanner_health(args.ui_port) else args.port
        launch_url = build_launch_url(target_port, token, backend_url="")
        print(f"[PCAPSCANNER] Running instance detected on http://127.0.0.1:{args.port}")
        if not args.no_browser:
            open_browser_url(launch_url)
        else:
            print(f"[PCAPSCANNER] Web UI ready on http://127.0.0.1:{target_port}/ (browser launch skipped)")
        return 0

    api_port = find_available_port(args.port)
    child_env = os.environ.copy()
    child_env["PCAP_API_TOKEN"] = token
    child_env["PCAP_WORKSPACE_CONFIG"] = str(ws_path)
    child_env["PCAP_ENABLE_NATIVE_PICKER"] = child_env.get("PCAP_ENABLE_NATIVE_PICKER", "1")
    child_env.pop("PCAP_DATA_DIR", None)  # Let workspace.json drive live data_dir switches unless --data-dir persisted above
    child_env.pop("PCAP_LOCAL_INGEST_ROOTS", None)

    dist_index = REPO_ROOT / "dist" / "index.html"
    serve_static_ui = not args.dev and dist_index.is_file()
    if serve_static_ui:
        child_env["PCAP_SERVE_UI"] = "1"
    elif not args.dev:
        print(f"[PCAPSCANNER] WARN: {dist_index} not built yet; API will run without bundled UI (run pnpm build or use --dev)")

    children: list[tuple[str, subprocess.Popen]] = []

    def handle_signal(signum, frame):  # noqa: ANN001
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        # 1. Standalone tier1-inference sidecar (or optional Trainer-Pipeline fallback)
        if not args.no_tier1 and not child_env.get("PCAP_TRIAGE_ENDPOINT_URL"):
            tier1_port = find_available_port(args.tier1_port)
            plan = resolve_tier1_launch_plan(
                repo_root=REPO_ROOT,
                home_dir=home_dir,
                port=tier1_port,
                no_tier1=args.no_tier1,
                with_tier1=args.with_tier1,
            )
            if plan is not None:
                tier1_cmd, tier1_cwd = plan
                tier1_token = (
                    os.environ.get("TIER1_API_TOKEN")
                    or os.environ.get("PCAP_TIER1_API_TOKEN")
                    or secrets.token_urlsafe(24)
                ).strip()
                tier1_env = os.environ.copy()
                tier1_env.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "1")
                tier1_env["TIER1_API_TOKEN"] = tier1_token
                print(f"[PCAPSCANNER] Starting Tier-1 classifier service on http://127.0.0.1:{tier1_port} ...")
                tier1_proc = subprocess.Popen(tier1_cmd, cwd=str(tier1_cwd), env=tier1_env)
                children.append(("tier1", tier1_proc))
                if _wait_for_http_ok(f"http://127.0.0.1:{tier1_port}/health", timeout_seconds=15.0, proc=tier1_proc):
                    origin = f"http://127.0.0.1:{tier1_port}"
                    child_env["PCAP_TRIAGE_ENABLED"] = "1"
                    child_env["PCAP_TRIAGE_MODE"] = "etbert_openjev"
                    child_env["PCAP_TRIAGE_ALLOWED_ORIGINS"] = _append_allowed_origin(
                        child_env.get("PCAP_TRIAGE_ALLOWED_ORIGINS"), origin
                    )
                    child_env["PCAP_TRIAGE_ENDPOINT_URL"] = f"{origin}/v1/systemone"
                    child_env["PCAP_TRIAGE_ETBERT_ENABLED"] = "1"
                    child_env["PCAP_TRIAGE_ETBERT_ENDPOINT_URL"] = f"{origin}/etbert/score"
                    child_env["PCAP_TIER1_API_TOKEN"] = tier1_token
                    print("[PCAPSCANNER] Tier-1 ET-BERT + OpenJev service ready.")
                else:
                    print("[PCAPSCANNER] Tier-1 service did not become ready in time; using built-in calibrated Tier-1 scorer.")

        # 2. Layer-2 Local Ollama auto-detection (opt-out with PCAP_AI_ENABLED=0)
        detected_ollama = maybe_autoconfigure_local_ai(child_env, ws_path)
        if detected_ollama:
            print(f"[PCAPSCANNER] Layer-2 Ollama model auto-selected: {detected_ollama}")

        # 3. Backend FastAPI server
        print(f"[PCAPSCANNER] Starting Backend API on http://127.0.0.1:{api_port} ...")
        api_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "backend.app.main:create_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                str(api_port),
            ],
            cwd=str(REPO_ROOT),
            env=child_env,
        )
        children.append(("api", api_proc))

        # 3. Offline PCAP parser worker
        worker_proc = subprocess.Popen([sys.executable, "-m", "backend.app.worker"], cwd=str(REPO_ROOT), env=child_env)
        children.append(("worker", worker_proc))

        # 4. Optional AI narrator worker
        ai_proc = subprocess.Popen([sys.executable, "-m", "backend.app.ai_worker"], cwd=str(REPO_ROOT), env=child_env)
        children.append(("ai_worker", ai_proc))

        if not _wait_for_http_ok(f"http://127.0.0.1:{api_port}/health", timeout_seconds=25.0, proc=api_proc):
            print("[PCAPSCANNER] ERROR: FastAPI backend failed to start cleanly.")
            return 1

        ui_port = api_port
        if args.dev:
            ui_port = find_available_port(args.ui_port)
            dev_env = os.environ.copy()
            dev_env["VITE_API_PROXY_TARGET"] = f"http://127.0.0.1:{api_port}"
            pkg_mgr = shutil.which("pnpm") or shutil.which("npm")
            if pkg_mgr:
                dev_args = (
                    [pkg_mgr, "dev", "--", "--host", "127.0.0.1", "--port", str(ui_port)]
                    if Path(pkg_mgr).name.startswith("npm")
                    else [pkg_mgr, "dev", "--host", "127.0.0.1", "--port", str(ui_port)]
                )
                vite_proc = subprocess.Popen(dev_args, cwd=str(REPO_ROOT), env=dev_env)
                children.append(("vite", vite_proc))
                _wait_for_http_ok(f"http://127.0.0.1:{ui_port}/", timeout_seconds=20.0, proc=vite_proc)

        launch_url = build_launch_url(ui_port, token, backend_url="")
        ws_cfg = load_workspace_config(ws_path)
        print("=================================================================")
        print(f" PCAPSCANNER ready! Open: http://127.0.0.1:{ui_port}/")
        print(f" Data Directory: {ws_cfg.get('data_dir')}")
        print(f" Workspace Config: {ws_path}")
        print(f" Token file (0600): {home_dir / 'local_token.secret'}")
        print(" Tip: You can change Data Directory & capture folders via")
        print("      native OS file picker dialogs directly inside the Web UI.")
        print(" Press Ctrl+C in this window to stop all PCAPSCANNER workers.")
        print("=================================================================")

        if not args.no_browser and (args.dev or serve_static_ui):
            open_browser_url(launch_url)

        while True:
            for name, proc in children:
                code = proc.poll()
                if code is not None and name in {"api", "worker"}:
                    print(f"[PCAPSCANNER] Core process '{name}' exited unexpectedly with code {code}; shutting down.")
                    return code if code != 0 else 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[PCAPSCANNER] Shutting down cleanly...")
        return 0
    finally:
        _terminate_children(children)


if __name__ == "__main__":
    raise SystemExit(main())
