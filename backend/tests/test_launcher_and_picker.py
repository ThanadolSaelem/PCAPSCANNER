from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

try:
    import pydantic

    HAS_PYDANTIC_V2 = int(getattr(pydantic, "__version__", "1").split(".")[0]) >= 2
except Exception:
    HAS_PYDANTIC_V2 = False

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import launcher, picker  # noqa: E402


class NativePickerUnitTests(unittest.TestCase):
    def test_workspace_config_isolated_unless_opted_in(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(picker.resolve_workspace_config_path())
        with mock.patch.dict(os.environ, {"PCAP_WORKSPACE_CONFIG": "/tmp/custom-ws.json"}, clear=True):
            self.assertEqual(picker.resolve_workspace_config_path(), Path("/tmp/custom-ws.json").resolve())
        with mock.patch.dict(os.environ, {"PCAP_ENABLE_NATIVE_PICKER": "1"}, clear=True):
            self.assertIsNotNone(picker.resolve_workspace_config_path())

    def test_sanitize_and_atomic_save_with_0600_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws_file = Path(tmp) / "cfg" / "workspace.json"
            dirty = {
                "data_dir": str(Path(tmp) / "data"),
                "local_ingest_roots": [str(Path(tmp) / "pcaps"), str(Path(tmp) / "pcaps"), "bad\x00path", ""],
                "resource_mode": "unlimited",
                "prefer_workspace": True,
                "api_token": "should-never-persist",
                "secret": "drop-me",
            }
            saved = picker.save_workspace_config(dirty, ws_file)
            self.assertEqual(saved, ws_file)
            mode = stat.S_IMODE(ws_file.stat().st_mode)
            self.assertEqual(mode, 0o600)
            loaded = picker.load_workspace_config(ws_file)
            self.assertNotIn("api_token", loaded)
            self.assertNotIn("secret", loaded)
            self.assertEqual(loaded["resource_mode"], "unlimited")
            self.assertEqual(loaded["local_ingest_roots"], [str((Path(tmp) / "pcaps").resolve())])
            self.assertTrue(loaded["prefer_workspace"])

    def test_is_loopback_client(self) -> None:
        for addr in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost", "testclient"):
            self.assertTrue(picker.is_loopback_client(addr), addr)
        for addr in (None, "", "10.0.0.12", "192.168.1.5", "8.8.8.8", "example.com"):
            self.assertFalse(picker.is_loopback_client(addr), str(addr))

    def test_pick_native_path_disabled_unavailable_cancel_and_mocked_selection(self) -> None:
        with mock.patch.dict(os.environ, {"PCAP_ENABLE_NATIVE_PICKER": "0"}):
            with self.assertRaises(picker.PickerDisabledError):
                picker.pick_native_path("data_dir")

        with (
            mock.patch.dict(os.environ, {"PCAP_ENABLE_NATIVE_PICKER": "1"}),
            mock.patch.object(picker, "detect_picker_backend", return_value=None),
        ):
            with self.assertRaises(picker.PickerUnavailableError):
                picker.pick_native_path("data_dir")

        cancel_proc = subprocess.CompletedProcess(
            args=["osascript"],
            returncode=1,
            stdout="",
            stderr="execution error: User canceled. (-128)",
        )
        with (
            mock.patch.dict(os.environ, {"PCAP_ENABLE_NATIVE_PICKER": "1"}),
            mock.patch.object(picker, "detect_picker_backend", return_value="osascript"),
            mock.patch("subprocess.run", return_value=cancel_proc),
        ):
            self.assertIsNone(picker.pick_native_path("capture_file"))

        with tempfile.TemporaryDirectory() as tmp:
            chosen = Path(tmp) / "trace.pcapng"
            ok_proc = subprocess.CompletedProcess(
                args=["osascript"],
                returncode=0,
                stdout=f"{chosen}\n",
                stderr="",
            )
            with (
                mock.patch.dict(os.environ, {"PCAP_ENABLE_NATIVE_PICKER": "1"}),
                mock.patch.object(picker, "detect_picker_backend", return_value="osascript"),
                mock.patch("subprocess.run", return_value=ok_proc) as mocked_run,
            ):
                picked = picker.pick_native_path("capture_file", initial_dir=tmp)
            self.assertEqual(picked, chosen.resolve())
            self.assertFalse(mocked_run.call_args.kwargs.get("shell", False))


class LauncherUnitTests(unittest.TestCase):
    def test_ensure_local_token_creates_0600_and_reuses_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tok_path = Path(tmp) / "pcap" / "local_token.secret"
            with mock.patch.dict(os.environ, {"PCAP_API_TOKEN": ""}):
                first = launcher.ensure_local_token(tok_path)
                self.assertGreaterEqual(len(first), 32)
                self.assertEqual(stat.S_IMODE(tok_path.stat().st_mode), 0o600)
                second = launcher.ensure_local_token(tok_path)
                self.assertEqual(first, second)

            with mock.patch.dict(os.environ, {"PCAP_API_TOKEN": "explicit-env-token-123456"}):
                self.assertEqual(launcher.ensure_local_token(tok_path), "explicit-env-token-123456")

    def test_ensure_workspace_initialized_and_launch_url_uses_fragment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws_path = Path(tmp) / "workspace.json"
            data_path = Path(tmp) / "my-data"
            with mock.patch.dict(os.environ, {}, clear=True):
                out_path = launcher.ensure_workspace_initialized(ws_path, default_data_dir=data_path)
            self.assertEqual(out_path, ws_path.resolve())
            loaded = json.loads(ws_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["data_dir"], str(data_path.resolve()))

            cli_dir = Path(tmp) / "ssd-data"
            launcher.ensure_workspace_initialized(ws_path, cli_data_dir=str(cli_dir))
            updated = json.loads(ws_path.read_text(encoding="utf-8"))
            self.assertEqual(updated["data_dir"], str(cli_dir.resolve()))
            self.assertTrue(updated["prefer_workspace"])

        url = launcher.build_launch_url(8000, "secret+tok/en=", backend_url="")
        self.assertIn("#token=", url)
        self.assertNotIn("?token=", url)

    def test_probe_pcapscanner_health_distinguishes_services(self) -> None:
        class _Handler(BaseHTTPRequestHandler):
            payload = {"status": "ok", "api_version": "1"}

            def do_GET(self) -> None:  # noqa: N802
                body = json.dumps(self.payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

        server = HTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            self.assertTrue(launcher.probe_pcapscanner_health(port))
            _Handler.payload = {"status": "ok"}  # Not PCAPSCANNER (missing api_version)
            self.assertFalse(launcher.probe_pcapscanner_health(port))
        finally:
            server.shutdown()
            server.server_close()

    def test_discover_local_ollama_model_and_autoconfigure_respect_opt_out(self) -> None:
        class _OllamaHandler(BaseHTTPRequestHandler):
            mode = "tags"

            def do_GET(self) -> None:  # noqa: N802
                if self.mode == "tags" and self.path == "/api/tags":
                    body = json.dumps(
                        {"models": [{"name": "nomic-embed-text:latest"}, {"name": "qwen2.5:7b"}]}
                    ).encode("utf-8")
                    self.send_response(200)
                elif self.mode == "v1" and self.path == "/v1/models":
                    body = json.dumps({"data": [{"id": "llama3.2:latest"}]}).encode("utf-8")
                    self.send_response(200)
                else:
                    body = b"{}"
                    self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

        # Reject non-loopback endpoint without attempting remote network call
        self.assertIsNone(launcher.discover_local_ollama_model("http://8.8.8.8:11434", timeout=0.2))

        server = HTTPServer(("127.0.0.1", 0), _OllamaHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            base = f"http://127.0.0.1:{port}"
            self.assertEqual(launcher.discover_local_ollama_model(base, timeout=1.0), "qwen2.5:7b")

            _OllamaHandler.mode = "v1"
            self.assertEqual(launcher.discover_local_ollama_model(base, timeout=1.0), "llama3.2:latest")

            with tempfile.TemporaryDirectory() as tmp:
                ws_path = Path(tmp) / "workspace.json"
                with mock.patch.object(
                    launcher,
                    "discover_local_ollama_model",
                    return_value="qwen2.5:7b",
                ):
                    env: dict[str, str] = {}
                    picked = launcher.maybe_autoconfigure_local_ai(env, ws_path)
                    self.assertEqual(picked, "qwen2.5:7b")
                    self.assertEqual(env["PCAP_AI_MODEL"], "qwen2.5:7b")
                    self.assertEqual(env["PCAP_AI_ENABLED"], "1")

                    # Respect operator opt-out via PCAP_AI_ENABLED=0
                    env_off = {"PCAP_AI_ENABLED": "0"}
                    self.assertIsNone(launcher.maybe_autoconfigure_local_ai(env_off, ws_path))
                    self.assertNotIn("PCAP_AI_MODEL", env_off)

                    # Respect explicit PCAP_AI_MODEL
                    env_set = {"PCAP_AI_MODEL": "custom-model"}
                    self.assertIsNone(launcher.maybe_autoconfigure_local_ai(env_set, ws_path))
                    self.assertEqual(env_set["PCAP_AI_MODEL"], "custom-model")

                    # Respect workspace.json ai.enabled=false
                    ws_path.write_text(json.dumps({"ai": {"enabled": False}}), encoding="utf-8")
                    env_ws_off: dict[str, str] = {}
                    self.assertIsNone(launcher.maybe_autoconfigure_local_ai(env_ws_off, ws_path))
                    self.assertNotIn("PCAP_AI_MODEL", env_ws_off)
        finally:
            server.shutdown()
            server.server_close()

        # Closed loopback port returns None cleanly
        self.assertIsNone(launcher.discover_local_ollama_model(f"http://127.0.0.1:{port}", timeout=0.2))

    def test_standalone_tier1_discovery_without_trainer_and_allowed_origins(self) -> None:
        self.assertIsNotNone(launcher.discover_tier1_inference_root(ROOT))

        with tempfile.TemporaryDirectory() as tmp:
            fake_repo = Path(tmp) / "repo"
            fake_home = Path(tmp) / "home"
            (fake_repo / "tier1-inference" / "tier1_inference").mkdir(parents=True)
            (fake_repo / "tier1-inference" / "tier1_inference" / "server.py").write_text("# stub\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {}, clear=True):
                # Without checkpoints, Trainer-Pipeline, or --with-tier1, do not spawn unnecessary daemon
                self.assertIsNone(
                    launcher.resolve_tier1_launch_plan(
                        repo_root=fake_repo,
                        home_dir=fake_home,
                        port=9123,
                    )
                )

                # Explicit --with-tier1 selects standalone tier1_inference even without Trainer-Pipeline
                plan_fallback = launcher.resolve_tier1_launch_plan(
                    repo_root=fake_repo,
                    home_dir=fake_home,
                    port=9123,
                    with_tier1=True,
                )
                self.assertIsNotNone(plan_fallback)
                assert plan_fallback is not None
                cmd_fb, cwd_fb = plan_fallback
                self.assertEqual(cwd_fb, (fake_repo / "tier1-inference").resolve())
                self.assertIn("tier1_inference", cmd_fb)
                self.assertNotIn("traffic_tier1.serve_tier1", cmd_fb)

                # Placing trained checkpoints in standalone models/ auto-enables sidecar without --with-tier1
                oj_ckpt = fake_repo / "tier1-inference" / "models" / "openjev-tier1"
                et_ckpt = fake_home / "models" / "etbert-l7"
                oj_ckpt.mkdir(parents=True)
                et_ckpt.mkdir(parents=True)
                plan_weights = launcher.resolve_tier1_launch_plan(
                    repo_root=fake_repo,
                    home_dir=fake_home,
                    port=9123,
                )
                self.assertIsNotNone(plan_weights)
                assert plan_weights is not None
                cmd_w, _ = plan_weights
                self.assertIn("--openjev-checkpoint", cmd_w)
                self.assertIn(str(oj_ckpt.resolve()), cmd_w)
                self.assertIn("--etbert-checkpoint", cmd_w)
                self.assertIn(str(et_ckpt.resolve()), cmd_w)

                # --no-tier1 always suppresses auto-start
                self.assertIsNone(
                    launcher.resolve_tier1_launch_plan(
                        repo_root=fake_repo,
                        home_dir=fake_home,
                        port=9123,
                        no_tier1=True,
                        with_tier1=True,
                    )
                )

        if HAS_PYDANTIC_V2:
            from backend.app import config

            origin = "http://127.0.0.1:9123"
            origins = launcher._append_allowed_origin("", origin)
            origins = launcher._append_allowed_origin(origins, origin)
            self.assertEqual(origins, origin)
            with mock.patch.dict(
                os.environ,
                {
                    "PCAP_TRIAGE_ENABLED": "1",
                    "PCAP_TRIAGE_MODE": "etbert_openjev",
                    "PCAP_TRIAGE_ALLOWED_ORIGINS": origins,
                    "PCAP_TRIAGE_ENDPOINT_URL": f"{origin}/v1/systemone",
                    "PCAP_TRIAGE_ETBERT_ENABLED": "1",
                    "PCAP_TRIAGE_ETBERT_ENDPOINT_URL": f"{origin}/etbert/score",
                },
                clear=True,
            ):
                loaded = config.load_settings()
                self.assertEqual(loaded.triage.endpoint_url, f"{origin}/v1/systemone")
                self.assertEqual(loaded.triage.allowed_origins, [origin])

    def test_probe_tier1_health_and_wire_tier1_env_reuses_running_sidecar(self) -> None:
        class _Tier1Handler(BaseHTTPRequestHandler):
            payload: dict[str, object] = {
                "status": "ok",
                "service": "pcapscanner-tier1-inference",
                "device": "mps",
                "openjev_loaded": False,
                "openjev_mode": "state_fallback",
                "etbert_loaded": True,
                "etbert_mode": "neural_hf",
                "auth_required": False,
            }

            def do_GET(self) -> None:  # noqa: N802
                body = json.dumps(self.payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

        server = HTTPServer(("127.0.0.1", 0), _Tier1Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            health = launcher.probe_tier1_health(port)
            self.assertIsNotNone(health)
            assert health is not None
            self.assertEqual(health["device"], "mps")
            self.assertEqual(health["etbert_mode"], "neural_hf")

            # Unrelated HTTP 200 service is ignored
            _Tier1Handler.payload = {"status": "ok", "api_version": "1"}
            self.assertIsNone(launcher.probe_tier1_health(port))

            # Wire env for open-loopback sidecar (no token invented)
            env: dict[str, str] = {}
            origin = launcher.wire_tier1_env(env, port=port, token=None)
            self.assertEqual(origin, f"http://127.0.0.1:{port}")
            self.assertEqual(env["PCAP_TRIAGE_ENDPOINT_URL"], f"{origin}/v1/systemone")
            self.assertEqual(env["PCAP_TRIAGE_ETBERT_ENDPOINT_URL"], f"{origin}/etbert/score")
            self.assertEqual(env["PCAP_TRIAGE_ETBERT_ENABLED"], "1")
            self.assertEqual(env["PCAP_TRIAGE_ALLOWED_ORIGINS"], origin)
            self.assertNotIn("PCAP_TIER1_API_TOKEN", env)

            # Wire env with explicit bearer token
            launcher.wire_tier1_env(env, port=port, token="shared-secret-token")
            self.assertEqual(env["PCAP_TIER1_API_TOKEN"], "shared-secret-token")
        finally:
            server.shutdown()
            server.server_close()

        # Closed port returns None
        self.assertIsNone(launcher.probe_tier1_health(port))


@unittest.skipUnless(HAS_PYDANTIC_V2, "requires pydantic>=2 + fastapi TestClient")
class WorkspaceApiAndSpaTests(unittest.TestCase):
    def test_workspace_mutation_picker_and_single_port_spa(self) -> None:
        from fastapi.testclient import TestClient
        from backend.app import config, main

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws_file = tmp_path / "workspace.json"
            data_dir_a = tmp_path / "data-a"
            data_dir_b = tmp_path / "data-b"
            cap_dir = tmp_path / "captures"
            cap_dir.mkdir(parents=True)
            sample_pcap = cap_dir / "trace.pcap"
            sample_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 24)

            dist_dir = tmp_path / "dist"
            assets_dir = dist_dir / "assets"
            assets_dir.mkdir(parents=True)
            (dist_dir / "index.html").write_text("<html><body>PCAPSCANNER-SPA</body></html>", encoding="utf-8")
            (assets_dir / "main.js").write_text("console.log('ok');", encoding="utf-8")
            (tmp_path / "secret.txt").write_text("do-not-leak", encoding="utf-8")

            env = {
                "PCAP_API_TOKEN": "test-workspace-token-32-characters",
                "PCAP_WORKSPACE_CONFIG": str(ws_file),
                "PCAP_ENABLE_NATIVE_PICKER": "1",
                "PCAP_SERVE_UI": "1",
                "PCAP_DATA_DIR": str(data_dir_a),
            }
            with (
                mock.patch.dict(os.environ, env, clear=False),
                mock.patch.object(main, "REPO_ROOT", tmp_path),
            ):
                settings = config.load_settings()
                app = main.create_app(settings)
                client = TestClient(app, headers={"Authorization": "Bearer test-workspace-token-32-characters"})

                # Single-port SPA serving checks
                self.assertIn("PCAPSCANNER-SPA", client.get("/").text)
                self.assertIn("PCAPSCANNER-SPA", client.get("/analyze").text)
                self.assertEqual(client.get("/assets/main.js").status_code, 200)
                self.assertEqual(client.get("/assets/missing.js").status_code, 404)
                self.assertEqual(client.get("/api/v1/nonexistent").status_code, 404)
                self.assertNotIn("do-not-leak", client.get("/../secret.txt").text)

                # Initial workspace GET
                ws = client.get("/api/v1/system/workspace").json()
                self.assertEqual(ws["data_dir"], str(data_dir_a.resolve()))
                self.assertEqual(ws["native_picker_available"], main.detect_picker_backend() is not None)

                # Switch data_dir live via PUT /workspace
                sw = client.put("/api/v1/system/workspace", json={"data_dir": str(data_dir_b)})
                self.assertEqual(sw.status_code, 200, sw.text)
                self.assertEqual(app.state.settings.data_dir, data_dir_b.resolve())
                self.assertEqual(client.get("/api/v1/system/capabilities").json()["limits"]["data_dir"], str(data_dir_b.resolve()))

                # A selected file grants one-time access to exactly that file; no folder is added.
                with mock.patch.object(main, "pick_native_path", return_value=sample_pcap):
                    picked = client.post("/api/v1/system/pick-path", json={"purpose": "capture_file"})
                self.assertEqual(picked.status_code, 200, picked.text)
                body = picked.json()
                self.assertFalse(body["cancelled"])
                self.assertIsNone(body["selected_path"])
                self.assertTrue(body["file_grant_token"])
                self.assertEqual(
                    body["sha256"],
                    __import__("hashlib").sha256(sample_pcap.read_bytes()).hexdigest(),
                )
                self.assertEqual(body["workspace"]["local_ingest_roots"], [])
                registered = client.post(
                    "/api/v1/captures/local",
                    json={"file_grant_token": body["file_grant_token"]},
                )
                self.assertEqual(registered.status_code, 201, registered.text)
                self.assertEqual(registered.json()["sha256"], body["sha256"])
                replay = client.post(
                    "/api/v1/captures/local",
                    json={"file_grant_token": body["file_grant_token"]},
                )
                self.assertEqual(replay.status_code, 409)
                self.assertEqual(client.get("/api/v1/system/workspace").json()["local_ingest_roots"], [])

                with mock.patch.object(main, "pick_native_path", return_value=sample_pcap):
                    picked_again = client.post("/api/v1/system/pick-path", json={"purpose": "capture_file"})
                self.assertEqual(picked_again.status_code, 200, picked_again.text)
                sample_pcap.write_bytes(sample_pcap.read_bytes() + b"\x01")
                tampered = client.post(
                    "/api/v1/captures/local",
                    json={"file_grant_token": picked_again.json()["file_grant_token"]},
                )
                self.assertEqual(tampered.status_code, 409)

                # Cancel path keeps workspace unchanged
                with mock.patch.object(main, "pick_native_path", return_value=None):
                    cancelled = client.post("/api/v1/system/pick-path", json={"purpose": "data_dir"})
                self.assertEqual(cancelled.status_code, 200)
                self.assertTrue(cancelled.json()["cancelled"])


if __name__ == "__main__":
    unittest.main()
