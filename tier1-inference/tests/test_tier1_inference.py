from __future__ import annotations

import io
import json
import pickle
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

MODULE_ROOT = Path(__file__).resolve().parents[1]
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from tier1_inference import (  # noqa: E402
    CHOICE_LETTERS,
    OPENJEV_CLASS_CRITERIA,
    TRAFFIC_CLASSES,
    ETBertDatagramScorer,
    OpenJevTier1Scorer,
    bytes_to_etbert_bigram_tokens,
    cli,
    create_app,
    inspect_etbert_checkpoint,
    is_data_bearing_flow,
    prompts,
    score_state_calibrated_fallback,
)


def _write_fake_uer_mlm_zip(path: Path) -> None:
    """Create a ZIP PyTorch-like archive containing pickle opcode strings without executing anything."""
    payload = {
        "embedding.word_embedding.weight": "tensor_placeholder",
        "encoder.transformer.0.self_attn.weight": "tensor_placeholder",
        "encoder.transformer.11.self_attn.weight": "tensor_placeholder",
        "target.mlm.linear.weight": "tensor_placeholder",
    }
    pkl_bytes = pickle.dumps(payload, protocol=4)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("archive/data.pkl", pkl_bytes)


class StandalonePackagingAndSchemaTests(unittest.TestCase):
    def test_no_training_or_backend_imports_in_package(self) -> None:
        pkg_dir = MODULE_ROOT / "tier1_inference"
        forbidden = ("train_openjev_rl", "rlcd_reward", "eval_tier1", "backend.app", "traffic_tier1")
        for py_file in pkg_dir.glob("*.py"):
            src = py_file.read_text(encoding="utf-8")
            for needle in forbidden:
                self.assertNotIn(needle, src, f"{py_file.name} unexpectedly references {needle}")

    def test_schema_and_prompts_and_choice_token_ids(self) -> None:
        self.assertEqual(len(TRAFFIC_CLASSES), 10)
        self.assertEqual(len(OPENJEV_CLASS_CRITERIA), 10)
        self.assertEqual(len(CHOICE_LETTERS), 10)

        p1 = prompts.to_single_token_choice_prompt("[EV-1] FLOW TCP host_a->host_b pkts=8 bytes=1200")
        self.assertIn("A. Benign", p1)
        self.assertIn("J. Protocol_Tunnel", p1)
        self.assertTrue(p1.endswith("Answer letter:"))

        p2 = prompts.to_choice_prompt("[EV-2] ARP", include_criteria=False)
        self.assertTrue(p2.endswith("\\boxed{"))

        class _GoodTok:
            def encode(self, text: str, add_special_tokens: bool = False):  # noqa: ARG002
                return [200 + ord(text.strip()[-1])]

        ids = prompts.resolve_choice_token_ids(_GoodTok())
        self.assertEqual(len(ids), 10)
        self.assertEqual(len(set(ids)), 10)

        class _DupTok:
            def encode(self, text: str, add_special_tokens: bool = False):  # noqa: ARG002
                return [999]

        with self.assertRaises(ValueError):
            prompts.resolve_choice_token_ids(_DupTok())


class CheckpointInspectionAndFallbackTests(unittest.TestCase):
    def test_etbert_data_filter_and_bigram_tokens(self) -> None:
        self.assertFalse(is_data_bearing_flow({"kind": "arp", "protocol": "ARP", "packets": 10, "bytes": 600}))
        self.assertFalse(is_data_bearing_flow({"kind": "wlan", "protocol": "WLAN", "packets": 30, "bytes": 1200}))
        self.assertFalse(
            is_data_bearing_flow(
                {"kind": "flow", "protocol": "TCP", "dst_port": 443, "packets": 200, "bytes": 12000, "data_len_sum": 0}
            )
        )
        self.assertTrue(
            is_data_bearing_flow(
                {"kind": "flow", "protocol": "TLS", "dst_port": 443, "packets": 12, "bytes": 14000, "data_len_sum": 12000}
            )
        )
        self.assertEqual(bytes_to_etbert_bigram_tokens(b"\x01\x02\xab\xcd"), ["0102", "02ab", "abcd"])

    def test_inspect_uer_bin_and_hf_dir_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)

            # 1. Raw UER pre-trained .bin archive (honest no classification head)
            bin_path = tmp_dir / "pre-trained_model.bin"
            _write_fake_uer_mlm_zip(bin_path)
            info = inspect_etbert_checkpoint(bin_path)
            self.assertTrue(info["exists"])
            self.assertEqual(info["format"], "pytorch_zip")
            self.assertEqual(info["checkpoint_type"], "uer_pretrained_encoder")
            self.assertEqual(info["num_layers"], 12)
            self.assertFalse(info["has_classification_head"])
            self.assertFalse(info["is_hf_dir"])

            scorer = ETBertDatagramScorer(checkpoint_path=bin_path, device="cpu", require_weights=False)
            self.assertFalse(scorer.loaded_weights)
            scored = scorer.score_batch(
                [{"item_id": "i1", "kind": "http", "features": {"http_sqli_hits": 1, "packets": 4, "bytes": 900}}]
            )
            self.assertEqual(scored[0]["label"], "Web_Injection_Or_Tunnel")
            self.assertIn("uer-mlm-unfinetuned", scored[0]["model"])

            with self.assertRaises(ValueError):
                ETBertDatagramScorer(checkpoint_path=bin_path, device="cpu", require_weights=True)

            # 2. Valid HF directory metadata check
            hf_dir = tmp_dir / "etbert-hf"
            hf_dir.mkdir()
            (hf_dir / "config.json").write_text('{"architectures": ["BertForSequenceClassification"]}', encoding="utf-8")
            (hf_dir / "model.safetensors").write_bytes(b"\x00" * 16)
            hf_info = inspect_etbert_checkpoint(hf_dir)
            self.assertTrue(hf_info["is_hf_dir"])
            self.assertTrue(hf_info["has_classification_head"])

            # 3. Missing path fails closed
            with self.assertRaises(FileNotFoundError):
                ETBertDatagramScorer(checkpoint_path=tmp_dir / "missing.bin", device="cpu")
            with self.assertRaises(FileNotFoundError):
                OpenJevTier1Scorer(checkpoint_path=tmp_dir / "missing_dir", device="cpu")

    def test_state_fallback_10_classes(self) -> None:
        benign = score_state_calibrated_fallback("[EV-1] FLOW TCP h1:50000->h2:443 pkts=6 bytes=1800")
        self.assertEqual(benign["predicted_class"], "Benign")
        self.assertEqual(benign["decision"], "fast_benign")

        arp = score_state_calibrated_fallback("[EV-2] ARP ARP h1->m1 pkts=25 bytes=1500 arp_conflicts=2")
        self.assertEqual(arp["predicted_class"], "ARP_Spoofing")
        self.assertEqual(arp["decision"], "escalate_attack")

        wifi = score_state_calibrated_fallback("[EV-3] WLAN WLAN m1->ff pkts=35 bytes=2100 wlan_deauth=35")
        self.assertEqual(wifi["predicted_class"], "WiFi_Attack")
        self.assertEqual(wifi["decision"], "escalate_attack")

        dns = score_state_calibrated_fallback("[EV-4] DNS DNS h1->h2 pkts=10 bytes=900 q_len=28 q_ent=3.92 rcode=3")
        self.assertEqual(dns["predicted_class"], "DNS_Tunnel_DGA")

        c2 = score_state_calibrated_fallback(
            "[EV-5] FLOW TLS h1->h2 pkts=18 bytes=12000 etbert_lbl=C2_Beaconing etbert_conf=0.93"
        )
        self.assertEqual(c2["predicted_class"], "C2_Beaconing")
        self.assertAlmostEqual(sum(c2["probabilities"].values()), 1.0, places=3)


class MockedNeuralScorerTests(unittest.TestCase):
    def test_mocked_peft_openjev_and_hf_etbert_inference(self) -> None:
        """Verify neural tensor paths cleanly without requiring PyTorch wheel in sandbox."""

        class _FakeTensor:
            def __init__(self, data) -> None:
                self.data = data

            def to(self, _device: str):
                return self

            def sum(self, dim: int = -1):  # noqa: ARG002
                if isinstance(self.data[0], list):
                    return _FakeTensor([sum(row) for row in self.data])
                return _FakeTensor(sum(self.data))

            def clamp(self, min: int = 0):  # noqa: A002, ARG002
                if isinstance(self.data, list):
                    return _FakeTensor([max(min, x) for x in self.data])
                return self

            def __sub__(self, other: int):
                return _FakeTensor([x - other for x in self.data])

            def __getitem__(self, idx):
                if isinstance(idx, tuple) and len(idx) == 2:
                    b_idx, s_idx = idx
                    return _FakeTensor([self.data[b][s] for b, s in zip(b_idx.data, s_idx.data)])
                return _FakeTensor(self.data[idx])

            def index_select(self, dim: int = -1, index=None):  # noqa: ARG002
                ids = index.data
                return _FakeTensor([[row[i] for i in ids] for row in self.data])

            def float(self):
                return self

            def cpu(self):
                return self

            def numpy(self):
                raise AssertionError("numpy() must not be required by tier1_inference")

            def tolist(self):
                return self.data

        class _NullCtx:
            def __enter__(self):
                return None

            def __exit__(self, *_args):
                return False

        fake_torch = types.ModuleType("torch")
        fake_torch.float16 = "fp16"
        fake_torch.float32 = "fp32"
        fake_torch.long = "int64"
        fake_torch.cuda = types.SimpleNamespace(is_available=lambda: False)
        fake_torch.backends = types.SimpleNamespace(mps=types.SimpleNamespace(is_available=lambda: False))
        fake_torch.tensor = lambda data, **_kwargs: _FakeTensor(data)
        fake_torch.arange = lambda n, **_kwargs: _FakeTensor(list(range(n)))
        fake_torch.inference_mode = lambda: _NullCtx()

        def _fake_softmax(tensor: _FakeTensor, dim: int = -1):  # noqa: ARG001
            import math

            out_rows = []
            for row in tensor.data:
                m = max(row)
                exps = [math.exp(x - m) for x in row]
                tot = sum(exps) or 1.0
                out_rows.append([v / tot for v in exps])
            return _FakeTensor(out_rows)

        fake_torch.softmax = _fake_softmax

        class _FakeTokenizer:
            pad_token = None
            eos_token = "<eos>"
            padding_side = "left"

            def encode(self, text: str, add_special_tokens: bool = False):  # noqa: ARG002
                return [ord(text.strip()[-1]) - ord("A")]  # Maps A..J -> token ids 0..9

            def __call__(self, texts, **_kwargs):
                batch = len(texts)
                return {
                    "input_ids": _FakeTensor([[1, 2, 3, 4]] * batch),
                    "attention_mask": _FakeTensor([[1, 1, 1, 1]] * batch),
                }

        class _FakeCausalModel:
            eval_called = False

            def to(self, _dev: str):
                return self

            def eval(self):
                self.eval_called = True
                return self

            def __call__(self, **enc):
                batch = len(enc["input_ids"].data)
                # Build 12-vocab logits peaking strongly at index 1 (B -> ARP_Spoofing)
                row_logits = [-5.0] * 12
                row_logits[1] = 6.0
                return types.SimpleNamespace(logits=_FakeTensor([[row_logits] * 4] * batch))

        class _FakeSeqClfModel:
            config = types.SimpleNamespace(id2label={i: cls for i, cls in enumerate(TRAFFIC_CLASSES)})
            eval_called = False

            def to(self, _dev: str):
                return self

            def eval(self):
                self.eval_called = True
                return self

            def __call__(self, **enc):
                batch = len(enc["input_ids"].data)
                # Peak strongly at index 4 (DNS_Tunnel_DGA)
                row_logits = [-4.0] * 10
                row_logits[4] = 5.5
                return types.SimpleNamespace(logits=_FakeTensor([row_logits] * batch))

        fake_transformers = types.ModuleType("transformers")
        fake_transformers.AutoTokenizer = types.SimpleNamespace(from_pretrained=lambda *_a, **_kw: _FakeTokenizer())
        fake_transformers.AutoModelForCausalLM = types.SimpleNamespace(from_pretrained=lambda *_a, **_kw: _FakeCausalModel())
        fake_transformers.AutoModelForSequenceClassification = types.SimpleNamespace(
            from_pretrained=lambda *_a, **_kw: _FakeSeqClfModel()
        )

        fake_peft = types.ModuleType("peft")
        fake_peft.PeftConfig = types.SimpleNamespace(
            from_pretrained=lambda *_a, **_kw: types.SimpleNamespace(base_model_name_or_path="mock-base-qwen")
        )
        fake_peft.PeftModel = types.SimpleNamespace(from_pretrained=lambda base, *_a, **_kw: base)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            oj_dir = tmp_dir / "openjev-ckpt"
            (oj_dir / "lora_adapter").mkdir(parents=True)
            (oj_dir / "lora_adapter" / "adapter_config.json").write_text("{}", encoding="utf-8")
            (oj_dir / "tier1_config.json").write_text(json.dumps({"base_model": "mock-qwen"}), encoding="utf-8")

            et_dir = tmp_dir / "etbert-ckpt"
            et_dir.mkdir()
            (et_dir / "config.json").write_text("{}", encoding="utf-8")
            (et_dir / "model.safetensors").write_bytes(b"\x00" * 16)

            with mock.patch.dict(
                sys.modules,
                {"torch": fake_torch, "transformers": fake_transformers, "peft": fake_peft},
            ):
                oj = OpenJevTier1Scorer(checkpoint_path=oj_dir, device="cpu")
                self.assertTrue(oj.loaded_weights)
                self.assertEqual(oj.checkpoint_mode, "neural_lora")
                self.assertEqual(oj._tokenizer.padding_side, "right")
                self.assertTrue(oj._model.eval_called)

                oj_res = oj.score_states(["[EV-10] ARP ARP h1->m2 pkts=5 bytes=300"])
                self.assertEqual(oj_res[0]["predicted_class"], "ARP_Spoofing")
                self.assertGreater(oj_res[0]["confidence"], 0.98)

                et = ETBertDatagramScorer(checkpoint_path=et_dir, device="cpu")
                self.assertTrue(et.loaded_weights)
                self.assertTrue(et._model.eval_called)
                et_res = et.score_batch([{"item_id": "d1", "kind": "dns", "features": {"packets": 4}}])
                self.assertEqual(et_res[0]["label"], "DNS_Tunnel_DGA")
                self.assertGreater(et_res[0]["score"], 0.95)


class FastApiServerAndCliTests(unittest.TestCase):
    def test_endpoints_batch_limits_and_bearer_auth(self) -> None:
        app = create_app(device="cpu", max_items=2, api_token="unit-test-secret-token-42")
        client = TestClient(app)

        # /health does not expose secrets and reports honest fallback status
        health = client.get("/health")
        self.assertEqual(health.status_code, 200)
        h_body = health.json()
        self.assertEqual(h_body["status"], "ok")
        self.assertEqual(h_body["openjev_mode"], "state_fallback")
        self.assertEqual(h_body["etbert_mode"], "feature_fallback")
        self.assertTrue(h_body["auth_required"])
        self.assertEqual(len(h_body["classes"]), 10)

        # Protected endpoints reject missing or invalid bearer tokens
        self.assertEqual(client.post("/classify", json={"items": []}).status_code, 401)
        self.assertEqual(
            client.post("/v1/systemone", json={"state": "hi"}, headers={"Authorization": "Bearer wrong"}).status_code,
            401,
        )

        auth_headers = {"Authorization": "Bearer unit-test-secret-token-42"}

        # /etbert/score
        et_resp = client.post(
            "/etbert/score",
            headers=auth_headers,
            json={
                "model": "etbert-l7-datagram",
                "items": [
                    {
                        "item_id": "ev_1",
                        "kind": "http",
                        "features": {"http_xss_hits": 2, "packets": 5, "bytes": 1600, "dst_port": 80},
                    }
                ],
            },
        )
        self.assertEqual(et_resp.status_code, 200)
        self.assertEqual(et_resp.json()["results"][0]["label"], "Web_Injection_Or_Tunnel")

        # /classify
        cls_resp = client.post(
            "/classify",
            headers=auth_headers,
            json={
                "items": [
                    {"evidence_id": "EV-1", "state": "[EV-1] FLOW TCP h1:50000->h2:443 pkts=6 bytes=1800"},
                    {"evidence_id": "EV-2", "state": "[EV-2] WLAN WLAN m1->ff pkts=40 bytes=2400 wlan_deauth=40"},
                ]
            },
        )
        self.assertEqual(cls_resp.status_code, 200)
        rows = cls_resp.json()["results"]
        self.assertEqual(rows[0]["decision"], "fast_benign")
        self.assertEqual(rows[1]["predicted_class"], "WiFi_Attack")

        # Enforce bounded batch cap (max_items=2 -> 3 items rejected with 413)
        too_big = client.post(
            "/classify",
            headers=auth_headers,
            json={"items": [{"evidence_id": f"EV-{i}", "state": "ok"} for i in range(3)]},
        )
        self.assertEqual(too_big.status_code, 413)

        # /v1/systemone
        sys1 = client.post(
            "/v1/systemone",
            headers=auth_headers,
            json={
                "model": "openjev-cal-tier1",
                "state": "[EV-4] ARP ARP h1->m2 pkts=20 bytes=1200 arp_conflicts=2",
                "questions": {"traffic_class": {"type": "choice", "criteria": OPENJEV_CLASS_CRITERIA}},
            },
        )
        self.assertEqual(sys1.status_code, 200)
        ans = sys1.json()["answers"]["traffic_class"]
        self.assertEqual(ans["prediction"], "ARP_Spoofing")
        self.assertEqual(ans["decision"], "escalate_attack")

    def test_require_weights_fails_closed_when_omitted(self) -> None:
        with self.assertRaises(RuntimeError):
            create_app(device="cpu", require_weights=True)

        stderr = io.StringIO()
        with mock.patch("sys.stderr", stderr):
            rc = cli.main(["--require-weights"])
        self.assertEqual(rc, 2)
        self.assertIn("require_weights=True", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
