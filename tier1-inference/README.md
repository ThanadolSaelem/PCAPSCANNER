# `tier1-inference` — Standalone Tier-1 Network Traffic Inference Module

**Inference-only** runtime extracted from `Trainer-Pipeline` for **PCAPSCANNER**. Contains zero training scripts, RL/GRPO loops, or dataset preparation code, so this directory can be zipped, containerized, or installed (`pip install ./tier1-inference`) and shipped directly to customers alongside trained model checkpoints.

## What You Deliver to Customers

Just this folder (`tier1-inference/`) plus your trained model folder(s):

```text
tier1-inference/
├── tier1_inference/        # Pure inference package (ET-BERT + OpenJev LoRA/HF)
├── models/                 # Optional: place openjev-tier1/ and/or etbert-l7/ here
├── pyproject.toml
├── requirements.txt        # Lightweight HTTP / calibrated fallback only
├── requirements-neural.txt # Full PyTorch/Transformers/PEFT runtime (MPS/CUDA/CPU)
├── Dockerfile
├── docker-compose.yml
└── start-tier1.sh
```

## Endpoints Exposed

- `GET /health` — Readiness, resolved compute device (`mps`/`cuda`/`cpu`), loaded neural modes, 10 classes.
- `POST /etbert/score` — L7 data-bearing flow scoring (`TLS`/`HTTP`/`DNS`/`flow`).
- `POST /classify` — Batch OpenJev 10-class traffic triage.
- `POST /v1/systemone` — Single-item OpenJev `/v1/systemone` compatible endpoint.

## Running Standalone

### Option A: One-click script

```bash
cd tier1-inference
chmod +x start-tier1.sh

# With trained HuggingFace / LoRA checkpoints placed under ./models/:
./start-tier1.sh --openjev-checkpoint ./models/openjev-tier1 --etbert-checkpoint ./models/etbert-l7

# Enforce failing closed unless neural weights actually load:
./start-tier1.sh --openjev-checkpoint ./models/openjev-tier1 --require-weights
```

### Option B: Python module / pip install

```bash
cd tier1-inference
python3 -m venv .venv
source .venv/bin/activate

# Lightweight runtime (calibrated fallback only):
pip install -r requirements.txt
python -m tier1_inference --host 127.0.0.1 --port 9000

# Full Neural runtime (Apple Silicon MPS, NVIDIA CUDA, or CPU):
pip install -r requirements-neural.txt
PYTORCH_ENABLE_MPS_FALLBACK=1 python -m tier1_inference \
  --host 127.0.0.1 --port 9000 --device auto \
  --openjev-checkpoint /path/to/openjev-tier1 \
  --etbert-checkpoint /path/to/etbert-l7
```

## Connecting `PCAPSCANNER`

When `PCAPSCANNER` and `tier1-inference` are in the same workspace or `PCAPSCANNER/models/{openjev-tier1,etbert-l7}` exists, running `Start PCAPSCANNER.command` or `python -m backend.app.launcher` auto-discovers `tier1-inference` without requiring `Trainer-Pipeline`.

To connect `PCAPSCANNER` to a separate `tier1-inference` host/container manually:

```bash
export PCAP_TRIAGE_ENABLED=1
export PCAP_TRIAGE_MODE=etbert_openjev
export PCAP_TRIAGE_ENDPOINT_URL="http://127.0.0.1:9000/v1/systemone"
export PCAP_TRIAGE_ETBERT_ENABLED=1
export PCAP_TRIAGE_ETBERT_ENDPOINT_URL="http://127.0.0.1:9000/etbert/score"
export PCAP_TRIAGE_ALLOWED_ORIGINS="http://127.0.0.1:9000"
```

## Note on Raw `pre-trained_model.bin` (UER MLM)

If you point `--etbert-checkpoint` to a raw UER masked-language-model archive (`pre-trained_model.bin`) rather than a fine-tuned HuggingFace sequence-classification checkpoint directory (`config.json` + `model.safetensors`), `/health` reports `has_classification_head: false` and `etbert_loaded: false`, and falls back safely to calibrated L7 telemetry scoring unless `--require-weights` is set.
