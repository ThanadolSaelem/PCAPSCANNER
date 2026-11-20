#!/usr/bin/env bash
# Standalone one-click runner for the customer-deliverable Tier-1 Inference Service.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

export PYTORCH_ENABLE_MPS_FALLBACK="${PYTORCH_ENABLE_MPS_FALLBACK:-1}"

pick_python() {
  for cand in "${PYTHON:-}" python3.12 python3.11 python3.10 python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    [[ -n "${cand}" ]] || continue
    if command -v "${cand}" >/dev/null 2>&1; then
      if "${cand}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
        command -v "${cand}"
        return 0
      fi
    fi
  done
  return 1
}

INSTALL_MODE="light"
PASS_ARGS=()
for arg in "$@"; do
  if [[ "${arg}" == "--neural" ]]; then
    INSTALL_MODE="neural"
  else
    PASS_ARGS+=("${arg}")
    if [[ "${arg}" == --openjev-checkpoint* || "${arg}" == --etbert-checkpoint* ]]; then
      INSTALL_MODE="neural"
    fi
  fi
done

if [[ -n "${TIER1_OPENJEV_CHECKPOINT:-}" || -n "${TIER1_ETBERT_CHECKPOINT:-}" ]]; then
  INSTALL_MODE="neural"
fi

if [[ -z "${TIER1_OPENJEV_CHECKPOINT:-}" && -d "${SCRIPT_DIR}/models/openjev-tier1" ]]; then
  export TIER1_OPENJEV_CHECKPOINT="${SCRIPT_DIR}/models/openjev-tier1"
  INSTALL_MODE="neural"
fi
if [[ -z "${TIER1_ETBERT_CHECKPOINT:-}" && -d "${SCRIPT_DIR}/models/etbert-l7" ]]; then
  export TIER1_ETBERT_CHECKPOINT="${SCRIPT_DIR}/models/etbert-l7"
  INSTALL_MODE="neural"
fi

VENV_DIR="${SCRIPT_DIR}/.venv"
VENV_PY="${VENV_DIR}/bin/python"
if [[ ! -x "${VENV_PY}" ]]; then
  BASE_PY="$(pick_python || true)"
  if [[ -z "${BASE_PY}" ]]; then
    echo "ERROR: Python 3.10+ is required." >&2
    exit 1
  fi
  echo "[tier1-inference] Creating virtual environment at ${VENV_DIR}..."
  "${BASE_PY}" -m venv "${VENV_DIR}"
  "${VENV_PY}" -m pip install --upgrade pip
fi

REQ_FILE="${SCRIPT_DIR}/requirements.txt"
CHECK_IMPORTS="import fastapi, uvicorn, pydantic"
if [[ "${INSTALL_MODE}" == "neural" ]]; then
  REQ_FILE="${SCRIPT_DIR}/requirements-neural.txt"
  CHECK_IMPORTS="import fastapi, uvicorn, pydantic, torch, transformers, peft"
fi

if ! "${VENV_PY}" -c "${CHECK_IMPORTS}" >/dev/null 2>&1; then
  echo "[tier1-inference] Installing dependencies from $(basename "${REQ_FILE}")..."
  "${VENV_PY}" -m pip install -r "${REQ_FILE}"
fi

exec "${VENV_PY}" -m tier1_inference "${PASS_ARGS[@]}"
