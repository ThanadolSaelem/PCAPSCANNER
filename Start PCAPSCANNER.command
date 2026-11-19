#!/usr/bin/env bash
# Double-click this file in macOS Finder (or run ./start.sh) to launch PCAPSCANNER in 1 click.
set -euo pipefail

# Finder launches .command scripts without user shell PATHs (Homebrew / Wireshark).
export PATH="/opt/homebrew/bin:/usr/local/bin:/Applications/Wireshark.app/Contents/MacOS:${HOME}/Library/pnpm:${HOME}/.local/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

pause_on_error() {
  local exit_code=$?
  if [[ ${exit_code} -ne 0 ]] && [[ -t 0 ]]; then
    echo ""
    read -r -p "PCAPSCANNER stopped with an error (code ${exit_code}). Press Enter to close..." _
  fi
}
trap pause_on_error EXIT

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

BASE_PY="$(pick_python || true)"
if [[ -z "${BASE_PY}" ]]; then
  echo "ERROR: Python 3.10+ is required."
  echo "macOS fix: brew install python@3.12 wireshark pnpm"
  exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "WARN: tshark not found yet — CSV mode still works, install Wireshark for full PCAP/PCAPNG:"
  echo "      brew install wireshark   (or install Wireshark.app into /Applications)"
fi

VENV_DIR="${SCRIPT_DIR}/.venv-backend"
VENV_PY="${VENV_DIR}/bin/python"
if [[ ! -x "${VENV_PY}" ]] || ! "${VENV_PY}" -c 'import fastapi, uvicorn, pydantic, yaml, httpx; assert int(pydantic.__version__.split(".")[0]) >= 2' >/dev/null 2>&1; then
  echo "[PCAPSCANNER] Setting up Python virtual environment (.venv-backend) with ${BASE_PY}..."
  if [[ ! -x "${VENV_PY}" ]]; then
    "${BASE_PY}" -m venv "${VENV_DIR}"
  fi
  "${VENV_PY}" -m pip install --upgrade pip
  "${VENV_PY}" -m pip install -r "${SCRIPT_DIR}/backend/requirements.txt"
fi

# Build frontend automatically on first run or whenever src/ changed
NEED_BUILD=0
if [[ ! -f "${SCRIPT_DIR}/dist/index.html" ]]; then
  NEED_BUILD=1
elif find "${SCRIPT_DIR}/src" "${SCRIPT_DIR}/index.html" "${SCRIPT_DIR}/package.json" "${SCRIPT_DIR}/vite.config.ts" -newer "${SCRIPT_DIR}/dist/index.html" -print -quit 2>/dev/null | grep -q .; then
  NEED_BUILD=1
fi

if [[ "${NEED_BUILD}" -eq 1 ]]; then
  echo "[PCAPSCANNER] Building Web UI bundle (dist/)..."
  if command -v pnpm >/dev/null 2>&1; then
    [[ -d "${SCRIPT_DIR}/node_modules" ]] || pnpm install --frozen-lockfile
    pnpm build
  elif command -v npm >/dev/null 2>&1; then
    [[ -d "${SCRIPT_DIR}/node_modules" ]] || npm install
    npm run build
  else
    echo "ERROR: pnpm or npm (Node.js) is required on first build of the Web UI."
    echo "macOS fix: brew install node pnpm"
    exit 1
  fi
fi

echo "[PCAPSCANNER] Starting workbench (API + Worker + UI)..."
"${VENV_PY}" -m backend.app.launcher "$@"
