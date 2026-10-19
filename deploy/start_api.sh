#!/usr/bin/env bash
# Render start command for the live-analyzer API. Bootstraps generated data and the
# threat KB on first boot (both gitignored), then runs the FastAPI app bound to $PORT.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
export PYTHONPATH="${ROOT}/src:${PYTHONPATH:-}"
export MCPSHIELD_CONFIG="${MCPSHIELD_CONFIG:-${ROOT}/config.yaml}"
export MCPSHIELD_LLM__BACKEND="${MCPSHIELD_LLM__BACKEND:-mock}"

echo "[api] boot | root=${ROOT} | config exists=$([ -f "${MCPSHIELD_CONFIG}" ] && echo yes || echo NO)"

if [ ! -f data/synthetic/invoices.json ]; then
  echo "[api] generating synthetic data"
  python scripts/generate_data.py
fi
if [ ! -d var/chroma ]; then
  echo "[api] building threat KB"
  python scripts/build_kb.py
fi

echo "[api] starting uvicorn on port ${PORT:-8000}"
exec uvicorn api.main:app --host 0.0.0.0 --port "${PORT:-8000}"
