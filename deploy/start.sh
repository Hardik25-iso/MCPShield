#!/usr/bin/env bash
# Render start command: bootstrap generated data and the threat KB on first boot
# (both live under gitignored dirs), then launch the Streamlit UI bound to $PORT.
set -euo pipefail

cd "$(dirname "$0")/.."

# Generate synthetic finance records if absent (idempotent, seeded).
if [ ! -f data/synthetic/invoices.json ]; then
  echo "[start] generating synthetic data"
  python scripts/generate_data.py
fi

# Build the threat knowledge base if absent. Uses the deterministic hashing
# embedder and lexical reranker when neural models are not installed.
if [ ! -d var/chroma ]; then
  echo "[start] building threat KB"
  python scripts/build_kb.py
fi

echo "[start] launching Streamlit on port ${PORT:-8501}"
exec streamlit run app/streamlit_app.py \
  --server.port "${PORT:-8501}" \
  --server.address 0.0.0.0 \
  --server.headless true \
  --server.enableCORS false \
  --server.enableXsrfProtection false \
  --browser.gatherUsageStats false
