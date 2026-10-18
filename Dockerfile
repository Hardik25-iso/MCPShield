# MCPShield - Streamlit demo image for Render (and any Docker host).
# Installs core dependencies only; the RAG layer falls back to the deterministic
# hashing embedder and lexical reranker, so no model downloads are required at boot.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Copy the whole project, then install editable so the package stays rooted at
# /app/src. config.py derives the repo root from its own file location
# (parents[2]); a non-editable install into site-packages would point that at the
# Python lib dir, so config.yaml and the data/var paths would not be found.
COPY . .

RUN pip install -e . && chmod +x deploy/start.sh

# Resolve the package from source and config from the repo root regardless of
# install location (start.sh sets these too; kept here for any other entrypoint).
ENV PYTHONPATH=/app/src \
    MCPSHIELD_CONFIG=/app/config.yaml

# Render provides $PORT; default to 8501 for local `docker run`.
ENV PORT=8501
EXPOSE 8501

CMD ["./deploy/start.sh"]
