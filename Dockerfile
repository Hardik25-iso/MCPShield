# MCPShield - Streamlit demo image for Render (and any Docker host).
# Installs core dependencies only; the RAG layer falls back to the deterministic
# hashing embedder and lexical reranker, so no model downloads are required at boot.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install the package and its core dependencies from pyproject.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

# Copy the rest of the project (app, data, scripts, config).
COPY . .

RUN chmod +x deploy/start.sh

# Render provides $PORT; default to 8501 for local `docker run`.
ENV PORT=8501
EXPOSE 8501

CMD ["./deploy/start.sh"]
