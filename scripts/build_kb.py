"""Build the threat knowledge base (Chroma vector index + BM25 corpus)."""

from __future__ import annotations

from mcpshield.config import get_settings
from mcpshield.logging_setup import setup_logging
from mcpshield.rag.ingest import build_kb


def main() -> None:
    settings = get_settings()
    setup_logging(settings, "build_kb")
    summary = build_kb(settings)
    print(
        f"threat KB built: {summary['chunks']} chunks, embedder={summary['embedder']}, reranker={summary['reranker']}"
    )


if __name__ == "__main__":
    main()
