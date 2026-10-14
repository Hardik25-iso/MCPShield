"""Threat-KB ingestion: chunk the curated sources, embed them, and index into a persistent Chroma collection.

The collection metadata records the embedder and reranker ids; `open_collection` rebuilds the index when the
configured ids no longer match, so switching backends never silently serves stale vectors. The BM25 half of
hybrid retrieval is rebuilt at load time from the documents stored here, so there is no second index on disk.
"""

from __future__ import annotations

import logging
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, cast

import chromadb

from mcpshield.config import Settings
from mcpshield.data_loader import read_yaml
from mcpshield.rag.embeddings import Embedder, Reranker, make_embedder, make_reranker

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Chunk:
    id: str
    text: str
    source: str
    attack_class: str
    kind: str


def _chunk_text(text: str, size: int, overlap: int) -> list[str]:
    words = text.split()
    if len(words) <= size:
        return [text.strip()] if text.strip() else []
    step = max(1, size - overlap)
    chunks = [" ".join(words[i : i + size]) for i in range(0, len(words), step)]
    return [c for c in chunks if c.strip()]


def collect_chunks(settings: Settings) -> list[Chunk]:
    kb_dir = settings.paths.threat_kb_dir
    chunks: list[Chunk] = []
    for path in sorted((kb_dir / "classes").glob("*.md")):
        for i, piece in enumerate(
            _chunk_text(path.read_text("utf-8"), settings.rag.chunk_size, settings.rag.chunk_overlap)
        ):
            chunks.append(Chunk(f"{path.stem}#{i}", piece, path.stem, path.stem, "summary"))
    examples = read_yaml(kb_dir / "examples.yaml")["examples"]
    for i, example in enumerate(examples):
        chunks.append(Chunk(f"example#{i}", example["text"], "examples", example["class"], "example"))
    return chunks


def _client(settings: Settings) -> chromadb.ClientAPI:
    settings.paths.chroma_dir.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(settings.paths.chroma_dir))


def build_kb(settings: Settings) -> dict[str, Any]:
    embedder = make_embedder(settings)
    reranker = make_reranker(settings)
    chunks = collect_chunks(settings)
    client = _client(settings)
    with suppress(Exception):
        client.delete_collection(settings.rag.collection)
    collection = client.create_collection(
        settings.rag.collection,
        metadata={"embedder": embedder.id, "reranker": reranker.id},
        embedding_function=None,
    )
    collection.add(
        ids=[c.id for c in chunks],
        embeddings=cast(Any, embedder.embed([c.text for c in chunks])),
        documents=[c.text for c in chunks],
        metadatas=[{"source": c.source, "attack_class": c.attack_class, "kind": c.kind} for c in chunks],
    )
    return {"chunks": len(chunks), "embedder": embedder.id, "reranker": reranker.id}


def open_collection(settings: Settings) -> tuple[chromadb.Collection, Embedder, Reranker] | None:
    """Return the KB collection with a matching embedder/reranker, or None if it is missing or stale."""
    embedder = make_embedder(settings)
    reranker = make_reranker(settings)
    try:
        collection = _client(settings).get_collection(settings.rag.collection, embedding_function=None)
    except Exception:
        return None
    meta = collection.metadata or {}
    if meta.get("embedder") != embedder.id or meta.get("reranker") != reranker.id:
        log.warning("KB backend mismatch (have %s, want %s/%s); rebuild with `make kb`", meta, embedder.id, reranker.id)
        return None
    return collection, embedder, reranker
