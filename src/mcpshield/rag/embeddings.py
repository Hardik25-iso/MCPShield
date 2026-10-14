"""Embedder and reranker with an offline deterministic fallback.

`sentence-transformers` provides neural embeddings (all-MiniLM-L6-v2) and a cross-encoder reranker when it
is installed and the models can be downloaded. Where that is unavailable (CI, blocked networks), the factory
falls back to a deterministic feature-hashing embedder and a token-overlap reranker, so the whole RAG path
runs offline. The active ids are reported so figures and the KB collection can record which backend was used.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from itertools import pairwise
from typing import Protocol

from mcpshield.config import Settings

log = logging.getLogger(__name__)
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


class Embedder(Protocol):
    id: str
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class Reranker(Protocol):
    id: str

    def score(self, query: str, documents: list[str]) -> list[float]: ...


class HashingEmbedder:
    """Deterministic feature-hashing embedder over word unigrams and bigrams, L2-normalized."""

    def __init__(self, dim: int) -> None:
        self.id = f"hashing-{dim}"
        self.dim = dim

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._one(text) for text in texts]

    def _one(self, text: str) -> list[float]:
        tokens = _tokens(text)
        features = tokens + [f"{a}_{b}" for a, b in pairwise(tokens)]
        vector = [0.0] * self.dim
        for feature in features:
            digest = hashlib.md5(feature.encode()).digest()
            index = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(v * v for v in vector)) or 1.0
        return [v / norm for v in vector]


class LexicalReranker:
    """Token-overlap reranker (Jaccard over query/document tokens); the offline cross-encoder stand-in."""

    id = "lexical"

    def score(self, query: str, documents: list[str]) -> list[float]:
        q = set(_tokens(query))
        scores = []
        for doc in documents:
            d = set(_tokens(doc))
            scores.append(len(q & d) / len(q | d) if q and d else 0.0)
        return scores


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(model_name)
        self.id = model_name
        self.dim = int(self._model.get_sentence_embedding_dimension())

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [v.tolist() for v in self._model.encode(texts, normalize_embeddings=True)]


class CrossEncoderReranker:
    def __init__(self, model_name: str) -> None:
        from sentence_transformers import CrossEncoder

        self._model = CrossEncoder(model_name)
        self.id = model_name

    def score(self, query: str, documents: list[str]) -> list[float]:
        if not documents:
            return []
        raw = self._model.predict([(query, doc) for doc in documents])
        return [1.0 / (1.0 + math.exp(-float(s))) for s in raw]


def make_embedder(settings: Settings) -> Embedder:
    choice = settings.rag.embedder
    if choice in {"auto", "sentence-transformers"}:
        try:
            return SentenceTransformerEmbedder(settings.rag.embed_model)
        except Exception as exc:
            if choice == "sentence-transformers":
                raise
            log.warning("neural embedder unavailable (%s); using hashing embedder", exc)
    return HashingEmbedder(settings.rag.hashing_dim)


def make_reranker(settings: Settings) -> Reranker:
    choice = settings.rag.reranker
    if choice in {"auto", "cross-encoder"}:
        try:
            return CrossEncoderReranker(settings.rag.rerank_model)
        except Exception as exc:
            if choice == "cross-encoder":
                raise
            log.warning("cross-encoder unavailable (%s); using lexical reranker", exc)
    return LexicalReranker()
