"""Hybrid threat-KB retriever: BM25 + vector candidates fused with RRF, then cross-encoder re-ranking.

`search` returns scored `Evidence`; `multi_hop` re-queries with combined fragments for split-payload checks.
BM25 is built in memory from the collection's documents at load time.
"""

from __future__ import annotations

from dataclasses import dataclass

from rank_bm25 import BM25Okapi

from mcpshield.config import Settings
from mcpshield.rag.embeddings import Embedder, Reranker
from mcpshield.rag.ingest import open_collection
from mcpshield.schemas import Evidence
from mcpshield.text_utils import tokenize


@dataclass(frozen=True)
class _Doc:
    id: str
    text: str
    attack_class: str
    kind: str


class HybridRetriever:
    def __init__(self, settings: Settings, collection, embedder: Embedder, reranker: Reranker) -> None:
        self._settings = settings
        self._embedder = embedder
        self._reranker = reranker
        payload = collection.get(include=["documents", "metadatas", "embeddings"])
        self._docs = [
            _Doc(doc_id, text, meta.get("attack_class", ""), meta.get("kind", ""))
            for doc_id, text, meta in zip(payload["ids"], payload["documents"], payload["metadatas"], strict=True)
        ]
        self._embeddings = [list(vec) for vec in payload["embeddings"]]
        self._bm25 = BM25Okapi([tokenize(d.text) for d in self._docs]) if self._docs else None

    @property
    def embedder_id(self) -> str:
        return self._embedder.id

    @property
    def reranker_id(self) -> str:
        return self._reranker.id

    def _vector_ranking(self, query: str) -> list[int]:
        (qvec,) = self._embedder.embed([query])
        scored = sorted(range(len(self._docs)), key=lambda i: self._cosine(qvec, self._embeddings[i]), reverse=True)
        return scored[: self._settings.rag.candidates]

    def _bm25_ranking(self, query: str) -> list[int]:
        if self._bm25 is None:
            return []
        scores = self._bm25.get_scores(tokenize(query))
        return sorted(range(len(self._docs)), key=lambda i: scores[i], reverse=True)[: self._settings.rag.candidates]

    def search(self, query: str, top_k: int | None = None) -> list[Evidence]:
        if not self._docs:
            return []
        top_k = top_k or self._settings.rag.top_k
        fused = self._rrf(self._bm25_ranking(query), self._vector_ranking(query))
        candidates = [self._docs[i] for i in fused[: max(top_k * 3, self._settings.rag.top_k)]]
        rerank_scores = self._reranker.score(query, [d.text for d in candidates])
        ranked = sorted(zip(candidates, rerank_scores, strict=True), key=lambda pair: pair[1], reverse=True)
        return [
            Evidence(source=f"{doc.attack_class}/{doc.kind}", detail=doc.text, score=round(float(score), 4))
            for doc, score in ranked[:top_k]
        ]

    def multi_hop(self, fragments: list[str], top_k: int | None = None) -> list[Evidence]:
        """Re-query with the combined fragments to surface a split payload the pieces hide individually."""
        return self.search(" ".join(fragments), top_k=top_k)

    def _rrf(self, *rankings: list[int]) -> list[int]:
        k = self._settings.rag.rrf_k
        scores: dict[int, float] = {}
        for ranking in rankings:
            for rank, idx in enumerate(ranking):
                scores[idx] = scores.get(idx, 0.0) + 1.0 / (k + rank + 1)
        return sorted(scores, key=lambda i: scores[i], reverse=True)

    @staticmethod
    def _cosine(a: list[float], b: list[float]) -> float:
        return sum(x * y for x, y in zip(a, b, strict=True))


def open_retriever(settings: Settings) -> HybridRetriever | None:
    opened = open_collection(settings)
    if opened is None:
        return None
    collection, embedder, reranker = opened
    return HybridRetriever(settings, collection, embedder, reranker)
