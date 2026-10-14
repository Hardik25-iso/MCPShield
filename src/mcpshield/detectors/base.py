"""Detector interface and shared context. All detection logic lives in detectors; agents compose them."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Literal

from mcpshield.config import Settings
from mcpshield.llm import LLMClient
from mcpshield.schemas import EventType, MCPEvent, PatternSpec, Policies, SessionContext, ToolDescriptor, Verdict
from mcpshield.storage import Storage
from mcpshield.text_utils import CompiledPattern, compile_patterns

if TYPE_CHECKING:
    from mcpshield.rag.retriever import HybridRetriever

Scope = Literal["event", "tool"]


@dataclass
class DetectorContext:
    settings: Settings
    policies: Policies
    storage: Storage
    session: SessionContext
    llm: LLMClient
    retriever: HybridRetriever | None = None


class Detector(ABC):
    name: str
    family: str
    stages: frozenset[EventType]
    scope: Scope = "event"

    @abstractmethod
    def detect(self, event: MCPEvent, ctx: DetectorContext) -> Verdict: ...

    def _verdict(self, risk: float, reasons: list[str], evidence: list, tool: str | None = None) -> Verdict:
        return Verdict(
            detector=self.name,
            family=self.family,
            risk=max(0.0, min(1.0, risk)),
            reasons=reasons,
            evidence=evidence,
            tool=tool,
        )


@lru_cache(maxsize=16)
def _compile(key: tuple[tuple[str, str, float], ...]) -> list[CompiledPattern]:
    return compile_patterns([PatternSpec(label=label, regex=regex, weight=weight) for label, regex, weight in key])


def compiled(specs: list[PatternSpec]) -> list[CompiledPattern]:
    return _compile(tuple((s.label, s.regex, s.weight) for s in specs))


def focus_tool(event: MCPEvent) -> ToolDescriptor | None:
    return event.tools[0] if event.tools else None


def arguments_text(event: MCPEvent) -> str:
    return json.dumps(event.arguments, ensure_ascii=False)


def content_text(event: MCPEvent) -> str:
    return event.content or ""
