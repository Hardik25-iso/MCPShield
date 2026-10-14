"""RAG-similarity detector: query the threat KB with the tool text; similarity to known payloads is risk.

No-ops when no retriever is injected (e.g. RAG ablation off, or the KB has not been built).
"""

from __future__ import annotations

from mcpshield.detectors.base import Detector, DetectorContext, content_text, focus_tool
from mcpshield.detectors.registry import register
from mcpshield.schemas import EventType, Evidence, MCPEvent, Verdict
from mcpshield.text_utils import reveal


class RagSimilarityDetector(Detector):
    name = "rag_similarity"
    family = "rag_similarity"
    stages = frozenset({EventType.TOOLS_LIST, EventType.TOOL_RESULT, EventType.RESOURCE_READ})
    scope = "tool"

    def detect(self, event: MCPEvent, ctx: DetectorContext) -> Verdict:
        if ctx.retriever is None:
            return self._verdict(0.0, [], [], event.tool)
        if event.type is EventType.TOOLS_LIST:
            tool = focus_tool(event)
            text, tool_name = (tool.description if tool else ""), (tool.name if tool else None)
        else:
            text, tool_name = content_text(event), event.tool
        if not text.strip():
            return self._verdict(0.0, [], [], tool_name)

        matches = ctx.retriever.search(reveal(text), top_k=ctx.settings.rag.top_k)
        if not matches:
            return self._verdict(0.0, [], [], tool_name)
        top = matches[0]
        risk = max(0.0, min(1.0, top.score or 0.0))
        reasons = [f"resembles known threat: {top.detail[:80]}"] if risk > 0 else []
        evidence = [Evidence(source=f"rag/{m.source}", detail=m.detail[:160], score=m.score) for m in matches[:3]]
        return self._verdict(risk, reasons, evidence, tool_name)


register(RagSimilarityDetector)
