"""Hidden-text detector: zero-width chars, homoglyphs, base64 blobs, HTML comments, hidden tags."""

from __future__ import annotations

from mcpshield.detectors.base import Detector, DetectorContext, content_text, focus_tool
from mcpshield.detectors.registry import register
from mcpshield.schemas import EventType, Evidence, MCPEvent, Verdict
from mcpshield.text_utils import (
    decode_base64_blobs,
    find_homoglyphs,
    find_html_comments,
    find_tagged_blocks,
    find_zero_width,
)


class HiddenTextDetector(Detector):
    name = "hidden_text"
    family = "hidden_text"
    stages = frozenset({EventType.TOOLS_LIST, EventType.TOOL_RESULT, EventType.RESOURCE_READ})
    scope = "tool"

    def detect(self, event: MCPEvent, ctx: DetectorContext) -> Verdict:
        if event.type is EventType.TOOLS_LIST:
            tool = focus_tool(event)
            text, tool_name = (tool.description if tool else ""), (tool.name if tool else None)
        else:
            text, tool_name = content_text(event), event.tool

        evidence: list[Evidence] = []
        reasons: list[str] = []
        risk = 0.0

        if zw := find_zero_width(text):
            risk = max(risk, 0.85)
            reasons.append(f"{len(zw)} zero-width character(s)")
            evidence.append(Evidence(source="hidden/zero_width", detail=f"{len(zw)} zero-width chars", score=0.85))
        if glyphs := find_homoglyphs(text):
            risk = max(risk, 0.8)
            reasons.append(f"{len(glyphs)} homoglyph(s) in Latin words")
            evidence.append(Evidence(source="hidden/homoglyph", detail=str([g[1] for g in glyphs[:8]]), score=0.8))
        for (start, end), decoded in decode_base64_blobs(text):
            risk = max(risk, 0.8)
            reasons.append("base64-encoded hidden text")
            evidence.append(Evidence(source="hidden/base64", detail=decoded[:160], span=(start, end), score=0.8))
        for (start, end), comment in find_html_comments(text):
            risk = max(risk, 0.6)
            reasons.append("HTML comment")
            evidence.append(Evidence(source="hidden/html_comment", detail=comment[:160], span=(start, end), score=0.6))
        for (start, end), tag, body in find_tagged_blocks(text, ctx.policies.hidden_tag_names):
            risk = max(risk, 0.7)
            reasons.append(f"hidden <{tag}> block")
            evidence.append(Evidence(source=f"hidden/tag/{tag}", detail=body[:160], span=(start, end), score=0.7))

        return self._verdict(risk, reasons, evidence, tool_name)


register(HiddenTextDetector)
