"""Instruction-pattern detector: imperative text aimed at the model inside tool descriptions or outputs."""

from __future__ import annotations

from mcpshield.detectors.base import Detector, DetectorContext, compiled, content_text, focus_tool
from mcpshield.detectors.registry import register
from mcpshield.schemas import EventType, Evidence, MCPEvent, Verdict
from mcpshield.text_utils import instruction_hits, reveal


class InstructionDetector(Detector):
    name = "instruction_patterns"
    family = "instruction"
    stages = frozenset({EventType.TOOLS_LIST, EventType.TOOL_RESULT, EventType.RESOURCE_READ})
    scope = "tool"

    def detect(self, event: MCPEvent, ctx: DetectorContext) -> Verdict:
        if event.type is EventType.TOOLS_LIST:
            tool = focus_tool(event)
            text, label, tool_name = (tool.description if tool else ""), "description", (tool.name if tool else None)
        else:
            text, label, tool_name = content_text(event), "output", event.tool

        hits = instruction_hits(reveal(text), compiled(ctx.policies.instruction_patterns))
        if not hits:
            return self._verdict(0.0, [], [], tool_name)
        risk = min(1.0, max(h.weight for h in hits) * (1.0 + 0.1 * (len(hits) - 1)))
        reasons = [f"instruction in tool {label}: {', '.join(sorted({h.label for h in hits}))}"]
        evidence = [
            Evidence(source=f"instruction/{h.label}", detail=h.text.strip()[:160], span=h.span) for h in hits[:5]
        ]
        return self._verdict(risk, reasons, evidence, tool_name)


register(InstructionDetector)
