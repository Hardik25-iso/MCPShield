"""Sensitive-data detector: secrets/PII in tool-call arguments (PAN, Aadhaar, API keys, .env secrets)."""

from __future__ import annotations

from mcpshield.detectors.base import Detector, DetectorContext, arguments_text, compiled
from mcpshield.detectors.registry import register
from mcpshield.schemas import EventType, Evidence, MCPEvent, Verdict
from mcpshield.text_utils import instruction_hits, reveal


class SensitiveDataDetector(Detector):
    name = "sensitive_data"
    family = "sensitive_data"
    stages = frozenset({EventType.TOOL_CALL})
    scope = "event"

    def detect(self, event: MCPEvent, ctx: DetectorContext) -> Verdict:
        text = reveal(arguments_text(event))
        hits = instruction_hits(text, compiled(ctx.policies.sensitive_patterns))
        if not hits:
            return self._verdict(0.0, [], [], event.tool)
        risk = min(1.0, max(h.weight for h in hits))
        labels = sorted({h.label for h in hits})
        evidence = [Evidence(source=f"sensitive/{h.label}", detail=_mask(h.text), span=h.span) for h in hits[:6]]
        return self._verdict(risk, [f"sensitive data in arguments: {labels}"], evidence, event.tool)


def _mask(text: str) -> str:
    text = text.strip()
    return text if len(text) <= 8 else f"{text[:4]}…{text[-2:]}"


register(SensitiveDataDetector)
