"""Cross-tool detector: split payloads across descriptions and shadowing of other servers' tools."""

from __future__ import annotations

import re

from mcpshield.detectors.base import Detector, DetectorContext, compiled
from mcpshield.detectors.registry import register
from mcpshield.schemas import EventType, Evidence, MCPEvent, Verdict
from mcpshield.text_utils import instruction_hits, reveal

# Privileged finance tools a utility description should never reference (shadowing signal).
_SHADOW_TARGETS = ("send_payment", "send_email", "read_file")


class CrossToolDetector(Detector):
    name = "cross_tool"
    family = "cross_tool"
    stages = frozenset({EventType.TOOLS_LIST})
    scope = "event"

    def detect(self, event: MCPEvent, ctx: DetectorContext) -> Verdict:
        if len(event.tools) < 1:
            return self._verdict(0.0, [], [])
        revealed = {t.name: reveal(t.description) for t in event.tools}
        patterns = compiled(ctx.policies.instruction_patterns)

        evidence: list[Evidence] = []
        reasons: list[str] = []
        risk = 0.0

        # Shadowing: a tool's description names a privileged tool it does not own.
        for name, text in revealed.items():
            owned = name.split("__")[-1]
            for target in _SHADOW_TARGETS:
                if target != owned and re.search(rf"\b{target}\b", text, re.I):
                    risk = max(risk, 0.85)
                    reasons.append(f"{name} references privileged tool '{target}'")
                    evidence.append(Evidence(source="cross_tool/shadow", detail=f"{name} -> {target}", score=0.85))

        # Split payload: instruction fragments spread so no single description looks dangerous,
        # but the concatenation does.
        per_tool = {name: len(instruction_hits(text, patterns)) for name, text in revealed.items()}
        combined = "\n".join(revealed.values())
        combined_hits = instruction_hits(combined, patterns)
        if combined_hits and max(per_tool.values(), default=0) == 0 and len(event.tools) > 1:
            risk = max(risk, 0.8)
            labels = sorted({h.label for h in combined_hits})
            reasons.append(f"instruction appears only when descriptions are concatenated: {labels}")
            evidence.append(Evidence(source="cross_tool/split_payload", detail=" | ".join(labels), score=0.8))

        return self._verdict(risk, reasons, evidence)


register(CrossToolDetector)
