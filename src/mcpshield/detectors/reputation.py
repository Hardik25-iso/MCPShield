"""Reputation detector: a prior from a server's past blocked incidents (long-term memory)."""

from __future__ import annotations

from mcpshield.detectors.base import Detector, DetectorContext
from mcpshield.detectors.registry import register
from mcpshield.schemas import EventType, Evidence, MCPEvent, Verdict


class ReputationDetector(Detector):
    name = "reputation"
    family = "reputation"
    stages = frozenset({EventType.TOOLS_LIST, EventType.TOOL_CALL, EventType.TOOL_RESULT, EventType.RESOURCE_READ})
    scope = "event"

    def detect(self, event: MCPEvent, ctx: DetectorContext) -> Verdict:
        count = ctx.storage.incident_count(event.server)
        if count == 0:
            return self._verdict(0.0, [], [], event.tool)
        saturation = max(1, ctx.settings.risk.reputation_saturation)
        risk = min(1.0, count / saturation)
        reason = f"server '{event.server}' has {count} prior blocked incident(s)"
        return self._verdict(risk, [reason], [Evidence(source="reputation", detail=reason, score=risk)], event.tool)


register(ReputationDetector)
