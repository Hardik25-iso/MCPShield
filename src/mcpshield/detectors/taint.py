"""Taint detector: high-risk arguments whose values originate from tainted tool output, not the user."""

from __future__ import annotations

from mcpshield.detectors.base import Detector, DetectorContext
from mcpshield.detectors.registry import register
from mcpshield.schemas import EventType, Evidence, MCPEvent, Verdict
from mcpshield.text_utils import normalize


class TaintDetector(Detector):
    name = "taint"
    family = "taint"
    stages = frozenset({EventType.TOOL_CALL})
    scope = "event"

    def detect(self, event: MCPEvent, ctx: DetectorContext) -> Verdict:
        tool = (event.tool or "").split(ctx.settings.servers.namespace_sep)[-1]
        watched = ctx.policies.high_risk_tools.get(tool)
        if not watched or not ctx.session.taint:
            return self._verdict(0.0, [], [], event.tool)

        tainted = [normalize(t.value) for t in ctx.session.taint]
        request = normalize(ctx.session.user_request)
        reasons: list[str] = []
        evidence: list[Evidence] = []
        for field in watched:
            value = normalize(str(event.arguments.get(field, "")))
            if len(value) < 3 or value in request:
                continue
            for i, blob in enumerate(tainted):
                if value in blob:
                    reasons.append(f"argument '{field}' came from tainted tool output, not the user request")
                    evidence.append(
                        Evidence(
                            source=f"taint/{field}", detail=f"{field}={value[:40]} from {ctx.session.taint[i].source}"
                        )
                    )
                    break

        risk = 0.8 if reasons else 0.0
        return self._verdict(risk, reasons, evidence, event.tool)


register(TaintDetector)
