"""Intent Verifier — Executor-side guard, goal-based agent (handles TOOL_CALL).

Derives and stores the user's intent in session memory, then runs the policy, sensitive-data and taint
detectors against the call. The LLM judge is added only on the deep path by the graph.
"""

from __future__ import annotations

from mcpshield.detectors.base import DetectorContext
from mcpshield.detectors.registry import get_detectors
from mcpshield.llm import REQUEST_TAG, tagged
from mcpshield.schemas import IntentResult, MCPEvent, Verdict


class IntentVerifier:
    name = "intent_verifier"

    def ensure_intent(self, ctx: DetectorContext) -> IntentResult:
        if ctx.session.intent is None:
            derived = ctx.llm.structured(tagged(REQUEST_TAG, ctx.session.user_request), IntentResult)
            ctx.session.intent = derived or IntentResult(intent=ctx.policies.default_intent, confidence=0.0)
        return ctx.session.intent

    def rule_verdicts(self, event: MCPEvent, ctx: DetectorContext, detector_names: set[str]) -> list[Verdict]:
        self.ensure_intent(ctx)
        detectors = [d for d in get_detectors(event.type) if d.name in detector_names]
        return [d.detect(event, ctx) for d in detectors]
