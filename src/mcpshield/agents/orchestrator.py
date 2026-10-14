"""Orchestrator — Planner, utility-based agent.

Classifies each MCP event and builds a hierarchical check plan: which detector families run on the fast
(rule-only) path and which are reserved for the deep (LLM) path. The fast/deep choice is a latency/risk
utility trade-off resolved after the rule risk is known (in the graph's conditional edge), using the
configurable grey zone; the rationale is recorded in the plan.
"""

from __future__ import annotations

from mcpshield.detectors.registry import get_detectors
from mcpshield.schemas import CheckPlan, EventType, MCPEvent

_AGENTS_BY_STAGE = {
    EventType.TOOLS_LIST: ["registry_auditor", "critic", "auditor"],
    EventType.TOOL_CALL: ["intent_verifier", "critic", "auditor"],
    EventType.TOOL_RESULT: ["output_sanitizer", "critic", "auditor"],
    EventType.RESOURCE_READ: ["output_sanitizer", "critic", "auditor"],
}


class Orchestrator:
    name = "orchestrator"

    def __init__(self, disabled: frozenset[str]) -> None:
        self._disabled = disabled

    def plan(self, event: MCPEvent) -> CheckPlan:
        detectors = get_detectors(event.type, disabled=self._disabled)
        rule = [d.name for d in detectors if d.family != "llm_judge"]
        deep = [d.name for d in detectors if d.family == "llm_judge"]
        return CheckPlan(
            event_type=event.type,
            agents=_AGENTS_BY_STAGE[event.type],
            rule_detectors=rule,
            deep_detectors=deep,
            rationale="fast path runs rule detectors; deep path adds the LLM judge only in the grey zone",
        )
