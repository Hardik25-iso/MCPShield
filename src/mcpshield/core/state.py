"""Internal LangGraph state for the shield pipeline. Carries schema objects, never raw dicts between nodes."""

from __future__ import annotations

from typing import TypedDict

from mcpshield.schemas import Action, CheckPlan, Decision, MCPEvent, RiskReport, ToolDescriptor, Verdict


class ShieldState(TypedDict, total=False):
    event: MCPEvent
    plan: CheckPlan
    verdicts: list[Verdict]
    rule_report: RiskReport
    report: RiskReport
    action: Action
    decision: Decision
    quarantined: list[str]
    filtered_tools: list[ToolDescriptor]
    sanitized_content: str | None
    confidence: float
    votes: list[bool]
    stage_latency_ms: dict[str, float]
    llm_calls: int
    deep: bool
