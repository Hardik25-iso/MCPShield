"""Critic / Arbiter — utility-based agent.

Aggregates detector verdicts into one risk score with a weighted noisy-OR plus a server-reputation prior,
maps the score to ALLOW / SANITIZE / ESCALATE / BLOCK using config thresholds, and in the grey zone applies
self-consistency by re-running the LLM-judge detector n times and majority-voting (agreement is confidence).
It also enforces the output-validation guardrail: every detector verdict is schema-validated, and a failed
LLM judge falls back to the conservative risk rather than crashing the pipeline.
"""

from __future__ import annotations

import statistics

from mcpshield.detectors.base import DetectorContext
from mcpshield.detectors.registry import get_detectors
from mcpshield.schemas import Action, EventType, MCPEvent, RiskReport, Verdict


class Critic:
    name = "critic"

    def __init__(self, settings) -> None:
        self._risk = settings.risk
        self._settings = settings

    def aggregate(self, verdicts: list[Verdict]) -> RiskReport:
        """Weighted noisy-OR over detector families, with the reputation verdict applied as a prior."""
        weights = self._risk.weights
        reputation = max((v.risk for v in verdicts if v.family == "reputation"), default=0.0)
        components: dict[str, float] = {}
        for verdict in verdicts:
            if verdict.risk <= 0 or verdict.family == "reputation":
                continue
            weighted = verdict.risk * weights.get(verdict.family, 0.5)
            components[verdict.family] = max(components.get(verdict.family, 0.0), weighted)
        product = 1.0
        for value in components.values():
            product *= 1.0 - value
        rule_score = 1.0 - product
        prior = self._risk.reputation_weight * reputation
        score = min(1.0, rule_score + prior * (1.0 - rule_score))
        return RiskReport(score=score, rule_score=rule_score, components=components, reputation_prior=prior)

    def in_grey_zone(self, rule_score: float) -> bool:
        low, high = self._risk.grey_zone
        return low <= rule_score <= high

    def self_consistency(self, event: MCPEvent, ctx: DetectorContext) -> tuple[float, float, list[bool]]:
        """Re-run the llm_judge detector n times and majority-vote. Returns (risk, confidence, votes)."""
        judges = [d for d in get_detectors(event.type) if d.name == "llm_judge"]
        if not judges:
            return 0.0, 1.0, []
        judge = judges[0]
        samples = [judge.detect(event, ctx) for _ in range(self._risk.self_consistency_n)]
        votes = [s.risk > 0.5 for s in samples]
        agreement = max(votes.count(True), votes.count(False)) / len(votes)
        risk = statistics.fmean(s.risk for s in samples)
        return risk, agreement, votes

    def decide(self, event: MCPEvent, verdicts: list[Verdict]) -> tuple[Action, RiskReport]:
        valid = [v for v in verdicts if isinstance(v, Verdict)]
        report = self.aggregate(valid)
        action = self._map(report.score, event.type)
        return action, report

    def _map(self, score: float, event_type: EventType) -> Action:
        t = self._risk.thresholds
        if score >= t.block:
            return Action.BLOCK
        if score >= t.escalate:
            return Action.ESCALATE
        if score >= t.sanitize:
            # Sanitizing only makes sense for content; for a tool call, degrade to escalate.
            return (
                Action.SANITIZE if event_type in (EventType.TOOL_RESULT, EventType.RESOURCE_READ) else Action.ESCALATE
            )
        return Action.ALLOW
