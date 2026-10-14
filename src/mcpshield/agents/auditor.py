"""Auditor — monitoring agent.

Writes one `AuditRecord` per event (inputs, detectors run, verdicts with reasons/evidence, final decision,
per-stage latency, LLM calls, backend/model) and records a blocked event as an incident so the reputation
prior reflects it. This is the explainability source for the UI.
"""

from __future__ import annotations

from mcpshield.detectors.base import DetectorContext
from mcpshield.schemas import AuditRecord, CheckPlan, Decision, Incident, MCPEvent


class Auditor:
    name = "auditor"

    def record(
        self,
        event: MCPEvent,
        plan: CheckPlan,
        decision: Decision,
        ctx: DetectorContext,
        stage_latency_ms: dict[str, float],
        llm_calls: int,
    ) -> AuditRecord:
        record = AuditRecord(
            session_id=event.session_id,
            event=event,
            plan=plan,
            decision=decision,
            stage_latency_ms=stage_latency_ms,
            total_latency_ms=round(sum(stage_latency_ms.values()), 3),
            llm_calls=llm_calls,
            backend=ctx.llm.backend,
            model=ctx.llm.model,
        )
        ctx.storage.write_audit(record)
        if decision.blocks:
            ctx.storage.add_incident(
                Incident(
                    server=event.server,
                    tool=event.tool,
                    action=decision.action,
                    risk=decision.risk.score,
                    summary=decision.explanation[:200],
                )
            )
        return record
