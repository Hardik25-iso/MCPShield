"""The LangGraph shield pipeline: plan -> rules -> (grey-zone) deep -> critic -> audit.

Conditional edges implement the fast path vs deep path. The agents own the detection logic; the nodes here
only sequence them and assemble the `Decision`. ESCALATE is returned as a terminal decision; the UI resolves
it to allow/deny via `ShieldCore.resolve_escalation` (no checkpointer/interrupt needed for the PoC).
"""

from __future__ import annotations

import time
from collections.abc import Callable

from langgraph.graph import END, START, StateGraph

from mcpshield.agents.auditor import Auditor
from mcpshield.agents.critic import Critic
from mcpshield.agents.intent_verifier import IntentVerifier
from mcpshield.agents.orchestrator import Orchestrator
from mcpshield.agents.output_sanitizer import OutputSanitizer
from mcpshield.agents.registry_auditor import RegistryAuditor
from mcpshield.config import Settings
from mcpshield.core.state import ShieldState
from mcpshield.detectors.base import DetectorContext
from mcpshield.schemas import Action, Decision, EventType, MCPEvent, Verdict, new_id

CtxFactory = Callable[[MCPEvent], DetectorContext]


class ShieldPipeline:
    def __init__(self, settings: Settings, ctx_factory: CtxFactory, disabled: frozenset[str], llm_checks: bool) -> None:
        self._settings = settings
        self._ctx_factory = ctx_factory
        self._llm_checks = llm_checks
        self._orchestrator = Orchestrator(disabled)
        self._registry = RegistryAuditor()
        self._intent = IntentVerifier()
        self._sanitizer = OutputSanitizer()
        self._critic = Critic(settings)
        self._auditor = Auditor()
        self._app = self._build()

    # ------------------------------------------------------------ graph wiring

    def _build(self):
        graph = StateGraph(ShieldState)
        graph.add_node("plan", self._plan_node)
        graph.add_node("rules", self._rules_node)
        graph.add_node("deep", self._deep_node)
        graph.add_node("critic", self._critic_node)
        graph.add_node("audit", self._audit_node)
        graph.add_edge(START, "plan")
        graph.add_edge("plan", "rules")
        graph.add_conditional_edges("rules", self._route, {"deep": "deep", "critic": "critic"})
        graph.add_edge("deep", "critic")
        graph.add_edge("critic", "audit")
        graph.add_edge("audit", END)
        return graph.compile()

    def run(self, event: MCPEvent) -> ShieldState:
        return self._app.invoke(
            {"event": event, "verdicts": [], "stage_latency_ms": {}, "llm_calls": 0, "deep": False}
        )

    # ------------------------------------------------------------ nodes

    def _plan_node(self, state: ShieldState) -> ShieldState:
        return {"plan": self._orchestrator.plan(state["event"])}

    def _rules_node(self, state: ShieldState) -> ShieldState:
        event, plan = state["event"], state["plan"]
        ctx = self._ctx_factory(event)
        names = set(plan.rule_detectors)
        start = time.perf_counter()
        quarantined: list[str] = []
        sanitized: str | None = None
        filtered = list(event.tools)

        if event.type is EventType.TOOLS_LIST:
            verdicts = self._registry.rule_verdicts(event, ctx, names)
            quar = self._registry.quarantined_tools(event, verdicts, self._settings.risk.thresholds.block)
            quarantined = sorted(quar)
            filtered = self._registry.filter_tools(event.tools, quar)
        elif event.type is EventType.TOOL_CALL:
            verdicts = self._intent.rule_verdicts(event, ctx, names)
        else:
            verdicts = self._sanitizer.rule_verdicts(event, ctx, names)
            self._sanitizer.taint(event, ctx)

        rule_report = self._critic.aggregate(verdicts)
        latency = {"rules": round((time.perf_counter() - start) * 1000, 3)}
        return {
            "verdicts": verdicts,
            "rule_report": rule_report,
            "quarantined": quarantined,
            "filtered_tools": filtered,
            "sanitized_content": sanitized,
            "stage_latency_ms": {**state["stage_latency_ms"], **latency},
            "llm_calls": state["llm_calls"] + sum(v.llm_calls for v in verdicts),
        }

    def _route(self, state: ShieldState) -> str:
        plan = state["plan"]
        if not plan.deep_detectors or not self._llm_checks:
            return "critic"
        return "deep" if self._critic.in_grey_zone(state["rule_report"].rule_score) else "critic"

    def _deep_node(self, state: ShieldState) -> ShieldState:
        event = state["event"]
        ctx = self._ctx_factory(event)
        start = time.perf_counter()
        judge_event = self._worst_tool_event(event, state["verdicts"])
        risk, confidence, votes = self._critic.self_consistency(judge_event, ctx)
        verdict = Verdict(
            detector="llm_judge",
            family="llm_judge",
            agent="critic",
            risk=risk,
            reasons=[f"self-consistency over {len(votes)} samples, agreement {confidence:.2f}"] if votes else [],
            llm_calls=len(votes),
        )
        latency = {"deep": round((time.perf_counter() - start) * 1000, 3)}
        return {
            "verdicts": [*state["verdicts"], verdict],
            "confidence": confidence,
            "votes": votes,
            "deep": True,
            "stage_latency_ms": {**state["stage_latency_ms"], **latency},
            "llm_calls": state["llm_calls"] + len(votes),
        }

    def _critic_node(self, state: ShieldState) -> ShieldState:
        event = state["event"]
        start = time.perf_counter()
        action, report = self._critic.decide(event, state["verdicts"])
        report = report.model_copy(update={"confidence": state.get("confidence", 1.0), "votes": state.get("votes", [])})

        sanitized = state.get("sanitized_content")
        if action is Action.SANITIZE and event.content is not None:
            sanitized = self._sanitizer.sanitize(event.content, self._ctx_factory(event))

        decision = Decision(
            event_id=event.id,
            action=action,
            risk=report,
            path=self._path(state),
            verdicts=[v for v in state["verdicts"] if v.risk > 0],
            explanation=self._explain(action, report, state["verdicts"]),
            sanitized_content=sanitized,
            allowed_tools=state.get("filtered_tools", []),
            quarantined_tools=state.get("quarantined", []),
            escalation_id=new_id() if action is Action.ESCALATE else None,
        )
        latency = {"critic": round((time.perf_counter() - start) * 1000, 3)}
        return {
            "action": action,
            "report": report,
            "decision": decision,
            "stage_latency_ms": {**state["stage_latency_ms"], **latency},
        }

    def _audit_node(self, state: ShieldState) -> ShieldState:
        event = state["event"]
        self._auditor.record(
            event,
            state["plan"],
            state["decision"],
            self._ctx_factory(event),
            state["stage_latency_ms"],
            state["llm_calls"],
        )
        return {}

    # ------------------------------------------------------------ helpers

    def _worst_tool_event(self, event: MCPEvent, verdicts: list[Verdict]) -> MCPEvent:
        if event.type is not EventType.TOOLS_LIST or not event.tools:
            return event
        risk_by_tool = {v.tool: v.risk for v in verdicts if v.tool}
        worst = max(event.tools, key=lambda t: risk_by_tool.get(t.name, 0.0))
        return event.model_copy(update={"tools": [worst], "tool": worst.name})

    def _path(self, state: ShieldState):
        from mcpshield.schemas import PathKind

        return PathKind.DEEP if state.get("deep") else PathKind.FAST

    def _explain(self, action: Action, report, verdicts: list[Verdict]) -> str:
        fired = sorted((v for v in verdicts if v.risk > 0), key=lambda v: v.risk, reverse=True)
        reasons = [r for v in fired for r in v.reasons][:4]
        detail = "; ".join(reasons) if reasons else "no detectors fired"
        return f"{action.value} at risk {report.score:.2f} (rule {report.rule_score:.2f}). {detail}"


def available_stages() -> list[EventType]:
    return list(EventType)
