"""ShieldCore — the one shield implementation. The proxy, evaluation harness and Streamlit app all use it.

It owns short-term session memory, builds a `DetectorContext` per event, runs the LangGraph pipeline, and
exposes a transport-agnostic API. An ablation config enables/disables each agent and detector family.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcpshield.config import Settings
from mcpshield.core.graph import ShieldPipeline
from mcpshield.data_loader import load_policies
from mcpshield.detectors.base import DetectorContext
from mcpshield.detectors.registry import load_builtin_detectors
from mcpshield.llm import LLMClient, make_llm
from mcpshield.rag.retriever import HybridRetriever, open_retriever
from mcpshield.schemas import (
    Action,
    Decision,
    EventType,
    MCPEvent,
    Policies,
    SessionContext,
    ToolDescriptor,
    new_id,
)
from mcpshield.storage import Storage

load_builtin_detectors()

# Detector families switched off when a given agent is ablated out.
_AGENT_FAMILIES = {
    "registry_auditor": {"rug_pull", "cross_tool", "schema_params"},
    "intent_verifier": {"policy", "taint"},
    "output_sanitizer": set(),  # sanitizer is handled by the stage dispatch, not a family toggle
}


@dataclass
class Ablation:
    registry_auditor: bool = True
    intent_verifier: bool = True
    output_sanitizer: bool = True
    llm_checks: bool = True
    rag: bool = True
    extra_disabled: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_settings(cls, settings: Settings) -> Ablation:
        a = settings.shield.ablation
        return cls(
            a.registry_auditor,
            a.intent_verifier,
            a.output_sanitizer,
            a.llm_checks,
            a.rag,
            frozenset(settings.shield.disabled_detectors),
        )

    @classmethod
    def preset(cls, name: str) -> Ablation:
        """Named ablation rungs for the evaluation matrix (cumulative capability)."""
        presets = {
            "static_only": cls(True, False, False, False, False),
            "plus_intent_verifier": cls(True, True, False, False, False),
            "plus_output_sanitizer": cls(True, True, True, False, False),
            "full": cls(True, True, True, True, True),
        }
        if name not in presets:
            raise ValueError(f"unknown ablation preset: {name}")
        return presets[name]

    def disabled_detectors(self) -> frozenset[str]:
        """Resolve the ablation into a concrete set of detector names to switch off."""
        from mcpshield.detectors.registry import all_detectors

        families_off: set[str] = set()
        if not self.rag:
            families_off.add("rag_similarity")
        if not self.llm_checks:
            families_off.add("llm_judge")
        for agent, families in _AGENT_FAMILIES.items():
            if not getattr(self, agent):
                families_off |= families
        disabled = set(self.extra_disabled)
        disabled |= {det.name for det in all_detectors() if det.family in families_off}
        return frozenset(disabled)


class ShieldCore:
    def __init__(
        self,
        settings: Settings,
        storage: Storage,
        llm: LLMClient | None = None,
        retriever: HybridRetriever | None = None,
        ablation: Ablation | None = None,
    ) -> None:
        self._settings = settings
        self._storage = storage
        self._policies: Policies = load_policies(settings)
        self._llm = llm or make_llm(settings, self._policies)
        self._ablation = ablation or Ablation.from_settings(settings)
        self._retriever = retriever if self._ablation.rag else None
        if self._retriever is None and self._ablation.rag:
            self._retriever = open_retriever(settings)
        self._session = SessionContext()
        self._pipeline = ShieldPipeline(
            settings, self._make_ctx, self._ablation.disabled_detectors(), self._ablation.llm_checks
        )

    # ------------------------------------------------------------ session memory

    def start_session(self, user_request: str) -> SessionContext:
        self._session = SessionContext(session_id=new_id(), user_request=user_request)
        self._storage.save_session(self._session)
        return self._session

    @property
    def session(self) -> SessionContext:
        return self._session

    @property
    def llm(self) -> LLMClient:
        return self._llm

    @property
    def retriever(self) -> HybridRetriever | None:
        return self._retriever

    def _make_ctx(self, event: MCPEvent) -> DetectorContext:
        return DetectorContext(
            settings=self._settings,
            policies=self._policies,
            storage=self._storage,
            session=self._session,
            llm=self._llm,
            retriever=self._retriever,
        )

    # ------------------------------------------------------------ public API

    def inspect(self, event: MCPEvent) -> Decision:
        event = event.model_copy(update={"session_id": self._session.session_id})
        state = self._pipeline.run(event)
        decision: Decision = state["decision"]
        self._storage.save_session(self._session)
        return decision

    def filter_tools(self, server: str, tools: list[ToolDescriptor]) -> tuple[Decision, list[ToolDescriptor]]:
        event = MCPEvent(session_id=self._session.session_id, type=EventType.TOOLS_LIST, server=server, tools=tools)
        decision = self.inspect(event)
        return decision, decision.allowed_tools

    def sanitize_result(self, server: str, tool: str, content: str) -> tuple[Decision, str]:
        event = MCPEvent(
            session_id=self._session.session_id, type=EventType.TOOL_RESULT, server=server, tool=tool, content=content
        )
        decision = self.inspect(event)
        if decision.action is Action.BLOCK or (
            decision.action is Action.ESCALATE and self._settings.shield.escalate_counts_as_blocked
        ):
            return decision, "[blocked by MCPShield: untrusted tool output withheld]"
        return decision, decision.sanitized_content if decision.sanitized_content is not None else content

    def read_resource(self, server: str, uri: str, content: str) -> tuple[Decision, str]:
        event = MCPEvent(
            session_id=self._session.session_id, type=EventType.RESOURCE_READ, server=server, uri=uri, content=content
        )
        decision = self.inspect(event)
        return decision, decision.sanitized_content if decision.sanitized_content is not None else content

    def resolve_escalation(self, approve: bool) -> Action:
        return Action.ALLOW if approve else Action.BLOCK
