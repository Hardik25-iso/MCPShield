"""Shared helpers and renderers for the Streamlit app. Pages import from here to avoid duplication."""

from __future__ import annotations

from functools import lru_cache

import streamlit as st

from mcpshield.config import Settings, get_settings
from mcpshield.core.shield_core import Ablation, ShieldCore
from mcpshield.data_loader import load_policies
from mcpshield.llm import make_llm
from mcpshield.schemas import Action, Decision, TraceStep
from mcpshield.storage import Storage

_ACTION_COLOR = {
    Action.ALLOW: "#1e8e3e",
    Action.SANITIZE: "#e8a000",
    Action.ESCALATE: "#e8710a",
    Action.BLOCK: "#c5221f",
}


@lru_cache(maxsize=1)
def settings() -> Settings:
    return get_settings()


def storage() -> Storage:
    return Storage(settings().paths.db_path)


def make_shield(ablation: Ablation | None = None) -> ShieldCore:
    s = settings()
    return ShieldCore(s, storage(), make_llm(s, load_policies(s)), ablation=ablation)


def backend_sidebar() -> None:
    s = settings()
    with st.sidebar:
        st.markdown("### MCPShield")
        st.caption("Multi-agent runtime firewall for MCP")
        st.divider()
        st.markdown(f"**Backend:** `{s.llm.backend}`")
        st.markdown(f"**Judge model:** `{s.llm.judge_model}`")
        st.markdown(f"**Fast model:** `{s.llm.fast_model}`")
        st.markdown(f"**RAG embedder:** `{s.rag.embedder}`")
        st.markdown(f"**Sanitize mode:** `{s.shield.sanitize_mode}`")
        st.divider()
        st.caption("Scenario data and LLM calls are synthetic/local. No paid APIs.")


def action_badge(action: Action) -> str:
    color = _ACTION_COLOR[action]
    style = f"background:{color};color:white;padding:2px 10px;border-radius:10px;font-weight:600"
    return f"<span style='{style}'>{action.value}</span>"


def render_decision(decision: Decision, title: str = "") -> None:
    if title:
        st.markdown(f"**{title}**")
    st.markdown(
        f"{action_badge(decision.action)} &nbsp; risk **{decision.risk.score:.2f}** "
        f"(rule {decision.risk.rule_score:.2f}, path {decision.path.value})",
        unsafe_allow_html=True,
    )
    st.caption(decision.explanation)
    if decision.quarantined_tools:
        st.markdown(f"Quarantined tools: {', '.join(f'`{t}`' for t in decision.quarantined_tools)}")
    fired = [v for v in decision.verdicts if v.risk > 0]
    if fired:
        with st.expander(f"Detector verdicts ({len(fired)})", expanded=False):
            for v in sorted(fired, key=lambda x: x.risk, reverse=True):
                st.markdown(f"- **{v.detector}** ({v.family}) risk `{v.risk:.2f}` - {'; '.join(v.reasons) or 'fired'}")
                for ev in v.evidence[:3]:
                    st.caption(f"    - {ev.source}: {ev.detail}")


def render_trace(trace: list[TraceStep]) -> None:
    icon = {"thought": "·", "action": ">", "observation": "<", "final": "=", "shield": "!"}
    for step in trace:
        prefix = icon.get(step.kind, "-")
        if step.kind == "action":
            st.markdown(f"`{prefix}` **{step.content}**")
            if step.arguments:
                st.caption(f"    args: {step.arguments}")
        elif step.kind == "final":
            st.success(f"{prefix} {step.content}")
        else:
            st.markdown(f"`{prefix}` {step.content}")
