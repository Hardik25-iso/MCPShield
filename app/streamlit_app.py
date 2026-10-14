"""MCPShield Streamlit app - Overview page and entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import backend_sidebar

st.set_page_config(page_title="MCPShield", layout="wide")
backend_sidebar()

st.title("MCPShield")
st.subheader("A multi-agent runtime firewall for MCP-connected AI agents")

st.markdown(
    """
Enterprises connect AI agents to tools through **MCP (Model Context Protocol)** servers. The agent treats
tool metadata and tool outputs as trusted context, so a malicious or compromised MCP server can hijack it:
tool poisoning, shadowing, rug pulls, indirect prompt injection, split payloads and data exfiltration.

**MCPShield** is a transparent proxy between an MCP host agent and its MCP servers. To the agent it is an MCP
server; to the real servers it is an MCP client. Every tool listing, tool call and tool result flows through a
LangGraph multi-agent pipeline that decides **ALLOW / SANITIZE / BLOCK / ESCALATE**, logs a full explanation
and reports metrics.
"""
)

st.divider()
left, right = st.columns(2)
with left:
    st.markdown("### Demo scenario")
    st.markdown(
        "A **Finance Ops Assistant** for an Indian SME reads invoices, looks up vendors, pays vendors and "
        "sends email. It is connected to one trusted finance MCP server and one third-party *utility* MCP "
        "server that is malicious. All data is synthetic."
    )
    st.markdown("### Decisions")
    st.markdown(
        "- **ALLOW** - event is safe\n"
        "- **SANITIZE** - untrusted content is spotlighted or injected spans removed\n"
        "- **BLOCK** - event is refused\n"
        "- **ESCALATE** - a human is asked to approve or deny"
    )

with right:
    st.markdown("### Agents (and their syllabus type)")
    st.markdown(
        "- **Orchestrator** - Planner, utility-based (fast vs deep path)\n"
        "- **Registry Auditor** - Research, model-based (hash pinning, rug-pull, RAG)\n"
        "- **Intent Verifier** - goal-based (policy, sensitive-data, taint)\n"
        "- **Output Sanitizer** - reflex + LLM (injection in outputs)\n"
        "- **Critic / Arbiter** - utility-based (risk aggregation, self-consistency)\n"
        "- **Auditor** - monitoring (audit log, explainability)"
    )

st.divider()
st.markdown("### Architecture")
st.markdown(
    "```mermaid\n"
    "flowchart LR\n"
    "  U[User] --> H[Finance Ops Agent]\n"
    "  H <--> P[MCPShield Proxy]\n"
    "  subgraph Shield pipeline\n"
    "    O[Orchestrator] --> R[Registry Auditor]\n"
    "    O --> I[Intent Verifier]\n"
    "    O --> S[Output Sanitizer]\n"
    "    R --> C[Critic]\n"
    "    I --> C\n"
    "    S --> C\n"
    "    C --> A[Auditor]\n"
    "  end\n"
    "  P --> O\n"
    "  C -->|ALLOW/SANITIZE/BLOCK/ESCALATE| P\n"
    "  R <--> KB[(Threat KB / RAG)]\n"
    "  A --> DB[(SQLite memory)]\n"
    "  P <--> F[finance MCP server]\n"
    "  P <--> M[utility MCP server - malicious]\n"
    "```"
)
st.caption("Use the pages in the sidebar: Live Agent, Attack Lab, Tool Registry, Audit Log, Metrics, Ledger & Outbox.")
