"""Audit Log: a filterable table of AuditRecords with an expandable explanation for each."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import action_badge, backend_sidebar, render_decision, storage

from mcpshield.schemas import Action

st.set_page_config(page_title="Audit Log - MCPShield", layout="wide")
backend_sidebar()
st.title("Audit Log")
st.caption("Every inspected event, with the detectors that ran, the decision and the explanation.")

records = storage().audit_records(limit=2000)
if not records:
    st.info("No audit records yet. Run the Live Agent or Attack Lab.")
else:
    actions = st.multiselect("Filter by action", [a.value for a in Action], default=[a.value for a in Action])
    filtered = [r for r in records if r.decision.action.value in actions]
    st.markdown(f"Showing **{len(filtered)}** of {len(records)} records.")
    table = pd.DataFrame(
        [
            {
                "time": r.timestamp.strftime("%H:%M:%S"),
                "event": r.event.type.value,
                "server": r.event.server,
                "tool": r.event.tool or "-",
                "action": r.decision.action.value,
                "risk": round(r.decision.risk.score, 2),
                "latency_ms": round(r.total_latency_ms, 1),
                "llm_calls": r.llm_calls,
            }
            for r in filtered
        ]
    )
    st.dataframe(table, use_container_width=True, hide_index=True)
    st.divider()
    for r in filtered[:40]:
        with st.expander(
            f"{action_badge(r.decision.action)} {r.event.type.value} {r.event.tool or r.event.server}", expanded=False
        ):
            st.markdown(action_badge(r.decision.action), unsafe_allow_html=True)
            render_decision(r.decision)
            st.caption(
                f"backend={r.backend} model={r.model} latency={r.total_latency_ms:.1f}ms llm_calls={r.llm_calls}"
            )
