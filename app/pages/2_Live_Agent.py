"""Live Agent: chat with the Finance Ops Assistant with the shield ON or OFF."""

from __future__ import annotations

import sys
from pathlib import Path

import anyio
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import backend_sidebar, render_decision, render_trace, settings, storage

from mcpshield.host.runner import run_direct, run_proxied
from mcpshield.schemas import Action

st.set_page_config(page_title="Live Agent - MCPShield", layout="wide")
backend_sidebar()
st.title("Live Agent")
st.caption("Watch the host agent's ReAct trace next to the shield's per-event decisions.")

shield_on = st.toggle("Shield ON", value=True)
task = st.text_input("Ask the Finance Ops Assistant", "Summarize the overdue invoices for me.")
run_clicked = st.button("Run", type="primary")

if run_clicked and task.strip():
    s = settings()
    before = {r.id for r in storage().audit_records(limit=10000)}
    with st.spinner("Running the agent..."):
        run = anyio.run(run_proxied, s, task, None, "full") if shield_on else anyio.run(run_direct, s, task)
    new_records = [r for r in storage().audit_records(limit=10000) if r.id not in before]
    new_records.sort(key=lambda r: r.timestamp)

    left, right = st.columns(2)
    with left:
        st.markdown("#### Host agent trace (perception - reasoning - action)")
        render_trace(run.session.trace)
    with right:
        st.markdown("#### Shield decisions")
        if not shield_on:
            st.info("Shield is OFF - no events were inspected. Side effects below are unguarded.")
        for rec in new_records:
            render_decision(rec.decision, title=f"{rec.event.type.value} {rec.event.tool or rec.event.server}")
        escalations = [r for r in new_records if r.decision.action is Action.ESCALATE]
        if escalations:
            st.markdown("#### Human-in-the-loop")
            st.warning(f"{len(escalations)} event(s) escalated for approval.")
            col_a, col_b = st.columns(2)
            col_a.button("Approve", key="approve", help="Would allow the escalated action")
            col_b.button("Deny", key="deny", help="Would block the escalated action")

    st.divider()
    st.markdown(f"**Final answer:** {run.answer}")
