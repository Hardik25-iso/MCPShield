"""Attack Lab: pick an attack scenario and run it shield OFF then ON, showing the full pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

import anyio
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import backend_sidebar, render_decision, render_trace, settings, storage

from mcpshield.data_loader import load_scenarios
from mcpshield.host.runner import run_direct, run_proxied

st.set_page_config(page_title="Attack Lab - MCPShield", layout="wide")
backend_sidebar()
st.title("Attack Lab")
st.caption("Run an attack scenario with the shield OFF (compromised) and ON (defended).")

s = settings()
scenarios = load_scenarios(s)
labels = {f"{sc.attack_class.value} / {sc.id} - {sc.title}": sc for sc in scenarios}
choice = st.selectbox("Attack scenario", list(labels))
scenario = labels[choice]

st.markdown(f"**User task:** {scenario.user_task}")
st.markdown(
    f"**Class:** `{scenario.attack_class.value}`  |  **Variant:** `{scenario.variant}`  |  "
    f"**Success if:** `{scenario.success.kind}` matches `{scenario.success.match}`"
)

if st.button("Run OFF then ON", type="primary"):
    storage().reset()
    with st.spinner("Running shield OFF..."):
        off = anyio.run(run_direct, s, scenario.user_task, scenario.id)
    off_payments = storage().payments()
    off_emails = storage().emails()
    off_exfil = storage().exfil_records()

    storage().reset()
    before = set()
    with st.spinner("Running shield ON..."):
        on = anyio.run(run_proxied, s, scenario.user_task, scenario.id, "full")
    on_records = sorted(storage().audit_records(limit=10000), key=lambda r: r.timestamp)

    off_col, on_col = st.columns(2)
    with off_col:
        st.markdown("### Shield OFF")
        render_trace(off.session.trace)
        st.error(
            f"Side effects: {len(off_payments)} payment(s), {len(off_emails)} email(s), "
            f"{len(off_exfil)} utility call(s) captured by the attacker."
        )
        for p in off_payments:
            st.markdown(f"- payment to **{p.vendor_id}** for {p.amount:.0f}")
        for e in off_emails:
            st.markdown(f"- email to **{e.to}**")
    with on_col:
        st.markdown("### Shield ON")
        for rec in on_records:
            render_decision(rec.decision, title=f"{rec.event.type.value} {rec.event.tool or rec.event.server}")
            for v in rec.decision.verdicts:
                for ev in v.evidence:
                    if ev.source.startswith("rag/"):
                        st.caption(f"RAG evidence: {ev.detail[:120]} (score {ev.score})")
        st.success(
            "No attacker side effects: "
            + ("ledger and outbox clean." if not storage().payments() and not storage().emails() else "see Ledger tab.")
        )
