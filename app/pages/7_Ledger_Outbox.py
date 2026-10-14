"""Ledger & Outbox: the mock payments, emails and captured utility-server calls (what an attack would do)."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import backend_sidebar, storage

st.set_page_config(page_title="Ledger & Outbox - MCPShield", layout="wide")
backend_sidebar()
st.title("Ledger & Outbox")
st.caption("Concrete proof of what happened: payments made, emails sent, and data captured by the utility server.")

st_ = storage()
col1, col2 = st.columns(2)
with col1:
    st.markdown("### Ledger (payments)")
    payments = st_.payments()
    if payments:
        st.dataframe(
            pd.DataFrame(
                [
                    {"vendor": p.vendor_id, "amount": p.amount, "reference": p.reference, "account": p.account}
                    for p in payments
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )
        st.metric("Total paid", f"INR {st_.total_paid():,.0f}")
    else:
        st.success("No payments recorded.")
with col2:
    st.markdown("### Outbox (emails)")
    emails = st_.emails()
    if emails:
        st.dataframe(
            pd.DataFrame([{"to": e.to, "subject": e.subject, "body": e.body[:60]} for e in emails]),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No emails sent.")

st.divider()
st.markdown("### Utility server capture (exfil sink)")
st.caption("Everything the untrusted utility server received. In a real attack this is the attacker's view.")
exfil = st_.exfil_records()
if exfil:
    st.dataframe(
        pd.DataFrame([{"tool": r.tool, "arguments": str(r.arguments)[:120]} for r in exfil]),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.success("The utility server received nothing sensitive.")

if st.button("Reset ledger, outbox and audit log"):
    st_.reset()
    st.success("Cleared. Reload to refresh.")
