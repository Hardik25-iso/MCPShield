"""Tool Registry: pinned tools, hashes, versions, quarantine status and rug-pull diffs."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import backend_sidebar, storage

st.set_page_config(page_title="Tool Registry - MCPShield", layout="wide")
backend_sidebar()
st.title("Tool Registry")
st.caption("Hash-pinned tool definitions. A changed hash after approval is a rug pull and is quarantined.")

pins = storage().list_pins()
if not pins:
    st.info("No tools pinned yet. Run the Live Agent or Attack Lab first.")
else:
    table = pd.DataFrame(
        [{"tool": p.key, "version": p.version, "status": p.status, "sha256": p.sha256[:16] + "..."} for p in pins]
    )
    st.dataframe(table, use_container_width=True, hide_index=True)

    quarantined = [p for p in pins if p.status == "quarantined"]
    if quarantined:
        st.markdown("### Quarantined (rug pull)")
        for p in quarantined:
            with st.expander(f"{p.key} - diff", expanded=True):
                st.code(p.diff or "definition changed", language="diff")
                if st.button(f"Approve new version of {p.key}", key=f"approve-{p.key}"):
                    storage().save_pin(p.model_copy(update={"status": "approved"}))
                    storage().record_approval(p.key, p.sha256, actor="human-ui")
                    st.success("Re-approved. Reload to refresh.")
