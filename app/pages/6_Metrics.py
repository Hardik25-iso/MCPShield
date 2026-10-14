"""Metrics: charts from the most recent evaluation, plus a button to re-run the mock-backend suite."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import backend_sidebar, settings

from mcpshield.metrics import compute
from mcpshield.schemas import RunResult

st.set_page_config(page_title="Metrics - MCPShield", layout="wide")
backend_sidebar()
st.title("Metrics")

s = settings()
results_path = s.paths.eval_dir / "results.json"

if st.button("Re-run evaluation (mock backend)", type="primary"):
    with st.spinner("Running the full matrix with the mock backend. This takes a few minutes..."):
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[2] / "scripts" / "run_eval.py"), "--backend", "mock"],
            cwd=str(Path(__file__).resolve().parents[2]),
            capture_output=True,
            text=True,
        )
    st.code(proc.stdout[-2000:] + proc.stderr[-1000:])

if not results_path.exists():
    st.info("No evaluation results yet. Run `make eval` or click the button above.")
    st.stop()

results = [RunResult.model_validate(r) for r in json.loads(results_path.read_text())]
configs = ["off", "static_only", "plus_intent_verifier", "plus_output_sanitizer", "full"]
groups = {
    c: [r for r in results if (c == "off" and not r.shield_on) or (r.shield_on and r.ablation == c)] for c in configs
}
groups = {c: v for c, v in groups.items() if v}
metrics = {c: compute(v) for c, v in groups.items()}
order = [c for c in configs if c in metrics]
ref = metrics[order[-1]]

st.caption(f"backend={ref.backend or 'n/a'}, embedder={ref.embedder or 'n/a'}, reranker={ref.reranker or 'n/a'}")
st.info("Shield-OFF ASR is 100% by construction in mock mode (worst-case obedient agent).")

c1, c2, c3 = st.columns(3)
c1.metric("ASR OFF", f"{metrics['off'].asr * 100:.0f}%" if "off" in metrics else "n/a")
c2.metric("ASR full shield", f"{metrics['full'].asr * 100:.0f}%" if "full" in metrics else "n/a")
c3.metric("FPR full shield", f"{metrics['full'].fpr * 100:.0f}%" if "full" in metrics else "n/a")

asr = go.Figure(
    [
        go.Bar(
            x=order,
            y=[metrics[c].asr * 100 for c in order],
            text=[f"{metrics[c].asr * 100:.0f}%" for c in order],
            textposition="outside",
        )
    ]
)
asr.update_layout(
    title="Attack success rate by configuration", yaxis_title="ASR (%)", yaxis_range=[0, 105], template="plotly_white"
)
st.plotly_chart(asr, use_container_width=True)

classes = sorted({c for cfg in order for c in metrics[cfg].per_class})
per_class = go.Figure()
for cfg in order:
    per_class.add_bar(
        name=cfg,
        x=classes,
        y=[metrics[cfg].per_class[c].asr * 100 if c in metrics[cfg].per_class else 0 for c in classes],
    )
per_class.update_layout(barmode="group", title="Per-class ASR", yaxis_title="ASR (%)", template="plotly_white")
st.plotly_chart(per_class, use_container_width=True)

table = pd.DataFrame(
    [
        {
            "config": c,
            "ASR %": round(metrics[c].asr * 100, 1),
            "FPR %": round(metrics[c].fpr * 100, 1),
            "task completion %": round(metrics[c].task_completion * 100, 1),
            "F1": round(metrics[c].f1, 2),
            "latency p50 ms": metrics[c].latency_p50_ms,
            "latency p95 ms": metrics[c].latency_p95_ms,
            "LLM calls/decision": metrics[c].llm_calls_per_decision,
        }
        for c in order
    ]
)
st.dataframe(table, use_container_width=True, hide_index=True)
