"""Turn eval RunResults into JSON/CSV, Plotly figures and a generated docs/results.md.

Every figure and the report are labeled with the backend, embedder and reranker that produced them.
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path

import plotly.graph_objects as go

from mcpshield.config import Settings
from mcpshield.metrics import Metrics, compute
from mcpshield.schemas import RunResult
from mcpshield.viz import configure_chrome

log = logging.getLogger(__name__)

_PALETTE = {
    "off": "#c0392b",
    "static_only": "#e67e22",
    "plus_intent_verifier": "#f1c40f",
    "plus_output_sanitizer": "#27ae60",
    "full": "#2d6cdf",
}


def _label(metrics: Metrics) -> str:
    return (
        f"backend={metrics.backend or 'n/a'}, embedder={metrics.embedder or 'n/a'}, "
        f"reranker={metrics.reranker or 'n/a'}"
    )


def _by_config(results: list[RunResult]) -> dict[str, list[RunResult]]:
    groups: dict[str, list[RunResult]] = {}
    for r in results:
        key = "off" if not r.shield_on else r.ablation
        groups.setdefault(key, []).append(r)
    return groups


def _save(fig: go.Figure, path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    configure_chrome()
    try:
        fig.write_image(str(path), width=900, height=500, scale=2)
        return path.name
    except Exception as exc:  # kaleido not installed
        log.warning("PNG export unavailable (%s); writing interactive HTML instead", exc)
        html = path.with_suffix(".html")
        fig.write_html(str(html))
        return html.name


def _order(keys: list[str]) -> list[str]:
    rung = ["off", "static_only", "plus_intent_verifier", "plus_output_sanitizer", "full"]
    return [k for k in rung if k in keys]


def write_figures(results: list[RunResult], settings: Settings, backend_label: str) -> dict[str, str]:
    groups = _by_config(results)
    metrics = {k: compute(v) for k, v in groups.items()}
    order = _order(list(groups))
    figs_dir = settings.paths.figures_dir
    saved: dict[str, str] = {}

    asr = go.Figure(
        [
            go.Bar(
                x=order,
                y=[metrics[k].asr * 100 for k in order],
                marker_color=[_PALETTE.get(k) for k in order],
                text=[f"{metrics[k].asr * 100:.0f}%" for k in order],
                textposition="outside",
            )
        ]
    )
    asr.update_layout(
        title=f"Attack success rate by configuration ({backend_label})",
        yaxis_title="ASR (%)",
        yaxis_range=[0, 105],
        template="plotly_white",
    )
    saved["asr_by_config"] = _save(asr, figs_dir / "asr_by_config.png")

    classes = sorted({c for k in order for c in metrics[k].per_class})
    per_class = go.Figure()
    for k in order:
        per_class.add_bar(
            name=k,
            x=classes,
            y=[metrics[k].per_class[c].asr * 100 if c in metrics[k].per_class else 0 for c in classes],
            marker_color=_PALETTE.get(k),
        )
    per_class.update_layout(
        barmode="group", title=f"Per-class ASR ({backend_label})", yaxis_title="ASR (%)", template="plotly_white"
    )
    saved["asr_per_class"] = _save(per_class, figs_dir / "asr_per_class.png")

    fpr = go.Figure(
        [
            go.Bar(
                x=order,
                y=[metrics[k].fpr * 100 for k in order],
                marker_color=[_PALETTE.get(k) for k in order],
                text=[f"{metrics[k].fpr * 100:.0f}%" for k in order],
                textposition="outside",
            )
        ]
    )
    fpr.update_layout(
        title=f"False-positive rate on benign tasks ({backend_label})",
        yaxis_title="FPR (%)",
        yaxis_range=[0, 105],
        template="plotly_white",
    )
    saved["fpr_by_config"] = _save(fpr, figs_dir / "fpr_by_config.png")

    lat_keys = [k for k in order if k != "off"]
    latency = go.Figure()
    latency.add_bar(name="p50", x=lat_keys, y=[metrics[k].latency_p50_ms for k in lat_keys], marker_color="#2d6cdf")
    latency.add_bar(name="p95", x=lat_keys, y=[metrics[k].latency_p95_ms for k in lat_keys], marker_color="#e67e22")
    latency.update_layout(
        barmode="group",
        title=f"Added shield latency per event ({backend_label})",
        yaxis_title="latency (ms)",
        template="plotly_white",
    )
    saved["latency"] = _save(latency, figs_dir / "latency.png")
    return saved


def _mtable(metrics: Metrics) -> str:
    return (
        f"| {metrics.asr * 100:.1f} | {metrics.fpr * 100:.1f} | {metrics.task_completion * 100:.1f} "
        f"| {metrics.precision:.2f} | {metrics.recall:.2f} | {metrics.f1:.2f} "
        f"| {metrics.latency_p50_ms:.1f} | {metrics.latency_p95_ms:.1f} "
        f"| {metrics.llm_calls_per_decision:.2f} |"
    )


def write_results_md(results: list[RunResult], settings: Settings, backend: str) -> Path:
    groups = _by_config(results)
    metrics = {k: compute(v) for k, v in groups.items()}
    order = _order(list(groups))
    ref = metrics.get("full") or next(iter(metrics.values()))
    label = _label(ref)

    lines = [
        "# MCPShield evaluation results",
        "",
        "_This file is generated by `scripts/run_eval.py`; do not edit by hand._",
        "",
        f"- Backend: **{backend}**",
        f"- Embedder / reranker: **{ref.embedder or 'n/a'} / {ref.reranker or 'n/a'}**",
        f"- Suite: {ref.n_attacks} attack scenarios, {ref.n_benign} benign tasks "
        f"({sum(r.hard_negative for r in results if r.kind == 'benign' and not r.shield_on)} hard negatives).",
        "",
        "> With the mock backend the host agent is a deliberately naive, worst-case obedient agent, so the "
        "shield-OFF attack success rate is 100% by construction. The shield's value is the drop from that "
        "baseline at low false-positive cost, not the baseline itself.",
        "",
        "## Headline (shield OFF vs full shield)",
        "",
        "| Config | ASR % | FPR % | Task completion % | Precision | Recall | F1 "
        "| Latency p50 (ms) | Latency p95 (ms) | LLM calls/decision |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for k in order:
        lines.append(f"| {k} {_mtable(metrics[k])}")
    lines += [
        "",
        "## Per-class attack success rate",
        "",
        "| Attack class | " + " | ".join(order) + " |",
        "|---" * (len(order) + 1) + "|",
    ]
    classes = sorted({c for k in order for c in metrics[k].per_class})
    for c in classes:
        row = [c] + [f"{metrics[k].per_class[c].asr * 100:.0f}%" if c in metrics[k].per_class else "-" for k in order]
        lines.append("| " + " | ".join(row) + " |")

    lines += [
        "",
        "## Figures",
        "",
        f"Figures (labeled `{label}`) are written to `docs/figures/`:",
        "",
        "- `asr_by_config` - attack success rate per configuration",
        "- `asr_per_class` - per-class ASR",
        "- `fpr_by_config` - false positives on benign tasks",
        "- `latency` - added shield latency per event (p50/p95)",
        "",
        "## Reference numbers (context only)",
        "",
        "Published systems such as ShieldMCP and related ACL 2026 work report ASR reductions on their own "
        "benchmarks. Those setups, agents and payloads differ from this PoC, so the numbers are not directly "
        "comparable; they are cited only to show the metric and the direction of effect are consistent.",
        "",
    ]
    out = settings.paths.results_md
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def write_raw(results: list[RunResult], settings: Settings) -> None:
    eval_dir = settings.paths.eval_dir
    eval_dir.mkdir(parents=True, exist_ok=True)
    (eval_dir / "results.json").write_text(
        json.dumps([r.model_dump(mode="json") for r in results], indent=2), encoding="utf-8"
    )
    rows = [asdict_flat(r) for r in results]
    with (eval_dir / "results.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else [])
        writer.writeheader()
        writer.writerows(rows)


def asdict_flat(result: RunResult) -> dict[str, object]:
    data = result.model_dump(mode="json")
    data["n_shield_events"] = len(result.shield_latencies_ms)
    data.pop("shield_latencies_ms", None)
    data.pop("actions", None)
    data.pop("final_answer", None)
    return data
