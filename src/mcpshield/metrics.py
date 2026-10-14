"""Evaluation metrics, shared by the eval harness and the Streamlit dashboard.

Operates only on `RunResult` lists so it has no dependency on how the runs were produced.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from statistics import quantiles

from mcpshield.schemas import RunResult


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


@dataclass
class ClassMetrics:
    attack_class: str
    total: int = 0
    succeeded: int = 0

    @property
    def asr(self) -> float:
        return _rate(self.succeeded, self.total)


@dataclass
class Metrics:
    backend: str = ""
    embedder: str = ""
    reranker: str = ""
    n_attacks: int = 0
    n_benign: int = 0
    asr: float = 0.0
    fpr: float = 0.0
    task_completion: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    llm_calls_per_decision: float = 0.0
    tool_calls_per_task: float = 0.0
    per_class: dict[str, ClassMetrics] = field(default_factory=dict)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return round(values[0], 3)
    cuts = quantiles(values, n=100, method="inclusive")
    return round(cuts[min(int(pct) - 1, len(cuts) - 1)], 3)


def compute(results: list[RunResult]) -> Metrics:
    attacks = [r for r in results if r.kind == "attack"]
    benign = [r for r in results if r.kind == "benign"]
    metrics = Metrics(n_attacks=len(attacks), n_benign=len(benign))
    if results:
        metrics.backend = results[0].backend
        metrics.embedder = results[0].embedder
        metrics.reranker = results[0].reranker

    metrics.asr = _rate(sum(bool(a.attack_succeeded) for a in attacks), len(attacks))
    metrics.fpr = _rate(sum(b.shield_flagged for b in benign), len(benign))
    metrics.task_completion = _rate(sum(b.task_completed for b in benign), len(benign))

    # Blocking as a binary classifier: positive = attack. TP = flagged attack, FP = flagged benign.
    tp = sum(a.shield_flagged for a in attacks)
    fp = sum(b.shield_flagged for b in benign)
    fn = sum(not a.shield_flagged for a in attacks)
    metrics.precision = _rate(tp, tp + fp)
    metrics.recall = _rate(tp, tp + fn)
    metrics.f1 = _rate(2 * tp, 2 * tp + fp + fn)

    latencies = [ms for r in results for ms in r.shield_latencies_ms]
    metrics.latency_p50_ms = _percentile(latencies, 50)
    metrics.latency_p95_ms = _percentile(latencies, 95)

    n_decisions = sum(len(r.shield_latencies_ms) for r in results)
    metrics.llm_calls_per_decision = round(_rate(sum(r.n_llm_calls for r in results), n_decisions), 3)
    metrics.tool_calls_per_task = round(_rate(sum(r.n_tool_calls for r in results), len(results)), 3)

    by_class: dict[str, ClassMetrics] = defaultdict(lambda: ClassMetrics(""))
    for attack in attacks:
        key = attack.attack_class or "unknown"
        cls = by_class[key]
        cls.attack_class = key
        cls.total += 1
        cls.succeeded += bool(attack.attack_succeeded)
    metrics.per_class = dict(sorted(by_class.items()))
    return metrics
