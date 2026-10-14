from __future__ import annotations

from mcpshield.metrics import compute
from mcpshield.schemas import RunResult


def _attack(succeeded: bool, flagged: bool, cls: str = "tool_poisoning") -> RunResult:
    return RunResult(
        case_id="a",
        kind="attack",
        attack_class=cls,
        shield_on=True,
        ablation="full",
        backend="mock",
        attack_succeeded=succeeded,
        shield_flagged=flagged,
        shield_latencies_ms=[1.0, 2.0],
        n_llm_calls=1,
        n_tool_calls=2,
    )


def _benign(completed: bool, flagged: bool) -> RunResult:
    return RunResult(
        case_id="b",
        kind="benign",
        shield_on=True,
        ablation="full",
        backend="mock",
        task_completed=completed,
        shield_flagged=flagged,
        shield_latencies_ms=[3.0],
        n_tool_calls=1,
    )


def test_asr_fpr_and_classification() -> None:
    results = [_attack(False, True), _attack(False, True), _benign(True, False), _benign(True, True)]
    m = compute(results)
    assert m.asr == 0.0
    assert m.fpr == 0.5  # one benign flagged
    assert m.recall == 1.0  # both attacks flagged
    assert 0 < m.precision < 1  # one false positive
    assert m.per_class["tool_poisoning"].asr == 0.0


def test_latency_percentiles_and_rates() -> None:
    m = compute([_attack(True, True), _benign(True, False)])
    assert m.latency_p50_ms > 0
    assert m.llm_calls_per_decision >= 0
    assert m.tool_calls_per_task > 0
    assert m.asr == 1.0
