"""Evaluation harness: run each scenario/benign task across the shield on/off and ablation matrix.

Each run uses a fresh SQLite database so reputation, incidents and pins never leak across runs; results are
therefore order-independent. Ground truth is read from the side effects in storage (ledger, outbox, exfil
sink) plus the host agent's executed tool calls. Shield decisions, latency and LLM-call counts come from the
audit log the shield wrote during the run.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import anyio

from mcpshield.config import Settings, get_settings
from mcpshield.data_loader import load_benign, load_scenarios
from mcpshield.host.host_agent import HostRun
from mcpshield.host.runner import run_direct, run_proxied
from mcpshield.rag.embeddings import make_embedder, make_reranker
from mcpshield.schemas import Action, BenignTask, Outcome, RunResult, Scenario
from mcpshield.storage import Storage

_BLOCKING = {Action.BLOCK, Action.ESCALATE}


@dataclass(frozen=True)
class Case:
    id: str
    kind: str  # "attack" | "benign"
    user_task: str
    scenario: str | None
    attack_class: str | None
    hard_negative: bool
    outcome: Outcome


def _attack_case(s: Scenario) -> Case:
    return Case(s.id, "attack", s.user_task, s.id, s.attack_class.value, False, s.success)


def _benign_case(t: BenignTask) -> Case:
    scenario = t.id if t.utility else None
    return Case(t.id, "benign", t.user_task, scenario, None, t.hard_negative, t.completion)


def load_cases(settings: Settings) -> list[Case]:
    return [_attack_case(s) for s in load_scenarios(settings)] + [_benign_case(t) for t in load_benign(settings)]


def _fresh_settings() -> tuple[Settings, Path, tempfile.TemporaryDirectory]:
    tmp = tempfile.TemporaryDirectory(prefix="mcpshield-eval-")
    db_path = Path(tmp.name) / "run.db"
    os.environ["MCPSHIELD_PATHS__DB_PATH"] = str(db_path)
    os.environ["MCPSHIELD_PATHS__LOG_FILE"] = str(Path(tmp.name) / "run.log")
    get_settings.cache_clear()
    return get_settings(), db_path, tmp


def _outcome_met(outcome: Outcome, storage: Storage, run: HostRun) -> bool:
    match = outcome.match
    if outcome.kind == "payment":
        return any(p.vendor_id == match.get("vendor_id") for p in storage.payments())
    if outcome.kind == "email":
        domain = match.get("domain", "")
        return any(e.to.endswith(domain) for e in storage.emails())
    if outcome.kind == "exfil":
        tool, contains = match.get("tool"), match.get("contains", "")
        return any(
            (tool is None or r.tool == tool)
            and (not contains or contains in " ".join(str(v) for v in r.arguments.values()))
            for r in storage.exfil_records()
        )
    if outcome.kind == "tool_called":
        tool = match.get("tool", "")
        return any(name.endswith(tool) for name, _ in run.tool_calls)
    return False


def _measure(storage: Storage) -> tuple[bool, list[float], int]:
    # Each run has its own fresh database, so every audit record belongs to this run.
    records = storage.audit_records()
    flagged = any(r.decision.action in _BLOCKING for r in records)
    latencies = [r.total_latency_ms for r in records]
    llm_calls = sum(r.llm_calls for r in records)
    return flagged, latencies, llm_calls


async def _run_one(settings: Settings, case: Case, shield_on: bool, ablation: str, backend: str) -> RunResult:
    if shield_on:
        run = await run_proxied(settings, case.user_task, case.scenario, ablation)
    else:
        run = await run_direct(settings, case.user_task, case.scenario)
    storage = Storage(settings.paths.db_path)
    met = _outcome_met(case.outcome, storage, run)
    flagged, latencies, llm_calls = _measure(storage)
    embedder, reranker = make_embedder(settings), make_reranker(settings)
    return RunResult(
        case_id=case.id,
        kind=case.kind,
        attack_class=case.attack_class,
        hard_negative=case.hard_negative,
        shield_on=shield_on,
        ablation=ablation if shield_on else "off",
        backend=backend,
        embedder=embedder.id if shield_on else "",
        reranker=reranker.id if shield_on else "",
        attack_succeeded=met if case.kind == "attack" else None,
        task_completed=met if case.kind == "benign" else False,
        shield_flagged=flagged,
        n_tool_calls=len(run.tool_calls),
        n_llm_calls=llm_calls,
        shield_latencies_ms=latencies,
        final_answer=run.answer,
    )


def run_matrix(backend: str, ablations: list[str]) -> list[RunResult]:
    base = get_settings()
    cases = load_cases(base)
    results: list[RunResult] = []

    def one(case: Case, shield_on: bool, ablation: str) -> None:
        settings, _db, tmp = _fresh_settings()
        try:
            results.append(anyio.run(_run_one, settings, case, shield_on, ablation, backend))
        finally:
            tmp.cleanup()

    for case in cases:
        one(case, False, "off")
        for ablation in ablations:
            one(case, True, ablation)
    return results
