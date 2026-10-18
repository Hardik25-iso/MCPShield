"""Export real OFF/ON attack traces (one per class) as JSON for the static landing-page demo."""

from __future__ import annotations

import json
from pathlib import Path

import anyio

from mcpshield.config import get_settings
from mcpshield.data_loader import load_scenarios
from mcpshield.host.runner import run_direct, run_proxied
from mcpshield.storage import Storage


def _evidence(decision) -> list[str]:
    out: list[str] = []
    for v in decision.verdicts:
        for ev in v.evidence:
            detail = (ev.detail or "").strip().replace("\n", " ")
            if detail:
                out.append(detail[:140])
    # de-dup preserving order
    seen: set[str] = set()
    uniq = []
    for e in out:
        if e not in seen:
            seen.add(e)
            uniq.append(e)
    return uniq[:4]


def _trace(run, limit: int = 6) -> list[dict]:
    steps = []
    for ts in run.session.trace:
        steps.append({"kind": ts.kind, "content": (ts.content or "")[:220], "tool": ts.tool})
    return steps[:limit]


def main() -> None:
    s = get_settings()
    storage = Storage(s.paths.db_path)
    scenarios = load_scenarios(s)

    # one representative scenario per class, in demo order
    order = ["tool_poisoning", "indirect_injection", "exfiltration", "shadowing", "rug_pull", "split_payload"]
    by_class: dict[str, object] = {}
    for sc in scenarios:
        cls = sc.attack_class.value
        if cls not in by_class:
            by_class[cls] = sc

    results = []
    for cls in order:
        sc = by_class.get(cls)
        if sc is None:
            continue

        storage.reset()
        off = anyio.run(run_direct, s, sc.user_task, sc.id)
        off_payments = storage.payments()
        off_emails = storage.emails()
        off_exfil = storage.exfil_records()

        storage.reset()
        on = anyio.run(run_proxied, s, sc.user_task, sc.id, "full")
        on_records = sorted(storage.audit_records(limit=10000), key=lambda r: r.timestamp)

        # the decisive non-ALLOW decision (BLOCK/SANITIZE/ESCALATE)
        decisive = None
        for rec in on_records:
            act = rec.decision.action.value
            if act != "ALLOW":
                decisive = rec
                break
        if decisive is None and on_records:
            decisive = on_records[-1]

        off_effects = []
        for p in off_payments:
            off_effects.append(f"payment to {p.vendor_id} for {p.amount:.0f}")
        for e in off_emails:
            off_effects.append(f"email sent to {e.to}")
        if off_exfil:
            off_effects.append(f"{len(off_exfil)} secret-bearing call(s) captured by attacker")

        dec = decisive.decision if decisive else None
        results.append(
            {
                "id": sc.id,
                "cls": cls,
                "title": sc.title,
                "user_task": sc.user_task,
                "variant": sc.variant,
                "off": {
                    "succeeded": bool(off_effects),
                    "effects": off_effects or ["attack payload executed by the naive agent"],
                    "answer": (off.answer or "")[:200],
                },
                "on": {
                    "action": dec.action.value if dec else "BLOCK",
                    "risk": round(float(dec.risk.score), 2) if dec else None,
                    "stage": decisive.event.type.value if decisive else None,
                    "tool": (decisive.event.tool or decisive.event.server) if decisive else None,
                    "evidence": _evidence(dec) if dec else [],
                    "clean": not storage.payments() and not storage.emails(),
                },
            }
        )

    out = Path("site/demo_traces.json")
    out.write_text(json.dumps({"scenarios": results}, indent=2))
    print(f"wrote {out} with {len(results)} scenarios")
    for r in results:
        print(f"  {r['cls']:20} OFF={'HIT' if r['off']['succeeded'] else '—':3} "
              f"ON={r['on']['action']} risk={r['on']['risk']}")


if __name__ == "__main__":
    main()
