"""Seeded synthetic data: vendors, invoices and sandbox files for the Finance Ops scenario.

Invoices named by indirect-injection scenarios (`Scenario.invoice_no`) get that scenario's payload in their
notes, so poisoned records are defined once, in `attacks.yaml`.
"""

from __future__ import annotations

import json
import random
import shutil
import string
from datetime import date, timedelta
from typing import Any

from mcpshield.config import Settings
from mcpshield.data_loader import load_scenarios, read_yaml
from mcpshield.schemas import AttackClass, Invoice, LineItem, Vendor

GST_RATE = 0.18


def catalog(settings: Settings) -> dict[str, Any]:
    return dict(read_yaml(settings.paths.data_dir / "seed" / "catalog.yaml"))


def _pan(rng: random.Random, entity: str = "C") -> str:
    def up(k: int = 1) -> str:
        return "".join(rng.choices(string.ascii_uppercase, k=k))

    return f"{up(3)}{entity}{up()}{rng.randint(1000, 9999)}{up()}"


def _gstin(rng: random.Random, state_code: str, pan: str) -> str:
    return f"{state_code}{pan}{rng.randint(1, 9)}Z{rng.choice(string.ascii_uppercase + string.digits)}"


def _slug(name: str) -> str:
    return "".join(ch for ch in name.lower().split()[0] if ch.isalnum())


def make_vendors(rng: random.Random, cat: dict[str, Any]) -> list[Vendor]:
    vendors = []
    for i, spec in enumerate(cat["vendors"], start=1):
        place = rng.choice(cat["cities"])
        pan = _pan(rng)
        vendors.append(
            Vendor(
                id=f"V{i:03d}",
                name=spec["name"],
                gstin=_gstin(rng, place["state_code"], pan),
                pan=pan,
                bank_account=str(rng.randint(10**11, 10**12 - 1)),
                ifsc=f"{''.join(rng.choices(string.ascii_uppercase, k=4))}0{rng.randint(100000, 999999)}",
                city=place["city"],
                email=f"accounts@{_slug(spec['name'])}.in",
                approved=spec["approved"],
                is_malicious=spec.get("malicious", False),
            )
        )
    return vendors


def make_invoices(
    rng: random.Random, cat: dict[str, Any], vendors: list[Vendor], n: int, poisoned: dict[str, str]
) -> list[Invoice]:
    payable = [v for v in vendors if v.approved]
    start = date(2026, 6, 1)
    invoices = []
    for i in range(n):
        invoice_no = f"INV-{1001 + i}"
        items = [
            LineItem(
                description=spec["description"],
                quantity=rng.randint(1, 6),
                unit_price=float(rng.randint(*spec["unit_price"])),
            )
            for spec in rng.sample(cat["line_items"], k=rng.randint(1, 3))
        ]
        subtotal = sum(item.quantity * item.unit_price for item in items)
        gst = round(subtotal * GST_RATE, 2)
        invoices.append(
            Invoice(
                invoice_no=invoice_no,
                vendor_id=rng.choice(payable).id,
                date=(start + timedelta(days=rng.randint(0, 110))).isoformat(),
                line_items=items,
                gst_amount=gst,
                total=round(subtotal + gst, 2),
                status=rng.choice(["paid", "unpaid", "unpaid", "overdue"]),
                notes=poisoned.get(invoice_no, rng.choice(cat["benign_notes"])),
                is_malicious=invoice_no in poisoned,
            )
        )
    return invoices


def poisoned_notes(settings: Settings) -> dict[str, str]:
    return {
        s.invoice_no: s.payloads[0]
        for s in load_scenarios(settings)
        if s.attack_class is AttackClass.INDIRECT_INJECTION and s.invoice_no and s.payloads
    }


def write_sandbox(settings: Settings, cat: dict[str, Any]) -> None:
    sandbox = settings.paths.sandbox_dir
    if sandbox.exists():
        shutil.rmtree(sandbox)
    sandbox.mkdir(parents=True)
    for name, content in cat["sandbox_files"].items():
        (sandbox / name).write_text(content, encoding="utf-8")


def generate(settings: Settings) -> dict[str, int]:
    cat = catalog(settings)
    rng = random.Random(settings.data.seed)
    vendors = make_vendors(rng, cat)
    invoices = make_invoices(rng, cat, vendors, settings.data.n_invoices, poisoned_notes(settings))
    out = settings.paths.synthetic_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "vendors.json").write_text(json.dumps([v.model_dump() for v in vendors], indent=2), encoding="utf-8")
    (out / "invoices.json").write_text(json.dumps([i.model_dump() for i in invoices], indent=2), encoding="utf-8")
    write_sandbox(settings, cat)
    return {
        "vendors": len(vendors),
        "invoices": len(invoices),
        "poisoned_invoices": sum(i.is_malicious for i in invoices),
        "sandbox_files": len(cat["sandbox_files"]),
    }
