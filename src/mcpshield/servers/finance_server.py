"""Trusted finance MCP server for the Finance Ops Assistant.

Tools read synthetic vendors/invoices and write side effects (payments, emails) through `storage.py`.
`read_file` is confined to the sandbox. Nothing leaves the machine.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcpshield.data_loader import load_invoices, load_vendors
from mcpshield.schemas import Email, Payment
from mcpshield.servers.common import server_context

log = logging.getLogger("mcpshield.servers.finance")
settings, storage = server_context("finance")
mcp = FastMCP("finance")

_VENDORS = {v.id: v for v in load_vendors(settings)}
_INVOICES = {inv.invoice_no: inv for inv in load_invoices(settings)}


def _sandbox_root() -> Path:
    return settings.paths.sandbox_dir.resolve()


@mcp.tool(description="List all invoices with their vendor, total and status.")
def list_invoices(status: str | None = None) -> str:
    items = [i for i in _INVOICES.values() if status is None or i.status == status]
    rows = [{"invoice_no": i.invoice_no, "vendor_id": i.vendor_id, "total": i.total, "status": i.status} for i in items]
    return json.dumps(rows)


@mcp.tool(description="Get one invoice by number, including line items and free-text notes.")
def get_invoice(invoice_no: str) -> str:
    invoice = _INVOICES.get(invoice_no)
    if invoice is None:
        return json.dumps({"error": f"invoice {invoice_no} not found"})
    return invoice.model_dump_json()


@mcp.tool(description="Get a vendor's profile, including GSTIN, bank account and approval status.")
def get_vendor(vendor_id: str) -> str:
    vendor = _VENDORS.get(vendor_id)
    if vendor is None:
        return json.dumps({"error": f"vendor {vendor_id} not found"})
    return vendor.model_dump_json()


@mcp.tool(description="Record a payment to a vendor. Writes to the mock ledger.")
def send_payment(vendor_id: str, amount: float, reference: str, account: str = "") -> str:
    vendor = _VENDORS.get(vendor_id)
    account = account or (vendor.bank_account if vendor else "")
    payment = Payment(vendor_id=vendor_id, amount=amount, reference=reference, account=account)
    storage.record_payment(payment)
    log.info("payment recorded", extra={"vendor_id": vendor_id, "amount": amount})
    return json.dumps({"status": "paid", "payment_id": payment.id, "vendor_id": vendor_id, "amount": amount})


@mcp.tool(description="Send an email. Writes to the mock outbox.")
def send_email(to: str, subject: str, body: str) -> str:
    email = Email(to=to, subject=subject, body=body)
    storage.record_email(email)
    log.info("email queued", extra={"to": to})
    return json.dumps({"status": "sent", "email_id": email.id, "to": to})


@mcp.tool(description="Read a text file from the finance sandbox directory.")
def read_file(path: str) -> str:
    root = _sandbox_root()
    target = (root / path).resolve()
    if not target.is_relative_to(root):
        return json.dumps({"error": "path outside sandbox"})
    if not target.is_file():
        return json.dumps({"error": f"file not found: {path}"})
    return target.read_text(encoding="utf-8")


@mcp.resource("ledger://balance", description="Current mock ledger balance in INR.")
def ledger_balance() -> str:
    opening = float(_catalog_balance())
    return json.dumps({"currency": "INR", "opening_balance": opening, "total_paid": storage.total_paid()})


@mcp.resource("policy://payment-limits", description="Payment limits and approval policy.")
def payment_limits() -> str:
    from mcpshield.data_loader import load_policies

    policies = load_policies(settings)
    return json.dumps({"payment_cap": policies.payment_cap, "allowed_email_domains": policies.allowed_email_domains})


def _catalog_balance() -> Any:
    from mcpshield.datagen import catalog

    return catalog(settings)["company"]["opening_balance"]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
