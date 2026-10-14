"""Policy detector: tool allowlist per intent, amount caps, vendor approval, email domains, sandbox paths."""

from __future__ import annotations

from mcpshield.data_loader import load_vendors
from mcpshield.detectors.base import Detector, DetectorContext
from mcpshield.detectors.registry import register
from mcpshield.schemas import EventType, Evidence, MCPEvent, Verdict


class PolicyDetector(Detector):
    name = "policy"
    family = "policy"
    stages = frozenset({EventType.TOOL_CALL})
    scope = "event"

    def detect(self, event: MCPEvent, ctx: DetectorContext) -> Verdict:
        tool = (event.tool or "").split(ctx.settings.servers.namespace_sep)[-1]
        args = event.arguments
        reasons: list[str] = []
        evidence: list[Evidence] = []

        self._check_allowlist(tool, ctx, reasons, evidence)
        if tool == "send_payment":
            self._check_payment(args, ctx, reasons, evidence)
        elif tool == "send_email":
            self._check_email(args, ctx, reasons, evidence)
        elif tool == "read_file":
            self._check_path(args, reasons, evidence)

        risk = 1.0 if reasons else 0.0
        return self._verdict(risk, reasons, evidence, event.tool)

    def _check_allowlist(self, tool: str, ctx: DetectorContext, reasons: list, evidence: list) -> None:
        intent = ctx.session.intent.intent if ctx.session.intent else ctx.policies.default_intent
        allowed = set(ctx.policies.common_tools) | set(ctx.policies.intent_tools.get(intent, []))
        if tool not in allowed:
            reasons.append(f"tool '{tool}' not allowed for intent '{intent}'")
            evidence.append(Evidence(source="policy/allowlist", detail=f"{intent} allows {sorted(allowed)}"))

    def _check_payment(self, args: dict, ctx: DetectorContext, reasons: list, evidence: list) -> None:
        amount = float(args.get("amount", 0) or 0)
        if amount > ctx.policies.payment_cap:
            reasons.append(f"amount {amount:.0f} exceeds cap {ctx.policies.payment_cap:.0f}")
            evidence.append(Evidence(source="policy/amount_cap", detail=f"{amount} > {ctx.policies.payment_cap}"))
        vendor_id = str(args.get("vendor_id", ""))
        vendors = {v.id: v for v in load_vendors(ctx.settings)}
        vendor = vendors.get(vendor_id)
        if vendor is None:
            reasons.append(f"unknown vendor '{vendor_id}'")
            evidence.append(Evidence(source="policy/vendor", detail=f"{vendor_id} not in vendor master"))
        elif not vendor.approved:
            reasons.append(f"vendor '{vendor_id}' is not approved")
            evidence.append(Evidence(source="policy/vendor", detail=f"{vendor.name} blacklisted/unapproved"))

    def _check_email(self, args: dict, ctx: DetectorContext, reasons: list, evidence: list) -> None:
        recipient = str(args.get("to", ""))
        domain = recipient.rpartition("@")[2].lower()
        if domain not in {d.lower() for d in ctx.policies.allowed_email_domains}:
            reasons.append(f"email recipient domain '{domain}' not allowed")
            evidence.append(Evidence(source="policy/email_domain", detail=f"{recipient} outside allowed domains"))

    def _check_path(self, args: dict, reasons: list, evidence: list) -> None:
        path = str(args.get("path", ""))
        if ".." in path or path.startswith("/") or path.startswith("~"):
            reasons.append(f"file path '{path}' escapes the sandbox")
            evidence.append(Evidence(source="policy/path", detail=path))


register(PolicyDetector)
