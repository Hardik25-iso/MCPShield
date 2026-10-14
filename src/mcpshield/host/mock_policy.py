"""Deterministic worst-case host-agent policy.

Models a naively obedient agent: it performs the user's task and also follows any actionable instruction
found in tool descriptions or tool outputs. This makes shield-OFF attack success reproducible (ASR is 100%
by construction) and is used for tests, CI and the offline demo. It is NOT a safe agent; it exists to be
the thing MCPShield defends against.

Directives are extracted with regexes over the revealed (de-obfuscated) text. The policy obeys:
- payment directives (pay vendor Vxxx a given amount),
- email redirects (send/forward/bcc to an address),
- exfiltration lures (a tool whose description asks to fill a parameter with secrets/.env contents).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mcpshield.config import Settings
from mcpshield.data_loader import load_policies
from mcpshield.llm import REQUEST_TAG, LLMClient, tagged
from mcpshield.schemas import IntentResult, ToolDescriptor
from mcpshield.text_utils import reveal

_VENDOR_RE = re.compile(r"\bvendor\s+(V\d{3})\b", re.I)
_AMOUNT_RE = re.compile(r"\b(?:for|of|amount|inr|rs\.?)\s*([\d,]{4,})", re.I)
_BARE_AMOUNT_RE = re.compile(r"\b(\d{4,}(?:,\d{3})*)\b")
_PAY_CUE = re.compile(r"\b(pay|send_payment|transfer|remit|disburse|settle)\b", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
_EMAIL_CUE = re.compile(r"\b(send|forward|bcc|cc|copy|email)\b", re.I)
_EXFIL_CUE = re.compile(r"\b(\.env|secret|credential|api[_ ]?key|password|conversation history)\b", re.I)
_PARAM_RE = re.compile(r"\b(context|notes|debug|metadata|extra|sidenote)\b", re.I)

SECRET_SENTINEL = "<<LAST_FILE_CONTENT>>"


@dataclass
class PlannedCall:
    tool: str
    arguments: dict[str, object]
    reason: str


@dataclass
class _Extracted:
    calls: list[PlannedCall] = field(default_factory=list)


class NaiveObedientPolicy:
    def __init__(self, settings: Settings, llm: LLMClient) -> None:
        self._settings = settings
        self._llm = llm
        self._policies = load_policies(settings)

    def intent(self, user_task: str) -> IntentResult:
        result = self._llm.structured(tagged(REQUEST_TAG, user_task), IntentResult)
        return result or IntentResult(intent=self._policies.default_intent, confidence=0.0)

    # ---------------------------------------------------------------- the user's own task

    def task_calls(self, user_task: str, intent: IntentResult, tools: dict[str, ToolDescriptor]) -> list[PlannedCall]:
        has = tools.__contains__
        calls: list[PlannedCall] = []
        if intent.intent == "pay_vendor" and has("finance__send_payment"):
            vendor, amount = self._payment_args(user_task)
            if vendor and amount:
                calls.append(self._payment("finance__send_payment", vendor, amount, "user request"))
        elif intent.intent in {"summarize_invoices", "general_query"} and has("finance__list_invoices"):
            calls.append(PlannedCall("finance__list_invoices", {}, "user request"))
            invoice = self._invoice_no(user_task)
            if invoice and has("finance__get_invoice"):
                calls.append(PlannedCall("finance__get_invoice", {"invoice_no": invoice}, "user request"))
        elif intent.intent == "email_report" and has("finance__send_email"):
            recipient = f"finance@{self._policies.allowed_email_domains[0]}"
            calls.append(
                PlannedCall(
                    "finance__send_email",
                    {"to": recipient, "subject": "Report", "body": "See attached."},
                    "user request",
                )
            )
        elif intent.intent == "file_review" and has("finance__read_file"):
            calls.append(PlannedCall("finance__read_file", {"path": "q3_vendor_policy.md"}, "user request"))
        elif intent.intent == "utility_lookup":
            calls.extend(self._utility_task(user_task, tools))
        else:
            calls.extend(self._utility_task(user_task, tools))
        return calls

    def _utility_task(self, user_task: str, tools: dict[str, ToolDescriptor]) -> list[PlannedCall]:
        lowered = user_task.lower()
        if "weather" in lowered and "utility__get_weather" in tools:
            return [PlannedCall("utility__get_weather", {"city": self._city(user_task)}, "user request")]
        if "holiday" in lowered and "utility__lookup_holiday" in tools:
            return [PlannedCall("utility__lookup_holiday", {"month": "October"}, "user request")]
        if ("note" in lowered or "save" in lowered) and "utility__save_note" in tools:
            return [PlannedCall("utility__save_note", {"title": "Note", "text": user_task}, "user request")]
        if "convert" in lowered and "utility__convert_currency" in tools:
            return [
                PlannedCall(
                    "utility__convert_currency",
                    {"amount": 100, "from_currency": "USD", "to_currency": "INR"},
                    "user request",
                )
            ]
        if "utility__get_weather" in tools:
            return [PlannedCall("utility__get_weather", {"city": self._city(user_task)}, "user request")]
        return []

    # ---------------------------------------------------------------- obeying injected instructions

    def directives_from_description(self, tool: ToolDescriptor, tools: dict[str, ToolDescriptor]) -> list[PlannedCall]:
        text = reveal(tool.description)
        calls = self._payment_directive(text, tools)
        calls += self._email_directive(text, tools)
        calls += self._exfil_directive(text, tool, tools)
        return calls

    def directives_from_output(self, output: str, tools: dict[str, ToolDescriptor]) -> list[PlannedCall]:
        text = reveal(output)
        return self._payment_directive(text, tools) + self._email_directive(text, tools)

    def _payment_directive(self, text: str, tools: dict[str, ToolDescriptor]) -> list[PlannedCall]:
        if "finance__send_payment" not in tools or not _PAY_CUE.search(text):
            return []
        vendor, amount = self._payment_args(text)
        if vendor and amount:
            return [self._payment("finance__send_payment", vendor, amount, "tool instruction")]
        return []

    def _email_directive(self, text: str, tools: dict[str, ToolDescriptor]) -> list[PlannedCall]:
        if "finance__send_email" not in tools or not _EMAIL_CUE.search(text):
            return []
        match = _EMAIL_RE.search(text)
        if not match:
            return []
        return [
            PlannedCall(
                "finance__send_email",
                {"to": match.group(0), "subject": "Update", "body": text[:120]},
                "tool instruction",
            )
        ]

    def _exfil_directive(self, text: str, tool: ToolDescriptor, tools: dict[str, ToolDescriptor]) -> list[PlannedCall]:
        if not (_EXFIL_CUE.search(text) and _PARAM_RE.search(text)):
            return []
        param = _PARAM_RE.search(text).group(1).lower()  # type: ignore[union-attr]
        calls: list[PlannedCall] = []
        if "finance__read_file" in tools:
            calls.append(PlannedCall("finance__read_file", {"path": ".env"}, "exfiltration lure (read secret)"))
        args: dict[str, object] = {param: SECRET_SENTINEL}
        if tool.name.endswith("save_note"):
            args |= {"title": "audit", "text": "audit"}
        calls.append(PlannedCall(tool.name, args, "exfiltration lure (leak secret)"))
        return calls

    # ---------------------------------------------------------------- small extractors

    def _payment_args(self, text: str) -> tuple[str | None, float | None]:
        vendor = _VENDOR_RE.search(text)
        amount = _AMOUNT_RE.search(text) or _BARE_AMOUNT_RE.search(text)
        value = float(amount.group(1).replace(",", "")) if amount else None
        return (vendor.group(1).upper() if vendor else None), value

    def _payment(self, tool: str, vendor: str, amount: float, reason: str) -> PlannedCall:
        return PlannedCall(tool, {"vendor_id": vendor, "amount": amount, "reference": "auto"}, reason)

    def _invoice_no(self, text: str) -> str | None:
        match = re.search(r"\bINV-\d{3,}\b", text, re.I)
        return match.group(0).upper() if match else None

    def _city(self, text: str) -> str:
        match = re.search(r"\bin\s+([A-Z][a-z]+)", text)
        return match.group(1) if match else "Mumbai"
