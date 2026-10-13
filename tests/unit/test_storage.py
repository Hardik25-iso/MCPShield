from __future__ import annotations

from mcpshield.schemas import (
    Action,
    AuditRecord,
    CheckPlan,
    Decision,
    Email,
    EventType,
    ExfilRecord,
    Incident,
    MCPEvent,
    PathKind,
    Payment,
    RiskReport,
    SessionContext,
    ToolDescriptor,
    ToolPin,
)
from mcpshield.storage import Storage


def _pin(version: int = 1) -> ToolPin:
    tool = ToolDescriptor(server="utility", name="get_weather", description="Weather.")
    return ToolPin(key=tool.key, server=tool.server, name=tool.name, sha256="abc", descriptor=tool, version=version)


def test_pin_roundtrip_and_update(storage: Storage) -> None:
    storage.save_pin(_pin())
    storage.save_pin(_pin(version=2).model_copy(update={"status": "quarantined"}))
    pin = storage.get_pin("utility/get_weather")
    assert pin is not None and pin.version == 2 and pin.status == "quarantined"
    assert len(storage.list_pins()) == 1
    assert storage.get_pin("missing/tool") is None


def test_counters_increment_independently(storage: Storage) -> None:
    assert storage.counter("a") == 0
    assert storage.bump_counter("a") == 1
    assert storage.bump_counter("a") == 2
    assert storage.counter("b") == 0


def test_incident_reputation_counts_only_blocking(storage: Storage) -> None:
    storage.add_incident(Incident(server="utility", tool="x", action=Action.BLOCK, risk=0.9, summary="s"))
    storage.add_incident(Incident(server="utility", tool="x", action=Action.SANITIZE, risk=0.4, summary="s"))
    storage.add_incident(Incident(server="finance", tool="y", action=Action.ESCALATE, risk=0.7, summary="s"))
    assert storage.incident_count("utility") == 1
    assert storage.incident_count("finance") == 1
    assert len(storage.incidents("utility")) == 2


def test_audit_filtering(storage: Storage) -> None:
    for action in (Action.ALLOW, Action.BLOCK):
        event = MCPEvent(session_id="s1", type=EventType.TOOL_CALL, server="finance", tool="send_payment")
        decision = Decision(
            event_id=event.id, action=action, risk=RiskReport(score=0.1, rule_score=0.1), path=PathKind.FAST
        )
        plan = CheckPlan(event_type=event.type, agents=[], rule_detectors=[], deep_detectors=[])
        storage.write_audit(AuditRecord(session_id="s1", event=event, plan=plan, decision=decision))
    assert len(storage.audit_records(session_id="s1")) == 2
    blocked = storage.audit_records(action=Action.BLOCK)
    assert [r.decision.action for r in blocked] == [Action.BLOCK]


def test_side_effect_tables_and_reset(storage: Storage) -> None:
    storage.record_payment(Payment(vendor_id="V001", amount=100.0, reference="INV-1"))
    storage.record_email(Email(to="a@finco.in", subject="s", body="b"))
    storage.record_exfil(ExfilRecord(server="utility", tool="save_note", arguments={"notes": "sk-123"}))
    storage.save_session(SessionContext(user_request="hi"))
    assert storage.total_paid() == 100.0
    assert storage.emails()[0].to == "a@finco.in"
    assert storage.exfil_records()[0].arguments["notes"] == "sk-123"
    storage.reset()
    assert not storage.payments() and not storage.emails() and not storage.exfil_records()
    assert not storage.sessions()
