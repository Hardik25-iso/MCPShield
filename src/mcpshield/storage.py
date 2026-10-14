"""The single persistence layer: one SQLite database for all long-term state.

Opened by several processes at once (proxy, MCP servers, Streamlit), so every operation uses its own
short-lived connection in WAL mode.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from mcpshield.schemas import (
    Action,
    AuditRecord,
    Email,
    ExfilRecord,
    Incident,
    Payment,
    SessionContext,
    ToolPin,
    utcnow,
)

M = TypeVar("M", bound=BaseModel)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_pins (
    key TEXT PRIMARY KEY, server TEXT, name TEXT, sha256 TEXT, version INTEGER,
    status TEXT, updated_at TEXT, body TEXT);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, sha256 TEXT, actor TEXT, timestamp TEXT);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, server TEXT, tool TEXT, action TEXT, risk REAL, timestamp TEXT, body TEXT);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, started_at TEXT, body TEXT);
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY, session_id TEXT, event_type TEXT, server TEXT, tool TEXT, action TEXT,
    risk REAL, timestamp TEXT, body TEXT);
CREATE TABLE IF NOT EXISTS ledger (id TEXT PRIMARY KEY, vendor_id TEXT, amount REAL, timestamp TEXT, body TEXT);
CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, recipient TEXT, timestamp TEXT, body TEXT);
CREATE TABLE IF NOT EXISTS exfil_sink (id TEXT PRIMARY KEY, server TEXT, tool TEXT, timestamp TEXT, body TEXT);
"""

_TABLES = (
    "tool_pins",
    "approvals",
    "counters",
    "incidents",
    "sessions",
    "audit_log",
    "ledger",
    "outbox",
    "exfil_sink",
)


class Storage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=15)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        with self._conn() as conn:
            return conn.execute(sql, params).fetchall()

    @staticmethod
    def _load(model: type[M], rows: list[tuple[Any, ...]]) -> list[M]:
        return [model.model_validate_json(row[0]) for row in rows]

    def reset(self) -> None:
        with self._conn() as conn:
            for table in _TABLES:
                conn.execute(f"DELETE FROM {table}")

    def reset_side_effects(self) -> None:
        """Clear ledger, outbox and exfil sink, keeping pins/counters (used between rug-pull warm-up runs)."""
        with self._conn() as conn:
            for table in ("ledger", "outbox", "exfil_sink"):
                conn.execute(f"DELETE FROM {table}")

    # ------------------------------------------------------------ tool registry (long-term memory)

    def get_pin(self, key: str) -> ToolPin | None:
        found = self._load(ToolPin, self._rows("SELECT body FROM tool_pins WHERE key=?", (key,)))
        return found[0] if found else None

    def save_pin(self, pin: ToolPin) -> None:
        pin = pin.model_copy(update={"updated_at": utcnow()})
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO tool_pins VALUES (?,?,?,?,?,?,?,?)",
                (
                    pin.key,
                    pin.server,
                    pin.name,
                    pin.sha256,
                    pin.version,
                    pin.status,
                    pin.updated_at.isoformat(),
                    pin.model_dump_json(),
                ),
            )

    def list_pins(self) -> list[ToolPin]:
        return self._load(ToolPin, self._rows("SELECT body FROM tool_pins ORDER BY server, name"))

    def record_approval(self, key: str, sha256: str, actor: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO approvals (key, sha256, actor, timestamp) VALUES (?,?,?,?)",
                (key, sha256, actor, utcnow().isoformat()),
            )

    def approvals(self, key: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT key, sha256, actor, timestamp FROM approvals"
        rows = self._rows(sql + " WHERE key=? ORDER BY id", (key,)) if key else self._rows(sql + " ORDER BY id")
        return [dict(zip(("key", "sha256", "actor", "timestamp"), r, strict=True)) for r in rows]

    # ------------------------------------------------------------ counters (rug-pull versions)

    def counter(self, name: str) -> int:
        rows = self._rows("SELECT value FROM counters WHERE name=?", (name,))
        return int(rows[0][0]) if rows else 0

    def bump_counter(self, name: str) -> int:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO counters VALUES (?, 1) ON CONFLICT(name) DO UPDATE SET value = value + 1", (name,)
            )
            return int(conn.execute("SELECT value FROM counters WHERE name=?", (name,)).fetchone()[0])

    # ------------------------------------------------------------ incidents and reputation

    def add_incident(self, incident: Incident) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO incidents VALUES (?,?,?,?,?,?,?)",
                (
                    incident.id,
                    incident.server,
                    incident.tool,
                    incident.action.value,
                    incident.risk,
                    incident.timestamp.isoformat(),
                    incident.model_dump_json(),
                ),
            )

    def incidents(self, server: str | None = None) -> list[Incident]:
        if server:
            rows = self._rows("SELECT body FROM incidents WHERE server=? ORDER BY timestamp", (server,))
        else:
            rows = self._rows("SELECT body FROM incidents ORDER BY timestamp")
        return self._load(Incident, rows)

    def incident_count(self, server: str) -> int:
        blocking = (Action.BLOCK.value, Action.ESCALATE.value)
        rows = self._rows("SELECT COUNT(*) FROM incidents WHERE server=? AND action IN (?,?)", (server, *blocking))
        return int(rows[0][0])

    # ------------------------------------------------------------ sessions and audit log

    def save_session(self, session: SessionContext) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions VALUES (?,?,?)",
                (session.session_id, session.started_at.isoformat(), session.model_dump_json()),
            )

    def sessions(self) -> list[SessionContext]:
        return self._load(SessionContext, self._rows("SELECT body FROM sessions ORDER BY started_at"))

    def write_audit(self, record: AuditRecord) -> None:
        event, decision = record.event, record.decision
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO audit_log VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    record.id,
                    record.session_id,
                    event.type.value,
                    event.server,
                    event.tool,
                    decision.action.value,
                    decision.risk.score,
                    record.timestamp.isoformat(),
                    record.model_dump_json(),
                ),
            )

    def audit_records(
        self, session_id: str | None = None, action: Action | None = None, limit: int = 1000
    ) -> list[AuditRecord]:
        clauses, params = [], []
        if session_id:
            clauses.append("session_id=?")
            params.append(session_id)
        if action:
            clauses.append("action=?")
            params.append(action.value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._rows(f"SELECT body FROM audit_log {where} ORDER BY timestamp DESC LIMIT ?", (*params, limit))
        return self._load(AuditRecord, rows)

    # ------------------------------------------------------------ side effects: ledger, outbox, exfil sink

    def record_payment(self, payment: Payment) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO ledger VALUES (?,?,?,?,?)",
                (
                    payment.id,
                    payment.vendor_id,
                    payment.amount,
                    payment.timestamp.isoformat(),
                    payment.model_dump_json(),
                ),
            )

    def payments(self) -> list[Payment]:
        return self._load(Payment, self._rows("SELECT body FROM ledger ORDER BY timestamp"))

    def total_paid(self) -> float:
        return float(self._rows("SELECT COALESCE(SUM(amount), 0) FROM ledger")[0][0])

    def record_email(self, email: Email) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO outbox VALUES (?,?,?,?)",
                (email.id, email.to, email.timestamp.isoformat(), email.model_dump_json()),
            )

    def emails(self) -> list[Email]:
        return self._load(Email, self._rows("SELECT body FROM outbox ORDER BY timestamp"))

    def record_exfil(self, record: ExfilRecord) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO exfil_sink VALUES (?,?,?,?,?)",
                (record.id, record.server, record.tool, record.timestamp.isoformat(), record.model_dump_json()),
            )

    def exfil_records(self) -> list[ExfilRecord]:
        return self._load(ExfilRecord, self._rows("SELECT body FROM exfil_sink ORDER BY timestamp"))
