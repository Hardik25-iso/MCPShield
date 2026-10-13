"""All shared data models. No other module defines cross-module data shapes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def utcnow() -> datetime:
    return datetime.now(UTC)


class EventType(StrEnum):
    TOOLS_LIST = "TOOLS_LIST"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    RESOURCE_READ = "RESOURCE_READ"


class Action(StrEnum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    ESCALATE = "ESCALATE"
    BLOCK = "BLOCK"

    @property
    def severity(self) -> int:
        return list(Action).index(self)


class PathKind(StrEnum):
    FAST = "fast"
    DEEP = "deep"


class AttackClass(StrEnum):
    TOOL_POISONING = "tool_poisoning"
    SHADOWING = "shadowing"
    RUG_PULL = "rug_pull"
    INDIRECT_INJECTION = "indirect_injection"
    SPLIT_PAYLOAD = "split_payload"
    EXFILTRATION = "exfiltration"


# ---------------------------------------------------------------- MCP events


class ToolDescriptor(BaseModel):
    model_config = ConfigDict(frozen=True)

    server: str
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.server}/{self.name}"


class MCPEvent(BaseModel):
    id: str = Field(default_factory=new_id)
    session_id: str
    type: EventType
    server: str
    tool: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    content: str | None = None
    tools: list[ToolDescriptor] = Field(default_factory=list)
    uri: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------- shield verdicts


class Evidence(BaseModel):
    source: str
    detail: str
    score: float | None = None
    span: tuple[int, int] | None = None


class Verdict(BaseModel):
    detector: str
    family: str
    agent: str = ""
    risk: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    tool: str | None = None
    llm_calls: int = 0

    @property
    def fired(self) -> bool:
        return self.risk > 0.0


class CheckPlan(BaseModel):
    event_type: EventType
    agents: list[str]
    rule_detectors: list[str]
    deep_detectors: list[str]
    path: PathKind = PathKind.FAST
    rationale: str = ""


class RiskReport(BaseModel):
    score: float
    rule_score: float
    components: dict[str, float] = Field(default_factory=dict)
    reputation_prior: float = 0.0
    confidence: float = 1.0
    votes: list[bool] = Field(default_factory=list)


class Decision(BaseModel):
    event_id: str
    action: Action
    risk: RiskReport
    path: PathKind
    verdicts: list[Verdict] = Field(default_factory=list)
    explanation: str = ""
    sanitized_content: str | None = None
    allowed_tools: list[ToolDescriptor] = Field(default_factory=list)
    quarantined_tools: list[str] = Field(default_factory=list)
    escalation_id: str | None = None

    @property
    def blocks(self) -> bool:
        return self.action in (Action.BLOCK, Action.ESCALATE)


class AuditRecord(BaseModel):
    id: str = Field(default_factory=new_id)
    session_id: str
    event: MCPEvent
    plan: CheckPlan
    decision: Decision
    stage_latency_ms: dict[str, float] = Field(default_factory=dict)
    total_latency_ms: float = 0.0
    llm_calls: int = 0
    backend: str = ""
    model: str = ""
    timestamp: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------- LLM structured outputs


class IntentResult(BaseModel):
    intent: str
    confidence: float = Field(ge=0.0, le=1.0)
    entities: dict[str, str] = Field(default_factory=dict)


class JudgeVerdict(BaseModel):
    malicious: bool
    serves_request: bool = True
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str


# ---------------------------------------------------------------- memory


class TraceStep(BaseModel):
    kind: Literal["thought", "action", "observation", "final", "shield"]
    content: str
    tool: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)


class TaintEntry(BaseModel):
    value: str
    source: str
    event_id: str


class SessionContext(BaseModel):
    """Short-term memory for one host-agent session."""

    session_id: str = Field(default_factory=new_id)
    user_request: str = ""
    intent: IntentResult | None = None
    taint: list[TaintEntry] = Field(default_factory=list)
    trace: list[TraceStep] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)

    def tainted_values(self) -> set[str]:
        return {t.value for t in self.taint}


class ToolPin(BaseModel):
    key: str
    server: str
    name: str
    sha256: str
    descriptor: ToolDescriptor
    version: int = 1
    status: Literal["approved", "quarantined"] = "approved"
    diff: str = ""
    updated_at: datetime = Field(default_factory=utcnow)


class Incident(BaseModel):
    id: str = Field(default_factory=new_id)
    server: str
    tool: str | None
    action: Action
    risk: float
    summary: str
    timestamp: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------- policies (data/policies/policies.yaml)


class PatternSpec(BaseModel):
    label: str
    regex: str
    weight: float = 1.0


class Policies(BaseModel):
    default_intent: str = "general_query"
    intent_keywords: dict[str, list[str]] = Field(default_factory=dict)
    intent_tools: dict[str, list[str]] = Field(default_factory=dict)
    common_tools: list[str] = Field(default_factory=list)
    high_risk_tools: dict[str, list[str]] = Field(default_factory=dict)
    payment_cap: float
    allowed_email_domains: list[str]
    instruction_patterns: list[PatternSpec] = Field(default_factory=list)
    sensitive_patterns: list[PatternSpec] = Field(default_factory=list)
    exfil_cue_patterns: list[PatternSpec] = Field(default_factory=list)
    suspicious_param_names: list[str] = Field(default_factory=list)
    hidden_tag_names: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------- business domain


class Vendor(BaseModel):
    id: str
    name: str
    gstin: str
    pan: str
    bank_account: str
    ifsc: str
    city: str
    email: str
    approved: bool
    is_malicious: bool = False


class LineItem(BaseModel):
    description: str
    quantity: int
    unit_price: float


class Invoice(BaseModel):
    invoice_no: str
    vendor_id: str
    date: str
    line_items: list[LineItem]
    gst_amount: float
    total: float
    status: Literal["paid", "unpaid", "overdue"]
    notes: str = ""
    is_malicious: bool = False


class Payment(BaseModel):
    id: str = Field(default_factory=new_id)
    vendor_id: str
    amount: float
    reference: str
    account: str = ""
    timestamp: datetime = Field(default_factory=utcnow)


class Email(BaseModel):
    id: str = Field(default_factory=new_id)
    to: str
    subject: str
    body: str
    timestamp: datetime = Field(default_factory=utcnow)


class ExfilRecord(BaseModel):
    """Every argument received by the untrusted utility server (the attacker's view)."""

    id: str = Field(default_factory=new_id)
    server: str
    tool: str
    arguments: dict[str, Any]
    timestamp: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------- scenarios and evaluation


class ToolBehavior(BaseModel):
    """Scenario-driven behaviour of one utility-server tool."""

    description: str | None = None
    encoding: Literal["plain", "important_tag", "zero_width", "base64", "homoglyph", "html_comment"] = "plain"
    description_versions: list[str] = Field(default_factory=list)
    output: str | None = None
    extra_params: dict[str, str] = Field(default_factory=dict)


class Outcome(BaseModel):
    """A side effect observable in storage (ledger, outbox, exfil sink)."""

    kind: Literal["payment", "email", "exfil", "tool_called"]
    match: dict[str, str] = Field(default_factory=dict)


class Scenario(BaseModel):
    id: str
    attack_class: AttackClass
    variant: str = ""
    title: str
    user_task: str
    utility: dict[str, ToolBehavior] = Field(default_factory=dict)
    invoice_no: str | None = None
    success: Outcome
    payloads: list[str] = Field(default_factory=list)
    expected_action: Action = Action.BLOCK


class BenignTask(BaseModel):
    id: str
    title: str
    user_task: str
    hard_negative: bool = False
    utility: dict[str, ToolBehavior] = Field(default_factory=dict)
    completion: Outcome
    expected_action: Action = Action.ALLOW


class RunResult(BaseModel):
    case_id: str
    kind: Literal["attack", "benign"]
    attack_class: str | None = None
    hard_negative: bool = False
    shield_on: bool
    ablation: str
    backend: str
    embedder: str = ""
    reranker: str = ""
    attack_succeeded: bool | None = None
    task_completed: bool = False
    shield_flagged: bool = False
    actions: list[Action] = Field(default_factory=list)
    n_tool_calls: int = 0
    n_llm_calls: int = 0
    shield_latencies_ms: list[float] = Field(default_factory=list)
    final_answer: str = ""
    error: str | None = None
