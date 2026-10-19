"""Live analyzer API: runs arbitrary text through the real ShieldCore agent pipeline.

Exposes the actual decision (action, fused risk, per-agent verdicts and evidence) so the
landing page can analyse any input through the genuine agents in real time, rather than a
client-side re-implementation. Mock LLM backend keeps it offline and deterministic.
"""

from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from mcpshield.config import get_settings
from mcpshield.core.shield_core import ShieldCore
from mcpshield.schemas import Decision, EventType, MCPEvent, ToolDescriptor
from mcpshield.storage import Storage

settings = get_settings()
storage = Storage(settings.paths.db_path)
shield = ShieldCore(settings, storage)

app = FastAPI(title="MCPShield live analyzer", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)

_STAGE_AGENT = {"desc": "Registry Auditor", "result": "Output Sanitizer", "call": "Intent Verifier"}
_STAGE_LABEL = {"desc": "tool listing", "result": "tool result", "call": "tool-call argument"}


class AnalyzeIn(BaseModel):
    text: str
    stage: Literal["desc", "result", "call"] = "desc"


class VerdictOut(BaseModel):
    family: str
    detector: str
    agent: str
    risk: float
    reasons: list[str]
    evidence: list[str]


class AnalyzeOut(BaseModel):
    action: str
    risk: float
    agent: str
    stage: str
    explanation: str
    verdicts: list[VerdictOut]


def _run(text: str, stage: str) -> Decision:
    """Dispatch the text to the real pipeline for the chosen MCP event stage."""
    storage.reset()
    shield.start_session("live analyzer: evaluate untrusted tool content")
    if stage == "result":
        decision, _ = shield.sanitize_result("utility", "utility__demo_tool", text)
        return decision
    if stage == "call":
        event = MCPEvent(
            session_id=shield.session.session_id,
            type=EventType.TOOL_CALL,
            server="finance",
            tool="finance__send_payment",
            arguments={"notes": text, "reference": text},
        )
        return shield.inspect(event)
    # A realistic tool surface: a free-text parameter the description could try to misuse,
    # so exfiltration lures in the description are detectable exactly as in the real scenarios.
    tool = ToolDescriptor(
        server="utility",
        name="utility__demo_tool",
        description=text,
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}, "context": {"type": "string"}, "notes": {"type": "string"}},
        },
    )
    decision, _ = shield.filter_tools("utility", [tool])
    return decision


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "backend": settings.llm.backend}


@app.post("/analyze", response_model=AnalyzeOut)
def analyze(body: AnalyzeIn) -> AnalyzeOut:
    decision = _run(body.text, body.stage)
    fired = [v for v in decision.verdicts if v.risk > 0.0]
    fired.sort(key=lambda v: v.risk, reverse=True)
    agent = next((v.agent for v in fired if v.agent), _STAGE_AGENT[body.stage])
    verdicts = [
        VerdictOut(
            family=v.family,
            detector=v.detector,
            agent=v.agent or _STAGE_AGENT[body.stage],
            risk=round(v.risk, 3),
            reasons=v.reasons,
            evidence=[e.detail[:180] for e in v.evidence if e.detail],
        )
        for v in fired
    ]
    return AnalyzeOut(
        action=decision.action.value,
        risk=round(decision.risk.score, 3),
        agent=agent,
        stage=_STAGE_LABEL[body.stage],
        explanation=decision.explanation,
        verdicts=verdicts,
    )
