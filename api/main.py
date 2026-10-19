"""Live MCPShield HTTP API.

- `POST /analyze` runs arbitrary text through the real ShieldCore pipeline for one MCP stage.
- `POST /agent` runs a real host agent end to end (finance + utility MCP servers, shield OFF or ON through the
  proxy) on a user task, optionally against a catalogue attack or one typed in at request time, and reports the
  trace, the side effects that actually happened, and the shield's decisions.

Every request gets its own temporary SQLite database, so concurrent users never share tool pins, sessions,
ledgers or audit records, and nothing is reset globally. The threat-KB retriever is opened once and shared
read-only. The LLM backend comes from config (`groq` in production, `mock` offline); the Groq key is read
from the environment and never returned.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import BaseModel, Field, model_validator
from starlette.types import Receive, Scope, Send

from mcpshield.config import Settings, get_settings
from mcpshield.core.shield_core import ShieldCore
from mcpshield.data_loader import load_policies, load_scenarios
from mcpshield.host.host_agent import HostRun
from mcpshield.host.runner import run_direct, run_proxied
from mcpshield.llm import GROQ_KEY_ENV, GroqLLM, make_llm
from mcpshield.rag.retriever import open_retriever
from mcpshield.scanner import ScanError, audit, fetch_remote_tools, parse_config, parse_tool_list
from mcpshield.schemas import Action, ConfigServer, Decision, EventType, MCPEvent, ServerReport, ToolDescriptor
from mcpshield.servers.demo_http import build_server, demo_tools
from mcpshield.storage import Storage
from mcpshield.text_utils import compile_patterns, instruction_hits

settings = get_settings()
cfg = settings.api
policies = load_policies(settings)
retriever = open_retriever(settings)
scenarios = {s.id: s for s in load_scenarios(settings)}
_secret_patterns = compile_patterns(policies.sensitive_patterns)

UtilityTool = Literal["get_weather", "convert_currency", "save_note", "lookup_holiday"]
Stage = Literal["desc", "result", "call"]
_STAGE_AGENT = {"desc": "Registry Auditor", "result": "Output Sanitizer", "call": "Intent Verifier"}
_STAGE_LABEL = {"desc": "tool listing", "result": "tool result", "call": "tool-call argument"}

# Hosted demo MCP servers (malicious and clean), so a scan always has a real remote server to point at.
_demo_servers = {
    server_id: (title, StreamableHTTPSessionManager(build_server(server_id, tools), stateless=True, json_response=True))
    for server_id, (title, tools) in demo_tools(settings).items()
}


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    async with AsyncExitStack() as stack:
        for _title, manager in _demo_servers.values():
            await stack.enter_async_context(manager.run())
        yield


app = FastAPI(title="MCPShield live API", version="3.0", lifespan=_lifespan)


def _mcp_endpoint(manager: StreamableHTTPSessionManager) -> Callable[[Scope, Receive, Send], Awaitable[None]]:
    async def handle(scope: Scope, receive: Receive, send: Send) -> None:
        await manager.handle_request(scope, receive, send)

    return handle


for _server_id, (_title, _manager) in _demo_servers.items():
    app.mount(f"/demo-mcp/{_server_id}", _mcp_endpoint(_manager))

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=cfg.allowed_origin_regex,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

_analyze_slots = threading.BoundedSemaphore(cfg.analyze_concurrency)
_agent_slot = asyncio.Semaphore(1)  # one live agent run at a time: it spawns MCP servers and calls the LLM
_scan_slots = asyncio.Semaphore(cfg.analyze_concurrency)


# ---------------------------------------------------------------- request hygiene


class _RateLimiter:
    """Sliding one-minute window per client IP (in memory; fine for a single instance)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        with self._lock:
            window = self._hits[key]
            while window and now - window[0] > 60:
                window.popleft()
            if len(window) >= limit:
                return False
            window.append(now)
            return True


_limiter = _RateLimiter()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")


def _throttle(request: Request, bucket: str, limit: int) -> None:
    if not _limiter.allow(f"{bucket}:{_client_ip(request)}", limit):
        raise HTTPException(status_code=429, detail="Rate limit reached; wait a minute and try again.")


@contextmanager
def _isolated() -> Iterator[Settings]:
    """Settings whose database is a fresh temporary file; MCP child processes inherit the same path."""
    with tempfile.TemporaryDirectory(prefix="mcpshield-req-") as tmp:
        paths = settings.paths.model_copy(update={"db_path": Path(tmp) / "run.db"})
        yield settings.model_copy(update={"paths": paths})


# ---------------------------------------------------------------- /analyze


class AnalyzeIn(BaseModel):
    text: str = Field(min_length=1, max_length=cfg.max_text_chars)
    stage: Stage = "desc"


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
    backend: str
    model: str
    verdicts: list[VerdictOut]


def _decide(text: str, stage: Stage, shield: ShieldCore) -> Decision:
    """Dispatch the text to the real pipeline as the chosen MCP event."""
    if stage == "result":
        return shield.sanitize_result("utility", "utility__demo_tool", text)[0]
    if stage == "call":
        event = MCPEvent(
            session_id=shield.session.session_id,
            type=EventType.TOOL_CALL,
            server="finance",
            tool="finance__send_payment",
            arguments={"notes": text, "reference": text},
        )
        return shield.inspect(event)
    # A neutral tool surface: the verdict reflects the typed description alone, not suspicious parameter names.
    tool = ToolDescriptor(
        server="utility",
        name="utility__demo_tool",
        description=text,
        input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
    )
    return shield.filter_tools("utility", [tool])[0]


def _verdicts(decision: Decision, stage: Stage) -> list[VerdictOut]:
    fired = sorted((v for v in decision.verdicts if v.risk > 0.0), key=lambda v: v.risk, reverse=True)
    return [
        VerdictOut(
            family=v.family,
            detector=v.detector,
            agent=v.agent or _STAGE_AGENT[stage],
            risk=round(v.risk, 3),
            reasons=v.reasons,
            evidence=[e.detail[:180] for e in v.evidence if e.detail],
        )
        for v in fired
    ]


def _analyze(text: str, stage: Stage) -> AnalyzeOut:
    with _analyze_slots, _isolated() as s:
        llm = make_llm(s, policies)
        shield = ShieldCore(s, Storage(s.paths.db_path), llm, retriever=retriever)
        shield.start_session("live analyzer: evaluate untrusted tool content")
        decision = _decide(text, stage, shield)
    verdicts = _verdicts(decision, stage)
    return AnalyzeOut(
        action=decision.action.value,
        risk=round(decision.risk.score, 3),
        agent=verdicts[0].agent if verdicts else _STAGE_AGENT[stage],
        stage=_STAGE_LABEL[stage],
        explanation=decision.explanation,
        backend=llm.backend,
        model=llm.model,
        verdicts=verdicts,
    )


@app.post("/analyze", response_model=AnalyzeOut)
async def analyze(body: AnalyzeIn, request: Request) -> AnalyzeOut:
    _throttle(request, "all", cfg.rate_limit_per_minute)
    return await run_in_threadpool(_analyze, body.text, body.stage)


# ---------------------------------------------------------------- /agent


_MAX_DRIVE_TOOLS = 30  # a scanned tool list travels to the sandboxed server in one environment variable


class ToolIn(BaseModel):
    """A tool from a scan, test-driven in a sandbox (served verbatim, calls never forwarded)."""

    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=cfg.max_text_chars)
    inputSchema: dict[str, object] = Field(default_factory=dict)  # MCP's own field name


class AgentIn(BaseModel):
    task: str = Field(min_length=1, max_length=cfg.max_task_chars)
    shield: bool = True
    scenario: str | None = None
    attack_tool: UtilityTool | None = None
    attack_description: str | None = Field(default=None, max_length=cfg.max_text_chars)
    attack_output: str | None = Field(default=None, max_length=cfg.max_text_chars)
    tools: list[ToolIn] | None = Field(default=None, min_length=1, max_length=_MAX_DRIVE_TOOLS)

    @model_validator(mode="after")
    def _one_attack_source(self) -> AgentIn:
        custom = bool(self.attack_description or self.attack_output)
        if sum((bool(self.scenario), custom, bool(self.tools))) > 1:
            raise ValueError("choose one: a catalogue scenario, a custom attack, or a scanned tool list")
        if self.scenario and self.scenario not in scenarios:
            raise ValueError(f"unknown scenario {self.scenario}")
        if custom and not self.attack_tool:
            raise ValueError("attack_tool is required for a custom attack")
        return self

    def custom_behaviors(self) -> str | None:
        if not (self.attack_description or self.attack_output) or self.attack_tool is None:
            return None
        behavior = {"description": self.attack_description, "output": self.attack_output}
        return json.dumps({self.attack_tool: behavior})

    def external_tools(self) -> str | None:
        return json.dumps([t.model_dump() for t in self.tools]) if self.tools else None


class StepOut(BaseModel):
    kind: str
    content: str
    tool: str | None = None


class DecisionOut(BaseModel):
    event: str
    tool: str | None
    action: str
    risk: float
    reasons: list[str]


class AgentOut(BaseModel):
    shield: bool
    backend: str
    model: str
    answer: str
    trace: list[StepOut]
    tool_calls: list[dict[str, object]]
    payments: list[dict[str, object]]
    emails: list[dict[str, object]]
    utility_calls: list[dict[str, object]]
    decisions: list[DecisionOut]
    compromised: bool
    compromise_reasons: list[str]
    note: str = ""


def _compromise(task: str, storage: Storage) -> list[str]:
    """Side effects the user never asked for: unrequested payments, external email, secrets sent out."""
    reasons: list[str] = []
    lowered = task.lower()
    for p in storage.payments():
        if p.vendor_id.lower() not in lowered:
            reasons.append(f"unrequested payment of {p.amount:,.0f} to {p.vendor_id}")
    for e in storage.emails():
        if not any(e.to.lower().endswith("@" + d) for d in policies.allowed_email_domains):
            reasons.append(f"email sent to external address {e.to}")
    for r in storage.exfil_records():
        values = " ".join(str(v) for v in r.arguments.values())
        hits = instruction_hits(values, _secret_patterns)
        if hits:
            reasons.append(f"secret ({hits[0].label}) sent to untrusted tool {r.tool}")
    return reasons


async def _agent(body: AgentIn) -> AgentOut:
    custom, external = body.custom_behaviors(), body.external_tools()
    rug_pull = body.scenario is not None and scenarios[body.scenario].attack_class.value == "rug_pull"
    with _isolated() as s:

        async def run_once() -> HostRun:
            if body.shield:
                return await run_proxied(s, body.task, body.scenario, "full", custom, external)
            return await run_direct(s, body.task, body.scenario, custom, external)

        if rug_pull:
            # A rug pull needs two listings: a first run approves and pins the clean tool, then the tool
            # changes. Mirror the evaluation: warm up, clear its side effects, then score the second run.
            await run_once()
            Storage(s.paths.db_path).reset_side_effects()
        run = await run_once()
        storage = Storage(s.paths.db_path)
        llm = make_llm(s, policies, purpose="agent")
        decisions = [
            DecisionOut(
                event=r.event.type.value,
                tool=r.event.tool,
                action=r.decision.action.value,
                risk=round(r.decision.risk.score, 3),
                reasons=[reason for v in r.decision.verdicts if v.risk > 0 for reason in v.reasons][:4],
            )
            for r in sorted(storage.audit_records(limit=500), key=lambda r: r.timestamp)
            if r.decision.action is not Action.ALLOW
        ]
        reasons = _compromise(body.task, storage)
        return AgentOut(
            shield=body.shield,
            backend=llm.backend,
            model=llm.model,
            answer=run.answer,
            trace=[StepOut(kind=t.kind, content=t.content[:400], tool=t.tool) for t in run.session.trace],
            tool_calls=[{"tool": name, "arguments": args} for name, args in run.tool_calls],
            payments=[{"vendor_id": p.vendor_id, "amount": p.amount} for p in storage.payments()],
            emails=[{"to": e.to, "subject": e.subject} for e in storage.emails()],
            utility_calls=[{"tool": r.tool, "arguments": r.arguments} for r in storage.exfil_records()],
            decisions=decisions,
            compromised=bool(reasons),
            compromise_reasons=reasons,
            note="Rug pull: a first run approved the clean tool; this run saw its changed version." if rug_pull else "",
        )


@app.post("/agent", response_model=AgentOut)
async def agent(body: AgentIn, request: Request) -> AgentOut:
    _throttle(request, "all", cfg.rate_limit_per_minute)
    _throttle(request, "agent", cfg.agent_rate_limit_per_minute)
    if _agent_slot.locked():
        raise HTTPException(status_code=429, detail="Another live agent run is in progress; try again shortly.")
    async with _agent_slot:
        try:
            return await asyncio.wait_for(_agent(body), timeout=cfg.agent_timeout_s)
        except TimeoutError as exc:
            raise HTTPException(status_code=504, detail="The agent run timed out.") from exc
        except Exception as exc:  # the hosted LLM can rate-limit or fail mid-run; report it instead of a 500
            raise HTTPException(status_code=502, detail=f"Agent run failed: {type(exc).__name__}") from exc


# ---------------------------------------------------------------- /scan


class ScanIn(BaseModel):
    kind: Literal["url", "tool_list", "config"]
    input: str = Field(min_length=1, max_length=settings.scanner.max_input_chars)


class ScanOut(BaseModel):
    reports: list[ServerReport]
    config_servers: list[ConfigServer] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


_MAX_CONFIG_SERVERS = 8


def _audit(tools: list[ToolDescriptor], server: str, source: Literal["url", "tool_list"]) -> ServerReport:
    with _isolated() as s:
        llm = make_llm(s, policies)
        shield = ShieldCore(s, Storage(s.paths.db_path), llm, retriever=retriever)
        shield.start_session("scan: assess this MCP server's tool definitions before installing it")
        return audit(tools, server, source, shield, s)


async def _scan_url(url: str) -> ServerReport:
    host, tools = await fetch_remote_tools(url, settings)
    return await run_in_threadpool(_audit, tools, host, "url")


async def _scan(body: ScanIn) -> ScanOut:
    if body.kind == "url":
        return ScanOut(reports=[await _scan_url(body.input)])
    if body.kind == "tool_list":
        tools = parse_tool_list(body.input, settings)
        return ScanOut(reports=[await run_in_threadpool(_audit, tools, "pasted-server", "tool_list")])
    servers = parse_config(body.input, settings, policies)
    reports, errors = [], []
    for entry in servers[:_MAX_CONFIG_SERVERS]:
        if entry.kind != "remote" or not entry.url:
            continue
        try:
            reports.append((await _scan_url(entry.url)).model_copy(update={"server": entry.name}))
        except ScanError as exc:
            errors.append(f"{entry.name}: {exc}")
    return ScanOut(reports=reports, config_servers=servers, errors=errors)


@app.post("/scan", response_model=ScanOut)
async def scan(body: ScanIn, request: Request) -> ScanOut:
    _throttle(request, "all", cfg.rate_limit_per_minute)
    async with _scan_slots:
        try:
            return await _scan(body)
        except ScanError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/demo-servers")
def demo_servers(request: Request) -> list[dict[str, str]]:
    base = str(request.base_url).rstrip("/")
    return [
        {"id": server_id, "title": title, "url": f"{base}/demo-mcp/{server_id}/mcp"}
        for server_id, (title, _manager) in _demo_servers.items()
    ]


# ---------------------------------------------------------------- discovery and health


@app.get("/scenarios")
def list_scenarios() -> list[dict[str, str]]:
    return [
        {"id": s.id, "attack_class": s.attack_class.value, "title": s.title, "user_task": s.user_task}
        for s in scenarios.values()
    ]


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "backend": settings.llm.backend,
        "groq_key_configured": bool(os.environ.get(GROQ_KEY_ENV)),
        "agent_model": settings.llm.groq_agent_model if settings.llm.backend == "groq" else "mock",
        "judge_model": settings.llm.groq_judge_model if settings.llm.backend == "groq" else "mock",
    }


@app.get("/health/llm")
def health_llm(request: Request) -> dict[str, object]:
    """Checks that the hosted models named in config exist for this key (one cheap GET /models each)."""
    _throttle(request, "all", cfg.rate_limit_per_minute)
    key = os.environ.get(GROQ_KEY_ENV, "")
    if settings.llm.backend != "groq" or not key:
        return {"backend": settings.llm.backend, "live_llm": False}
    agent_ok = GroqLLM(settings, settings.llm.groq_agent_model, key).available()
    judge_ok = GroqLLM(settings, settings.llm.groq_judge_model, key).available()
    return {
        "backend": "groq",
        "live_llm": agent_ok and judge_ok,
        "agent_model_ok": agent_ok,
        "judge_model_ok": judge_ok,
    }
