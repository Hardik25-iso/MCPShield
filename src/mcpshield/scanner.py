"""MCP server scanner: "is this server safe to plug into my assistant?"

Gets a server's tool list (from a remote MCP URL, a pasted `tools/list` JSON, or the hosted demo servers),
audits every tool definition with the real ShieldCore (the same Registry Auditor, detectors and Critic the
proxy uses), and returns a per-tool report. Tools are only listed, never called.

Remote fetching is an SSRF surface, so URLs must be http(s), carry no credentials, resolve only to public
addresses (unless `scanner.allow_private_urls`), and redirects are not followed. A DNS answer that changes
between the check and the connection is not defended against; deploy behind an egress policy for that.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import anyio
import httpx
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Tool

from mcpshield.agents.critic import Critic
from mcpshield.agents.registry_auditor import tool_hash
from mcpshield.config import ScannerConfig, Settings
from mcpshield.core.shield_core import ShieldCore
from mcpshield.schemas import (
    Action,
    ConfigServer,
    EventType,
    Grade,
    MCPEvent,
    Policies,
    ReportSource,
    ServerReport,
    ToolDescriptor,
    ToolFinding,
    Verdict,
)
from mcpshield.text_utils import compile_patterns, instruction_hits, reveal


class ScanError(ValueError):
    """Input that cannot be scanned. The message is safe to show to the user."""


# ---------------------------------------------------------------- getting the tool list


def check_url(url: str, allow_private: bool) -> str:
    """Validate a user-supplied server URL; returns the label for the report (host and path)."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ScanError("Enter the http(s) URL of a remote MCP server.")
    if parsed.username or parsed.password:
        raise ScanError("URLs with embedded credentials are not accepted.")
    if not allow_private:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            infos = socket.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ScanError(f"Could not resolve {parsed.hostname}.") from exc
        if not infos or any(not ipaddress.ip_address(info[4][0]).is_global for info in infos):
            raise ScanError("That address is private or internal; only public MCP servers can be scanned.")
    return f"{parsed.hostname}{parsed.path}".rstrip("/")


def _client(
    headers: dict[str, str] | None = None, timeout: httpx.Timeout | None = None, auth: httpx.Auth | None = None
) -> httpx.AsyncClient:
    # Redirects are not followed: a public URL must not bounce the scanner to an internal address.
    return httpx.AsyncClient(headers=headers, timeout=timeout, auth=auth, follow_redirects=False)


async def _list_tools(read: Any, write: Any, limit: int) -> list[Tool]:
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools: list[Tool] = []
        cursor: str | None = None
        while len(tools) < limit:
            page = await session.list_tools(cursor=cursor)
            tools.extend(page.tools)
            cursor = page.nextCursor
            if not cursor:
                break
        return tools[:limit]


async def _via_streamable_http(url: str, cfg: ScannerConfig) -> list[Tool]:
    async with (
        _client(timeout=httpx.Timeout(cfg.timeout_s)) as http,
        streamable_http_client(url, http_client=http) as (read, write, _),
    ):
        return await _list_tools(read, write, cfg.max_tools)


async def _via_sse(url: str, cfg: ScannerConfig) -> list[Tool]:
    async with sse_client(url, timeout=cfg.timeout_s, httpx_client_factory=_client) as (read, write):
        return await _list_tools(read, write, cfg.max_tools)


async def fetch_remote_tools(url: str, settings: Settings) -> tuple[str, list[ToolDescriptor]]:
    """Connect to a remote MCP server (streamable HTTP, falling back to SSE) and list its tools."""
    cfg = settings.scanner
    host = await anyio.to_thread.run_sync(check_url, url, cfg.allow_private_urls)
    order = (_via_sse, _via_streamable_http) if url.rstrip("/").endswith("/sse") else (_via_streamable_http, _via_sse)
    for transport in order:
        try:
            with anyio.fail_after(cfg.timeout_s):
                tools = await transport(url.strip(), cfg)
        except Exception:  # unreachable, wrong transport, not an MCP server: try the next transport
            continue
        return host, [_descriptor(host, t.name, t.description, t.inputSchema, cfg) for t in tools]
    raise ScanError("Could not list tools from that URL. Is it a public MCP server endpoint (streamable HTTP or SSE)?")


def _descriptor(
    server: str, name: str, description: str | None, schema: dict[str, Any] | None, cfg: ScannerConfig
) -> ToolDescriptor:
    return ToolDescriptor(
        server=server,
        name=str(name)[:200],
        description=(description or "")[: cfg.max_description_chars],
        input_schema=schema if isinstance(schema, dict) else {},
    )


def _load_json(raw: str, cfg: ScannerConfig) -> Any:
    if len(raw) > cfg.max_input_chars:
        raise ScanError(f"Input is larger than {cfg.max_input_chars:,} characters.")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ScanError(f"That is not valid JSON (line {exc.lineno}, column {exc.colno}).") from exc


def parse_tool_list(raw: str, settings: Settings, server: str = "pasted-server") -> list[ToolDescriptor]:
    """Accept a `tools/list` result, a raw JSON-RPC response, or a bare list of tools."""
    cfg = settings.scanner
    data = _load_json(raw, cfg)
    if isinstance(data, dict):
        data = data.get("result", data)
        data = data.get("tools", data) if isinstance(data, dict) else data
    if not isinstance(data, list) or not data:
        raise ScanError('Paste a tool list: {"tools": [{"name": ..., "description": ..., "inputSchema": ...}]}.')
    tools = []
    for item in data[: cfg.max_tools]:
        if not isinstance(item, dict) or not item.get("name"):
            raise ScanError("Every tool needs at least a name.")
        schema = item.get("inputSchema", item.get("input_schema", item.get("parameters")))
        tools.append(_descriptor(server, item["name"], item.get("description"), schema, cfg))
    return tools


def parse_config(raw: str, settings: Settings, policies: Policies) -> list[ConfigServer]:
    """Read a Claude Desktop / Cursor (`mcpServers`) or VS Code (`servers`) MCP client config."""
    data = _load_json(raw, settings.scanner)
    if not isinstance(data, dict):
        raise ScanError("Paste the whole config file (a JSON object).")
    servers = data.get("mcpServers") or data.get("servers") or data.get("mcp", {}).get("servers")
    if not isinstance(servers, dict) or not servers:
        raise ScanError(
            'No servers found. Expected an "mcpServers" (Claude Desktop, Cursor) or "servers" (VS Code) map.'
        )
    secret_patterns = compile_patterns(policies.sensitive_patterns)
    entries = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        url = spec.get("url") or spec.get("serverUrl")
        command = " ".join(str(part) for part in [spec.get("command", ""), *spec.get("args", [])]).strip()
        inline = [
            f"{field} {key}"
            for field in ("env", "headers")
            for key, value in (spec.get(field) or {}).items()
            if _looks_secret(str(key), str(value), secret_patterns)
        ]
        entries.append(
            ConfigServer(
                name=str(name),
                kind="remote" if url else "local",
                url=str(url) if url else None,
                command=command or None,
                inline_secrets=inline,
            )
        )
    return entries


def _looks_secret(key: str, value: str, patterns: list[Any]) -> bool:
    placeholder = value.startswith(("${", "<", "$")) or value.lower() in {"", "changeme", "your-key-here"}
    named = any(marker in key.upper() for marker in ("KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH"))
    return not placeholder and (named or bool(instruction_hits(value, patterns)))


# ---------------------------------------------------------------- auditing


def audit(
    tools: list[ToolDescriptor], server: str, source: ReportSource, shield: ShieldCore, settings: Settings
) -> ServerReport:
    """Run the tool list through the real shield and attribute every verdict to its tool."""
    if not tools:
        raise ScanError("The server offers no tools, so there is nothing to scan.")
    decision, _ = shield.filter_tools(server, tools)
    names = {t.name for t in tools}
    by_tool: dict[str, list[Verdict]] = defaultdict(list)
    shared: list[Verdict] = []
    for verdict in decision.verdicts:
        (by_tool[verdict.tool] if verdict.tool in names else shared).append(verdict)

    critic = Critic(settings)
    event = MCPEvent(session_id=shield.session.session_id, type=EventType.TOOLS_LIST, server=server, tools=tools)
    findings = [_finding(tool, by_tool[tool.name], critic, event) for tool in tools]
    findings.sort(key=lambda f: f.risk, reverse=True)
    server_findings = sorted({reason for v in shared if v.risk > 0 for reason in v.reasons})
    return ServerReport(
        server=server,
        source=source,
        grade=_grade(findings),
        risk=round(decision.risk.score, 3),
        tools=findings,
        server_findings=server_findings,
    )


def _finding(tool: ToolDescriptor, verdicts: list[Verdict], critic: Critic, event: MCPEvent) -> ToolFinding:
    action, report = critic.decide(event, verdicts)
    fired = [v for v in verdicts if v.risk > 0]
    revealed = reveal(tool.description)
    return ToolFinding(
        name=tool.name,
        description=tool.description,
        input_schema=tool.input_schema,
        action=action,
        risk=round(report.score, 3),
        families=sorted({v.family for v in fired}),
        reasons=list(dict.fromkeys(reason for v in fired for reason in v.reasons))[:8],
        evidence=list(dict.fromkeys(e.detail[:200] for v in fired for e in v.evidence if e.detail))[:6],
        # Shown when decoding changed anything: invisible characters, homoglyphs, base64 or comment payloads.
        revealed=revealed if revealed.strip() != tool.description.strip() else None,
        fingerprint=tool_hash(tool),
    )


def _grade(findings: list[ToolFinding]) -> Grade:
    actions = {f.action for f in findings}
    if Action.BLOCK in actions:
        return "dangerous"
    if actions & {Action.ESCALATE, Action.SANITIZE}:
        return "review"
    return "safe"
