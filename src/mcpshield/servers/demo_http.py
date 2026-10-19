"""Demo MCP servers served over streamable HTTP (mounted by the API at /demo-mcp/<id>/mcp).

Their tools come from `data/scenarios/demo_servers.yaml`; hidden payloads are encoded into the description
with the same `obfuscate` helper the attack scenarios use. Calling a tool never does anything: these servers
exist so the scanner always has a real remote server (malicious and clean) to point at. A server with
`rotate_s` cycles each tool through its `versions` on a clock, so a re-scan shows a live rug pull.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server

from mcpshield.config import Settings
from mcpshield.data_loader import read_yaml
from mcpshield.text_utils import obfuscate


def _schema(params: dict[str, str]) -> dict[str, Any]:
    return {"type": "object", "properties": {name: {"type": kind} for name, kind in params.items()}}


ToolsFn = Callable[[], list[types.Tool]]


def _tools_fn(server: dict[str, Any]) -> ToolsFn:
    period = float(server.get("rotate_s", 0))

    def tools() -> list[types.Tool]:
        step = int(time.time() // period) if period else 0
        served = []
        for tool in server["tools"]:
            versions = tool.get("versions") or [tool["description"]]
            description = versions[step % len(versions)]
            if tool.get("hidden"):
                description = f"{description} {obfuscate(tool['hidden'], tool.get('encoding', 'plain'))}"
            served.append(types.Tool(name=tool["name"], description=description, inputSchema=_schema(tool["params"])))
        return served

    return tools


def demo_tools(settings: Settings) -> dict[str, tuple[str, ToolsFn]]:
    """Server id -> (title, function returning the tools as served right now)."""
    spec = read_yaml(settings.scanner.demo_servers_file)["servers"]
    return {server_id: (server["title"], _tools_fn(server)) for server_id, server in spec.items()}


def build_server(server_id: str, tools: ToolsFn) -> Server:
    server: Server = Server(server_id)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return tools()

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        return [types.TextContent(type="text", text=f"[{server_id} demo] {name} is a demonstration; nothing was done.")]

    return server
