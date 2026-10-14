"""MCPShield proxy: a thin MCP adapter around ShieldCore.

To the host agent it is one MCP server exposing namespaced tools (`finance__send_payment`); to the real
servers it is an MCP client over stdio. Every tool list, tool call, tool result and resource read is routed
through `ShieldCore`; the proxy contains no detection logic of its own. The user request is passed in via
`MCPSHIELD_USER_REQUEST` so the shield can derive intent and run taint checks; the tool list is re-fetched on
session start and on a configurable interval so rug pulls are caught.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import AsyncExitStack
from typing import Any

import anyio
import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcpshield.core.shield_core import Ablation, ShieldCore
from mcpshield.host.channel import _child_env
from mcpshield.schemas import Action, EventType, MCPEvent, ToolDescriptor
from mcpshield.servers.common import server_context

log = logging.getLogger("mcpshield.proxy")
BLOCK_TEXT = "[blocked by MCPShield]"
SEP = "__"


class Downstream:
    """Holds the client sessions to the real servers and the shield-approved tool list."""

    def __init__(self, settings, shield: ShieldCore) -> None:
        self._settings = settings
        self._shield = shield
        self.sessions: dict[str, ClientSession] = {}
        self._allowed: dict[str, ToolDescriptor] = {}
        self._refreshed = 0.0

    def _specs(self) -> dict[str, tuple[str, dict[str, str]]]:
        scenario = os.environ.get("MCPSHIELD_SCENARIO")
        utility_env = {"MCPSHIELD_SCENARIO": scenario} if scenario else {}
        return {
            "finance": (self._settings.servers.finance.module, {}),
            "utility": (self._settings.servers.utility.module, utility_env),
        }

    async def open(self, stack: AsyncExitStack) -> None:
        for name, (module, env) in self._specs().items():
            params = StdioServerParameters(
                command=__import__("sys").executable, args=["-m", module], env=_child_env(self._settings, env)
            )
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self.sessions[name] = session

    async def refresh(self, force: bool = False) -> None:
        interval = self._settings.shield.tool_refresh_interval_s
        if not force and (time.monotonic() - self._refreshed) < interval and self._allowed:
            return
        allowed: dict[str, ToolDescriptor] = {}
        for server, session in self.sessions.items():
            descriptors = [
                ToolDescriptor(
                    server=server,
                    name=f"{server}{SEP}{tool.name}",
                    description=tool.description or "",
                    input_schema=tool.inputSchema or {},
                )
                for tool in (await session.list_tools()).tools
            ]
            _decision, approved = self._shield.filter_tools(server, descriptors)
            allowed.update({t.name: t for t in approved})
        self._allowed = allowed
        self._refreshed = time.monotonic()

    def exposed_tools(self) -> list[types.Tool]:
        return [
            types.Tool(name=t.name, description=t.description, inputSchema=t.input_schema or {"type": "object"})
            for t in self._allowed.values()
        ]

    async def call(self, qualified: str, arguments: dict[str, Any]) -> str:
        server, _, tool = qualified.partition(SEP)
        if qualified not in self._allowed:
            return f"{BLOCK_TEXT}: tool '{qualified}' is quarantined or unknown."
        event = MCPEvent(
            session_id=self._shield.session.session_id,
            type=EventType.TOOL_CALL,
            server=server,
            tool=qualified,
            arguments=arguments,
        )
        decision = self._shield.inspect(event)
        if decision.action is Action.BLOCK or (
            decision.action is Action.ESCALATE and self._settings.shield.escalate_counts_as_blocked
        ):
            return f"{BLOCK_TEXT}: {decision.explanation}"
        result = await self.sessions[server].call_tool(tool, arguments)
        output = "".join(block.text for block in result.content if block.type == "text")
        _sanitize_decision, safe = self._shield.sanitize_result(server, qualified, output)
        return safe


async def _serve() -> None:
    settings, storage = server_context("proxy")
    ablation = Ablation.preset(os.environ.get("MCPSHIELD_ABLATION", "full"))
    shield = ShieldCore(settings, storage, ablation=ablation)
    shield.start_session(os.environ.get("MCPSHIELD_USER_REQUEST", ""))
    downstream = Downstream(settings, shield)
    server: Server = Server("mcpshield")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        await downstream.refresh(force=True)
        return downstream.exposed_tools()

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        await downstream.refresh()
        return [types.TextContent(type="text", text=await downstream.call(name, arguments))]

    async with AsyncExitStack() as stack:
        await downstream.open(stack)
        await downstream.refresh(force=True)
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    anyio.run(_serve)


if __name__ == "__main__":
    main()
