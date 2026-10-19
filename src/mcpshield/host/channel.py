"""Transport-only tool channel for the host agent.

Opens one stdio MCP client session per downstream server and exposes namespaced tools
(`finance__send_payment`). Shield OFF connects to the finance and utility servers directly; shield ON
connects to the MCPShield proxy as a single server whose tools are already namespaced. Either way the host
sees the same `finance__send_payment` names. The channel carries no detection logic; it is an async context
manager so sessions stay open for a whole host-agent run.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcpshield.config import Settings, config_path
from mcpshield.schemas import ToolDescriptor


@dataclass(frozen=True)
class ServerSpec:
    namespace: str
    module: str
    env: dict[str, str] = field(default_factory=dict)
    prefix: bool = True  # False when the server already returns namespaced tool names (the proxy)


def _child_env(settings: Settings, extra: dict[str, str]) -> dict[str, str]:
    base = {
        "MCPSHIELD_CONFIG": str(config_path()),
        "MCPSHIELD_PATHS__DB_PATH": str(settings.paths.db_path),
        "MCPSHIELD_PATHS__CHROMA_DIR": str(settings.paths.chroma_dir),
        "MCPSHIELD_PATHS__LOG_FILE": str(settings.paths.log_file),
        "MCPSHIELD_LLM__BACKEND": settings.llm.backend,
    }
    return {**os.environ, **base, **extra}


def _attack_env(scenario: str | None, custom: str | None, external: str | None = None) -> dict[str, str]:
    """What the utility server serves: a catalogue scenario, a custom JSON behaviour map, or a scanned
    server's tool list (JSON) in its place."""
    env = {"MCPSHIELD_SCENARIO": scenario} if scenario else {}
    if custom:
        env["MCPSHIELD_CUSTOM_BEHAVIORS"] = custom
    if external:
        env["MCPSHIELD_EXTERNAL_TOOLS"] = external
    return env


def direct_specs(
    settings: Settings, scenario: str | None, custom: str | None = None, external: str | None = None
) -> list[ServerSpec]:
    return [
        ServerSpec("finance", settings.servers.finance.module),
        ServerSpec("utility", settings.servers.utility.module, _attack_env(scenario, custom, external)),
    ]


def proxy_specs(
    settings: Settings,
    scenario: str | None,
    user_request: str,
    ablation: str = "full",
    custom: str | None = None,
    external: str | None = None,
) -> list[ServerSpec]:
    # The proxy's own environment is inherited by the servers it spawns, so the attack reaches the utility server.
    attack = _attack_env(scenario, custom, external)
    env = {"MCPSHIELD_USER_REQUEST": user_request, "MCPSHIELD_ABLATION": ablation, **attack}
    return [ServerSpec("shield", "mcpshield.proxy.mcp_proxy", env, prefix=False)]


class ToolChannel:
    def __init__(self, settings: Settings) -> None:
        self._sep = settings.servers.namespace_sep
        self._sessions: dict[str, ClientSession] = {}
        self._prefix: dict[str, bool] = {}
        self._routes: dict[str, tuple[ClientSession, str]] = {}

    async def list_tools(self) -> list[ToolDescriptor]:
        descriptors: list[ToolDescriptor] = []
        self._routes.clear()
        for namespace, session in self._sessions.items():
            for tool in (await session.list_tools()).tools:
                exposed = f"{namespace}{self._sep}{tool.name}" if self._prefix[namespace] else tool.name
                self._routes[exposed] = (session, tool.name)
                descriptors.append(
                    ToolDescriptor(
                        server=exposed.split(self._sep)[0],
                        name=exposed,
                        description=tool.description or "",
                        input_schema=tool.inputSchema or {},
                    )
                )
        return descriptors

    async def call_tool(self, qualified: str, arguments: dict[str, object]) -> str:
        if qualified not in self._routes:
            await self.list_tools()
        session, downstream = self._routes[qualified]
        result = await session.call_tool(downstream, dict(arguments))
        return "".join(block.text for block in result.content if block.type == "text")


@asynccontextmanager
async def open_channel(settings: Settings, specs: list[ServerSpec]) -> AsyncIterator[ToolChannel]:
    channel = ToolChannel(settings)
    async with AsyncExitStack() as stack:
        for spec in specs:
            params = StdioServerParameters(
                command=sys.executable, args=["-m", spec.module], env=_child_env(settings, spec.env)
            )
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            channel._sessions[spec.namespace] = session
            channel._prefix[spec.namespace] = spec.prefix
        yield channel
