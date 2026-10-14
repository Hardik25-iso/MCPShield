"""Transport-only tool channel for the host agent.

Opens one stdio MCP client session per downstream server and exposes namespaced tools
(`finance__send_payment`). Shield OFF connects to the finance and utility servers directly; shield ON
connects to the MCPShield proxy as a single server (the proxy already namespaces). The channel carries no
detection logic; it is an async context manager so sessions stay open for a whole host-agent run.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcpshield.config import Settings, config_path
from mcpshield.schemas import ToolDescriptor


@dataclass(frozen=True)
class ServerSpec:
    namespace: str
    module: str
    env: dict[str, str]


def _child_env(settings: Settings, extra: dict[str, str]) -> dict[str, str]:
    """Pass the current config and path overrides down to child server processes."""
    base = {
        "MCPSHIELD_CONFIG": str(config_path()),
        "MCPSHIELD_PATHS__DB_PATH": str(settings.paths.db_path),
        "MCPSHIELD_PATHS__CHROMA_DIR": str(settings.paths.chroma_dir),
        "MCPSHIELD_PATHS__LOG_FILE": str(settings.paths.log_file),
        "MCPSHIELD_LLM__BACKEND": settings.llm.backend,
    }
    return {**os.environ, **base, **extra}


def direct_specs(settings: Settings, scenario: str | None) -> list[ServerSpec]:
    scenario_env = {"MCPSHIELD_SCENARIO": scenario} if scenario else {}
    return [
        ServerSpec("finance", settings.servers.finance.module, {}),
        ServerSpec("utility", settings.servers.utility.module, scenario_env),
    ]


class ToolChannel:
    def __init__(self, settings: Settings, specs: list[ServerSpec]) -> None:
        self._settings = settings
        self._specs = specs
        self._sep = settings.servers.namespace_sep
        self._sessions: dict[str, ClientSession] = {}

    def split(self, qualified: str) -> tuple[str, str]:
        namespace, _, tool = qualified.partition(self._sep)
        return namespace, tool

    async def list_tools(self) -> list[ToolDescriptor]:
        descriptors = []
        for namespace, session in self._sessions.items():
            for tool in (await session.list_tools()).tools:
                descriptors.append(
                    ToolDescriptor(
                        server=namespace,
                        name=f"{namespace}{self._sep}{tool.name}",
                        description=tool.description or "",
                        input_schema=tool.inputSchema or {},
                    )
                )
        return descriptors

    async def call_tool(self, qualified: str, arguments: dict[str, object]) -> str:
        namespace, tool = self.split(qualified)
        session = self._sessions[namespace]
        result = await session.call_tool(tool, dict(arguments))
        return "".join(block.text for block in result.content if block.type == "text")

    async def read_resource(self, namespace: str, uri: str) -> str:
        result = await self._sessions[namespace].read_resource(uri)  # type: ignore[arg-type]
        return "".join(getattr(block, "text", "") for block in result.contents)


@asynccontextmanager
async def open_channel(settings: Settings, specs: list[ServerSpec]) -> AsyncIterator[ToolChannel]:
    channel = ToolChannel(settings, specs)
    async with AsyncExitStack() as stack:
        for spec in specs:
            params = StdioServerParameters(
                command=sys.executable, args=["-m", spec.module], env=_child_env(settings, spec.env)
            )
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            channel._sessions[spec.namespace] = session
        yield channel
