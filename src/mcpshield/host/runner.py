"""Convenience entry points to run the host agent against the direct (shield-OFF) channel."""

from __future__ import annotations

from mcpshield.config import Settings
from mcpshield.data_loader import load_policies
from mcpshield.host.channel import direct_specs, open_channel
from mcpshield.host.host_agent import HostAgent, HostRun
from mcpshield.llm import make_llm


async def run_direct(settings: Settings, user_task: str, scenario: str | None = None) -> HostRun:
    """Run the host agent connected straight to the finance and utility servers (no shield)."""
    llm = make_llm(settings, load_policies(settings))
    agent = HostAgent(settings, llm)
    async with open_channel(settings, direct_specs(settings, scenario)) as channel:
        return await agent.run(user_task, channel)
