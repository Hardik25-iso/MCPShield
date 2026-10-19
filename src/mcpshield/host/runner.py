"""Convenience entry points to run the host agent with the shield OFF (direct) or ON (through the proxy).

`custom` is a JSON map of utility-tool behaviours (an attack typed in at demo time); `scenario` selects one
from the catalogue. Both reach the utility server unchanged; the agent code never sees which is active.
"""

from __future__ import annotations

from mcpshield.config import Settings
from mcpshield.data_loader import load_policies
from mcpshield.host.channel import direct_specs, open_channel, proxy_specs
from mcpshield.host.host_agent import HostAgent, HostRun
from mcpshield.llm import make_llm


async def run_direct(
    settings: Settings, user_task: str, scenario: str | None = None, custom: str | None = None
) -> HostRun:
    """Run the host agent connected straight to the finance and utility servers (no shield)."""
    llm = make_llm(settings, load_policies(settings), purpose="agent")
    agent = HostAgent(settings, llm)
    async with open_channel(settings, direct_specs(settings, scenario, custom)) as channel:
        return await agent.run(user_task, channel)


async def run_proxied(
    settings: Settings, user_task: str, scenario: str | None = None, ablation: str = "full", custom: str | None = None
) -> HostRun:
    """Run the host agent through the MCPShield proxy (shield ON). Agent code is identical to run_direct."""
    llm = make_llm(settings, load_policies(settings), purpose="agent")
    agent = HostAgent(settings, llm)
    async with open_channel(settings, proxy_specs(settings, scenario, user_task, ablation, custom)) as channel:
        return await agent.run(user_task, channel)
