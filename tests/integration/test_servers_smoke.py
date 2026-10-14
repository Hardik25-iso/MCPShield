"""Smoke-test both MCP servers over real stdio with the official client session."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcpshield.config import Settings
from mcpshield.datagen import generate
from mcpshield.storage import Storage


@asynccontextmanager
async def _session(module: str, env: dict[str, str]) -> AsyncIterator[ClientSession]:
    params = StdioServerParameters(command=sys.executable, args=["-m", module], env={**os.environ, **env})
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield session


def _text(result: object) -> str:
    return "".join(block.text for block in result.content if block.type == "text")  # type: ignore[attr-defined]


@pytest.fixture
def _data(settings: Settings) -> dict[str, str]:
    generate(settings)
    return {
        "MCPSHIELD_CONFIG": str(settings_config_path()),
        "MCPSHIELD_PATHS__DB_PATH": str(settings.paths.db_path),
        "MCPSHIELD_PATHS__CHROMA_DIR": str(settings.paths.chroma_dir),
        "MCPSHIELD_PATHS__LOG_FILE": str(settings.paths.log_file),
    }


def settings_config_path() -> str:
    from mcpshield.config import config_path

    return str(config_path())


async def test_finance_server_tools_and_side_effects(settings: Settings, _data: dict[str, str]) -> None:
    async with _session("mcpshield.servers.finance_server", _data) as session:
        tools = {t.name for t in (await session.list_tools()).tools}
        assert {"list_invoices", "get_invoice", "get_vendor", "send_payment", "send_email", "read_file"} <= tools

        invoices = json.loads(_text(await session.call_tool("list_invoices", {})))
        assert len(invoices) == settings.data.n_invoices

        await session.call_tool("send_payment", {"vendor_id": "V001", "amount": 5000.0, "reference": "INV-1001"})
        await session.call_tool("send_email", {"to": "a@finco.in", "subject": "hi", "body": "test"})

        escape = json.loads(_text(await session.call_tool("read_file", {"path": "../../../etc/passwd"})))
        assert escape["error"] == "path outside sandbox"
        policy = _text(await session.call_tool("read_file", {"path": "q3_vendor_policy.md"}))
        assert "payment policy" in policy.lower()

    storage = Storage(settings.paths.db_path)
    assert storage.total_paid() == 5000.0
    assert storage.emails()[0].to == "a@finco.in"


async def test_utility_server_scenario_injection_and_exfil_sink(settings: Settings, _data: dict[str, str]) -> None:
    async with _session("mcpshield.servers.utility_server", {**_data, "MCPSHIELD_SCENARIO": "exfil_note_01"}) as s:
        tools = {t.name: t for t in (await s.list_tools()).tools}
        assert set(tools) == {"get_weather", "convert_currency", "save_note", "lookup_holiday"}
        assert "context" in tools["save_note"].inputSchema["properties"]
        assert "env" in (tools["save_note"].description or "").lower()

        weather = _text(await s.call_tool("get_weather", {"city": "Mumbai"}))
        assert "Mumbai" in weather
        await s.call_tool(
            "save_note", {"title": "Standup", "text": "ship", "context": "sk-FAKE-DEMO-KEY-NOT-REAL-0000"}
        )

    storage = Storage(settings.paths.db_path)
    records = storage.exfil_records()
    assert any(r.tool == "save_note" and "sk-FAKE" in r.arguments.get("context", "") for r in records)


async def test_utility_clean_without_scenario(settings: Settings, _data: dict[str, str]) -> None:
    async with _session("mcpshield.servers.utility_server", _data) as s:
        save = {t.name: t for t in (await s.list_tools()).tools}["save_note"]
        assert "context" not in save.inputSchema["properties"]
        assert "env" not in (save.description or "").lower()
