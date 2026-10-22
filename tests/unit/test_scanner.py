"""Scanner: URL safety, input parsing and the per-tool audit through the real ShieldCore."""

from __future__ import annotations

import json

import httpx
import pytest

from mcpshield.config import Settings
from mcpshield.core.shield_core import ShieldCore
from mcpshield.llm import MockLLM
from mcpshield.scanner import ScanError, audit, check_url, failure_reason, parse_config, parse_tool_list
from mcpshield.schemas import Action, Policies, ToolDescriptor
from mcpshield.servers.demo_http import demo_tools
from mcpshield.storage import Storage


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("ftp://example.com/mcp", "URL of a remote MCP server"),
        ("not a url", "URL of a remote MCP server"),
        ("https://user:secret@example.com/mcp", "credentials"),
        ("http://127.0.0.1:8000/mcp", "private or internal"),
        ("http://10.0.0.7/mcp", "private or internal"),
        ("http://169.254.169.254/latest/meta-data", "private or internal"),
    ],
)
def test_unsafe_urls_are_rejected(url: str, message: str) -> None:
    with pytest.raises(ScanError, match=message):
        check_url(url, allow_private=False)


def test_private_urls_allowed_only_when_configured() -> None:
    assert check_url("http://127.0.0.1:8000/demo-mcp/x/mcp", allow_private=True) == "127.0.0.1/demo-mcp/x/mcp"


@pytest.mark.parametrize(
    "payload",
    [
        {"tools": [{"name": "a", "description": "d", "inputSchema": {"type": "object"}}]},
        {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "a", "description": "d"}]}},
        [{"name": "a", "description": "d", "parameters": {"type": "object"}}],
    ],
)
def test_tool_list_shapes_are_accepted(settings: Settings, payload: object) -> None:
    tools = parse_tool_list(json.dumps(payload), settings)
    assert [t.name for t in tools] == ["a"]


@pytest.mark.parametrize(("raw", "message"), [("{not json", "not valid JSON"), ('[{"description": "x"}]', "name")])
def test_bad_tool_lists_explain_themselves(settings: Settings, raw: str, message: str) -> None:
    with pytest.raises(ScanError, match=message):
        parse_tool_list(raw, settings)


def test_config_lists_servers_and_flags_inline_secrets_by_name_only(settings: Settings, policies: Policies) -> None:
    config = {
        "mcpServers": {
            "remote": {"url": "https://example.com/mcp"},
            "github": {
                "command": "npx",
                "args": ["-y", "server-github"],
                "env": {"GITHUB_TOKEN": "ghp_live0000000000"},
            },
            "safe": {"command": "uvx", "args": ["thing"], "env": {"API_KEY": "${API_KEY}"}},
        }
    }
    entries = {e.name: e for e in parse_config(json.dumps(config), settings, policies)}
    assert entries["remote"].kind == "remote" and entries["remote"].url == "https://example.com/mcp"
    assert entries["github"].kind == "local" and entries["github"].inline_secrets == ["env GITHUB_TOKEN"]
    assert entries["safe"].inline_secrets == [], "a ${VAR} reference is not an inline secret"
    assert "ghp_live" not in json.dumps([e.model_dump() for e in entries.values()])


def test_vs_code_config_shape(settings: Settings, policies: Policies) -> None:
    entries = parse_config(
        json.dumps({"servers": {"docs": {"type": "http", "url": "https://x.dev/mcp"}}}), settings, policies
    )
    assert entries[0].kind == "remote"


@pytest.mark.parametrize(
    ("status", "headers", "message"),
    [
        (401, {}, "requires sign-in"),
        (400, {"WWW-Authenticate": 'Bearer realm="x"'}, "requires sign-in"),
        (302, {"Location": "https://elsewhere.example/mcp"}, "redirects"),
        (200, {"Content-Type": "text/html; charset=utf-8"}, "web page"),
        (404, {}, "No MCP endpoint"),
        (429, {}, "rate-limiting"),
        (502, {}, "failed to answer"),
        (200, {"Content-Type": "application/json"}, "not as an MCP server"),
    ],
)
def test_failed_scans_say_why(status: int, headers: dict[str, str], message: str) -> None:
    assert message in failure_reason(httpx.Response(status, headers=headers))


def _demo(settings: Settings, server_id: str) -> list[ToolDescriptor]:
    _title, tools = demo_tools(settings)[server_id]
    return [
        ToolDescriptor(server=server_id, name=t.name, description=t.description or "", input_schema=t.inputSchema)
        for t in tools()
    ]


def _shield(settings: Settings, storage: Storage, mock_llm: MockLLM) -> ShieldCore:
    shield = ShieldCore(settings, storage, mock_llm)
    shield.start_session("scan")
    return shield


def test_malicious_demo_server_is_dangerous_tool_by_tool(
    settings: Settings, storage: Storage, mock_llm: MockLLM
) -> None:
    report = audit(_demo(settings, "travel-desk"), "travel-desk", "url", _shield(settings, storage, mock_llm), settings)
    assert report.grade == "dangerous"
    assert all(t.action is Action.BLOCK for t in report.tools)
    revealed = {t.name for t in report.tools if t.revealed}
    assert revealed == {"get_forecast", "convert_fare"}, "only the obfuscated payloads have hidden text to reveal"
    assert all(len(t.fingerprint) == 64 for t in report.tools)


def test_clean_demo_server_is_safe(settings: Settings, storage: Storage, mock_llm: MockLLM) -> None:
    report = audit(_demo(settings, "docs-search"), "docs-search", "url", _shield(settings, storage, mock_llm), settings)
    assert report.grade == "safe"
    assert all(t.action is Action.ALLOW and t.revealed is None for t in report.tools)


def test_rug_pull_demo_changes_its_fingerprint_over_time(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"now": 0.0}
    monkeypatch.setattr("mcpshield.servers.demo_http.time.time", lambda: clock["now"])
    first = {t.name: t.description for t in _demo(settings, "weather-pro")}
    clock["now"] = 61.0
    later = {t.name: t.description for t in _demo(settings, "weather-pro")}
    assert first["current_weather"] != later["current_weather"]
    assert first["air_quality"] == later["air_quality"]
