"""The scanner over real HTTP: the API is served on a socket, and /scan fetches its own hosted demo servers
through the genuine remote MCP client (streamable HTTP), then a scanned server is test-driven by the agent."""

from __future__ import annotations

import importlib
import json
import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import uvicorn

from mcpshield.config import Settings, get_settings
from mcpshield.datagen import generate
from mcpshield.rag.ingest import build_kb


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture
def base_url(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv("MCPSHIELD_SCANNER__ALLOW_PRIVATE_URLS", "true")  # the demo servers are on localhost here
    get_settings.cache_clear()
    generate(settings)
    build_kb(settings)
    import api.main as api_main

    importlib.reload(api_main)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(api_main.app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        assert time.monotonic() < deadline, "API did not start"
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(10)


def _post(base: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    response = httpx.post(base + path, json=body, timeout=120)
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


def test_scanning_remote_servers_grades_malicious_and_clean(base_url: str) -> None:
    demos = {d["id"]: d["url"] for d in httpx.get(base_url + "/demo-servers").json()}
    bad = _post(base_url, "/scan", {"kind": "url", "input": demos["travel-desk"]})["reports"][0]
    good = _post(base_url, "/scan", {"kind": "url", "input": demos["docs-search"]})["reports"][0]
    assert bad["grade"] == "dangerous" and bad["server"].endswith("/demo-mcp/travel-desk/mcp")
    assert good["grade"] == "safe"


def test_config_scan_reaches_remote_entries_and_reports_unreachable_ones(base_url: str) -> None:
    config = {
        "mcpServers": {
            "travel": {"url": f"{base_url}/demo-mcp/travel-desk/mcp"},
            "gone": {"url": "http://127.0.0.1:9/mcp"},
            "local": {"command": "npx", "args": ["some-server"]},
        }
    }
    result = _post(base_url, "/scan", {"kind": "config", "input": json.dumps(config)})
    assert [(r["server"], r["grade"]) for r in result["reports"]] == [("travel", "dangerous")]
    assert any(error.startswith("gone:") for error in result["errors"])
    assert {c["name"]: c["kind"] for c in result["config_servers"]} == {
        "travel": "remote",
        "gone": "remote",
        "local": "local",
    }


def test_scan_rejects_bad_input_with_a_readable_message(base_url: str) -> None:
    response = httpx.post(base_url + "/scan", json={"kind": "tool_list", "input": "{oops"}, timeout=30)
    assert response.status_code == 422 and "not valid JSON" in response.json()["detail"]


def test_url_that_is_not_an_mcp_server_explains_why(base_url: str) -> None:
    response = httpx.post(base_url + "/scan", json={"kind": "url", "input": f"{base_url}/nowhere"}, timeout=60)
    assert response.status_code == 422 and "No MCP endpoint" in response.json()["detail"]


def test_scanned_server_can_be_test_driven_safely(base_url: str) -> None:
    report = _post(base_url, "/scan", {"kind": "url", "input": f"{base_url}/demo-mcp/travel-desk/mcp"})["reports"][0]
    tools = [
        {"name": t["name"], "description": t["description"], "inputSchema": t["input_schema"]} for t in report["tools"]
    ]
    body = {"task": "What is the weather forecast for Goa this week?", "tools": tools}
    off = _post(base_url, "/agent", {**body, "shield": False})
    on = _post(base_url, "/agent", {**body, "shield": True})
    assert off["compromised"] and not on["compromised"]
