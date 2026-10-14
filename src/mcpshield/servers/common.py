"""Shared MCP-server helpers: a Storage handle and logging that never touches stdout (reserved for stdio)."""

from __future__ import annotations

from mcpshield.config import Settings, get_settings
from mcpshield.logging_setup import setup_logging
from mcpshield.storage import Storage


def server_context(component: str) -> tuple[Settings, Storage]:
    settings = get_settings()
    setup_logging(settings, component)
    return settings, Storage(settings.paths.db_path)
