"""Structured logging: JSON lines to stderr and the configured log file.

stdout is reserved for MCP stdio transport, so nothing here ever writes to it.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from mcpshield.config import Settings

_RESERVED = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        payload.update({k: v for k, v in vars(record).items() if k not in _RESERVED})
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def setup_logging(settings: Settings, component: str = "mcpshield") -> None:
    root = logging.getLogger()
    if getattr(root, "_mcpshield_configured", False):
        return
    settings.paths.log_file.parent.mkdir(parents=True, exist_ok=True)
    formatter: logging.Formatter = (
        JsonFormatter() if settings.logging.json_format else logging.Formatter("%(levelname)s %(name)s %(message)s")
    )
    handlers: list[logging.Handler] = [
        logging.StreamHandler(sys.stderr),
        logging.FileHandler(settings.paths.log_file, encoding="utf-8"),
    ]
    for handler in handlers:
        handler.setFormatter(formatter)
        root.addHandler(handler)
    root.setLevel(settings.logging.level)
    for noisy in ("httpx", "chromadb", "urllib3", "mcp", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.getLogger(component).debug("logging configured")
    root._mcpshield_configured = True  # type: ignore[attr-defined]
