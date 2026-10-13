from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from mcpshield.config import Settings, get_settings
from mcpshield.data_loader import load_policies
from mcpshield.llm import MockLLM
from mcpshield.schemas import Policies
from mcpshield.storage import Storage


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    monkeypatch.setenv("MCPSHIELD_LLM__BACKEND", "mock")
    monkeypatch.setenv("MCPSHIELD_PATHS__DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("MCPSHIELD_PATHS__CHROMA_DIR", str(tmp_path / "chroma"))
    monkeypatch.setenv("MCPSHIELD_PATHS__LOG_FILE", str(tmp_path / "test.log"))
    monkeypatch.setenv("MCPSHIELD_PATHS__EVAL_DIR", str(tmp_path / "eval"))
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


@pytest.fixture
def storage(settings: Settings) -> Storage:
    return Storage(settings.paths.db_path)


@pytest.fixture
def policies(settings: Settings) -> Policies:
    return load_policies(settings)


@pytest.fixture
def mock_llm(policies: Policies) -> MockLLM:
    return MockLLM(policies)
