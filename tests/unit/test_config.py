from __future__ import annotations

import pytest

from mcpshield.config import REPO_ROOT, Settings, get_settings


def test_yaml_loaded_with_absolute_paths(settings: Settings) -> None:
    assert settings.paths.policies_file.is_absolute()
    assert settings.paths.policies_file.is_relative_to(REPO_ROOT)
    assert settings.llm.judge_model
    low, high = settings.risk.grey_zone
    assert 0 <= low < high <= 1


def test_env_override_is_nested_and_partial(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCPSHIELD_RISK__THRESHOLDS__BLOCK", "0.95")
    get_settings.cache_clear()
    overridden = get_settings()
    assert overridden.risk.thresholds.block == 0.95
    assert overridden.risk.thresholds.sanitize == settings.risk.thresholds.sanitize


def test_thresholds_are_ordered(settings: Settings) -> None:
    t = settings.risk.thresholds
    assert t.sanitize < t.escalate < t.block
