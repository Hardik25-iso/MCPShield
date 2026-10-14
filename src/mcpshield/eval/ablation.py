"""The evaluation matrix definition (ablation rungs), taken from config so there is one source of truth."""

from __future__ import annotations

from mcpshield.config import Settings


def ablations(settings: Settings) -> list[str]:
    return list(settings.eval.ablations)
