"""Detector registry: construct the enabled detectors for a stage, honouring ablation config."""

from __future__ import annotations

from collections.abc import Callable

from mcpshield.detectors.base import Detector
from mcpshield.schemas import EventType

_FACTORIES: dict[str, Callable[[], Detector]] = {}


def register(factory: Callable[[], Detector]) -> Callable[[], Detector]:
    instance = factory()
    if instance.name in _FACTORIES:
        raise ValueError(f"duplicate detector name: {instance.name}")
    _FACTORIES[instance.name] = factory
    return factory


def all_detectors() -> list[Detector]:
    return [factory() for factory in _FACTORIES.values()]


def get_detectors(
    stage: EventType, disabled: frozenset[str] = frozenset(), families: frozenset[str] | None = None
) -> list[Detector]:
    detectors = []
    for factory in _FACTORIES.values():
        det = factory()
        if stage not in det.stages or det.name in disabled:
            continue
        if families is not None and det.family not in families:
            continue
        detectors.append(det)
    return detectors


def load_builtin_detectors() -> None:
    """Import detector modules so their `register` calls run. Idempotent."""
    from mcpshield.detectors import (  # noqa: F401
        cross_tool,
        hidden_text,
        instruction,
        llm_judge,
        policy,
        rag_similarity,
        reputation,
        schema_params,
        sensitive_data,
        taint,
    )
