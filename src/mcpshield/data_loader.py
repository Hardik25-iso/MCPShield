"""Typed loaders for the data-driven inputs under `data/` (policies, scenarios, synthetic records)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from mcpshield.config import Settings
from mcpshield.schemas import BenignTask, Invoice, Policies, Scenario, Vendor


def read_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@lru_cache(maxsize=4)
def _policies(path: Path) -> Policies:
    return Policies.model_validate(read_yaml(path))


def load_policies(settings: Settings) -> Policies:
    return _policies(settings.paths.policies_file)


def load_scenarios(settings: Settings) -> list[Scenario]:
    raw = read_yaml(settings.paths.scenarios_dir / "attacks.yaml")
    return [Scenario.model_validate(item) for item in raw["scenarios"]]


def load_benign(settings: Settings) -> list[BenignTask]:
    raw = read_yaml(settings.paths.scenarios_dir / "benign.yaml")
    return [BenignTask.model_validate(item) for item in raw["tasks"]]


def load_vendors(settings: Settings) -> list[Vendor]:
    path = settings.paths.synthetic_dir / "vendors.json"
    return [Vendor.model_validate(v) for v in json.loads(path.read_text(encoding="utf-8"))]


def load_invoices(settings: Settings) -> list[Invoice]:
    path = settings.paths.synthetic_dir / "invoices.json"
    return [Invoice.model_validate(v) for v in json.loads(path.read_text(encoding="utf-8"))]
