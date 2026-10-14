"""The threat-KB example payloads must stay held-out from the eval scenario payloads."""

from __future__ import annotations

from mcpshield.config import Settings
from mcpshield.data_loader import load_benign, load_scenarios, read_yaml
from mcpshield.text_utils import jaccard, normalize, shingles

_NEAR_DUPLICATE = 0.6


def _scenario_payloads(settings: Settings) -> list[str]:
    texts: list[str] = []
    for scenario in load_scenarios(settings):
        texts.extend(scenario.payloads)
        for behavior in scenario.utility.values():
            if behavior.description:
                texts.append(behavior.description)
            texts.extend(behavior.description_versions)
            if behavior.output:
                texts.append(behavior.output)
            texts.extend(behavior.extra_params.values())
    for task in load_benign(settings):
        for behavior in task.utility.values():
            if behavior.description:
                texts.append(behavior.description)
    return [t for t in texts if t.strip()]


def test_kb_examples_disjoint_from_scenarios(settings: Settings) -> None:
    examples = [e["text"] for e in read_yaml(settings.paths.threat_kb_dir / "examples.yaml")["examples"]]
    scenario_texts = _scenario_payloads(settings)
    scenario_norm = {normalize(t) for t in scenario_texts}
    scenario_shingles = [shingles(t, n=4) for t in scenario_texts]

    for example in examples:
        norm = normalize(example)
        assert norm not in scenario_norm, f"exact overlap: {example!r}"
        ex_sh = shingles(example, n=4)
        worst = max((jaccard(ex_sh, sh) for sh in scenario_shingles), default=0.0)
        assert worst < _NEAR_DUPLICATE, f"near-duplicate (jaccard={worst:.2f}): {example!r}"
