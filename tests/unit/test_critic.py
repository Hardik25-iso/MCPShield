from __future__ import annotations

from mcpshield.agents.critic import Critic
from mcpshield.config import Settings
from mcpshield.schemas import Action, EventType, Verdict


def _v(family: str, risk: float) -> Verdict:
    return Verdict(detector=family, family=family, risk=risk)


def test_noisy_or_combines_and_saturates(settings: Settings) -> None:
    critic = Critic(settings)
    one = critic.aggregate([_v("instruction", 0.9)])
    two = critic.aggregate([_v("instruction", 0.9), _v("hidden_text", 0.9)])
    assert two.rule_score > one.rule_score
    assert two.rule_score <= 1.0


def test_reputation_is_applied_as_prior_not_double_counted(settings: Settings) -> None:
    critic = Critic(settings)
    base = critic.aggregate([_v("instruction", 0.4)])
    with_rep = critic.aggregate([_v("instruction", 0.4), _v("reputation", 1.0)])
    assert with_rep.reputation_prior > 0
    assert with_rep.score > base.score
    assert "reputation" not in with_rep.components


def test_threshold_mapping(settings: Settings) -> None:
    critic = Critic(settings)
    t = settings.risk.thresholds
    assert critic._map(t.block + 0.05, EventType.TOOL_CALL) is Action.BLOCK
    assert critic._map((t.escalate + t.block) / 2, EventType.TOOL_CALL) is Action.ESCALATE
    assert critic._map(0.0, EventType.TOOL_CALL) is Action.ALLOW
    # Sanitize only applies to content stages; a tool call in that band escalates instead.
    mid = (t.sanitize + t.escalate) / 2
    assert critic._map(mid, EventType.TOOL_RESULT) is Action.SANITIZE
    assert critic._map(mid, EventType.TOOL_CALL) is Action.ESCALATE


def test_grey_zone_bounds(settings: Settings) -> None:
    critic = Critic(settings)
    low, high = settings.risk.grey_zone
    assert critic.in_grey_zone((low + high) / 2)
    assert not critic.in_grey_zone(low - 0.01)
    assert not critic.in_grey_zone(high + 0.01)
