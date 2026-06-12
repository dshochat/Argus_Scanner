"""Unit tests for the Anthropic adapter's model-aware thinking config.

Opus 4.7+ removed the legacy extended-thinking API
(``thinking.type=enabled`` + ``budget_tokens`` → 400) and requires
adaptive thinking + ``output_config.effort``. The adapter must pick the
right shape per model so Argus can scan with any Anthropic model
(Opus 4.6 legacy path AND Opus 4.7/4.8 adaptive path)."""
from __future__ import annotations

from inference.adapters import (
    _anthropic_thinking_kwargs,
    _budget_to_effort,
    _requires_adaptive_thinking,
)


def test_requires_adaptive_thinking_by_version() -> None:
    # Opus 4.7+ rejects legacy enabled → needs adaptive.
    assert _requires_adaptive_thinking("claude-opus-4-8") is True
    assert _requires_adaptive_thinking("claude-opus-4-7") is True
    assert _requires_adaptive_thinking("claude-opus-5-0") is True  # future-proof
    assert _requires_adaptive_thinking("claude-sonnet-4-7") is True
    # 4.6 / earlier still accept the legacy enabled path.
    assert _requires_adaptive_thinking("claude-opus-4-6") is False
    assert _requires_adaptive_thinking("claude-sonnet-4-6") is False
    assert _requires_adaptive_thinking("claude-haiku-4-5") is False
    # Unknown / unparseable model strings default to legacy (safe).
    assert _requires_adaptive_thinking("some-custom-model") is False
    assert _requires_adaptive_thinking("") is False


def test_budget_to_effort_mapping() -> None:
    assert _budget_to_effort(24000) == "high"   # cascade default "extra high"
    assert _budget_to_effort(20000) == "high"
    assert _budget_to_effort(12000) == "medium"
    assert _budget_to_effort(8000) == "medium"
    assert _budget_to_effort(2000) == "low"


def test_thinking_kwargs_opus_48_uses_adaptive() -> None:
    """Opus 4.8 must get adaptive + effort — NOT enabled/budget_tokens
    (which 400s). This is the exact bug that made Opus 4.8 scans fail."""
    kw = _anthropic_thinking_kwargs("claude-opus-4-8", 24000)
    assert kw == {"thinking": {"type": "adaptive"}, "output_config": {"effort": "high"}}
    assert "budget_tokens" not in str(kw)
    assert "enabled" not in str(kw)


def test_thinking_kwargs_opus_46_keeps_legacy() -> None:
    """Opus 4.6 keeps the legacy enabled+budget path (deprecated but
    accepted) to preserve the cascade's tuned explicit-budget behavior."""
    kw = _anthropic_thinking_kwargs("claude-opus-4-6", 24000)
    assert kw == {"thinking": {"type": "enabled", "budget_tokens": 24000}}


def test_thinking_kwargs_below_floor_is_omitted() -> None:
    """budget < 1024 means 'thinking off' — omit entirely for BOTH paths
    (legacy 400s on budget<1024; adaptive has no budget knob)."""
    assert _anthropic_thinking_kwargs("claude-opus-4-8", 0) == {}
    assert _anthropic_thinking_kwargs("claude-opus-4-6", 500) == {}
