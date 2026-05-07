"""Unit tests for DAST-101 — dast.inference.

Tests the pure helpers (``build_anthropic_kwargs`` + ``parse_anthropic_
response``) directly. The streaming-client wrapper is exercised by
DAST-107's live integration test post-DAST-106.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from dast.inference import build_anthropic_kwargs, parse_anthropic_response

# ── Fake Anthropic response objects ────────────────────────────────────────


@dataclass
class _FakeUsage:
    input_tokens: int = 100
    output_tokens: int = 50


@dataclass
class _FakeBlock:
    type: str
    text: str = ""
    input: dict[str, Any] | None = None


@dataclass
class _FakeMessage:
    content: list[_FakeBlock]
    usage: _FakeUsage = None  # type: ignore[assignment]
    stop_reason: str | None = "end_turn"

    def __post_init__(self) -> None:
        if self.usage is None:
            self.usage = _FakeUsage()


# ── build_anthropic_kwargs ─────────────────────────────────────────────────


def test_build_kwargs_no_schema() -> None:
    out = build_anthropic_kwargs(
        prompt="analyze this",
        options={"max_tokens": 4096, "temperature": 0.0, "seed": 0},
        schema=None,
        model_id="claude-sonnet-4-6",
        thinking_budget=8000,
    )
    assert out["model"] == "claude-sonnet-4-6"
    # max_tokens = base + thinking_budget so the model has 4096 tokens
    # of OUTPUT after using its 8000-token thinking budget.
    assert out["max_tokens"] == 4096 + 8000
    assert out["messages"] == [{"role": "user", "content": "analyze this"}]
    assert out["thinking"] == {"type": "enabled", "budget_tokens": 8000}
    # Temperature / seed are not propagated — Claude 4.x with extended
    # thinking ignores them; passing them can trigger SDK warnings.
    assert "temperature" not in out
    assert "seed" not in out
    # Without a schema, no tool_use forcing
    assert "tools" not in out
    assert "tool_choice" not in out
    # output_config no longer used (was for the adaptive-thinking shape)
    assert "output_config" not in out


def test_build_kwargs_with_schema_sets_tool_use_mode() -> None:
    schema = {
        "type": "object",
        "properties": {"plans": {"type": "array"}},
        "required": ["plans"],
    }
    out = build_anthropic_kwargs(
        prompt="generate plans",
        options={"max_tokens": 6144},
        schema=schema,
        model_id="claude-sonnet-4-6",
    )
    assert "tools" in out
    assert len(out["tools"]) == 1
    tool = out["tools"][0]
    assert tool["name"] == "emit_response"
    assert tool["input_schema"] == schema
    assert out["tool_choice"] == {"type": "tool", "name": "emit_response"}
    # Schema path: max_tokens is the base value (no thinking budget added,
    # since thinking is disabled when forcing tool_choice).
    assert out["max_tokens"] == 6144


def test_build_kwargs_drops_thinking_when_schema_forces_tool_choice() -> None:
    """Regression test for the Anthropic API constraint:
    'Thinking may not be enabled when tool_choice forces tool use.'
    Discovered live during DAST-107's first run. When a schema is
    supplied (orchestrator wants structured output via forced tool_use),
    we MUST omit ``thinking`` or the API returns 400.
    """
    out = build_anthropic_kwargs(
        prompt="x",
        options={},
        schema={"type": "object", "properties": {}, "required": []},
        model_id="claude-sonnet-4-6",
        thinking_budget=8000,
    )
    assert "thinking" not in out, "thinking must NOT be set when tool_choice forces a tool"
    # Forced tool_choice still in place
    assert out["tool_choice"] == {"type": "tool", "name": "emit_response"}


def test_build_kwargs_default_max_tokens_and_budget() -> None:
    """max_tokens defaults to 6144; thinking_budget defaults to 8000;
    final max_tokens (no-schema path) sums to 14144."""
    out = build_anthropic_kwargs(prompt="x", options={}, schema=None, model_id="claude-sonnet-4-6")
    assert out["max_tokens"] == 6144 + 8000
    assert out["thinking"] == {"type": "enabled", "budget_tokens": 8000}


def test_build_kwargs_opus_extra_high_thinking() -> None:
    """Iter-3 Opus path uses thinking_budget=24000 (DAST-103 hookup)."""
    out = build_anthropic_kwargs(
        prompt="x",
        options={},
        schema=None,
        model_id="claude-opus-4-6",
        thinking_budget=24000,
    )
    assert out["model"] == "claude-opus-4-6"
    assert out["thinking"] == {"type": "enabled", "budget_tokens": 24000}
    assert out["max_tokens"] == 6144 + 24000


# ── parse_anthropic_response ───────────────────────────────────────────────


def test_parse_with_schema_serializes_tool_input() -> None:
    """When a schema was provided and the model returned tool_use, the
    structured input must come back as a JSON string in the ``text``
    field — that's what the orchestrator's _parse_json_or_empty reads."""
    plans = {"plans": [{"hypothesis_id": "H001", "commands": ["echo hi"]}]}
    msg = _FakeMessage(
        content=[_FakeBlock(type="tool_use", input=plans)],
        stop_reason="tool_use",
    )
    out = parse_anthropic_response(msg, schema_provided=True)
    assert json.loads(out["text"]) == plans
    assert out["usage"] == {"prompt_tokens": 100, "completion_tokens": 50}
    assert out["finish_reason"] == "tool_use"


def test_parse_no_schema_concatenates_text_blocks() -> None:
    msg = _FakeMessage(
        content=[
            _FakeBlock(type="text", text="part one"),
            _FakeBlock(type="text", text="part two"),
        ],
    )
    out = parse_anthropic_response(msg, schema_provided=False)
    assert out["text"] == "part one\npart two"
    assert out["finish_reason"] == "end_turn"


def test_parse_with_schema_but_no_tool_use_falls_back_to_text() -> None:
    """If schema was requested but the model emitted text instead of
    tool_use (rare — defensive path), we don't crash; we surface the
    text and log a warning. Downstream JSON parse may fail but that's
    the orchestrator's existing failure mode, not ours."""
    msg = _FakeMessage(
        content=[_FakeBlock(type="text", text='{"plans": []}')],
    )
    out = parse_anthropic_response(msg, schema_provided=True)
    assert out["text"] == '{"plans": []}'  # passed through, not re-wrapped


def test_parse_handles_thinking_blocks_implicitly() -> None:
    """Thinking blocks (type='thinking') should be filtered out — they
    aren't text or tool_use, so parse just ignores them naturally."""
    msg = _FakeMessage(
        content=[
            _FakeBlock(type="thinking", text="internal reasoning..."),
            _FakeBlock(type="text", text="final answer"),
        ],
    )
    out = parse_anthropic_response(msg, schema_provided=False)
    assert out["text"] == "final answer"


def test_parse_missing_usage_zero_tokens() -> None:
    msg = _FakeMessage(content=[_FakeBlock(type="text", text="x")])
    msg.usage = None  # type: ignore[assignment]
    out = parse_anthropic_response(msg, schema_provided=False)
    assert out["usage"] == {"prompt_tokens": 0, "completion_tokens": 0}


def test_parse_missing_stop_reason_defaults_unknown() -> None:
    msg = _FakeMessage(content=[_FakeBlock(type="text", text="x")])
    msg.stop_reason = None
    out = parse_anthropic_response(msg, schema_provided=False)
    assert out["finish_reason"] == "unknown"
