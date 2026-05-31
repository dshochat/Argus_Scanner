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


# ── v1.9 SCAN-008: JSON schema validation ─────────────────────────────


def test_validate_against_schema_returns_ok_when_schema_none() -> None:
    """When no schema is passed, validation is skipped — fail-open."""
    from dast.inference import validate_against_schema

    ok, err = validate_against_schema({"x": 1}, None)
    assert ok is True
    assert err == ""


def test_validate_against_schema_returns_ok_on_valid_payload() -> None:
    """Valid payload passes validation cleanly."""
    from dast.inference import validate_against_schema

    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "required": ["verdict"],
    }
    ok, err = validate_against_schema({"verdict": "clean"}, schema)
    assert ok is True
    assert err == ""


def test_validate_against_schema_catches_missing_required_field() -> None:
    """Missing required field surfaces as a validation error."""
    from dast.inference import validate_against_schema

    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "required": ["verdict"],
    }
    ok, err = validate_against_schema({"other": "value"}, schema)
    assert ok is False
    assert "verdict" in err.lower() or "required" in err.lower()


def test_validate_against_schema_catches_wrong_type() -> None:
    """Type mismatch surfaces as a validation error."""
    from dast.inference import validate_against_schema

    schema = {
        "type": "object",
        "properties": {"count": {"type": "integer"}},
        "required": ["count"],
    }
    ok, err = validate_against_schema({"count": "not_an_int"}, schema)
    assert ok is False


def test_validate_against_schema_catches_extra_field_when_additional_props_forbidden() -> None:
    """When ``additionalProperties: false`` is set, extra fields fail."""
    from dast.inference import validate_against_schema

    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"a": {"type": "string"}},
        "required": ["a"],
    }
    ok, err = validate_against_schema({"a": "x", "b": "extra"}, schema)
    assert ok is False


def test_validate_against_schema_catches_enum_violation() -> None:
    """Value outside declared enum fails."""
    from dast.inference import validate_against_schema

    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string", "enum": ["clean", "malicious"]}},
        "required": ["verdict"],
    }
    ok, err = validate_against_schema({"verdict": "garbage"}, schema)
    assert ok is False


def test_validate_against_schema_fail_open_on_malformed_schema() -> None:
    """A malformed schema (e.g., invalid keyword) should NOT block the
    scan — schema validation is defense-in-depth, not the primary
    correctness gate. Log + return True."""
    from dast.inference import validate_against_schema

    bad_schema = {"type": 12345}
    ok, err = validate_against_schema({"any": "data"}, bad_schema)
    assert ok is True


def test_parse_anthropic_response_surfaces_schema_violation() -> None:
    """When schema is passed and tool_use violates it, the response
    dict carries schema_valid=False + schema_error so the orchestrator
    can detect malformed structured output."""
    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "required": ["verdict"],
    }
    msg = _FakeMessage(content=[_FakeBlock(type="tool_use", input={"wrong_field": "x"})])
    out = parse_anthropic_response(msg, schema_provided=True, schema=schema)
    assert out["schema_valid"] is False
    assert "verdict" in out["schema_error"].lower() or "required" in out["schema_error"].lower()


def test_parse_anthropic_response_schema_valid_on_clean_payload() -> None:
    """Clean tool_use payload surfaces schema_valid=True."""
    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "required": ["verdict"],
    }
    msg = _FakeMessage(content=[_FakeBlock(type="tool_use", input={"verdict": "clean"})])
    out = parse_anthropic_response(msg, schema_provided=True, schema=schema)
    assert out["schema_valid"] is True
    assert out["schema_error"] == ""


def test_parse_anthropic_response_no_schema_no_validation() -> None:
    """When schema is None, no validation occurs and schema_valid=True."""
    msg = _FakeMessage(content=[_FakeBlock(type="text", text="hello")])
    out = parse_anthropic_response(msg, schema_provided=False, schema=None)
    assert out["schema_valid"] is True
    assert out["text"] == "hello"


def test_parse_anthropic_response_schema_supplied_but_no_tool_use_surfaces_error() -> None:
    """When schema_provided=True but the model emitted only text
    (thinking-mode bug, model misbehaved), we surface schema_valid=False
    so the orchestrator can detect the silent-fail path that previously
    looked like 'empty response'."""
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}
    msg = _FakeMessage(content=[_FakeBlock(type="text", text="reasoning text here")])
    out = parse_anthropic_response(msg, schema_provided=True, schema=schema)
    assert out["schema_valid"] is False
    assert out["schema_error"]


# ── v1.10 SCAN-009: infer_with_schema_retry ────────────────────────────────


import pytest  # noqa: E402

from dast.inference import infer_with_schema_retry  # noqa: E402


def _stub_response(
    *,
    schema_valid: bool,
    text: str = "{}",
    prompt_tokens: int = 100,
    completion_tokens: int = 50,
    schema_error: str = "",
) -> dict[str, Any]:
    """Minimal InferenceFn response dict for the retry helper tests."""
    out: dict[str, Any] = {
        "text": text,
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
        "finish_reason": "tool_use",
        "schema_valid": schema_valid,
        "schema_error": schema_error,
    }
    return out


@pytest.mark.asyncio
async def test_infer_with_schema_retry_no_retry_on_valid_first() -> None:
    """Happy path: original call passes validation → no retry fires.
    Original response is returned untouched (plus diagnostic flags)."""
    calls: list[str] = []

    async def fake_inference(prompt: str, opts: dict, schema: dict | None) -> dict:
        calls.append(prompt)
        return _stub_response(schema_valid=True, text='{"ok": true}')

    out = await infer_with_schema_retry(fake_inference, "original prompt", {}, {"type": "object"})

    assert len(calls) == 1, "no retry should fire when first call passes"
    assert calls[0] == "original prompt"
    assert out["_schema_retry_attempted"] is False
    assert out["_schema_retry_succeeded"] is False
    assert out["text"] == '{"ok": true}'


@pytest.mark.asyncio
async def test_infer_with_schema_retry_succeeds_on_retry() -> None:
    """First call fails validation, retry succeeds: returns retry
    response, sums token usage, sets succeeded flag."""
    calls: list[str] = []
    responses = iter(
        [
            _stub_response(
                schema_valid=False,
                text='{"partial": true}',
                prompt_tokens=200,
                completion_tokens=80,
                schema_error="'current_verdict' is a required property",
            ),
            _stub_response(
                schema_valid=True,
                text='{"full": true}',
                prompt_tokens=210,
                completion_tokens=90,
            ),
        ]
    )

    async def fake_inference(prompt: str, opts: dict, schema: dict | None) -> dict:
        calls.append(prompt)
        return next(responses)

    out = await infer_with_schema_retry(fake_inference, "original", {}, {"type": "object"})

    assert len(calls) == 2
    assert calls[0] == "original"
    assert "[SCHEMA VALIDATION RETRY]" in calls[1]
    assert "current_verdict" in calls[1], "preamble must include the specific schema error"
    assert "original" in calls[1], "retry must include the original prompt body"
    assert out["text"] == '{"full": true}', "retry response is returned, not original"
    assert out["_schema_retry_attempted"] is True
    assert out["_schema_retry_succeeded"] is True
    # Cost discipline: token usage must be summed across both calls so
    # ScanConfig.max_cost_per_file_usd accounting catches retry spend.
    assert out["usage"]["prompt_tokens"] == 200 + 210
    assert out["usage"]["completion_tokens"] == 80 + 90


@pytest.mark.asyncio
async def test_infer_with_schema_retry_exhausted_returns_retry_response() -> None:
    """First call fails validation, retry ALSO fails: returns retry
    response (model's latest best-effort), flags failure, surfaces
    the error so the orchestrator can append a journal record."""
    responses = iter(
        [
            _stub_response(
                schema_valid=False,
                text='{"partial1": true}',
                schema_error="missing claim_verdicts",
            ),
            _stub_response(
                schema_valid=False,
                text='{"partial2": true}',
                schema_error="missing current_verdict",
            ),
        ]
    )

    async def fake_inference(prompt: str, opts: dict, schema: dict | None) -> dict:
        return next(responses)

    out = await infer_with_schema_retry(fake_inference, "orig", {}, {"type": "object"})

    assert out["_schema_retry_attempted"] is True
    assert out["_schema_retry_succeeded"] is False
    assert "current_verdict" in out["_schema_retry_error"]
    # We return the retry response, not the original — it's the model's
    # latest best-effort and the orchestrator's _parse_json_or_empty
    # already handles partial JSON gracefully.
    assert out["text"] == '{"partial2": true}'


@pytest.mark.asyncio
async def test_infer_with_schema_retry_retry_raises_falls_back_to_original() -> None:
    """If the retry call raises (network/API error), fall back to the
    ORIGINAL response so we never leave the orchestrator with less than
    it had before the retry attempt. Production-grade defense-in-depth:
    a retry helper that crashes the call is worse than no retry at all.
    """
    call_count = [0]

    async def fake_inference(prompt: str, opts: dict, schema: dict | None) -> dict:
        call_count[0] += 1
        if call_count[0] == 1:
            return _stub_response(
                schema_valid=False,
                text='{"original": true}',
                schema_error="missing field",
            )
        raise RuntimeError("simulated network error on retry")

    out = await infer_with_schema_retry(fake_inference, "orig", {}, {"type": "object"})

    assert call_count[0] == 2
    # We fall back to the original response, not the exception.
    assert out["text"] == '{"original": true}'
    assert out["_schema_retry_attempted"] is True
    assert out["_schema_retry_succeeded"] is False
    assert "retry_call_raised" in out["_schema_retry_error"]
    assert "RuntimeError" in out["_schema_retry_error"]


@pytest.mark.asyncio
async def test_infer_with_schema_retry_original_call_exception_propagates() -> None:
    """Exceptions on the FIRST call must propagate — they signal a real
    failure mode (network, auth, rate limit) that the helper shouldn't
    mask as a schema issue. Only the retry call gets the safety net.
    """

    async def fake_inference(prompt: str, opts: dict, schema: dict | None) -> dict:
        raise RuntimeError("first-call network error")

    with pytest.raises(RuntimeError, match="first-call"):
        await infer_with_schema_retry(fake_inference, "orig", {}, {"type": "object"})


@pytest.mark.asyncio
async def test_infer_with_schema_retry_preamble_does_not_modify_options() -> None:
    """The retry must pass the original options dict unchanged — no
    temperature drift, no max_tokens mutation. Production hardening
    against accidental coupling."""
    seen_options: list[dict] = []

    async def fake_inference(prompt: str, opts: dict, schema: dict | None) -> dict:
        seen_options.append(opts)
        if len(seen_options) == 1:
            return _stub_response(schema_valid=False, schema_error="bad")
        return _stub_response(schema_valid=True)

    original_opts = {"temperature": 0.0, "max_tokens": 6144, "seed": 0}
    await infer_with_schema_retry(fake_inference, "orig", original_opts, {"type": "object"})

    assert seen_options[0] == original_opts
    assert seen_options[1] == original_opts
    # The caller's dict reference is preserved (no defensive copy needed
    # because we don't mutate it).
    assert seen_options[0] is original_opts


@pytest.mark.asyncio
async def test_infer_with_schema_retry_missing_schema_valid_treated_as_valid() -> None:
    """Defensive: if an InferenceFn returns a response without the
    ``schema_valid`` key (non-Anthropic adapter, malformed response),
    don't fire a retry — that's a different bug. ``.get(..., True)``
    fail-open semantics."""
    calls = [0]

    async def fake_inference(prompt: str, opts: dict, schema: dict | None) -> dict:
        calls[0] += 1
        return {"text": "{}", "usage": {}, "finish_reason": "x"}  # no schema_valid key

    out = await infer_with_schema_retry(fake_inference, "orig", {}, {"type": "object"})

    assert calls[0] == 1, "no retry when schema_valid key is absent"
    assert out["_schema_retry_attempted"] is False
