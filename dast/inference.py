"""DAST-101 — Sonnet 4.6 inference function for the DAST orchestrator.

The orchestrator (`dast.orchestrator.run_dast`) takes a callable matching
:data:`dast.orchestrator.InferenceFn`::

    inference(prompt: str, options: dict, schema: dict | None) -> dict

This module wraps :class:`anthropic.AsyncAnthropic` to satisfy that
contract, with two key adaptations to the lifted echoDefense interface:

  * Schema enforcement uses Anthropic's ``tool_use`` mode (force a
    specific tool with the orchestrator-supplied JSON schema). This
    gives us first-class structured output without prompt-engineering
    the schema into the user message body.
  * ``options`` accepts ``temperature`` / ``seed`` for compatibility
    with the orchestrator's existing call sites, but these are
    advisory under Claude 4.x adaptive thinking. ``max_tokens`` is
    honored.

Phase 3 deliberately wires a single provider per agentic loop (see
README architecture invariants). Iter-3 Opus escalation lands in
DAST-103 by *swapping* the inference function mid-loop, not by
mixing providers within one call.

Public API::

    make_dast_sonnet_inference(api_key)
        Production factory — claude-sonnet-4-6, effort=medium (DAST is
        a many-call iter loop; Opus escalation handles the deep cases).

    build_anthropic_kwargs(prompt, options, schema, model_id, effort)
        Pure helper. Constructs the messages.stream kwargs dict.
        Exported for tests.

    parse_anthropic_response(response, schema_provided)
        Pure helper. Converts an Anthropic Message to the
        orchestrator's expected {text, usage, finish_reason} shape.
        Exported for tests.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable

log = logging.getLogger("argus.dast.inference")

InferenceFn = Callable[[str, dict[str, Any], dict[str, Any] | None], Awaitable[dict[str, Any]]]


# ── Pure helpers (testable without a network) ──────────────────────────────


def build_anthropic_kwargs(
    prompt: str,
    options: dict[str, Any],
    schema: dict[str, Any] | None,
    *,
    model_id: str,
    thinking_budget: int = 8000,
) -> dict[str, Any]:
    """Map the orchestrator's (prompt, options, schema) to messages.stream
    kwargs.

    The full prompt becomes the user message — the orchestrator's prompt
    builders embed system-style instructions inline, so we don't try to
    parse out a system block. Temperature / seed in ``options`` are
    ignored (Claude 4.x with extended thinking doesn't honor them).

    Anthropic API constraint: ``thinking`` cannot be combined with a
    forced ``tool_choice`` (the API returns 400 with "Thinking may not
    be enabled when tool_choice forces tool use"). When a schema is
    supplied we drop ``thinking`` and let the model emit a single
    forced tool call. When no schema, thinking is enabled with the
    configured budget.

    DAST defaults to ``thinking_budget=8000`` — DAST is a many-call iter
    loop (3 phases × up to 3 iterations × N hypotheses) so per-call
    spend matters; deeper budgets are reserved for the DAST-103 iter-3
    Opus escalation path.
    """
    max_tokens_base = int(options.get("max_tokens", 6144))

    kwargs: dict[str, Any] = {
        "model": model_id,
        "messages": [{"role": "user", "content": prompt}],
    }

    if schema:
        # Force the model to emit a single tool call carrying the
        # structured response. Thinking is intentionally OFF here; see
        # docstring for the API constraint that drives this.
        kwargs["max_tokens"] = max_tokens_base
        kwargs["tools"] = [
            {
                "name": "emit_response",
                "description": (
                    "Emit the structured response. Required: input must "
                    "conform to the supplied JSON schema exactly."
                ),
                "input_schema": schema,
            }
        ]
        kwargs["tool_choice"] = {"type": "tool", "name": "emit_response"}
    else:
        # Free-text path — extended thinking on, with explicit budget.
        kwargs["max_tokens"] = max_tokens_base + thinking_budget
        kwargs["thinking"] = {"type": "enabled", "budget_tokens": thinking_budget}

    return kwargs


def parse_anthropic_response(
    response: Any, schema_provided: bool
) -> dict[str, Any]:
    """Convert an Anthropic ``Message`` to the orchestrator dict shape.

    When a schema was provided, the model returns a ``tool_use`` block
    whose ``input`` carries the structured response — we serialize it as
    JSON for the orchestrator's existing ``_parse_json_or_empty`` path.
    When no schema, we concatenate text blocks.
    """
    text_parts: list[str] = []
    tool_input: dict[str, Any] | None = None

    for block in response.content:
        block_type = getattr(block, "type", None)
        if block_type == "text":
            text_parts.append(block.text)
        elif block_type == "tool_use":
            tool_input = block.input

    if schema_provided and tool_input is not None:
        text = json.dumps(tool_input)
    else:
        text = "\n".join(text_parts)
        if schema_provided and not tool_input:
            log.warning(
                "DAST inference: schema provided but no tool_use block in "
                "response; falling back to concatenated text (likely to "
                "fail downstream JSON parse)"
            )

    usage = response.usage
    return {
        "text": text,
        "usage": {
            "prompt_tokens": getattr(usage, "input_tokens", 0) if usage else 0,
            "completion_tokens": getattr(usage, "output_tokens", 0) if usage else 0,
        },
        "finish_reason": getattr(response, "stop_reason", None) or "unknown",
    }


# ── Production factory ─────────────────────────────────────────────────────


def make_dast_sonnet_inference(api_key: str) -> InferenceFn:
    """Sonnet 4.6 backing for the DAST orchestrator.

    DAST is a many-call iter loop (3 phases × up to 3 iterations × N
    hypotheses) so per-call spend matters. ``thinking_budget=8000``
    keeps cost in check; iter-3 Opus escalation (DAST-103) bumps to a
    deeper budget by swapping in a different inference function.
    """
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=api_key)
    model_id = "claude-sonnet-4-6"
    thinking_budget = 8000

    async def infer(
        prompt: str,
        options: dict[str, Any],
        schema: dict[str, Any] | None,
    ) -> dict[str, Any]:
        kwargs = build_anthropic_kwargs(
            prompt, options, schema, model_id=model_id, thinking_budget=thinking_budget
        )
        async with client.messages.stream(**kwargs) as stream:
            response = await stream.get_final_message()
        return parse_anthropic_response(response, schema_provided=schema is not None)

    return infer


def make_dast_opus_inference(api_key: str) -> InferenceFn:
    """Opus 4.6 backing for DAST iter-3 escalation (DAST-103).

    Same shape as the Sonnet inference but ``thinking_budget=24000``
    ("extra high" depth) and the deeper model. Used by the orchestrator
    only when iter-1 and iter-2 both produced inconclusive verdicts.
    """
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=api_key)
    model_id = "claude-opus-4-6"
    thinking_budget = 24000

    async def infer(
        prompt: str,
        options: dict[str, Any],
        schema: dict[str, Any] | None,
    ) -> dict[str, Any]:
        kwargs = build_anthropic_kwargs(
            prompt, options, schema, model_id=model_id, thinking_budget=thinking_budget
        )
        async with client.messages.stream(**kwargs) as stream:
            response = await stream.get_final_message()
        return parse_anthropic_response(response, schema_provided=schema is not None)

    return infer


__all__ = [
    "InferenceFn",
    "build_anthropic_kwargs",
    "make_dast_opus_inference",
    "make_dast_sonnet_inference",
    "parse_anthropic_response",
]
