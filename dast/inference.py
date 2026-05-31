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


def validate_against_schema(
    parsed: dict[str, Any], schema: dict[str, Any] | None
) -> tuple[bool, str]:
    """v1.9 SCAN-008: JSON schema validation for model responses.

    Even when the model is forced into tool_use mode, the emitted
    ``input`` dict can violate the schema — missing required fields,
    wrong types, extra fields under ``additionalProperties: false``,
    enum values outside the declared set. Without explicit validation,
    those violations propagate into downstream code as silent
    KeyErrors or wrong-shape data.

    Returns ``(ok, error_msg)``. ``ok=True`` means valid (or no
    schema supplied — skipped). ``error_msg`` is empty on success,
    a short human-readable diagnostic on failure.

    The validator is lenient on transitive failures: if jsonschema
    itself can't import or the schema is malformed, we return
    ``(True, "")`` rather than blocking the scan — schema validation
    is defense-in-depth, not the primary correctness gate.
    """
    if not schema or not isinstance(schema, dict):
        return True, ""
    if not isinstance(parsed, dict):
        return False, f"response is not a dict (got {type(parsed).__name__})"
    try:
        import jsonschema  # noqa: PLC0415
    except ImportError:
        return True, ""  # validation unavailable — fail open
    try:
        jsonschema.validate(instance=parsed, schema=schema)
        return True, ""
    except jsonschema.ValidationError as exc:
        # Compact the error: path + message, no traceback.
        path = ".".join(str(p) for p in exc.absolute_path) or "<root>"
        msg = str(exc.message)[:200]
        return False, f"schema violation at {path}: {msg}"
    except jsonschema.SchemaError as exc:
        # Malformed schema — log + skip rather than block.
        log.warning("schema malformed, skipping validation: %s", exc)
        return True, ""


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
    response: Any,
    schema_provided: bool,
    schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert an Anthropic ``Message`` to the orchestrator dict shape.

    When a schema was provided, the model returns a ``tool_use`` block
    whose ``input`` carries the structured response — we serialize it as
    JSON for the orchestrator's existing ``_parse_json_or_empty`` path.
    When no schema, we concatenate text blocks.

    v1.9 SCAN-008: when ``schema`` is passed (alongside
    ``schema_provided=True``), the extracted tool_input is validated
    against the schema via :func:`validate_against_schema`. On
    violation, the response dict surfaces ``schema_valid=False`` +
    ``schema_error`` so the orchestrator can detect malformed
    structured output explicitly rather than treating it as a silent
    empty response.
    """
    text_parts: list[str] = []
    tool_input: dict[str, Any] | None = None

    for block in response.content:
        block_type = getattr(block, "type", None)
        if block_type == "text":
            text_parts.append(block.text)
        elif block_type == "tool_use":
            tool_input = block.input

    schema_valid = True
    schema_error = ""

    if schema_provided and tool_input is not None:
        text = json.dumps(tool_input)
        # v1.9 SCAN-008: validate the extracted tool_input against the
        # caller-supplied schema. Failures surface in the response dict;
        # we don't raise (preserves caller's exception handling).
        schema_valid, schema_error = validate_against_schema(tool_input, schema)
        if not schema_valid:
            log.warning(
                "DAST inference: tool_use response failed schema validation: %s",
                schema_error,
            )
    else:
        text = "\n".join(text_parts)
        if schema_provided and not tool_input:
            log.warning(
                "DAST inference: schema provided but no tool_use block in "
                "response; falling back to concatenated text (likely to "
                "fail downstream JSON parse)"
            )
            schema_valid = False
            schema_error = "schema supplied but model emitted no tool_use block"

    usage = response.usage
    return {
        "text": text,
        "usage": {
            "prompt_tokens": getattr(usage, "input_tokens", 0) if usage else 0,
            "completion_tokens": getattr(usage, "output_tokens", 0) if usage else 0,
        },
        "finish_reason": getattr(response, "stop_reason", None) or "unknown",
        "schema_valid": schema_valid,
        "schema_error": schema_error,
    }


# ── Production factory ─────────────────────────────────────────────────────


def make_dast_sonnet_inference(
    api_key: str,
    *,
    model_id: str = "claude-sonnet-4-6",
) -> InferenceFn:
    """Workhorse-tier backing for the DAST orchestrator.

    DAST is a many-call iter loop (3 phases × up to 3 iterations × N
    hypotheses) so per-call spend matters. ``thinking_budget=8000``
    keeps cost in check; iter-3 reasoning-tier escalation (DAST-103)
    bumps to a deeper budget by swapping in
    :func:`make_dast_opus_inference`.

    SCAN-020 v1.11.1: ``model_id`` is the scan-tier model. Default is
    the v1.11 Sonnet 4.6 pin; CLI's ``--scan-model`` flag overrides
    via ScanConfig.scan_model.
    """
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=api_key)
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
        return parse_anthropic_response(response, schema_provided=schema is not None, schema=schema)

    return infer


def make_dast_opus_inference(
    api_key: str,
    *,
    model_id: str = "claude-opus-4-6",
) -> InferenceFn:
    """Reasoning-tier backing for DAST iter-3 escalation (DAST-103)
    and the Adversarial Reasoning loop (Phase 3 Stage 2).

    Same shape as the scan-tier inference but ``thinking_budget=24000``
    ("extra high" depth) and the deeper model. Used by the orchestrator
    only when iter-1 and iter-2 both produced inconclusive verdicts.

    SCAN-020 v1.11.1: ``model_id`` is the reasoning-tier model.
    Default is the v1.11 Opus 4.6 pin; CLI's ``--reasoning-model``
    flag overrides via ScanConfig.reasoning_model.
    """
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=api_key)
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
        return parse_anthropic_response(response, schema_provided=schema is not None, schema=schema)

    return infer


# ── v1.10 SCAN-009: Phase A schema-retry chokepoint hardening ──────────────


async def infer_with_schema_retry(
    inference: InferenceFn,
    prompt: str,
    options: dict[str, Any],
    schema: dict[str, Any],
) -> dict[str, Any]:
    """Retry-once wrapper for Phase A inference calls.

    Phase A is the cascade chokepoint: ``claim_verdicts`` populate
    ``findings_validated``, which gates Phase D, DAST-304, Tier 1.5,
    and adjudication. A single bad LLM response (Opus 4.6 occasionally
    drops a required top-level key in tool_use mode) demotes a scan
    from full coverage to near-zero coverage. SCAN-008's fail-open
    behavior preserves the partial response but the silent degradation
    is too high a blast radius for the disclosure surface.

    On schema-validation failure, retries ONCE with a stricter preamble
    that frames the retry as re-serialization (not re-analysis), so the
    model fixes schema conformance without perturbing the verdict.

    Contract
    --------
    * Exceptions from the FIRST call propagate (don't mask network/
      API failures as schema drift).
    * Exceptions from the RETRY call are caught — return the original
      response with ``_schema_retry_error`` set so the caller can
      surface the cascade explicitly.
    * Token usage is summed across both calls so per-file/per-scan
      cost caps catch the retry spend.
    * Returns the retry's response if it fired; the model's latest
      best-effort even when the retry also fails (existing orchestrator
      fallback handles partial JSON).
    * Hard cap = 1 retry. Subsequent retries on the same prompt return
      the same drift empirically.

    Diagnostic keys added to the response dict (prefixed ``_`` to mark
    them as internal, not part of the ``InferenceFn`` public contract):
      * ``_schema_retry_attempted``: bool
      * ``_schema_retry_succeeded``: bool
      * ``_schema_retry_error``: str (only when retry failed or raised)
    """
    first = await inference(prompt, options, schema)
    if first.get("schema_valid", True):
        first["_schema_retry_attempted"] = False
        first["_schema_retry_succeeded"] = False
        return first

    schema_error = first.get("schema_error", "") or "schema validation failed"
    log.warning(
        "Phase A schema validation failed; retrying with stricter preamble: %s",
        schema_error,
    )

    retry_preamble = (
        "[SCHEMA VALIDATION RETRY] Your previous response was rejected by "
        f"schema validation: {schema_error}. Re-emit the SAME analysis "
        "using the emit_response tool, but ensure ALL required top-level "
        "keys are present AND every nested required field is populated. "
        "Do not change your verdict or rationale — only fix schema "
        "conformance.\n\n"
    )

    try:
        second = await inference(retry_preamble + prompt, options, schema)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "Phase A schema retry raised %s; falling back to original response",
            type(exc).__name__,
        )
        first["_schema_retry_attempted"] = True
        first["_schema_retry_succeeded"] = False
        first["_schema_retry_error"] = f"retry_call_raised: {type(exc).__name__}: {exc}"[:200]
        return first

    first_usage = first.get("usage") or {}
    second_usage = second.get("usage") or {}
    second["usage"] = {
        "prompt_tokens": (first_usage.get("prompt_tokens") or 0)
        + (second_usage.get("prompt_tokens") or 0),
        "completion_tokens": (first_usage.get("completion_tokens") or 0)
        + (second_usage.get("completion_tokens") or 0),
    }
    second["_schema_retry_attempted"] = True
    second["_schema_retry_succeeded"] = bool(second.get("schema_valid", True))
    if not second["_schema_retry_succeeded"]:
        second["_schema_retry_error"] = second.get("schema_error", "") or schema_error
    return second


__all__ = [
    "InferenceFn",
    "build_anthropic_kwargs",
    "infer_with_schema_retry",
    "make_dast_opus_inference",
    "make_dast_sonnet_inference",
    "parse_anthropic_response",
    "validate_against_schema",
]
