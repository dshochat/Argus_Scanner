"""Argus analysis-tier runners.

Each runner wraps an inference adapter with the combined SECURITY_SCAN_PROMPT
and produces the dict shape ``engine.scan_file`` consumes (vulnerabilities,
behavioral_profile, attack_chains, ai_tool_analysis, verdict_label, plus
cost / token / latency telemetry).

Runners are async callables with the signature::

    async def runner(filename: str, content: bytes, pp: Preprocessing,
                     classification: str) -> dict

The factories in this module wire the adapter + pricing for each tier:

  * :func:`make_sonnet_runner` — Sonnet 4.6 (HIGH-tier default)
  * :func:`make_opus_runner` — Opus 4.6 (high-stakes / borderline escalation,
    added in SCAN-003)

Tests build runners via :func:`make_anthropic_runner_from_adapter` with a
fake adapter, bypassing the live API.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from inference.adapters import AnthropicAdapter, GoogleAdapter
from prompts.scanner import SECURITY_SCAN_PROMPT, TRIAGE_PROMPT
from scanner.sanitizer import sanitize_response

log = logging.getLogger("argus.runners")


# ── Pricing ($/M tokens) ───────────────────────────────────────────────────
# Anthropic public rates. Move to a config module if we need per-customer
# overrides or tier shifts.
SONNET_46_COST_IN = 3.0
SONNET_46_COST_OUT = 15.0
OPUS_46_COST_IN = 15.0
OPUS_46_COST_OUT = 75.0
# Pricing assumed identical for 4.6 (was used as Argus's Opus tier through
# v0.1.0; switched from 4.7 after observing stop_reason=refusal on live-
# payload fixtures). Update if Anthropic publishes a different rate.
# Gemini Flash-Lite preview public rates (verify with BENCH-006 before
# customer-facing cost reporting).
GEMINI_FLASH_LITE_COST_IN = 0.10
GEMINI_FLASH_LITE_COST_OUT = 0.40

_VALID_TRIAGE_CLASSIFICATIONS = ("CLEAN", "LOW", "HIGH")


# ── Uncertainty derivation (SCAN-004) ─────────────────────────────────────


def derive_uncertainty(parsed: dict) -> float:
    """Derive a 0.0-1.0 verdict uncertainty score from a parsed analysis
    response.

    Two signals combine:

    1. **Mean per-finding confidence.** Each ``vulnerabilities[*]``
       entry carries a ``confidence`` field (0.0-1.0). The inverse of
       the mean is a direct measure of how sure the model is about its
       findings. No findings → 0.0 (clean / informational verdicts are
       usually unambiguous).

    2. **Composite-score boundary distance.** ``composite_risk.score``
       is a 0-100 number with verdict cutoffs at 25 / 50 / 75. A score
       close to a cutoff (e.g., 24 vs 26) is inherently borderline —
       even a high-confidence finding could land in either bucket. We
       compute the distance to the nearest cutoff (max half-width 12.5)
       and grow the uncertainty as we approach an edge.

    The two signals are combined with ``max`` — either is sufficient
    to mark the file borderline. The engine compares this against
    ``ScanConfig.sonnet_uncertainty_threshold`` (default 0.4) to decide
    whether to escalate Sonnet to Opus.
    """
    vulns = parsed.get("vulnerabilities") or []
    confidences = [
        float(v.get("confidence", 0.5))
        for v in vulns
        if isinstance(v.get("confidence"), (int, float))
    ]
    if not confidences:
        # No findings or no confidence data → use boundary distance only;
        # clean verdicts (score=0) → 0.0 uncertainty.
        finding_uncertainty = 0.0
    else:
        mean_conf = sum(confidences) / len(confidences)
        finding_uncertainty = max(0.0, min(1.0, 1.0 - mean_conf))

    composite = parsed.get("composite_risk") or {}
    raw_score = composite.get("score")
    try:
        score = float(raw_score) if raw_score is not None else 0.0
    except (TypeError, ValueError):
        score = 0.0
    if 0.0 < score < 100.0:
        # Distance to the nearest verdict cutoff (25/50/75). Each band's
        # half-width is 12.5; closer to the edge → higher uncertainty.
        edge_dist = min(abs(score - 25.0), abs(score - 50.0), abs(score - 75.0))
        boundary_uncertainty = max(0.0, min(1.0, 1.0 - edge_dist / 12.5))
    else:
        # Extreme verdicts (clean = 0 or critical = 100) are unambiguous.
        boundary_uncertainty = 0.0

    return max(finding_uncertainty, boundary_uncertainty)


# ── Score → verdict mapping (inverse of engine._VERDICT_TO_RISK) ───────────


def score_to_verdict(score: int | float | None) -> str:
    """Map composite_risk.score (0-100) to engine verdict_label.

    Verdict scale matches the regression-suite oracle (4 labels):
    ``clean``, ``suspicious``, ``malicious``, ``critical_malicious``.
    The previous 5-label scale included ``informational`` for score 1-24,
    which could never verdict-match the oracle (which never emits
    ``informational``). Score 1-49 now collapses into ``suspicious`` —
    a broad band covering vulnerable code, weak crypto, missing auth,
    and other anomalous-but-not-actively-attacking patterns.

    Conservative on missing/invalid input — defaults to ``suspicious``
    rather than ``clean`` so a parse glitch never silently downgrades.
    """
    if score is None:
        return "suspicious"
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "suspicious"
    if s <= 0:
        return "clean"
    if s < 50:
        return "suspicious"
    if s < 75:
        return "malicious"
    return "critical_malicious"


# ── Generic runner factory ─────────────────────────────────────────────────


def make_anthropic_runner_from_adapter(
    adapter: Any,
    *,
    model_label: str,
    cost_per_m_input: float,
    cost_per_m_output: float,
) -> Callable[..., Awaitable[dict]]:
    """Compose an engine-shape runner from any object with a
    ``scan(content, filename, system_prompt) -> dict`` coroutine method.

    Used by :func:`make_sonnet_runner` (and SCAN-003's Opus runner). Tests
    inject fake adapters that return canned dicts — no live API needed.
    """

    async def runner(
        filename: str,
        content: bytes,
        pp: Any,  # Preprocessing — unused in v1; SCAN-008 will add context
        classification: str,
    ) -> dict:
        text = content.decode("utf-8", errors="replace")
        result = await adapter.scan(text, filename, SECURITY_SCAN_PROMPT)

        parsed = result.get("parsed") or {}
        json_valid = result.get("json_valid", False)
        if not json_valid:
            log.warning(
                "Runner %s: JSON parse failed for %s; returning suspicious",
                model_label,
                filename,
            )

        # SCAN-009: sanitize provider-name and identity leaks before the
        # parsed analysis flows to the engine. Three outcomes:
        #   (clean)  → pass through unchanged
        #   (soft)   → provider names replaced with [redacted]
        #   (hard)   → sanitize_response returns None; treat as error and
        #              fall back to suspicious so DAST can still pick it
        #              up if it's truly malicious.
        sanitizer_error: str | None = None
        if json_valid and parsed:
            sanitized, had_leak = sanitize_response(parsed)
            if sanitized is None:
                sanitizer_error = "identity_leak_in_response"
                log.warning(
                    "Runner %s: identity leak in response for %s",
                    model_label,
                    filename,
                )
                parsed = {}  # treat as parse-failed for downstream extraction
            else:
                if had_leak:
                    log.info(
                        "Runner %s: provider-name leak sanitized for %s",
                        model_label,
                        filename,
                    )
                parsed = sanitized

        score = (parsed.get("composite_risk") or {}).get("score")
        verdict = score_to_verdict(score)

        in_tokens = int(result.get("input_tokens", 0))
        out_tokens = int(result.get("output_tokens", 0))
        cost = (
            in_tokens / 1_000_000 * cost_per_m_input
            + out_tokens / 1_000_000 * cost_per_m_output
        )

        # Surface JSON parse failures as a runner error. Engine logs
        # ``error`` distinctly from a clean scan; without this, a parse
        # failure silently downgrades the verdict (often to suspicious)
        # AND skips DAST (since "suspicious" isn't a DAST trigger),
        # losing scans with no telemetry signal of the underlying issue.
        # Common cause: max_tokens too low → response truncated mid-JSON.
        # Sanitizer errors take precedence over parse-fail since they
        # represent a stronger signal (model identity leaked vs. just
        # truncation).
        adapter_error = result.get("error")
        runner_error: str | None
        if adapter_error:
            runner_error = adapter_error
        elif sanitizer_error:
            runner_error = sanitizer_error
        elif not json_valid:
            runner_error = (
                f"json_parse_failed: model output not valid JSON "
                f"(out_tokens={out_tokens}; possible truncation)"
            )
        else:
            runner_error = None

        return {
            "vulnerabilities": parsed.get("vulnerabilities", []),
            "behavioral_profile": parsed.get("behavioral_profile", {}),
            "attack_chains": parsed.get("attack_chains", []),
            "ai_tool_analysis": parsed.get("ai_tool_analysis", {}),
            "verdict_label": verdict,
            "model": model_label,
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "cost_usd": round(cost, 6),
            "duration_ms": int(result.get("response_time_ms", 0)),
            # SCAN-004: uncertainty derived from per-finding confidence
            # + composite-score boundary distance. Engine compares
            # against cfg.sonnet_uncertainty_threshold (default 0.4)
            # to decide Opus escalation.
            "uncertainty": derive_uncertainty(parsed) if parsed else 0.5,
            "error": runner_error,
        }

    return runner


# ── Public factories ───────────────────────────────────────────────────────


def make_sonnet_runner(api_key: str) -> Callable[..., Awaitable[dict]]:
    """Build the Sonnet 4.6 analysis runner — default HIGH-tier path.

    Configured for deep security analysis: ``thinking_budget=24000``
    ("extra high" depth), system-prompt caching enabled (90% read
    discount on the shared SECURITY_SCAN_PROMPT across multi-file scans).
    """
    adapter = AnthropicAdapter(
        {
            "name": "argus-sonnet-4-6",
            "model_id": "claude-sonnet-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": {
                # 24000 = "extra high" thinking depth (legacy enabled mode
                # supports explicit budgeting; adaptive mode does not).
                "thinking_budget": 24000,
                # 32768 covers Sonnet's full schema response on dense files.
                # Adapter adds thinking_budget on top so the model has
                # 32k tokens of OUTPUT after using its thinking budget.
                "max_tokens": 32768,
                "enable_system_cache": True,
            },
        }
    )
    return make_anthropic_runner_from_adapter(
        adapter,
        model_label="claude-sonnet-4-6",
        cost_per_m_input=SONNET_46_COST_IN,
        cost_per_m_output=SONNET_46_COST_OUT,
    )


# ── Triage runner factory ──────────────────────────────────────────────────


def make_triage_runner_from_adapter(
    adapter: Any,
    *,
    model_label: str,
    cost_per_m_input: float,
    cost_per_m_output: float,
) -> Callable[..., Awaitable[dict]]:
    """Compose an engine-shape triage runner from any object with a
    ``scan(content, filename, system_prompt) -> dict`` coroutine method.

    Triage runners have a different signature than analysis runners — three
    args (filename, content, pp), no classification — and a much smaller
    return shape (classification + reason + telemetry). Used by
    :func:`make_gemini_triage_runner` and unit tests.
    """

    async def runner(filename: str, content: bytes, pp: Any) -> dict:
        text = content.decode("utf-8", errors="replace")
        result = await adapter.scan(text, filename, TRIAGE_PROMPT)

        parsed = result.get("parsed") or {}
        if not result.get("json_valid"):
            log.warning(
                "Triage runner %s: JSON parse failed for %s; defaulting HIGH",
                model_label,
                filename,
            )

        # SCAN-009: sanitize provider-name leaks in the triage `reason`
        # field. Triage has a tighter response shape (no vulns / chains),
        # so the hard-identity-leak fields sanitize_response inspects
        # don't apply — only the soft provider-name sanitization runs.
        sanitizer_error: str | None = None
        if result.get("json_valid") and parsed:
            sanitized, had_leak = sanitize_response(parsed)
            if sanitized is None:
                sanitizer_error = "identity_leak_in_response"
                log.warning(
                    "Triage runner %s: identity leak in response for %s",
                    model_label,
                    filename,
                )
                parsed = {}
            else:
                if had_leak:
                    log.info(
                        "Triage runner %s: provider-name leak sanitized for %s",
                        model_label,
                        filename,
                    )
                parsed = sanitized

        # Safety-net: any unparseable / unexpected classification → HIGH so
        # the cascade pays for deep analysis rather than missing a threat.
        classification = parsed.get("classification")
        if classification not in _VALID_TRIAGE_CLASSIFICATIONS:
            if classification is not None:
                log.warning(
                    "Triage runner %s: invalid classification %r → HIGH",
                    model_label,
                    classification,
                )
            classification = "HIGH"

        reason = parsed.get("reason", "")

        in_tokens = int(result.get("input_tokens", 0))
        out_tokens = int(result.get("output_tokens", 0))
        cost = (
            in_tokens / 1_000_000 * cost_per_m_input
            + out_tokens / 1_000_000 * cost_per_m_output
        )

        adapter_error = result.get("error")
        return {
            "classification": classification,
            "reason": reason,
            "model": model_label,
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "cost_usd": round(cost, 6),
            "duration_ms": int(result.get("response_time_ms", 0)),
            "error": adapter_error or sanitizer_error,
        }

    return runner


def make_gemini_triage_runner(api_key: str) -> Callable[..., Awaitable[dict]]:
    """Build the Gemini Flash-Lite triage runner — cheapest cascade tier.

    No thinking (instant classification); short max_tokens (response is
    <100 tokens). Falls back to HIGH on any unexpected output so the
    cascade favors false-positive cost over false-negative risk.
    """
    adapter = GoogleAdapter(
        {
            "name": "argus-gemini-flash-lite",
            "model_id": "gemini-3.1-flash-lite-preview",
            "api_key_encrypted": api_key,
            "provider": "google",
            "config": {
                "thinking_budget": 0,
                "max_tokens": 512,
            },
        }
    )
    return make_triage_runner_from_adapter(
        adapter,
        model_label="gemini-3.1-flash-lite-preview",
        cost_per_m_input=GEMINI_FLASH_LITE_COST_IN,
        cost_per_m_output=GEMINI_FLASH_LITE_COST_OUT,
    )


def make_opus_runner(api_key: str) -> Callable[..., Awaitable[dict]]:
    """Build the Opus 4.6 analysis runner — high-stakes / borderline tier.

    Same composition as Sonnet but with Opus pricing and the deeper model.
    Engine routes here for files where preprocessing flags a high-stakes
    category (crypto, AI-tool, obfuscation) and for borderline-uncertainty
    escalation from Sonnet.

    thinking_budget=24000 — when we pay Opus's premium we want full
    reasoning depth; tuning happens at the cascade routing layer, not here.
    """
    adapter = AnthropicAdapter(
        {
            "name": "argus-opus-4-6",
            "model_id": "claude-opus-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": {
                "thinking_budget": 24000,
                # See Sonnet runner: 16384 was too tight on dense files.
                "max_tokens": 32768,
                "enable_system_cache": True,
            },
        }
    )
    return make_anthropic_runner_from_adapter(
        adapter,
        model_label="claude-opus-4-6",
        cost_per_m_input=OPUS_46_COST_IN,
        cost_per_m_output=OPUS_46_COST_OUT,
    )


__all__ = [
    "GEMINI_FLASH_LITE_COST_IN",
    "GEMINI_FLASH_LITE_COST_OUT",
    "OPUS_46_COST_IN",
    "OPUS_46_COST_OUT",
    "SONNET_46_COST_IN",
    "SONNET_46_COST_OUT",
    "derive_uncertainty",
    "make_anthropic_runner_from_adapter",
    "make_gemini_triage_runner",
    "make_opus_runner",
    "make_sonnet_runner",
    "make_triage_runner_from_adapter",
    "score_to_verdict",
]
