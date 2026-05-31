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
from prompts.scanner import (
    ATTACK_CLASS_HUNTERS,
    SCAN_PROMPT_BEHAVIORAL,
    SCAN_PROMPT_BEHAVIORAL_BODY,
    SCAN_PROMPT_CHAINS,
    SCAN_PROMPT_CHAINS_BODY,
    SCAN_PROMPT_SYSTEM,
    SCAN_PROMPT_VULNS,
    SCAN_PROMPT_VULNS_BODY,
    SECURITY_SCAN_PROMPT,
    TRIAGE_PROMPT,
)
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
        cost = in_tokens / 1_000_000 * cost_per_m_input + out_tokens / 1_000_000 * cost_per_m_output

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
            # v1.6 Fix #8a: surface the model's intent reasoning so the
            # engine + bench output preserve it. Empty dict when model
            # doesn't fill it (backward-compat with old runs / older models).
            "file_intent_analysis": parsed.get("file_intent_analysis", {}),
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


# ── SCAN-010: split-L1 runner factory ──────────────────────────────────────


def make_anthropic_split_runner_from_adapter(
    adapter: Any,
    *,
    model_label: str,
    cost_per_m_input: float,
    cost_per_m_output: float,
) -> Callable[..., Awaitable[dict]]:
    """SCAN-010 — fan-out variant of ``make_anthropic_runner_from_adapter``.

    Instead of one ``adapter.scan(...)`` call with the combined
    ``SECURITY_SCAN_PROMPT``, fires the three SPECIALIZED prompts
    (``SCAN_PROMPT_VULNS`` + ``SCAN_PROMPT_BEHAVIORAL`` +
    ``SCAN_PROMPT_CHAINS``) in parallel via ``asyncio.gather`` and
    merges the disjoint sub-schemas into the engine-shape dict the
    existing runner emits.

    Cloudflare's published harness blog and Argus's own combined-L1
    audit converge on the same insight: narrower prompts produce less
    hedged findings. The three specialized prompts already existed in
    ``prompts/scanner.py`` (lifted from CNAPPPOC) but were never
    wired into production — engine.py / runners.py only called the
    combined prompt. SCAN-010 wires them.

    Failure modes (production-grade):

    * **1 of 3 sub-calls fails JSON-parse** → ship merged result with
      that section blanked. Existing engine-side code already handles
      empty ``behavioral_profile`` / ``attack_chains`` gracefully.
    * **2+ sub-calls fail JSON-parse** → systemic problem (rate limit,
      model degradation, etc.). Return a runner_error so engine can
      mark the scan as analysis_failure and surface to operator.
      Don't transparently retry against the combined prompt — that
      would mask a real upstream issue.
    * **Identity-leak hard sanitize on any sub-result** → blank that
      sub-result + apply the same defensive treatment as the combined
      runner.
    * **adapter.scan raises** on any sub-call → ``asyncio.gather``
      propagates; outer try/except marks the scan as errored. Same
      surface as combined.

    Verdict derivation is identical to combined mode —
    ``score_to_verdict(merged["composite_risk"]["score"])`` — so
    downstream cascade comparisons (Sonnet vs Opus, borderline
    ensemble) work unchanged.

    Uncertainty: max of per-section uncertainties (most conservative —
    if ANY section is borderline, escalate). Sum-of-tokens for cost.
    Max-of-durations for wall-clock (the three calls fan out, so
    elapsed time is bounded by the slowest one).
    """
    import asyncio  # noqa: PLC0415
    import time as _time  # noqa: PLC0415

    async def runner(
        filename: str,
        content: bytes,
        pp: Any,
        classification: str,
    ) -> dict:
        text = content.decode("utf-8", errors="replace")
        t_start = _time.time()

        # Fan out the three specialized calls in parallel. Anthropic's
        # async adapter handles connection re-use across the three
        # concurrent requests; rate-limit handling is the adapter's
        # responsibility (existing exponential backoff applies).
        #
        # SCAN-010.1 (cache prefix sharing): when the adapter supports
        # ``scan_with_prefix_body`` (AnthropicAdapter), pass the shared
        # SCAN_PROMPT_SYSTEM as the first cacheable block and just the
        # specialized body as the second block. The shared prefix
        # caches once across the three calls instead of each writing
        # its own ~2800-token entry. Falls back to single-block
        # ``adapter.scan(concatenated_prompt)`` when the adapter
        # doesn't expose the two-block path — preserves back-compat
        # for non-Anthropic adapters and stubs.
        use_two_block = hasattr(adapter, "scan_with_prefix_body")
        if use_two_block:
            # SCAN-010.1 cache-coherent fan-out: the three calls share
            # the SCAN_PROMPT_SYSTEM cache entry, but if all three fire
            # in parallel on a cold cache, all three race to WRITE the
            # cache (cache_create is 2.0× input cost) and only one
            # accidentally gets a read hit on cache_read 0.1× cost. Net
            # cold-cache cost balloons to ~2.9× combined (validated by
            # live spike — cost_ratio = 2.88× with parallel cold).
            #
            # Fix: sequentialize the FIRST call. It writes the
            # SCAN_PROMPT_SYSTEM cache entry. Then calls 2 + 3 run in
            # parallel — both READ from the now-existing cache at 0.1×
            # input cost. Wall-clock impact: ~+25s on the first file
            # of a scan (call 1 gates calls 2 + 3); subsequent files
            # in the same scan run fully parallel because the cache
            # is already warm.
            #
            # The pattern: gather() with one already-awaited Future
            # acts as parallel for the remaining two. Equivalent to
            # ``await call1; await asyncio.gather(call2, call3)``
            # but expressed in a single gather for uniform error
            # handling via ``return_exceptions=True``.
            vulns_r = await _safe_await(
                adapter.scan_with_prefix_body(
                    text, filename, SCAN_PROMPT_SYSTEM, SCAN_PROMPT_VULNS_BODY
                )
            )
            behav_r, chains_r = await asyncio.gather(
                adapter.scan_with_prefix_body(
                    text, filename, SCAN_PROMPT_SYSTEM, SCAN_PROMPT_BEHAVIORAL_BODY
                ),
                adapter.scan_with_prefix_body(
                    text, filename, SCAN_PROMPT_SYSTEM, SCAN_PROMPT_CHAINS_BODY
                ),
                return_exceptions=True,
            )
        else:
            # Back-compat path: adapters without scan_with_prefix_body
            # (test stubs, non-Anthropic) get the old single-block fan-
            # out. No cache prefix to share, so parallel is fine — each
            # call writes its own full entry. Cost matches pre-SCAN-010.1
            # split behavior (~1.66× combined cold-cache); operators who
            # want SCAN-010.1's optimization need an Anthropic adapter.
            vulns_r, behav_r, chains_r = await asyncio.gather(
                adapter.scan(text, filename, SCAN_PROMPT_VULNS),
                adapter.scan(text, filename, SCAN_PROMPT_BEHAVIORAL),
                adapter.scan(text, filename, SCAN_PROMPT_CHAINS),
                return_exceptions=True,
            )

        # Surface a gather-level exception immediately. Engine treats
        # this as analysis_failure (status 500); operator sees it as
        # a clear error rather than a degraded verdict.
        for r in (vulns_r, behav_r, chains_r):
            if isinstance(r, BaseException):
                return _split_error_response(
                    error=f"split_l1_call_failed: {type(r).__name__}: {str(r)[:200]}",
                    model_label=model_label,
                    elapsed_ms=int((_time.time() - t_start) * 1000),
                )

        # Count JSON-valid sub-results.
        vulns_valid = bool(vulns_r.get("json_valid"))
        behav_valid = bool(behav_r.get("json_valid"))
        chains_valid = bool(chains_r.get("json_valid"))
        n_valid = sum((vulns_valid, behav_valid, chains_valid))

        # 2+ JSON-parse failures = systemic issue. Don't transparently
        # fall back to combined — that masks the upstream problem
        # (likely rate-limit, model degradation, or schema drift).
        if n_valid < 2:
            return _split_error_response(
                error=(
                    f"split_l1_systemic_parse_failure: "
                    f"vulns_valid={vulns_valid} behav_valid={behav_valid} "
                    f"chains_valid={chains_valid}"
                ),
                model_label=model_label,
                elapsed_ms=int((_time.time() - t_start) * 1000),
                vulns_r=vulns_r,
                behav_r=behav_r,
                chains_r=chains_r,
                cost_in_per_m=cost_per_m_input,
                cost_out_per_m=cost_per_m_output,
            )

        # Merge — each specialized prompt fills its slice; missing
        # sections from a JSON-parse-failed sub-result come through
        # as empty dicts/lists so the engine + downstream consumers
        # never see KeyError. SCAN-009 sanitizer applies per-section.
        vp = (vulns_r.get("parsed") or {}) if vulns_valid else {}
        bp = (behav_r.get("parsed") or {}) if behav_valid else {}
        cp = (chains_r.get("parsed") or {}) if chains_valid else {}

        sanitizer_error: str | None = None
        for section_name, section in (("vulns", vp), ("behav", bp), ("chains", cp)):
            if not section:
                continue
            sanitized, _had_leak = sanitize_response(section)
            if sanitized is None:
                # Hard leak in this sub-result — null it out and mark
                # so the engine sees a clear error rather than a
                # half-merged response.
                sanitizer_error = f"identity_leak_in_response:{section_name}"
                log.warning(
                    "Split-L1 runner %s: identity leak in %s section for %s",
                    model_label,
                    section_name,
                    filename,
                )
                if section is vp:
                    vp = {}
                elif section is bp:
                    bp = {}
                else:
                    cp = {}
            elif sanitized is not section:
                # In-place replacement so the merge below sees the
                # sanitized variant.
                section.clear()
                section.update(sanitized)

        # v1.9 composite_risk aggregation across sub-calls.
        #
        # Pre-v1.9 bug: only the VULNS sub-call's composite_risk was
        # used. VULNS sees vulnerabilities but NOT behavioral_profile /
        # attack_chains / ai_tool_analysis — context that's needed to
        # score INTENT (the score-band rubric is intent-based, not
        # finding-count-based). The model would emit findings but
        # under-call composite_risk.score to 0 because it couldn't see
        # the behavioral signals that distinguish "vulnerable utility
        # code" from "actively-attacking malware." Net result: 3
        # documented findings + verdict=clean.
        #
        # Fix: BEHAVIORAL + CHAINS sub-calls now also emit
        # composite_risk (each schema updated). Each sub-call scores
        # from its own context (VULNS from findings, BEHAVIORAL from
        # exfiltration_risk + capabilities, CHAINS from chain impact
        # + AI-tool surface). The runner takes MAX score across all
        # three — safest aggregation: any sub-call seeing high-risk
        # signals will lift the verdict, none can suppress.
        scores: list[tuple[int, dict, str]] = []
        for section, label in ((vp, "vulns"), (bp, "behavioral"), (cp, "chains")):
            cr = section.get("composite_risk") if isinstance(section, dict) else None
            if not cr or not isinstance(cr, dict):
                continue
            raw = cr.get("score")
            try:
                s = int(raw) if raw is not None else 0
            except (TypeError, ValueError):
                s = 0
            s = max(0, min(100, s))
            scores.append((s, cr, label))
        if scores:
            scores.sort(key=lambda t: t[0], reverse=True)
            max_score, max_cr, max_label = scores[0]
            # Surface the winning sub-call's reasoning so operators
            # can see WHICH angle drove the final verdict.
            composite_risk_merged = dict(max_cr)
            composite_risk_merged["score"] = max_score
            composite_risk_merged["aggregation_source"] = max_label
            composite_risk_merged["sub_call_scores"] = {
                label: s for s, _, label in scores
            }
        else:
            composite_risk_merged = {"score": 0, "reasoning": "", "exploitability": "none"}

        merged = {
            "file_intent_analysis": vp.get("file_intent_analysis", {}),
            "vulnerabilities": vp.get("vulnerabilities", []),
            "composite_risk": composite_risk_merged,
            "behavioral_profile": bp.get("behavioral_profile", {}),
            "ai_tool_analysis": cp.get("ai_tool_analysis", {}),
            "attack_chains": cp.get("attack_chains", []),
        }

        score = composite_risk_merged.get("score")
        verdict = score_to_verdict(score)

        # Aggregate tokens + cost across the three calls. Effective
        # token count benefits from system-prompt caching when
        # ``adapter.scan`` reports ``cache_read_input_tokens``;
        # ``input_tokens`` is already the cache-adjusted count.
        in_tokens = sum(
            int(r.get("input_tokens", 0))
            for r in (vulns_r, behav_r, chains_r)
        )
        out_tokens = sum(
            int(r.get("output_tokens", 0))
            for r in (vulns_r, behav_r, chains_r)
        )
        cost = (
            in_tokens / 1_000_000 * cost_per_m_input
            + out_tokens / 1_000_000 * cost_per_m_output
        )

        # Uncertainty: max of per-section uncertainty derived from
        # whatever signals each sub-result carries. derive_uncertainty
        # looks at composite_risk + vulnerabilities — both live in vp.
        # For the borderline-ensemble decision the engine compares
        # this against a threshold; we want a conservative number so
        # ambiguous splits escalate to Opus.
        section_uncs = [derive_uncertainty(vp) if vp else 0.5]
        # Cheap behavioral-uncertainty proxy: empty profile or empty
        # ``actual_capabilities`` = sub-result was thin, treat as
        # uncertain so the engine considers escalation.
        if bp:
            actual_caps = (bp.get("behavioral_profile") or {}).get("actual_capabilities") or {}
            section_uncs.append(0.0 if actual_caps else 0.4)
        else:
            section_uncs.append(0.5)
        uncertainty = max(section_uncs)

        # Wall-clock = slowest of the three sub-calls. The engine logs
        # this as duration_ms; the underlying gather() already returned
        # at this point, so subtracting from t_start gives the bound.
        durations = [
            int(r.get("response_time_ms", 0))
            for r in (vulns_r, behav_r, chains_r)
        ]
        duration_ms = max(durations) if durations else 0

        runner_error = sanitizer_error  # None when no hard leak

        return {
            "vulnerabilities": merged["vulnerabilities"],
            "behavioral_profile": merged["behavioral_profile"],
            "attack_chains": merged["attack_chains"],
            "ai_tool_analysis": merged["ai_tool_analysis"],
            "file_intent_analysis": merged["file_intent_analysis"],
            # v1.9: surface the aggregated composite_risk so operators
            # + tests can inspect WHICH sub-call drove the verdict
            # (``aggregation_source``) and the per-sub-call scores
            # (``sub_call_scores``). The engine itself only reads
            # ``verdict_label``; this field is for transparency.
            "composite_risk": merged["composite_risk"],
            "verdict_label": verdict,
            "model": f"{model_label}-split",
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "cost_usd": round(cost, 6),
            "duration_ms": duration_ms,
            "uncertainty": uncertainty,
            "error": runner_error,
            # SCAN-010 telemetry — operators + bench tooling can see
            # which sub-calls succeeded for cost / quality analysis.
            "split_telemetry": {
                "vulns_valid": vulns_valid,
                "behav_valid": behav_valid,
                "chains_valid": chains_valid,
                "n_valid": n_valid,
                # Cache-hit visibility. The load-bearing assumption
                # behind SCAN-010's cost story is that the shared
                # ``SCAN_PROMPT_SYSTEM`` prefix gets cached on call 1
                # and read by calls 2 + 3. If cache_read totals stay
                # at 0 across the three sub-calls, the cache key
                # isn't matching (likely because the SDK keys on the
                # full system message, not just a cacheable prefix).
                # That's the Gate-1 signal in the SCAN-010 validation
                # plan — operators should monitor it post-deploy.
                "cache_creation_total": sum(
                    int(r.get("cache_creation_input_tokens", 0) or 0)
                    for r in (vulns_r, behav_r, chains_r)
                ),
                "cache_read_total": sum(
                    int(r.get("cache_read_input_tokens", 0) or 0)
                    for r in (vulns_r, behav_r, chains_r)
                ),
                "per_call_cache_read": [
                    int(vulns_r.get("cache_read_input_tokens", 0) or 0),
                    int(behav_r.get("cache_read_input_tokens", 0) or 0),
                    int(chains_r.get("cache_read_input_tokens", 0) or 0),
                ],
            },
        }

    return runner


async def _safe_await(coro: Any) -> Any:
    """Mirror ``asyncio.gather(return_exceptions=True)``'s behavior for
    a single awaitable — return the exception object instead of
    raising. Used by the split runner's two-block path so the
    sequentialized first call has the same exception-as-value
    semantics as the gather() that follows it. The downstream code
    checks ``isinstance(r, BaseException)`` to surface the error
    uniformly."""
    try:
        return await coro
    except BaseException as exc:  # noqa: BLE001 — boundary
        return exc


def _split_error_response(
    *,
    error: str,
    model_label: str,
    elapsed_ms: int,
    vulns_r: dict | None = None,
    behav_r: dict | None = None,
    chains_r: dict | None = None,
    cost_in_per_m: float = 0.0,
    cost_out_per_m: float = 0.0,
) -> dict:
    """Build the runner's error-shape return for split-L1 systemic
    failures. Aggregates tokens/cost across whatever sub-results
    completed so the operator sees the spend even on a failed scan."""
    in_tokens = 0
    out_tokens = 0
    for r in (vulns_r, behav_r, chains_r):
        if isinstance(r, dict):
            in_tokens += int(r.get("input_tokens", 0))
            out_tokens += int(r.get("output_tokens", 0))
    cost = (
        in_tokens / 1_000_000 * cost_in_per_m
        + out_tokens / 1_000_000 * cost_out_per_m
    )
    return {
        "vulnerabilities": [],
        "behavioral_profile": {},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "file_intent_analysis": {},
        "verdict_label": "suspicious",
        "model": f"{model_label}-split",
        "input_tokens": in_tokens,
        "output_tokens": out_tokens,
        "cost_usd": round(cost, 6),
        "duration_ms": elapsed_ms,
        "uncertainty": 0.5,
        "error": error,
    }


# ── SCAN-011: per-attack-class hunter runner ───────────────────────────────


def make_anthropic_hunter_runner_from_adapter(
    adapter: Any,
    *,
    hunter_set: tuple[str, ...] | None = None,
    max_concurrent_hunters: int = 10,
    model_label: str,
    cost_per_m_input: float,
    cost_per_m_output: float,
) -> Callable[..., Awaitable[dict]]:
    """SCAN-011 — fan-out variant of the split-L1 runner that replaces
    the single VULNS slot with N attack-class-specialized hunters.

    Layered on top of SCAN-010 + SCAN-010.1:

    * Each hunter call sends the cacheable ``SCAN_PROMPT_SYSTEM`` prefix
      via ``adapter.scan_with_prefix_body`` (SCAN-010.1's two-block
      path). Cache prefix-sharing makes N hunter calls plausible from
      a cost perspective — cold-cache cost is bounded by the single
      write of SCAN_PROMPT_SYSTEM that the first call performs.
    * The first hunter call is sequentialized to write the prefix
      cache; the remaining hunters + BEHAVIORAL + CHAINS fan out via
      ``asyncio.gather`` bounded by ``max_concurrent_hunters``
      semaphore (avoids overwhelming the Anthropic per-key rate limit
      on large hunter sets).
    * Findings from each hunter are merged into a single
      ``vulnerabilities[]`` list with dedup by ``(type, line, code)``
      triple — different hunters flagging the same underlying bug
      collapse into one entry, the highest-confidence variant wins.

    ``hunter_set`` selects which attack classes to run; ``None`` means
    all hunters in :data:`prompts.scanner.ATTACK_CLASS_HUNTERS`. Slice 1
    ships 3 hunters (injection / ssrf / malicious_intent) — see the
    design doc at ``docs/scan_011_attack_class_hunters_design.md`` for
    slice 2's remaining 7.

    Adapters that don't expose ``scan_with_prefix_body`` (test stubs,
    non-Anthropic) fall back to the SCAN-010 split runner — without
    cache prefix-sharing the hunter fan-out would cost N× full input
    per call, which is unjustified outside test contexts.

    Returns the same engine-shape dict as the split / combined
    runners. Adds a ``hunter_telemetry`` block parallel to SCAN-010's
    ``split_telemetry`` with per-hunter validity + finding counts +
    cache reads.
    """
    import asyncio  # noqa: PLC0415
    import time as _time  # noqa: PLC0415

    # Resolve the active hunter list once at factory time so we don't
    # re-read the dict + filter on every scan.
    if hunter_set is None:
        active = list(ATTACK_CLASS_HUNTERS.items())
    else:
        active = [(k, ATTACK_CLASS_HUNTERS[k]) for k in hunter_set if k in ATTACK_CLASS_HUNTERS]
    if not active:
        raise ValueError(
            "make_anthropic_hunter_runner_from_adapter: hunter_set "
            "selected zero active hunters. Pass None for all hunters "
            "or a subset of ATTACK_CLASS_HUNTERS keys."
        )

    # Build a split-runner instance as the fallback for adapters that
    # don't support the two-block path. Hunter fan-out without cache
    # prefix-sharing is economically unsound.
    split_fallback = make_anthropic_split_runner_from_adapter(
        adapter,
        model_label=model_label,
        cost_per_m_input=cost_per_m_input,
        cost_per_m_output=cost_per_m_output,
    )

    async def runner(
        filename: str,
        content: bytes,
        pp: Any,
        classification: str,
    ) -> dict:
        if not hasattr(adapter, "scan_with_prefix_body"):
            log.warning(
                "Hunter runner %s: adapter lacks scan_with_prefix_body "
                "(two-block cache path) — hunter fan-out is unsupported "
                "on this adapter. Falling back to SCAN-010 split mode.",
                model_label,
            )
            return await split_fallback(filename, content, pp, classification)

        text = content.decode("utf-8", errors="replace")
        t_start = _time.time()

        # Sequentialize the FIRST hunter call to write the
        # SCAN_PROMPT_SYSTEM cache entry. Choosing injection as the
        # first hunter — it's the most-common-finding class so the
        # warm-up call is also likely to produce real findings,
        # amortizing its "cache primer" duty.
        first_key, first_body = active[0]
        first_r = await _safe_await(
            adapter.scan_with_prefix_body(
                text, filename, SCAN_PROMPT_SYSTEM, first_body
            )
        )

        # Fan out remaining hunters + BEHAVIORAL + CHAINS in parallel
        # bounded by the semaphore. After the first call's cache write,
        # every subsequent call reads the cache at 0.1× input cost.
        sem = asyncio.Semaphore(max_concurrent_hunters)

        async def _gated(coro: Any) -> Any:
            async with sem:
                return await coro

        rest_hunter_coros = [
            adapter.scan_with_prefix_body(
                text, filename, SCAN_PROMPT_SYSTEM, body
            )
            for _key, body in active[1:]
        ]
        behav_coro = adapter.scan_with_prefix_body(
            text, filename, SCAN_PROMPT_SYSTEM, SCAN_PROMPT_BEHAVIORAL_BODY
        )
        chains_coro = adapter.scan_with_prefix_body(
            text, filename, SCAN_PROMPT_SYSTEM, SCAN_PROMPT_CHAINS_BODY
        )

        rest_results = await asyncio.gather(
            *(_gated(c) for c in [*rest_hunter_coros, behav_coro, chains_coro]),
            return_exceptions=True,
        )
        n_rest_hunters = len(active) - 1
        rest_hunter_rs = list(rest_results[:n_rest_hunters])
        behav_r = rest_results[n_rest_hunters]
        chains_r = rest_results[n_rest_hunters + 1]

        # Per-hunter validity + findings extraction. Each hunter
        # response is either a dict (success) or an exception (gather
        # captured it via return_exceptions=True).
        hunter_results: list[tuple[str, Any]] = [(first_key, first_r)]
        for (key, _body), r in zip(active[1:], rest_hunter_rs):
            hunter_results.append((key, r))

        n_valid = 0
        merged_findings: list[dict] = []
        dedup_keys: set[tuple[str, int, str]] = set()
        n_collisions = 0
        per_hunter_telemetry: dict[str, dict] = {}
        max_composite_score = 0
        file_intent: dict = {}
        in_tokens = 0
        out_tokens = 0
        cache_reads_total = 0
        durations: list[int] = []

        sanitizer_error: str | None = None

        for hunter_key, r in hunter_results:
            if isinstance(r, BaseException):
                per_hunter_telemetry[hunter_key] = {
                    "valid": False,
                    "error": f"{type(r).__name__}: {str(r)[:200]}",
                    "n_findings": 0,
                }
                continue
            if not isinstance(r, dict):
                per_hunter_telemetry[hunter_key] = {
                    "valid": False,
                    "error": "non_dict_response",
                    "n_findings": 0,
                }
                continue
            valid = bool(r.get("json_valid"))
            parsed = (r.get("parsed") or {}) if valid else {}

            # Sanitizer applies per-hunter (SCAN-009 identity-leak
            # defense). Hard leak → drop this hunter's contribution.
            if parsed:
                sanitized, _had_leak = sanitize_response(parsed)
                if sanitized is None:
                    sanitizer_error = f"identity_leak_in_response:{hunter_key}"
                    parsed = {}
                elif sanitized is not parsed:
                    parsed.clear()
                    parsed.update(sanitized)

            in_tokens += int(r.get("input_tokens", 0) or 0)
            out_tokens += int(r.get("output_tokens", 0) or 0)
            cache_reads_total += int(r.get("cache_read_input_tokens", 0) or 0)
            durations.append(int(r.get("response_time_ms", 0) or 0))

            findings = parsed.get("vulnerabilities") or []
            kept = 0
            for f in findings:
                if not isinstance(f, dict):
                    continue
                key = (
                    str(f.get("type", "")),
                    int(f.get("line", 0) or 0),
                    str(f.get("code", ""))[:200],
                )
                if key in dedup_keys:
                    n_collisions += 1
                    continue
                dedup_keys.add(key)
                merged_findings.append(f)
                kept += 1

            score = (parsed.get("composite_risk") or {}).get("score")
            try:
                score_i = int(score)
                if score_i > max_composite_score:
                    max_composite_score = score_i
            except (TypeError, ValueError):
                pass

            # Adopt the first non-empty file_intent_analysis we see —
            # the malicious-intent hunter's view is authoritative for
            # files where it fires, otherwise the first valid one.
            if not file_intent and parsed.get("file_intent_analysis"):
                file_intent = parsed["file_intent_analysis"]

            if valid:
                n_valid += 1
            per_hunter_telemetry[hunter_key] = {
                "valid": valid,
                "n_findings": kept,
                "input_tokens": int(r.get("input_tokens", 0) or 0),
                "output_tokens": int(r.get("output_tokens", 0) or 0),
                "cache_read_input_tokens": int(r.get("cache_read_input_tokens", 0) or 0),
            }

        # If too few hunters succeeded, surface systemic error rather
        # than ship sparse/empty results. Threshold: at least 50% of
        # hunters must have produced valid JSON.
        if n_valid < max(1, len(active) // 2):
            return _split_error_response(
                error=(
                    f"hunter_systemic_failure: only {n_valid} / {len(active)} "
                    f"hunters produced valid JSON; falling back to SCAN-010 "
                    f"split runner. Per-hunter telemetry: {per_hunter_telemetry}"
                ),
                model_label=model_label,
                elapsed_ms=int((_time.time() - t_start) * 1000),
                cost_in_per_m=cost_per_m_input,
                cost_out_per_m=cost_per_m_output,
            )

        # Behavioral + chains: same logic as split runner — they
        # contribute their own schema slices to the merged result.
        behav_valid = (
            isinstance(behav_r, dict)
            and bool(behav_r.get("json_valid"))
        )
        chains_valid = (
            isinstance(chains_r, dict)
            and bool(chains_r.get("json_valid"))
        )
        bp = (behav_r.get("parsed") or {}) if behav_valid else {}
        cp = (chains_r.get("parsed") or {}) if chains_valid else {}

        # Sanitize behavioral + chains slices.
        for section_name, section in (("behav", bp), ("chains", cp)):
            if not section:
                continue
            s, _ = sanitize_response(section)
            if s is None:
                sanitizer_error = f"identity_leak_in_response:{section_name}"
                if section is bp:
                    bp = {}
                else:
                    cp = {}
            elif s is not section:
                section.clear()
                section.update(s)

        if isinstance(behav_r, dict):
            in_tokens += int(behav_r.get("input_tokens", 0) or 0)
            out_tokens += int(behav_r.get("output_tokens", 0) or 0)
            cache_reads_total += int(behav_r.get("cache_read_input_tokens", 0) or 0)
            durations.append(int(behav_r.get("response_time_ms", 0) or 0))
        if isinstance(chains_r, dict):
            in_tokens += int(chains_r.get("input_tokens", 0) or 0)
            out_tokens += int(chains_r.get("output_tokens", 0) or 0)
            cache_reads_total += int(chains_r.get("cache_read_input_tokens", 0) or 0)
            durations.append(int(chains_r.get("response_time_ms", 0) or 0))

        merged = {
            "file_intent_analysis": file_intent,
            "vulnerabilities": merged_findings,
            "composite_risk": {
                "score": max_composite_score,
                "reasoning": (
                    f"max composite score across {n_valid} hunters; "
                    f"{len(merged_findings)} unique findings post-dedup "
                    f"({n_collisions} dedupe collisions)"
                ),
                "exploitability": (
                    "high" if max_composite_score >= 75
                    else "medium" if max_composite_score >= 50
                    else "low" if max_composite_score >= 25
                    else "none"
                ),
            },
            "behavioral_profile": bp.get("behavioral_profile", {}),
            "ai_tool_analysis": cp.get("ai_tool_analysis", {}),
            "attack_chains": cp.get("attack_chains", []),
        }

        verdict = score_to_verdict(max_composite_score)
        cost = (
            in_tokens / 1_000_000 * cost_per_m_input
            + out_tokens / 1_000_000 * cost_per_m_output
        )

        # Uncertainty: combine vuln-confidence-based + boundary distance
        # from the merged composite score. Uses the same derive_uncertainty
        # helper as combined mode — just feeds it the merged dict.
        merged_unc = derive_uncertainty(merged)

        return {
            "vulnerabilities": merged["vulnerabilities"],
            "behavioral_profile": merged["behavioral_profile"],
            "attack_chains": merged["attack_chains"],
            "ai_tool_analysis": merged["ai_tool_analysis"],
            "file_intent_analysis": merged["file_intent_analysis"],
            "verdict_label": verdict,
            "model": f"{model_label}-hunter",
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "cost_usd": round(cost, 6),
            "duration_ms": max(durations) if durations else 0,
            "uncertainty": merged_unc,
            "error": sanitizer_error,
            # Hunter-specific telemetry parallel to split_telemetry.
            "hunter_telemetry": {
                "n_hunters_active": len(active),
                "n_hunters_valid": n_valid,
                "per_hunter": per_hunter_telemetry,
                "n_findings_merged": len(merged_findings),
                "n_dedup_collisions": n_collisions,
                "cache_read_total": cache_reads_total,
            },
        }

    return runner


# ── Public factories ───────────────────────────────────────────────────────


def make_sonnet_runner(
    api_key: str,
    *,
    thinking_budget: int = 24000,
) -> Callable[..., Awaitable[dict]]:
    """Build the Sonnet 4.6 analysis runner — default HIGH-tier path.

    Configured for deep security analysis: ``thinking_budget=24000``
    ("extra high" depth) by default, system-prompt caching enabled (90%
    read discount on the shared SECURITY_SCAN_PROMPT across multi-file
    scans).

    Pass ``thinking_budget=0`` (or any value <2048) to disable extended
    thinking entirely. Used by the install path on bulk scans where
    speed matters more than reasoning depth — we trade ~30% accuracy
    on subtle multi-step exploits for ~3× throughput. Deterministic
    preprocessing flags (``imperative_install_detected``,
    ``attack_vector_extension``, ``crypto_sensitivity_detected``,
    ``ai_file_match``, ``obfuscation_detected``) still force-escalate
    files to HIGH-tier scrutiny regardless of thinking budget.
    """
    cfg: dict[str, Any] = {
        # 32768 covers Sonnet's full schema response on dense files.
        # Adapter adds thinking_budget on top so the model has 32k
        # tokens of OUTPUT after using its thinking budget.
        "max_tokens": 32768,
        "enable_system_cache": True,
    }
    if thinking_budget >= 2048:
        # Anthropic requires thinking_budget >= 2048 when set; below that
        # we drop the field entirely (adapter then doesn't request thinking).
        cfg["thinking_budget"] = thinking_budget
    adapter = AnthropicAdapter(
        {
            "name": "argus-sonnet-4-6",
            "model_id": "claude-sonnet-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": cfg,
        }
    )
    return make_anthropic_runner_from_adapter(
        adapter,
        model_label="claude-sonnet-4-6",
        cost_per_m_input=SONNET_46_COST_IN,
        cost_per_m_output=SONNET_46_COST_OUT,
    )


def make_sonnet_runner_hunter(
    api_key: str,
    *,
    hunter_set: tuple[str, ...] | None = None,
    max_concurrent_hunters: int = 10,
    thinking_budget: int = 24000,
) -> Callable[..., Awaitable[dict]]:
    """SCAN-011 — Sonnet 4.6 runner that fans out N attack-class
    specialized hunters in parallel. See
    :func:`make_anthropic_hunter_runner_from_adapter` for the full
    behavior + cost story.

    Same adapter configuration as :func:`make_sonnet_runner_split`
    (thinking budget, system-prompt caching, two-block path enabled).
    The hunter runner internally uses the two-block path to share the
    SCAN_PROMPT_SYSTEM cache across the N hunter calls.

    Cost expectation: ~$0.32 per HIGH-triage file (12 calls vs
    SCAN-010 split's 3). Default off until validated on the regression
    suite. See ``docs/scan_011_attack_class_hunters_design.md``."""
    cfg: dict[str, Any] = {
        "max_tokens": 32768,
        "enable_system_cache": True,
    }
    if thinking_budget >= 2048:
        cfg["thinking_budget"] = thinking_budget
    adapter = AnthropicAdapter(
        {
            "name": "argus-sonnet-4-6-hunter",
            "model_id": "claude-sonnet-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": cfg,
        }
    )
    return make_anthropic_hunter_runner_from_adapter(
        adapter,
        hunter_set=hunter_set,
        max_concurrent_hunters=max_concurrent_hunters,
        model_label="claude-sonnet-4-6",
        cost_per_m_input=SONNET_46_COST_IN,
        cost_per_m_output=SONNET_46_COST_OUT,
    )


def make_sonnet_runner_split(
    api_key: str,
    *,
    thinking_budget: int = 24000,
) -> Callable[..., Awaitable[dict]]:
    """SCAN-010 — Sonnet 4.6 runner that fans out three specialized
    prompts (VULNS / BEHAVIORAL / CHAINS) in parallel.

    Same configuration as :func:`make_sonnet_runner` (thinking budget,
    system-prompt caching). Wraps
    :func:`make_anthropic_split_runner_from_adapter` instead of the
    combined factory.

    Cost expectation: ~1.3× combined-runner cost when system-prompt
    caching applies cleanly across the three back-to-back calls
    (Anthropic's cache key is per system message; ``SCAN_PROMPT_SYSTEM``
    is the shared prefix). Empirically verify post-deploy before
    flipping the engine default to split — see
    ``docs/scan_010_split_l1_design.md`` section 12.4.
    """
    cfg: dict[str, Any] = {
        "max_tokens": 32768,
        "enable_system_cache": True,
    }
    if thinking_budget >= 2048:
        cfg["thinking_budget"] = thinking_budget
    adapter = AnthropicAdapter(
        {
            "name": "argus-sonnet-4-6-split",
            "model_id": "claude-sonnet-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": cfg,
        }
    )
    return make_anthropic_split_runner_from_adapter(
        adapter,
        model_label="claude-sonnet-4-6",
        cost_per_m_input=SONNET_46_COST_IN,
        cost_per_m_output=SONNET_46_COST_OUT,
    )


# ── Triage runner factory ──────────────────────────────────────────────────


# v15.23 security-marker preprocessing bias.
#
# Pre-LLM scan for high-signal patterns that should NEVER route CLEAN.
# Deterministic safety net catching the auth/credentials/SDK boundary
# cases where Sonnet's classification has measurable variance even with
# thinking_budget=8000.
#
# Each tuple = (regex pattern, weight). Total score across all matching
# patterns drives the bias:
#   score >= 1  → min-classification = LOW (if Sonnet said CLEAN, bump
#                  to LOW)
#   score >= 3  → min-classification = HIGH (if Sonnet said CLEAN/LOW,
#                  bump to HIGH)
#
# Tuned for "SDK auth/credentials" canonical pattern. Bias never
# DOWNGRADES — it can only push UP the classification. So if Sonnet
# already said HIGH, the bias is a no-op.

_SECURITY_MARKER_PATTERNS: tuple[tuple[str, int], ...] = (
    # Crypto / signing / hashing libraries
    (r"\bimport\s+hashlib\b", 1),
    (r"\bimport\s+hmac\b", 1),
    (r"\bimport\s+secrets\b", 2),
    (r"\bfrom\s+cryptography\b", 2),
    (r"\bfrom\s+Crypto\b", 2),
    (r"\bimport\s+jwt\b|\bfrom\s+jwt\b", 2),
    (r"\bimport\s+boto3\b|\bfrom\s+boto3\b", 2),
    (r"\bfrom\s+botocore\b|\bimport\s+botocore\b", 2),
    # Token / credential / signer class names
    (r"class\s+\w*(Token|Credentials?|Authoriz|Signer|SigV4|OAuth|Bearer)\w*", 2),
    # Token / credential / signer attribute names
    (
        r"\b(api_key|secret_key|access_key|aws_secret|aws_access|"
        r"bearer_token|auth_token|refresh_token|client_secret|"
        r"credentials_path|signing_key)\b",
        1,
    ),
    # base_url / endpoint as configurable parameter (SSRF + cleartext surface)
    (r"\b(base_url|endpoint)\s*[:=]", 1),
    # Authorization header construction
    (r"['\"]Authorization['\"]\s*:", 2),
    (r"['\"]Bearer\s", 2),
    # HTTP client libraries with potentially user-controlled URLs
    (r"\bimport\s+requests\b|\bfrom\s+requests\b", 1),
    (r"\bimport\s+httpx\b|\bfrom\s+httpx\b", 1),
    (r"\bimport\s+urllib\b|\bfrom\s+urllib\b", 1),
    (r"\bimport\s+socket\b", 1),
    # Token-exchange / OIDC / federation
    (r"\b(token_exchange|federation|identity_token|grant_type)\b", 2),
    # Supply-chain extension points
    (r"^\s*import\s+.*$", 0),  # pth-file detection requires more context;
    # leave 0-weight here so this row doesn't pollute the score.
)


def _compute_security_marker_score(text: str) -> tuple[int, list[str]]:
    """Return (total_score, list_of_matched_pattern_descriptions).

    Used by the triage runner to bias the LLM classification away from
    CLEAN/LOW when the file shows multiple security-sensitive patterns
    (auth/credentials/SDK shape). The score is a deterministic count
    of matched markers; the bias rule lives in the runner itself.

    Caller passes the decoded file text. Patterns are compiled once
    per call — fine because triage runs once per file (not per probe).
    Total runtime is microseconds per file.
    """
    import re

    matched: list[str] = []
    total = 0
    for pattern, weight in _SECURITY_MARKER_PATTERNS:
        if weight <= 0:
            continue
        if re.search(pattern, text, flags=re.MULTILINE):
            matched.append(f"{pattern[:60]} ({weight})")
            total += weight
    return total, matched


# v15.23 — auto-escalation thresholds. Confidence below this bumps the
# classification up one tier.
_TRIAGE_CONFIDENCE_FLOOR = 0.7

# Ranking helper (already defined later in the file as _TRIAGE_RANK,
# but the function-local one is small and standalone so we don't
# create import-order surprise).
_RANK = {"CLEAN": 0, "LOW": 1, "HIGH": 2}
_RANK_INV = {0: "CLEAN", 1: "LOW", 2: "HIGH"}


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

        # v15.23 — confidence field. Old models may not emit it; default
        # to 1.0 (no auto-escalation) so legacy outputs preserve their
        # behavior. Sonnet-thinking at v15.23 fills this every call.
        confidence_raw = parsed.get("confidence")
        try:
            confidence = float(confidence_raw) if confidence_raw is not None else 1.0
        except (TypeError, ValueError):
            confidence = 1.0
        confidence = max(0.0, min(1.0, confidence))

        bump_reasons: list[str] = []

        # v15.23 — auto-escalation rule #1: low confidence bumps up one
        # tier. Sonnet acknowledging "I'm not sure" should cost extra
        # cascade work, not silently route to the cheap path.
        if confidence < _TRIAGE_CONFIDENCE_FLOOR and classification in ("CLEAN", "LOW"):
            rank = _RANK[classification]
            new_rank = min(rank + 1, _RANK["HIGH"])
            new_class = _RANK_INV[new_rank]
            if new_class != classification:
                bump_reasons.append(
                    f"confidence={confidence:.2f}<{_TRIAGE_CONFIDENCE_FLOOR} "
                    f"escalated {classification}->{new_class}"
                )
                classification = new_class

        # v15.23 — auto-escalation rule #2: deterministic security-marker
        # bias. Pre-scan the file for high-signal patterns the model
        # might miss. score≥1 → min LOW; score≥3 → min HIGH. Bias only
        # raises, never lowers.
        try:
            marker_score, matched = _compute_security_marker_score(text)
        except Exception:
            marker_score, matched = 0, []
        if marker_score >= 3 and classification != "HIGH":
            bump_reasons.append(
                f"security_markers={marker_score} ({len(matched)} matches) "
                f"escalated {classification}->HIGH"
            )
            classification = "HIGH"
        elif marker_score >= 1 and classification == "CLEAN":
            bump_reasons.append(
                f"security_markers={marker_score} ({len(matched)} matches) "
                f"escalated CLEAN->LOW"
            )
            classification = "LOW"

        if bump_reasons:
            log.info(
                "Triage runner %s: v15.23 bumps applied to %s — %s",
                model_label,
                filename,
                "; ".join(bump_reasons),
            )

        in_tokens = int(result.get("input_tokens", 0))
        out_tokens = int(result.get("output_tokens", 0))
        cost = in_tokens / 1_000_000 * cost_per_m_input + out_tokens / 1_000_000 * cost_per_m_output

        adapter_error = result.get("error")
        return {
            "classification": classification,
            "reason": reason,
            "confidence": confidence,
            "security_marker_score": marker_score,
            "bumps_applied": bump_reasons,
            "model": model_label,
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "cost_usd": round(cost, 6),
            "duration_ms": int(result.get("response_time_ms", 0)),
            "error": adapter_error or sanitizer_error,
        }

    return runner


def make_sonnet_triage_runner(api_key: str) -> Callable[..., Awaitable[dict]]:
    """Sonnet 4.6 triage runner. v15.9 → v15.23.

    v15.9 (2026-05-20): switched default away from Gemini Flash-Lite
    because Flash-Lite flipped CLEAN ↔ HIGH on identical input.
    Sonnet at ``thinking_budget=0`` was more deterministic out of the
    box, at ~20× per-file cost (~$0.001 → ~$0.02).

    v15.23 (2026-05-20): the anthropic-sdk-python campaign showed
    Sonnet ALSO flips classification on borderline SDK auth/credentials
    files (3 of 7 files routed CLEAN/LOW instead of HIGH, skipping DAST
    entirely). v15.23 closes that gap with three layered changes:

      1. ``thinking_budget=8000`` — gives Sonnet space to reason about
         boundary cases before committing to a bucket. Cost per triage
         call moves from ~$0.02 to ~$0.05-0.10. Still <10% of full
         scan cost.
      2. Confidence field in the schema (see TRIAGE_PROMPT) +
         auto-escalation when confidence < 0.7 (applied at the runner
         layer; see ``make_triage_runner_from_adapter`` v15.23 patch).
      3. Security-marker preprocessing bias (also in
         ``make_triage_runner_from_adapter``): pre-Sonnet scan for
         high-signal markers (boto3, hashlib, secrets, JWT, Authorization
         headers, credential class attrs, base_url config parameters) —
         if matched, the runner forces min-classification to LOW (HIGH
         when multiple categories match). Deterministic safety net.

    Config:
      * ``thinking_budget=8000`` — v15.23 stability bump
      * ``max_tokens=1024`` — small bump from 512 to accommodate the
        new ``confidence`` + structured ``reason``
      * ``enable_system_cache=True`` — caches the TRIAGE_PROMPT prefix
        across files (~90% read discount on multi-file scans).
    """
    cfg: dict[str, Any] = {
        "max_tokens": 1024,
        "thinking_budget": 8000,  # v15.23: borderline-file determinism
        "enable_system_cache": True,
    }
    adapter = AnthropicAdapter(
        {
            "name": "argus-sonnet-4-6-triage",
            "model_id": "claude-sonnet-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": cfg,
        }
    )
    return make_triage_runner_from_adapter(
        adapter,
        model_label="claude-sonnet-4-6-triage",
        cost_per_m_input=SONNET_46_COST_IN,
        cost_per_m_output=SONNET_46_COST_OUT,
    )


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


# v15.8 Gap 3 (2026-05-20): triage classifications ranked so the
# confirm-clean wrapper can take the max across multiple calls.
# Higher rank = more conservative (more pipeline work scheduled).
_TRIAGE_RANK = {"CLEAN": 0, "LOW": 1, "HIGH": 2}


def with_confirm_clean(
    triage_runner: Callable[..., Awaitable[dict]],
) -> Callable[..., Awaitable[dict]]:
    """v15.8 Gap 3 (2026-05-20): wrap a triage runner so a CLEAN result
    triggers a SECOND triage call; the max-rank classification wins.

    Why: Gemini Flash-Lite at ``thinking_budget=0`` has measurable
    variance on borderline files. The WCtesting campaign observed
    ruamel-yaml/loader.py flip CLEAN ↔ HIGH between back-to-back runs
    with identical input. A single CLEAN result short-circuits the
    entire cascade (triage → no L1 → no DAST), so a single bad flip
    causes a file to ship as ``clean`` despite having real attack
    surface.

    Two-shot triage with max-rank aggregation cuts the flip rate
    geometrically: if Flash-Lite has 30% CLEAN-flip on a borderline
    file, two calls make that 9%; three calls make it 2.7%. Cost is
    only doubled on CLEAN-first results (~$0.001 extra per CLEAN
    file), so the campaign budget impact is negligible.

    Telemetry: the wrapper adds ``triage_runs`` (count) and
    ``triage_classifications_all`` (list) to the returned dict so
    operators can audit which files had a flip caught by the wrapper.

    Non-CLEAN first results (LOW / HIGH) pass through unchanged —
    those are already conservative enough that re-running doesn't add
    value, and any flip toward "less alarmed" on a re-call would be
    LESS conservative (wrong direction to take the max).
    """

    async def wrapped(filename: str, content: bytes, pp: Any) -> dict:
        first = await triage_runner(filename, content, pp)
        first_cls = first.get("classification") or "HIGH"
        if first_cls != "CLEAN":
            # Already at LOW or HIGH — don't spend cycles re-confirming
            # a more-conservative result.
            first["triage_runs"] = 1
            first["triage_classifications_all"] = [first_cls]
            return first

        # First call was CLEAN — confirm with a second call.
        second = await triage_runner(filename, content, pp)
        second_cls = second.get("classification") or "HIGH"

        rank1 = _TRIAGE_RANK.get(first_cls, 2)
        rank2 = _TRIAGE_RANK.get(second_cls, 2)
        winner = first if rank1 >= rank2 else second

        # Carry forward the winning classification's full result but
        # annotate cost + telemetry across BOTH runs so operators see
        # the confirm-clean overhead.
        out = dict(winner)
        out["cost_usd"] = round(
            float(first.get("cost_usd") or 0) + float(second.get("cost_usd") or 0), 6
        )
        out["input_tokens"] = int(first.get("input_tokens") or 0) + int(
            second.get("input_tokens") or 0
        )
        out["output_tokens"] = int(first.get("output_tokens") or 0) + int(
            second.get("output_tokens") or 0
        )
        out["duration_ms"] = int(first.get("duration_ms") or 0) + int(
            second.get("duration_ms") or 0
        )
        out["triage_runs"] = 2
        out["triage_classifications_all"] = [first_cls, second_cls]
        return out

    return wrapped


def make_opus_runner(
    api_key: str,
    *,
    thinking_budget: int = 24000,
) -> Callable[..., Awaitable[dict]]:
    """Build the Opus 4.6 analysis runner — high-stakes / borderline tier.

    Same composition as Sonnet but with Opus pricing and the deeper model.
    Engine routes here for files where preprocessing flags a high-stakes
    category (crypto, AI-tool, obfuscation) and for borderline-uncertainty
    escalation from Sonnet.

    Default ``thinking_budget=24000`` (full reasoning depth — when we pay
    Opus's premium we usually want it). Pass ``thinking_budget=0`` to
    disable extended thinking on the install path's bulk-scan mode where
    throughput matters more than reasoning depth on already-Opus-tier
    files (rare on the install path because most wheels stay in Sonnet).
    """
    cfg: dict[str, Any] = {
        # See Sonnet runner: 16384 was too tight on dense files.
        "max_tokens": 32768,
        "enable_system_cache": True,
    }
    if thinking_budget >= 2048:
        cfg["thinking_budget"] = thinking_budget
    adapter = AnthropicAdapter(
        {
            "name": "argus-opus-4-6",
            "model_id": "claude-opus-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": cfg,
        }
    )
    return make_anthropic_runner_from_adapter(
        adapter,
        model_label="claude-opus-4-6",
        cost_per_m_input=OPUS_46_COST_IN,
        cost_per_m_output=OPUS_46_COST_OUT,
    )


def make_opus_runner_hunter(
    api_key: str,
    *,
    hunter_set: tuple[str, ...] | None = None,
    max_concurrent_hunters: int = 10,
    thinking_budget: int = 24000,
) -> Callable[..., Awaitable[dict]]:
    """SCAN-011 — Opus 4.6 runner with attack-class hunter fan-out.
    Used on high-stakes HIGH-triage files. See
    :func:`make_sonnet_runner_hunter` for behavior + cost story."""
    cfg: dict[str, Any] = {
        "max_tokens": 32768,
        "enable_system_cache": True,
    }
    if thinking_budget >= 2048:
        cfg["thinking_budget"] = thinking_budget
    adapter = AnthropicAdapter(
        {
            "name": "argus-opus-4-6-hunter",
            "model_id": "claude-opus-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": cfg,
        }
    )
    return make_anthropic_hunter_runner_from_adapter(
        adapter,
        hunter_set=hunter_set,
        max_concurrent_hunters=max_concurrent_hunters,
        model_label="claude-opus-4-6",
        cost_per_m_input=OPUS_46_COST_IN,
        cost_per_m_output=OPUS_46_COST_OUT,
    )


def make_opus_runner_split(
    api_key: str,
    *,
    thinking_budget: int = 24000,
) -> Callable[..., Awaitable[dict]]:
    """SCAN-010 — Opus 4.6 runner that fans out three specialized
    prompts. See :func:`make_sonnet_runner_split` for the rationale;
    same change, Opus pricing + deeper model. Used when triage flags
    a HIGH-stakes routing AND ``l1_split_enabled`` is on."""
    cfg: dict[str, Any] = {
        "max_tokens": 32768,
        "enable_system_cache": True,
    }
    if thinking_budget >= 2048:
        cfg["thinking_budget"] = thinking_budget
    adapter = AnthropicAdapter(
        {
            "name": "argus-opus-4-6-split",
            "model_id": "claude-opus-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": cfg,
        }
    )
    return make_anthropic_split_runner_from_adapter(
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
    "make_anthropic_hunter_runner_from_adapter",
    "make_anthropic_runner_from_adapter",
    "make_anthropic_split_runner_from_adapter",
    "make_gemini_triage_runner",
    "make_sonnet_triage_runner",
    "make_opus_runner",
    "make_opus_runner_hunter",
    "make_opus_runner_split",
    "make_sonnet_runner",
    "make_sonnet_runner_hunter",
    "make_sonnet_runner_split",
    "make_triage_runner_from_adapter",
    "score_to_verdict",
    "with_confirm_clean",
]
