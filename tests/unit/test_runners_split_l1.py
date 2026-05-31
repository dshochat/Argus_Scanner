"""SCAN-010 regression tests for the split-L1 runner.

Stubs the Anthropic adapter so the three specialized prompts can be
verified by inspection without live API spend. Covers:

* Fan-out shape (3 calls with VULNS / BEHAVIORAL / CHAINS prompts)
* Merge correctness (disjoint schema slices combine into the engine
  dict the existing combined runner emits)
* Verdict derivation via the same score_to_verdict path as combined
* Cost = sum across sub-calls
* Wall-clock = max across sub-calls
* Uncertainty = max across sections (conservative escalation signal)
* Telemetry surfaces per-sub-call validity flags

Failure modes:
* One sub-call JSON-fails → merged result blanks that section,
  ship anyway (engine handles empty sections)
* 2+ sub-calls JSON-fail → systemic error surfaces to engine
* Sub-call raises → asyncio.gather propagates → error response
* Identity leak in one section → that section blanked + sanitizer_error
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from prompts.scanner import (
    SCAN_PROMPT_BEHAVIORAL,
    SCAN_PROMPT_CHAINS,
    SCAN_PROMPT_VULNS,
)
from scanner.runners import (
    make_anthropic_split_runner_from_adapter,
)


class _FakeSplitAdapter:
    """Stub adapter that returns prompt-specific responses keyed by the
    system prompt's first N chars. Lets one adapter instance serve all
    three specialized prompts within a single test."""

    def __init__(self, responses_by_prompt_prefix: dict[str, dict]) -> None:
        self._responses = responses_by_prompt_prefix
        self.calls: list[tuple[str, str]] = []

    async def scan(self, content: str, filename: str, system_prompt: str) -> dict:
        # Record the full system prompt (the three specialized prompts
        # share SCAN_PROMPT_SYSTEM as their first ~2000 chars — that's
        # by design and is what makes prompt caching beneficial across
        # the fan-out). The discriminating content is later in each
        # prompt's body.
        self.calls.append((filename, system_prompt))
        # Find the canned response by matching a stable substring from
        # the specialized prompt. The match avoids depending on exact
        # byte-for-byte prompt content (which changes when prompts.scanner
        # is edited).
        for marker, response in self._responses.items():
            if marker in system_prompt:
                return response
        raise AssertionError(
            f"FakeSplitAdapter has no canned response for system_prompt "
            f"prefix {system_prompt[:200]!r}"
        )


def _vulns_response(
    *,
    score: int | float | None = 60,
    n_vulns: int = 1,
    json_valid: bool = True,
    in_tokens: int = 1500,
    out_tokens: int = 600,
    duration_ms: int = 1800,
) -> dict:
    if not json_valid:
        return {
            "parsed": None,
            "json_valid": False,
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "response_time_ms": duration_ms,
            "error": None,
        }
    vulns_list = [
        {
            "type": "ssrf",
            "severity": "high",
            "line": 7,
            "code": "urlopen(url)",
            "explanation": "User-controlled URL flows to urlopen.",
            "fix": "Validate scheme + host allowlist.",
            "cwe": "CWE-918",
            "confidence": 0.9,
            "data_flow_trace": "url → urlopen",
            "proof_of_concept": "http://169.254.169.254/",
            "intent_check": "Not by-design — function description says fetch external URL.",
        }
        for _ in range(n_vulns)
    ]
    return {
        "parsed": {
            "file_intent_analysis": {
                "purpose": "fetch a URL",
                "deployment_context": "library",
                "trust_boundary": "any caller can pass URLs",
                "powerful_by_design": [],
            },
            "vulnerabilities": vulns_list,
            "composite_risk": {
                "score": score,
                "reasoning": "Unvalidated URL passed to urlopen.",
                "exploitability": "high",
            },
        },
        "json_valid": True,
        "input_tokens": in_tokens,
        "output_tokens": out_tokens,
        "response_time_ms": duration_ms,
        "error": None,
    }


def _behavioral_response(
    *,
    json_valid: bool = True,
    in_tokens: int = 1200,
    out_tokens: int = 500,
    duration_ms: int = 1500,
    composite_score: int | None = None,
) -> dict:
    """``composite_score`` (v1.9): when not None, include a composite_risk
    block on the parsed payload. Lets tests exercise the max-aggregation
    path that v1.9 added. None (default) preserves the v1.8 shape (no
    composite_risk emitted from this sub-call)."""
    if not json_valid:
        return {
            "parsed": None,
            "json_valid": False,
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "response_time_ms": duration_ms,
            "error": None,
        }
    parsed: dict[str, Any] = {
        "behavioral_profile": {
            "actual_capabilities": {
                "network_calls": [
                    {"destination": "user-supplied", "method": "GET"},
                ]
            },
            "deviations": [],
            "shield_policy": "block private-IP egress",
        }
    }
    if composite_score is not None:
        parsed["composite_risk"] = {
            "score": composite_score,
            "reasoning": "behavioral-side scoring",
            "exploitability": "medium",
        }
    return {
        "parsed": parsed,
        "json_valid": True,
        "input_tokens": in_tokens,
        "output_tokens": out_tokens,
        "response_time_ms": duration_ms,
        "error": None,
    }


def _chains_response(
    *,
    json_valid: bool = True,
    in_tokens: int = 1000,
    out_tokens: int = 400,
    duration_ms: int = 1300,
    composite_score: int | None = None,
) -> dict:
    """``composite_score`` (v1.9): when not None, include a composite_risk
    block on the parsed payload (parallel of _behavioral_response)."""
    if not json_valid:
        return {
            "parsed": None,
            "json_valid": False,
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "response_time_ms": duration_ms,
            "error": None,
        }
    parsed: dict[str, Any] = {
        "ai_tool_analysis": {"mcp_servers": [], "agent_configs": []},
        "attack_chains": [],
    }
    if composite_score is not None:
        parsed["composite_risk"] = {
            "score": composite_score,
            "reasoning": "chain-side scoring",
            "exploitability": "low",
        }
    return {
        "parsed": parsed,
        "json_valid": True,
        "input_tokens": in_tokens,
        "output_tokens": out_tokens,
        "response_time_ms": duration_ms,
        "error": None,
    }


def _all_responses(**overrides: dict[str, Any]) -> dict[str, dict]:
    """Build the response map keyed on stable prompt-content markers."""
    vulns_marker = "security vulnerabilities and provide an overall risk"
    behav_marker = "this file's runtime behavior. Trace every capability"
    chains_marker = "AI tool security issues and multi-step attack chains"
    # Sanity — markers must actually appear in the live specialized
    # prompts. If a prompt edit drops one, this assertion fires loud
    # and we update the test rather than discovering it at runtime.
    assert vulns_marker in SCAN_PROMPT_VULNS, "vulns marker drifted"
    assert behav_marker in SCAN_PROMPT_BEHAVIORAL, "behavioral marker drifted"
    assert chains_marker in SCAN_PROMPT_CHAINS, "chains marker drifted"
    return {
        vulns_marker: overrides.get("vulns", _vulns_response()),
        behav_marker: overrides.get("behav", _behavioral_response()),
        chains_marker: overrides.get("chains", _chains_response()),
    }


def _build_runner(adapter: _FakeSplitAdapter) -> Any:
    return make_anthropic_split_runner_from_adapter(
        adapter,
        model_label="test-sonnet",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )


# ── Happy path ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_split_runner_fans_out_three_specialized_prompts() -> None:
    """The split runner MUST send the three specialized prompts —
    not the combined SECURITY_SCAN_PROMPT. Each call goes to the
    same adapter; the test confirms the adapter saw three different
    prompts."""
    adapter = _FakeSplitAdapter(_all_responses())
    runner = _build_runner(adapter)

    result = await runner("app.py", b"import urllib.request\n", None, "HIGH")

    # Three calls landed.
    assert len(adapter.calls) == 3
    # Each call used a distinct specialized prompt — full-body
    # comparison (they share SCAN_PROMPT_SYSTEM but diverge in the
    # body the marker substrings live in).
    seen_prompts = {p for (_filename, p) in adapter.calls}
    assert len(seen_prompts) == 3
    # Every specialized prompt's distinguishing marker appears in
    # exactly one of the three calls — confirms each prompt was
    # actually sent, not the same one three times.
    full_concat = " ".join(seen_prompts)
    assert full_concat.count("security vulnerabilities and provide") == 1
    assert full_concat.count("runtime behavior. Trace every capability") == 1
    assert full_concat.count("AI tool security issues and multi-step") == 1
    # No call mistakenly fired the combined prompt.
    assert not any(
        "Analyze this file for security vulnerabilities, behavioral"
        in p
        for p in seen_prompts
    )


@pytest.mark.asyncio
async def test_split_runner_merges_disjoint_sections() -> None:
    """VULNS contributes file_intent_analysis + vulnerabilities +
    composite_risk; BEHAVIORAL contributes behavioral_profile;
    CHAINS contributes ai_tool_analysis + attack_chains. The merged
    output must show every section."""
    adapter = _FakeSplitAdapter(_all_responses())
    runner = _build_runner(adapter)

    out = await runner("app.py", b"x = 1\n", None, "HIGH")

    # From VULNS
    assert out["vulnerabilities"]
    assert out["vulnerabilities"][0]["type"] == "ssrf"
    assert out["file_intent_analysis"]["deployment_context"] == "library"
    # From BEHAVIORAL — surfaces on behavioral_profile, not as a
    # top-level "deviations" key (the section nests under behavioral_profile).
    assert out["behavioral_profile"]["shield_policy"] == "block private-IP egress"
    # From CHAINS
    assert out["ai_tool_analysis"] == {"mcp_servers": [], "agent_configs": []}
    assert out["attack_chains"] == []


@pytest.mark.asyncio
async def test_split_runner_derives_verdict_from_vulns_composite_score() -> None:
    """Verdict comes from VULNS' composite_risk.score via the same
    score_to_verdict mapping the combined runner uses. score=60 is in
    the malicious band (50-74)."""
    adapter = _FakeSplitAdapter(_all_responses())
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    assert out["verdict_label"] == "malicious"


@pytest.mark.asyncio
async def test_split_runner_costs_aggregate_across_subcalls() -> None:
    """input + output tokens are summed across the three sub-calls;
    cost is computed from the aggregate at the runner's rate."""
    adapter = _FakeSplitAdapter(_all_responses())
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")

    # VULNS 1500/600 + BEHAV 1200/500 + CHAINS 1000/400 = 3700/1500
    assert out["input_tokens"] == 3700
    assert out["output_tokens"] == 1500
    # 3700 × $3/M + 1500 × $15/M = $0.0111 + $0.0225 = $0.0336
    assert out["cost_usd"] == pytest.approx(0.0336, abs=1e-4)


@pytest.mark.asyncio
async def test_split_runner_duration_is_max_subcall() -> None:
    """Wall-clock for the fan-out = slowest sub-call (asyncio.gather
    blocks on the longest). VULNS=1800 > BEHAV=1500 > CHAINS=1300."""
    adapter = _FakeSplitAdapter(_all_responses())
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    assert out["duration_ms"] == 1800


@pytest.mark.asyncio
async def test_split_runner_model_label_marks_split() -> None:
    """Operators distinguishing split from combined need a clear
    telemetry signal."""
    adapter = _FakeSplitAdapter(_all_responses())
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    assert out["model"] == "test-sonnet-split"


@pytest.mark.asyncio
async def test_split_runner_emits_split_telemetry_block() -> None:
    """split_telemetry surfaces per-sub-call validity so bench tooling
    + operators can see which prompts succeeded."""
    adapter = _FakeSplitAdapter(_all_responses())
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    tel = out.get("split_telemetry") or {}
    assert tel.get("n_valid") == 3
    assert tel.get("vulns_valid") is True
    assert tel.get("behav_valid") is True
    assert tel.get("chains_valid") is True


# ── Failure handling ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_split_runner_one_subcall_invalid_ships_anyway() -> None:
    """1 of 3 sub-calls JSON-fails → merged output blanks that section
    but the scan still completes. No transparent fallback to the
    combined prompt — engine downstream handles empty sections."""
    adapter = _FakeSplitAdapter(
        _all_responses(behav=_behavioral_response(json_valid=False))
    )
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")

    # Vulns + chains preserved; behavioral blanked.
    assert out["vulnerabilities"]
    assert out["attack_chains"] == []
    assert out["behavioral_profile"] == {}
    # Verdict still derived from vulns composite_risk.
    assert out["verdict_label"] == "malicious"
    # Telemetry reflects the partial success.
    tel = out["split_telemetry"]
    assert tel["n_valid"] == 2
    assert tel["behav_valid"] is False


@pytest.mark.asyncio
async def test_split_runner_two_subcalls_invalid_surfaces_systemic_error() -> None:
    """2+ JSON-parse failures across 3 calls = systemic problem
    (rate limit / schema drift / model degradation). Don't silently
    fall back to combined — surface the error so the engine sees it
    distinctly and the operator can diagnose."""
    adapter = _FakeSplitAdapter(
        _all_responses(
            behav=_behavioral_response(json_valid=False),
            chains=_chains_response(json_valid=False),
        )
    )
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    assert out["error"] is not None
    assert "systemic_parse_failure" in out["error"]
    assert out["verdict_label"] == "suspicious"  # conservative fallback
    # Tokens + cost from the sub-calls that did complete are still
    # surfaced so the operator sees the spend on the failed scan.
    assert out["input_tokens"] > 0


@pytest.mark.asyncio
async def test_split_runner_gather_exception_surfaces_as_error() -> None:
    """If a sub-call coroutine raises (network error, etc.),
    asyncio.gather(..., return_exceptions=True) catches it and the
    runner ships an error response — does NOT crash the engine."""

    class _RaisingAdapter:
        async def scan(self, content: str, filename: str, system_prompt: str) -> dict:
            if "AI tool security" in system_prompt:
                raise ConnectionError("transient")
            # Return valid responses for the other two so we exercise
            # the partial-failure path AND the exception path.
            if "behavioral" in system_prompt or "runtime behavior" in system_prompt:
                return _behavioral_response()
            return _vulns_response()

    runner = make_anthropic_split_runner_from_adapter(
        _RaisingAdapter(),
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    out = await runner("app.py", b"x", None, "HIGH")
    assert out["error"] is not None
    assert "split_l1_call_failed" in out["error"]
    assert "ConnectionError" in out["error"]


# ── Asyncio.gather concurrency ────────────────────────────────────────


@pytest.mark.asyncio
async def test_split_runner_fans_out_in_parallel_not_sequential() -> None:
    """The three calls fire via asyncio.gather. Verify by introducing
    a small sleep per sub-call and confirming total elapsed is close
    to the longest sub-call (parallel) rather than the sum (sequential)."""

    class _SleepingAdapter:
        async def scan(self, content: str, filename: str, system_prompt: str) -> dict:
            await asyncio.sleep(0.05)  # 50ms per sub-call
            if "security vulnerabilities and provide" in system_prompt:
                return _vulns_response()
            if "runtime behavior" in system_prompt:
                return _behavioral_response()
            return _chains_response()

    runner = make_anthropic_split_runner_from_adapter(
        _SleepingAdapter(),
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    import time

    t0 = time.perf_counter()
    await runner("app.py", b"x", None, "HIGH")
    elapsed_s = time.perf_counter() - t0

    # Parallel: ~50ms. Sequential would be ~150ms. Allow 30% headroom
    # for event-loop scheduling jitter on CI.
    assert elapsed_s < 0.13, (
        f"Split runner appears to be sequential — total elapsed "
        f"{elapsed_s * 1000:.0f}ms (expected ~50ms parallel)"
    )


# ── Uncertainty derivation ────────────────────────────────────────────


# ── SCAN-010.1 — Two-block prefix-sharing path ────────────────────────


class _FakeTwoBlockAdapter:
    """Stub adapter that exposes the SCAN-010.1 two-block API. Tracks
    (system_prefix, system_body) pairs so tests can assert the prefix
    is byte-identical across the 3 specialized calls (i.e., the cache
    key is shared)."""

    def __init__(self, responses_by_body_marker: dict[str, dict]) -> None:
        self._responses = responses_by_body_marker
        self.two_block_calls: list[dict[str, str]] = []
        self.single_block_calls: list[tuple[str, str]] = []

    async def scan_with_prefix_body(
        self,
        content: str,
        filename: str,
        system_prefix: str,
        system_body: str,
    ) -> dict:
        self.two_block_calls.append(
            {
                "filename": filename,
                "prefix": system_prefix,
                "body": system_body,
            }
        )
        for marker, response in self._responses.items():
            if marker in system_body:
                return response
        raise AssertionError(
            f"FakeTwoBlockAdapter has no response for body prefix "
            f"{system_body[:200]!r}"
        )

    async def scan(self, content: str, filename: str, system_prompt: str) -> dict:
        # Records the call but should NOT fire when scan_with_prefix_body
        # is available — the runner prefers the two-block path. If this
        # method gets called, the test will catch it via the assertion
        # in the runner tests that two_block_calls has the entries.
        self.single_block_calls.append((filename, system_prompt))
        raise AssertionError(
            "Single-block scan() called on adapter that supports two-block; "
            "runner should prefer scan_with_prefix_body when available"
        )


def _two_block_response_map() -> dict[str, dict]:
    """Build a response map keyed on stable body-content markers."""
    return {
        "security vulnerabilities and provide": _vulns_response(),
        "runtime behavior. Trace every capability": _behavioral_response(),
        "AI tool security issues and multi-step": _chains_response(),
    }


@pytest.mark.asyncio
async def test_split_runner_uses_two_block_path_when_adapter_supports_it() -> None:
    """SCAN-010.1: when the adapter exposes ``scan_with_prefix_body``,
    the split runner MUST use it (not single-block ``scan``). Critical
    for cache-prefix-sharing to work in production."""
    adapter = _FakeTwoBlockAdapter(_two_block_response_map())
    runner = make_anthropic_split_runner_from_adapter(
        adapter,
        model_label="test-sonnet",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    out = await runner("app.py", b"x = 1\n", None, "HIGH")

    # Three calls landed on the two-block path; zero on single-block.
    assert len(adapter.two_block_calls) == 3
    assert len(adapter.single_block_calls) == 0
    # All three sub-calls produced valid JSON, verdict derived from VULNS.
    assert out["error"] is None
    assert out["verdict_label"] == "malicious"


@pytest.mark.asyncio
async def test_split_runner_two_block_prefix_byte_identical_across_calls() -> None:
    """SCAN-010.1: the three specialized calls MUST send byte-identical
    ``system_prefix`` text. That's what enables Anthropic's cache to
    return the same cache entry for all three — the load-bearing
    invariant behind the cost-reduction claim."""
    adapter = _FakeTwoBlockAdapter(_two_block_response_map())
    runner = make_anthropic_split_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    await runner("app.py", b"x = 1\n", None, "HIGH")

    prefixes = {c["prefix"] for c in adapter.two_block_calls}
    assert len(prefixes) == 1, (
        f"Expected 1 unique system_prefix across the 3 sub-calls "
        f"(cache key sharing). Got {len(prefixes)} distinct prefixes — "
        f"each call would write its own cache entry, defeating the "
        f"SCAN-010.1 optimization."
    )


@pytest.mark.asyncio
async def test_split_runner_two_block_prefix_is_scan_prompt_system() -> None:
    """The shared prefix MUST be exactly ``SCAN_PROMPT_SYSTEM`` — not
    one of the specialized prompts or some other text. Guards against
    a future refactor accidentally passing the wrong constant."""
    from prompts.scanner import SCAN_PROMPT_SYSTEM

    adapter = _FakeTwoBlockAdapter(_two_block_response_map())
    runner = make_anthropic_split_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    await runner("app.py", b"x = 1\n", None, "HIGH")

    for call in adapter.two_block_calls:
        assert call["prefix"] == SCAN_PROMPT_SYSTEM, (
            "Prefix block must be exactly SCAN_PROMPT_SYSTEM for "
            "Anthropic's cache to key on it. Any drift defeats the "
            "shared-prefix optimization."
        )


@pytest.mark.asyncio
async def test_split_runner_two_block_bodies_are_distinct_per_specialized_prompt() -> None:
    """Each sub-call's body must be the body of its specific
    specialized prompt — VULNS body, BEHAVIORAL body, CHAINS body —
    in some order. Confirms the runner sends the RIGHT body for each
    cache key, not the same body three times."""
    from prompts.scanner import (
        SCAN_PROMPT_BEHAVIORAL_BODY,
        SCAN_PROMPT_CHAINS_BODY,
        SCAN_PROMPT_VULNS_BODY,
    )

    adapter = _FakeTwoBlockAdapter(_two_block_response_map())
    runner = make_anthropic_split_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    await runner("app.py", b"x = 1\n", None, "HIGH")

    bodies = {c["body"] for c in adapter.two_block_calls}
    expected = {
        SCAN_PROMPT_VULNS_BODY,
        SCAN_PROMPT_BEHAVIORAL_BODY,
        SCAN_PROMPT_CHAINS_BODY,
    }
    assert bodies == expected


@pytest.mark.asyncio
async def test_split_runner_falls_back_to_single_block_for_old_adapters() -> None:
    """SCAN-010.1 back-compat: adapters that don't expose
    ``scan_with_prefix_body`` (older builds, test stubs without the
    new method) get the single-block ``scan`` path. The runner detects
    via ``hasattr`` so the back-compat path is automatic."""
    # _FakeSplitAdapter doesn't have scan_with_prefix_body — it's the
    # pre-SCAN-010.1 stub used by every other test in this module.
    adapter = _FakeSplitAdapter(_all_responses())
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x = 1\n", None, "HIGH")

    # Pre-SCAN-010.1 path fires; no errors; result shape preserved.
    assert out["error"] is None
    assert out["verdict_label"] == "malicious"
    assert len(adapter.calls) == 3


@pytest.mark.asyncio
async def test_split_runner_uncertainty_picks_max_across_sections() -> None:
    """Conservative escalation: if ANY section is uncertain, the
    aggregate uncertainty reflects that — the engine then escalates
    to Opus via the borderline-ensemble path. Empty behavioral_profile
    contributes 0.4 to the aggregate."""
    adapter = _FakeSplitAdapter(
        _all_responses(
            behav={
                "parsed": {"behavioral_profile": {}},  # empty actual_capabilities
                "json_valid": True,
                "input_tokens": 1200,
                "output_tokens": 500,
                "response_time_ms": 1500,
                "error": None,
            }
        )
    )
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    # Behavioral section was empty → 0.4 floor; vulns has a single
    # finding at confidence 0.9 = 0.1 vulnerability-uncertainty; score 60
    # is 10 from the 50/75 boundary so boundary_uncertainty = 0.2.
    # Max of {0.4, 0.2} = 0.4.
    assert out["uncertainty"] == pytest.approx(0.4, abs=0.05)


# ── v1.9 composite_risk max-aggregation across sub-calls ───────────────


@pytest.mark.asyncio
async def test_composite_risk_takes_max_across_sub_calls() -> None:
    """v1.9 — when all three sub-calls emit composite_risk, the merge
    takes MAX score. Mirrors the n8n regression: VULNS scored 0
    (clean) but BEHAVIORAL had context to score the cleartext-creds
    flow as 35 (suspicious). The max-aggregation path lifts the
    final verdict to suspicious so DAST's trigger gate fires."""
    adapter = _FakeSplitAdapter(
        _all_responses(
            vulns=_vulns_response(score=0, n_vulns=2),         # under-call
            behav=_behavioral_response(composite_score=35),    # behavioral angle
            chains=_chains_response(composite_score=10),       # low-stakes chains
        )
    )
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")

    # Max(0, 35, 10) = 35 → suspicious.
    assert out["composite_risk"]["score"] == 35
    assert out["verdict_label"] == "suspicious"
    # The merge surfaces which sub-call drove the verdict.
    assert out["composite_risk"]["aggregation_source"] == "behavioral"
    # And exposes the per-sub-call scores for audit.
    assert out["composite_risk"]["sub_call_scores"] == {
        "vulns": 0, "behavioral": 35, "chains": 10,
    }


@pytest.mark.asyncio
async def test_composite_risk_max_picks_chains_when_highest() -> None:
    """Symmetric case: CHAINS scores highest (e.g., an exploit chain
    spans multiple findings). MAX correctly picks chains."""
    adapter = _FakeSplitAdapter(
        _all_responses(
            vulns=_vulns_response(score=20),
            behav=_behavioral_response(composite_score=25),
            chains=_chains_response(composite_score=60),  # malicious-band
        )
    )
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    assert out["composite_risk"]["score"] == 60
    assert out["composite_risk"]["aggregation_source"] == "chains"
    assert out["verdict_label"] == "malicious"


@pytest.mark.asyncio
async def test_composite_risk_falls_back_when_sub_calls_omit_field() -> None:
    """Back-compat: if BEHAVIORAL and CHAINS don't emit composite_risk
    (the v1.8 shape — what the existing test fixtures use), the merge
    still works using only VULNS's score. Lets old fixtures coexist
    with the new behavior."""
    adapter = _FakeSplitAdapter(
        _all_responses(
            vulns=_vulns_response(score=60),
            # behav + chains default to v1.8 shape (no composite_risk)
        )
    )
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    assert out["composite_risk"]["score"] == 60
    assert out["composite_risk"]["aggregation_source"] == "vulns"
    assert out["verdict_label"] == "malicious"


@pytest.mark.asyncio
async def test_composite_risk_clamps_to_unit_range() -> None:
    """Defensive: a model emitting score=150 or score=-5 gets clamped
    to [0, 100]. Same for negative / non-int / None values per
    sub-call."""
    adapter = _FakeSplitAdapter(
        _all_responses(
            vulns=_vulns_response(score=150),                  # over-cap
            behav=_behavioral_response(composite_score=-10),   # under-cap
            chains=_chains_response(composite_score=50),
        )
    )
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    # Vulns clamps to 100; chains 50; behav 0. Max → 100 →
    # critical_malicious.
    assert out["composite_risk"]["score"] == 100
    assert out["verdict_label"] == "critical_malicious"


@pytest.mark.asyncio
async def test_composite_risk_handles_invalid_score_types() -> None:
    """A sub-call emitting score=null or a string-typed score should
    fall through to 0 (defensive), not crash the merge."""
    adapter = _FakeSplitAdapter(
        _all_responses(
            vulns=_vulns_response(score=None),
            behav=_behavioral_response(composite_score=30),
            chains=_chains_response(composite_score=15),
        )
    )
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    assert out["composite_risk"]["score"] == 30
    assert out["composite_risk"]["aggregation_source"] == "behavioral"


@pytest.mark.asyncio
async def test_composite_risk_no_sub_call_emits_score_returns_zero() -> None:
    """Pathological case: all three sub-calls JSON-fail or omit
    composite_risk entirely. Merge defaults to score=0 with empty
    reasoning — engine's anti-undercall backstop is the final safety
    net for this case."""
    adapter = _FakeSplitAdapter(
        _all_responses(
            vulns={
                "parsed": {"file_intent_analysis": {}, "vulnerabilities": []},
                "json_valid": True,
                "input_tokens": 100,
                "output_tokens": 50,
                "response_time_ms": 100,
                "error": None,
            },
            behav={
                "parsed": {"behavioral_profile": {}},
                "json_valid": True,
                "input_tokens": 100,
                "output_tokens": 50,
                "response_time_ms": 100,
                "error": None,
            },
            chains={
                "parsed": {"ai_tool_analysis": {}, "attack_chains": []},
                "json_valid": True,
                "input_tokens": 100,
                "output_tokens": 50,
                "response_time_ms": 100,
                "error": None,
            },
        )
    )
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x", None, "HIGH")
    assert out["composite_risk"]["score"] == 0
    assert out["verdict_label"] == "clean"
