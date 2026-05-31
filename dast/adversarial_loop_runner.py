"""Phase 3 Stage 2 — adversarial-loop orchestrator (v1.6 minimal).

This module implements the actual loop that consumes
:mod:`dast.adversarial_loop` scaffolding (data types + tunables) and
the :func:`dast.prompts.build_phase_3_loop_hypothesis_batch_prompt`
prompt to drive an adversarial reasoning session against one file.

Minimal scope (v1.6):

* ``run_one_turn`` — production-ready single-turn primitive: call the
  model for a hypothesis batch, decode it, dispatch each hypothesis to
  the right plan-builder + sandbox + interpreter combination, parallel-
  test in the sandbox, and return an :class:`AdversarialTurn` populated
  with hypotheses + outcomes + cost.
* ``run_adversarial_loop`` — outer wrapper that calls ``run_one_turn``
  in a loop bounded by ``max_turns`` (default 1). The seams for full
  multi-turn refinement (dedup across turns, L1 short-circuit, cost/
  wall-clock budget enforcement) are in place but not exercised at
  ``max_turns=1`` — they activate when a future commit lands the
  refinement logic.

Why "minimal" and not full multi-turn from day one: the thin-slice
measurement gate decides whether multi-turn refinement is worth the
extra engineering. We ship the single-turn primitive correctly, run
it on the 5-vuln-plus-3-clean regression slice, and then either keep
max_turns=1 (if Turn 0 closes the gap) or invest in refinement logic
(if it doesn't). Same decision gate, less throwaway code than a
separate measurement harness in ``methodology/``.

Each hypothesis kind dispatches to:

* ``probe`` — reuses :func:`build_runtime_probe_plan` +
  :func:`parse_probe_trace` from Phase B+, but interprets the trace
  via :func:`interpret_probe_observation` (descriptive — never asserts
  exploit). Outcome verdict is ``VERDICT_PROBE_OBSERVED``.
* ``single_function`` — reuses the Phase B+ plan-build + trace-parse
  + :func:`interpret_probe_trace` path verbatim. Outcome is
  ``VERDICT_CONFIRMED`` when a finding lands, ``VERDICT_REFUTED``
  otherwise.
* ``stateful_sequence`` — reuses Phase 3 Stage 2 stateful-sequence
  plan + parse + :func:`interpret_stateful_sequence_trace`. Outcome
  shape mirrors ``single_function``.

Cost tracking matches Phase B+ rates (Sonnet 4.6); the loop's total
cost feeds the production cap once Step 7 wires this into engine.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from dast.adversarial_loop import (
    HYPOTHESIS_KIND_PROBE,
    HYPOTHESIS_KIND_SINGLE_FUNCTION,
    HYPOTHESIS_KIND_STATEFUL_SEQUENCE,
    LANGUAGE_JAVASCRIPT,
    LANGUAGE_PYTHON,
    LANGUAGE_SHELL,
    LANGUAGE_TYPESCRIPT,  # v9
    MAX_HYPOTHESES_PER_TURN,
    MIN_TURNS_BEFORE_EARLY_EXIT,
    TERMINATED_BY_MAX_TURNS,
    TERMINATED_BY_NO_NEW,
    VERDICT_BLOCKED,
    VERDICT_CONFIRMED,
    VERDICT_PROBE_OBSERVED,
    VERDICT_REFUTED,
    AdversarialHypothesis,
    AdversarialHypothesisOutcome,
    AdversarialLoopResult,
    AdversarialTurn,
)
from dast.prompts import (
    build_phase_3_loop_hypothesis_batch_prompt,
    build_post_trace_judge_prompt,
    phase_3_loop_hypothesis_batch_schema,
    post_trace_judge_schema,
)
from dast.runtime_probe import (
    RuntimeProbeCandidate,
    RuntimeProbeInput,
    build_runtime_probe_plan,
    build_runtime_stateful_sequence_plan,
    cwe_for_attack_class,
    interpret_probe_observation,
    interpret_probe_trace,
    interpret_stateful_sequence_trace,
    normalize_args_json,
    normalize_kwargs_json,
    parse_probe_trace,
    parse_stateful_sequence_trace,
    severity_for_attack_class,
)
from dast.sandbox.client import SandboxClient, SandboxPlan

log = structlog.get_logger(__name__)


#: Inference-callable shape. Matches the production
#: ``make_dast_sonnet_inference`` signature: ``(prompt, params, schema)
#: -> {"text": "...", "usage": {"prompt_tokens": N, "completion_tokens": M}}``.
InferenceFn = Callable[[str, dict[str, Any], dict[str, Any]], Awaitable[dict[str, Any]]]


# ── Cost model (matches Phase B+ Sonnet 4.6 rates) ─────────────────────────

#: USD per 1M input tokens (Sonnet 4.6).
INFERENCE_INPUT_USD_PER_M: float = 3.0
#: USD per 1M output tokens (Sonnet 4.6).
INFERENCE_OUTPUT_USD_PER_M: float = 15.0


def _inference_cost_usd(usage: dict[str, Any]) -> float:
    """Compute USD cost for one inference call from token usage."""
    pin = int(usage.get("prompt_tokens", 0) or 0)
    pout = int(usage.get("completion_tokens", 0) or 0)
    return (pin / 1_000_000) * INFERENCE_INPUT_USD_PER_M + (
        pout / 1_000_000
    ) * INFERENCE_OUTPUT_USD_PER_M


# ── Fixture / demo-context detection (v1.6 Fix #4) ────────────────────────
#
# The 23-file adjudication eval (Gemini 3.1 Pro on 18 W1 candidates)
# found 8/16 over-claims were on TEST FIXTURE files where Argus treated
# explicit fixture annotations as real exploits. The pattern: a file
# has a header comment like "Consistency fixture 1 to test scanner
# obfuscation detection" or "scrubbed reproduction of the 2018
# event-stream supply chain attack" with a "neutered payload"
# explicitly stating the malicious behavior was removed. Argus's L1
# correctly identifies the vulnerable pattern + DAST observes the
# benign reproduction firing -- both produce CONFIRMED. But the
# finding isn't a production-grade zero-day; it's an intentional test
# artifact.
#
# This helper scans the file's first ~4KB for fixture markers. When
# matched, the runner downgrades CONFIRMED outcome confidence to <=0.5
# and prefixes ``runtime_evidence`` with ``FIXTURE_CONTEXT:`` so the
# customer-facing output makes the test-artifact framing explicit.
#
# We do NOT reject the finding entirely -- the pattern detection is
# still valuable, and a fixture file CAN expose real bugs (e.g., the
# scanner-test code itself might be vulnerable). We just don't claim
# zero-day strength when the file labels itself a fixture.

_FIXTURE_MARKERS: tuple[str, ...] = (
    "# fixture",
    "# scrubbed",
    "# neutered",
    "# regression fixture",
    "# test fixture",
    "# intentional",
    "# for benchmark",
    "# for scanner test",
    "scrubbed reproduction",
    "neutered payload",
    "scanner test",
    "consistency fixture",
    "regression baseline",
    # JSDoc / JS block comments
    "/* fixture",
    "/* scrubbed",
    "/* neutered",
    "// fixture",
    "// scrubbed",
    "// neutered",
)

#: Confidence cap applied to CONFIRMED outcomes on fixture-context
#: files. Picked at 0.5 so the finding still has positive signal
#: (something matched a real exploit pattern) but stays below the
#: 0.7 class-signature threshold and the 1.0 canary threshold.
_FIXTURE_CONFIDENCE_CAP: float = 0.5


def _is_fixture_context(file_bytes: bytes, scan_bytes: int = 4000) -> bool:
    """Return True iff the file's header contains a fixture marker.

    Scans the first ``scan_bytes`` characters (default 4KB -- enough
    to cover docstring + license + first dozen lines). Case-insensitive
    substring match. Defensive: returns False on any decode error so a
    malformed file can't take down the runner.
    """
    if not file_bytes:
        return False
    try:
        head = file_bytes[:scan_bytes].decode("utf-8", errors="replace").lower()
    except Exception:  # noqa: BLE001
        return False
    return any(marker in head for marker in _FIXTURE_MARKERS)


def _apply_fixture_downgrade(
    outcome: AdversarialHypothesisOutcome,
    file_bytes: bytes,
) -> AdversarialHypothesisOutcome:
    """If file is fixture-context AND outcome is CONFIRMED, downgrade
    confidence to ``_FIXTURE_CONFIDENCE_CAP`` and prefix the
    ``runtime_evidence`` so the framing is explicit. Other verdicts
    (REFUTED / BLOCKED / PROBE_OBSERVED) are unaffected.
    """
    if outcome.verdict != VERDICT_CONFIRMED:
        return outcome
    if not _is_fixture_context(file_bytes):
        return outcome
    outcome.fixture_context = True
    if outcome.confidence > _FIXTURE_CONFIDENCE_CAP:
        outcome.confidence = _FIXTURE_CONFIDENCE_CAP
    if not outcome.runtime_evidence.startswith("FIXTURE_CONTEXT:"):
        outcome.runtime_evidence = (
            "FIXTURE_CONTEXT: file headers mark this as a test/scrubbed/"
            "neutered fixture; treat as pattern-match, not production "
            "zero-day. " + outcome.runtime_evidence
        )
    return outcome


# ── Strategy C: post-trace LLM judge (v1.8) ────────────────────────────────


async def _invoke_judge(
    outcome: AdversarialHypothesisOutcome,
    *,
    trace: Any,
    inference: InferenceFn,
) -> AdversarialHypothesisOutcome:
    """Strategy C: post-trace LLM judge.

    After the deterministic interpreter says CONFIRMED, ask a model to
    independently judge: "did the exploit ACTUALLY fire, or did the
    application REJECT the input?" Catches the FP class Strategy B
    can't: model wrote a poor / missing ``rejection_signature``, so the
    substring oracle falsely confirmed because the application's error
    message echoed the attacker payload.

    Combining rule:
      * Judge=CONFIRMED → keep CONFIRMED (both agree)
      * Judge=REFUTED → FLIP TO REFUTED (judge override — the FP defense)
      * Judge=INCONCLUSIVE → keep CONFIRMED unchanged (surface verdict
        so the operator sees the uncertainty)
      * Judge call fails → keep CONFIRMED (fail-open: interpreter wins)

    Only invoked when ``outcome.verdict == VERDICT_CONFIRMED``. REFUTED
    outcomes are already negative; spending API on them is waste.

    Mutates and returns ``outcome``. Always sets ``judge_verdict`` and
    ``judge_reasoning`` (empty strings if call errored).
    """
    if outcome.verdict != VERDICT_CONFIRMED:
        return outcome

    hyp = outcome.hypothesis
    hyp_dict = {
        "function_name": hyp.function_name,
        "args_json": hyp.args_json,
        "kwargs_json": hyp.kwargs_json,
        "attack_class": hyp.attack_class,
        "rationale": hyp.rationale,
        "expected_observable": hyp.expected_observable,
        "rejection_signature": getattr(hyp, "rejection_signature", "") or "",
        "exploit_proof_if_observed": hyp.exploit_proof_if_observed,
    }
    trace_dict = {
        "exit_code": getattr(trace, "exit_code", None),
        "elapsed_ms": getattr(trace, "elapsed_ms", 0),
        "stdout_excerpt": getattr(trace, "stdout_excerpt", ""),
        "stderr_excerpt": getattr(trace, "stderr_excerpt", ""),
        "parsed_result": getattr(trace, "parsed_result", None)
        or getattr(trace, "side_effects", {})
        or {},
        "side_effects": getattr(trace, "side_effects", None) or {},
    }
    prompt = build_post_trace_judge_prompt(
        hypothesis=hyp_dict,
        trace=trace_dict,
        interpreter_oracle_type=outcome.oracle_type,
        interpreter_runtime_evidence=outcome.runtime_evidence,
    )
    schema = post_trace_judge_schema()
    try:
        response = await inference(
            prompt,
            {"temperature": 0.0, "max_tokens": 800, "seed": 0},
            schema,
        )
        decoded = json.loads(response.get("text") or "{}")
        judge_verdict = decoded.get("judge_verdict", "")
        judge_reasoning = (decoded.get("judge_reasoning") or "")[:600]
        outcome.judge_verdict = judge_verdict
        outcome.judge_reasoning = judge_reasoning
        if judge_verdict == "REFUTED":
            # The FP defense: flip CONFIRMED -> REFUTED. Surface the
            # judge's reasoning in runtime_evidence so the operator
            # sees WHY this got refuted vs the interpreter's claim.
            outcome.verdict = VERDICT_REFUTED
            outcome.confidence = 0.0
            outcome.runtime_evidence = (
                f"STRATEGY_C_REFUTED: judge overruled interpreter's "
                f"CONFIRMED. Judge: {judge_reasoning} "
                f"| Interpreter's claim was: {outcome.runtime_evidence}"
            )
        # CONFIRMED + INCONCLUSIVE both keep the interpreter's verdict;
        # surfacing judge_verdict in the output lets the operator see
        # the judge's stance without us silently down-weighting.
    except (json.JSONDecodeError, ValueError, KeyError):
        # Fail-open: keep interpreter's verdict + log the miss.
        outcome.judge_verdict = ""
        outcome.judge_reasoning = "(judge call failed; interpreter verdict kept)"
    except Exception as exc:  # noqa: BLE001
        # Sandbox / network / API errors. Fail-open per contract.
        outcome.judge_verdict = ""
        outcome.judge_reasoning = (
            f"(judge call errored: {type(exc).__name__}; interpreter verdict kept)"
        )
    return outcome


# ── Hypothesis JSON <-> dataclass conversion ──────────────────────────────


_VALID_LANGUAGES = {
    LANGUAGE_PYTHON,
    LANGUAGE_JAVASCRIPT,
    LANGUAGE_TYPESCRIPT,  # v9 — reuses JS harness via ts-node loader
    LANGUAGE_SHELL,
}
_VALID_KINDS = {
    HYPOTHESIS_KIND_PROBE,
    HYPOTHESIS_KIND_SINGLE_FUNCTION,
    HYPOTHESIS_KIND_STATEFUL_SEQUENCE,
}


def hypothesis_from_dict(d: dict[str, Any]) -> AdversarialHypothesis | None:
    """Decode one model-emitted hypothesis JSON object into the dataclass.

    Returns ``None`` for malformed inputs (defense-in-depth after the
    schema): unknown language, unknown kind, non-dict input. Field
    normalization (args_json / kwargs_json) follows the Phase B+
    pattern of repairing Python-syntax single-quoted args via
    :func:`normalize_args_json` so the model can be slightly sloppy
    without burning a hypothesis slot.
    """
    if not isinstance(d, dict):
        return None
    language = str(d.get("language") or "")
    kind = str(d.get("kind") or "")
    if language not in _VALID_LANGUAGES:
        return None
    if kind not in _VALID_KINDS:
        return None

    raw_sequence = d.get("sequence") or []
    sequence = [op for op in raw_sequence if isinstance(op, dict)]

    return AdversarialHypothesis(
        language=language,
        kind=kind,
        rationale=str(d.get("rationale") or ""),
        attack_class=str(d.get("attack_class") or ""),
        expected_observable=str(d.get("expected_observable") or ""),
        rejection_signature=str(d.get("rejection_signature") or ""),
        exploit_proof_if_observed=str(d.get("exploit_proof_if_observed") or ""),
        confidence_prior=str(d.get("confidence_prior") or "MEDIUM"),
        function_name=str(d.get("function_name") or ""),
        args_json=normalize_args_json(str(d.get("args_json") or "[]")),
        kwargs_json=normalize_kwargs_json(str(d.get("kwargs_json") or "{}")),
        sequence=sequence,
    )


def _hypothesis_to_dict(h: AdversarialHypothesis) -> dict[str, Any]:
    """Render a hypothesis as a dict for the next-turn prompt's
    ``prior_turns``. Omits the full args/kwargs/sequence payload to
    keep the prior-turn context-budget bounded — the model already saw
    its own emission and can refer to it by rationale + function name.
    """
    return {
        "kind": h.kind,
        "language": h.language,
        "function_name": h.function_name,
        "rationale": h.rationale,
        "attack_class": h.attack_class,
    }


def _outcome_to_dict(outcome: AdversarialHypothesisOutcome) -> dict[str, Any]:
    """Render an outcome as a dict for the next-turn prompt's ``prior_turns``."""
    return {
        "verdict": outcome.verdict,
        "confidence": outcome.confidence,
        "oracle_type": outcome.oracle_type,
        "runtime_evidence": outcome.runtime_evidence,
    }


# ── Per-hypothesis sandbox dispatcher ──────────────────────────────────────


def _plan_id(turn_idx: int, hyp_idx: int) -> str:
    """Adversarial-loop hypothesis ID convention: ``HRP_AL_T<turn>_H<hyp>``.

    Distinct from Phase B+ single-function (``HRP_<c>_<i>``) and Phase 2
    chain (``HRP_C<n>``) IDs so journal grep + downstream analysis can
    isolate adversarial-loop findings.
    """
    return f"HRP_AL_T{turn_idx}_H{hyp_idx}"


async def _run_probe(
    hypothesis: AdversarialHypothesis,
    *,
    file_name: str,
    file_bytes: bytes,
    file_id: str,
    sandbox: SandboxClient,
    turn_idx: int,
    hyp_idx: int,
    entry_rel_path: str = "",
) -> AdversarialHypothesisOutcome:
    """Execute a ``probe``-kind hypothesis: invoke a function for
    exploration, interpret the trace as an OBSERVATION (no attack
    confirmation), emit ``VERDICT_PROBE_OBSERVED``."""
    candidate = RuntimeProbeCandidate(
        function_name=hypothesis.function_name,
        attack_class="exploratory",
        rationale=hypothesis.rationale,
        test_inputs=[],
    )
    test_input = RuntimeProbeInput(
        args_json=hypothesis.args_json,
        kwargs_json=hypothesis.kwargs_json,
        expected_observable=hypothesis.expected_observable,
        rejection_signature=hypothesis.rejection_signature,
        exploit_proof_if_observed="",
        # Phase 1 (SCAN-016) — plumb the structured assertion from the
        # hypothesis into the probe input so the sandbox harness can
        # evaluate it. Empty string for probe-kind hypotheses (no
        # exploit shape expected); the harness handles that case.
        assertion_expr=getattr(hypothesis, "assertion_expr", "") or "",
    )
    plan_dict = build_runtime_probe_plan(
        file_name=file_name,
        file_bytes=file_bytes,
        candidate=candidate,
        test_input=test_input,
        candidate_idx=turn_idx,
        input_idx=hyp_idx,
        entry_rel_path=entry_rel_path,
    )
    if plan_dict is None:
        return AdversarialHypothesisOutcome(
            hypothesis=hypothesis,
            verdict=VERDICT_BLOCKED,
            runtime_evidence=(
                f"probe plan_build returned None (unsupported language "
                f"or extension for {file_name})"
            ),
        )

    t0 = time.monotonic()
    plan = SandboxPlan(
        plan_id=f"phase3-{_plan_id(turn_idx, hyp_idx)}",
        file_id=file_id,
        hypothesis_id=_plan_id(turn_idx, hyp_idx),
        commands=plan_dict["commands"],
        expected_oracle=plan_dict["oracle"],
        payload=plan_dict["payload"],
        timeout_sec=plan_dict["timeout_sec"],
        image_hint=plan_dict.get("image_hint", "lean"),
        file_name=file_name,
        synthesis_context={"phase_3_loop": True, "kind": HYPOTHESIS_KIND_PROBE},
    )
    try:
        trace = await sandbox.submit(plan)
    except Exception as exc:  # noqa: BLE001
        return AdversarialHypothesisOutcome(
            hypothesis=hypothesis,
            verdict=VERDICT_BLOCKED,
            runtime_evidence=(f"sandbox submit failed: {type(exc).__name__}: {str(exc)[:200]}"),
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    probe_trace = parse_probe_trace(
        candidate_function=hypothesis.function_name,
        input_args_json=hypothesis.args_json,
        exit_code=trace.exit_code,
        stdout=trace.stdout_excerpt,
        stderr=trace.stderr_excerpt,
        elapsed_ms=trace.elapsed_ms,
    )
    observation = interpret_probe_observation(
        probe_trace,
        function_name=hypothesis.function_name,
        kwargs_json=hypothesis.kwargs_json,
    )
    trace_ref = trace.events[0].event_id if trace.events else ""
    return AdversarialHypothesisOutcome(
        hypothesis=hypothesis,
        verdict=VERDICT_PROBE_OBSERVED,
        confidence=0.0,
        runtime_evidence=observation.summary,
        trace_ref=trace_ref,
        elapsed_ms=elapsed_ms,
    )


async def _run_single_function(
    hypothesis: AdversarialHypothesis,
    *,
    file_name: str,
    file_bytes: bytes,
    file_id: str,
    sandbox: SandboxClient,
    turn_idx: int,
    hyp_idx: int,
    judge_inference: InferenceFn | None = None,
    entry_rel_path: str = "",
) -> AdversarialHypothesisOutcome:
    """Execute a ``single_function``-kind hypothesis: build a Phase B+
    plan, submit, interpret via :func:`interpret_probe_trace`.

    When ``judge_inference`` is provided (Strategy C v1.8), any CONFIRMED
    outcome is sent to the post-trace LLM judge for an independent
    second opinion. Judge=REFUTED flips the outcome to VERDICT_REFUTED.
    Judge=INCONCLUSIVE keeps CONFIRMED but surfaces in output."""
    candidate = RuntimeProbeCandidate(
        function_name=hypothesis.function_name,
        attack_class=hypothesis.attack_class or "code_injection",
        rationale=hypothesis.rationale,
        test_inputs=[],
    )
    test_input = RuntimeProbeInput(
        args_json=hypothesis.args_json,
        kwargs_json=hypothesis.kwargs_json,
        expected_observable=hypothesis.expected_observable,
        rejection_signature=hypothesis.rejection_signature,
        exploit_proof_if_observed=hypothesis.exploit_proof_if_observed,
        # Phase 1 (SCAN-016) — plumb structured assertion. This is the
        # hot path for single_function attack hypotheses; the assertion
        # oracle's verdict (when emitted) overrides string-based oracles
        # — that's where FP reduction lands.
        assertion_expr=getattr(hypothesis, "assertion_expr", "") or "",
    )
    plan_dict = build_runtime_probe_plan(
        file_name=file_name,
        file_bytes=file_bytes,
        candidate=candidate,
        test_input=test_input,
        candidate_idx=turn_idx,
        input_idx=hyp_idx,
        entry_rel_path=entry_rel_path,
    )
    if plan_dict is None:
        return AdversarialHypothesisOutcome(
            hypothesis=hypothesis,
            verdict=VERDICT_BLOCKED,
            runtime_evidence=(f"single_function plan_build returned None for {file_name}"),
        )

    t0 = time.monotonic()
    plan = SandboxPlan(
        plan_id=f"phase3-{_plan_id(turn_idx, hyp_idx)}",
        file_id=file_id,
        hypothesis_id=_plan_id(turn_idx, hyp_idx),
        commands=plan_dict["commands"],
        expected_oracle=plan_dict["oracle"],
        payload=plan_dict["payload"],
        timeout_sec=plan_dict["timeout_sec"],
        image_hint=plan_dict.get("image_hint", "lean"),
        file_name=file_name,
        synthesis_context={
            "phase_3_loop": True,
            "kind": HYPOTHESIS_KIND_SINGLE_FUNCTION,
        },
    )
    try:
        trace = await sandbox.submit(plan)
    except Exception as exc:  # noqa: BLE001
        # v1.6 Fix #10: log infra gaps so operator can review patterns
        # and decide which sandbox images to extend. Fire-and-forget.
        from dast.infra_telemetry import log_infra_gap  # noqa: PLC0415

        log_infra_gap(
            file_name=file_name,
            phase="phase_3_loop_single_function",
            error_message=f"{type(exc).__name__}: {exc}",
            finding_cwe=None,
            image_hint=plan_dict.get("image_hint", "lean"),
        )
        return AdversarialHypothesisOutcome(
            hypothesis=hypothesis,
            verdict=VERDICT_BLOCKED,
            runtime_evidence=(f"sandbox submit failed: {type(exc).__name__}: {str(exc)[:200]}"),
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    trace_ref = trace.events[0].event_id if trace.events else ""

    probe_trace = parse_probe_trace(
        candidate_function=hypothesis.function_name,
        input_args_json=hypothesis.args_json,
        exit_code=trace.exit_code,
        stdout=trace.stdout_excerpt,
        stderr=trace.stderr_excerpt,
        elapsed_ms=trace.elapsed_ms,
    )
    finding = interpret_probe_trace(
        probe_trace,
        candidate,
        test_input,
        candidate_idx=turn_idx,
        input_idx=hyp_idx,
    )
    if finding is None:
        # Preserve a tail of the actual value_preview + exception fields
        # on refuted outcomes so FN debugging is self-serve from the JSON
        # report. Without this the runtime_evidence is uselessly generic.
        preview_tail = ""
        if probe_trace.parsed_result:
            pr = probe_trace.parsed_result
            if pr.get("ok"):
                preview = str(pr.get("value_preview", ""))[:400]
                preview_tail = f" preview={preview!r}"
            else:
                exc = pr.get("exception_type", "")
                msg = str(pr.get("exception_msg", ""))[:200]
                preview_tail = f" raised={exc}: {msg!r}"
        return AdversarialHypothesisOutcome(
            hypothesis=hypothesis,
            verdict=VERDICT_REFUTED,
            runtime_evidence=(
                f"single_function probe ran but no exploit signal "
                f"(exit_code={trace.exit_code}, elapsed={elapsed_ms}ms)"
                f"{preview_tail}"
            ),
            trace_ref=trace_ref,
            elapsed_ms=elapsed_ms,
        )

    # Phase B+ single-function findings default to 1.0 (the signature-
    # match rule is FP-defended). v1.6 Fix #4b: downgrade confidence
    # when the canary fired alone (no class-signature backup), since
    # canary creation proves "exploit fired" but not "exploit
    # demonstrated the L1-claimed CWE class."
    #
    # Oracle-type → confidence mapping:
    #   canary+class_signature → 1.0  (both fired — strongest)
    #   class_signature        → 1.0  (CWE-class demonstrated)
    #   canary                 → 0.8  (CWE class unverified)
    #   observable_keyword     → 0.6  (weakest oracle, kept for parity
    #                                  with chain confidence calibration)
    #   ""                     → 1.0  (backward-compat: pre-Fix-4b)
    finding_oracle = getattr(finding, "oracle_type", "") or ""
    if finding_oracle == "assertion":
        # Phase 1 (SCAN-016): structured-assertion oracle. The harness
        # evaluated a model-supplied Python predicate against the live
        # return value and it held — strongest non-canary signal.
        # Treat at parity with class_signature (1.0) — same precision
        # class, but verified via structural invariant on the actual
        # object instead of substring match on its repr.
        confidence = 1.0
        outcome_oracle = "single_function_assertion"
    elif finding_oracle == "canary":
        confidence = 0.8
        outcome_oracle = "single_function_canary_only"
    elif finding_oracle == "observable_keyword":
        # Phase 1 (SCAN-016): the keyword oracle is the v15.27 FP source
        # (URL.repr containing "scheme" matched the keyword "scheme"
        # from expected_observable). Drop confidence from 0.6 → 0.3 so
        # the engine's undercall_backstop / DAST-trigger gates filter
        # these out of the headline verdict by default. Still surfaced
        # in per_finding_validation for audit.
        confidence = 0.3
        outcome_oracle = "single_function_observable_keyword"
    else:
        # class_signature, class_signature_causal, canary+class_signature,
        # or "" → keep 1.0.
        confidence = 1.0
        outcome_oracle = "single_function_rule_fired"

    outcome = AdversarialHypothesisOutcome(
        hypothesis=hypothesis,
        verdict=VERDICT_CONFIRMED,
        confidence=confidence,
        oracle_type=outcome_oracle,
        runtime_evidence=finding.runtime_evidence,
        trace_ref=trace_ref,
        elapsed_ms=elapsed_ms,
    )
    # v1.8 Strategy C: post-trace LLM judge before fixture downgrade so
    # judge=REFUTED skips the cap math (which only applies to CONFIRMED).
    if judge_inference is not None:
        outcome = await _invoke_judge(outcome, trace=trace, inference=judge_inference)
    # v1.6 Fix #4a: cap confidence + flag context on fixture files.
    return _apply_fixture_downgrade(outcome, file_bytes)


async def _run_stateful_sequence(
    hypothesis: AdversarialHypothesis,
    *,
    file_name: str,
    file_bytes: bytes,
    file_id: str,
    sandbox: SandboxClient,
    turn_idx: int,
    hyp_idx: int,
    judge_inference: InferenceFn | None = None,
    entry_rel_path: str = "",
) -> AdversarialHypothesisOutcome:
    """Execute a ``stateful_sequence``-kind hypothesis: build the
    sequence plan, submit, interpret via
    :func:`interpret_stateful_sequence_trace`.

    When ``judge_inference`` is provided (Strategy C v1.8), any CONFIRMED
    outcome is sent to the post-trace LLM judge for an independent
    second opinion."""
    hypothesis_id = _plan_id(turn_idx, hyp_idx)
    plan_dict = build_runtime_stateful_sequence_plan(
        file_name=file_name,
        file_bytes=file_bytes,
        ops=hypothesis.sequence,
        hypothesis_id=hypothesis_id,
        entry_rel_path=entry_rel_path,
    )
    if plan_dict is None:
        return AdversarialHypothesisOutcome(
            hypothesis=hypothesis,
            verdict=VERDICT_BLOCKED,
            runtime_evidence=(
                "stateful_sequence plan_build returned None — empty ops or unsupported language"
            ),
        )

    t0 = time.monotonic()
    plan = SandboxPlan(
        plan_id=f"phase3-{hypothesis_id}",
        file_id=file_id,
        hypothesis_id=hypothesis_id,
        commands=plan_dict["commands"],
        expected_oracle=plan_dict["oracle"],
        payload=plan_dict["payload"],
        timeout_sec=plan_dict["timeout_sec"],
        image_hint=plan_dict.get("image_hint", "lean"),
        file_name=file_name,
        synthesis_context={
            "phase_3_loop": True,
            "kind": HYPOTHESIS_KIND_STATEFUL_SEQUENCE,
        },
    )
    try:
        trace = await sandbox.submit(plan)
    except Exception as exc:  # noqa: BLE001
        # v1.6 Fix #10: log infra gaps. Fire-and-forget.
        from dast.infra_telemetry import log_infra_gap  # noqa: PLC0415

        log_infra_gap(
            file_name=file_name,
            phase="phase_3_loop_stateful_sequence",
            error_message=f"{type(exc).__name__}: {exc}",
            finding_cwe=None,
            image_hint=plan_dict.get("image_hint", "lean"),
        )
        return AdversarialHypothesisOutcome(
            hypothesis=hypothesis,
            verdict=VERDICT_BLOCKED,
            runtime_evidence=(f"sandbox submit failed: {type(exc).__name__}: {str(exc)[:200]}"),
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    trace_ref = trace.events[0].event_id if trace.events else ""

    seq_trace = parse_stateful_sequence_trace(
        hypothesis_id=hypothesis_id,
        exit_code=trace.exit_code,
        stdout=trace.stdout_excerpt,
        stderr=trace.stderr_excerpt,
        elapsed_ms=trace.elapsed_ms,
        probe_result_json=getattr(trace, "probe_result_json", "") or "",
    )
    finding = interpret_stateful_sequence_trace(
        seq_trace,
        attack_class=hypothesis.attack_class or "code_injection",
        expected_observable=hypothesis.expected_observable,
        exploit_proof_if_observed=hypothesis.exploit_proof_if_observed,
        hypothesis_id=hypothesis_id,
    )
    if finding is None:
        return AdversarialHypothesisOutcome(
            hypothesis=hypothesis,
            verdict=VERDICT_REFUTED,
            runtime_evidence=(
                f"stateful_sequence ran but no exploit signal "
                f"(ops={len(hypothesis.sequence)}, "
                f"exit_code={trace.exit_code}, elapsed={elapsed_ms}ms)"
            ),
            trace_ref=trace_ref,
            elapsed_ms=elapsed_ms,
        )

    outcome = AdversarialHypothesisOutcome(
        hypothesis=hypothesis,
        verdict=VERDICT_CONFIRMED,
        confidence=finding.confidence,
        oracle_type=finding.oracle_type,
        runtime_evidence=finding.runtime_evidence,
        trace_ref=trace_ref,
        elapsed_ms=elapsed_ms,
    )
    # v1.8 Strategy C: post-trace LLM judge before fixture downgrade.
    if judge_inference is not None:
        outcome = await _invoke_judge(outcome, trace=trace, inference=judge_inference)
    # v1.6 Fix #4: cap confidence + flag context on fixture files.
    return _apply_fixture_downgrade(outcome, file_bytes)


async def _dispatch(
    hypothesis: AdversarialHypothesis,
    *,
    file_name: str,
    file_bytes: bytes,
    file_id: str,
    sandbox: SandboxClient,
    turn_idx: int,
    hyp_idx: int,
    judge_inference: InferenceFn | None = None,
    entry_rel_path: str = "",
) -> AdversarialHypothesisOutcome:
    """Route one hypothesis to the right kind-specific executor.

    ``judge_inference`` (Strategy C v1.8) is forwarded to the
    single_function / stateful_sequence executors. probe-kind outcomes
    don't get judged — they're descriptive (VERDICT_PROBE_OBSERVED),
    not exploit claims.

    ``entry_rel_path`` (v12, 2026-05-17) is forwarded to plan builders
    so multi-file project staging works for adversarial-loop
    hypotheses. Empty for single-file scans (default).
    """
    kwargs = {
        "file_name": file_name,
        "file_bytes": file_bytes,
        "file_id": file_id,
        "sandbox": sandbox,
        "turn_idx": turn_idx,
        "hyp_idx": hyp_idx,
        "entry_rel_path": entry_rel_path,
    }
    if hypothesis.kind == HYPOTHESIS_KIND_PROBE:
        return await _run_probe(hypothesis, **kwargs)
    if hypothesis.kind == HYPOTHESIS_KIND_SINGLE_FUNCTION:
        return await _run_single_function(hypothesis, judge_inference=judge_inference, **kwargs)
    if hypothesis.kind == HYPOTHESIS_KIND_STATEFUL_SEQUENCE:
        return await _run_stateful_sequence(hypothesis, judge_inference=judge_inference, **kwargs)
    # Defensive — _hypothesis_from_dict gates this, but guard the dispatch
    # too in case future kinds get added without a handler.
    return AdversarialHypothesisOutcome(
        hypothesis=hypothesis,
        verdict=VERDICT_BLOCKED,
        runtime_evidence=f"unknown hypothesis kind: {hypothesis.kind!r}",
    )


# ── Single-turn primitive ──────────────────────────────────────────────────


async def run_one_turn(
    *,
    turn_idx: int,
    file_text: str,
    file_name: str,
    file_bytes: bytes,
    file_id: str,
    behavioral_profile: dict[str, Any],
    prior_turns_dict: list[dict[str, Any]] | None,
    inference: InferenceFn,
    sandbox: SandboxClient,
    enable_strategy_c_judge: bool = True,
    entry_rel_path: str = "",
    coverage_tracker: Any | None = None,
    adversarial_addendum: str = "",
) -> AdversarialTurn:
    """Run one turn: model proposes hypotheses, sandbox tests them in
    parallel, outcomes are interpreted per kind.

    This is the production-ready primitive. The outer
    :func:`run_adversarial_loop` invokes it 1+ times.

    ``enable_strategy_c_judge`` (v1.8, default True): when True, every
    CONFIRMED outcome from single_function / stateful_sequence kinds
    is sent to the post-trace LLM judge for an independent second
    opinion. Catches the FP class where the application correctly
    rejects the attack with an error message echoing the attacker
    payload (substring oracle false-positive). Adds ~$0.01 per
    CONFIRMED outcome. Set False to opt out (operator's call).
    """
    turn = AdversarialTurn(turn_idx=turn_idx)
    t0 = time.monotonic()

    # 1. Call the model for a hypothesis batch.
    prompt = build_phase_3_loop_hypothesis_batch_prompt(
        file_text=file_text,
        behavioral_profile=behavioral_profile,
        prior_turns=prior_turns_dict,
        adversarial_addendum=adversarial_addendum,
    )
    schema = phase_3_loop_hypothesis_batch_schema()
    response = await inference(
        prompt,
        {"temperature": 0.0, "max_tokens": 4096, "seed": 0},
        schema,
    )
    usage = response.get("usage") or {}
    turn.inference_tokens_in = int(usage.get("prompt_tokens", 0) or 0)
    turn.inference_tokens_out = int(usage.get("completion_tokens", 0) or 0)
    turn.inference_cost_usd = _inference_cost_usd(usage)

    try:
        decoded = json.loads(response.get("text") or "{}")
    except (json.JSONDecodeError, ValueError):
        decoded = {}
    if not isinstance(decoded, dict):
        decoded = {}

    turn.no_new_hypotheses_flag = bool(decoded.get("no_new_hypotheses"))
    # v15.8 (2026-05-20): capture the model's intent analysis so the
    # scan JSON carries it when hypotheses_total=0 — turns silent
    # "Stage 2 declined" outcomes into diagnosable ones for operators.
    cia_raw = decoded.get("code_intent_analysis")
    if isinstance(cia_raw, dict):
        turn.code_intent_analysis = cia_raw
    raw_hypotheses = decoded.get("hypotheses") or []
    if not isinstance(raw_hypotheses, list):
        raw_hypotheses = []

    # 2. Decode + cap (schema enforces; defense-in-depth here).
    for raw in raw_hypotheses[:MAX_HYPOTHESES_PER_TURN]:
        decoded_h = hypothesis_from_dict(raw)
        if decoded_h is not None:
            turn.hypotheses.append(decoded_h)

    # v1.9.1 — coverage dedupe. Drop hypotheses whose (function,
    # attack_class) is already covered by L1 / Phase B+ confirmations
    # in the tracker. Each suppression is recorded in tracker telemetry.
    # The adversarial loop's fixed budget then redirects to NEW
    # callables / NEW attack classes, matching the user-stated goal:
    # "Phase B+ and Phase 3 focus on new findings rather than find
    # existing ones."
    if coverage_tracker is not None and getattr(
        coverage_tracker, "enabled", False
    ):
        kept_after_dedupe: list[Any] = []
        for hyp in turn.hypotheses:
            covered = coverage_tracker.is_covered(
                function=hyp.function_name,
                attack_class=hyp.attack_class,
            )
            if covered is None:
                kept_after_dedupe.append(hyp)
            else:
                coverage_tracker.record_suppression("phase_3")
                # No journal record here — the adversarial loop has
                # its own outcome/telemetry stream. The
                # diagnostics["coverage_tracker"]["suppressions_by_stage"]
                # surface tracks the savings.
        turn.hypotheses = kept_after_dedupe

    if not turn.hypotheses:
        turn.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return turn

    # 3. Parallel dispatch. No semaphore at minimum scope — typical
    # turn ships <= 3 hypotheses, well below Fly rate limits. Step 6
    # adds bounded concurrency if measurement surfaces the need.
    # v1.8 Strategy C: pass inference as judge_inference when enabled,
    # so single_function / stateful_sequence outcomes get judged.
    judge_fn: InferenceFn | None = inference if enable_strategy_c_judge else None
    tasks = [
        _dispatch(
            hyp,
            file_name=file_name,
            file_bytes=file_bytes,
            file_id=file_id,
            sandbox=sandbox,
            turn_idx=turn_idx,
            hyp_idx=i,
            judge_inference=judge_fn,
            entry_rel_path=entry_rel_path,
        )
        for i, hyp in enumerate(turn.hypotheses)
    ]
    turn.outcomes = list(await asyncio.gather(*tasks))
    turn.elapsed_ms = int((time.monotonic() - t0) * 1000)
    return turn


# ── Outer loop (minimal — default max_turns=1) ────────────────────────────


async def run_adversarial_loop(
    *,
    file_name: str,
    file_bytes: bytes,
    file_id: str,
    behavioral_profile: dict[str, Any],
    inference: InferenceFn,
    sandbox: SandboxClient,
    max_turns: int = 1,
    enable_strategy_c_judge: bool = True,
    entry_rel_path: str = "",
    coverage_tracker: Any | None = None,
    adversarial_addendum: str = "",
) -> AdversarialLoopResult:
    """Run Phase 3 Stage 2 adversarial loop on one file.

    v1.6 minimal default: ``max_turns=1`` (single-turn execution). The
    multi-turn outer is fully functional — passing ``max_turns=N``
    drives N turns with prior-turn context plumbed through. We default
    to 1 so the thin-slice measurement can decide whether multi-turn
    refinement is worth turning on as the production default.

    The cost / wall-clock / no_new_hypotheses termination signals are
    wired and respected. Dedup + L1 short-circuit + caching are NOT
    in minimum scope — those land in Step 6 if the measurement says
    they're worth it.
    """
    file_text = file_bytes.decode("utf-8", errors="replace")
    # Derive language from the file extension via the canonical
    # detector instead of hardcoding Python. Plan builders downstream
    # already dispatch on ``language`` (see ``_VALID_LANGUAGES`` —
    # Python / JS / TS / Shell admitted as of v9).
    # ``detect_probe_language`` returns None for unsupported
    # extensions; we fall back to Python so the loop still has a
    # language to record on the result (orchestrator gates Stage 2
    # on language up the call stack — a non-py/js/ts file wouldn't
    # reach us via the production path).
    from dast.runtime_probe import detect_probe_language  # noqa: PLC0415

    detected = detect_probe_language(file_name)
    if detected == "javascript":
        runner_language = LANGUAGE_JAVASCRIPT
    elif detected == "typescript":
        runner_language = LANGUAGE_TYPESCRIPT
    else:
        runner_language = LANGUAGE_PYTHON  # default / shell rare-path
    result = AdversarialLoopResult(
        file_id=file_id,
        file_name=file_name,
        language=runner_language,
    )
    t0 = time.monotonic()
    prior_turns_dict: list[dict[str, Any]] = []

    turns_to_run = max(1, max_turns)
    early_exit = False
    for turn_idx in range(turns_to_run):
        turn = await run_one_turn(
            turn_idx=turn_idx,
            file_text=file_text,
            file_name=file_name,
            file_bytes=file_bytes,
            file_id=file_id,
            behavioral_profile=behavioral_profile,
            prior_turns_dict=prior_turns_dict or None,
            inference=inference,
            sandbox=sandbox,
            enable_strategy_c_judge=enable_strategy_c_judge,
            entry_rel_path=entry_rel_path,
            coverage_tracker=coverage_tracker,
            adversarial_addendum=adversarial_addendum,
        )
        result.turns.append(turn)
        prior_turns_dict.append(
            {
                "turn_idx": turn_idx,
                "hypotheses": [_hypothesis_to_dict(h) for h in turn.hypotheses],
                "outcomes": [_outcome_to_dict(o) for o in turn.outcomes],
            }
        )

        if turn.no_new_hypotheses_flag and turn_idx >= MIN_TURNS_BEFORE_EARLY_EXIT:
            result.terminated_by = TERMINATED_BY_NO_NEW
            early_exit = True
            break

    if not early_exit:
        result.terminated_by = TERMINATED_BY_MAX_TURNS

    # ── Aggregate counts + costs ──────────────────────────────────────────
    for turn in result.turns:
        result.inference_tokens_in += turn.inference_tokens_in
        result.inference_tokens_out += turn.inference_tokens_out
        result.total_cost_usd += turn.inference_cost_usd
        for outcome in turn.outcomes:
            result.hypotheses_total += 1
            if outcome.verdict == VERDICT_CONFIRMED:
                result.hypotheses_confirmed += 1
                result.hypotheses_tested += 1
            elif outcome.verdict == VERDICT_REFUTED:
                result.hypotheses_refuted += 1
                result.hypotheses_tested += 1
            elif outcome.verdict == VERDICT_PROBE_OBSERVED:
                result.explore_calls_used += 1
                result.hypotheses_tested += 1
            else:  # VERDICT_BLOCKED
                result.hypotheses_blocked += 1
    result.total_elapsed_ms = int((time.monotonic() - t0) * 1000)

    # ── Findings: confirmed outcomes from attack-kind hypotheses ──────────
    # Probe-kind outcomes never produce findings (they're observations).
    for turn in result.turns:
        for outcome in turn.outcomes:
            if outcome.verdict != VERDICT_CONFIRMED:
                continue
            hyp = outcome.hypothesis
            result.findings.append(
                {
                    "finding_ref": _plan_id(turn.turn_idx, _outcome_position(turn, outcome)),
                    "kind": hyp.kind,
                    "attack_class": hyp.attack_class,
                    "function_name": hyp.function_name,
                    "severity": severity_for_attack_class(hyp.attack_class),
                    "cwe": cwe_for_attack_class(hyp.attack_class),
                    "confidence": outcome.confidence,
                    "oracle_type": outcome.oracle_type,
                    "runtime_evidence": outcome.runtime_evidence,
                    "exploit_proof": hyp.exploit_proof_if_observed,
                    "trace_ref": outcome.trace_ref,
                }
            )

    return result


def _outcome_position(turn: AdversarialTurn, outcome: AdversarialHypothesisOutcome) -> int:
    """Find the outcome's index within its turn for finding_ref ID."""
    for i, o in enumerate(turn.outcomes):
        if o is outcome:
            return i
    return 0


__all__ = [
    "INFERENCE_INPUT_USD_PER_M",
    "INFERENCE_OUTPUT_USD_PER_M",
    "InferenceFn",
    "hypothesis_from_dict",
    "run_adversarial_loop",
    "run_one_turn",
]
