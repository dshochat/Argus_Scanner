"""Unit tests for Phase 3 Stage 2 orchestrator gate (Step 7 wiring).

Covers the gate logic in :func:`dast.orchestrator.run_dast` that decides
whether to invoke :func:`run_adversarial_loop`:

* Flag off (default) -> no loop, ``DastResult.phase_3_loop`` is None.
* Flag on but Stage 1 produced no profile -> no loop. Prevents the loop
  from designing attacks with no runtime evidence to anchor on.
* Flag on + profile present -> loop runs, summary populated on
  DastResult including the FULL outcomes list (not just findings) so
  FN debugging via raw hypothesis inspection works.

No live API; no real sandbox. The orchestrator's Stage 1 helper
``_run_phase_3_behavioral_probe`` is monkeypatched to return a canned
profile dict, and ``run_adversarial_loop`` is monkeypatched to return a
deterministic :class:`AdversarialLoopResult`. This isolates the gate
logic under test.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from dast.adversarial_loop import (
    HYPOTHESIS_KIND_SINGLE_FUNCTION,
    LANGUAGE_PYTHON,
    TERMINATED_BY_MAX_TURNS,
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    AdversarialHypothesis,
    AdversarialHypothesisOutcome,
    AdversarialLoopResult,
    AdversarialTurn,
)
from dast.orchestrator import run_dast
from dast.validator import HypothesisValidator
from tests.unit.test_behavioral_probe import (
    _CapturingBehavioralSandbox,
    _minimal_phase_a_response,
)

# ── Shared helpers ────────────────────────────────────────────────────────


def _fake_inference():
    async def fake(prompt, options, schema):
        return {
            "text": _minimal_phase_a_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    return fake


def _file_record():
    return {
        "file_id": "fid",
        "source_text": "def f(p): return p\n",
        "file_name": "v.py",
        "original_bytes": b"def f(p): return p\n",
        "ml_format": None,
    }


def _stub_loop_result_with_one_confirmed() -> AdversarialLoopResult:
    """Build a deterministic AdversarialLoopResult: 1 turn with 2
    hypotheses, 1 CONFIRMED + 1 REFUTED. The refuted hypothesis carries
    distinguishable fields so the test can assert it's visible in the
    serialized outcomes (FN-debugging guarantee)."""
    h_attack = AdversarialHypothesis(
        language=LANGUAGE_PYTHON,
        kind=HYPOTHESIS_KIND_SINGLE_FUNCTION,
        attack_class="command_injection",
        function_name="run_cmd",
        args_json='["test"]',
        rationale="audit_hook caught subprocess",
    )
    h_refuted = AdversarialHypothesis(
        language=LANGUAGE_PYTHON,
        kind=HYPOTHESIS_KIND_SINGLE_FUNCTION,
        attack_class="path_traversal",
        function_name="read_file",
        args_json='["../etc/passwd"]',
        rationale="guess from static",
    )
    o_confirmed = AdversarialHypothesisOutcome(
        hypothesis=h_attack,
        verdict=VERDICT_CONFIRMED,
        confidence=1.0,
        oracle_type="single_function_rule_fired",
        runtime_evidence="canary file appeared",
    )
    o_refuted = AdversarialHypothesisOutcome(
        hypothesis=h_refuted,
        verdict=VERDICT_REFUTED,
        runtime_evidence="probe ran, no exploit signal",
    )
    turn = AdversarialTurn(
        turn_idx=0,
        hypotheses=[h_attack, h_refuted],
        outcomes=[o_confirmed, o_refuted],
        inference_tokens_in=1000,
        inference_tokens_out=200,
        inference_cost_usd=0.005,
    )
    return AdversarialLoopResult(
        file_id="fid",
        file_name="v.py",
        language=LANGUAGE_PYTHON,
        turns=[turn],
        terminated_by=TERMINATED_BY_MAX_TURNS,
        hypotheses_total=2,
        hypotheses_tested=2,
        hypotheses_confirmed=1,
        hypotheses_refuted=1,
        total_cost_usd=0.005,
        total_elapsed_ms=42,
        findings=[
            {
                "finding_ref": "HRP_AL_T0_H0",
                "kind": "single_function",
                "attack_class": "command_injection",
                "function_name": "run_cmd",
                "severity": "critical",  # command_injection -> critical
                "confidence": 1.0,
            }
        ],
    )


# ── Gate logic tests ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_phase_3_loop_skipped_when_flag_disabled(tmp_path) -> None:
    """Default ``enable_phase_3_loop=False`` -> no loop runs,
    DastResult.phase_3_loop is None. Sanity guard so existing users
    don't start paying loop cost unintentionally."""
    sandbox = _CapturingBehavioralSandbox()
    result = await run_dast(
        file_record=_file_record(),
        l1_output={"verdict": {"verdict_label": "malicious"}, "hypotheses": []},
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=_fake_inference(),
        enable_runtime_probe=True,
        enable_phase_3_discovery=True,
        enable_phase_3_loop=False,  # OFF
    )
    assert result.phase_3_loop is None


@pytest.mark.asyncio
async def test_phase_3_loop_skipped_when_no_behavioral_profile(tmp_path) -> None:
    """Flag ON but Stage 1 didn't run (``enable_phase_3_discovery=False``)
    -> no profile -> loop must NOT run. Prevents designing attacks with
    no runtime evidence to anchor on (the whole point of profile-anchoring)."""
    sandbox = _CapturingBehavioralSandbox()
    result = await run_dast(
        file_record=_file_record(),
        l1_output={"verdict": {"verdict_label": "malicious"}, "hypotheses": []},
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=_fake_inference(),
        enable_runtime_probe=True,
        enable_phase_3_discovery=False,  # Stage 1 OFF -> no profile
        enable_phase_3_loop=True,
    )
    assert result.runtime_behavioral_profile is None
    assert result.phase_3_loop is None


@pytest.mark.asyncio
async def test_phase_3_loop_runs_and_serializes_full_outcomes(tmp_path, monkeypatch) -> None:
    """Happy path: flag ON + Stage 1 profile present -> run_adversarial_loop
    is called, ``DastResult.phase_3_loop`` summary is populated, and the
    FULL outcomes list (not just confirmed findings) is serialized so
    FN debugging via raw-hypothesis inspection works.

    Stubs both Stage 1 (returns a canned profile dict) and the loop
    runner (returns a deterministic AdversarialLoopResult). Verifies
    the gate dispatches AND the orchestrator's serialization path
    surfaces the raw hypothesis on each outcome.
    """
    canned_profile = {
        "file_id": "fid",
        "file_name": "v.py",
        "callables_total": 1,
        "callables_explored": 1,
        "callables": [],
        "elapsed_ms": 100,
        "dataflow_hints": [],
        "audit_hook_events": [],
        "import_error": "",
    }

    async def stub_stage_1(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return canned_profile

    stub_result = _stub_loop_result_with_one_confirmed()

    async def stub_run_loop(**kwargs: Any) -> AdversarialLoopResult:
        return stub_result

    monkeypatch.setattr(
        "dast.orchestrator._run_phase_3_behavioral_probe",
        stub_stage_1,
    )
    monkeypatch.setattr(
        "dast.adversarial_loop_runner.run_adversarial_loop",
        stub_run_loop,
    )

    sandbox = _CapturingBehavioralSandbox()
    result = await run_dast(
        file_record=_file_record(),
        l1_output={"verdict": {"verdict_label": "malicious"}, "hypotheses": []},
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=_fake_inference(),
        enable_runtime_probe=True,
        enable_phase_3_discovery=True,
        enable_phase_3_loop=True,
    )

    # Summary populated
    assert result.phase_3_loop is not None
    summary = result.phase_3_loop
    assert summary["ran"] is True
    assert summary["hypotheses_total"] == 2
    assert summary["hypotheses_confirmed"] == 1
    assert summary["hypotheses_refuted"] == 1
    assert summary["coverage_ratio"] == 1.0

    # Findings: 1 confirmed
    assert len(summary["findings"]) == 1
    assert summary["findings"][0]["attack_class"] == "command_injection"

    # Outcomes: full list including REFUTED with raw hypothesis visible.
    # This is the FN-debugging guarantee — without it, we can't tell
    # what the model proposed when a vuln file comes back clean.
    assert "outcomes" in summary
    assert len(summary["outcomes"]) == 2
    refuted = [o for o in summary["outcomes"] if o["verdict"] == VERDICT_REFUTED]
    assert len(refuted) == 1
    assert refuted[0]["hypothesis"]["function_name"] == "read_file"
    assert refuted[0]["hypothesis"]["attack_class"] == "path_traversal"
    assert refuted[0]["hypothesis"]["args_json"] == '["../etc/passwd"]'

    # Confirmed finding's finding_ref must appear in the engine-facing
    # findings_validated list (engine surfaces via dast_findings).
    # This is verified indirectly via the summary["findings"][0] presence.


# ── Verdict resolver wiring ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resolver_decision_populated_when_loop_disabled(tmp_path) -> None:
    """Even when ``enable_phase_3_loop=False``, the resolver runs and
    surfaces a decision (source=l1_no_phase_3, static_only=True). This
    guarantees downstream consumers always have a verdict_source to
    attribute, never None."""
    sandbox = _CapturingBehavioralSandbox()
    result = await run_dast(
        file_record=_file_record(),
        l1_output={
            "verdict": {"verdict_label": "malicious"},
            "hypotheses": [],
        },
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=_fake_inference(),
        enable_runtime_probe=True,
        enable_phase_3_discovery=True,
        enable_phase_3_loop=False,
    )
    assert result.phase_3_resolver_decision is not None
    decision = result.phase_3_resolver_decision
    assert decision["verdict_source"] == "l1_no_phase_3"
    assert decision["coverage_class"] == "no_run"
    assert decision["static_only"] is True
    # The L1 verdict is preserved as the final verdict when Phase 3
    # didn't run.
    assert decision["final_verdict"] == "malicious"


@pytest.mark.asyncio
async def test_resolver_decision_phase_3_confirmed_when_loop_lands_findings(
    tmp_path, monkeypatch
) -> None:
    """Happy path: full coverage + confirmed exploit ->
    verdict_source='phase_3_confirmed', final_verdict from the
    confirmed finding's severity (NOT from L1)."""
    canned_profile = {
        "file_id": "fid",
        "file_name": "v.py",
        "callables_total": 1,
        "callables_explored": 1,
        "callables": [],
        "elapsed_ms": 100,
        "dataflow_hints": [],
        "audit_hook_events": [],
        "import_error": "",
    }

    async def stub_stage_1(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return canned_profile

    async def stub_run_loop(**kwargs: Any) -> Any:
        return _stub_loop_result_with_one_confirmed()

    monkeypatch.setattr(
        "dast.orchestrator._run_phase_3_behavioral_probe",
        stub_stage_1,
    )
    monkeypatch.setattr(
        "dast.adversarial_loop_runner.run_adversarial_loop",
        stub_run_loop,
    )

    sandbox = _CapturingBehavioralSandbox()
    result = await run_dast(
        file_record=_file_record(),
        l1_output={
            "verdict": {"verdict_label": "suspicious"},  # softer than P3
            "hypotheses": [],
        },
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=_fake_inference(),
        enable_runtime_probe=True,
        enable_phase_3_discovery=True,
        enable_phase_3_loop=True,
    )

    assert result.phase_3_resolver_decision is not None
    decision = result.phase_3_resolver_decision
    assert decision["verdict_source"] == "phase_3_confirmed"
    assert decision["coverage_class"] == "high"
    assert decision["static_only"] is False
    # The confirmed finding has attack_class=command_injection ->
    # severity=critical -> verdict=critical_malicious. Phase 3
    # overrides L1's softer "suspicious".
    assert decision["final_verdict"] == "critical_malicious"
