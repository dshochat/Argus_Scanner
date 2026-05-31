"""Unit tests for Phase 3 Stage 2 adversarial-loop runner.

Covers the minimal Step 5 surface:

* ``hypothesis_from_dict`` decoding — happy paths per kind, defensive
  rejection of unknown language/kind/non-dict inputs.
* ``run_one_turn`` per-kind dispatch with stubbed inference + sandbox:
  probe → VERDICT_PROBE_OBSERVED with summary; single_function with
  canary side-effect → VERDICT_CONFIRMED; single_function with no
  exploit signal → VERDICT_REFUTED; sandbox failure → VERDICT_BLOCKED.
* ``run_adversarial_loop`` outer aggregation: max_turns=1 default,
  multi-turn with no_new_hypotheses early-exit honored,
  findings/cost/coverage roll-up.

No live API; no real sandbox. Tests use a ``StubSandbox`` and a
``stub_inference`` callable that return canned values. Step 8 will
add cross-kind dedup / language-switching tests once those features
land.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from dast import adversarial_loop as al
from dast.adversarial_loop_runner import (
    INFERENCE_INPUT_USD_PER_M,
    hypothesis_from_dict,
    run_adversarial_loop,
    run_one_turn,
)
from dast.sandbox.client import SandboxPlan, SandboxTrace

# ── Stubs ─────────────────────────────────────────────────────────────────


class StubSandbox:
    """Async sandbox stub: returns a canned trace per submitted plan.

    The ``trace_factory`` callable receives the submitted
    :class:`SandboxPlan` and returns the :class:`SandboxTrace` to
    emit. Plans submitted are recorded on ``submitted_plans`` so
    assertions can inspect dispatch behavior.
    """

    def __init__(self, trace_factory):
        self.trace_factory = trace_factory
        self.submitted_plans: list[SandboxPlan] = []

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        self.submitted_plans.append(plan)
        return self.trace_factory(plan)


def _trace_with_stdout(plan: SandboxPlan, stdout: str, **kwargs: Any) -> SandboxTrace:
    """Build a SandboxTrace matching one submitted plan."""
    return SandboxTrace(
        plan_id=plan.plan_id,
        file_id=plan.file_id,
        hypothesis_id=plan.hypothesis_id,
        events=[],
        exit_code=kwargs.get("exit_code", 0),
        stdout_excerpt=stdout,
        stderr_excerpt=kwargs.get("stderr_excerpt", ""),
        elapsed_ms=kwargs.get("elapsed_ms", 50),
        probe_result_json=kwargs.get("probe_result_json", ""),
    )


def _make_stub_inference(response_text: str, usage: dict[str, int] | None = None):
    """Return an async inference fn returning canned text + usage."""

    async def stub(prompt: str, params: dict, schema: dict) -> dict:
        return {
            "text": response_text,
            "usage": usage or {"prompt_tokens": 100, "completion_tokens": 50},
        }

    return stub


def _hypothesis_batch_response(*hypotheses: dict, no_new: bool = False) -> str:
    """Build the JSON-encoded model response shape the loop expects."""
    return json.dumps(
        {
            "no_new_hypotheses": no_new,
            "hypotheses": list(hypotheses),
        }
    )


def _stub_python_file() -> tuple[str, bytes]:
    """Smallest valid Python file for plan-builder dispatch."""
    return "module.py", b"def foo(x):\n    return x\n"


# ── hypothesis_from_dict decoding ─────────────────────────────────────────


def test_hypothesis_from_dict_probe_kind() -> None:
    raw = {
        "language": "python",
        "kind": "probe",
        "rationale": "explore load_config behavior",
        "attack_class": "exploratory",
        "expected_observable": "want to learn what load_config returns",
        "exploit_proof_if_observed": "",
        "confidence_prior": "MEDIUM",
        "function_name": "load_config",
        "args_json": '["/tmp/test.json"]',
        "kwargs_json": "{}",
        "sequence": [],
    }
    h = hypothesis_from_dict(raw)
    assert h is not None
    assert h.kind == al.HYPOTHESIS_KIND_PROBE
    assert h.language == al.LANGUAGE_PYTHON
    assert h.function_name == "load_config"
    assert h.args_json == '["/tmp/test.json"]'
    assert h.sequence == []


def test_hypothesis_from_dict_stateful_sequence_keeps_sequence_dicts() -> None:
    raw = {
        "language": "python",
        "kind": "stateful_sequence",
        "rationale": "state-poisoning via config",
        "attack_class": "code_injection",
        "expected_observable": "canary file appears",
        "exploit_proof_if_observed": "RCE via config loader",
        "confidence_prior": "HIGH",
        "function_name": "",
        "args_json": "[]",
        "kwargs_json": "{}",
        "sequence": [
            {"op": "fs_write", "path": "/tmp/cfg", "content": "..."},
            {"op": "call", "function_name": "load", "args_json": '["/tmp/cfg"]'},
            "not-a-dict-should-be-dropped",
            42,
        ],
    }
    h = hypothesis_from_dict(raw)
    assert h is not None
    assert h.kind == al.HYPOTHESIS_KIND_STATEFUL_SEQUENCE
    # Non-dict entries filtered out, dict entries preserved in order.
    assert len(h.sequence) == 2
    assert h.sequence[0]["op"] == "fs_write"
    assert h.sequence[1]["op"] == "call"


def test_hypothesis_from_dict_rejects_unknown_kind() -> None:
    raw = {"language": "python", "kind": "telepathy"}
    assert hypothesis_from_dict(raw) is None


def test_hypothesis_from_dict_rejects_unknown_language() -> None:
    raw = {"language": "fortran", "kind": "probe"}
    assert hypothesis_from_dict(raw) is None


def test_hypothesis_from_dict_rejects_non_dict() -> None:
    assert hypothesis_from_dict("not-a-dict") is None  # type: ignore[arg-type]
    assert hypothesis_from_dict(None) is None  # type: ignore[arg-type]
    assert hypothesis_from_dict(42) is None  # type: ignore[arg-type]


# ── run_one_turn dispatch ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_one_turn_probe_kind_returns_probe_observed_with_summary() -> None:
    """A probe-kind hypothesis must produce VERDICT_PROBE_OBSERVED with a
    descriptive summary, never an attack confirmation."""
    response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "probe",
            "rationale": "explore foo behavior",
            "attack_class": "exploratory",
            "expected_observable": "what does foo do",
            "exploit_proof_if_observed": "",
            "confidence_prior": "LOW",
            "function_name": "foo",
            "args_json": '["x"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_stub_inference(response)
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(
            plan,
            stdout='RESULT_JSON:{"ok": true, "type": "str", "value_preview": "\\"x\\""}',
        )
    )
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-1",
        behavioral_profile={"callables": ["foo"]},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
    )
    assert len(turn.hypotheses) == 1
    assert len(turn.outcomes) == 1
    outcome = turn.outcomes[0]
    assert outcome.verdict == al.VERDICT_PROBE_OBSERVED
    assert outcome.confidence == 0.0
    assert "foo" in outcome.runtime_evidence
    assert "returned cleanly" in outcome.runtime_evidence
    assert turn.inference_cost_usd > 0


@pytest.mark.asyncio
async def test_run_one_turn_single_function_canary_returns_confirmed() -> None:
    """Single-function hypothesis with canary side-effect must produce
    VERDICT_CONFIRMED — Rule 2 canary firing is the strongest signal."""
    response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "audit_hook caught subprocess in foo",
            "attack_class": "command_injection",
            "expected_observable": "canary file /tmp/argus_probe_pwned appears",
            "exploit_proof_if_observed": "command injection via foo arg",
            "confidence_prior": "HIGH",
            "function_name": "foo",
            "args_json": '["test"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_stub_inference(response)
    # Canary tmp file appears in side_effects → Rule 2 fires.
    sandbox_stdout = (
        'RESULT_JSON:{"ok": true, "type": "NoneType", "value_preview": "None"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned_xyz"]}'
    )
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=sandbox_stdout))
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-2",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
    )
    outcome = turn.outcomes[0]
    assert outcome.verdict == al.VERDICT_CONFIRMED
    # v1.6 Fix #4b: canary-only (no class-signature backup) → 0.8.
    # The canary proves the exploit primitive fired, but it doesn't
    # verify the firing demonstrates the L1-claimed CWE class
    # (canary creation is mechanism-agnostic).
    assert outcome.confidence == 0.8
    assert outcome.oracle_type == "single_function_canary_only"
    assert "argus_probe_pwned" in outcome.runtime_evidence


@pytest.mark.asyncio
async def test_run_one_turn_single_function_no_signal_returns_refuted() -> None:
    """Function returned an unrelated value, no canary — must be REFUTED."""
    response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "guess",
            "attack_class": "path_traversal",
            "expected_observable": "reads /etc/passwd",
            "exploit_proof_if_observed": "path traversal in foo",
            "confidence_prior": "LOW",
            "function_name": "foo",
            "args_json": '["unrelated_input"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_stub_inference(response)
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(
            plan,
            stdout=(
                'RESULT_JSON:{"ok": true, "type": "str", "value_preview": "\\"unrelated_input\\""}'
            ),
        )
    )
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-3",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
    )
    outcome = turn.outcomes[0]
    assert outcome.verdict == al.VERDICT_REFUTED
    assert outcome.confidence == 0.0


@pytest.mark.asyncio
async def test_run_one_turn_sandbox_exception_returns_blocked() -> None:
    """When the sandbox raises, the outcome MUST be VERDICT_BLOCKED — the
    loop must never crash on infrastructure failures."""
    response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "test",
            "attack_class": "code_injection",
            "expected_observable": "...",
            "exploit_proof_if_observed": "...",
            "confidence_prior": "MEDIUM",
            "function_name": "foo",
            "args_json": "[]",
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_stub_inference(response)

    def _raise(_plan: SandboxPlan) -> SandboxTrace:
        raise RuntimeError("fly api unreachable")

    sandbox = StubSandbox(_raise)
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-4",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
    )
    outcome = turn.outcomes[0]
    assert outcome.verdict == al.VERDICT_BLOCKED
    assert "fly api unreachable" in outcome.runtime_evidence


@pytest.mark.asyncio
async def test_run_one_turn_no_new_hypotheses_returns_empty_turn() -> None:
    """When the model signals no_new_hypotheses with no batch, the turn
    must still produce a valid (empty) AdversarialTurn and propagate
    the flag for the outer loop to consume."""
    response = _hypothesis_batch_response(no_new=True)
    inference = _make_stub_inference(response)
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=""))
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-5",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
    )
    assert turn.no_new_hypotheses_flag is True
    assert turn.hypotheses == []
    assert turn.outcomes == []
    # Sandbox should NOT have been called for an empty hypothesis list.
    assert sandbox.submitted_plans == []


@pytest.mark.asyncio
async def test_run_one_turn_captures_code_intent_analysis_when_present() -> None:
    """v15.8 Gap 2 fix: the model's code_intent_analysis (purpose /
    deployment_context / trust_boundary / powerful_by_design) is
    captured on the turn even when hypotheses=[].

    Reason: when Stage 2 declines to emit hypotheses (the shopify-api
    / homebridge case), the scan JSON needs the model's structured
    intent reasoning so operators can distinguish "legitimate decline
    on a library file" from "Stage 2 was too conservative on real
    attack surface."
    """
    # Hand-build a response that includes code_intent_analysis (the
    # full schema; _hypothesis_batch_response helper omits it for
    # back-compat with the existing tests).
    response = json.dumps(
        {
            "no_new_hypotheses": True,
            "hypotheses": [],
            "code_intent_analysis": {
                "purpose": "REST API helper for shopify-api SDK",
                "deployment_context": "library",
                "trust_boundary": "internal SDK callers",
                "powerful_by_design": ["http_request", "json_parse"],
            },
        }
    )
    inference = _make_stub_inference(response)
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=""))
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-cia",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
    )
    assert turn.no_new_hypotheses_flag is True
    assert turn.hypotheses == []
    assert isinstance(turn.code_intent_analysis, dict)
    assert turn.code_intent_analysis["deployment_context"] == "library"
    assert turn.code_intent_analysis["purpose"].startswith("REST API helper")


@pytest.mark.asyncio
async def test_run_one_turn_code_intent_analysis_none_when_absent() -> None:
    """v15.8 boundary: turn.code_intent_analysis stays None when the
    response omits the field (back-compat with older fixtures + the
    existing _hypothesis_batch_response helper)."""
    response = _hypothesis_batch_response(no_new=True)  # no CIA field
    inference = _make_stub_inference(response)
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=""))
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-no-cia",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
    )
    assert turn.code_intent_analysis is None


@pytest.mark.asyncio
async def test_run_one_turn_caps_at_max_hypotheses_per_turn() -> None:
    """Defense-in-depth: model emits 5 hypotheses but the schema's
    maxItems is 3. Even if the schema is bypassed, the loop must cap
    at MAX_HYPOTHESES_PER_TURN."""
    hypotheses = [
        {
            "language": "python",
            "kind": "probe",
            "rationale": f"probe {i}",
            "attack_class": "exploratory",
            "expected_observable": "",
            "exploit_proof_if_observed": "",
            "confidence_prior": "LOW",
            "function_name": "foo",
            "args_json": "[]",
            "kwargs_json": "{}",
            "sequence": [],
        }
        for i in range(5)
    ]
    response = _hypothesis_batch_response(*hypotheses)
    inference = _make_stub_inference(response)
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(
            plan,
            stdout='RESULT_JSON:{"ok": true, "type": "str", "value_preview": "\\"x\\""}',
        )
    )
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-6",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
    )
    assert len(turn.hypotheses) == al.MAX_HYPOTHESES_PER_TURN
    assert len(turn.outcomes) == al.MAX_HYPOTHESES_PER_TURN


# ── run_adversarial_loop aggregation + termination ───────────────────────


@pytest.mark.asyncio
async def test_run_adversarial_loop_default_max_turns_one() -> None:
    """Default ``max_turns=1`` runs exactly one turn and terminates
    via MAX_TURNS (NOT no_new_hypotheses — the model didn't signal it)."""
    response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "probe",
            "rationale": "test",
            "attack_class": "exploratory",
            "expected_observable": "",
            "exploit_proof_if_observed": "",
            "confidence_prior": "LOW",
            "function_name": "foo",
            "args_json": "[]",
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_stub_inference(response)
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(
            plan,
            stdout='RESULT_JSON:{"ok": true, "type": "str", "value_preview": "\\"x\\""}',
        )
    )
    file_name, file_bytes = _stub_python_file()

    result = await run_adversarial_loop(
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-loop-1",
        behavioral_profile={"callables": ["foo"]},
        inference=inference,
        sandbox=sandbox,
    )
    assert len(result.turns) == 1
    assert result.terminated_by == al.TERMINATED_BY_MAX_TURNS
    assert result.hypotheses_total == 1
    assert result.explore_calls_used == 1  # probe-kind counts here
    assert result.total_cost_usd > 0


@pytest.mark.asyncio
async def test_run_adversarial_loop_no_new_hypotheses_terminates_early() -> None:
    """When ``no_new_hypotheses`` fires on turn >= MIN_TURNS_BEFORE_EARLY_EXIT,
    the loop must terminate with TERMINATED_BY_NO_NEW."""
    # Turn 0 — real batch. Turn 1 — no_new_hypotheses.
    responses = [
        _hypothesis_batch_response(
            {
                "language": "python",
                "kind": "probe",
                "rationale": "explore",
                "attack_class": "exploratory",
                "expected_observable": "",
                "exploit_proof_if_observed": "",
                "confidence_prior": "LOW",
                "function_name": "foo",
                "args_json": "[]",
                "kwargs_json": "{}",
                "sequence": [],
            }
        ),
        _hypothesis_batch_response(no_new=True),
    ]
    call_count = {"n": 0}

    async def varying_inference(prompt: str, params: dict, schema: dict) -> dict:
        idx = call_count["n"]
        call_count["n"] += 1
        return {"text": responses[idx], "usage": {"prompt_tokens": 100, "completion_tokens": 50}}

    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(
            plan,
            stdout='RESULT_JSON:{"ok": true, "type": "str", "value_preview": "\\"x\\""}',
        )
    )
    file_name, file_bytes = _stub_python_file()

    result = await run_adversarial_loop(
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-loop-2",
        behavioral_profile={"callables": ["foo"]},
        inference=varying_inference,
        sandbox=sandbox,
        max_turns=5,
    )
    assert len(result.turns) == 2
    assert result.terminated_by == al.TERMINATED_BY_NO_NEW
    assert call_count["n"] == 2


@pytest.mark.asyncio
async def test_run_adversarial_loop_aggregates_findings_only_from_confirmations() -> None:
    """Findings list must include CONFIRMED outcomes only. PROBE_OBSERVED
    counts toward explore_calls_used but never produces a finding."""
    response = _hypothesis_batch_response(
        # probe — counts toward explore_calls, no finding.
        {
            "language": "python",
            "kind": "probe",
            "rationale": "exploration",
            "attack_class": "exploratory",
            "expected_observable": "",
            "exploit_proof_if_observed": "",
            "confidence_prior": "LOW",
            "function_name": "foo",
            "args_json": "[]",
            "kwargs_json": "{}",
            "sequence": [],
        },
        # single_function with canary — confirmed, produces finding.
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "attack",
            "attack_class": "command_injection",
            "expected_observable": "canary appears",
            "exploit_proof_if_observed": "command injection",
            "confidence_prior": "HIGH",
            "function_name": "foo",
            "args_json": '["bad"]',
            "kwargs_json": "{}",
            "sequence": [],
        },
    )
    inference = _make_stub_inference(response)

    def trace_for_plan(plan: SandboxPlan) -> SandboxTrace:
        # First plan (probe) returns clean; second (attack) returns canary.
        if "H0" in plan.hypothesis_id:
            return _trace_with_stdout(
                plan,
                stdout='RESULT_JSON:{"ok": true, "type": "str", "value_preview": "\\"x\\""}',
            )
        return _trace_with_stdout(
            plan,
            stdout=(
                'RESULT_JSON:{"ok": true, "type": "NoneType", "value_preview": "None"}\n'
                'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned"]}'
            ),
        )

    sandbox = StubSandbox(trace_for_plan)
    file_name, file_bytes = _stub_python_file()

    result = await run_adversarial_loop(
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-loop-3",
        behavioral_profile={"callables": ["foo"]},
        inference=inference,
        sandbox=sandbox,
    )
    assert result.hypotheses_total == 2
    assert result.hypotheses_confirmed == 1
    assert result.explore_calls_used == 1
    assert len(result.findings) == 1
    assert result.findings[0]["attack_class"] == "command_injection"
    # v1.6 Fix #4b: canary-only oracle → 0.8 (class-signature didn't fire).
    assert result.findings[0]["confidence"] == 0.8
    # Probe outcome must NOT appear in findings.
    assert all(f["kind"] != al.HYPOTHESIS_KIND_PROBE for f in result.findings)


@pytest.mark.asyncio
async def test_run_adversarial_loop_cost_aggregates_across_turns() -> None:
    """Inference cost must accumulate per turn (cost cap depends on this)."""
    response = _hypothesis_batch_response(no_new=True)
    inference = _make_stub_inference(
        response,
        usage={"prompt_tokens": 1_000_000, "completion_tokens": 0},
    )
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=""))
    file_name, file_bytes = _stub_python_file()

    result = await run_adversarial_loop(
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="fid-loop-4",
        behavioral_profile={},
        inference=inference,
        sandbox=sandbox,
        max_turns=1,
    )
    # 1M input tokens @ Sonnet 4.6 rate = INFERENCE_INPUT_USD_PER_M USD.
    assert result.total_cost_usd == pytest.approx(INFERENCE_INPUT_USD_PER_M)
    assert result.inference_tokens_in == 1_000_000


# ── Fix #4: fixture-context downgrade ────────────────────────────────────


@pytest.mark.asyncio
async def test_confirmed_on_fixture_file_gets_downgraded() -> None:
    """When a CONFIRMED outcome fires on a file marked as fixture/
    scrubbed/neutered, confidence is capped at 0.5 and
    ``fixture_context=True`` is set. Addresses the 8/16 W1 over-claim
    cases from the v1.5.1 adjudication (commit 29e9ca9) where Argus
    treated explicit test fixtures as production zero-days."""
    fixture_source = (
        b'"""Consistency fixture 1: scrubbed reproduction of the\n'
        b"obfuscated-exec backdoor for scanner test purposes."
        b'"""\n\n'
        b"def foo(x):\n    return x\n"
    )
    response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "exec(decoded payload)",
            "attack_class": "code_injection",
            "expected_observable": "canary file argus_probe_pwned appears",
            "exploit_proof_if_observed": "fixture-style exploit",
            "confidence_prior": "HIGH",
            "function_name": "foo",
            "args_json": '["test"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_stub_inference(response)
    canary_stdout = (
        'RESULT_JSON:{"ok": true, "type": "NoneType", "value_preview": "None"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned_xyz"]}'
    )
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=canary_stdout))

    turn = await run_one_turn(
        turn_idx=0,
        file_text=fixture_source.decode(),
        file_name="consistency_fixture.py",
        file_bytes=fixture_source,
        file_id="fix-fid",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
    )
    outcome = turn.outcomes[0]
    assert outcome.verdict == al.VERDICT_CONFIRMED
    assert outcome.fixture_context is True
    assert outcome.confidence <= 0.5
    assert "FIXTURE_CONTEXT" in outcome.runtime_evidence


@pytest.mark.asyncio
async def test_confirmed_on_production_file_keeps_full_confidence() -> None:
    """Non-fixture file with BOTH class-signature AND canary oracles:
    CONFIRMED keeps confidence=1.0 and fixture_context=False. Regression
    guard for the Fix #4a downgrade not over-firing on legitimate
    production code; doubles as the Fix #4b strongest-oracle case
    (``canary+class_signature``)."""
    prod_source = b'"""Production module for parsing user input."""\n\ndef foo(x):\n    return x\n'
    response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "real exploit",
            "attack_class": "command_injection",
            "expected_observable": "canary file argus_probe_pwned appears",
            "exploit_proof_if_observed": "command injection",
            "confidence_prior": "HIGH",
            "function_name": "foo",
            "args_json": '["test"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_stub_inference(response)
    # value_preview contains "uid=" — the command_injection class
    # signature — so Rule 1 + Rule 2 both fire (canary+class_signature).
    canary_stdout = (
        'RESULT_JSON:{"ok": true, "type": "str", '
        '"value_preview": "uid=0(root) gid=0(root) groups=0(root)"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned_xyz"]}'
    )
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=canary_stdout))

    turn = await run_one_turn(
        turn_idx=0,
        file_text=prod_source.decode(),
        file_name="production_module.py",
        file_bytes=prod_source,
        file_id="prod-fid",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
    )
    outcome = turn.outcomes[0]
    assert outcome.verdict == al.VERDICT_CONFIRMED
    assert outcome.fixture_context is False
    assert outcome.confidence == 1.0
    assert outcome.oracle_type == "single_function_rule_fired"
    assert "FIXTURE_CONTEXT" not in outcome.runtime_evidence


@pytest.mark.asyncio
async def test_confirmed_canary_only_caps_confidence_at_0_8() -> None:
    """v1.6 Fix #4b: a CONFIRMED outcome on a production file where
    only the canary oracle fired (no class-signature backup) is
    capped at confidence=0.8 with ``oracle_type='single_function_canary_only'``.
    Addresses the 1/16 CWE mis-attribution case from the v1.5.1
    adjudication where the canary fired but the actual exploit
    primitive didn't demonstrate the L1-claimed CWE class."""
    prod_source = b'"""Production module."""\n\ndef foo(x):\n    return x\n'
    response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "speculative attack",
            "attack_class": "command_injection",
            "expected_observable": "canary file argus_probe_pwned appears",
            "exploit_proof_if_observed": "command injection",
            "confidence_prior": "HIGH",
            "function_name": "foo",
            "args_json": '["test"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_stub_inference(response)
    # value_preview is benign ("None") — class signature does NOT
    # match. Canary still appears in side_effects. Result: canary-only.
    canary_only_stdout = (
        'RESULT_JSON:{"ok": true, "type": "NoneType", "value_preview": "None"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned_xyz"]}'
    )
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=canary_only_stdout))

    turn = await run_one_turn(
        turn_idx=0,
        file_text=prod_source.decode(),
        file_name="production_module.py",
        file_bytes=prod_source,
        file_id="prod-fid-canary-only",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
        enable_strategy_c_judge=False,  # isolate the canary-only verdict
    )
    outcome = turn.outcomes[0]
    assert outcome.verdict == al.VERDICT_CONFIRMED
    assert outcome.fixture_context is False
    assert outcome.confidence == 0.8
    assert outcome.oracle_type == "single_function_canary_only"


# ── v1.8 Strategy C: post-trace LLM judge ────────────────────────────────


def _make_routed_inference(
    hypothesis_response: str,
    judge_response: str | None = None,
    judge_raises: BaseException | None = None,
):
    """Stub inference router. Returns the hypothesis batch on the FIRST
    call and (optionally) a Strategy-C judge response on subsequent
    calls. Use ``judge_raises`` to simulate a judge-call failure
    (verifies fail-open behavior).

    Calls past the first are treated as judge calls; if you pass
    ``judge_response=None`` and ``judge_raises=None`` the stub returns
    an empty-text response so JSON decode fails (also fail-open).
    """
    call_count = {"n": 0}

    async def stub(prompt: str, params: dict, schema: dict) -> dict:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return {
                "text": hypothesis_response,
                "usage": {"prompt_tokens": 100, "completion_tokens": 50},
            }
        # Second+ call = judge.
        if judge_raises is not None:
            raise judge_raises
        return {
            "text": judge_response or "",
            "usage": {"prompt_tokens": 200, "completion_tokens": 50},
        }

    stub.call_count = call_count  # attached for assertions
    return stub


@pytest.mark.asyncio
async def test_strategy_c_judge_confirmed_keeps_outcome_confirmed() -> None:
    """v1.8 Strategy C: when the judge agrees CONFIRMED, the outcome
    stays CONFIRMED. Both interpreter and judge agreed → ship."""
    hyp_response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "exec",
            "attack_class": "command_injection",
            "expected_observable": "canary appears",
            "exploit_proof_if_observed": "rce confirmed",
            "confidence_prior": "HIGH",
            "function_name": "foo",
            "args_json": '["x"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    judge_response = json.dumps(
        {
            "judge_verdict": "CONFIRMED",
            "judge_reasoning": "Canary file argus_probe_pwned_abc materialized; operation fired.",
            "evidence_strength": "high",
        }
    )
    inference = _make_routed_inference(hyp_response, judge_response)
    canary_stdout = (
        'RESULT_JSON:{"ok": true, "type": "NoneType", "value_preview": "None"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned_abc"]}'
    )
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=canary_stdout))
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="judge-conf-fid",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
        enable_strategy_c_judge=True,
    )
    outcome = turn.outcomes[0]
    assert outcome.verdict == al.VERDICT_CONFIRMED
    assert outcome.judge_verdict == "CONFIRMED"
    assert "Canary file" in outcome.judge_reasoning
    # Hypothesis call + judge call = 2 inference calls.
    assert inference.call_count["n"] == 2


@pytest.mark.asyncio
async def test_strategy_c_judge_refuted_flips_to_refuted() -> None:
    """v1.8 Strategy C THE FP DEFENSE: when judge says REFUTED on a
    CONFIRMED outcome, the runner flips outcome.verdict to
    VERDICT_REFUTED. This catches the substring-oracle false-positive
    class (PermissionError on '../../../etc/passwd' echoing payload)."""
    hyp_response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "path traversal attempt",
            "attack_class": "path_traversal",
            "expected_observable": "etc/passwd content read",
            "exploit_proof_if_observed": "LFI confirmed",
            "confidence_prior": "HIGH",
            "function_name": "foo",
            "args_json": '["../../../etc/passwd"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    judge_response = json.dumps(
        {
            "judge_verdict": "REFUTED",
            "judge_reasoning": "Application raised PermissionError at the access "
            "boundary; error message merely echoes the attacker payload. No "
            "file content was actually read.",
            "evidence_strength": "high",
        }
    )
    inference = _make_routed_inference(hyp_response, judge_response)
    # v15.27 — use a class-signature trigger (``root:x:0:0:``) instead
    # of the pass-through ``etc/passwd`` keyword. v15.27's causality
    # check now correctly suppresses pass-through keyword matches, so
    # the prior test setup (where etc/passwd appeared in both input
    # AND output) never fires the matcher anymore. Class-signature
    # path is unaffected by the causality gate and still triggers
    # CONFIRMED — letting Strategy C demonstrate the REFUTED flip.
    confirmed_stdout = (
        'RESULT_JSON:{"ok": true, "type": "str", '
        '"value_preview": "root:x:0:0:root:/root:/bin/bash leaked"}'
    )
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=confirmed_stdout))
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="judge-refute-fid",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
        enable_strategy_c_judge=True,
    )
    outcome = turn.outcomes[0]
    # The FP defense: judge override flipped CONFIRMED -> REFUTED.
    assert outcome.verdict == al.VERDICT_REFUTED
    assert outcome.judge_verdict == "REFUTED"
    assert "PermissionError" in outcome.judge_reasoning
    assert outcome.confidence == 0.0
    # Evidence text records the override so the operator can audit.
    assert "STRATEGY_C_REFUTED" in outcome.runtime_evidence


@pytest.mark.asyncio
async def test_strategy_c_judge_inconclusive_keeps_confirmed() -> None:
    """v1.8 Strategy C: when judge says INCONCLUSIVE, the verdict stays
    CONFIRMED unchanged (we don't down-weight or refute on uncertainty).
    judge_verdict='INCONCLUSIVE' surfaces in the output so the
    operator sees the ambiguity without it being buried in a
    confidence number."""
    hyp_response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "attack",
            "attack_class": "code_injection",
            "expected_observable": "exec fires",
            "exploit_proof_if_observed": "RCE",
            "confidence_prior": "HIGH",
            "function_name": "foo",
            "args_json": '["x"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    judge_response = json.dumps(
        {
            "judge_verdict": "INCONCLUSIVE",
            "judge_reasoning": "Trace shows ambiguous output. Cannot tell from "
            "evidence whether exec actually ran or function returned early.",
            "evidence_strength": "medium",
        }
    )
    inference = _make_routed_inference(hyp_response, judge_response)
    canary_stdout = (
        'RESULT_JSON:{"ok": true, "type": "NoneType", "value_preview": "None"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned_xyz"]}'
    )
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=canary_stdout))
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="judge-incl-fid",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
        enable_strategy_c_judge=True,
    )
    outcome = turn.outcomes[0]
    # CONFIRMED preserved despite judge uncertainty.
    assert outcome.verdict == al.VERDICT_CONFIRMED
    assert outcome.judge_verdict == "INCONCLUSIVE"
    assert "ambiguous" in outcome.judge_reasoning


@pytest.mark.asyncio
async def test_strategy_c_judge_error_failopen_keeps_confirmed() -> None:
    """v1.8 Strategy C contract: if the judge call ERRORS (sandbox down,
    bad JSON from model, network blip), the runner KEEPS the
    interpreter's CONFIRMED verdict — fail-open. The hot path must
    not be affected by judge-layer failures."""
    hyp_response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "attack",
            "attack_class": "command_injection",
            "expected_observable": "canary",
            "exploit_proof_if_observed": "rce",
            "confidence_prior": "HIGH",
            "function_name": "foo",
            "args_json": '["x"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_routed_inference(
        hyp_response,
        judge_raises=RuntimeError("simulated judge-call failure"),
    )
    canary_stdout = (
        'RESULT_JSON:{"ok": true, "type": "NoneType", "value_preview": "None"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned"]}'
    )
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=canary_stdout))
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="judge-err-fid",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
        enable_strategy_c_judge=True,
    )
    outcome = turn.outcomes[0]
    # CONFIRMED preserved on judge-call failure.
    assert outcome.verdict == al.VERDICT_CONFIRMED
    assert outcome.judge_verdict == ""
    assert "errored" in outcome.judge_reasoning


@pytest.mark.asyncio
async def test_strategy_c_disabled_skips_judge_call() -> None:
    """When ``enable_strategy_c_judge=False``, the judge is never
    called — preserves backward-compat for callers that opt out.
    Only the hypothesis-batch inference call happens."""
    hyp_response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "single_function",
            "rationale": "attack",
            "attack_class": "command_injection",
            "expected_observable": "canary",
            "exploit_proof_if_observed": "rce",
            "confidence_prior": "HIGH",
            "function_name": "foo",
            "args_json": '["x"]',
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_routed_inference(hyp_response)
    canary_stdout = (
        'RESULT_JSON:{"ok": true, "type": "NoneType", "value_preview": "None"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned"]}'
    )
    sandbox = StubSandbox(lambda plan: _trace_with_stdout(plan, stdout=canary_stdout))
    file_name, file_bytes = _stub_python_file()

    turn = await run_one_turn(
        turn_idx=0,
        file_text=file_bytes.decode(),
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="judge-off-fid",
        behavioral_profile={},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
        enable_strategy_c_judge=False,
    )
    outcome = turn.outcomes[0]
    assert outcome.verdict == al.VERDICT_CONFIRMED
    # Judge fields stay empty because the judge was never invoked.
    assert outcome.judge_verdict == ""
    assert outcome.judge_reasoning == ""
    # Only the hypothesis-batch call happened.
    assert inference.call_count["n"] == 1


# ── JS DAST parity: run_adversarial_loop language derivation ──────────────


@pytest.mark.asyncio
async def test_run_adversarial_loop_derives_python_from_py_extension() -> None:
    """``.py`` file ⇒ ``AdversarialLoopResult.language == LANGUAGE_PYTHON``.

    Pre-v1.8 the runner hardcoded LANGUAGE_PYTHON unconditionally. With
    JS DAST parity wiring, language is derived via
    ``detect_probe_language`` from the file_name. This test pins the
    Python path stays correct."""
    response = _hypothesis_batch_response(
        {
            "language": "python",
            "kind": "probe",
            "rationale": "test",
            "attack_class": "exploratory",
            "expected_observable": "",
            "exploit_proof_if_observed": "",
            "confidence_prior": "LOW",
            "function_name": "foo",
            "args_json": "[]",
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_stub_inference(response)
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(
            plan,
            stdout='RESULT_JSON:{"ok": true, "type": "str", "value_preview": "\\"x\\""}',
        )
    )
    file_name, file_bytes = _stub_python_file()

    result = await run_adversarial_loop(
        file_name=file_name,
        file_bytes=file_bytes,
        file_id="lang-test-py",
        behavioral_profile={"callables": ["foo"]},
        inference=inference,
        sandbox=sandbox,
    )
    assert result.language == al.LANGUAGE_PYTHON


@pytest.mark.asyncio
async def test_run_adversarial_loop_derives_javascript_from_js_extension() -> None:
    """``.js`` file ⇒ ``AdversarialLoopResult.language == LANGUAGE_JAVASCRIPT``.

    Critical for JS DAST parity: the runner must record the JS
    language correctly so downstream consumers (verdict resolver,
    journal, telemetry) can attribute findings to the right language.
    Plan builders dispatch on this field internally."""
    response = _hypothesis_batch_response(
        {
            "language": "javascript",
            "kind": "probe",
            "rationale": "test js",
            "attack_class": "exploratory",
            "expected_observable": "",
            "exploit_proof_if_observed": "",
            "confidence_prior": "LOW",
            "function_name": "doStuff",
            "args_json": "[]",
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    inference = _make_stub_inference(response)
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(
            plan,
            stdout='RESULT_JSON:{"ok": true, "type": "string", "value_preview": "\\"x\\""}',
        )
    )

    result = await run_adversarial_loop(
        file_name="malicious.js",
        file_bytes=b"function doStuff() { return 'ok'; }\nmodule.exports = { doStuff };\n",
        file_id="lang-test-js",
        behavioral_profile={"callables": ["doStuff"]},
        inference=inference,
        sandbox=sandbox,
    )
    assert result.language == al.LANGUAGE_JAVASCRIPT


@pytest.mark.asyncio
async def test_run_adversarial_loop_mjs_and_cjs_extensions() -> None:
    """``.mjs`` (ES modules) and ``.cjs`` (CommonJS) both route to
    LANGUAGE_JAVASCRIPT — the canonical detector treats them as one
    language."""
    response = _hypothesis_batch_response(
        {
            "language": "javascript",
            "kind": "probe",
            "rationale": "test",
            "attack_class": "exploratory",
            "expected_observable": "",
            "exploit_proof_if_observed": "",
            "confidence_prior": "LOW",
            "function_name": "x",
            "args_json": "[]",
            "kwargs_json": "{}",
            "sequence": [],
        }
    )
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(
            plan,
            stdout='RESULT_JSON:{"ok": true, "type": "string", "value_preview": "\\"x\\""}',
        )
    )

    for ext in (".mjs", ".cjs"):
        inference = _make_stub_inference(response)
        result = await run_adversarial_loop(
            file_name=f"target{ext}",
            file_bytes=b"export function x() { return 'ok'; }\n",
            file_id=f"lang-test{ext}",
            behavioral_profile={"callables": ["x"]},
            inference=inference,
            sandbox=sandbox,
        )
        assert result.language == al.LANGUAGE_JAVASCRIPT, (
            f"{ext} should map to LANGUAGE_JAVASCRIPT, got {result.language}"
        )


# ── v1.9.1 coverage tracker dedupe ────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_one_turn_filters_covered_hypotheses() -> None:
    """When the coverage tracker reports a hypothesis's (function,
    attack_class) as already covered (e.g., by an L1 finding or
    Phase B+ confirmation), the adversarial loop skips it before
    sandbox dispatch. Suppression telemetry increments."""
    from dast.coverage_tracker import CoverageTracker

    tracker = CoverageTracker()
    tracker.add(
        function="run_user_command",
        attack_class="command_injection",
        source="phase_b",
        finding_id="HRP_0_0",
    )

    inference = _make_stub_inference(
        _hypothesis_batch_response(
            {
                "language": "python",
                "kind": "single_function",
                "rationale": "test cmd injection",
                "attack_class": "command_injection",
                "expected_observable": "canary",
                "exploit_proof_if_observed": "rce",
                "confidence_prior": "HIGH",
                # SAME function the tracker has covered — should be
                # filtered out before sandbox call.
                "function_name": "run_user_command",
                "args_json": '[". ; touch /tmp/x"]',
                "kwargs_json": "{}",
                "sequence": [],
            },
            {
                "language": "python",
                "kind": "single_function",
                "rationale": "test ssrf",
                "attack_class": "ssrf",
                "expected_observable": "outbound network",
                "exploit_proof_if_observed": "ssrf",
                "confidence_prior": "HIGH",
                # DIFFERENT function — NOT in tracker, should run.
                "function_name": "fetch_remote_resource",
                "args_json": '["http://169.254.169.254/"]',
                "kwargs_json": "{}",
                "sequence": [],
            },
        ),
    )
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(plan, "no signal", exit_code=0)
    )

    turn = await run_one_turn(
        turn_idx=0,
        file_text="def run_user_command(x): pass\ndef fetch_remote_resource(u): pass\n",
        file_name="module.py",
        file_bytes=b"def run_user_command(x): pass\ndef fetch_remote_resource(u): pass\n",
        file_id="t1",
        behavioral_profile={"callables": ["run_user_command", "fetch_remote_resource"]},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
        coverage_tracker=tracker,
    )

    # Only the UNCOVERED hypothesis (fetch_remote_resource) survived.
    assert len(turn.hypotheses) == 1
    assert turn.hypotheses[0].function_name == "fetch_remote_resource"
    # Sandbox only saw 1 plan (the SSRF one).
    assert len(sandbox.submitted_plans) == 1
    # Suppression telemetry recorded.
    stats = tracker.stats()
    assert stats["suppressions_by_stage"].get("phase_3") == 1


@pytest.mark.asyncio
async def test_run_one_turn_no_dedupe_when_tracker_absent() -> None:
    """Back-compat: when coverage_tracker is None, run_one_turn behaves
    exactly as v1.9.0 — every hypothesis flows through to the sandbox."""
    inference = _make_stub_inference(
        _hypothesis_batch_response(
            {
                "language": "python",
                "kind": "single_function",
                "rationale": "x",
                "attack_class": "command_injection",
                "expected_observable": "x",
                "exploit_proof_if_observed": "x",
                "confidence_prior": "HIGH",
                "function_name": "run_user_command",
                "args_json": "[]",
                "kwargs_json": "{}",
                "sequence": [],
            },
        ),
    )
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(plan, "no signal", exit_code=0)
    )
    turn = await run_one_turn(
        turn_idx=0,
        file_text="def run_user_command(x): pass\n",
        file_name="module.py",
        file_bytes=b"def run_user_command(x): pass\n",
        file_id="t2",
        behavioral_profile={"callables": ["run_user_command"]},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
        # coverage_tracker omitted (default None)
    )
    assert len(turn.hypotheses) == 1
    assert len(sandbox.submitted_plans) == 1


@pytest.mark.asyncio
async def test_run_one_turn_no_dedupe_when_tracker_disabled() -> None:
    """``--no-enable-coverage-dedupe`` → tracker has enabled=False →
    is_covered always returns None → no suppressions."""
    from dast.coverage_tracker import CoverageTracker

    tracker = CoverageTracker(enabled=False)
    tracker.add(
        function="run_user_command",
        attack_class="command_injection",
        source="phase_b",
        finding_id="HRP_0_0",
    )

    inference = _make_stub_inference(
        _hypothesis_batch_response(
            {
                "language": "python",
                "kind": "single_function",
                "rationale": "x",
                "attack_class": "command_injection",
                "expected_observable": "x",
                "exploit_proof_if_observed": "x",
                "confidence_prior": "HIGH",
                "function_name": "run_user_command",
                "args_json": "[]",
                "kwargs_json": "{}",
                "sequence": [],
            },
        ),
    )
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(plan, "no signal", exit_code=0)
    )
    turn = await run_one_turn(
        turn_idx=0,
        file_text="def run_user_command(x): pass\n",
        file_name="module.py",
        file_bytes=b"def run_user_command(x): pass\n",
        file_id="t3",
        behavioral_profile={"callables": ["run_user_command"]},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
        coverage_tracker=tracker,
    )
    # Disabled tracker → hypothesis NOT filtered.
    assert len(turn.hypotheses) == 1
    assert len(sandbox.submitted_plans) == 1


@pytest.mark.asyncio
async def test_run_one_turn_dedupe_normalizes_attack_class_aliases() -> None:
    """Tracker stores ``server_side_request_forgery`` → ``ssrf``.
    Hypothesis with ``attack_class=ssrf`` should still match."""
    from dast.coverage_tracker import CoverageTracker

    tracker = CoverageTracker()
    tracker.add(
        function="fetch_url",
        attack_class="server_side_request_forgery",
        source="l1",
        finding_id="H001",
    )

    inference = _make_stub_inference(
        _hypothesis_batch_response(
            {
                "language": "python",
                "kind": "single_function",
                "rationale": "x",
                "attack_class": "ssrf",  # canonical form
                "expected_observable": "x",
                "exploit_proof_if_observed": "x",
                "confidence_prior": "HIGH",
                "function_name": "fetch_url",
                "args_json": "[]",
                "kwargs_json": "{}",
                "sequence": [],
            },
        ),
    )
    sandbox = StubSandbox(
        lambda plan: _trace_with_stdout(plan, "no signal", exit_code=0)
    )
    turn = await run_one_turn(
        turn_idx=0,
        file_text="def fetch_url(u): pass\n",
        file_name="module.py",
        file_bytes=b"def fetch_url(u): pass\n",
        file_id="t4",
        behavioral_profile={"callables": ["fetch_url"]},
        prior_turns_dict=None,
        inference=inference,
        sandbox=sandbox,
        coverage_tracker=tracker,
    )
    # Filtered out via attack-class alias normalization.
    assert len(turn.hypotheses) == 0
    assert len(sandbox.submitted_plans) == 0
    assert tracker.stats()["suppressions_by_stage"].get("phase_3") == 1
