"""Unit tests for Phase 3 Stage 2 adversarial-loop scaffolding.

Covers:
* Constants in :mod:`dast.adversarial_loop` stay aligned with the schema
  enums in :func:`dast.prompts.phase_3_loop_hypothesis_batch_schema` —
  drift between them would silently break model-output → loop dispatch.
* ``should_short_circuit`` gate semantics: L1 confidence threshold +
  profile-confirm requirement + profile-contradict veto.
* Phase 3 loop schema shape — top-level required fields, max hypotheses
  per turn, profile-anchor field requirement, function_name pattern
  accepts empty for stateful-sequence hypotheses.
* Phase 3 loop prompt builder — turn 0 vs turn 1+ section, profile
  signals rendered, no L1 hypotheses in signature (anchoring guard).

No live API; no sandbox. Step 8 will add deeper coverage (loop
termination, dedup, language switching).
"""

from __future__ import annotations

import inspect
import re

from dast import adversarial_loop as al
from dast.prompts import (
    build_phase_3_loop_hypothesis_batch_prompt,
    phase_3_loop_hypothesis_batch_schema,
)

# ── Constants ↔ schema drift guard ────────────────────────────────────────


def test_loop_constants_match_schema_enums() -> None:
    """``adversarial_loop`` constants must match the schema enum strings
    exactly. If they drift, the model emits valid JSON that the loop
    dispatch fails to route — and the failure is silent."""
    schema = phase_3_loop_hypothesis_batch_schema()
    item_props = schema["properties"]["hypotheses"]["items"]["properties"]

    assert set(item_props["kind"]["enum"]) == {
        al.HYPOTHESIS_KIND_PROBE,
        al.HYPOTHESIS_KIND_SINGLE_FUNCTION,
        al.HYPOTHESIS_KIND_STATEFUL_SEQUENCE,
    }

    assert set(item_props["language"]["enum"]) == {
        al.LANGUAGE_PYTHON,
        al.LANGUAGE_JAVASCRIPT,
        al.LANGUAGE_TYPESCRIPT,  # v9 (2026-05-16)
        al.LANGUAGE_SHELL,
    }

    op_enum = set(item_props["sequence"]["items"]["properties"]["op"]["enum"])
    assert op_enum == {
        al.SEQ_OP_CALL,
        al.SEQ_OP_FS_WRITE,
        al.SEQ_OP_ENV_SET,
        al.SEQ_OP_FS_READ,
    }


def test_verdict_probe_observed_is_distinct_value() -> None:
    """Probe-kind verdict must be distinguishable from attack verdicts
    so the loop / resolver can route correctly."""
    assert al.VERDICT_PROBE_OBSERVED not in {
        al.VERDICT_CONFIRMED,
        al.VERDICT_REFUTED,
        al.VERDICT_BLOCKED,
    }


# ── should_short_circuit gate ─────────────────────────────────────────────


def test_short_circuit_false_when_l1_below_threshold() -> None:
    inputs = al.L1ShortcircuitInput(
        l1_max_confidence=0.5,
        behavioral_profile_confirms_pattern=True,
        behavioral_profile_contradicts=False,
    )
    assert al.should_short_circuit(inputs) is False


def test_short_circuit_true_when_high_l1_and_profile_confirms() -> None:
    inputs = al.L1ShortcircuitInput(
        l1_max_confidence=0.98,
        behavioral_profile_confirms_pattern=True,
        behavioral_profile_contradicts=False,
    )
    assert al.should_short_circuit(inputs) is True


def test_short_circuit_false_when_profile_contradicts_overrides_l1() -> None:
    """Profile contradiction is a hard veto — even at 1.0 L1 confidence
    we must run the loop to surface the disagreement."""
    inputs = al.L1ShortcircuitInput(
        l1_max_confidence=1.0,
        behavioral_profile_confirms_pattern=True,
        behavioral_profile_contradicts=True,
    )
    assert al.should_short_circuit(inputs) is False


def test_short_circuit_false_when_profile_does_not_confirm() -> None:
    """High L1 confidence alone isn't enough — without independent
    profile confirmation, we run the loop."""
    inputs = al.L1ShortcircuitInput(
        l1_max_confidence=0.99,
        behavioral_profile_confirms_pattern=False,
        behavioral_profile_contradicts=False,
    )
    assert al.should_short_circuit(inputs) is False


def test_short_circuit_threshold_override_param_works() -> None:
    """The threshold override lets benchmark runs force the loop to
    always execute (``--always-run-adversarial-loop`` semantics)."""
    inputs = al.L1ShortcircuitInput(
        l1_max_confidence=0.99,
        behavioral_profile_confirms_pattern=True,
        behavioral_profile_contradicts=False,
    )
    assert al.should_short_circuit(inputs, threshold=1.01) is False


# ── Phase 3 loop schema shape ─────────────────────────────────────────────


def test_phase_3_schema_top_level_required_fields() -> None:
    schema = phase_3_loop_hypothesis_batch_schema()
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    # v1.6 Fix #8b: code_intent_analysis added — forces the model to
    # reason about file intent before generating attack hypotheses.
    assert set(schema["required"]) == {
        "code_intent_analysis",
        "no_new_hypotheses",
        "hypotheses",
    }


def test_phase_3_schema_code_intent_analysis_block() -> None:
    """v1.6 Fix #8b + v15.21: code_intent_analysis is a structured
    object with purpose / deployment_context / trust_boundary /
    trust_boundary_class / powerful_by_design. v15.21 added the
    explicit trust_boundary_class enum so the scoring engine can
    apply deterministic clamping (Gemini Issue 2)."""
    schema = phase_3_loop_hypothesis_batch_schema()
    intent = schema["properties"]["code_intent_analysis"]
    assert intent["type"] == "object"
    assert intent["additionalProperties"] is False
    assert set(intent["required"]) == {
        "purpose",
        "deployment_context",
        "trust_boundary",
        "trust_boundary_class",
        "powerful_by_design",
    }
    # deployment_context is an enum — narrowing the model's commitment
    # to one of the known contexts is the whole point.
    ctx_enum = set(intent["properties"]["deployment_context"]["enum"])
    expected = {
        "library",
        "cli_tool",
        "admin_endpoint",
        "test_artifact",
        "setup_script",
        "web_handler",
        "build_tool",
        "notebook",
        "other",
    }
    assert ctx_enum == expected
    # v15.21: explicit trust_boundary_class enum
    tbc_enum = set(intent["properties"]["trust_boundary_class"]["enum"])
    assert tbc_enum == {
        "EXTERNAL_UNTRUSTED",
        "INTERNAL_DEVELOPER",
        "LIBRARY_CONSUMER",
    }
    # powerful_by_design is an array of strings (operations).
    pbd = intent["properties"]["powerful_by_design"]
    assert pbd["type"] == "array"
    assert pbd["items"]["type"] == "string"


def test_phase_3_schema_max_three_hypotheses_per_turn() -> None:
    schema = phase_3_loop_hypothesis_batch_schema()
    assert schema["properties"]["hypotheses"]["maxItems"] == al.MAX_HYPOTHESES_PER_TURN


def test_phase_3_schema_targets_profile_observation_is_required() -> None:
    """The profile-anchor field is the structural mechanism preventing
    static-only attack design under context pressure. It MUST be in
    required[] — otherwise the model can omit it and the loop loses its
    runtime-evidence-grounding guarantee."""
    schema = phase_3_loop_hypothesis_batch_schema()
    required = schema["properties"]["hypotheses"]["items"]["required"]
    assert "targets_profile_observation" in required


def test_phase_3_schema_attack_class_includes_exploratory() -> None:
    """``exploratory`` is the attack_class value for probe-kind
    hypotheses (which don't actually claim an exploit)."""
    schema = phase_3_loop_hypothesis_batch_schema()
    enum_list = schema["properties"]["hypotheses"]["items"]["properties"]["attack_class"]["enum"]
    assert "exploratory" in enum_list


def test_phase_3_schema_function_name_pattern_allows_empty() -> None:
    """For stateful_sequence hypotheses, function_name is unused. The
    pattern must allow an empty string or the schema rejects all
    stateful_sequence outputs."""
    schema = phase_3_loop_hypothesis_batch_schema()
    pattern = schema["properties"]["hypotheses"]["items"]["properties"]["function_name"]["pattern"]
    assert re.match(pattern, "") is not None
    assert re.match(pattern, "foo") is not None
    assert re.match(pattern, "MyClass.method") is not None
    assert re.match(pattern, "bad name with spaces") is None


# ── Phase 3 loop prompt builder ───────────────────────────────────────────


def test_build_phase_3_prompt_turn_0_omits_prior_turns_section() -> None:
    prompt = build_phase_3_loop_hypothesis_batch_prompt(
        file_text="def foo(): return 1",
        behavioral_profile={"callables": ["foo"]},
        prior_turns=None,
    )
    assert "PRIOR TURNS" not in prompt


def test_build_phase_3_prompt_renders_behavioral_profile_signals() -> None:
    """The model must SEE the profile signals concretely — not just
    behind a structured handle. Anchoring on observations only works if
    the observations are in the prompt text."""
    prompt = build_phase_3_loop_hypothesis_batch_prompt(
        file_text="def load(x): return open(x).read()",
        behavioral_profile={
            "callables": ["load"],
            "audit_hook_events": ["open(/etc/passwd) in load"],
            "calls_eval_static": False,
        },
        prior_turns=None,
    )
    assert "callables" in prompt
    assert "load" in prompt
    assert "audit_hook_events" in prompt
    assert "open(/etc/passwd)" in prompt


def test_build_phase_3_prompt_with_prior_turns_renders_hypotheses_and_outcomes() -> None:
    prior = [
        {
            "turn_idx": 0,
            "hypotheses": [
                {
                    "kind": "single_function",
                    "function_name": "load",
                    "rationale": "audit hook caught open(/etc/passwd) at load entry",
                }
            ],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "runtime_evidence": "canary file /tmp/argus_probe_pwned created",
                }
            ],
        }
    ]
    prompt = build_phase_3_loop_hypothesis_batch_prompt(
        file_text="def load(x): return open(x).read()",
        behavioral_profile={"callables": ["load"]},
        prior_turns=prior,
    )
    assert "PRIOR TURNS" in prompt
    assert "Turn 0" in prompt
    assert "kind=single_function" in prompt
    assert "target=load" in prompt
    assert "verdict=confirmed" in prompt
    assert "canary file" in prompt


def test_build_phase_3_prompt_signature_rejects_l1_inputs() -> None:
    """Architecture invariant: L1 hypotheses are NOT passed to Phase 3's
    adversarial loop (anchoring contamination — see CLAUDE.md / handoff).
    The builder signature must not accept an L1 parameter, even
    optionally."""
    sig = inspect.signature(build_phase_3_loop_hypothesis_batch_prompt)
    params = set(sig.parameters)
    assert "file_text" in params
    assert "behavioral_profile" in params
    assert "prior_turns" in params
    assert "l1_output" not in params
    assert "l1_hypotheses" not in params


def test_build_phase_3_prompt_emphasizes_profile_anchor_rule() -> None:
    """The prompt body must surface the profile-anchor rule prominently
    so the model doesn't drift to static-only attack design under
    context pressure. Both the structured field name and a prose
    callout must appear."""
    prompt = build_phase_3_loop_hypothesis_batch_prompt(
        file_text="x = 1",
        behavioral_profile={},
        prior_turns=None,
    )
    assert "targets_profile_observation" in prompt
    assert "PROFILE-ANCHOR" in prompt
