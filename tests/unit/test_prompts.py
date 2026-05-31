"""Schema regression for prose-length caps in dast/prompts.py.

Argus DAST schemas constrain free-text fields (rationale,
expected_observable, exploit_proof_if_observed, judge_reasoning, etc.)
with ``maxLength`` caps. These caps must accommodate the natural prose
length Opus 4.6 emits at temperature 0 — when Opus exceeds the cap,
``jsonschema.validate`` fails inside :func:`dast.inference.parse_anthropic_response`
and the response is dropped with ``schema_valid=False``. Per SCAN-008
fail-open, the scan continues but the hypothesis / judge verdict is
lost — degrading quality without operator-visible failure.

These tests round-trip representative Opus-style multi-sentence
reasoning through the production schemas. Lengths are calibrated from
real prod traces (.argus_local/v15_validation/synthetic_phase_d_v4):

* judge_reasoning: ~750 chars when Opus cites parsed_result + side
  effect markers + canary evidence
* hypothesis rationale: ~600-900 chars when the model justifies
  trust-boundary bypass
* expected_observable: ~400-700 chars for multi-step canary chains

If a future schema tightening drops a prose cap below ~1500 these
tests should fail loudly rather than silently degrading scan quality.
"""

from __future__ import annotations

from typing import Any, Callable

import jsonschema
import pytest

from dast.prompts import (
    phase_3_loop_hypothesis_batch_schema,
    phase_b_chain_schema,
    phase_b_refinement_schema,
    phase_b_runtime_probe_schema,
    post_trace_judge_schema,
)

# Representative Opus 4.6 prose at temp=0 — sampled from a real Phase D
# validation scan against synthetic_phase_d_v4. ~900 chars; covers the
# multi-sentence justification + trace-evidence-citation shape the
# model emits when asked to explain a CONFIRMED ssrf finding.
_OPUS_STYLE_LONG_RATIONALE = (
    "fetch_url uses urllib.request.urlopen with zero URL validation. "
    "The file:// scheme allows reading local files, and the profile "
    "shows the function is invoked directly from an unauthenticated "
    "web handler at line 47 (req_handler.dispatch -> fetch_url(url)). "
    "Trust boundary: web requests reach this function pre-auth via "
    "the public /preview endpoint. Bypass: the URL string flows "
    "unvalidated from request.GET['target'] into urlopen, so an "
    "attacker can pivot from the public endpoint into the loopback "
    "metadata service (169.254.169.254) or read /etc/passwd via the "
    "file:// handler. This is a classic SSRF where the dangerous "
    "operation (urlopen on attacker-controlled URL) is reachable "
    "from outside the file's intended trust boundary."
)

_OPUS_STYLE_LONG_JUDGE_REASONING = (
    "The function `fetch_url` successfully processed a `data:` URI "
    "and returned the embedded attacker-controlled content "
    "'SSRF_DATA_EXFIL_PROOF' (ok=true, exit_code=0). The "
    "parsed_result.value_preview shows the canary string verbatim, "
    "confirming the urlopen call completed and the response body "
    "was returned to the caller. side_effects.network shows no "
    "outbound call (data: URIs are handled in-process by urllib), "
    "but the canary in the return value is unambiguous evidence the "
    "scheme handler fired. No rejection_signature pattern matched: "
    "no exception was raised, no defensive ValueError, no URL-scheme "
    "allowlist check. This is a clean CONFIRMED — the dangerous "
    "operation executed and produced observable output."
)

_OPUS_STYLE_LONG_OBSERVABLE = (
    "function returns a string containing the canary token "
    "'ARGUS_PROBE_SSRF_PROOF_42' which was embedded in the attack "
    "URL's path component, indicating urlopen successfully fetched "
    "and returned the response body. parsed_result.ok will be true "
    "and parsed_result.value_preview will contain the canary "
    "substring. side_effects may also show an outbound network "
    "request to the sandbox's test fixture host."
)


# ── phase_b_runtime_probe_schema ─────────────────────────────────────────


def _valid_probe_candidate() -> dict[str, Any]:
    """Minimal valid Phase B runtime-probe response shape."""
    return {
        "non_probable_reason": "",
        "candidates": [
            {
                "function_name": "fetch_url",
                "attack_class": "ssrf",
                "rationale": "stub",
                "test_inputs": [
                    {
                        "args_json": '["http://169.254.169.254/latest/meta-data/"]',
                        "kwargs_json": "{}",
                        "expected_observable": "stub",
                        "rejection_signature": "stub",
                        "assertion_expr": "",
                        "exploit_proof_if_observed": "stub",
                    }
                ],
            }
        ],
    }


def test_phase_b_probe_schema_accepts_opus_length_rationale() -> None:
    """Candidate rationale must accommodate Opus's multi-sentence
    trust-boundary-bypass justification (~900 chars in prod traces)."""
    instance = _valid_probe_candidate()
    instance["candidates"][0]["rationale"] = _OPUS_STYLE_LONG_RATIONALE
    jsonschema.validate(instance=instance, schema=phase_b_runtime_probe_schema())


def test_phase_b_probe_schema_accepts_opus_length_observables() -> None:
    """expected_observable / rejection_signature / exploit_proof must
    accept Opus's prose-form trace descriptions."""
    instance = _valid_probe_candidate()
    test_input = instance["candidates"][0]["test_inputs"][0]
    test_input["expected_observable"] = _OPUS_STYLE_LONG_OBSERVABLE
    test_input["rejection_signature"] = _OPUS_STYLE_LONG_OBSERVABLE
    test_input["exploit_proof_if_observed"] = _OPUS_STYLE_LONG_OBSERVABLE
    jsonschema.validate(instance=instance, schema=phase_b_runtime_probe_schema())


# ── phase_b_refinement_schema ────────────────────────────────────────────


def test_phase_b_refinement_schema_accepts_opus_length_rationale() -> None:
    """Refinement rationale (explaining which prior failure mode this
    input addresses) must fit Opus's multi-sentence answers."""
    instance = {
        "non_refinable_reason": "",
        "refined_inputs": [
            {
                "args_json": '["..%2F..%2Fetc%2Fpasswd"]',
                "kwargs_json": "{}",
                "rationale": _OPUS_STYLE_LONG_RATIONALE,
            }
        ],
    }
    jsonschema.validate(instance=instance, schema=phase_b_refinement_schema())


def test_phase_b_refinement_schema_accepts_opus_length_non_refinable() -> None:
    """non_refinable_reason can run long when Opus explains why no
    refinement is feasible (e.g., all failures were ImportError on
    missing optional dependency)."""
    instance = {
        "non_refinable_reason": _OPUS_STYLE_LONG_RATIONALE,
        "refined_inputs": [],
    }
    jsonschema.validate(instance=instance, schema=phase_b_refinement_schema())


# ── phase_b_chain_schema ─────────────────────────────────────────────────


def test_phase_b_chain_schema_accepts_opus_length_prose() -> None:
    """Chain rationale + observable + proof fields must all accommodate
    Opus's multi-sentence explanation of the multi-step exploit."""
    instance = {
        "no_chains_reason": "",
        "chains": [
            {
                "steps": [
                    {
                        "function_name": "save_upload",
                        "args_json": '["payload"]',
                        "kwargs_json": "{}",
                    },
                    {
                        "function_name": "render_template",
                        "args_json": '["uploaded"]',
                        "kwargs_json": "{}",
                    },
                ],
                "attack_class": "code_injection",
                "rationale": _OPUS_STYLE_LONG_RATIONALE,
                "expected_observable": _OPUS_STYLE_LONG_OBSERVABLE,
                "exploit_proof_if_observed": _OPUS_STYLE_LONG_OBSERVABLE,
            }
        ],
    }
    jsonschema.validate(instance=instance, schema=phase_b_chain_schema())


def test_phase_b_chain_schema_accepts_opus_length_no_chains_reason() -> None:
    instance = {
        "no_chains_reason": _OPUS_STYLE_LONG_RATIONALE,
        "chains": [],
    }
    jsonschema.validate(instance=instance, schema=phase_b_chain_schema())


# ── phase_3_loop_hypothesis_batch_schema ─────────────────────────────────


def test_phase_3_loop_hypothesis_schema_accepts_opus_length_prose() -> None:
    """Adversarial-loop hypothesis rationale + observables must fit
    Opus's multi-sentence outputs. This was the schema flagged in the
    v15_validation/synthetic_phase_d_v4 stderr — Opus's trust-boundary
    rationale exceeded the prior 500-char cap and the entire hypothesis
    was dropped (fail-open per SCAN-008)."""
    instance = {
        "code_intent_analysis": {
            "purpose": "Library exposing URL fetcher for downstream callers.",
            "deployment_context": "library",
            "trust_boundary": "Called from public web handler pre-auth.",
            "trust_boundary_class": "EXTERNAL_UNTRUSTED",
            "powerful_by_design": [],
        },
        "no_new_hypotheses": False,
        "hypotheses": [
            {
                "language": "python",
                "kind": "single_function",
                "rationale": _OPUS_STYLE_LONG_RATIONALE,
                "targets_profile_observation": (
                    "profile shows urllib.request.urlopen invoked at line 47"
                ),
                "attack_class": "ssrf",
                "confidence_prior": "HIGH",
                "expected_observable": _OPUS_STYLE_LONG_OBSERVABLE,
                "assertion_expr": (
                    "str(getattr(result, 'host', '')).startswith('169.254.')"
                ),
                "exploit_proof_if_observed": _OPUS_STYLE_LONG_OBSERVABLE,
                "function_name": "fetch_url",
                "args_json": '["http://169.254.169.254/"]',
                "kwargs_json": "{}",
                "sequence": [],
            }
        ],
    }
    jsonschema.validate(instance=instance, schema=phase_3_loop_hypothesis_batch_schema())


# ── post_trace_judge_schema (Strategy-C) ─────────────────────────────────


def test_post_trace_judge_schema_accepts_opus_length_reasoning() -> None:
    """judge_reasoning must accommodate Opus citing parsed_result, side
    effects, and exception-class evidence (~750 chars in prod traces).
    The v15_validation/synthetic_phase_d_v4 scan observed Opus's
    reasoning exceed the prior 600-char cap, causing the judge call to
    fail schema validation and the verdict to be dropped."""
    instance = {
        "judge_verdict": "CONFIRMED",
        "judge_reasoning": _OPUS_STYLE_LONG_JUDGE_REASONING,
        "evidence_strength": "high",
    }
    jsonschema.validate(instance=instance, schema=post_trace_judge_schema())


# ── Cap-floor regression guard ───────────────────────────────────────────
#
# Calibrated against measured Opus 4.6 outputs. If a future change drops
# a prose cap below this floor it likely re-introduces the silent
# schema-validation failure mode. The test names the schema so the
# failure points directly at the regression.


_PROSE_CAP_FLOOR = 1500


@pytest.mark.parametrize(
    "schema_fn, prose_paths",
    [
        (
            phase_b_runtime_probe_schema,
            [
                ("properties", "candidates", "items", "properties", "rationale"),
                (
                    "properties",
                    "candidates",
                    "items",
                    "properties",
                    "test_inputs",
                    "items",
                    "properties",
                    "expected_observable",
                ),
                (
                    "properties",
                    "candidates",
                    "items",
                    "properties",
                    "test_inputs",
                    "items",
                    "properties",
                    "rejection_signature",
                ),
                (
                    "properties",
                    "candidates",
                    "items",
                    "properties",
                    "test_inputs",
                    "items",
                    "properties",
                    "exploit_proof_if_observed",
                ),
            ],
        ),
        (
            phase_b_refinement_schema,
            [
                ("properties", "non_refinable_reason"),
                (
                    "properties",
                    "refined_inputs",
                    "items",
                    "properties",
                    "rationale",
                ),
            ],
        ),
        (
            phase_b_chain_schema,
            [
                ("properties", "no_chains_reason"),
                ("properties", "chains", "items", "properties", "rationale"),
                (
                    "properties",
                    "chains",
                    "items",
                    "properties",
                    "expected_observable",
                ),
                (
                    "properties",
                    "chains",
                    "items",
                    "properties",
                    "exploit_proof_if_observed",
                ),
            ],
        ),
        (
            phase_3_loop_hypothesis_batch_schema,
            [
                ("properties", "hypotheses", "items", "properties", "rationale"),
                (
                    "properties",
                    "hypotheses",
                    "items",
                    "properties",
                    "expected_observable",
                ),
                (
                    "properties",
                    "hypotheses",
                    "items",
                    "properties",
                    "exploit_proof_if_observed",
                ),
            ],
        ),
        (
            post_trace_judge_schema,
            [
                ("properties", "judge_reasoning"),
            ],
        ),
    ],
)
def test_prose_cap_floor(
    schema_fn: Callable[[], dict[str, Any]],
    prose_paths: list[tuple[str, ...]],
) -> None:
    """Every prose field must have at least :data:`_PROSE_CAP_FLOOR`
    chars of headroom. Calibrated against measured Opus 4.6 output;
    drops below this floor cause silent schema-validation failures."""
    schema = schema_fn()
    for path in prose_paths:
        node = schema
        for key in path:
            node = node[key]
        cap = node.get("maxLength")
        assert cap is not None, f"{schema_fn.__name__}: {'.'.join(path)} missing maxLength"
        assert cap >= _PROSE_CAP_FLOOR, (
            f"{schema_fn.__name__}: {'.'.join(path)} maxLength={cap} "
            f"below {_PROSE_CAP_FLOOR}-char floor — likely to silently "
            f"reject Opus prose outputs (see SCAN-008 fail-open path)."
        )
