"""Unit tests for dast.cross_validation — Gemini auto-validation.

Productionizes the manual cross-validation workflow from the 2026-05-16
mcp-server-fetch eval. Covers prompt construction, response parsing,
and the dispute-detection logic. No live Gemini calls; the API
integration smoke test happens via the engine-level scan.
"""

from __future__ import annotations

from dast.cross_validation import (
    CrossValidationResult,
    DEFAULT_GEMINI_MODEL,
    MAX_SOURCE_BYTES,
    build_cross_validation_prompt,
    is_disputed,
    parse_gemini_response,
)


# ── Prompt construction ─────────────────────────────────────────────────────


def test_prompt_includes_full_source() -> None:
    """Prompt must inline the file source verbatim so Gemini reads
    the actual code, not just the hypothesis claim."""
    source = "def fetch(url):\n    return httpx.get(url)\n"
    prompt = build_cross_validation_prompt(
        hypothesis={"kind": "single_function", "attack_class": "ssrf"},
        trace={"exit_code": 0},
        interpreter_oracle_type="class_signature",
        interpreter_runtime_evidence="match: localhost",
        judge_verdict="CONFIRMED",
        judge_reasoning="judge agreed",
        file_source=source,
        file_name="fetch.py",
    )
    assert "fetch.py" in prompt
    assert "def fetch(url):" in prompt
    assert "httpx.get(url)" in prompt


def test_prompt_includes_hypothesis_fields() -> None:
    """Every hypothesis field needed for cross-validation goes into
    the prompt — Gemini can't validate what it doesn't see."""
    prompt = build_cross_validation_prompt(
        hypothesis={
            "kind": "stateful_sequence",
            "attack_class": "command_injection",
            "function_name": "runShell",
            "args_json": '["evil"]',
            "kwargs_json": "{}",
            "rationale": "uses subprocess",
            "expected_observable": "canary file",
            "rejection_signature": "permission denied",
            "exploit_proof_if_observed": "CWE-78 demonstrated",
        },
        trace={"exit_code": 0},
        interpreter_oracle_type="canary",
        interpreter_runtime_evidence="canary fired",
        judge_verdict="CONFIRMED",
        judge_reasoning="",
        file_source="",
        file_name="x.py",
    )
    assert "stateful_sequence" in prompt
    assert "command_injection" in prompt
    assert "runShell" in prompt
    assert "canary file" in prompt
    assert "CWE-78 demonstrated" in prompt


def test_prompt_includes_argus_verdicts() -> None:
    """Both interpreter + judge verdicts surfaced — Gemini sees
    what Argus concluded, so it can disagree informedly."""
    prompt = build_cross_validation_prompt(
        hypothesis={},
        trace={},
        interpreter_oracle_type="class_signature",
        interpreter_runtime_evidence="evidence text",
        judge_verdict="CONFIRMED",
        judge_reasoning="judge said this",
        file_source="",
        file_name="x.py",
    )
    assert "class_signature" in prompt
    assert "evidence text" in prompt
    assert "CONFIRMED" in prompt
    assert "judge said this" in prompt


def test_prompt_includes_judge_not_run_when_empty() -> None:
    """When judge wasn't run (judge_verdict empty), prompt clearly
    shows that — Gemini shouldn't assume the judge agreed."""
    prompt = build_cross_validation_prompt(
        hypothesis={},
        trace={},
        interpreter_oracle_type="class_signature",
        interpreter_runtime_evidence="",
        judge_verdict="",
        judge_reasoning="",
        file_source="",
        file_name="x.py",
    )
    assert "<not run>" in prompt


def test_prompt_is_not_leading() -> None:
    """Working agreement: Gemini's verdict must be independent.
    Prompt must explicitly tell Gemini it can refute, not just
    confirm. (Smoke check on key non-leading phrases.)"""
    prompt = build_cross_validation_prompt(
        hypothesis={},
        trace={},
        interpreter_oracle_type="",
        interpreter_runtime_evidence="",
        judge_verdict="",
        judge_reasoning="",
        file_source="",
        file_name="x.py",
    )
    # Must enumerate refute / refine as valid outcomes
    assert "refute" in prompt.lower()
    assert "refine" in prompt.lower()
    # Must explicitly tell Gemini not to pre-judge
    assert "DO NOT pre-judge" in prompt or "do not pre-judge" in prompt.lower()


def test_prompt_includes_known_fp_classes() -> None:
    """Prompt must list the empirically-known FP classes (pure-string
    transformation, keyword pattern matching) so Gemini knows what
    to be skeptical of."""
    prompt = build_cross_validation_prompt(
        hypothesis={},
        trace={},
        interpreter_oracle_type="",
        interpreter_runtime_evidence="",
        judge_verdict="",
        judge_reasoning="",
        file_source="",
        file_name="x.py",
    )
    # Empirical FP from mcp-server-fetch
    assert "pure string transformation" in prompt.lower()
    # Common noisy keywords
    assert "localhost" in prompt or "127.0.0.1" in prompt


def test_prompt_asks_for_related_issues() -> None:
    """The 'what did Argus miss' question — Gemini's biggest value-
    add per the mcp-server-fetch eval where it surfaced 4 net-new
    items (redirect-bypass, DNS rebinding, tool-desc-injection, lxml)."""
    prompt = build_cross_validation_prompt(
        hypothesis={},
        trace={},
        interpreter_oracle_type="",
        interpreter_runtime_evidence="",
        judge_verdict="",
        judge_reasoning="",
        file_source="",
        file_name="x.py",
    )
    assert "related_issues_surfaced" in prompt
    assert "ADDITIONAL bugs" in prompt or "OTHER" in prompt


def test_prompt_truncates_oversized_source() -> None:
    """Source > MAX_SOURCE_BYTES must be truncated with a clear
    marker — bounds prompt cost and provides visibility."""
    big_source = "x" * (MAX_SOURCE_BYTES + 1000)
    prompt = build_cross_validation_prompt(
        hypothesis={},
        trace={},
        interpreter_oracle_type="",
        interpreter_runtime_evidence="",
        judge_verdict="",
        judge_reasoning="",
        file_source=big_source,
        file_name="big.py",
    )
    assert "truncated" in prompt.lower()
    assert str(MAX_SOURCE_BYTES) in prompt


def test_prompt_includes_file_purpose_when_provided() -> None:
    """When Argus has done file-intent analysis, surface that so
    Gemini doesn't waste cycles re-deriving it."""
    prompt = build_cross_validation_prompt(
        hypothesis={},
        trace={},
        interpreter_oracle_type="",
        interpreter_runtime_evidence="",
        judge_verdict="",
        judge_reasoning="",
        file_source="",
        file_name="x.py",
        file_purpose="MCP server for fetching URLs",
    )
    assert "MCP server for fetching URLs" in prompt


# ── Response parsing ──────────────────────────────────────────────────────


def test_parse_valid_json_response() -> None:
    """Happy path: valid JSON with all fields populated."""
    raw = """{
        "gemini_verdict": "REFUTED",
        "gemini_reasoning": "Pure string transformation. No side effects.",
        "related_issues_surfaced": [
            "Tool description contains adversarial prompt"
        ],
        "suggested_fix": "Add IP allowlist check"
    }"""
    parsed = parse_gemini_response(raw)
    assert parsed["gemini_verdict"] == "REFUTED"
    assert "pure string" in parsed["gemini_reasoning"].lower()
    assert len(parsed["related_issues_surfaced"]) == 1
    assert parsed["suggested_fix"] == "Add IP allowlist check"


def test_parse_handles_markdown_code_fence() -> None:
    """Gemini sometimes wraps JSON in ```json ... ``` despite explicit
    format requests. Parser must tolerate that."""
    raw = """Sure, here's my analysis:

```json
{
  "gemini_verdict": "CONFIRMED",
  "gemini_reasoning": "Real bug.",
  "related_issues_surfaced": [],
  "suggested_fix": ""
}
```

Hope that helps!"""
    parsed = parse_gemini_response(raw)
    assert parsed["gemini_verdict"] == "CONFIRMED"
    assert parsed["gemini_reasoning"] == "Real bug."


def test_parse_handles_prose_around_json() -> None:
    """Tolerates leading/trailing prose."""
    raw = """My verdict on this hypothesis:

    {"gemini_verdict":"INCONCLUSIVE","gemini_reasoning":"Need more data","related_issues_surfaced":[],"suggested_fix":""}

    Let me know if you want me to elaborate."""
    parsed = parse_gemini_response(raw)
    assert parsed["gemini_verdict"] == "INCONCLUSIVE"


def test_parse_normalizes_unknown_verdict_to_inconclusive() -> None:
    """If Gemini emits something other than the 3 enum values
    (e.g., 'PARTIALLY_CONFIRMED', 'YES', 'NO'), conservatively
    treat as INCONCLUSIVE — don't dispute Argus on garbled input."""
    raw = '{"gemini_verdict":"YES","gemini_reasoning":"x"}'
    parsed = parse_gemini_response(raw)
    assert parsed["gemini_verdict"] == "INCONCLUSIVE"


def test_parse_no_json_in_response() -> None:
    """When Gemini doesn't emit any JSON, return parse-error marker."""
    raw = "I think this finding is real but I can't structure that."
    parsed = parse_gemini_response(raw)
    assert "_parse_error" in parsed


def test_parse_malformed_json() -> None:
    """Broken JSON returns parse-error marker (caller treats as
    INCONCLUSIVE)."""
    raw = '{"gemini_verdict": "REFUTED", "missing_close_brace"'
    parsed = parse_gemini_response(raw)
    assert "_parse_error" in parsed


def test_parse_response_not_object() -> None:
    """JSON that parses but isn't an object (e.g., array, string)
    returns parse-error."""
    raw = '["some", "list"]'
    parsed = parse_gemini_response(raw)
    assert "_parse_error" in parsed


def test_parse_missing_fields_have_safe_defaults() -> None:
    """Partial responses get safe defaults for missing fields."""
    raw = '{"gemini_verdict": "REFUTED"}'
    parsed = parse_gemini_response(raw)
    assert parsed["gemini_verdict"] == "REFUTED"
    assert parsed["gemini_reasoning"] == ""
    assert parsed["related_issues_surfaced"] == []
    assert parsed["suggested_fix"] == ""


def test_parse_related_issues_must_be_list() -> None:
    """If related_issues_surfaced is malformed (string instead of
    list, etc.), default to empty list — never crash."""
    raw = '{"gemini_verdict":"CONFIRMED","related_issues_surfaced":"just one string"}'
    parsed = parse_gemini_response(raw)
    assert parsed["related_issues_surfaced"] == []


# ── Dispute detection ─────────────────────────────────────────────────────


def test_dispute_when_argus_confirmed_gemini_refuted() -> None:
    """The case that matters: Argus CONFIRMED + Gemini REFUTED.
    Empirically the mcp-server-fetch userinfo FP."""
    assert is_disputed(argus_verdict="CONFIRMED", gemini_verdict="REFUTED")


def test_no_dispute_when_both_confirmed() -> None:
    """Agreement is not dispute."""
    assert not is_disputed(argus_verdict="CONFIRMED", gemini_verdict="CONFIRMED")


def test_no_dispute_when_gemini_inconclusive() -> None:
    """Gemini being unsure doesn't mean Argus is wrong — leave
    Argus's verdict standing."""
    assert not is_disputed(argus_verdict="CONFIRMED", gemini_verdict="INCONCLUSIVE")


def test_dispute_case_insensitive() -> None:
    """Case variants don't break the comparison."""
    assert is_disputed(argus_verdict="confirmed", gemini_verdict="refuted")
    assert is_disputed(argus_verdict="Confirmed", gemini_verdict="Refuted")


# ── CrossValidationResult shape ───────────────────────────────────────────


def test_result_defaults_are_sane() -> None:
    """Dataclass defaults should let callers construct minimal
    results without surprises (e.g., for error paths)."""
    r = CrossValidationResult(
        finding_id="X",
        gemini_verdict="INCONCLUSIVE",
        gemini_reasoning="couldn't analyze",
        disputed=False,
    )
    assert r.related_issues_surfaced == []
    assert r.suggested_fix == ""
    assert r.cost_usd == 0.0
    assert r.duration_ms == 0
    assert r.error == ""


def test_default_gemini_model_is_pro_tier() -> None:
    """Cross-validation needs the deepest-reasoning model — using
    Flash would defeat the purpose (it would miss the subtle FPs).
    Lock in Pro as default."""
    assert "pro" in DEFAULT_GEMINI_MODEL.lower()
