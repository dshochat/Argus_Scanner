"""Unit tests for scanner.runners — score-to-verdict mapping, cost math,
and JSON-parse-failure handling. Adapter is stubbed; no live API."""

from __future__ import annotations

from typing import Any

import pytest

from scanner.runners import (
    derive_uncertainty,
    make_anthropic_runner_from_adapter,
    make_triage_runner_from_adapter,
    score_to_verdict,
    with_confirm_clean,
)


class _FakeAdapter:
    """Minimal stub matching the adapter.scan(...) coroutine shape."""

    def __init__(self, response: dict) -> None:
        self._response = response
        self.calls: list[tuple[str, str]] = []

    async def scan(self, content: str, filename: str, system_prompt: str) -> dict:
        self.calls.append((filename, system_prompt[:40]))
        return self._response


def _adapter_response(
    *,
    score: int | None = 50,
    json_valid: bool = True,
    in_tokens: int = 1000,
    out_tokens: int = 500,
    duration_ms: int = 1200,
    extra_parsed: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict:
    parsed: dict[str, Any] | None
    if json_valid:
        parsed = {"composite_risk": {"score": score, "exploitability": "medium"}}
        if extra_parsed:
            parsed.update(extra_parsed)
    else:
        parsed = None
    return {
        "raw_response": "stub",
        "parsed": parsed,
        "input_tokens": in_tokens,
        "output_tokens": out_tokens,
        "response_time_ms": duration_ms,
        "json_valid": json_valid,
        "error": error,
    }


# ── score_to_verdict ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, "clean"),
        (1, "suspicious"),
        (24, "suspicious"),
        (25, "suspicious"),
        (49, "suspicious"),
        (50, "malicious"),
        (74, "malicious"),
        (75, "critical_malicious"),
        (100, "critical_malicious"),
        (None, "suspicious"),  # missing → conservative
        ("garbage", "suspicious"),  # malformed → conservative
    ],
)
def test_score_to_verdict_boundaries(score: Any, expected: str) -> None:
    assert score_to_verdict(score) == expected


# ── derive_uncertainty (SCAN-004) ──────────────────────────────────────────


def test_uncertainty_clean_verdict_zero() -> None:
    """No vulns + score 0 (clean) → unambiguous, uncertainty 0."""
    parsed = {"vulnerabilities": [], "composite_risk": {"score": 0}}
    assert derive_uncertainty(parsed) == pytest.approx(0.0)


def test_uncertainty_critical_extreme_zero() -> None:
    """No vulns surfaced + score 100 (rare but possible) → unambiguous."""
    parsed = {"vulnerabilities": [], "composite_risk": {"score": 100}}
    assert derive_uncertainty(parsed) == pytest.approx(0.0)


def test_uncertainty_high_confidence_findings_low_uncertainty() -> None:
    """All findings confidence 0.95 + score in middle of band → low total."""
    parsed = {
        "vulnerabilities": [
            {"type": "x", "confidence": 0.95},
            {"type": "y", "confidence": 0.95},
        ],
        "composite_risk": {"score": 87},  # well into critical_malicious band
    }
    out = derive_uncertainty(parsed)
    # 1 - 0.95 = 0.05 finding uncertainty
    # boundary distance: |87-75| = 12 → close to 75 cutoff
    # boundary_uncertainty = max(0, 1 - 12/12.5) = 0.04
    assert out == pytest.approx(0.05, abs=0.01)


def test_uncertainty_low_confidence_findings_high_uncertainty() -> None:
    """Findings with confidence 0.4 → high finding uncertainty regardless
    of score position."""
    parsed = {
        "vulnerabilities": [
            {"type": "x", "confidence": 0.4},
            {"type": "y", "confidence": 0.4},
        ],
        "composite_risk": {"score": 60},
    }
    out = derive_uncertainty(parsed)
    # finding_uncertainty = 1 - 0.4 = 0.6
    assert out >= 0.6


def test_uncertainty_score_on_boundary_high_uncertainty() -> None:
    """Score exactly on a verdict cutoff → boundary uncertainty 1.0
    even with high-confidence findings."""
    parsed = {
        "vulnerabilities": [{"type": "x", "confidence": 0.99}],
        "composite_risk": {"score": 50},  # exact boundary suspicious↔malicious
    }
    out = derive_uncertainty(parsed)
    assert out == pytest.approx(1.0)


def test_uncertainty_score_mid_band_low_uncertainty() -> None:
    """Score in the middle of a band (e.g., 37 = mid suspicious) →
    low boundary uncertainty."""
    parsed = {
        "vulnerabilities": [{"type": "x", "confidence": 0.9}],
        "composite_risk": {"score": 37},  # mid suspicious band (25-50)
    }
    out = derive_uncertainty(parsed)
    # boundary distance: |37-50| = 13 (out of band, so 0)
    # finding_uncertainty: 0.1
    assert out == pytest.approx(0.1, abs=0.05)


def test_uncertainty_handles_missing_or_malformed_data() -> None:
    assert derive_uncertainty({}) == 0.0
    assert derive_uncertainty({"vulnerabilities": None, "composite_risk": None}) == 0.0
    assert (
        derive_uncertainty(
            {"vulnerabilities": [{"type": "x"}], "composite_risk": {"score": "garbage"}}
        )
        >= 0.0
    )


@pytest.mark.asyncio
async def test_runner_threads_derived_uncertainty_through() -> None:
    """The analysis runner must surface the derived uncertainty in its
    output dict so the engine can compare against the threshold."""
    adapter = _FakeAdapter(
        _adapter_response(
            score=50,  # exact boundary → uncertainty 1.0
            extra_parsed={"vulnerabilities": [{"type": "x", "confidence": 0.9}]},
        )
    )
    runner = make_anthropic_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    out = await runner("a.py", b"x", None, "HIGH")
    assert out["uncertainty"] == pytest.approx(1.0)


# ── runner output mapping ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_runner_maps_score_to_malicious() -> None:
    adapter = _FakeAdapter(
        _adapter_response(
            score=60,
            extra_parsed={
                "vulnerabilities": [{"type": "command_injection", "severity": "high"}],
                "behavioral_profile": {"sensitivity": "high"},
                "attack_chains": [{"name": "shell_to_exfil"}],
                "ai_tool_analysis": {"is_ai_tool": False},
            },
        )
    )
    runner = make_anthropic_runner_from_adapter(
        adapter,
        model_label="test-sonnet",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    out = await runner("evil.py", b"import os", None, "HIGH")

    assert out["verdict_label"] == "malicious"
    assert out["vulnerabilities"] == [{"type": "command_injection", "severity": "high"}]
    assert out["behavioral_profile"] == {"sensitivity": "high"}
    assert out["attack_chains"] == [{"name": "shell_to_exfil"}]
    assert out["ai_tool_analysis"] == {"is_ai_tool": False}
    assert out["model"] == "test-sonnet"
    # SCAN-004: score=60 sits 10 from the 50 boundary (within the 12.5
    # half-width); vulns have no confidence field. Uncertainty is
    # boundary-driven: max(0, 1 - 10/12.5) = 0.2.
    assert out["uncertainty"] == pytest.approx(0.2, abs=0.01)


@pytest.mark.asyncio
async def test_runner_cost_math() -> None:
    """1000 input × $3/M + 500 output × $15/M = 0.003 + 0.0075 = 0.0105."""
    adapter = _FakeAdapter(_adapter_response(in_tokens=1000, out_tokens=500))
    runner = make_anthropic_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    out = await runner("a.py", b"x", None, "HIGH")
    assert out["input_tokens"] == 1000
    assert out["output_tokens"] == 500
    assert out["cost_usd"] == pytest.approx(0.0105)
    assert out["duration_ms"] == 1200


@pytest.mark.asyncio
async def test_runner_json_parse_failure_returns_suspicious_with_error() -> None:
    adapter = _FakeAdapter(_adapter_response(json_valid=False, in_tokens=200, out_tokens=50))
    runner = make_anthropic_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    out = await runner("a.py", b"x", None, "HIGH")

    # Parse failure must NOT raise — graceful degrade to suspicious + empty
    # findings, but cost telemetry still flows so guardrails work.
    assert out["verdict_label"] == "suspicious"
    assert out["vulnerabilities"] == []
    assert out["behavioral_profile"] == {}
    assert out["input_tokens"] == 200
    assert out["output_tokens"] == 50
    assert out["cost_usd"] > 0
    # Surfaces the parse failure as a runner error so the engine can
    # distinguish "model said suspicious" from "model output unparseable
    # and we fell back to suspicious". Without this, parse failures
    # silently downgraded the verdict AND skipped DAST.
    assert out["error"] is not None
    assert "json_parse_failed" in out["error"]
    assert "out_tokens=50" in out["error"]


@pytest.mark.asyncio
async def test_runner_sanitizes_provider_name_leak_in_vuln() -> None:
    """SCAN-009: a soft provider-name leak in a vulnerability field is
    sanitized inline; the runner returns the cleaned dict with no error."""
    adapter = _FakeAdapter(
        _adapter_response(
            score=60,
            extra_parsed={
                "vulnerabilities": [
                    {
                        "type": "code_injection",
                        "severity": "critical",
                        "explanation": "The Claude model could be tricked here.",
                    }
                ],
            },
        )
    )
    runner = make_anthropic_runner_from_adapter(
        adapter,
        model_label="test-sonnet",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    out = await runner("v.py", b"x", None, "HIGH")

    assert out["verdict_label"] == "malicious"
    # Provider name redacted in the explanation
    assert "[redacted]" in out["vulnerabilities"][0]["explanation"].lower()
    assert "claude" not in out["vulnerabilities"][0]["explanation"].lower()
    # Soft leak is not a runner error
    assert out["error"] is None


@pytest.mark.asyncio
async def test_runner_hard_identity_leak_returns_suspicious_with_error() -> None:
    """SCAN-009: a hard identity leak (e.g., 'as a language model') in a
    structured field forces sanitize_response to return None. Runner
    falls back to suspicious with explicit error."""
    adapter = _FakeAdapter(
        _adapter_response(
            score=80,  # would be critical_malicious if accepted
            extra_parsed={
                "vulnerabilities": [
                    {
                        "type": "code_injection",
                        "explanation": "As a large language model, I see exec().",
                    }
                ],
            },
        )
    )
    runner = make_anthropic_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    out = await runner("v.py", b"x", None, "HIGH")

    # Hard leak → fallback verdict + error surfaced
    assert out["verdict_label"] == "suspicious"
    assert out["vulnerabilities"] == []
    assert out["error"] == "identity_leak_in_response"


@pytest.mark.asyncio
async def test_runner_propagates_adapter_error_over_parse_status() -> None:
    """If the adapter itself reported an error, that takes precedence
    over the json_parse_failed synthetic error — adapter-level errors
    are more informative."""
    adapter = _FakeAdapter(
        _adapter_response(json_valid=False, in_tokens=10, out_tokens=10, error="rate_limited")
    )
    runner = make_anthropic_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    out = await runner("a.py", b"x", None, "HIGH")
    assert out["error"] == "rate_limited"


@pytest.mark.asyncio
async def test_runner_decodes_invalid_utf8() -> None:
    adapter = _FakeAdapter(_adapter_response(score=0))
    runner = make_anthropic_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
    )
    # Invalid UTF-8 bytes must not crash the runner — replaced silently.
    out = await runner("bin.py", b"\xff\xfe\xfdvalid_text", None, "HIGH")
    assert out["verdict_label"] == "clean"
    # Adapter received the (replacement-decoded) string
    assert "valid_text" in adapter.calls[0][0] or len(adapter.calls) == 1


# ── triage runner ──────────────────────────────────────────────────────────


def _triage_response(
    *,
    classification: str | None = "HIGH",
    reason: str = "test reason",
    confidence: float | None = 1.0,
    json_valid: bool = True,
    in_tokens: int = 100,
    out_tokens: int = 20,
    duration_ms: int = 800,
) -> dict:
    if json_valid:
        parsed: dict[str, Any] | None = {
            "classification": classification,
            "reason": reason,
        }
        if confidence is not None:
            parsed["confidence"] = confidence
    else:
        parsed = None
    return {
        "raw_response": "stub",
        "parsed": parsed,
        "input_tokens": in_tokens,
        "output_tokens": out_tokens,
        "response_time_ms": duration_ms,
        "json_valid": json_valid,
        "error": None,
    }


@pytest.mark.parametrize("classification", ["CLEAN", "LOW", "HIGH"])
@pytest.mark.asyncio
async def test_triage_runner_passes_valid_classifications(classification: str) -> None:
    adapter = _FakeAdapter(_triage_response(classification=classification))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test-flash-lite",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("ok.py", b"print('hi')", None)
    assert out["classification"] == classification
    assert out["model"] == "test-flash-lite"
    assert out["reason"] == "test reason"


@pytest.mark.asyncio
async def test_triage_runner_invalid_classification_defaults_high() -> None:
    """Anything outside CLEAN/LOW/HIGH must safety-net to HIGH."""
    adapter = _FakeAdapter(_triage_response(classification="MAYBE"))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("a.py", b"x", None)
    assert out["classification"] == "HIGH"


@pytest.mark.asyncio
async def test_triage_runner_json_parse_failure_defaults_high() -> None:
    adapter = _FakeAdapter(_triage_response(json_valid=False, in_tokens=80, out_tokens=10))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("a.py", b"x", None)
    assert out["classification"] == "HIGH"
    assert out["reason"] == ""
    # Cost telemetry still flows so guardrails work
    assert out["input_tokens"] == 80
    assert out["output_tokens"] == 10
    assert out["cost_usd"] > 0


@pytest.mark.asyncio
async def test_triage_runner_cost_math() -> None:
    """100 in × $0.10/M + 20 out × $0.40/M = 0.00001 + 0.000008 = 0.000018."""
    adapter = _FakeAdapter(_triage_response(in_tokens=100, out_tokens=20))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("a.py", b"x", None)
    assert out["cost_usd"] == pytest.approx(0.000018)
    assert out["duration_ms"] == 800


# ── v15.23: confidence + security-marker bias on triage ────────────────────


@pytest.mark.asyncio
async def test_v1523_triage_passes_confidence_field_through() -> None:
    """High-confidence classifications pass through unchanged; the
    confidence field is surfaced on the returned dict for downstream
    observability."""
    adapter = _FakeAdapter(_triage_response(classification="HIGH", confidence=0.95))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("a.py", b"x = 1\n", None)
    assert out["classification"] == "HIGH"
    assert out["confidence"] == pytest.approx(0.95)
    assert out["bumps_applied"] == []


@pytest.mark.asyncio
async def test_v1523_low_confidence_escalates_clean_to_low() -> None:
    """Sonnet says CLEAN/0.4 — auto-escalates to LOW. Low-confidence
    CLEAN was the silent-failure mode the campaign exposed."""
    adapter = _FakeAdapter(_triage_response(classification="CLEAN", confidence=0.4))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("a.py", b"x = 1\n", None)
    assert out["classification"] == "LOW"
    assert any("confidence" in b for b in out["bumps_applied"])


@pytest.mark.asyncio
async def test_v1523_low_confidence_escalates_low_to_high() -> None:
    """Low-confidence LOW → HIGH. Borderline cases shouldn't silently
    take the cheap-L1 path when the model itself isn't sure."""
    adapter = _FakeAdapter(_triage_response(classification="LOW", confidence=0.5))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("a.py", b"x = 1\n", None)
    assert out["classification"] == "HIGH"


@pytest.mark.asyncio
async def test_v1523_low_confidence_high_stays_high() -> None:
    """Low-confidence HIGH stays HIGH (already at the top tier)."""
    adapter = _FakeAdapter(_triage_response(classification="HIGH", confidence=0.5))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("a.py", b"x = 1\n", None)
    assert out["classification"] == "HIGH"
    # No bump applied (already at HIGH)
    assert not any("confidence" in b for b in out["bumps_applied"])


@pytest.mark.asyncio
async def test_v1523_missing_confidence_defaults_to_one() -> None:
    """Legacy outputs without ``confidence`` get 1.0 — no auto-escalation,
    pre-v15.23 behavior preserved."""
    adapter = _FakeAdapter(_triage_response(classification="CLEAN", confidence=None))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("clean.py", b"x = 1\n", None)
    assert out["confidence"] == pytest.approx(1.0)
    assert out["classification"] == "CLEAN"


@pytest.mark.asyncio
async def test_v1523_security_marker_bias_bumps_clean_to_low(tmp_path) -> None:
    """File imports hashlib + has API key string → score>=1 → CLEAN
    bumps to LOW. Single marker is borderline; bias intentionally
    soft on 1-marker matches."""
    # Use one weight-1 marker (urllib) only — score=1
    content = (
        b"import urllib.request\n"
        b"def fetch(u):\n    return urllib.request.urlopen(u).read()\n"
    )
    adapter = _FakeAdapter(_triage_response(classification="CLEAN", confidence=0.95))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("util.py", content, None)
    assert out["classification"] == "LOW"
    assert out["security_marker_score"] >= 1
    assert any("security_markers" in b for b in out["bumps_applied"])


@pytest.mark.asyncio
async def test_v1523_security_marker_high_signal_bumps_to_high(tmp_path) -> None:
    """File matches multiple high-weight markers (boto3 + Credentials
    class + secret_key attr + Authorization header) → score >= 3 →
    bump to HIGH regardless of model classification."""
    content = (
        b"import boto3\n"
        b"from cryptography.hazmat.primitives import hashes\n"
        b"class AwsCredentials:\n"
        b"    aws_secret_key: str | None\n"
        b"    def sign(self, req):\n"
        b"        req.headers['Authorization'] = 'Bearer ' + self.aws_secret_key\n"
    )
    adapter = _FakeAdapter(_triage_response(classification="CLEAN", confidence=0.95))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("creds.py", content, None)
    assert out["classification"] == "HIGH"
    assert out["security_marker_score"] >= 3


@pytest.mark.asyncio
async def test_v1523_security_marker_bias_never_downgrades(tmp_path) -> None:
    """Even a file with security markers shouldn't be DOWNGRADED if
    the model said HIGH. The bias is always a raising operation."""
    content = (
        b"import boto3\n"
        b"from cryptography.hazmat.primitives import hashes\n"
        b"class AwsCredentials: aws_secret_key: str\n"
    )
    adapter = _FakeAdapter(_triage_response(classification="HIGH", confidence=0.95))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("creds.py", content, None)
    # Stays HIGH
    assert out["classification"] == "HIGH"


def test_v1523_security_marker_score_pure_data_file() -> None:
    """Pure data / no-import file scores 0 — bias never fires on
    code that doesn't import anything security-relevant."""
    from scanner.runners import _compute_security_marker_score

    score, matched = _compute_security_marker_score(
        "x = 1\ny = 'hello'\ndef add(a, b): return a + b\n"
    )
    assert score == 0
    assert matched == []


def test_v1523_security_marker_score_auth_file_high_signal() -> None:
    """Auth file with boto3 + Credentials + secret_key + Authorization
    scores >= 3. Verifies the canonical anthropic-sdk-python failure
    pattern would now route to HIGH."""
    from scanner.runners import _compute_security_marker_score

    text = (
        "import boto3\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "class AwsCredentials:\n"
        "    aws_secret_key: str | None = None\n"
        "def sign(req):\n"
        "    req.headers['Authorization'] = 'Bearer abc'\n"
    )
    score, matched = _compute_security_marker_score(text)
    assert score >= 3, f"expected score>=3, got {score}; matched: {matched}"


def test_v1523_security_marker_score_url_handler_minimum_one() -> None:
    """File that takes base_url + uses requests qualifies for the LOW
    bias (score>=1) — at minimum doesn't route CLEAN."""
    from scanner.runners import _compute_security_marker_score

    text = (
        "import requests\n"
        "def fetch(base_url: str, token: str):\n"
        "    return requests.get(base_url, headers={'X-Auth-Token': token})\n"
    )
    score, _ = _compute_security_marker_score(text)
    assert score >= 1


@pytest.mark.asyncio
async def test_v1523_combined_low_conf_and_security_markers() -> None:
    """Low-confidence CLEAN + security markers stack: first the
    confidence bump fires (CLEAN→LOW), then the marker bump fires
    (LOW→HIGH if score≥3). Defense-in-depth."""
    content = (
        b"import boto3\n"
        b"from cryptography.hazmat.primitives import hashes\n"
        b"class AwsCredentials: aws_secret_key: str\n"
    )
    adapter = _FakeAdapter(_triage_response(classification="CLEAN", confidence=0.4))
    runner = make_triage_runner_from_adapter(
        adapter,
        model_label="test",
        cost_per_m_input=0.10,
        cost_per_m_output=0.40,
    )
    out = await runner("creds.py", content, None)
    assert out["classification"] == "HIGH"
    # Both bumps recorded
    assert len(out["bumps_applied"]) == 2


# ── v15.8 Gap 3: confirm-clean triage wrapper ───────────────────────────────


def _make_scripted_triage_runner(classifications: list[str]):
    """Return a triage runner that yields successive classifications from
    the given list. Each call pops the next one (caller controls order)."""
    calls = {"n": 0}

    async def runner(filename: str, content: bytes, pp):
        idx = calls["n"]
        calls["n"] += 1
        cls = classifications[min(idx, len(classifications) - 1)]
        return {
            "classification": cls,
            "reason": f"call_{idx}",
            "model": "stub",
            "input_tokens": 100,
            "output_tokens": 20,
            "cost_usd": 0.001,
            "duration_ms": 50,
            "error": None,
        }

    return runner, calls


@pytest.mark.asyncio
async def test_confirm_clean_non_clean_passes_through_unchanged() -> None:
    """v15.8 Gap 3: when the first call returns LOW or HIGH, the wrapper
    does NOT make a second call — those are already conservative."""
    base, calls = _make_scripted_triage_runner(["LOW"])
    wrapped = with_confirm_clean(base)
    out = await wrapped("x.py", b"x", None)
    assert out["classification"] == "LOW"
    assert calls["n"] == 1
    assert out["triage_runs"] == 1
    assert out["triage_classifications_all"] == ["LOW"]


@pytest.mark.asyncio
async def test_confirm_clean_high_passes_through_unchanged() -> None:
    base, calls = _make_scripted_triage_runner(["HIGH"])
    wrapped = with_confirm_clean(base)
    out = await wrapped("x.py", b"x", None)
    assert out["classification"] == "HIGH"
    assert calls["n"] == 1
    assert out["triage_runs"] == 1


@pytest.mark.asyncio
async def test_confirm_clean_clean_then_clean_stays_clean() -> None:
    """Both calls returned CLEAN — confidence is real, ship CLEAN."""
    base, calls = _make_scripted_triage_runner(["CLEAN", "CLEAN"])
    wrapped = with_confirm_clean(base)
    out = await wrapped("x.py", b"x", None)
    assert out["classification"] == "CLEAN"
    assert calls["n"] == 2
    assert out["triage_runs"] == 2
    assert out["triage_classifications_all"] == ["CLEAN", "CLEAN"]
    # Cost / token telemetry sum both runs
    assert out["cost_usd"] == pytest.approx(0.002)
    assert out["input_tokens"] == 200


@pytest.mark.asyncio
async def test_confirm_clean_clean_then_high_takes_high() -> None:
    """v15.8 Gap 3 core case: the wrapper catches a CLEAN-flip and
    promotes to HIGH so the cascade runs."""
    base, calls = _make_scripted_triage_runner(["CLEAN", "HIGH"])
    wrapped = with_confirm_clean(base)
    out = await wrapped("x.py", b"x", None)
    assert out["classification"] == "HIGH"
    assert calls["n"] == 2
    assert out["triage_runs"] == 2
    assert out["triage_classifications_all"] == ["CLEAN", "HIGH"]


@pytest.mark.asyncio
async def test_confirm_clean_clean_then_low_takes_low() -> None:
    """LOW is more conservative than CLEAN — wrapper picks the more
    conservative classification."""
    base, calls = _make_scripted_triage_runner(["CLEAN", "LOW"])
    wrapped = with_confirm_clean(base)
    out = await wrapped("x.py", b"x", None)
    assert out["classification"] == "LOW"
    assert out["triage_runs"] == 2
