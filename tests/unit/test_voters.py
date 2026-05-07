"""Unit tests for methodology.voters — multi-vendor consensus voters.

No live API; the OpenAI HTTP layer is stubbed via respx, the Anthropic +
Google adapters are stub-injected via duck-typed fakes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx

from methodology.voters import (
    GPT_55_COST_IN,
    GPT_55_COST_OUT,
    GROK_43_COST_IN,
    GROK_43_COST_OUT,
    VoterRecord,
    _load_existing_voter_records,
    load_opus_voter_from_bench_rows,
    make_gpt5_voter,
    make_grok_voter,
    run_voter,
)

# ── VoterRecord ──────────────────────────────────────────────────────────────


def test_voter_record_to_dict_round_trip() -> None:
    r = VoterRecord(
        file_name="a.py",
        voter_name="opus_4_6",
        predicted_verdict="critical_malicious",
        composite_score=85,
        cost_usd=0.1234,
        duration_ms=12000,
        input_tokens=1000,
        output_tokens=500,
    )
    d = r.to_dict()
    assert d["file_name"] == "a.py"
    assert d["voter_name"] == "opus_4_6"
    assert d["predicted_verdict"] == "critical_malicious"
    assert d["composite_score"] == 85
    assert d["cost_usd"] == 0.1234


# ── load_opus_voter_from_bench_rows ──────────────────────────────────────────


def test_load_opus_voter_from_bench_rows(tmp_path: Path) -> None:
    bench_data = [
        {
            "file_name": "a.py",
            "predicted_verdict": "critical_malicious",
            "cost_usd": 0.30,
            "duration_ms": 60000,
            "input_tokens": 1000,
            "output_tokens": 500,
            "vulnerabilities": [{"cwe": "CWE-78"}],
        },
        {
            "file_name": "b.py",
            "predicted_verdict": "clean",
            "cost_usd": 0.10,
            "duration_ms": 5000,
        },
    ]
    p = tmp_path / "raw_opus_run1.json"
    p.write_text(json.dumps(bench_data))
    out = load_opus_voter_from_bench_rows(p)
    assert len(out) == 2
    assert out[0].voter_name == "opus_4_6"
    assert out[0].file_name == "a.py"
    assert out[0].predicted_verdict == "critical_malicious"
    assert out[0].raw_findings == [{"cwe": "CWE-78"}]
    assert out[1].file_name == "b.py"


def test_load_opus_voter_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_opus_voter_from_bench_rows(tmp_path / "missing.json") == []


# ── _load_existing_voter_records ─────────────────────────────────────────────


def test_load_existing_voter_records_round_trip(tmp_path: Path) -> None:
    payload = [
        {
            "file_name": "a.py",
            "voter_name": "gemini_3_1_pro",
            "predicted_verdict": "suspicious",
            "composite_score": 35,
            "cost_usd": 0.05,
            "duration_ms": 8000,
            "input_tokens": 800,
            "output_tokens": 200,
            "raw_findings": [],
        }
    ]
    p = tmp_path / "voter.json"
    p.write_text(json.dumps(payload))
    out = _load_existing_voter_records(p)
    assert len(out) == 1
    assert out[0].voter_name == "gemini_3_1_pro"
    assert out[0].composite_score == 35


# ── make_gpt5_voter (with stubbed HTTP) ──────────────────────────────────────


def _ok_openai_response(content: str, in_tokens: int = 1000, out_tokens: int = 500) -> dict:
    return {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": in_tokens, "completion_tokens": out_tokens},
    }


@pytest.mark.asyncio
@respx.mock
async def test_gpt5_voter_happy_path() -> None:
    response_body = json.dumps(
        {
            "vulnerabilities": [{"cwe": "CWE-78", "type": "command_injection", "severity": "critical"}],
            "composite_risk": {"score": 80, "reasoning": "...", "exploitability": "high"},
        }
    )
    respx.post("https://api.openai.com/v1/chat/completions").respond(
        json=_ok_openai_response(response_body, in_tokens=2000, out_tokens=600)
    )
    voter = make_gpt5_voter("sk-test")
    out = await voter("exfil.py", b"import os\nos.system('rm -rf /')")

    assert out.error is None
    assert out.voter_name == "gpt_5_4"  # default model
    assert out.file_name == "exfil.py"
    assert out.predicted_verdict == "critical_malicious"  # score 80 -> critical
    assert out.composite_score == 80
    assert out.input_tokens == 2000
    assert out.output_tokens == 600
    expected_cost = 2000 / 1_000_000 * GPT_55_COST_IN + 600 / 1_000_000 * GPT_55_COST_OUT
    assert abs(out.cost_usd - expected_cost) < 1e-6
    assert len(out.raw_findings) == 1


@pytest.mark.asyncio
@respx.mock
async def test_gpt5_voter_low_score_is_clean() -> None:
    response_body = json.dumps(
        {
            "vulnerabilities": [],
            "composite_risk": {"score": 0, "reasoning": "clean", "exploitability": "none"},
        }
    )
    respx.post("https://api.openai.com/v1/chat/completions").respond(json=_ok_openai_response(response_body))
    voter = make_gpt5_voter("sk-test")
    out = await voter("clean.py", b"print('hello')")
    assert out.error is None
    assert out.predicted_verdict == "clean"
    assert out.composite_score == 0


@pytest.mark.asyncio
@respx.mock
async def test_gpt5_voter_http_error_captured() -> None:
    respx.post("https://api.openai.com/v1/chat/completions").respond(status_code=500, json={"error": "boom"})
    voter = make_gpt5_voter("sk-test")
    out = await voter("a.py", b"x = 1")
    assert out.error is not None
    assert "HTTPStatusError" in out.error or "500" in out.error
    assert out.predicted_verdict is None


@pytest.mark.asyncio
@respx.mock
async def test_gpt5_voter_invalid_json_captured() -> None:
    respx.post("https://api.openai.com/v1/chat/completions").respond(json=_ok_openai_response("not json{"))
    voter = make_gpt5_voter("sk-test")
    out = await voter("a.py", b"x = 1")
    assert out.error is not None
    assert "JSONDecodeError" in out.error


# ── make_grok_voter (xAI, OpenAI-compatible) ─────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_grok_voter_happy_path() -> None:
    response_body = json.dumps(
        {
            "vulnerabilities": [{"cwe": "CWE-94", "type": "code_injection", "severity": "critical"}],
            "composite_risk": {"score": 85, "reasoning": "...", "exploitability": "high"},
        }
    )
    respx.post("https://api.x.ai/v1/chat/completions").respond(
        json=_ok_openai_response(response_body, in_tokens=2000, out_tokens=600)
    )
    voter = make_grok_voter("xai-test")
    out = await voter("exploit.py", b"exec(input())")

    assert out.error is None
    assert out.voter_name == "grok_4_3"
    assert out.predicted_verdict == "critical_malicious"
    assert out.composite_score == 85
    expected_cost = 2000 / 1_000_000 * GROK_43_COST_IN + 600 / 1_000_000 * GROK_43_COST_OUT
    assert abs(out.cost_usd - expected_cost) < 1e-6
    assert len(out.raw_findings) == 1
    # Full raw_output preserved.
    assert out.raw_output["composite_risk"]["score"] == 85


@pytest.mark.asyncio
@respx.mock
async def test_grok_voter_http_error_captured() -> None:
    respx.post("https://api.x.ai/v1/chat/completions").respond(status_code=429, json={"error": "rate limited"})
    voter = make_grok_voter("xai-test")
    out = await voter("a.py", b"x = 1")
    assert out.error is not None
    assert "429" in out.error or "HTTPStatusError" in out.error


# ── raw_output capture (full JSON, not just findings) ────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_voter_raw_output_captures_full_json() -> None:
    """Verify the full parsed JSON is stored in raw_output for downstream
    CWE / capability / behavioral analysis."""
    full_json = {
        "vulnerabilities": [{"cwe": "CWE-78", "severity": "high"}],
        "behavioral_profile": {
            "actual_capabilities": {"network_calls": ["http://attacker.com"]},
            "exfiltration_risk": {"external_network_calls": ["http://attacker.com"]},
        },
        "ai_tool_analysis": {"is_ai_tool": False, "tool_type": "none"},
        "attack_chains": [{"name": "exfil chain"}],
        "composite_risk": {"score": 70, "reasoning": "exfil risk"},
    }
    respx.post("https://api.openai.com/v1/chat/completions").respond(json=_ok_openai_response(json.dumps(full_json)))
    voter = make_gpt5_voter("sk-test")
    out = await voter("a.py", b"x = 1")
    assert out.error is None
    # raw_output preserves every top-level field
    assert "vulnerabilities" in out.raw_output
    assert "behavioral_profile" in out.raw_output
    assert "ai_tool_analysis" in out.raw_output
    assert "attack_chains" in out.raw_output
    assert "composite_risk" in out.raw_output
    # And it's the exact JSON the model returned
    assert out.raw_output["behavioral_profile"]["actual_capabilities"]["network_calls"] == ["http://attacker.com"]
    assert out.raw_output["attack_chains"][0]["name"] == "exfil chain"


# ── run_voter (batch + resume) ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_voter_streams_and_resumes(tmp_path: Path) -> None:
    """A pre-existing record on disk is preserved (resume); only new
    files get re-voted."""
    out_path = tmp_path / "voter.json"
    out_path.write_text(
        json.dumps(
            [
                {
                    "file_name": "a.py",
                    "voter_name": "test_voter",
                    "predicted_verdict": "clean",
                    "composite_score": 0,
                    "cost_usd": 0.01,
                    "duration_ms": 100,
                    "input_tokens": 100,
                    "output_tokens": 10,
                    "error": None,
                    "raw_findings": [],
                }
            ]
        )
    )

    calls: list[str] = []

    async def stub_voter(filename: str, content: bytes) -> VoterRecord:
        calls.append(filename)
        return VoterRecord(
            file_name=filename,
            voter_name="test_voter",
            predicted_verdict="suspicious",
            composite_score=30,
            cost_usd=0.02,
            duration_ms=500,
        )

    files = [("a.py", b"print('a')"), ("b.py", b"print('b')")]
    out = await run_voter(stub_voter, files, output_path=out_path, resume=True)

    # Only b.py should have been called (a.py was already saved).
    assert calls == ["b.py"]
    assert len(out) == 2
    saved = json.loads(out_path.read_text())
    assert {r["file_name"] for r in saved} == {"a.py", "b.py"}


@pytest.mark.asyncio
async def test_run_voter_progress_callback(tmp_path: Path) -> None:
    out_path = tmp_path / "voter.json"

    async def stub_voter(filename: str, content: bytes) -> VoterRecord:
        return VoterRecord(
            file_name=filename,
            voter_name="test_voter",
            predicted_verdict="clean",
            composite_score=0,
            cost_usd=0.01,
            duration_ms=100,
        )

    seen: list[tuple[int, int]] = []
    files = [("a.py", b""), ("b.py", b"")]
    await run_voter(
        stub_voter,
        files,
        output_path=out_path,
        progress_callback=lambda i, n, r: seen.append((i, n)),
    )
    assert seen == [(1, 2), (2, 2)]
