"""Unit tests for methodology.judge — BENCH-011 GPT-5.5 independent judge.

No live API; the OpenAI HTTP layer is stubbed via respx. Test the
A/B blinding, prompt construction, judgment parsing + decoding, and
the batch runner end-to-end with stubbed responses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import respx

from methodology.judge import (
    DEFAULT_JUDGE_MODEL,
    DEFAULT_OPENAI_BASE_URL,
    JUDGE_SYSTEM_PROMPT,
    JudgmentRecord,
    _decode_agree_with,
    _truncate_file_content,
    build_user_message,
    disagreement_records,
    judge_one,
    parse_judgment,
    randomize_positions,
    run_judge,
    summarize_judgments,
)


def _diff_record(
    *,
    file_name: str = "f.py",
    argus_verdict: str = "critical_malicious",
    opus_verdict: str = "suspicious",
    oracle_verdict: str = "critical_malicious",
    file_content: str = "import os\nos.system('rm -rf /')",
    argus_findings: list[dict[str, Any]] | None = None,
    opus_findings: list[dict[str, Any]] | None = None,
    has_disagreement: bool = True,
) -> dict[str, Any]:
    """Build a synthetic diff_report record (matches BENCH-010 output)."""
    judge_payload = None
    if has_disagreement:
        judge_payload = {
            "file_name": file_name,
            "file_content": file_content,
            "oracle_verdict": oracle_verdict,
            "positions": [
                {
                    "_label_internal": "argus",
                    "verdict": argus_verdict,
                    "n_findings": len(argus_findings or []),
                    "findings": argus_findings or [],
                    "scan_path": ["triage", "sonnet"],
                    "dast_attempted": False,
                    "refused": False,
                },
                {
                    "_label_internal": "opus",
                    "verdict": opus_verdict,
                    "n_findings": len(opus_findings or []),
                    "findings": opus_findings or [],
                    "scan_path": [],
                    "dast_attempted": False,
                    "refused": False,
                },
            ],
        }
    return {
        "file_name": file_name,
        "verdict_match": {
            "argus": argus_verdict,
            "opus": opus_verdict,
            "oracle": oracle_verdict,
            "label_provenance": "opus_confirmed",
            "all_match": False,
        },
        "findings_per_source": {"argus": [], "opus": [], "oracle": None},
        "cwe_overlap": None,
        "capability_overlap": None,
        "dast_artifacts_argus": [],
        "argus_refused": False,
        "opus_refused": False,
        "judge_payload": judge_payload,
    }


# ── randomize_positions ───────────────────────────────────────────────────────


def test_randomize_positions_strips_internal_labels() -> None:
    record = _diff_record()
    blinded, mapping = randomize_positions(record["judge_payload"], seed="seed1")
    for pos in blinded["positions_AB"]:
        assert "_label_internal" not in pos
        assert pos["_ab"] in ("A", "B")
    assert set(mapping.keys()) == {"A", "B"}
    assert set(mapping.values()) == {"argus", "opus"}


def test_randomize_positions_deterministic_per_seed() -> None:
    record = _diff_record()
    a1, m1 = randomize_positions(record["judge_payload"], seed="filex.py")
    a2, m2 = randomize_positions(record["judge_payload"], seed="filex.py")
    assert m1 == m2  # same seed → same mapping
    assert a1["positions_AB"][0]["verdict"] == a2["positions_AB"][0]["verdict"]


def test_randomize_positions_different_seeds_can_swap() -> None:
    """At least one of N seeds should produce the opposite mapping."""
    record = _diff_record()
    seen_argus_first = False
    seen_opus_first = False
    for i in range(20):
        _, mapping = randomize_positions(record["judge_payload"], seed=f"s{i}")
        if mapping["A"] == "argus":
            seen_argus_first = True
        else:
            seen_opus_first = True
        if seen_argus_first and seen_opus_first:
            break
    assert seen_argus_first and seen_opus_first


def test_randomize_positions_rejects_wrong_count() -> None:
    payload = {"positions": [{"_label_internal": "argus"}]}  # only 1
    with pytest.raises(ValueError, match="expected 2 positions"):
        randomize_positions(payload)


# ── _truncate_file_content ────────────────────────────────────────────────────


def test_truncate_file_content_short_passthrough() -> None:
    assert _truncate_file_content("short content") == "short content"


def test_truncate_file_content_long_marked() -> None:
    long = "x" * 100_000
    out = _truncate_file_content(long, max_chars=1000)
    assert len(out) > 1000  # truncated text + marker
    assert out.endswith("[file truncated]")


def test_truncate_file_content_handles_none() -> None:
    assert _truncate_file_content(None) == "[file content unavailable]"


# ── build_user_message ────────────────────────────────────────────────────────


def test_build_user_message_includes_all_signals() -> None:
    record = _diff_record(
        argus_findings=[
            {
                "cwe": "CWE-78",
                "type": "command_injection",
                "severity": "critical",
                "line": 42,
                "title": "shell exec from user input",
            }
        ]
    )
    blinded, _ = randomize_positions(record["judge_payload"], seed="foo")
    msg = build_user_message(blinded)
    assert "File: f.py" in msg
    assert "Oracle verdict" in msg
    assert "critical_malicious" in msg
    assert "Position A" in msg
    assert "Position B" in msg
    assert "CWE-78" in msg
    assert "command_injection" in msg
    assert "rm -rf" in msg  # source code passed through


def test_build_user_message_caps_findings() -> None:
    findings = [
        {"cwe": f"CWE-{i}", "type": "x", "severity": "low", "line": i, "title": f"f{i}"}
        for i in range(50)
    ]
    record = _diff_record(argus_findings=findings)
    blinded, _ = randomize_positions(record["judge_payload"], seed="bar")
    msg = build_user_message(blinded)
    assert "more findings omitted" in msg


# ── parse_judgment ────────────────────────────────────────────────────────────


def _ok_response(content: str, in_tokens: int = 1000, out_tokens: int = 200) -> dict:
    return {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": in_tokens, "completion_tokens": out_tokens},
    }


def test_parse_judgment_success() -> None:
    j_text = json.dumps(
        {
            "verdict": "critical_malicious",
            "agree_with": "A",
            "reasoning": "code clearly does X",
            "confidence": 0.9,
        }
    )
    judgment, in_t, out_t, raw = parse_judgment(_ok_response(j_text, 100, 50))
    assert judgment["verdict"] == "critical_malicious"
    assert judgment["agree_with"] == "A"
    assert in_t == 100
    assert out_t == 50
    assert raw == j_text


def test_parse_judgment_invalid_json_raises() -> None:
    with pytest.raises(ValueError, match="invalid JSON"):
        parse_judgment(_ok_response("not json{"))


def test_parse_judgment_missing_choices_raises() -> None:
    with pytest.raises(ValueError, match="no choices"):
        parse_judgment({"choices": []})


def test_parse_judgment_empty_content_raises() -> None:
    with pytest.raises(ValueError, match="empty content"):
        parse_judgment({"choices": [{"message": {"content": ""}}]})


# ── _decode_agree_with ────────────────────────────────────────────────────────


def test_decode_agree_with_translates_ab() -> None:
    mapping = {"A": "argus", "B": "opus"}
    assert _decode_agree_with("A", mapping) == "argus"
    assert _decode_agree_with("B", mapping) == "opus"


def test_decode_agree_with_passes_both_neither() -> None:
    mapping = {"A": "argus", "B": "opus"}
    assert _decode_agree_with("both", mapping) == "both"
    assert _decode_agree_with("neither", mapping) == "neither"


def test_decode_agree_with_unknown_passes_through() -> None:
    mapping = {"A": "argus", "B": "opus"}
    assert _decode_agree_with("X", mapping) == "X"
    assert _decode_agree_with(None, mapping) is None


# ── judge_one (with stubbed HTTP) ─────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_judge_one_happy_path() -> None:
    record = _diff_record()
    judge_resp = _ok_response(
        json.dumps(
            {
                "verdict": "critical_malicious",
                "agree_with": "A",
                "reasoning": "the code calls os.system on user input",
                "confidence": 0.92,
            }
        ),
        in_tokens=2000,
        out_tokens=300,
    )
    respx.post(f"{DEFAULT_OPENAI_BASE_URL}/chat/completions").respond(json=judge_resp)

    out = await judge_one(record, api_key="sk-test", seed="f.py")

    assert out.error is None
    assert out.file_name == "f.py"
    assert out.judge_model == DEFAULT_JUDGE_MODEL
    assert out.tokens_in == 2000
    assert out.tokens_out == 300
    # cost = 2000/1M * 3.0 + 300/1M * 15.0 = 0.006 + 0.0045 = 0.0105
    assert abs(out.cost_usd - 0.0105) < 1e-6
    # agree_with should decode into "argus" or "opus" depending on
    # the deterministic mapping for seed="f.py".
    assert out.judgment["agree_with_blinded"] == "A"
    assert out.judgment["agree_with"] in ("argus", "opus")
    assert out.judgment["agree_with"] == out.ab_mapping["A"]
    assert out.judgment["verdict"] == "critical_malicious"
    assert out.argus_verdict == "critical_malicious"
    assert out.opus_verdict == "suspicious"


@pytest.mark.asyncio
@respx.mock
async def test_judge_one_http_error_captured() -> None:
    record = _diff_record()
    respx.post(f"{DEFAULT_OPENAI_BASE_URL}/chat/completions").respond(
        status_code=500, json={"error": "boom"}
    )

    out = await judge_one(record, api_key="sk-test", seed="x")

    assert out.error is not None
    assert "HTTPStatusError" in out.error or "500" in out.error
    assert out.judgment == {}


@pytest.mark.asyncio
@respx.mock
async def test_judge_one_invalid_json_captured() -> None:
    record = _diff_record()
    respx.post(f"{DEFAULT_OPENAI_BASE_URL}/chat/completions").respond(
        json=_ok_response("not parseable")
    )
    out = await judge_one(record, api_key="sk-test", seed="x")
    assert out.error is not None
    assert "invalid JSON" in out.error


@pytest.mark.asyncio
async def test_judge_one_rejects_record_without_payload() -> None:
    rec = _diff_record(has_disagreement=False)
    with pytest.raises(ValueError, match="no judge_payload"):
        await judge_one(rec, api_key="sk-test")


# ── disagreement_records ─────────────────────────────────────────────────────


def test_disagreement_records_filters_none() -> None:
    records = [
        _diff_record(file_name="a.py", has_disagreement=True),
        _diff_record(file_name="b.py", has_disagreement=False),
        _diff_record(file_name="c.py", has_disagreement=True),
    ]
    out = disagreement_records(records)
    assert [r["file_name"] for r in out] == ["a.py", "c.py"]


# ── run_judge (batch) ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_run_judge_streams_to_output(tmp_path: Path) -> None:
    records = [
        _diff_record(file_name="a.py"),
        _diff_record(file_name="b.py", argus_verdict="suspicious", opus_verdict="clean"),
        _diff_record(file_name="c.py", has_disagreement=False),  # skipped
    ]
    respx.post(f"{DEFAULT_OPENAI_BASE_URL}/chat/completions").respond(
        json=_ok_response(
            json.dumps(
                {
                    "verdict": "critical_malicious",
                    "agree_with": "A",
                    "reasoning": "...",
                    "confidence": 0.7,
                }
            )
        )
    )
    out_path = tmp_path / "judgments.json"
    out = await run_judge(records, api_key="sk-test", output_path=out_path)
    assert len(out) == 2  # only two disagreements
    # Streamed output contains both judgments.
    saved = json.loads(out_path.read_text())
    assert len(saved) == 2
    assert {r["file_name"] for r in saved} == {"a.py", "b.py"}


@pytest.mark.asyncio
@respx.mock
async def test_run_judge_progress_callback() -> None:
    records = [
        _diff_record(file_name="a.py"),
        _diff_record(file_name="b.py", argus_verdict="clean"),
    ]
    respx.post(f"{DEFAULT_OPENAI_BASE_URL}/chat/completions").respond(
        json=_ok_response(
            json.dumps(
                {
                    "verdict": "clean",
                    "agree_with": "B",
                    "reasoning": "x",
                    "confidence": 0.5,
                }
            )
        )
    )
    seen: list[tuple[int, int]] = []
    await run_judge(
        records,
        api_key="sk-test",
        progress_callback=lambda i, n, j: seen.append((i, n)),
    )
    assert seen == [(1, 2), (2, 2)]


# ── summarize_judgments ──────────────────────────────────────────────────────


def _judgment(
    file_name: str,
    agree_with: str | None,
    *,
    error: str | None = None,
    confidence: float | None = 0.8,
    cost: float = 0.01,
) -> JudgmentRecord:
    return JudgmentRecord(
        file_name=file_name,
        judge_model="gpt-5.5",
        oracle_verdict="critical_malicious",
        argus_verdict="critical_malicious",
        opus_verdict="suspicious",
        judgment={"agree_with": agree_with, "confidence": confidence} if not error else {},
        ab_mapping={"A": "argus", "B": "opus"},
        tokens_in=1000,
        tokens_out=200,
        cost_usd=cost,
        duration_ms=1234,
        error=error,
    )


def test_summarize_judgments_tallies() -> None:
    judgments = [
        _judgment("a.py", "argus", confidence=0.9, cost=0.01),
        _judgment("b.py", "argus", confidence=0.8, cost=0.02),
        _judgment("c.py", "opus", confidence=0.7, cost=0.015),
        _judgment("d.py", "neither", confidence=0.5, cost=0.01),
        _judgment("e.py", None, error="timeout", cost=0.0),
    ]
    s = summarize_judgments(judgments)
    assert s["n_disagreements"] == 5
    assert s["judge_picked_argus"] == 2
    assert s["judge_picked_opus"] == 1
    assert s["judge_picked_neither"] == 1
    assert s["judge_errors"] == 1
    assert s["mean_confidence"] == round((0.9 + 0.8 + 0.7 + 0.5) / 4, 3)
    assert s["total_cost_usd"] == round(0.01 + 0.02 + 0.015 + 0.01, 4)


def test_summarize_judgments_empty() -> None:
    s = summarize_judgments([])
    assert s["n_disagreements"] == 0
    assert s["judge_picked_argus"] == 0
    assert s["mean_confidence"] is None
    assert s["total_cost_usd"] == 0.0


# ── System prompt sanity ─────────────────────────────────────────────────────


def test_system_prompt_demands_json_only() -> None:
    """Belt-and-suspenders alongside response_format json_object."""
    assert "JSON" in JUDGE_SYSTEM_PROMPT
    assert "agree_with" in JUDGE_SYSTEM_PROMPT
    assert "verdict" in JUDGE_SYSTEM_PROMPT
    assert "No prose outside" in JUDGE_SYSTEM_PROMPT
