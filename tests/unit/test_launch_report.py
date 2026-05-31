"""Unit tests for methodology.launch_report — BENCH-012 v1 launch aggregator.

No live API; all inputs synthesized. Verifies the section assembly,
the headline gate-pass logic, and the end-to-end build_launch_report
loader path.
"""

from __future__ import annotations

import json
from pathlib import Path

from methodology.bench import BenchRow
from methodology.judge import JudgmentRecord
from methodology.launch_report import (
    VERDICT_RANK,
    _dast_evidence_count,
    _gate_lift_pp,
    _load_judgments,
    _render_section_5_dast_evidence,
    _verdict_match_stats,
    build_launch_report,
    render_launch_report,
)


def _row(
    file_name: str,
    oracle: str,
    predicted: str | None,
    *,
    config: str = "argus_full",
    cost: float = 0.05,
    scan_path: list[str] | None = None,
    dast_attempted: bool = False,
) -> BenchRow:
    return BenchRow(
        file_name=file_name,
        oracle_verdict=oracle,
        predicted_verdict=predicted,
        config=config,
        cost_usd=cost,
        duration_ms=1000,
        scan_path=scan_path or [],
        dast_attempted=dast_attempted,
    )


def _diff_record(
    file_name: str,
    *,
    argus: str,
    opus: str,
    oracle: str,
    judge_payload: dict | None = None,
    cwe_overlap: dict | None = None,
    cap_overlap: dict | None = None,
    rich_oracle_findings: list[dict] | None = None,
) -> dict:
    return {
        "file_name": file_name,
        "verdict_match": {
            "argus": argus,
            "opus": opus,
            "oracle": oracle,
            "label_provenance": "opus_confirmed",
            "all_match": argus == opus == oracle,
        },
        "findings_per_source": {
            "argus": [],
            "opus": [],
            "oracle": rich_oracle_findings,
        },
        "cwe_overlap": cwe_overlap,
        "capability_overlap": cap_overlap,
        "dast_artifacts_argus": [],
        "argus_refused": False,
        "opus_refused": False,
        "judge_payload": judge_payload,
    }


# ── Helpers ──────────────────────────────────────────────────────────────────


def test_verdict_rank_monotonic() -> None:
    assert VERDICT_RANK["clean"] < VERDICT_RANK["low_concern"]
    assert VERDICT_RANK["low_concern"] < VERDICT_RANK["suspicious"]
    assert VERDICT_RANK["suspicious"] < VERDICT_RANK["malicious"]
    assert VERDICT_RANK["malicious"] < VERDICT_RANK["critical_malicious"]


def test_verdict_match_stats_counts_exact_and_distance() -> None:
    rows = [
        _row("a.py", "critical_malicious", "critical_malicious"),
        _row("b.py", "clean", "clean"),
        _row("c.py", "critical_malicious", "suspicious"),  # distance 2
        _row("d.py", "malicious", None),  # no prediction → no distance
    ]
    s = _verdict_match_stats(rows)
    assert s["n"] == 4
    assert s["exact_match"] == 2
    assert s["exact_pct"] == 50.0
    # distances: 0, 0, 2 → mean 0.667
    assert s["mean_distance"] is not None
    assert abs(s["mean_distance"] - 0.667) < 1e-2


def test_verdict_match_stats_empty() -> None:
    s = _verdict_match_stats([])
    assert s["n"] == 0
    assert s["exact_pct"] == 0.0
    assert s["mean_distance"] is None


def test_gate_lift_pp() -> None:
    assert _gate_lift_pp(80.0, 60.0) == 20.0
    assert _gate_lift_pp(50.0, 60.0) == -10.0


def test_dast_evidence_count_tallies() -> None:
    rows = [
        _row(
            "a.py",
            "critical_malicious",
            "critical_malicious",
            dast_attempted=True,
            scan_path=["triage", "sonnet", "dast_verification"],
        ),
        _row("b.py", "clean", "clean"),
        _row("c.py", "malicious", "malicious", dast_attempted=True, scan_path=["dast_iter3_opus"]),
    ]
    counts = _dast_evidence_count(rows)
    assert counts["n_dast_attempted"] == 2
    assert counts["n_with_dast_stage"] == 2


# ── _load_judgments ──────────────────────────────────────────────────────────


def test_load_judgments_round_trip(tmp_path: Path) -> None:
    payload = [
        {
            "file_name": "a.py",
            "judge_model": "gpt-5.5",
            "oracle_verdict": "critical_malicious",
            "argus_verdict": "critical_malicious",
            "opus_verdict": "suspicious",
            "judgment": {"agree_with": "argus", "confidence": 0.9},
            "ab_mapping": {"A": "argus", "B": "opus"},
            "tokens_in": 1000,
            "tokens_out": 200,
            "cost_usd": 0.0105,
            "duration_ms": 4321,
            "error": None,
        }
    ]
    p = tmp_path / "judgments.json"
    p.write_text(json.dumps(payload))
    out = _load_judgments(p)
    assert len(out) == 1
    assert out[0].file_name == "a.py"
    assert out[0].judgment["agree_with"] == "argus"


def test_load_judgments_missing_returns_empty(tmp_path: Path) -> None:
    assert _load_judgments(tmp_path / "nope.json") == []


def test_load_judgments_handles_malformed(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("not json")
    assert _load_judgments(p) == []


# ── render_launch_report ─────────────────────────────────────────────────────


def test_render_launch_report_passes_gate_when_lift_ge_15() -> None:
    # Argus 80%, Opus 60% → 20pp lift, gate PASS.
    argus_rows = [
        _row(f"f{i}.py", "critical_malicious", "critical_malicious") for i in range(8)
    ] + [_row(f"f{i}.py", "critical_malicious", "suspicious") for i in range(8, 10)]
    opus_rows = [_row(f"f{i}.py", "critical_malicious", "critical_malicious") for i in range(6)] + [
        _row(f"f{i}.py", "critical_malicious", "suspicious") for i in range(6, 10)
    ]
    diff_records = [
        _diff_record(
            f"f{i}.py",
            argus="critical_malicious",
            opus="critical_malicious",
            oracle="critical_malicious",
        )
        for i in range(10)
    ]
    md = render_launch_report(argus_rows, opus_rows, diff_records, [])
    assert "# Argus v1" in md  # em-dash may not survive Windows codepage round-trips
    assert "ARGUS v1" in md  # scoreboard header
    assert "**80.0%**" in md
    assert "60.0%" in md
    assert "+20.0pp" in md
    assert "Gate" in md and "PASS" in md


def test_render_launch_report_fails_gate_when_lift_lt_15() -> None:
    # Argus 60%, Opus 60% → 0pp lift, gate FAIL.
    argus_rows = [
        _row(f"f{i}.py", "critical_malicious", "critical_malicious") for i in range(6)
    ] + [_row(f"f{i}.py", "critical_malicious", "suspicious") for i in range(6, 10)]
    opus_rows = list(argus_rows)
    diff_records = [
        _diff_record(
            f"f{i}.py",
            argus="critical_malicious",
            opus="critical_malicious",
            oracle="critical_malicious",
        )
        for i in range(10)
    ]
    md = render_launch_report(argus_rows, opus_rows, diff_records, [])
    assert "FAIL" in md
    assert "needs +" in md  # "needs +X.Xpp more" message in scoreboard


def test_render_launch_report_includes_judge_section_when_present() -> None:
    judgments = [
        JudgmentRecord(
            file_name="a.py",
            judge_model="gpt-5.5",
            oracle_verdict="critical_malicious",
            argus_verdict="critical_malicious",
            opus_verdict="suspicious",
            judgment={"agree_with": "argus", "confidence": 0.92, "verdict": "critical_malicious"},
            ab_mapping={"A": "argus", "B": "opus"},
            tokens_in=1000,
            tokens_out=200,
            cost_usd=0.0105,
            duration_ms=4321,
        )
    ]
    md = render_launch_report([], [], [], judgments)
    assert "GPT-5.5 independent judge" in md
    assert "Judge picked Argus" in md
    assert "**1**" in md  # judge picked argus count
    assert "0.92" in md  # confidence


def test_render_launch_report_judge_section_says_skipped_when_empty() -> None:
    md = render_launch_report([], [], [], [])
    assert "No judgments available" in md


def test_render_launch_report_includes_cwe_overlap_section() -> None:
    diff_records = [
        _diff_record(
            "rich.py",
            argus="critical_malicious",
            opus="critical_malicious",
            oracle="critical_malicious",
            cwe_overlap={
                "argus_vs_oracle": {"precision": 0.8, "recall": 1.0, "f1": 0.889, "jaccard": 0.8},
                "opus_vs_oracle": {"precision": 0.6, "recall": 0.5, "f1": 0.545, "jaccard": 0.4},
            },
            cap_overlap={
                "argus_vs_oracle": {"precision": 0.7, "recall": 0.9, "f1": 0.789, "jaccard": 0.6},
                "opus_vs_oracle": {"precision": 0.5, "recall": 0.4, "f1": 0.444, "jaccard": 0.3},
            },
            rich_oracle_findings=[{"cwe": "CWE-78"}],
        ),
    ]
    md = render_launch_report([], [], diff_records, [])
    assert "3. CWE overlap" in md
    assert "0.889" in md  # argus F1
    assert "0.545" in md  # opus F1
    assert "4. Capability-tag overlap" in md
    assert "0.789" in md  # argus capability F1


def test_render_launch_report_skips_overlap_sections_when_no_rich() -> None:
    diff_records = [
        _diff_record(
            "plain.py",
            argus="clean",
            opus="clean",
            oracle="clean",
        )
    ]
    md = render_launch_report([], [], diff_records, [])
    assert "section skipped" in md  # both finding-count and overlap


def test_render_launch_report_includes_mythos_footer() -> None:
    md = render_launch_report([], [], [], [])
    assert "9. Mythos validation" in md
    assert "v1.1" in md


def test_render_launch_report_dast_section_counts_correctly() -> None:
    argus_rows = [
        _row(
            "a.py",
            "critical_malicious",
            "critical_malicious",
            dast_attempted=True,
            scan_path=["dast_verification"],
        ),
        _row("b.py", "clean", "clean"),
    ]
    md = render_launch_report(argus_rows, [], [], [])
    assert "DAST attempted" in md
    assert "**1**/2" in md


def test_render_launch_report_cost_section_includes_judge_when_present() -> None:
    argus_rows = [_row("a.py", "x", "x", cost=0.20)]
    opus_rows = [_row("a.py", "x", "x", config="raw_opus", cost=0.10)]
    judgments = [
        JudgmentRecord(
            file_name="a.py",
            judge_model="gpt-5.5",
            oracle_verdict="x",
            argus_verdict="x",
            opus_verdict="x",
            judgment={"agree_with": "both"},
            ab_mapping={"A": "argus", "B": "opus"},
            tokens_in=1000,
            tokens_out=200,
            cost_usd=0.0105,
            duration_ms=1000,
        )
    ]
    md = render_launch_report(argus_rows, opus_rows, [], judgments)
    assert "Cost comparison" in md
    assert "$0.2000" in md  # argus
    assert "$0.1000" in md  # opus
    assert "GPT-5.5 judge" in md
    assert "$0.0105" in md  # judge total


# ── build_launch_report (end-to-end) ─────────────────────────────────────────


def test_build_launch_report_end_to_end(tmp_path: Path) -> None:
    # Stage all four input files.
    argus_path = tmp_path / "argus.json"
    opus_path = tmp_path / "opus.json"
    baseline_path = tmp_path / "baseline.json"
    out_path = tmp_path / "launch.md"

    argus_rows_data = [
        {
            "file_name": "a.py",
            "oracle_verdict": "critical_malicious",
            "predicted_verdict": "critical_malicious",
            "config": "argus_full",
            "cost_usd": 0.10,
            "duration_ms": 1000,
        },
        {
            "file_name": "b.py",
            "oracle_verdict": "clean",
            "predicted_verdict": "clean",
            "config": "argus_full",
            "cost_usd": 0.05,
            "duration_ms": 500,
        },
    ]
    opus_rows_data = [
        {
            "file_name": "a.py",
            "oracle_verdict": "critical_malicious",
            "predicted_verdict": "suspicious",
            "config": "raw_opus",
            "cost_usd": 0.20,
            "duration_ms": 2000,
        },
        {
            "file_name": "b.py",
            "oracle_verdict": "clean",
            "predicted_verdict": "clean",
            "config": "raw_opus",
            "cost_usd": 0.10,
            "duration_ms": 1000,
        },
    ]
    argus_path.write_text(json.dumps(argus_rows_data))
    opus_path.write_text(json.dumps(opus_rows_data))
    baseline_path.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file_name": "a.py",
                        "oracle_verdict": "critical_malicious",
                        "source": "opus_confirmed",
                    },
                    {
                        "file_name": "b.py",
                        "oracle_verdict": "clean",
                        "source": "variance_characterization",
                    },
                ]
            }
        )
    )

    summary = build_launch_report(
        argus_rows_path=argus_path,
        opus_rows_path=opus_path,
        baseline_oracle_path=baseline_path,
        rich_oracle_path=None,
        suite_dir=None,
        diff_records_path=None,
        judgments_path=None,
        output_path=out_path,
    )
    assert out_path.exists()
    md = out_path.read_text(encoding="utf-8")
    assert "Argus v1" in md
    assert "launch report" in md
    # Argus matches both, Opus matches only b.py → 100% vs 50% → +50pp lift.
    assert summary["argus_exact_pct"] == 100.0
    assert summary["opus_exact_pct"] == 50.0
    assert summary["lift_pp"] == 50.0
    assert summary["n_argus_rows"] == 2
    assert summary["n_judgments"] == 0


def test_build_launch_report_handles_missing_inputs(tmp_path: Path) -> None:
    """If argus/opus run files don't exist, report still builds with empty rows."""
    out_path = tmp_path / "launch.md"
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps({"files": []}))
    summary = build_launch_report(
        argus_rows_path=tmp_path / "missing_a.json",
        opus_rows_path=tmp_path / "missing_o.json",
        baseline_oracle_path=baseline_path,
        rich_oracle_path=None,
        output_path=out_path,
    )
    assert out_path.exists()
    assert summary["n_argus_rows"] == 0
    assert summary["n_opus_rows"] == 0
    md = out_path.read_text(encoding="utf-8")
    assert "FAIL" in md  # 0 lift -> below gate


# ── v1.6: REJECTED status + expanded NOT_TESTED reasons rendering ───────────


def test_render_section_5_includes_rejected_bucket() -> None:
    """v1.6 Fix #1: per-finding aggregate must split REJECTED out of
    NOT_TESTED, both in the headline bar chart and the per-file table.
    Regression guard for the launch_report.py renderer to ensure
    REJECTED findings don't silently disappear into the NOT_TESTED
    bucket (which they did pre-v1.6 — the renderer only knew 4 statuses)."""
    row = _row("a.py", "malicious", "malicious", dast_attempted=True)
    row.per_finding_validation = [
        {
            "finding_id": "H001",
            "cwe": "CWE-78",
            "type": "x",
            "severity": "high",
            "line": 1,
            "status": "CONFIRMED",
            "confidence": 1.0,
            "rejection_reason": None,
            "not_tested_reason": None,
            "proof_of_concept": "",
            "runtime_evidence": "",
        },
        {
            "finding_id": "H002",
            "cwe": "CWE-89",
            "type": "x",
            "severity": "high",
            "line": 2,
            "status": "BLOCKED",
            "confidence": 0.6,
            "rejection_reason": "input sanitized",
            "not_tested_reason": None,
            "proof_of_concept": None,
            "runtime_evidence": None,
        },
        {
            "finding_id": "H003",
            "cwe": "CWE-22",
            "type": "x",
            "severity": "high",
            "line": 3,
            "status": "UNREACHED",
            "confidence": 0.6,
            "rejection_reason": "code path unreachable",
            "not_tested_reason": None,
            "proof_of_concept": None,
            "runtime_evidence": None,
        },
        {
            "finding_id": "H004",
            "cwe": "CWE-918",
            "type": "x",
            "severity": "high",
            "line": 4,
            "status": "REJECTED",
            "confidence": 0.6,
            "rejection_reason": "DAST observed no signal",
            "not_tested_reason": None,
            "proof_of_concept": None,
            "runtime_evidence": None,
        },
        {
            "finding_id": "H005",
            "cwe": "CWE-451",
            "type": "x",
            "severity": "low",
            "line": 5,
            "status": "NOT_TESTED",
            "confidence": 0.4,
            "rejection_reason": None,
            "not_tested_reason": "unfireable_pattern_cwe",
            "proof_of_concept": None,
            "runtime_evidence": None,
        },
    ]
    md = _render_section_5_dast_evidence([row])
    # Headline bar chart: REJECTED has its own row with its own count.
    assert "REJECTED" in md
    assert "(1)  DAST ran the exploit" in md
    # Per-file table includes REJECTED column AND the row reflects the count.
    assert "| File | L1 | CONFIRMED | BLOCKED | UNREACHED | REJECTED | NOT_TESTED |" in md
    assert "| `a.py` | 5 | **1** | 1 | 1 | 1 | 1 |" in md


def test_render_section_5_handles_all_eight_not_tested_reasons() -> None:
    """v1.6 Fix #3: NOT_TESTED reason breakdown must render prose for
    every reason variant in the data, not just the 3 original ones
    (infra_stub / inconclusive / not_planned). Regression guard:
    creates a row with all 5 new reasons and asserts each renders."""
    new_reasons = [
        "unfireable_pattern_cwe",
        "budget_exceeded",
        "non_python_file",
        "unreachable_function",
        "dast_not_attempted",
    ]
    row = _row("b.py", "malicious", "malicious", dast_attempted=True)
    row.per_finding_validation = [
        {
            "finding_id": f"H{i:03d}",
            "cwe": "CWE-451",
            "type": "x",
            "severity": "low",
            "line": i,
            "status": "NOT_TESTED",
            "confidence": 0.3,
            "rejection_reason": None,
            "not_tested_reason": rsn,
            "proof_of_concept": None,
            "runtime_evidence": None,
        }
        for i, rsn in enumerate(new_reasons, start=1)
    ]
    md = _render_section_5_dast_evidence([row])
    # Every new reason renders prose, with the count attached.
    for rsn in new_reasons:
        assert f"`{rsn}` (1):" in md
    # And the section header is present.
    assert "NOT_TESTED breakdown" in md
