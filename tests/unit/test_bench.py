"""Unit tests for methodology.bench — BENCH-002, BENCH-003 helpers and
BENCH-005 pass-criteria check.

No live API; all model interactions are stubbed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from methodology.bench import (
    BenchRow,
    bench_pass_criteria,
    compare_configs,
    compute_metrics,
    run_suite,
)


def _row(
    file_name: str,
    oracle: str,
    predicted: str | None,
    *,
    config: str = "argus_full",
    cost: float = 0.1,
    tier: str = "tier1",
) -> BenchRow:
    return BenchRow(
        file_name=file_name,
        oracle_verdict=oracle,
        predicted_verdict=predicted,
        config=config,
        cost_usd=cost,
        duration_ms=1000,
        baseline={"tracking": tier},
    )


# ── BenchRow ────────────────────────────────────────────────────────────────


def test_bench_row_to_dict_round_trip() -> None:
    row = _row("a.py", "malicious", "malicious")
    d = row.to_dict()
    assert d["file_name"] == "a.py"
    assert d["oracle_verdict"] == "malicious"
    assert d["predicted_verdict"] == "malicious"
    assert d["baseline"] == {"tracking": "tier1"}
    assert d["cost_usd"] == 0.1
    assert d["scan_path"] == []
    assert d["dast_attempted"] is False


# ── compute_metrics ─────────────────────────────────────────────────────────


def test_compute_metrics_three_of_five_exact() -> None:
    rows = [
        _row("a.py", "clean", "clean"),
        _row("b.py", "suspicious", "suspicious"),
        _row("c.py", "malicious", "malicious"),
        _row("d.py", "malicious", "suspicious"),  # 1-notch miss
        _row("e.py", "clean", "critical_malicious"),  # full disagreement
    ]
    m = compute_metrics(rows)
    assert m["n_total"] == 5
    assert m["n_scored"] == 5
    assert m["verdict_exact"] == 3
    assert m["verdict_exact_pct"] == pytest.approx(60.0)
    # 0 + 0 + 0 + 0.25 + 1.0 = 1.25; mean = 0.25
    assert m["mean_distance"] == pytest.approx(0.25)


def test_compute_metrics_skips_unresolvable() -> None:
    rows = [
        _row("a.py", "clean", "clean"),
        _row("b.py", "malicious", None),  # predicted missing → skipped
        _row("c.py", "malicious", "garbage_label"),  # unresolvable → skipped
    ]
    m = compute_metrics(rows)
    assert m["n_scored"] == 1
    assert m["n_skipped"] == 2
    assert m["verdict_exact"] == 1
    assert m["verdict_exact_pct"] == pytest.approx(100.0)


def test_compute_metrics_aggregates_cost_and_errors() -> None:
    rows = [
        _row("a.py", "clean", "clean", cost=0.001),
        _row("b.py", "malicious", "malicious", cost=0.5),
    ]
    rows[1].error = "rate_limited"
    m = compute_metrics(rows)
    assert m["total_cost_usd"] == pytest.approx(0.501, abs=0.01)
    assert m["n_errors"] == 1


# ── compare_configs ─────────────────────────────────────────────────────────


def test_compare_configs_lift_and_distance_improvement() -> None:
    """Argus 80% verdict-exact (4/5) vs raw Opus 40% (2/5) → +40pp lift."""
    opus = [
        _row("a.py", "clean", "clean"),
        _row("b.py", "malicious", "malicious"),
        _row("c.py", "suspicious", "clean"),
        _row("d.py", "malicious", "suspicious"),
        _row("e.py", "critical_malicious", "informational"),
    ]
    argus = [
        _row("a.py", "clean", "clean"),
        _row("b.py", "malicious", "malicious"),
        _row("c.py", "suspicious", "suspicious"),
        _row("d.py", "malicious", "malicious"),
        _row("e.py", "critical_malicious", "suspicious"),  # still misses
    ]
    cmp = compare_configs(opus, argus)
    assert cmp["raw_opus"]["verdict_exact_pct"] == pytest.approx(40.0)
    assert cmp["argus_full"]["verdict_exact_pct"] == pytest.approx(80.0)
    assert cmp["verdict_exact_pp_lift"] == pytest.approx(40.0)
    # Argus distance is lower (closer to oracle) → improvement positive
    assert cmp["mean_distance_improvement"] > 0


# ── bench_pass_criteria (BENCH-005 gate) ────────────────────────────────────


def test_bench_pass_criteria_clean_pass() -> None:
    comparison = {"verdict_exact_pp_lift": 18.0, "mean_distance_improvement": 0.08}
    out = bench_pass_criteria(comparison)
    assert out["passed"] is True
    assert out["verdict_exact_pp_lift_pass"] is True
    assert out["mean_distance_improvement_pass"] is True


def test_bench_pass_criteria_fails_on_distance_only() -> None:
    """Verdict-exact lift passes (>=15pp) but distance improvement
    misses (< 0.05) → overall fail."""
    comparison = {"verdict_exact_pp_lift": 18.0, "mean_distance_improvement": 0.02}
    out = bench_pass_criteria(comparison)
    assert out["passed"] is False
    assert out["verdict_exact_pp_lift_pass"] is True
    assert out["mean_distance_improvement_pass"] is False


def test_bench_pass_criteria_fails_on_lift_only() -> None:
    comparison = {"verdict_exact_pp_lift": 12.0, "mean_distance_improvement": 0.10}
    out = bench_pass_criteria(comparison)
    assert out["passed"] is False
    assert out["verdict_exact_pp_lift_pass"] is False


def test_bench_pass_criteria_threshold_overrides() -> None:
    """Stricter thresholds let us tighten the gate later if needed."""
    comparison = {"verdict_exact_pp_lift": 18.0, "mean_distance_improvement": 0.08}
    out = bench_pass_criteria(
        comparison,
        min_verdict_exact_lift_pp=20.0,
        min_distance_improvement=0.05,
    )
    assert out["passed"] is False
    assert out["verdict_exact_pp_lift_pass"] is False


# ── run_suite (with stub runner_fn) ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_suite_iterates_baseline_and_skips_missing(
    tmp_path: Path,
) -> None:
    """run_suite reads regression_baseline.json, runs runner_fn for each
    file present on disk, skips missing files. Stub runner_fn echoes
    the oracle so we can assert the ordering."""
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "a.py").write_text("# a")
    (suite / "b.py").write_text("# b")
    # 'c.py' is in the oracle but missing from disk

    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({
        "files": [
            {"file_name": "a.py", "oracle_verdict": "clean", "tracking": "tier1"},
            {"file_name": "b.py", "oracle_verdict": "malicious", "tracking": "tier2"},
            {"file_name": "c.py", "oracle_verdict": "suspicious", "tracking": "tier1"},
        ]
    }))

    async def stub_runner(filename, content, baseline_meta):
        return BenchRow(
            file_name=filename,
            oracle_verdict=baseline_meta["oracle_verdict"],
            predicted_verdict=baseline_meta["oracle_verdict"],  # echo
            config="argus_full",
            cost_usd=0.01,
            duration_ms=100,
            baseline={"tracking": baseline_meta["tracking"]},
        )

    rows = await run_suite(suite, baseline, stub_runner)
    assert [r.file_name for r in rows] == ["a.py", "b.py"]
    assert rows[0].oracle_verdict == "clean"
    assert rows[1].oracle_verdict == "malicious"


@pytest.mark.asyncio
async def test_run_suite_captures_runner_exception_per_file(tmp_path: Path) -> None:
    """A runner exception on one file must not abort the whole suite —
    that file gets a row with error set; other files complete."""
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "ok.py").write_text("# ok")
    (suite / "bad.py").write_text("# bad")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({
        "files": [
            {"file_name": "ok.py", "oracle_verdict": "clean", "tracking": "tier1"},
            {"file_name": "bad.py", "oracle_verdict": "malicious", "tracking": "tier1"},
        ]
    }))

    async def flaky_runner(filename, content, baseline_meta):
        if filename == "bad.py":
            raise RuntimeError("simulated_failure")
        return BenchRow(
            file_name=filename,
            oracle_verdict=baseline_meta["oracle_verdict"],
            predicted_verdict="clean",
            config="argus_full",
            cost_usd=0.001,
            duration_ms=100,
            baseline={"tracking": baseline_meta["tracking"]},
        )

    rows = await run_suite(suite, baseline, flaky_runner)
    assert len(rows) == 2
    assert rows[0].error is None
    assert rows[1].error is not None
    assert "simulated_failure" in (rows[1].error or "")
    assert rows[1].predicted_verdict is None
