"""One-shot orchestrator for Phase A reporting (BENCH-010 + BENCH-011 + BENCH-012).

Reads BENCH-002 / BENCH-003 outputs from a bench_results timestamp dir,
produces:

  - comparison_report.json  (BENCH-010, free + deterministic)
  - comparison_report.md    (BENCH-010 human-readable)
  - gpt5_judgments.json     (BENCH-011, $5-15 — only if OPENAI_API_KEY set)
  - launch_report.md        (BENCH-012)

Usage::

    uv run python -m methodology.run_phase_a_report \\
        --bench-dir bench_results/20260506T000705Z \\
        [--skip-judge]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

from methodology.diff_report import build_diff_report, render_markdown
from methodology.judge import (
    DEFAULT_JUDGE_MODEL,
    disagreement_records,
    get_api_key_from_env,
    run_judge,
)
from methodology.launch_report import build_launch_report

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE = REPO_ROOT / "samples" / "regression_v1" / "regression_baseline.json"
DEFAULT_RICH = REPO_ROOT / "samples" / "extras" / "eval_benchmark_v1_ground_truth_augmented_final.json"
DEFAULT_SUITE = REPO_ROOT / "samples" / "regression_v1"


async def _run_judge_step(
    diff_records: list[dict],
    *,
    api_key: str,
    model: str,
    output_path: Path,
) -> int:
    targets = disagreement_records(diff_records)
    print(f"\nBENCH-011: {len(targets)} disagreements to send to {model}")
    if not targets:
        print("  (no disagreements — judge step skipped)")
        return 0

    def _progress(i: int, n: int, judgment) -> None:
        agree = (judgment.judgment or {}).get("agree_with") or "?"
        err = f" error={judgment.error}" if judgment.error else ""
        print(
            f"  [{i:>2}/{n}] {judgment.file_name:<48} "
            f"verdict={(judgment.judgment or {}).get('verdict') or '?':<22} "
            f"agree_with={agree}{err}",
            flush=True,
        )

    judgments = await run_judge(
        diff_records,
        api_key=api_key,
        model=model,
        output_path=output_path,
        progress_callback=_progress,
    )
    total_cost = sum(j.cost_usd for j in judgments)
    print(f"\n  -> {len(judgments)} judgments, ${total_cost:.4f}, saved {output_path}")
    return len(judgments)


def main() -> int:
    parser = argparse.ArgumentParser(prog="run_phase_a_report")
    parser.add_argument(
        "--bench-dir",
        type=Path,
        required=True,
        help="bench_results/<timestamp> — must contain raw_opus_run1.json + argus_full_run1.json (the 'no DAST' or main run)",
    )
    parser.add_argument(
        "--with-dast-bench-dir",
        type=Path,
        default=None,
        help="Optional second bench dir holding the DAST-enabled Argus run. When provided, the launch report renders 3 configs (no-DAST, +DAST, raw Opus). Reads only argus_full_run1.json from this dir; raw_opus + diff + judgments come from --bench-dir.",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help=f"baseline oracle path (default: {DEFAULT_BASELINE})",
    )
    parser.add_argument(
        "--rich-oracle",
        type=Path,
        default=DEFAULT_RICH,
        help="rich oracle path (Tier 2 finding overlap)",
    )
    parser.add_argument(
        "--suite-dir",
        type=Path,
        default=DEFAULT_SUITE,
        help="regression suite dir (for file content in judge payload)",
    )
    parser.add_argument(
        "--skip-judge",
        action="store_true",
        help="skip BENCH-011 (no OpenAI calls)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=f"judge model id (default: ${{JUDGE_MODEL}} env or {DEFAULT_JUDGE_MODEL})",
    )
    args = parser.parse_args()

    load_dotenv(REPO_ROOT / ".env", override=True)

    bench_dir = args.bench_dir
    if not bench_dir.exists():
        print(f"ERROR: bench dir not found: {bench_dir}", file=sys.stderr)
        return 2

    argus_path = bench_dir / "argus_full_run1.json"
    opus_path = bench_dir / "raw_opus_run1.json"
    if not argus_path.exists() or not opus_path.exists():
        print(
            f"ERROR: expected {argus_path.name} and {opus_path.name} in {bench_dir}",
            file=sys.stderr,
        )
        return 2

    diff_records_path = bench_dir / "comparison_report.json"
    diff_md_path = bench_dir / "comparison_report.md"
    judgments_path = bench_dir / "gpt5_judgments.json"
    launch_md_path = bench_dir / "launch_report.md"

    # ── BENCH-010 ──────────────────────────────────────────────────────────
    print("=== BENCH-010: three-source comparison ===")
    from methodology.bench import _load_existing_rows

    argus_rows = _load_existing_rows(argus_path)
    opus_rows = _load_existing_rows(opus_path)
    print(f"  argus rows: {len(argus_rows)}")
    print(f"  opus  rows: {len(opus_rows)}")

    diff_records = build_diff_report(
        argus_rows,
        opus_rows,
        args.baseline,
        args.rich_oracle if args.rich_oracle.exists() else None,
        suite_dir=args.suite_dir if args.suite_dir.exists() else None,
    )
    diff_records_path.write_text(json.dumps(diff_records, indent=2), encoding="utf-8")
    diff_md_path.write_text(render_markdown(diff_records), encoding="utf-8")
    n_disagreements = sum(1 for r in diff_records if r.get("judge_payload") is not None)
    print(f"  records: {len(diff_records)}, disagreements: {n_disagreements}")
    print(f"  -> {diff_records_path}")
    print(f"  -> {diff_md_path}")

    # ── BENCH-011 ──────────────────────────────────────────────────────────
    if args.skip_judge:
        print("\n=== BENCH-011: SKIPPED (--skip-judge) ===")
    else:
        api_key = get_api_key_from_env()
        if not api_key:
            print(
                "\n=== BENCH-011: SKIPPED (OPENAI_API_KEY not set) ===",
                file=sys.stderr,
            )
        else:
            import os

            model = args.model or os.environ.get("JUDGE_MODEL") or DEFAULT_JUDGE_MODEL
            print(f"\n=== BENCH-011: GPT judge ({model}) ===")
            asyncio.run(
                _run_judge_step(
                    diff_records,
                    api_key=api_key,
                    model=model,
                    output_path=judgments_path,
                )
            )

    # ── BENCH-012 ──────────────────────────────────────────────────────────
    print("\n=== BENCH-012: launch report ===")

    with_dast_path: Path | None = None
    if args.with_dast_bench_dir is not None:
        candidate = args.with_dast_bench_dir / "argus_full_run1.json"
        if candidate.exists():
            with_dast_path = candidate
            print(f"  +DAST argus rows: {with_dast_path}")
        else:
            print(
                f"  warning: --with-dast-bench-dir set but {candidate} not found; falling back to 2-config layout",
                file=sys.stderr,
            )

    summary = build_launch_report(
        argus_rows_path=argus_path,
        opus_rows_path=opus_path,
        baseline_oracle_path=args.baseline,
        rich_oracle_path=args.rich_oracle if args.rich_oracle.exists() else None,
        suite_dir=args.suite_dir if args.suite_dir.exists() else None,
        diff_records_path=diff_records_path,
        judgments_path=judgments_path if judgments_path.exists() else None,
        output_path=launch_md_path,
        argus_with_dast_rows_path=with_dast_path,
    )

    print(f"\n  argus exact (no DAST): {summary['argus_exact_pct']}%")
    if "argus_with_dast_exact_pct" in summary:
        print(f"  argus exact (+DAST):   {summary['argus_with_dast_exact_pct']}%")
        print(f"  lift +DAST:            {summary['lift_with_dast_pp']:+.1f}pp")
    print(f"  opus  exact:           {summary['opus_exact_pct']}%")
    print(f"  lift no-DAST:          {summary['lift_pp']:+.1f}pp")
    print(f"  judgments:             {summary['n_judgments']}")
    print(f"  -> {launch_md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
