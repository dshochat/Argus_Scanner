"""Build a multi-vendor consensus oracle from voter output files (BENCH-014).

Usage::

    uv run python -m methodology.build_consensus \\
        --opus-bench-rows bench_results/<ts>/raw_opus_run1.json \\
        --gemini-voter   bench_results/<ts>/voters/gemini_3_1_pro_max_thinking.json \\
        --gpt-voter      bench_results/<ts>/voters/gpt_5_4.json \\
        --grok-voter     bench_results/<ts>/voters/grok_4_3.json \\
        --output         bench_results/<ts>/consensus_oracle.json

Derives the canonical 23-file list from the existing
``regression_baseline.json``. Each voter's output is loaded; per-file
consensus is computed via ordinal-median verdict + majority-vote
on CWEs, capability tags, dangerous APIs, and behavioral categories.

Also writes a quick comparison summary to stdout (n_unanimous,
n_majority, files where new oracle differs from old).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from methodology.oracle_builder import (
    build_consensus_oracle,
    compare_oracles,
    write_consensus_oracle,
)
from methodology.voters import (
    _load_existing_voter_records,
    load_opus_voter_from_bench_rows,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE = REPO_ROOT / "samples" / "regression_v1" / "regression_baseline.json"


def _file_list_from_baseline(baseline_path: Path) -> list[str]:
    if not baseline_path.exists():
        return []
    data = json.loads(baseline_path.read_text())
    return [f["file_name"] for f in (data.get("files") or []) if f.get("file_name")]


def main() -> int:
    parser = argparse.ArgumentParser(prog="build_consensus")
    parser.add_argument(
        "--opus-bench-rows",
        type=Path,
        required=True,
        help="raw_opus_run1.json from a bench dir — converted to opus voter records",
    )
    parser.add_argument(
        "--gemini-voter",
        type=Path,
        required=True,
        help="Gemini voter JSON (output of run_voter_pass --voter gemini)",
    )
    parser.add_argument(
        "--gpt-voter",
        type=Path,
        required=True,
        help="OpenAI voter JSON (gpt-5.4)",
    )
    parser.add_argument(
        "--grok-voter",
        type=Path,
        required=True,
        help="Grok voter JSON",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help=f"regression baseline (default: {DEFAULT_BASELINE}) — defines the canonical file list",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="output path for consensus_oracle.json",
    )
    parser.add_argument(
        "--compare-old-oracle",
        action="store_true",
        help="emit a summary of how the new consensus oracle differs from --baseline",
    )
    args = parser.parse_args()

    # Validate inputs.
    missing = [
        p
        for p in [args.opus_bench_rows, args.gemini_voter, args.gpt_voter, args.grok_voter]
        if not p.exists()
    ]
    if missing:
        print(f"ERROR: missing inputs: {missing}", file=sys.stderr)
        return 2

    file_list = _file_list_from_baseline(args.baseline)
    if not file_list:
        print(f"ERROR: no files in baseline {args.baseline}", file=sys.stderr)
        return 2

    print(f"=== build consensus oracle ===")
    print(f"  baseline files: {len(file_list)}")
    print(f"  opus rows:      {args.opus_bench_rows}")
    print(f"  gemini voter:   {args.gemini_voter}")
    print(f"  gpt voter:      {args.gpt_voter}")
    print(f"  grok voter:     {args.grok_voter}")
    print()

    # Load voters. Opus comes from bench rows (we reuse BENCH-002 data,
    # don't re-pay API for it). The other three come from voter pass JSON.
    opus_records = load_opus_voter_from_bench_rows(args.opus_bench_rows)
    gemini_records = _load_existing_voter_records(args.gemini_voter)
    gpt_records = _load_existing_voter_records(args.gpt_voter)
    grok_records = _load_existing_voter_records(args.grok_voter)

    print("Loaded records per voter:")
    print(f"  opus_4_6:        {len(opus_records)}")
    print(f"  gemini_3_1_pro:  {len(gemini_records)}")
    print(f"  gpt_5_4:         {len(gpt_records)}")
    print(f"  grok_4_3:        {len(grok_records)}")
    print()

    # Persist each voter's records to a uniform layout (so build_consensus_oracle
    # can read them via _load_existing_voter_records). Opus comes from bench
    # rows so we materialise it as a voter file too.
    voters_dir = args.output.parent / "voters"
    voters_dir.mkdir(parents=True, exist_ok=True)
    opus_voter_path = voters_dir / "opus_4_6.json"
    opus_voter_path.write_text(json.dumps([r.to_dict() for r in opus_records], indent=2))
    print(f"  wrote opus voter records -> {opus_voter_path}")

    voter_files = {
        "opus_4_6": opus_voter_path,
        "gemini_3_1_pro": args.gemini_voter,
        "gpt_5_4": args.gpt_voter,
        "grok_4_3": args.grok_voter,
    }
    oracle = build_consensus_oracle(voter_files, file_list)
    write_consensus_oracle(oracle, args.output)
    print(f"\n  wrote consensus oracle -> {args.output}")

    # Quick stats.
    files = oracle.get("files", []) or []
    n_total = len(files)
    n_with_voters = sum(1 for f in files if f.get("n_voters", 0) > 0)
    n_unanimous = sum(1 for f in files if f.get("is_unanimous"))
    n_majority = sum(1 for f in files if f.get("is_majority") and not f.get("is_unanimous"))
    n_no_majority = sum(1 for f in files if f.get("n_voters", 0) > 0 and not f.get("is_majority"))

    print("\n=== consensus stats ===")
    print(f"  files with all voters:    {n_with_voters}/{n_total}")
    print(f"  unanimous (all 4 agree):  {n_unanimous}")
    print(f"  majority (3-1 or 2-1-1):  {n_majority}")
    print(f"  no majority (3-way+):     {n_no_majority}")
    print()

    # Compare to old oracle if requested.
    if args.compare_old_oracle:
        diff = compare_oracles(args.baseline, args.output)
        print("=== diff vs old oracle ===")
        print(f"  shared files:  {diff['n_shared']}")
        print(f"  changed:       {diff['n_changed']}")
        print(f"  only in old:   {diff['n_only_old']}")
        print(f"  only in new:   {diff['n_only_new']}")
        if diff["changed_files"]:
            print()
            print("  CHANGED labels:")
            for c in diff["changed_files"]:
                voter_str = ", ".join(
                    f"{k}={v}" for k, v in (c.get("voter_verdicts") or {}).items()
                )
                print(
                    f"    {c['file_name']:<48} "
                    f"old={c['old_verdict']!s:<22} -> new={c['new_verdict']!s:<22} "
                    f"(votes: {voter_str})"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
