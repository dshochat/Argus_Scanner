"""Run a single voter on the 23-file regression suite (BENCH-014).

Usage::

    uv run python -m methodology.run_voter_pass --voter gemini --output \
        bench_results/<ts>/voters/gemini_3_1_pro.json

    uv run python -m methodology.run_voter_pass --voter gpt5 --model gpt-5.4 \
        --output bench_results/<ts>/voters/gpt_5_4.json

    uv run python -m methodology.run_voter_pass --voter grok --output \
        bench_results/<ts>/voters/grok_4_3.json

Streams per-file output as the run progresses; resumable on crash.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from methodology.voters import (
    VoterRecord,
    make_gemini_voter,
    make_gpt5_voter,
    make_grok_voter,
    run_voter,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUITE = REPO_ROOT / "samples" / "regression_v1"
DEFAULT_BASELINE = DEFAULT_SUITE / "regression_baseline.json"


def _load_files(suite_dir: Path, baseline_path: Path | None) -> list[tuple[str, bytes]]:
    """Load files in the regression suite that are listed in the baseline.

    When ``baseline_path`` is provided (default), only files named in
    ``regression_baseline.json`` are loaded — that's the canonical 23-file
    set we measure against. Without a baseline, every non-special file
    in ``suite_dir`` is loaded (use --no-filter for ad-hoc smokes).
    """
    if baseline_path and baseline_path.exists():
        import json as _json

        data = _json.loads(baseline_path.read_text())
        labelled = {f.get("file_name") for f in (data.get("files") or [])}
        labelled.discard(None)
    else:
        labelled = None  # no filter

    files: list[tuple[str, bytes]] = []
    for p in sorted(suite_dir.iterdir()):
        if not p.is_file():
            continue
        if p.name in {"regression_baseline.json", "oracle.json"}:
            continue
        if labelled is not None and p.name not in labelled:
            continue
        files.append((p.name, p.read_bytes()))
    return files


def _progress(i: int, n: int, record: VoterRecord) -> None:
    err = f"  ERR: {record.error}" if record.error else ""
    verdict = record.predicted_verdict or "?"
    print(
        f"  [{i:>2}/{n}] {record.file_name:<48} "
        f"verdict={verdict:<22} "
        f"score={record.composite_score if record.composite_score is not None else '?':>4} "
        f"cost=${record.cost_usd:>6.4f} "
        f"dur={record.duration_ms:>6}ms"
        f"{err}",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(prog="run_voter_pass")
    parser.add_argument(
        "--voter",
        choices=["gemini", "gpt5", "grok"],
        required=True,
        help="which voter to run",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="optional model override (default: gemini-3.1-pro-preview / gpt-5.4 / grok-4.3)",
    )
    parser.add_argument(
        "--suite-dir",
        type=Path,
        default=DEFAULT_SUITE,
        help=f"regression suite directory (default: {DEFAULT_SUITE})",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help=(
            f"regression baseline JSON; voter only runs on files listed in "
            f"this baseline (default: {DEFAULT_BASELINE}). Pass empty string "
            f"or --no-filter to run on every file in suite-dir."
        ),
    )
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="don't filter to baseline files (run on every file in suite-dir)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="output JSON path (atomic-saved per file; resumable on crash)",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="don't resume from existing output (re-run every file)",
    )
    args = parser.parse_args()

    load_dotenv(REPO_ROOT / ".env", override=True)

    baseline = None if args.no_filter else args.baseline
    files = _load_files(args.suite_dir, baseline)
    if not files:
        print(f"ERROR: no files found in {args.suite_dir}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)

    # Build the chosen voter.
    if args.voter == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            print("ERROR: GEMINI_API_KEY not set", file=sys.stderr)
            return 2
        voter = make_gemini_voter(api_key)
        voter_label = args.model or "gemini-3.1-pro-preview"
    elif args.voter == "gpt5":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            print("ERROR: OPENAI_API_KEY not set", file=sys.stderr)
            return 2
        model = args.model or "gpt-5.4"
        voter = make_gpt5_voter(api_key, model=model)
        voter_label = model
    elif args.voter == "grok":
        api_key = os.environ.get("GROK_API_KEY")
        if not api_key:
            print("ERROR: GROK_API_KEY not set", file=sys.stderr)
            return 2
        model = args.model or "grok-4.3"
        voter = make_grok_voter(api_key, model=model)
        voter_label = model
    else:
        print(f"ERROR: unknown voter: {args.voter}", file=sys.stderr)
        return 2

    print(f"=== voter pass: {args.voter} ({voter_label}) ===", flush=True)
    print(f"  suite:  {args.suite_dir}", flush=True)
    print(f"  files:  {len(files)}", flush=True)
    print(f"  output: {args.output}", flush=True)
    print()

    records = asyncio.run(
        run_voter(
            voter,
            files,
            output_path=args.output,
            progress_callback=_progress,
            resume=not args.no_resume,
        )
    )

    total_cost = sum(r.cost_usd for r in records)
    n_errors = sum(1 for r in records if r.error)
    print(
        f"\n  done: {len(records)} records, ${total_cost:.4f}, errors={n_errors}, output={args.output}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
