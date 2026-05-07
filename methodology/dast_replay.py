"""Tier 1 DAST replay (BENCH-014 / v1.1).

Re-runs only the DAST stage on saved L1 outputs from a prior bench run,
so we can capture per-finding validation data without re-paying for the
L1 cascade.

Why replay vs full re-run:
  * Step 9 (yesterday) ran the full Argus pipeline with Tier 0 DAST.
    L1 outputs are saved in argus_full_run1.json — vulnerabilities,
    behavioral_profile, attack_chains, etc.
  * Tier 1 only changes what happens INSIDE DAST (and engine post-
    processing). L1 outputs are unaffected.
  * Replay loads each row's L1 data, builds a minimal ScanResult-shape
    object, calls dast_runner directly, derives per-finding validation,
    saves augmented rows.

Cost: ~$15-25 for 23 files (DAST iterations only, no L1 re-run).
Wall clock: ~2-3 hours sequential.

Usage::

    uv run python -m methodology.dast_replay \\
        --input  bench_results/<step9_ts>/argus_full_run1.json \\
        --output bench_results/<step9_ts>/argus_full_run1_tier1.json \\
        --suite-dir samples/regression_v1
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from dast.per_finding import derive_per_finding_validation
from dast.runner import make_dast_runner_from_env
from methodology.bench import BenchRow, _load_existing_rows

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUITE = REPO_ROOT / "samples" / "regression_v1"

log = logging.getLogger("argus.dast_replay")


# ── Pseudo ScanResult (just the fields dast_runner reads) ────────────────────


class _ReplayScanResult:
    """Minimal ScanResult-shape object the dast_runner can consume.

    ``make_dast_runner_from_env`` calls into ``run_dast`` via a thin
    translator (``_scan_result_to_l1_output``) that reads
    ``final_verdict``, ``vulnerabilities``, ``behavioral_profile``,
    ``attack_chains``. We provide just those.
    """

    def __init__(self, row: BenchRow) -> None:
        self.final_verdict = row.predicted_verdict or "suspicious"
        self.vulnerabilities = list(row.vulnerabilities)
        self.behavioral_profile = dict(row.behavioral_profile)
        self.attack_chains = list(row.attack_chains)


# ── Replay one row ───────────────────────────────────────────────────────────


async def replay_one(
    row: BenchRow,
    *,
    dast_runner: Any,
    suite_dir: Path,
) -> dict[str, Any]:
    """Run only the DAST stage on one saved BenchRow's L1 data.

    Returns an augmented dict (BenchRow.to_dict() + Tier 1 fields) so
    the existing serialisation pipeline can write it out.
    """
    file_path = suite_dir / row.file_name
    if not file_path.exists():
        log.warning("file missing for replay: %s", file_path)
        out = row.to_dict()
        out["per_finding_validation"] = []
        out["dast_replay_error"] = "file_not_found"
        return out

    content = file_path.read_bytes()
    pseudo_result = _ReplayScanResult(row)

    # Build a Preprocessing-ish object — DAST runner reads this from
    # the engine's pipeline output. For replay, we pass an empty dict
    # (matching what bench.run_argus_pipeline_one's preprocessing
    # would produce for already-deobfuscated input). The DAST
    # orchestrator doesn't strictly require pp metadata.
    pp = {}

    t0 = time.time()
    error: str | None = None
    dast_findings: list[Any] = []
    dast_iterations: list[dict[str, Any]] = []
    dast_cost = 0.0
    dast_verdict_label = None
    journal_records: list[dict[str, Any]] = []
    try:
        dast_out = await dast_runner(row.file_name, content, pp, pseudo_result)
        dast_findings = (dast_out or {}).get("validated_findings") or []
        dast_iterations = (dast_out or {}).get("iterations") or []
        journal_records = (dast_out or {}).get("journal_records") or []
        dast_cost = float((dast_out or {}).get("total_cost_usd") or 0.0)
        final_verdict_obj = (dast_out or {}).get("final_verdict") or {}
        if isinstance(final_verdict_obj, dict):
            dast_verdict_label = final_verdict_obj.get("verdict_label")
    except Exception as e:  # noqa: BLE001
        error = f"{type(e).__name__}: {e}"
        log.warning("DAST replay failed for %s: %s", row.file_name, error)
    elapsed_ms = int((time.time() - t0) * 1000)

    per_finding = [
        pf.to_dict()
        for pf in derive_per_finding_validation(
            row.vulnerabilities,
            list(dast_findings),
            journal_records,
        )
    ]

    out = row.to_dict()
    out["per_finding_validation"] = per_finding
    out["dast_replay"] = {
        "dast_findings": list(dast_findings),
        "dast_iterations": list(dast_iterations),
        "dast_cost_usd": round(dast_cost, 6),
        "dast_duration_ms": elapsed_ms,
        "dast_verdict_label": dast_verdict_label,
        "error": error,
    }
    return out


# ── Atomic write ─────────────────────────────────────────────────────────────


def _atomic_write_json(path: Path, payload: list[dict[str, Any]]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    try:
        tmp.replace(path)
    except OSError:
        path.write_text(json.dumps(payload, indent=2))
        try:
            tmp.unlink()
        except OSError:
            pass


# ── Orchestrator ─────────────────────────────────────────────────────────────


async def replay_all(
    input_path: Path,
    output_path: Path,
    *,
    suite_dir: Path,
    dast_runner: Any,
    resume: bool = True,
    only_dast_eligible: bool = True,
) -> list[dict[str, Any]]:
    """Replay DAST on every row in ``input_path``.

    ``only_dast_eligible``: skip rows whose verdict isn't in DAST's
    trigger set ({malicious, critical_malicious}). DAST wouldn't have
    fired in the live pipeline; replaying would be wasteful and add
    no signal.

    ``resume``: if the output file already has rows, skip files already
    processed (matched by file_name).
    """
    rows = _load_existing_rows(input_path)
    print(f"  loaded {len(rows)} rows from {input_path}")

    existing: list[dict[str, Any]] = []
    done_names: set[str] = set()
    if resume and output_path.exists():
        try:
            existing = json.loads(output_path.read_text())
            done_names = {r["file_name"] for r in existing if "file_name" in r}
            print(f"  resuming with {len(done_names)} already-done rows")
        except (OSError, json.JSONDecodeError):
            existing = []
            done_names = set()

    out_rows: list[dict[str, Any]] = list(existing)
    eligible_verdicts = {"malicious", "critical_malicious"}

    for i, row in enumerate(rows, 1):
        if row.file_name in done_names:
            continue
        if only_dast_eligible and row.predicted_verdict not in eligible_verdicts:
            # Skip — DAST would not have fired. Carry the row through
            # with empty per-finding validation so the full file list
            # is preserved.
            out = row.to_dict()
            out["per_finding_validation"] = [
                pf.to_dict() for pf in derive_per_finding_validation(row.vulnerabilities, [])
            ]
            out["dast_replay"] = {"skipped_reason": "verdict_not_dast_eligible"}
            out_rows.append(out)
            print(
                f"  [{i:>2}/{len(rows)}] {row.file_name:<48} "
                f"SKIP (verdict={row.predicted_verdict} not in {eligible_verdicts})"
            )
            _atomic_write_json(output_path, out_rows)
            continue

        out = await replay_one(row, dast_runner=dast_runner, suite_dir=suite_dir)
        out_rows.append(out)
        _atomic_write_json(output_path, out_rows)

        replay_meta = out.get("dast_replay") or {}
        cost = replay_meta.get("dast_cost_usd", 0.0)
        dur = replay_meta.get("dast_duration_ms", 0)
        err = replay_meta.get("error")
        n_conf = sum(1 for pf in (out.get("per_finding_validation") or []) if pf.get("status") == "CONFIRMED")
        n_total = len(out.get("per_finding_validation") or [])
        print(
            f"  [{i:>2}/{len(rows)}] {row.file_name:<48} "
            f"confirmed={n_conf}/{n_total} cost=${cost:.4f} dur={dur}ms" + (f"  ERR: {err[:80]}" if err else "")
        )

    return out_rows


def main() -> int:
    parser = argparse.ArgumentParser(prog="dast_replay")
    parser.add_argument("--input", type=Path, required=True, help="step 9's argus_full_run1.json")
    parser.add_argument("--output", type=Path, required=True, help="path for Tier 1 augmented JSON")
    parser.add_argument("--suite-dir", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument(
        "--all-files",
        action="store_true",
        help="replay every file even if its verdict wouldn't trigger DAST in production",
    )
    args = parser.parse_args()

    load_dotenv(REPO_ROOT / ".env", override=True)

    if not args.input.exists():
        print(f"ERROR: input not found: {args.input}", file=sys.stderr)
        return 2

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 2

    dast_runner = make_dast_runner_from_env(api_key=api_key)
    if dast_runner is None:
        print(
            "ERROR: DAST runner couldn't be built — check FLY_API_TOKEN + image tags in .env",
            file=sys.stderr,
        )
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)

    print("=== DAST replay (Tier 1) ===")
    print(f"  input:  {args.input}")
    print(f"  output: {args.output}")
    print(f"  suite:  {args.suite_dir}")
    print(f"  dast eligibility: {'ALL' if args.all_files else 'malicious + critical_malicious only'}")
    print()

    out_rows = asyncio.run(
        replay_all(
            args.input,
            args.output,
            suite_dir=args.suite_dir,
            dast_runner=dast_runner,
            resume=not args.no_resume,
            only_dast_eligible=not args.all_files,
        )
    )

    n_total = len(out_rows)
    n_with_dast = sum(1 for r in out_rows if (r.get("dast_replay") or {}).get("skipped_reason") is None)
    total_cost = sum((r.get("dast_replay") or {}).get("dast_cost_usd", 0.0) for r in out_rows)
    n_errors = sum(1 for r in out_rows if (r.get("dast_replay") or {}).get("error"))
    print(f"\n  done: {n_total} rows, {n_with_dast} with DAST replay, ${total_cost:.4f} total, {n_errors} errors")
    print(f"  -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
