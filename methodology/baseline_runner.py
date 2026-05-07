"""N=5 baseline characterization runner — Phase 3 methodology.

Aggregates N independent full-regression runs into a noise-aware
baseline file. Replaces the 3-run baseline (`_regression_baseline.json`)
with a per-file variance band that reflects the true L1 verdict
nondeterminism documented in `campaign_summary.md`.

Why N=5 (vs N=3)
----------------
Empirical: per-file verdict-flip rate observed at ~26% on Fireworks
(seed=0/temp=0). With N=3 votes per file, a 26%-flip distribution
yields ~52% probability that at least one of the three samples
disagrees with the most-frequent label — usable but noisy. N=5 cuts
that to ~17% and gives an exact 5th/95th percentile band; N=10 would
bring it to ~7% but doubles cost. N=5 is the sweet spot for our
~30-40-min wall clock per run.

Usage
-----
This script does NOT run the regression pipeline itself — orchestrating
five 30-minute Fireworks runs in one Python process is fragile (cookies,
rate limits, disk I/O). Instead, run the existing
`_run_full_regression_fireworks.py` (or any compatible runner) N times,
saving each run's JSON to a distinct path:

    for i in 1 2 3 4 5; do
      uv run python scripts/dast_prototype/_run_full_regression_fireworks.py
      mv scripts/dast_prototype/results/_full_regression_fireworks.json \\
         scripts/dast_prototype/results/_baseline_run_$i.json
    done

Then aggregate:

    uv run python scripts/dast_prototype/_run_baseline_characterization.py \\
        scripts/dast_prototype/results/_baseline_run_*.json

This emits `_regression_baseline_n5.json` with the new schema.

Input JSON shape
----------------
Each input file is the output of `_run_full_regression_fireworks.py` —
a dict with `results: list[per-file row]`, each row carrying
`file_name`, `oracle_verdict`, `dast_final_verdict`, `baseline.tier`,
`baseline.tracking`, `stratum`. The aggregator uses these fields and
ignores the rest.

Output schema
-------------
Drop-in compatible with the existing `_regression_baseline.json` plus
new fields. Each `files[i]` entry adds:

    {
      ...existing fields...
      "verdict_distribution": {"malicious": 4, "suspicious": 1},
      "most_frequent_verdict": "malicious",
      "most_frequent_pct": 80.0,
      "flip_rate": 0.2,
      "observed_band": ["suspicious", "malicious"],
      "mean_distance_to_oracle": 0.05,
      "distance_std_to_oracle": 0.10,
      "n_runs": 5,
      "source": "n5_characterization"
    }

The `baseline_verdict` is set to `most_frequent_verdict` (with the
security-conservative tie-break). `is_stable` is `True` only when all
N runs agreed; otherwise the file gets flagged with `flip_rate > 0`
and downstream regression scoring should weight accordingly.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# Windows console defaults to cp1252; output strings may include
# sigma / arrow glyphs. Reconfigure stdout to utf-8 if available.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

# Allow running both as a module and as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from methodology.scoring import (  # noqa: E402
    aggregate_run,
    characterize_file_variance,
)


def _load_run(path: Path) -> list[dict]:
    """Load a regression-run JSON; return its `results` list."""
    with path.open("r", encoding="utf-8") as f:
        doc = json.load(f)
    rows = doc.get("results")
    if not isinstance(rows, list):
        raise ValueError(f"{path}: missing 'results' list (got {type(rows).__name__})")
    return rows


def _key_run_by_file(rows: list[dict]) -> dict[str, dict]:
    """Build {file_name: row} index for one run."""
    out: dict[str, dict] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        fn = r.get("file_name")
        if isinstance(fn, str):
            out[fn] = r
    return out


def aggregate_baseline_runs(run_paths: list[Path]) -> dict:
    """Aggregate N regression-run JSONs into a single baseline doc.

    Cross-references runs by ``file_name``. Files present in some runs
    but missing from others are still characterized — their verdicts
    will list ``None`` for the missing runs and the variance band will
    reflect partial coverage.
    """
    if not run_paths:
        raise ValueError("aggregate_baseline_runs: no run paths supplied")

    runs = [(_load_run(p), p) for p in run_paths]
    n_runs = len(runs)

    # Union of file names across runs
    all_files: set[str] = set()
    for rows, _ in runs:
        for r in rows:
            if isinstance(r, dict) and isinstance(r.get("file_name"), str):
                all_files.add(r["file_name"])

    keyed_runs = [_key_run_by_file(rows) for rows, _ in runs]

    files_out: list[dict] = []
    for fn in sorted(all_files):
        # Per-run verdicts (None if file missing or verdict missing in this run)
        per_run_verdicts: list[str | None] = []
        oracle: str | None = None
        stratum: str | None = None
        tier: str | None = None
        tracking: str | None = None
        for keyed in keyed_runs:
            row = keyed.get(fn)
            if row is None:
                per_run_verdicts.append(None)
                continue
            v = row.get("dast_final_verdict")
            per_run_verdicts.append(v if isinstance(v, str) else None)
            # Capture stable per-file metadata from any run that has it
            if oracle is None and isinstance(row.get("oracle_verdict"), str):
                oracle = row["oracle_verdict"]
            if stratum is None and isinstance(row.get("stratum"), str):
                stratum = row["stratum"]
            base_block = row.get("baseline") or {}
            if isinstance(base_block, dict):
                if tier is None and isinstance(base_block.get("tier"), str):
                    tier = base_block["tier"]
                if tracking is None and isinstance(base_block.get("tracking"), str):
                    tracking = base_block["tracking"]

        band = characterize_file_variance(
            file_name=fn,
            per_run_verdicts=per_run_verdicts,
            oracle=oracle,
        )

        # Build the file entry preserving the legacy schema fields and
        # extending with characterization metadata.
        files_out.append(
            {
                "file_name": fn,
                "stratum": stratum or "?",
                "oracle_verdict": oracle,
                "baseline_verdict": band.most_frequent_verdict,
                "variance_band": band.observed_band,
                "is_stable": band.is_stable,
                "n_runs": n_runs,
                "tier": tier or "miss",
                "tracking": tracking or "tier3",
                "source": "n5_characterization",
                # New methodology fields
                "verdict_distribution": band.verdict_distribution,
                "most_frequent_verdict": band.most_frequent_verdict,
                "most_frequent_pct": band.most_frequent_pct,
                "flip_rate": band.flip_rate,
                "mean_distance_to_oracle": band.mean_distance_to_oracle,
                "distance_std_to_oracle": band.distance_std_to_oracle,
            }
        )

    # Aggregate-level rollups
    n_oracle_match = sum(
        1 for f in files_out if f["oracle_verdict"] and f["most_frequent_verdict"] == f["oracle_verdict"]
    )
    n_stable = sum(1 for f in files_out if f["is_stable"])
    n_unstable = len(files_out) - n_stable

    # Per-run verdict-exact + verdict-distance summaries
    per_run_summaries = []
    for keyed in keyed_runs:
        rows = list(keyed.values())
        s = aggregate_run(rows)
        per_run_summaries.append(
            {
                "n_scored": s.n_scored,
                "verdict_exact": s.verdict_exact,
                "verdict_exact_pct": s.verdict_exact_pct,
                "mean_distance": s.mean_distance,
            }
        )

    tier_breakdown = defaultdict(int)
    tracking_breakdown = defaultdict(int)
    for f in files_out:
        tier_breakdown[f["tier"]] += 1
        tracking_breakdown[f["tracking"]] += 1

    # Mean across runs for the headline number
    mean_exact = (sum(s["verdict_exact_pct"] for s in per_run_summaries) / n_runs) if n_runs else 0.0
    mean_dist = (sum(s["mean_distance"] for s in per_run_summaries) / n_runs) if n_runs else 0.0

    return {
        "n_files": len(files_out),
        "n_runs": n_runs,
        "n_oracle_match_most_frequent": n_oracle_match,
        "verdict_exact_pct_mean_across_runs": round(mean_exact, 2),
        "mean_distance_across_runs": round(mean_dist, 4),
        "stability": {
            "stable_files": n_stable,
            "unstable_files": n_unstable,
            "unstable_pct": (round(100.0 * n_unstable / len(files_out), 2) if files_out else 0.0),
        },
        "tier_breakdown": dict(tier_breakdown),
        "tracking_breakdown": dict(tracking_breakdown),
        "per_run_summaries": per_run_summaries,
        "input_run_paths": [str(p) for _, p in runs],
        "files": files_out,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate N pre-computed regression run JSONs into a single "
            "noise-aware baseline. Inputs are the JSON outputs of "
            "_run_full_regression_fireworks.py (or any runner emitting "
            "the same schema)."
        ),
    )
    parser.add_argument(
        "runs",
        nargs="+",
        type=Path,
        help="Paths to N regression-run JSON files (recommended N=5)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path(__file__).parent / "_regression_baseline_n5.json",
        help="Output baseline JSON path",
    )
    args = parser.parse_args()

    for p in args.runs:
        if not p.exists():
            print(f"ERROR: input file not found: {p}", file=sys.stderr)
            return 2

    if len(args.runs) < 3:
        print(
            f"WARNING: aggregating only {len(args.runs)} run(s); "
            "N≥3 is recommended for a useful variance band, N=5 ideal.",
            file=sys.stderr,
        )

    doc = aggregate_baseline_runs(args.runs)
    args.output.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Console summary
    print(f"\n=== N={doc['n_runs']} baseline characterization ===")
    print(f"  Files: {doc['n_files']}")
    print(f"  Mean verdict-exact across runs: {doc['verdict_exact_pct_mean_across_runs']}%")
    print(f"  Mean distance across runs: {doc['mean_distance_across_runs']}")
    stability = doc["stability"]
    print(
        f"  Stable files (all N runs agree): {stability['stable_files']} / "
        f"{doc['n_files']} ({100 - stability['unstable_pct']}%)"
    )
    print(f"  Unstable files (any disagreement): {stability['unstable_files']} ({stability['unstable_pct']}%)")
    print(f"  Wrote: {args.output}")

    # List the most unstable files (highest flip_rate)
    unstable = [f for f in doc["files"] if not f["is_stable"]]
    if unstable:
        unstable.sort(key=lambda f: f["flip_rate"], reverse=True)
        print("\n  Highest-variance files (verdict flips across runs):")
        for f in unstable[:10]:
            dist_summary = ", ".join(f"{lbl}={n}" for lbl, n in f["verdict_distribution"].items())
            print(
                f"    {f['file_name']:42s}  "
                f"flip_rate={f['flip_rate']:.2f}  "
                f"oracle={f['oracle_verdict']}  "
                f"distribution={{{dist_summary}}}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
