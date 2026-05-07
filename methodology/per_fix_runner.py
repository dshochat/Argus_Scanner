"""N=3 per-fix evaluation runner — Phase 3 methodology.

Compares two sets of regression-run JSONs (a "before" group and an
"after" group) and reports whether the fix between them produced a
detectable lift, accounting for run-to-run variance.

Why N=3 (vs N=5 for baseline)
-----------------------------
N=5 baseline characterization is a one-time cost — it sets the variance
band against which every subsequent fix is measured. Per-fix evaluation
is a recurring cost (one or two runs per code change), so we want it
cheap. N=3 each side gives a pooled standard error large enough to
demand real signals while keeping the wall-clock at ~2 hours per
evaluation.

The lift gate uses ``min_z=1.0`` by default — a soft 1σ threshold that
matches small-N statistics. Tune up to 1.96σ (roughly "95% confident")
for stricter calls when stakes are higher.

Usage
-----
    # 1. Run regression on "before" code state N=3 times
    git checkout main
    for i in 1 2 3; do
      uv run python scripts/dast_prototype/_run_full_regression_fireworks.py
      mv scripts/dast_prototype/results/_full_regression_fireworks.json \\
         scripts/dast_prototype/results/_eval_before_$i.json
    done

    # 2. Apply the fix, run N=3 more
    git checkout my-fix-branch
    for i in 1 2 3; do
      uv run python scripts/dast_prototype/_run_full_regression_fireworks.py
      mv scripts/dast_prototype/results/_full_regression_fireworks.json \\
         scripts/dast_prototype/results/_eval_after_$i.json
    done

    # 3. Compare
    uv run python scripts/dast_prototype/_run_per_fix_evaluation.py \\
        --before scripts/dast_prototype/results/_eval_before_*.json \\
        --after  scripts/dast_prototype/results/_eval_after_*.json

Output
------
Console report + JSON file with:

    {
      "n_before": 3,
      "n_after": 3,
      "before_mean_exact_pct": 43.5,
      "after_mean_exact_pct": 56.5,
      "exact_lift_pp": 13.0,
      "before_mean_distance": 0.30,
      "after_mean_distance": 0.20,
      "distance_lift": -0.10,
      "z_exact": 4.62,
      "z_distance": -3.18,
      "lift_detected": true,
      "rationale": "exact +13.00pp (z=+4.62σ); distance -0.1000 (z=-3.18σ — improvement)",
      "min_z_threshold": 1.0,
      "per_file_changes": {
        "litellm_obfuscated.py": {
          "before_distribution": {"suspicious": 3},
          "after_distribution":  {"critical_malicious": 3},
          "improved": true
        },
        ...
      }
    }
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# Windows console defaults to cp1252; the rationale strings include
# sigma + arrow glyphs. Reconfigure stdout to utf-8 if available.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from methodology.scoring import (  # noqa: E402
    aggregate_run,
    assess_lift,
    characterize_file_variance,
)


def _load_run_results(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as f:
        doc = json.load(f)
    rows = doc.get("results")
    if not isinstance(rows, list):
        raise ValueError(f"{path}: missing 'results' list (got {type(rows).__name__})")
    return rows


def evaluate_fix(
    before_paths: list[Path],
    after_paths: list[Path],
    *,
    min_z: float = 1.0,
) -> dict:
    """Compare before/after regression runs and report lift assessment."""
    before_rows = [_load_run_results(p) for p in before_paths]
    after_rows = [_load_run_results(p) for p in after_paths]

    before_summaries = [aggregate_run(rows) for rows in before_rows]
    after_summaries = [aggregate_run(rows) for rows in after_rows]

    lift = assess_lift(before_summaries, after_summaries, min_z=min_z)

    # Per-file change analysis: did each file's verdict distribution
    # shift in a meaningful way across the runs?
    per_file_before: dict[str, list[str | None]] = defaultdict(list)
    per_file_after: dict[str, list[str | None]] = defaultdict(list)
    per_file_oracle: dict[str, str | None] = {}
    per_file_tier: dict[str, str | None] = {}

    for run in before_rows:
        for r in run:
            if not isinstance(r, dict):
                continue
            fn = r.get("file_name")
            if not isinstance(fn, str):
                continue
            per_file_before[fn].append(r.get("dast_final_verdict"))
            if fn not in per_file_oracle and isinstance(r.get("oracle_verdict"), str):
                per_file_oracle[fn] = r["oracle_verdict"]
            base = r.get("baseline") or {}
            if fn not in per_file_tier and isinstance(base, dict) and isinstance(base.get("tracking"), str):
                per_file_tier[fn] = base["tracking"]

    for run in after_rows:
        for r in run:
            if not isinstance(r, dict):
                continue
            fn = r.get("file_name")
            if not isinstance(fn, str):
                continue
            per_file_after[fn].append(r.get("dast_final_verdict"))
            if fn not in per_file_oracle and isinstance(r.get("oracle_verdict"), str):
                per_file_oracle[fn] = r["oracle_verdict"]

    per_file_changes: dict[str, dict] = {}
    for fn in sorted(set(per_file_before.keys()) | set(per_file_after.keys())):
        oracle = per_file_oracle.get(fn)
        before_band = characterize_file_variance(
            file_name=fn,
            per_run_verdicts=per_file_before.get(fn, []),
            oracle=oracle,
        )
        after_band = characterize_file_variance(
            file_name=fn,
            per_run_verdicts=per_file_after.get(fn, []),
            oracle=oracle,
        )

        # Did the after distribution improve over the before distribution
        # in mean distance to oracle? Three-way classification:
        #   "improved"  — after_distance < before_distance
        #   "regressed" — after_distance > before_distance
        #   "unchanged" — equal distances (same most-frequent verdict + same
        #                 distribution + so same mean)
        #   "unknown"   — oracle missing on either side
        change_status: str
        if before_band.mean_distance_to_oracle is None or after_band.mean_distance_to_oracle is None:
            change_status = "unknown"
        elif after_band.mean_distance_to_oracle < before_band.mean_distance_to_oracle:
            change_status = "improved"
        elif after_band.mean_distance_to_oracle > before_band.mean_distance_to_oracle:
            change_status = "regressed"
        else:
            change_status = "unchanged"

        per_file_changes[fn] = {
            "tier": per_file_tier.get(fn),
            "oracle": oracle,
            "before_distribution": before_band.verdict_distribution,
            "after_distribution": after_band.verdict_distribution,
            "before_most_frequent": before_band.most_frequent_verdict,
            "after_most_frequent": after_band.most_frequent_verdict,
            "before_flip_rate": before_band.flip_rate,
            "after_flip_rate": after_band.flip_rate,
            "before_mean_distance": before_band.mean_distance_to_oracle,
            "after_mean_distance": after_band.mean_distance_to_oracle,
            "change_status": change_status,
        }

    return {
        "min_z_threshold": min_z,
        "before_paths": [str(p) for p in before_paths],
        "after_paths": [str(p) for p in after_paths],
        "n_before": lift.n_before,
        "n_after": lift.n_after,
        "before_mean_exact_pct": lift.before_mean_exact_pct,
        "after_mean_exact_pct": lift.after_mean_exact_pct,
        "exact_lift_pp": lift.exact_lift_pp,
        "pooled_se_exact_pct": lift.pooled_se_exact_pct,
        "z_exact": lift.z_exact,
        "before_mean_distance": lift.before_mean_distance,
        "after_mean_distance": lift.after_mean_distance,
        "distance_lift": lift.distance_lift,
        "pooled_se_distance": lift.pooled_se_distance,
        "z_distance": lift.z_distance,
        "lift_detected": lift.lift_detected,
        "rationale": lift.rationale,
        "before_per_run": [
            {
                "verdict_exact_pct": s.verdict_exact_pct,
                "mean_distance": s.mean_distance,
            }
            for s in before_summaries
        ],
        "after_per_run": [
            {
                "verdict_exact_pct": s.verdict_exact_pct,
                "mean_distance": s.mean_distance,
            }
            for s in after_summaries
        ],
        "per_file_changes": per_file_changes,
    }


def _print_report(report: dict) -> None:
    """Print a console-friendly summary of the lift assessment."""
    print(f"\n=== Per-fix evaluation (N_before={report['n_before']}, N_after={report['n_after']}) ===")
    print(
        f"  Verdict-exact: {report['before_mean_exact_pct']:.2f}% ->"
        f"{report['after_mean_exact_pct']:.2f}% "
        f"({report['exact_lift_pp']:+.2f}pp, "
        f"z={report['z_exact'] if report['z_exact'] is not None else 'N/A'})"
    )
    print(
        f"  Mean distance: {report['before_mean_distance']:.4f} ->"
        f"{report['after_mean_distance']:.4f} "
        f"({report['distance_lift']:+.4f}, "
        f"z={report['z_distance'] if report['z_distance'] is not None else 'N/A'})"
    )
    print(f"  min_z threshold: {report['min_z_threshold']:.1f} sigma")
    print(f"  Lift detected: {'YES' if report['lift_detected'] else 'NO'}")
    print(f"  Rationale: {report['rationale']}")

    # Per-file: what improved, what didn't, what regressed
    improved = []
    regressed = []
    unchanged = []
    for fn, change in report["per_file_changes"].items():
        status = change.get("change_status")
        if status == "improved":
            improved.append((fn, change))
        elif status == "regressed":
            regressed.append((fn, change))
        elif status == "unchanged":
            unchanged.append((fn, change))

    if improved:
        improved.sort(
            key=lambda x: (
                x[1]["before_mean_distance"] - x[1]["after_mean_distance"]
                if (x[1]["before_mean_distance"] is not None and x[1]["after_mean_distance"] is not None)
                else 0
            ),
            reverse=True,
        )
        print("\n  Files that improved (mean distance dropped):")
        for fn, c in improved[:10]:
            print(
                f"    {fn:42s}  oracle={c['oracle']}  "
                f"before={c['before_most_frequent']}  -> "
                f"after={c['after_most_frequent']}"
            )

    if regressed:
        print("\n  Files that regressed (mean distance grew):")
        for fn, c in regressed[:10]:
            print(
                f"    {fn:42s}  oracle={c['oracle']}  "
                f"before={c['before_most_frequent']}  -> "
                f"after={c['after_most_frequent']}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare before/after regression-run JSONs and report whether "
            "the fix produced a detectable lift, accounting for run-to-run "
            "variance. Default min_z=1.0 (soft 1σ). Tune up to 1.96σ for "
            "stricter calls."
        ),
    )
    parser.add_argument(
        "--before",
        nargs="+",
        required=True,
        type=Path,
        help="N regression-run JSONs from the BEFORE state (recommended N=3)",
    )
    parser.add_argument(
        "--after",
        nargs="+",
        required=True,
        type=Path,
        help="N regression-run JSONs from the AFTER state (recommended N=3)",
    )
    parser.add_argument(
        "--min-z",
        type=float,
        default=1.0,
        help="Minimum z-score for lift detection (default 1.0σ; try 1.96σ for ~95% confidence)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path(__file__).parent / "_per_fix_evaluation.json",
        help="Output report JSON path",
    )
    args = parser.parse_args()

    for p in list(args.before) + list(args.after):
        if not p.exists():
            print(f"ERROR: input file not found: {p}", file=sys.stderr)
            return 2

    if len(args.before) < 2 or len(args.after) < 2:
        print(
            f"WARNING: N_before={len(args.before)}, N_after={len(args.after)}; "
            "N≥2 each side is the minimum to compute pooled SE; "
            "N=3 each is recommended.",
            file=sys.stderr,
        )

    report = evaluate_fix(args.before, args.after, min_z=args.min_z)
    args.output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    _print_report(report)
    print(f"\n  Wrote: {args.output}")

    return 0 if report["lift_detected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
