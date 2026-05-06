"""Verdict-distance + run-aggregation helpers — Phase 3 methodology.

The DAST campaign closure (2026-05-04) showed that verdict-exact
single-run scoring has too much noise to detect ±2-file lifts honestly
(L1 verdicts flip on ~6/23 files between two Fireworks runs at
seed=0/temp=0). This module adds the building blocks for the
methodology upgrade documented in ``ROADMAP.md`` Phase 1.5:

  * ``verdict_distance(predicted, oracle)`` — continuous metric in
    [0, 1.25] computed from the verdict anchor scale (clean=0,
    informational=25, suspicious=50, malicious=75, critical=100).
    Captures direction even when the categorical label flips. A
    suspicious-vs-malicious miss (one notch) scores 0.25; a clean-vs-
    critical miss (full disagreement) scores 1.0.

  * ``aggregate_run_distance(rows)`` — mean / total / per-tier
    breakdown of verdict-distance across a regression run.

  * ``aggregate_run_exact(rows)`` — verdict-exact rate alongside
    distance, so callers see both numbers.

  * ``aggregate_runs_for_lift(before_runs, after_runs)`` — N=3
    before-vs-after comparison with confidence-interval gate. Reports
    "lift_detected" only when the after_mean improvement exceeds the
    pooled standard error by ``min_z`` (default 1.0σ — a soft gate
    matched to small-N runs; tune up to 1.96 for stricter calls).

The shape of ``rows`` matches ``_run_full_regression_fireworks.py``
output: each row is a dict with at minimum ``oracle_verdict``,
``dast_final_verdict``, ``baseline.tracking`` (tier1 / tier2 / tier3).
Missing fields are tolerated — a row with no oracle is skipped from
distance scoring.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Any, Iterable

# Anchors mirror ``shared.types.enums.VERDICT_ANCHORS`` but keyed by
# label-string. Kept local so the prototype's scripts/ surface stays
# importable without the full echoDefense package being installed.
VERDICT_ANCHORS: dict[str, int] = {
    "clean": 0,
    "informational": 25,
    "suspicious": 50,
    "malicious": 75,
    "critical_malicious": 100,
}

VERDICT_RANK: dict[str, int] = {
    label: i for i, label in enumerate(
        ["clean", "informational", "suspicious", "malicious", "critical_malicious"]
    )
}


def verdict_distance(predicted: str | None, oracle: str | None) -> float | None:
    """Return the verdict distance ``|anchor(p) - anchor(o)| / 100``.

    Returns ``None`` if either side is missing or unrecognized — the
    caller should skip the row in aggregations rather than treat the
    missing label as zero distance (which would silently inflate
    "perfect match" rates).

    Range when both sides resolve: ``[0.0, 1.0]``. A one-notch miss
    (e.g. malicious vs critical_malicious) is 0.25; a full
    disagreement (clean vs critical_malicious) is 1.0.
    """
    if not predicted or not oracle:
        return None
    p_anchor = VERDICT_ANCHORS.get(predicted)
    o_anchor = VERDICT_ANCHORS.get(oracle)
    if p_anchor is None or o_anchor is None:
        return None
    return abs(p_anchor - o_anchor) / 100.0


@dataclass(frozen=True)
class RunSummary:
    """Aggregate scoring of a single regression run."""

    n_scored: int  # rows with both oracle and predicted resolvable
    n_skipped: int  # rows with missing oracle / predicted / unresolvable label
    verdict_exact: int
    verdict_exact_pct: float  # 0.0 - 100.0
    mean_distance: float  # over scored rows
    sum_distance: float
    per_tier: dict[str, dict[str, Any]] = field(default_factory=dict)


def aggregate_run(
    rows: Iterable[dict],
    *,
    oracle_field: str = "oracle_verdict",
    predicted_field: str = "dast_final_verdict",
    tier_path: tuple[str, ...] = ("baseline", "tracking"),
) -> RunSummary:
    """Score one regression run by both verdict-exact and verdict-distance.

    ``rows`` is an iterable of per-file dicts (the shape produced by
    ``_run_full_regression_fireworks.py``). ``tier_path`` is a tuple of
    nested keys to read the file's tracking tier (default
    ``baseline.tracking``).

    Per-tier breakdown groups by ``tier1`` / ``tier2`` / ``tier3`` and
    reports n / verdict_exact / mean_distance for each tier. Tiers with
    zero scored rows are omitted from the per-tier dict.
    """
    rows = list(rows)
    n_scored = 0
    n_skipped = 0
    verdict_exact = 0
    sum_dist = 0.0
    per_tier_acc: dict[str, dict[str, float]] = {}

    for row in rows:
        oracle = row.get(oracle_field)
        predicted = row.get(predicted_field)
        d = verdict_distance(predicted, oracle)
        if d is None:
            n_skipped += 1
            continue
        n_scored += 1
        sum_dist += d
        if predicted == oracle:
            verdict_exact += 1
        # Walk tier_path
        tier_value: Any = row
        for key in tier_path:
            if isinstance(tier_value, dict):
                tier_value = tier_value.get(key)
            else:
                tier_value = None
                break
        if isinstance(tier_value, str):
            t = per_tier_acc.setdefault(
                tier_value, {"n": 0, "verdict_exact": 0, "sum_distance": 0.0}
            )
            t["n"] += 1
            t["sum_distance"] += d
            if predicted == oracle:
                t["verdict_exact"] += 1

    per_tier_out: dict[str, dict[str, Any]] = {}
    for tier, acc in per_tier_acc.items():
        n_t = int(acc["n"])
        per_tier_out[tier] = {
            "n": n_t,
            "verdict_exact": int(acc["verdict_exact"]),
            "verdict_exact_pct": (
                round(100.0 * acc["verdict_exact"] / n_t, 2) if n_t else 0.0
            ),
            "mean_distance": round(acc["sum_distance"] / n_t, 4) if n_t else 0.0,
        }

    mean_dist = sum_dist / n_scored if n_scored else 0.0
    pct = 100.0 * verdict_exact / n_scored if n_scored else 0.0
    return RunSummary(
        n_scored=n_scored,
        n_skipped=n_skipped,
        verdict_exact=verdict_exact,
        verdict_exact_pct=round(pct, 2),
        mean_distance=round(mean_dist, 4),
        sum_distance=round(sum_dist, 4),
        per_tier=per_tier_out,
    )


@dataclass(frozen=True)
class FileVarianceBand:
    """N-run variance characterization for a single file."""

    file_name: str
    n_runs: int
    verdict_distribution: dict[str, int]
    most_frequent_verdict: str
    most_frequent_pct: float  # 0.0 - 100.0
    is_stable: bool  # all N runs same verdict
    flip_rate: float  # 1 - (most_frequent_pct / 100)
    observed_band: list[str]  # min and max verdict by anchor across runs
    mean_distance_to_oracle: float | None  # None if oracle unknown
    distance_std_to_oracle: float | None  # population stddev across runs


def characterize_file_variance(
    file_name: str,
    per_run_verdicts: list[str | None],
    oracle: str | None = None,
) -> FileVarianceBand:
    """Compute the noise-aware variance band for one file across N runs.

    ``per_run_verdicts`` is the list of ``dast_final_verdict`` values
    observed across runs. ``None`` entries (e.g. errored rows) are
    excluded from the distribution but the run still counts toward
    ``n_runs``. If every run errors, the band is empty.
    """
    n_runs = len(per_run_verdicts)
    valid = [v for v in per_run_verdicts if v]
    distribution: dict[str, int] = {}
    for v in valid:
        distribution[v] = distribution.get(v, 0) + 1

    if not distribution:
        return FileVarianceBand(
            file_name=file_name,
            n_runs=n_runs,
            verdict_distribution={},
            most_frequent_verdict="",
            most_frequent_pct=0.0,
            is_stable=False,
            flip_rate=1.0,
            observed_band=[],
            mean_distance_to_oracle=None,
            distance_std_to_oracle=None,
        )

    # Most frequent (ties broken by highest anchor — security-conservative)
    max_count = max(distribution.values())
    candidates = [v for v, c in distribution.items() if c == max_count]
    candidates.sort(key=lambda v: VERDICT_ANCHORS.get(v, -1), reverse=True)
    mf = candidates[0]
    mf_pct = 100.0 * max_count / len(valid)

    # Observed band — sorted by anchor; reports the [min, max] verdict
    # actually seen. With N=5 this is exact (5th-95th percentile = min/max).
    sorted_by_anchor = sorted(
        distribution.keys(), key=lambda v: VERDICT_ANCHORS.get(v, 0)
    )
    band = [sorted_by_anchor[0], sorted_by_anchor[-1]] if sorted_by_anchor else []

    is_stable = len(distribution) == 1
    flip_rate = 1.0 - (max_count / len(valid))

    # Oracle distance stats
    if oracle and oracle in VERDICT_ANCHORS:
        per_run_dist = [
            verdict_distance(v, oracle) for v in per_run_verdicts
        ]
        per_run_dist = [d for d in per_run_dist if d is not None]
        if per_run_dist:
            mean_d = sum(per_run_dist) / len(per_run_dist)
            std_d = (
                statistics.pstdev(per_run_dist)
                if len(per_run_dist) > 1
                else 0.0
            )
        else:
            mean_d = None
            std_d = None
    else:
        mean_d = None
        std_d = None

    return FileVarianceBand(
        file_name=file_name,
        n_runs=n_runs,
        verdict_distribution=distribution,
        most_frequent_verdict=mf,
        most_frequent_pct=round(mf_pct, 2),
        is_stable=is_stable,
        flip_rate=round(flip_rate, 4),
        observed_band=band,
        mean_distance_to_oracle=round(mean_d, 4) if mean_d is not None else None,
        distance_std_to_oracle=round(std_d, 4) if std_d is not None else None,
    )


@dataclass(frozen=True)
class LiftAssessment:
    """Before-vs-after lift assessment with a confidence-interval gate."""

    n_before: int
    n_after: int
    before_mean_exact_pct: float
    after_mean_exact_pct: float
    before_mean_distance: float
    after_mean_distance: float
    exact_lift_pp: float  # percentage-points; positive = improvement
    distance_lift: float  # negative = improvement (lower distance is better)
    pooled_se_exact_pct: float  # standard error of the difference
    pooled_se_distance: float
    z_exact: float | None  # exact_lift / pooled_se_exact (None if SE=0)
    z_distance: float | None
    lift_detected: bool  # |z_exact| >= min_z OR |z_distance| >= min_z
    rationale: str


def assess_lift(
    before_summaries: list[RunSummary],
    after_summaries: list[RunSummary],
    min_z: float = 1.0,
) -> LiftAssessment:
    """Pool N=3 before runs and N=3 after runs into a lift judgment.

    Uses the standard two-sample comparison: pooled SE = sqrt(s_b²/n_b
    + s_a²/n_a). With N=3 each, this is a soft estimate; ``min_z=1.0``
    matches that softness. Tune up to 1.96 for stricter "we're 95%
    confident there's a lift" calls.

    A negative ``distance_lift`` is good — lower distance to oracle is
    closer to the right answer. The ``rationale`` string explains
    which metric (if any) crossed the gate.
    """
    if not before_summaries or not after_summaries:
        return LiftAssessment(
            n_before=len(before_summaries),
            n_after=len(after_summaries),
            before_mean_exact_pct=0.0,
            after_mean_exact_pct=0.0,
            before_mean_distance=0.0,
            after_mean_distance=0.0,
            exact_lift_pp=0.0,
            distance_lift=0.0,
            pooled_se_exact_pct=0.0,
            pooled_se_distance=0.0,
            z_exact=None,
            z_distance=None,
            lift_detected=False,
            rationale="empty input — no runs to compare",
        )

    before_exact = [s.verdict_exact_pct for s in before_summaries]
    after_exact = [s.verdict_exact_pct for s in after_summaries]
    before_dist = [s.mean_distance for s in before_summaries]
    after_dist = [s.mean_distance for s in after_summaries]

    bm_exact = statistics.mean(before_exact)
    am_exact = statistics.mean(after_exact)
    bm_dist = statistics.mean(before_dist)
    am_dist = statistics.mean(after_dist)

    # Pooled SE for difference of means. Use sample variance (n-1) when
    # we have ≥ 2 samples; fall back to 0 with a single sample.
    def _var(xs: list[float]) -> float:
        return statistics.variance(xs) if len(xs) >= 2 else 0.0

    se_exact = math.sqrt(
        _var(before_exact) / len(before_exact)
        + _var(after_exact) / len(after_exact)
    )
    se_dist = math.sqrt(
        _var(before_dist) / len(before_dist)
        + _var(after_dist) / len(after_dist)
    )

    exact_lift = am_exact - bm_exact
    distance_lift = am_dist - bm_dist

    z_e = (exact_lift / se_exact) if se_exact > 0 else None
    z_d = (distance_lift / se_dist) if se_dist > 0 else None

    # Detect lift if either metric crosses min_z in the IMPROVING direction
    # (positive z_exact = exact rate up; negative z_distance = distance down).
    detected = False
    parts: list[str] = []
    if z_e is not None and z_e >= min_z:
        detected = True
        parts.append(
            f"exact +{exact_lift:.2f}pp (z={z_e:+.2f}σ)"
        )
    elif z_e is not None and z_e <= -min_z:
        parts.append(
            f"exact {exact_lift:+.2f}pp (z={z_e:+.2f}σ — REGRESSION)"
        )
    if z_d is not None and z_d <= -min_z:
        detected = True
        parts.append(
            f"distance {distance_lift:+.4f} (z={z_d:+.2f}σ — improvement)"
        )
    elif z_d is not None and z_d >= min_z:
        parts.append(
            f"distance {distance_lift:+.4f} (z={z_d:+.2f}σ — REGRESSION)"
        )
    if not parts:
        parts.append(
            f"exact {exact_lift:+.2f}pp, distance {distance_lift:+.4f} — "
            f"both within ±{min_z:.1f}σ noise"
        )
    rationale = "; ".join(parts)

    return LiftAssessment(
        n_before=len(before_summaries),
        n_after=len(after_summaries),
        before_mean_exact_pct=round(bm_exact, 2),
        after_mean_exact_pct=round(am_exact, 2),
        before_mean_distance=round(bm_dist, 4),
        after_mean_distance=round(am_dist, 4),
        exact_lift_pp=round(exact_lift, 2),
        distance_lift=round(distance_lift, 4),
        pooled_se_exact_pct=round(se_exact, 4),
        pooled_se_distance=round(se_dist, 4),
        z_exact=round(z_e, 4) if z_e is not None else None,
        z_distance=round(z_d, 4) if z_d is not None else None,
        lift_detected=detected,
        rationale=rationale,
    )
