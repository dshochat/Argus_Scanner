"""N-sample ensemble runner — model-agnostic majority vote over verdict labels.

Lifted from echoDefense ``sast/analysis/l1/ensemble.py`` and refactored to
be model-agnostic — the original was hardcoded to call the FT-SLM L1
runner. In Argus, the SAME ensemble pattern works against any model
stack (Sonnet, Opus, Gemini Flash, or future additions).

Rationale (from echoDefense campaign closure, 2026-05-04):
    Single-model verdict-flip rate observed at ~26% on Fireworks at
    seed=0/temp=0 (server-side batching nondeterminism). For Anthropic
    models the variance is lower but still nonzero; ensemble N=3 cuts
    per-file flip rate from ~10% to ~2%.

The runner injection pattern lets us:
  * Use Sonnet for the workhorse ensemble on standard HIGH files
  * Swap to Opus for high-stakes / borderline files without code change
  * Run a mixed-model ensemble (Sonnet × 2 + Opus × 1) for the hardest
    files — Opus's vote breaks ties

Usage::

    from analysis.ensemble import run_ensemble, EnsembleResult

    async def my_runner(seed: int) -> EnsembleSample:
        # Whatever calls Sonnet/Opus/Gemini and returns a verdict label
        ...

    result = await run_ensemble(my_runner, n_samples=3, base_seed=0)
    # result.selected_label, result.distribution, result.was_unanimous, ...

Tie-break: highest verdict anchor (security-conservative — false-
negative cost > false-positive cost in this product).

Schema-failed samples (e.g. malformed JSON, API error) are excluded
from the distribution. If every sample fails, falls through to a
"suspicious" fallback (matches single-call semantics).
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from shared.types.enums import VERDICT_ANCHORS

# Type alias for the per-sample runner the caller injects.
# Takes a seed, returns a single sample's verdict label + telemetry.
SampleRunner = Callable[[int], Awaitable["EnsembleSample"]]


@dataclass(frozen=True)
class EnsembleSample:
    """One sample's outcome from the runner. Model-agnostic."""

    seed: int
    verdict_label: str  # "clean" | "informational" | "suspicious" | "malicious" | "critical_malicious"
    schema_failure: bool = False
    raw_payload: Any = None  # opaque — caller's full result if they want to retain it


@dataclass(frozen=True)
class EnsembleResult:
    """Aggregate outcome from N-sample majority vote."""

    selected_label: str
    selected_seed: int
    selected_sample: EnsembleSample  # the sample whose label won
    distribution: dict[str, int]  # label -> count (excludes schema failures)
    was_unanimous: bool
    had_tie: bool
    all_seeds: list[int]
    schema_failures: int
    every_sample_failed: bool = False
    telemetry: dict[str, Any] = field(default_factory=dict)


def _select_winner(
    samples: Sequence[EnsembleSample],
) -> tuple[int, dict[str, Any]]:
    """Pick the index of the sample whose verdict wins the majority vote.

    Tie-break: highest verdict anchor (security-conservative).
    Schema-failed samples are excluded from the distribution.
    """
    distribution: dict[str, int] = {}
    successful_indices: list[int] = []
    schema_failures = 0
    for i, s in enumerate(samples):
        if s.schema_failure:
            schema_failures += 1
            continue
        distribution[s.verdict_label] = distribution.get(s.verdict_label, 0) + 1
        successful_indices.append(i)

    seeds = [s.seed for s in samples]

    if not successful_indices:
        return 0, {
            "ensemble_size": len(samples),
            "verdict_distribution": {},
            "selected_seed": seeds[0] if seeds else 0,
            "selected_verdict": samples[0].verdict_label if samples else "suspicious",
            "was_unanimous": False,
            "had_tie": False,
            "all_seeds": list(seeds),
            "schema_failures": schema_failures,
            "every_sample_failed": True,
        }

    max_count = max(distribution.values())
    winners = [label for label, c in distribution.items() if c == max_count]
    had_tie = len(winners) > 1
    if had_tie:
        # Highest anchor wins. ``VERDICT_ANCHORS`` covers all five labels;
        # any other label string would fail upstream validation, so the
        # lookup is total over real inputs.
        winners.sort(key=lambda lbl: VERDICT_ANCHORS.get(lbl, -1), reverse=True)
    selected_label = winners[0]

    # Among samples carrying the selected label, pick the FIRST (deterministic).
    chosen_idx = next(i for i in successful_indices if samples[i].verdict_label == selected_label)

    telemetry = {
        "ensemble_size": len(samples),
        "verdict_distribution": distribution,
        "selected_seed": seeds[chosen_idx],
        "selected_verdict": selected_label,
        "was_unanimous": len(distribution) == 1,
        "had_tie": had_tie,
        "all_seeds": list(seeds),
        "schema_failures": schema_failures,
        "every_sample_failed": False,
    }
    return chosen_idx, telemetry


async def run_ensemble(
    runner: SampleRunner,
    *,
    n_samples: int = 3,
    base_seed: int | None = None,
) -> EnsembleResult:
    """Run ``runner`` ``n_samples`` times with distinct seeds; majority-vote.

    All samples are dispatched concurrently via ``asyncio.gather`` so wall-
    clock time is bounded by the slowest sample, not the sum.

    ``base_seed`` defaults to ``$ARGUS_ENSEMBLE_SEED`` (fallback ``0``);
    seeds used are ``[base_seed, base_seed+1, ..., base_seed+n_samples-1]``.

    Raises ``ValueError`` if ``n_samples < 1``.

    The runner is responsible for translating its own seed into the
    relevant inference call (e.g. Anthropic's ``temperature`` + small
    perturbations, or N independent calls if true seed pinning isn't
    available — Anthropic's API is non-deterministic by default).
    """
    if n_samples < 1:
        raise ValueError(f"n_samples must be >= 1, got {n_samples!r}")

    if base_seed is None:
        base_seed = int(os.environ.get("ARGUS_ENSEMBLE_SEED", "0"))

    seeds = [base_seed + i for i in range(n_samples)]
    samples = await asyncio.gather(*(runner(s) for s in seeds))

    chosen_idx, telemetry = _select_winner(samples)
    chosen = samples[chosen_idx]

    return EnsembleResult(
        selected_label=chosen.verdict_label,
        selected_seed=chosen.seed,
        selected_sample=chosen,
        distribution=telemetry["verdict_distribution"],
        was_unanimous=telemetry["was_unanimous"],
        had_tie=telemetry["had_tie"],
        all_seeds=telemetry["all_seeds"],
        schema_failures=telemetry["schema_failures"],
        every_sample_failed=telemetry.get("every_sample_failed", False),
        telemetry=telemetry,
    )
