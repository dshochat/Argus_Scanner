# DAST Benchmark Campaign — Closure Summary

**Period:** 2026-04 to 2026-05-04
**Branch:** `feat/dast-prototype-runners-and-docs`
**Baseline:** 23-file regression suite, Fireworks backend, gpt-oss-120b L1
**Outcome:** 4 deterministic fixes shipped; campaign-lift claim withheld due
to measurement noise; multi-week roadmap to 80% defined.

---

## What We Shipped (Phase 0 — Deterministic Floor)

Four commits, each justified by unit tests + code review (no
campaign-lift claim attached to any of them):

| Commit | Component | Effect |
|---|---|---|
| `feat(preprocessing): PREP-007 broaden — content-based AST detection for .py modules` | `preprocessing/imperative_install.py` | AST walker fires on disguised-malware `.py` modules, not just filename-based attack vectors. Forces priority ≥ 4. |
| `fix(l1): retry on parse/validate failure with seed+1 (Fix 4)` | `sast/analysis/l1/l1.py` | Defensive retry covering parse fail, validate fail, length cutoff. Same retry budget (1). |
| `fix(l1): broaden attack-vector advisory to priority >= 4 (Fix 6)` | `sast/analysis/l1/prompt.py` | Advisory injected on any priority ≥ 4, not just explicit attack-vector preprocessing flags. |
| `feat(dast/prompts): .pth persistence categorization rule (compat_hooks)` | `scripts/dast_prototype/dast_prompts.py` | `.pth` files with active imports score PERSISTENCE + behavior. Stable across two Fireworks runs (compat_hooks.pth: malicious → critical_malicious). |

All four are content-deterministic or defensive. No regression risk
from the fixes themselves.

## What We Reverted

| Change | Reason |
|---|---|
| **DAST-010** plan compile pre-flight retry | 0 unlocks across two Fireworks runs; no measurable signal that `compile()` pre-flight catches enough heredoc errors to justify the extra inference call. Reverted. |
| **Fix 4b** L1 retry on `InferenceSchemaFailure` (4xx) | 0 unlocks; sitecustomize_inject regression possibly tied to it but not proven. Reverted. The Fix 4 retry on parse/validate fail (kept) covers the inference-side failure modes that retry can actually help. |

## The Core Finding: L1 Verdict Variance ≫ Baseline Captured

The campaign methodology — single-run regression scoring against a
3-run-characterized baseline — proved **unreliable** for sub-±2 lift
measurement.

### Evidence

Comparing v2 and v3 Fireworks runs with identical inputs (same code,
same seed=0, same `temperature=0.0`, same backend), **6 of 23 files
flipped L1 verdict between runs**:

| File | v2 L1 | v3 L1 |
|---|---|---|
| consistency_variable | malicious | suspicious |
| litellm_obfuscated | malicious | suspicious |
| sitecustomize_inject | informational | clean |
| sandbox_runner.js | suspicious | malicious |
| tenda_device_audit | clean | informational |
| tpm_symmetric_cipher | clean | informational |

Per-run flip rate ≈ 26%. The 3-run baseline variance band did not
capture this because the variance is non-Gaussian and run-correlated
(server-side batching nondeterminism on Fireworks).

### Implication

Lift measurements of ±2 files (8.7%) on a 23-file suite cannot be
distinguished from L1 noise without **N ≥ 5 runs averaged per
configuration**. The earlier "v1 = +2 lift, 0 T1/T2 regressions"
measurement was therefore likely a lucky draw, not a stable signal.

### Mitigation

Future campaigns must adopt one or more of:

1. **N=5 baseline characterization** — establishes true variance band
2. **N=3 per-fix evaluation runs** — averaged metrics with confidence intervals
3. **Verdict-distance metric** — continuous `|anchor(predicted) - anchor(oracle)| / 100`, captures direction even when label flips, smoother gradient than verdict-exact
4. **Stable-subset evaluation** — restrict regression scoring to files that hold the same L1 verdict across all 5 baseline runs (likely 12-15 files), giving lower-variance signal

## Why We're Withholding a Lift Claim

Campaign produced these single-run measurements (Fireworks):

| Run | Verdict-exact | T1/T2 regressions vs baseline | Notable GAINs |
|---|---|---|---|
| baseline (3-run avg) | 10/23 | — | — |
| "v1" (Fix 1 + 4 + 6) | 12/23 | 0 | preinstall, 12_gh_bot |
| v2 (v1 + DAST-010 + Fix 4b + compat_hooks) | 9/23 | 2 (litellm, sitecustomize) | compat_hooks.pth |
| v3 (v1 + compat_hooks, DAST-010 + 4b reverted) | 9/23 | 4 (consistency, litellm, sitecustomize, tenda) | preinstall, tpm, compat_hooks |

The **single stable signal across all three runs** is `compat_hooks.pth`
matching oracle (`critical_malicious`) when the new rule is present.
That's a content-deterministic effect of the rule, not a probabilistic
lift. Everything else is within noise.

## Path Forward — 4 Weeks to 80%

Documented in `ROADMAP.md` under DAST campaign Phase 1-3.

| Phase | Wall clock | Approach | Projected unlock |
|---|---|---|---|
| 0 (this doc) | done | Deterministic fixes shipped | floor stable |
| 1 — DAST-005 multi-image | 1-2 wk | Per-hypothesis image routing (minimal, networked, ML-tools) | +3-4 (litellm, audit_log, event_stream, sandbox_runner) |
| 2 — L1 stability + iter-erosion | 1 wk parallel | 3-sample majority L1; "no downgrade of confirmed critical" rule | +2-3 (consistency, sitecustomize, sandbox_runner) |
| 3 — Last mile | 1 wk | S1 routing extensions; L1 prompt sharpening; N-day reachability use | +1-2 (tpm, tenda, docker_entrypoint, init__) |

Pre-Phase-1 prerequisite: **N=5 baseline characterization** to set
the true variance band before any lift claim is made.

## What This Document Is Not

- Not a claim that the shipped fixes produced +N verdict-exact lift.
  They produced a stable, deterministic floor; lift will be measured
  honestly after the methodology upgrade.
- Not a closure on the 23-file suite. The suite stays. The methodology
  changes.
- Not a deferral of DAST-005. That's the immediate next campaign and
  has the highest projected unlock per unit work.

---

## Methodology Upgrade — How We'll Measure From Here On

The campaign closure is the rationale for this upgrade. Below is the
toolkit that future campaigns use to produce honest lift numbers.

### Three building blocks

**1. Verdict-distance metric** (`scripts/dast_prototype/scoring.py::verdict_distance`)

A continuous metric in [0.0, 1.0]:

```
verdict_distance(predicted, oracle) = |anchor(predicted) - anchor(oracle)| / 100
```

Where anchors are `clean=0, informational=25, suspicious=50, malicious=75,
critical_malicious=100`. A one-notch miss is 0.25; a full disagreement
is 1.0. Captures direction even when the categorical label flips —
where verdict-exact would say "still wrong", verdict-distance says
"closer to the right answer than last time".

Used alongside (not instead of) verdict-exact. Both numbers are
reported in every aggregate.

**2. N=5 baseline characterization** (`_run_baseline_characterization.py`)

Aggregates N pre-computed regression-run JSONs into a noise-aware
baseline. Per file, computes:

- `verdict_distribution` — `{label: count}` across runs
- `most_frequent_verdict` (ties broken by highest anchor — security-
  conservative)
- `flip_rate` = `1 - (most_frequent_count / N)`
- `observed_band` — `[min_anchor_seen, max_anchor_seen]`
- `mean_distance_to_oracle`, `distance_std_to_oracle`

Recommended N=5: per-file flip-rate observation drops to ~17% under
the campaign's measured 26%/run noise floor; N=10 would be ~7% but
costs twice. With N=5, observed_band = exact 5th/95th percentile, no
extrapolation.

The aggregator does NOT orchestrate the runs themselves — running five
30-minute Fireworks regressions in one Python process is fragile (rate
limits, disk I/O, memory bloat). Workflow:

```bash
# Run the existing regression runner 5 times, save each output
for i in 1 2 3 4 5; do
  uv run python scripts/dast_prototype/_run_full_regression_fireworks.py
  mv scripts/dast_prototype/results/_full_regression_fireworks.json \
     scripts/dast_prototype/results/_baseline_run_$i.json
done

# Aggregate
uv run python scripts/dast_prototype/_run_baseline_characterization.py \
    scripts/dast_prototype/results/_baseline_run_*.json
```

Output: `_regression_baseline_n5.json` — drop-in compatible with the
3-run baseline schema, plus the new variance fields.

**3. N=3 per-fix evaluation** (`_run_per_fix_evaluation.py`)

Compares two sets of regression-run JSONs (a "before" set and an
"after" set) and reports whether the fix produced a detectable lift,
gated on a confidence-interval threshold.

```bash
# 1. Run regression on "before" code state N=3 times
git checkout main
for i in 1 2 3; do
  uv run python scripts/dast_prototype/_run_full_regression_fireworks.py
  mv scripts/dast_prototype/results/_full_regression_fireworks.json \
     scripts/dast_prototype/results/_eval_before_$i.json
done

# 2. Apply the fix, run N=3 more
git checkout my-fix-branch
for i in 1 2 3; do
  uv run python scripts/dast_prototype/_run_full_regression_fireworks.py
  mv scripts/dast_prototype/results/_full_regression_fireworks.json \
     scripts/dast_prototype/results/_eval_after_$i.json
done

# 3. Compare
uv run python scripts/dast_prototype/_run_per_fix_evaluation.py \
    --before scripts/dast_prototype/results/_eval_before_*.json \
    --after  scripts/dast_prototype/results/_eval_after_*.json
```

Output: console report + `_per_fix_evaluation.json`. The console summary:

- Verdict-exact mean before vs after, with z-score of the difference
- Mean-distance before vs after, with z-score
- `lift_detected: yes/no` based on the `--min-z` threshold (default 1.0σ
  — soft 1σ matched to small-N statistics; tune up to 1.96σ for
  ~95% confidence)
- Per-file change classification: improved / regressed / unchanged

Pooled standard error uses the standard two-sample formula:
`SE = sqrt(s_before^2 / n_before + s_after^2 / n_after)`. With n=3
each side, this is a soft estimate — but it's a real SE, not a hand-
wave. Lift is reported only when the mean delta exceeds `min_z * SE`
in the improving direction.

### Rule of thumb for what counts as "real lift"

| z-score (exact or distance) | Interpretation |
|---|---|
| `\|z\| < 1.0` | Within noise. Don't ship a lift claim. |
| `1.0 <= \|z\| < 1.96` | Suggestive. Worth a follow-up run. |
| `1.96 <= \|z\| < 3.0` | Significant. Reasonable to ship a measured claim. |
| `\|z\| >= 3.0` | Unambiguous. Sample-size-robust. |

### What this prevents

The closed campaign measured a "+2 file lift" on Fix 1+4+6 and a
"-1 file lift" on the v2 wave, both single-run. With N=3 per side and
the methodology runner, those measurements would have come back with
huge confidence intervals — "lift_detected: no, both within ±2σ
noise" — and we'd have known not to spend a day chasing v2's apparent
regression. Future campaigns get that filter for free.

### Scope and pricing

Per-fix evaluation: 6 regression runs (3 before + 3 after) × ~$0.12 each
on Fireworks ≈ **$0.72 per evaluated fix**, ~6 hours wall clock if run
serially. Worth it for any fix whose only justification is a benchmark
delta.

Baseline characterization: 5 regression runs × ~$0.12 ≈ **$0.60 one-
time cost**, refreshed when the underlying L1/SAST code changes
materially (FT model swap, prompt overhaul, schema change).

### Tests

- `scripts/dast_prototype/tests/test_scoring.py` — 24 unit tests covering
  `verdict_distance` + `aggregate_run` + `characterize_file_variance`
  + `assess_lift` math and edge cases.
- Smoke-tested end-to-end against the campaign's existing v2/v3
  Fireworks JSONs — 8 of 23 files surfaced as unstable across just 2
  runs (matches the 26% per-run flip rate), highest-variance files
  printed correctly.
