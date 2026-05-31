"""Run the full Argus pipeline (L1 cascade + DAST) on the regression suite.

Thin CLI wrapper around :func:`methodology.bench.run_suite` +
:func:`methodology.bench.run_argus_pipeline_one`. Builds the
production runners from env, optionally enables Phase 3 Stage 2 (the
v1.6 adversarial loop), and writes BenchRow output JSON for downstream
scoring via :mod:`methodology.voters` +
:mod:`methodology.build_consensus`.

Why this file exists: ``methodology/bench.py`` itself is library-only;
historically benchmark runs were kicked off by external scripts in
``scripts/dast_prototype/`` (not committed). This CLI gives the
beat-Opus measurement a stable, in-repo entry point.

Env vars consumed (via dotenv):

* ``ANTHROPIC_API_KEY`` — Sonnet 4.6 + Opus 4.6 runners.
* ``GEMINI_API_KEY``    — Flash-Lite triage runner.
* ``FLY_API_TOKEN`` + ``ECHO_DAST_IMAGE_LEAN`` — DAST sandbox.

Usage::

    uv run python -m methodology.run_argus_bench \
        --output bench_results/argus_full_phase3.json \
        --enable-phase-3-loop

    uv run python -m methodology.run_argus_bench \
        --suite-dir samples/regression_v1 \
        --output bench_results/argus_full_baseline.json
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from dast.runner import make_dast_runner_from_env
from methodology.bench import run_argus_pipeline_one, run_suite
from scanner.engine import ScanConfig
from scanner.runners import (
    make_gemini_triage_runner,
    make_opus_runner,
    make_sonnet_runner,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUITE_DIR = REPO_ROOT / "samples" / "regression_v1"
DEFAULT_BASELINE = DEFAULT_SUITE_DIR / "regression_baseline.json"

log = logging.getLogger("argus.run_argus_bench")


def _build_config(args: argparse.Namespace) -> ScanConfig:
    """Translate CLI flags to a :class:`ScanConfig`. Phase 3 loop
    implies Phase 3 discovery (Stage 1) + runtime probe (sandbox
    machinery) -- same convention as ``scanner.cli``."""
    kwargs: dict = {}
    if args.enable_phase_3_loop:
        kwargs["enable_runtime_probe"] = True
        kwargs["enable_phase_3_discovery"] = True
        kwargs["enable_phase_3_loop"] = True
    elif args.enable_phase_3_discovery:
        kwargs["enable_runtime_probe"] = True
        kwargs["enable_phase_3_discovery"] = True
    elif args.enable_runtime_probe:
        kwargs["enable_runtime_probe"] = True
    if args.max_cost is not None:
        kwargs["max_cost_per_file_usd"] = float(args.max_cost)
    if args.no_phase_c:
        # Phase C is remediation (fix-and-verify patch generation). It
        # doesn't change verdicts -- the headline measurement vs raw
        # Opus is about detection, not patching. Disabling saves
        # ~$0.05-0.10/file without affecting the comparison.
        kwargs["enable_phase_c"] = False
    return ScanConfig(**kwargs)


def _progress(idx: int, total: int, row) -> None:  # type: ignore[no-untyped-def]
    """One-liner per file — matches the existing run-suite progress
    style so output mirrors prior benchmark logs."""
    oracle = row.oracle_verdict or "?"
    pred = row.predicted_verdict or "ERROR"
    # ASCII status marker (Windows cp1252 doesn't have check/cross glyphs).
    status = "OK" if oracle == pred else "!="
    err = f" err={row.error[:80]!r}" if row.error else ""
    print(
        f"  [{idx}/{total}] {status} {row.file_name:40s} "
        f"oracle={oracle:20s} pred={pred:20s} "
        f"cost=${row.cost_usd:.3f}{err}",
        flush=True,
    )


async def _run(args: argparse.Namespace) -> int:
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    missing: list[str] = []
    if not anthropic_key:
        missing.append("ANTHROPIC_API_KEY")
    if not gemini_key:
        missing.append("GEMINI_API_KEY")
    if missing:
        log.error("missing env vars: %s", ", ".join(missing))
        return 2

    triage_runner = make_gemini_triage_runner(gemini_key)
    sonnet_runner = make_sonnet_runner(anthropic_key)
    opus_runner = make_opus_runner(anthropic_key)
    dast_runner = make_dast_runner_from_env(anthropic_key)
    if dast_runner is None:
        log.warning("DAST runner could not be constructed -- DAST will be skipped")

    config = _build_config(args)
    log.info(
        "ScanConfig: enable_runtime_probe=%s, enable_phase_3_discovery=%s, "
        "enable_phase_3_loop=%s, max_cost_per_file_usd=%s",
        config.enable_runtime_probe,
        config.enable_phase_3_discovery,
        config.enable_phase_3_loop,
        config.max_cost_per_file_usd,
    )

    suite_dir = Path(args.suite_dir)
    baseline_path = Path(args.baseline) if args.baseline else suite_dir / "regression_baseline.json"
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = await run_suite(
        suite_dir=suite_dir,
        baseline_path=baseline_path,
        runner_fn=run_argus_pipeline_one,
        runner_kwargs={
            "triage_runner": triage_runner,
            "sonnet_runner": sonnet_runner,
            "opus_runner": opus_runner,
            "dast_runner": dast_runner,
            "config": config,
        },
        output_path=output_path,
        progress_callback=_progress,
        auto_abort_consecutive_errors=args.auto_abort,
        resume=args.resume,
    )

    n_ok = sum(1 for r in rows if r.error is None)
    n_err = len(rows) - n_ok
    total_cost = sum(float(r.cost_usd or 0) for r in rows)
    print()
    print(f"=== bench summary: {n_ok} ok / {n_err} errored / {len(rows)} total")
    print(f"=== total cost: ${total_cost:.2f}")
    print(f"=== wrote {output_path}")
    return 0 if n_err == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run full Argus pipeline on the regression suite",
    )
    parser.add_argument(
        "--suite-dir",
        type=str,
        default=str(DEFAULT_SUITE_DIR),
        help="Directory containing the suite files (default: samples/regression_v1)",
    )
    parser.add_argument(
        "--baseline",
        type=str,
        default=None,
        help="Path to regression_baseline.json (default: <suite-dir>/regression_baseline.json)",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Path to write per-file BenchRow JSON list",
    )
    parser.add_argument(
        "--enable-phase-3-loop",
        action="store_true",
        help="Enable Phase 3 Stage 2 adversarial loop. Implies "
        "--enable-phase-3-discovery and --enable-runtime-probe.",
    )
    parser.add_argument(
        "--enable-phase-3-discovery",
        action="store_true",
        help="Enable Phase 3 Stage 1 behavioral probe only. Implies --enable-runtime-probe.",
    )
    parser.add_argument(
        "--enable-runtime-probe",
        action="store_true",
        help="Enable Phase B+ runtime probe.",
    )
    parser.add_argument(
        "--max-cost",
        type=float,
        default=None,
        help="Per-file cost cap (default: ScanConfig.max_cost_per_file_usd).",
    )
    parser.add_argument(
        "--no-phase-c",
        action="store_true",
        help="Disable Phase C (fix-and-verify) -- saves ~$0.05-0.10/file "
        "without affecting verdicts. Remediation is orthogonal to "
        "detection; the headline measurement is about detection only.",
    )
    parser.add_argument(
        "--auto-abort",
        type=int,
        default=3,
        help="Abort after K consecutive errored rows. 0 = disabled.",
    )
    parser.add_argument(
        "--no-resume",
        dest="resume",
        action="store_false",
        help="Start from scratch (default: resume from existing output file).",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        help="Logging level (default: INFO).",
    )
    args = parser.parse_args()

    load_dotenv(REPO_ROOT / ".env", override=True)
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
