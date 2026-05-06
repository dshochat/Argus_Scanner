"""Argus CLI — `argus scan <file>` entry point.

Wires the Phase 1 cascade together for the first end-to-end live scan:

    argus scan path/to/file.py [--output json|markdown] [--no-dast]

Loads ``.env`` (override mode), instantiates the triage / sonnet / opus
runners via :mod:`scanner.runners`, calls
:func:`scanner.engine.scan_file`, prints the result.

DAST is not yet wired — ``--no-dast`` is accepted for forward compatibility
but is currently a no-op (Phase 3 / DAST-102 wires the dast_runner).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from dast.runner import make_dast_runner_from_env
from scanner.engine import ScanConfig, ScanResult, scan_file
from scanner.runners import (
    make_gemini_triage_runner,
    make_opus_runner,
    make_sonnet_runner,
)
from methodology.bench import (
    BenchAborted,
    BenchRow,
    bench_pass_criteria,
    compare_configs,
    make_raw_opus_baseline_runner,
    run_argus_pipeline_one,
    run_suite,
)

log = logging.getLogger("argus.cli")


# ── Output formatters ──────────────────────────────────────────────────────


def format_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, default=str)


def format_markdown(result: ScanResult) -> str:
    """Compact human-readable report for terminal use."""
    lines: list[str] = [
        f"# {result.filename}",
        "",
        f"**Verdict:** `{result.final_verdict}`  ",
        f"**Risk:** {result.risk_score}/100 ({result.risk_level})  ",
        f"**Language:** {result.language or '?'}  ",
        f"**Triage:** {result.triage_classification} — {result.triage_reason}",
        "",
        f"**Cost:** ${result.total_cost_usd:.4f}  "
        f"**Time:** {result.total_duration_ms} ms",
        "",
        f"**Scan path:** {' → '.join(result.scan_path) or '(empty)'}",
        "",
    ]
    if result.vulnerabilities:
        lines.append(f"## Vulnerabilities ({len(result.vulnerabilities)})")
        lines.append("")
        for v in result.vulnerabilities:
            line = v.get("line", "?")
            lines.append(
                f"- **{v.get('type', '?')}** "
                f"(severity: {v.get('severity', '?')}, line {line})"
            )
            if v.get("explanation"):
                lines.append(f"  - {v['explanation']}")
            if v.get("fix"):
                lines.append(f"  - **Fix:** {v['fix']}")
        lines.append("")
    if result.attack_chains:
        lines.append(f"## Attack chains ({len(result.attack_chains)})")
        lines.append("")
        for chain in result.attack_chains:
            steps = chain.get("steps", [])
            lines.append(f"- **{chain.get('name', '?')}**")
            for step in steps:
                lines.append(f"  - {step}")
        lines.append("")
    bp = result.behavioral_profile or {}
    sensitivity = bp.get("sensitivity")
    if sensitivity:
        lines.append(f"## Behavioral summary")
        lines.append("")
        lines.append(f"- Sensitivity: **{sensitivity}**")
        purpose = bp.get("purpose_summary")
        if purpose:
            lines.append(f"- Purpose: {purpose}")
        lines.append("")
    if result.dast_attempted:
        lines.append(
            f"## DAST: {len(result.dast_findings)} validated findings, "
            f"{len(result.dast_iterations)} iterations"
        )
        lines.append("")
    if result.error:
        lines.append(f"## Error")
        lines.append("")
        lines.append(f"`{result.error}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ── argparse + entry ───────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus", description="AI-native code security scanner"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a single file")
    scan.add_argument("file", type=Path, help="path to file to scan")
    scan.add_argument(
        "--output",
        choices=("json", "markdown"),
        default="json",
        help="output format (default: json)",
    )
    scan.add_argument(
        "--no-dast",
        action="store_true",
        help="skip DAST verification (no-op until Phase 3 / DAST-102)",
    )
    scan.add_argument(
        "--max-cost",
        type=float,
        default=None,
        metavar="USD",
        help="abort the scan if cumulative API spend on this file exceeds "
        "USD (overrides ScanConfig.max_cost_per_file_usd default of 1.00). "
        "Pass 0 to disable.",
    )
    scan.add_argument(
        "--enable-discovery",
        action="store_true",
        help="enable DAST-204 v0.0 proactive vulnerability discovery — "
        "runs a hardcoded library of attack payloads against the file "
        "in the sandbox, surfaces any runtime-confirmed CWEs as new "
        "findings (in addition to validating L1's findings). Adds "
        "~$0.25/file in API cost. Requires --no-dast NOT set.",
    )
    scan.add_argument(
        "--dast-trigger-verdicts",
        type=str,
        default=None,
        metavar="LIST",
        help="comma-separated list of L1 verdict labels that trigger DAST "
        "validation. Default: 'malicious,critical_malicious'. Use "
        "'suspicious,malicious,critical_malicious' to also DAST suspicious "
        "files (broader coverage, ~30-50%% more API cost). Use "
        "'critical_malicious' for the strictest cost-controlled mode. "
        "Allowed labels: clean, suspicious, malicious, critical_malicious.",
    )

    bench = sub.add_parser(
        "bench",
        help="Beat-Opus benchmark — run the regression suite N times "
        "against both raw Opus 4.6 and Argus's full pipeline; report "
        "verdict-exact lift and the BENCH-005 pass-criteria gate.",
    )
    bench.add_argument(
        "--suite",
        type=Path,
        default=Path("samples/regression_v1"),
        help="path to the regression-suite directory (default: samples/regression_v1)",
    )
    bench.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="path to regression_baseline.json (default: <suite>/regression_baseline.json)",
    )
    bench.add_argument(
        "--n",
        type=int,
        default=2,
        help="number of runs per config (default: 2 — matches CLAUDE.md methodology)",
    )
    bench.add_argument(
        "--output",
        type=Path,
        default=None,
        help="output directory for per-run JSON results (default: bench_results/<UTC timestamp>)",
    )
    bench.add_argument(
        "--no-dast",
        action="store_true",
        help="run Argus pipeline without DAST (L1-only). Lets you compare "
        "L1-vs-Opus separately from the full L1+DAST pipeline.",
    )
    bench.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="skip the cost-projection confirmation prompt",
    )
    bench.add_argument(
        "--dry-run",
        action="store_true",
        help="print cost projection + setup, do not call any models",
    )
    bench.add_argument(
        "--abort-on",
        type=int,
        default=3,
        metavar="K",
        help="abort the run after K consecutive errored rows (default: 3). "
        "Pass 0 to disable.",
    )
    bench.add_argument(
        "--no-resume",
        action="store_true",
        help="ignore any existing per-config JSON in --output dir and "
        "scan every file from scratch (default: skip files already "
        "present in the output JSON, allowing ctrl-C-and-restart).",
    )

    # ── scan-repo ──────────────────────────────────────────────────────────
    repo = sub.add_parser(
        "scan-repo",
        help="Scan an entire directory tree (a cloned repo, a project dir). "
        "Walks PATH, applies file-type filters + .gitignore, dispatches each "
        "supported file through the Argus cascade, aggregates results.",
    )
    repo.add_argument(
        "path",
        type=Path,
        help="directory to scan (e.g., '.', '~/work/myrepo'). Argus reads "
        "files from disk; for a private repo, clone it first with your "
        "existing git credentials, then point Argus at the local path.",
    )
    repo.add_argument(
        "--diff",
        type=str,
        default=None,
        metavar="REF",
        help="only scan files that differ vs git ref REF. Uses "
        "'git diff --name-only REF...HEAD' against the repo at PATH. "
        "Useful for PR / CI mode (e.g., --diff origin/main).",
    )
    repo.add_argument(
        "--max-cost",
        type=float,
        default=None,
        metavar="USD",
        help="abort the run when cumulative API spend exceeds USD. Files "
        "remaining at the cap are recorded as skipped with reason "
        "'cost_cap_reached' rather than scanned. Pass 0 or omit to disable.",
    )
    repo.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="additional gitignore-style pattern to exclude. Repeatable. "
        "Argus already honors .gitignore by default plus an always-ignore "
        "list (.git, node_modules, __pycache__, .venv, etc.).",
    )
    repo.add_argument(
        "--no-gitignore",
        action="store_true",
        help="ignore .gitignore files during the walk (default: respected).",
    )
    repo.add_argument(
        "--max-file-bytes",
        type=int,
        default=None,
        metavar="BYTES",
        help="skip files larger than BYTES (default: 1 MiB). Files past the "
        "cap are recorded as skipped with reason 'too_large' and don't "
        "count toward cost.",
    )
    repo.add_argument(
        "--output",
        choices=("markdown", "json", "sarif"),
        default="markdown",
        help="output format. 'sarif' produces SARIF v2.1.0 JSON suitable "
        "for upload to GitHub Code Scanning. Default: markdown summary.",
    )
    repo.add_argument(
        "--output-file",
        type=Path,
        default=None,
        help="write output to this file instead of stdout. Useful for SARIF.",
    )
    repo.add_argument(
        "--no-dast",
        action="store_true",
        help="skip DAST verification on every file in the run.",
    )
    repo.add_argument(
        "--enable-discovery",
        action="store_true",
        help="enable DAST-204 v0.0 proactive vulnerability discovery on "
        "every file in the run that triggers DAST. Adds ~$0.25 per file.",
    )
    repo.add_argument(
        "--dast-trigger-verdicts",
        type=str,
        default=None,
        metavar="LIST",
        help="comma-separated list of L1 verdict labels that trigger DAST "
        "validation (default: 'malicious,critical_malicious').",
    )
    repo.add_argument(
        "--continue-on-error",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="if a single file errors during scan, record the error and "
        "continue (default: --continue-on-error). Use --no-continue-on-error "
        "to abort the run on the first file-level exception.",
    )
    return parser


async def _run_scan(args: argparse.Namespace) -> int:
    load_dotenv(override=True)

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if not anthropic_key:
        print(
            "error: ANTHROPIC_API_KEY not set in environment or .env",
            file=sys.stderr,
        )
        return 2
    if not gemini_key:
        print(
            "error: GEMINI_API_KEY not set in environment or .env",
            file=sys.stderr,
        )
        return 2

    file_path: Path = args.file
    if not file_path.exists():
        print(f"error: file not found: {file_path}", file=sys.stderr)
        return 2
    if not file_path.is_file():
        print(f"error: not a regular file: {file_path}", file=sys.stderr)
        return 2

    content = file_path.read_bytes()

    triage = make_gemini_triage_runner(gemini_key)
    sonnet = make_sonnet_runner(anthropic_key)
    opus = make_opus_runner(anthropic_key)
    # DAST: build from env if FLY_API_TOKEN + image vars are set.
    # --no-dast forces it off even when the env is configured.
    if args.no_dast:
        dast_runner = None
    else:
        dast_runner = make_dast_runner_from_env(api_key=anthropic_key)
        if dast_runner is None:
            log.info(
                "DAST disabled: missing Fly config "
                "(FLY_API_TOKEN / ECHO_DAST_IMAGE_*); running L1-only"
            )

    # Build per-scan config — only override the cost cap if the user
    # passed --max-cost (None means "use ScanConfig default of $1.00").
    # --enable-discovery toggles DAST-204 v0.0 proactive payload sweep.
    # --dast-trigger-verdicts overrides the default trigger gate.
    config_kwargs: dict[str, Any] = {}
    if args.max_cost is not None:
        config_kwargs["max_cost_per_file_usd"] = args.max_cost
    if getattr(args, "enable_discovery", False):
        config_kwargs["enable_discovery"] = True
    trigger_str = getattr(args, "dast_trigger_verdicts", None)
    if trigger_str:
        verdicts = tuple(v.strip() for v in trigger_str.split(",") if v.strip())
        valid = {"clean", "suspicious", "malicious", "critical_malicious"}
        invalid = [v for v in verdicts if v not in valid]
        if invalid:
            print(
                f"ERROR: invalid --dast-trigger-verdicts entries: {invalid}. "
                f"Allowed: {sorted(valid)}",
                file=sys.stderr,
            )
            return 2
        if not verdicts:
            print(
                "ERROR: --dast-trigger-verdicts produced an empty list. "
                "Pass at least one verdict label or omit the flag.",
                file=sys.stderr,
            )
            return 2
        config_kwargs["dast_trigger_verdicts"] = verdicts
        # Discovery's default gate mirrors DAST's default — keep them aligned
        # when the user customises DAST trigger.
        config_kwargs["discovery_trigger_verdicts"] = verdicts
    config = ScanConfig(**config_kwargs) if config_kwargs else None

    result = await scan_file(
        filename=file_path.name,
        content=content,
        config=config,
        triage_runner=triage,
        sonnet_runner=sonnet,
        opus_runner=opus,
        dast_runner=dast_runner,
    )

    if args.output == "json":
        print(format_json(result))
    else:
        print(format_markdown(result))

    return 0 if result.error is None else 1


async def _run_bench(args: argparse.Namespace) -> int:
    """argus bench — N=2 runs of raw Opus baseline + Argus full pipeline
    over the regression suite. Saves per-run JSONs and prints the
    BENCH-005 pass-criteria gate result."""
    load_dotenv(override=True)
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if not anthropic_key or not gemini_key:
        print(
            "error: ANTHROPIC_API_KEY + GEMINI_API_KEY required",
            file=sys.stderr,
        )
        return 2

    suite_dir: Path = args.suite
    baseline_path: Path = args.baseline or (suite_dir / "regression_baseline.json")
    if not baseline_path.exists():
        print(f"error: baseline not found: {baseline_path}", file=sys.stderr)
        return 2

    with baseline_path.open() as f:
        baseline = json.load(f)
    n_files = len(baseline.get("files", []))
    if n_files == 0:
        print(f"error: baseline has zero files: {baseline_path}", file=sys.stderr)
        return 2

    # Output dir
    if args.output is None:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir = Path("bench_results") / ts
    else:
        out_dir = args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    # Cost projection. Rough per-file averages from live runs:
    #   raw Opus: ~$0.30/file (1 Opus call at high effort)
    #   Argus L1:  ~$0.10-0.30/file (cascade) + ~$0.30/file when DAST fires
    # Budget: assume worst case where every file triggers DAST.
    avg_opus_per_file = 0.30
    avg_argus_per_file = 0.60 if not args.no_dast else 0.20
    proj_total = (avg_opus_per_file + avg_argus_per_file) * n_files * args.n

    print(f"=== argus bench ===")
    print(f"  suite:        {suite_dir}")
    print(f"  baseline:     {baseline_path}  ({n_files} files)")
    print(f"  N (runs/cfg): {args.n}")
    print(f"  configs:      raw_opus + argus_full" + (" (no DAST)" if args.no_dast else ""))
    print(f"  output dir:   {out_dir}")
    print(f"  cost (est.):  ~${proj_total:.2f}  "
          f"({avg_opus_per_file:.2f} opus + {avg_argus_per_file:.2f} argus per file × {n_files} × N={args.n})")
    # Per-file wall time observed live: raw Opus ~1-2 min, Argus full
    # pipeline 3-7 min when DAST fires. So per-pair-per-run: ~4-9 min.
    avg_min = (1.5 + (5.0 if not args.no_dast else 1.5))  # opus + argus avg
    n_pairs = n_files * args.n
    print(f"  wall time:    ~{n_pairs * avg_min * 0.6 / 60:.1f}-"
          f"{n_pairs * avg_min * 1.4 / 60:.1f} hours "
          f"(per-file: {avg_min:.1f} min avg, sequential)")
    print()

    if args.dry_run:
        print("dry-run: skipping all model calls")
        return 0

    if not args.yes:
        try:
            answer = input("Proceed? [y/N]: ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted")
            return 1

    # Build runners ONCE; reuse across all N runs.
    raw_opus_runner = make_raw_opus_baseline_runner(anthropic_key)

    triage = make_gemini_triage_runner(gemini_key)
    sonnet = make_sonnet_runner(anthropic_key)
    opus = make_opus_runner(anthropic_key)
    if args.no_dast:
        argus_dast = None
    else:
        argus_dast = make_dast_runner_from_env(api_key=anthropic_key)
        if argus_dast is None:
            print("warning: DAST not configured — Argus pipeline will run L1-only",
                  file=sys.stderr)

    async def argus_full_runner(filename, content, baseline_meta):
        return await run_argus_pipeline_one(
            filename, content, baseline_meta,
            triage_runner=triage,
            sonnet_runner=sonnet,
            opus_runner=opus,
            dast_runner=argus_dast,
        )

    all_opus: list[list[BenchRow]] = []
    all_argus: list[list[BenchRow]] = []
    abort_threshold: int | None = args.abort_on if args.abort_on > 0 else None
    resume_enabled = not args.no_resume

    def _make_progress_cb(run_idx: int, n: int, label: str, opus_lookup: dict | None):
        """Per-row progress printer. flush=True so each line ships
        immediately even when stdout is a file (block-buffered by
        default; bench is typically captured to a log)."""
        def cb(idx: int, total: int, row: BenchRow) -> None:
            verdict = row.predicted_verdict or "ERROR"
            mark = "==" if row.predicted_verdict == row.oracle_verdict else "!="
            extra = ""
            if opus_lookup is not None:
                opus_v = opus_lookup.get(row.file_name)
                if opus_v is not None and opus_v != row.predicted_verdict:
                    extra = f"  vs opus={opus_v} DIFF"
            err = f"  err={row.error[:50]}" if row.error else ""
            print(
                f"[{run_idx}/{n}][{label}][{idx:2d}/{total}] "
                f"{row.file_name:50s} predicted={verdict:18s} {mark} oracle={row.oracle_verdict}"
                f"{extra}{err}",
                flush=True,
            )
        return cb

    for run_idx in range(1, args.n + 1):
        # ── raw Opus baseline ─────────────────────────────────────────
        print(f"\n=== run {run_idx}/{args.n} — raw Opus baseline ===", flush=True)
        opus_path = out_dir / f"raw_opus_run{run_idx}.json"
        try:
            opus_rows = await run_suite(
                suite_dir, baseline_path, raw_opus_runner,
                output_path=opus_path,
                progress_callback=_make_progress_cb(run_idx, args.n, "opus", None),
                auto_abort_consecutive_errors=abort_threshold,
                resume=resume_enabled,
            )
        except BenchAborted as e:
            print(f"\nBENCH ABORTED: {e}", file=sys.stderr, flush=True)
            return 3
        n_exact_o = sum(1 for r in opus_rows if r.predicted_verdict == r.oracle_verdict)
        print(
            f"  -> {n_exact_o}/{len(opus_rows)} verdict-exact, "
            f"${sum(r.cost_usd for r in opus_rows):.2f} total -> {opus_path}",
            flush=True,
        )
        all_opus.append(opus_rows)

        # Build a lookup so the Argus pass can show the divergence.
        opus_lookup = {r.file_name: r.predicted_verdict for r in opus_rows}

        # ── Argus full pipeline ───────────────────────────────────────
        print(f"\n=== run {run_idx}/{args.n} — Argus full pipeline ===", flush=True)
        argus_path = out_dir / f"argus_full_run{run_idx}.json"
        try:
            argus_rows = await run_suite(
                suite_dir, baseline_path, argus_full_runner,
                output_path=argus_path,
                progress_callback=_make_progress_cb(run_idx, args.n, "argus", opus_lookup),
                auto_abort_consecutive_errors=abort_threshold,
                resume=resume_enabled,
            )
        except BenchAborted as e:
            print(f"\nBENCH ABORTED: {e}", file=sys.stderr, flush=True)
            return 3
        n_exact_a = sum(1 for r in argus_rows if r.predicted_verdict == r.oracle_verdict)
        print(
            f"  -> {n_exact_a}/{len(argus_rows)} verdict-exact, "
            f"${sum(r.cost_usd for r in argus_rows):.2f} total -> {argus_path}",
            flush=True,
        )
        all_argus.append(argus_rows)

    # Aggregate across all runs (concatenate rows; aggregate_run handles
    # the rest). Fairness note: per-run analysis is also possible from
    # the saved JSONs.
    flat_opus = [r for run in all_opus for r in run]
    flat_argus = [r for run in all_argus for r in run]
    comparison = compare_configs(flat_opus, flat_argus)
    gate = bench_pass_criteria(comparison)

    # BENCH-010 / BENCH-011 / BENCH-012 (3-way finding diff + GPT-5.5
    # independent judging + launch report) are wired in follow-up
    # commits. For now this CLI only emits the Tier 1 verdict-match
    # comparison; subsequent stages run as separate `argus bench`
    # subcommands once they land.

    summary_path = out_dir / "summary.json"
    summary_path.write_text(
        json.dumps({"comparison": comparison, "gate": gate}, indent=2)
    )

    print(flush=True)
    print("=== summary (aggregated across all runs) ===", flush=True)
    print("--- Tier 1: verdict-label match ---", flush=True)
    print(
        f"  raw_opus:        {comparison['raw_opus']['verdict_exact_pct']:.1f}% "
        f"verdict-exact, mean_distance={comparison['raw_opus']['mean_distance']:.3f}",
        flush=True,
    )
    print(
        f"  argus_full:      {comparison['argus_full']['verdict_exact_pct']:.1f}% "
        f"verdict-exact, mean_distance={comparison['argus_full']['mean_distance']:.3f}",
        flush=True,
    )
    print(
        f"  pp lift:         {comparison['verdict_exact_pp_lift']:+.1f}pp "
        f"(threshold +{gate['verdict_exact_pp_lift_threshold']}pp)",
        flush=True,
    )
    print(
        f"  distance better: {comparison['mean_distance_improvement']:+.3f} "
        f"(threshold +{gate['mean_distance_improvement_threshold']:.2f})",
        flush=True,
    )
    if comparison.get("cost_ratio") is not None:
        print(f"  cost ratio:      {comparison['cost_ratio']:.2f}x argus/opus", flush=True)

    print(flush=True)
    print(
        "Note: BENCH-010 (3-way finding diff) + BENCH-011 (GPT-5.5 judge) + "
        "BENCH-012 (launch report) wire in via separate subcommands once landed.",
        flush=True,
    )

    print(flush=True)
    if gate["passed"]:
        print("BENCH-005 GATE (Tier 1): PASS", flush=True)
    else:
        print("BENCH-005 GATE (Tier 1): FAIL", flush=True)
        if not gate["verdict_exact_pp_lift_pass"]:
            print("  - verdict-exact lift below threshold", flush=True)
        if not gate["mean_distance_improvement_pass"]:
            print("  - distance improvement below threshold", flush=True)
    print(f"\nfull JSON: {summary_path}", flush=True)
    return 0 if gate["passed"] else 1


async def _run_scan_repo(args: argparse.Namespace) -> int:
    """argus scan-repo PATH — walk a directory, scan every supported file."""
    load_dotenv(override=True)

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if not anthropic_key:
        print("error: ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 2
    if not gemini_key:
        print("error: GEMINI_API_KEY not set", file=sys.stderr)
        return 2

    root: Path = args.path.resolve()
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    # Build per-file ScanConfig from the same flags as `argus scan`.
    config_kwargs: dict[str, Any] = {}
    if args.max_cost is not None:
        # On scan-repo, --max-cost is the AGGREGATE cap, not per-file.
        # Per-file caps stay at the ScanConfig default ($1.00) so a
        # single runaway file can't consume the whole budget.
        pass
    if getattr(args, "enable_discovery", False):
        config_kwargs["enable_discovery"] = True
    trigger_str = getattr(args, "dast_trigger_verdicts", None)
    if trigger_str:
        verdicts = tuple(v.strip() for v in trigger_str.split(",") if v.strip())
        valid = {"clean", "suspicious", "malicious", "critical_malicious"}
        invalid = [v for v in verdicts if v not in valid]
        if invalid:
            print(
                f"error: invalid --dast-trigger-verdicts entries: {invalid}. "
                f"Allowed: {sorted(valid)}",
                file=sys.stderr,
            )
            return 2
        if not verdicts:
            print(
                "error: --dast-trigger-verdicts produced an empty list",
                file=sys.stderr,
            )
            return 2
        config_kwargs["dast_trigger_verdicts"] = verdicts
        config_kwargs["discovery_trigger_verdicts"] = verdicts
    scan_config = ScanConfig(**config_kwargs) if config_kwargs else None

    # Build runners (same wiring as `argus scan`).
    triage = make_gemini_triage_runner(gemini_key)
    sonnet = make_sonnet_runner(anthropic_key)
    opus = make_opus_runner(anthropic_key)
    if args.no_dast:
        dast_runner = None
    else:
        dast_runner = make_dast_runner_from_env(api_key=anthropic_key)
        if dast_runner is None:
            log.info(
                "DAST disabled: missing Fly config (FLY_API_TOKEN / "
                "ECHO_DAST_IMAGE_*); running L1-only on every file"
            )

    # Build RepoScanConfig.
    from scanner.repo_scanner import RepoScanConfig, scan_repo
    repo_cfg_kwargs: dict[str, Any] = {
        "root": root,
        "extra_excludes": tuple(args.exclude),
        "respect_gitignore": not args.no_gitignore,
        "diff_ref": args.diff,
        "max_cost_run_usd": args.max_cost,
        "scan_config": scan_config,
        "continue_on_error": args.continue_on_error,
    }
    if args.max_file_bytes is not None:
        repo_cfg_kwargs["max_file_bytes"] = args.max_file_bytes
    repo_cfg = RepoScanConfig(**repo_cfg_kwargs)

    # Progress callback — print as files complete.
    def _progress(idx: int, total: int, path: Path, result: Any, skip: str | None) -> None:
        rel = path.relative_to(root) if root in path.parents or path == root else path
        if skip:
            print(
                f"  [{idx:>3}/{total}] {str(rel)[:60]:<60}  SKIP ({skip})",
                file=sys.stderr,
                flush=True,
            )
            return
        verdict = result.final_verdict if result else "?"
        n_vulns = len(result.vulnerabilities) if result and result.vulnerabilities else 0
        cost = result.total_cost_usd if result else 0.0
        print(
            f"  [{idx:>3}/{total}] {str(rel)[:60]:<60}  {verdict:<20} "
            f"vulns={n_vulns:<2} ${cost:.4f}",
            file=sys.stderr,
            flush=True,
        )

    print(f"=== argus scan-repo {root} ===", file=sys.stderr, flush=True)
    if args.diff:
        print(f"  --diff {args.diff} (incremental mode)", file=sys.stderr, flush=True)
    if args.max_cost is not None:
        print(f"  --max-cost ${args.max_cost:.2f} (aggregate cap)", file=sys.stderr, flush=True)

    report = await scan_repo(
        repo_cfg,
        triage_runner=triage,
        sonnet_runner=sonnet,
        opus_runner=opus,
        dast_runner=dast_runner,
        progress_cb=_progress,
    )

    print(file=sys.stderr, flush=True)
    print(
        f"=== done: {len(report.results)} scanned, "
        f"{len(report.skips)} skipped, "
        f"{len(report.errors)} errored | "
        f"${report.total_cost_usd:.4f} | "
        f"{report.elapsed_s:.1f}s ===",
        file=sys.stderr,
        flush=True,
    )
    if report.cost_cap_hit:
        print(
            f"  WARNING: aggregate cost cap (${args.max_cost:.2f}) hit — "
            f"some files were not scanned.",
            file=sys.stderr,
            flush=True,
        )

    # Render output.
    output_text = _render_repo_output(report, args.output)
    if args.output_file:
        args.output_file.parent.mkdir(parents=True, exist_ok=True)
        args.output_file.write_text(output_text, encoding="utf-8")
        print(f"  -> {args.output_file}", file=sys.stderr, flush=True)
    else:
        print(output_text)

    # Exit code: non-zero if any error and continue-on-error is False; else
    # 0 unless every file errored (degenerate case).
    if report.errors and not report.results:
        return 1
    return 0


def _render_repo_output(report: Any, fmt: str) -> str:
    """Render a RepoScanReport in markdown / json / sarif."""
    if fmt == "sarif":
        from scanner.sarif import render_repo_scan_sarif, to_sarif_string
        return to_sarif_string(render_repo_scan_sarif(report))
    if fmt == "json":
        return json.dumps(
            {
                "root": str(report.root),
                "elapsed_s": report.elapsed_s,
                "total_cost_usd": report.total_cost_usd,
                "cost_cap_hit": report.cost_cap_hit,
                "verdict_counts": report.verdict_counts,
                "results": [r.to_dict() for r in report.results],
                "skips": [
                    {"path": str(s.path), "reason": s.reason, "detail": s.detail}
                    for s in report.skips
                ],
                "errors": [
                    {
                        "path": str(e.path),
                        "error_type": e.error_type,
                        "error_msg": e.error_msg,
                    }
                    for e in report.errors
                ],
            },
            indent=2,
            default=str,
        )
    return _render_repo_markdown(report)


def _render_repo_markdown(report: Any) -> str:
    """Compact human-readable repo-scan summary."""
    lines: list[str] = [
        f"# argus scan-repo: {report.root}",
        "",
        f"**Scanned:** {len(report.results)} files  ",
        f"**Skipped:** {len(report.skips)}  ",
        f"**Errored:** {len(report.errors)}  ",
        f"**Cost:** ${report.total_cost_usd:.4f}  ",
        f"**Time:** {report.elapsed_s:.1f}s",
        "",
    ]
    if report.cost_cap_hit:
        lines.append("> :warning: Aggregate cost cap reached — some files were not scanned.")
        lines.append("")
    if report.verdict_counts:
        lines.append("## Verdicts")
        lines.append("")
        for verdict, count in sorted(
            report.verdict_counts.items(), key=lambda kv: -kv[1]
        ):
            lines.append(f"- `{verdict}` × {count}")
        lines.append("")

    # Notable findings — anything not clean / low_concern.
    notable = [
        r
        for r in report.results
        if r.final_verdict and r.final_verdict not in ("clean", "low_concern")
    ]
    if notable:
        lines.append(f"## Notable findings ({len(notable)})")
        lines.append("")
        for r in sorted(notable, key=lambda r: r.filename):
            n_vulns = len(r.vulnerabilities) if r.vulnerabilities else 0
            lines.append(
                f"- **{r.filename}** — `{r.final_verdict}` "
                f"(risk={r.risk_score}/100, {n_vulns} vulnerabilities, "
                f"${r.total_cost_usd:.4f})"
            )
            for v in (r.vulnerabilities or [])[:5]:
                line_no = v.get("line", "?")
                cwe = v.get("cwe", "?")
                lines.append(
                    f"  - [{cwe}] {v.get('type', '?')} "
                    f"({v.get('severity', '?')}, line {line_no})"
                )
                if v.get("status"):
                    lines.append(f"    - status: `{v['status']}`")
        lines.append("")

    # Errors block.
    if report.errors:
        lines.append("## Errors")
        lines.append("")
        for e in report.errors:
            lines.append(f"- `{e.path}` — `{e.error_type}`: {e.error_msg[:200]}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    # Force UTF-8 stdout so Windows cp1252 consoles don't choke on
    # model-generated unicode (em-dashes, arrows, emoji, etc.).
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return asyncio.run(_run_scan(args))
    if args.command == "bench":
        return asyncio.run(_run_bench(args))
    if args.command == "scan-repo":
        return asyncio.run(_run_scan_repo(args))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
