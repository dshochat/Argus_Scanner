"""Phase 3 Stage 2 scope-gate measurement (thin slice).

Runs the minimal Step 5 ``run_adversarial_loop`` (default ``max_turns=1``)
on a small file slice to decide whether multi-turn refinement is worth
the engineering investment. The decision gate:

  TP >= 4/5 on vuln files AND TN >= 2/3 on clean files
  → ship at ``max_turns=1`` (multi-turn is hardening, not the lever).
  Otherwise → invest in full multi-turn refinement scope.

For each file the harness:

1. Runs Stage 1 (:func:`dast.behavioral_probe.build_behavioral_probe_plan`)
   in the sandbox and parses the :class:`BehavioralProfile`.
2. Runs Phase 3 Stage 2 minimal loop (:func:`run_adversarial_loop`) with
   the file source + Stage 1 profile.
3. Applies a naive binary resolver: any ``VERDICT_CONFIRMED`` outcome →
   ``vulnerable``; otherwise → ``clean``. This is coarser than the full
   Phase 3 verdict resolver (4-state with coverage thresholds) but the
   gate decision only needs the binary axis.
4. Records TP/TN/FP/FN against the file's expected verdict.

Output: a JSON report + a summary table printed to stdout.

Usage::

    uv run python -m methodology.phase_3_thin_slice
    uv run python -m methodology.phase_3_thin_slice --max-turns 3 --output thin_slice_n3.json
    uv run python -m methodology.phase_3_thin_slice --suite-dir samples/regression_v1

The CLI loads ``.env`` for ``ANTHROPIC_API_KEY``, ``FLY_API_TOKEN``,
and ``ECHO_DAST_IMAGE_LEAN`` — same env contract as the production
DAST runner (v1.8 P2b renamed from ECHO_DAST_IMAGE_MINIMAL).
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from dast.adversarial_loop import VERDICT_CONFIRMED, AdversarialLoopResult
from dast.adversarial_loop_runner import run_adversarial_loop
from dast.behavioral_probe import (
    BehavioralProfile,
    build_behavioral_probe_plan,
    parse_behavioral_probe_trace,
)
from dast.inference import make_dast_sonnet_inference
from dast.runner import DEFAULT_FLY_APP, DEFAULT_FLY_REGION, _iter_inner_sandbox_clients
from dast.sandbox.client import (
    FirecrackerSandboxClient,
    FlyMachinesClient,
    MultiImageSandboxClient,
    SandboxClient,
    SandboxPlan,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUITE_DIR = REPO_ROOT / "samples" / "regression_v1"
DEFAULT_OUTPUT = REPO_ROOT / "thin_slice_results.json"

log = logging.getLogger("argus.phase_3_thin_slice")

#: Files validated by Stage 1 (5/5 in the handoff) — used as the vuln
#: subset for the scope-gate measurement. Mix of regression-baseline
#: members and one synthetic probe-target file from samples/.
DEFAULT_VULN_FILES: list[str] = [
    "runtime_probe_path_traversal.py",
    "db2_query_health_check.py",
    "docker_entrypoint_init.py",
    "preinstall.py",
    "xrechnung_visualizer.py",
]

#: Clean files for the TN side of the gate. ``tenda_device_audit.py`` is
#: the only ``clean``-verdict file in the regression baseline; the other
#: two are samples-only utility files.
DEFAULT_CLEAN_FILES: list[str] = [
    "tenda_device_audit.py",
    "clean.py",
    "low.py",
]

#: Gate thresholds — must hold for "Step 5 stays minimal" decision.
GATE_TP_THRESHOLD: int = 4
GATE_TP_OF: int = 5
GATE_TN_THRESHOLD: int = 2
GATE_TN_OF: int = 3


# ── Sandbox + inference construction ──────────────────────────────────────


def _build_components() -> tuple[Any, SandboxClient] | None:
    """Build the sandbox + inference stack from env vars.

    Mirrors :func:`dast.runner.make_dast_runner_from_env`'s wiring but
    returns the components directly rather than wrapped in a
    ``DastRunner`` (we need to call them piecewise for Stage 1 + Stage 2).
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    fly_token = os.environ.get("FLY_API_TOKEN", "")
    image_lean = os.environ.get("ECHO_DAST_IMAGE_LEAN", "")
    missing = [
        name
        for name, val in (
            ("ANTHROPIC_API_KEY", api_key),
            ("FLY_API_TOKEN", fly_token),
            ("ECHO_DAST_IMAGE_LEAN", image_lean),
        )
        if not val
    ]
    if missing:
        log.error("missing required env vars: %s", ", ".join(missing))
        return None

    image_rich_python = os.environ.get("ECHO_DAST_IMAGE_RICH_PYTHON") or image_lean
    image_ml_tools = os.environ.get("ECHO_DAST_IMAGE_ML_TOOLS") or image_lean
    fly_app = os.environ.get("ARGUS_DAST_FLY_APP", DEFAULT_FLY_APP)
    fly_region = os.environ.get("ARGUS_DAST_FLY_REGION", DEFAULT_FLY_REGION)

    fly_client = FlyMachinesClient(
        app_name=fly_app,
        api_token=fly_token,
        region=fly_region,
    )
    sandbox = MultiImageSandboxClient(
        inner_by_hint={
            "lean": FirecrackerSandboxClient(fly_client=fly_client, image=image_lean),
            "rich_python": FirecrackerSandboxClient(fly_client=fly_client, image=image_rich_python),
            "ml_tools": FirecrackerSandboxClient(fly_client=fly_client, image=image_ml_tools),
        },
        fallback_hint="lean",
    )
    inference = make_dast_sonnet_inference(api_key)
    return inference, sandbox


# ── Stage 1 invocation ────────────────────────────────────────────────────


async def _run_stage_1(
    *,
    file_name: str,
    file_bytes: bytes,
    file_id: str,
    sandbox: SandboxClient,
) -> BehavioralProfile | None:
    """Run the Stage 1 behavioral probe in the sandbox and parse the
    profile. Returns ``None`` for non-Python files (probe is Python-only
    in v1.6) or sandbox failures."""
    plan_dict = build_behavioral_probe_plan(
        file_name=file_name,
        file_bytes=file_bytes,
        file_id=file_id,
    )
    if plan_dict is None:
        return None

    plan = SandboxPlan(
        plan_id=f"phase3-thin-slice-stage1-{plan_dict['hypothesis_id']}",
        file_id=file_id,
        hypothesis_id=plan_dict["hypothesis_id"],
        commands=plan_dict["commands"],
        expected_oracle=plan_dict["oracle"],
        payload=plan_dict["payload"],
        timeout_sec=plan_dict["timeout_sec"],
        image_hint=plan_dict["image_hint"],
        file_name=file_name,
        synthesis_context={"behavioral_probe": True},
    )
    try:
        trace = await sandbox.submit(plan)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "Stage 1 sandbox failed for %s: %s",
            file_name,
            f"{type(exc).__name__}: {str(exc)[:200]}",
        )
        return None

    return parse_behavioral_probe_trace(
        file_id=file_id,
        file_name=file_name,
        stdout=trace.stdout_excerpt,
        probe_result_json=getattr(trace, "probe_result_json", "") or "",
    )


# ── Per-file driver ──────────────────────────────────────────────────────


async def _process_file(
    *,
    file_path: Path,
    expected_vuln: bool,
    inference: Any,
    sandbox: SandboxClient,
    max_turns: int,
) -> dict[str, Any]:
    """Run Stage 1 + Phase 3 minimal loop on one file; record metrics."""
    file_name = file_path.name
    file_bytes = file_path.read_bytes()
    file_id = file_name  # naive but unique within a slice

    # Populate every inner sandbox client's file_content_map so the
    # Firecracker VM stages /workspace/<file_name> before Stage 1 tries
    # to import it. Without this Stage 1 hits ModuleNotFoundError, the
    # behavioral profile comes back empty, and Phase 3 designs attacks
    # blind. Production DastRunner does this in dast/runner.py:234.
    for client in _iter_inner_sandbox_clients(sandbox):
        content_map = getattr(client, "file_content_map", None)
        if isinstance(content_map, dict):
            content_map[file_id] = file_bytes

    t0 = time.monotonic()
    profile = await _run_stage_1(
        file_name=file_name,
        file_bytes=file_bytes,
        file_id=file_id,
        sandbox=sandbox,
    )
    stage1_elapsed_ms = int((time.monotonic() - t0) * 1000)

    profile_dict: dict[str, Any] = {}
    if profile is not None:
        # BehavioralProfile is a dataclass — asdict for the prompt.
        profile_dict = dataclasses.asdict(profile)

    t1 = time.monotonic()
    loop_result: AdversarialLoopResult = await run_adversarial_loop(
        file_name=file_name,
        file_bytes=file_bytes,
        file_id=file_id,
        behavioral_profile=profile_dict,
        inference=inference,
        sandbox=sandbox,
        max_turns=max_turns,
    )
    phase3_elapsed_ms = int((time.monotonic() - t1) * 1000)

    # Binary verdict: any CONFIRMED outcome -> vulnerable.
    observed_vuln = any(
        outcome.verdict == VERDICT_CONFIRMED
        for turn in loop_result.turns
        for outcome in turn.outcomes
    )

    # Full per-outcome serialization for FN debugging + Step 9 analysis.
    # ``dataclasses.asdict`` recurses into the nested ``hypothesis``
    # field so we see exactly what the model designed (function_name,
    # args_json, kwargs_json, rationale, attack_class, sequence).
    all_outcomes = [
        dataclasses.asdict(outcome) for turn in loop_result.turns for outcome in turn.outcomes
    ]

    if expected_vuln and observed_vuln:
        verdict_label = "TP"
    elif not expected_vuln and not observed_vuln:
        verdict_label = "TN"
    elif not expected_vuln and observed_vuln:
        verdict_label = "FP"
    else:  # expected_vuln and not observed_vuln
        verdict_label = "FN"

    return {
        "file_name": file_name,
        "expected_vuln": expected_vuln,
        "observed_vuln": observed_vuln,
        "verdict_label": verdict_label,
        "stage1": {
            "ran": profile is not None,
            "callables_explored": profile.callables_explored if profile else 0,
            "callables_total": profile.callables_total if profile else 0,
            "import_error": profile.import_error if profile else "stage1_skipped",
            "elapsed_ms": stage1_elapsed_ms,
        },
        "phase_3": {
            "turn_count": len(loop_result.turns),
            "terminated_by": loop_result.terminated_by,
            "hypotheses_total": loop_result.hypotheses_total,
            "hypotheses_tested": loop_result.hypotheses_tested,
            "hypotheses_confirmed": loop_result.hypotheses_confirmed,
            "hypotheses_refuted": loop_result.hypotheses_refuted,
            "hypotheses_blocked": loop_result.hypotheses_blocked,
            "probe_observed_count": loop_result.explore_calls_used,
            "coverage_ratio": loop_result.coverage_ratio,
            "cost_usd": loop_result.total_cost_usd,
            "tokens_in": loop_result.inference_tokens_in,
            "tokens_out": loop_result.inference_tokens_out,
            "elapsed_ms": phase3_elapsed_ms,
            "findings": loop_result.findings,
            "outcomes": all_outcomes,
        },
    }


# ── Aggregation + gate evaluation ────────────────────────────────────────


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute TP/TN/FP/FN + gate pass/fail."""
    tp = sum(1 for r in rows if r["verdict_label"] == "TP")
    tn = sum(1 for r in rows if r["verdict_label"] == "TN")
    fp = sum(1 for r in rows if r["verdict_label"] == "FP")
    fn = sum(1 for r in rows if r["verdict_label"] == "FN")
    vuln_total = sum(1 for r in rows if r["expected_vuln"])
    clean_total = sum(1 for r in rows if not r["expected_vuln"])
    total_cost = sum(r["phase_3"]["cost_usd"] for r in rows)
    total_phase3_ms = sum(r["phase_3"]["elapsed_ms"] for r in rows)
    total_stage1_ms = sum(r["stage1"]["elapsed_ms"] for r in rows)

    gate_passed = tp >= GATE_TP_THRESHOLD and tn >= GATE_TN_THRESHOLD

    return {
        "total_files": len(rows),
        "vuln_files": vuln_total,
        "clean_files": clean_total,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp_rate": tp / vuln_total if vuln_total else 0.0,
        "tn_rate": tn / clean_total if clean_total else 0.0,
        "gate_thresholds": {
            "tp": f">= {GATE_TP_THRESHOLD}/{GATE_TP_OF}",
            "tn": f">= {GATE_TN_THRESHOLD}/{GATE_TN_OF}",
        },
        "gate_passed": gate_passed,
        "decision": (
            "Ship at max_turns=1 — multi-turn refinement is hardening, not the lever."
            if gate_passed
            else "Invest in full multi-turn refinement scope."
        ),
        "total_cost_usd": total_cost,
        "total_stage1_elapsed_ms": total_stage1_ms,
        "total_phase3_elapsed_ms": total_phase3_ms,
    }


def _print_summary(summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    """Render a human-readable summary table to stdout."""
    print()
    print("=" * 78)
    print("Phase 3 Stage 2 -- thin-slice measurement")
    print("=" * 78)
    print(f"{'FILE':40s} {'EXP':6s} {'OBS':6s} {'LABEL':6s} {'COST $':>8s} {'COV':>5s}")
    print("-" * 78)
    for r in rows:
        exp = "vuln" if r["expected_vuln"] else "clean"
        obs = "vuln" if r["observed_vuln"] else "clean"
        cost = r["phase_3"]["cost_usd"]
        cov = r["phase_3"]["coverage_ratio"]
        print(
            f"{r['file_name']:40s} {exp:6s} {obs:6s} {r['verdict_label']:6s} "
            f"{cost:>8.3f} {cov:>5.2f}"
        )
    print("-" * 78)
    print(
        f"TP={summary['tp']}/{summary['vuln_files']}  "
        f"TN={summary['tn']}/{summary['clean_files']}  "
        f"FP={summary['fp']}  FN={summary['fn']}"
    )
    print(f"Gate: TP {summary['gate_thresholds']['tp']} AND TN {summary['gate_thresholds']['tn']}")
    print(f"Result: {'PASS' if summary['gate_passed'] else 'FAIL'}")
    print(f"Decision: {summary['decision']}")
    print(f"Total cost: ${summary['total_cost_usd']:.2f}")
    print(
        f"Total wall-clock: stage1={summary['total_stage1_elapsed_ms'] / 1000:.1f}s, "
        f"phase3={summary['total_phase3_elapsed_ms'] / 1000:.1f}s"
    )
    print("=" * 78)


# ── CLI ───────────────────────────────────────────────────────────────────


async def _run_async(args: argparse.Namespace) -> int:
    components = _build_components()
    if components is None:
        return 2
    inference, sandbox = components

    suite_dir = Path(args.suite_dir)
    file_specs: list[tuple[str, bool]] = [(name, True) for name in args.vuln_files] + [
        (name, False) for name in args.clean_files
    ]

    # Resolve every file path up-front so missing files fail fast.
    resolved: list[tuple[Path, bool]] = []
    for name, expected_vuln in file_specs:
        path = suite_dir / name
        if not path.exists():
            log.error("file not found: %s", path)
            return 3
        resolved.append((path, expected_vuln))

    rows: list[dict[str, Any]] = []
    for path, expected_vuln in resolved:
        log.info("scanning %s (expected_vuln=%s)", path.name, expected_vuln)
        row = await _process_file(
            file_path=path,
            expected_vuln=expected_vuln,
            inference=inference,
            sandbox=sandbox,
            max_turns=args.max_turns,
        )
        rows.append(row)
        log.info(
            "  -> %s (cost=$%.3f, cov=%.2f, confirmed=%d, refuted=%d, blocked=%d)",
            row["verdict_label"],
            row["phase_3"]["cost_usd"],
            row["phase_3"]["coverage_ratio"],
            row["phase_3"]["hypotheses_confirmed"],
            row["phase_3"]["hypotheses_refuted"],
            row["phase_3"]["hypotheses_blocked"],
        )

    summary = _aggregate(rows)
    report = {
        "config": {
            "max_turns": args.max_turns,
            "suite_dir": str(suite_dir),
            "vuln_files": args.vuln_files,
            "clean_files": args.clean_files,
        },
        "summary": summary,
        "files": rows,
    }
    Path(args.output).write_text(json.dumps(report, indent=2))
    log.info("wrote report to %s", args.output)
    _print_summary(summary, rows)
    return 0 if summary["gate_passed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 3 Stage 2 thin-slice measurement")
    parser.add_argument(
        "--suite-dir",
        type=str,
        default=str(DEFAULT_SUITE_DIR),
        help="Directory containing the slice files (default: samples/regression_v1)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(DEFAULT_OUTPUT),
        help="JSON report output path (default: thin_slice_results.json)",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=1,
        help="Adversarial-loop max turns (default: 1, minimal Step 5)",
    )
    parser.add_argument(
        "--vuln-files",
        nargs="+",
        default=DEFAULT_VULN_FILES,
        help="Vulnerable file basenames in --suite-dir (default: Stage 1-validated set)",
    )
    parser.add_argument(
        "--clean-files",
        nargs="+",
        default=DEFAULT_CLEAN_FILES,
        help="Clean file basenames in --suite-dir (default: tenda + clean.py + low.py)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        help="Logging level (default: INFO)",
    )
    args = parser.parse_args()

    load_dotenv(REPO_ROOT / ".env", override=True)
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )
    return asyncio.run(_run_async(args))


if __name__ == "__main__":
    sys.exit(main())
