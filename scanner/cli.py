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
from dataclasses import replace
from datetime import UTC
from pathlib import Path
from typing import Any

from dotenv import find_dotenv, load_dotenv

from dast.runner import make_dast_runner_from_env
from methodology.bench import (
    BenchAborted,
    BenchRow,
    bench_pass_criteria,
    compare_configs,
    make_raw_opus_baseline_runner,
    run_argus_pipeline_one,
    run_suite,
)
from scanner.engine import ScanConfig, ScanResult, scan_file
from scanner.runners import (
    make_anthropic_hunter_runner_from_adapter,
    make_gemini_triage_runner,
    make_sonnet_triage_runner,
    with_confirm_clean,
    make_opus_runner,
    make_opus_runner_hunter,
    make_opus_runner_split,
    make_sonnet_runner,
    make_sonnet_runner_hunter,
    make_sonnet_runner_split,
)

log = logging.getLogger("argus.cli")


# ── .env auto-loading (v1.8 quick win) ─────────────────────────────────────


def _load_argus_env() -> Path | None:
    """Find and load the right ``.env`` for this invocation of Argus.

    Search order (first hit wins, all calls use ``override=True``):

      1. Walk up from CWD looking for ``.env`` (python-dotenv's
         ``find_dotenv(usecwd=True)``). Lets users run
         ``argus scan ~/work/customer-repo/file.py`` from any project
         directory that has its own ``.env`` (or any parent that does).
      2. Fall back to the Argus install directory's ``.env``
         (resolved via ``__file__``). Lets users run ``argus`` from
         anywhere on the filesystem as long as they did the standard
         clone-and-cp-.env-example setup.
      3. Skip — env vars must come from the OS environment directly.

    Returns the loaded path (or ``None`` if no ``.env`` was found —
    callers shouldn't rely on this since OS-env vars are still picked
    up downstream).

    v1.7 and earlier called ``load_dotenv(override=True)`` directly, which
    only checked CWD. Users had to ``cd`` back to the Argus repo before
    every scan or copy ``.env`` to every target project (a security
    antipattern). This helper eliminates that friction.
    """
    # Step 1: walk up from CWD
    local = find_dotenv(usecwd=True)
    if local:
        load_dotenv(local, override=True)
        log.debug("Loaded .env from CWD walk-up: %s", local)
        return Path(local)

    # Step 2: Argus install directory's .env
    # scanner/cli.py → scanner/ → repo root
    install_env = Path(__file__).resolve().parent.parent / ".env"
    if install_env.exists():
        load_dotenv(install_env, override=True)
        log.debug("Loaded .env from Argus install dir: %s", install_env)
        return install_env

    # Step 3: no .env found — OS env vars must carry the keys.
    log.debug(
        "No .env found via CWD walk-up or Argus install dir; "
        "relying on OS environment for API keys."
    )
    return None


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
        f"**Cost:** ${result.total_cost_usd:.4f}  **Time:** {result.total_duration_ms} ms",
        "",
        f"**Scan path:** {' → '.join(result.scan_path) or '(empty)'}",
        "",
    ]
    # Partition L1 findings by their DAST disposition. The
    # ``per_finding_validation`` list (Tier 1.5, v1.1) carries one entry
    # per L1 vulnerability indicating whether DAST CONFIRMED, BLOCKED,
    # UNREACHED, or didn't test it. Customer reports surface the live
    # (CONFIRMED + UNTESTED) findings under the main heading and move
    # BLOCKED findings to a sub-section so the report doesn't read as
    # noise on hardened code. Falls back to "all live" when no DAST
    # validation ran.
    _validation = result.per_finding_validation or []
    _blocked_keys = {
        (v.get("cwe"), v.get("line"))
        for v in _validation
        if (v.get("status") or "").upper() == "BLOCKED"
    }

    def _vuln_key(v: dict) -> tuple:
        return (v.get("cwe"), v.get("line"))

    live_vulns = [v for v in result.vulnerabilities if _vuln_key(v) not in _blocked_keys]
    blocked_vulns = [v for v in result.vulnerabilities if _vuln_key(v) in _blocked_keys]

    if live_vulns:
        lines.append(f"## Vulnerabilities ({len(live_vulns)})")
        lines.append("")
        for v in live_vulns:
            line = v.get("line", "?")
            lines.append(
                f"- **{v.get('type', '?')}** (severity: {v.get('severity', '?')}, line {line})"
            )
            if v.get("explanation"):
                lines.append(f"  - {v['explanation']}")
            if v.get("fix"):
                lines.append(f"  - **Fix:** {v['fix']}")
        lines.append("")
    if blocked_vulns:
        # Application defended against these in the sandbox. Surface
        # for transparency (operators may still want to know L1 saw a
        # pattern), but visually downranked.
        lines.append(f"## Defended by application ({len(blocked_vulns)})")
        lines.append("")
        lines.append(
            "L1 flagged these patterns, but Finding Validation (sandbox runtime) confirmed the application correctly rejects the attack input. Listed for transparency; **not actionable** for the customer."
        )
        lines.append("")
        for v in blocked_vulns:
            line = v.get("line", "?")
            lines.append(f"- ~~**{v.get('type', '?')}** (line {line})~~ — defended")
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
        lines.append("## Behavioral summary")
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
        lines.append("## Error")
        lines.append("")
        lines.append(f"`{result.error}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ── argparse + entry ───────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argus", description="AI-native code security scanner")
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
        "--enable-remediation",
        action=argparse.BooleanOptionalAction,
        default=None,  # None = use ScanConfig default (v1.11: True)
        help="Remediation (fix-and-verify; aka 'Phase C' in internal "
        "code/JSON). When ON, DAST generates a patched source for "
        "CONFIRMED findings and replays the original exploit against "
        "the patched code to confirm the fix actually closes the bug. "
        "**Default ON as of v1.11** — runtime-grade FP reduction + "
        "verified remediation is Argus's headline pitch. Adds "
        "~$0.05/file in patch-generation token cost. Compliance / CI / "
        "read-only audit users opt out via --no-enable-remediation.",
    )
    scan.add_argument(
        "--enable-phase-d",
        action="store_true",
        help="enable Phase D variant analysis (DAST-301 v1.0 same-file + "
        "DAST-302 v1.1 cross-file). When Finding Validation confirms a "
        "finding, Phase D extracts a semantic signature, hunts for "
        "variants of the same flaw across the project (Python-only in "
        "v1.1; TS/JS is v1.2 work), retargets the seed harness, and "
        "verifies each variant in the sandbox. Confirmed variants "
        "surface as L1+Validation-shaped findings that flow into "
        "Remediation. "
        "Cost-gated at $0.50/seed (PHASE_D_MAX_COST_PER_SEED_USD). "
        "Default OFF for v1 MVP — flip to ON in v1.2 after measurement "
        "on real-world scans. See docs/dast_301_variant_analysis.md.",
    )
    scan.add_argument(
        "--l1-mode",
        choices=("auto", "split", "combined"),
        default="auto",
        help="SCAN-010: L1 analysis mode. ``auto`` (default) = ``split``. "
        "``split`` fans out three specialized prompts "
        "(VULNS / BEHAVIORAL / CHAINS) in parallel on HIGH-triage files — "
        "less hedged findings, ~16% fewer output tokens, 2.6× faster "
        "wall-clock from the fan-out. LOW + CLEAN paths keep the combined "
        "prompt regardless of this flag (cost preservation on the cheap "
        "path). ``combined`` reverts to v1.0's single-call behavior — "
        "useful for A/B regression checks or if cost telemetry shows "
        "split mode regressing on your workload.",
    )
    scan.add_argument(
        "--l1-hunters",
        default=None,
        help="SCAN-011: enable per-attack-class hunter fan-out on "
        "HIGH-triage files. Layered on top of --l1-mode split: the VULNS "
        "slot is replaced by N specialized hunters in parallel. "
        "``all`` enables the full 10-hunter taxonomy "
        "(injection / ssrf / malicious_intent / path_traversal / "
        "deserialization / prompt_injection / credentials / authz / "
        "crypto / exfiltration). Or pass a comma-list to opt into a "
        "subset (e.g. ``ssrf,injection``). Default OFF — cost increase "
        "is ~2× SCAN-010 baseline (~$0.32/HIGH-file). See "
        "docs/scan_011_attack_class_hunters_design.md.",
    )
    scan.add_argument(
        "--enable-runtime-probe",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Exploit Discovery (v1.5; aka 'Phase B+' in internal code/"
        "JSON). Sonnet generates concrete attack inputs for probe-"
        "attractive functions; the sandbox executes each in a "
        "Firecracker microVM; findings come from observed runtime "
        "evidence rather than static analysis. Python-only. Adds "
        "~$0.20-0.50/file in API cost on top of Finding Validation. "
        "Requires DAST configured (Fly). **Default OFF as of v1.11** "
        "— opt in to add zero-day hunting on top of the default "
        "Validation + Remediation cascade. Pass --enable-runtime-probe "
        "to enable.",
    )
    scan.add_argument(
        "--enable-runtime-probe-mutation",
        action="store_true",
        help="enable deterministic mutation expansion of runtime-probe "
        "inputs. For each model-generated attack input, fans out to "
        "known-bypass variants (URL-encode, double-encode, ....// path-"
        "traversal, '; id' command-injection, ' OR 1=1-- SQLi, etc.). "
        "Catches exploits the model's first input shape didn't hit. "
        "Adds ~5x sandbox cost on top of --enable-runtime-probe. "
        "Implies --enable-runtime-probe.",
    )
    scan.add_argument(
        "--enable-runtime-probe-iterative",
        action="store_true",
        help="enable iterative refinement on BLOCKED probes. When all "
        "initial probes for a candidate function failed but the function "
        "was reached (recoverable exceptions like TypeError, SyntaxError, "
        "RangeError), Sonnet sees the actual exception types/messages "
        "and generates refined inputs that address them. Up to 2 retries "
        "per candidate. Adds ~$0.20-0.40/file when refinement fires. "
        "Implies --enable-runtime-probe.",
    )
    scan.add_argument(
        "--enable-runtime-probe-chains",
        action="store_true",
        help="enable cross-function exploit-chain probing. Sonnet "
        "nominates 2-3 step call sequences where each step's args may "
        "reference prior steps' return values (parse->eval, store->load, "
        "sanitize->render). Catches chains where no single call is "
        "exploitable but the sequence is. Adds ~$0.15-0.35/file when "
        "chains land. Independent of mutation and iterative. Implies "
        "--enable-runtime-probe.",
    )
    scan.add_argument(
        "--enable-phase-3-discovery",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Behavioral Profiling (aka 'Phase 3 Stage 1' in internal "
        "code/JSON). Sandbox introspects the module, exercises every "
        "public callable with deterministic benign inputs, captures "
        "runtime observations (eval/exec/subprocess/pickle reach, "
        "file opens, network attempts) into a structured behavioral "
        "profile. Non-destructive: doesn't generate findings, just "
        "surfaces the profile in scan JSON; Adversarial Reasoning "
        "consumes the profile to design attack hypotheses. Adds "
        "~$0.05-0.10/file. **Default OFF as of v1.11** — opt in "
        "alongside --enable-phase-3-loop when you want zero-day "
        "hunting beyond the default Validation + Remediation cascade.",
    )
    scan.add_argument(
        "--enable-phase-3-loop",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Adversarial Reasoning (aka 'Phase 3 Stage 2' in internal "
        "code/JSON). After Behavioral Profiling produces a runtime "
        "profile, the model designs 1-3 attack hypotheses anchored on "
        "observed behavior (rather than static reading) and the sandbox "
        "tests them. Confirmed exploits surface as findings; clean "
        "sandbox execution authoritatively refutes model speculation. "
        "Strategy C (post-trace LLM judge, shipped v1.8) gates FP risk "
        "on CONFIRMED outcomes. Default max_turns=1. Adds ~$0.05/file "
        "+ 3 sandbox runs. **Default OFF as of v1.11** — opt in for "
        "deeper zero-day hunting (also enable "
        "--enable-phase-3-discovery for the Behavioral Profile and "
        "--enable-runtime-probe for the sandbox-probe machinery this "
        "stage dispatches into).",
    )
    scan.add_argument(
        "--phase-3-max-turns",
        type=int,
        default=None,
        metavar="N",
        help="Adversarial Reasoning loop turn cap (default 1). Bump to "
        "2-3 when Exploit Discovery surfaced findings but turn-1 returned "
        "0 hypotheses — gives Opus a second pass to either refute the "
        "existing findings or design adversarial inputs explicitly. Each "
        "extra turn adds ~$0.05-0.10/file.",
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
        "--enable-per-scan-dep-install",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="P2a v0.1 (v1.8): parse the target file's imports and "
        "pip-install missing packages inside the sandbox before plan "
        "execution. Approach A — imports-only, --no-deps (refuses "
        "transitive installs). Only fires when the orchestrator "
        "routes a plan to rich_python or ml_tools tier (lean stays "
        "minimal). Cuts the most common Exploit Discovery / "
        "Behavioral Profiling failure mode (NOT_TESTED:infra_stub from "
        "missing modules). Adds "
        "~5-30s sandbox time per scan when packages need install. "
        "**Default ON as of v1.8.** Pass --no-enable-per-scan-dep-install "
        "to disable per scan.",
    )
    scan.add_argument(
        "--force-dast-through-clean",
        action="store_true",
        default=False,
        help="v15 debug: when triage returns CLEAN, treat as LOW for "
        "routing so the full L1 + DAST cascade runs anyway. The "
        "triage_classification field still reports CLEAN. Use to "
        "exercise sandbox infrastructure end-to-end on a known-"
        "uninteresting file (DAST integration smokes, multi-file "
        "staging validation, etc.). Wastes ~$0.05-0.50 per file vs "
        "the normal short-circuit's $0.001 — NOT for production runs.",
    )
    scan.add_argument(
        "--enable-coverage-dedupe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="v1.9.1: dedupe Exploit Discovery / Adversarial Reasoning "
        "candidate probes against L1-claimed and earlier-stage-confirmed "
        "(function, attack_class) pairs. Default ON — Exploit Discovery's "
        "fixed budget redirects to NEW exploits / NEW callables instead "
        "of re-confirming what L1 already claimed at conf >= 0.6. "
        "Confirmed runtime findings from Exploit Discovery feed back into "
        "the tracker so Adversarial Reasoning + Finding Validation can "
        "dedupe against them too. Each suppression is logged with "
        "rationale citing the source finding. Pass "
        "--no-enable-coverage-dedupe to restore v1.9.0 behavior where "
        "every stage runs unconstrained — useful for investigating a "
        "suspected dedupe false-positive.",
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
        "validation. Default: 'suspicious,malicious,critical_malicious'. "
        "Use 'malicious,critical_malicious' to skip DAST on suspicious files "
        "(saves ~30-50%% API cost; raises FN risk). Use "
        "'critical_malicious' for the strictest cost-controlled mode. "
        "Allowed labels: clean, suspicious, malicious, critical_malicious.",
    )
    scan.add_argument(
        "--dast-trigger-on-finding-confidence",
        type=float,
        default=None,
        metavar="FLOAT",
        help="v1.9: also trigger DAST when ANY L1 vulnerability has "
        "confidence >= this threshold, regardless of the rolled-up "
        "verdict. Use when verdict aggregation rolls down to clean / "
        "suspicious but you want runtime confirmation of a high-"
        "confidence finding anyway (manual audits, DAST-303 cross-"
        "repo candidate validation). Typical value: 0.6. Pass 0.0 to "
        "fire DAST whenever ANY finding exists. Default disabled — "
        "preserves v1.8 verdict-only behavior.",
    )
    scan.add_argument(
        "--triage-model",
        choices=("gemini-flash-lite", "sonnet-4-6"),
        default="sonnet-4-6",
        help="v15.9 (2026-05-20): which model serves the triage stage. "
        "Default 'sonnet-4-6' switched from Flash-Lite. Rationale: the "
        "WCtesting campaign found Flash-Lite variance flipped CLEAN ↔ "
        "HIGH on identical input for borderline files; Sonnet 4.6 at "
        "thinking_budget=0 is far more deterministic at ~20x the per-"
        "file triage cost (~$0.001 -> ~$0.02). Cascade economy is "
        "preserved overall — triage is still <5%% of a typical full "
        "scan's cost. Pass --triage-model gemini-flash-lite to "
        "explicitly opt back to the v1.8-era default; pairs well with "
        "--triage-confirm-clean if so.",
    )
    scan.add_argument(
        "--triage-confirm-clean",
        action="store_true",
        default=False,
        help="v15.8 Gap 3 (2026-05-20): when the first triage call "
        "returns CLEAN, run a SECOND triage call and take the more "
        "conservative (higher-rank) classification. Cuts the "
        "Gemini-Flash-Lite variance flip rate geometrically: a 30%% "
        "single-call CLEAN-flip becomes 9%% with two calls, 2.7%% "
        "with three (not yet exposed). Doubles triage cost on CLEAN "
        "files only (~$0.001 extra per CLEAN file, negligible). "
        "Non-CLEAN first results pass through unchanged. Recommended "
        "for campaign runs where a single CLEAN short-circuit can "
        "skip the full L1+DAST cascade on a real exploit. Adds "
        "triage_runs + triage_classifications_all telemetry to the "
        "scan output so operators can audit which files had a flip "
        "caught by the wrapper.",
    )
    scan.add_argument(
        "--dast-required-policy",
        type=str,
        choices=("downgrade_cap", "strict"),
        default=None,
        help="P3a (v1.8): how Finding Validation per-finding evidence is "
        "mapped onto the published verdict. 'downgrade_cap' (default) "
        "downgrades L1's verdict by at most 1 tier when DAST proposes a "
        "lower verdict (legacy v1.1-v1.7 behavior). 'strict' preserves "
        "L1's verdict unconditionally — never downgrades — and suppresses "
        "only findings that Finding Validation actively tested AND proved "
        "non-exploitable (BLOCKED, UNREACHED, REJECTED). Findings the "
        "sandbox couldn't "
        "reach (NOT_TESTED, including infra failures and non-Python "
        "files) are NEVER suppressed in strict mode. Use 'strict' when "
        "you trust L1's static analysis more than sandbox reachability "
        "and want to avoid DAST infra limitations downgrading real "
        "exploits (e.g. SSRF that needs a real internal endpoint to "
        "demonstrate).",
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
        help="abort the run after K consecutive errored rows (default: 3). Pass 0 to disable.",
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
        "--enable-remediation",
        action=argparse.BooleanOptionalAction,
        default=None,  # None = use ScanConfig default (v1.11: True)
        help="Remediation (fix-and-verify; aka 'Phase C' in internal "
        "code/JSON) on every file in the run. **Default ON as of "
        "v1.11.** Compliance / CI / read-only audit users opt out "
        "via --no-enable-remediation. See `argus scan --help` for full "
        "rationale.",
    )
    repo.add_argument(
        "--enable-phase-d",
        action="store_true",
        help="enable Phase D variant analysis (DAST-301 + DAST-302) on every "
        "file in the run. When Finding Validation confirms a finding, "
        "Phase D hunts for variants across the project + verifies them "
        "in the sandbox. "
        "Adds ~$0.50/seed in inference + sandbox cost. Off by default "
        "for v1 MVP. See `argus scan --help` for the full description.",
    )
    repo.add_argument(
        "--l1-mode",
        choices=("auto", "split", "combined"),
        default="auto",
        help="SCAN-010: L1 analysis mode. See `argus scan --help` for the "
        "full description. ``auto`` (default) = split. ``combined`` "
        "explicitly reverts to v1.0's single-call behavior for this scan.",
    )
    repo.add_argument(
        "--l1-hunters",
        default=None,
        help="SCAN-011: enable per-attack-class hunter fan-out on every "
        "HIGH-triage file in the run. See `argus scan --help` for the "
        "full description. Default OFF.",
    )
    repo.add_argument(
        "--enable-discovery",
        action="store_true",
        help="enable DAST-204 v0.0 proactive vulnerability discovery on "
        "every file in the run that triggers DAST. Adds ~$0.25 per file.",
    )
    repo.add_argument(
        "--enable-runtime-probe",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Exploit Discovery on every DAST-eligible Python / JS / "
        "shell file (aka 'Phase B+' in internal code/JSON). Adds "
        "~$0.20-0.50/file on top of Finding Validation. **Default OFF "
        "as of v1.11** — opt in to add zero-day hunting on top of "
        "the default Validation + Remediation cascade.",
    )
    repo.add_argument(
        "--enable-runtime-probe-mutation",
        action="store_true",
        help="enable deterministic mutation expansion of runtime-probe "
        "inputs (Phase 1a). Fans out each model-generated input to "
        "known-bypass variants. Adds ~5x sandbox cost on top of "
        "--enable-runtime-probe. Implies --enable-runtime-probe.",
    )
    repo.add_argument(
        "--enable-runtime-probe-iterative",
        action="store_true",
        help="enable iterative refinement on BLOCKED probes (Phase 1b). "
        "When all probes for a candidate failed but the function was "
        "reached, Sonnet generates refined inputs addressing the "
        "specific failure modes. Adds ~$0.20-0.40/file when refinement "
        "fires. Implies --enable-runtime-probe.",
    )
    repo.add_argument(
        "--enable-runtime-probe-chains",
        action="store_true",
        help="enable cross-function exploit-chain probing (Phase 2). "
        "Sonnet nominates 2-3 step call sequences where each step's "
        "args may reference prior steps' return values. Adds "
        "~$0.15-0.35/file when chains land. Implies --enable-runtime-probe.",
    )
    repo.add_argument(
        "--enable-phase-3-discovery",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Behavioral Profiling (aka 'Phase 3 Stage 1' in internal "
        "code/JSON). Surfaces a runtime behavioral profile in the scan "
        "output. **Default OFF as of v1.11** — opt in alongside "
        "--enable-phase-3-loop for zero-day hunting.",
    )
    repo.add_argument(
        "--enable-phase-3-loop",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Adversarial Reasoning (aka 'Phase 3 Stage 2' in internal "
        "code/JSON). Model designs attack hypotheses anchored on "
        "Behavioral Profiling's runtime profile and sandbox tests "
        "them. **Default OFF as of v1.11** — opt in for deeper "
        "zero-day hunting beyond the default Validation + Remediation "
        "cascade. See `argus scan --help` for full semantics.",
    )
    repo.add_argument(
        "--enable-per-scan-dep-install",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="P2a v0.1: pip-install the target file's imports inside "
        "the sandbox before plan execution (approach A — imports-only, "
        "--no-deps). Only fires for rich_python/ml_tools tiers. "
        "**Default ON as of v1.8.** See `argus scan --help` for the "
        "full security contract.",
    )
    repo.add_argument(
        "--dast-trigger-verdicts",
        type=str,
        default=None,
        metavar="LIST",
        help="comma-separated list of L1 verdict labels that trigger DAST "
        "validation (default: 'suspicious,malicious,critical_malicious'). "
        "Pass 'malicious,critical_malicious' to skip DAST on suspicious "
        "files for the v1.8-era cost-controlled mode.",
    )
    repo.add_argument(
        "--dast-required-policy",
        type=str,
        choices=("downgrade_cap", "strict"),
        default=None,
        help="P3a (v1.8): 'downgrade_cap' (default) or 'strict'. Strict "
        "preserves L1's verdict unconditionally and suppresses only "
        "findings Finding Validation actively proved non-exploitable "
        "(BLOCKED, UNREACHED, REJECTED) — never on infra/NOT_TESTED. See "
        "`argus scan --help` for details.",
    )
    repo.add_argument(
        "--continue-on-error",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="if a single file errors during scan, record the error and "
        "continue (default: --continue-on-error). Use --no-continue-on-error "
        "to abort the run on the first file-level exception.",
    )

    # ── argus install — pre-install supply-chain gate ──────────────────────
    install = sub.add_parser(
        "install",
        help="Pre-install package gate: scan a PyPI package (and its "
        "dependency closure) before installing it. Blocks on malicious "
        "verdicts; otherwise calls real pip install.",
        description=(
            "Stage a package via `pip download` (no setup.py execution), "
            "scan every wheel/sdist in the dependency closure with the "
            "Argus cascade harness (and DAST Finding Validation + "
            "Exploit Discovery if Fly is "
            "configured), then either install or block based on the "
            "worst verdict found. Remediation (aka 'Phase C') is always "
            "off on the install path — for a not-yet-installed package, "
            "the right action is 'don't install', not 'patch'."
        ),
    )
    install.add_argument(
        "target",
        nargs="?",
        default=None,
        help="package spec (e.g. 'requests', 'litellm==1.50.0', 'fastapi[all]'). "
        "Mutually exclusive with --requirement.",
    )
    install.add_argument(
        "-r",
        "--requirement",
        type=Path,
        default=None,
        metavar="PATH",
        help="install from a requirements.txt file. Argus scans every wheel "
        "in the resolved closure.",
    )
    install.add_argument(
        "--block-on",
        type=str,
        default="malicious,critical_malicious",
        metavar="LIST",
        help="comma-separated verdict tiers that block install. "
        "Default: 'malicious,critical_malicious'. "
        "Allowed: clean,suspicious,malicious,critical_malicious. "
        "Use 'suspicious,malicious,critical_malicious' for stricter gating.",
    )
    install.add_argument(
        "--no-dast",
        action="store_true",
        help="cascade only — skip DAST runtime detonation even if Fly is "
        "configured. Faster + cheaper, but leaves runtime-only "
        "exploits (load-time RCE in pickles, etc.) un-validated.",
    )
    install.add_argument(
        "--no-cache",
        action="store_true",
        help="ignore the wheel-hash verdict cache. Re-scans every artifact "
        "from scratch even if it's been scanned before. By default, Argus "
        "caches verdicts at ~/.cache/argus/install/<sha256>.json.",
    )
    install.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        metavar="PATH",
        help="override the cache directory (default: ~/.cache/argus/install).",
    )
    install.add_argument(
        "--dry-run",
        action="store_true",
        help="run the scan + report verdict; do NOT call pip install at the end. "
        "Useful for CI gating without side-effects.",
    )
    install.add_argument(
        "--strict-coverage",
        action="store_true",
        help="escalate verdict to 'suspicious' when Argus could only "
        "statically analyze <70%% of files in a wheel (the rest are "
        "typically native binaries: .so, .pyd, .dll, .dylib, .exe — "
        "Argus does not decompile these in v1.2). For security-paranoid "
        "users / strict CI gates that prefer to block on uncertainty. "
        "Without this flag, unscanned counts are reported but do not "
        "affect the verdict.",
    )
    install.add_argument(
        "--max-total-cost",
        type=float,
        default=None,
        metavar="USD",
        help="aggregate cost cap across the whole dependency-closure "
        "scan (default: $10.00). When cumulative API spend hits this, "
        "remaining wheels are flagged 'suspicious / unscanned-due-to-cost-cap' "
        "and the install fails closed. Pass 0 to disable. Use a higher "
        "cap for big closures with --deep mode.",
    )
    install.add_argument(
        "--deep",
        action="store_true",
        help="full-fidelity scan: enables thinking_budget=24000 on every "
        "Sonnet/Opus call, sets per-file concurrency to 1 (sequential, "
        "deterministic cost-cap enforcement), and lowers parallel_scans "
        "to 4. Use when reasoning depth on subtle multi-step exploits "
        "matters more than throughput. Cost: 5–10x more than default. "
        "Mutually exclusive with --no-thinking.",
    )
    install.add_argument(
        "--no-thinking",
        action="store_true",
        help="explicit: drop Anthropic extended-thinking on every "
        "Sonnet/Opus call (sets thinking_budget=0). Already the install "
        "default; pass this flag to make the choice explicit in scripts. "
        "Mutually exclusive with --deep.",
    )
    install.add_argument(
        "--enable-runtime-probe",
        action="store_true",
        help="enable Exploit Discovery (v1.5; aka 'Phase B+' in internal "
        "code/JSON). Sonnet generates concrete attack inputs for "
        "probe-attractive functions inside each wheel; the sandbox "
        "executes each in a Firecracker microVM; findings come from "
        "runtime evidence rather than static analysis. Python-only in "
        "v1.5. Adds ~$0.20-0.50/file in API cost on top of Finding "
        "Validation. Requires DAST configured (Fly) and --no-dast NOT set.",
    )
    install.add_argument(
        "--enable-runtime-probe-mutation",
        action="store_true",
        help="enable deterministic mutation expansion of runtime-probe "
        "inputs. Fans out each model-generated attack input to known-"
        "bypass variants (URL-encode, ....// path-traversal, '; id' "
        "command-injection, etc.). Adds ~5x sandbox cost on top of "
        "--enable-runtime-probe. Implies --enable-runtime-probe.",
    )
    install.add_argument(
        "--enable-runtime-probe-iterative",
        action="store_true",
        help="enable iterative refinement on BLOCKED probes (Phase 1b). "
        "Implies --enable-runtime-probe. See `argus scan` for details.",
    )
    install.add_argument(
        "--enable-runtime-probe-chains",
        action="store_true",
        help="enable cross-function exploit-chain probing (Phase 2). "
        "Implies --enable-runtime-probe. See `argus scan` for details.",
    )
    install.add_argument(
        "--enable-phase-3-discovery",
        action="store_true",
        help="enable Behavioral Profiling (aka 'Phase 3 Stage 1' in "
        "internal code/JSON). Implies --enable-runtime-probe. See "
        "`argus scan` for details.",
    )
    install.add_argument(
        "--enable-phase-3-loop",
        action="store_true",
        help="enable Adversarial Reasoning (aka 'Phase 3 Stage 2' in "
        "internal code/JSON). Implies --enable-phase-3-discovery and "
        "--enable-runtime-probe. See `argus scan` for details.",
    )
    install.add_argument(
        "--max-cost",
        type=float,
        default=None,
        metavar="USD",
        help="per-file cost cap during scanning (default: $1.00; pass 0 to disable).",
    )
    install.add_argument(
        "--output",
        choices=("text", "json"),
        default="text",
        help="output format. Default: text (human-readable). 'json' for CI consumption.",
    )
    install.add_argument(
        "--pip",
        type=str,
        default="pip",
        metavar="EXEC",
        help="pip executable to use for download + install. Default: pip. "
        "Pass 'uv pip' for uv-managed environments. Note: use a venv-local "
        "pip to install into the right place.",
    )
    install.add_argument(
        "--parallel",
        type=int,
        default=4,
        metavar="N",
        help="max number of artifacts scanned concurrently (default: 4). "
        "Lower if you hit API rate limits.",
    )
    return parser


async def _run_scan(args: argparse.Namespace) -> int:
    _load_argus_env()

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if not anthropic_key:
        print(
            "error: ANTHROPIC_API_KEY not set in environment or .env",
            file=sys.stderr,
        )
        return 2
    # v15.9: GEMINI_API_KEY only required when --triage-model is
    # gemini-flash-lite. Default Sonnet triage runs on Anthropic alone.
    if getattr(args, "triage_model", "sonnet-4-6") == "gemini-flash-lite" and not gemini_key:
        print(
            "error: GEMINI_API_KEY required when --triage-model=gemini-flash-lite. "
            "Either set GEMINI_API_KEY in .env or drop the flag to use the default "
            "Sonnet 4.6 triage (runs on ANTHROPIC_API_KEY alone).",
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

    # v15.9 (2026-05-20): triage model is selectable. Default is
    # Sonnet 4.6 (higher determinism, ~$0.02/file) per the v15.9
    # switch; Flash-Lite is the explicit opt-back option.
    _triage_model = getattr(args, "triage_model", "sonnet-4-6")
    if _triage_model == "gemini-flash-lite":
        triage = make_gemini_triage_runner(gemini_key)
    else:
        triage = make_sonnet_triage_runner(anthropic_key)
    # v15.8 Gap 3: optional confirm-clean wrapper. Opt-in via
    # --triage-confirm-clean so default behavior stays unchanged.
    if getattr(args, "triage_confirm_clean", False):
        triage = with_confirm_clean(triage)
    sonnet = make_sonnet_runner(anthropic_key)
    opus = make_opus_runner(anthropic_key)
    # SCAN-010 (v1.1, default-enabled 2026-05-18): build split-mode
    # runners when --l1-mode is split OR auto. ``auto`` was a
    # placeholder during the validation period that resolved to
    # combined; post-Gate-1 it resolves to split (the new default
    # behavior). ``combined`` is the explicit opt-out for operators
    # who want v1.0's single-call behavior.
    l1_mode = getattr(args, "l1_mode", "auto") or "auto"
    use_split = l1_mode in ("split", "auto")
    if use_split:
        sonnet_split = make_sonnet_runner_split(anthropic_key)
        opus_split = make_opus_runner_split(anthropic_key)
    else:
        sonnet_split = None
        opus_split = None

    # SCAN-011 — hunter runners built only when --l1-hunters is passed.
    # Value is ``all`` (full taxonomy) or a comma-list of hunter keys
    # (e.g., ``ssrf,injection``). None / empty → hunter mode off.
    l1_hunters_arg = getattr(args, "l1_hunters", None)
    if l1_hunters_arg:
        hunter_set: tuple[str, ...] | None
        if l1_hunters_arg == "all":
            hunter_set = None  # None means all in ATTACK_CLASS_HUNTERS
        else:
            hunter_set = tuple(
                k.strip() for k in l1_hunters_arg.split(",") if k.strip()
            )
        sonnet_hunter = make_sonnet_runner_hunter(
            anthropic_key, hunter_set=hunter_set
        )
        opus_hunter = make_opus_runner_hunter(
            anthropic_key, hunter_set=hunter_set
        )
    else:
        sonnet_hunter = None
        opus_hunter = None
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
    # v1.11: Remediation default flipped to ON. The CLI flag is now
    # BooleanOptionalAction(default=None) so we can distinguish:
    #   * None  → user didn't pass the flag → use ScanConfig default (True)
    #   * True  → --enable-remediation passed → force ON
    #   * False → --no-enable-remediation passed → force OFF
    _rem_flag = getattr(args, "enable_remediation", None)
    if _rem_flag is not None:
        config_kwargs["enable_phase_c"] = bool(_rem_flag)
    # DAST-301/302 v1.0/v1.1: Phase D variant analysis opt-in.
    if getattr(args, "enable_phase_d", False):
        config_kwargs["enable_phase_d"] = True
    # SCAN-010 (default-enabled 2026-05-18): split mode is the
    # new default. ``--l1-mode combined`` explicitly disables it for
    # this scan; everything else (split / auto / unset) keeps the
    # ScanConfig default of True. Don't override when the user
    # passed combined — let the dataclass default handle the True
    # case so we don't double-set.
    if l1_mode == "combined":
        config_kwargs["l1_split_enabled"] = False
    # SCAN-011 — hunter mode is opt-in. ``--l1-hunters`` sets the
    # flag; absence keeps the ScanConfig default (False).
    if l1_hunters_arg:
        config_kwargs["l1_hunter_enabled"] = True
    # v1.8: --enable-runtime-probe / --enable-phase-3-discovery /
    # --enable-phase-3-loop are BooleanOptionalAction with default=True.
    # args.X is always a bool; propagate directly so --no-enable-X
    # actually disables.
    config_kwargs["enable_runtime_probe"] = bool(getattr(args, "enable_runtime_probe", True))
    config_kwargs["enable_phase_3_discovery"] = bool(
        getattr(args, "enable_phase_3_discovery", True)
    )
    config_kwargs["enable_phase_3_loop"] = bool(getattr(args, "enable_phase_3_loop", True))
    p3_turns = getattr(args, "phase_3_max_turns", None)
    if p3_turns is not None:
        config_kwargs["phase_3_loop_max_turns"] = int(p3_turns)
    # P2a v0.1: per-scan dep installer. Default ON; orchestrator further
    # gates by image tier (only rich_python / ml_tools actually install).
    config_kwargs["enable_per_scan_dep_install"] = bool(
        getattr(args, "enable_per_scan_dep_install", True)
    )
    # v15 debug bypass — treat CLEAN as LOW for routing purposes only.
    # Wastes API spend on uninteresting files; use for sandbox-path
    # validation only.
    config_kwargs["force_dast_through_clean"] = bool(
        getattr(args, "force_dast_through_clean", False)
    )
    # Variants stay opt-in store_true. They still imply the base probe
    # — defend against `--no-enable-runtime-probe --enable-runtime-probe-mutation`.
    if getattr(args, "enable_runtime_probe_mutation", False):
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_runtime_probe_mutation"] = True
    if getattr(args, "enable_runtime_probe_iterative", False):
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_runtime_probe_iterative"] = True
    if getattr(args, "enable_runtime_probe_chains", False):
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_runtime_probe_chains"] = True
    # Stage 2 requires Stage 1 + runtime probe machinery. Defend
    # against contradictory opt-out combos.
    if config_kwargs.get("enable_phase_3_loop"):
        config_kwargs["enable_phase_3_discovery"] = True
        config_kwargs["enable_runtime_probe"] = True
    elif config_kwargs.get("enable_phase_3_discovery"):
        config_kwargs["enable_runtime_probe"] = True
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
    # v1.9: finding-based DAST trigger override. None = disabled
    # (verdict-only gate, the v1.8 default).
    finding_threshold = getattr(args, "dast_trigger_on_finding_confidence", None)
    if finding_threshold is not None:
        if not (0.0 <= finding_threshold <= 1.0):
            print(
                f"ERROR: --dast-trigger-on-finding-confidence must be in "
                f"[0.0, 1.0], got {finding_threshold}",
                file=sys.stderr,
            )
            return 2
        config_kwargs["dast_trigger_on_finding_confidence"] = finding_threshold
    # P3a (v1.8): report-layer DAST policy. Default is None on argparse so
    # we only override ScanConfig when the user explicitly passed the flag.
    policy = getattr(args, "dast_required_policy", None)
    if policy is not None:
        config_kwargs["dast_required_policy"] = policy
    config = ScanConfig(**config_kwargs) if config_kwargs else None

    result = await scan_file(
        filename=file_path.name,
        content=content,
        config=config,
        triage_runner=triage,
        sonnet_runner=sonnet,
        opus_runner=opus,
        sonnet_runner_split=sonnet_split,
        opus_runner_split=opus_split,
        sonnet_runner_hunter=sonnet_hunter,
        opus_runner_hunter=opus_hunter,
        dast_runner=dast_runner,
        # v11 (2026-05-17): full host path threaded through so the
        # DAST runner can resolve sibling project files for multi-
        # file TS/JS/Python targets (relative ``./foo`` imports).
        # ``filename`` stays as basename for back-compat (result
        # display + sandbox staging path).
        host_path=str(file_path),
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
    _load_argus_env()
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
        from datetime import datetime

        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
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

    print("=== argus bench ===")
    print(f"  suite:        {suite_dir}")
    print(f"  baseline:     {baseline_path}  ({n_files} files)")
    print(f"  N (runs/cfg): {args.n}")
    print("  configs:      raw_opus + argus_full" + (" (no DAST)" if args.no_dast else ""))
    print(f"  output dir:   {out_dir}")
    print(
        f"  cost (est.):  ~${proj_total:.2f}  "
        f"({avg_opus_per_file:.2f} opus + {avg_argus_per_file:.2f} argus per file × {n_files} × N={args.n})"
    )
    # Per-file wall time observed live: raw Opus ~1-2 min, Argus full
    # pipeline 3-7 min when DAST fires. So per-pair-per-run: ~4-9 min.
    avg_min = 1.5 + (5.0 if not args.no_dast else 1.5)  # opus + argus avg
    n_pairs = n_files * args.n
    print(
        f"  wall time:    ~{n_pairs * avg_min * 0.6 / 60:.1f}-"
        f"{n_pairs * avg_min * 1.4 / 60:.1f} hours "
        f"(per-file: {avg_min:.1f} min avg, sequential)"
    )
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

    # v15.9 (2026-05-20): triage model is selectable. Default is
    # Sonnet 4.6 (higher determinism, ~$0.02/file) per the v15.9
    # switch; Flash-Lite is the explicit opt-back option.
    _triage_model = getattr(args, "triage_model", "sonnet-4-6")
    if _triage_model == "gemini-flash-lite":
        triage = make_gemini_triage_runner(gemini_key)
    else:
        triage = make_sonnet_triage_runner(anthropic_key)
    # v15.8 Gap 3: optional confirm-clean wrapper. Opt-in via
    # --triage-confirm-clean so default behavior stays unchanged.
    if getattr(args, "triage_confirm_clean", False):
        triage = with_confirm_clean(triage)
    sonnet = make_sonnet_runner(anthropic_key)
    opus = make_opus_runner(anthropic_key)
    if args.no_dast:
        argus_dast = None
    else:
        argus_dast = make_dast_runner_from_env(api_key=anthropic_key)
        if argus_dast is None:
            print("warning: DAST not configured — Argus pipeline will run L1-only", file=sys.stderr)

    async def argus_full_runner(filename, content, baseline_meta):
        return await run_argus_pipeline_one(
            filename,
            content,
            baseline_meta,
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
                suite_dir,
                baseline_path,
                raw_opus_runner,
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
                suite_dir,
                baseline_path,
                argus_full_runner,
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
    summary_path.write_text(json.dumps({"comparison": comparison, "gate": gate}, indent=2))

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
    _load_argus_env()

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
    # v1.11: Remediation default flipped to ON. The CLI flag is now
    # BooleanOptionalAction(default=None) so we can distinguish:
    #   * None  → user didn't pass the flag → use ScanConfig default (True)
    #   * True  → --enable-remediation passed → force ON
    #   * False → --no-enable-remediation passed → force OFF
    _rem_flag = getattr(args, "enable_remediation", None)
    if _rem_flag is not None:
        config_kwargs["enable_phase_c"] = bool(_rem_flag)
    # DAST-301/302 v1.0/v1.1: Phase D variant analysis opt-in.
    if getattr(args, "enable_phase_d", False):
        config_kwargs["enable_phase_d"] = True
    # v1.8: --enable-runtime-probe / --enable-phase-3-discovery /
    # --enable-phase-3-loop are BooleanOptionalAction with default=True.
    # args.X is always a bool; propagate directly so --no-enable-X
    # actually disables.
    config_kwargs["enable_runtime_probe"] = bool(getattr(args, "enable_runtime_probe", True))
    config_kwargs["enable_phase_3_discovery"] = bool(
        getattr(args, "enable_phase_3_discovery", True)
    )
    config_kwargs["enable_phase_3_loop"] = bool(getattr(args, "enable_phase_3_loop", True))
    p3_turns = getattr(args, "phase_3_max_turns", None)
    if p3_turns is not None:
        config_kwargs["phase_3_loop_max_turns"] = int(p3_turns)
    # P2a v0.1: per-scan dep installer. Default ON; orchestrator further
    # gates by image tier (only rich_python / ml_tools actually install).
    config_kwargs["enable_per_scan_dep_install"] = bool(
        getattr(args, "enable_per_scan_dep_install", True)
    )
    # v15 debug bypass — treat CLEAN as LOW for routing purposes only.
    # Wastes API spend on uninteresting files; use for sandbox-path
    # validation only.
    config_kwargs["force_dast_through_clean"] = bool(
        getattr(args, "force_dast_through_clean", False)
    )
    # Variants stay opt-in store_true. They still imply the base probe
    # — defend against `--no-enable-runtime-probe --enable-runtime-probe-mutation`.
    if getattr(args, "enable_runtime_probe_mutation", False):
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_runtime_probe_mutation"] = True
    if getattr(args, "enable_runtime_probe_iterative", False):
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_runtime_probe_iterative"] = True
    if getattr(args, "enable_runtime_probe_chains", False):
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_runtime_probe_chains"] = True
    # Stage 2 requires Stage 1 + runtime probe machinery. Defend
    # against contradictory opt-out combos.
    if config_kwargs.get("enable_phase_3_loop"):
        config_kwargs["enable_phase_3_discovery"] = True
        config_kwargs["enable_runtime_probe"] = True
    elif config_kwargs.get("enable_phase_3_discovery"):
        config_kwargs["enable_runtime_probe"] = True
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
    # P3a (v1.8): see `_run_scan` for rationale.
    policy = getattr(args, "dast_required_policy", None)
    if policy is not None:
        config_kwargs["dast_required_policy"] = policy
    scan_config = ScanConfig(**config_kwargs) if config_kwargs else None

    # Build runners (same wiring as `argus scan`).
    # v15.9 (2026-05-20): triage model is selectable. Default is
    # Sonnet 4.6 (higher determinism, ~$0.02/file) per the v15.9
    # switch; Flash-Lite is the explicit opt-back option.
    _triage_model = getattr(args, "triage_model", "sonnet-4-6")
    if _triage_model == "gemini-flash-lite":
        triage = make_gemini_triage_runner(gemini_key)
    else:
        triage = make_sonnet_triage_runner(anthropic_key)
    # v15.8 Gap 3: optional confirm-clean wrapper. Opt-in via
    # --triage-confirm-clean so default behavior stays unchanged.
    if getattr(args, "triage_confirm_clean", False):
        triage = with_confirm_clean(triage)
    sonnet = make_sonnet_runner(anthropic_key)
    opus = make_opus_runner(anthropic_key)
    # SCAN-010 (default-enabled 2026-05-18) — split runs by default
    # (l1_mode auto / split). ``combined`` is the opt-out.
    l1_mode = getattr(args, "l1_mode", "auto") or "auto"
    use_split = l1_mode in ("split", "auto")
    if use_split:
        sonnet_split = make_sonnet_runner_split(anthropic_key)
        opus_split = make_opus_runner_split(anthropic_key)
        # scan_config default already has l1_split_enabled=True; no
        # mutation needed in the auto case. Force it on for explicit
        # ``--l1-mode split`` in case the caller built a ScanConfig
        # with the flag overridden False.
        if l1_mode == "split":
            if scan_config is None:
                scan_config = ScanConfig(l1_split_enabled=True)
            else:
                scan_config = replace(scan_config, l1_split_enabled=True)
    else:
        sonnet_split = None
        opus_split = None
        # Explicit opt-out: combined mode means flag off for this scan.
        if scan_config is None:
            scan_config = ScanConfig(l1_split_enabled=False)
        else:
            scan_config = replace(scan_config, l1_split_enabled=False)
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
        sonnet_runner_split=sonnet_split,
        opus_runner_split=opus_split,
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
        for verdict, count in sorted(report.verdict_counts.items(), key=lambda kv: -kv[1]):
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
                    f"  - [{cwe}] {v.get('type', '?')} ({v.get('severity', '?')}, line {line_no})"
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


# ── argus install handler ─────────────────────────────────────────────────


_VALID_VERDICT_TIERS: frozenset[str] = frozenset(
    {"clean", "suspicious", "malicious", "critical_malicious"}
)


def _format_install_text(report: Any) -> str:
    """Human-readable install report. Surfaces blocked findings up top
    with file/CWE/severity so the user can read the analysis without
    parsing JSON."""
    from scanner.install import VERDICT_RANK  # noqa: PLC0415

    lines: list[str] = []
    if report.blocked:
        lines.append(f"❌ BLOCKED: {report.target}")
        lines.append(f"   verdict: {report.worst_verdict}")
        lines.append(f"   reason:  {report.block_reason}")
    elif report.error:
        lines.append(f"❌ ERROR:   {report.target}")
        lines.append(f"   {report.error}")
    elif not report.pip_install_attempted:
        lines.append(f"✓  DRY-RUN: {report.target}")
        lines.append(f"   verdict: {report.worst_verdict} (would install)")
    elif report.pip_install_succeeded:
        lines.append(f"✓  INSTALLED: {report.target}")
        lines.append(f"   verdict: {report.worst_verdict}")
    else:
        lines.append(f"⚠  pip install FAILED after Argus passed: {report.target}")
        lines.append(f"   verdict: {report.worst_verdict} (Argus passed)")
        if report.pip_install_stderr:
            lines.append(f"   pip stderr: {report.pip_install_stderr[:300]}")

    lines.append("")
    lines.append(
        f"   artifacts={report.n_artifacts} "
        f"cache_hits={report.n_cache_hits} "
        f"dast_runs={report.n_dast_runs} "
        f"cost=${report.aggregate_cost_usd:.4f} "
        f"elapsed={report.elapsed_s:.1f}s"
    )

    if report.wheels:
        lines.append("")
        lines.append("   Per-artifact verdicts:")
        # Sort worst-first
        for w in sorted(
            report.wheels,
            key=lambda x: -VERDICT_RANK.get(x.verdict, 0),
        ):
            cache_tag = "  [cached]" if w.cached else ""
            dast_tag = " +DAST" if w.dast_attempted else ""
            cov = ""
            if w.n_files_unscanned > 0:
                pct = w.coverage_ratio * 100
                cov = f"  [coverage {pct:.0f}%, {w.n_files_unscanned} unscanned]"
            lines.append(f"     {w.verdict:<20} {w.artifact_name}{dast_tag}{cache_tag}{cov}")

    # Coverage warnings — surface artifacts where Argus skipped a
    # meaningful chunk of files (native binaries / compiled bytecode).
    # A 'clean' verdict on a wheel that's 50% .so files is much weaker
    # evidence than a clean verdict on a wheel that's 100% .py files.
    low_coverage = [w for w in report.wheels if w.coverage_ratio < 0.7 and w.n_files_unscanned >= 2]
    if low_coverage:
        lines.append("")
        lines.append(
            "   ⚠ Coverage warning — these artifacts contain files Argus could not statically analyze:"
        )
        for w in low_coverage:
            ext_summary = ", ".join(
                f"{ext}×{n}"
                for ext, n in sorted(w.unscanned_extensions.items(), key=lambda kv: -kv[1])[:5]
            )
            lines.append(
                f"     {w.artifact_name}: "
                f"{w.coverage_ratio * 100:.0f}% scanned ({w.n_files_unscanned} skipped: {ext_summary})"
            )
        lines.append(
            "     Native binaries (.so, .pyd, .dylib, .dll) are not decompiled in v1.2. "
            "A 'clean' verdict on these artifacts attests only to the analyzable code."
        )
        lines.append("     Use --strict-coverage to escalate these to 'suspicious' automatically.")

    if report.blocked:
        # Show the worst findings so the user understands WHY
        culprits = sorted(
            report.wheels,
            key=lambda x: -VERDICT_RANK.get(x.verdict, 0),
        )[:3]
        lines.append("")
        lines.append("   Worst findings (top 5 from blocked artifacts):")
        n_shown = 0
        for w in culprits:
            for f in w.findings_summary[:5]:
                if n_shown >= 5:
                    break
                cwe = f.get("cwe") or "?"
                sev = f.get("severity") or "?"
                ftype = f.get("type") or "?"
                fpath = f.get("file") or "?"
                expl = f.get("explanation") or ""
                lines.append(f"     [{sev:>8}] {cwe:<10} {ftype:<24} {fpath}")
                if expl:
                    lines.append(f"               {expl[:120]}")
                n_shown += 1

    return "\n".join(lines) + "\n"


async def _run_install(args: argparse.Namespace) -> int:
    """Handler for ``argus install <pkg>``."""
    _load_argus_env()
    from scanner.install import (  # noqa: PLC0415
        CACHE_DIR_DEFAULT,
    )
    from scanner.install import (
        install as run_install,
    )

    # Validate exactly-one of target / -r
    if args.target is None and args.requirement is None:
        print(
            "ERROR: provide either a package spec (e.g. 'argus install requests') "
            "or -r requirements.txt",
            file=sys.stderr,
        )
        return 2
    if args.target is not None and args.requirement is not None:
        print(
            "ERROR: --requirement and a positional target are mutually exclusive",
            file=sys.stderr,
        )
        return 2

    # Validate --block-on tiers
    block_on = tuple(t.strip() for t in args.block_on.split(",") if t.strip())
    invalid = [t for t in block_on if t not in _VALID_VERDICT_TIERS]
    if invalid:
        print(
            f"ERROR: invalid --block-on entries: {invalid}. "
            f"Allowed: {sorted(_VALID_VERDICT_TIERS)}",
            file=sys.stderr,
        )
        return 2

    # Build runners — same wiring as ``argus scan``. DAST runner is
    # built only if Fly env is present (gracefully degrades to None).
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GOOGLE_API_KEY", "")
    if not anthropic_key:
        print("ERROR: ANTHROPIC_API_KEY env var required", file=sys.stderr)
        return 2
    if not gemini_key:
        print(
            "ERROR: GEMINI_API_KEY (or GOOGLE_API_KEY) env var required",
            file=sys.stderr,
        )
        return 2

    # --deep / --no-thinking are mutually exclusive
    if args.deep and args.no_thinking:
        print(
            "ERROR: --deep and --no-thinking are mutually exclusive",
            file=sys.stderr,
        )
        return 2

    # Tier the cascade depth based on flags. Default install path drops
    # extended thinking entirely (5-10x faster on Sonnet/Opus calls); the
    # ~3-5pp accuracy loss on subtle multi-step exploits is recovered by
    # the deterministic preprocessing escalation flags. --deep flips it
    # back to thinking_budget=24000 for users who want full fidelity.
    thinking_budget = 24000 if args.deep else 0

    # Per-file concurrency inside each wheel. v1.3.1 default = 4 inside
    # a wheel × 8 wheels in parallel = up to 32 concurrent file scans on
    # a big closure. --deep falls back to 1 (sequential per file) so the
    # per-file cost-cap check stays strictly pre-scan.
    file_concurrency = 1 if args.deep else 4
    parallel_scans = 4 if args.deep else max(1, args.parallel)

    # v15.9 (2026-05-20): triage model is selectable. Default is
    # Sonnet 4.6 (higher determinism, ~$0.02/file) per the v15.9
    # switch; Flash-Lite is the explicit opt-back option.
    _triage_model = getattr(args, "triage_model", "sonnet-4-6")
    if _triage_model == "gemini-flash-lite":
        triage = make_gemini_triage_runner(gemini_key)
    else:
        triage = make_sonnet_triage_runner(anthropic_key)
    # v15.8 Gap 3: optional confirm-clean wrapper. Opt-in via
    # --triage-confirm-clean so default behavior stays unchanged.
    if getattr(args, "triage_confirm_clean", False):
        triage = with_confirm_clean(triage)
    sonnet = make_sonnet_runner(anthropic_key, thinking_budget=thinking_budget)
    opus = make_opus_runner(anthropic_key, thinking_budget=thinking_budget)
    dast_runner = None if args.no_dast else make_dast_runner_from_env(api_key=anthropic_key)
    if dast_runner is None and not args.no_dast:
        log.info("DAST not configured (Fly env missing); install gate runs cascade-only")

    # Build a per-file ScanConfig — install path always disables Phase C
    # (handled inside scanner.install.scan_one_artifact, defensive in caller too).
    #
    # v1.8: scan defaults flipped Phase 3 (Stage 1+2+runtime probe) ON
    # globally, but the install path scans every wheel in a dep closure
    # — Phase 3 on every wheel would be a ~10x cost blowout. Force the
    # 3 phase-3 flags off here unless the user explicitly opts in via
    # the install-path --enable-* flags (those stay store_true, default
    # False — i.e., install is the one place that didn't get the
    # BooleanOptionalAction treatment, intentionally).
    config_kwargs: dict[str, Any] = {
        "enable_phase_c": False,
        "enable_runtime_probe": False,
        "enable_phase_3_discovery": False,
        "enable_phase_3_loop": False,
    }
    if args.max_cost is not None:
        config_kwargs["max_cost_per_file_usd"] = args.max_cost
    if getattr(args, "enable_runtime_probe", False):
        config_kwargs["enable_runtime_probe"] = True
    if getattr(args, "enable_runtime_probe_mutation", False):
        # Mutation implies probing — turn both on so users can pass
        # only --enable-runtime-probe-mutation without needing the
        # parent flag too.
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_runtime_probe_mutation"] = True
    if getattr(args, "enable_runtime_probe_iterative", False):
        # Iterative refinement implies probing — same convenience rule.
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_runtime_probe_iterative"] = True
    if getattr(args, "enable_runtime_probe_chains", False):
        # Chain probing implies probing — same convenience rule.
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_runtime_probe_chains"] = True
    if getattr(args, "enable_phase_3_discovery", False):
        # Phase 3 behavioral probe needs the sandbox machinery that
        # enable_runtime_probe brings up. Imply it so users don't have
        # to set both flags.
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_phase_3_discovery"] = True
    if getattr(args, "enable_phase_3_loop", False):
        # Phase 3 Stage 2 adversarial loop consumes Stage 1's behavioral
        # profile and the sandbox machinery. Imply both parent flags so
        # users only need --enable-phase-3-loop on the command line.
        config_kwargs["enable_runtime_probe"] = True
        config_kwargs["enable_phase_3_discovery"] = True
        config_kwargs["enable_phase_3_loop"] = True
    scan_cfg = ScanConfig(**config_kwargs)

    cache_dir = args.cache_dir or CACHE_DIR_DEFAULT

    # Aggregate cost cap. CLI default is None (=> install function's
    # DEFAULT_MAX_TOTAL_COST_USD = $10); user can override or disable.
    max_total_cost = args.max_total_cost
    if max_total_cost is not None and max_total_cost <= 0:
        max_total_cost = None  # explicit "disable"

    report = await run_install(
        target=args.target,
        requirement_file=args.requirement,
        block_on=block_on,
        no_dast=args.no_dast,
        use_cache=not args.no_cache,
        cache_dir=cache_dir,
        dry_run=args.dry_run,
        strict_coverage=args.strict_coverage,
        pip_executable=args.pip,
        scan_cfg=scan_cfg,
        triage_runner=triage,
        sonnet_runner=sonnet,
        opus_runner=opus,
        dast_runner=dast_runner,
        parallel_scans=parallel_scans,
        file_concurrency=file_concurrency,
        max_total_cost_usd=max_total_cost,
    )

    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        print(_format_install_text(report))

    if report.error:
        return 2
    if report.blocked:
        return 1
    if report.pip_install_attempted and not report.pip_install_succeeded:
        return 3
    return 0


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
    if args.command == "install":
        return asyncio.run(_run_install(args))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
