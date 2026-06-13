"""DAST iteration loop. Hard cap = 3 iterations.

Pipeline
--------
S models → L1 (existing, frozen) → DAST (this module) → final verdict.

Each iteration is three model calls + N sandbox calls:
  Phase A plan      (1 call)  — emit executable sandbox plans for the
                                pending hypothesis pool
  Phase A verdict   (1 call)  — score per-claim + emit current_verdict
  Phase B explore   (1 call)  — propose new hypotheses for next iter

Stop conditions (whichever fires first)
---------------------------------------
S1  ``iter > MAX_ITERATIONS``                        (hard cap = 3)
S2  iteration produced 0 new confirmed findings
S3  iteration produced 0 hypotheses passing the validator gate
TC  per-file token count exceeded ``TOKEN_CAP_PER_FILE``  (1M)

Final verdict = the last iteration's Phase-A ``current_verdict``. There
is no L2 stage.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import prompts as dast_prompts
from .inference import infer_with_schema_retry
from .sandbox.client import _derive_python_module_name
from .journal import (
    Journal,
    JournalPhase,
    JournalRecord,
)
from .sandbox.client import SandboxClient, SandboxPlan, SandboxTrace
from .validator import HypothesisValidator

MAX_ITERATIONS: int = 3
TOKEN_CAP_PER_FILE: int = 1_000_000

# SCAN-007 — in-flight DAST cost cap. ``run_dast`` self-bounds spend so a
# single file's validation + remediation can't blow past the per-file
# budget the engine passes in (``max_cost_usd`` = the per-file ceiling
# minus what triage/L1 already spent). Without this, DAST is one
# monolithic await and the engine's post-stage cost check can only abort
# the REST of the scan AFTER the overspend already happened.
#
# The rates below are deliberately the OPUS tier (5/25), not the Sonnet
# 3/15 the runner reports DAST cost on. A safety cap must never
# UNDER-count: using the higher tier guarantees the in-flight estimate is
# an upper bound, so run_dast stops AT OR BEFORE the real $ ceiling
# regardless of the scan/reason tier mix (Phase C gates run on Opus).
# Reported cost is unchanged — this estimate is only the stop trigger.
_COST_CAP_IN_PER_M: float = 5.0
_COST_CAP_OUT_PER_M: float = 25.0


def _dast_cost_estimate_usd(tokens_in: int, tokens_out: int) -> float:
    """Conservative (upper-bound) USD estimate of DAST spend so far, used
    ONLY for the in-flight safety cap — not for reported cost."""
    return (tokens_in * _COST_CAP_IN_PER_M + tokens_out * _COST_CAP_OUT_PER_M) / 1_000_000


# One inference call returns this dict shape (matches our streaming
# helper output): { text, usage{prompt_tokens, completion_tokens, ...},
# finish_reason, ... }
InferenceFn = Callable[[str, dict[str, Any], dict[str, Any] | None], Awaitable[dict[str, Any]]]


@dataclass
class IterationStats:
    iter: int
    phase_a_plan_in: int = 0
    phase_a_plan_out: int = 0
    phase_a_verdict_in: int = 0
    phase_a_verdict_out: int = 0
    phase_b_in: int = 0
    phase_b_out: int = 0
    # v1.5: Phase B+ runtime exploit probing — token usage from the
    # candidate-generation inference call. Zero when the probe stage
    # doesn't fire (default path).
    phase_b_runtime_probe_in: int = 0
    phase_b_runtime_probe_out: int = 0
    new_confirmed_findings: int = 0
    hypotheses_proposed: int = 0
    hypotheses_accepted: int = 0
    hypotheses_rejected: int = 0
    sandbox_calls: int = 0
    iter_erosion_guard_fired: bool = False  # Phase 2b: clamped a downgrade
    journal_input_tokens: int = 0  # tokens read from journal at iter start
    elapsed_s: float = 0.0
    current_verdict_label: str = "clean"
    finish_reasons: dict[str, str] = field(default_factory=dict)
    # v1.10 SCAN-009: Phase A schema-retry telemetry. Counts retry
    # firings (regardless of outcome) and retry-exhausted failures.
    # Cross-phase: covers both Phase A plan and Phase A verdict calls.
    # ``retries`` >= ``failed`` always. When ``failed`` > 0, the
    # journal has matching ``PHASE_A_SCHEMA_INVALID`` records for
    # post-hoc debugging.
    phase_a_schema_validation_retries: int = 0
    phase_a_schema_validation_failed: int = 0


@dataclass
class DastResult:
    file_id: str
    iterations: list[IterationStats]
    final_verdict: dict[str, Any]
    findings_validated: list[str]
    total_tokens_in: int
    total_tokens_out: int
    total_sandbox_calls: int
    elapsed_s: float
    stop_reason: str
    journal_path: Path
    diagnostics: dict[str, Any] = field(default_factory=dict)
    # v1.9: rich detail for each entry in ``findings_validated``.
    # Keyed by the same finding_ref string. Each value carries the
    # FULL finding dict the source phase built — finding_type,
    # severity, cwe, line, code_snippet, explanation,
    # data_flow_trace, proof_of_concept, confidence,
    # runtime_evidence. Populated only for DAST-DISCOVERED findings
    # (HRP_* from Phase B+ runtime probe, HRP_AL_* from Phase 3
    # adversarial loop, HRP_C* from Phase B chain probes) — L1
    # findings already have their detail in ``l1_output["hypotheses"]``
    # so the per_finding_validation builder reads it from there.
    # Engine reads this map to extend per_finding_validation with
    # rows for findings that DAST discovered net-new (no L1
    # hypothesis backing). Empty dict when no probe/chain
    # confirmations fired.
    findings_validated_meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Tier 1.5 (v1.1): per-record journal dump (claim_id, verdict,
    # rationale per hypothesis). Lets downstream consumers classify
    # rejected hypotheses into BLOCKED / UNREACHED / NOT_TESTED.
    # Populated at end-of-run from journal.read_all().
    journal_records: list[dict[str, Any]] = field(default_factory=list)

    # v1.2: Phase C — fix-and-verify result. None if Phase C didn't run
    # (no confirmed findings, or skipped). When populated, contains:
    #   {
    #     "attempted": bool,
    #     "patched_source": str | None,
    #     "fix_summary": str,
    #     "post_patch_verdict": "clean|suspicious|malicious|critical_malicious",
    #     "per_finding": [{finding_ref, post_patch_status:
    #         NEUTRALIZED|STILL_EXPLOITABLE|UNVERIFIABLE}, ...],
    #     "n_neutralized": int, "n_still_exploitable": int,
    #     "tokens_in": int, "tokens_out": int, "n_replays": int,
    #     "elapsed_s": float, "error": str | None,
    #   }
    phase_c: dict[str, Any] | None = None

    # DAST-301 Phase D variant analysis results (v1 MVP).
    # One entry per L1 finding that Phase A confirmed AND that Phase D
    # ran on. Each entry is a PhaseDResult asdict() with the semantic
    # signature, AST-enumerated candidates, LLM-judged similarity
    # scores, and per-candidate sandbox verdicts. Empty list when
    # ``enable_phase_d=False`` or no Phase A confirmations exist.
    variant_analysis: list[dict[str, Any]] = field(default_factory=list)

    # DAST-304 Phase C multi-file patch propagation (v2.0).
    # Populated when ``enable_phase_d=True`` AND ``enable_phase_c=True``
    # AND Phase D surfaced confirmed variants in sibling files (not
    # the seed's own file). Shape:
    #   {
    #     "attempted": bool,
    #     "patched_files": [
    #       {
    #         "file_path": "lib/helpers.py",
    #         "patched_source": "...",
    #         "fix_summary": "...",
    #         "variants_in_file": ["D-H001-1", ...],
    #         "verifications": [
    #           {"finding_ref": "D-H001-1", "status": "UNVERIFIABLE",
    #            "rationale": "..."},
    #         ],
    #         "tokens_in": int, "tokens_out": int,
    #       },
    #       ...
    #     ],
    #     "n_files_patched": int,
    #     "n_variants_neutralized": int,
    #     "n_variants_still_exploitable": int,
    #     "n_variants_unverifiable": int,
    #     "tokens_in": int, "tokens_out": int,
    #     "cost_usd": float, "elapsed_s": float,
    #   }
    # None when DAST-304 didn't run (flag combo off, no cross-file
    # variants, no project_root).
    variant_remediation: dict[str, Any] | None = None

    # Phase 3 Stage 1: RUNTIME behavioral exploration profile. Populated
    # when ``enable_phase_3_discovery=True`` and the probe stage ran.
    # Captures what each public callable actually does at runtime (side
    # effects, dangerous-builtin reach, file/network attempts). Stage 2's
    # adversarial reasoning loop uses this profile as the ground-truth
    # input for attack hypothesis generation. ``None`` when the probe
    # stage didn't run (flag off, non-Python file, or import failed
    # cleanly without producing a usable profile).
    #
    # Named ``runtime_behavioral_profile`` to disambiguate from the
    # static-analysis cascade's separate ``behavioral_profile`` field
    # surfaced on ScanResult (different schema, different concept).
    runtime_behavioral_profile: dict[str, Any] | None = None

    # Phase 3 Stage 2 (v1.6): adversarial reasoning loop summary.
    # Populated when ``enable_phase_3_loop=True`` and the loop ran
    # (which requires Stage 1's behavioral profile to be present).
    # Shape:
    #   {
    #     "ran": bool,
    #     "max_turns": int,
    #     "turns_executed": int,
    #     "terminated_by": str,
    #     "hypotheses_total": int,
    #     "hypotheses_confirmed": int,
    #     "hypotheses_refuted": int,
    #     "hypotheses_blocked": int,
    #     "probe_observed_count": int,
    #     "coverage_ratio": float,
    #     "cost_usd": float,
    #     "tokens_in": int, "tokens_out": int,
    #     "elapsed_ms": int,
    #     "findings": list[dict],  # CONFIRMED outcomes; probes skipped
    #   }
    # ``None`` when the loop didn't run (flag off, non-Python file,
    # no behavioral profile, or Stage 1 failed). The 4-state verdict
    # resolver (Phase 3 follow-on) consumes this field to decide
    # confirmed_high_confidence / clean_run / partial_run / unreachable.
    phase_3_loop: dict[str, Any] | None = None

    # Phase 3 verdict resolver decision. Always populated (the resolver
    # is a pure function that handles ``phase_3_loop=None`` gracefully).
    # Shape:
    #   {
    #     "final_verdict": str,    # one of VERDICT_RANK labels
    #     "verdict_source": str,   # phase_3_confirmed | phase_3_clean
    #                              # | phase_3_partial | l1_fallback
    #                              # | l1_no_phase_3
    #     "coverage_class": str,   # high | partial | unreachable | no_run
    #     "static_only": bool,     # True iff L1 floor used as canonical
    #     "rationale": str,        # human-readable explanation
    #   }
    # Currently surfaced as observation -- the engine's existing
    # final_verdict logic is unchanged. The JSON v3 output schema will
    # promote this to canonical (deferred follow-on so we can ship
    # behavior changes after live-validation on the 23-file suite).
    phase_3_resolver_decision: dict[str, Any] | None = None


def _parse_json_or_empty(text: str) -> dict:
    if not text or not text.strip():
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


# ─── Phase A planner antipattern validator ────────────────────────────
#
# v1.9.2 (2026-05-19) — production-grade compliance gate for the Phase A
# planner LLM. The planner is instructed via the "HARD CHECKLIST" in
# dast/prompts.py to use ``$MODULE_NAME`` / ``$ENTRY_REL_PATH`` when
# the target is a Python package member or JS/TS subdir target. The LLM
# is mostly compliant but occasionally regresses on individual
# hypotheses (smoke #6: 1 of 3 emitted ``python3 /workspace/<basename>``
# instead). Those probes deterministically fail with ImportError on the
# entry file's relative-import statements (Python) or unresolved
# parent-dir imports (JS/TS) — silently masking real exploits as
# NOT_TESTED.
#
# Strategy: detect deterministic antipatterns on the host side after
# the planner returns; if any plans are tainted, call inference ONCE
# more with a focused correction note. Caps the cost at +1 inference
# call per iteration (~$0.03-0.05).


# Plan-command antipatterns we detect. Each entry is a (pattern, reason)
# pair; the pattern is a literal substring OR a regex (compiled lazily).
def _python_antipattern_substrings(file_name: str) -> list[tuple[str, str]]:
    """Literal substrings that signal a flat-file Python invocation
    of a package-member target. Generated dynamically from the target's
    basename so the check works for any package member, not just
    jsonpickle."""
    basename = Path(file_name).name
    if not basename.endswith(".py"):
        return []
    return [
        (
            f"python3 /workspace/{basename}",
            f"flat-file Python execution `python3 /workspace/{basename}` "
            f"loads the basename copy which fails on the entry's `from .` "
            f"relative imports; use `import $MODULE_NAME` instead",
        ),
        (
            f'python3 "/workspace/{basename}"',
            f"flat-file Python execution (double-quoted form); use `import $MODULE_NAME` instead",
        ),
        (
            f"python3 '/workspace/{basename}'",
            f"flat-file Python execution (single-quoted form); use `import $MODULE_NAME` instead",
        ),
    ]


def _js_ts_antipattern_substrings(file_name: str) -> list[tuple[str, str]]:
    """Literal substrings that signal a flat-file Node/tsx invocation
    of a multi-file project target. Checks BOTH runners regardless
    of extension — the planner sometimes invokes a .ts file via
    plain `node` (which would fail at runtime, but the antipattern
    target is the flat path, not the runner choice)."""
    basename = Path(file_name).name
    if not basename.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx")):
        return []
    runners = ("node", "tsx")
    out: list[tuple[str, str]] = []
    for runner in runners:
        out.extend(
            [
                (
                    f'{runner} "/workspace/{basename}"',
                    f"flat-file {runner} execution `{runner} "
                    f"/workspace/{basename}` loads the basename copy "
                    f"which breaks any parent-dir / sibling imports "
                    f"inside the target; use $ENTRY_REL_PATH",
                ),
                (
                    f"{runner} /workspace/{basename}",
                    f"flat-file {runner} execution (unquoted form); use $ENTRY_REL_PATH",
                ),
                (
                    f"{runner} '/workspace/{basename}'",
                    f"flat-file {runner} execution (single-quoted form); use $ENTRY_REL_PATH",
                ),
            ]
        )
    return out


def _detect_planner_antipatterns(
    commands: list[Any],
    *,
    file_name: str,
    entry_rel_path: str,
    module_name: str,
) -> list[str]:
    """Return a list of antipattern descriptions found in plan commands.

    Triggers only when the target is a multi-file scan member:
      * Python: ``module_name`` non-empty (i.e. ``$MODULE_NAME`` is set
        — entry file lives in a package directory). The flat copy at
        ``/workspace/<basename>`` lacks the parent package context.
      * JS/TS: ``entry_rel_path`` contains a directory separator (entry
        lives in a subdir of the project root). The flat copy at
        ``/workspace/<basename>`` lacks parent-dir context for
        ``../sibling`` imports.

    Returns ``[]`` for flat single-file scans (no antipatterns possible).

    Detection rules:
      1. ``python3 /workspace/<basename>`` (any quoting) — flat-file
         script execution of a package member.
      2. ``import <basename_stem>`` as bare statement (no sys.path setup,
         no dotted form) — basename-only import that loads the flat copy.
      3. ``pip install <pkg_root>`` — attempt to fetch a pre-staged
         package from PyPI. DNS hijacked → SSL-fail. Also catches
         ``pip install -r requirements.txt`` indirectly (we don't
         specifically match that — it's usually benign).
      4. ``node /workspace/<basename>`` (any quoting) — flat-file JS exec.
      5. ``tsx /workspace/<basename>`` (any quoting) — flat-file TS exec.
      6. ``npm install <pkg_root>`` — analog of (3) for npm.
    """
    if not commands:
        return []

    findings: list[str] = []
    is_python_pkg = bool(module_name)
    is_js_ts_subdir = (
        bool(entry_rel_path)
        and "/" in entry_rel_path
        and file_name.lower().endswith((".js", ".mjs", ".cjs", ".ts", ".tsx"))
    )
    if not (is_python_pkg or is_js_ts_subdir):
        return []

    basename = Path(file_name).name
    basename_stem = Path(file_name).stem
    pkg_root = module_name.split(".", 1)[0] if module_name else ""

    py_substrings = _python_antipattern_substrings(file_name) if is_python_pkg else []
    js_substrings = _js_ts_antipattern_substrings(file_name) if is_js_ts_subdir else []

    # Bare basename import — only fires when MODULE_NAME is set. Matches
    # `import unpickler` but NOT `import jsonpickle.unpickler` (the
    # dotted form is correct).
    bare_import_re = (
        re.compile(rf"\bimport\s+{re.escape(basename_stem)}\b(?!\s*\.)") if is_python_pkg and basename_stem else None
    )

    # pip install of the local pre-staged package.
    pip_install_re = re.compile(rf"pip\s+install\b.*\b{re.escape(pkg_root)}\b") if is_python_pkg and pkg_root else None

    # npm install of the local pre-staged package. Conservative: only
    # fire if the entry's project_root has a package.json (heuristic via
    # entry_rel_path containing a leading scoped/unscoped pkg dir).
    npm_install_re = None
    if is_js_ts_subdir and entry_rel_path:
        first_seg = entry_rel_path.split("/", 1)[0]
        if first_seg:
            npm_install_re = re.compile(rf"npm\s+install\b.*\b{re.escape(first_seg)}\b")

    for cmd in commands:
        if not isinstance(cmd, str) or not cmd:
            continue
        for needle, reason in py_substrings:
            if needle in cmd:
                findings.append(reason)
                break
        for needle, reason in js_substrings:
            if needle in cmd:
                findings.append(reason)
                break
        if bare_import_re is not None and bare_import_re.search(cmd):
            if f"import {module_name}" not in cmd:
                findings.append(
                    f"basename-only import `import {basename_stem}` "
                    f"loads the flat copy; use `import {module_name}` "
                    f"(package-qualified)"
                )
        if pip_install_re is not None and pip_install_re.search(cmd):
            findings.append(
                f"`pip install {pkg_root}` attempts to fetch a "
                f"pre-staged local package; sandbox DNS is hijacked to "
                f"127.0.0.1 — install will SSL-fail. The package is "
                f"already at /workspace/{pkg_root}/"
            )
        if npm_install_re is not None and npm_install_re.search(cmd):
            findings.append(
                f"`npm install` of a pre-staged local package; use the file at /workspace/$ENTRY_REL_PATH directly"
            )

    # Dedupe while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for f in findings:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _build_planner_correction_appendix(
    *,
    plans: list[dict],
    file_name: str,
    entry_rel_path: str,
    module_name: str,
    findings_by_plan: dict[int, list[str]],
) -> str:
    """Build the appendix text added to the Phase A planner prompt
    when one or more plans need correction. The appendix lists which
    plan IDs had which issues and reiterates the required template.

    The full original prompt is preserved verbatim; the appendix is
    APPENDED so the LLM has every original constraint plus the
    specific correction note. Conservative wrt prompt length: only
    fires when antipatterns are actually present.
    """
    is_python_pkg = bool(module_name)
    lines = [
        "",
        "═══════════════════════════════════════════════════════════════════",
        "PLAN VALIDATION FAILURE — REGENERATE THE FOLLOWING PLANS",
        "═══════════════════════════════════════════════════════════════════",
        "",
        "Your previous response included plans that violate the HARD",
        "CHECKLIST. You MUST emit a new plan list where the offending",
        "commands are rewritten using the required template.",
        "",
    ]
    for idx, issues in sorted(findings_by_plan.items()):
        plan = plans[idx] if 0 <= idx < len(plans) else {}
        hyp_id = plan.get("hypothesis_id", f"plan-{idx}")
        lines.append(f"Plan {idx} (hypothesis_id={hyp_id!r}) — issues:")
        for issue in issues:
            lines.append(f"  • {issue}")
        lines.append("")

    if is_python_pkg:
        lines.extend(
            [
                "Required template for Python package member"
                f" ($MODULE_NAME = {module_name!r}, $ENTRY_REL_PATH = "
                f"{entry_rel_path!r}):",
                "",
                '  python3 -c \'import sys; sys.path.insert(0, "/workspace"); '
                f"import {module_name} as m; <your exploit code that uses m.xxx>'",
                "",
            ]
        )
    if entry_rel_path and not is_python_pkg:
        # JS/TS subdir target
        runner = "tsx" if file_name.endswith((".ts", ".tsx")) else "node"
        lines.extend(
            [
                f"Required template for JS/TS subdir target ($ENTRY_REL_PATH = {entry_rel_path!r}):",
                "",
                f'  cd /workspace && {runner} "$ENTRY_REL_PATH" <args...>',
                "",
            ]
        )
    lines.extend(
        [
            "Return the COMPLETE plan list (all plans, not just the corrected",
            "ones). Use the same `hypothesis_id` for each plan as before so",
            "the orchestrator can correlate.",
            "═══════════════════════════════════════════════════════════════════",
        ]
    )
    return "\n".join(lines)


# Phase 2b: iter-erosion guard.
# Verdict labels ordered low → high. The orchestrator tracks the highest
# DAST-emitted verdict reached and refuses downgrades that aren't
# grounded in explicit sandbox refutation of a previously confirmed
# finding. Without this, a follow-up iter that fails to re-confirm an
# already-confirmed exploit (e.g. environmental: "curl missing in
# image") is given the same weight as actual disconfirmation, eroding a
# correct verdict. See campaign_summary.md → litellm_obfuscated case.
_VERDICT_RANK: dict[str, int] = {
    "clean": 0,
    "informational": 1,
    "suspicious": 2,
    "malicious": 3,
    "critical_malicious": 4,
}

# Storage bound for the verdict's free-text log_summary. The request
# schema deliberately has no hard maxLength (so the model is never
# rejected for an over-long log string); we truncate to this on ingest.
# Kept in sync with shared.types.verdict.Verdict.log_summary's max_length.
_LOG_SUMMARY_MAX = 400


def _post_patch_status(claim_verdict: str | None) -> str:
    """Map a post-patch per-claim verdict to a remediation status.

    Claim-verdict vocabulary (see ``dast/prompts.py`` — the verdict enum
    is ``confirmed`` / ``refuted`` / ``inconclusive``):

      * ``confirmed``    — the exploit STILL fires against the patched
        code  → ``STILL_EXPLOITABLE``.
      * ``refuted``      — the trace AFFIRMATIVELY shows the exploit no
        longer fires  → ``NEUTRALIZED`` (a verified fix).
      * ``inconclusive`` / ``None`` / anything else — no decisive
        evidence either way  → ``UNVERIFIABLE``.

    Prior bug (pre-2026-06): this matched the phantom value ``rejected``
    (never emitted by the schema), so ``refuted`` — the actual proof of a
    fix — fell through to ``UNVERIFIABLE``, while ``inconclusive`` (no
    evidence) was wrongly reported as ``NEUTRALIZED``. The mapping was
    effectively inverted; remediation could not report a verified fix.
    """
    if claim_verdict == "confirmed":
        return "STILL_EXPLOITABLE"
    if claim_verdict == "refuted":
        return "NEUTRALIZED"
    return "UNVERIFIABLE"


def _confirmation_is_grounded(cited_event_ids: Any, real_event_ids: set[str]) -> bool:
    """T19 precision guard: a CONFIRMED Phase A verdict must cite at least
    one event_id that actually exists in the iteration's sandbox traces.

    The verdict prompt requires a runtime side-effect event for a
    "confirmed" claim, but nothing verified the model's citation was real —
    a confidently-wrong model could fabricate a confirmation off a
    non-existent event_id. This checks the citation against the genuine
    trace events. Returns False (→ caller downgrades to inconclusive) when
    the citation is empty, malformed, or wholly fabricated. The downgrade
    is the SAFE direction: inconclusive keeps L1's verdict, never erases.
    """
    if not isinstance(cited_event_ids, list):
        return False
    return any(str(e) in real_event_ids for e in cited_event_ids)


def _has_refutation_of_prior_confirmed(
    claim_verdicts: list,
    hyp_index: dict,
    prev_confirmed: set[str],
) -> bool:
    """Did this iteration produce a sandbox-grounded refutation of a
    previously confirmed finding?

    A refutation counts only when ALL of:
      * ``cv["verdict"] == "refuted"``
      * ``cv["sandbox_event_ids"]`` is non-empty (real evidence, not
        a freelance verdict)
      * The refuted hypothesis's finding_ref (or upstream chain
        confirmed_finding_ref) is in ``prev_confirmed`` — i.e. it
        targets something a prior iter actually confirmed.
    """
    for cv in claim_verdicts:
        if not isinstance(cv, dict):
            continue
        if cv.get("verdict") != "refuted":
            continue
        ev_ids = cv.get("sandbox_event_ids") or []
        if not (isinstance(ev_ids, list) and ev_ids):
            continue
        hyp = hyp_index.get(cv.get("hypothesis_id", "")) or {}
        fref = hyp.get("finding_ref") or ((hyp.get("upstream_chain") or {}).get("confirmed_finding_ref"))
        if fref and fref in prev_confirmed:
            return True
    return False


async def run_dast(
    *,
    file_record: dict,
    l1_output: dict,
    sandbox: SandboxClient,
    validator: HypothesisValidator,
    journal_dir: Path,
    inference: InferenceFn,
    phase_3_inference: InferenceFn | None = None,
    enable_phase_c: bool = True,
    enable_runtime_probe: bool = False,
    enable_runtime_probe_mutation: bool = False,
    enable_runtime_probe_iterative: bool = False,
    enable_runtime_probe_chains: bool = False,
    enable_phase_3_discovery: bool = False,
    enable_phase_3_loop: bool = False,
    phase_3_loop_max_turns: int = 1,
    enable_phase_d: bool = False,
    enable_remediation_verify: bool = False,
    enable_per_scan_dep_install: bool = False,
    enable_coverage_dedupe: bool = True,
    max_cost_usd: float | None = None,
) -> DastResult:
    """Run the DAST loop on one file.

    ``file_record`` carries ``file_id``, ``source_text``, plus optional
    diagnostics. ``l1_output`` is the frozen Pass-1 ``scan_report`` block
    (after sanitization to compact form). ``inference`` is a coroutine
    that takes (prompt, sampling_params, json_schema) and returns the
    dict shape produced by ``_run_capability_bundles.stream_call``.
    """
    # Capture L1's pre-DAST verdict for the Phase 3 verdict resolver
    # call at end-of-run. Must be the pre-DAST floor (not the verdict
    # the cascade bumps to during DAST) so the resolver compares Phase 3
    # against L1, not against the DAST-bumped state.
    initial_l1_verdict_label = str((l1_output.get("verdict") or {}).get("verdict_label", "suspicious"))

    file_id = file_record["file_id"]
    source_text = file_record["source_text"]
    # Real basename (with extension) used to stage the file at
    # /workspace/<file_name> in the sandbox. Falls back to file_id so
    # legacy callers without name plumbing still produce a non-empty
    # value, but extension-routed languages (Node, Java) need this set
    # to the real basename for require()/class-loader resolution.
    file_name = file_record.get("file_name", "") or file_id
    started = time.time()

    # P2a v0.2 (v1.8): propagate the per-scan dep-install flag down to
    # the sandbox client. MultiImageSandboxClient.submit() then
    # populates ``plan.runtime_packages`` for any plan whose builder
    # didn't set it (every Phase 3 / runtime probe / behavioral probe
    # path). The Phase A plan-build site (below) already sets it
    # explicitly; MultiImageSandboxClient's check is a no-op when the
    # field is already non-empty.
    #
    # We set unconditionally on EVERY run_dast call so the flag tracks
    # the per-scan cfg state. ``setattr`` is dynamic — sets the field
    # cleanly on MultiImageSandboxClient (production), is harmless on
    # StubSandboxClient (test fixtures) since the field exists with
    # default False from the dataclass declaration. Single-image
    # FirecrackerSandboxClient doesn't read the attr; setting it
    # there is a no-op.
    if hasattr(sandbox, "enable_per_scan_dep_install"):
        sandbox.enable_per_scan_dep_install = enable_per_scan_dep_install

    journal = Journal(file_id=file_id, base_dir=journal_dir)
    iterations: list[IterationStats] = []
    total_in = 0
    total_out = 0
    total_sb = 0
    last_verdict: dict[str, Any] = {
        "verdict_label": (l1_output.get("verdict") or {}).get("verdict_label", "suspicious"),
        "log_summary": "no DAST iteration completed yet",
        "validated_findings": [],
        "confirmed_categories": [],
    }
    findings_validated: list[str] = []
    # v1.9: rich detail for DAST-DISCOVERED findings (HRP_*/HRP_AL_*/
    # HRP_C*). Populated alongside findings_validated by each phase
    # that emits a new finding. Surfaced via DastResult.
    # findings_validated_meta and consumed by the engine to extend
    # per_finding_validation with rows for findings that have no L1
    # hypothesis backing.
    findings_validated_meta: dict[str, dict[str, Any]] = {}
    stop_reason = "unknown"

    # v1.9.1 — coverage tracker for cross-stage dedupe. Pre-populated
    # from L1's high-confidence findings BEFORE Phase B+ fires, so
    # Phase B+ + Phase 3 spend their budget on NEW exploits instead of
    # re-confirming what L1 already claimed with conf >= 0.6.
    # Phase B+/3 confirmations feed back into the tracker so the
    # downstream stage can dedupe against them too. Phase A's iter
    # loop uses it to skip sandbox calls on L1 hypotheses already
    # confirmed by a runtime probe (synthesizes a confirmed journal
    # entry citing the probe's HRP_*/HRP_AL_* finding ID).
    #
    # Default ON. Operators disable via ``--disable-coverage-dedupe``
    # (config ``enable_coverage_dedupe=False``) to restore v1.9.0
    # behavior — every stage runs unconstrained.
    from dast.coverage_tracker import CoverageTracker  # noqa: PLC0415

    coverage_tracker = CoverageTracker(enabled=enable_coverage_dedupe)
    coverage_tracker.populate_from_l1_findings(l1_output.get("hypotheses") or [])

    # Phase 2b: max DAST verdict reached so far (NOT counting the
    # initial L1 verdict). Iters can only downgrade below this with
    # sandbox-grounded refutation evidence.
    max_dast_verdict_rank = -1
    max_dast_verdict_label: str | None = None

    # iter 1 starts with L1 hypotheses; iter ≥ 2 starts with the previous
    # iteration's validator-accepted Phase B hypotheses
    pending_hypotheses: list[dict] = list(l1_output.get("hypotheses") or [])

    # v1.2: capture iter-1 plans for Phase C replay (fix-and-verify).
    # Iter 1 is the natural plan set for re-testing the patched file because
    # iter ≥ 2 plans target Phase B hypotheses that wouldn't exist on a
    # patched (presumed-safe) file. We only need plans; Phase C generates
    # fresh traces against the patched source.
    iter1_plan_records: list[dict] | None = None

    # v1.5 Phase B+ — runtime exploit probing. Runs ONCE before the
    # iteration loop, so even files where L1 found nothing get a probe
    # pass when the flag is on. Findings are surfaced via
    # ``findings_validated`` (NOT via l1_output.hypotheses — see Fix #2).
    #
    # Pre-create iter-1 stats here so the probe's token-usage
    # accounting (Fix #4) goes into the actual stats record the iter
    # loop will pick up — not a throwaway. The loop below detects this
    # pre-init via ``iterations`` non-empty + iter==1 and reuses.
    probe_pre_init_stats: IterationStats | None = None
    # Probe-supported language gate: Python / JavaScript (.js, .mjs, .cjs)
    # / shell (.sh, .bash). detect_probe_language is the single source of
    # truth; plan builder dispatches by the same function.
    from dast.runtime_probe import detect_probe_language  # noqa: PLC0415

    _probe_lang = detect_probe_language(file_name) if enable_runtime_probe else None
    if (
        enable_runtime_probe
        and _probe_lang is not None
        and isinstance(file_record.get("original_bytes"), (bytes, bytearray))
    ):
        probe_pre_init_stats = IterationStats(iter=1)
        iterations.append(probe_pre_init_stats)
        try:
            probe_findings = await _run_phase_b_runtime_probe(
                file_record=file_record,
                l1_output=l1_output,
                journal=journal,
                journal_summary=journal.summarize(up_to_iter=0),
                inference=inference,
                sandbox=sandbox,
                iter_num=1,
                stats=probe_pre_init_stats,
                enable_mutation=enable_runtime_probe_mutation,
                enable_iterative=enable_runtime_probe_iterative,
                enable_per_scan_dep_install=enable_per_scan_dep_install,
                coverage_tracker=coverage_tracker,
            )
            # Fix #2: HRPs are NOT appended to l1_output.hypotheses (would
            # cause Phase A re-test + contradiction). They flow only via
            # findings_validated. pending_hypotheses stays as the original
            # L1 set.

            # Fix #3 (surfacing): every confirmed HRP id reaches engine.py
            # via findings_validated → ScanResult.dast_findings.
            #
            # v1.9 — also stash the FULL finding dict in
            # findings_validated_meta so per_finding_validation can
            # build a row for this DAST-discovered finding (which has
            # no L1 hypothesis backing). Without this, the user sees
            # the verdict-upgrade signal but no PoC / runtime evidence
            # / exploited-function name.
            for f in probe_findings:
                fid = f.get("finding_ref")
                if not fid:
                    continue
                # v15.17: probe_findings can include UNREACHED / REFUTED
                # diagnostic rows in addition to CONFIRMED. Only CONFIRMED
                # rows enter findings_validated (which feeds verdict bumps
                # and dast_findings). Non-CONFIRMED rows still land in
                # findings_validated_meta so per_finding_validation can
                # render them — diagnostics without verdict impact.
                # Default to CONFIRMED for backwards compat (pre-v15.17
                # probe_findings entries don't carry a status field).
                _probe_status = "CONFIRMED"
                if isinstance(f, dict) and f.get("status"):
                    _probe_status = str(f["status"])
                if _probe_status == "CONFIRMED" and fid not in findings_validated:
                    findings_validated.append(fid)
                if isinstance(f, dict) and fid not in findings_validated_meta:
                    findings_validated_meta[fid] = dict(f)
                if _probe_status == "CONFIRMED" and isinstance(f, dict):
                    # v1.9.1: feed this confirmation into the
                    # tracker so Phase 3 + Phase A can dedupe
                    # against it. Phase B+ stores the candidate's
                    # function_name in the finding dict's
                    # ``code_snippet`` field (see
                    # findings_from_probes construction in
                    # _run_phase_b_runtime_probe — naming legacy
                    # carried from when probes shared the L1
                    # finding schema).
                    if coverage_tracker is not None:
                        coverage_tracker.add(
                            function=str(f.get("code_snippet") or ""),
                            attack_class=str(f.get("finding_type") or ""),
                            source="phase_b",
                            finding_id=str(fid),
                            cwe=str(f.get("cwe") or ""),
                            runtime_evidence=str(f.get("runtime_evidence") or "")[:500],
                        )

            # Fix #1 (verdict bump): a probe-CONFIRMED finding at
            # severity >= high is GROUNDED runtime evidence of a real
            # exploit. Bump the DAST max-verdict floor so the
            # iter-erosion guard (which clamps downgrades to within
            # ``max_dast_verdict_rank``) protects this signal against
            # later iterations downgrading.
            #
            # Safety: only bump UP, never down. Only by one tier max.
            # Only on high/critical severity. medium/low don't bump.
            # Critical+code-exec attack class → critical_malicious;
            # everything else high/critical → malicious.
            _CRITICAL_EXEC_CLASSES = {"code_injection", "command_injection", "deserialization"}
            for f in probe_findings:
                sev = (f.get("severity") or "").lower()
                if sev not in {"high", "critical"}:
                    continue
                if sev == "critical" and f.get("finding_type") in _CRITICAL_EXEC_CLASSES:
                    target_label = "critical_malicious"
                else:
                    target_label = "malicious"
                target_rank = _VERDICT_RANK.get(target_label, -1)
                if target_rank > max_dast_verdict_rank:
                    max_dast_verdict_rank = target_rank
                    max_dast_verdict_label = target_label
            # If the probe established a floor higher than the current
            # last_verdict, lift last_verdict to the floor so the
            # downstream verdict logic sees the probe-grounded evidence.
            current_rank = _VERDICT_RANK.get(str(last_verdict.get("verdict_label", "suspicious")), -1)
            if max_dast_verdict_rank > current_rank and max_dast_verdict_label:
                last_verdict["verdict_label"] = max_dast_verdict_label
                last_verdict["log_summary"] = (
                    f"runtime probe CONFIRMED {len([f for f in probe_findings if f.get('severity') in {'high', 'critical'}])} "
                    f"high/critical exploit(s); verdict raised to {max_dast_verdict_label}"
                )
        except Exception as exc:  # noqa: BLE001
            journal.append(
                JournalRecord(
                    iter=1,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id="HRP_ERROR",
                    verdict="rejected",
                    rationale=f"runtime probe stage failed: {type(exc).__name__}: {str(exc)[:240]}",
                    evidence_refs=[],
                )
            )

    # Placeholder for DAST-301 Phase D variant analysis — moved
    # AFTER the Phase A iter loop completes (line ~1207). See the
    # block tagged "DAST-301 Variant Analysis (v1 MVP)" below.
    variant_analysis_results: list[dict[str, Any]] = []

    # Phase 3 Stage 1 — Behavioral exploration probe. Runs after Phase B+
    # single-function and BEFORE Phase 2 chains so its profile can
    # eventually feed Stage 2's adversarial loop (when implemented).
    # For Phase 3 v1 (this commit), the probe runs and surfaces a
    # behavioral_profile in DastResult; it does NOT yet drive attack
    # design. That's Stage 2 work. This stage shipped early because the
    # profile is independently useful (visible in scan output even
    # without Stage 2).
    runtime_behavioral_profile_dict: dict[str, Any] | None = None
    if (
        enable_phase_3_discovery
        # Language gate. Stage 1 has harnesses for:
        #   * python (.py)               — v1.6
        #   * javascript (.js/.mjs/.cjs) — v1.8 JS DAST parity
        #   * typescript (.ts/.tsx)      — v9 (2026-05-16), reuses the
        #     JS harness via ts-node ESM loader (see
        #     ``dast.behavioral_probe._build_javascript_behavioral_probe_script``
        #     and the typescript branch of ``build_behavioral_probe_plan``).
        # The probe helper (``run_phase_3_behavioral_probe``) dispatches
        # to the language-specific harness internally and returns None
        # for unsupported languages — orchestrator code below already
        # tolerates None (Stage 2 gates on ``profile is not None``).
        and _probe_lang in ("python", "javascript", "typescript")
        and isinstance(file_record.get("original_bytes"), (bytes, bytearray))
    ):
        if probe_pre_init_stats is None:
            probe_pre_init_stats = IterationStats(iter=1)
            iterations.append(probe_pre_init_stats)
        try:
            runtime_behavioral_profile_dict = await _run_phase_3_behavioral_probe(
                file_record=file_record,
                journal=journal,
                sandbox=sandbox,
                iter_num=1,
                stats=probe_pre_init_stats,
                enable_per_scan_dep_install=enable_per_scan_dep_install,
            )
        except Exception as exc:  # noqa: BLE001
            journal.append(
                JournalRecord(
                    iter=1,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id="BP_ERROR",
                    verdict="rejected",
                    rationale=(f"behavioral probe stage failed: {type(exc).__name__}: {str(exc)[:240]}"),
                    evidence_refs=[],
                )
            )

    # Phase 3 Stage 2 — Adversarial reasoning loop. Runs AFTER Stage 1
    # (it consumes the behavioral profile) and BEFORE Phase 2 chains
    # so that Stage 2's stateful_sequence kind can land first when both
    # are enabled. Independent flag from Stage 1: the loop only runs
    # when ``enable_phase_3_loop=True`` AND Stage 1 produced a usable
    # profile. Python-only at v1.6 MVP.
    #
    # Default max_turns=1 — measured to close 4/5 vuln gap on the
    # thin-slice regression (commit 7d42813). Multi-turn refinement
    # is a future opt-in if production data shows the need.
    #
    # Findings flow into ``findings_validated`` (same shape as Phase 2
    # chains at line 419-422 below) so the engine surfaces them in
    # ``ScanResult.dast_findings``. The summary populates
    # ``DastResult.phase_3_loop`` for the verdict resolver (follow-on).
    phase_3_loop_summary: dict[str, Any] | None = None
    if (
        enable_phase_3_loop
        and runtime_behavioral_profile_dict is not None
        # Language gate — same set as Stage 1 above:
        # python (.py) + javascript (.js/.mjs/.cjs) + typescript (.ts/.tsx, v9).
        # The ``runtime_behavioral_profile_dict is not None`` guard above
        # already protects us — Stage 2 only fires when Stage 1 produced
        # a profile, so scans without a matching harness in Stage 1 stay
        # no-op'd here.
        and _probe_lang in ("python", "javascript", "typescript")
        and isinstance(file_record.get("original_bytes"), (bytes, bytearray))
    ):
        from dast.adversarial_loop_runner import run_adversarial_loop  # noqa: PLC0415

        if probe_pre_init_stats is None:
            probe_pre_init_stats = IterationStats(iter=1)
            iterations.append(probe_pre_init_stats)
        try:
            # v12 (2026-05-17): use phase_3_inference (Opus 4.6 in
            # production) for the adversarial loop's hypothesis
            # generation. Sonnet stays on L1 / Phase A / Phase B+ —
            # Opus is reserved for the novel attack-design step
            # where reasoning quality drives zero-day catch rate.
            # Falls back to the main inference when phase_3_inference
            # is None (back-compat / tests / users passing a custom
            # single inference).
            stage_2_inference = phase_3_inference or inference
            loop_result = await run_adversarial_loop(
                file_name=file_record.get("file_name") or "module.py",
                file_bytes=bytes(file_record["original_bytes"]),
                file_id=file_record.get("file_id", ""),
                behavioral_profile=runtime_behavioral_profile_dict,
                inference=stage_2_inference,
                sandbox=sandbox,
                max_turns=phase_3_loop_max_turns,
                entry_rel_path=file_record.get("entry_rel_path", ""),
                coverage_tracker=coverage_tracker,
            )

            # v15.17 (2026-05-20): adaptive borderline re-prompt.
            # When Opus declines to design hypotheses on turn 1 ("library
            # trust boundary, no attack surface") BUT Phase B+ already
            # surfaced confirmed exploits in this file, that's an
            # internal disagreement the resolver can't break alone — the
            # safe call is to force a second turn with explicit framing:
            # name the existing findings and ask the model to either
            # refute them in the sandbox or design adversarial inputs
            # that demonstrate exploitability. Cost: ~$0.05-0.10 extra
            # on borderline files only (turn 1's 0-hyp finding is the
            # gate; non-borderline files never trigger this).
            borderline_reinvocation: dict[str, Any] | None = None
            if (
                loop_result.hypotheses_total == 0
                and phase_3_loop_max_turns < 2
                and (runtime_behavioral_profile_dict or {}).get("callables_explored", 0)
                # Only re-prompt when Phase B+ already produced confirmed
                # exploit evidence in this file. Use findings_validated
                # (CONFIRMED-only, post-v15.17) so UNREACHED diagnostics
                # don't trigger spurious re-prompts.
                and any(fid.startswith("HRP_") and not fid.startswith("HRP_AL_") for fid in findings_validated)
            ):
                _b_plus_ids = [
                    fid for fid in findings_validated if fid.startswith("HRP_") and not fid.startswith("HRP_AL_")
                ]
                _b_plus_meta_lines = []
                for _fid in _b_plus_ids[:6]:
                    _m = findings_validated_meta.get(_fid) or {}
                    _b_plus_meta_lines.append(
                        f"- {_fid} ({_m.get('cwe') or '?'}, "
                        f"{_m.get('severity') or '?'}): "
                        f"{_m.get('code_snippet') or '?'} — "
                        f"{(_m.get('explanation') or '')[:120]}"
                    )
                _addendum = (
                    "Phase B+ already surfaced confirmed runtime evidence "
                    f"in this file ({len(_b_plus_ids)} findings). You "
                    "previously declined to design hypotheses on the "
                    "library-trust-boundary classification. That call may "
                    "be correct, but Phase B+'s evidence contradicts it. "
                    "Reconsider deliberately: for each finding below, "
                    "either (a) design a sandbox test input that refutes "
                    "the exploit claim explicitly, or (b) design an "
                    "adversarial input that demonstrates the exploit "
                    "fires under realistic conditions. Returning 0 "
                    "hypotheses again is acceptable ONLY if you can "
                    "articulate per-finding why each Phase B+ confirmation "
                    "is a false positive.\n\n"
                    "Phase B+ findings:\n" + "\n".join(_b_plus_meta_lines)
                )
                _reprompt = await run_adversarial_loop(
                    file_name=file_record.get("file_name") or "module.py",
                    file_bytes=bytes(file_record["original_bytes"]),
                    file_id=file_record.get("file_id", ""),
                    behavioral_profile=runtime_behavioral_profile_dict,
                    inference=stage_2_inference,
                    sandbox=sandbox,
                    max_turns=2,
                    entry_rel_path=file_record.get("entry_rel_path", ""),
                    coverage_tracker=coverage_tracker,
                    adversarial_addendum=_addendum,
                )
                borderline_reinvocation = {
                    "triggered": True,
                    "trigger_reason": "turn1_0hyp_with_phase_b_plus_evidence",
                    "phase_b_plus_finding_count": len(_b_plus_ids),
                    "reinvocation_max_turns": 2,
                    "reinvocation_turns_executed": len(_reprompt.turns),
                    "reinvocation_terminated_by": _reprompt.terminated_by,
                    "reinvocation_hypotheses_total": _reprompt.hypotheses_total,
                    "reinvocation_hypotheses_confirmed": _reprompt.hypotheses_confirmed,
                    "reinvocation_hypotheses_refuted": _reprompt.hypotheses_refuted,
                    "reinvocation_cost_usd": _reprompt.total_cost_usd,
                }
                # If the re-prompt produced hypotheses, the re-prompt
                # result becomes canonical (it's strictly more informed
                # than the initial 0-hyp turn). If it ALSO returned 0,
                # the initial result stays canonical but we record the
                # re-prompt diagnostic so operators see the deliberation.
                if _reprompt.hypotheses_total > 0:
                    loop_result = _reprompt
            # Full per-outcome serialization so downstream consumers
            # (verdict resolver + FN debugging + Step 9 analysis) can
            # inspect the raw hypothesis the model designed, not just
            # the confirmed findings. ``dataclasses.asdict`` recurses
            # into the nested ``hypothesis`` field so rationale,
            # function_name, args_json, kwargs_json, and sequence are
            # all visible.
            import dataclasses as _dc  # noqa: PLC0415

            all_outcomes = [_dc.asdict(o) for t in loop_result.turns for o in t.outcomes]
            # Stage 1 introspection count propagated to the resolver so
            # it can detect "model designed hypotheses blind from static
            # reading" cases. When Stage 1 enumerated no callables, the
            # model has no behavioral profile to anchor on -- sandbox
            # refutations of its guesses are not reliable enough to
            # override an L1 'malicious' verdict. See the 23-file
            # measurement (commit fd5be0e) for the regression evidence.
            callables_explored = int((runtime_behavioral_profile_dict or {}).get("callables_explored", 0) or 0)
            # v15.8 (2026-05-20): surface the model's code_intent_analysis
            # from each turn so the scan JSON carries the rationale for
            # any hypotheses_total=0 outcome. Gap 2: shopify-api +
            # homebridge came back with 0 hypotheses and no signal for
            # WHY — capturing the intent analysis turns silent "Stage 2
            # declined" into diagnosable ("declined because file is a
            # generic library with no attacker-controlled flow"). When
            # multiple turns ran, the LAST turn's analysis is the most
            # informative (model refined understanding across turns);
            # all turns are kept so operators can audit progression.
            turns_intent = [
                t.code_intent_analysis
                for t in loop_result.turns
                if getattr(t, "code_intent_analysis", None) is not None
            ]
            phase_3_loop_summary = {
                "ran": True,
                "max_turns": phase_3_loop_max_turns,
                "turns_executed": len(loop_result.turns),
                "terminated_by": loop_result.terminated_by,
                "hypotheses_total": loop_result.hypotheses_total,
                "hypotheses_confirmed": loop_result.hypotheses_confirmed,
                "hypotheses_refuted": loop_result.hypotheses_refuted,
                "hypotheses_blocked": loop_result.hypotheses_blocked,
                "probe_observed_count": loop_result.explore_calls_used,
                "coverage_ratio": loop_result.coverage_ratio,
                "stage_1_callables_explored": callables_explored,
                "cost_usd": loop_result.total_cost_usd,
                "tokens_in": loop_result.inference_tokens_in,
                "tokens_out": loop_result.inference_tokens_out,
                "elapsed_ms": loop_result.total_elapsed_ms,
                "findings": list(loop_result.findings),
                "outcomes": all_outcomes,
                "code_intent_analysis_per_turn": turns_intent,
                # v15.17 (2026-05-20): borderline-reinvocation diagnostic.
                # Populated only when the orchestrator detected the
                # "turn-1 declined despite Phase B+ evidence" pattern
                # and re-invoked the loop with an adversarial addendum.
                # See orchestrator.py around line 925 for the trigger
                # logic. ``None`` on non-borderline files.
                "borderline_reinvocation": borderline_reinvocation,
            }
            # Surface findings the same way Phase 2 chains do (line 419-422
            # below). Each adversarial-loop finding's finding_ref is
            # ``HRP_AL_T<turn>_H<hyp>`` — distinct namespace from chain
            # IDs so journal lookups remain unambiguous.
            #
            # v1.9: stash full dict in findings_validated_meta so
            # per_finding_validation can render a row with PoC +
            # runtime evidence for this DAST-discovered finding.
            # v1.9.1: also feed back into the coverage tracker so
            # Phase A / Phase B chains can dedupe against Phase 3
            # confirmations.
            for f in loop_result.findings:
                fid = f.get("finding_ref")
                if fid and fid not in findings_validated:
                    findings_validated.append(fid)
                    if isinstance(f, dict):
                        findings_validated_meta[fid] = dict(f)
                        if coverage_tracker is not None:
                            coverage_tracker.add(
                                function=str(f.get("function_name") or f.get("code_snippet") or ""),
                                attack_class=str(f.get("attack_class") or f.get("finding_type") or ""),
                                source="phase_3",
                                finding_id=str(fid),
                                cwe=str(f.get("cwe") or ""),
                                runtime_evidence=str(f.get("runtime_evidence") or "")[:500],
                            )
            # Roll inference tokens into the iter-1 stats record so the
            # cost cap stays accurate. Sandbox calls are already counted
            # by sandbox.submit() going through the existing stats path
            # in the per-hypothesis dispatchers.
            probe_pre_init_stats.phase_b_runtime_probe_in += loop_result.inference_tokens_in
            probe_pre_init_stats.phase_b_runtime_probe_out += loop_result.inference_tokens_out
            journal.append(
                JournalRecord(
                    iter=1,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id="HRP_AL_LOOP",
                    verdict=("confirmed" if loop_result.hypotheses_confirmed > 0 else "inconclusive"),
                    rationale=(
                        f"adversarial loop: {loop_result.hypotheses_total} "
                        f"hypotheses, {loop_result.hypotheses_confirmed} "
                        f"confirmed, {loop_result.hypotheses_refuted} "
                        f"refuted, {loop_result.hypotheses_blocked} blocked"
                    ),
                    evidence_refs=[],
                )
            )
        except Exception as exc:  # noqa: BLE001
            phase_3_loop_summary = {
                "ran": False,
                "error": f"{type(exc).__name__}: {str(exc)[:240]}",
            }
            journal.append(
                JournalRecord(
                    iter=1,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id="HRP_AL_ERROR",
                    verdict="rejected",
                    rationale=(f"adversarial loop stage failed: {type(exc).__name__}: {str(exc)[:240]}"),
                    evidence_refs=[],
                )
            )

    # Phase 2 — Cross-function exploit chains. Runs as a SEPARATE stage
    # after single-function probing because (a) it uses a different
    # prompt + schema (chain-shaped output, not candidate-shaped),
    # (b) chains are Python-only in v1.6 MVP while single-function
    # probing supports Python/JS/shell, and (c) chain findings flow
    # under their own ``HRP_C<n>`` namespace so journal lookups + report
    # rendering can render them distinctly.
    #
    # Reuses the iter-1 stats record created by the single-function
    # stage so chain inference + sandbox tokens roll into the same iter
    # accounting (cost cap stays accurate). If the single-function stage
    # didn't pre-init stats (e.g., non-probable language), create the
    # iter-1 stats record now.
    if (
        enable_runtime_probe_chains
        # Language gate. Chain plan builder dispatches by language
        # internally and handles:
        #   python (.py) + javascript (.js/.mjs/.cjs) + typescript
        #   (.ts/.tsx, v9 — reuses JS chain harness via ts-node loader).
        and _probe_lang in ("python", "javascript", "typescript")
        and isinstance(file_record.get("original_bytes"), (bytes, bytearray))
    ):
        if probe_pre_init_stats is None:
            probe_pre_init_stats = IterationStats(iter=1)
            iterations.append(probe_pre_init_stats)
        try:
            chain_findings = await _run_phase_b_runtime_probe_chains(
                file_record=file_record,
                l1_output=l1_output,
                journal=journal,
                journal_summary=journal.summarize(up_to_iter=0),
                inference=inference,
                sandbox=sandbox,
                iter_num=1,
                stats=probe_pre_init_stats,
                enable_per_scan_dep_install=enable_per_scan_dep_install,
            )
            # Surface chain findings the same way single-function findings
            # surface: into findings_validated → engine.ScanResult.dast_findings.
            #
            # v1.9: stash full dict in findings_validated_meta so
            # per_finding_validation can render a row with chain
            # evidence (steps, final_impact, MITRE attack) for this
            # DAST-discovered finding.
            for f in chain_findings:
                fid = f.get("finding_ref")
                if fid and fid not in findings_validated:
                    findings_validated.append(fid)
                    if isinstance(f, dict):
                        findings_validated_meta[fid] = dict(f)

            # Apply the same verdict-bump rule as single-function chains
            # — confirmed chain at severity >= high is grounded runtime
            # evidence; lift the DAST max-verdict floor.
            critical_exec_chain_classes = {
                "code_injection",
                "command_injection",
                "deserialization",
            }
            for f in chain_findings:
                sev = (f.get("severity") or "").lower()
                if sev not in {"high", "critical"}:
                    continue
                if sev == "critical" and f.get("finding_type") in critical_exec_chain_classes:
                    target_label = "critical_malicious"
                else:
                    target_label = "malicious"
                target_rank = _VERDICT_RANK.get(target_label, -1)
                if target_rank > max_dast_verdict_rank:
                    max_dast_verdict_rank = target_rank
                    max_dast_verdict_label = target_label
            current_rank = _VERDICT_RANK.get(str(last_verdict.get("verdict_label", "suspicious")), -1)
            if max_dast_verdict_rank > current_rank and max_dast_verdict_label:
                last_verdict["verdict_label"] = max_dast_verdict_label
                high_crit = [f for f in chain_findings if f.get("severity") in {"high", "critical"}]
                last_verdict["log_summary"] = (
                    f"runtime probe chain CONFIRMED {len(high_crit)} "
                    f"high/critical exploit chain(s); "
                    f"verdict raised to {max_dast_verdict_label}"
                )
        except Exception as exc:  # noqa: BLE001
            journal.append(
                JournalRecord(
                    iter=1,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id="HRP_C_ERROR",
                    verdict="rejected",
                    rationale=(f"runtime probe chain stage failed: {type(exc).__name__}: {str(exc)[:240]}"),
                    evidence_refs=[],
                )
            )

    # v1.9.1 — Phase A skip-on-covered. For each L1 hypothesis whose
    # (function, attack_class) is ALREADY covered by a Phase B+ or
    # Phase 3 runtime confirmation in the tracker, write a synthetic
    # ``confirmed`` journal record citing the upstream finding's
    # evidence + add the L1 finding_ref to ``findings_validated``,
    # then DROP the hypothesis from ``pending_hypotheses`` so Phase A
    # doesn't waste a sandbox call re-proving it.
    #
    # Without this, Phase A's harness builder runs against L1
    # hypotheses already proven by Phase B+'s canary-file oracle,
    # paying for the sandbox call even when the result is foregone.
    # In failure modes where Phase A's specific harness pattern
    # doesn't fire but Phase B+ DID confirm, the user previously
    # saw a confusing ``H001: NOT_TESTED`` next to ``HRP_0_0:
    # CONFIRMED`` — same exploit, contradictory statuses. The
    # synthetic journal record fixes that: per_finding_validation
    # now shows ``H001: CONFIRMED via HRP_0_0 runtime evidence``.
    if coverage_tracker is not None and coverage_tracker.enabled and pending_hypotheses:
        from dast.coverage_tracker import _extract_function_name  # noqa: PLC0415

        kept_hypotheses: list[dict] = []
        for hyp in pending_hypotheses:
            attack_class = str(hyp.get("finding_type") or hyp.get("type") or "")
            func_name = _extract_function_name(hyp)
            if not func_name or not attack_class:
                kept_hypotheses.append(hyp)
                continue
            covered = coverage_tracker.is_covered(function=func_name, attack_class=attack_class)
            if covered is None or covered.source == "l1":
                # Not covered, OR covered only by L1 itself (which is
                # what Phase A is supposed to verify) — process normally.
                kept_hypotheses.append(hyp)
                continue
            # Covered by a B+/3 runtime confirmation. Synthesize a
            # confirmed journal entry citing the upstream finding.
            fref = hyp.get("finding_ref") or hyp.get("id") or ""
            rationale = (
                f"Phase A skipped: (function={func_name}, "
                f"attack_class={attack_class}) already runtime-confirmed "
                f"by {covered.source} finding {covered.finding_id}. "
                f"Evidence: {covered.runtime_evidence[:200]}"
            )
            journal.append(
                JournalRecord(
                    iter=1,
                    phase=JournalPhase.PHASE_A_VERDICT,
                    claim_id=str(hyp.get("id") or fref),
                    verdict="confirmed",
                    rationale=rationale,
                    evidence_refs=[covered.finding_id] if covered.finding_id else [],
                )
            )
            if fref and fref not in findings_validated:
                findings_validated.append(fref)
            coverage_tracker.record_suppression("phase_a")
        pending_hypotheses = kept_hypotheses

    for it in range(1, MAX_ITERATIONS + 1):
        it_started = time.time()
        # Fix #4 ordering: when the v1.5 probe stage pre-created iter-1
        # stats, reuse that record so probe token usage isn't orphaned.
        # All later iters create fresh stats normally.
        if it == 1 and probe_pre_init_stats is not None:
            st = probe_pre_init_stats
        else:
            st = IterationStats(iter=it)
            iterations.append(st)

        prior_summary = journal.summarize(up_to_iter=it - 1)
        st.journal_input_tokens = prior_summary.token_count

        if not pending_hypotheses:
            stop_reason = "no_pending_hypotheses_for_iter"
            st.elapsed_s = round(time.time() - it_started, 2)
            break

        # ---- Phase A — Plan ------------------------------------------
        # For iter 1 the pending pool IS the L1 hypotheses (already in
        # l1_output). For iter ≥ 2 the pool is the Phase B hypotheses
        # accepted by the validator in iter N-1 — we replace l1_output's
        # ``hypotheses`` block so the prompt sees only the new pool and
        # the model doesn't re-plan already-verdicted L1 claims.
        if it == 1:
            l1_output_for_plan = l1_output
            pending_for_kwarg = None
        else:
            l1_output_for_plan = {**l1_output, "hypotheses": pending_hypotheses}
            pending_for_kwarg = pending_hypotheses
        plan_prompt = dast_prompts.build_phase_a_plan_prompt(
            file_text=source_text,
            l1_output=l1_output_for_plan,
            journal_summary=prior_summary.to_dict(),
            pending_hypotheses=pending_for_kwarg,
        )
        plan_resp = await infer_with_schema_retry(
            inference,
            plan_prompt,
            {"temperature": 0.0, "max_tokens": 6144, "seed": 0},
            dast_prompts.phase_a_plan_schema(),
        )
        st.phase_a_plan_in = (plan_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
        st.phase_a_plan_out = (plan_resp.get("usage") or {}).get("completion_tokens", 0) or 0
        st.finish_reasons["plan"] = plan_resp.get("finish_reason") or "?"
        if plan_resp.get("_schema_retry_attempted"):
            st.phase_a_schema_validation_retries += 1
            if not plan_resp.get("_schema_retry_succeeded"):
                st.phase_a_schema_validation_failed += 1
                journal.append(
                    JournalRecord(
                        iter=it,
                        phase=JournalPhase.PHASE_A_SCHEMA_INVALID,
                        claim_id="phase_a_plan",
                        verdict=None,
                        rationale=(
                            "Phase A plan tool_use response failed schema "
                            "validation after retry: "
                            + (plan_resp.get("_schema_retry_error") or plan_resp.get("schema_error") or "")
                        )[:300],
                        evidence_refs=[],
                    )
                )
        plans_obj = _parse_json_or_empty(plan_resp.get("text", ""))
        plans = (plans_obj.get("plans") or []) if isinstance(plans_obj, dict) else []

        # v1.9.2: planner antipattern validator + one-shot retry.
        # See _detect_planner_antipatterns docstring for rationale —
        # catches Phase A LLM regressions on $MODULE_NAME / $ENTRY_REL_PATH
        # usage that would otherwise mask real exploits as NOT_TESTED at
        # sandbox runtime. Bounded cost: one extra inference call per
        # iteration (~$0.03-0.05) if any plan trips the gate.
        _entry_rel_path = str(file_record.get("entry_rel_path") or "")
        _module_name = _derive_python_module_name(_entry_rel_path)
        findings_by_plan: dict[int, list[str]] = {}
        for idx, p in enumerate(plans):
            if not isinstance(p, dict):
                continue
            cmds = p.get("commands") or []
            issues = _detect_planner_antipatterns(
                cmds,
                file_name=file_name,
                entry_rel_path=_entry_rel_path,
                module_name=_module_name,
            )
            if issues:
                findings_by_plan[idx] = issues

        if findings_by_plan:
            n_bad = len(findings_by_plan)
            n_total = len(plans)
            logging.getLogger("argus.dast.orchestrator").info(
                "Phase A planner antipattern detected: %d/%d plans need correction; "
                "calling inference once more with correction appendix",
                n_bad,
                n_total,
            )
            journal.append(
                JournalRecord(
                    iter=it,
                    phase=JournalPhase.PHASE_A_PLAN,
                    claim_id="phase_a_antipattern",
                    verdict=None,
                    rationale=(
                        f"Planner emitted {n_bad}/{n_total} plans with "
                        f"flat-file antipatterns despite the HARD CHECKLIST. "
                        f"Re-calling inference with correction appendix. "
                        f"First issue: {next(iter(findings_by_plan.values()))[0]}"
                    )[:600],
                    evidence_refs=[],
                )
            )

            correction = _build_planner_correction_appendix(
                plans=plans,
                file_name=file_name,
                entry_rel_path=_entry_rel_path,
                module_name=_module_name,
                findings_by_plan=findings_by_plan,
            )
            corrected_prompt = plan_prompt + "\n" + correction
            try:
                retry_resp = await infer_with_schema_retry(
                    inference,
                    corrected_prompt,
                    {"temperature": 0.0, "max_tokens": 6144, "seed": 0},
                    dast_prompts.phase_a_plan_schema(),
                )
                retry_obj = _parse_json_or_empty(retry_resp.get("text", ""))
                retry_plans = (retry_obj.get("plans") or []) if isinstance(retry_obj, dict) else []
                if retry_plans:
                    # Validate the corrected plans too; if STILL bad,
                    # accept anyway (one-shot retry; further retries
                    # would unbound the cost).
                    remaining: dict[int, list[str]] = {}
                    for ridx, rp in enumerate(retry_plans):
                        if not isinstance(rp, dict):
                            continue
                        rissues = _detect_planner_antipatterns(
                            rp.get("commands") or [],
                            file_name=file_name,
                            entry_rel_path=_entry_rel_path,
                            module_name=_module_name,
                        )
                        if rissues:
                            remaining[ridx] = rissues
                    if remaining:
                        logging.getLogger("argus.dast.orchestrator").warning(
                            "Phase A planner antipattern persisted after "
                            "retry on %d/%d plans; accepting anyway "
                            "(one-shot retry exhausted). Affected plans "
                            "will likely come back NOT_TESTED.",
                            len(remaining),
                            len(retry_plans),
                        )
                    plans = retry_plans
                    # Track usage for cost accounting.
                    st.phase_a_plan_in += (retry_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
                    st.phase_a_plan_out += (retry_resp.get("usage") or {}).get("completion_tokens", 0) or 0
                else:
                    logging.getLogger("argus.dast.orchestrator").warning(
                        "Phase A planner antipattern retry returned empty "
                        "plans list; keeping originals (will likely come "
                        "back NOT_TESTED)."
                    )
            except Exception as exc:  # noqa: BLE001
                # Inference failures must never block the scan — fall
                # back to the original (tainted) plans. They'll come
                # back NOT_TESTED, but the rest of the iteration runs.
                logging.getLogger("argus.dast.orchestrator").warning(
                    "Phase A planner antipattern retry failed: %s; keeping original plans",
                    exc,
                )

        # ML-artifact deterministic detonation: when iter 1 starts on a
        # recognized model file (.pkl/.pt/.bin/.safetensors/.h5/.onnx),
        # we PREPEND a fixed load plan so the sandbox detonates the
        # artifact regardless of what the model-driven planner emits.
        # The plan template lives in dast.ml_detonation; it produces a
        # python-c oneliner that calls pickle.load / torch.load / etc.
        # — i.e., the canonical "load = execution" attack surface.
        if it == 1 and file_record.get("ml_format"):
            from dast.ml_detonation import build_ml_load_plan  # noqa: PLC0415

            ml_bytes = file_record.get("original_bytes")
            if isinstance(ml_bytes, (bytes, bytearray)):
                ml_plan = build_ml_load_plan(
                    file_name=file_name,
                    file_id=file_id,
                    hypothesis_id="HML_LOAD",
                    original_bytes=bytes(ml_bytes),
                )
                if ml_plan is not None:
                    plans = [ml_plan, *plans]

        # Cross-reference hypothesis_id → hypothesis dict so the stub
        # sandbox can resolve Phase B upstream context.
        hyp_index = {h.get("id"): h for h in pending_hypotheses}

        # ---- Sandbox ------------------------------------------------
        plan_records: list[dict] = []
        trace_records: list[dict] = []
        for p in plans:
            if not isinstance(p, dict):
                continue
            hid = p.get("hypothesis_id", "")
            if p.get("plan_status") != "executable":
                # Not_testable plans are journaled but no sandbox call.
                journal.append(
                    JournalRecord(
                        iter=it,
                        phase=JournalPhase.PHASE_A_PLAN,
                        claim_id=hid,
                        verdict=None,
                        rationale=f"not_testable: {p.get('rationale', '')[:200]}",
                        evidence_refs=[],
                        sandbox_event_id=None,
                    )
                )
                plan_records.append(p)
                continue
            # DAST-005: pass through image_hint. Default to "lean" (v1.8 P2b) so
            # plans from older planners (no field) and stub clients are
            # unaffected. MultiImageSandboxClient routes; single-image
            # clients ignore.
            raw_hint = p.get("image_hint")
            image_hint = raw_hint if isinstance(raw_hint, str) and raw_hint else "lean"
            # P2a v0.1: compute pip packages to install in sandbox.
            # Helper returns [] for lean tier / disabled flag / non-Python.
            # ``original_bytes`` is always populated by dast/runner.py
            # (line ~255) before orchestrator runs. Fall back to encoded
            # source_text if absent (defensive — should never trigger).
            from preprocessing.imports import runtime_packages_for_plan

            _file_bytes = file_record.get("original_bytes") or source_text.encode("utf-8", errors="replace")
            runtime_pkgs = runtime_packages_for_plan(
                file_bytes=_file_bytes,
                file_name=file_name,
                image_hint=image_hint,
                enabled=enable_per_scan_dep_install,
                # v15: pass project_root so the file's own distribution
                # (PKG-INFO Name) gets pre-installed alongside its
                # imported deps. Cuts the "circular __init__ + C
                # extension" failure mode where file-staged-only
                # imports can't satisfy the package's own init.
                project_root=file_record.get("project_root", "") or "",
            )
            # v15.10 (2026-05-20): own_dist_name is the manifest-declared
            # distribution name (PKG-INFO/pyproject.toml). When set, the
            # sandbox client routes the own_dist install into the
            # with-deps env var so its transitive dependencies (pygments
            # for readme-renderer, _vendor for rich_rst, etc.) actually
            # get installed. Cuts the ModuleNotFoundError on transitive
            # dep failure mode that v15.6's excepthook caught.
            from preprocessing.imports import _detect_distribution_name_for_install  # noqa: PLC0415

            _own_dist = _detect_distribution_name_for_install(file_record.get("project_root", "") or "") or ""
            plan = SandboxPlan(
                plan_id=f"i{it}-{hid}",
                file_id=file_id,
                hypothesis_id=hid,
                commands=p.get("commands") or [],
                expected_oracle=p.get("oracle") or "",
                payload=p.get("payload") or "",
                timeout_sec=int(p.get("timeout_sec") or 30),
                image_hint=image_hint,
                file_name=file_name,
                runtime_packages=runtime_pkgs,
                own_dist_name=_own_dist,
                synthesis_context={
                    "upstream_chain": (hyp_index.get(hid) or {}).get("upstream_chain") or {},
                    "hypothesis": hyp_index.get(hid) or {},
                },
            )
            try:
                trace: SandboxTrace = await sandbox.submit(plan)
            except Exception as e:
                trace = SandboxTrace(
                    plan_id=plan.plan_id,
                    file_id=plan.file_id,
                    hypothesis_id=plan.hypothesis_id,
                    events=[],
                    exit_code=None,
                    stdout_excerpt="",
                    stderr_excerpt=f"sandbox_error: {type(e).__name__}: {e}",
                    elapsed_ms=0,
                    is_stub_no_trace=True,
                    stub_synthesis_note=f"exception: {type(e).__name__}",
                )
            st.sandbox_calls += 1
            total_sb += 1
            plan_records.append(p)
            trace_records.append(trace.model_dump())
            # v15.8 (2026-05-20): include the sandbox stderr in the
            # journal rationale so per_finding_validation can surface
            # actual Python tracebacks (AttributeError, ImportError,
            # etc.) instead of relying on the Phase A verdict LLM's
            # interpretation. The LLM is known to hallucinate the
            # failure cause (ruamel-yaml H001 — judge wrote
            # 'No module named ruamel' when reality was a removed-API
            # AttributeError). Real stderr is authoritative.
            stderr_excerpt = (trace.stderr_excerpt or "").strip()
            stub_note = trace.stub_synthesis_note or ""
            if stderr_excerpt and stub_note:
                _journal_rationale = f"{stub_note} | stderr: {stderr_excerpt[:1500]}"
            elif stderr_excerpt:
                _journal_rationale = stderr_excerpt[:1500]
            else:
                _journal_rationale = stub_note
            journal.append(
                JournalRecord(
                    iter=it,
                    phase=JournalPhase.SANDBOX_EXEC,
                    claim_id=hid,
                    verdict=None,
                    rationale=_journal_rationale,
                    evidence_refs=[e.event_id for e in trace.events],
                    sandbox_event_id=(trace.events[0].event_id if trace.events else None),
                )
            )

        # v1.2: snapshot iter-1 plans for Phase C replay (fix-and-verify)
        if it == 1:
            iter1_plan_records = list(plan_records)

        # ---- Phase A — Verdict --------------------------------------
        verdict_prompt = dast_prompts.build_phase_a_verdict_prompt(
            file_text=source_text,
            l1_output=l1_output,
            plans=plan_records,
            traces=trace_records,
            journal_summary=prior_summary.to_dict(),
        )
        verdict_resp = await infer_with_schema_retry(
            inference,
            verdict_prompt,
            {"temperature": 0.0, "max_tokens": 6144, "seed": 0},
            dast_prompts.phase_a_verdict_schema(),
        )
        st.phase_a_verdict_in = (verdict_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
        st.phase_a_verdict_out = (verdict_resp.get("usage") or {}).get("completion_tokens", 0) or 0
        st.finish_reasons["verdict"] = verdict_resp.get("finish_reason") or "?"
        if verdict_resp.get("_schema_retry_attempted"):
            st.phase_a_schema_validation_retries += 1
            if not verdict_resp.get("_schema_retry_succeeded"):
                st.phase_a_schema_validation_failed += 1
                journal.append(
                    JournalRecord(
                        iter=it,
                        phase=JournalPhase.PHASE_A_SCHEMA_INVALID,
                        claim_id="phase_a_verdict",
                        verdict=None,
                        rationale=(
                            "Phase A verdict tool_use response failed schema "
                            "validation after retry: "
                            + (verdict_resp.get("_schema_retry_error") or verdict_resp.get("schema_error") or "")
                        )[:300],
                        evidence_refs=[],
                    )
                )
        verdict_obj = _parse_json_or_empty(verdict_resp.get("text", ""))
        claim_verdicts = (verdict_obj.get("claim_verdicts") or []) if isinstance(verdict_obj, dict) else []
        cur = (verdict_obj.get("current_verdict") or {}) if isinstance(verdict_obj, dict) else {}

        prev_confirmed = set(prior_summary.confirmed_findings)
        new_confirmed_count = 0
        # T19 precision: the REAL event IDs the sandbox produced this
        # iteration. A CONFIRMED verdict must cite at least one of these
        # (the prompt requires a runtime side-effect event for "confirmed");
        # checking it in code stops a confidently-wrong model fabricating a
        # confirmation off a non-existent event_id.
        iter_event_ids: set[str] = {
            str(ev.get("event_id")) for tr in trace_records for ev in (tr.get("events") or []) if ev.get("event_id")
        }
        for cv in claim_verdicts:
            if not isinstance(cv, dict):
                continue
            hid = cv.get("hypothesis_id", "")
            v = cv.get("verdict") or "inconclusive"
            ev_ids = cv.get("sandbox_event_ids") or []
            rationale = cv.get("rationale", "")[:300]
            # T19: downgrade an UNGROUNDED confirmation (cites no real
            # runtime event) to inconclusive. SAFE failure mode —
            # inconclusive keeps L1's verdict, never erases a finding.
            if v == "confirmed" and not _confirmation_is_grounded(ev_ids, iter_event_ids):
                _cited = [str(e) for e in ev_ids] if isinstance(ev_ids, list) else []
                v = "inconclusive"
                rationale = (
                    "[ungrounded_confirmation] downgraded confirmed->inconclusive: "
                    f"cited sandbox_event_ids {_cited or '[]'} not found in this "
                    "iteration's sandbox trace (no runtime side-effect evidence). " + rationale
                )[:300]
            evidence_refs: list[str] = []
            # If we can map back to a finding ID via the L1 hypothesis,
            # record it as a Finding in the journal.
            hyp = hyp_index.get(hid) or {}
            # L1 hypotheses use ``finding_ref``; Phase B hypotheses use
            # ``upstream_chain.confirmed_finding_ref``. Try both.
            fref = hyp.get("finding_ref") or ((hyp.get("upstream_chain") or {}).get("confirmed_finding_ref"))
            if fref:
                evidence_refs.append(fref)
            evidence_refs.extend(ev_ids if isinstance(ev_ids, list) else [])
            journal.append(
                JournalRecord(
                    iter=it,
                    phase=JournalPhase.PHASE_A_VERDICT,
                    claim_id=hid,
                    verdict=v,
                    rationale=rationale,
                    evidence_refs=evidence_refs,
                    sandbox_event_id=(ev_ids[0] if isinstance(ev_ids, list) and ev_ids else None),
                )
            )
            if v == "confirmed" and fref and fref not in prev_confirmed:
                new_confirmed_count += 1
                if fref not in findings_validated:
                    findings_validated.append(fref)
        st.new_confirmed_findings = new_confirmed_count

        if cur.get("verdict_label"):
            new_label = cur.get("verdict_label") or "suspicious"
            new_rank = _VERDICT_RANK.get(new_label, -1)

            # Phase 2b: iter-erosion guard. If a prior DAST iter reached
            # a higher verdict and this iter wants to downgrade WITHOUT
            # producing a sandbox-grounded refutation of a previously
            # confirmed finding, clamp the verdict back up. This blocks
            # the litellm_obfuscated-style erosion where iter 2's failed
            # re-confirmation (curl missing in image) was treated as
            # disconfirmation.
            # Truncate on ingest: the request schema no longer caps
            # log_summary length (so the model is never rejected for an
            # over-long log string), so bound it here for storage + to
            # satisfy the Verdict model's max_length.
            log_summary = (cur.get("log_summary") or "")[:_LOG_SUMMARY_MAX]
            if (
                max_dast_verdict_rank >= 0
                and new_rank < max_dast_verdict_rank
                and max_dast_verdict_label is not None
                and not _has_refutation_of_prior_confirmed(claim_verdicts, hyp_index, prev_confirmed)
            ):
                clamp_msg = (
                    f"[iter_erosion_guard] iter {it} model emitted "
                    f"'{new_label}' but no sandbox-grounded refutation of "
                    f"prior confirmed findings; clamped to prior max "
                    f"'{max_dast_verdict_label}'."
                )
                if log_summary:
                    clamp_msg = f"{clamp_msg} Original: {log_summary[:120]}"
                new_label = max_dast_verdict_label
                new_rank = max_dast_verdict_rank
                log_summary = clamp_msg
                st.iter_erosion_guard_fired = True

            last_verdict = {
                "verdict_label": new_label,
                "log_summary": log_summary,
                "validated_findings": list(cur.get("validated_findings") or []),
                "confirmed_categories": list(cur.get("confirmed_categories") or []),
            }
            st.current_verdict_label = new_label

            if new_rank > max_dast_verdict_rank:
                max_dast_verdict_rank = new_rank
                max_dast_verdict_label = new_label
        else:
            st.current_verdict_label = last_verdict.get("verdict_label", "suspicious")

        # Phase B+ runtime probing already ran ONCE before the iter loop
        # (see ``_run_phase_b_runtime_probe`` call above the for-loop).
        # Its findings — if any — were appended to ``l1_output`` /
        # ``pending_hypotheses`` and have already been planned + verified
        # by Phase A this iter. No per-iter probe call.

        # ---- Phase B — Exploration ----------------------------------
        # Re-summarize the journal so the explore prompt sees the *just-
        # written* iteration's evidence.
        live_summary = journal.summarize(up_to_iter=it)
        explore_prompt = dast_prompts.build_phase_b_prompt(
            file_text=source_text,
            l1_output=l1_output,
            journal_summary=live_summary.to_dict(),
        )
        explore_resp = await inference(
            explore_prompt,
            {"temperature": 0.0, "max_tokens": 6144, "seed": 0},
            dast_prompts.phase_b_schema(),
        )
        st.phase_b_in = (explore_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
        st.phase_b_out = (explore_resp.get("usage") or {}).get("completion_tokens", 0) or 0
        st.finish_reasons["explore"] = explore_resp.get("finish_reason") or "?"
        explore_obj = _parse_json_or_empty(explore_resp.get("text", ""))
        new_hyps = (explore_obj.get("new_hypotheses") or []) if isinstance(explore_obj, dict) else []
        st.hypotheses_proposed = len(new_hyps)

        # Validator gate
        accepted_hyps: list[dict] = []
        rejected_hyps: list[dict] = []
        l1_findings_for_validator = list(l1_output.get("findings") or [])
        for h in new_hyps:
            if not isinstance(h, dict):
                continue
            v = validator.validate(h, l1_findings_for_validator, live_summary)
            hid = h.get("id") or "H???"
            if v.accepted:
                accepted_hyps.append(h)
                journal.append(
                    JournalRecord(
                        iter=it,
                        phase=JournalPhase.PHASE_B_HYPOTHESIS,
                        claim_id=hid,
                        verdict="confirmed" if v.is_borderline else "confirmed",
                        rationale=f"validator accepted{' (borderline)' if v.is_borderline else ''}: {v.reasoning[:240]}",
                        evidence_refs=[],
                    )
                )
            else:
                rejected_hyps.append(h)
                journal.append(
                    JournalRecord(
                        iter=it,
                        phase=JournalPhase.PHASE_B_HYPOTHESIS,
                        claim_id=hid,
                        verdict="rejected",
                        rationale=f"validator rejected: {v.reasoning[:240]}",
                        evidence_refs=[],
                    )
                )
        st.hypotheses_accepted = len(accepted_hyps)
        st.hypotheses_rejected = len(rejected_hyps)

        # Per-iteration totals
        iter_in = (
            st.phase_a_plan_in
            + st.phase_a_verdict_in
            + st.phase_b_in
            # v1.5 Fix #4: include probe inference tokens in the iter
            # roll-up so they reach total_tokens_in → DAST cost → install
            # path's aggregate cost cap.
            + st.phase_b_runtime_probe_in
        )
        iter_out = st.phase_a_plan_out + st.phase_a_verdict_out + st.phase_b_out + st.phase_b_runtime_probe_out
        total_in += iter_in
        total_out += iter_out
        st.elapsed_s = round(time.time() - it_started, 2)

        # Token-cap check
        if total_in + total_out > TOKEN_CAP_PER_FILE:
            stop_reason = "token_cap"
            break

        # SCAN-007 in-flight cost cap — stop the validation loop once the
        # (conservative) DAST spend estimate reaches the per-file budget.
        if max_cost_usd is not None and _dast_cost_estimate_usd(total_in, total_out) >= max_cost_usd:
            stop_reason = "cost_cap"
            break

        # Stop-condition checks for next iter (OR semantics per spec —
        # whichever fires first ends the loop)
        if new_confirmed_count == 0:
            stop_reason = "no_new_confirmed_findings"
            break
        if st.hypotheses_accepted == 0:
            stop_reason = "no_valid_hypotheses_remaining"
            break
        if it == MAX_ITERATIONS:
            stop_reason = "max_iter"
            break

        # Hand-off to next iteration: pending hypotheses are this iter's
        # validator-accepted Phase B output.
        pending_hypotheses = accepted_hyps

    # Snapshot the journal as a list of dicts so downstream consumers
    # (engine -> per_finding derivation) can classify rejected hypotheses
    # without having to re-read the file. JournalRecord is a Pydantic
    # model — model_dump() gives a JSON-serializable dict.
    try:
        journal_dump: list[dict[str, Any]] = [r.model_dump(mode="json") for r in journal.read_all()]
    except Exception:  # noqa: BLE001
        journal_dump = []

    # ──── Phase D — DAST-301 Variant Analysis (v1 MVP) ───────────────
    #
    # When Phase A has confirmed at least one finding, abstract the
    # seed exploit into a semantic signature, hunt for candidate
    # variants in the same file via AST, verify each variant via a
    # retargeted Phase A harness. Confirmed variants are unioned into
    # ``findings_validated`` so Phase C remediates them alongside
    # the seed.
    #
    # Feature-flagged off-by-default for v1 MVP. Cost-gated per seed
    # at $0.50. See ``docs/dast_301_variant_analysis.md`` for the
    # full pipeline + future v1.1 cross-file roadmap.
    if enable_phase_d and findings_validated:
        try:
            from dast.variant_runner import run_phase_d  # noqa: PLC0415
            from dataclasses import asdict as _asdict_pd  # noqa: PLC0415

            l1_findings_by_id: dict[str, dict[str, Any]] = {}
            for h in l1_output.get("hypotheses") or []:
                if isinstance(h, dict):
                    hid = h.get("id") or h.get("finding_ref")
                    if hid:
                        l1_findings_by_id[str(hid)] = h
            plan_records_by_hid: dict[str, dict[str, Any]] = {}
            for p in iter1_plan_records or []:
                if isinstance(p, dict):
                    phid = p.get("hypothesis_id")
                    if phid:
                        plan_records_by_hid[str(phid)] = p

            # Snapshot findings_validated BEFORE Phase D so we don't
            # iterate variants we just appended.
            seeds_for_phase_d = list(findings_validated)
            for seed_ref in seeds_for_phase_d:
                seed_hyp = l1_findings_by_id.get(seed_ref) or {}
                if not seed_hyp:
                    continue
                seed_pa: dict[str, Any] = {}
                for rec in journal_dump:
                    if (
                        rec.get("phase") == "phase_a_verdict"
                        and rec.get("claim_id") == seed_ref
                        and rec.get("verdict") == "confirmed"
                    ):
                        seed_pa = {
                            "proof_of_concept": rec.get("rationale", "")[:600],
                            "runtime_evidence": ", ".join(rec.get("evidence_refs") or [])[:400],
                        }
                        break
                seed_plan = plan_records_by_hid.get(seed_ref)
                file_record_for_d = {
                    "file_id": file_id,
                    "file_name": file_name,
                    "source_text": source_text,
                }
                try:
                    pd_result = await run_phase_d(
                        file_record=file_record_for_d,
                        seed_finding=seed_hyp,
                        seed_phase_a_validation=seed_pa,
                        seed_plan=seed_plan,
                        inference=phase_3_inference or inference,
                        sandbox=sandbox,
                        language=("python" if file_name.lower().endswith((".py", ".pth")) else "unsupported"),
                        # DAST-302 v1.1: pass project_root + entry_rel_path
                        # so Phase D builds the cross-file code graph.
                        # Both empty for single-file scans → Phase D falls
                        # back to same-file behavior.
                        project_root=file_record.get("project_root") or None,
                        entry_rel_path=file_record.get("entry_rel_path") or None,
                    )
                except Exception as exc:  # noqa: BLE001
                    journal.append(
                        JournalRecord(
                            iter=1,
                            phase=JournalPhase.PHASE_B_HYPOTHESIS,
                            claim_id=f"PhaseD-{seed_ref}",
                            verdict="rejected",
                            rationale=(f"Phase D variant analysis failed: {type(exc).__name__}: {str(exc)[:200]}"),
                            evidence_refs=[],
                        )
                    )
                    continue
                variant_analysis_results.append(_asdict_pd(pd_result))
                for vid in pd_result.confirmed_variant_ids:
                    if vid not in findings_validated:
                        findings_validated.append(vid)
        except Exception as exc:  # noqa: BLE001
            journal.append(
                JournalRecord(
                    iter=1,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id="PhaseD-ENTRY",
                    verdict="rejected",
                    rationale=(f"Phase D wiring failed: {type(exc).__name__}: {str(exc)[:200]}"),
                    evidence_refs=[],
                )
            )

    # ──── Phase C — Fix-and-verify (v1.2) ────────────────────────────
    # If DAST confirmed any L1 findings, generate a patch and re-test
    # the iter-1 plans against the patched source. Output: patched
    # source, post-patch verdict, per-finding NEUTRALIZED/STILL/UNVERIFIABLE.
    #
    # Trigger gate (v1.2.1): orchestrator's `findings_validated` only
    # captures hypotheses where claim_verdict="confirmed" AND finding_ref
    # was tied back to an L1 finding. The journal often contains broader
    # CONFIRMED evidence (sandbox events showing the exploit fired) that
    # didn't get tied via finding_ref. Phase C should fire on either —
    # so we union findings_validated with journal-derived confirmations.
    phase_c_findings: list[str] = list(findings_validated)
    for rec in journal_dump:
        if rec.get("phase") != "phase_a_verdict":
            continue
        if rec.get("verdict") != "confirmed":
            continue
        ev = rec.get("evidence_refs") or []
        if not (isinstance(ev, list) and ev):
            continue
        cid = rec.get("claim_id")
        if cid and cid not in phase_c_findings:
            phase_c_findings.append(cid)

    phase_c_result: dict[str, Any] | None = None
    if not enable_phase_c:
        # User opted out of remediation (compliance / CI gate / cost
        # control). ALWAYS surface the opt-out as a structured Phase C
        # marker — consumers parsing the report shouldn't have to infer
        # "is Phase C off, or did it run and find nothing to fix?" from
        # an absent field. ``n_confirmed_findings`` tells them what
        # WOULD have been remediated.
        phase_c_result = {
            "attempted": False,
            "skipped_reason": "phase_c_disabled_by_config",
            "n_confirmed_findings": len(phase_c_findings),
        }
    elif phase_c_findings and iter1_plan_records:
        # v14 Fix #1: build synthetic hypothesis dicts from DAST-
        # discovered findings (Phase 3 Stage 2, runtime_probe_chains,
        # Phase B+ probe) so Phase C's hyp_by_ref index can resolve
        # them. Without this, DAST findings were silently dropped
        # from ``confirmed`` and never patched.
        dast_findings_synthetic: list[dict[str, Any]] = []
        # Phase 3 Stage 2 outcomes — pull from phase_3_loop_summary if
        # present (Phase 3 v1.6+ contract).
        if phase_3_loop_summary and isinstance(phase_3_loop_summary, dict):
            for o in phase_3_loop_summary.get("outcomes") or []:
                if not isinstance(o, dict):
                    continue
                if str(o.get("verdict", "")).lower() != "confirmed":
                    continue
                hyp = o.get("hypothesis") or {}
                if not isinstance(hyp, dict):
                    continue
                # Synthesize a hyp-shaped dict for the patcher prompt.
                # finding_ref drives lookup; remaining fields feed the
                # build_phase_c_fix_prompt template.
                fref = (
                    o.get("finding_ref")
                    or hyp.get("finding_ref")
                    or hyp.get("id")
                    or f"P3-{hyp.get('function_name', 'anon')}"
                )
                dast_findings_synthetic.append(
                    {
                        "id": fref,
                        "finding_ref": fref,
                        "type": hyp.get("attack_class") or "unknown",
                        "severity": hyp.get("severity") or "high",
                        "description": (
                            hyp.get("rationale")
                            or hyp.get("description")
                            or f"Phase 3 Stage 2 runtime-confirmed {hyp.get('attack_class')} "
                            f"on {hyp.get('function_name')}"
                        ),
                        "fix": "",
                        "_source": "phase_3_stage_2",
                        "_function_name": hyp.get("function_name"),
                    }
                )
        # Phase 2 chains + Phase B+ probe findings — these were appended
        # to findings_validated earlier; their hyp dicts live in
        # findings_validated_meta (if the orchestrator persisted them).
        # For v14, we use a best-effort approach: any finding_ref in
        # phase_c_findings that's NOT in l1_output.hypotheses AND NOT
        # in dast_findings_synthetic so far gets a generic synthetic
        # hyp so the patcher at least sees the ref name.
        existing_refs = {h.get("id") for h in (l1_output.get("hypotheses") or [])}
        existing_refs |= {h.get("finding_ref") for h in (l1_output.get("hypotheses") or [])}
        existing_refs |= {f["finding_ref"] for f in dast_findings_synthetic}
        existing_refs.discard(None)
        for ref in phase_c_findings:
            if ref in existing_refs:
                continue
            dast_findings_synthetic.append(
                {
                    "id": ref,
                    "finding_ref": ref,
                    "type": "unknown",
                    "severity": "high",
                    "description": (
                        f"DAST-confirmed finding {ref} (Phase B+ probe or chain). "
                        f"Patcher should harden the file's general attack surface."
                    ),
                    "fix": "",
                    "_source": "phase_b_or_chain",
                }
            )
        try:
            # v15 verified-remediation attempt loop: generate → replay the
            # PoC → run functional + adversarial gates. If a gate FAILS
            # (shallow patch or broken functionality) and the severity
            # budget allows, regenerate the patch with the failure as
            # feedback and re-verify. Budget caps the retries per severity.
            attempt = 0
            prior_feedback: str | None = None
            phase_c_result = None
            prior_patch: str | None = None
            while True:
                # SCAN-007 — don't start (or retry) remediation once the
                # per-file budget is spent. Remediation + its gates are the
                # most expensive part of DAST, so this guard is the main
                # thing keeping a critical-severity file's verify+retry
                # loop from blowing past the cost ceiling.
                if max_cost_usd is not None and _dast_cost_estimate_usd(total_in, total_out) >= max_cost_usd:
                    if phase_c_result is None:
                        phase_c_result = {
                            "attempted": False,
                            "skipped_reason": "cost_cap",
                            "note": (
                                f"remediation skipped — DAST reached the ${max_cost_usd:.2f} per-file cost budget"
                            ),
                        }
                    break
                phase_c_result = await _run_phase_c_fix_verify(
                    file_record=file_record,
                    findings_validated=phase_c_findings,
                    l1_output=l1_output,
                    iter1_plans=iter1_plan_records,
                    inference=inference,
                    sandbox=sandbox,
                    journal=journal,
                    dast_findings=dast_findings_synthetic,
                    # v15 follow-on: ``dast_plans`` for sandbox replay of
                    # Stage 2 plans against the patched source. v14 leaves
                    # DAST findings as UNVERIFIABLE in the per_finding
                    # output rather than misclassifying as NEUTRALIZED.
                    dast_plans=None,
                    enable_verify_gates=enable_remediation_verify,
                    gate_inference=phase_3_inference or inference,
                    prior_feedback=prior_feedback,
                )
                if phase_c_result:
                    total_in += phase_c_result.get("tokens_in", 0)
                    total_out += phase_c_result.get("tokens_out", 0)
                    total_sb += phase_c_result.get("n_replays", 0)
                # Retry stuck-state guard: a regeneration byte-identical to
                # the PRIOR attempt means the feedback isn't moving the model
                # — stop retrying so we don't re-burn the full gate + token
                # cost on the same patch. (The byte-identical check inside
                # _run_phase_c_fix_verify only compares against the ORIGINAL
                # source, not the previous attempt, so this is a distinct
                # guard. Patch generation runs at temp=0/seed=0, so a
                # non-moving model would otherwise loop to the retry cap.)
                new_patch = (phase_c_result or {}).get("patched_source") or ""
                if attempt > 0 and new_patch and new_patch == prior_patch:
                    if isinstance(phase_c_result, dict):
                        phase_c_result["retry_stuck"] = True
                    break
                prior_patch = new_patch
                ver = (phase_c_result or {}).get("verification") or {}
                max_retries = int((ver.get("budget") or {}).get("retries", 0) or 0)
                if not (phase_c_result and phase_c_result.get("needs_retry") and attempt < max_retries):
                    break
                prior_feedback = phase_c_result.get("failure_evidence") or None
                attempt += 1
            # Surface how many regenerations happened; strip the internal
            # retry signals from the public result.
            if isinstance(phase_c_result, dict):
                if attempt:
                    phase_c_result["retry_attempts"] = attempt
                phase_c_result.pop("needs_retry", None)
                phase_c_result.pop("failure_evidence", None)
        except Exception as e:  # noqa: BLE001
            phase_c_result = {
                "attempted": True,
                "error": f"{type(e).__name__}: {str(e)[:300]}",
            }

    # ──── DAST-304 — Phase C multi-file patch propagation (v2.0) ──────
    # When Phase D (DAST-301/302) surfaced confirmed variants in
    # SIBLING files (not the seed's own file), generate a coherent
    # patch for each sibling file independently. Phase C v14 above
    # already handled the entry file's patch; DAST-304 handles every
    # other file Phase D found variants in.
    #
    # Feature-gated by ``enable_phase_d`` AND ``enable_phase_c`` —
    # the user opted into both variant analysis AND remediation. The
    # variant findings are surfaced regardless of remediation;
    # DAST-304 only runs when the operator wants patches generated.
    variant_remediation_result: dict[str, Any] | None = None
    if (
        enable_phase_d
        and enable_phase_c
        and variant_analysis_results
        and phase_c_result is not None
        and phase_c_result.get("attempted") is not False
    ):
        try:
            from dast.phase_c_multi_file import run_phase_c_multi_file_patch  # noqa: PLC0415

            # DAST-304 v2.0 doesn't yet use seed_plan_records for
            # sandbox replay (deferred to v2.1) — pass empty dict.
            variant_remediation_result = await run_phase_c_multi_file_patch(
                file_record=file_record,
                variant_analysis_results=variant_analysis_results,
                seed_plan_records_by_hid={},
                inference=phase_3_inference or inference,
                sandbox=sandbox,
            )
            if variant_remediation_result:
                total_in += variant_remediation_result.get("tokens_in", 0)
                total_out += variant_remediation_result.get("tokens_out", 0)
        except Exception as exc:  # noqa: BLE001
            variant_remediation_result = {
                "attempted": True,
                "error": f"{type(exc).__name__}: {str(exc)[:300]}",
            }
            journal.append(
                JournalRecord(
                    iter=1,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id="DAST-304-ENTRY",
                    verdict="rejected",
                    rationale=(f"DAST-304 multi-file patch failed: {type(exc).__name__}: {str(exc)[:200]}"),
                    evidence_refs=[],
                )
            )

    return DastResult(
        file_id=file_id,
        iterations=iterations,
        final_verdict=last_verdict,
        findings_validated=findings_validated,
        total_tokens_in=total_in,
        total_tokens_out=total_out,
        total_sandbox_calls=total_sb,
        elapsed_s=round(time.time() - started, 2),
        stop_reason=stop_reason,
        journal_path=journal.path,
        diagnostics={
            "max_iterations": MAX_ITERATIONS,
            "token_cap": TOKEN_CAP_PER_FILE,
            "cost_cap_usd": max_cost_usd,
            # v1.9.1: coverage-dedupe telemetry. Surfaces:
            #   * n_entries / entries_by_source — how many
            #     (function, attack_class) pairs the tracker held
            #   * suppressions_by_stage — how many candidates each
            #     stage skipped because the tracker already covered
            #     them. Operators see "Phase B+ skipped 5 probes
            #     already claimed by L1" → directly quantifies
            #     the new-exploit budget that got redirected.
            "coverage_tracker": coverage_tracker.stats(),
        },
        journal_records=journal_dump,
        findings_validated_meta=findings_validated_meta,
        phase_c=phase_c_result,
        variant_analysis=variant_analysis_results,
        variant_remediation=variant_remediation_result,
        runtime_behavioral_profile=runtime_behavioral_profile_dict,
        phase_3_loop=phase_3_loop_summary,
        phase_3_resolver_decision=_resolve_phase_3_decision(
            phase_3_loop_summary=phase_3_loop_summary,
            initial_l1_verdict_label=initial_l1_verdict_label,
        ),
    )


def _resolve_phase_3_decision(
    *,
    phase_3_loop_summary: dict[str, Any] | None,
    initial_l1_verdict_label: str,
) -> dict[str, Any]:
    """Run the Phase 3 verdict resolver and serialize the decision.

    Always runs (the resolver handles ``phase_3_loop_summary=None``
    gracefully -> ``l1_no_phase_3`` source). Surfaced on
    :class:`DastResult.phase_3_resolver_decision` as observation;
    the engine's existing final_verdict logic is unchanged until the
    JSON v3 schema work promotes the resolver decision to canonical.

    ``l1_findings`` is currently passed as an empty list. The partial-
    coverage branch (30-80% coverage) would benefit from real L1
    findings to fill the coverage gap, but L1 findings flow through
    ``l1_output["hypotheses"]`` with a hypothesis-shaped schema (not
    a finding-shaped one with explicit severity). Extracting them
    cleanly is a follow-on; the live measurement showed coverage_ratio
    consistently at 1.0 so partial-coverage is uncommon today.
    """
    from dast.verdict_resolver import (  # noqa: PLC0415
        VerdictResolverInput,
        resolve_verdict,
    )

    inputs = VerdictResolverInput(
        phase_3_loop_summary=phase_3_loop_summary,
        l1_verdict_label=initial_l1_verdict_label,
        l1_findings=[],  # TODO: extract from l1_output["hypotheses"]
    )
    output = resolve_verdict(inputs)
    return {
        "final_verdict": output.final_verdict,
        "verdict_source": output.verdict_source,
        "coverage_class": output.coverage_class,
        "static_only": output.static_only,
        "rationale": output.rationale,
        # findings list omitted -- already surfaced via findings_validated;
        # avoid duplication in the engine output JSON.
    }


async def _run_phase_b_runtime_probe(
    *,
    file_record: dict,
    l1_output: dict,
    journal: Journal,
    journal_summary: Any,
    inference: InferenceFn,
    sandbox: SandboxClient,
    iter_num: int,
    stats: IterationStats,
    enable_mutation: bool = False,
    enable_iterative: bool = False,
    enable_per_scan_dep_install: bool = False,
    coverage_tracker: Any | None = None,
) -> list[dict]:
    """Phase B+ — runtime-guided exploit discovery (v1.5).

    Three steps:
    1. Ask Sonnet for probe candidates + attack inputs (one LLM call).
    2. For each (candidate × input), build a Phase-A-shaped harness plan
       and submit to the sandbox.
    3. Interpret each trace via the deterministic
       :func:`dast.runtime_probe.interpret_probe_trace` rules; any
       finding gets journaled as a CONFIRMED phase_b_hypothesis with
       sandbox-grounded runtime evidence.

    Mutates the passed-in ``journal`` and ``stats`` in place — no return.
    Errors during candidate generation or trace interpretation are
    captured into rejected-hypothesis journal records so the caller's
    outer try/except has something to surface.
    """
    from dast.runtime_probe import (  # noqa: PLC0415
        MAX_CANDIDATES,
        MAX_INPUTS_PER_CANDIDATE,
        MAX_PROBE_RUNS_PER_FILE,
        RuntimeProbeCandidate,
        RuntimeProbeInput,
        build_runtime_probe_plan,
        interpret_probe_trace,
        normalize_args_json,
        parse_probe_trace,
    )

    def _normalize_kwargs_json(s: str) -> str:
        """Same auto-repair as ``normalize_args_json`` but for kwargs
        (must decode to a dict, not a list). Inlined here so we don't
        leak a second public helper for a single caller."""
        if not isinstance(s, str) or not s.strip():
            return "{}"
        try:
            parsed = json.loads(s)
            if isinstance(parsed, dict):
                return json.dumps(parsed)
        except (json.JSONDecodeError, ValueError):
            pass
        try:
            import ast as _ast  # noqa: PLC0415

            parsed = _ast.literal_eval(s)
            if isinstance(parsed, dict):
                return json.dumps(parsed)
        except (ValueError, SyntaxError, MemoryError, TypeError):
            pass
        return "{}"

    source_text = file_record.get("source_text", "") or ""
    original_bytes = file_record.get("original_bytes")
    if not isinstance(original_bytes, (bytes, bytearray)):
        # No original bytes available — can't stage the file for execution.
        # Skip silently; orchestrator will fall through to standard Phase B.
        return []
    original_bytes = bytes(original_bytes)
    file_name = file_record.get("file_name") or "module.py"
    file_id = file_record.get("file_id", "")

    # ── Step 1: candidate generation ─────────────────────────────────────
    probe_prompt = dast_prompts.build_phase_b_runtime_probe_prompt(
        file_text=source_text,
        l1_output=l1_output,
        journal_summary=journal_summary.to_dict() if hasattr(journal_summary, "to_dict") else journal_summary,
    )
    probe_resp = await inference(
        probe_prompt,
        {"temperature": 0.0, "max_tokens": 4096, "seed": 0},
        dast_prompts.phase_b_runtime_probe_schema(),
    )
    # Fix #4: track probe inference tokens on the iteration stats so
    # they roll into total_tokens_in/out → DAST cost_usd → engine
    # ScanResult.total_cost_usd → install path's aggregate cost cap.
    # Without this, probe tokens leak out of cost accounting and the
    # aggregate cap can be silently exceeded.
    stats.phase_b_runtime_probe_in = (probe_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
    stats.phase_b_runtime_probe_out = (probe_resp.get("usage") or {}).get("completion_tokens", 0) or 0
    probe_obj = _parse_json_or_empty(probe_resp.get("text", ""))
    if not isinstance(probe_obj, dict):
        return []
    raw_candidates = probe_obj.get("candidates") or []
    if not isinstance(raw_candidates, list) or not raw_candidates:
        # Model legitimately declined to probe (file has no probe-attractive
        # functions). Journal the rationale so downstream telemetry sees it.
        rationale = str(probe_obj.get("non_probable_reason") or "no candidates")
        journal.append(
            JournalRecord(
                iter=iter_num,
                phase=JournalPhase.PHASE_B_HYPOTHESIS,
                claim_id="HRP_NONE",
                verdict="rejected",
                rationale=f"runtime probe declined: {rationale[:200]}",
                evidence_refs=[],
            )
        )
        return []

    # Decode + cap to bounded sizes (schema enforces but defense-in-depth)
    candidates: list[RuntimeProbeCandidate] = []
    for c in raw_candidates[:MAX_CANDIDATES]:
        if not isinstance(c, dict):
            continue
        inputs_raw = c.get("test_inputs") or []
        inputs: list[RuntimeProbeInput] = []
        for i in (inputs_raw if isinstance(inputs_raw, list) else [])[:MAX_INPUTS_PER_CANDIDATE]:
            if not isinstance(i, dict):
                continue
            # Phase 1a hardening: auto-repair model-emitted args_json /
            # kwargs_json that arrives as Python-syntax (single-quoted
            # strings) instead of valid JSON. Without this, the mutator
            # silently returns empty (json.loads fails) AND the harness
            # crashes inside the sandbox with SyntaxError. Auto-repair
            # via ast.literal_eval recovers the model's intent without
            # wasting a probe slot.
            inputs.append(
                RuntimeProbeInput(
                    args_json=normalize_args_json(str(i.get("args_json") or "[]")),
                    kwargs_json=_normalize_kwargs_json(str(i.get("kwargs_json") or "{}")),
                    expected_observable=str(i.get("expected_observable") or ""),
                    exploit_proof_if_observed=str(i.get("exploit_proof_if_observed") or ""),
                    # v15.18: constructor args for instance_method targets.
                    # Schema defaults to "[]"/"{}" so legacy candidates
                    # (no field emitted) fall back to no-arg constructor.
                    instance_init_args_json=normalize_args_json(str(i.get("instance_init_args_json") or "[]")),
                    instance_init_kwargs_json=_normalize_kwargs_json(str(i.get("instance_init_kwargs_json") or "{}")),
                )
            )
        candidates.append(
            RuntimeProbeCandidate(
                function_name=str(c.get("function_name") or ""),
                attack_class=str(c.get("attack_class") or "code_injection"),
                rationale=str(c.get("rationale") or ""),
                test_inputs=inputs,
                # v15.18: target_kind selects the harness invocation
                # strategy (function / class_constructor /
                # instance_method / classmethod / staticmethod).
                # Defaults to "function" for backwards compat with
                # legacy candidates that don't emit the field.
                target_kind=str(c.get("target_kind") or "function"),
            )
        )

    # v1.9.1 — coverage dedupe. Drop candidates that are already
    # covered (function + attack_class match an entry in the
    # tracker). Pre-Phase-B+ the tracker is seeded from L1's
    # high-confidence findings; so the model's probe set focuses
    # on NEW exploits / NEW functions instead of re-confirming
    # what L1 already claimed. Each suppression is counted in
    # tracker telemetry so operators see the savings.
    if coverage_tracker is not None and coverage_tracker.enabled:
        kept_after_dedupe: list[RuntimeProbeCandidate] = []
        for cand in candidates:
            covered = coverage_tracker.is_covered(
                function=cand.function_name,
                attack_class=cand.attack_class,
            )
            if covered is None:
                kept_after_dedupe.append(cand)
            else:
                coverage_tracker.record_suppression("phase_b")
                journal.append(
                    JournalRecord(
                        iter=iter_num,
                        phase=JournalPhase.PHASE_B_HYPOTHESIS,
                        claim_id=f"HRP_SKIP_{cand.function_name}_{cand.attack_class}",
                        verdict="rejected",
                        rationale=(
                            f"runtime probe suppressed: "
                            f"({cand.function_name}, {cand.attack_class}) "
                            f"already covered by {covered.source} "
                            f"finding {covered.finding_id}"
                        ),
                        evidence_refs=[],
                    )
                )
        candidates = kept_after_dedupe

    # ── Step 2: per-probe sandbox submission ─────────────────────────────
    # Phase 1a — mutation expansion. For each model-generated test_input,
    # optionally fan out to N mutated variants drawn from known-bypass
    # families (URL-encode, quad-dot path traversal, semicolon command
    # chaining, etc.). The original input is always probed first; mutations
    # are appended afterward. Each mutation gets a distinct hypothesis ID
    # (HRP_<c>_<i>_m<m>) and a journal-tagged mutation_strategy so we can
    # attribute confirmations to specific bypass families.
    #
    # Phase 1c — parallel probe submission. Build all SandboxPlans first
    # (fast, in-process), then submit them concurrently via
    # asyncio.gather with a bounded semaphore. Without this, a file with
    # mutation enabled (up to 54 probes) takes 18-25 min wall-clock at
    # ~20s per cold-started Fly machine. Parallel submission compresses
    # that to ~30-90s while spending the same total Fly machine-seconds
    # (Fly bills compute time, not wall-clock). Trace interpretation +
    # journal writes happen sequentially AFTER the gather so the journal
    # records land in deterministic order.
    import asyncio as _asyncio  # noqa: PLC0415

    from dast.probe_mutator import mutate_input  # noqa: PLC0415

    findings_from_probes: list[dict[str, Any]] = []
    # Phase 1b — per-candidate bookkeeping for iterative refinement.
    # confirmed_by_candidate[c_idx] = True iff any probe for that
    # candidate fired Rule 1 or Rule 2. recoverable_failures_by_candidate
    # accumulates BLOCKED probes where the function was reached (i.e.,
    # exception_type is NOT ImportError / AttributeError). Refinement
    # only fires when (a) no confirm + (b) at least one recoverable
    # failure → the model has something concrete to refine against.
    confirmed_by_candidate: dict[int, bool] = {}
    recoverable_failures_by_candidate: dict[int, list[dict[str, str]]] = {}
    _UNRECOVERABLE_EXC_TYPES: frozenset[str] = frozenset(
        {
            "ImportError",
            "AttributeError",
            "ModuleNotFoundError",
            "",  # empty exception_type — harness failed before invocation
        }
    )
    # Stops the outer build loop early if a HARD cap is exceeded; protects
    # against exotic candidates with many string args producing
    # cartesian-product blow-up.
    _HARD_PROBE_CAP = MAX_PROBE_RUNS_PER_FILE * 6  # 9 × 6 = 54
    # Concurrency limit for parallel sandbox submissions. Default Fly
    # accounts allow ~25 concurrent machines per app, but burst-creating
    # too many in <1 min hits Fly's machine-create rate limit.
    #
    # Tuning history:
    #   * 15 (initial Phase 1c): produced FlyMachinesError on significant
    #     fraction of probes — burst-rate limit hit.
    #   * 8 (Phase 1c v2): no more FlyMachinesError but ~20% of probes
    #     had "exit_code=None, empty exception" — machine boot timeout,
    #     not API throttling. Diagnosis: v5 image is 200MB heavier
    #     than v2; 8 parallel cold-pulls competed for Fly host bandwidth.
    #   * 12 (current, paired with MAX_MUTATIONS_PER_INPUT=3): probe
    #     count drops via the mutation cap, so Sem=12 fits within Fly's
    #     burst limit AND each batch's cold-pulls don't saturate the
    #     host. Net: faster wall-clock + higher per-probe reliability.
    _PROBE_CONCURRENCY: int = 12

    # ── Sub-step 2a: build all SandboxPlans (fast, in-process) ─────────
    # Each entry tracks the metadata we need at interpret-time so we can
    # produce ordered journal records after the parallel gather completes.
    pending_probes: list[tuple[int, int, int, str, Any, RuntimeProbeInput, str, SandboxPlan]] = []

    for c_idx, cand in enumerate(candidates):
        if not cand.function_name or not cand.test_inputs:
            continue
        for i_idx, test_in in enumerate(cand.test_inputs):
            # Build the fan-out list: (input, mutation_idx, strategy_label).
            # mutation_idx = 0 → original model input
            # mutation_idx >= 1 → mutated variant
            fanout: list[tuple[Any, int, str]] = [(test_in, 0, "original")]
            if enable_mutation:
                mutations = mutate_input(
                    args_json=test_in.args_json,
                    attack_class=cand.attack_class,
                )
                for m_idx, (mutated_args_json, strategy) in enumerate(mutations, start=1):
                    # Wrap mutated args in a fresh RuntimeProbeInput keeping
                    # the model's expected_observable + exploit_proof so the
                    # interpreter rules + journal narration still attribute
                    # the mutated probe to the same intent.
                    mutated_input = RuntimeProbeInput(
                        args_json=mutated_args_json,
                        kwargs_json=test_in.kwargs_json,
                        expected_observable=test_in.expected_observable,
                        exploit_proof_if_observed=test_in.exploit_proof_if_observed,
                        # v15.18: carry the original input's constructor
                        # args through mutation so the mutated harness
                        # uses the same instance for instance_method
                        # targets.
                        instance_init_args_json=test_in.instance_init_args_json,
                        instance_init_kwargs_json=test_in.instance_init_kwargs_json,
                    )
                    fanout.append((mutated_input, m_idx, strategy))

            for probe_input, m_idx, mutation_strategy in fanout:
                if len(pending_probes) >= _HARD_PROBE_CAP:
                    break
                plan_dict = build_runtime_probe_plan(
                    file_name=file_name,
                    file_bytes=original_bytes,
                    candidate=cand,
                    test_input=probe_input,
                    candidate_idx=c_idx,
                    input_idx=i_idx,
                    entry_rel_path=file_record.get("entry_rel_path", ""),
                )
                if plan_dict is None:
                    continue
                # Distinct hypothesis ID per mutation. Originals stay
                # HRP_<c>_<i> (backwards-compatible with v1.5.0 journal
                # grep patterns); mutations get HRP_<c>_<i>_m<m>.
                base_hid = plan_dict["hypothesis_id"]
                hid = base_hid if m_idx == 0 else f"{base_hid}_m{m_idx}"
                # v15.17 (2026-05-20): mirror the Phase A behavioral-probe
                # plan construction (orchestrator.py:3370-3401) so Phase B+
                # harnesses ship with ``runtime_packages`` + ``own_dist_name``.
                # Without this, dast-init skips ``pip install`` of the target
                # distribution and every HRP_X_Y probe inside a Python sdist
                # ImportErrors at ``import <pkg>``. The anthropic-sdk-python
                # campaign (2026-05-20) showed 24/35 (69%) of confirmed
                # findings were spurious ImportError-driven matches because
                # of this asymmetry. Phase A worked, Phase B+ didn't. Fix
                # is to compute the same two values here.
                from preprocessing.imports import (  # noqa: PLC0415
                    _detect_distribution_name_for_install,
                    runtime_packages_for_plan,
                )

                _image_hint = plan_dict["image_hint"]
                _runtime_pkgs = runtime_packages_for_plan(
                    file_bytes=original_bytes,
                    file_name=file_name,
                    image_hint=_image_hint,
                    enabled=enable_per_scan_dep_install,
                    project_root=file_record.get("project_root", "") or "",
                )
                _own_dist = _detect_distribution_name_for_install(file_record.get("project_root", "") or "") or ""
                plan = SandboxPlan(
                    plan_id=f"i{iter_num}-{hid}",
                    file_id=file_id,
                    hypothesis_id=hid,
                    commands=plan_dict["commands"],
                    expected_oracle=plan_dict["oracle"],
                    payload=plan_dict["payload"],
                    timeout_sec=plan_dict["timeout_sec"],
                    image_hint=_image_hint,
                    file_name=file_name,
                    runtime_packages=_runtime_pkgs,
                    own_dist_name=_own_dist,
                    synthesis_context={
                        "runtime_probe": True,
                        "candidate_idx": c_idx,
                        "input_idx": i_idx,
                        "mutation_idx": m_idx,
                        "mutation_strategy": mutation_strategy,
                        "attack_class": cand.attack_class,
                    },
                )
                pending_probes.append((c_idx, i_idx, m_idx, mutation_strategy, cand, probe_input, hid, plan))

    n_probes_run = len(pending_probes)

    # ── Sub-step 2b: parallel sandbox submission ────────────────────────
    # asyncio.gather with a Semaphore bounds concurrent Fly machines.
    # Each probe is independent (fresh microVM, no shared state), so
    # parallel submission is safe. We capture (trace, exception) per
    # probe and interpret them in declaration order afterwards.
    _sem = _asyncio.Semaphore(_PROBE_CONCURRENCY)

    async def _submit_one(p: SandboxPlan) -> tuple[SandboxTrace | None, BaseException | None]:
        """Bounded sandbox.submit() — returns (trace, None) on success
        and (None, exc) on failure. Never raises; the caller journals
        either path. The semaphore is acquired in this coroutine so the
        gather() spawns all coroutines instantly and they queue on the
        semaphore — keeps gather()'s structured-concurrency contract."""
        async with _sem:
            try:
                return await sandbox.submit(p), None
            except BaseException as exc:  # noqa: BLE001
                return None, exc

    if pending_probes:
        plans_only = [pp[7] for pp in pending_probes]
        results: list[tuple[SandboxTrace | None, BaseException | None]] = await _asyncio.gather(
            *(_submit_one(p) for p in plans_only)
        )
    else:
        results = []

    # ── Sub-step 2c: interpret traces + write journal records (sequential
    # for deterministic order; all CPU-local, very fast). ───────────────
    for (c_idx, i_idx, _m_idx, mutation_strategy, cand, probe_input, hid, _plan), (
        trace,
        submit_exc,
    ) in zip(pending_probes, results, strict=True):
        if submit_exc is not None:
            journal.append(
                JournalRecord(
                    iter=iter_num,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id=hid,
                    verdict="rejected",
                    rationale=(
                        f"sandbox submit failed (mutation={mutation_strategy}): "
                        f"{type(submit_exc).__name__}: {str(submit_exc)[:200]}"
                    ),
                    evidence_refs=[],
                )
            )
            continue

        # ── Step 3: trace interpretation ────────────────────────────────
        parsed_trace = parse_probe_trace(
            candidate_function=cand.function_name,
            input_args_json=probe_input.args_json,
            exit_code=trace.exit_code,
            stdout=trace.stdout_excerpt,
            stderr=trace.stderr_excerpt,
            elapsed_ms=trace.elapsed_ms,
        )
        finding = interpret_probe_trace(
            parsed_trace,
            cand,
            probe_input,
            candidate_idx=c_idx,
            input_idx=i_idx,
        )
        if finding is None:
            _pr = parsed_trace.parsed_result or {}
            _exc_type = _pr.get("exception_type", "")
            _exc_msg = (_pr.get("exception_msg") or "")[:160]
            _ok = bool(_pr.get("ok"))
            # v15.17 (2026-05-20): when the matcher returned None because
            # of sandbox-infra failure (ImportError/ModuleNotFoundError —
            # function-under-test never loaded), surface the probe as an
            # UNREACHED diagnostic row instead of dropping it silently.
            # Without this, Issue #1's matcher guard suppresses fake
            # CONFIRMs but the operator has no visibility into whether
            # Issue #2's runtime_packages plumbing is actually working
            # OR whether imports are still failing. UNREACHED entries
            # land in per_finding_validation via findings_validated_meta
            # but do NOT bump the verdict (they're diagnostic, not
            # exploit evidence).
            _is_infra_failure = _exc_type in {"ImportError", "ModuleNotFoundError"}
            _rationale_text = (
                f"runtime probe sandbox import failure — function was "
                f"never loaded. Vulnerable code path unreachable in this "
                f"run. exception_type={_exc_type}, msg={_exc_msg}"
                if _is_infra_failure
                else (
                    f"runtime probe ran; no exploit observed. "
                    f"Function={cand.function_name}, class={cand.attack_class}, "
                    f"mutation={mutation_strategy}, "
                    f"input={probe_input.args_json[:100]}, "
                    f"exit_code={parsed_trace.exit_code}, "
                    f"call_ok={_ok}, "
                    f"exc={_exc_type}: {_exc_msg}"
                )
            )
            journal.append(
                JournalRecord(
                    iter=iter_num,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id=hid,
                    verdict="rejected",
                    rationale=_rationale_text,
                    evidence_refs=[trace.events[0].event_id] if trace.events else [],
                )
            )
            # v15.17 diagnostic: emit per_finding_validation row for
            # EVERY non-CONFIRMED probe outcome — UNREACHED on infra
            # failure, REFUTED on clean run with no exploit. Caller
            # routes these into ``findings_validated_meta`` (not
            # ``findings_validated``), so they appear in PFV without
            # bumping the verdict. This lets a single re-run prove
            # whether Issue #2's runtime_packages plumbing actually
            # delivered (REFUTED rows = probes ran cleanly; UNREACHED
            # rows = imports still failing).
            _probe_status = "UNREACHED" if _is_infra_failure else "REFUTED"
            _unreached_reason = "sandbox_import_failure" if _is_infra_failure else "clean_run_no_exploit_evidence"
            _explanation = (
                f"Sandbox couldn't load the function-under-test ({_exc_type}); the hypothesis was never tested."
                if _is_infra_failure
                else (
                    f"Sandbox executed the function with attack input; "
                    f"matcher found no class signature or canary evidence "
                    f"(exit_code={parsed_trace.exit_code}, "
                    f"call_ok={_ok}, exc={_exc_type or 'none'})."
                )
            )
            findings_from_probes.append(
                {
                    "id": hid,
                    "finding_ref": hid,
                    "finding_type": cand.attack_class,
                    "severity": "unknown",
                    "cwe": "",
                    "line": None,
                    "code_snippet": cand.function_name,
                    "explanation": _explanation,
                    "data_flow_trace": "",
                    "proof_of_concept": (f"{cand.function_name}(*{probe_input.args_json})"),
                    "confidence": 0.0,
                    "runtime_evidence": _rationale_text,
                    "mutation_strategy": mutation_strategy,
                    "status": _probe_status,
                    "unreached_reason": _unreached_reason,
                }
            )
            # Phase 1b bookkeeping: track recoverable failures so the
            # refinement stage knows which candidates have a real chance
            # of being unblocked by a payload tweak.
            if _exc_type not in _UNRECOVERABLE_EXC_TYPES:
                recoverable_failures_by_candidate.setdefault(c_idx, []).append(
                    {
                        "args_json": probe_input.args_json,
                        "mutation_strategy": mutation_strategy,
                        "exception_type": _exc_type,
                        "exception_msg": _exc_msg,
                    }
                )
            continue

        # v15.25 — purpose-aware oracle suppression (Gemini Issue Fix A
        # + Fix B). The matcher emitted a finding, but two precision
        # heuristics check whether the finding is by-design:
        #
        #   Fix A: Function name declares its return is sensitive
        #          material (e.g., ``get_auth_headers`` returning
        #          authorization headers, ``IdentityTokenFile.__call__``
        #          returning a token). For ``data_exfiltration`` /
        #          CWE-200 only — returning is the function's contract.
        #   Fix B: Attack class requires actual network I/O (ssrf /
        #          cleartext_transmission / open_redirect), but the
        #          file's ``behavioral_profile.actual_capabilities.
        #          network_calls`` is empty — the function is a pure
        #          string-manipulation utility (signer, builder,
        #          encoder) that can't actually dispatch the request
        #          even if its output is malformed.
        #
        # When either suppression fires:
        #   * Don't add to ``findings_from_probes`` as CONFIRMED
        #   * DO emit a SUPPRESSED row (similar to UNREACHED/REFUTED
        #     v15.17 diagnostic pattern) so the per_finding_validation
        #     table shows what was filtered out
        #   * Don't mark ``confirmed_by_candidate[c_idx]`` — the cand
        #     can still have other inputs confirmed later
        from dast.runtime_probe import (  # noqa: PLC0415
            _function_name_declares_purpose,
            _file_has_network_io,
            _NETWORK_IO_REQUIRED_ATTACK_CLASSES,
        )

        # Phase 2 (SCAN-017) — downstream-cap detector.
        from dast.downstream_cap import (  # noqa: PLC0415
            find_capping_for_function,
            find_downstream_caps,
        )

        # Phase 3 (SCAN-018) — sandbox-syscall sink observation.
        from dast.sink_observation import (  # noqa: PLC0415
            extract_syscall_observations_from_events,
            find_missing_expected_sink,
        )

        _file_bp = file_record.get("behavioral_profile") or {}
        _suppress_reason = ""
        _purpose_match, _purpose_reason = _function_name_declares_purpose(cand.function_name, finding.attack_class)
        if _purpose_match:
            _suppress_reason = f"purpose_aligned_return: {_purpose_reason}"
        elif finding.attack_class in _NETWORK_IO_REQUIRED_ATTACK_CLASSES and not _file_has_network_io(_file_bp):
            _suppress_reason = (
                f"no_network_io: attack_class={finding.attack_class} requires "
                f"actual network dispatch, but file's behavioral_profile shows "
                f"empty actual_capabilities.network_calls — the function is a "
                f"pure transformer not a network client"
            )
        else:
            # Phase 2 (SCAN-017): static downstream-cap detection.
            # Pure-static scan; cached on file_record so it runs once per
            # file regardless of how many probes / hypotheses target it.
            _cached_caps = file_record.get("_downstream_caps")
            if _cached_caps is None:
                _orig_bytes = file_record.get("original_bytes")
                if isinstance(_orig_bytes, (bytes, bytearray)):
                    _src_text = bytes(_orig_bytes).decode("utf-8", errors="replace")
                    _cached_caps = find_downstream_caps(_src_text)
                else:
                    _cached_caps = []
                file_record["_downstream_caps"] = _cached_caps

            _cap = find_capping_for_function(
                cand.function_name,
                finding.attack_class,
                _cached_caps,
            )
            if _cap is not None:
                _suppress_reason = (
                    f"downstream_cap_detected: {_cap.capper_function} "
                    f"(line {_cap.capper_line}) bounds "
                    f"{_cap.capped_function}'s return at "
                    f"{_cap.cap_value} via {_cap.pattern}; attack_class="
                    f"{finding.attack_class} requires unbounded magnitude — "
                    f"unit-level CONFIRMED is misleading because the "
                    f"caller bounds the value before any sink uses it"
                )
            else:
                # Phase 3 (SCAN-018): kernel-syscall sink observation.
                # Last precision gate before CONFIRMED lands. Consults the
                # bpftrace sidecar's per-probe syscall_observations event
                # (one is emitted per sandbox plan run). When the
                # attack-class-specific expected sink (execve for
                # command_injection, network connect for ssrf, openat on
                # the target path for path_traversal) did NOT fire during
                # this probe run, the string-oracle match was almost
                # certainly a content-overlap FP — the function returned
                # something that LOOKED LIKE the exploit signature without
                # actually executing the exploit. Fail-open on missing
                # observations so kernel-feature regressions don't cause
                # silent suppression of real findings.
                _per_probe_obs = extract_syscall_observations_from_events(list(getattr(trace, "events", []) or []))
                _missing_sink = find_missing_expected_sink(
                    attack_class=finding.attack_class,
                    syscall_observations=_per_probe_obs,
                    args_json=probe_input.args_json,
                )
                if _missing_sink is not None:
                    _suppress_reason = f"expected_sink_not_observed: {_missing_sink.rationale}"

        if _suppress_reason:
            evidence_ref = trace.events[0].event_id if trace.events else ""
            journal.append(
                JournalRecord(
                    iter=iter_num,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id=hid,
                    verdict="rejected",
                    rationale=(
                        f"v15.25 suppression: {_suppress_reason}. Matcher "
                        f"observed {finding.attack_class} signal in {cand.function_name} "
                        f"but the finding shape is by-design / unexploitable. "
                        f"Original evidence: {finding.runtime_evidence[:200]}"
                    ),
                    evidence_refs=[evidence_ref] if evidence_ref else [],
                )
            )
            findings_from_probes.append(
                {
                    "id": hid,
                    "finding_ref": hid,
                    "finding_type": finding.attack_class,
                    "severity": finding.severity,
                    "cwe": finding.cwe,
                    "line": None,
                    "code_snippet": cand.function_name,
                    "explanation": (f"v15.25 SUPPRESSED: {_suppress_reason}"),
                    "data_flow_trace": "",
                    "proof_of_concept": (f"{cand.function_name}(*{finding.test_input_args})"),
                    "confidence": 0.0,
                    "runtime_evidence": (f"[SUPPRESSED v15.25 — {_suppress_reason}] {finding.runtime_evidence}"),
                    "mutation_strategy": mutation_strategy,
                    "status": "SUPPRESSED",
                    "unreached_reason": _suppress_reason.split(":")[0].strip(),
                }
            )
            continue

        # CONFIRMED via runtime evidence.
        confirmed_by_candidate[c_idx] = True
        evidence_ref = trace.events[0].event_id if trace.events else ""
        journal.append(
            JournalRecord(
                iter=iter_num,
                phase=JournalPhase.PHASE_B_HYPOTHESIS,
                claim_id=hid,
                verdict="confirmed",
                rationale=(
                    f"runtime probe CONFIRMED {finding.attack_class} in "
                    f"{cand.function_name} (mutation={mutation_strategy}): "
                    f"{finding.runtime_evidence[:240]}"
                ),
                evidence_refs=[evidence_ref] if evidence_ref else [],
            )
        )
        findings_from_probes.append(
            {
                "id": hid,
                "finding_ref": hid,
                "finding_type": finding.attack_class,
                "severity": finding.severity,
                "cwe": finding.cwe,
                "line": None,
                "code_snippet": cand.function_name,
                "explanation": finding.description,
                "data_flow_trace": (
                    f"runtime probe via Phase B+ (mutation={mutation_strategy}): {finding.runtime_evidence}"
                ),
                "proof_of_concept": (f"{cand.function_name}(*{finding.test_input_args})"),
                "confidence": 1.0,
                "runtime_evidence": finding.runtime_evidence,
                "mutation_strategy": mutation_strategy,
            }
        )

    stats.sandbox_calls += n_probes_run

    # ── Phase 1b — Iterative refinement on BLOCKED probes ────────────────
    # When opt-in, for each candidate that BLOCKED on the initial fan-out
    # but had at least one recoverable failure (function was reached;
    # exception is something like TypeError / SyntaxError / RangeError
    # rather than ImportError / AttributeError), ask Sonnet to generate
    # refined inputs that address the SPECIFIC exception types observed.
    # Up to MAX_REFINEMENT_ATTEMPTS new probes per candidate. Costs ~1
    # inference call + N sandbox calls per refined candidate.
    if enable_iterative:
        await _run_phase_b_iterative_refinement(
            file_record=file_record,
            candidates=candidates,
            confirmed_by_candidate=confirmed_by_candidate,
            recoverable_failures_by_candidate=recoverable_failures_by_candidate,
            findings_from_probes=findings_from_probes,
            file_name=file_name,
            file_id=file_id,
            original_bytes=original_bytes,
            inference=inference,
            sandbox=sandbox,
            journal=journal,
            iter_num=iter_num,
            stats=stats,
            enable_per_scan_dep_install=enable_per_scan_dep_install,
        )

    # v1.5 design choice (Fix #2): probe-confirmed HRP findings are
    # SURFACED via findings_validated (engine → ScanResult.dast_findings)
    # but are NOT appended to ``l1_output["hypotheses"]``. The probe
    # stage IS the test — re-running them through Phase A in iter 1
    # would (a) double the sandbox cost, (b) produce contradictory
    # NOT_TESTED verdicts when Fly returns stub traces, (c) make the
    # journal a mess of duplicate records.
    #
    # Phase B (iter ≥ 2, model-driven exploration) still has visibility
    # of HRP findings via journal_summary — it sees the
    # ``phase_b_hypothesis verdict=confirmed`` records and won't re-
    # propose them as new hypotheses.

    # Return the confirmed HRP_ finding dicts so run_dast can:
    # 1. Extend findings_validated with their IDs (→ engine surfacing).
    # 2. Decide whether to bump max_dast_verdict_rank (Fix #1).
    return findings_from_probes


async def _run_phase_b_iterative_refinement(
    *,
    file_record: dict,
    candidates: list,
    confirmed_by_candidate: dict[int, bool],
    recoverable_failures_by_candidate: dict[int, list[dict[str, str]]],
    findings_from_probes: list[dict[str, Any]],
    file_name: str,
    file_id: str,
    original_bytes: bytes,
    inference: InferenceFn,
    sandbox: SandboxClient,
    journal: Journal,
    iter_num: int,
    stats: IterationStats,
    enable_per_scan_dep_install: bool = False,
) -> None:
    """Phase 1b — iterative refinement helper.

    For each candidate where the initial fan-out (originals + mutations)
    blocked AND the function was reached at least once, ask Sonnet for
    refined inputs that address the SPECIFIC exception types observed.
    Submit those refined probes; if any confirm, append to
    ``findings_from_probes`` (mutated in place).

    No-op when:
    * No candidates have recoverable failures (every failure was
      ImportError / AttributeError or the original confirmed).
    * Caller didn't opt in (``enable_iterative=False``).

    All exceptions during refinement are journaled as REJECTED records
    rather than propagated — the helper is best-effort, never fatal.
    """
    from dast.prompts import (  # noqa: PLC0415
        build_phase_b_refinement_prompt,
        phase_b_refinement_schema,
    )
    from dast.runtime_probe import (  # noqa: PLC0415
        MAX_REFINEMENT_ATTEMPTS,
        RuntimeProbeInput,
        build_runtime_probe_plan,
        interpret_probe_trace,
        normalize_args_json,
        normalize_kwargs_json,
        parse_probe_trace,
    )

    source_text = file_record.get("source_text", "") or ""

    # Build the list of candidates to refine.
    to_refine: list[tuple[int, Any]] = []
    for c_idx, cand in enumerate(candidates):
        if confirmed_by_candidate.get(c_idx):
            # Already confirmed via initial fan-out — no need to refine
            continue
        rejections = recoverable_failures_by_candidate.get(c_idx, [])
        if not rejections:
            # No recoverable failures (all ImportError/AttributeError, or
            # we just didn't probe this candidate at all). Refining
            # without runtime evidence is just guessing.
            continue
        to_refine.append((c_idx, cand))

    if not to_refine:
        return

    # Refinement plans per candidate: build sequentially (need the
    # inference call to complete before knowing the plan), then submit
    # all of them in parallel via gather using the same semaphore the
    # initial fan-out used.
    refined_probes: list[tuple[int, int, Any, RuntimeProbeInput, str, SandboxPlan]] = []

    for c_idx, cand in to_refine:
        rejections = recoverable_failures_by_candidate[c_idx]
        # Use the first rejection's test_input as the representative
        # template for expected_observable / exploit_proof — they all
        # share these (mutator preserves them).
        # Locate it from cand.test_inputs (assume i=0 since refinement
        # is candidate-level, not input-level).
        if not cand.test_inputs:
            continue
        template_input = cand.test_inputs[0]

        # Ask the model for refined inputs given the recoverable failures
        prompt = build_phase_b_refinement_prompt(
            function_name=cand.function_name,
            attack_class=cand.attack_class,
            expected_observable=template_input.expected_observable,
            exploit_proof_if_observed=template_input.exploit_proof_if_observed,
            file_text=source_text,
            previous_attempts=rejections[:5],  # cap to 5 most informative
        )
        try:
            refine_resp = await inference(
                prompt,
                {"temperature": 0.0, "max_tokens": 2048, "seed": 0},
                phase_b_refinement_schema(),
            )
        except Exception as exc:  # noqa: BLE001
            journal.append(
                JournalRecord(
                    iter=iter_num,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id=f"HRP_{c_idx}_REFINE_ERROR",
                    verdict="rejected",
                    rationale=(
                        f"refinement inference failed for {cand.function_name}: {type(exc).__name__}: {str(exc)[:200]}"
                    ),
                    evidence_refs=[],
                )
            )
            continue

        # Track refinement inference tokens against the iter total so
        # the cost cap accounts for them.
        usage = refine_resp.get("usage") or {}
        stats.phase_b_runtime_probe_in += usage.get("prompt_tokens", 0) or 0
        stats.phase_b_runtime_probe_out += usage.get("completion_tokens", 0) or 0

        refine_obj = _parse_json_or_empty(refine_resp.get("text", ""))
        if not isinstance(refine_obj, dict):
            continue
        refined_inputs_raw = refine_obj.get("refined_inputs") or []
        if not isinstance(refined_inputs_raw, list) or not refined_inputs_raw:
            # Model legitimately couldn't refine — journal the reason
            reason = str(refine_obj.get("non_refinable_reason") or "no refinable inputs")
            journal.append(
                JournalRecord(
                    iter=iter_num,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id=f"HRP_{c_idx}_REFINE_NONE",
                    verdict="rejected",
                    rationale=f"refinement declined: {reason[:200]}",
                    evidence_refs=[],
                )
            )
            continue

        for r_idx, ref in enumerate(refined_inputs_raw[:MAX_REFINEMENT_ATTEMPTS]):
            if not isinstance(ref, dict):
                continue
            refined_input = RuntimeProbeInput(
                args_json=normalize_args_json(str(ref.get("args_json") or "[]")),
                kwargs_json=normalize_kwargs_json(str(ref.get("kwargs_json") or "{}"))
                if isinstance(ref.get("kwargs_json"), str)
                else "{}",
                expected_observable=template_input.expected_observable,
                exploit_proof_if_observed=template_input.exploit_proof_if_observed,
                # v15.18: carry the original input's constructor args
                # through refinement so the refined harness still
                # instantiates the same instance for instance_method
                # targets. Refinement only rewrites args/kwargs.
                instance_init_args_json=template_input.instance_init_args_json,
                instance_init_kwargs_json=template_input.instance_init_kwargs_json,
            )
            plan_dict = build_runtime_probe_plan(
                file_name=file_name,
                file_bytes=original_bytes,
                candidate=cand,
                test_input=refined_input,
                candidate_idx=c_idx,
                input_idx=0,
                entry_rel_path=file_record.get("entry_rel_path", ""),
            )
            if plan_dict is None:
                continue
            hid = f"HRP_{c_idx}_r{r_idx}"
            # v15.17: pin runtime_packages + own_dist on refinement plans
            # too. Same root-cause path as the primary HRP site above
            # (orchestrator.py:2459). The campaign data showed refinement
            # probes also ImportError'd for the same reason — dast-init
            # never received the install instruction.
            from preprocessing.imports import (  # noqa: PLC0415
                _detect_distribution_name_for_install,
                runtime_packages_for_plan,
            )

            _ref_image_hint = plan_dict["image_hint"]
            _ref_runtime_pkgs = runtime_packages_for_plan(
                file_bytes=original_bytes,
                file_name=file_name,
                image_hint=_ref_image_hint,
                enabled=enable_per_scan_dep_install,
                project_root=file_record.get("project_root", "") or "",
            )
            _ref_own_dist = _detect_distribution_name_for_install(file_record.get("project_root", "") or "") or ""
            plan = SandboxPlan(
                plan_id=f"i{iter_num}-{hid}",
                file_id=file_id,
                hypothesis_id=hid,
                commands=plan_dict["commands"],
                expected_oracle=plan_dict["oracle"],
                payload=plan_dict["payload"],
                timeout_sec=plan_dict["timeout_sec"],
                image_hint=_ref_image_hint,
                file_name=file_name,
                runtime_packages=_ref_runtime_pkgs,
                own_dist_name=_ref_own_dist,
                synthesis_context={
                    "runtime_probe": True,
                    "candidate_idx": c_idx,
                    "input_idx": 0,
                    "refinement_idx": r_idx,
                    "refinement_rationale": str(ref.get("rationale") or "")[:200],
                    "attack_class": cand.attack_class,
                },
            )
            refined_probes.append((c_idx, r_idx, cand, refined_input, hid, plan))

    if not refined_probes:
        return

    # Submit refined probes in parallel via the same gather pattern.
    # Reuse the semaphore-bound _submit_one shape inline (the outer
    # function's semaphore is out of scope here; we make a small one
    # for refinement traffic separately).
    import asyncio as _asyncio  # noqa: PLC0415

    _ref_sem = _asyncio.Semaphore(8)

    async def _submit_one_ref(p: SandboxPlan) -> tuple[SandboxTrace | None, BaseException | None]:
        async with _ref_sem:
            try:
                return await sandbox.submit(p), None
            except BaseException as exc:  # noqa: BLE001
                return None, exc

    plans_only = [pp[5] for pp in refined_probes]
    ref_results: list[tuple[SandboxTrace | None, BaseException | None]] = await _asyncio.gather(
        *(_submit_one_ref(p) for p in plans_only)
    )

    stats.sandbox_calls += len(refined_probes)

    for (c_idx, r_idx, cand, refined_input, hid, _plan), (trace, submit_exc) in zip(
        refined_probes, ref_results, strict=True
    ):
        if submit_exc is not None:
            journal.append(
                JournalRecord(
                    iter=iter_num,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id=hid,
                    verdict="rejected",
                    rationale=(
                        f"refinement sandbox submit failed: {type(submit_exc).__name__}: {str(submit_exc)[:200]}"
                    ),
                    evidence_refs=[],
                )
            )
            continue

        parsed_trace = parse_probe_trace(
            candidate_function=cand.function_name,
            input_args_json=refined_input.args_json,
            exit_code=trace.exit_code,
            stdout=trace.stdout_excerpt,
            stderr=trace.stderr_excerpt,
            elapsed_ms=trace.elapsed_ms,
        )
        finding = interpret_probe_trace(
            parsed_trace,
            cand,
            refined_input,
            candidate_idx=c_idx,
            input_idx=0,
        )
        if finding is None:
            _pr = parsed_trace.parsed_result or {}
            _exc_type = _pr.get("exception_type", "")
            _exc_msg = (_pr.get("exception_msg") or "")[:160]
            journal.append(
                JournalRecord(
                    iter=iter_num,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id=hid,
                    verdict="rejected",
                    rationale=(
                        f"refinement probe ran; no exploit observed. "
                        f"Function={cand.function_name}, "
                        f"refinement_idx={r_idx}, "
                        f"input={refined_input.args_json[:100]}, "
                        f"exc={_exc_type}: {_exc_msg}"
                    ),
                    evidence_refs=[trace.events[0].event_id] if trace.events else [],
                )
            )
            continue

        # CONFIRMED via refined input
        evidence_ref = trace.events[0].event_id if trace.events else ""
        journal.append(
            JournalRecord(
                iter=iter_num,
                phase=JournalPhase.PHASE_B_HYPOTHESIS,
                claim_id=hid,
                verdict="confirmed",
                rationale=(
                    f"refinement probe CONFIRMED {finding.attack_class} in "
                    f"{cand.function_name} (refinement_idx={r_idx}): "
                    f"{finding.runtime_evidence[:240]}"
                ),
                evidence_refs=[evidence_ref] if evidence_ref else [],
            )
        )
        findings_from_probes.append(
            {
                "id": hid,
                "finding_ref": hid,
                "finding_type": finding.attack_class,
                "severity": finding.severity,
                "cwe": finding.cwe,
                "line": None,
                "code_snippet": cand.function_name,
                "explanation": finding.description,
                "data_flow_trace": (f"runtime probe via Phase B+ (refinement_idx={r_idx}): {finding.runtime_evidence}"),
                "proof_of_concept": (f"{cand.function_name}(*{finding.test_input_args})"),
                "confidence": 1.0,
                "runtime_evidence": finding.runtime_evidence,
                "mutation_strategy": f"refinement_r{r_idx}",
            }
        )


async def _run_phase_b_runtime_probe_chains(
    *,
    file_record: dict,
    l1_output: dict,
    journal: Journal,
    journal_summary: Any,
    inference: InferenceFn,
    sandbox: SandboxClient,
    iter_num: int,
    stats: IterationStats,
    enable_per_scan_dep_install: bool = False,
) -> list[dict]:
    """Phase 2 — Cross-function exploit chains (v1.6).

    Mirrors :func:`_run_phase_b_runtime_probe` but for multi-step
    chains. Three steps:

    1. Ask Sonnet for chain candidates (one LLM call). Chains are 2-3
       step function-call sequences where each step's args may
       reference prior steps' return values via ``<<_stepN_result>>``
       placeholders. Distinct prompt + schema from single-function
       probing.
    2. For each chain, build a Phase-A-shaped plan that wraps a single
       harness running ALL steps inside one sandbox VM, and submit in
       parallel via asyncio.gather (one VM per chain, not per step —
       the harness handles step ordering + placeholder substitution
       internally).
    3. Interpret each chain trace via
       :func:`dast.runtime_probe.interpret_probe_chain_trace`. Rule 1
       (final-step evidence-signature match) + Rule 2 (canary side
       effect anywhere in chain) determine confirmation. Confirmed
       chains journal as ``phase_b_hypothesis verdict=confirmed`` with
       ``HRP_C<idx>`` claim_id.

    Mutates the passed-in ``journal`` and ``stats`` in place — no
    return mutation. Returns the list of confirmed-chain finding dicts
    so the caller can extend ``findings_validated`` + bump verdict.

    Errors during candidate generation or chain submission are
    captured as REJECTED journal records — the helper is best-effort
    and never fatal.
    """
    from dast.prompts import build_phase_b_chain_prompt, phase_b_chain_schema  # noqa: PLC0415
    from dast.runtime_probe import (  # noqa: PLC0415
        MAX_CHAIN_STEPS,
        MAX_CHAINS_PER_FILE,
        RuntimeProbeChain,
        RuntimeProbeChainStep,
        build_runtime_probe_chain_plan,
        detect_probe_language,
        interpret_probe_chain_trace,
        normalize_args_json,
        normalize_kwargs_json,
        parse_probe_chain_trace,
    )

    # Language gate. Chain probing admits:
    #   python (.py) + javascript (.js/.mjs/.cjs) + typescript
    #   (.ts/.tsx, v9 — reuses JS chain harness via ts-node loader).
    # Plan builder dispatches by language internally. Bail early on
    # other languages to save the inference call.
    file_name = file_record.get("file_name") or "module.py"
    if detect_probe_language(file_name) not in ("python", "javascript", "typescript"):
        return []

    source_text = file_record.get("source_text", "") or ""
    original_bytes = file_record.get("original_bytes")
    if not isinstance(original_bytes, (bytes, bytearray)):
        return []
    original_bytes = bytes(original_bytes)
    file_id = file_record.get("file_id", "")

    # ── Step 1: chain candidate generation ───────────────────────────────
    chain_prompt = build_phase_b_chain_prompt(
        file_text=source_text,
        l1_output=l1_output,
        journal_summary=journal_summary.to_dict() if hasattr(journal_summary, "to_dict") else journal_summary,
    )
    try:
        chain_resp = await inference(
            chain_prompt,
            {"temperature": 0.0, "max_tokens": 4096, "seed": 0},
            phase_b_chain_schema(),
        )
    except Exception as exc:  # noqa: BLE001
        journal.append(
            JournalRecord(
                iter=iter_num,
                phase=JournalPhase.PHASE_B_HYPOTHESIS,
                claim_id="HRP_C_ERROR",
                verdict="rejected",
                rationale=(f"chain inference failed: {type(exc).__name__}: {str(exc)[:200]}"),
                evidence_refs=[],
            )
        )
        return []

    # Roll chain inference tokens into the iter total (same accounting
    # as single-function probing so the cost cap stays accurate).
    usage = chain_resp.get("usage") or {}
    stats.phase_b_runtime_probe_in += usage.get("prompt_tokens", 0) or 0
    stats.phase_b_runtime_probe_out += usage.get("completion_tokens", 0) or 0

    chain_obj = _parse_json_or_empty(chain_resp.get("text", ""))
    if not isinstance(chain_obj, dict):
        return []
    raw_chains = chain_obj.get("chains") or []
    if not isinstance(raw_chains, list) or not raw_chains:
        reason = str(chain_obj.get("no_chains_reason") or "no chain candidates")
        journal.append(
            JournalRecord(
                iter=iter_num,
                phase=JournalPhase.PHASE_B_HYPOTHESIS,
                claim_id="HRP_C_NONE",
                verdict="rejected",
                rationale=f"chain probing declined: {reason[:200]}",
                evidence_refs=[],
            )
        )
        return []

    # Decode + cap to bounded sizes (schema enforces but defense-in-depth).
    chains: list[RuntimeProbeChain] = []
    for c in raw_chains[:MAX_CHAINS_PER_FILE]:
        if not isinstance(c, dict):
            continue
        raw_steps = c.get("steps") or []
        if not isinstance(raw_steps, list):
            continue
        steps: list[RuntimeProbeChainStep] = []
        for s in raw_steps[:MAX_CHAIN_STEPS]:
            if not isinstance(s, dict):
                continue
            fn = str(s.get("function_name") or "")
            if not fn:
                continue
            steps.append(
                RuntimeProbeChainStep(
                    function_name=fn,
                    args_json=normalize_args_json(str(s.get("args_json") or "[]")),
                    kwargs_json=normalize_kwargs_json(str(s.get("kwargs_json") or "{}"))
                    if isinstance(s.get("kwargs_json"), str)
                    else "{}",
                )
            )
        if len(steps) < 2:
            # Single-step "chain" — model should have submitted as a
            # single-function probe. Reject silently so we don't pollute
            # the single-function FP defenses.
            continue
        chains.append(
            RuntimeProbeChain(
                steps=steps,
                attack_class=str(c.get("attack_class") or "code_injection"),
                rationale=str(c.get("rationale") or ""),
                expected_observable=str(c.get("expected_observable") or ""),
                exploit_proof_if_observed=str(c.get("exploit_proof_if_observed") or ""),
            )
        )

    if not chains:
        return []

    # ── Step 2: parallel sandbox submission ──────────────────────────────
    # One chain → one sandbox VM (chain harness handles step ordering +
    # placeholder substitution internally). asyncio.gather submits all
    # chains concurrently, bounded by a small semaphore (chain probing
    # caps at MAX_CHAINS_PER_FILE = 3 per file, so a Sem of 4 is plenty
    # and never hits Fly's burst rate limit).
    import asyncio as _asyncio  # noqa: PLC0415

    pending_chain_plans: list[tuple[int, RuntimeProbeChain, str, SandboxPlan]] = []
    for chain_idx, chain in enumerate(chains):
        plan_dict = build_runtime_probe_chain_plan(
            file_name=file_name,
            file_bytes=original_bytes,
            chain=chain,
            chain_idx=chain_idx,
            entry_rel_path=file_record.get("entry_rel_path", ""),
        )
        if plan_dict is None:
            continue
        hid = plan_dict["hypothesis_id"]
        # v15.17: same runtime_packages + own_dist plumbing as the
        # single-function HRP site (orchestrator.py:2459). Chain probes
        # importerror'd for the same reason without it.
        from preprocessing.imports import (  # noqa: PLC0415
            _detect_distribution_name_for_install,
            runtime_packages_for_plan,
        )

        _ch_image_hint = plan_dict["image_hint"]
        _ch_runtime_pkgs = runtime_packages_for_plan(
            file_bytes=original_bytes,
            file_name=file_name,
            image_hint=_ch_image_hint,
            enabled=enable_per_scan_dep_install,
            project_root=file_record.get("project_root", "") or "",
        )
        _ch_own_dist = _detect_distribution_name_for_install(file_record.get("project_root", "") or "") or ""
        plan = SandboxPlan(
            plan_id=f"i{iter_num}-{hid}",
            file_id=file_id,
            hypothesis_id=hid,
            commands=plan_dict["commands"],
            expected_oracle=plan_dict["oracle"],
            payload=plan_dict["payload"],
            timeout_sec=plan_dict["timeout_sec"],
            image_hint=_ch_image_hint,
            file_name=file_name,
            runtime_packages=_ch_runtime_pkgs,
            own_dist_name=_ch_own_dist,
            synthesis_context={
                "runtime_probe_chain": True,
                "chain_idx": chain_idx,
                "n_steps": len(chain.steps),
                "attack_class": chain.attack_class,
            },
        )
        pending_chain_plans.append((chain_idx, chain, hid, plan))

    if not pending_chain_plans:
        return []

    _chain_sem = _asyncio.Semaphore(4)

    async def _submit_chain(
        p: SandboxPlan,
    ) -> tuple[SandboxTrace | None, BaseException | None]:
        async with _chain_sem:
            try:
                return await sandbox.submit(p), None
            except BaseException as exc:  # noqa: BLE001
                return None, exc

    plans_only = [pp[3] for pp in pending_chain_plans]
    chain_results: list[tuple[SandboxTrace | None, BaseException | None]] = await _asyncio.gather(
        *(_submit_chain(p) for p in plans_only)
    )

    stats.sandbox_calls += len(pending_chain_plans)

    # ── Step 3: chain trace interpretation ───────────────────────────────
    chain_findings: list[dict[str, Any]] = []
    for (chain_idx, chain, hid, _plan), (trace, submit_exc) in zip(pending_chain_plans, chain_results, strict=True):
        if submit_exc is not None:
            journal.append(
                JournalRecord(
                    iter=iter_num,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id=hid,
                    verdict="rejected",
                    rationale=(f"chain sandbox submit failed: {type(submit_exc).__name__}: {str(submit_exc)[:200]}"),
                    evidence_refs=[],
                )
            )
            continue

        parsed_trace = parse_probe_chain_trace(
            chain_idx=chain_idx,
            exit_code=trace.exit_code,
            stdout=trace.stdout_excerpt,
            stderr=trace.stderr_excerpt,
            elapsed_ms=trace.elapsed_ms,
            # File-based transport: prefer reassembled chunk payload
            # over stdout. Bypasses Fly's per-log-line ~4KB cap that
            # truncates large multi-step chain markers.
            probe_result_json=getattr(trace, "probe_result_json", "") or "",
        )
        finding = interpret_probe_chain_trace(parsed_trace, chain, chain_idx=chain_idx)
        if finding is None:
            chain_summary = " -> ".join(s.function_name for s in chain.steps)
            steps_summary_str = " | ".join(parsed_trace.steps_summary) if parsed_trace.steps_summary else "(no steps)"
            journal.append(
                JournalRecord(
                    iter=iter_num,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id=hid,
                    verdict="rejected",
                    rationale=(
                        f"chain probe ran; no exploit observed. "
                        f"Chain={chain_summary}, "
                        f"short_circuited={parsed_trace.short_circuited}, "
                        f"per_step={steps_summary_str[:240]}"
                    ),
                    evidence_refs=[trace.events[0].event_id] if trace.events else [],
                )
            )
            continue

        # CONFIRMED via chain runtime evidence.
        evidence_ref = trace.events[0].event_id if trace.events else ""
        chain_str = " -> ".join(s.function_name for s in chain.steps)
        journal.append(
            JournalRecord(
                iter=iter_num,
                phase=JournalPhase.PHASE_B_HYPOTHESIS,
                claim_id=hid,
                verdict="confirmed",
                rationale=(
                    f"chain probe CONFIRMED {finding.attack_class} via "
                    f"{len(chain.steps)}-step chain ({chain_str}): "
                    f"{finding.runtime_evidence[:240]}"
                ),
                evidence_refs=[evidence_ref] if evidence_ref else [],
            )
        )
        chain_findings.append(
            {
                "id": hid,
                "finding_ref": hid,
                "finding_type": finding.attack_class,
                "severity": finding.severity,
                "cwe": finding.cwe,
                "line": None,
                "code_snippet": chain.steps[-1].function_name,
                "explanation": finding.description,
                "data_flow_trace": (f"runtime probe via Phase B+ chain ({chain_str}): {finding.runtime_evidence}"),
                "proof_of_concept": (f"{chain_str} starting with args={finding.chain_inputs_json}"),
                # Phase 2 v1.0 confidence calibration. Surfaces oracle-specific
                # FP risk into the finding so the adjudicator / report writer
                # / human operator can filter by threshold. 1.0=Rule 2 canary
                # (zero observed FPs), 0.7=Rule 1 class signature, 0.4=Rule 1
                # observable keyword (the db2 FP source).
                "confidence": finding.confidence,
                "oracle_type": finding.oracle_type,
                "runtime_evidence": finding.runtime_evidence,
                "chain_steps": finding.chain_steps,
            }
        )

    return chain_findings


async def _run_phase_3_behavioral_probe(
    *,
    file_record: dict,
    journal: Journal,
    sandbox: SandboxClient,
    iter_num: int,
    stats: IterationStats,
    enable_per_scan_dep_install: bool = True,
) -> dict[str, Any] | None:
    """Phase 3 Stage 1 — Behavioral exploration probe (v1.6).

    Runs a deterministic instrumentation pass inside the sandbox: import
    the target module, exercise every public callable with benign
    discovery inputs, capture per-callable observations (eval / exec /
    subprocess / pickle reach, file opens, network attempts) via
    ``sys.addaudithook``. Emits a structured behavioral profile that
    Stage 2's adversarial reasoning loop will consume as ground-truth
    input for attack hypothesis generation.

    Returns the profile as a dict (serialized form of
    :class:`dast.behavioral_probe.BehavioralProfile`) on success, or
    ``None`` when the probe couldn't run (non-Python file, sandbox
    submission failed) or produced no usable profile (harness crashed
    before emit marker). The orchestrator surfaces the profile on
    ``DastResult.behavioral_profile`` for the engine to embed in the
    final scan JSON.

    Stage 1 is non-destructive: it doesn't generate findings, doesn't
    bump verdicts, doesn't journal as confirmed/rejected. It journals
    one informational record (``BP_<file_id>:noop``) for traceability.
    """
    from dataclasses import asdict  # noqa: PLC0415

    from dast.behavioral_probe import (  # noqa: PLC0415
        build_behavioral_probe_plan,
        parse_behavioral_probe_trace,
    )

    file_name = file_record.get("file_name") or "module.py"
    file_id = file_record.get("file_id", "")
    original_bytes = file_record.get("original_bytes")
    if not isinstance(original_bytes, (bytes, bytearray)):
        return None
    original_bytes = bytes(original_bytes)

    plan_dict = build_behavioral_probe_plan(
        file_name=file_name,
        file_bytes=original_bytes,
        file_id=file_id,
        entry_rel_path=file_record.get("entry_rel_path", ""),
    )
    if plan_dict is None:
        # Non-Python file. Stage 1 is Python-only in v1.
        return None

    hid = plan_dict["hypothesis_id"]

    # v15.5 (2026-05-20): wire runtime_packages_for_plan into BP plan
    # construction. The Phase A iteration-1 plans (line ~1435) and
    # Phase 3 Stage 2 plans (adversarial_loop_runner) both call this
    # helper; the BP / behavioral-probe path was the only DAST plan
    # construction site that didn't, so BP harnesses shipped with
    # runtime_packages=[] regardless of project_root. Net effect:
    # dast-init never pip-installed the target's own distribution,
    # ``import <pkg>.<module>`` failed inside the sandbox, and the
    # harness produced callables_total=0 for every file inside a
    # Python sdist — even after v15.4's lean-tier own_dist lift,
    # because the lift could never be exercised on this path.
    #
    # Fix: compute runtime_packages once here and pass it through
    # to SandboxPlan, matching the Phase A site's pattern verbatim.
    from preprocessing.imports import runtime_packages_for_plan  # noqa: PLC0415

    image_hint = plan_dict["image_hint"]
    runtime_pkgs = runtime_packages_for_plan(
        file_bytes=original_bytes,
        file_name=file_name,
        image_hint=image_hint,
        enabled=enable_per_scan_dep_install,
        project_root=file_record.get("project_root", "") or "",
    )
    # v15.10 (2026-05-20): own_dist routes to with-deps install. See
    # the corresponding fix at the Phase A plan-construction site
    # (line ~1465) for full rationale.
    from preprocessing.imports import _detect_distribution_name_for_install  # noqa: PLC0415

    _own_dist = _detect_distribution_name_for_install(file_record.get("project_root", "") or "") or ""

    plan = SandboxPlan(
        plan_id=f"i{iter_num}-{hid}",
        file_id=file_id,
        hypothesis_id=hid,
        commands=plan_dict["commands"],
        expected_oracle=plan_dict["oracle"],
        payload=plan_dict["payload"],
        timeout_sec=plan_dict["timeout_sec"],
        image_hint=image_hint,
        file_name=file_name,
        runtime_packages=runtime_pkgs,
        own_dist_name=_own_dist,
        synthesis_context={"behavioral_probe": True},
    )

    try:
        trace = await sandbox.submit(plan)
    except Exception as exc:  # noqa: BLE001
        journal.append(
            JournalRecord(
                iter=iter_num,
                phase=JournalPhase.PHASE_B_HYPOTHESIS,
                claim_id=hid,
                verdict="rejected",
                rationale=(f"behavioral probe sandbox submit failed: {type(exc).__name__}: {str(exc)[:200]}"),
                evidence_refs=[],
            )
        )
        return None

    stats.sandbox_calls += 1

    profile = parse_behavioral_probe_trace(
        file_id=file_id,
        file_name=file_name,
        stdout=trace.stdout_excerpt,
        # File-based transport: prefer the reassembled chunk payload
        # over stdout. Bypasses Fly's per-log-line ~4KB cap that
        # truncates large probe markers when delivered via stdout.
        probe_result_json=getattr(trace, "probe_result_json", "") or "",
    )

    # Phase 2 sandbox-observability: merge kernel-level syscall
    # observations from the bpftrace sidecar (when present in the
    # trace). The dast-init.sh script launches bpftrace as a root
    # sidecar before the privilege drop; entrypoint.py drains
    # /tmp/syscalls.jsonl at end-of-run and emits ONE
    # ``syscall_observations`` event. Pull it out of the trace
    # events, parse via parse_syscall_observations, attach to the
    # profile so Stage 2's prompt builder can render the summary.
    #
    # When the kernel doesn't support the required tracepoints (older
    # Firecracker kernels lacking CONFIG_FTRACE_SYSCALLS or
    # CONFIG_TRACEPOINTS for raw_syscalls), bpftrace fails to load
    # and the entrypoint emits ``syscall_observability_error``
    # instead. In that case profile.syscall_observations stays None
    # and Stage 2 falls back to language-instrumentation alone.
    try:
        from dast.syscall_observability import (  # noqa: PLC0415
            parse_syscall_observations,
        )
        from dataclasses import asdict as _asdict_local  # noqa: PLC0415

        for ev in trace.events:
            if ev.kind == "syscall_observations":
                obs = parse_syscall_observations(ev.payload)
                profile.syscall_observations = _asdict_local(obs)
                break
    except Exception as _merge_err:  # noqa: BLE001
        # Best-effort merge — never poison the profile if parsing
        # blows up. Stage 2 still works without the new signal.
        journal.append(
            JournalRecord(
                iter=iter_num,
                phase=JournalPhase.PHASE_B_HYPOTHESIS,
                claim_id=hid,
                verdict="inconclusive",
                rationale=(f"syscall_observations merge failed: {type(_merge_err).__name__}: {str(_merge_err)[:200]}"),
                evidence_refs=[],
            )
        )

    # Journal one informational record so operators can trace the probe's
    # presence. Verdict is "inconclusive" — Stage 1 doesn't make verdicts.
    evidence_ref = trace.events[0].event_id if trace.events else ""
    journal.append(
        JournalRecord(
            iter=iter_num,
            phase=JournalPhase.PHASE_B_HYPOTHESIS,
            claim_id=hid,
            verdict="inconclusive",
            rationale=(
                f"behavioral probe: explored {profile.callables_explored}/"
                f"{profile.callables_total} callables in "
                f"{profile.elapsed_ms}ms; dataflow_hints="
                f"{len(profile.dataflow_hints)}; "
                f"import_error={profile.import_error or 'none'}"
            ),
            evidence_refs=[evidence_ref] if evidence_ref else [],
        )
    )

    return asdict(profile)


def _iter_inner_sandbox_clients(sandbox: SandboxClient):
    """Yield each underlying SandboxClient — for MultiImageSandboxClient
    iterate the per-hint inners; for any other client yield itself.

    Phase C uses this to mutate file_content_map across all backing
    Firecracker clients when injecting the patched source.
    """
    inner_by_hint = getattr(sandbox, "inner_by_hint", None)
    if isinstance(inner_by_hint, dict):
        yield from inner_by_hint.values()
    else:
        yield sandbox


_GATE_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _build_gate_failure_evidence(outcome: Any, details: dict[str, Any]) -> str:
    """Render a verification-gate failure into retry feedback for the
    patch generator — concrete enough that the next attempt fixes the
    CLASS / preserves behavior instead of repeating the shallow fix."""
    parts: list[str] = []
    if outcome.functional_ok is False:
        f = details.get("functional") or {}
        parts.append(
            "FUNCTIONAL REGRESSION: the patch rejected a LEGITIMATE request "
            f"({f.get('benign_url') or 'a benign input'}). The fix must keep "
            "valid public hosts/inputs working — do not over-block."
        )
    fired = [v for v in (details.get("variants") or []) if v.get("result") == "FIRED"]
    if fired:
        lines = "; ".join(f"{v.get('description')}: {v.get('payload')}" for v in fired[:5])
        # Class-agnostic guidance: the variant descriptions already name the
        # technique that got through; tell the patcher to defeat the whole
        # class, not the specific payloads. (Do NOT bake in an SSRF-only
        # hint here — this feedback path serves every vuln class.)
        parts.append(
            f"BYPASS STILL WORKS: {len(fired)} same-class variant(s) reached the "
            f"target against the PATCHED code — [{lines}]. Defeat the underlying "
            "technique for the WHOLE vulnerability class (validate/encode against "
            "a positive model before the dangerous operation), not just the "
            "originally-reported payload or these specific variants."
        )
    return "\n".join(parts)


async def _run_phase_c_verify_gates(
    *,
    confirmed: list[dict],
    original_text: str,
    patched_source: str,
    patched_bytes: bytes,
    original_bytes: bytes,
    file_id: str,
    file_name: str,
    re_plans: list[dict],
    iter1_plans: list[dict],
    per_finding: list[dict],
    inference: InferenceFn,
    sandbox: SandboxClient,
) -> dict[str, Any]:
    """Run the Stage 2 (functional) + Stage 3 (adversarial) gates for a
    patch that already neutralized the reported PoC, and fold the result
    into a structured ``verification`` dict.

    Generation (LLM) runs first, lock-free; the variant/functional
    harnesses are then replayed against freshly re-injected patched bytes
    inside one per-sandbox content-lock window (Stage-1 restored the
    originals). Mutates ``per_finding`` in place to stamp each NEUTRALIZED
    finding with the gate confidence. Returns the verification dict with
    two private keys — ``_needs_retry`` / ``_failure_evidence`` — for the
    caller's attempt loop to pop.
    """
    import asyncio as _asyncio_g  # noqa: PLC0415

    from dast.phase_c_verify_gates import (  # noqa: PLC0415
        execute_gates,
        prepare_gate_plans,
    )
    from dast.remediation_verify import verify_budget_for  # noqa: PLC0415

    # Severity → verification budget (depth/spend). Max across findings.
    severity = "high"
    for h in confirmed:
        s = str(h.get("severity") or "").lower()
        if _GATE_SEV_RANK.get(s, 0) > _GATE_SEV_RANK.get(severity, 0):
            severity = s
    budget = verify_budget_for(severity)

    # Seed harness template: prefer a plan that actually replayed this
    # round (proven imports + entrypoint call shape); else first
    # executable iter-1 plan.
    seed_plan_dict: dict[str, Any] = {}
    for p in re_plans or []:
        if isinstance(p, dict) and p.get("commands"):
            seed_plan_dict = p
            break
    if not seed_plan_dict:
        for p in iter1_plans or []:
            if isinstance(p, dict) and p.get("plan_status") == "executable" and p.get("commands"):
                seed_plan_dict = p
                break
    seed_commands = [c for c in (seed_plan_dict.get("commands") or []) if isinstance(c, str)]
    seed_payload = str(seed_plan_dict.get("payload") or "")
    raw_hint = seed_plan_dict.get("image_hint")
    gate_image_hint = raw_hint if isinstance(raw_hint, str) and raw_hint else "lean"
    gate_timeout = int(seed_plan_dict.get("timeout_sec") or 30)

    # SSRF-class findings get the deterministic DNS-rebinding (TOCTOU)
    # probe in addition to the LLM encoding variants.
    ssrf_class = any(
        "918" in str(h.get("cwe") or "") or "ssrf" in str(h.get("type") or h.get("cwe") or "").lower()
        for h in confirmed
    )

    try:
        gate_plans = await prepare_gate_plans(
            inference=inference,
            file_name=file_name,
            confirmed_findings=confirmed,
            original_source=original_text,
            patched_source=patched_source,
            seed_commands=seed_commands,
            seed_payload=seed_payload,
            budget=budget,
            ssrf_class=ssrf_class,
        )

        # Re-inject patched bytes (Stage-1 restored originals) and replay
        # the gate harnesses in one locked window.
        gate_locks: list[Any] = []
        for client in _iter_inner_sandbox_clients(sandbox):
            lk = getattr(client, "_phase_c_content_lock", None)
            if lk is None:
                lk = _asyncio_g.Lock()
                try:
                    setattr(client, "_phase_c_content_lock", lk)  # noqa: B010
                except (AttributeError, TypeError):
                    pass
            gate_locks.append(lk)
        for lk in gate_locks:
            await lk.acquire()
        try:
            for client in _iter_inner_sandbox_clients(sandbox):
                cmap = getattr(client, "file_content_map", None)
                if isinstance(cmap, dict):
                    cmap[file_id] = patched_bytes

            async def _submit_patched(plan: SandboxPlan) -> Any:
                return await sandbox.submit(plan)

            outcome, details = await execute_gates(
                plans=gate_plans,
                submit_patched=_submit_patched,
                file_id=file_id,
                file_name=file_name,
                image_hint=gate_image_hint,
                timeout_sec=gate_timeout,
                severity=severity,
                poc_refuted=True,  # caller guarantees n_neutralized > 0
                budget=budget,
            )
        finally:
            for client in _iter_inner_sandbox_clients(sandbox):
                cmap = getattr(client, "file_content_map", None)
                if isinstance(cmap, dict):
                    cmap[file_id] = original_bytes
            for lk in gate_locks:
                try:
                    lk.release()
                except (RuntimeError, ValueError):
                    pass

        # Stamp gate confidence onto every NEUTRALIZED finding.
        for pf in per_finding:
            if pf.get("post_patch_status") == "NEUTRALIZED":
                pf["confidence"] = outcome.confidence

        verification: dict[str, Any] = {
            "confidence": outcome.confidence,
            "severity": severity,
            "budget": {
                "functional": budget.functional,
                "variants": budget.variants,
                "retries": budget.retries,
                "max_usd": budget.max_usd,
            },
            "functional_ok": outcome.functional_ok,
            "functional": details.get("functional"),
            "variants_total": outcome.variants_total,
            "variants_fired": outcome.variants_fired,
            "variants": details.get("variants") or [],
            "notes": (gate_plans.notes or []) + (outcome.notes or []),
            "gate_errors": details.get("errors") or [],
            "n_sandbox_calls": details.get("n_sandbox_calls", 0),
            "tokens_in": gate_plans.tokens_in,
            "tokens_out": gate_plans.tokens_out,
            "_needs_retry": outcome.needs_retry,
            "_failure_evidence": (_build_gate_failure_evidence(outcome, details) if outcome.needs_retry else ""),
        }
        return verification
    except Exception as exc:  # noqa: BLE001
        return {
            "attempted": True,
            "error": f"{type(exc).__name__}: {str(exc)[:240]}",
            "_needs_retry": False,
            "_failure_evidence": "",
            "tokens_in": 0,
            "tokens_out": 0,
            "n_sandbox_calls": 0,
        }


async def _run_phase_c_fix_verify(
    *,
    file_record: dict,
    findings_validated: list[str],
    l1_output: dict,
    iter1_plans: list[dict],
    inference: InferenceFn,
    sandbox: SandboxClient,
    journal: Journal,
    dast_findings: list[dict] | None = None,
    dast_plans: list[dict] | None = None,
    enable_verify_gates: bool = False,
    gate_inference: InferenceFn | None = None,
    prior_feedback: str | None = None,
) -> dict[str, Any]:
    """Phase C (v1.2 → v14): generate a patch for confirmed findings,
    then re-test the original exploit plans against the patched source.

    v14 hardening (2026-05-17):
      * **Fix #1+#5 — DAST findings included.** Previously, only L1
        hypotheses fed ``hyp_by_ref`` and only iter-1 L1 plans were
        replayed. DAST-discovered findings (Phase 3 Stage 2 NEW attack
        classes, Phase B+ runtime probes, Phase 2 chains) were silently
        dropped. ``dast_findings`` + ``dast_plans`` kwargs let the
        caller pass synthetic hyp dicts + corresponding plans for each
        DAST-confirmed finding so they get patched + verified too.
      * **Fix #2 — patched_source syntax validation.** ``ast.parse``
        (Python) / ``node --check`` (JS) fail-fast before sandbox
        replay so we surface ``patch_syntax_invalid`` instead of
        misclassifying all-replays-failed as a separate condition.
      * **Fix #3 — diff-size sanity.** Reject patches that are
        byte-identical to the original (model returned no change) or
        whose size delta is wildly suspicious (<20% or >300% of
        original; common model failure modes).
      * **Fix #4 — empty source_text guard.** Fail-fast before
        generating a patch against an empty file.

    Returns a dict with patched_source, fix_summary, post-patch verdict,
    and per-finding neutralization status. Caller is expected to surface
    this in DastResult.phase_c — no journal records are written to keep
    Phase C effects visible only in the structured result.
    """
    started = time.time()
    file_id = file_record.get("file_id", "")
    file_name = file_record.get("file_name", "unknown")
    original_text = file_record.get("source_text", "") or ""

    # v14 Fix #4: empty source_text guard. Without source we cannot
    # generate or verify a meaningful patch.
    if not original_text.strip():
        return {
            "attempted": False,
            "skipped_reason": "no_source_text",
            "elapsed_s": round(time.time() - started, 2),
        }

    original_bytes = original_text.encode("utf-8", errors="replace")

    # Find the L1 hypothesis dicts that correspond to confirmed findings,
    # so we can hand the patcher the L1-suggested fix as a starting point.
    # Index by both id and finding_ref since journal claim_id ↔ hypothesis
    # id, but findings_validated may use either form.
    hyp_by_ref: dict[str, dict] = {}
    for h in l1_output.get("hypotheses") or []:
        if not isinstance(h, dict):
            continue
        h_id = h.get("id")
        h_ref = h.get("finding_ref")
        if h_id:
            hyp_by_ref[h_id] = h
        if h_ref and h_ref != h_id:
            hyp_by_ref[h_ref] = h

    # v14 Fix #1: also index DAST-discovered findings so they get
    # patched + verified along with L1 findings. Without this, Phase 3
    # Stage 2 zero-day-class outcomes were silently dropped from the
    # confirmed set; Phase C would patch only L1 findings and never
    # test the patch against the Stage 2 exploit, so the Stage 2 vuln
    # could survive a "NEUTRALIZED" report.
    for df in dast_findings or []:
        if not isinstance(df, dict):
            continue
        d_id = df.get("id") or df.get("finding_ref") or df.get("hypothesis_id")
        d_ref = df.get("finding_ref")
        if d_id:
            hyp_by_ref.setdefault(str(d_id), df)
        if d_ref and d_ref != d_id:
            hyp_by_ref.setdefault(str(d_ref), df)

    confirmed = [hyp_by_ref[ref] for ref in findings_validated if ref in hyp_by_ref]

    if not confirmed:
        return {
            "attempted": False,
            "skipped_reason": "no_confirmed_findings_with_finding_ref",
            "elapsed_s": round(time.time() - started, 2),
        }

    # ── Binary-artifact guard ────────────────────────────────────────
    # Phase C's patch generator produces a ``patched_source`` text blob
    # which the replay step writes back as the "fixed" file. That works
    # for source-code artifacts but is WRONG for binary ML files
    # (.pkl/.pt/.bin/.safetensors/.h5/.onnx) — the model can't emit
    # valid binary bytes, so a text "patch" of a pickle is corrupt and
    # the replay would load garbage. Instead we emit structured
    # remediation guidance: replace the artifact with safetensors,
    # don't auto-patch. Phase C status is UNVERIFIABLE because we did
    # NOT run a sandbox replay against a synthetic fix — we declined.
    ml_format = file_record.get("ml_format")
    if ml_format:
        guidance_summary = (
            f"Argus does not auto-patch {ml_format} artifacts in v1.2: "
            "binary model files cannot be safely text-edited and a "
            "model-emitted byte-level patch would not be verifiable. "
            "Recommended remediation: regenerate the model from a clean "
            "training pipeline and serialize using `safetensors` instead "
            "of pickle / torch.save() — safetensors is structurally "
            "incapable of carrying executable __reduce__ payloads. If a "
            "safetensors version isn't available, treat the artifact as "
            "discardable."
        )
        return {
            "attempted": False,
            "skipped_reason": "binary_artifact_remediation_is_replacement_not_patch",
            "ml_format": ml_format,
            "fix_summary": guidance_summary,
            "post_patch_verdict": "UNVERIFIABLE",
            "per_finding": [
                {
                    "finding_id": h.get("id") or h.get("finding_ref"),
                    "post_patch_status": "UNVERIFIABLE",
                    "rationale": (
                        "Binary ML artifact — Argus declined to auto-patch. See fix_summary for remediation guidance."
                    ),
                }
                for h in confirmed
            ],
            "n_neutralized": 0,
            "n_still_exploitable": 0,
            "elapsed_s": round(time.time() - started, 2),
        }

    # ── Step 1: generate patch ────────────────────────────────────────
    fix_prompt = dast_prompts.build_phase_c_fix_prompt(
        file_name=file_name,
        original_source=original_text,
        confirmed_findings=confirmed,
        prior_feedback=prior_feedback,
    )
    fix_resp = await inference(
        fix_prompt,
        {"temperature": 0.0, "max_tokens": 8192, "seed": 0},
        dast_prompts.phase_c_fix_schema(),
    )
    fix_obj = _parse_json_or_empty(fix_resp.get("text", ""))
    patched_source = (fix_obj.get("patched_source") or "").strip()
    fix_summary = (fix_obj.get("fix_summary") or "").strip()
    per_finding_fixes = fix_obj.get("per_finding_fixes") or []
    fix_in = (fix_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
    fix_out = (fix_resp.get("usage") or {}).get("completion_tokens", 0) or 0

    if not patched_source:
        return {
            "attempted": True,
            "patched_source": None,
            "fix_summary": fix_summary,
            "skipped_reason": "patch_generation_returned_empty",
            "tokens_in": fix_in,
            "tokens_out": fix_out,
            "elapsed_s": round(time.time() - started, 2),
        }

    # ── v14 Fix #3: diff-size sanity ──────────────────────────────────
    # Reject byte-identical patches (model returned the input unchanged)
    # and patches with wildly suspicious size deltas (common model
    # failure modes: returned `# safe` truncation, hallucinated a
    # different file entirely, dropped 80%+ of the source). Without
    # this, "n_neutralized" can falsely report NEUTRALIZED when the
    # exploit simply doesn't reproduce against a broken-shape file.
    # Compare patched_source against original_text.strip() because
    # patched_source went through .strip() during JSON extraction —
    # we'd otherwise miss byte-identical patches when the original
    # has trailing whitespace.
    if patched_source == original_text.strip():
        return {
            "attempted": True,
            "patched_source": None,
            "fix_summary": fix_summary,
            "skipped_reason": "patch_byte_identical_to_original",
            "tokens_in": fix_in,
            "tokens_out": fix_out,
            "elapsed_s": round(time.time() - started, 2),
        }
    orig_len = len(original_text)
    new_len = len(patched_source)
    # Bounds: <20% of original (truncation/stub) or > max(3×, original +
    # 8 KB) (likely a hallucinated wrong file) is rejected. The absolute
    # headroom is load-bearing for SHORT seed functions: a correct,
    # class-complete fix to a tiny file is large in ABSOLUTE terms — e.g.
    # a proper SSRF mitigation (resolve host→IP via socket.getaddrinfo +
    # ipaddress private/loopback/link-local/reserved checks + a helper +
    # docstrings) runs ~4–6 KB regardless of how small the original was.
    # The 2 KB headroom we used pre-2026-06 rejected exactly those real
    # fixes. Size alone can't distinguish a thorough fix from bloat —
    # correctness is enforced downstream by the syntax check + sandbox
    # replay + the verification gates — so this stays permissive and only
    # catches egregious truncation / whole-file hallucination. 3× ratio
    # still governs large originals (permits a proportional rewrite).
    upper_bound = max(orig_len * 3.0, orig_len + 8192)
    if orig_len > 100 and (new_len < orig_len * 0.20 or new_len > upper_bound):
        return {
            "attempted": True,
            "patched_source": patched_source[:2000],  # preview only
            "fix_summary": fix_summary,
            "skipped_reason": "patch_size_suspicious",
            "size_delta": {"original_chars": orig_len, "patched_chars": new_len},
            "tokens_in": fix_in,
            "tokens_out": fix_out,
            "elapsed_s": round(time.time() - started, 2),
        }

    # ── v14 Fix #2: syntax validation on patched source ───────────────
    # If the model emitted syntactically-invalid code, every replay
    # would error with SyntaxError and we'd punt with all_replays_failed.
    # That misclassifies "model generated garbage" as a sandbox
    # infrastructure problem. Detect it explicitly here.
    syntax_err = ""
    lower_name = (file_name or "").lower()
    if lower_name.endswith((".py", ".pth")):
        try:
            import ast as _ast_local  # noqa: PLC0415

            _ast_local.parse(patched_source, filename=file_name)
        except SyntaxError as exc:
            syntax_err = f"SyntaxError at line {exc.lineno}: {(exc.msg or '')[:120]}"
    elif lower_name.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
        # JS/TS: shell out to node --check. Bounded by 5s.
        import subprocess as _subprocess_local  # noqa: PLC0415
        import tempfile as _tempfile_local  # noqa: PLC0415

        suffix = ".cjs" if lower_name.endswith((".js", ".cjs")) else ".mjs"
        # tsx for .ts handles type-stripping; node --check parses TS as
        # JS which would false-positive on type annotations. So only
        # check JS-shaped files; TS we trust the model.
        if suffix in (".cjs", ".mjs"):
            try:
                with _tempfile_local.NamedTemporaryFile(
                    mode="w",
                    suffix=suffix,
                    delete=False,
                    encoding="utf-8",
                ) as tf:
                    tf.write(patched_source)
                    tf_path = tf.name
                try:
                    res = _subprocess_local.run(
                        ["node", "--check", tf_path],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if res.returncode != 0:
                        syntax_err = f"node --check failed: {(res.stderr or '')[:200]}"
                finally:
                    try:
                        import os as _os_local  # noqa: PLC0415

                        _os_local.unlink(tf_path)
                    except OSError:
                        pass
            except (OSError, _subprocess_local.TimeoutExpired) as exc:
                # node not present or timed out — don't block on the
                # check; let the replay surface real errors instead.
                syntax_err = ""
    if syntax_err:
        return {
            "attempted": True,
            "patched_source": patched_source[:2000],  # preview only
            "fix_summary": fix_summary,
            "skipped_reason": "patch_syntax_invalid",
            "syntax_error": syntax_err,
            "tokens_in": fix_in,
            "tokens_out": fix_out,
            "elapsed_s": round(time.time() - started, 2),
        }

    # ── Step 2: replay iter-1 plans against the patched source ────────
    patched_bytes = patched_source.encode("utf-8", errors="replace")
    re_traces: list[dict] = []
    re_plans: list[dict] = []
    replay_errors: list[dict[str, Any]] = []  # v14 B5: surface failures
    n_replays = 0
    # v14 B4: serialize Phase C's content-map mutation under an
    # asyncio.Lock so concurrent scans on the same backing sandbox
    # client can't observe each other's patched bytes. The lock is
    # held for the entire inject → replay → restore window. Without
    # this, a concurrent scan on file_id=X while we're mid-replay on
    # file_id=Y could see Y's patched bytes mistakenly attributed to
    # X — silent verdict cross-contamination.
    #
    # Each sandbox client owns its own lock attached at runtime; if
    # it's not present we create a fresh one on the fly. The
    # serialization is per-client, so independent sandbox clients on
    # different Fly machines don't block each other.
    _phase_c_locks: list[Any] = []
    try:
        import asyncio as _asyncio_local  # noqa: PLC0415

        for client in _iter_inner_sandbox_clients(sandbox):
            existing_lock = getattr(client, "_phase_c_content_lock", None)
            if existing_lock is None:
                existing_lock = _asyncio_local.Lock()
                try:
                    setattr(client, "_phase_c_content_lock", existing_lock)
                except (AttributeError, TypeError):
                    pass  # frozen / immutable client — fall through
            _phase_c_locks.append(existing_lock)

        # Acquire ALL per-client locks (in deterministic order to avoid
        # cross-client deadlock if multiple Phase C calls race). Then
        # inject; the locks are held until the finally block restores.
        for lock in _phase_c_locks:
            await lock.acquire()

        # Inject patched content into every backing sandbox's content map
        for client in _iter_inner_sandbox_clients(sandbox):
            cmap = getattr(client, "file_content_map", None)
            if isinstance(cmap, dict):
                cmap[file_id] = patched_bytes

        # v14 Fix #5: replay BOTH iter-1 L1 plans AND any DAST-discovered
        # plans (Phase 3 Stage 2, Phase B+, Phase 2 chains) that
        # confirmed exploits. Without this, Phase C would generate a
        # patch for L1 findings, replay only L1 plans, and report
        # NEUTRALIZED even if the Stage 2 zero-day still works against
        # the patched source.
        all_replay_plans: list[dict] = list(iter1_plans or [])
        seen_hids = {p.get("hypothesis_id") for p in all_replay_plans if isinstance(p, dict) and p.get("hypothesis_id")}
        for dp in dast_plans or []:
            if not isinstance(dp, dict):
                continue
            hid = dp.get("hypothesis_id")
            # Deduplicate by hypothesis_id so a DAST hypothesis whose
            # plan happens to overlap with an L1 plan doesn't get
            # replayed twice (wastes sandbox budget).
            if hid and hid in seen_hids:
                continue
            all_replay_plans.append(dp)
            if hid:
                seen_hids.add(hid)

        # Re-submit each plan with a fresh plan_id so the journal can
        # distinguish Phase C runs from the original iter-1 ones.
        for p in all_replay_plans:
            if not isinstance(p, dict):
                continue
            if p.get("plan_status") != "executable":
                continue
            hid = p.get("hypothesis_id", "")
            raw_hint = p.get("image_hint")
            image_hint = raw_hint if isinstance(raw_hint, str) and raw_hint else "lean"
            plan = SandboxPlan(
                plan_id=f"phaseC-{hid}",
                file_id=file_id,
                hypothesis_id=hid,
                commands=p.get("commands") or [],
                expected_oracle=p.get("oracle") or "",
                payload=p.get("payload") or "",
                timeout_sec=int(p.get("timeout_sec") or 30),
                image_hint=image_hint,
                file_name=file_name,
                synthesis_context={
                    "phase": "C",
                    "purpose": "fix_verify",
                    "patched": True,
                },
            )
            try:
                trace = await sandbox.submit(plan)
                re_traces.append(trace.model_dump())
                re_plans.append(p)
                n_replays += 1
            except Exception as replay_exc:  # noqa: BLE001
                # v14 B5: surface replay failures explicitly instead of
                # silently swallowing. Without this, a sandbox timeout
                # or Fly 403 makes the per-finding loop mark the
                # finding NEUTRALIZED even though the patched plan
                # never executed.
                replay_errors.append(
                    {
                        "hypothesis_id": hid,
                        "plan_id": plan.plan_id,
                        "exception_type": type(replay_exc).__name__,
                        "exception_msg": str(replay_exc)[:240],
                    }
                )
                continue
    finally:
        # ALWAYS restore original content so subsequent operations
        # (e.g., engine post-DAST hooks) see the unpatched file.
        for client in _iter_inner_sandbox_clients(sandbox):
            cmap = getattr(client, "file_content_map", None)
            if isinstance(cmap, dict):
                cmap[file_id] = original_bytes
        # Release all per-client locks acquired above.
        for lock in _phase_c_locks:
            try:
                lock.release()
            except (RuntimeError, ValueError):
                # Lock wasn't held or was released elsewhere — log
                # but don't raise; we're in a finally block.
                pass

    # ── Step 3: re-run Phase A verdict against the new traces ────────
    # Use patched_source as file_text so the verdict-judge sees the
    # actual code that was tested. Empty journal_summary because Phase C
    # is a fresh evaluation, not a continuation of prior iters.
    if not re_traces:
        return {
            "attempted": True,
            "patched_source": patched_source,
            "fix_summary": fix_summary,
            "per_finding_fixes": per_finding_fixes,
            "skipped_reason": "all_replays_failed",
            "tokens_in": fix_in,
            "tokens_out": fix_out,
            "n_replays": 0,
            # v14 B5: surface why every replay failed (sandbox timeout,
            # Fly 403, network jitter, etc.) so operators can correlate
            # the all_replays_failed verdict with the underlying cause.
            "replay_errors": replay_errors,
            "n_replay_errors": len(replay_errors),
            "elapsed_s": round(time.time() - started, 2),
        }

    verdict_prompt = dast_prompts.build_phase_a_verdict_prompt(
        file_text=patched_source,
        l1_output=l1_output,
        plans=re_plans,
        traces=re_traces,
        journal_summary={
            "phase_c_replay": True,
            "note": (
                "These traces are from re-running the original "
                "iter-1 plans against a PATCHED version of the file. "
                "If the patch neutralized the exploit, the traces should "
                "show no oracle hits."
            ),
        },
        # Replay calibration: absence of the original exploit effect means
        # the patch NEUTRALIZED it (refuted), not 'inconclusive' — so a
        # good patch reaches NEUTRALIZED and the functional/adversarial
        # gates run, instead of stalling at UNVERIFIABLE.
        replay_mode=True,
    )
    verdict_resp = await inference(
        verdict_prompt,
        {"temperature": 0.0, "max_tokens": 6144, "seed": 0},
        dast_prompts.phase_a_verdict_schema(),
    )
    verdict_obj = _parse_json_or_empty(verdict_resp.get("text", ""))
    cur = (verdict_obj.get("current_verdict") or {}) if isinstance(verdict_obj, dict) else {}
    post_patch_verdict = cur.get("verdict_label", "unknown")
    new_claim_verdicts = (verdict_obj.get("claim_verdicts") or []) if isinstance(verdict_obj, dict) else []
    new_v_by_hid = {cv.get("hypothesis_id"): cv.get("verdict") for cv in new_claim_verdicts if isinstance(cv, dict)}

    verdict_in = (verdict_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
    verdict_out = (verdict_resp.get("usage") or {}).get("completion_tokens", 0) or 0

    # ── Step 4: per-finding NEUTRALIZED / STILL_EXPLOITABLE / UNVERIFIABLE
    from dast.remediation_verify import compute_confidence  # noqa: PLC0415

    per_finding: list[dict] = []
    for ref in findings_validated:
        h = hyp_by_ref.get(ref) or {}
        hid = h.get("id") or ref
        new_v = new_v_by_hid.get(hid)
        status = _post_patch_status(new_v)
        # Patch-confidence for a NEUTRALIZED claim. Stage 1: based on the
        # original-PoC replay ONLY (no functional / adversarial gates yet),
        # so a verified-refuted finding is LOW confidence by construction —
        # honest until those gates raise it. Non-NEUTRALIZED findings carry
        # no confidence (nothing was claimed fixed).
        confidence = None
        if status == "NEUTRALIZED":
            confidence = compute_confidence(
                poc_refuted=True,
                functional_ok=None,
                variants_total=0,
                variants_fired=0,
            )
        per_finding.append(
            {
                "finding_ref": ref,
                "hypothesis_id": hid,
                "original_status": "CONFIRMED",
                "post_patch_status": status,
                "post_patch_verdict": new_v or "unknown",
                "confidence": confidence,
            }
        )

    n_neutralized = sum(1 for pf in per_finding if pf["post_patch_status"] == "NEUTRALIZED")
    n_still_exploitable = sum(1 for pf in per_finding if pf["post_patch_status"] == "STILL_EXPLOITABLE")

    # ── Step 5 (v15) — verified-remediation gates (Stage 2 + Stage 3) ──
    # The original-PoC replay above only proves the REPORTED exploit no
    # longer fires (a LOW-confidence signal). When enabled, run the
    # functional-preservation + adversarial-variant gates to upgrade a
    # bare NEUTRALIZED into a CONFIDENCE-rated, class-complete verdict.
    # The retry decision (regenerate the patch with this failure as
    # feedback) is taken by the caller, which owns the attempt budget.
    verification: dict[str, Any] | None = None
    needs_retry = False
    failure_evidence = ""
    gate_sandbox_calls = 0
    if enable_verify_gates and n_neutralized > 0:
        verification = await _run_phase_c_verify_gates(
            confirmed=confirmed,
            original_text=original_text,
            patched_source=patched_source,
            patched_bytes=patched_bytes,
            original_bytes=original_bytes,
            file_id=file_id,
            file_name=file_name,
            re_plans=re_plans,
            iter1_plans=iter1_plans or [],
            per_finding=per_finding,
            inference=gate_inference or inference,
            sandbox=sandbox,
        )
        if verification:
            needs_retry = bool(verification.pop("_needs_retry", False))
            failure_evidence = str(verification.pop("_failure_evidence", "") or "")
            gate_sandbox_calls = int(verification.get("n_sandbox_calls", 0) or 0)
            fix_in += int(verification.get("tokens_in", 0) or 0)
            fix_out += int(verification.get("tokens_out", 0) or 0)

    return {
        "attempted": True,
        "patched_source": patched_source,
        "fix_summary": fix_summary,
        "per_finding_fixes": per_finding_fixes,
        "post_patch_verdict": post_patch_verdict,
        "per_finding": per_finding,
        "n_neutralized": n_neutralized,
        "n_still_exploitable": n_still_exploitable,
        "n_unverifiable": len(per_finding) - n_neutralized - n_still_exploitable,
        "n_replays": n_replays + gate_sandbox_calls,
        # v15: verified-remediation gate results (None when gates disabled
        # or nothing was neutralized). Carries the confidence label, the
        # per-variant fire results, and the functional-preservation check.
        "verification": verification,
        # Retry signals for the caller's attempt loop (popped from
        # verification so they don't leak into the public report).
        "needs_retry": needs_retry,
        "failure_evidence": failure_evidence,
        # v14 B5: surface per-plan replay failures instead of silently
        # masking them. Operators can correlate NEUTRALIZED claims with
        # the underlying sandbox health; a NEUTRALIZED with 5 replay
        # errors is much weaker signal than NEUTRALIZED with zero.
        "replay_errors": replay_errors,
        "n_replay_errors": len(replay_errors),
        "tokens_in": fix_in + verdict_in,
        "tokens_out": fix_out + verdict_out,
        "elapsed_s": round(time.time() - started, 2),
    }
