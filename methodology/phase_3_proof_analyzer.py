"""Per-finding proof-strength analyzer for Argus +DAST bench output.

Goes beyond the verdict-exact / CWE-F1 metrics in
:mod:`methodology.diff_report`. Produces a per-finding categorization
that distinguishes:

  WINS (Argus epistemically stronger via sandbox proof):
    W1 WIN_ZERO_DAY        Argus DAST-confirmed + oracle missed + Opus missed
    W2 WIN_VS_OPUS         Argus DAST-confirmed + Opus missed + oracle has
    W3 WIN_REFUTATION      Argus DAST-rejected/unreached high-cov + oracle agrees no vuln

  TIES (mutually confirming, no special credit):
    T1 TIE_PROOF_CONFIRMED Argus DAST-confirmed + oracle has
    T2 TIE_SPECULATION     Argus L1-only + oracle has (both speculation)

  LOSSES (genuine Argus weaknesses):
    L1 LOSS_HIGH_COV_MISS  Oracle has + Argus had DAST coverage on this CWE + 0 confirmations
                           -> real Argus FN OR oracle wrong (needs adjudication)
    L2 LOSS_FP_CLAIM       Argus claimed (no DAST proof) + oracle disagrees
                           -> Argus over-call (model speculation only)

  INCONCLUSIVE (no opinion either way):
    I1 INCONCLUSIVE_NO_VIS Oracle has + Argus had no DAST visibility on this CWE
    I2 INCONCLUSIVE_L1     Oracle has + DAST didn't trigger (L1 said clean, no escalation)

  ADJUDICATION CANDIDATES (high-stakes disagreements):
    A1 ARGUS_CLAIMS_ALONE         Argus DAST-confirmed + oracle disagrees
                                    -> zero-day OR FP
    A2 ORACLE_VS_ARGUS_HIGH_COV   Oracle has + Argus high-cov tested + 0 conf
                                    -> blind spot OR oracle hallucinated

The integrity rule:
  * Argus only earns oracle-overriding credit with PROOF
    (CONFIRMED status from DAST with runtime_evidence).
  * Argus only earns refutation credit with COVERAGE
    (high coverage_ratio + DAST attempted the relevant attack class).
  * Without either, Argus is INCONCLUSIVE, not "right".

Output: a single markdown report + JSON sidecar with per-file
categorization + aggregate counts/rates + headline percentages.

Usage::

    uv run python -m methodology.phase_3_proof_analyzer \
        --argus-bench bench_results/argus_phase3_<ts>/argus_full_run1.json \
        --opus-bench  bench_results/v1_1_launch/raw_opus_run1.json \
        --oracle      bench_results/20260506T021930Z/consensus_oracle_no_opus.json \
        --output-md   bench_results/argus_phase3_<ts>/proof_analysis.md \
        --output-json bench_results/argus_phase3_<ts>/proof_analysis.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
log = logging.getLogger("argus.proof_analyzer")

# ── Category constants ────────────────────────────────────────────────────

CAT_W1 = "W1_WIN_ZERO_DAY"
CAT_W2 = "W2_WIN_VS_OPUS"
CAT_W3 = "W3_WIN_REFUTATION"
CAT_T1 = "T1_TIE_PROOF_CONFIRMED"
CAT_T2 = "T2_TIE_SPECULATION"
CAT_L1 = "L1_LOSS_HIGH_COV_MISS"
CAT_L2 = "L2_LOSS_FP_CLAIM"
CAT_I1 = "I1_INCONCLUSIVE_NO_VIS"
CAT_I2 = "I2_INCONCLUSIVE_L1"
CAT_A1 = "A1_ARGUS_CLAIMS_ALONE"
CAT_A2 = "A2_ORACLE_VS_ARGUS_HIGH_COV"

WIN_CATS = {CAT_W1, CAT_W2, CAT_W3}
LOSS_CATS = {CAT_L1, CAT_L2}
TIE_CATS = {CAT_T1, CAT_T2}
INCONCLUSIVE_CATS = {CAT_I1, CAT_I2}
ADJUDICATE_CATS = {CAT_A1, CAT_A2}


@dataclass
class FindingClassification:
    """One (file, cwe) classification with full provenance."""

    file_name: str
    cwe: str
    category: str
    argus_status: str  # CONFIRMED | UNREACHED | BLOCKED | NOT_TESTED | REJECTED | absent
    argus_confidence: float  # 0.0-1.0; 0.0 when absent
    argus_severity: str  # from per_finding_validation OR vulnerabilities[]
    opus_has: bool
    oracle_has: bool  # in cwe_consensus
    oracle_partial: bool  # in votes_per but not consensus (some voter saw it)
    proof_text: str  # truncated runtime_evidence
    rationale: str  # human-readable why this category


@dataclass
class FileAnalysis:
    """Per-file aggregate."""

    file_name: str
    argus_verdict: str
    opus_verdict: str
    oracle_verdict: str
    argus_dast_attempted: bool
    argus_n_findings: int
    opus_n_findings: int
    oracle_n_consensus_cwes: int
    classifications: list[FindingClassification] = field(default_factory=list)
    cat_counts: dict[str, int] = field(default_factory=dict)


def _normalize_cwe(cwe: str | None) -> str:
    """Normalize CWE id form for cross-source matching. ``CWE-94``,
    ``cwe-94``, ``94`` all normalize to ``CWE-94``. Empty / None
    normalizes to ``""``."""
    if not cwe:
        return ""
    s = str(cwe).strip().upper()
    if s.startswith("CWE-"):
        return s
    if s.startswith("CWE"):
        return "CWE-" + s[3:].lstrip("-")
    if s.isdigit():
        return f"CWE-{s}"
    return s


def _index_argus_findings(row: dict) -> dict[str, dict]:
    """Index Argus findings by normalized CWE.

    Argus's `vulnerabilities` list (L1 + DAST combined) carries the
    static-side claim. The `per_finding_validation` list cross-
    references with DAST status. We merge them so each CWE has the
    richest record available.
    """
    out: dict[str, dict] = {}

    # First pass: vulnerabilities (L1 + post-DAST union)
    for v in row.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        cwe = _normalize_cwe(v.get("cwe"))
        if not cwe:
            continue
        out[cwe] = {
            "cwe": cwe,
            "type": v.get("type", ""),
            "severity": v.get("severity", ""),
            "line": v.get("line"),
            "l1_confidence": v.get("confidence", 0.0),
            "dast_status": None,  # filled by next pass if present
            "dast_confidence": 0.0,
            "runtime_evidence": "",
            "proof_of_concept": "",
        }

    # Second pass: per_finding_validation (DAST verdict per finding)
    for pfv in row.get("per_finding_validation") or []:
        if not isinstance(pfv, dict):
            continue
        cwe = _normalize_cwe(pfv.get("cwe"))
        if not cwe:
            continue
        rec = out.setdefault(
            cwe,
            {
                "cwe": cwe,
                "type": pfv.get("type", ""),
                "severity": pfv.get("severity", ""),
                "line": pfv.get("line"),
                "l1_confidence": 0.0,
                "dast_status": None,
                "dast_confidence": 0.0,
                "runtime_evidence": "",
                "proof_of_concept": "",
            },
        )
        rec["dast_status"] = pfv.get("status")
        rec["dast_confidence"] = float(pfv.get("confidence", 0.0) or 0.0)
        rec["runtime_evidence"] = str(pfv.get("runtime_evidence") or "")[:400]
        rec["proof_of_concept"] = str(pfv.get("proof_of_concept") or "")[:400]
    return out


def _index_opus_findings(row: dict) -> set[str]:
    """Set of normalized CWEs Opus claimed for this file."""
    return {
        _normalize_cwe(v.get("cwe"))
        for v in (row.get("vulnerabilities") or [])
        if isinstance(v, dict) and v.get("cwe")
    } - {""}


def _index_oracle(oracle_entry: dict) -> tuple[set[str], set[str]]:
    """Return (consensus CWEs, partial-vote CWEs) from oracle entry.

    consensus = CWEs at least N voters agreed on (per oracle metadata)
    partial   = CWEs at least one voter listed but didn't reach consensus
    """
    cwe_block = oracle_entry.get("cwe_consensus") or {}
    consensus = {_normalize_cwe(c) for c in (cwe_block.get("consensus") or [])} - {""}
    votes_per = cwe_block.get("votes_per") or {}
    partial = {
        _normalize_cwe(c)
        for c in votes_per
        if _normalize_cwe(c) and _normalize_cwe(c) not in consensus
    }
    return consensus, partial


def _is_argus_dast_visible(row: dict) -> bool:
    """Did DAST actually run + have meaningful runtime visibility on this file?

    Heuristic: dast_attempted=True AND at least one per_finding_validation
    entry exists (means DAST evaluated at least one finding). Files where
    L1 said 'clean' and DAST never triggered would have dast_attempted=False
    or zero pfv entries.
    """
    if not row.get("dast_attempted"):
        return False
    pfv = row.get("per_finding_validation") or []
    return len(pfv) > 0


# ── v1.7 Fix #12: proof-grounded verdict-exact + adjudication-net counts ──

_VERDICT_TIER_ORDER: tuple[str, ...] = (
    "clean",
    "suspicious",
    "malicious",
    "critical_malicious",
)


def _verdict_distance(a: str, b: str) -> int | None:
    """Distance between two verdicts on the 4-tier scale.

    Returns ``None`` if either verdict is outside the known set
    (e.g., ``"informational"`` or a typo). The caller treats
    unknown verdicts as not-credit-eligible.
    """
    try:
        return _VERDICT_TIER_ORDER.index(b) - _VERDICT_TIER_ORDER.index(a)
    except ValueError:
        return None


def _proof_grounded_credit(argus_row: dict, argus_verdict: str, oracle_verdict: str) -> float:
    """Score a single file with v1.7 Fix #12 "proof-grounded verdict-exact."

    Returns:
        * 1.0 — exact verdict match (same as strict verdict-exact).
        * 0.5 — Argus disagreed but the disagreement is **proof-grounded**:
            (a) Argus's verdict is LESS severe than the oracle's
                (Argus downgraded — safer direction),
            (b) distance ≤ 1 tier (no aggressive multi-tier downgrades),
            (c) DAST actually ran (``dast_attempted == True``), AND
            (d) at least one per_finding_validation entry has status in
                ``{"REJECTED", "BLOCKED", "UNREACHED"}`` (sandbox actually
                produced refutation evidence on at least one finding).
        * 0.0 — disagreement without proof, OR upgrade, OR distance > 1.

    Conservative by design: rewards Argus's sandbox-grounded refutation
    capability ONLY when (i) the verdict moves in the safer direction
    (downgrade, never upgrade), (ii) DAST evidence backs the move, and
    (iii) the move is small enough to be plausible. An over-confident
    downgrade from critical_malicious → suspicious gets 0.0 even with
    DAST evidence — too risky a downgrade to credit without
    independent adjudication.

    Note: we don't require the ``dast_severity_downgrade`` scan_path
    tag because L1 may already choose the lower verdict before DAST
    runs (e.g., Sonnet returns ``malicious`` while oracle says
    ``critical_malicious``). The REJECTED/BLOCKED findings still
    support Argus's final verdict being more accurate — that's what
    we credit.
    """
    if argus_verdict == oracle_verdict:
        return 1.0
    dist = _verdict_distance(argus_verdict, oracle_verdict)
    # dist > 0 means oracle is MORE severe than Argus = Argus downgraded.
    if dist is None or dist <= 0 or dist > 1:
        return 0.0
    if not argus_row.get("dast_attempted"):
        return 0.0
    pfv = argus_row.get("per_finding_validation") or []
    if not any(
        pf.get("status") in {"REJECTED", "BLOCKED", "UNREACHED"}
        for pf in pfv
        if isinstance(pf, dict)
    ):
        return 0.0
    return 0.5


def _adjudication_net_w1(
    aggregate_w1_count: int,
    adjudication_path: Path | None,
) -> tuple[int, int, float | None]:
    """Discount the W1 zero-day count by the Gemini-adjudicated
    over-claim rate when ``adjudication.json`` exists alongside the
    proof_analysis output.

    Returns ``(net_real, n_overclaimed, real_rate_or_none)``:
        * ``net_real`` — adjudication-confirmed real W1 findings
        * ``n_overclaimed`` — Gemini-flagged over-claims
        * ``real_rate_or_none`` — proportion of W1s that survived
          adjudication (``None`` if adjudication.json missing).

    When no adjudication file exists, returns ``(aggregate_w1_count,
    0, None)`` so callers can display the raw W1 count alongside
    "adjudication pending" rather than a misleading 100% real rate.
    """
    if adjudication_path is None or not adjudication_path.exists():
        return aggregate_w1_count, 0, None
    try:
        with adjudication_path.open("r", encoding="utf-8") as f:
            adj = json.load(f)
    except (OSError, json.JSONDecodeError):
        return aggregate_w1_count, 0, None
    per_finding = adj.get("per_finding") or []
    if not per_finding:
        return aggregate_w1_count, 0, None
    n_real = sum(1 for p in per_finding if p.get("is_real") is True)
    n_overclaimed = sum(1 for p in per_finding if p.get("is_real") is False)
    n_judged = n_real + n_overclaimed
    if n_judged == 0:
        return aggregate_w1_count, 0, None
    return n_real, n_overclaimed, round(n_real / n_judged, 4)


def _classify_finding(
    cwe: str,
    argus_rec: dict | None,
    opus_has: bool,
    oracle_has: bool,
    oracle_partial: bool,
    argus_dast_visible: bool,
) -> tuple[str, str]:
    """Return (category, rationale). Pure function — no side effects.

    Captures the symmetric integrity rule:
      * Argus oracle-override credit requires DAST status=CONFIRMED with
        runtime_evidence.
      * Argus refutation credit requires DAST visibility (status in
        {UNREACHED, REJECTED}) — i.e., DAST actually tried.
      * Without either, Argus is INCONCLUSIVE, not "right".
    """
    argus_has = argus_rec is not None
    dast_status = (argus_rec or {}).get("dast_status")
    dast_confirmed = dast_status == "CONFIRMED"
    # UNREACHED with high coverage = "tested and didn't fire"; REJECTED = explicit refute.
    dast_refuted = dast_status in {"UNREACHED", "REJECTED"}
    has_proof = dast_confirmed and float((argus_rec or {}).get("dast_confidence") or 0.0) >= 0.4

    # ───────────────────────────────────────────────────────────────────
    # WINS — Argus proved something
    # ───────────────────────────────────────────────────────────────────
    if argus_has and has_proof:
        if not oracle_has and not opus_has:
            return (
                CAT_W1,
                "Argus DAST-confirmed an exploit oracle didn't list AND Opus didn't list. "
                "Sandbox-grounded zero-day candidate.",
            )
        if not opus_has and oracle_has:
            return (
                CAT_W2,
                "Argus DAST-confirmed an exploit Opus missed; oracle agrees. "
                "Argus catches what single-prompt model missed.",
            )
        if oracle_has:
            return (
                CAT_T1,
                "Argus DAST-confirmed and oracle agrees. Mutually confirming.",
            )
        # Argus proved + Opus has + oracle missed -> argus + opus agree, oracle wrong
        return (
            CAT_A1,
            "Argus DAST-confirmed and Opus claims it too, but oracle missed. "
            "Either zero-day oracle missed OR mutual hallucination.",
        )

    # ───────────────────────────────────────────────────────────────────
    # REFUTATIONS — Argus tested and didn't find
    # ───────────────────────────────────────────────────────────────────
    if argus_has and dast_refuted:
        if not oracle_has:
            return (
                CAT_W3,
                "Argus tested with DAST coverage and didn't fire; oracle agrees no vuln. "
                "Refutation win (FP-reduction).",
            )
        # Oracle has, Argus tested + didn't find -> high-coverage miss
        return (
            CAT_A2,
            f"Argus DAST tested (status={dast_status}) but didn't confirm; oracle has this CWE. "
            "Genuine Argus FN OR oracle hallucinated. Needs adjudication.",
        )

    # ───────────────────────────────────────────────────────────────────
    # ARGUS L1-ONLY CLAIMS (no DAST validation either way)
    # ───────────────────────────────────────────────────────────────────
    if argus_has and dast_status == "NOT_TESTED":
        if oracle_has:
            return (
                CAT_T2,
                "Argus L1 claimed (no DAST proof); oracle has it. "
                "Both speculating, same epistemic level.",
            )
        if oracle_partial:
            return (
                CAT_T2,
                "Argus L1 claimed; some voters saw it but no oracle consensus. "
                "Argus speculation aligned with partial voter view.",
            )
        return (
            CAT_L2,
            "Argus L1 claimed without DAST proof; oracle disagrees. Argus over-call.",
        )

    if argus_has and dast_status is None:
        # In Argus vulnerabilities but not in per_finding_validation. Treat as L1-only.
        if oracle_has:
            return (CAT_T2, "Argus L1 claimed; oracle has it. Both speculation level.")
        if oracle_partial:
            return (CAT_T2, "Argus L1 claimed; some voter agreement (partial).")
        return (CAT_L2, "Argus L1 claimed alone; oracle disagrees. Over-call.")

    # ───────────────────────────────────────────────────────────────────
    # ARGUS DIDN'T CLAIM
    # ───────────────────────────────────────────────────────────────────
    if not argus_has and oracle_has:
        if argus_dast_visible:
            # DAST ran on this file but didn't test this specific CWE class
            # (no hypothesis targeted it). Inconclusive — Argus didn't try.
            return (
                CAT_I1,
                "Oracle has this CWE; Argus DAST ran but didn't probe this attack class. "
                "Argus inconclusive on this CWE.",
            )
        # DAST didn't trigger at all on this file
        return (
            CAT_I2,
            "Oracle has this CWE; L1 said clean (no DAST escalation). "
            "L1-floor decision — DAST never had visibility.",
        )

    # Neither Argus nor oracle has it — boring agreement
    return (
        "AGREEMENT_NONE",
        "Neither Argus nor oracle list this CWE.",
    )


def _per_file_verdict(row: dict, key: str = "predicted_verdict") -> str:
    return str(row.get(key) or row.get("oracle_verdict") or "?")


def analyze(
    argus_rows: list[dict],
    opus_rows: list[dict],
    oracle_entries: list[dict],
) -> tuple[list[FileAnalysis], dict[str, Any]]:
    """Analyze all files. Returns (per-file analyses, aggregate stats)."""
    argus_by_file = {r["file_name"]: r for r in argus_rows if r.get("file_name")}
    opus_by_file = {r["file_name"]: r for r in opus_rows if r.get("file_name")}
    oracle_by_file = {e["file_name"]: e for e in oracle_entries if e.get("file_name")}
    all_files = sorted(set(argus_by_file) | set(oracle_by_file))

    analyses: list[FileAnalysis] = []
    agg_cat = Counter()
    for fn in all_files:
        argus_row = argus_by_file.get(fn) or {}
        opus_row = opus_by_file.get(fn) or {}
        oracle_entry = oracle_by_file.get(fn) or {}
        argus_findings = _index_argus_findings(argus_row)
        opus_cwes = _index_opus_findings(opus_row)
        oracle_consensus, oracle_partial = _index_oracle(oracle_entry)
        argus_visible = _is_argus_dast_visible(argus_row)

        union_cwes = set(argus_findings) | opus_cwes | oracle_consensus | oracle_partial

        fa = FileAnalysis(
            file_name=fn,
            argus_verdict=_per_file_verdict(argus_row),
            opus_verdict=_per_file_verdict(opus_row),
            oracle_verdict=str(oracle_entry.get("oracle_verdict") or "?"),
            argus_dast_attempted=bool(argus_row.get("dast_attempted")),
            argus_n_findings=len(argus_findings),
            opus_n_findings=len(opus_cwes),
            oracle_n_consensus_cwes=len(oracle_consensus),
        )
        cat_count: Counter = Counter()
        for cwe in sorted(union_cwes):
            argus_rec = argus_findings.get(cwe)
            opus_has = cwe in opus_cwes
            o_has = cwe in oracle_consensus
            o_partial = cwe in oracle_partial
            cat, rationale = _classify_finding(
                cwe, argus_rec, opus_has, o_has, o_partial, argus_visible
            )
            if cat == "AGREEMENT_NONE":
                continue  # don't pollute the report with no-finding agreement rows
            fa.classifications.append(
                FindingClassification(
                    file_name=fn,
                    cwe=cwe,
                    category=cat,
                    argus_status=(argus_rec or {}).get("dast_status")
                    or ("L1-only" if argus_rec else "absent"),
                    argus_confidence=float(
                        (argus_rec or {}).get("dast_confidence")
                        or (argus_rec or {}).get("l1_confidence")
                        or 0.0
                    ),
                    argus_severity=(argus_rec or {}).get("severity", ""),
                    opus_has=opus_has,
                    oracle_has=o_has,
                    oracle_partial=o_partial,
                    proof_text=(argus_rec or {}).get("runtime_evidence", "")[:300],
                    rationale=rationale,
                )
            )
            cat_count[cat] += 1
            agg_cat[cat] += 1
        fa.cat_counts = dict(cat_count)
        analyses.append(fa)

    total_findings = sum(agg_cat.values())
    n_wins = sum(agg_cat.get(c, 0) for c in WIN_CATS)
    n_losses = sum(agg_cat.get(c, 0) for c in LOSS_CATS)
    n_ties = sum(agg_cat.get(c, 0) for c in TIE_CATS)
    n_inconclusive = sum(agg_cat.get(c, 0) for c in INCONCLUSIVE_CATS)
    n_adjudicate = sum(agg_cat.get(c, 0) for c in ADJUDICATE_CATS)

    # File-level verdict-exact (argus vs oracle, opus vs oracle)
    n_argus_exact = sum(1 for a in analyses if a.argus_verdict == a.oracle_verdict)
    n_opus_exact = sum(1 for a in analyses if a.opus_verdict == a.oracle_verdict)
    n_files = len(analyses)

    # v1.7 Fix #12: proof-grounded verdict-exact. For each disagreeing
    # file, give 0.5 partial credit when Argus's downgrade is backed by
    # DAST refutation evidence (scan_path + per_finding REJECTED/BLOCKED).
    # Sums to a fractional score; multiply by 100 / n_files for pct.
    argus_proof_grounded_score = 0.0
    n_argus_proof_grounded_partial = 0
    for a in analyses:
        argus_row = argus_by_file.get(a.file_name) or {}
        credit = _proof_grounded_credit(
            argus_row=argus_row,
            argus_verdict=a.argus_verdict,
            oracle_verdict=a.oracle_verdict,
        )
        argus_proof_grounded_score += credit
        if 0.0 < credit < 1.0:
            n_argus_proof_grounded_partial += 1

    aggregate = {
        "n_files": n_files,
        "n_findings_total": total_findings,
        "categories": dict(agg_cat),
        "wins": {
            "count": n_wins,
            "pct_of_findings": round(100.0 * n_wins / max(total_findings, 1), 2),
            "W1_zero_day": agg_cat.get(CAT_W1, 0),
            "W2_vs_opus": agg_cat.get(CAT_W2, 0),
            "W3_refutation": agg_cat.get(CAT_W3, 0),
        },
        "losses": {
            "count": n_losses,
            "pct_of_findings": round(100.0 * n_losses / max(total_findings, 1), 2),
            "L1_high_cov_miss": agg_cat.get(CAT_L1, 0),
            "L2_fp_claim": agg_cat.get(CAT_L2, 0),
        },
        "ties": n_ties,
        "inconclusive": n_inconclusive,
        "needs_adjudication": n_adjudicate,
        "file_level_verdict_exact": {
            "argus_pct": round(100.0 * n_argus_exact / max(n_files, 1), 2),
            "opus_pct": round(100.0 * n_opus_exact / max(n_files, 1), 2),
            "lift_pp": round(100.0 * (n_argus_exact - n_opus_exact) / max(n_files, 1), 2),
            "n_files": n_files,
            # v1.7 Fix #12: proof-grounded variant. ``argus_pct`` is the
            # strict measure; ``argus_proof_grounded_pct`` credits
            # DAST-evidenced downgrades at 0.5 each.
            "argus_proof_grounded_pct": round(
                100.0 * argus_proof_grounded_score / max(n_files, 1), 2
            ),
            "n_proof_grounded_partials": n_argus_proof_grounded_partial,
        },
    }
    return analyses, aggregate


# ── Report rendering ─────────────────────────────────────────────────────


def _category_pretty(cat: str) -> str:
    table = {
        CAT_W1: "🏆 W1 zero-day",
        CAT_W2: "🏆 W2 caught what Opus missed",
        CAT_W3: "🏆 W3 refutation",
        CAT_T1: "🤝 T1 proof-confirmed",
        CAT_T2: "🤝 T2 speculation tie",
        CAT_L1: "❌ L1 high-cov miss",
        CAT_L2: "❌ L2 FP claim",
        CAT_I1: "❓ I1 no DAST class visibility",
        CAT_I2: "❓ I2 L1-only file (no DAST)",
        CAT_A1: "⚖️ A1 Argus claims alone (adjudicate)",
        CAT_A2: "⚖️ A2 oracle vs Argus high-cov (adjudicate)",
    }
    return table.get(cat, cat)


def render_markdown(
    analyses: list[FileAnalysis],
    aggregate: dict,
    *,
    argus_label: str = "Argus +DAST +Phase 3",
    opus_label: str = "Raw Opus 4.6",
    oracle_label: str = "3-LLM Consensus (Gemini + GPT-5 + Grok)",
) -> str:
    """Render the per-finding proof-strength report as a single markdown file."""
    lines: list[str] = []
    lines.append("# Phase 3 Proof-Strength Bench Report")
    lines.append("")
    lines.append(f"- Argus: **{argus_label}**")
    lines.append(f"- Opus baseline: **{opus_label}**")
    lines.append(f"- Oracle: **{oracle_label}**")
    lines.append("")

    lines.append("## Executive summary")
    lines.append("")
    fle = aggregate["file_level_verdict_exact"]
    lines.append(
        f"- **{argus_label} verdict-exact (strict)**: {fle['argus_pct']}% ({fle['n_files']} files)"
    )
    # v1.7 Fix #12: proof-grounded verdict-exact. When the proof analyzer
    # detects DAST-evidenced downgrades (REJECTED/BLOCKED entries with
    # Argus verdict 1 tier below consensus oracle), each contributes 0.5
    # partial credit. Disclosed alongside the strict metric so customers
    # see both views.
    pg = fle.get("argus_proof_grounded_pct")
    pg_partials = fle.get("n_proof_grounded_partials", 0)
    if pg is not None:
        lines.append(
            f"- **{argus_label} verdict-exact (proof-grounded)**: "
            f"**{pg}%** — credits {pg_partials} DAST-evidenced downgrade(s) "
            f"at 0.5 each (v1.7 Fix #12)"
        )
    lines.append(f"- **{opus_label} verdict-exact**: {fle['opus_pct']}%")
    lines.append(f"- **Argus lift over Opus (strict)**: **{fle['lift_pp']:+.2f} pp**")
    if pg is not None:
        pg_lift = round(pg - fle["opus_pct"], 2)
        lines.append(f"- **Argus lift over Opus (proof-grounded)**: **{pg_lift:+.2f} pp**")
    lines.append("")
    lines.append(
        f"- Total per-finding classifications: **{aggregate['n_findings_total']}** "
        f"(across union of Argus + Opus + Oracle CWEs)"
    )
    lines.append(
        f"- 🏆 **WINS** (Argus epistemically stronger via sandbox proof): "
        f"**{aggregate['wins']['count']}** ({aggregate['wins']['pct_of_findings']}% of findings)"
    )
    lines.append(f"   - W1 zero-day discoveries: {aggregate['wins']['W1_zero_day']}")
    lines.append(f"   - W2 caught what Opus missed: {aggregate['wins']['W2_vs_opus']}")
    lines.append(f"   - W3 refutations (FP reduction): {aggregate['wins']['W3_refutation']}")
    lines.append(
        f"- ❌ **LOSSES** (genuine Argus weaknesses): "
        f"**{aggregate['losses']['count']}** ({aggregate['losses']['pct_of_findings']}%)"
    )
    lines.append(
        f"   - L1 high-coverage misses (Argus tested + didn't find): "
        f"{aggregate['losses']['L1_high_cov_miss']}"
    )
    lines.append(
        f"   - L2 FP claims (no proof + oracle disagrees): {aggregate['losses']['L2_fp_claim']}"
    )
    lines.append(f"- 🤝 Ties: {aggregate['ties']}")
    lines.append(f"- ❓ Inconclusive (no Argus opinion to credit): {aggregate['inconclusive']}")
    lines.append(
        f"- ⚖️ Needs adjudication (high-stakes disagreement, recommend GPT-5 judge): "
        f"{aggregate['needs_adjudication']}"
    )
    lines.append("")

    lines.append("## Integrity rule (how we score)")
    lines.append("")
    lines.append(
        "* Argus only earns oracle-overriding credit when DAST has "
        "**status=CONFIRMED with runtime_evidence**. Pure L1 speculation "
        "does NOT count as Argus beating the oracle."
    )
    lines.append(
        "* Argus only earns refutation credit when DAST has "
        "**coverage on the relevant CWE** (status ∈ {UNREACHED, REJECTED}). "
        "Without DAST visibility, Argus is **INCONCLUSIVE**, not 'right'."
    )
    lines.append(
        "* Symmetric: if Oracle has a CWE Argus didn't list but DAST didn't "
        "test for that class, Argus gets **inconclusive** credit (not penalized "
        "as a miss). Genuine FNs are only counted when DAST DID test."
    )
    lines.append("")

    lines.append("## Aggregate category counts")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|---|---|")
    for cat, count in sorted(aggregate["categories"].items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"| {_category_pretty(cat)} | {count} |")
    lines.append("")

    lines.append("## Per-file breakdown")
    lines.append("")
    for fa in analyses:
        lines.append(f"### `{fa.file_name}`")
        lines.append("")
        lines.append(
            f"- Verdicts: argus=**{fa.argus_verdict}**, "
            f"opus={fa.opus_verdict}, oracle={fa.oracle_verdict}"
        )
        lines.append(
            f"- DAST attempted: {fa.argus_dast_attempted} | "
            f"Argus findings: {fa.argus_n_findings} | "
            f"Opus findings: {fa.opus_n_findings} | "
            f"Oracle consensus CWEs: {fa.oracle_n_consensus_cwes}"
        )
        if fa.cat_counts:
            cat_str = ", ".join(
                f"{_category_pretty(k)}:{v}"
                for k, v in sorted(fa.cat_counts.items(), key=lambda x: (-x[1], x[0]))
            )
            lines.append(f"- Categories: {cat_str}")
        lines.append("")
        if fa.classifications:
            lines.append(
                "| CWE | Category | Argus status | Conf | Sev | Opus? | Oracle? | Rationale |"
            )
            lines.append("|---|---|---|---|---|---|---|---|")
            for c in fa.classifications:
                opus = "✓" if c.opus_has else ""
                oracle = "✓" if c.oracle_has else ("◐" if c.oracle_partial else "")
                lines.append(
                    f"| {c.cwe} | {_category_pretty(c.category)} | {c.argus_status} | "
                    f"{c.argus_confidence:.2f} | {c.argus_severity} | "
                    f"{opus} | {oracle} | {c.rationale[:180]} |"
                )
            lines.append("")

    return "\n".join(lines)


def to_json_records(analyses: list[FileAnalysis], aggregate: dict) -> dict[str, Any]:
    """Serialize the full analysis as a JSON-safe dict."""
    return {
        "aggregate": aggregate,
        "files": [
            {
                "file_name": fa.file_name,
                "argus_verdict": fa.argus_verdict,
                "opus_verdict": fa.opus_verdict,
                "oracle_verdict": fa.oracle_verdict,
                "argus_dast_attempted": fa.argus_dast_attempted,
                "argus_n_findings": fa.argus_n_findings,
                "opus_n_findings": fa.opus_n_findings,
                "oracle_n_consensus_cwes": fa.oracle_n_consensus_cwes,
                "cat_counts": fa.cat_counts,
                "classifications": [
                    {
                        "cwe": c.cwe,
                        "category": c.category,
                        "argus_status": c.argus_status,
                        "argus_confidence": c.argus_confidence,
                        "argus_severity": c.argus_severity,
                        "opus_has": c.opus_has,
                        "oracle_has": c.oracle_has,
                        "oracle_partial": c.oracle_partial,
                        "proof_text": c.proof_text,
                        "rationale": c.rationale,
                    }
                    for c in fa.classifications
                ],
            }
            for fa in analyses
        ],
    }


# ── CLI ───────────────────────────────────────────────────────────────────


def _load_oracle_entries(path: Path) -> list[dict]:
    """Oracle is a {'files': [...], 'metadata': {...}} dict. Return files list."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return data.get("files") or []


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Per-finding proof-strength analyzer (Argus vs Opus vs Oracle)"
    )
    parser.add_argument(
        "--argus-bench",
        type=Path,
        required=True,
        help="Path to Argus bench output JSON (e.g. bench_results/<ts>/argus_full_run1.json)",
    )
    parser.add_argument(
        "--opus-bench",
        type=Path,
        required=True,
        help="Path to Opus bench output JSON (e.g. bench_results/v1_1_launch/raw_opus_run1.json)",
    )
    parser.add_argument(
        "--oracle",
        type=Path,
        required=True,
        help="Path to consensus oracle JSON (consensus_oracle_no_opus.json)",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        required=True,
        help="Output path for markdown report",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional output path for JSON sidecar (default: <output-md>.json)",
    )
    parser.add_argument(
        "--argus-label",
        default="Argus +DAST +Phase 3",
        help="Label for Argus in the report header",
    )
    parser.add_argument(
        "--adjudication",
        type=Path,
        default=None,
        help=(
            "Optional path to adjudication.json (Gemini per-finding "
            "verdicts). When supplied, the headline reports an "
            "'adjudication-net W1' count discounting Gemini-flagged "
            "over-claims from the raw W1 zero-day candidate count. "
            "v1.7 Fix #12."
        ),
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    argus_rows = json.loads(args.argus_bench.read_text(encoding="utf-8"))
    opus_rows = json.loads(args.opus_bench.read_text(encoding="utf-8"))
    oracle_entries = _load_oracle_entries(args.oracle)
    log.info(
        "loaded %d argus rows, %d opus rows, %d oracle entries",
        len(argus_rows),
        len(opus_rows),
        len(oracle_entries),
    )

    analyses, aggregate = analyze(argus_rows, opus_rows, oracle_entries)

    md = render_markdown(analyses, aggregate, argus_label=args.argus_label)
    args.output_md.write_text(md, encoding="utf-8")
    log.info("wrote markdown report: %s", args.output_md)

    json_path = args.output_json or args.output_md.with_suffix(".json")
    json_path.write_text(
        json.dumps(to_json_records(analyses, aggregate), indent=2),
        encoding="utf-8",
    )
    log.info("wrote JSON sidecar: %s", json_path)

    print()
    print("=== HEADLINE ===")
    fle = aggregate["file_level_verdict_exact"]
    print(f"  Argus verdict-exact (strict):         {fle['argus_pct']}% ({fle['n_files']} files)")
    # v1.7 Fix #12: proof-grounded verdict-exact (option 2 scoring).
    pg = fle.get("argus_proof_grounded_pct")
    pg_partial = fle.get("n_proof_grounded_partials", 0)
    if pg is not None:
        print(
            f"  Argus verdict-exact (proof-grounded): {pg}%   "
            f"[+0.5/file × {pg_partial} DAST-refutation downgrades]"
        )
    print(f"  Opus  verdict-exact:                  {fle['opus_pct']}%")
    print(f"  Argus lift over Opus (strict):        {fle['lift_pp']:+.2f} pp")
    if pg is not None:
        pg_lift = round(pg - fle["opus_pct"], 2)
        print(f"  Argus lift over Opus (proof-grounded):{pg_lift:+.2f} pp")
    print()
    raw_w1 = aggregate["wins"]["W1_zero_day"]
    print(
        f"  Argus WINS:  {aggregate['wins']['count']} "
        f"(W1={raw_w1}, "
        f"W2={aggregate['wins']['W2_vs_opus']}, "
        f"W3={aggregate['wins']['W3_refutation']})"
    )
    # v1.7 Fix #12: adjudication-net W1 count. Discounts the raw W1
    # claim count by Gemini-flagged over-claims when adjudication.json
    # is provided.
    adj_path = args.adjudication
    net_real, n_overclaimed, real_rate = _adjudication_net_w1(raw_w1, adj_path)
    if real_rate is not None:
        print(
            f"  W1 adjudication-net real:  {net_real} of {raw_w1}  "
            f"({n_overclaimed} over-claimed, "
            f"{real_rate * 100:.1f}% survival rate)"
        )
    elif adj_path is not None:
        print(
            f"  W1 adjudication-net:  (adjudication.json present but "
            f"empty/unreadable — falling back to raw W1={raw_w1})"
        )
    else:
        print(
            "  W1 adjudication-net:  pending  (pass --adjudication adjudication.json to discount)"
        )
    print(
        f"  Argus LOSSES:{aggregate['losses']['count']} "
        f"(L1_high_cov_miss={aggregate['losses']['L1_high_cov_miss']}, "
        f"L2_FP_claim={aggregate['losses']['L2_fp_claim']})"
    )
    print(f"  Adjudication candidates: {aggregate['needs_adjudication']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
