"""Phase 3 verdict resolver -- final verdict from loop summary + L1 floor.

Implements the L1-as-floor / Phase 3-as-additive architecture (per
the per-phase invariant codified in CLAUDE.md after the 2026-05-16
mcp-server-fetch eval):

* **L1 cascade**: establishes the baseline verdict + findings.
* **Phase A**: VERIFIES L1 findings. Can downgrade L1's verdict when
  per-finding evidence shows L1 was wrong, or keep flat. Never raises
  by itself (raising comes from Phase B+ or Phase 3 confirming NEW
  exploits).
* **Phase B+ runtime probe / chains**: generates NEW hypotheses. Can
  only RAISE the verdict (by adding new high/critical-severity
  CONFIRMED findings).
* **Phase 3 Stage 2 adversarial loop**: generates NEW hypotheses
  anchored on Stage 1's behavioral profile. Can only RAISE (same as
  Phase B+).
* This resolver decides the FINAL verdict by combining them with
  coverage-based confidence — but it MUST respect the invariant:
  Phase 3 silence is silence about NEW vectors, not refutation of L1.

Four coverage classes drive the routing:

  ``high`` (>= ``COVERAGE_STRICT_THRESHOLD``):
    Phase 3 Stage 2 ran cleanly. Confirmations contribute NEW
    findings → ``phase_3_confirmed`` state, verdict = max severity
    across the new findings (raises L1 if higher). No confirmations
    → ``phase_3_no_new_findings`` state; L1 verdict and L1 findings
    preserved verbatim. (Pre-2026-05-16 this branch returned
    ``final_verdict="clean"`` and ``findings=[]`` which violated the
    invariant — the user's mcp-fetch eval surfaced this as a real bug
    and we fixed it.)

  ``partial`` (between ``COVERAGE_FALLBACK_THRESHOLD`` and
  ``COVERAGE_STRICT_THRESHOLD``):
    Blend. Phase 3 confirmed findings ship + L1 findings fill the
    coverage gap. Verdict = max severity across both.

  ``unreachable`` (< ``COVERAGE_FALLBACK_THRESHOLD``):
    L1 wins. Phase 3 didn't run enough of the code to override.
    ``static_only`` flag set so downstream consumers know.

  ``no_run`` (Phase 3 didn't execute at all):
    L1 verdict is canonical. Distinct from ``unreachable`` because
    "didn't try" and "tried but couldn't reach much" should be
    visible separately in telemetry.

This is a PURE function -- no IO, no async, no side effects.
Designed for exhaustive unit testing.

Thresholds were chosen from the thin-slice measurement (commit
7d42813): at ``max_turns=1``, the loop achieved coverage_ratio=1.0
on every file where Stage 1 successfully produced a profile. So
``high`` is the common case; ``partial`` covers the in-between when
Stage 1 partially explores; ``unreachable`` covers Stage 1 import
failures that left the profile mostly empty.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Coverage ratio at or above which Phase 3 is trusted as authoritative
#: (the loop tested >= 80% of the hypotheses it proposed, so a clean
#: result reliably refutes L1 speculation and a confirmation reliably
#: lands an exploit).
COVERAGE_STRICT_THRESHOLD: float = 0.80

#: Coverage ratio below which Phase 3 is too partial to override L1.
#: Between this and ``COVERAGE_STRICT_THRESHOLD`` we BLEND.
COVERAGE_FALLBACK_THRESHOLD: float = 0.30

#: 5-tier verdict scale, low -> high. Matches
#: :data:`dast.orchestrator._VERDICT_RANK`.
VERDICT_RANK: dict[str, int] = {
    "clean": 0,
    "informational": 1,
    "suspicious": 2,
    "malicious": 3,
    "critical_malicious": 4,
}

#: Severity (per-finding) -> verdict (whole-file) mapping. The verdict
#: for a file is determined by the MAX severity of its findings.
SEVERITY_TO_VERDICT: dict[str, str] = {
    "info": "informational",
    "low": "informational",
    "medium": "suspicious",
    "high": "malicious",
    "critical": "critical_malicious",
}

#: Verdict source enum values surfaced on
#: :class:`VerdictResolverOutput.verdict_source` so downstream
#: consumers (reports, telemetry, SARIF) can attribute each verdict
#: to its origin.
SOURCE_PHASE_3_CONFIRMED: str = "phase_3_confirmed"
#: Phase 3 ran with high coverage but generated zero NEW confirmed
#: findings. Renamed from ``SOURCE_PHASE_3_CLEAN`` (2026-05-16) after
#: it was empirically clear that "Phase 3 found nothing new" is NOT
#: the same as "L1 is wrong / clean". The user's per-phase invariant
#: says only Phase A (which verifies L1 findings) can downgrade L1;
#: Phase 3 Stage 2 generates NEW hypotheses, so its silence is silence
#: about NEW vectors, not refutation of L1's existing findings.
#:
#: When this source fires, verdict + findings are preserved from L1.
#: The source label tells downstream consumers "Phase 3 ran cleanly
#: with high coverage, contributed no additional findings" — not
#: "Phase 3 declared the file clean".
SOURCE_PHASE_3_NO_NEW_FINDINGS: str = "phase_3_no_new_findings"
#: Back-compat alias for the renamed constant. Kept for any external
#: consumers that imported the old name. Will be removed in v2.0.
SOURCE_PHASE_3_CLEAN: str = SOURCE_PHASE_3_NO_NEW_FINDINGS
SOURCE_PHASE_3_PARTIAL: str = "phase_3_partial"
SOURCE_L1_FALLBACK: str = "l1_fallback"
SOURCE_L1_NO_PHASE_3: str = "l1_no_phase_3"

#: Coverage class enum.
COVERAGE_HIGH: str = "high"
COVERAGE_PARTIAL: str = "partial"
COVERAGE_UNREACHABLE: str = "unreachable"
COVERAGE_NO_RUN: str = "no_run"


@dataclass
class VerdictResolverInput:
    """Inputs to the resolver. Shape designed to be cheap to construct
    from existing structures: the ``phase_3_loop`` summary dict from
    :class:`DastResult.phase_3_loop` and the L1 verdict + findings from
    the engine's static cascade.
    """

    phase_3_loop_summary: dict[str, Any] | None
    """The summary dict surfaced on ``DastResult.phase_3_loop``. ``None``
    when the loop didn't run (flag off, non-Python file, Stage 1 failed
    to produce a profile)."""

    l1_verdict_label: str
    """The static cascade's verdict label, one of :data:`VERDICT_RANK`
    keys. Treated as a floor -- the resolver never returns a lower-rank
    verdict unless Phase 3 authoritatively refutes L1 via
    ``phase_3_clean`` (>= 80% coverage + 0 confirmed)."""

    l1_findings: list[dict[str, Any]] = field(default_factory=list)
    """L1 static-analysis findings with shape compatible with the
    canonical findings list (must carry ``severity`` and a stable
    identifier; other fields pass through verbatim). Used in
    ``partial_run`` to fill the coverage gap and as the canonical
    findings list when Phase 3 is unreachable / no_run."""


@dataclass
class VerdictResolverOutput:
    """Resolver decision. Carries the final verdict + provenance so
    downstream consumers can attribute and explain it."""

    final_verdict: str
    """One of :data:`VERDICT_RANK` keys."""

    verdict_source: str
    """One of the SOURCE_* enum values -- explains which input drove
    the verdict (Phase 3 vs L1 vs blend)."""

    coverage_class: str
    """One of the COVERAGE_* enum values -- captures the coverage
    interpretation that led to the routing decision."""

    static_only: bool
    """True iff the final verdict came from L1 alone because Phase 3
    coverage was too low to override (``unreachable`` or ``no_run``).
    Tells consumers the verdict is static-grounded, not sandbox-
    grounded."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    """Canonical findings list for downstream consumers. Composition
    depends on coverage:

    * ``phase_3_confirmed`` -> Phase 3 confirmed findings only
      (sandbox-grounded; supersedes L1 speculation).
    * ``phase_3_clean`` -> empty list (sandbox refuted everything).
    * ``phase_3_partial`` -> Phase 3 confirmed + L1 findings (blended).
    * ``l1_fallback`` / ``l1_no_phase_3`` -> L1 findings only.
    """

    rationale: str = ""
    """Human-readable explanation of the routing decision -- shown in
    reports + telemetry for verdict accountability."""


# ── Helpers ───────────────────────────────────────────────────────────────


def _coverage_class(summary: dict[str, Any] | None) -> str:
    """Classify Phase 3's coverage into one of the four bands.

    Stage 1 blindness check: if ``stage_1_callables_explored == 0`` AND
    no confirmations landed, the model designed hypotheses from static
    source reading alone (no behavioral profile to anchor on). Sandbox
    refutations of those guesses are not reliable enough to override
    L1's verdict -- route to ``unreachable`` so the resolver falls
    back to L1. Confirmed exploits remain authoritative regardless of
    callables_explored (a fired canary is sandbox-grounded evidence).

    Evidence base for this rule: the 23-file regression measurement
    (commit fd5be0e). 5 of 17 FNs had ``callables_explored == 0`` AND
    ``coverage_ratio == 1.0`` AND ``hypotheses_confirmed == 0``, which
    the old resolver routed to ``phase_3_clean`` (final_verdict=clean
    overriding L1 'malicious'). Architecturally wrong: those files
    are real malware that Phase 3 had no real visibility into.
    """
    if summary is None or not summary.get("ran"):
        return COVERAGE_NO_RUN

    callables_explored = int(summary.get("stage_1_callables_explored", 0) or 0)
    confirmed = int(summary.get("hypotheses_confirmed", 0) or 0)
    if callables_explored == 0 and confirmed == 0:
        return COVERAGE_UNREACHABLE

    ratio = float(summary.get("coverage_ratio", 0.0) or 0.0)
    if ratio >= COVERAGE_STRICT_THRESHOLD:
        return COVERAGE_HIGH
    if ratio >= COVERAGE_FALLBACK_THRESHOLD:
        return COVERAGE_PARTIAL
    return COVERAGE_UNREACHABLE


def _max_verdict(findings: list[dict[str, Any]]) -> str:
    """Derive a verdict label from a findings list by taking the
    highest severity. Empty list -> ``clean``."""
    if not findings:
        return "clean"
    best_rank = -1
    best_label = "clean"
    for f in findings:
        severity = str(f.get("severity", "") or "").lower()
        verdict = SEVERITY_TO_VERDICT.get(severity, "informational")
        rank = VERDICT_RANK.get(verdict, 0)
        if rank > best_rank:
            best_rank = rank
            best_label = verdict
    return best_label


def _phase_3_findings(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the Phase 3 confirmed findings list from the summary
    dict, defending against malformed shapes."""
    raw = summary.get("findings") or []
    if not isinstance(raw, list):
        return []
    return [f for f in raw if isinstance(f, dict)]


# ── Resolver ──────────────────────────────────────────────────────────────


def resolve_verdict(inputs: VerdictResolverInput) -> VerdictResolverOutput:
    """Compute the final verdict + provenance from Phase 3 loop summary
    + L1 verdict + L1 findings.

    Routing table (see module docstring for the architecture):

    +------------------+--------------------+-------------------------+
    | coverage class   | confirmed > 0?     | result                  |
    +==================+====================+=========================+
    | high             | yes                | phase_3_confirmed       |
    |                  |                    | (Phase 3 NEW findings   |
    |                  |                    | raise verdict)          |
    | high             | no                 | phase_3_no_new_findings |
    |                  |                    | (L1 verdict + findings  |
    |                  |                    | preserved; Phase 3      |
    |                  |                    | silence ≠ refutation)   |
    | partial          | yes                | phase_3_partial (blend) |
    | partial          | no                 | phase_3_partial (L1     |
    |                  |                    | fills gap; verdict = L1)|
    | unreachable      | (irrelevant)       | l1_fallback             |
    | no_run           | (irrelevant)       | l1_no_phase_3           |
    +------------------+--------------------+-------------------------+
    """
    coverage = _coverage_class(inputs.phase_3_loop_summary)

    if coverage in (COVERAGE_UNREACHABLE, COVERAGE_NO_RUN):
        source = SOURCE_L1_FALLBACK if coverage == COVERAGE_UNREACHABLE else SOURCE_L1_NO_PHASE_3
        return VerdictResolverOutput(
            final_verdict=inputs.l1_verdict_label,
            verdict_source=source,
            coverage_class=coverage,
            static_only=True,
            findings=list(inputs.l1_findings),
            rationale=(
                f"Phase 3 coverage {coverage} -- L1 verdict canonical "
                f"({inputs.l1_verdict_label}). Static analysis only."
            ),
        )

    # We have a summary because coverage is high or partial.
    assert inputs.phase_3_loop_summary is not None  # nosec: enum exhaustive
    summary = inputs.phase_3_loop_summary
    confirmed = int(summary.get("hypotheses_confirmed", 0) or 0)
    p3_findings = _phase_3_findings(summary)
    coverage_ratio = float(summary.get("coverage_ratio", 0.0) or 0.0)

    if coverage == COVERAGE_HIGH:
        if confirmed > 0:
            verdict = _max_verdict(p3_findings)
            return VerdictResolverOutput(
                final_verdict=verdict,
                verdict_source=SOURCE_PHASE_3_CONFIRMED,
                coverage_class=coverage,
                static_only=False,
                findings=p3_findings,
                rationale=(
                    f"Phase 3 high coverage ({coverage_ratio:.0%}) + "
                    f"{confirmed} confirmed exploit(s); sandbox-grounded "
                    f"findings supersede L1 ({inputs.l1_verdict_label})."
                ),
            )
        # High coverage + zero confirmations -> Phase 3 added no NEW
        # exploits. Per the per-phase invariant (only Phase A verifies
        # L1; Phase 3 Stage 2 generates NEW hypotheses → can only
        # RAISE, never lower), "Phase 3 didn't confirm new exploits"
        # does NOT refute L1's existing findings.
        #
        # Pre-2026-05-16 this branch hardcoded `final_verdict="clean"`
        # and `findings=[]`, wiping L1's findings entirely. Empirically
        # surfaced by the mcp-server-fetch eval where Phase 3's 3
        # hypotheses all refuted in sandbox (sandbox-verification
        # limits on redirect-bypass class, not bug-absence proof) — the
        # resolver wrongly recommended `final_verdict="clean"` and
        # `findings=[]` even though L1's 4 high-confidence findings
        # were still real.
        #
        # Correct behavior: preserve L1's verdict + findings, mark the
        # source as SOURCE_PHASE_3_NO_NEW_FINDINGS so downstream
        # consumers know Phase 3 ran cleanly with high coverage but
        # added no signal — NOT that Phase 3 refuted L1.
        return VerdictResolverOutput(
            final_verdict=inputs.l1_verdict_label,
            verdict_source=SOURCE_PHASE_3_NO_NEW_FINDINGS,
            coverage_class=coverage,
            static_only=False,
            findings=list(inputs.l1_findings),
            rationale=(
                f"Phase 3 high coverage ({coverage_ratio:.0%}) ran but "
                f"generated no NEW confirmed exploits; L1 verdict "
                f"({inputs.l1_verdict_label}) and findings preserved. "
                f"Phase 3 Stage 2 designs NEW hypotheses — its silence "
                f"is silence about new vectors, not refutation of L1."
            ),
        )

    # COVERAGE_PARTIAL: blend Phase 3 confirmed findings with L1.
    blended: list[dict[str, Any]] = list(p3_findings) + list(inputs.l1_findings)
    phase_3_verdict = _max_verdict(p3_findings)
    l1_rank = VERDICT_RANK.get(inputs.l1_verdict_label, 0)
    p3_rank = VERDICT_RANK.get(phase_3_verdict, 0)
    # Pick the more severe of the two -- L1 fills the coverage gap,
    # but Phase 3 confirmations are still authoritative for what was
    # tested.
    final = phase_3_verdict if p3_rank >= l1_rank else inputs.l1_verdict_label
    return VerdictResolverOutput(
        final_verdict=final,
        verdict_source=SOURCE_PHASE_3_PARTIAL,
        coverage_class=coverage,
        static_only=False,
        findings=blended,
        rationale=(
            f"Phase 3 partial coverage ({coverage_ratio:.0%}) + "
            f"{confirmed} confirmed; blended with L1 "
            f"({inputs.l1_verdict_label}). Final verdict = "
            f"max(phase_3={phase_3_verdict}, l1={inputs.l1_verdict_label})."
        ),
    )


__all__ = [
    "COVERAGE_FALLBACK_THRESHOLD",
    "COVERAGE_HIGH",
    "COVERAGE_NO_RUN",
    "COVERAGE_PARTIAL",
    "COVERAGE_STRICT_THRESHOLD",
    "COVERAGE_UNREACHABLE",
    "SEVERITY_TO_VERDICT",
    "SOURCE_L1_FALLBACK",
    "SOURCE_L1_NO_PHASE_3",
    "SOURCE_PHASE_3_CLEAN",
    "SOURCE_PHASE_3_CONFIRMED",
    "SOURCE_PHASE_3_NO_NEW_FINDINGS",
    "SOURCE_PHASE_3_PARTIAL",
    "VERDICT_RANK",
    "VerdictResolverInput",
    "VerdictResolverOutput",
    "resolve_verdict",
]
