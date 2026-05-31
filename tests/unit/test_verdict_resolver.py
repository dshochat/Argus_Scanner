"""Unit tests for the Phase 3 verdict resolver.

Exhaustive coverage of the routing table:

    coverage_class | confirmed > 0 | expected verdict_source
    ---------------+---------------+--------------------------
    high           | yes           | phase_3_confirmed
    high           | no            | phase_3_clean
    partial        | yes           | phase_3_partial (blend)
    partial        | no            | phase_3_partial (L1 fills gap)
    unreachable    | (any)         | l1_fallback (static_only=True)
    no_run         | (any)         | l1_no_phase_3 (static_only=True)

Plus edge cases: empty findings, severity -> verdict mapping correctness,
coverage threshold boundary behavior, L1 floor preservation.

Pure function tests, no fixtures.
"""

from __future__ import annotations

from typing import Any

from dast.verdict_resolver import (
    COVERAGE_FALLBACK_THRESHOLD,
    COVERAGE_HIGH,
    COVERAGE_NO_RUN,
    COVERAGE_PARTIAL,
    COVERAGE_STRICT_THRESHOLD,
    COVERAGE_UNREACHABLE,
    SOURCE_L1_FALLBACK,
    SOURCE_L1_NO_PHASE_3,
    SOURCE_PHASE_3_CLEAN,
    SOURCE_PHASE_3_CONFIRMED,
    SOURCE_PHASE_3_PARTIAL,
    VerdictResolverInput,
    resolve_verdict,
)

# ── Phase 3 summary fixtures ──────────────────────────────────────────────


def _summary(
    *,
    coverage_ratio: float = 1.0,
    confirmed: int = 0,
    findings: list[dict[str, Any]] | None = None,
    ran: bool = True,
    stage_1_callables_explored: int = 5,
) -> dict[str, Any]:
    """Build a minimal phase_3_loop_summary-shaped dict.

    Default ``stage_1_callables_explored=5`` represents the normal
    case where Stage 1 successfully introspected the file's public
    callables. The Stage-1-blindness path (callables_explored=0) has
    dedicated tests further down.
    """
    return {
        "ran": ran,
        "coverage_ratio": coverage_ratio,
        "hypotheses_confirmed": confirmed,
        "stage_1_callables_explored": stage_1_callables_explored,
        "findings": findings or [],
    }


def _finding(severity: str = "high", ref: str = "HRP_AL_T0_H0") -> dict[str, Any]:
    return {
        "finding_ref": ref,
        "severity": severity,
        "attack_class": "command_injection",
        "function_name": "f",
    }


# ── Coverage class routing ────────────────────────────────────────────────


def test_no_phase_3_summary_routes_to_l1_no_phase_3() -> None:
    """``phase_3_loop_summary=None`` means the loop didn't run at all
    -> L1 verdict is canonical, distinct telemetry source."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=None,
        l1_verdict_label="suspicious",
        l1_findings=[_finding("medium")],
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_NO_RUN
    assert out.verdict_source == SOURCE_L1_NO_PHASE_3
    assert out.final_verdict == "suspicious"
    assert out.static_only is True
    assert len(out.findings) == 1


def test_summary_with_ran_false_routes_to_no_phase_3() -> None:
    """When ``ran=False`` (loop attempted but errored), the gate
    treats it as no_run -- L1 fallback."""
    inp = VerdictResolverInput(
        phase_3_loop_summary={"ran": False, "error": "sandbox unreachable"},
        l1_verdict_label="malicious",
        l1_findings=[_finding("high")],
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_NO_RUN
    assert out.verdict_source == SOURCE_L1_NO_PHASE_3
    assert out.final_verdict == "malicious"


def test_unreachable_coverage_routes_to_l1_fallback() -> None:
    """Below the fallback threshold -> L1 wins, static_only=True,
    distinct from no_run so telemetry sees the difference."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(coverage_ratio=0.2, confirmed=0),
        l1_verdict_label="malicious",
        l1_findings=[_finding("high")],
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_UNREACHABLE
    assert out.verdict_source == SOURCE_L1_FALLBACK
    assert out.final_verdict == "malicious"
    assert out.static_only is True


def test_high_coverage_with_confirmations_routes_to_phase_3_confirmed() -> None:
    """High coverage + >= 1 confirmed -> Phase 3 sandbox-grounded
    verdict supersedes L1, regardless of L1's label."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=1.0,
            confirmed=1,
            findings=[_finding("critical")],
        ),
        l1_verdict_label="suspicious",  # L1 said softer
        l1_findings=[_finding("medium")],
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_HIGH
    assert out.verdict_source == SOURCE_PHASE_3_CONFIRMED
    assert out.final_verdict == "critical_malicious"  # from critical severity
    assert out.static_only is False
    # Phase 3 findings only -- L1 findings dropped (Phase 3 had full coverage)
    assert len(out.findings) == 1
    assert out.findings[0]["finding_ref"] == "HRP_AL_T0_H0"


def test_high_coverage_zero_confirmations_preserves_l1_per_phase_invariant() -> None:
    """High coverage + 0 confirmed -> phase_3_no_new_findings. PER-PHASE
    INVARIANT: only Phase A verifies L1 and can downgrade. Phase 3
    Stage 2 generates NEW hypotheses — its silence is silence about
    NEW vectors, NOT refutation of L1's existing findings.

    History: pre-2026-05-16 this branch returned final_verdict='clean'
    and findings=[], wiping L1 entirely. Empirically caught by the
    mcp-server-fetch eval where Phase 3's 3 hypotheses all refuted in
    sandbox (sandbox-verification limits, NOT bug-absence proof) — the
    resolver wrongly recommended 'clean' even though L1's 4 high-
    confidence findings were still real. Fix: preserve L1 verdict +
    findings; only flag the source as phase_3_no_new_findings so
    downstream knows Phase 3 ran cleanly with high coverage but added
    no signal."""
    from dast.verdict_resolver import SOURCE_PHASE_3_NO_NEW_FINDINGS

    l1_findings = [_finding("high")]
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(coverage_ratio=1.0, confirmed=0),
        l1_verdict_label="malicious",  # L1's verdict — must be preserved
        l1_findings=l1_findings,
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_HIGH
    assert out.verdict_source == SOURCE_PHASE_3_NO_NEW_FINDINGS
    # L1 verdict preserved (was 'clean' pre-fix — the bug)
    assert out.final_verdict == "malicious"
    # L1 findings preserved (was [] pre-fix — the bug)
    assert out.findings == l1_findings
    assert out.static_only is False
    # Rationale must explain the per-phase invariant so future readers
    # don't re-introduce the bug
    assert "no NEW" in out.rationale or "no new" in out.rationale.lower()
    assert "L1" in out.rationale


def test_high_coverage_zero_confirmations_backcompat_alias_works() -> None:
    """SOURCE_PHASE_3_CLEAN is kept as a back-compat alias for the
    renamed SOURCE_PHASE_3_NO_NEW_FINDINGS. Any external consumer
    importing the old name should still get a matching value."""
    from dast.verdict_resolver import (
        SOURCE_PHASE_3_CLEAN as alias,
        SOURCE_PHASE_3_NO_NEW_FINDINGS as new_name,
    )

    assert alias == new_name
    assert alias == "phase_3_no_new_findings"


def test_high_coverage_zero_confirmations_preserves_multiple_l1_findings() -> None:
    """Regression guard: L1 findings list (even multi-element) must
    survive Phase 3's no-new-findings outcome. mcp-server-fetch had
    4 L1 findings; pre-fix all 4 disappeared. Post-fix all 4 must
    survive verbatim."""
    from dast.verdict_resolver import SOURCE_PHASE_3_NO_NEW_FINDINGS

    l1_findings = [
        _finding("high"),
        _finding("medium"),
        _finding("medium"),
        _finding("low"),
    ]
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(coverage_ratio=1.0, confirmed=0),
        l1_verdict_label="malicious",
        l1_findings=l1_findings,
    )
    out = resolve_verdict(inp)
    assert out.verdict_source == SOURCE_PHASE_3_NO_NEW_FINDINGS
    assert len(out.findings) == 4
    assert out.findings == l1_findings


def test_high_coverage_zero_confirmations_preserves_clean_verdict_too() -> None:
    """Edge case: when L1 ITSELF said clean, Phase 3's
    no-new-findings result preserves the clean verdict (no change).
    This tests the path that pre-fix also returned 'clean' — so
    behavior is the same on the surface; only the source label
    distinguishes 'L1 said clean + Phase 3 agrees' from the bug case
    where 'L1 said malicious but Phase 3 wrongly says clean'."""
    from dast.verdict_resolver import SOURCE_PHASE_3_NO_NEW_FINDINGS

    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(coverage_ratio=1.0, confirmed=0),
        l1_verdict_label="clean",
        l1_findings=[],
    )
    out = resolve_verdict(inp)
    assert out.verdict_source == SOURCE_PHASE_3_NO_NEW_FINDINGS
    assert out.final_verdict == "clean"
    assert out.findings == []


def test_partial_coverage_with_confirmations_blends_phase_3_and_l1() -> None:
    """Partial coverage + confirmations -> blend. Phase 3 findings ship
    + L1 fills the gap. Verdict = max(Phase 3, L1)."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=0.5,
            confirmed=1,
            findings=[_finding("medium", ref="HRP_AL_T0_H0")],
        ),
        l1_verdict_label="malicious",  # L1 had a high-severity hit
        l1_findings=[_finding("high", ref="L1_finding_0")],
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_PARTIAL
    assert out.verdict_source == SOURCE_PHASE_3_PARTIAL
    # Max severity wins: L1's "high" -> malicious beats P3's "medium" -> suspicious
    assert out.final_verdict == "malicious"
    # Blended findings list
    assert len(out.findings) == 2
    refs = {f["finding_ref"] for f in out.findings}
    assert refs == {"HRP_AL_T0_H0", "L1_finding_0"}
    assert out.static_only is False


def test_partial_coverage_phase_3_more_severe_than_l1() -> None:
    """When Phase 3's confirmed severity exceeds L1's, Phase 3 verdict
    wins in the blend."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=0.5,
            confirmed=1,
            findings=[_finding("critical")],
        ),
        l1_verdict_label="suspicious",
        l1_findings=[_finding("medium")],
    )
    out = resolve_verdict(inp)
    assert out.verdict_source == SOURCE_PHASE_3_PARTIAL
    assert out.final_verdict == "critical_malicious"


def test_partial_coverage_zero_confirmations_falls_back_to_l1() -> None:
    """Partial coverage + 0 confirmations -> Phase 3 hasn't refuted L1
    authoritatively. L1 verdict wins; Phase 3 findings (none) + L1
    findings ship."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(coverage_ratio=0.5, confirmed=0),
        l1_verdict_label="suspicious",
        l1_findings=[_finding("medium")],
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_PARTIAL
    assert out.verdict_source == SOURCE_PHASE_3_PARTIAL
    assert out.final_verdict == "suspicious"  # L1 verdict
    assert len(out.findings) == 1  # L1 only


# ── Threshold boundaries ──────────────────────────────────────────────────


def test_coverage_exactly_at_strict_threshold_is_high() -> None:
    """Boundary check: coverage == 0.80 should be ``high`` (inclusive)."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=COVERAGE_STRICT_THRESHOLD,
            confirmed=0,
        ),
        l1_verdict_label="suspicious",
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_HIGH
    assert out.verdict_source == SOURCE_PHASE_3_CLEAN


def test_coverage_exactly_at_fallback_threshold_is_partial() -> None:
    """Boundary check: coverage == 0.30 should be ``partial`` (inclusive)."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=COVERAGE_FALLBACK_THRESHOLD,
            confirmed=0,
        ),
        l1_verdict_label="suspicious",
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_PARTIAL


def test_coverage_just_below_fallback_threshold_is_unreachable() -> None:
    """Boundary check: coverage just below 0.30 should be ``unreachable``."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=COVERAGE_FALLBACK_THRESHOLD - 0.01,
            confirmed=0,
        ),
        l1_verdict_label="suspicious",
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_UNREACHABLE
    assert out.verdict_source == SOURCE_L1_FALLBACK


# ── Severity -> verdict mapping ───────────────────────────────────────────


def test_severity_to_verdict_critical_maps_to_critical_malicious() -> None:
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=1.0,
            confirmed=1,
            findings=[_finding("critical")],
        ),
        l1_verdict_label="clean",
    )
    out = resolve_verdict(inp)
    assert out.final_verdict == "critical_malicious"


def test_severity_to_verdict_max_wins_on_multiple_findings() -> None:
    """When multiple confirmed findings exist, the max severity drives
    the verdict (the standard cascade rule)."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=1.0,
            confirmed=3,
            findings=[
                _finding("low", ref="a"),
                _finding("medium", ref="b"),
                _finding("high", ref="c"),
            ],
        ),
        l1_verdict_label="clean",
    )
    out = resolve_verdict(inp)
    assert out.final_verdict == "malicious"


def test_severity_unknown_falls_back_to_informational() -> None:
    """Unknown severity labels degrade to ``informational`` -- defense-
    in-depth against malformed finding dicts."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=1.0,
            confirmed=1,
            findings=[{"severity": "weird_label", "finding_ref": "x"}],
        ),
        l1_verdict_label="clean",
    )
    out = resolve_verdict(inp)
    assert out.final_verdict == "informational"


# ── Defensive: malformed inputs ──────────────────────────────────────────


def test_malformed_findings_list_does_not_crash() -> None:
    """``findings`` may be missing or non-list (defense-in-depth)."""
    inp = VerdictResolverInput(
        phase_3_loop_summary={
            "ran": True,
            "coverage_ratio": 1.0,
            "hypotheses_confirmed": 1,
            "findings": "not-a-list",  # malformed
        },
        l1_verdict_label="clean",
    )
    out = resolve_verdict(inp)
    # Defensive parsing -> empty findings list. confirmed=1 but no
    # findings to derive severity from -> max_verdict returns "clean".
    assert out.final_verdict == "clean"


def test_unreachable_passes_l1_findings_through_verbatim() -> None:
    """When falling back to L1, the L1 findings list flows to output
    unchanged -- engine output uses these for SARIF / dast_findings."""
    l1_findings = [
        _finding("high", ref="L1_a"),
        _finding("critical", ref="L1_b"),
    ]
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(coverage_ratio=0.1, confirmed=0),
        l1_verdict_label="critical_malicious",
        l1_findings=l1_findings,
    )
    out = resolve_verdict(inp)
    assert out.findings == l1_findings


# ── Stage 1 blindness routing (Path 1: regression guard) ─────────────────


def test_stage_1_blind_zero_callables_zero_confirmed_routes_to_unreachable() -> None:
    """The 23-file measurement (commit fd5be0e) found 5 FN files where
    Stage 1 returned 0 callables but the model still designed 3 attack
    hypotheses from static reading -- all refuted in sandbox. Old
    resolver fired phase_3_clean (final_verdict=clean), incorrectly
    downgrading L1's 'malicious'. New rule: callables=0 AND confirmed=0
    -> unreachable -> L1 wins."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=1.0,
            confirmed=0,
            stage_1_callables_explored=0,  # Stage 1 saw nothing
        ),
        l1_verdict_label="malicious",
        l1_findings=[_finding("high")],
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_UNREACHABLE
    assert out.verdict_source == SOURCE_L1_FALLBACK
    assert out.final_verdict == "malicious"
    assert out.static_only is True


def test_stage_1_blind_but_confirmed_still_routes_to_phase_3_confirmed() -> None:
    """Even when Stage 1 found 0 callables, a CONFIRMED outcome is
    sandbox-grounded evidence (typically via stateful_sequence which
    invokes by name, not via callable enumeration). Don't route those
    to unreachable -- preserve the confirmation."""
    inp = VerdictResolverInput(
        phase_3_loop_summary=_summary(
            coverage_ratio=1.0,
            confirmed=1,
            stage_1_callables_explored=0,
            findings=[_finding("critical")],
        ),
        l1_verdict_label="suspicious",
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_HIGH
    assert out.verdict_source == SOURCE_PHASE_3_CONFIRMED
    assert out.final_verdict == "critical_malicious"


def test_callables_explored_field_missing_defaults_to_blind() -> None:
    """Older summary dicts without the ``stage_1_callables_explored``
    field default to 0 -- routes to unreachable on zero-confirmed.
    Defense against forward-incompatible summary shapes."""
    summary = {
        "ran": True,
        "coverage_ratio": 1.0,
        "hypotheses_confirmed": 0,
        "findings": [],
        # stage_1_callables_explored intentionally missing
    }
    inp = VerdictResolverInput(
        phase_3_loop_summary=summary,
        l1_verdict_label="malicious",
        l1_findings=[_finding("high")],
    )
    out = resolve_verdict(inp)
    assert out.coverage_class == COVERAGE_UNREACHABLE
    assert out.verdict_source == SOURCE_L1_FALLBACK
    assert out.final_verdict == "malicious"
