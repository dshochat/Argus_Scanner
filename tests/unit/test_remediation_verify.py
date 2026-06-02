"""Unit tests for the remediation verification foundation:
per-severity budget policy + the patch-confidence model."""
from __future__ import annotations

from dast.remediation_verify import (
    CONFIDENCE_FAILED,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    VerifyBudget,
    compute_confidence,
    verify_budget_for,
)

# ── budget policy ────────────────────────────────────────────────────


def test_budget_tiers_scale_with_severity() -> None:
    crit = verify_budget_for("critical")
    high = verify_budget_for("high")
    med = verify_budget_for("medium")
    low = verify_budget_for("low")
    # Depth (variants/retries/$) is monotonically non-increasing by severity.
    assert crit.variants >= high.variants >= med.variants >= low.variants
    assert crit.retries >= high.retries >= med.retries >= low.retries
    assert crit.max_usd >= high.max_usd >= med.max_usd >= low.max_usd
    # low never spends on adversarial variants or retries.
    assert low.variants == 0 and low.retries == 0


def test_budget_unknown_or_missing_severity_falls_back_to_medium() -> None:
    assert verify_budget_for("bogus") == verify_budget_for("medium")
    assert verify_budget_for(None) == verify_budget_for("medium")


def test_budget_severity_is_case_insensitive() -> None:
    assert verify_budget_for("CRITICAL") == verify_budget_for("critical")


def test_budget_table_override() -> None:
    custom = {"medium": VerifyBudget(9, 9, 9, 9.0)}
    assert verify_budget_for("medium", custom).variants == 9


# ── confidence model ─────────────────────────────────────────────────


def test_confidence_failed_when_poc_still_fires() -> None:
    assert compute_confidence(
        poc_refuted=False, functional_ok=True, variants_total=5, variants_fired=0
    ) == CONFIDENCE_FAILED


def test_confidence_failed_when_patch_breaks_functionality() -> None:
    """The worst outcome: exploit gone but the app no longer works."""
    assert compute_confidence(
        poc_refuted=True, functional_ok=False, variants_total=3, variants_fired=0
    ) == CONFIDENCE_FAILED


def test_confidence_failed_when_a_variant_still_exploits() -> None:
    """Shallow patch: blocks the PoC but a variant of the same class fires."""
    assert compute_confidence(
        poc_refuted=True, functional_ok=True, variants_total=5, variants_fired=1
    ) == CONFIDENCE_FAILED


def test_confidence_high_when_fully_verified() -> None:
    assert compute_confidence(
        poc_refuted=True, functional_ok=True, variants_total=5, variants_fired=0
    ) == CONFIDENCE_HIGH


def test_confidence_medium_when_capped_or_partial() -> None:
    # Budget cap hit mid-verification → not full assurance.
    assert compute_confidence(
        poc_refuted=True, functional_ok=True, variants_total=5,
        variants_fired=0, budget_capped=True,
    ) == CONFIDENCE_MEDIUM
    # Functional passed but no adversarial variants run → partial.
    assert compute_confidence(
        poc_refuted=True, functional_ok=True, variants_total=0, variants_fired=0
    ) == CONFIDENCE_MEDIUM
    # Variants passed but functional gate didn't run.
    assert compute_confidence(
        poc_refuted=True, functional_ok=None, variants_total=3, variants_fired=0
    ) == CONFIDENCE_MEDIUM


def test_confidence_low_when_poc_replay_only() -> None:
    """Today's behaviour (Stage 1): original-PoC replay only, no deeper
    gates → LOW, not an over-confident NEUTRALIZED."""
    assert compute_confidence(
        poc_refuted=True, functional_ok=None, variants_total=0, variants_fired=0
    ) == CONFIDENCE_LOW
