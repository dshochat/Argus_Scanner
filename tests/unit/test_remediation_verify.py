"""Unit tests for the remediation verification foundation:
per-severity budget policy + the patch-confidence model + the
verification orchestrator (Stage 2+3)."""

from __future__ import annotations

import asyncio

from dast.remediation_verify import (
    CONFIDENCE_FAILED,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    VerifyBudget,
    compute_confidence,
    verify_budget_for,
    verify_patch,
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
    assert (
        compute_confidence(poc_refuted=False, functional_ok=True, variants_total=5, variants_fired=0)
        == CONFIDENCE_FAILED
    )


def test_confidence_failed_when_patch_breaks_functionality() -> None:
    """The worst outcome: exploit gone but the app no longer works."""
    assert (
        compute_confidence(poc_refuted=True, functional_ok=False, variants_total=3, variants_fired=0)
        == CONFIDENCE_FAILED
    )


def test_confidence_failed_when_a_variant_still_exploits() -> None:
    """Shallow patch: blocks the PoC but a variant of the same class fires."""
    assert (
        compute_confidence(poc_refuted=True, functional_ok=True, variants_total=5, variants_fired=1)
        == CONFIDENCE_FAILED
    )


def test_confidence_high_when_fully_verified() -> None:
    assert (
        compute_confidence(poc_refuted=True, functional_ok=True, variants_total=5, variants_fired=0) == CONFIDENCE_HIGH
    )


def test_confidence_medium_when_capped_or_partial() -> None:
    # Budget cap hit mid-verification → not full assurance.
    assert (
        compute_confidence(
            poc_refuted=True,
            functional_ok=True,
            variants_total=5,
            variants_fired=0,
            budget_capped=True,
        )
        == CONFIDENCE_MEDIUM
    )
    # Functional passed but no adversarial variants run → partial.
    assert (
        compute_confidence(poc_refuted=True, functional_ok=True, variants_total=0, variants_fired=0)
        == CONFIDENCE_MEDIUM
    )
    # Variants passed but functional gate didn't run.
    assert (
        compute_confidence(poc_refuted=True, functional_ok=None, variants_total=3, variants_fired=0)
        == CONFIDENCE_MEDIUM
    )


def test_confidence_low_when_poc_replay_only() -> None:
    """Today's behaviour (Stage 1): original-PoC replay only, no deeper
    gates → LOW, not an over-confident NEUTRALIZED."""
    assert (
        compute_confidence(poc_refuted=True, functional_ok=None, variants_total=0, variants_fired=0) == CONFIDENCE_LOW
    )


# ── verification orchestrator (Stage 2+3) ────────────────────────────


def test_verify_skips_all_gates_when_poc_still_fires() -> None:
    async def func():  # must not run
        raise AssertionError("functional gate should not run")

    async def adv(n):
        raise AssertionError("adversarial gate should not run")

    out = asyncio.run(verify_patch(poc_refuted=False, severity="critical", run_functional=func, run_adversarial=adv))
    assert out.confidence == CONFIDENCE_FAILED
    assert out.needs_retry is False  # nothing was fixed → not a retryable patch


def test_verify_functional_fail_skips_adversarial_and_signals_retry() -> None:
    calls = {"adv": 0}

    async def func():
        return False  # patch broke the app

    async def adv(n):
        calls["adv"] += 1
        return (n, 0)

    out = asyncio.run(verify_patch(poc_refuted=True, severity="critical", run_functional=func, run_adversarial=adv))
    assert out.confidence == CONFIDENCE_FAILED
    assert out.functional_ok is False
    assert calls["adv"] == 0  # early-exit: don't spend adversarial budget
    assert out.needs_retry is True


def test_verify_high_when_functional_passes_and_no_variant_fires() -> None:
    async def func():
        return True

    async def adv(n):
        return (n, 0)

    out = asyncio.run(verify_patch(poc_refuted=True, severity="critical", run_functional=func, run_adversarial=adv))
    assert out.confidence == CONFIDENCE_HIGH
    assert out.is_high_quality is True
    assert out.variants_total == 5  # critical budget


def test_verify_failed_and_retries_when_a_variant_still_exploits() -> None:
    async def func():
        return True

    async def adv(n):
        return (n, 1)  # shallow patch: one variant still gets through

    out = asyncio.run(verify_patch(poc_refuted=True, severity="high", run_functional=func, run_adversarial=adv))
    assert out.confidence == CONFIDENCE_FAILED
    assert out.variants_fired == 1
    assert out.needs_retry is True


def test_verify_medium_for_low_severity_no_variants() -> None:
    async def func():
        return True

    async def adv(n):
        raise AssertionError("low severity budgets zero variants")

    out = asyncio.run(verify_patch(poc_refuted=True, severity="low", run_functional=func, run_adversarial=adv))
    assert out.confidence == CONFIDENCE_MEDIUM  # functional pass, no variants run


# ── SCAN-007: per-finding cost cap (max_usd / budget_capped) ──────────


def test_confidence_budget_capped_downgrades_high_to_medium() -> None:
    # Fully-passing gates, but verification was capped on $ → MEDIUM, not HIGH.
    assert (
        compute_confidence(
            poc_refuted=True,
            functional_ok=True,
            variants_total=3,
            variants_fired=0,
            budget_capped=True,
        )
        == CONFIDENCE_MEDIUM
    )


def test_verify_skips_adversarial_when_spent_over_max_usd() -> None:
    """When the per-finding verification spend has hit max_usd, the
    expensive adversarial gate is skipped and the result is MEDIUM
    (capped/partial) — not an overspend, not a false HIGH."""
    adv_called = {"n": 0}

    async def func():
        return True

    async def adv(n):
        adv_called["n"] += 1
        return (n, 0)

    # high budget max_usd = 0.75; report spend already over it.
    out = asyncio.run(
        verify_patch(
            poc_refuted=True,
            severity="high",
            run_functional=func,
            run_adversarial=adv,
            spent_usd=lambda: 0.80,
        )
    )
    assert adv_called["n"] == 0  # adversarial gate did NOT run
    assert out.budget_capped is True
    assert out.variants_total == 0
    assert out.confidence == CONFIDENCE_MEDIUM
    assert out.needs_retry is False


def test_verify_runs_adversarial_when_spend_under_max_usd() -> None:
    """Under the per-finding cap, the adversarial gate runs normally and a
    clean pass earns HIGH (budget_capped stays False)."""

    async def func():
        return True

    async def adv(n):
        return (n, 0)

    out = asyncio.run(
        verify_patch(
            poc_refuted=True,
            severity="high",
            run_functional=func,
            run_adversarial=adv,
            spent_usd=lambda: 0.10,  # well under high's $0.75 cap
        )
    )
    assert out.budget_capped is False
    assert out.variants_total == 3  # high budget
    assert out.confidence == CONFIDENCE_HIGH
