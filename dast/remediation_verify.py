"""Verified-remediation support: budget policy + patch-confidence model.

Argus's headline feature is *verified* remediation. Replaying the
ORIGINAL exploit against a patch (Phase C) tells us the patch isn't
obviously-still-exploitable — but not that it's a GOOD fix. A patch can:

  * be SHALLOW   — blocks the one PoC, not the vulnerability class;
  * BREAK the app — the exploit "doesn't fire" because the function now
    always errors (a false NEUTRALIZED — the worst outcome);
  * introduce a NEW bug.

The full verification loop (built in stages) layers gates on top of the
original-PoC replay:

  1. functional-preservation  — benign inputs still work          (Stage 2)
  2. adversarial variants     — novel exploits of the same class  (Stage 3)
  3. retry                    — regenerate on any gate failure     (Stage 3)

This module owns the two pieces every stage shares: the per-severity
VERIFICATION BUDGET (the spend/time/quality sweet spot) and the
CONFIDENCE model that turns the gate results into an honest label.
"""

from __future__ import annotations

from dataclasses import dataclass

# ── Confidence labels ────────────────────────────────────────────────
CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"
CONFIDENCE_FAILED = "FAILED"  # patch is not a usable fix


@dataclass(frozen=True)
class VerifyBudget:
    """How much verification a single finding's patch is worth.

    The spend/time sweet spot is encoded here and tiered by severity:
    verify deeply only where it matters. ``max_usd`` is a hard per-finding
    cap on the verification spend (replays + LLM); when hit, verification
    stops and the confidence is reported as capped/partial rather than
    pretending to full assurance.
    """

    functional: int   # # of benign functional-preservation tests
    variants: int     # # of novel adversarial exploit variants
    retries: int      # # of patch regenerations on gate failure
    max_usd: float    # hard cap on verification spend for this finding


# Balanced posture (operator default; tunable per-scan). Rationale:
# verify deeply for high/critical (where a bad/shallow patch is costly),
# stay cheap for low. Replays within a finding run CONCURRENTLY, so depth
# costs money, not much wall-clock.
_BALANCED: dict[str, VerifyBudget] = {
    "critical": VerifyBudget(functional=2, variants=5, retries=2, max_usd=1.50),
    "high": VerifyBudget(functional=1, variants=3, retries=1, max_usd=0.75),
    "medium": VerifyBudget(functional=1, variants=2, retries=0, max_usd=0.30),
    "low": VerifyBudget(functional=1, variants=0, retries=0, max_usd=0.10),
}

_DEFAULT_SEVERITY = "medium"


def verify_budget_for(
    severity: str | None, table: dict[str, VerifyBudget] | None = None
) -> VerifyBudget:
    """Resolve the verification budget for a finding severity."""
    t = table or _BALANCED
    key = (severity or _DEFAULT_SEVERITY).strip().lower()
    return t.get(key, t[_DEFAULT_SEVERITY])


def compute_confidence(
    *,
    poc_refuted: bool,
    functional_ok: bool | None,
    variants_total: int,
    variants_fired: int,
    budget_capped: bool = False,
) -> str:
    """Turn gate results into a patch-confidence label.

    Inputs:
      * ``poc_refuted``     — did replaying the ORIGINAL exploit show it
                              no longer fires?
      * ``functional_ok``   — did benign inputs still work? ``None`` =
                              the functional gate didn't run.
      * ``variants_total``  — # adversarial variants attempted.
      * ``variants_fired``  — # that still exploited the patch.
      * ``budget_capped``   — verification stopped early on the $ cap.

    Semantics (fail-closed — any hard failure ⇒ FAILED, not a soft label):
      * not poc_refuted              → FAILED (exploit still fires)
      * functional_ok is False       → FAILED (patch broke the app)
      * variants_fired > 0           → FAILED (shallow patch)
      * poc + functional + variants  → HIGH   (fully verified)
      * poc + (functional OR variants), partial/capped → MEDIUM
      * poc only (no deeper gates)   → LOW
    """
    if not poc_refuted:
        return CONFIDENCE_FAILED
    if functional_ok is False:
        return CONFIDENCE_FAILED
    if variants_fired > 0:
        return CONFIDENCE_FAILED
    have_functional = functional_ok is True
    have_variants = variants_total > 0
    if have_functional and have_variants and not budget_capped:
        return CONFIDENCE_HIGH
    if have_functional or have_variants:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW
