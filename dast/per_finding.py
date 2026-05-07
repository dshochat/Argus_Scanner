"""Per-finding DAST validation (Tier 1.5, v1.1).

Derives a per-finding validation status from the existing DAST output.
For each L1 vulnerability, classifies it as:

    CONFIRMED   — DAST's hypothesis-validation loop accepted a
                  hypothesis whose ``finding_ref`` matches this
                  finding's index. The file's runtime behavior backs
                  the L1 claim.

    BLOCKED     — DAST tested this finding via a hypothesis that the
                  validator rejected with reasoning indicating an
                  in-code defense (sanitization, escaping, allowlist,
                  validation, filter, etc.). The vulnerability class
                  exists in the code, but the file's own mitigations
                  prevent exploitation.

    UNREACHED   — DAST tested this finding via a hypothesis that the
                  validator rejected with reasoning indicating the
                  code path couldn't be triggered (missing trigger,
                  unreachable, no path observed). The vulnerability
                  class exists but isn't reachable from any tested
                  input vector.

    NOT_TESTED  — DAST didn't generate a hypothesis for this finding.
                  The orchestrator's plan didn't pick it (typically
                  because L1's confidence was low or the iteration
                  budget ran out before reaching it).

CONFIRMED comes from ``dast.findings_validated`` (the existing
hypothesis-loop output). BLOCKED / UNREACHED / NOT_TESTED come from
journal records — the orchestrator's append-only log of accepted
and rejected hypotheses with rationale text. We classify rejection
text with a regex keyword set; no prompt or validator changes
required.

This is Tier 1.5 — heuristic but actionable. Tier 2.0 (future) will
replace the keyword classifier with structured ``rejection_category``
emitted by the validator itself.

Effective CWE filtering: :func:`effective_findings` returns only the
CONFIRMED subset, basis for "Effective CWE F1" in the launch report.
``effective_findings_with_blocked`` (also exposed) returns CONFIRMED
+ BLOCKED — the "real vulns regardless of mitigation" view useful for
defense-in-depth audits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

# Status of one L1 finding after DAST.
PerFindingStatus = Literal["CONFIRMED", "BLOCKED", "UNREACHED", "NOT_TESTED"]


# ── Rejection-rationale classifier ───────────────────────────────────────────

# Keywords indicating the file's own code defended against the attack.
# Matched with word-boundary regex on the validator's rationale string.
_BLOCKED_KEYWORDS = (
    r"\bsanitiz",
    r"\bescape[ds]?\b",
    r"\bescaping\b",
    # NOTE: ``\bvalidat`` would match ``validator`` (the orchestrator's
    # validator class — present in every rejection message: "validator
    # rejected: ..."). We need verb forms only.
    r"\bvalidates?\b",
    r"\bvalidated\b",
    r"\bvalidating\b",
    r"\bvalidation\b",
    r"\ballow[- ]?list",
    r"\bdeny[- ]?list",
    r"\bblock(?:ed|s|ing)?\b",
    r"\bguard(?:ed|s|ing)?\b",
    r"shlex\.quote",
    r"escape_html",
    r"parameteri[sz]ed",
    r"prepared\s+statement",
    r"input.*?(?:check|verif)",
    r"safely\s+(?:handled|escaped|encoded)",
    r"\bfilter(?:ed|ing|s)?\b",
)

# Keywords indicating the code path wasn't reachable from tested inputs.
_UNREACHED_KEYWORDS = (
    r"\bunreach",
    r"\bnot\s+reach",
    r"\bno\s+path",
    r"path.*?not\s+(?:hit|triggered|reached)",
    r"couldn'?t\s+trigger",
    r"trigger\s+fail",
    r"\bnever\s+(?:executed|invoked|called|reached|triggered|hit)\b",
    r"\bnot\s+(?:invoked|called|reached|triggered)\b",
    r"\bdead\s+code\b",
    r"no\s+input\s+(?:reaches|hits)",
    r"input\s+vector\s+missing",
)

# Keywords indicating the sandbox returned an empty / stub trace —
# DAST-203 case. Often correlates with the orchestrator generating a
# static-only hypothesis ("verify presence of X comments") that has no
# runtime test to execute.
_STUB_KEYWORDS = (
    r"is_stub_no_trace",
    r"stub\s+(?:with\s+)?no\s+events",
    r"sandbox\s+trace.*?stub",
    r"empty\s+(?:sandbox\s+)?trace",
    r"no\s+(?:sandbox\s+)?events\s+(?:captured|observed)",
    r"static[- ]only\s+(?:plan|hypothesis)",
    r"no\s+runtime\s+(?:trigger|test|action)",
)

_BLOCKED_RE = re.compile("|".join(_BLOCKED_KEYWORDS), re.IGNORECASE)
_UNREACHED_RE = re.compile("|".join(_UNREACHED_KEYWORDS), re.IGNORECASE)
_STUB_RE = re.compile("|".join(_STUB_KEYWORDS), re.IGNORECASE)


# Sub-reason for NOT_TESTED — surfaced in the launch report so users can
# see WHY each finding wasn't validated.
NotTestedReason = Literal[
    "infra_stub",  # sandbox returned stub trace (DAST-203 case)
    "inconclusive",  # rationale doesn't match any classification keyword
    "not_planned",  # no journal entry for this finding
]


def _classify_rejection_rationale(
    rationale: str,
) -> Literal["BLOCKED", "UNREACHED", "STUB", "OTHER"]:
    """Map a free-text rejection reason to one of four buckets.

    Order matters: STUB > BLOCKED > UNREACHED. STUB is checked first
    because a stub trace ("is_stub_no_trace=true") indicates the
    rationale is about infrastructure, not behavior — even if it
    happens to mention "validation" or "filter" in surrounding text.

    Returns:
        BLOCKED   — defensive code observed (sanitization, filtering, ...)
        UNREACHED — code path not reachable from any tested input
        STUB      — sandbox returned a stub / no-events trace (DAST-203)
        OTHER     — none of the above; downstream treats as NOT_TESTED
    """
    if not rationale:
        return "OTHER"
    if _STUB_RE.search(rationale):
        return "STUB"
    if _BLOCKED_RE.search(rationale):
        return "BLOCKED"
    if _UNREACHED_RE.search(rationale):
        return "UNREACHED"
    return "OTHER"


@dataclass(frozen=True)
class PerFindingValidation:
    """One L1 vulnerability's DAST validation outcome."""

    finding_id: str  # "H001", "H002", ... — matches DAST runner's translator
    cwe: str
    type: str
    severity: str
    line: int | None
    status: PerFindingStatus
    confidence: float | None  # carried through from L1's per-finding confidence
    # Tier 1.5: rejection reasoning text from the validator, surfaced
    # for BLOCKED / UNREACHED entries so users can see WHY the attack
    # didn't validate. None for CONFIRMED.
    rejection_reason: str | None = None
    # DAST-203: when status == NOT_TESTED, this further classifies why.
    # ``infra_stub`` — sandbox returned stub trace (DAST-203 H004 case).
    # ``inconclusive`` — rationale fell through all classifiers.
    # ``not_planned`` — orchestrator never picked this finding (no journal entry).
    # None for any non-NOT_TESTED status.
    not_tested_reason: NotTestedReason | None = None
    # PoC export (v1.1): for CONFIRMED findings, the proof_of_concept
    # exploit string from the L1 vulnerability — the literal input that
    # triggered the runtime evidence. Lets the launch report show
    # demoable PoCs ("here's the curl command that exfiltrated /etc/
    # passwd"). Empty string for CONFIRMED findings without a PoC,
    # None for non-CONFIRMED statuses (PoC is meaningless until DAST
    # validates).
    proof_of_concept: str | None = None
    # PoC export (v1.1): a short summary of the runtime evidence DAST
    # observed when validating this finding. Pulled from journal records
    # that match the finding_id. Examples: "Sandbox observed network call
    # to attacker.com" / "subprocess.run was invoked with shell=True".
    runtime_evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "cwe": self.cwe,
            "type": self.type,
            "severity": self.severity,
            "line": self.line,
            "status": self.status,
            "confidence": self.confidence,
            "rejection_reason": self.rejection_reason,
            "not_tested_reason": self.not_tested_reason,
            "proof_of_concept": self.proof_of_concept,
            "runtime_evidence": self.runtime_evidence,
        }


def _finding_id_for_index(index_zero_based: int) -> str:
    """Match the convention used by ``dast.runner._scan_result_to_l1_output``
    so per-finding IDs zip cleanly with DAST's ``finding_ref`` values."""
    return f"H{index_zero_based + 1:03d}"


def _index_journal_by_finding(
    journal_records: list[dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """Build a ``{finding_id: most_severe_record}`` mapping from journal
    records. When multiple records exist for the same finding (multiple
    hypotheses across iterations), prefer the one most informative for
    classification: a CONFIRMED beats a REJECTED, and a REJECTED with
    rationale beats one without.

    Journal records are dicts with keys: iter, phase, claim_id, verdict,
    rationale. ``claim_id`` matches finding_id by convention (the DAST
    runner translator sets ``hypothesis.id == hypothesis.finding_ref ==
    H001/H002/...``).
    """
    out: dict[str, dict[str, Any]] = {}
    if not journal_records:
        return out
    priority = {"confirmed": 4, "refuted": 3, "rejected": 2, "inconclusive": 1, None: 0}
    for r in journal_records:
        if not isinstance(r, dict):
            continue
        cid = r.get("claim_id")
        if not cid or not isinstance(cid, str):
            continue
        existing = out.get(cid)
        if existing is None:
            out[cid] = r
            continue
        # Pick the higher-priority verdict; tiebreak prefers one with rationale.
        ev_pri = priority.get(existing.get("verdict"), 0)
        new_pri = priority.get(r.get("verdict"), 0)
        if new_pri > ev_pri or (
            new_pri == ev_pri and len(str(r.get("rationale") or "")) > len(str(existing.get("rationale") or ""))
        ):
            out[cid] = r
    return out


def derive_per_finding_validation(
    l1_vulnerabilities: list[dict[str, Any]],
    dast_validated_findings: list[str],
    journal_records: list[dict[str, Any]] | None = None,
) -> list[PerFindingValidation]:
    """Zip L1 findings with DAST output to produce per-finding validation.

    Status precedence (Tier 2, v1.1):
      1. ``finding_id`` in ``dast_validated_findings`` -> CONFIRMED.
      2. Journal record's ``verdict`` field (structured, validator-emitted)
         is the authoritative signal:
            - ``"confirmed"`` -> CONFIRMED
            - ``"refuted"``   -> BLOCKED (validator explicitly proved no-attack)
            - ``"inconclusive"`` -> NOT_TESTED (sandbox couldn't decide)
      3. Fallback for ``"rejected"`` (rule-failure, not behaviorally
         conclusive): use the rationale text classifier
         (:func:`_classify_rejection_rationale`) to split BLOCKED /
         UNREACHED / NOT_TESTED. Heuristic — catches sanitization,
         escape, parameterization, allowlists, etc.
      4. No journal entry -> NOT_TESTED.

    Why precedence matters: the validator's ``verdict`` is emitted by
    structured rule logic, not free-text. ``rejected`` simply means
    "fails one of the validator's hypothesis-quality rules" (R1/R2/R3
    in HypothesisValidator) and doesn't tell us about the file's
    defensive posture — that's where the rationale text classifier
    comes in.

    Args:
        l1_vulnerabilities: ``ScanResult.vulnerabilities`` after L1.
        dast_validated_findings: ``dast_out["validated_findings"]``.
        journal_records: optional ``dast_out["journal_records"]`` — list
            of journal dicts (claim_id, verdict, rationale).

    Returns:
        One :class:`PerFindingValidation` per L1 finding, ordered.
    """
    confirmed_ids = set(dast_validated_findings or [])
    journal_by_id = _index_journal_by_finding(journal_records)

    out: list[PerFindingValidation] = []
    for i, v in enumerate(l1_vulnerabilities or []):
        if not isinstance(v, dict):
            continue
        fid = _finding_id_for_index(i)
        status: PerFindingStatus
        rejection_reason: str | None = None
        not_tested_reason: NotTestedReason | None = None
        proof_of_concept: str | None = None
        runtime_evidence: str | None = None

        if fid in confirmed_ids:
            status = "CONFIRMED"
            # Surface PoC + runtime evidence for CONFIRMED findings.
            poc = v.get("proof_of_concept")
            if isinstance(poc, str) and poc.strip():
                proof_of_concept = poc.strip()[:500]
            jrec = journal_by_id.get(fid)
            if jrec is not None:
                rat = str(jrec.get("rationale") or "").strip()
                if rat:
                    runtime_evidence = rat[:500]
        else:
            jrec = journal_by_id.get(fid)
            if jrec is None:
                status = "NOT_TESTED"
                not_tested_reason = "not_planned"
            else:
                verdict = jrec.get("verdict")
                rationale = str(jrec.get("rationale") or "")
                # Structured verdict takes precedence over rationale text.
                if verdict == "confirmed":
                    status = "CONFIRMED"
                    poc = v.get("proof_of_concept")
                    if isinstance(poc, str) and poc.strip():
                        proof_of_concept = poc.strip()[:500]
                    if rationale:
                        runtime_evidence = rationale[:500]
                elif verdict == "refuted":
                    status = "BLOCKED"
                    rejection_reason = rationale[:240] if rationale else None
                elif verdict == "inconclusive":
                    status = "NOT_TESTED"
                    not_tested_reason = "inconclusive"
                    rejection_reason = rationale[:240] if rationale else None
                else:
                    # "rejected" or unknown — fall back to rationale text
                    # classifier. Note: "rejected" is a hypothesis-quality
                    # failure (rules R1/R2/R3 in HypothesisValidator),
                    # not a runtime observation. Text classifier extracts
                    # what we can from the validator's reasoning.
                    cls = _classify_rejection_rationale(rationale)
                    if cls == "BLOCKED":
                        status = "BLOCKED"
                        rejection_reason = rationale[:240]
                    elif cls == "UNREACHED":
                        status = "UNREACHED"
                        rejection_reason = rationale[:240]
                    elif cls == "STUB":
                        # DAST-203: sandbox returned stub trace — typically
                        # a static-only hypothesis the orchestrator
                        # generated that has no runtime test to execute.
                        status = "NOT_TESTED"
                        not_tested_reason = "infra_stub"
                        rejection_reason = rationale[:240]
                    else:
                        status = "NOT_TESTED"
                        not_tested_reason = "inconclusive"
                        rejection_reason = rationale[:240] if rationale else None

        line_val = v.get("line") if isinstance(v.get("line"), int) else None
        conf = v.get("confidence")
        confidence = float(conf) if isinstance(conf, (int, float)) else None
        out.append(
            PerFindingValidation(
                finding_id=fid,
                cwe=str(v.get("cwe") or ""),
                type=str(v.get("type") or ""),
                severity=str(v.get("severity") or ""),
                line=line_val,
                status=status,
                confidence=confidence,
                rejection_reason=rejection_reason,
                not_tested_reason=not_tested_reason,
                proof_of_concept=proof_of_concept,
                runtime_evidence=runtime_evidence,
            )
        )
    return out


# ── Effective findings (CONFIRMED-only filter) ───────────────────────────────


def _status_of(p: PerFindingValidation | dict[str, Any]) -> str:
    """Read status field from either dataclass or dict form."""
    if isinstance(p, PerFindingValidation):
        return p.status
    if isinstance(p, dict):
        return str(p.get("status") or "")
    return ""


def _id_of(p: PerFindingValidation | dict[str, Any]) -> str:
    if isinstance(p, PerFindingValidation):
        return p.finding_id
    if isinstance(p, dict):
        return str(p.get("finding_id") or "")
    return ""


def effective_findings(
    l1_vulnerabilities: list[dict[str, Any]],
    per_finding: list[PerFindingValidation] | list[dict[str, Any]],
    *,
    include_blocked: bool = False,
) -> list[dict[str, Any]]:
    """Return L1 vulnerabilities filtered by DAST status.

    By default returns only CONFIRMED — the strictest filter, used
    for "Effective CWE F1" precision metric. With ``include_blocked=True``,
    also includes BLOCKED findings (real vulnerabilities defended by
    in-code mitigations — useful for defense-in-depth audits).

    Order is preserved.
    """
    keep_statuses = {"CONFIRMED"}
    if include_blocked:
        keep_statuses.add("BLOCKED")

    keep_ids = {_id_of(p) for p in per_finding if _status_of(p) in keep_statuses}
    return [
        v
        for i, v in enumerate(l1_vulnerabilities or [])
        if isinstance(v, dict) and _finding_id_for_index(i) in keep_ids
    ]


# ── Aggregate stats (for launch report) ──────────────────────────────────────


def per_finding_stats(
    records: list[PerFindingValidation] | list[dict[str, Any]],
) -> dict[str, int | float]:
    """Counts + percentages for a single file's per-finding validation list.

    Reports all four status buckets plus convenience aggregates.
    """
    total = 0
    n_confirmed = 0
    n_blocked = 0
    n_unreached = 0
    n_not_tested = 0
    for r in records:
        total += 1
        s = _status_of(r)
        if s == "CONFIRMED":
            n_confirmed += 1
        elif s == "BLOCKED":
            n_blocked += 1
        elif s == "UNREACHED":
            n_unreached += 1
        else:
            n_not_tested += 1
    return {
        "n_findings": total,
        "n_confirmed": n_confirmed,
        "n_blocked": n_blocked,
        "n_unreached": n_unreached,
        "n_not_tested": n_not_tested,
        # Legacy field — confirmed / total — kept for backward compat with
        # consumers that haven't been updated for Tier 1.5.
        "n_untested": total - n_confirmed,
        "confirmed_pct": round(n_confirmed / total * 100, 1) if total else 0.0,
        "blocked_pct": round(n_blocked / total * 100, 1) if total else 0.0,
        "unreached_pct": round(n_unreached / total * 100, 1) if total else 0.0,
        "not_tested_pct": round(n_not_tested / total * 100, 1) if total else 0.0,
    }


__all__ = [
    "PerFindingStatus",
    "PerFindingValidation",
    "derive_per_finding_validation",
    "effective_findings",
    "per_finding_stats",
]
