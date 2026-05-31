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
#
# Semantics (v1.6+ — REJECTED added):
#   * CONFIRMED  — DAST tested + sandbox observed the exploit firing.
#                  The strongest positive result. Confidence in
#                  exploitability.
#   * REJECTED   — DAST tested + sandbox observed no exploit AND there
#                  was no specific defense (sanitization, validation)
#                  in the file. The L1 claim looks WRONG. The strongest
#                  negative result; FP-reduction win.
#   * BLOCKED    — DAST tested + the file's own code defended against
#                  the attack (sanitization, escaping, allowlist,
#                  validation). The L1 claim may be correct in
#                  principle but is mitigated in this codebase.
#   * UNREACHED  — DAST tested + the vulnerable code path was not
#                  reachable from any input we tried. Possibly real
#                  vuln, possibly dead code.
#   * NOT_TESTED — DAST didn't actually test this finding (budget,
#                  pattern-only CWE, infra stub, etc.). See
#                  ``NotTestedReason`` for the sub-cause.
PerFindingStatus = Literal[
    "CONFIRMED",
    "REJECTED",
    "BLOCKED",
    "UNREACHED",
    "NOT_TESTED",
]


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
#
# v1.6+: expanded from 3 to 7 reasons after the 23-file eval found all
# 26 NOT_TESTED entries collapsed to "inconclusive", losing the actual
# failure mode (commit cae9e5f).
NotTestedReason = Literal[
    "infra_stub",  # sandbox returned stub trace (DAST-203 case)
    "inconclusive",  # rationale doesn't match any classifier keyword
    "not_planned",  # no journal entry; reason unknown
    "unfireable_pattern_cwe",  # CWE is pattern-detection (CWE-506/451/etc.);
    # DAST has no exploit payload that fires it
    "budget_exceeded",  # MAX_PROBE_RUNS_PER_FILE / max_cost reached
    # before this finding got a slot
    "non_python_file",  # file extension not in Python-probe scope
    "unreachable_function",  # named function not in module namespace
    "dast_not_attempted",  # DAST didn't run on this file
    # (L1 verdict below discovery_trigger_verdicts)
    "runtime_error",  # v15.8 (2026-05-20): PoC crashed with a Python
    # runtime error (AttributeError / ImportError / NameError /
    # TypeError / ModuleNotFoundError) rather than producing a
    # refutation signal. Most common cause: L1 wrote the PoC against
    # a deprecated or removed API (e.g. ``ruamel.yaml.load()`` which
    # was removed in v0.19+). Distinct from ``inconclusive`` because
    # we KNOW what went wrong — the PoC crashed deterministically —
    # and from ``infra_stub`` because the sandbox DID execute the
    # plan, the failure is in the PoC code itself. Marking this
    # separately gives operators a concrete fix-it signal: regenerate
    # the PoC against the installed API surface.
]


# CWEs whose definition is pattern-detection rather than exploit-firing.
# DAST has no payload to test against these — they're identified by
# static patterns (presence of code shape, embedded data, comment style).
# When DAST doesn't validate them, the right NOT_TESTED reason is
# ``unfireable_pattern_cwe``, not ``inconclusive`` or ``not_planned``.
#
# Why each is here:
#   * CWE-451  — UI/UX representation mismatch (clickjacking-class).
#                Browser-level concern, no Python sandbox payload.
#   * CWE-506  — embedded malicious code. The MERE PRESENCE of an
#                encoded blob is the finding. DAST can run the
#                decoded blob (separate finding) but can't fire
#                "embedded code exists" as an exploit.
#   * CWE-532  — info exposure through log. Pattern: "this code logs
#                X". DAST can't fire "logging happens" as exploit
#                fire-signal.
#   * CWE-1021 — improper frame restriction. Browser-level; no
#                Python sandbox equivalent.
#   * CWE-354  — improper integrity check. Pattern: "missing
#                signature verification". DAST can't synthesize a
#                bypass — no signed input to corrupt.
#   * CWE-1059 — code without security feature. Anti-pattern; no
#                exploit input fires it.
#   * CWE-1039 — inadequate detection of malicious input on a model.
#                ML-pattern; DAST has no adversarial example payload
#                generator for general models.
_UNFIREABLE_PATTERN_CWES: frozenset[str] = frozenset(
    {
        "CWE-451",
        "CWE-506",
        "CWE-532",
        "CWE-1021",
        "CWE-354",
        "CWE-1059",
        "CWE-1039",
    }
)


# File extensions DAST's Python probe path can handle. Non-Python
# files (JS, .pth, etc.) get NOT_TESTED + reason=non_python_file when
# DAST didn't validate them.
_PYTHON_PROBE_EXTS: frozenset[str] = frozenset({".py"})


def _normalize_cwe(s: str | None) -> str:
    """``CWE-94`` / ``cwe-94`` / ``94`` -> ``CWE-94`` for matching."""
    if not s:
        return ""
    v = str(s).strip().upper()
    if v.startswith("CWE-"):
        return v
    if v.startswith("CWE"):
        return "CWE-" + v[3:].lstrip("-")
    if v.isdigit():
        return f"CWE-{v}"
    return v


def _is_unfireable_pattern_cwe(cwe: str | None) -> bool:
    """True iff this CWE class can't be DAST-fired as an exploit."""
    return _normalize_cwe(cwe) in _UNFIREABLE_PATTERN_CWES


def _is_non_python_file(file_name: str | None) -> bool:
    """True iff the file extension isn't in the Python-probe scope."""
    if not file_name:
        return False
    lower = file_name.lower()
    return not any(lower.endswith(ext) for ext in _PYTHON_PROBE_EXTS)


# v15.8 (2026-05-20): Python runtime errors in the PoC stderr.
# When the sandbox executes the PoC and Python raises one of these
# before the exploit payload runs, the finding is NOT_TESTED for a
# very specific reason: the PoC code itself was wrong (most often,
# L1 wrote it against a deprecated API). Distinct from refutation
# (the file's defense) or stub-trace (no execution at all).
_RUNTIME_ERROR_RE = re.compile(
    r"\b(?:AttributeError|ImportError|ModuleNotFoundError|NameError|"
    r"TypeError|SyntaxError|IndentationError|ValueError|KeyError|"
    r"IndexError|RuntimeError|RecursionError)\b"
    r"|Traceback \(most recent call last\)",
    re.IGNORECASE,
)


def _classify_runtime_error(text: str) -> bool:
    """v15.8: detect Python runtime errors in PoC stderr/stdout.

    Returns True iff ``text`` contains a Python traceback or one of
    the common exception names (case-insensitive). Used to set
    ``not_tested_reason='runtime_error'`` on H### findings whose
    PoC crashed before producing a refutation signal — typically
    because L1 wrote the PoC against a removed / renamed API.
    """
    if not text:
        return False
    return bool(_RUNTIME_ERROR_RE.search(text))


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
            new_pri == ev_pri
            and len(str(r.get("rationale") or "")) > len(str(existing.get("rationale") or ""))
        ):
            out[cid] = r
    return out


def _index_sandbox_stderr_by_finding(
    journal_records: list[dict[str, Any]] | None,
) -> dict[str, str]:
    """v15.8 (2026-05-20): pull the sandbox stderr excerpt for each
    H### finding out of SANDBOX_EXEC journal records.

    The orchestrator writes one SANDBOX_EXEC entry per probe submission
    with ``rationale`` carrying ``trace.stderr_excerpt`` (orchestrator
    line ~1484, the journal write following ``sandbox.submit``).
    This helper extracts those so ``derive_per_finding_validation`` can
    surface the REAL Python traceback in ``rejection_reason`` rather
    than relying on the Phase A verdict LLM's interpretation (which is
    known to hallucinate on edge cases — see ruamel-yaml H001 where
    the judge wrote 'No module named ruamel' for what was actually
    'AttributeError: module ruamel.yaml has no attribute load').

    When multiple SANDBOX_EXEC entries exist for the same finding
    (multiple iterations), keep the LONGEST non-empty stderr — that
    typically carries the most diagnostic content.
    """
    out: dict[str, str] = {}
    if not journal_records:
        return out
    for r in journal_records:
        if not isinstance(r, dict):
            continue
        # JournalPhase.SANDBOX_EXEC.value is the string "sandbox_exec";
        # journal entries serialize as ``phase: "sandbox_exec"``.
        phase = r.get("phase")
        if phase != "sandbox_exec" and str(phase) != "JournalPhase.SANDBOX_EXEC":
            continue
        cid = r.get("claim_id")
        if not cid or not isinstance(cid, str):
            continue
        stderr_text = str(r.get("rationale") or "").strip()
        if not stderr_text:
            continue
        existing = out.get(cid, "")
        if len(stderr_text) > len(existing):
            out[cid] = stderr_text
    return out


def derive_per_finding_validation(
    l1_vulnerabilities: list[dict[str, Any]],
    dast_validated_findings: list[str],
    journal_records: list[dict[str, Any]] | None = None,
    *,
    file_name: str | None = None,
    dast_attempted: bool = True,
    findings_validated_meta: dict[str, dict[str, Any]] | None = None,
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
    sandbox_stderr_by_id = _index_sandbox_stderr_by_finding(journal_records)

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

        cwe = v.get("cwe")
        # v1.6: granular NOT_TESTED reasoning — surface ACTUAL cause
        # before falling into the generic "inconclusive" bucket. Order
        # of precedence:
        #   1. CONFIRMED via DAST validation (overrides everything)
        #   2. Journal-emitted verdict (when journal entry exists)
        #   3. DAST not attempted on this file (engine didn't escalate)
        #   4. Non-Python file (DAST probe scope)
        #   5. Pattern-only CWE (DAST can't fire it)
        #   6. Otherwise -> not_planned (fallback for cases we can't
        #      pin down without orchestrator-level context, e.g.
        #      budget_exceeded vs unreachable_function)
        is_confirmed_via_dast = fid in confirmed_ids
        has_journal_entry = fid in journal_by_id

        if is_confirmed_via_dast:
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
        elif not dast_attempted:
            # Engine didn't escalate this file to DAST (L1 verdict was
            # below discovery_trigger_verdicts). The finding has no
            # DAST opinion, but the reason is structural -- not budget,
            # not unfireable, just "DAST didn't run."
            status = "NOT_TESTED"
            not_tested_reason = "dast_not_attempted"
        elif _is_unfireable_pattern_cwe(cwe) and not has_journal_entry:
            # Pattern-only CWE (CWE-506 / 451 / 532 / 1021 / 354 /
            # 1059 / 1039) -- DAST has no exploit payload that fires
            # this class. Honest labeling: it's not "inconclusive,"
            # the CWE is structurally outside DAST's exploit space.
            status = "NOT_TESTED"
            not_tested_reason = "unfireable_pattern_cwe"
        elif _is_non_python_file(file_name) and not has_journal_entry:
            # File extension outside the Python-probe scope. JS / .pth
            # / shell files get a different DAST path or none at all.
            status = "NOT_TESTED"
            not_tested_reason = "non_python_file"
        else:
            jrec = journal_by_id.get(fid)
            if jrec is None:
                # Fallback: L1 had this finding, no journal entry, none
                # of the structural reasons (unfireable CWE / non-Python
                # / DAST-not-attempted) apply. Most likely cause is
                # MAX_PROBE_RUNS_PER_FILE budget exceeded OR the
                # candidate-picker prompt dropped this finding from
                # the top-K. We can't distinguish those without
                # orchestrator-level telemetry; mark as not_planned
                # rather than misleading "inconclusive."
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
                    # DAST tested + got no exploit signal. Sub-classify by
                    # what the rationale says about WHY:
                    #   * BLOCKED keywords (sanitization, validation, etc.)
                    #     -> file's code defended  -> BLOCKED.
                    #   * UNREACHED keywords (path not reached, dead code)
                    #     -> code path not hit     -> UNREACHED.
                    #   * STUB keywords (no sandbox trace, static-only)
                    #     -> infra stub            -> NOT_TESTED (infra_stub).
                    #   * Otherwise -> REJECTED (sandbox-grounded refutation
                    #     with no specific defense or unreach signal --
                    #     the L1 claim looks WRONG). This is the
                    #     architectural FP-reduction win that prior to
                    #     v1.6 was collapsed into BLOCKED, making it
                    #     invisible in the output.
                    cls = _classify_rejection_rationale(rationale)
                    if cls == "BLOCKED":
                        status = "BLOCKED"
                        rejection_reason = rationale[:1500] if rationale else None
                    elif cls == "UNREACHED":
                        status = "UNREACHED"
                        rejection_reason = rationale[:1500] if rationale else None
                    elif cls == "STUB":
                        status = "NOT_TESTED"
                        not_tested_reason = "infra_stub"
                        rejection_reason = rationale[:1500] if rationale else None
                    else:
                        status = "REJECTED"
                        rejection_reason = rationale[:1500] if rationale else None
                elif verdict == "inconclusive":
                    status = "NOT_TESTED"
                    not_tested_reason = "inconclusive"
                    rejection_reason = rationale[:1500] if rationale else None
                else:
                    # "rejected" or unknown — fall back to rationale text
                    # classifier. Note: "rejected" is a hypothesis-quality
                    # failure (rules R1/R2/R3 in HypothesisValidator),
                    # not a runtime observation. Text classifier extracts
                    # what we can from the validator's reasoning.
                    cls = _classify_rejection_rationale(rationale)
                    if cls == "BLOCKED":
                        status = "BLOCKED"
                        rejection_reason = rationale[:1500]
                    elif cls == "UNREACHED":
                        status = "UNREACHED"
                        rejection_reason = rationale[:1500]
                    elif cls == "STUB":
                        # DAST-203: sandbox returned stub trace — typically
                        # a static-only hypothesis the orchestrator
                        # generated that has no runtime test to execute.
                        status = "NOT_TESTED"
                        not_tested_reason = "infra_stub"
                        rejection_reason = rationale[:1500]
                    else:
                        status = "NOT_TESTED"
                        not_tested_reason = "inconclusive"
                        rejection_reason = rationale[:1500] if rationale else None

        # v15.8 (2026-05-20): when the sandbox stderr for this finding
        # contains a Python runtime error (AttributeError, ImportError,
        # ModuleNotFoundError, NameError, TypeError, Traceback, ...),
        # promote the classification to ``runtime_error`` and surface
        # the REAL stderr in rejection_reason rather than the LLM
        # judge's interpretation. Reasons:
        #
        #   1. The LLM judge is known to hallucinate (ruamel-yaml H001:
        #      judge wrote 'No module named ruamel' when reality was
        #      'AttributeError: module ruamel.yaml has no attribute load'
        #      — a removed legacy API). Real stderr is authoritative.
        #
        #   2. ``runtime_error`` is a concrete fix-it signal: "the PoC
        #      crashed, regenerate against the installed API surface."
        #      vs ``inconclusive`` which gives operators nothing.
        #
        #   3. Adjacent NOT_TESTED reasons (infra_stub, not_planned,
        #      unfireable_pattern_cwe) are about WHERE in the pipeline
        #      it failed; ``runtime_error`` is about WHY — distinct and
        #      complementary signal.
        #
        # Only promotes statuses already classified as NOT_TESTED or
        # REJECTED — CONFIRMED / BLOCKED / UNREACHED outcomes mean DAST
        # did produce a meaningful signal and shouldn't be overwritten.
        if status in ("NOT_TESTED", "REJECTED"):
            stderr_text = sandbox_stderr_by_id.get(fid, "")
            if _classify_runtime_error(stderr_text) or _classify_runtime_error(
                rejection_reason or ""
            ):
                status = "NOT_TESTED"
                not_tested_reason = "runtime_error"
                # Prepend the real stderr to whatever the LLM judge
                # said, so operators see ground truth first.
                real_err = stderr_text[:1200] if stderr_text else ""
                judge_text = rejection_reason[:300] if rejection_reason else ""
                if real_err and judge_text:
                    rejection_reason = (
                        f"[sandbox stderr] {real_err}\n[judge] {judge_text}"
                    )
                elif real_err:
                    rejection_reason = f"[sandbox stderr] {real_err}"
                elif judge_text:
                    rejection_reason = judge_text

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

    # v1.9 — emit rows for DAST-DISCOVERED findings (HRP_* / HRP_AL_*
    # / HRP_C*) that have no L1 hypothesis backing.
    #
    # The L1-iteration loop above only covers ``H001..HN`` IDs. Phase
    # B+ runtime probes and Phase 3 adversarial loop hypotheses also
    # produce confirmed findings, with their own ID namespaces:
    #
    #   * ``HRP_<cand>_<input>`` — Phase B+ runtime probe (single-fn)
    #   * ``HRP_AL_T<turn>_H<hyp>`` — Phase 3 adversarial loop
    #   * ``HRP_C<chain>_<step>``  — Phase B chain runtime probe
    #
    # Before v1.9 these surfaced only as bare ID strings in
    # ``dast_findings`` (and as journal rationale text). The user
    # could see "DAST upgraded clean→malicious" but couldn't see WHAT
    # exploit DAST observed at runtime. The orchestrator now stashes
    # the full finding dict in ``findings_validated_meta`` (mapped by
    # finding_ref) so this loop can emit a properly-populated
    # PerFindingValidation row.
    #
    # We dedupe by finding_id against the loop above. An L1 finding
    # whose finding_ref happens to be ``HRP_*`` (shouldn't happen in
    # practice; H001-N convention) would already be in ``out`` and we
    # skip the meta-derived row to avoid double-counting.
    if findings_validated_meta:
        already_emitted = {pf.finding_id for pf in out}
        # Sort by ID for deterministic output ordering (matches the
        # behavior of the L1 loop, which iterates in source order).
        for fid in sorted(findings_validated_meta):
            if fid in already_emitted:
                continue
            meta = findings_validated_meta[fid]
            if not isinstance(meta, dict):
                continue

            # Pull runtime_evidence from the meta first (the probe
            # built it from the sandbox trace), falling back to the
            # journal rationale if for some reason the meta dict is
            # incomplete. Same precedence for proof_of_concept.
            meta_runtime_ev = meta.get("runtime_evidence")
            poc_val = meta.get("proof_of_concept")
            jrec = journal_by_id.get(fid)
            if not meta_runtime_ev and jrec is not None:
                rat = str(jrec.get("rationale") or "").strip()
                if rat:
                    meta_runtime_ev = rat

            line_val = (
                meta.get("line")
                if isinstance(meta.get("line"), int)
                else None
            )
            meta_conf = meta.get("confidence")
            confidence_val = (
                float(meta_conf)
                if isinstance(meta_conf, (int, float))
                else None
            )

            # v15.17: honor explicit ``status`` field on the meta dict
            # (CONFIRMED / UNREACHED / REFUTED). Pre-v15.17 the meta
            # collection contained only CONFIRMED rows, so status was
            # hardcoded; v15.17 adds UNREACHED + REFUTED diagnostic
            # rows for HRP probes whose matcher returned None (sandbox
            # import failure vs clean-run-no-exploit). Defaults to
            # CONFIRMED to preserve backwards-compat with callers that
            # don't set status.
            _meta_status = str(meta.get("status") or "CONFIRMED")
            # v15.17 added UNREACHED + REFUTED. v15.25 adds SUPPRESSED
            # for findings the matcher emitted but a precision heuristic
            # (purpose-aligned getter, no-network-io check) suppressed
            # as by-design / unexploitable.
            if _meta_status not in {
                "CONFIRMED",
                "UNREACHED",
                "REFUTED",
                "BLOCKED",
                "SUPPRESSED",
            }:
                _meta_status = "CONFIRMED"
            out.append(
                PerFindingValidation(
                    finding_id=fid,
                    # The probe finding-dict uses ``finding_type`` for
                    # the attack class (matching the orchestrator
                    # convention); fall back to ``type`` so this works
                    # for any dict shape that carries either key.
                    cwe=str(meta.get("cwe") or ""),
                    type=str(meta.get("finding_type") or meta.get("type") or ""),
                    severity=str(meta.get("severity") or ""),
                    line=line_val,
                    status=_meta_status,  # type: ignore[arg-type]
                    confidence=confidence_val,
                    rejection_reason=(
                        str(meta.get("unreached_reason") or "")
                        or None
                    )
                    if _meta_status != "CONFIRMED"
                    else None,
                    not_tested_reason=None,
                    proof_of_concept=(
                        # v15.24 (2026-05-20): bumped 500 → 2500 chars.
                        # For HRP findings the call signature + kwargs
                        # alone is typically ~400 chars; the pre-v15.24
                        # cap clipped the sandbox's response payload
                        # ("Value preview") off the end of
                        # runtime_evidence, losing the actual exploit
                        # signal Gemini reviewers need to see.
                        str(poc_val)[:2500]
                        if isinstance(poc_val, str) and poc_val.strip()
                        else None
                    ),
                    runtime_evidence=(
                        # v15.24: see comment above on proof_of_concept.
                        str(meta_runtime_ev)[:2500]
                        if isinstance(meta_runtime_ev, str) and meta_runtime_ev.strip()
                        else None
                    ),
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
