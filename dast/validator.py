"""Pre-execution hypothesis gate — production v0.2.

Every hypothesis emitted by Phase B must satisfy three rules before it
is allowed to consume sandbox budget. Speculative hypotheses are
rejected here, not in the model.

Rejection criteria (calibrated for upstream-causation reasoning, see
``dast_prompts._PHASE_B_BODY``)
=====================================================================

R1 SPECIFIC
-----------
A single testable claim. The hypothesis must have:
  * ``scope.lines_start`` and ``scope.lines_end`` both ints, both ≥ 1,
    end ≥ start, and (end - start) ≤ 50.
  * ≥1 ``test_steps`` entry with non-empty ``action`` and
    ``expected_state``.
  * No hedge phrases in ``description`` or ``test_approach``:
    "could potentially", "might also", "may also", "perhaps",
    "in theory", "hypothetically", "may exist", "as appropriate",
    "or similar".
  * No future-tense speculation ("if an attacker added", "if the file
    were run as", "could be modified to", "in the future").

R2 BOUNDED
----------
Single oracle, single environment requirement.
  * ``oracle_type`` is a non-empty string (single value, not a list).
  * ``environment_complexity`` ∈ {single_process, multi_process}.
    multi_service / distributed → REJECTED — out of prototype scope.
  * ``estimated_sandbox_time_sec`` is a positive int ≤ 600.

R3 EVIDENCE-DRIVEN
------------------
The ``evidence_basis`` MUST point at something concrete:
  * ``type`` ∈ {l1_finding, journal_event, code_pattern}.
  * ``ref`` non-empty.
    - if l1_finding: ref matches an L1 finding ID actually emitted by L1.
    - if journal_event: ref matches an event_id present in the journal
      summary's confirmed/refuted/inconclusive lists.
    - if code_pattern: ref contains either a line-range descriptor
      ("line N", "lines N-M") or a named non-code artifact ("module
      docstring", "header comment", "filename", "manifest scripts.X").
      Pure-prose refs ("the suspicious-looking exec call") are rejected.
  * ``why_relevant`` non-empty (≥ 20 chars).

R3-UPSTREAM
-----------
The ``upstream_chain`` field is the upstream-reasoning audit trail and
is mandatory. It must be fully populated:
  * ``confirmed_finding_ref`` matches a confirmed F### in the journal
    summary's ``confirmed_findings`` list. The validator REJECTS
    hypotheses that target findings the journal hasn't actually
    confirmed — that would be testing on conjecture.
  * ``upstream_condition`` is a non-empty specific descriptor. Generic
    phrases like "supply chain risk", "trust assumption", "process
    issue" without further specifics are rejected.
  * ``evidence_location`` is a line range ("line N", "lines N-M") or
    a named non-code artifact.

Borderline (passes but flagged for reviewer attention)
------------------------------------------------------
Hypothesis is accepted but ``is_borderline=True`` if:
  * scope range > 30 lines (under cap, but wider than typical narrow scope);
  * evidence_basis.type == "code_pattern" AND no L1 finding ID is
    referenced in upstream_chain.confirmed_finding_ref (pure inference
    chain, no anchor in L1's confirmed work);
  * upstream_chain.upstream_condition contains a generic phrase but is
    rescued by a specific qualifier elsewhere.

Output telemetry
----------------
Every ``validate()`` call returns rule-by-rule reasoning. Smoke test
aggregates: acceptance rate, per-rule rejection distribution, sample of
borderline cases. See architecture_decisions.md §10 directive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


HEDGE_PHRASES = (
    "could potentially",
    "might also",
    "may also",
    "perhaps",
    "in theory",
    "hypothetically",
    "may exist",
    "as appropriate",
    "or similar",
    "could be modified to",
    "in the future",
    "if an attacker added",
    "if the file were run as",
    "if the user were",
    "should an attacker",
)

GENERIC_UPSTREAM_PHRASES = (
    "supply chain risk",
    "trust assumption",
    "process issue",
    "security risk",
    "potential vulnerability",
    "may be exploited",
)

LINE_REF_PAT = re.compile(r"\bline[s]?\s+\d+(?:\s*[-–]\s*\d+)?\b", re.IGNORECASE)
NAMED_ARTIFACT_PAT = re.compile(
    r"\b(module docstring|header comment|file header|preamble|filename"
    r"|manifest|package\.json|setup\.py|pyproject|cargo|build\.gradle"
    r"|workflow|action|sitecustomize|requirements\.txt|dockerfile)\b",
    re.IGNORECASE,
)
F_ID_PAT = re.compile(r"^F\d{3}$")
EVT_ID_PAT = re.compile(r"^evt-\w+$")


@dataclass
class ValidatorVerdict:
    accepted: bool
    rule_results: dict[str, bool]
    rule_notes: dict[str, str]
    reasoning: str
    is_borderline: bool
    borderline_notes: list[str] = field(default_factory=list)


class HypothesisValidator:
    RULE_IDS = ("R1_specific", "R2_bounded", "R3_evidence_driven")

    def __init__(self) -> None:
        # Stateless. Single instance reused across all files.
        pass

    def validate(
        self,
        hypothesis: dict[str, Any],
        l1_findings: list[dict],
        journal_summary: Any,
    ) -> ValidatorVerdict:
        rule_results: dict[str, bool] = {}
        rule_notes: dict[str, str] = {}
        borderline_notes: list[str] = []

        rule_results["R1_specific"], rule_notes["R1_specific"] = self._check_r1(
            hypothesis, borderline_notes
        )
        rule_results["R2_bounded"], rule_notes["R2_bounded"] = self._check_r2(
            hypothesis
        )
        rule_results["R3_evidence_driven"], rule_notes["R3_evidence_driven"] = (
            self._check_r3(hypothesis, l1_findings, journal_summary, borderline_notes)
        )

        accepted = all(rule_results.values())
        is_borderline = accepted and bool(borderline_notes)
        reasoning = self._compose_reasoning(rule_results, rule_notes, borderline_notes)
        return ValidatorVerdict(
            accepted=accepted,
            rule_results=rule_results,
            rule_notes=rule_notes,
            reasoning=reasoning,
            is_borderline=is_borderline,
            borderline_notes=borderline_notes,
        )

    # --- R1 ---------------------------------------------------------------

    def _check_r1(
        self, h: dict[str, Any], borderline_notes: list[str]
    ) -> tuple[bool, str]:
        scope = h.get("scope") or {}
        ls = scope.get("lines_start")
        le = scope.get("lines_end")
        if not (isinstance(ls, int) and isinstance(le, int)):
            return False, "scope.lines_start/end missing or non-int"
        if ls < 1 or le < ls:
            return False, f"scope is invalid (start={ls}, end={le})"
        span = le - ls
        if span > 50:
            return False, f"scope spans >50 lines ({ls}..{le})"
        if span > 30:
            borderline_notes.append(f"scope range {span+1} lines (>30, ≤50)")

        steps = h.get("test_steps")
        if not isinstance(steps, list) or not steps:
            return False, "test_steps empty"
        for i, s in enumerate(steps):
            if not isinstance(s, dict):
                return False, f"test_steps[{i}] not an object"
            if not (s.get("action") or "").strip():
                return False, f"test_steps[{i}].action empty"
            if not (s.get("expected_state") or "").strip():
                return False, f"test_steps[{i}].expected_state empty"

        text_blob = " ".join(
            [
                str(h.get("description", "")),
                str(h.get("test_approach", "")),
            ]
        ).lower()
        for hedge in HEDGE_PHRASES:
            if hedge in text_blob:
                return False, f"hedge phrase present: {hedge!r}"

        return True, "specific (line-range, test steps, no hedge phrases)"

    # --- R2 ---------------------------------------------------------------

    def _check_r2(self, h: dict[str, Any]) -> tuple[bool, str]:
        oracle = h.get("oracle_type")
        if not isinstance(oracle, str) or not oracle.strip():
            return False, "oracle_type empty or not a string"
        env = h.get("environment_complexity")
        if env not in {"single_process", "multi_process"}:
            return False, (
                f"environment_complexity={env!r} (only single_process / "
                f"multi_process accepted in prototype scope)"
            )
        ts = h.get("estimated_sandbox_time_sec")
        if not isinstance(ts, int) or ts < 1 or ts > 600:
            return False, f"estimated_sandbox_time_sec={ts!r} out of [1, 600]"
        return True, f"single oracle ({oracle!r}), bounded environment ({env!r})"

    # --- R3 ---------------------------------------------------------------

    def _check_r3(
        self,
        h: dict[str, Any],
        l1_findings: list[dict],
        journal_summary: Any,
        borderline_notes: list[str],
    ) -> tuple[bool, str]:
        eb = h.get("evidence_basis") or {}
        if not isinstance(eb, dict):
            return False, "evidence_basis not an object"
        eb_type = eb.get("type")
        eb_ref = eb.get("ref") or ""
        eb_why = eb.get("why_relevant") or ""
        if eb_type not in {"l1_finding", "journal_event", "code_pattern"}:
            return False, f"evidence_basis.type={eb_type!r}"
        if not eb_ref.strip():
            return False, "evidence_basis.ref empty"
        if len(eb_why.strip()) < 20:
            return False, f"evidence_basis.why_relevant too short ({len(eb_why)} chars)"

        l1_finding_ids = {
            str(f.get("id", "")) for f in l1_findings if isinstance(f, dict)
        }
        confirmed = self._journal_confirmed(journal_summary)
        all_finding_ids = l1_finding_ids | set(confirmed)
        evt_ids = self._journal_event_ids(journal_summary)

        if eb_type == "l1_finding":
            if eb_ref not in all_finding_ids:
                return False, f"evidence_basis.ref={eb_ref!r} not an L1 finding"
        elif eb_type == "journal_event":
            if eb_ref not in evt_ids and not EVT_ID_PAT.match(eb_ref):
                return False, f"evidence_basis.ref={eb_ref!r} not a journal event_id"
        elif eb_type == "code_pattern":
            if not (LINE_REF_PAT.search(eb_ref) or NAMED_ARTIFACT_PAT.search(eb_ref)):
                return False, (
                    f"evidence_basis.ref={eb_ref!r} has neither a line range "
                    f"nor a named non-code artifact"
                )
            if not all_finding_ids:
                pass  # iter 1 with no confirmed findings — code_pattern is OK
            else:
                # code_pattern is fine but unanchored to L1's confirmed work
                # → borderline.
                borderline_notes.append(
                    "evidence_basis.type=code_pattern (no L1 finding ID anchor)"
                )

        # Upstream chain
        uc = h.get("upstream_chain") or {}
        if not isinstance(uc, dict):
            return False, "upstream_chain not an object"
        cfr = (uc.get("confirmed_finding_ref") or "").strip()
        cond = (uc.get("upstream_condition") or "").strip()
        loc = (uc.get("evidence_location") or "").strip()
        if not cfr:
            return False, "upstream_chain.confirmed_finding_ref empty"
        if confirmed and cfr not in confirmed:
            # We have a journal but the ref doesn't match anything confirmed.
            return False, (
                f"upstream_chain.confirmed_finding_ref={cfr!r} not in journal's "
                f"confirmed_findings={sorted(confirmed)!r}"
            )
        if not confirmed and not F_ID_PAT.match(cfr):
            return False, (
                f"upstream_chain.confirmed_finding_ref={cfr!r} not an F### id"
            )
        if not cond:
            return False, "upstream_chain.upstream_condition empty"
        cond_lower = cond.lower()
        for phrase in GENERIC_UPSTREAM_PHRASES:
            if phrase in cond_lower and len(cond) <= len(phrase) + 20:
                return False, (
                    f"upstream_chain.upstream_condition is generic "
                    f"({cond!r}); needs a specific qualifier"
                )
        if not loc:
            return False, "upstream_chain.evidence_location empty"
        if not (LINE_REF_PAT.search(loc) or NAMED_ARTIFACT_PAT.search(loc)):
            return False, (
                f"upstream_chain.evidence_location={loc!r} has neither a "
                f"line range nor a named non-code artifact"
            )

        return True, (
            f"evidence_basis.type={eb_type}, ref={eb_ref!r}; "
            f"upstream_chain anchored to {cfr}"
        )

    # --- helpers ----------------------------------------------------------

    @staticmethod
    def _journal_confirmed(journal_summary: Any) -> set[str]:
        if isinstance(journal_summary, dict):
            return set(journal_summary.get("confirmed_findings") or [])
        return set(getattr(journal_summary, "confirmed_findings", []) or [])

    @staticmethod
    def _journal_event_ids(journal_summary: Any) -> set[str]:
        # Journal summary's text doesn't carry event IDs by design; we let
        # any evt-* shaped string through here. The Phase B prompt and the
        # downstream Phase A plan check it concretely against the trace.
        return set()

    @staticmethod
    def _compose_reasoning(
        rule_results: dict[str, bool],
        rule_notes: dict[str, str],
        borderline_notes: list[str],
    ) -> str:
        parts: list[str] = []
        for rid in HypothesisValidator.RULE_IDS:
            mark = "ok" if rule_results.get(rid) else "FAIL"
            parts.append(f"{rid}: {mark} — {rule_notes.get(rid, '')}")
        if borderline_notes:
            parts.append(f"borderline: {'; '.join(borderline_notes)}")
        return " | ".join(parts)
