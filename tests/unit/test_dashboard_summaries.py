"""Unit tests for dashboard summary projections (pure, no DB)."""

from __future__ import annotations

from typing import Any

from dashboard.server.summaries import flow_rollup, summary_cols

# A realistic ScanResult.to_dict() slice: TS SSRF — 2 L1 findings, 1 DAST
# CONFIRMED, remediation verified HIGH.
_TS_SSRF: dict[str, Any] = {
    "filename": "vuln_ssrf.ts",
    "file_hash": "abc123",
    "language": "typescript",
    "triage_classification": "HIGH",
    "final_verdict": "suspicious",
    "risk_score": 45,
    "risk_level": "medium",
    "intent": "legitimate",
    "dast_attempted": True,
    "vulnerabilities": [
        {"type": "ssrf", "severity": "high", "cwe": "CWE-918", "line": 7},
        {"type": "ssrf", "severity": "medium", "cwe": "CWE-918", "line": 9},
    ],
    "per_finding_validation": [
        {"finding_id": "H001", "status": "CONFIRMED", "cwe": "CWE-918"},
        {"finding_id": "H002", "status": "BLOCKED", "cwe": "CWE-918"},
    ],
    "phase_c": {"attempted": True, "verification": {"confidence": "HIGH"}},
    "total_cost_usd": 0.3527,
    "total_duration_ms": 127630,
}


def test_flow_rollup_counts_and_confidence() -> None:
    roll = flow_rollup(_TS_SSRF)
    assert roll["n_findings"] == 2
    assert roll["n_confirmed"] == 1  # only the CONFIRMED one
    assert roll["remediation_confidence"] == "HIGH"


def test_summary_cols_extracts_all_columns() -> None:
    cols = summary_cols(_TS_SSRF)
    assert cols["filename"] == "vuln_ssrf.ts"
    assert cols["language"] == "typescript"
    assert cols["final_verdict"] == "suspicious"
    assert cols["risk_score"] == 45
    assert cols["dast_attempted"] is True
    assert cols["n_findings"] == 2
    assert cols["n_confirmed"] == 1
    assert cols["remediation_confidence"] == "HIGH"
    assert cols["total_cost_usd"] == 0.3527


def test_handles_empty_and_missing_blocks() -> None:
    roll = flow_rollup({})
    assert roll == {"n_findings": 0, "n_confirmed": 0, "remediation_confidence": None}
    cols = summary_cols({})
    assert cols["filename"] == ""
    assert cols["dast_attempted"] is False
    assert cols["total_cost_usd"] is None
    assert cols["remediation_confidence"] is None


def test_phase_c_without_verification_yields_no_confidence() -> None:
    raw = {"phase_c": {"attempted": True, "skipped_reason": "no_confirmed_findings"}}
    assert flow_rollup(raw)["remediation_confidence"] is None


def test_phase_c_none_is_safe() -> None:
    raw = {"vulnerabilities": [{"type": "xss"}], "phase_c": None}
    roll = flow_rollup(raw)
    assert roll["n_findings"] == 1
    assert roll["remediation_confidence"] is None


def test_malformed_lists_are_ignored() -> None:
    raw = {"vulnerabilities": "not-a-list", "per_finding_validation": [None, {"status": "CONFIRMED"}]}
    roll = flow_rollup(raw)
    assert roll["n_findings"] == 0  # string coerced to empty
    assert roll["n_confirmed"] == 1  # None entry skipped, dict counted
