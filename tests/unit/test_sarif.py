"""Unit tests for scanner.sarif — SARIF v2.1.0 output writer.

Validates the document shape, severity mapping, and Argus-specific
properties wiring. Doesn't validate against the full SARIF JSON schema
(out of scope — we trust the schema URL in the document).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from scanner.engine import ScanResult
from scanner.sarif import (
    SARIF_VERSION,
    render_repo_scan_sarif,
    render_scan_results_sarif,
    to_sarif_string,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def _result_with_findings(filename: str, findings: list[dict]) -> ScanResult:
    return ScanResult(
        filename=filename,
        file_hash="0" * 64,
        language=None,
        triage_classification="HIGH",
        triage_reason="stub",
        final_verdict="malicious",
        risk_score=80,
        risk_level="high",
        vulnerabilities=findings,
    )


@dataclass
class _StubReport:
    """Stand-in for RepoScanReport — render_repo_scan_sarif only reads
    ``results``."""

    results: list[ScanResult] = field(default_factory=list)


# ── Document shape ───────────────────────────────────────────────────────────


def test_sarif_empty_results_produces_valid_doc() -> None:
    """Zero findings still produces a well-formed SARIF v2.1.0 doc."""
    doc = render_repo_scan_sarif(_StubReport(results=[]))

    assert doc["version"] == SARIF_VERSION
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Argus"
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_single_finding_populates_rule_and_result() -> None:
    """One finding yields one rule + one result, with correct shape."""
    finding = {
        "cwe": "CWE-78",
        "type": "command_injection",
        "severity": "critical",
        "line": 42,
        "explanation": "Unsanitized user input flows to shell exec",
        "fix": "Use shlex.quote() or subprocess with a list arg",
        "status": "CONFIRMED",
        "confidence": 0.95,
    }
    result = _result_with_findings("evil.py", [finding])

    doc = render_repo_scan_sarif(_StubReport(results=[result]))
    run = doc["runs"][0]

    # one rule
    assert len(run["tool"]["driver"]["rules"]) == 1
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "CWE-78"
    assert rule["defaultConfiguration"]["level"] == "error"  # critical → error
    assert rule["properties"]["cwe"] == "CWE-78"
    assert rule["help"]["text"].startswith("Use shlex.quote")

    # one result
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "CWE-78"
    assert res["level"] == "error"
    assert res["message"]["text"].startswith("Unsanitized")
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "evil.py"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
    assert res["properties"]["argus_status"] == "CONFIRMED"
    assert res["properties"]["argus_confidence"] == 0.95


def test_sarif_severity_mapping() -> None:
    """All Argus severities map to a SARIF level."""
    cases = [
        ("info", "note"),
        ("low", "note"),
        ("medium", "warning"),
        ("high", "error"),
        ("critical", "error"),
        (None, "warning"),  # unknown → default
        ("nonsense", "warning"),
    ]
    for arg_sev, expected_level in cases:
        finding = {
            "cwe": "CWE-1",
            "type": "x",
            "severity": arg_sev,
            "line": 1,
            "explanation": "x",
        }
        result = _result_with_findings("f.py", [finding])
        doc = render_repo_scan_sarif(_StubReport(results=[result]))
        assert doc["runs"][0]["results"][0]["level"] == expected_level, f"severity {arg_sev!r} → {expected_level!r}"


def test_sarif_multiple_findings_same_rule_dedup() -> None:
    """Multiple findings sharing a CWE produce one rule + multiple results."""
    findings = [
        {"cwe": "CWE-89", "type": "sqli", "severity": "high", "line": 10, "explanation": "x"},
        {"cwe": "CWE-89", "type": "sqli", "severity": "high", "line": 20, "explanation": "y"},
    ]
    result = _result_with_findings("app.py", findings)
    doc = render_repo_scan_sarif(_StubReport(results=[result]))

    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]

    assert len(rules) == 1
    assert rules[0]["id"] == "CWE-89"
    assert len(results) == 2
    start_lines = {r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results}
    assert start_lines == {10, 20}


def test_sarif_runtime_evidence_in_properties() -> None:
    """CONFIRMED findings carry runtime evidence into result properties
    so consumers can surface it in their UI."""
    finding = {
        "cwe": "CWE-200",
        "type": "data_exfiltration",
        "severity": "critical",
        "line": 5,
        "explanation": "exfil to attacker C2",
        "status": "CONFIRMED",
        "runtime_evidence": "Mock HTTP captured POST body with SSH keys",
        "proof_of_concept": "On any host with ~/.ssh/, execution leaks keys",
    }
    result = _result_with_findings("malware.py", [finding])
    doc = render_repo_scan_sarif(_StubReport(results=[result]))
    res = doc["runs"][0]["results"][0]

    assert res["properties"]["argus_runtime_evidence"].startswith("Mock HTTP")
    assert res["properties"]["argus_poc"].startswith("On any host")


def test_sarif_blocked_finding_carries_status() -> None:
    """BLOCKED status surfaces in properties — consumers can downgrade
    severity in their UI based on this signal."""
    finding = {
        "cwe": "CWE-79",
        "type": "xss",
        "severity": "high",
        "line": 100,
        "explanation": "Untrusted output to HTML, but file uses html.escape",
        "status": "BLOCKED",
        "rejection_reason": "html.escape() defends the output context",
    }
    result = _result_with_findings("view.py", [finding])
    doc = render_repo_scan_sarif(_StubReport(results=[result]))
    res = doc["runs"][0]["results"][0]

    assert res["properties"]["argus_status"] == "BLOCKED"
    assert "html.escape" in res["properties"]["argus_rejection_reason"]


def test_sarif_finding_without_cwe_falls_back_to_type() -> None:
    """When CWE is missing, ruleId falls back to the type field."""
    finding = {
        "type": "hardcoded_secret",
        "severity": "medium",
        "line": 7,
        "explanation": "API key in source",
    }
    result = _result_with_findings("config.py", [finding])
    doc = render_repo_scan_sarif(_StubReport(results=[result]))
    rule_id = doc["runs"][0]["results"][0]["ruleId"]

    assert rule_id == "hardcoded_secret"


def test_sarif_invalid_line_defaults_to_1() -> None:
    """Bad line values don't crash the writer; they become startLine=1."""
    finding = {
        "cwe": "CWE-1",
        "type": "x",
        "severity": "low",
        "line": "not-an-int",
        "explanation": "x",
    }
    result = _result_with_findings("f.py", [finding])
    doc = render_repo_scan_sarif(_StubReport(results=[result]))
    line = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
    assert line == 1


def test_to_sarif_string_round_trip() -> None:
    """to_sarif_string produces parseable JSON."""
    finding = {
        "cwe": "CWE-78",
        "type": "shell_injection",
        "severity": "high",
        "line": 5,
        "explanation": "x",
    }
    result = _result_with_findings("a.py", [finding])
    doc = render_repo_scan_sarif(_StubReport(results=[result]))
    json_str = to_sarif_string(doc)
    parsed = json.loads(json_str)
    assert parsed == doc


def test_render_scan_results_sarif_iterable() -> None:
    """render_scan_results_sarif accepts any iterable of ScanResult."""
    findings_a = [{"cwe": "CWE-1", "type": "x", "severity": "low", "line": 1, "explanation": "a"}]
    findings_b = [{"cwe": "CWE-2", "type": "y", "severity": "high", "line": 2, "explanation": "b"}]
    r1 = _result_with_findings("a.py", findings_a)
    r2 = _result_with_findings("b.py", findings_b)

    doc = render_scan_results_sarif([r1, r2])
    assert len(doc["runs"][0]["results"]) == 2
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 2
