"""Unit tests for mcp_scanner.findings (MCPFinding model + CVSS/severity)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_scanner.findings import MCPFinding, cvss_estimate_for, severity_for


def test_mcp_finding_minimum_valid() -> None:
    """Smallest set of fields that satisfies the schema."""
    f = MCPFinding(
        id="F001",
        probe_class="ssrf",
        vuln_class="Server-Side Request Forgery",
        severity="critical",
        target_locus="tool:fetch_url.url",
        target="stdio: x",
        transport="stdio",
        title="Confirmed SSRF: fetch_url(url) → AWS IMDS",
        explanation="Tool fetches url without filter.",
        fix="Add allowlist + private-IP block.",
    )
    assert f.id == "F001"
    assert f.severity == "critical"
    assert f.cvss_estimate is None  # optional


def test_mcp_finding_id_pattern_enforced() -> None:
    with pytest.raises(ValidationError):
        MCPFinding(
            id="oops",
            probe_class="ssrf",
            vuln_class="x",
            severity="low",
            target_locus="x",
            target="x",
            transport="stdio",
            title="x",
            explanation="x",
            fix="x",
        )


def test_mcp_finding_severity_pattern_enforced() -> None:
    with pytest.raises(ValidationError):
        MCPFinding(
            id="F001",
            probe_class="ssrf",
            vuln_class="x",
            severity="apocalyptic",
            target_locus="x",
            target="x",
            transport="stdio",
            title="x",
            explanation="x",
            fix="x",
        )


def test_mcp_finding_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        MCPFinding(
            id="F001",
            probe_class="ssrf",
            vuln_class="x",
            severity="low",
            target_locus="x",
            target="x",
            transport="stdio",
            title="x",
            explanation="x",
            fix="x",
            invented_field="oops",  # type: ignore[call-arg]
        )


def test_cvss_estimate_confirmed_higher_than_heuristic() -> None:
    for cls in ("ssrf", "redirect_internal", "fail_open", "auth_bypass"):
        confirmed = cvss_estimate_for(cls, confirmed=True)
        heuristic = cvss_estimate_for(cls, confirmed=False)
        assert confirmed > heuristic, (
            f"{cls}: confirmed CVSS ({confirmed}) must exceed heuristic ({heuristic})"
        )


def test_cvss_estimate_unknown_class_returns_default() -> None:
    assert cvss_estimate_for("never_heard_of_it", confirmed=True) == 4.0


def test_severity_for_uses_first_org_cutoffs() -> None:
    """FIRST.org CVSS v3.1 severity bands."""
    assert severity_for(9.5) == "critical"
    assert severity_for(9.0) == "critical"
    assert severity_for(8.9) == "high"
    assert severity_for(7.0) == "high"
    assert severity_for(6.9) == "medium"
    assert severity_for(4.0) == "medium"
    assert severity_for(3.9) == "low"
    assert severity_for(0.0) == "low"
