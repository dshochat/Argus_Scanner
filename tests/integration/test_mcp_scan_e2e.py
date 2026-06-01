"""End-to-end argus mcp scan test against the fixture vulnerable server.

Drives the public `argus mcp scan --stdio "<fixture>"` entry point as
a real subprocess, parses the JSON report, and asserts that each
probe class produces findings against the vulnerable tools.

The fixture vulnerable_server.py exposes 5 tools:
  * fetch_url            — SSRF (no validation)
  * read_url_with_redirects — redirect-chain SSRF
  * safe_fetch           — fail-open validator
  * admin_lookup         — auth bypass
  * echo                 — harmless baseline

Expected findings on a clean scan:
  * 3x SSRF heuristic findings (fetch_url + read_url_with_redirects +
    safe_fetch — each accepts a URL but the fixture's URLError text
    in response content fires the SSRF heuristic).
  * Redirect-probe heuristic findings (same 3 tools).
  * Fail-open heuristic findings (same 3 tools).
  * Auth-bypass heuristic findings on admin_lookup (and potentially
    echo, since unauthed call returns content).

We don't pin EXACT finding counts because heuristic logic may evolve;
we pin invariants:
  * Each probe class produces >= 1 finding for the eligible tools.
  * No findings for echo on the SSRF / redirect / fail-open probes
    (it has no URL params).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_SERVER = REPO_ROOT / "tests" / "fixtures" / "mcp" / "vulnerable_server.py"


def _argus_cmd(*extra: str) -> list[str]:
    return [sys.executable, "-m", "scanner.cli", *extra]


def test_scan_fixture_produces_findings(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = subprocess.run(
        _argus_cmd(
            "mcp", "scan",
            "--stdio", f"{sys.executable} {FIXTURE_SERVER}",
            "--report", "json",
            "--output-file", str(out),
        ),
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO_ROOT),
    )
    # Exit code 1 expected (findings present, none confirmed in local mode
    # because there's no in-sandbox network capture-server). Allow exit 0
    # too in case the heuristic finds nothing (would be a regression).
    assert result.returncode in (0, 1), (
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    payload = json.loads(out.read_text(encoding="utf-8"))

    # Schema sanity.
    assert payload["schema"] == "argus.mcp.scan-report"
    assert payload["schema_version"] == 1
    assert payload["transport"] == "stdio"

    # The 5 fixture tools should appear in the surface map.
    tool_names = {t["name"] for t in payload["surface"]["tools"]}
    assert tool_names == {
        "fetch_url",
        "read_url_with_redirects",
        "safe_fetch",
        "admin_lookup",
        "echo",
    }

    findings = payload["findings"]
    assert isinstance(findings, list)
    assert len(findings) > 0, "expected at least one finding against the fixture"

    # Group findings by probe class.
    by_class: dict[str, list[dict]] = {}
    for f in findings:
        by_class.setdefault(f["probe_class"], []).append(f)

    # SSRF — heuristic findings for each URL-taking tool.
    ssrf_findings = by_class.get("ssrf", [])
    assert ssrf_findings, "SSRF probe should produce findings against fixture"
    ssrf_tools = {f["target_locus"].split(".")[0].split(":", 1)[1] for f in ssrf_findings}
    assert "fetch_url" in ssrf_tools

    # Redirect — heuristic findings.
    redirect_findings = by_class.get("redirect_internal", [])
    assert redirect_findings, "Redirect probe should produce findings against fixture"

    # Fail-open — should fire on the fixture's safe_fetch.
    fail_open_findings = by_class.get("fail_open", [])
    assert fail_open_findings, "Fail-open probe should produce findings against fixture"

    # Auth-bypass — admin_lookup returns content unauthenticated.
    auth_findings = by_class.get("auth_bypass", [])
    assert auth_findings, "Auth-bypass probe should produce findings against fixture"
    auth_tools = {f["target_locus"].split(":", 1)[1] for f in auth_findings}
    assert ["tool", "admin_lookup"][1] in auth_tools or "admin_lookup" in auth_tools

    # echo SHOULD NOT have SSRF / redirect / fail-open findings (no URL params).
    for cls in ("ssrf", "redirect_internal", "fail_open"):
        for f in by_class.get(cls, []):
            assert "echo" not in f["target_locus"], (
                f"echo (FUZZ-only) should not produce {cls} findings; got {f['title']!r}"
            )

    # All findings must carry the required schema fields populated.
    for f in findings:
        for required in ("id", "severity", "cwe", "title", "fix", "explanation"):
            assert f[required], f"finding {f['id']} missing {required}"
        assert f["severity"] in ("low", "medium", "high", "critical")
        assert f["confirmed"] in (True, False)

    # Session metadata populated.
    sm = payload["session_metadata"]
    assert sm["probe_count"] > 0
    assert sm["probes_by_class"]


def test_scan_fixture_markdown_report(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    result = subprocess.run(
        _argus_cmd(
            "mcp", "scan",
            "--stdio", f"{sys.executable} {FIXTURE_SERVER}",
            "--report", "md",
            "--output-file", str(out),
        ),
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode in (0, 1), result.stderr
    md = out.read_text(encoding="utf-8")
    assert "# Argus MCP — Scan Report" in md
    assert "## Headline" in md
    assert "## Session telemetry" in md
    # Should mention at least one CWE.
    assert "CWE-" in md


def test_scan_tools_filter_narrows_surface(tmp_path: Path) -> None:
    """--tools fetch_url should restrict probes to that tool only."""
    out = tmp_path / "report.json"
    result = subprocess.run(
        _argus_cmd(
            "mcp", "scan",
            "--stdio", f"{sys.executable} {FIXTURE_SERVER}",
            "--tools", "fetch_url",
            "--report", "json",
            "--output-file", str(out),
        ),
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode in (0, 1), result.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    # Only fetch_url should appear in the filtered surface map.
    tool_names = {t["name"] for t in payload["surface"]["tools"]}
    assert tool_names == {"fetch_url"}
    # Findings should be limited to fetch_url too.
    for f in payload["findings"]:
        assert "fetch_url" in f["target_locus"]
