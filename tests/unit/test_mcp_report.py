"""Unit tests for mcp_scanner.report."""

from __future__ import annotations

import json

from mcp_scanner.classifier import ParamClass
from mcp_scanner.findings import MCPFinding
from mcp_scanner.oob_listener import OOBHit
from mcp_scanner.report import render_json, render_markdown
from mcp_scanner.sandbox_launcher import (
    ProbeResponse,
    SandboxedSessionResult,
)
from mcp_scanner.surface import MCPParam, MCPSurfaceMap, MCPTool


def _sample_session() -> SandboxedSessionResult:
    surface = MCPSurfaceMap(
        target="stdio: python fixture.py",
        transport="stdio",
        protocol_version="2025-03-26",
        server_info={"name": "vuln-srv", "version": "0.1"},
        tools=[
            MCPTool(
                name="fetch_url",
                params=[MCPParam(name="url", param_class=ParamClass.URL, required=True)],
            ),
        ],
    )
    return SandboxedSessionResult(
        surface=surface,
        responses=[
            ProbeResponse(
                probe_id="ssrf-fetch_url-url-aws_imdsv1",
                probe_class="ssrf",
                tool_name="fetch_url",
                arguments={"url": "http://169.254.169.254/"},
                response={"jsonrpc": "2.0", "id": 1, "result": {}},
            ),
            ProbeResponse(
                probe_id="failopen-fetch_url-url-null_bytes",
                probe_class="fail_open",
                tool_name="fetch_url",
                arguments={"url": "x\x00"},
                response={"jsonrpc": "2.0", "id": 2, "result": {}},
            ),
        ],
        network_captures=[
            {"host": "169.254.169.254", "path": "/", "scheme": "http", "method": "GET"}
        ],
        diagnostics=["initialize completed in 230ms"],
        server_stderr_excerpt="[server] starting on stdio",
    )


def _sample_findings() -> list[MCPFinding]:
    return [
        MCPFinding(
            id="F001",
            probe_class="ssrf",
            vuln_class="Server-Side Request Forgery",
            cwe="CWE-918",
            severity="critical",
            cvss_estimate=9.1,
            confirmed=True,
            target_locus="tool:fetch_url.url",
            target="stdio: python fixture.py",
            transport="stdio",
            payload={"url": "http://169.254.169.254/"},
            response_excerpt="imds-creds-here",
            network_evidence=[{"host": "169.254.169.254", "path": "/"}],
            title="Confirmed SSRF: fetch_url(url) → AWS IMDSv1",
            explanation="Tool sends URL straight to urlopen with no filter.",
            fix="Add scheme + IP allowlist.",
            repro="$ argus mcp scan --stdio 'python fixture.py' --authorized",
        ),
        MCPFinding(
            id="F002",
            probe_class="auth_bypass",
            vuln_class="Authorization bypass",
            cwe="CWE-862",
            severity="high",
            cvss_estimate=8.6,
            confirmed=False,
            target_locus="tool:admin_lookup",
            target="stdio: python fixture.py",
            transport="stdio",
            payload={"user_id": "1"},
            response_excerpt="role=admin",
            authed_diff={"authed_excerpt": "role=admin", "unauthed_excerpt": "role=admin"},
            title="Suspected authorization bypass: admin_lookup returns data unauthenticated",
            explanation="No auth-token was supplied so no diff available.",
            fix="Validate Authorization header at handler entry.",
            repro="$ argus mcp scan --auth token --auth-token \"$T\"",
        ),
    ]


# ── render_json ──────────────────────────────────────────────────────


def test_render_json_top_level_schema() -> None:
    payload = json.loads(render_json(session=_sample_session(), findings=_sample_findings()))
    assert payload["schema"] == "argus.mcp.scan-report"
    assert payload["schema_version"] == 1
    assert "argus_version" in payload
    assert "scanned_at_utc" in payload
    assert payload["target"] == "stdio: python fixture.py"
    assert payload["transport"] == "stdio"
    assert "surface" in payload
    assert isinstance(payload["findings"], list)
    assert payload["session_metadata"]["probe_count"] == 2


def test_render_json_findings_sorted_critical_first() -> None:
    payload = json.loads(render_json(session=_sample_session(), findings=_sample_findings()))
    severities = [f["severity"] for f in payload["findings"]]
    assert severities[0] == "critical"
    assert severities[1] == "high"


def test_render_json_includes_server_stderr_when_present() -> None:
    payload = json.loads(render_json(session=_sample_session(), findings=[]))
    assert "server_stderr_excerpt" in payload


def test_render_json_omits_server_stderr_when_empty() -> None:
    session = _sample_session()
    session.server_stderr_excerpt = ""
    payload = json.loads(render_json(session=session, findings=[]))
    assert "server_stderr_excerpt" not in payload


def test_render_json_session_metadata_counts_probe_classes() -> None:
    payload = json.loads(render_json(session=_sample_session(), findings=[]))
    by_class = payload["session_metadata"]["probes_by_class"]
    assert by_class["ssrf"] == 1
    assert by_class["fail_open"] == 1


def test_render_json_includes_oob_hits() -> None:
    hits = [
        OOBHit(token="tokABC1234567890Z", method="GET", path="/argus/tokABC1234567890Z",
               headers={"user-agent": "test"})
    ]
    payload = json.loads(render_json(session=_sample_session(), findings=[], oob_hits=hits))
    assert payload["session_metadata"]["oob_hits_observed"] == 1
    assert payload["oob_hits"][0]["token"] == "tokABC1234567890Z"


def test_render_json_extra_diagnostics_appended() -> None:
    payload = json.loads(render_json(
        session=_sample_session(),
        findings=[],
        extra_diagnostics=["operator note: scan ran from CI"],
    ))
    # Original diagnostic from session + our extra.
    assert "operator note: scan ran from CI" in payload["diagnostics"]
    assert any("initialize completed" in d for d in payload["diagnostics"])


def test_render_json_no_findings_produces_empty_list() -> None:
    payload = json.loads(render_json(session=_sample_session(), findings=[]))
    assert payload["findings"] == []


def test_render_json_is_valid_pretty_printed_json() -> None:
    text = render_json(session=_sample_session(), findings=_sample_findings())
    assert "\n  " in text  # indented
    # Round-trip.
    assert json.loads(text)


# ── render_markdown ──────────────────────────────────────────────────


def test_render_markdown_no_findings_shows_clean_headline() -> None:
    md = render_markdown(session=_sample_session(), findings=[])
    assert "# Argus MCP — Scan Report" in md
    assert "✅" in md
    assert "No findings" in md


def test_render_markdown_renders_severity_summary() -> None:
    md = render_markdown(session=_sample_session(), findings=_sample_findings())
    assert "2 findings" in md
    assert "1 confirmed" in md
    assert "1 heuristic" in md
    assert "1 critical" in md
    assert "1 high" in md


def test_render_markdown_per_finding_sections() -> None:
    md = render_markdown(session=_sample_session(), findings=_sample_findings())
    # F001 should appear first (critical) — check ordering.
    f001_idx = md.find("F001")
    f002_idx = md.find("F002")
    assert 0 <= f001_idx < f002_idx
    assert "🟥 CONFIRMED" in md  # F001 was confirmed
    assert "🟧 SUSPECTED" in md  # F002 was heuristic


def test_render_markdown_renders_authed_diff_for_auth_bypass() -> None:
    md = render_markdown(session=_sample_session(), findings=_sample_findings())
    assert "Authed-vs-unauthed diff" in md
    assert "authed: `role=admin`" in md
    assert "unauthed: `role=admin`" in md


def test_render_markdown_renders_network_evidence() -> None:
    md = render_markdown(session=_sample_session(), findings=_sample_findings())
    assert "Sandbox-observed egress" in md
    assert "169.254.169.254" in md


def test_render_markdown_renders_payload_and_response_code_blocks() -> None:
    md = render_markdown(session=_sample_session(), findings=_sample_findings())
    assert "**Payload:**" in md
    assert "**Server response (excerpt):**" in md
    assert "**Fix:**" in md
    assert "**Reproduce:**" in md


def test_render_markdown_session_telemetry_section() -> None:
    md = render_markdown(session=_sample_session(), findings=[])
    assert "## Session telemetry" in md
    assert "Probes fired: **2**" in md
    assert "Sandbox network captures observed: **1**" in md


def test_render_markdown_renders_oob_hits_count_in_telemetry() -> None:
    hits = [OOBHit(token="tokABCdefGHI67890")]
    md = render_markdown(session=_sample_session(), findings=[], oob_hits=hits)
    assert "OOB hits observed: **1**" in md


def test_render_markdown_shows_diagnostics_when_present() -> None:
    md = render_markdown(
        session=_sample_session(),
        findings=[],
        extra_diagnostics=["extra: timeout on probe foo"],
    )
    assert "### Diagnostics" in md
    assert "extra: timeout on probe foo" in md
    assert "initialize completed in 230ms" in md


def test_render_markdown_renders_server_stderr_when_present() -> None:
    md = render_markdown(session=_sample_session(), findings=[])
    assert "Server stderr" in md
    assert "[server] starting on stdio" in md


def test_render_markdown_no_telemetry_diagnostics_when_clean() -> None:
    session = _sample_session()
    session.diagnostics = []
    session.server_stderr_excerpt = ""
    md = render_markdown(session=session, findings=[])
    assert "### Diagnostics" not in md
    assert "Server stderr" not in md
