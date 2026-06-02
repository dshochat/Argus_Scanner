"""Unit tests for the SSRF + redirect probes.

Covers:
  * build_requests fans out across URL/HOST params with correct
    probe-spec shape.
  * evaluate attributes confirmed findings to the right
    (tool, param) pair using network captures.
  * Heuristic findings emit at the lower CVSS / "suspected" title.
  * Probes register themselves at import.
"""

from __future__ import annotations

from mcp_scanner.classifier import ParamClass
from mcp_scanner.probes.base import PROBE_REGISTRY
from mcp_scanner.probes.redirect import RedirectProbe
from mcp_scanner.probes.ssrf import SSRFProbe
from mcp_scanner.sandbox_launcher import ProbeResponse
from mcp_scanner.surface import MCPParam, MCPSurfaceMap, MCPTool


def _surface_with_fetch_tool() -> MCPSurfaceMap:
    return MCPSurfaceMap(
        target="stdio: fixture",
        transport="stdio",
        tools=[
            MCPTool(
                name="fetch_url",
                description="Fetch a URL.",
                params=[MCPParam(name="url", param_class=ParamClass.URL, required=True)],
            ),
            MCPTool(
                name="echo",
                description="harmless",
                params=[MCPParam(name="text", param_class=ParamClass.FUZZ)],
            ),
        ],
    )


# ── probe registry ──────────────────────────────────────────────────


def test_ssrf_probe_registered_in_registry() -> None:
    assert any(isinstance(p, SSRFProbe) for p in PROBE_REGISTRY)


def test_redirect_probe_registered_in_registry() -> None:
    assert any(isinstance(p, RedirectProbe) for p in PROBE_REGISTRY)


# ── SSRF probe build_requests ───────────────────────────────────────


def test_ssrf_build_requests_skips_non_url_params() -> None:
    """echo(text=FUZZ) shouldn't get SSRF probes — only URL/HOST params."""
    surface = _surface_with_fetch_tool()
    reqs = SSRFProbe().build_requests(surface)
    # All requests target fetch_url.
    assert all(r.tool_name == "fetch_url" for r in reqs)
    # No echo probes.
    assert not any(r.tool_name == "echo" for r in reqs)


def test_ssrf_build_requests_fans_out_one_per_canary() -> None:
    """8 canaries × 1 URL param = 8 probes."""
    surface = _surface_with_fetch_tool()
    reqs = SSRFProbe().build_requests(surface)
    assert len(reqs) == 8
    # Probe class set consistently.
    assert all(r.probe_class == "ssrf" for r in reqs)
    # Probe id formula stable: ``ssrf-<tool>-<param>-<canary>``.
    ids = [r.probe_id for r in reqs]
    assert "ssrf-fetch_url-url-aws_imdsv1" in ids
    assert "ssrf-fetch_url-url-gcp_metadata" in ids
    assert "ssrf-fetch_url-url-alt_decimal_imds" in ids


def test_ssrf_build_requests_argument_carries_canary_url() -> None:
    surface = _surface_with_fetch_tool()
    reqs = SSRFProbe().build_requests(surface)
    aws = next(r for r in reqs if r.probe_id == "ssrf-fetch_url-url-aws_imdsv1")
    assert aws.arguments["url"].startswith("http://169.254.169.254/")


def test_ssrf_build_requests_empty_on_no_url_params() -> None:
    surface = MCPSurfaceMap(
        target="x",
        transport="stdio",
        tools=[
            MCPTool(
                name="add",
                params=[
                    MCPParam(name="a", param_class=ParamClass.INTEGER),
                    MCPParam(name="b", param_class=ParamClass.INTEGER),
                ],
            )
        ],
    )
    assert SSRFProbe().build_requests(surface) == []


def test_ssrf_build_requests_fills_other_required_params_with_defaults() -> None:
    """When the URL probe targets a multi-param tool, the other
    required params get plausible defaults so the schema validator
    doesn't reject the call before the canary even lands."""
    surface = MCPSurfaceMap(
        target="x",
        transport="stdio",
        tools=[
            MCPTool(
                name="complex_fetch",
                params=[
                    MCPParam(name="url", param_class=ParamClass.URL, required=True),
                    MCPParam(name="filter_query", param_class=ParamClass.QUERY, required=True),
                    MCPParam(name="optional_count", param_class=ParamClass.INTEGER, required=False),
                ],
            )
        ],
    )
    reqs = SSRFProbe().build_requests(surface)
    sample = reqs[0]
    assert "url" in sample.arguments
    assert "filter_query" in sample.arguments  # required → default supplied
    assert "optional_count" not in sample.arguments  # not required → omit


# ── SSRF probe evaluate ─────────────────────────────────────────────


def test_ssrf_evaluate_emits_confirmed_finding_on_imds_capture() -> None:
    surface = _surface_with_fetch_tool()
    probe = SSRFProbe()
    responses = [
        ProbeResponse(
            probe_id="ssrf-fetch_url-url-aws_imdsv1",
            probe_class="ssrf",
            tool_name="fetch_url",
            arguments={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
            response={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": "imds-creds-here"}]},
            },
        )
    ]
    captures = [
        {
            "host": "169.254.169.254",
            "path": "/latest/meta-data/iam/security-credentials/",
            "scheme": "http",
            "method": "GET",
        }
    ]
    findings = probe.evaluate(surface, responses, captures)
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is True
    assert f.cwe == "CWE-918"
    assert f.severity == "critical"
    assert f.cvss_estimate is not None and f.cvss_estimate >= 9.0
    assert "fetch_url" in f.title
    assert "url" in f.target_locus
    # Network evidence preserved on the finding.
    assert len(f.network_evidence) == 1
    assert f.network_evidence[0]["host"] == "169.254.169.254"
    assert f.payload == {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}


def test_ssrf_evaluate_emits_heuristic_when_no_capture() -> None:
    surface = _surface_with_fetch_tool()
    probe = SSRFProbe()
    responses = [
        ProbeResponse(
            probe_id="ssrf-fetch_url-url-aws_imdsv1",
            probe_class="ssrf",
            tool_name="fetch_url",
            arguments={"url": "http://169.254.169.254/latest/meta-data/"},
            response={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [{"type": "text", "text": "URLError: connection refused"}]
                },
            },
        )
    ]
    findings = probe.evaluate(surface, responses, [])  # no captures
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is False
    assert f.severity == "medium"  # heuristic CVSS ~6.5
    assert "Suspected SSRF" in f.title


def test_ssrf_evaluate_collapses_multiple_canaries_to_one_finding_per_param() -> None:
    """8 canary responses for the SAME (tool, param) should produce
    ONE finding, not 8. The probe picks the strongest evidence."""
    surface = _surface_with_fetch_tool()
    probe = SSRFProbe()
    responses = [
        ProbeResponse(
            probe_id="ssrf-fetch_url-url-aws_imdsv1",
            probe_class="ssrf",
            tool_name="fetch_url",
            arguments={"url": "http://169.254.169.254/latest/meta-data/"},
            response={"jsonrpc": "2.0", "id": 1, "result": {"content": []}},
        ),
        ProbeResponse(
            probe_id="ssrf-fetch_url-url-loopback_127001",
            probe_class="ssrf",
            tool_name="fetch_url",
            arguments={"url": "http://127.0.0.1:80/"},
            response={"jsonrpc": "2.0", "id": 2, "result": {"content": []}},
        ),
    ]
    captures = [
        {"host": "169.254.169.254", "path": "/latest/meta-data/iam/security-credentials/"},
        {"host": "127.0.0.1", "path": "/"},
    ]
    findings = probe.evaluate(surface, responses, captures)
    assert len(findings) == 1
    # The IMDS canary takes priority over loopback (canary tuple order).
    assert "AWS IMDSv1" in findings[0].title


def test_ssrf_evaluate_ignores_other_probe_classes() -> None:
    """A ProbeResponse from the redirect probe should NOT be counted
    by SSRFProbe.evaluate — each probe filters by its probe_class."""
    surface = _surface_with_fetch_tool()
    probe = SSRFProbe()
    responses = [
        ProbeResponse(
            probe_id="redirect-fetch_url-url-public_to_aws_imds",
            probe_class="redirect_internal",  # not ssrf
            tool_name="fetch_url",
            arguments={"url": "http://canary.example/"},
            response={"jsonrpc": "2.0", "id": 1, "result": {"content": []}},
        )
    ]
    findings = probe.evaluate(surface, responses, [])
    assert findings == []


def test_ssrf_evaluate_empty_responses_returns_empty() -> None:
    findings = SSRFProbe().evaluate(_surface_with_fetch_tool(), [], [])
    assert findings == []


# ── redirect probe ──────────────────────────────────────────────────


def test_redirect_build_requests_fans_out_per_canary() -> None:
    surface = _surface_with_fetch_tool()
    reqs = RedirectProbe().build_requests(surface)
    # 2 canaries × 1 URL param = 2 probes.
    assert len(reqs) == 2
    assert all(r.probe_class == "redirect_internal" for r in reqs)
    assert all(r.tool_name == "fetch_url" for r in reqs)
    payloads = [r.arguments["url"] for r in reqs]
    assert all(p.startswith("http://argus-redirect-canary.example/") for p in payloads)


def test_redirect_evaluate_confirmed_on_post_redirect_capture() -> None:
    surface = _surface_with_fetch_tool()
    probe = RedirectProbe()
    responses = [
        ProbeResponse(
            probe_id="redirect-fetch_url-url-public_to_aws_imds",
            probe_class="redirect_internal",
            tool_name="fetch_url",
            arguments={"url": "http://argus-redirect-canary.example/redirect/aws-imds"},
            response={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": "imds-body"}]},
            },
        )
    ]
    captures = [
        # Initial decoy fetch.
        {"host": "argus-redirect-canary.example", "path": "/redirect/aws-imds"},
        # The target followed our 302 to the internal SINK — the smoking
        # gun. The sink host is requested by nothing else, so this is
        # unambiguously attributable to a redirect-follow (no contamination
        # from the SSRF probe's direct loopback/IMDS canaries).
        {"host": "argus-redirect-sink.internal", "path": "/sunk"},
    ]
    findings = probe.evaluate(surface, responses, captures)
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is True
    assert f.cwe == "CWE-601"
    assert f.severity == "high"  # confirmed redirect CVSS 8.1 → high
    assert "follows 30x" in f.title


def test_redirect_does_not_confirm_off_ssrf_loopback_capture() -> None:
    """FP fix: a loopback/IMDS capture (the SSRF probe's territory) must
    NOT confirm the redirect probe. Only the unique internal sink host —
    reachable solely by following our 302 — confirms a redirect-follow."""
    surface = _surface_with_fetch_tool()
    probe = RedirectProbe()
    responses = [
        ProbeResponse(
            probe_id="redirect-fetch_url-url-public_to_localhost",
            probe_class="redirect_internal",
            tool_name="fetch_url",
            arguments={"url": "http://argus-redirect-canary.example/redirect/loopback"},
            response={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": "ok"}]},
            },
        )
    ]
    # Decoy fetch + a 127.0.0.1 capture that the SSRF probe produced —
    # this used to falsely confirm the redirect.
    captures = [
        {"host": "argus-redirect-canary.example", "path": "/redirect/loopback"},
        {"host": "127.0.0.1", "path": "/"},
    ]
    findings = probe.evaluate(surface, responses, captures)
    assert len(findings) == 1
    assert findings[0].confirmed is False  # heuristic, NOT confirmed


def test_redirect_evaluate_heuristic_when_no_post_redirect_capture() -> None:
    surface = _surface_with_fetch_tool()
    probe = RedirectProbe()
    responses = [
        ProbeResponse(
            probe_id="redirect-fetch_url-url-public_to_aws_imds",
            probe_class="redirect_internal",
            tool_name="fetch_url",
            arguments={"url": "http://argus-redirect-canary.example/redirect/aws-imds"},
            response={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": "URLError: timeout"}]},
            },
        )
    ]
    # Capture for decoy only — NO post-redirect IMDS hit.
    captures = [
        {"host": "argus-redirect-canary.example", "path": "/redirect/aws-imds"}
    ]
    findings = probe.evaluate(surface, responses, captures)
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is False
    assert "Suspected" in f.title


def test_redirect_evaluate_skips_non_redirect_responses() -> None:
    surface = _surface_with_fetch_tool()
    probe = RedirectProbe()
    responses = [
        ProbeResponse(
            probe_id="ssrf-fetch_url-url-aws_imdsv1",
            probe_class="ssrf",
            tool_name="fetch_url",
            arguments={"url": "x"},
            response={},
        )
    ]
    assert probe.evaluate(surface, responses, []) == []
