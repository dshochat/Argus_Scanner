"""Unit tests for the fail-open + auth-bypass probes."""

from __future__ import annotations

from mcp_scanner.classifier import ParamClass
from mcp_scanner.probes.auth_bypass import AuthBypassProbe
from mcp_scanner.probes.base import PROBE_REGISTRY
from mcp_scanner.probes.fail_open import FailOpenProbe
from mcp_scanner.sandbox_launcher import ProbeResponse
from mcp_scanner.surface import MCPParam, MCPSurfaceMap, MCPTool


def _surface_with_url_and_admin_tools() -> MCPSurfaceMap:
    return MCPSurfaceMap(
        target="stdio: x",
        transport="stdio",
        tools=[
            MCPTool(
                name="fetch_url",
                params=[MCPParam(name="url", param_class=ParamClass.URL, required=True)],
            ),
            MCPTool(
                name="admin_lookup",
                params=[MCPParam(name="user_id", param_class=ParamClass.FUZZ, required=True)],
            ),
            MCPTool(
                name="echo",
                params=[MCPParam(name="text", param_class=ParamClass.FUZZ)],
            ),
        ],
    )


# ── registry ─────────────────────────────────────────────────────────


def test_fail_open_probe_registered() -> None:
    assert any(isinstance(p, FailOpenProbe) for p in PROBE_REGISTRY)


def test_auth_bypass_probe_registered() -> None:
    assert any(isinstance(p, AuthBypassProbe) for p in PROBE_REGISTRY)


# ── fail-open: build_requests ────────────────────────────────────────


def test_fail_open_build_requests_only_url_host_params() -> None:
    """Fail-open is URL/HOST-focused in v1 — should skip FUZZ params."""
    surface = _surface_with_url_and_admin_tools()
    reqs = FailOpenProbe().build_requests(surface)
    assert all(r.tool_name == "fetch_url" for r in reqs)


def test_fail_open_build_requests_fan_out_one_per_payload() -> None:
    """6 payloads × 1 URL param = 6 probes for fetch_url."""
    surface = _surface_with_url_and_admin_tools()
    reqs = FailOpenProbe().build_requests(surface)
    assert len(reqs) == 6
    payload_names = [r.probe_id.rsplit("-", 1)[-1] for r in reqs]
    expected = {
        "null_bytes",
        "oversize",
        "control_chars",
        "empty",
        "not_a_url",
        "wrong_type_int",
    }
    assert expected == set(payload_names)


def test_fail_open_build_requests_wrong_type_int_carries_int() -> None:
    surface = _surface_with_url_and_admin_tools()
    reqs = FailOpenProbe().build_requests(surface)
    wrong = next(r for r in reqs if r.probe_id.endswith("wrong_type_int"))
    assert wrong.arguments["url"] == 42


# ── fail-open: evaluate ─────────────────────────────────────────────


def test_fail_open_evaluate_confirmed_on_unattributed_capture() -> None:
    surface = _surface_with_url_and_admin_tools()
    responses = [
        ProbeResponse(
            probe_id="failopen-fetch_url-url-null_bytes",
            probe_class="fail_open",
            tool_name="fetch_url",
            arguments={"url": "http://example.com/\x00"},
            response={"jsonrpc": "2.0", "id": 1, "result": {"content": []}},
        )
    ]
    # Capture is for evil.com — NOT a SSRF/redirect canary host →
    # attributable to fail-open.
    captures = [
        {"host": "evil.com", "path": "/exfil", "scheme": "http", "method": "GET"}
    ]
    findings = FailOpenProbe().evaluate(surface, responses, captures)
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is True
    assert f.cwe == "CWE-755"
    assert "fetch_url" in f.target_locus


def test_fail_open_evaluate_skips_ssrf_attributed_capture() -> None:
    """A capture whose host matches an SSRF canary signature should
    NOT be attributed to fail-open (it belongs to the SSRF probe)."""
    surface = _surface_with_url_and_admin_tools()
    responses = [
        ProbeResponse(
            probe_id="failopen-fetch_url-url-null_bytes",
            probe_class="fail_open",
            tool_name="fetch_url",
            arguments={"url": "x"},
            # Non-error result, so heuristic might still fire below.
            response={"jsonrpc": "2.0", "id": 1, "result": {"content": []}},
        )
    ]
    captures = [
        {"host": "169.254.169.254", "path": "/latest/meta-data/", "scheme": "http"}
    ]
    findings = FailOpenProbe().evaluate(surface, responses, captures)
    # Should NOT have a confirmed finding; no heuristic either since
    # the response has empty content.
    assert findings == []


def test_fail_open_evaluate_heuristic_on_200_for_malformed_input() -> None:
    """Non-error response for malformed input → heuristic finding."""
    surface = _surface_with_url_and_admin_tools()
    responses = [
        ProbeResponse(
            probe_id="failopen-fetch_url-url-null_bytes",
            probe_class="fail_open",
            tool_name="fetch_url",
            arguments={"url": "http://x/\x00"},
            response={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": "got data"}]},
            },
        )
    ]
    findings = FailOpenProbe().evaluate(surface, responses, [])
    assert len(findings) == 1
    assert findings[0].confirmed is False
    assert "Suspected fail-open" in findings[0].title


def test_fail_open_evaluate_no_finding_when_server_rejects() -> None:
    """JSON-RPC-erroring on malformed input is PROPER behavior — no
    fail-open."""
    surface = _surface_with_url_and_admin_tools()
    responses = [
        ProbeResponse(
            probe_id="failopen-fetch_url-url-null_bytes",
            probe_class="fail_open",
            tool_name="fetch_url",
            arguments={"url": "http://x/\x00"},
            is_error=True,
            response={
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32602, "message": "Invalid URL"},
            },
        )
    ]
    findings = FailOpenProbe().evaluate(surface, responses, [])
    assert findings == []


# ── auth-bypass: build_requests ──────────────────────────────────────


def test_auth_bypass_build_requests_emits_paired_calls_per_tool() -> None:
    surface = _surface_with_url_and_admin_tools()
    reqs = AuthBypassProbe().build_requests(surface)
    # 3 tools × 2 calls each = 6 requests.
    tools = {r.tool_name for r in reqs}
    assert tools == {"fetch_url", "admin_lookup", "echo"}
    # Each tool has one authed and one unauthed.
    for tool in tools:
        tool_reqs = [r for r in reqs if r.tool_name == tool]
        assert len(tool_reqs) == 2
        suffixes = {r.probe_id.rsplit("-", 1)[-1] for r in tool_reqs}
        assert suffixes == {"withauth", "noauth"}


def test_auth_bypass_unauthed_request_sends_explicit_empty_token() -> None:
    surface = _surface_with_url_and_admin_tools()
    reqs = AuthBypassProbe().build_requests(surface)
    unauthed = next(
        r for r in reqs
        if r.tool_name == "admin_lookup" and r.probe_id.endswith("noauth")
    )
    assert unauthed.override_auth_token == ""


def test_auth_bypass_authed_request_uses_default_token() -> None:
    surface = _surface_with_url_and_admin_tools()
    reqs = AuthBypassProbe().build_requests(surface)
    authed = next(
        r for r in reqs
        if r.tool_name == "admin_lookup" and r.probe_id.endswith("withauth")
    )
    # None means "use session default" — the harness threads the
    # operator's --auth-token through.
    assert authed.override_auth_token is None


def test_auth_bypass_skips_tools_with_unknown_required_params() -> None:
    """We refuse to synthesise args for required UNKNOWN-class
    params — would produce false positives from schema validation."""
    surface = MCPSurfaceMap(
        target="x",
        transport="stdio",
        tools=[
            MCPTool(
                name="weird_tool",
                params=[
                    MCPParam(name="opaque", param_class=ParamClass.UNKNOWN, required=True)
                ],
            )
        ],
    )
    assert AuthBypassProbe().build_requests(surface) == []


# ── auth-bypass: evaluate ────────────────────────────────────────────


def _ok_response(probe_id: str, tool: str, text: str) -> ProbeResponse:
    return ProbeResponse(
        probe_id=probe_id,
        probe_class="auth_bypass",
        tool_name=tool,
        arguments={"user_id": "1"},
        response={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": text}]},
        },
    )


def test_auth_bypass_evaluate_confirmed_when_unauthed_mirrors_authed() -> None:
    surface = _surface_with_url_and_admin_tools()
    responses = [
        _ok_response("authbp-admin_lookup-withauth", "admin_lookup",
                     '{"user_id": "1", "role": "admin", "api_key": "AKIA-X"}'),
        _ok_response("authbp-admin_lookup-noauth", "admin_lookup",
                     '{"user_id": "1", "role": "admin", "api_key": "AKIA-X"}'),
    ]
    findings = AuthBypassProbe().evaluate(surface, responses, [])
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is True
    assert f.cwe == "CWE-862"
    assert "admin_lookup" in f.title
    assert "admin" in f.authed_diff["authed_excerpt"]
    assert "admin" in f.authed_diff["unauthed_excerpt"]


def test_auth_bypass_evaluate_heuristic_when_no_authed_sample() -> None:
    """If the operator didn't pass --auth-token, we still flag unauthed
    responses that returned data — just at lower confidence."""
    surface = _surface_with_url_and_admin_tools()
    responses = [
        _ok_response("authbp-admin_lookup-noauth", "admin_lookup",
                     '{"role": "admin"}'),
    ]
    findings = AuthBypassProbe().evaluate(surface, responses, [])
    assert len(findings) == 1
    assert findings[0].confirmed is False


def test_auth_bypass_evaluate_no_finding_when_unauthed_rejected() -> None:
    """Server returns JSON-RPC error on unauthed call → proper auth
    enforcement → no finding."""
    surface = _surface_with_url_and_admin_tools()
    responses = [
        _ok_response("authbp-admin_lookup-withauth", "admin_lookup",
                     '{"role": "admin"}'),
        ProbeResponse(
            probe_id="authbp-admin_lookup-noauth",
            probe_class="auth_bypass",
            tool_name="admin_lookup",
            arguments={"user_id": "1"},
            response={
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32000, "message": "missing auth token"},
            },
            is_error=True,
        ),
    ]
    findings = AuthBypassProbe().evaluate(surface, responses, [])
    assert findings == []


def test_auth_bypass_evaluate_no_finding_on_different_responses() -> None:
    """authed returns admin data, unauthed returns only a hello-world —
    the responses are different enough that Jaccard < 0.5 → no
    confirmed bypass (but unauthed had content, so a heuristic still
    fires)."""
    surface = _surface_with_url_and_admin_tools()
    responses = [
        _ok_response("authbp-admin_lookup-withauth", "admin_lookup",
                     '{"user_id": "1", "role": "admin", "api_key": "AKIA-X"}'),
        _ok_response("authbp-admin_lookup-noauth", "admin_lookup",
                     "hello"),
    ]
    findings = AuthBypassProbe().evaluate(surface, responses, [])
    # Unauthed had content → heuristic finding emitted.
    assert len(findings) == 1
    assert findings[0].confirmed is False
