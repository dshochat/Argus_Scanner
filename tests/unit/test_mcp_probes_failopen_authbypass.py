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


def test_fail_open_build_requests_emits_direct_and_confusion_pair() -> None:
    """One (direct, confusion) pair per URL param — the differential the
    evaluator needs to prove a real bypass."""
    surface = _surface_with_url_and_admin_tools()
    reqs = FailOpenProbe().build_requests(surface)
    assert len(reqs) == 2
    suffixes = {r.probe_id.rsplit("-", 1)[-1] for r in reqs}
    assert suffixes == {"direct", "confusion"}
    confusion = next(r for r in reqs if r.probe_id.endswith("confusion"))
    # Looks external (userinfo) but resolves to the internal metadata host.
    assert confusion.arguments["url"] == (
        "http://allowed.example@metadata.google.internal/argus-fo-bypass"
    )
    direct = next(r for r in reqs if r.probe_id.endswith("direct"))
    assert direct.arguments["url"] == "http://metadata.google.internal/argus-fo-direct"


# ── fail-open: evaluate ─────────────────────────────────────────────


def _fo_pair(direct_resp: dict, confusion_resp: dict) -> list[ProbeResponse]:
    return [
        ProbeResponse(
            probe_id="failopen-fetch_url-url-direct",
            probe_class="fail_open",
            tool_name="fetch_url",
            arguments={"url": "http://metadata.google.internal/argus-fo-direct"},
            response=direct_resp,
            is_error="error" in direct_resp,
        ),
        ProbeResponse(
            probe_id="failopen-fetch_url-url-confusion",
            probe_class="fail_open",
            tool_name="fetch_url",
            arguments={
                "url": "http://allowed.example@metadata.google.internal/argus-fo-bypass"
            },
            response=confusion_resp,
        ),
    ]


_OK = {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}
_BLOCKED = {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "blocked"}}


def test_fail_open_confirmed_on_differential_bypass() -> None:
    """Confirm ONLY on a real differential: the confusion leg reached
    internal but the DIRECT internal URL was blocked (no direct capture)."""
    surface = _surface_with_url_and_admin_tools()
    responses = _fo_pair(_BLOCKED, _OK)
    captures = [  # only the confusion leg landed
        {"host": "metadata.google.internal", "path": "/argus-fo-bypass", "scheme": "http"}
    ]
    findings = FailOpenProbe().evaluate(surface, responses, captures)
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is True
    assert f.cwe == "CWE-918"
    assert "fetch_url" in f.target_locus


def test_fail_open_silent_when_no_host_control() -> None:
    """The FP fix: if the DIRECT internal URL ALSO reached internal, there's
    no defense to bypass — it's plain SSRF. fail-open stays SILENT so the
    SSRF probe owns it (no duplicate finding on unprotected servers)."""
    surface = _surface_with_url_and_admin_tools()
    responses = _fo_pair(_OK, _OK)
    captures = [
        {"host": "metadata.google.internal", "path": "/argus-fo-direct", "scheme": "http"},
        {"host": "metadata.google.internal", "path": "/argus-fo-bypass", "scheme": "http"},
    ]
    assert FailOpenProbe().evaluate(surface, responses, captures) == []


def test_fail_open_silent_off_external_or_offpath_capture() -> None:
    """Captures to benign external hosts, or off the unique bypass path
    (e.g. the SSRF probe's loopback / IMDS hits), must not confirm."""
    surface = _surface_with_url_and_admin_tools()
    responses = _fo_pair(_BLOCKED, _OK)
    # External host on a non-bypass path:
    assert FailOpenProbe().evaluate(surface, responses, [{"host": "example.com", "path": "/"}]) == []
    # SSRF probe's loopback capture (not on the fail-open bypass path):
    assert FailOpenProbe().evaluate(surface, responses, [{"host": "127.0.0.1", "path": "/"}]) == []
    # IMDS on the SSRF canary path (not the fail-open bypass path):
    assert (
        FailOpenProbe().evaluate(
            surface, responses, [{"host": "169.254.169.254", "path": "/latest/meta-data/"}]
        )
        == []
    )


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


def _authed_probe() -> AuthBypassProbe:
    """An AuthBypassProbe with a token configured (the CLI sets this
    per-scan; tests that expect findings must opt in)."""
    p = AuthBypassProbe()
    p.auth_token_configured = True
    return p


def test_auth_bypass_evaluate_confirmed_when_unauthed_mirrors_authed() -> None:
    surface = _surface_with_url_and_admin_tools()
    responses = [
        _ok_response("authbp-admin_lookup-withauth", "admin_lookup",
                     '{"user_id": "1", "role": "admin", "api_key": "AKIA-X"}'),
        _ok_response("authbp-admin_lookup-noauth", "admin_lookup",
                     '{"user_id": "1", "role": "admin", "api_key": "AKIA-X"}'),
    ]
    findings = _authed_probe().evaluate(surface, responses, [])
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is True
    assert f.cwe == "CWE-862"
    assert "admin_lookup" in f.title
    assert "admin" in f.authed_diff["authed_excerpt"]
    assert "admin" in f.authed_diff["unauthed_excerpt"]


def test_auth_bypass_silent_when_token_not_configured() -> None:
    """Default (no --auth-token) → the target is unauthenticated by the
    operator's own config, so there's nothing to bypass. Even a perfect
    authed/unauthed mirror must NOT produce a finding (kills the dominant
    false positive against intentionally-public tools)."""
    surface = _surface_with_url_and_admin_tools()
    responses = [
        _ok_response("authbp-admin_lookup-withauth", "admin_lookup",
                     '{"role": "admin"}'),
        _ok_response("authbp-admin_lookup-noauth", "admin_lookup",
                     '{"role": "admin"}'),
    ]
    # AuthBypassProbe() defaults auth_token_configured=False.
    assert AuthBypassProbe().evaluate(surface, responses, []) == []


def test_auth_bypass_evaluate_heuristic_when_no_authed_sample() -> None:
    """With a token configured but only the unauthed sample present, we
    still flag the unauthed response that returned data — at lower
    confidence (no authed comparison to confirm against)."""
    surface = _surface_with_url_and_admin_tools()
    responses = [
        _ok_response("authbp-admin_lookup-noauth", "admin_lookup",
                     '{"role": "admin"}'),
    ]
    findings = _authed_probe().evaluate(surface, responses, [])
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
    findings = _authed_probe().evaluate(surface, responses, [])
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
    findings = _authed_probe().evaluate(surface, responses, [])
    # Unauthed had content → heuristic finding emitted.
    assert len(findings) == 1
    assert findings[0].confirmed is False
