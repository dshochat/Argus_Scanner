"""Unit tests for mcp_scanner.sandbox_launcher.

Covers:
  * ``LocalMCPSession`` end-to-end against the fixture vuln server
    (no sandbox, no API costs — just subprocess).
  * ``FirecrackerMCPSession`` SandboxPlan construction (verifies the
    plan shape the harness expects).
  * Trace parser correctly assembles SandboxedSessionResult from a
    SandboxTrace that carries a probe_result_json + network captures.
  * Probe spec serialisation round-trips through json.loads.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from mcp_scanner.classifier import ParamClass
from mcp_scanner.sandbox_launcher import (
    FirecrackerMCPSession,
    LocalMCPSession,
    ProbeRequest,
    ProbeResponse,
    SandboxedSessionResult,
    _parse_trace,
    _serialise_probe_spec,
)

pytestmark = pytest.mark.asyncio

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_SERVER = REPO_ROOT / "tests" / "fixtures" / "mcp" / "vulnerable_server.py"


# ── _serialise_probe_spec ────────────────────────────────────────────


async def test_serialise_probe_spec_round_trips() -> None:
    """The harness parses what we serialise — must round-trip through
    json.loads with the field names the harness reads."""
    spec_text = _serialise_probe_spec(
        launch_command="python -m fake_server",
        probes=[
            ProbeRequest(
                probe_id="P001",
                probe_class="ssrf",
                tool_name="fetch_url",
                arguments={"url": "http://169.254.169.254/"},
                note="IMDS canary",
            ),
            ProbeRequest(
                probe_id="P002",
                probe_class="auth_bypass",
                tool_name="admin_lookup",
                arguments={"user_id": "1"},
                override_auth_token="",  # explicit no-auth
            ),
        ],
        default_auth_token="abc",
    )
    spec = json.loads(spec_text)
    assert spec["version"] == 1
    assert spec["launch_command"] == "python -m fake_server"
    assert spec["default_auth_token"] == "abc"
    assert len(spec["probes"]) == 2
    p0 = spec["probes"][0]
    assert p0["probe_id"] == "P001"
    assert p0["probe_class"] == "ssrf"
    assert p0["tool_name"] == "fetch_url"
    assert p0["arguments"] == {"url": "http://169.254.169.254/"}
    assert p0["override_auth_token"] is None
    p1 = spec["probes"][1]
    assert p1["override_auth_token"] == ""


async def test_serialise_probe_spec_empty_probe_list() -> None:
    spec_text = _serialise_probe_spec(
        launch_command="x",
        probes=[],
        default_auth_token=None,
    )
    spec = json.loads(spec_text)
    assert spec["probes"] == []
    assert spec["default_auth_token"] is None


# ── LocalMCPSession ──────────────────────────────────────────────────


async def test_local_session_enumerate_and_run_probes_against_fixture() -> None:
    """End-to-end against the fixture vuln server.

    Drives:
      * Surface enumeration (5 tools should land).
      * One harmless probe (echo) — should succeed.
      * One SSRF-ish probe against fetch_url with an INVALID URL —
        the server returns a URLError text body but no JSON-RPC error,
        so ``is_error`` should be False.
    """
    session = LocalMCPSession([sys.executable, str(FIXTURE_SERVER)])
    probes = [
        ProbeRequest(
            probe_id="L01",
            probe_class="baseline",
            tool_name="echo",
            arguments={"text": "hello"},
        ),
        ProbeRequest(
            probe_id="L02",
            probe_class="ssrf",
            tool_name="fetch_url",
            # Use a URL that resolves but errors out (localhost:1) so the
            # fixture's URLError path fires — no real outbound traffic.
            arguments={"url": "http://127.0.0.1:1/argus-test"},
        ),
    ]
    result = await session.drive(probes)
    assert isinstance(result, SandboxedSessionResult)
    assert result.surface.server_info.get("name") == "argus-fixture-vuln-server"
    assert {t.name for t in result.surface.tools} == {
        "fetch_url",
        "read_url_with_redirects",
        "safe_fetch",
        "admin_lookup",
        "echo",
    }
    # Param classifier ran inside enumerate.
    url_param = next(
        p for tool in result.surface.tools if tool.name == "fetch_url" for p in tool.params
    )
    assert url_param.param_class == ParamClass.URL

    assert len(result.responses) == 2
    echo_r = result.responses[0]
    assert echo_r.probe_id == "L01"
    assert echo_r.is_error is False
    # Server wraps the text result.
    content = (echo_r.response.get("result") or {}).get("content") or []
    assert any("hello" in (c.get("text") or "") for c in content)

    fetch_r = result.responses[1]
    assert fetch_r.probe_id == "L02"
    # Server returned text content (URLError body) — not a JSON-RPC error.
    assert fetch_r.is_error is False
    content = (fetch_r.response.get("result") or {}).get("content") or []
    assert any("URLError" in (c.get("text") or "") for c in content)

    # No sandbox → no network captures.
    assert result.network_captures == []


async def test_local_session_handles_nonexistent_binary() -> None:
    """Spawn failure surfaces as MCPTransportError from inside
    transport.start. The session lets it propagate so the CLI layer
    can render a clean error."""
    from mcp_scanner.transport.base import MCPTransportError

    session = LocalMCPSession(["/nonexistent/bin/never-going-to-work-9999"])
    with pytest.raises(MCPTransportError):
        await session.drive([])


# ── FirecrackerMCPSession + StubSandboxClient ────────────────────────


@pytest.fixture
def stub_sandbox_with_recorded_plan() -> Any:
    """A SandboxClient stub that records the plan submitted to it and
    returns a canned trace. Lets us assert on the SandboxPlan's shape
    without spinning up Fly."""
    from dast.sandbox.client import (
        SandboxEvent,
        SandboxTrace,
    )

    submitted_plans: list[Any] = []
    additional_files_seen: dict[str, dict[str, bytes]] = {}

    class _Stub:
        # Real FirecrackerSandboxClient has this attr; we mirror so the
        # launcher's hasattr() check passes. Values are bytes (matches
        # FirecrackerSandboxClient.additional_files_map).
        additional_files_map: dict[str, dict[str, bytes]] = {}

        async def submit(self, plan: Any) -> SandboxTrace:
            submitted_plans.append(plan)
            additional_files_seen.update(self.additional_files_map)
            # Return a trace whose probe_result_json contains a
            # realistic harness payload.
            harness_result = {
                "surface": {
                    "target": "python /workspace/launch.py",
                    "transport": "stdio",
                    "protocol_version": "2025-03-26",
                    "server_info": {"name": "in-sandbox-srv", "version": "1.0"},
                    "capabilities": {"tools": {}},
                    "tools": [
                        {
                            "name": "fetch_url",
                            "description": "Fetch a URL.",
                            "params": [
                                {
                                    "name": "url",
                                    "param_class": "url",
                                    "required": True,
                                    "json_schema": {"type": "string"},
                                }
                            ],
                            "raw_input_schema": {
                                "type": "object",
                                "properties": {"url": {"type": "string"}},
                            },
                        }
                    ],
                    "resources": [],
                    "prompts": [],
                    "discovery_errors": [],
                },
                "responses": [
                    {
                        "probe_id": "P001",
                        "probe_class": "ssrf",
                        "tool_name": "fetch_url",
                        "arguments": {"url": "http://169.254.169.254/"},
                        "response": {
                            "jsonrpc": "2.0",
                            "id": 7,
                            "result": {
                                "content": [{"type": "text", "text": "imds-response"}]
                            },
                        },
                        "is_error": False,
                        "elapsed_ms": 123,
                        "stderr_excerpt": "",
                        "note": "",
                    }
                ],
                "diagnostics": ["test harness ran fine"],
            }
            return SandboxTrace(
                plan_id=plan.plan_id,
                file_id=plan.file_id,
                hypothesis_id=plan.hypothesis_id,
                events=[
                    SandboxEvent(
                        event_id="evt-net1",
                        kind="network_call_captured",
                        payload={
                            "method": "GET",
                            "host": "169.254.169.254",
                            "path": "/",
                            "scheme": "http",
                        },
                    )
                ],
                exit_code=0,
                stdout_excerpt="",
                stderr_excerpt="",
                elapsed_ms=2000,
                probe_result_json=json.dumps(harness_result),
            )

    return _Stub(), submitted_plans, additional_files_seen


async def test_firecracker_session_builds_well_formed_plan(
    stub_sandbox_with_recorded_plan: Any,
) -> None:
    stub, submitted, files_seen = stub_sandbox_with_recorded_plan
    sess = FirecrackerMCPSession(
        stub,
        launch_command="python /workspace/server.py",
        image_hint="lean",
    )
    probes = [
        ProbeRequest(
            probe_id="P001",
            probe_class="ssrf",
            tool_name="fetch_url",
            arguments={"url": "http://169.254.169.254/"},
        )
    ]
    result = await sess.drive(probes)

    assert len(submitted) == 1
    plan = submitted[0]
    assert plan.image_hint == "lean"
    # Commands MUST reference the staged paths the harness expects.
    assert any("mcp_probe_harness.py" in c for c in plan.commands)
    assert any("mcp_probe_spec.json" in c for c in plan.commands)
    assert any("argus_probe_result.json" in c for c in plan.commands)

    # Multi-file staging: harness source + spec must have been routed
    # through additional_files_map keyed by file_id.
    assert plan.file_id in files_seen
    staged = files_seen[plan.file_id]
    assert "mcp_probe_harness.py" in staged
    assert "mcp_probe_spec.json" in staged
    # Staged values are BYTES (the sandbox client tars them as bytes).
    # The harness file content should look like our harness (sanity
    # check — first line is the shebang or docstring).
    assert isinstance(staged["mcp_probe_harness.py"], bytes)
    assert b"argus" in staged["mcp_probe_harness.py"].lower()

    # Trace was parsed back: harness's reported surface + responses
    # are surfaced on the SandboxedSessionResult.
    assert result.surface.server_info["name"] == "in-sandbox-srv"
    assert len(result.responses) == 1
    assert result.responses[0].probe_id == "P001"
    assert result.responses[0].response["result"]["content"][0]["text"] == "imds-response"
    # network_call_captured event reached network_captures.
    assert len(result.network_captures) == 1
    assert result.network_captures[0]["host"] == "169.254.169.254"
    assert "test harness ran fine" in result.diagnostics


async def test_firecracker_session_propagates_runtime_packages(
    stub_sandbox_with_recorded_plan: Any,
) -> None:
    stub, submitted, _ = stub_sandbox_with_recorded_plan
    sess = FirecrackerMCPSession(
        stub,
        launch_command="python /workspace/server.py",
        runtime_packages=["mcp", "httpx"],
        runtime_npm_packages=[],
    )
    await sess.drive([])
    plan = submitted[0]
    assert plan.runtime_packages == ["mcp", "httpx"]


async def test_firecracker_session_custom_timeout(
    stub_sandbox_with_recorded_plan: Any,
) -> None:
    stub, submitted, _ = stub_sandbox_with_recorded_plan
    sess = FirecrackerMCPSession(
        stub,
        launch_command="x",
        timeout_sec=300,
    )
    await sess.drive([])
    assert submitted[0].timeout_sec == 300


# ── _parse_trace ────────────────────────────────────────────────────


async def test_parse_trace_handles_empty_probe_result_json() -> None:
    """When the harness didn't write anything (e.g. it crashed before
    main()), the parser should produce a session result with empty
    responses + a diagnostic that surfaces the failure to the report
    layer rather than crash."""
    from dast.sandbox.client import SandboxTrace

    trace = SandboxTrace(
        plan_id="x",
        file_id="y",
        hypothesis_id="z",
        events=[],
        exit_code=137,  # killed
        stdout_excerpt="",
        stderr_excerpt="OOM",
        elapsed_ms=10,
        probe_result_json="",
    )
    result = _parse_trace(trace, probes=[], launch_command="cmd")
    # Empty inputs → empty result with stderr surfaced.
    assert result.responses == []
    assert result.server_stderr_excerpt == "OOM"


async def test_parse_trace_handles_malformed_probe_result_json() -> None:
    from dast.sandbox.client import SandboxTrace

    trace = SandboxTrace(
        plan_id="x",
        file_id="y",
        hypothesis_id="z",
        events=[],
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
        probe_result_json="<<not json>>",
    )
    result = _parse_trace(trace, probes=[], launch_command="cmd")
    # Diagnostic added; no crash.
    assert any("could not parse" in d for d in result.diagnostics)


async def test_parse_trace_attributes_probe_class_from_request(
    stub_sandbox_with_recorded_plan: Any,
) -> None:
    """When the harness doesn't echo ``probe_class``, the parser falls
    back to the originating ProbeRequest's class — this is the
    attribution the report layer uses to group findings."""
    from dast.sandbox.client import SandboxTrace

    harness_result = {
        "surface": {
            "target": "x",
            "transport": "stdio",
        },
        "responses": [
            {
                "probe_id": "P-abc",
                # Note: no probe_class in the response.
                "tool_name": "fetch_url",
                "arguments": {"url": "x"},
                "response": {"jsonrpc": "2.0", "id": 1, "result": {}},
                "is_error": False,
                "elapsed_ms": 5,
            }
        ],
    }
    trace = SandboxTrace(
        plan_id="x",
        file_id="y",
        hypothesis_id="z",
        events=[],
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
        probe_result_json=json.dumps(harness_result),
    )
    probes = [
        ProbeRequest(probe_id="P-abc", probe_class="ssrf", tool_name="fetch_url")
    ]
    result = _parse_trace(trace, probes=probes, launch_command="x")
    assert len(result.responses) == 1
    assert result.responses[0].probe_class == "ssrf"


async def test_parse_trace_merges_harness_network_captures() -> None:
    """The harness folds the in-sandbox capture-server log into its
    result payload (reliable transport). _parse_trace must surface those
    in ``network_captures`` so the SSRF/redirect evaluators can confirm
    — even when the trace carried no network_call_captured log events."""
    from dast.sandbox.client import SandboxTrace

    harness_result = {
        "surface": {"target": "x", "transport": "stdio"},
        "responses": [],
        "network_captures": [
            {
                "capture_kind": "http_request",
                "host": "metadata.google.internal",
                "path": "/computeMetadata/v1/",
                "method": "GET",
                "scheme": "http",
            }
        ],
    }
    trace = SandboxTrace(
        plan_id="x",
        file_id="y",
        hypothesis_id="z",
        events=[],  # no log-event captures at all
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
        probe_result_json=json.dumps(harness_result),
    )
    result = _parse_trace(trace, probes=[], launch_command="x")
    assert len(result.network_captures) == 1
    assert result.network_captures[0]["host"] == "metadata.google.internal"
    assert result.network_captures[0]["path"] == "/computeMetadata/v1/"


async def test_harness_collect_captures_normalises_records(tmp_path: Any) -> None:
    """The in-sandbox harness reads /tmp/captured.jsonl and normalises
    http_request records (host from headers → top-level) so the host's
    SSRF evaluator can match them. Sentinels are dropped."""
    from mcp_scanner.sandbox_probe_harness import _collect_captures

    cap_file = tmp_path / "captured.jsonl"
    cap_file.write_text(
        "\n".join(
            [
                '{"kind": "server_start", "ports": [80, 443, 53]}',
                '{"kind": "http_request", "method": "GET", "path": "/computeMetadata/v1/",'
                ' "headers": {"host": "metadata.google.internal"}, "peer": "127.0.0.1:5"}',
                '{"kind": "dns_query", "qname": "evil.example", "qtype": 1,'
                ' "responded_with": "127.0.0.1"}',
                "not json",
            ]
        ),
        encoding="utf-8",
    )
    caps = _collect_captures(str(cap_file))
    # server_start sentinel + the malformed line are dropped.
    assert len(caps) == 2
    http = next(c for c in caps if c["capture_kind"] == "http_request")
    assert http["host"] == "metadata.google.internal"
    assert http["path"] == "/computeMetadata/v1/"
    dns = next(c for c in caps if c["capture_kind"] == "dns_query")
    assert dns["host"] == "evil.example"


async def test_harness_collect_captures_missing_file_is_empty() -> None:
    from mcp_scanner.sandbox_probe_harness import _collect_captures

    assert _collect_captures("/nonexistent/path/captured.jsonl") == []


# ── ProbeResponse / ProbeRequest dataclass sanity ────────────────────


async def test_probe_request_defaults() -> None:
    p = ProbeRequest(probe_id="X", probe_class="ssrf", tool_name="t")
    assert p.arguments == {}
    assert p.override_auth_token is None
    assert p.setup == []
    assert p.note == ""


async def test_probe_response_defaults() -> None:
    r = ProbeResponse(
        probe_id="X", probe_class="ssrf", tool_name="t", arguments={}
    )
    assert r.response == {}
    assert r.is_error is False
    assert r.elapsed_ms == 0
    assert r.stderr_excerpt == ""
    assert r.note == ""
