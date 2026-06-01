"""Sandbox launcher for stdio MCP targets.

The safety contract (v1.12, per the project's working agreements):
**stdio MCP servers are untrusted binaries. Active scans MUST run
them inside the existing Firecracker sandbox** with controlled egress
so SSRF probes hit the in-sandbox capture-server, never real cloud
IMDS / internal infrastructure / the operator's loopback services.

Two session flavors share one interface:

  * ``LocalMCPSession`` — direct subprocess on the host. Used by
    ``argus mcp enumerate`` (recon only, no attack payloads sent) and
    by integration tests that hit the fixture vulnerable server. Fast,
    no Fly cost.

  * ``FirecrackerMCPSession`` — packages the MCP scan as a single
    ``SandboxPlan`` whose entrypoint is the in-sandbox probe harness
    (see ``sandbox_probe_harness.py``). The harness spawns the
    user-supplied MCP launch command INSIDE the sandbox, drives all
    probes sequentially, and writes the per-probe results to
    ``/workspace/argus_probe_result.json`` for the host to parse back.
    Used by ``argus mcp scan`` for stdio targets.

Both flavors return ``SandboxedSessionResult`` with the same shape so
the probe layer doesn't care which one it ran against.
"""

from __future__ import annotations

import json
import logging
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp_scanner.client import MCPClient
from mcp_scanner.transport.stdio import StdioTransport

if TYPE_CHECKING:
    from dast.sandbox.client import SandboxClient, SandboxTrace
    from mcp_scanner.surface import MCPSurfaceMap

log = logging.getLogger("argus.mcp.sandbox_launcher")

# Location inside the sandbox where the probe harness reads / writes
# its data files. Aligned with the existing sandbox staging convention
# (everything goes under /workspace).
_SANDBOX_WORKSPACE = "/workspace"
_SANDBOX_HARNESS_PATH = f"{_SANDBOX_WORKSPACE}/mcp_probe_harness.py"
_SANDBOX_PROBE_SPEC_PATH = f"{_SANDBOX_WORKSPACE}/mcp_probe_spec.json"
_SANDBOX_RESULT_PATH = f"{_SANDBOX_WORKSPACE}/argus_probe_result.json"

# Per-tier defaults. MCP scans default to ``lean`` (Python stdlib +
# Node) since most MCP servers are written in Python or TS. The
# ``rich_python`` tier is the right pick for a server that imports
# common third-party libs (requests, pandas).
_DEFAULT_IMAGE_HINT = "lean"


@dataclass
class ProbeRequest:
    """One probe the harness will run against the MCP server.

    Probes (Steps 4-5) emit a list of these. The shape is intentionally
    minimal: a probe identifier + tool name + arguments to send. The
    harness invokes ``tools/call`` and records the response. Probes
    that need pre-call setup (auth-bypass needs paired calls with and
    without the token; redirect needs a canary URL the harness should
    GET first) carry that via ``setup``.
    """

    probe_id: str
    probe_class: str  # ssrf | redirect | fail_open | auth_bypass | ...
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    # Optional: override the default --auth-token for this probe.
    # ``None`` means "use the session's default auth"; explicit ``""``
    # means "send unauthenticated". The harness records both
    # variations so the auth-bypass probe can diff them.
    override_auth_token: str | None = None
    # Optional: setup steps the harness should run before tools/call.
    # Currently unused by the harness; reserved for v1.13's
    # multi-step probe chains.
    setup: list[dict[str, Any]] = field(default_factory=list)
    # Free-form note shown in the report ("payload encodes IMDS via
    # decimal IP", "redirect target = 169.254.169.254", etc.)
    note: str = ""


@dataclass
class ProbeResponse:
    """What one ProbeRequest yielded after execution."""

    probe_id: str
    probe_class: str
    tool_name: str
    arguments: dict[str, Any]
    # Raw JSON-RPC envelope returned by the server. Probes inspect
    # this for ``result.content`` text, ``error`` objects, ``isError``
    # flags.
    response: dict[str, Any] = field(default_factory=dict)
    # ``True`` iff the server sent a JSON-RPC error response.
    is_error: bool = False
    # Wall-clock duration in milliseconds.
    elapsed_ms: int = 0
    # Stderr the server emitted during this call (truncated). Useful
    # evidence for fail-open probes: when the validator raises but the
    # tool returns 200, the traceback often appears here.
    stderr_excerpt: str = ""
    # Free-form note from the harness (e.g. "transport disconnected
    # mid-call" — itself a fail-open signal).
    note: str = ""


@dataclass
class SandboxedSessionResult:
    """Aggregate output of one scan session.

    The probe layer (Steps 4-5) reads this:
      * ``responses`` — every probe's tools/call result.
      * ``network_captures`` — events from the in-sandbox capture-server
        (HTTP / TLS / TCP egress attempts the server made during
        probes). Empty when running ``LocalMCPSession`` — the OOB
        listener picks up the slack there.
      * ``surface`` — the enumerated MCPSurfaceMap (handshake +
        tools/list / resources/list / prompts/list).
    """

    surface: MCPSurfaceMap
    responses: list[ProbeResponse] = field(default_factory=list)
    network_captures: list[dict[str, Any]] = field(default_factory=list)
    # Server-level diagnostics — non-fatal but worth surfacing.
    diagnostics: list[str] = field(default_factory=list)
    # Truncated stderr from the server process (catches crashes /
    # tracebacks that happened OUTSIDE of any single tool call).
    server_stderr_excerpt: str = ""


# ── Local subprocess flavor ──────────────────────────────────────────


class LocalMCPSession:
    """Drive a stdio MCP server as a direct subprocess on the host.

    NO SANDBOX. Use ONLY for:
      * Recon (``argus mcp enumerate``) — no attack payloads sent.
      * Integration tests against the fixture vulnerable server.
      * Operators explicitly opting in via ``--unsafe-direct-stdio``
        (NOT exposed in v1.12; reserved as an extension point).

    For active scans against untrusted binaries, use
    ``FirecrackerMCPSession`` instead.
    """

    def __init__(self, command: str | list[str]) -> None:
        self._command = command

    async def drive(
        self,
        probes: list[ProbeRequest],
        *,
        default_auth_token: str | None = None,
        per_call_timeout: float = 10.0,
    ) -> SandboxedSessionResult:
        """Spawn the server, handshake, fan out the probes, return
        aggregated results. The local flavor never produces
        ``network_captures`` — outbound traffic from probe payloads
        actually hits the host network. Use only against trusted
        targets (own server, fixture).
        """
        # mypy: StdioTransport satisfies MCPTransport at runtime.
        transport = StdioTransport(self._command)
        await transport.start()
        client = MCPClient(transport)
        responses: list[ProbeResponse] = []
        diagnostics: list[str] = []
        try:
            label = "stdio"
            target = (
                self._command
                if isinstance(self._command, str)
                else shlex.join(self._command)
            )
            surface = await client.enumerate(target=target, transport_label=label)
            for probe in probes:
                resp = await _run_one_probe_local(
                    client,
                    probe,
                    default_auth_token=default_auth_token,
                    per_call_timeout=per_call_timeout,
                )
                responses.append(resp)
        finally:
            # Drain stderr before closing for the report.
            stderr_bytes = b""
            try:
                stderr_bytes = await transport.read_stderr(max_bytes=8192)
            except Exception as e:  # noqa: BLE001
                diagnostics.append(f"stderr drain failed: {e}")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            await transport.aclose()
        return SandboxedSessionResult(
            surface=surface,
            responses=responses,
            network_captures=[],
            diagnostics=diagnostics,
            server_stderr_excerpt=stderr[:4096],
        )


async def _run_one_probe_local(
    client: MCPClient,
    probe: ProbeRequest,
    *,
    default_auth_token: str | None,
    per_call_timeout: float,
) -> ProbeResponse:
    """Run one probe via the local client. Catches per-call exceptions
    so a probe that crashes the server doesn't kill the whole scan."""
    import time

    started_ms = int(time.monotonic() * 1000)
    response: dict[str, Any] = {}
    is_error = False
    note = ""
    try:
        # default_auth_token / probe.override_auth_token are reserved
        # for v1.13 multi-auth runs. v1.12 local sessions send a
        # single tools/call per probe via the open client.
        _ = default_auth_token
        _ = probe.override_auth_token
        response = await client.call_tool(
            probe.tool_name, probe.arguments, timeout=per_call_timeout
        )
        is_error = "error" in response or bool(
            (response.get("result") or {}).get("isError")
        )
    except TimeoutError:
        note = "timeout"
        is_error = True
    except Exception as e:  # noqa: BLE001 — probes must keep running
        note = f"{type(e).__name__}: {e}"
        is_error = True
    elapsed_ms = max(0, int(time.monotonic() * 1000) - started_ms)
    return ProbeResponse(
        probe_id=probe.probe_id,
        probe_class=probe.probe_class,
        tool_name=probe.tool_name,
        arguments=probe.arguments,
        response=response,
        is_error=is_error,
        elapsed_ms=elapsed_ms,
        stderr_excerpt="",
        note=note,
    )


# ── Firecracker (Fly-managed) flavor ─────────────────────────────────


class FirecrackerMCPSession:
    """Drive a stdio MCP server INSIDE the existing Firecracker sandbox.

    The sandbox VM has the in-sandbox dast-capture-server.py listening
    on 127.0.0.1:80 / :443 with DNS-hijacked to return 127.0.0.1 for
    every hostname — so any outbound HTTP/HTTPS/TCP from the MCP
    server during probe execution lands as a ``network_call_captured``
    SandboxEvent and surfaces here as ``network_captures``.

    Implementation: builds ONE ``SandboxPlan`` whose entrypoint is the
    Argus probe harness (``sandbox_probe_harness.py``). The harness
    spawns the user's launch command, runs all probes, writes the
    result file. We then unpack the trace.
    """

    def __init__(
        self,
        sandbox_client: SandboxClient,
        launch_command: str,
        *,
        image_hint: str = _DEFAULT_IMAGE_HINT,
        runtime_packages: list[str] | None = None,
        runtime_npm_packages: list[str] | None = None,
        timeout_sec: int = 120,
    ) -> None:
        self._sandbox = sandbox_client
        self._launch_command = launch_command
        self._image_hint = image_hint
        self._runtime_packages = list(runtime_packages or [])
        self._runtime_npm_packages = list(runtime_npm_packages or [])
        self._timeout_sec = timeout_sec

    async def drive(
        self,
        probes: list[ProbeRequest],
        *,
        plan_id: str = "mcp-scan-1",
        file_id: str = "mcp-target",
        hypothesis_id: str = "mcp-multi-probe",
        default_auth_token: str | None = None,
    ) -> SandboxedSessionResult:
        # Lazy import — only land the dast.sandbox.client import when
        # the production sandbox path actually runs, so unit tests
        # using LocalMCPSession don't pay for it.
        from dast.sandbox.client import SandboxPlan as _SandboxPlan

        probe_spec = _serialise_probe_spec(
            launch_command=self._launch_command,
            probes=probes,
            default_auth_token=default_auth_token,
        )
        harness_source = _read_bundled_harness_source()

        # Wire the harness + spec into the plan as multi-file staging.
        # The sandbox client's ``additional_files_map`` keyed by file_id
        # delivers these into /workspace before commands run.
        additional_files: dict[str, dict[str, str]] = {
            file_id: {
                "mcp_probe_harness.py": harness_source,
                "mcp_probe_spec.json": probe_spec,
            }
        }

        plan = _SandboxPlan(
            plan_id=plan_id,
            file_id=file_id,
            hypothesis_id=hypothesis_id,
            commands=[
                f"python3 {_SANDBOX_HARNESS_PATH} "
                f"--probe-spec {_SANDBOX_PROBE_SPEC_PATH} "
                f"--result {_SANDBOX_RESULT_PATH}"
            ],
            expected_oracle="probe_result_present",
            payload=probe_spec[:512],
            timeout_sec=self._timeout_sec,
            image_hint=self._image_hint,
            runtime_packages=self._runtime_packages,
            runtime_npm_packages=self._runtime_npm_packages,
            file_name="mcp_probe_spec.json",  # sentinel — actual target is the launch cmd
        )

        # The SandboxClient Protocol does NOT define a way to inject
        # ``additional_files_map`` — that's an attribute on the
        # FirecrackerSandboxClient. Production path sets it; the unit
        # test stub ignores the attribute and just runs the plan.
        if hasattr(self._sandbox, "additional_files_map"):
            self._sandbox.additional_files_map = additional_files  # type: ignore[attr-defined]

        trace = await self._sandbox.submit(plan)
        return _parse_trace(trace, probes=probes, launch_command=self._launch_command)


def _serialise_probe_spec(
    *,
    launch_command: str,
    probes: list[ProbeRequest],
    default_auth_token: str | None,
) -> str:
    """JSON-encode the harness's input: launch command + probe list."""
    payload: dict[str, Any] = {
        "version": 1,
        "launch_command": launch_command,
        "default_auth_token": default_auth_token,
        "probes": [
            {
                "probe_id": p.probe_id,
                "probe_class": p.probe_class,
                "tool_name": p.tool_name,
                "arguments": p.arguments,
                "override_auth_token": p.override_auth_token,
                "setup": p.setup,
                "note": p.note,
            }
            for p in probes
        ],
    }
    return json.dumps(payload, separators=(",", ":"))


def _read_bundled_harness_source() -> str:
    """Read the harness script from disk so we can stage it into the
    sandbox. Bundled with the package — no external download path."""
    here = Path(__file__).parent
    harness = here / "sandbox_probe_harness.py"
    return harness.read_text(encoding="utf-8")


def _parse_trace(
    trace: SandboxTrace,
    *,
    probes: list[ProbeRequest],
    launch_command: str,
) -> SandboxedSessionResult:
    """Decode the sandbox trace into ``SandboxedSessionResult``.

    The harness writes one JSON document with this shape:

        {
          "surface": <MCPSurfaceMap-dump>,
          "responses": [
            {"probe_id": ..., "tool_name": ..., "response": {...},
             "is_error": bool, "elapsed_ms": int, "stderr_excerpt": ...},
            ...
          ],
          "diagnostics": [str, ...]
        }

    The host parses this BACK plus harvests ``network_call_captured``
    events from the trace for the per-probe attribution layer.
    """
    from mcp_scanner.surface import MCPSurfaceMap

    diagnostics: list[str] = []
    network_captures: list[dict[str, Any]] = []
    for evt in trace.events:
        if evt.kind == "network_call_captured":
            network_captures.append(evt.payload)

    # Parse the harness's JSON result. The sandbox client puts it in
    # probe_result_json (file-based transport) — preferred over stdout
    # because stdout can be truncated by Fly's per-log-line cap.
    payload_text = trace.probe_result_json or trace.stdout_excerpt or ""
    surface: MCPSurfaceMap
    responses: list[ProbeResponse] = []

    try:
        payload = json.loads(payload_text) if payload_text else {}
    except json.JSONDecodeError as e:
        diagnostics.append(
            f"could not parse harness output ({type(e).__name__}: {e})"
        )
        payload = {}

    surface_raw = payload.get("surface") or {}
    try:
        surface = MCPSurfaceMap.model_validate(surface_raw)
    except Exception as e:  # noqa: BLE001
        diagnostics.append(f"surface validation failed: {type(e).__name__}: {e}")
        surface = MCPSurfaceMap(target=launch_command, transport="stdio")

    probe_lookup = {p.probe_id: p for p in probes}
    for rraw in payload.get("responses") or []:
        if not isinstance(rraw, dict):
            continue
        pid = rraw.get("probe_id") or ""
        probe = probe_lookup.get(pid)
        responses.append(
            ProbeResponse(
                probe_id=pid,
                probe_class=(probe.probe_class if probe else rraw.get("probe_class", "")),
                tool_name=rraw.get("tool_name") or "",
                arguments=rraw.get("arguments") or {},
                response=rraw.get("response") or {},
                is_error=bool(rraw.get("is_error")),
                elapsed_ms=int(rraw.get("elapsed_ms") or 0),
                stderr_excerpt=str(rraw.get("stderr_excerpt") or "")[:4096],
                note=str(rraw.get("note") or ""),
            )
        )

    diagnostics.extend(str(d) for d in (payload.get("diagnostics") or []))

    return SandboxedSessionResult(
        surface=surface,
        responses=responses,
        network_captures=network_captures,
        diagnostics=diagnostics,
        server_stderr_excerpt=trace.stderr_excerpt[:4096],
    )
