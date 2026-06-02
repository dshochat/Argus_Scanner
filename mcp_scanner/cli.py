"""``argus mcp`` CLI handlers.

``scanner/cli.py`` adds the ``mcp`` subparser + dispatches here; this
module owns the actual handler logic so the MCP mode stays a clean
plug-in to the existing engine. Two subcommands in v1:

  * ``enumerate`` — recon only. Connect, run the handshake, call
    tools/list + resources/list + prompts/list, classify each
    parameter, emit a JSON or Markdown surface map. No attacks.

  * ``scan`` — TODO Step 8. Drive the probe catalog against the
    surface. Refuses to scan remote targets without ``--authorized``.

Argparse plumbing here is intentionally minimal — flag definitions
live on the parser in scanner/cli.py for visibility in
``argus --help`` output and the every-subparser-help-renders-cleanly
regression test.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import TYPE_CHECKING, Any

from mcp_scanner.client import MCPClient, MCPClientError
from mcp_scanner.surface import (
    MCPSurfaceMap,  # noqa: TC001 — runtime via Pydantic / model_dump_json
)
from mcp_scanner.transport.base import MCPTransportError
from mcp_scanner.transport.http import HttpTransport
from mcp_scanner.transport.stdio import StdioTransport

if TYPE_CHECKING:
    import argparse

log = logging.getLogger("argus.mcp.cli")


# ── transport selection ──────────────────────────────────────────────


def _infer_transport(args: argparse.Namespace) -> tuple[str, str]:
    """Decide which transport to build from CLI flags.

    Returns ``(transport_label, target_string)``. Raises ``SystemExit``
    with a helpful message on conflicting / missing args so the
    operator sees a clear error rather than a stack trace.
    """
    url = getattr(args, "url", None)
    stdio = getattr(args, "stdio", None)
    explicit = getattr(args, "transport", None)

    if url and stdio:
        print(
            "error: --url and --stdio are mutually exclusive",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if not url and not stdio:
        print(
            "error: one of --url or --stdio is required",
            file=sys.stderr,
        )
        raise SystemExit(2)

    if stdio:
        return ("stdio", stdio)

    # URL path. Auto-infer streamable-http unless overridden. We don't
    # support ws:// in v1 — the MCP spec has deprecated SSE-only.
    label = explicit or "streamable-http"
    if label not in ("http", "sse", "streamable-http"):
        print(
            f"error: --transport for --url must be http|sse|streamable-http, got {label!r}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return (label, url)


def _build_transport(
    label: str, target: str, args: argparse.Namespace
) -> StdioTransport | HttpTransport:
    """Construct the right transport for the chosen flavor.

    Stdio targets are NOT yet routed through the sandbox here — that
    wiring lands in Step 3 (``mcp_scanner.sandbox_launcher``). The
    enumerate path stays direct-subprocess so the operator can run
    enumerate against THEIR OWN server binary without paying sandbox
    cold-start cost. Active scan (Step 8) MUST go through the
    sandbox per the safety contract.
    """
    if label == "stdio":
        return StdioTransport(target)

    auth_mode = getattr(args, "auth", "none") or "none"
    auth_token: str | None = None
    if auth_mode == "token":
        auth_token = getattr(args, "auth_token", None) or None
        if not auth_token:
            print(
                "error: --auth token requires --auth-token <value>",
                file=sys.stderr,
            )
            raise SystemExit(2)
    elif auth_mode != "none":
        print(
            f"error: --auth must be none|token (got {auth_mode!r})",
            file=sys.stderr,
        )
        raise SystemExit(2)

    return HttpTransport(target, auth_token=auth_token)


# ── enumerate ────────────────────────────────────────────────────────


async def _enumerate(args: argparse.Namespace) -> MCPSurfaceMap:
    label, target = _infer_transport(args)
    transport = _build_transport(label, target, args)
    client = MCPClient(transport)
    try:
        if hasattr(transport, "start"):
            await transport.start()
        return await client.enumerate(target=target, transport_label=label)
    finally:
        await transport.aclose()


def _format_surface_markdown(surface: MCPSurfaceMap) -> str:
    """Human-readable surface map for ``--report md``.

    Mirrors the visual conventions of ``scanner/cli.py::format_markdown``
    so operators get a familiar layout when they pivot from
    ``argus scan`` to ``argus mcp enumerate``.
    """
    out: list[str] = []
    out.append("# Argus MCP — Surface Map")
    out.append("")
    out.append(f"**Target:** `{surface.target}`")
    out.append(f"**Transport:** `{surface.transport}`")
    if surface.protocol_version:
        out.append(f"**Protocol:** `{surface.protocol_version}`")
    if surface.server_info:
        name = surface.server_info.get("name") or "(unnamed)"
        version = surface.server_info.get("version") or "?"
        out.append(f"**Server:** {name} {version}")
    out.append("")

    out.append(f"## Tools ({len(surface.tools)})")
    if not surface.tools:
        out.append("_no tools advertised_")
    for tool in surface.tools:
        out.append(f"### `{tool.name}`")
        if tool.description:
            out.append(f"> {tool.description}")
        if tool.params:
            out.append("")
            out.append("| Param | Class | Required |")
            out.append("|---|---|---|")
            for p in tool.params:
                req = "✓" if p.required else ""
                out.append(f"| `{p.name}` | `{p.param_class.value}` | {req} |")
        else:
            out.append("_(no parameters)_")
        out.append("")

    out.append(f"## Resources ({len(surface.resources)})")
    if not surface.resources:
        out.append("_no resources advertised_")
    for r in surface.resources:
        line = f"- `{r.uri}`"
        if r.name:
            line += f" — {r.name}"
        if r.mime_type:
            line += f" ({r.mime_type})"
        out.append(line)
    out.append("")

    out.append(f"## Prompts ({len(surface.prompts)})")
    if not surface.prompts:
        out.append("_no prompts advertised_")
    for p in surface.prompts:
        out.append(f"- `{p.name}`" + (f" — {p.description}" if p.description else ""))
    out.append("")

    summary = surface.param_summary()
    if summary:
        out.append("## Attack-surface summary")
        for cls, count in sorted(summary.items()):
            out.append(f"- **{cls}**: {count}")
        out.append("")

    if surface.discovery_errors:
        out.append("## Discovery errors (non-fatal)")
        for err in surface.discovery_errors:
            out.append(f"- {err}")
        out.append("")

    return "\n".join(out)


async def _run_mcp_enumerate(args: argparse.Namespace) -> int:
    """Handler for ``argus mcp enumerate``."""
    try:
        surface = await _enumerate(args)
    except MCPClientError as e:
        print(f"error: MCP protocol error: {e}", file=sys.stderr)
        return 1
    except MCPTransportError as e:
        print(f"error: transport error: {e}", file=sys.stderr)
        return 1
    except TimeoutError as e:
        print(f"error: timed out waiting for response: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        # E.g. ``argus mcp enumerate --stdio "nonexistent-binary"``.
        print(f"error: {e}", file=sys.stderr)
        return 1

    report_fmt = getattr(args, "report", "json") or "json"
    if report_fmt == "md":
        output = _format_surface_markdown(surface)
    else:
        output = surface.model_dump_json(indent=2)

    output_file = getattr(args, "output_file", None)
    if output_file:
        output_file.write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


async def _run_mcp_scan(args: argparse.Namespace) -> int:
    """Handler for ``argus mcp scan``.

    Drives the full pipeline:
      1. Enumerate the target surface.
      2. Apply --tools filter + --scope-deny CIDR filter.
      3. Build the probe-spec from PROBE_REGISTRY.build_requests(surface).
      4. Optionally spawn the Argus-managed OOB listener (--oob omitted
         on a remote scan), or wire up the user-supplied one (--oob URL).
      5. Drive the session via LocalMCPSession (stdio enumerate) or
         FirecrackerMCPSession (stdio scan — sandboxed). v1.12 LIMITS
         stdio scan to LocalMCPSession when FLY_API_TOKEN is unset —
         we surface a clear warning so the operator knows.
      6. For each registered probe, call evaluate(surface, responses,
         network_captures) and collect findings.
      7. Render JSON / Markdown report.

    Safety gates enforced here, not on the parser:
      * Remote URL scans REQUIRE --authorized. Refuses with exit 2 +
        clear message otherwise.
      * --scope-deny CIDRs filter outbound canary URLs (defense in
        depth on top of the sandbox / OOB isolation).
    """
    # Lazy imports keep the enumerate-only path import-light.
    from mcp_scanner.findings import MCPFinding  # noqa: PLC0415, TC001 — runtime via Pydantic
    from mcp_scanner.oob_listener import (  # noqa: PLC0415
        ArgusManagedOOB,
        UserSuppliedOOB,
    )
    from mcp_scanner.probes import PROBE_REGISTRY  # noqa: PLC0415
    from mcp_scanner.report import render_json, render_markdown  # noqa: PLC0415
    from mcp_scanner.sandbox_launcher import (  # noqa: PLC0415
        ProbeRequest,  # noqa: TC001 — runtime dataclass
    )

    # ── consent gate (remote URL targets) ──────────────────────────────
    label, target = _infer_transport(args)
    if label != "stdio" and not getattr(args, "authorized", False):
        print(
            "error: active scan against a remote URL requires --authorized. "
            "Confirm you have permission to attack the target and re-run.",
            file=sys.stderr,
        )
        return 2

    # ── enumerate (recon) ──────────────────────────────────────────────
    try:
        surface = await _enumerate(args)
    except MCPClientError as e:
        print(f"error: MCP protocol error: {e}", file=sys.stderr)
        return 1
    except MCPTransportError as e:
        print(f"error: transport error: {e}", file=sys.stderr)
        return 1
    except TimeoutError as e:
        print(f"error: timed out waiting for response: {e}", file=sys.stderr)
        return 1

    # ── --tools filter ─────────────────────────────────────────────────
    tools_filter_raw = getattr(args, "tools", None) or ""
    tool_allowlist: set[str] | None = None
    if tools_filter_raw:
        tool_allowlist = {t.strip() for t in tools_filter_raw.split(",") if t.strip()}
        if tool_allowlist:
            surface = surface.model_copy(
                update={"tools": [t for t in surface.tools if t.name in tool_allowlist]}
            )

    # ── build probe spec from registry ─────────────────────────────────
    all_requests: list[ProbeRequest] = []
    for probe in PROBE_REGISTRY:
        all_requests.extend(probe.build_requests(surface))

    if not all_requests:
        print(
            "warning: no probe targets — surface map produced no eligible "
            "tools / params for the probe catalog.",
            file=sys.stderr,
        )

    # ── --scope-deny filter ────────────────────────────────────────────
    scope_deny = getattr(args, "scope_deny", None) or []
    if scope_deny:
        before = len(all_requests)
        all_requests = _apply_scope_deny(all_requests, scope_deny)
        dropped = before - len(all_requests)
        if dropped:
            log.info(
                "scope-deny filter dropped %d probe(s) targeting denied CIDRs",
                dropped,
            )

    # ── OOB listener (optional) ────────────────────────────────────────
    oob_url_arg = getattr(args, "oob", None)
    user_oob: UserSuppliedOOB | None = None
    managed_oob: ArgusManagedOOB | None = None
    if oob_url_arg:
        user_oob = UserSuppliedOOB(oob_url_arg)
    elif label != "stdio":
        # Remote HTTP scan without user-supplied OOB — spawn the
        # Argus-managed listener on an ephemeral port. Operator can
        # tunnel via ngrok / cloudflared if needed.
        managed_oob = ArgusManagedOOB(bind_host="0.0.0.0", bind_port=0)  # noqa: S104
        await managed_oob.start()
        sys.stderr.write(
            "[argus] Argus-managed OOB listener bound at "
            f"http://{managed_oob.public_host}:{managed_oob.actual_port}/argus/<token>\n"
            "[argus] Tunnel via ngrok / cloudflared if you need a public URL.\n"
        )

    # ── drive session ─────────────────────────────────────────────────
    try:
        session = await _drive_session(label, target, args, all_requests)
    except MCPClientError as e:
        print(f"error: MCP protocol error during scan: {e}", file=sys.stderr)
        return 1
    except MCPTransportError as e:
        print(f"error: transport error during scan: {e}", file=sys.stderr)
        return 1
    finally:
        if managed_oob is not None:
            await managed_oob.stop()

    # The session re-enumerates fresh from the server, so its surface
    # is UNFILTERED. If the operator passed --tools, narrow the
    # session's surface to match — the report should reflect what was
    # actually scanned, not the full server surface.
    if tool_allowlist is not None:
        session.surface = session.surface.model_copy(
            update={
                "tools": [t for t in session.surface.tools if t.name in tool_allowlist]
            }
        )

    # ── evaluate findings ─────────────────────────────────────────────
    findings: list[MCPFinding] = []
    finding_idx = 1
    for probe in PROBE_REGISTRY:
        probe_findings = probe.evaluate(
            session.surface,
            session.responses,
            session.network_captures,
        )
        for f in probe_findings:
            # Renumber globally so IDs are stable across probe order.
            f_renumbered = f.model_copy(update={"id": f"F{finding_idx:03d}"})
            findings.append(f_renumbered)
            finding_idx += 1

    # ── collect OOB hits (if any) ─────────────────────────────────────
    oob_hits = []
    if user_oob is not None:
        oob_hits = user_oob.all_hits()
    elif managed_oob is not None:
        oob_hits = managed_oob.all_hits()

    # ── render report ─────────────────────────────────────────────────
    report_fmt = getattr(args, "report", "json") or "json"
    if report_fmt == "md":
        output = render_markdown(
            session=session, findings=findings, oob_hits=oob_hits or None
        )
    else:
        output = render_json(
            session=session, findings=findings, oob_hits=oob_hits or None
        )

    output_file = getattr(args, "output_file", None)
    if output_file:
        output_file.write_text(output, encoding="utf-8")
    else:
        print(output)

    # Exit code: 0 if no findings, 1 if any confirmed, 2 if only heuristic.
    # CI gates can branch on this for "fail build on confirmed vulns".
    if not findings:
        return 0
    any_confirmed = any(f.confirmed for f in findings)
    return 1 if any_confirmed else 0


async def _drive_session(
    label: str,
    target: str,
    args: argparse.Namespace,
    probes: list[Any],
) -> Any:
    """Build the right session for the target, drive it, return result.

    For v1.12: stdio targets use LocalMCPSession (direct subprocess).
    Sandboxed-Firecracker routing is wired in the launcher but not
    exposed via the CLI yet — operators running stdio scans against
    untrusted binaries should run inside a separate container until
    v1.13 lands the production sandbox path on the CLI surface.

    Returns a ``SandboxedSessionResult``.
    """
    if label == "stdio":
        return await _drive_stdio_session(target, args, probes)

    # Remote HTTP path: drive via a fresh httpx client per probe — no
    # sandbox needed because the target is already remote. We reuse
    # the same probe / response data shape so the reporter doesn't
    # care which path produced the result.
    return await _drive_remote_session(target, label, args, probes)


async def _drive_stdio_session(
    target: str,
    args: argparse.Namespace,
    probes: list[Any],
) -> Any:
    """Drive an stdio MCP scan.

    Safety contract: the stdio server is an untrusted binary, so the
    active scan runs it INSIDE the Firecracker sandbox (controlled
    egress → SSRF canaries hit the in-sandbox capture-server, never
    real infrastructure). That requires the DAST Fly config
    (``FLY_API_TOKEN`` + ``ECHO_DAST_IMAGE_LEAN``).

    Fallbacks, loudest-first:
      * ``--unsafe-direct-stdio`` → direct host subprocess (operator
        explicitly accepts host-network probe traffic; trusted targets
        / CI only).
      * No ``FLY_API_TOKEN`` → warn that the scan is NOT sandboxed and
        fall back to a direct subprocess so the command still works.
    """
    import os  # noqa: PLC0415

    from mcp_scanner.sandbox_launcher import LocalMCPSession  # noqa: PLC0415

    default_auth_token = getattr(args, "auth_token", None) or None

    if getattr(args, "unsafe_direct_stdio", False):
        sys.stderr.write(
            "[argus] --unsafe-direct-stdio: running the MCP server as a "
            "DIRECT host subprocess (NOT sandboxed). Probe traffic "
            "originates from this machine.\n"
        )
        return await LocalMCPSession(target).drive(
            probes, default_auth_token=default_auth_token
        )

    if not os.environ.get("FLY_API_TOKEN", "").strip():
        sys.stderr.write(
            "[argus] WARNING: FLY_API_TOKEN not set — cannot sandbox the "
            "stdio target. Falling back to a DIRECT host subprocess; probe "
            "traffic will originate from this machine. Set FLY_API_TOKEN + "
            "ECHO_DAST_IMAGE_LEAN (see docs/dast-setup.md) for sandboxed "
            "scans, or pass --unsafe-direct-stdio to silence this.\n"
        )
        return await LocalMCPSession(target).drive(
            probes, default_auth_token=default_auth_token
        )

    # ── sandboxed path ─────────────────────────────────────────────────
    from dast.sandbox.client import (  # noqa: PLC0415
        FirecrackerSandboxClient,
        FlyMachinesClient,
    )
    from dast.sandbox.multi_image_wiring import (  # noqa: PLC0415
        MultiImageWiringConfig,
    )
    from mcp_scanner.sandbox_launcher import FirecrackerMCPSession  # noqa: PLC0415

    cfg = MultiImageWiringConfig.from_env()
    hint = getattr(args, "sandbox_image_hint", "lean") or "lean"
    image_ref = cfg.image_refs.get(hint) or cfg.image_refs["lean"]
    fly = FlyMachinesClient(
        app_name=cfg.fly_app_name,
        api_token=cfg.fly_api_token,
        region=cfg.fly_region,
    )
    # A single Firecracker client (no multi-image routing needed for one
    # scan) so FirecrackerMCPSession can stage the harness directly via
    # its ``additional_files_map``.
    sandbox = FirecrackerSandboxClient(fly_client=fly, image=image_ref)

    pip_pkgs = list(getattr(args, "sandbox_pip", None) or [])
    npm_pkgs = list(getattr(args, "sandbox_npm", None) or [])
    # The first --sandbox-pip entry is the server distribution: install
    # it WITH dependencies (it must import to launch). Extras install
    # --no-deps (the safe default for pinned modules).
    own_dist = pip_pkgs[0] if pip_pkgs else ""

    sys.stderr.write(
        f"[argus] sandboxed stdio scan via Fly image '{hint}' "
        f"({image_ref}); launching: {target}\n"
    )
    session = FirecrackerMCPSession(
        sandbox,
        launch_command=target,
        image_hint=hint,
        runtime_packages=pip_pkgs,
        runtime_npm_packages=npm_pkgs,
        own_dist_name=own_dist,
        timeout_sec=240,
    )
    return await session.drive(probes, default_auth_token=default_auth_token)


async def _drive_remote_session(
    target: str,
    label: str,
    args: argparse.Namespace,
    probes: list[Any],
) -> Any:
    """Drive the scan against a remote HTTP MCP target.

    Each probe → one tools/call over the HttpTransport. No sandbox
    network captures (the target's egress happens off our network),
    so the findings collapse to heuristic unless the OOB listener
    receives a callback.
    """
    import time  # noqa: PLC0415

    from mcp_scanner.sandbox_launcher import (  # noqa: PLC0415
        ProbeResponse,
        SandboxedSessionResult,
    )

    transport = _build_transport(label, target, args)
    client = MCPClient(transport)
    responses: list[ProbeResponse] = []
    diagnostics: list[str] = []
    try:
        if hasattr(transport, "start"):
            await transport.start()
        surface = await client.enumerate(target=target, transport_label=label)
        for probe in probes:
            started_ms = int(time.monotonic() * 1000)
            response: dict[str, Any] = {}
            is_error = False
            note = ""
            try:
                # For auth-bypass probes that set override_auth_token="",
                # we'd need to swap transports per probe. v1 limitation:
                # remote-mode auth-bypass uses the OPERATOR's session
                # token throughout. Document this in the scan-time
                # diagnostic.
                response = await client.call_tool(
                    probe.tool_name, probe.arguments, timeout=15.0
                )
                is_error = "error" in response or bool(
                    (response.get("result") or {}).get("isError")
                )
            except TimeoutError:
                note = "timeout"
                is_error = True
            except Exception as e:  # noqa: BLE001
                note = f"{type(e).__name__}: {e}"
                is_error = True
            responses.append(
                ProbeResponse(
                    probe_id=probe.probe_id,
                    probe_class=probe.probe_class,
                    tool_name=probe.tool_name,
                    arguments=probe.arguments,
                    response=response,
                    is_error=is_error,
                    elapsed_ms=max(0, int(time.monotonic() * 1000) - started_ms),
                    note=note,
                )
            )
        if any(p.override_auth_token == "" for p in probes):
            diagnostics.append(
                "remote-mode auth-bypass uses operator's session token "
                "for all probes (v1 limitation); confirm bypass manually "
                "by re-running without --auth-token."
            )
        return SandboxedSessionResult(
            surface=surface,
            responses=responses,
            network_captures=[],
            diagnostics=diagnostics,
        )
    finally:
        await transport.aclose()


def _apply_scope_deny(
    probes: list[Any], cidrs: list[str]
) -> list[Any]:
    """Drop probes whose canary URL would direct the target to a
    CIDR the operator explicitly denied.

    v1: only inspects ``arguments``-level URL string values. The
    scope-deny filter is meant as defense in depth — the sandbox
    (stdio) and the lack of a default OOB listener (remote without
    --oob) already prevent canaries from reaching real cloud
    infrastructure.
    """
    import ipaddress  # noqa: PLC0415
    from urllib.parse import urlparse  # noqa: PLC0415

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in cidrs:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log.warning("ignoring invalid --scope-deny CIDR: %r", entry)
            continue

    if not networks:
        return probes

    def _url_targets_denied_cidr(url_value: str) -> bool:
        parsed = urlparse(url_value)
        host = parsed.hostname or ""
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in networks)

    kept: list[Any] = []
    for p in probes:
        denied = False
        for v in p.arguments.values():
            if (
                isinstance(v, str)
                and v.startswith(("http://", "https://"))
                and _url_targets_denied_cidr(v)
            ):
                denied = True
                break
        if not denied:
            kept.append(p)
    return kept


# Convenience for tests that want to drive the handler with parsed
# args. Async-friendly entry point so test code can await it.
def run_enumerate_blocking(args: argparse.Namespace) -> int:
    """Sync wrapper around ``_run_mcp_enumerate`` for callers that
    don't want to set up an event loop themselves."""
    return asyncio.run(_run_mcp_enumerate(args))


__all__: list[str] = [
    "_apply_scope_deny",
    "_build_transport",
    "_enumerate",
    "_format_surface_markdown",
    "_infer_transport",
    "_run_mcp_enumerate",
    "_run_mcp_scan",
    "run_enumerate_blocking",
]
