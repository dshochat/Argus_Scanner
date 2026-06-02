"""Redirect-to-internal probe — CWE-601 + CWE-918.

Strategy: supply a URL that LOOKS external but 30x-redirects to an
internal target (AWS IMDS, link-local, loopback). If the MCP server
follows redirects with its default HTTP client (urllib / requests /
fetch) AND doesn't re-validate the post-redirect Location header,
the tool fetches the internal target. Argus's evidence is the same
in-sandbox capture-server callback the SSRF probe relies on.

Canary URL: the same payload format the SSRF probe uses, but pointed
at a host running a redirect script INSIDE the sandbox. Operators
who run ``argus mcp scan --oob <interactsh URL>`` for remote targets
get a redirector at the OOB endpoint instead.

v1 lights up one redirect target per (tool, url-param) pair to keep
the probe count small. Multi-hop chains (A→B→C→IMDS) ship in v1.13.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from mcp_scanner.classifier import ParamClass
from mcp_scanner.findings import MCPFinding, cvss_estimate_for, severity_for
from mcp_scanner.probes.base import register_probe
from mcp_scanner.probes.ssrf import _build_args_for_param
from mcp_scanner.sandbox_launcher import ProbeRequest

if TYPE_CHECKING:
    from mcp_scanner.sandbox_launcher import ProbeResponse
    from mcp_scanner.surface import MCPSurfaceMap


@dataclass(frozen=True)
class _RedirectCanary:
    """Public-looking URL that 30x-redirects to an internal target.

    In the sandbox flavor, the host part resolves to 127.0.0.1 (DNS
    hijack) and the in-sandbox capture-server returns the redirect.
    In the OOB flavor, the host is the user-supplied interactsh URL
    (which most OOB services CAN issue redirects from).
    """

    name: str
    decoy_url: str
    redirect_target_host: str
    redirect_target_path: str
    description: str


_CANARIES: tuple[_RedirectCanary, ...] = (
    _RedirectCanary(
        name="public_to_aws_imds",
        decoy_url="http://argus-redirect-canary.example/redirect/aws-imds",
        redirect_target_host="169.254.169.254",
        redirect_target_path="/latest/meta-data/",
        description="External-looking URL that 30x-redirects to AWS IMDS",
    ),
    _RedirectCanary(
        name="public_to_localhost",
        decoy_url="http://argus-redirect-canary.example/redirect/loopback",
        redirect_target_host="127.0.0.1",
        redirect_target_path="/",
        description="External-looking URL that 30x-redirects to loopback",
    ),
)


class RedirectProbe:
    """Redirect-to-internal (CWE-601) leading to SSRF (CWE-918)."""

    probe_class: str = "redirect_internal"

    def build_requests(self, surface: MCPSurfaceMap) -> list[ProbeRequest]:
        out: list[ProbeRequest] = []
        for tool in surface.tools:
            for param in tool.params:
                if param.param_class not in (ParamClass.URL, ParamClass.HOST):
                    continue
                for canary in _CANARIES:
                    probe_id = (
                        f"redirect-{tool.name}-{param.name}-{canary.name}"[:96]
                    )
                    out.append(
                        ProbeRequest(
                            probe_id=probe_id,
                            probe_class=self.probe_class,
                            tool_name=tool.name,
                            arguments=_build_args_for_param(
                                tool, param.name, canary.decoy_url
                            ),
                            note=f"redirect canary: {canary.description}",
                        )
                    )
        return out

    def evaluate(
        self,
        surface: MCPSurfaceMap,
        responses: list[ProbeResponse],
        network_captures: list[dict],
    ) -> list[MCPFinding]:
        my_responses = [r for r in responses if r.probe_class == self.probe_class]
        if not my_responses:
            return []

        findings: list[MCPFinding] = []
        grouped: dict[tuple[str, str], list[ProbeResponse]] = {}
        for r in my_responses:
            pname = _extract_param_name(r)
            grouped.setdefault((r.tool_name, pname), []).append(r)

        for (tool_name, param_name), rs in grouped.items():
            # Confirmation: TWO captures should exist for this probe —
            # the initial decoy fetch + the post-redirect target. The
            # post-redirect host is the strong signal; emit one finding
            # if it landed.
            confirmed_hit: tuple[ProbeResponse, _RedirectCanary, dict] | None = None
            for r in rs:
                canary = _lookup_canary_by_probe_id(r.probe_id)
                if canary is None:
                    continue
                for cap in network_captures:
                    if _capture_is_sink_hit(cap):
                        confirmed_hit = (r, canary, cap)
                        break
                if confirmed_hit is not None:
                    break

            if confirmed_hit is not None:
                r, canary, cap = confirmed_hit
                findings.append(
                    _build_redirect_finding(
                        idx=len(findings) + 1,
                        surface=surface,
                        tool_name=tool_name,
                        param_name=param_name,
                        response=r,
                        canary=canary,
                        capture=cap,
                        confirmed=True,
                    )
                )
                continue

            # Heuristic: the server's response shows it fetched the
            # decoy URL (any non-error content) but we have no
            # network evidence. Flag suspected with lower CVSS.
            heuristic = _pick_heuristic_response(rs)
            if heuristic is not None:
                canary = _lookup_canary_by_probe_id(heuristic.probe_id)
                if canary is not None:
                    findings.append(
                        _build_redirect_finding(
                            idx=len(findings) + 1,
                            surface=surface,
                            tool_name=tool_name,
                            param_name=param_name,
                            response=heuristic,
                            canary=canary,
                            capture={},
                            confirmed=False,
                        )
                    )

        return findings


# ── helpers (mirror SSRF probe's helpers, kept module-local for clarity) ──


def _lookup_canary_by_probe_id(probe_id: str) -> _RedirectCanary | None:
    parts = probe_id.rsplit("-", 1)
    if len(parts) != 2:
        return None
    name = parts[1]
    for c in _CANARIES:
        if c.name == name:
            return c
    return None


# The in-sandbox capture-server answers any ``/redirect/*`` decoy with a
# real 302 to this host. It is NEVER requested directly by any probe, so
# a capture for it is unambiguous proof the target FOLLOWED the redirect
# into internal space — no contamination with the SSRF probe's direct
# loopback / IMDS canaries (the bug this replaced).
_SINK_HOST = "argus-redirect-sink.internal"


def _capture_is_sink_hit(cap: dict) -> bool:
    """True when a capture shows the target reached the internal redirect
    sink — i.e. it followed our 30x without re-validating the
    destination."""
    return _SINK_HOST in (cap.get("host") or "").lower()


def _pick_heuristic_response(rs: list[ProbeResponse]) -> ProbeResponse | None:
    """A response that looks like it tried to follow the redirect (got
    SOMETHING back rather than scheme-rejection) is the heuristic."""
    for r in rs:
        content = (r.response.get("result") or {}).get("content") or []
        for c in content:
            text = (c.get("text") if isinstance(c, dict) else "") or ""
            if any(m in text for m in ("URLError", "ConnectionError", "timeout")):
                return r
    for r in rs:
        if r.is_error:
            return r
    return rs[0] if rs else None


def _extract_param_name(r: ProbeResponse) -> str:
    parts = r.probe_id.split("-")
    if len(parts) < 4 or parts[0] != "redirect":
        return ""
    middle = parts[1:-1]
    return middle[-1] if middle else ""


def _build_redirect_finding(
    *,
    idx: int,
    surface: MCPSurfaceMap,
    tool_name: str,
    param_name: str,
    response: ProbeResponse,
    canary: _RedirectCanary,
    capture: dict,
    confirmed: bool,
) -> MCPFinding:
    cvss = cvss_estimate_for("redirect_internal", confirmed=confirmed)
    severity = severity_for(cvss)
    response_text = _response_excerpt(response)
    title_prefix = (
        "Confirmed redirect-to-internal"
        if confirmed
        else "Suspected redirect-to-internal"
    )
    title = (
        f"{title_prefix}: {tool_name}({param_name}) follows 30x redirect "
        f"into internal space"
    )
    explanation = (
        f"Tool ``{tool_name}`` accepts a URL via ``{param_name}``. Argus "
        f"supplied an external-looking decoy (``{canary.decoy_url}``); the "
        f"in-sandbox redirector answered with a 302 to an internal host. "
        + (
            "The capture-server then observed the server reaching that "
            "internal sink — confirming it follows cross-origin redirects "
            "WITHOUT re-validating the post-redirect destination "
            "(CWE-601 → CWE-918). An allowlist checked only on the first "
            "request is bypassed this way."
            if confirmed
            else "The server's response shape suggests it fetched the "
            "decoy URL, but the sandbox didn't observe it following the "
            "redirect to internal. Treat as suspected; confirm with an "
            "OOB redirector (``--oob``)."
        )
    )
    fix = (
        "Configure the HTTP client to NOT follow redirects automatically "
        "(``follow_redirects=False`` in httpx, ``allow_redirects=False`` "
        "in requests). If redirects are required, re-run the URL "
        "allowlist + private-IP filter against the post-redirect Location "
        "BEFORE issuing the next request. Cap redirect depth at 1-2."
    )
    repro = (
        f"$ argus mcp scan --stdio '<launch_cmd>' "
        f"--tools {tool_name} --authorized"
    )
    return MCPFinding(
        id=f"F{idx:03d}",
        probe_class="redirect_internal",
        vuln_class="Redirect-to-internal SSRF",
        cwe="CWE-601",  # Open Redirect (chains into CWE-918 SSRF)
        severity=severity,
        cvss_estimate=cvss,
        confirmed=confirmed,
        target_locus=f"tool:{tool_name}.{param_name}",
        target=surface.target,
        transport=surface.transport,
        payload=dict(response.arguments),
        response_excerpt=response_text,
        network_evidence=[capture] if capture else [],
        title=title,
        explanation=explanation,
        fix=fix,
        repro=repro,
    )


def _response_excerpt(r: ProbeResponse) -> str:
    if "error" in r.response:
        err = r.response["error"] or {}
        if isinstance(err, dict):
            return f"JSON-RPC error code={err.get('code')} message={err.get('message')!r}"
        return f"JSON-RPC error: {err}"
    content = (r.response.get("result") or {}).get("content") or []
    for c in content:
        if isinstance(c, dict) and isinstance(c.get("text"), str):
            return c["text"][:400]
    return ""


_INSTANCE = RedirectProbe()
register_probe(_INSTANCE)
