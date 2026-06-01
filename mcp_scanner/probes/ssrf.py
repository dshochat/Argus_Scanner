"""SSRF probe — CWE-918.

Strategy: for every MCP tool param classified as URL or HOST (see
``mcp_scanner.classifier``), emit one ``ProbeRequest`` per canonical
SSRF payload. Reuses the curated payload catalog from
``dast.behavioral_probe`` so MCP-mode probes and existing
behavioral-probe seeds stay in lockstep.

Canary payload set (v1):

  * AWS IMDSv1 — ``http://169.254.169.254/latest/meta-data/iam/security-credentials/``
  * AWS IMDSv2 token flow — ``http://169.254.169.254/latest/api/token``
    (a real IMDSv2 fetch requires a PUT with ``X-aws-ec2-metadata-token-ttl-seconds``;
    most MCP tools that accept URLs use GET, so v1 fires the GET against
    /latest/api/token to detect attempts that would normally precede the
    PUT step. v1.13 will add a proper PUT primitive.)
  * GCP metadata — ``http://metadata.google.internal/computeMetadata/v1/``
  * Azure IMDS — ``http://169.254.169.254/metadata/instance``
  * Loopback HTTP — ``http://127.0.0.1:80/`` and ``http://localhost/``
  * Alt IP encodings — ``http://2852039166/`` (decimal IMDS) and
    ``http://0xa9fea9fe/`` (hex IMDS)

Confirmation: a finding is ``confirmed=True`` iff the in-sandbox
capture-server observed an outbound connection whose ``host`` /
``path`` matches the probe's canary signature. Otherwise the finding
is heuristic (the tool's response shape suggests it tried to fetch,
but the sandbox didn't observe the egress — usually means the server
refused the URL early).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from mcp_scanner.classifier import ParamClass
from mcp_scanner.findings import MCPFinding, cvss_estimate_for, severity_for
from mcp_scanner.probes.base import register_probe
from mcp_scanner.sandbox_launcher import ProbeRequest

if TYPE_CHECKING:
    from mcp_scanner.sandbox_launcher import ProbeResponse
    from mcp_scanner.surface import MCPSurfaceMap


@dataclass(frozen=True)
class _SSRFCanary:
    """One SSRF payload + its expected network-capture signature."""

    name: str
    url: str
    #: Hostname the in-sandbox capture-server will see (post-DNS-hijack
    #: this is the literal name from the URL, even though all DNS
    #: answers come back as 127.0.0.1).
    expected_host: str
    #: Substring the captured path should contain. Used as a secondary
    #: check so a probe that targeted /computeMetadata isn't attributed
    #: to the IMDSv1 finding (different paths, same host).
    expected_path_contains: str
    description: str


# Order matters for reporting (first match wins on attribution
# ambiguity). Loopback variants go LAST so a real metadata-host hit
# beats a generic localhost hit on attribution.
_CANARIES: tuple[_SSRFCanary, ...] = (
    _SSRFCanary(
        name="aws_imdsv1",
        url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        expected_host="169.254.169.254",
        expected_path_contains="/latest/meta-data",
        description="AWS IMDSv1 credentials endpoint",
    ),
    _SSRFCanary(
        name="aws_imdsv2_token",
        url="http://169.254.169.254/latest/api/token",
        expected_host="169.254.169.254",
        expected_path_contains="/latest/api/token",
        description="AWS IMDSv2 token-fetch endpoint",
    ),
    _SSRFCanary(
        name="gcp_metadata",
        url="http://metadata.google.internal/computeMetadata/v1/",
        expected_host="metadata.google.internal",
        expected_path_contains="/computeMetadata/v1",
        description="GCP instance metadata service",
    ),
    _SSRFCanary(
        name="azure_imds",
        url="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        expected_host="169.254.169.254",
        expected_path_contains="/metadata/instance",
        description="Azure IMDS instance endpoint",
    ),
    _SSRFCanary(
        name="alt_decimal_imds",
        url="http://2852039166/latest/meta-data/",
        # Capture-server sees the decimal-encoded form as a host literal.
        expected_host="2852039166",
        expected_path_contains="/latest/meta-data",
        description="AWS IMDS via decimal IP encoding (allowlist bypass)",
    ),
    _SSRFCanary(
        name="alt_hex_imds",
        url="http://0xa9fea9fe/latest/meta-data/",
        expected_host="0xa9fea9fe",
        expected_path_contains="/latest/meta-data",
        description="AWS IMDS via hex IP encoding (allowlist bypass)",
    ),
    _SSRFCanary(
        name="loopback_localhost",
        url="http://localhost/",
        expected_host="localhost",
        expected_path_contains="/",
        description="Loopback via 'localhost' hostname",
    ),
    _SSRFCanary(
        name="loopback_127001",
        url="http://127.0.0.1:80/",
        expected_host="127.0.0.1",
        expected_path_contains="/",
        description="Loopback via 127.0.0.1",
    ),
)


class SSRFProbe:
    """Server-Side Request Forgery probe (CWE-918)."""

    probe_class: str = "ssrf"

    def build_requests(self, surface: MCPSurfaceMap) -> list[ProbeRequest]:
        """For each URL/HOST param on each tool, emit one probe per
        canary. Probe IDs are stable across runs so re-reporting picks
        up the same finding identity."""
        out: list[ProbeRequest] = []
        for tool in surface.tools:
            for param in tool.params:
                if param.param_class not in (ParamClass.URL, ParamClass.HOST):
                    continue
                for canary in _CANARIES:
                    probe_id = (
                        f"ssrf-{tool.name}-{param.name}-{canary.name}"[:96]
                    )
                    out.append(
                        ProbeRequest(
                            probe_id=probe_id,
                            probe_class=self.probe_class,
                            tool_name=tool.name,
                            arguments=_build_args_for_param(
                                tool, param.name, canary.url
                            ),
                            note=f"ssrf canary: {canary.description}",
                        )
                    )
        return out

    def evaluate(
        self,
        surface: MCPSurfaceMap,
        responses: list[ProbeResponse],
        network_captures: list[dict],
    ) -> list[MCPFinding]:
        """Walk this probe's responses; emit one finding per
        (tool, param) pair where ANY canary landed.

        We collapse multiple landing canaries into ONE finding per
        (tool, param) because the underlying vulnerability is "this
        sink doesn't filter URLs" — emitting 8 nearly-identical
        findings would just spam the report.
        """
        my_responses = [r for r in responses if r.probe_class == self.probe_class]
        if not my_responses:
            return []

        findings: list[MCPFinding] = []
        # Group by (tool_name, param_name); pick the strongest evidence.
        grouped: dict[tuple[str, str], list[ProbeResponse]] = {}
        for r in my_responses:
            pname = _extract_param_name(r)
            grouped.setdefault((r.tool_name, pname), []).append(r)

        for (tool_name, param_name), rs in grouped.items():
            # Look for confirmed canary hits first.
            confirmed_hits: list[tuple[ProbeResponse, _SSRFCanary, dict]] = []
            for r in rs:
                canary = _lookup_canary_by_probe_id(r.probe_id)
                if canary is None:
                    continue
                for cap in network_captures:
                    if _capture_matches_canary(cap, canary):
                        confirmed_hits.append((r, canary, cap))
                        break

            if confirmed_hits:
                # Pick the canary with the strongest signal — IMDS
                # variants over loopback ones — by sort key (canaries
                # tuple is already ordered by priority).
                strongest = min(
                    confirmed_hits,
                    key=lambda triple: _CANARIES.index(triple[1]),
                )
                r, canary, cap = strongest
                findings.append(
                    _build_ssrf_finding(
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

            # Heuristic path: any of these responses came back with
            # text content that's clearly an attempt at outbound HTTP?
            # (e.g. ``URLError: connection refused``, ``timeout``, etc.)
            # The fixture vuln server returns these; real targets often
            # do too. We flag only one heuristic finding per (tool, param).
            heuristic_r = _pick_heuristic_response(rs)
            if heuristic_r is not None:
                canary = _lookup_canary_by_probe_id(heuristic_r.probe_id)
                if canary is not None:
                    findings.append(
                        _build_ssrf_finding(
                            idx=len(findings) + 1,
                            surface=surface,
                            tool_name=tool_name,
                            param_name=param_name,
                            response=heuristic_r,
                            canary=canary,
                            capture={},
                            confirmed=False,
                        )
                    )

        return findings


# ── helpers ──────────────────────────────────────────────────────────


def _build_args_for_param(
    tool: object, param_name: str, payload: str
) -> dict[str, object]:
    """Construct a tools/call ``arguments`` dict that fills the named
    param with our payload and supplies plausible defaults for other
    required params (so the server's schema validator doesn't reject
    the call before our canary lands)."""
    from mcp_scanner.surface import MCPTool

    if not isinstance(tool, MCPTool):
        return {param_name: payload}
    args: dict[str, object] = {}
    for p in tool.params:
        if p.name == param_name:
            args[p.name] = payload
        elif p.required:
            args[p.name] = _default_for_param_class(p.param_class)
    return args


def _default_for_param_class(cls: ParamClass) -> object:
    if cls in (ParamClass.URL, ParamClass.HOST):
        return "http://example.invalid/"
    if cls == ParamClass.PATH:
        return "/tmp/x"
    if cls == ParamClass.COMMAND:
        return "true"
    if cls == ParamClass.QUERY:
        return "1=1"
    if cls == ParamClass.INTEGER:
        return 1
    if cls == ParamClass.BOOLEAN:
        return False
    return "x"


def _lookup_canary_by_probe_id(probe_id: str) -> _SSRFCanary | None:
    # probe_id format: ``ssrf-<tool>-<param>-<canary_name>``
    parts = probe_id.rsplit("-", 1)
    if len(parts) != 2:
        return None
    canary_name = parts[1]
    for c in _CANARIES:
        if c.name == canary_name:
            return c
    return None


def _capture_matches_canary(cap: dict, canary: _SSRFCanary) -> bool:
    """The in-sandbox capture-server records ``{host, path, scheme,
    method, ...}`` per outbound connection. We attribute a capture to
    a canary if host matches AND path contains the canary's signature
    substring."""
    host = (cap.get("host") or "").lower()
    path = cap.get("path") or ""
    if canary.expected_host.lower() not in host:
        return False
    return canary.expected_path_contains in path


def _pick_heuristic_response(rs: list[ProbeResponse]) -> ProbeResponse | None:
    """Choose the most informative response when no canary landed in
    network captures. Order:
      1. A response that returned tool ``content`` containing an
         HTTP/URL error message (server tried to fetch + failed).
      2. A response with ``isError: true`` (server raised but didn't
         block at the schema level).
      3. Anything else — falls through.
    """
    for r in rs:
        content = (r.response.get("result") or {}).get("content") or []
        for c in content:
            text = (c.get("text") if isinstance(c, dict) else "") or ""
            if any(
                marker in text
                for marker in (
                    "URLError",
                    "ConnectionError",
                    "ConnectionRefusedError",
                    "timeout",
                    "Connection refused",
                )
            ):
                return r
    for r in rs:
        if r.is_error:
            return r
    return rs[0] if rs else None


def _extract_param_name(r: ProbeResponse) -> str:
    """Recover the param name we filled with the canary from the
    probe_id. Used by the evaluator to group findings.
    """
    parts = r.probe_id.split("-")
    # probe_id = ``ssrf-<tool>-<param>-<canary>``
    # ``<tool>`` may contain dashes, ``<canary>`` does not.
    # Strategy: drop leading ``ssrf-``, drop trailing ``-<canary>``,
    # and the LAST remaining segment is the param name.
    if len(parts) < 4 or parts[0] != "ssrf":
        return ""
    middle = parts[1:-1]
    return middle[-1] if middle else ""


def _build_ssrf_finding(
    *,
    idx: int,
    surface: MCPSurfaceMap,
    tool_name: str,
    param_name: str,
    response: ProbeResponse,
    canary: _SSRFCanary,
    capture: dict,
    confirmed: bool,
) -> MCPFinding:
    cvss = cvss_estimate_for("ssrf", confirmed=confirmed)
    severity = severity_for(cvss)
    response_text = _response_excerpt(response)
    network_evidence: list[dict] = [capture] if capture else []
    title_prefix = "Confirmed SSRF" if confirmed else "Suspected SSRF"
    title = f"{title_prefix}: {tool_name}({param_name}) → {canary.description}"
    explanation = (
        f"Tool ``{tool_name}`` accepts a URL via ``{param_name}`` and sends "
        f"the request without scheme / private-IP / hostname filtering. "
        f"Argus supplied the canary URL ``{canary.url}`` "
        + (
            "and the sandbox capture-server observed the outbound "
            "connection — exploitation is confirmed."
            if confirmed
            else "and the server's response shape indicates an attempted "
            "outbound fetch (URLError / timeout / connection-refused text "
            "in the tool result). The sandbox didn't observe the egress "
            "directly, so this finding is heuristic."
        )
    )
    fix = (
        "Add a URL allowlist (scheme ∈ {https}, host ∈ {documented "
        "external endpoints}). Reject any URL whose resolved IP is in "
        "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "
        "169.254.0.0/16, or fc00::/7. Block alt encodings (decimal / hex "
        "IPv4 literals, IDN homoglyphs). Re-validate after every redirect."
    )
    repro = (
        f"$ argus mcp scan --stdio '<launch_cmd>' "
        f"--tools {tool_name} --authorized"
    )
    return MCPFinding(
        id=f"F{idx:03d}",
        probe_class="ssrf",
        vuln_class="Server-Side Request Forgery",
        cwe="CWE-918",
        severity=severity,
        cvss_estimate=cvss,
        confirmed=confirmed,
        target_locus=f"tool:{tool_name}.{param_name}",
        target=surface.target,
        transport=surface.transport,
        payload=dict(response.arguments),
        response_excerpt=response_text,
        network_evidence=network_evidence,
        title=title,
        explanation=explanation,
        fix=fix,
        repro=repro,
    )


def _response_excerpt(r: ProbeResponse) -> str:
    """Render the tool response into a short string evidence excerpt."""
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


# Register on import so the scan handler picks it up automatically.
_INSTANCE = SSRFProbe()
register_probe(_INSTANCE)
