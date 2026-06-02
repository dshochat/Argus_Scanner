"""Host-allowlist bypass probe (parser confusion → SSRF) — reported
under the ``fail_open`` class, CWE-918 via a bypassed host control.

Differential strategy: for each URL/HOST param, send a PAIR aimed at the
SAME internal host, each on a UNIQUE path (so a resulting capture is
unambiguously attributable to THIS probe — no contamination from the
SSRF / redirect probes):

  * DIRECT baseline  — ``http://metadata.google.internal/argus-fo-direct``
  * CONFUSION variant — ``http://allowed.example@metadata.google.internal/argus-fo-bypass``
    (apparent host ``allowed.example`` — that's userinfo — but the
    EFFECTIVE host is the internal metadata service)

Confirmation requires a genuine DEFENSE BYPASS, not merely "it fetched
something":

  * the CONFUSION variant reached internal (attributed capture on
    ``/argus-fo-bypass``), AND
  * the DIRECT baseline did NOT (no attributed capture on
    ``/argus-fo-direct``) — i.e. the server HAS a host control that
    blocks the obvious internal URL, but the confusion slips past it.

On a server with NO host filtering (it fetches the direct URL too) there
is nothing to bypass — the direct request already reached internal — so
this probe stays SILENT and the plain SSRF probe owns the finding. That
differential is what stops fail-open from duplicating SSRF on
unprotected servers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mcp_scanner.classifier import ParamClass
from mcp_scanner.findings import MCPFinding, cvss_estimate_for, severity_for
from mcp_scanner.probes.base import register_probe
from mcp_scanner.sandbox_launcher import ProbeRequest

if TYPE_CHECKING:
    from mcp_scanner.sandbox_launcher import ProbeResponse
    from mcp_scanner.surface import MCPSurfaceMap


# Internal host both legs target (DNS-hijacked to loopback in the
# sandbox, so the in-sandbox capture-server observes it).
_INTERNAL_TARGET = "metadata.google.internal"
# Unique paths = attribution keys (requested by nothing else in the scan).
_FO_DIRECT_PATH = "/argus-fo-direct"
_FO_BYPASS_PATH = "/argus-fo-bypass"
# Hosts that mean "the request reached internal space".
_INTERNAL_HOSTS: tuple[str, ...] = (
    "metadata.google.internal",
    "169.254.169.254",
    "127.0.0.1",
    "localhost",
)

_SUFFIX_DIRECT = "direct"
_SUFFIX_CONFUSION = "confusion"


class FailOpenProbe:
    """Host-allowlist bypass via parser/userinfo confusion (differential)."""

    probe_class: str = "fail_open"

    def build_requests(self, surface: MCPSurfaceMap) -> list[ProbeRequest]:
        """Emit a (direct, confusion) pair per URL/HOST param. The
        evaluator only confirms when the direct leg is blocked but the
        confusion leg reaches internal."""
        out: list[ProbeRequest] = []
        for tool in surface.tools:
            for param in tool.params:
                if param.param_class not in (ParamClass.URL, ParamClass.HOST):
                    continue
                base_id = f"failopen-{tool.name}-{param.name}"[:80]
                out.append(
                    ProbeRequest(
                        probe_id=f"{base_id}-{_SUFFIX_DIRECT}",
                        probe_class=self.probe_class,
                        tool_name=tool.name,
                        arguments=_args(
                            tool, param.name,
                            f"http://{_INTERNAL_TARGET}{_FO_DIRECT_PATH}",
                        ),
                        note="fail-open baseline: direct request to internal host",
                    )
                )
                out.append(
                    ProbeRequest(
                        probe_id=f"{base_id}-{_SUFFIX_CONFUSION}",
                        probe_class=self.probe_class,
                        tool_name=tool.name,
                        arguments=_args(
                            tool, param.name,
                            f"http://allowed.example@{_INTERNAL_TARGET}{_FO_BYPASS_PATH}",
                        ),
                        note="fail-open bypass: userinfo-confusion URL "
                        "(looks external, resolves internal)",
                    )
                )
        return out

    def evaluate(
        self,
        surface: MCPSurfaceMap,
        responses: list[ProbeResponse],
        network_captures: list[dict],
    ) -> list[MCPFinding]:
        my = [r for r in responses if r.probe_class == self.probe_class]
        if not my:
            return []

        findings: list[MCPFinding] = []
        grouped: dict[tuple[str, str], list[ProbeResponse]] = {}
        for r in my:
            grouped.setdefault((r.tool_name, _extract_param_name(r)), []).append(r)

        for (tool_name, param_name), rs in grouped.items():
            direct_reached = any(
                _capture_reached(cap, _FO_DIRECT_PATH) for cap in network_captures
            )
            bypass_cap = next(
                (cap for cap in network_captures if _capture_reached(cap, _FO_BYPASS_PATH)),
                None,
            )
            # Confirm ONLY on a genuine differential: the confusion leg
            # reached internal but the DIRECT internal URL was blocked.
            # If both reached (no host control) it's plain SSRF — stay
            # silent so the SSRF probe owns it (no duplicate finding).
            if bypass_cap is None or direct_reached:
                continue
            confusion_resp = next(
                (r for r in rs if r.probe_id.endswith(_SUFFIX_CONFUSION)), None
            )
            if confusion_resp is None:
                continue
            findings.append(
                _build_finding(
                    idx=len(findings) + 1,
                    surface=surface,
                    tool_name=tool_name,
                    param_name=param_name,
                    response=confusion_resp,
                    capture=bypass_cap,
                )
            )
        return findings


# ── helpers ──────────────────────────────────────────────────────────


def _args(tool: object, param_name: str, value: object) -> dict[str, object]:
    """Fill ``param_name`` with ``value`` + benign defaults for other
    required params."""
    from mcp_scanner.surface import MCPTool

    if not isinstance(tool, MCPTool):
        return {param_name: value}
    args: dict[str, object] = {}
    for p in tool.params:
        if p.name == param_name:
            args[p.name] = value
            continue
        if not p.required:
            continue
        if p.param_class in (ParamClass.URL, ParamClass.HOST):
            args[p.name] = "http://example.invalid/"
        elif p.param_class == ParamClass.PATH:
            args[p.name] = "/tmp/x"
        elif p.param_class == ParamClass.COMMAND:
            args[p.name] = "true"
        elif p.param_class == ParamClass.QUERY:
            args[p.name] = "1=1"
        elif p.param_class == ParamClass.INTEGER:
            args[p.name] = 1
        elif p.param_class == ParamClass.BOOLEAN:
            args[p.name] = False
        else:
            args[p.name] = "x"
    return args


def _capture_reached(cap: dict, path: str) -> bool:
    """True iff a capture shows an internal host reached on ``path`` —
    the unique path is the attribution key, the internal host is the
    impact."""
    host = (cap.get("host") or "").lower()
    cpath = cap.get("path") or ""
    return path in cpath and any(h in host for h in _INTERNAL_HOSTS)


def _extract_param_name(r: ProbeResponse) -> str:
    parts = r.probe_id.split("-")
    if len(parts) < 4 or parts[0] != "failopen":
        return ""
    return parts[-2]


def _build_finding(
    *,
    idx: int,
    surface: MCPSurfaceMap,
    tool_name: str,
    param_name: str,
    response: ProbeResponse,
    capture: dict,
) -> MCPFinding:
    cvss = cvss_estimate_for("fail_open", confirmed=True)
    severity = severity_for(cvss)
    title = (
        f"Confirmed host-allowlist bypass: {tool_name}({param_name}) "
        f"reaches internal via userinfo confusion"
    )
    explanation = (
        f"Tool ``{tool_name}`` BLOCKED a direct request to the internal "
        f"metadata host, but a userinfo-confusion URL "
        f"(``http://allowed.example@{_INTERNAL_TARGET}{_FO_BYPASS_PATH}`` — "
        f"apparent host ``allowed.example``, effective host "
        f"``{_INTERNAL_TARGET}``) slipped past that control and reached "
        f"internal space. The capture-server observed the bypass request "
        f"on Argus's unique path while the direct request did not land — "
        f"confirming the host control is bypassable (SSRF via a host-"
        f"validation bypass)."
    )
    fix = (
        "Apply the private-range / metadata block to the RESOLVED IP after "
        "parsing (urllib.parse + ipaddress on the resolved address), not "
        "to the apparent hostname. Strip or reject URL userinfo, and "
        "re-apply the check after every redirect."
    )
    repro = (
        f"$ argus mcp scan --stdio '<launch_cmd>' --tools {tool_name} --authorized"
    )
    return MCPFinding(
        id=f"F{idx:03d}",
        probe_class="fail_open",
        vuln_class="Host-allowlist bypass (SSRF)",
        cwe="CWE-918",
        severity=severity,
        cvss_estimate=cvss,
        confirmed=True,
        target_locus=f"tool:{tool_name}.{param_name}",
        target=surface.target,
        transport=surface.transport,
        payload=dict(response.arguments),
        response_excerpt=_response_excerpt(response),
        network_evidence=[capture],
        title=title,
        explanation=explanation,
        fix=fix,
        repro=repro,
    )


def _response_excerpt(r: ProbeResponse) -> str:
    if "error" in r.response:
        err: Any = r.response["error"] or {}
        if isinstance(err, dict):
            return f"JSON-RPC error code={err.get('code')} message={err.get('message')!r}"
        return f"JSON-RPC error: {err}"
    content = (r.response.get("result") or {}).get("content") or []
    for c in content:
        if isinstance(c, dict) and isinstance(c.get("text"), str):
            return c["text"][:400]
    return ""


_INSTANCE = FailOpenProbe()
register_probe(_INSTANCE)
