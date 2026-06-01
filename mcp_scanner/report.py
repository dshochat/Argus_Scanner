"""Scan-report rendering for ``argus mcp scan``.

Two output formats in v1:

  * ``json`` — machine-readable. Stable schema, mirror of the
    JSON-RPC-ish wire shape downstream CI / SARIF converters expect.
    Top-level shape::

        {
          "schema": "argus.mcp.scan-report",
          "schema_version": 1,
          "target": str,
          "transport": str,
          "scanned_at_utc": str,
          "argus_version": str,
          "surface": {<MCPSurfaceMap-dump>},
          "findings": [{<MCPFinding-dump>}, ...],
          "diagnostics": [str, ...],
          "session_metadata": {
              "probe_count": int,
              "probes_by_class": {str: int},
              "responses_received": int,
              "network_captures_observed": int,
              "oob_hits_observed": int
          }
        }

  * ``md`` — human summary. Mirrors the look of
    ``scanner.cli.format_markdown`` so operators see a familiar
    layout when pivoting between file-scan and MCP-scan reports.

Findings are sorted (severity desc, then CWE asc) before serialisation
so the top of the report is always the most actionable.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_scanner.findings import MCPFinding
    from mcp_scanner.oob_listener import OOBHit
    from mcp_scanner.sandbox_launcher import SandboxedSessionResult


#: Stable schema name for the JSON report. Bump ``schema_version`` (not
#: this string) when the wire shape changes incompatibly.
_SCHEMA_NAME = "argus.mcp.scan-report"
_SCHEMA_VERSION = 1


_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _argus_version() -> str:
    """Best-effort lookup of the installed argus version. Falls back to
    'dev' when the package isn't pip-installed (running from source)."""
    try:
        from importlib.metadata import PackageNotFoundError, version  # noqa: PLC0415

        try:
            return version("argus-ai-scanner")
        except PackageNotFoundError:
            return "dev"
    except ImportError:
        return "dev"


def _sorted_findings(findings: list[MCPFinding]) -> list[MCPFinding]:
    """Sort findings: severity desc → CWE asc → id asc. This is the
    order the JSON report serialises in AND the order Markdown renders.
    A stable order means CI diffs across scan runs stay legible."""
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 99),
            f.cwe or "ZZZ",
            f.id,
        ),
    )


def render_json(
    *,
    session: SandboxedSessionResult,
    findings: list[MCPFinding],
    oob_hits: list[OOBHit] | None = None,
    extra_diagnostics: list[str] | None = None,
) -> str:
    """Build the JSON scan report. Pretty-printed (indent=2) so it's
    human-skim-able even though the primary consumer is automation."""
    sorted_findings = _sorted_findings(findings)
    payload: dict[str, Any] = {
        "schema": _SCHEMA_NAME,
        "schema_version": _SCHEMA_VERSION,
        "argus_version": _argus_version(),
        "scanned_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "target": session.surface.target,
        "transport": session.surface.transport,
        "surface": session.surface.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in sorted_findings],
        "diagnostics": list(session.diagnostics) + list(extra_diagnostics or []),
        "session_metadata": {
            "probe_count": len(session.responses),
            "probes_by_class": _count_by_attr(session.responses, "probe_class"),
            "responses_received": sum(1 for r in session.responses if r.response),
            "network_captures_observed": len(session.network_captures),
            "oob_hits_observed": len(oob_hits or []),
        },
    }
    if oob_hits:
        payload["oob_hits"] = [_oob_hit_dump(h) for h in oob_hits]
    if session.server_stderr_excerpt:
        payload["server_stderr_excerpt"] = session.server_stderr_excerpt
    return json.dumps(payload, indent=2, default=str)


def render_markdown(
    *,
    session: SandboxedSessionResult,
    findings: list[MCPFinding],
    oob_hits: list[OOBHit] | None = None,
    extra_diagnostics: list[str] | None = None,
) -> str:
    """Human-readable scan summary."""
    sorted_findings = _sorted_findings(findings)
    lines: list[str] = []
    lines.append("# Argus MCP — Scan Report")
    lines.append("")
    lines.append(f"**Target:** `{session.surface.target}`")
    lines.append(f"**Transport:** `{session.surface.transport}`")
    if session.surface.protocol_version:
        lines.append(f"**Protocol:** `{session.surface.protocol_version}`")
    if session.surface.server_info:
        name = session.surface.server_info.get("name") or "(unnamed)"
        ver = session.surface.server_info.get("version") or "?"
        lines.append(f"**Server:** {name} {ver}")
    lines.append(f"**Scanned at:** {datetime.now(UTC).isoformat(timespec='seconds')}")
    lines.append(f"**Argus version:** {_argus_version()}")
    lines.append("")

    # ── headline counts ────────────────────────────────────────────
    by_sev = _count_by_attr(sorted_findings, "severity")
    by_class = _count_by_attr(sorted_findings, "probe_class")
    confirmed = sum(1 for f in sorted_findings if f.confirmed)
    lines.append("## Headline")
    lines.append("")
    if not sorted_findings:
        lines.append("✅ **No findings.** All probes ran cleanly.")
    else:
        lines.append(f"**{len(sorted_findings)} findings** "
                     f"({confirmed} confirmed, {len(sorted_findings) - confirmed} heuristic).")
        if by_sev:
            line = " · ".join(
                f"{count} {sev}"
                for sev in ("critical", "high", "medium", "low")
                for count in [by_sev.get(sev, 0)]
                if count
            )
            if line:
                lines.append(f"Severity: {line}")
        if by_class:
            cls_line = " · ".join(f"{count} {cls}" for cls, count in sorted(by_class.items()))
            lines.append(f"Probe class: {cls_line}")
    lines.append("")

    # ── per-finding breakdown ──────────────────────────────────────
    if sorted_findings:
        lines.append("## Findings")
        for f in sorted_findings:
            lines.append("")
            confirmed_mark = "🟥 CONFIRMED" if f.confirmed else "🟧 SUSPECTED"
            severity_mark = f.severity.upper()
            lines.append(f"### {f.id} · {severity_mark} · {confirmed_mark} · {f.title}")
            lines.append("")
            if f.cwe:
                cvss_str = f" · CVSS {f.cvss_estimate:.1f}" if f.cvss_estimate else ""
                lines.append(f"**{f.cwe}** · {f.vuln_class}{cvss_str}")
            lines.append(f"**Locus:** `{f.target_locus}`")
            lines.append("")
            lines.append(f.explanation)
            lines.append("")
            if f.payload:
                lines.append("**Payload:**")
                lines.append("```json")
                lines.append(json.dumps(f.payload, indent=2, default=str))
                lines.append("```")
                lines.append("")
            if f.response_excerpt:
                lines.append("**Server response (excerpt):**")
                lines.append("```")
                lines.append(f.response_excerpt[:400])
                lines.append("```")
                lines.append("")
            if f.network_evidence:
                lines.append("**Sandbox-observed egress:**")
                for cap in f.network_evidence[:5]:
                    method = cap.get("method") or "?"
                    scheme = cap.get("scheme") or ""
                    host = cap.get("host") or "?"
                    path = cap.get("path") or "/"
                    lines.append(f"- `{method} {scheme}://{host}{path}`")
                lines.append("")
            if f.authed_diff:
                lines.append("**Authed-vs-unauthed diff:**")
                a = f.authed_diff.get("authed_excerpt") or "(none)"
                u = f.authed_diff.get("unauthed_excerpt") or "(none)"
                lines.append(f"- authed: `{a}`")
                lines.append(f"- unauthed: `{u}`")
                lines.append("")
            lines.append("**Fix:**")
            lines.append(f.fix)
            lines.append("")
            if f.repro:
                lines.append("**Reproduce:**")
                lines.append("```bash")
                lines.append(f.repro)
                lines.append("```")
                lines.append("")

    # ── session telemetry ──────────────────────────────────────────
    lines.append("## Session telemetry")
    lines.append("")
    lines.append(f"- Probes fired: **{len(session.responses)}**")
    if by_class:
        lines.append("- Probes by class: " + ", ".join(
            f"{cls}={c}" for cls, c in sorted(by_class.items())
        ))
    lines.append(f"- Sandbox network captures observed: **{len(session.network_captures)}**")
    lines.append(f"- OOB hits observed: **{len(oob_hits or [])}**")
    diagnostics = list(session.diagnostics) + list(extra_diagnostics or [])
    if diagnostics:
        lines.append("")
        lines.append("### Diagnostics")
        for d in diagnostics:
            lines.append(f"- {d}")
    if session.server_stderr_excerpt:
        lines.append("")
        lines.append("### Server stderr (excerpt)")
        lines.append("```")
        lines.append(session.server_stderr_excerpt[:400])
        lines.append("```")
    lines.append("")

    return "\n".join(lines)


# ── helpers ──────────────────────────────────────────────────────────


def _count_by_attr(items: list[Any], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        v = getattr(item, attr, "")
        if v:
            counts[str(v)] = counts.get(str(v), 0) + 1
    return counts


def _oob_hit_dump(hit: OOBHit) -> dict[str, Any]:
    return {
        "token": hit.token,
        "method": hit.method,
        "path": hit.path,
        "source_ip": hit.source_ip,
        "headers": dict(hit.headers),
        "body_excerpt": hit.body_excerpt[:512],
        "received_at_ms": hit.received_at_ms,
    }


__all__ = [
    "render_json",
    "render_markdown",
]
