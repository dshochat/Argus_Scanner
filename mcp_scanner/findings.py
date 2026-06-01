"""Findings model for MCP scans.

Wraps the existing ``shared.types.analysis.Finding`` shape and adds
MCP-specific provenance fields (target, transport, tool name,
authed-vs-unauthed diff). The reporter layer (Step 7) renders these
to JSON / Markdown / SARIF; probes (Step 4-5) construct them.

Severity + CWE are pinned per probe class via the existing
``dast.cwe_probe_registry`` mapping so MCP findings line up with the
rest of Argus's CWE taxonomy.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MCPFinding(BaseModel):
    """One MCP vulnerability finding.

    Field names that mirror ``shared.types.analysis.Finding`` are kept
    spellings-aligned so callers can join the two collections in a
    single report without translation.
    """

    model_config = ConfigDict(extra="forbid")

    #: Stable ID local to this scan ("F001", "F002"…). The reporter
    #: assigns these in the order findings are appended so cross-
    #: references in the Markdown report are stable.
    id: str = Field(pattern=r"^F[0-9]{3}$")
    #: Argus's internal probe class label ("ssrf", "redirect_internal",
    #: "fail_open", "auth_bypass"). Reports group by this.
    probe_class: str
    #: Vulnerability class label rendered to humans ("SSRF",
    #: "Redirect-to-internal", "Fail-open validation",
    #: "Authorization bypass").
    vuln_class: str
    #: CWE identifier (e.g. "CWE-918" for SSRF). Pulled from
    #: ``dast.cwe_probe_registry`` so MCP CWEs match the rest of Argus.
    cwe: str = ""
    #: Per-finding severity. Use the spelled-out lower-case values to
    #: match shared.types.enums.Severity so a downstream consumer can
    #: join MCP findings with file-scan findings without translation.
    severity: str = Field(
        description="low | medium | high | critical",
        pattern=r"^(low|medium|high|critical)$",
    )
    #: CVSS-v3.1 base estimate. Probes compute this from a small
    #: lookup table keyed on probe_class — not a model call.
    cvss_estimate: float | None = Field(default=None, ge=0, le=10)
    #: Whether the probe actually demonstrated exploitation. False for
    #: heuristic findings (e.g. "this tool LOOKS like SSRF but the
    #: server returned an error we couldn't fully attribute"); True
    #: when there's a sandbox-observed network callback.
    confirmed: bool = False
    #: Where the vulnerability lives — usually ``tool_name``, but
    #: resource probes set this to ``resources://...``.
    target_locus: str
    #: The MCP target URL or stdio command this finding came from.
    target: str
    #: Transport label (stdio | http | sse | streamable-http).
    transport: str
    #: The probe payload that triggered the finding — verbatim, so
    #: the report can render a reproducible PoC line.
    payload: dict[str, Any] = Field(default_factory=dict)
    #: What the server returned (truncated). The reporter renders
    #: this as the "Evidence: server-response excerpt" block.
    response_excerpt: str = ""
    #: Sandbox-observed egress that confirmed blind exploitation.
    #: Empty for findings derived only from response shape.
    network_evidence: list[dict[str, Any]] = Field(default_factory=list)
    #: Authed-vs-unauthed response diff. Populated by auth-bypass
    #: only; other probe classes leave this empty.
    authed_diff: dict[str, Any] = Field(default_factory=dict)
    #: One-sentence summary rendered as the finding's title.
    title: str = Field(max_length=120)
    #: Human-readable explanation of what's broken + why it matters.
    explanation: str = Field(max_length=600)
    #: Concrete remediation guidance. Probes embed copy-paste-ready
    #: fixes per class (e.g. "add netloc allowlist + private-IP block").
    fix: str = Field(max_length=600)
    #: Repro command line. The reporter renders this verbatim in a
    #: code block.
    repro: str = ""


def cvss_estimate_for(probe_class: str, *, confirmed: bool) -> float:
    """Per-probe-class CVSS base score. Lifted from the existing
    Argus rubric — confirmed exploits get the higher value (active
    detection), heuristic findings get the lower (static suspicion).
    """
    confirmed_table = {
        "ssrf": 9.1,
        "redirect_internal": 8.1,
        "fail_open": 7.5,
        "auth_bypass": 8.6,
    }
    heuristic_table = {
        "ssrf": 6.5,
        "redirect_internal": 5.4,
        "fail_open": 5.3,
        "auth_bypass": 5.4,
    }
    table = confirmed_table if confirmed else heuristic_table
    return table.get(probe_class, 4.0)


def severity_for(cvss: float) -> str:
    """CVSS → ordinal severity using the standard FIRST.org cutoffs."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"
