"""Authorization-bypass probe — CWE-862 (missing authorization) +
CWE-285 (improper authorization).

Strategy: invoke every tool / resource / prompt the server exposes
twice — once with the operator's auth token (if any), once without —
and diff the responses. If the unauthenticated response carries the
same data shape as the authenticated one, the server lacks
enforcement.

The auth-bypass probe is the one probe whose semantics REQUIRE
paired calls. The sandbox harness handles this: when the spec carries
a ``default_auth_token`` AND a probe sets ``override_auth_token=""``,
the harness runs the call unauthenticated. v1 emits PAIRS — one
authed, one unauthed — per tool, so the evaluator can diff them.

Gating: this probe only runs when the operator configured an auth
token for the scan (``--auth token --auth-token ...``). Without one,
the target is unauthenticated *by the operator's own configuration*,
so there is nothing to "bypass" — the probe stays silent rather than
flagging every public tool (the dominant false positive, e.g. a fetch
server that returns data on every call). The CLI sets
``auth_token_configured`` before ``evaluate`` runs.

Confirmation: the unauthed response's content has length > 0 (the
server didn't refuse) AND the JSON-RPC envelope has no ``error`` AND
the response shape matches the authed version (same keys at top
level, similar text length). Heuristic findings fire when the
unauthed call returned ANY data at all (server didn't reject — even
if the content shape differs from authed).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp_scanner.findings import MCPFinding, cvss_estimate_for, severity_for
from mcp_scanner.probes.base import register_probe
from mcp_scanner.sandbox_launcher import ProbeRequest

if TYPE_CHECKING:
    from mcp_scanner.sandbox_launcher import ProbeResponse
    from mcp_scanner.surface import MCPSurfaceMap


# Suffix codes baked into probe IDs so the evaluator can pair
# authed vs unauthed responses for the same tool.
_AUTHED_SUFFIX = "withauth"
_UNAUTHED_SUFFIX = "noauth"


class AuthBypassProbe:
    """Authorization-bypass probe (CWE-862)."""

    probe_class: str = "auth_bypass"

    def __init__(self) -> None:
        # Whether the operator configured an auth token for this scan
        # (``--auth token --auth-token ...``). Set per-scan by the CLI
        # before ``evaluate`` runs. When False, the target tool is
        # unauthenticated *by the operator's own configuration* — there
        # is nothing to "bypass", so the probe stays silent rather than
        # flagging every public tool as an auth bypass. This kills the
        # dominant false positive: an intentionally-unauthenticated tool
        # (e.g. a fetch server) returning data on every call.
        self.auth_token_configured: bool = False

    def build_requests(self, surface: MCPSurfaceMap) -> list[ProbeRequest]:
        """For every tool, emit a paired (authed, unauthed) call.

        Argument values are picked to satisfy the schema without
        hitting other probe surfaces — e.g. URL params get a benign
        ``http://example.invalid/`` rather than an IMDS canary.

        The paired-call mechanism uses ``override_auth_token``:

          * ``None`` (default) → harness uses session's default auth.
            Probe ID suffix: ``withauth``.
          * ``""`` (empty string) → harness sends no Authorization
            header. Probe ID suffix: ``noauth``.
        """
        out: list[ProbeRequest] = []
        for tool in surface.tools:
            args = _benign_args(tool)
            # Skip tools we can't even invoke (no synthesisable args).
            if args is None:
                continue
            base_id = f"authbp-{tool.name}"[:80]
            out.append(
                ProbeRequest(
                    probe_id=f"{base_id}-{_AUTHED_SUFFIX}",
                    probe_class=self.probe_class,
                    tool_name=tool.name,
                    arguments=args,
                    override_auth_token=None,
                    note=f"auth-bypass paired call (authed) for {tool.name}",
                )
            )
            out.append(
                ProbeRequest(
                    probe_id=f"{base_id}-{_UNAUTHED_SUFFIX}",
                    probe_class=self.probe_class,
                    tool_name=tool.name,
                    arguments=args,
                    override_auth_token="",  # explicit no-auth
                    note=f"auth-bypass paired call (unauthed) for {tool.name}",
                )
            )
        return out

    def evaluate(
        self,
        surface: MCPSurfaceMap,
        responses: list[ProbeResponse],
        network_captures: list[dict],
    ) -> list[MCPFinding]:
        # No auth token configured → the operator has declared the
        # target unauthenticated; "bypass" is meaningless. Stay silent
        # to avoid flagging every public tool. (Re-run with
        # ``--auth token --auth-token ...`` to actually test enforcement.)
        if not self.auth_token_configured:
            return []

        my = [r for r in responses if r.probe_class == self.probe_class]
        if not my:
            return []

        # Group by tool — one finding per tool that bypasses auth.
        by_tool: dict[str, dict[str, ProbeResponse]] = {}
        for r in my:
            tool = r.tool_name
            if r.probe_id.endswith(_AUTHED_SUFFIX):
                by_tool.setdefault(tool, {})["authed"] = r
            elif r.probe_id.endswith(_UNAUTHED_SUFFIX):
                by_tool.setdefault(tool, {})["unauthed"] = r

        findings: list[MCPFinding] = []
        for tool, pair in by_tool.items():
            authed = pair.get("authed")
            unauthed = pair.get("unauthed")
            if unauthed is None:
                # Missing unauthed sample — can't diff.
                continue

            # ── confirmation: unauthed produced data AND mirrors authed ──
            unauthed_content = _content_text(unauthed)
            if not unauthed_content:
                continue  # server rejected — good

            authed_content = _content_text(authed) if authed else ""
            same_shape = _shape_overlap(authed_content, unauthed_content)

            # If we have both samples AND they look the same, this is
            # confirmed auth-bypass. If we only have the unauthed
            # sample (no default token configured), drop to heuristic.
            confirmed = bool(authed) and same_shape

            findings.append(
                _build_finding(
                    idx=len(findings) + 1,
                    surface=surface,
                    tool_name=tool,
                    authed=authed,
                    unauthed=unauthed,
                    confirmed=confirmed,
                )
            )
        return findings


# ── helpers ──────────────────────────────────────────────────────────


def _benign_args(tool: object) -> dict[str, object] | None:
    """Synthesise args that satisfy the tool's required schema
    without triggering SSRF / redirect / fail-open paths. Returns
    None if any required param is too exotic to synthesise (we'd
    rather skip than emit a misleading "auth bypass" finding rooted
    in a schema-validation refusal)."""
    from mcp_scanner.classifier import ParamClass
    from mcp_scanner.surface import MCPTool

    if not isinstance(tool, MCPTool):
        return None
    args: dict[str, object] = {}
    for p in tool.params:
        if not p.required:
            continue
        if p.param_class in (ParamClass.URL, ParamClass.HOST):
            args[p.name] = "http://example.invalid/argus-authbypass-probe"
        elif p.param_class == ParamClass.PATH:
            args[p.name] = "/tmp/argus-authbp"
        elif p.param_class == ParamClass.COMMAND:
            args[p.name] = "true"
        elif p.param_class == ParamClass.QUERY:
            args[p.name] = "1=1"
        elif p.param_class == ParamClass.INTEGER:
            args[p.name] = 1
        elif p.param_class == ParamClass.BOOLEAN:
            args[p.name] = False
        elif p.param_class == ParamClass.FUZZ:
            args[p.name] = "argus-test"
        elif p.param_class == ParamClass.UNKNOWN:
            # Skip tools whose schema we can't synthesise for —
            # would just produce a useless "schema validation error"
            # response.
            return None
        else:
            args[p.name] = "x"
    return args


def _content_text(r: ProbeResponse | None) -> str:
    """Concatenated text content from a tool result. Empty when the
    server JSON-RPC-errored or returned no text content."""
    if r is None:
        return ""
    if "error" in r.response:
        return ""
    result = r.response.get("result") or {}
    if not isinstance(result, dict):
        return ""
    if result.get("isError"):
        return ""
    content = result.get("content") or []
    parts: list[str] = []
    if isinstance(content, list):
        for c in content:
            if isinstance(c, dict) and isinstance(c.get("text"), str):
                parts.append(c["text"])
    return "".join(parts)


def _shape_overlap(authed: str, unauthed: str) -> bool:
    """True iff the two text bodies are similar enough that we treat
    them as the same "shape" of response.

    v1 uses a coarse Jaccard-on-tokens over the first 256 chars; that's
    enough to catch "identical JSON keys" without needing a real LLM
    diff. Refines in v1.13 when we have evidence on false-positive
    rates from real targets.
    """
    if not authed or not unauthed:
        # No authed sample — can't compute a real diff. The probe
        # evaluator handles this by dropping the confidence
        # (confirmed=False); _shape_overlap returns False so the
        # call-site logic stays simple.
        return False
    a_tokens = set(authed[:256].lower().split())
    u_tokens = set(unauthed[:256].lower().split())
    if not a_tokens or not u_tokens:
        return False
    inter = a_tokens & u_tokens
    union = a_tokens | u_tokens
    jaccard = len(inter) / len(union)
    return jaccard >= 0.5


def _build_finding(
    *,
    idx: int,
    surface: MCPSurfaceMap,
    tool_name: str,
    authed: ProbeResponse | None,
    unauthed: ProbeResponse,
    confirmed: bool,
) -> MCPFinding:
    cvss = cvss_estimate_for("auth_bypass", confirmed=confirmed)
    severity = severity_for(cvss)
    title_prefix = (
        "Confirmed authorization bypass"
        if confirmed
        else "Suspected authorization bypass"
    )
    title = f"{title_prefix}: {tool_name} returns data unauthenticated"
    authed_excerpt = _content_text(authed)[:200]
    unauthed_excerpt = _content_text(unauthed)[:200]
    response_text = f"unauthed: {unauthed_excerpt!r}"
    explanation = (
        f"Tool ``{tool_name}`` returned a non-error tool response when "
        f"invoked WITHOUT an Authorization header. "
        + (
            "The authed and unauthed responses overlap enough that the "
            "tool isn't enforcing authentication — this is a confirmed "
            "auth bypass. Compare the response excerpts above."
            if confirmed
            else "No authed comparison was available (operator didn't pass "
            "--auth-token), so the diff is one-sided. Re-run with "
            "--auth-token to confirm the bypass."
        )
    )
    fix = (
        "Validate the Authorization header at the handler entry point "
        "BEFORE any tool-specific logic runs. Return MCP error -32000 "
        "(or a tool-result with isError=true) when the token is "
        "missing / invalid. Don't make auth optional — make it the "
        "default and add an explicit ``public_tools`` allowlist if some "
        "tools legitimately don't require it."
    )
    repro = (
        f"$ argus mcp scan --stdio '<launch_cmd>' "
        f"--tools {tool_name} --authorized "
        f"--auth token --auth-token \"$REAL_TOKEN\""
    )
    return MCPFinding(
        id=f"F{idx:03d}",
        probe_class="auth_bypass",
        vuln_class="Authorization bypass",
        cwe="CWE-862",
        severity=severity,
        cvss_estimate=cvss,
        confirmed=confirmed,
        target_locus=f"tool:{tool_name}",
        target=surface.target,
        transport=surface.transport,
        payload=dict(unauthed.arguments),
        response_excerpt=response_text,
        network_evidence=[],
        authed_diff={
            "authed_excerpt": authed_excerpt,
            "unauthed_excerpt": unauthed_excerpt,
        },
        title=title,
        explanation=explanation,
        fix=fix,
        repro=repro,
    )


_INSTANCE = AuthBypassProbe()
register_probe(_INSTANCE)
