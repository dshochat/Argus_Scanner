"""Fail-open probe — CWE-755 (improper exception handling) +
CWE-693 (protection mechanism bypass).

Strategy: drive the server's validation paths into error states and
see whether the protection (URL allowlist, scheme check, auth check)
silently bypasses on the exception.

Three failure modes per eligible tool param:

  1. Malformed input the validator can't even parse — e.g. a URL
     containing raw null bytes / control chars, or a string that's
     pretending to be the right type (``" "`` for required URL).
  2. Boundary-condition payloads (empty string, oversized string)
     that trip pre-validator string-length checks.
  3. Wrong-type payloads (sending an integer where a URL is required).
     Most servers JSON-RPC-error on schema validation, but some
     pass through to the handler which then mis-coerces.

Evidence: fail-open is CONFIRMED when:
  * The probe drove validation into an error state (we know because
    we crafted the payload to be unparseable / out-of-bounds), AND
  * The server STILL produced a tool response that includes ANY of
    the SSRF / sensitive payload outcomes (a non-error content body
    that mentions external host attempts, a 200 OK with content,
    etc.), OR a network capture landed despite the validation
    boundary.

Less ambiguous proof requires Step 6's OOB listener to confirm the
server attempted an outbound fetch after the validator should have
blocked. v1's probe lights up the suspicion and the report flags it.
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
class _FailOpenPayload:
    """One adversarial input + the kind of validator path it tries
    to drive into an exception."""

    name: str
    value: object
    description: str


# Unique path stamped on the confusion payloads so a resulting network
# capture is attributable to THIS probe (no other probe uses this path)
# — that's what lets us confirm a bypass without contaminating off the
# SSRF / redirect probes' captures.
_FO_BYPASS_PATH = "/argus-fo-bypass"

# Hosts that mean "the bypass reached internal space".
_INTERNAL_HOSTS: tuple[str, ...] = (
    "metadata.google.internal",
    "169.254.169.254",
    "127.0.0.1",
    "localhost",
)

# Payloads split into two intents:
#   * CONFIRMING (userinfo/parser confusion): the URL LOOKS external
#     (allowed.example) but its effective host is INTERNAL. A naive
#     host-allowlist that trusts the apparent host fails open. If the
#     server fetches the internal host (attributed capture on
#     _FO_BYPASS_PATH), that's a confirmed bypass.
#   * PROBING (malformed/garbage): drive parsers into exception paths;
#     a non-error response is a heuristic "validator absent / swallowed".
_PAYLOADS_FOR_URL: tuple[_FailOpenPayload, ...] = (
    _FailOpenPayload(
        name="userinfo_confusion",
        value=f"http://allowed.example@metadata.google.internal{_FO_BYPASS_PATH}",
        description="userinfo-confusion URL — looks like allowed.example, "
        "resolves to the internal metadata host (host-allowlist bypass)",
    ),
    _FailOpenPayload(
        name="null_bytes",
        value="http://example.com/\x00.\x00internal",
        description="URL with embedded NUL bytes (validators usually raise)",
    ),
    _FailOpenPayload(
        name="oversize",
        value="http://" + ("a" * 8192) + ".example/",
        description="oversize URL (~8 KiB) to trip length guards",
    ),
    _FailOpenPayload(
        name="empty",
        value="",
        description="empty string (startswith() check should reject)",
    ),
    _FailOpenPayload(
        name="not_a_url",
        value=">>>not-a-url-at-all<<<",
        description="garbage that can't be parsed as a URL",
    ),
    _FailOpenPayload(
        name="wrong_type_int",
        # JSON-RPC will likely refuse this at schema validation, but
        # some servers coerce silently — and that's the fail-open we
        # want to catch.
        value=42,
        description="wrong type (int) where URL string was required",
    ),
)


class FailOpenProbe:
    """Validator-bypass / fail-open probe."""

    probe_class: str = "fail_open"

    def build_requests(self, surface: MCPSurfaceMap) -> list[ProbeRequest]:
        """Fire payload set across URL/HOST params on every tool.

        Path / Command / Query params have their own validator
        idioms; v1 limits fail-open testing to network-shaped params
        because that's where the SSRF-validation-bypass risk lives.
        """
        out: list[ProbeRequest] = []
        for tool in surface.tools:
            for param in tool.params:
                if param.param_class not in (ParamClass.URL, ParamClass.HOST):
                    continue
                for payload in _PAYLOADS_FOR_URL:
                    probe_id = (
                        f"failopen-{tool.name}-{param.name}-{payload.name}"[:96]
                    )
                    out.append(
                        ProbeRequest(
                            probe_id=probe_id,
                            probe_class=self.probe_class,
                            tool_name=tool.name,
                            arguments=_args_with_payload(tool, param.name, payload.value),
                            note=f"fail-open: {payload.description}",
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
            pname = _extract_param_name(r)
            grouped.setdefault((r.tool_name, pname), []).append(r)

        for (tool_name, param_name), rs in grouped.items():
            # Confirmation: the userinfo-confusion payload reached an
            # INTERNAL host on our unique bypass path. The path
            # (_FO_BYPASS_PATH) is requested by NOTHING else, so the
            # capture is unambiguously attributable to this probe — it
            # can't be contaminated by the SSRF / redirect probes'
            # captures (the false-positive bug this replaced).
            confirmed_hit: tuple[ProbeResponse, dict] | None = None
            bypass_cap = next(
                (c for c in network_captures if _capture_attests_internal_bypass(c)),
                None,
            )
            if bypass_cap is not None:
                attributed = next(
                    (rr for rr in rs if _FO_BYPASS_PATH in str(rr.arguments)),
                    None,
                )
                if attributed is not None:
                    confirmed_hit = (attributed, bypass_cap)

            if confirmed_hit is not None:
                r, cap = confirmed_hit
                findings.append(
                    _build_finding(
                        idx=len(findings) + 1,
                        surface=surface,
                        tool_name=tool_name,
                        param_name=param_name,
                        response=r,
                        capture=cap,
                        confirmed=True,
                    )
                )
                continue

            # Heuristic: server returned 200 OK content for an input
            # that's clearly malformed. That's evidence the validator
            # was bypassed (or never ran). The exception we track is:
            #   * isError = False AND no JSON-RPC error
            #   * content has non-error text content
            # Skipping when the server JSON-RPC-errored, since that's
            # PROPER rejection.
            heuristic = _pick_heuristic_response(rs)
            if heuristic is not None:
                findings.append(
                    _build_finding(
                        idx=len(findings) + 1,
                        surface=surface,
                        tool_name=tool_name,
                        param_name=param_name,
                        response=heuristic,
                        capture={},
                        confirmed=False,
                    )
                )

        return findings


# ── helpers ──────────────────────────────────────────────────────────


def _args_with_payload(tool: object, param_name: str, payload: object) -> dict[str, object]:
    """Fill ``param_name`` with ``payload`` and supply defaults for
    other required params. Mirrors the SSRF probe's args helper but
    accepts non-string payloads (the wrong-type test cases)."""
    from mcp_scanner.surface import MCPTool

    if not isinstance(tool, MCPTool):
        return {param_name: payload}
    args: dict[str, object] = {}
    for p in tool.params:
        if p.name == param_name:
            args[p.name] = payload
            continue
        if p.required:
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


def _capture_attests_internal_bypass(cap: dict) -> bool:
    """True iff a capture proves a fail-open confusion payload reached
    internal space: it must be on THIS probe's unique bypass path AND
    target an internal host. The unique path is the attribution key —
    no other probe requests it, so this can't be contaminated by the
    SSRF / redirect probes' captures (the FP this replaced).
    """
    host = (cap.get("host") or "").lower()
    path = cap.get("path") or ""
    if _FO_BYPASS_PATH not in path:
        return False
    return any(h in host for h in _INTERNAL_HOSTS)


def _pick_heuristic_response(rs: list[ProbeResponse]) -> ProbeResponse | None:
    """A non-error 200 with content text for a malformed input. The
    server's validator either ran and returned silently, or never ran.
    """
    for r in rs:
        if r.is_error:
            continue
        if "error" in r.response:
            continue
        content = (r.response.get("result") or {}).get("content") or []
        for c in content:
            if isinstance(c, dict) and c.get("text"):
                return r
    return None


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
    confirmed: bool,
) -> MCPFinding:
    cvss = cvss_estimate_for("fail_open", confirmed=confirmed)
    severity = severity_for(cvss)
    title_prefix = "Confirmed fail-open" if confirmed else "Suspected fail-open"
    title = f"{title_prefix}: {tool_name}({param_name}) validator bypass"
    response_text = _response_excerpt(response)
    explanation = (
        f"Tool ``{tool_name}`` accepts a URL via ``{param_name}``. Argus "
        f"supplied a payload designed to drive the validator into an "
        f"exception path (note: ``{response.note}``). "
        + (
            "The URL's apparent host is external (``allowed.example``) but "
            "its EFFECTIVE host (via userinfo confusion) is the internal "
            "metadata service. The capture-server observed the server "
            "fetching that internal host on Argus's unique bypass path — "
            "confirmed: a host-allowlist that trusts the apparent host is "
            "bypassed and the request reaches internal space."
            if confirmed
            else "The server returned a non-error tool result for the "
            "malformed input, suggesting the validator either never ran or "
            "swallowed the exception and fell through to the unrestricted "
            "fetch path. Recommend confirming with the OOB listener."
        )
    )
    fix = (
        "Validate BEFORE the try/except so any exception leaves the "
        "function via the same error path the validator owns. Use an "
        "allowlist-based check (urllib.parse + idna.decode + ipaddress) "
        "with explicit reject-on-error semantics. Avoid bare ``except "
        "Exception:`` around the validation block."
    )
    repro = (
        f"$ argus mcp scan --stdio '<launch_cmd>' "
        f"--tools {tool_name} --authorized"
    )
    return MCPFinding(
        id=f"F{idx:03d}",
        probe_class="fail_open",
        vuln_class="Fail-open validation",
        cwe="CWE-755",
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


_INSTANCE = FailOpenProbe()
register_probe(_INSTANCE)
