"""Argus MCP scanning mode (v1.12).

Dynamic security testing for Model Context Protocol servers. Speaks
MCP over stdio (sandboxed) and streamable-HTTP / SSE (remote).
Reuses the existing DAST sandbox, SSRF payload catalog, CWE→probe
registry, and findings schema — this package is a self-contained
plug-in, not a re-implementation.

Entry points:

  * ``argus mcp enumerate <target>`` — recon only: handshake, list
    tools/resources/prompts, classify params, emit surface map.
  * ``argus mcp scan <target>`` — run the probe catalog (SSRF,
    redirect, fail-open, auth-bypass) against the enumerated surface.

Safety:

  * Stdio servers ALWAYS execute inside the Firecracker sandbox
    (``dast.sandbox.client``) with controlled egress — SSRF probes
    hit the in-sandbox capture-server, never real infrastructure.
  * Remote targets refuse to scan without ``--authorized``.
  * ``--scope-deny <cidr>`` (repeatable) filters outbound probe URLs.

Out of scope for v1 (clean extension points left intact):

  * Prompt-injection / LLM testing
  * Static MCP code analysis
  * Continuous monitoring / polling
  * Advisory auto-generation

See ``docs/mcp.md`` for the operator guide.
"""

from __future__ import annotations

#: MCP protocol version Argus speaks during the ``initialize``
#: handshake. Matches the public spec revision Argus was built and
#: tested against. The server is free to respond with any version it
#: supports; Argus falls back to the server-reported version.
MCP_PROTOCOL_VERSION: str = "2025-03-26"
