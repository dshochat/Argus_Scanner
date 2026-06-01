"""MCP surface map — typed view of what a server exposes.

The enumerator builds an ``MCPSurfaceMap`` and the scanner consumes
it. Probes fan out across ``map.tools`` (each with classified params),
``map.resources``, and ``map.prompts`` to decide what to attack.

Pydantic v2 throughout for cross-boundary validation + clean
serialisation to the report JSON.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ParamClass is used in Pydantic field types so it MUST be imported at
# runtime — Pydantic v2 resolves field annotations via get_type_hints
# during model construction. Suppressing TC001 (false positive for
# Pydantic models).
from mcp_scanner.classifier import ParamClass  # noqa: TC001


class MCPParam(BaseModel):
    """A single parameter slot on an MCP tool's input schema."""

    model_config = ConfigDict(extra="forbid")

    name: str
    param_class: ParamClass = Field(
        description="Classifier output — which payload family this param attracts."
    )
    required: bool = False
    json_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw JSON Schema for the parameter (kept as dict so callers"
        " can render evidence without re-deriving).",
    )


class MCPTool(BaseModel):
    """One callable tool the server exposes."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    params: list[MCPParam] = Field(default_factory=list)
    raw_input_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="Full ``inputSchema`` as returned by tools/list."
        " Persisted verbatim so the probe layer can build syntactically"
        " valid call payloads even for nested object params.",
    )


class MCPResource(BaseModel):
    """One resource the server exposes via ``resources/list``."""

    model_config = ConfigDict(extra="forbid")

    uri: str
    name: str = ""
    description: str = ""
    mime_type: str | None = None


class MCPPrompt(BaseModel):
    """One prompt the server exposes via ``prompts/list``."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = Field(default_factory=list)


class MCPSurfaceMap(BaseModel):
    """Everything an MCP server exposes, plus metadata from the
    initialize handshake.

    This is the contract between ``argus mcp enumerate`` (which writes
    it) and ``argus mcp scan`` (which reads it). Serialises to JSON
    cleanly via ``model_dump_json``.
    """

    model_config = ConfigDict(extra="forbid")

    target: str = Field(
        description="The user-supplied target — URL or stdio command."
    )
    transport: str = Field(
        description="One of: stdio | http | sse | streamable-http."
    )
    protocol_version: str = Field(
        default="",
        description="Server-reported protocolVersion from the initialize response.",
    )
    server_info: dict[str, Any] = Field(
        default_factory=dict,
        description="serverInfo block from initialize: usually {name, version}.",
    )
    capabilities: dict[str, Any] = Field(
        default_factory=dict,
        description="Server capabilities block from initialize. Used to decide"
        " which discovery methods to call (e.g. don't request prompts/list"
        " if capabilities.prompts is absent).",
    )
    tools: list[MCPTool] = Field(default_factory=list)
    resources: list[MCPResource] = Field(default_factory=list)
    prompts: list[MCPPrompt] = Field(default_factory=list)
    discovery_errors: list[str] = Field(
        default_factory=list,
        description="Per-method errors from the enumeration pass — non-fatal."
        " E.g. ``prompts/list`` may 404 on minimal servers; we record it"
        " rather than abort. The scan path skips probe classes that have no"
        " surface to attack.",
    )

    def param_summary(self) -> dict[str, int]:
        """Counts of param classes across all tools.

        Used by the report layer + the operator to gauge attack surface
        at a glance ("12 URL params, 3 PATH params, 4 QUERY params"…).
        """
        counts: dict[str, int] = {}
        for tool in self.tools:
            for p in tool.params:
                counts[p.param_class.value] = counts.get(p.param_class.value, 0) + 1
        return counts
