"""Unit tests for mcp_scanner.surface.

Surface map is the contract between enumerate and scan; this file
pins its shape (Pydantic v2 validation, serialisation round-trips,
param_summary helper).
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from mcp_scanner.classifier import ParamClass
from mcp_scanner.surface import (
    MCPParam,
    MCPPrompt,
    MCPResource,
    MCPSurfaceMap,
    MCPTool,
)


def test_mcp_param_basic_shape() -> None:
    p = MCPParam(name="url", param_class=ParamClass.URL, required=True)
    assert p.name == "url"
    assert p.param_class == ParamClass.URL
    assert p.required is True
    assert p.json_schema == {}


def test_mcp_param_extra_field_forbidden() -> None:
    """Extra fields must be rejected — we don't want silently-ignored
    typos polluting the surface map."""
    with pytest.raises(ValidationError):
        MCPParam(name="url", param_class=ParamClass.URL, totally_invalid="x")  # type: ignore[call-arg]


def test_mcp_tool_with_params() -> None:
    t = MCPTool(
        name="fetch_url",
        description="naive fetch",
        params=[
            MCPParam(name="url", param_class=ParamClass.URL, required=True),
            MCPParam(name="timeout", param_class=ParamClass.INTEGER),
        ],
        raw_input_schema={"type": "object"},
    )
    assert t.name == "fetch_url"
    assert len(t.params) == 2


def test_mcp_resource_optional_mime_type() -> None:
    r = MCPResource(uri="file:///tmp/data.txt", name="data")
    assert r.mime_type is None


def test_mcp_prompt_default_args_empty() -> None:
    p = MCPPrompt(name="summarise")
    assert p.arguments == []


# ── full surface map ──────────────────────────────────────────────────


def _sample_surface() -> MCPSurfaceMap:
    return MCPSurfaceMap(
        target="stdio: uvx some-server",
        transport="stdio",
        protocol_version="2025-03-26",
        server_info={"name": "vuln-server", "version": "0.1"},
        capabilities={"tools": {}, "resources": {}},
        tools=[
            MCPTool(
                name="fetch_url",
                description="naive fetch",
                params=[
                    MCPParam(name="url", param_class=ParamClass.URL, required=True),
                    MCPParam(name="timeout", param_class=ParamClass.INTEGER),
                ],
            ),
            MCPTool(
                name="read_file",
                description="reads a file",
                params=[
                    MCPParam(name="path", param_class=ParamClass.PATH, required=True),
                ],
            ),
        ],
        resources=[MCPResource(uri="file:///tmp/data.txt")],
        prompts=[MCPPrompt(name="summarise")],
        discovery_errors=[],
    )


def test_param_summary_counts_param_classes() -> None:
    surface = _sample_surface()
    summary = surface.param_summary()
    # Two URL? No — one URL, one INTEGER, one PATH.
    assert summary == {"url": 1, "integer": 1, "path": 1}


def test_param_summary_empty_when_no_tools() -> None:
    surface = MCPSurfaceMap(target="x", transport="stdio")
    assert surface.param_summary() == {}


def test_surface_map_json_round_trip() -> None:
    """The report layer dumps the map to JSON; the scanner reads it
    back. Round-trip must preserve every typed field including the
    ParamClass enum values."""
    surface = _sample_surface()
    text = surface.model_dump_json()
    parsed = json.loads(text)
    assert parsed["target"] == "stdio: uvx some-server"
    assert parsed["tools"][0]["params"][0]["param_class"] == "url"

    rebuilt = MCPSurfaceMap.model_validate_json(text)
    assert rebuilt.target == surface.target
    assert rebuilt.tools[0].params[0].param_class == ParamClass.URL
    assert rebuilt.tools[1].params[0].param_class == ParamClass.PATH


def test_surface_map_records_discovery_errors() -> None:
    surface = MCPSurfaceMap(
        target="x",
        transport="http",
        discovery_errors=["prompts/list: TimeoutError"],
    )
    assert len(surface.discovery_errors) == 1


def test_surface_map_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        MCPSurfaceMap(target="x", transport="stdio", bogus_field="y")  # type: ignore[call-arg]
