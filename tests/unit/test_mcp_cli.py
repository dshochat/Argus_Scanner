"""Unit tests for the ``argus mcp enumerate`` / ``argus mcp scan``
argparse plumbing + the handler logic that doesn't need a live server.

End-to-end testing against the fixture server lives in
``tests/integration/test_mcp_enumerate_e2e.py`` — that one's
@pytest.mark.integration because it actually spawns subprocesses.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from mcp_scanner.classifier import ParamClass
from mcp_scanner.cli import (
    _build_transport,
    _format_surface_markdown,
    _infer_transport,
)
from mcp_scanner.surface import MCPParam, MCPSurfaceMap, MCPTool
from mcp_scanner.transport.http import HttpTransport
from mcp_scanner.transport.stdio import StdioTransport
from scanner import cli

# ── argparse plumbing — parses cleanly + every-subparser-help passes ─


def test_mcp_subparser_exists_in_main_parser() -> None:
    """``argus mcp enumerate --url ...`` parses into a valid Namespace."""
    parser = cli._build_parser()
    args = parser.parse_args(
        ["mcp", "enumerate", "--url", "https://example.test/mcp"]
    )
    assert args.command == "mcp"
    assert args.mcp_command == "enumerate"
    assert args.url == "https://example.test/mcp"
    assert args.stdio is None


def test_mcp_enumerate_with_stdio() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        ["mcp", "enumerate", "--stdio", "python -m fake_server"]
    )
    assert args.stdio == "python -m fake_server"
    assert args.url is None


def test_mcp_enumerate_requires_url_or_stdio() -> None:
    """argparse's mutually-exclusive group with ``required=True`` should
    refuse a bare ``argus mcp enumerate`` call."""
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["mcp", "enumerate"])


def test_mcp_enumerate_url_and_stdio_mutually_exclusive() -> None:
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["mcp", "enumerate", "--url", "https://x", "--stdio", "y"]
        )


def test_mcp_scan_adds_authorized_flag() -> None:
    """The scan subcommand carries the active-attack consent gate;
    enumerate does not."""
    parser = cli._build_parser()
    scan_args = parser.parse_args(
        ["mcp", "scan", "--url", "https://example.test/mcp", "--authorized"]
    )
    assert scan_args.authorized is True
    # The enumerate subparser must NOT define --authorized.
    enum_args = parser.parse_args(
        ["mcp", "enumerate", "--url", "https://example.test/mcp"]
    )
    assert not hasattr(enum_args, "authorized")


def test_mcp_scan_scope_deny_repeatable() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "mcp", "scan",
            "--url", "https://x",
            "--authorized",
            "--scope-deny", "10.0.0.0/8",
            "--scope-deny", "192.168.0.0/16",
        ]
    )
    assert args.scope_deny == ["10.0.0.0/8", "192.168.0.0/16"]


def test_mcp_auth_token_threaded_through() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "mcp", "enumerate",
            "--url", "https://x",
            "--auth", "token",
            "--auth-token", "secret",
        ]
    )
    assert args.auth == "token"
    assert args.auth_token == "secret"


def test_mcp_report_default_json() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(["mcp", "enumerate", "--stdio", "x"])
    assert args.report == "json"


def test_mcp_report_md_accepted() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        ["mcp", "enumerate", "--stdio", "x", "--report", "md"]
    )
    assert args.report == "md"


def test_every_mcp_subparser_help_renders_cleanly() -> None:
    """``--help`` on each MCP subparser must not crash. Catches the
    same class of bug the existing scan / scan-repo / install
    regression test catches (unescaped ``%`` in help strings)."""
    parser = cli._build_parser()
    # Walk down: main → mcp → {enumerate, scan}.
    for action in parser._actions:
        if hasattr(action, "choices") and isinstance(action.choices, dict):
            for sub_name, sub_parser in action.choices.items():
                if sub_name != "mcp":
                    continue
                sub_parser.format_help()
                for sub_action in sub_parser._actions:
                    if hasattr(sub_action, "choices") and isinstance(
                        sub_action.choices, dict
                    ):
                        for ssn, ssp in sub_action.choices.items():
                            ssp.format_help()
                            for a in ssp._actions:
                                if a.help:
                                    try:
                                        _ = a.help % {}
                                    except (TypeError, ValueError, KeyError) as e:
                                        opts = "|".join(a.option_strings) or a.dest
                                        raise AssertionError(
                                            f"help for ``mcp {ssn} {opts}`` "
                                            f"failed %-formatting "
                                            f"({type(e).__name__}: {e})"
                                        ) from e


# ── _infer_transport ────────────────────────────────────────────────


def _ns(**kwargs: object) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


def test_infer_transport_stdio() -> None:
    args = _ns(url=None, stdio="python -m srv", transport=None)
    assert _infer_transport(args) == ("stdio", "python -m srv")


def test_infer_transport_url_defaults_to_streamable_http() -> None:
    args = _ns(url="https://x/mcp", stdio=None, transport=None)
    assert _infer_transport(args) == ("streamable-http", "https://x/mcp")


def test_infer_transport_url_explicit_sse() -> None:
    args = _ns(url="https://x/mcp", stdio=None, transport="sse")
    assert _infer_transport(args) == ("sse", "https://x/mcp")


def test_infer_transport_both_set_raises(capsys: pytest.CaptureFixture[str]) -> None:
    args = _ns(url="https://x", stdio="y", transport=None)
    with pytest.raises(SystemExit) as exc:
        _infer_transport(args)
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "mutually exclusive" in err


def test_infer_transport_neither_set_raises(capsys: pytest.CaptureFixture[str]) -> None:
    args = _ns(url=None, stdio=None, transport=None)
    with pytest.raises(SystemExit) as exc:
        _infer_transport(args)
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "required" in err


def test_infer_transport_invalid_transport_for_url_raises(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = _ns(url="https://x", stdio=None, transport="ws")
    with pytest.raises(SystemExit):
        _infer_transport(args)
    err = capsys.readouterr().err
    assert "http|sse|streamable-http" in err


# ── _build_transport ────────────────────────────────────────────────


def test_build_transport_stdio_returns_stdio_transport() -> None:
    args = _ns(auth="none", auth_token=None)
    t = _build_transport("stdio", f"{sys.executable} -c 'pass'", args)
    assert isinstance(t, StdioTransport)


def test_build_transport_http_returns_http_transport() -> None:
    args = _ns(auth="none", auth_token=None)
    t = _build_transport("streamable-http", "https://x", args)
    assert isinstance(t, HttpTransport)


def test_build_transport_token_requires_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = _ns(auth="token", auth_token=None)
    with pytest.raises(SystemExit) as exc:
        _build_transport("streamable-http", "https://x", args)
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "--auth-token" in err


def test_build_transport_token_propagated_to_http() -> None:
    args = _ns(auth="token", auth_token="secret-abc")
    t = _build_transport("streamable-http", "https://x", args)
    assert isinstance(t, HttpTransport)
    # Probe the private (_) field — we don't want to expose the token
    # via a public property, but the test needs to verify wire shape.
    assert t._auth_token == "secret-abc"  # noqa: SLF001


def test_build_transport_invalid_auth_mode_raises(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = _ns(auth="basic", auth_token=None)
    with pytest.raises(SystemExit):
        _build_transport("streamable-http", "https://x", args)
    err = capsys.readouterr().err
    assert "none|token" in err


# ── _format_surface_markdown ─────────────────────────────────────────


def test_format_markdown_renders_target_and_transport() -> None:
    s = MCPSurfaceMap(target="stdio: uvx vuln-server", transport="stdio")
    md = _format_surface_markdown(s)
    assert "stdio: uvx vuln-server" in md
    assert "**Transport:** `stdio`" in md
    assert "_no tools advertised_" in md


def test_format_markdown_renders_tool_param_table() -> None:
    s = MCPSurfaceMap(
        target="x",
        transport="http",
        protocol_version="2025-03-26",
        server_info={"name": "vuln-server", "version": "0.1"},
        tools=[
            MCPTool(
                name="fetch_url",
                description="Fetch a URL",
                params=[
                    MCPParam(name="url", param_class=ParamClass.URL, required=True),
                    MCPParam(name="timeout", param_class=ParamClass.INTEGER),
                ],
            )
        ],
    )
    md = _format_surface_markdown(s)
    assert "### `fetch_url`" in md
    assert "Fetch a URL" in md
    assert "| `url` | `url` | ✓ |" in md
    assert "| `timeout` | `integer` |  |" in md
    assert "## Attack-surface summary" in md
    assert "- **url**: 1" in md


def test_format_markdown_shows_discovery_errors_when_present() -> None:
    s = MCPSurfaceMap(
        target="x",
        transport="http",
        discovery_errors=["prompts/list: TimeoutError"],
    )
    md = _format_surface_markdown(s)
    assert "## Discovery errors" in md
    assert "prompts/list: TimeoutError" in md


def test_format_markdown_skips_discovery_errors_when_empty() -> None:
    s = MCPSurfaceMap(target="x", transport="http")
    md = _format_surface_markdown(s)
    assert "Discovery errors" not in md


def test_format_markdown_includes_resources_and_prompts() -> None:
    from mcp_scanner.surface import MCPPrompt, MCPResource

    s = MCPSurfaceMap(
        target="x",
        transport="http",
        resources=[
            MCPResource(uri="file:///tmp/x", name="scratch", mime_type="text/plain")
        ],
        prompts=[MCPPrompt(name="summarise", description="Summarise something")],
    )
    md = _format_surface_markdown(s)
    assert "## Resources (1)" in md
    assert "file:///tmp/x" in md
    assert "## Prompts (1)" in md
    assert "summarise" in md


def test_format_markdown_round_trip_no_crash_on_empty_map() -> None:
    """A server that exposes nothing should still produce a renderable
    surface map."""
    s = MCPSurfaceMap(target="x", transport="stdio")
    md = _format_surface_markdown(s)
    assert "_no tools advertised_" in md
    assert "_no resources advertised_" in md
    assert "_no prompts advertised_" in md


# ── output-file plumbing ─────────────────────────────────────────────


def test_mcp_output_file_flag_accepts_path(tmp_path: Path) -> None:
    parser = cli._build_parser()
    out = tmp_path / "surface.json"
    args = parser.parse_args(
        ["mcp", "enumerate", "--stdio", "x", "--output-file", str(out)]
    )
    assert args.output_file == out
