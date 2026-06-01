"""End-to-end MCP enumerate test against the fixture vulnerable server.

Spawns ``tests/fixtures/mcp/vulnerable_server.py`` as a real
subprocess and drives ``argus mcp enumerate --stdio ...`` through the
public CLI entry point. Validates:

  * Handshake completes (protocolVersion + serverInfo round-trip).
  * All 5 fixture tools surface with correct param classification:
      - ``fetch_url`` / ``read_url_with_redirects`` / ``safe_fetch``
        → ``url`` param classified as URL.
      - ``admin_lookup`` → ``user_id`` param classified as FUZZ.
      - ``echo`` → ``text`` param classified as FUZZ.
  * The output JSON parses back into ``MCPSurfaceMap`` cleanly.
  * Markdown report renders without crashing.

No external services, no API keys — fully hermetic. Marked
@pytest.mark.integration per ``tests/CLAUDE.md`` convention because it
spawns a subprocess (slower than pure-in-memory unit tests).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_scanner.classifier import ParamClass
from mcp_scanner.surface import MCPSurfaceMap

pytestmark = pytest.mark.integration


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_SERVER = REPO_ROOT / "tests" / "fixtures" / "mcp" / "vulnerable_server.py"


def _argus_cmd(*extra: str) -> list[str]:
    """Build the ``argus`` invocation. We go through ``python -m`` so
    the test doesn't depend on the entry-point script being on PATH."""
    return [sys.executable, "-m", "scanner.cli", *extra]


def test_enumerate_against_fixture_server_returns_full_surface_map(
    tmp_path: Path,
) -> None:
    """Live e2e: spawn the fixture, drive enumerate, parse the result."""
    out_file = tmp_path / "surface.json"
    result = subprocess.run(
        _argus_cmd(
            "mcp", "enumerate",
            "--stdio", f"{sys.executable} {FIXTURE_SERVER}",
            "--output-file", str(out_file),
        ),
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, (
        f"argus mcp enumerate exited {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert out_file.is_file(), "expected --output-file to be written"
    payload = json.loads(out_file.read_text(encoding="utf-8"))

    # The CLI's output should round-trip cleanly into the typed model.
    surface = MCPSurfaceMap.model_validate(payload)

    # ── handshake ──
    assert surface.transport == "stdio"
    assert surface.protocol_version == "2025-03-26"
    assert surface.server_info.get("name") == "argus-fixture-vuln-server"

    # ── all 5 fixture tools surfaced ──
    tool_names = {t.name for t in surface.tools}
    assert tool_names == {
        "fetch_url",
        "read_url_with_redirects",
        "safe_fetch",
        "admin_lookup",
        "echo",
    }

    # ── param classification correct on each tool ──
    tool_by_name = {t.name: t for t in surface.tools}

    for fetch_name in ("fetch_url", "read_url_with_redirects", "safe_fetch"):
        tool = tool_by_name[fetch_name]
        assert len(tool.params) == 1
        p = tool.params[0]
        assert p.name == "url"
        assert p.param_class == ParamClass.URL, (
            f"{fetch_name}.url must classify as URL; got {p.param_class}"
        )
        assert p.required is True

    admin = tool_by_name["admin_lookup"]
    assert len(admin.params) == 1
    assert admin.params[0].name == "user_id"
    # ``user_id`` doesn't match a URL/HOST/PATH/COMMAND/QUERY keyword,
    # so it falls through to the FUZZ generic-string class.
    assert admin.params[0].param_class == ParamClass.FUZZ

    echo = tool_by_name["echo"]
    assert echo.params[0].name == "text"
    assert echo.params[0].param_class == ParamClass.FUZZ

    # ── discovery side-effects clean ──
    # The fixture implements resources/list + prompts/list (both empty)
    # so there should be no discovery errors.
    assert surface.discovery_errors == []
    assert surface.resources == []
    assert surface.prompts == []

    # ── attack-surface summary aggregates correctly ──
    summary = surface.param_summary()
    # 3x URL (fetch_url, read_url_with_redirects, safe_fetch)
    # 2x FUZZ (admin_lookup.user_id, echo.text)
    assert summary == {"url": 3, "fuzz": 2}


def test_enumerate_md_report_renders_without_crash(tmp_path: Path) -> None:
    """Same fixture, ``--report md``. The Markdown output should
    include the tool names + param table + attack-surface summary."""
    out_file = tmp_path / "surface.md"
    result = subprocess.run(
        _argus_cmd(
            "mcp", "enumerate",
            "--stdio", f"{sys.executable} {FIXTURE_SERVER}",
            "--report", "md",
            "--output-file", str(out_file),
        ),
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, (
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    md = out_file.read_text(encoding="utf-8")
    assert "# Argus MCP — Surface Map" in md
    assert "fetch_url" in md
    assert "admin_lookup" in md
    assert "## Attack-surface summary" in md
    assert "- **url**: 3" in md


def test_enumerate_to_stdout_when_no_output_file() -> None:
    """Without ``--output-file``, the JSON surface map writes to stdout."""
    result = subprocess.run(
        _argus_cmd(
            "mcp", "enumerate",
            "--stdio", f"{sys.executable} {FIXTURE_SERVER}",
        ),
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    payload = json.loads(result.stdout)
    assert payload["target"].endswith("vulnerable_server.py")
    assert len(payload["tools"]) == 5


def test_enumerate_bad_command_returns_nonzero_with_clear_error() -> None:
    """A nonexistent binary should produce exit code != 0 and a
    helpful stderr message (not a stack trace)."""
    result = subprocess.run(
        _argus_cmd(
            "mcp", "enumerate",
            "--stdio", "this-binary-does-not-exist-anywhere-9999",
        ),
        capture_output=True,
        text=True,
        timeout=10,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode != 0
    assert "error" in result.stderr.lower()
    # Should NOT print a Python traceback to the user.
    assert "Traceback (most recent call last)" not in result.stderr
