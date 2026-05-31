"""Unit tests for dast.infra_telemetry (v1.6 Fix #10).

Verifies error categorization + JSONL log format. Uses tmp_path for
log writes so tests never touch the real .argus_local/infra_gaps.jsonl.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dast.infra_telemetry import categorize_error, log_infra_gap

# ── categorize_error ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "error_message, expected_category, expected_tool",
    [
        # Shell command not found
        (
            "/bin/sh: 1: npm: not found",
            "missing_binary",
            "npm",
        ),
        (
            "command not found: docker",
            "missing_binary",
            "docker",
        ),
        # Python missing module
        (
            "ModuleNotFoundError: No module named 'pickle5'",
            "missing_python_pkg",
            "pickle5",
        ),
        (
            "ImportError: No module named yaml",
            "missing_python_pkg",
            "yaml",
        ),
        # Node missing module
        (
            "Error: Cannot find module 'express'",
            "missing_node_pkg",
            "express",
        ),
        (
            "Error: Cannot find module '@scope/pkg'",
            "missing_node_pkg",
            "@scope/pkg",
        ),
        # Network (minimal image has no egress)
        (
            "ConnectionError: Connection refused",
            "network_blocked",
            None,
        ),
        (
            "socket.gaierror: [Errno -3] Temporary failure in name resolution",
            "network_blocked",
            None,
        ),
        (
            "curl: (6) Could not resolve host: api.example.com",
            "network_blocked",
            None,
        ),
        # Unknown patterns fall to "other"
        (
            "Some completely unrelated traceback from the harness",
            "other",
            None,
        ),
        # Empty / malformed input
        ("", "other", None),
    ],
)
def test_categorize_error_pattern_matching(
    error_message: str,
    expected_category: str,
    expected_tool: str | None,
) -> None:
    """Each error pattern should map to the right category + extract
    the missing tool when applicable."""
    category, tool = categorize_error(error_message)
    assert category == expected_category, f"category mismatch for {error_message!r}: got {category}"
    assert tool == expected_tool, f"tool mismatch for {error_message!r}: got {tool}"


def test_categorize_error_handles_non_string() -> None:
    """Defensive: non-string input doesn't crash."""
    assert categorize_error(None) == ("other", None)  # type: ignore[arg-type]
    assert categorize_error(123) == ("other", None)  # type: ignore[arg-type]


# ── log_infra_gap ──────────────────────────────────────────────────────────


def test_log_infra_gap_writes_jsonl_entry(tmp_path: Path) -> None:
    """A single call writes one valid JSON line to the configured path."""
    log_path = tmp_path / "infra_gaps.jsonl"
    ok = log_infra_gap(
        file_name="suspicious_file.py",
        phase="phase_3_loop",
        error_message="ModuleNotFoundError: No module named 'pickle5'",
        finding_cwe="CWE-502",
        image_hint="lean",
        log_path=log_path,
    )
    assert ok is True
    assert log_path.exists()

    lines = log_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["file_name"] == "suspicious_file.py"
    assert entry["phase"] == "phase_3_loop"
    assert entry["finding_cwe"] == "CWE-502"
    assert entry["image_hint"] == "lean"
    assert entry["error_category"] == "missing_python_pkg"
    assert entry["missing_tool"] == "pickle5"
    assert "pickle5" in entry["error_excerpt"]
    # timestamp should be ISO 8601 with Z suffix or +00:00
    assert entry["timestamp"].endswith("+00:00") or entry["timestamp"].endswith("Z")
    # scan_id defaults to file_name when not provided
    assert entry["scan_id"] == "suspicious_file.py"


def test_log_infra_gap_appends_multiple_entries(tmp_path: Path) -> None:
    """Multiple calls append to the same file — one line per call."""
    log_path = tmp_path / "infra_gaps.jsonl"
    for i in range(3):
        log_infra_gap(
            file_name=f"file_{i}.py",
            phase="phase_3_loop",
            error_message=f"/bin/sh: 1: tool_{i}: not found",
            log_path=log_path,
        )
    lines = log_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 3
    for i, line in enumerate(lines):
        entry = json.loads(line)
        assert entry["file_name"] == f"file_{i}.py"
        assert entry["missing_tool"] == f"tool_{i}"
        assert entry["error_category"] == "missing_binary"


def test_log_infra_gap_creates_parent_directory(tmp_path: Path) -> None:
    """If the log's parent directory doesn't exist, it's created. The
    operator can drop a clean repo and the .argus_local/ dir spawns
    on first scan."""
    log_path = tmp_path / "nested" / "deeper" / "infra_gaps.jsonl"
    ok = log_infra_gap(
        file_name="x.py",
        phase="dast_orchestrator",
        error_message="ConnectionError: Connection refused",
        log_path=log_path,
    )
    assert ok is True
    assert log_path.exists()
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["error_category"] == "network_blocked"


def test_log_infra_gap_never_raises_on_disk_error(tmp_path: Path) -> None:
    """Fire-and-forget contract: a disk error returns False but never
    raises. The scan hot path must not be affected by logging issues."""
    # Pass a path whose parent is a FILE (impossible to mkdir -p over).
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    log_path = blocker / "subdir" / "infra_gaps.jsonl"

    # Must not raise.
    ok = log_infra_gap(
        file_name="x.py",
        phase="phase_3_loop",
        error_message="x",
        log_path=log_path,
    )
    assert ok is False


def test_log_infra_gap_unknown_error_still_logged(tmp_path: Path) -> None:
    """Unrecognized error patterns still get logged with category=other.
    This is critical so the operator sees NEW gap patterns we haven't
    coded a regex for yet."""
    log_path = tmp_path / "infra_gaps.jsonl"
    log_infra_gap(
        file_name="x.py",
        phase="phase_3_loop",
        error_message="some weird error I haven't seen before",
        log_path=log_path,
    )
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["error_category"] == "other"
    assert entry["missing_tool"] is None
    assert "weird error" in entry["error_excerpt"]


def test_log_infra_gap_explicit_scan_id_used(tmp_path: Path) -> None:
    """When scan_id is explicit, it's preserved (not overridden by
    file_name)."""
    log_path = tmp_path / "infra_gaps.jsonl"
    log_infra_gap(
        file_name="x.py",
        phase="phase_3_loop",
        error_message="x",
        scan_id="scan-2026-05-12-abc123",
        log_path=log_path,
    )
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["scan_id"] == "scan-2026-05-12-abc123"
    assert entry["file_name"] == "x.py"


# ── v1.8 test-isolation guardrails ─────────────────────────────────────────


def test_resolve_log_path_explicit_env_var_wins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ARGUS_INFRA_GAPS_PATH takes precedence over BOTH the pytest
    sink and the production default. This is the path the autouse
    conftest fixture uses to per-test-isolate writes."""
    from dast.infra_telemetry import _resolve_log_path

    explicit = tmp_path / "explicit.jsonl"
    monkeypatch.setenv("ARGUS_INFRA_GAPS_PATH", str(explicit))
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "fake::test_name")  # belt + braces

    assert _resolve_log_path() == explicit


def test_resolve_log_path_pytest_detection_routes_to_temp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When PYTEST_CURRENT_TEST is set and ARGUS_INFRA_GAPS_PATH is not,
    _resolve_log_path() routes to the OS temp dir — NOT to the
    production ``.argus_local/infra_gaps.jsonl``. This is the load-
    bearing guardrail: even if a test bypasses the autouse fixture
    or unsets ARGUS_INFRA_GAPS_PATH, the production log stays clean."""
    import tempfile

    from dast.infra_telemetry import _resolve_log_path

    monkeypatch.delenv("ARGUS_INFRA_GAPS_PATH", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "fake_test_name")

    path = _resolve_log_path()
    # Must be in the OS temp dir, not the repo root's .argus_local/
    assert str(path).startswith(tempfile.gettempdir()), (
        f"pytest-guardrail bypass: _resolve_log_path returned {path}, "
        f"expected something under {tempfile.gettempdir()}"
    )
    assert ".argus_local" not in str(path)


def test_resolve_log_path_production_default_when_no_pytest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In a real production run (no pytest env, no override), the
    log resolves to the repo-root ``.argus_local/infra_gaps.jsonl``.
    Regression guard against accidentally always routing to temp."""
    from dast.infra_telemetry import _resolve_log_path

    monkeypatch.delenv("ARGUS_INFRA_GAPS_PATH", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    path = _resolve_log_path()
    assert path.name == "infra_gaps.jsonl"
    assert ".argus_local" in str(path)


def test_autouse_fixture_writes_to_tmp_not_real_log(
    isolate_infra_gaps_log: Path,
) -> None:
    """End-to-end: the conftest's autouse fixture redirects writes.
    A real ``log_infra_gap`` call (no explicit log_path) should land
    in the fixture's tmp_path, not in the repo's
    ``.argus_local/infra_gaps.jsonl``.

    This is the integration test that pins the whole guardrail stack —
    if conftest's autouse fixture, the env override, OR
    _resolve_log_path's behavior regresses, this test fails.
    """
    # Call log_infra_gap with NO explicit log_path — exercises the
    # full _resolve_log_path() resolution chain. The env var set by
    # the autouse fixture wins (priority 1), so writes land in the
    # per-test tmp path.
    ok = log_infra_gap(
        file_name="regression_test.py",
        phase="phase_3_loop_single_function",
        error_message="RuntimeError: synthetic for regression test",
    )
    assert ok is True

    # The autouse fixture's path got written
    assert isolate_infra_gaps_log.exists()
    entry = json.loads(isolate_infra_gaps_log.read_text(encoding="utf-8").strip())
    assert entry["file_name"] == "regression_test.py"
    assert "synthetic for regression test" in entry["error_excerpt"]

    # And confirm the REAL log was NOT modified. Note: we use the
    # production resolver path directly here, not env-influenced —
    # this is the operator-facing path.
    real_log = Path(__file__).resolve().parent.parent.parent / ".argus_local" / "infra_gaps.jsonl"
    if real_log.exists():
        text = real_log.read_text(encoding="utf-8")
        assert "synthetic for regression test" not in text, (
            "GUARDRAIL FAILURE: a unit test wrote to the real production "
            "infra_gaps.jsonl. Re-check tests/conftest.py + "
            "dast/infra_telemetry._resolve_log_path()."
        )
