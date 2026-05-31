"""Tests for the Phase A planner antipattern detector.

The detector catches LLM regressions where the Phase A planner emits
flat-file invocations (`python3 /workspace/<basename>`) for targets
that need the package-import pattern (`import $MODULE_NAME`). Without
this gate, every probe that uses the bad command silently fails with
ImportError on the entry file's `from .` relative imports, masking
real exploits as NOT_TESTED.

These tests pin the detection rules so they don't regress as the
prompt evolves.
"""

from __future__ import annotations

import pytest

from dast.orchestrator import _detect_planner_antipatterns


# ─── Python package-member context ────────────────────────────────────


PYTHON_CTX = dict(
    file_name="unpickler.py",
    entry_rel_path="jsonpickle/unpickler.py",
    module_name="jsonpickle.unpickler",
)


@pytest.mark.parametrize(
    "command",
    [
        # flat-file script execution
        "python3 /workspace/unpickler.py",
        'python3 "/workspace/unpickler.py"',
        "python3 '/workspace/unpickler.py'",
        # bare-basename import (loads flat copy)
        'python3 -c "import unpickler; m.x()"',
        "python3 -c 'import unpickler as m; m.decode(payload)'",
        # pip install of the pre-staged local package
        "pip install jsonpickle --quiet 2>&1 | tail -5",
        "pip install jsonpickle==4.1.1",
    ],
)
def test_python_package_antipatterns_detected(command: str) -> None:
    findings = _detect_planner_antipatterns([command], **PYTHON_CTX)
    assert findings, f"Expected antipattern detection on: {command!r}"


@pytest.mark.parametrize(
    "command",
    [
        # Correct: package-qualified import with sys.path setup
        'python3 -c \'import sys; sys.path.insert(0, "/workspace"); '
        'import jsonpickle.unpickler as m; print(m.decode(payload))\'',
        # Correct: dotted name in the import statement
        'python3 -c "import jsonpickle.unpickler"',
        # Unrelated commands shouldn't trip the detector
        "echo setup",
        "ls /workspace",
        "cat /workspace/jsonpickle/__init__.py",
    ],
)
def test_python_package_correct_patterns_not_flagged(command: str) -> None:
    findings = _detect_planner_antipatterns([command], **PYTHON_CTX)
    assert not findings, f"False positive on correct pattern: {command!r} → {findings}"


def test_python_mixed_plan_flags_only_bad_commands() -> None:
    cmds = [
        "echo setup",
        "python3 /workspace/unpickler.py",  # bad
        "echo done",
    ]
    findings = _detect_planner_antipatterns(cmds, **PYTHON_CTX)
    assert len(findings) == 1
    assert "flat-file" in findings[0].lower()


# ─── JS/TS multi-file context ─────────────────────────────────────────


JS_CTX = dict(
    file_name="index.ts",
    entry_rel_path="shopify/lib/index.ts",
    module_name="",
)


@pytest.mark.parametrize(
    "command",
    [
        'node "/workspace/index.ts"',
        "node /workspace/index.ts",
        "tsx /workspace/index.ts",
        'tsx "/workspace/index.ts"',
        "tsx '/workspace/index.ts'",
        "npm install shopify --quiet",
    ],
)
def test_js_ts_subdir_antipatterns_detected(command: str) -> None:
    findings = _detect_planner_antipatterns([command], **JS_CTX)
    assert findings, f"Expected antipattern detection on: {command!r}"


@pytest.mark.parametrize(
    "command",
    [
        'cd /workspace && tsx "src/index.ts"',
        'cd /workspace && tsx "$ENTRY_REL_PATH"',
        'cd /workspace && node "$ENTRY_REL_PATH"',
        "echo setup",
    ],
)
def test_js_ts_correct_patterns_not_flagged(command: str) -> None:
    findings = _detect_planner_antipatterns([command], **JS_CTX)
    assert not findings, f"False positive on correct pattern: {command!r} → {findings}"


# ─── Flat single-file context (no antipatterns possible) ─────────────


FLAT_CTX = dict(file_name="exploit.py", entry_rel_path="", module_name="")


@pytest.mark.parametrize(
    "command",
    [
        "python3 /workspace/exploit.py",  # legitimate flat-file execution
        'python3 -c "import exploit"',  # legitimate bare import
        "pip install requests --quiet",  # legitimate third-party install
    ],
)
def test_flat_file_scan_never_flags(command: str) -> None:
    findings = _detect_planner_antipatterns([command], **FLAT_CTX)
    assert not findings


# ─── Edge cases ──────────────────────────────────────────────────────


def test_empty_command_list() -> None:
    assert _detect_planner_antipatterns([], **PYTHON_CTX) == []


def test_non_string_commands_ignored() -> None:
    findings = _detect_planner_antipatterns(
        [None, 42, {"x": "y"}, "python3 /workspace/unpickler.py"],
        **PYTHON_CTX,
    )
    assert len(findings) == 1  # only the real command is checked


def test_dedupes_repeated_findings() -> None:
    # Same antipattern in 3 commands → 1 finding (deduped)
    cmds = [
        "python3 /workspace/unpickler.py",
        "python3 /workspace/unpickler.py x",
        'python3 "/workspace/unpickler.py" y',
    ]
    findings = _detect_planner_antipatterns(cmds, **PYTHON_CTX)
    # Different patterns (unquoted + double-quoted) → may yield 2 entries,
    # but the first form repeated twice should dedupe to 1.
    assert len(findings) <= 2
    assert all("flat-file" in f.lower() for f in findings)
