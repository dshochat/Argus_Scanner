"""DAST infra-gap telemetry (v1.6 Fix #10).

When DAST can't test an L1 finding because the sandbox image is missing
a required tool (npm, docker, gcc, a Python package, a system binary,
etc.), we log it here so the operator can periodically review the
patterns and decide which images to extend.

**Privacy**: writes to ``.argus_local/infra_gaps.jsonl`` by default.
``.argus_local/`` is in ``.gitignore`` and MUST stay there — this log
contains scan-internal telemetry that we never want to leak to the
public repo (Argus_Scanner). Override the path via the
``ARGUS_INFRA_GAPS_PATH`` env var for non-default deployments.

Test-isolation contract (v1.8)
------------------------------
Several production code paths catch broad ``Exception`` and call
``log_infra_gap()`` fire-and-forget (see callers in
``dast/adversarial_loop_runner.py`` and ``scanner/engine.py``). Unit
tests that drive those code paths via injected sandbox stubs that
raise synthetic exceptions WOULD pollute the real operator-facing log
unless something stops them.

Two layers of defense, both implemented:

1. **Telemetry-side guardrail (this module)**: ``_resolve_log_path()``
   detects pytest at runtime via the ``PYTEST_CURRENT_TEST`` env var
   (pytest sets it automatically per test) and routes writes to a
   per-process sink under ``tempfile.gettempdir()``. The production
   code path is unchanged.

2. **Test-side autouse fixture (``tests/conftest.py``)**: redirects
   ``ARGUS_INFRA_GAPS_PATH`` to a per-test ``tmp_path`` regardless of
   whether the test explicitly calls ``log_infra_gap``. Belt + braces.

If a test needs to exercise the real on-disk write (e.g.,
``test_infra_telemetry`` itself), it passes ``log_path=tmp_path /
"infra_gaps.jsonl"`` explicitly — both guardrails respect the explicit
override.

Format: JSON Lines. Each entry is one observed infra gap. Schema:

  {
    "timestamp": "2026-05-12T15:30:00Z",
    "scan_id": "unique scan identifier or file_name",
    "file_name": "the file being scanned when the gap fired",
    "phase": "phase_b | phase_2_chain | phase_3_loop | dast_verification | ...",
    "finding_cwe": "CWE-XXX or null",
    "image_hint": "lean | rich_python | ml_tools | null",
    "error_category": "missing_binary | missing_python_pkg | "
                      "missing_node_pkg | network_blocked | other",
    "missing_tool": "best-effort extracted tool name (e.g., 'npm', 'docker', 'pickle5')",
    "error_excerpt": "first 400 chars of the original error message",
  }

The module is intentionally tiny + dependency-free so it can be called
from any sandbox-failure path without circular imports.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ── Configuration ──────────────────────────────────────────────────────────

#: Default log path. Override via ``ARGUS_INFRA_GAPS_PATH`` env var.
#: Resolved against the repo root (parent of the ``dast`` directory).
_DEFAULT_LOG_REL = ".argus_local/infra_gaps.jsonl"

#: Per-process sink used when running under pytest. Files written here
#: live in the OS temp dir and are GC'd by normal temp-dir cleanup. The
#: tests/conftest.py autouse fixture additionally redirects each test
#: to its own ``tmp_path`` — this is the second-layer fallback for when
#: the fixture isn't loaded (e.g., bare ``pytest --import-mode``).
_PYTEST_SINK_REL = f"argus_infra_gaps_pytest_pid{os.getpid()}.jsonl"


def _resolve_log_path() -> Path:
    """Return the log file path, honoring (in priority order):

    1. ``ARGUS_INFRA_GAPS_PATH`` env override — explicit; always wins.
       Used by the ``tests/conftest.py`` autouse fixture to redirect
       per-test writes to ``tmp_path``.
    2. Pytest detection — ``PYTEST_CURRENT_TEST`` set by pytest. Routes
       writes to a per-process sink in the OS tmp dir so production
       exception paths called from tests never pollute the real
       operator-facing log at ``.argus_local/infra_gaps.jsonl``.
    3. Production default — ``<repo-root>/.argus_local/infra_gaps.jsonl``.

    Path is resolved against the repo root in the production case so
    the log lives in a known location regardless of where Argus is
    invoked from.
    """
    override = os.environ.get("ARGUS_INFRA_GAPS_PATH")
    if override:
        return Path(override)
    if "PYTEST_CURRENT_TEST" in os.environ:
        # v1.8: guardrail — never pollute the production telemetry log
        # from a test run. See the module docstring's "Test-isolation
        # contract" section for the full rationale.
        return Path(tempfile.gettempdir()) / _PYTEST_SINK_REL
    # dast/infra_telemetry.py -> dast -> repo root
    repo_root = Path(__file__).resolve().parent.parent
    return repo_root / _DEFAULT_LOG_REL


# ── Error pattern detection ────────────────────────────────────────────────
#
# Each entry: (compiled regex, error_category, tool-extraction lambda).
# Order matters — more specific patterns first.

_PATTERNS: list[tuple[re.Pattern[str], str, Any]] = [
    # System binary missing: shell-side "command not found" or
    # "/bin/sh: 1: foo: not found"
    (
        re.compile(r"(?:command not found|: not found)\s*:?\s*([A-Za-z0-9_./-]+)"),
        "missing_binary",
        lambda m: m.group(1) if m.lastindex else None,
    ),
    (
        re.compile(r"No such file or directory:\s*['\"]?([A-Za-z0-9_./-]+)"),
        "missing_binary",
        lambda m: m.group(1) if m.lastindex else None,
    ),
    (
        re.compile(r"/bin/sh:.*?:\s*([A-Za-z0-9_./-]+):\s*not found"),
        "missing_binary",
        lambda m: m.group(1) if m.lastindex else None,
    ),
    # Python missing package
    (
        re.compile(r"ModuleNotFoundError:\s*No module named\s*['\"]([A-Za-z0-9_.-]+)['\"]"),
        "missing_python_pkg",
        lambda m: m.group(1) if m.lastindex else None,
    ),
    (
        re.compile(r"ImportError:\s*No module named\s*['\"]?([A-Za-z0-9_.-]+)"),
        "missing_python_pkg",
        lambda m: m.group(1) if m.lastindex else None,
    ),
    # Node missing package
    (
        re.compile(r"Cannot find module\s*['\"]([A-Za-z0-9_./@-]+)['\"]"),
        "missing_node_pkg",
        lambda m: m.group(1) if m.lastindex else None,
    ),
    (
        re.compile(r"npm ERR! 404.*?'([A-Za-z0-9_./@-]+)'"),
        "missing_node_pkg",
        lambda m: m.group(1) if m.lastindex else None,
    ),
    # Network blocked (the minimal image has no egress)
    (
        re.compile(
            r"(?:Connection refused|Network is unreachable|"
            r"Could not resolve host|Temporary failure in name resolution|"
            r"getaddrinfo.*failed)"
        ),
        "network_blocked",
        lambda _m: None,
    ),
    # Permission / capability missing (e.g., raw sockets, setuid)
    (
        re.compile(r"(?:Operation not permitted|PermissionError.*?:\s*['\"]?([A-Za-z0-9_./-]+))"),
        "permission_denied",
        lambda m: m.group(1) if m.lastindex and m.group(1) else None,
    ),
]


def categorize_error(error_message: str) -> tuple[str, str | None]:
    """Categorize an error message + best-effort extract the missing tool.

    Returns ``(error_category, missing_tool_or_none)``. When no pattern
    matches, returns ``("other", None)`` so the entry is still logged for
    human review.
    """
    if not isinstance(error_message, str) or not error_message:
        return "other", None
    for pattern, category, extractor in _PATTERNS:
        m = pattern.search(error_message)
        if m:
            try:
                tool = extractor(m)
            except (IndexError, AttributeError):
                tool = None
            return category, tool
    return "other", None


# ── Public API ─────────────────────────────────────────────────────────────


def log_infra_gap(
    *,
    file_name: str,
    phase: str,
    error_message: str,
    finding_cwe: str | None = None,
    image_hint: str | None = None,
    scan_id: str | None = None,
    log_path: Path | None = None,
) -> bool:
    """Append a JSON line describing an infra gap to the local log.

    This is fire-and-forget telemetry — never raise on disk errors.
    Returns ``True`` on successful write, ``False`` on any failure.
    The caller's hot path is not affected by logging issues.

    Args:
        file_name: file being scanned when the gap fired.
        phase: which DAST phase tried to fire (e.g., ``"phase_3_loop"``).
        error_message: original error from sandbox / runner.
        finding_cwe: the L1 finding's CWE if known (for grouping).
        image_hint: which sandbox image was requested (minimal/etc.).
        scan_id: unique scan identifier; defaults to ``file_name``.
        log_path: explicit path override (mostly for tests).
    """
    category, tool = categorize_error(error_message)
    entry = {
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "scan_id": scan_id or file_name,
        "file_name": file_name,
        "phase": phase,
        "finding_cwe": finding_cwe,
        "image_hint": image_hint,
        "error_category": category,
        "missing_tool": tool,
        "error_excerpt": (error_message or "")[:400],
    }
    path = log_path or _resolve_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return True
    except OSError:
        # Defensive — never block scan progress on log failures.
        return False


__all__ = [
    "categorize_error",
    "log_infra_gap",
]
