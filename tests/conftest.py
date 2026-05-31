"""Pytest configuration for the Argus test suite.

Houses cross-suite fixtures that need to apply globally — currently
just one: the test-isolation guardrail for ``dast.infra_telemetry``.

Why an autouse conftest fixture (v1.8)
--------------------------------------
Several production code paths catch broad ``Exception`` and call
``dast.infra_telemetry.log_infra_gap()`` fire-and-forget — e.g.,
``_run_single_function`` and ``_run_stateful_sequence`` in
``dast/adversarial_loop_runner.py`` and the top-level DAST exception
handler in ``scanner/engine.py``. Unit tests that drive those code
paths via injected sandbox stubs that raise (e.g.,
``test_run_one_turn_sandbox_exception_returns_blocked``) WILL trigger
the production exception handler, which calls ``log_infra_gap``.

Without this fixture, every such test run appends an entry to the
operator-facing ``.argus_local/infra_gaps.jsonl`` log. Forensic
diagnosis in v1.8 found 33+ such pollution entries accumulated over
weeks of development, drowning the 5 real entries with synthetic
"fly api unreachable" rows.

Defense-in-depth — TWO independent guardrails:

  1. ``dast.infra_telemetry._resolve_log_path`` detects pytest via the
     ``PYTEST_CURRENT_TEST`` env var and routes writes to a per-process
     sink in the OS temp dir. Lives in the production code itself.

  2. ``isolate_infra_gaps_log`` (this file) — autouse fixture that
     sets ``ARGUS_INFRA_GAPS_PATH`` to a per-test ``tmp_path``. Even
     if (1) is bypassed (env var unset, _resolve_log_path replaced via
     monkeypatch by a different test), this layer catches the write.

Tests that explicitly want to verify on-disk write behavior (e.g.,
``test_infra_telemetry.py``) pass ``log_path=tmp_path / "..."``
explicitly — both guardrails respect the explicit override.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_infra_gaps_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Redirect ARGUS_INFRA_GAPS_PATH to a per-test tmp file.

    Production code in ``log_infra_gap`` honors this env var first
    (see ``dast.infra_telemetry._resolve_log_path``). Without this
    fixture, any test that drives a code path calling
    ``log_infra_gap()`` fire-and-forget would pollute the real
    ``.argus_local/infra_gaps.jsonl`` operator log.

    Returns the tmp path so individual tests can inspect what got
    written if they care.
    """
    log_path = tmp_path / "infra_gaps.jsonl"
    monkeypatch.setenv("ARGUS_INFRA_GAPS_PATH", str(log_path))
    return log_path
