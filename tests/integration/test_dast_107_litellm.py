"""DAST-107 — live end-to-end test on litellm_obfuscated.py.

The full Phase 1 + 2 + 3 chain: preprocessing -> triage -> Sonnet/Opus
analysis -> DAST orchestrator -> sandbox executions -> validated findings.

Asserts the final verdict matches the regression_baseline oracle and
that DAST was actually exercised (attempted, ran iterations, surfaced
findings). Skips if any of the four requirements is unconfigured:
ANTHROPIC_API_KEY, GEMINI_API_KEY, FLY_API_TOKEN, ECHO_DAST_IMAGE_MINIMAL.

Cost per pass: ~$0.50-1.50 (Sonnet inference x 3 iterations +
Fly Firecracker microvms x several sandbox calls). Test takes 3-8 min
of wall clock.

Run:
    uv run pytest tests/integration/test_dast_107_litellm.py -v -s
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

from dast.runner import make_dast_runner_from_env
from scanner.engine import scan_file
from scanner.runners import (
    make_gemini_triage_runner,
    make_opus_runner,
    make_sonnet_runner,
)

load_dotenv(override=True)

_FIXTURE = Path(__file__).parent.parent.parent / "samples" / "regression_v1" / "litellm_obfuscated.py"
_BASELINE = Path(__file__).parent.parent.parent / "samples" / "regression_v1" / "regression_baseline.json"


def _baseline_entry(file_name: str) -> dict:
    with _BASELINE.open() as f:
        data = json.load(f)
    return next(f for f in data["files"] if f["file_name"] == file_name)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_dast_107_litellm_obfuscated() -> None:
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if not anthropic_key or not gemini_key:
        pytest.skip("ANTHROPIC_API_KEY + GEMINI_API_KEY required")

    dast_runner = make_dast_runner_from_env(api_key=anthropic_key)
    if dast_runner is None:
        pytest.skip(
            "DAST not configured (FLY_API_TOKEN / ECHO_DAST_IMAGE_MINIMAL). "
            "Run dast/sandbox/firecracker/preflight.* + build_and_push_multi.sh "
            "and set the env vars to enable this test."
        )

    triage = make_gemini_triage_runner(gemini_key)
    sonnet = make_sonnet_runner(anthropic_key)
    opus = make_opus_runner(anthropic_key)

    content = _FIXTURE.read_bytes()
    oracle = _baseline_entry("litellm_obfuscated.py")

    result = await scan_file(
        filename="litellm_obfuscated.py",
        content=content,
        triage_runner=triage,
        sonnet_runner=sonnet,
        opus_runner=opus,
        dast_runner=dast_runner,
    )

    print(
        f"\n  verdict={result.final_verdict} "
        f"(oracle: {oracle['oracle_verdict']}, "
        f"baseline: {oracle['baseline_verdict']}) "
        f"path={' -> '.join(result.scan_path)}"
    )
    print(
        f"  cost=${result.total_cost_usd:.4f} "
        f"time={result.total_duration_ms}ms "
        f"vulns={len(result.vulnerabilities)} "
        f"dast_attempted={result.dast_attempted} "
        f"dast_findings={len(result.dast_findings)} "
        f"dast_iterations={len(result.dast_iterations)}"
    )

    # Engine ran cleanly
    assert result.error is None, f"scan errored: {result.error}"

    # Verdict matches oracle (allowing variance_band = same verdict twice
    # in litellm's case, both critical_malicious)
    expected = set(oracle["variance_band"])
    assert result.final_verdict in expected, f"verdict {result.final_verdict!r} not in oracle band {expected}"

    # DAST actually fired
    assert result.dast_attempted, "DAST stage was not attempted"
    assert "dast_verification" in result.scan_path, f"scan_path missing dast_verification: {result.scan_path}"

    # DAST produced at least one iteration of structured output
    assert len(result.dast_iterations) >= 1, "DAST ran zero iterations"

    # Cost is within the soft envelope we expect for a Tier-1 win
    assert result.total_cost_usd < 5.0, f"unexpectedly expensive scan: ${result.total_cost_usd:.4f}"
