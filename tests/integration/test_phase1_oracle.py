"""ARG-002 — Phase 1 oracle validation.

Runs the live cascade against a 5-file regression suite with hand-
labeled oracles in samples/regression_v1/oracle.json. Asserts:
  * verdict is a member of the oracle's expected_verdicts set
  * vulnerability count is within [min, max] bounds (max optional)

This is the formal Phase 1 close-out gate: if the cascade can't
correctly classify these five canonical cases, something's wrong
upstream.

Cost ≈ $0.20-0.40 per full pass (4 model calls + 1 short-circuit).

Run:
    uv run pytest tests/integration/test_phase1_oracle.py -v -s
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

from scanner.engine import scan_file
from scanner.runners import (
    make_gemini_triage_runner,
    make_opus_runner,
    make_sonnet_runner,
)

load_dotenv(override=True)

_SUITE_DIR = Path(__file__).parent.parent.parent / "samples" / "regression_v1"
_ORACLE_PATH = _SUITE_DIR / "oracle.json"


def _load_oracle() -> dict:
    with _ORACLE_PATH.open() as f:
        return json.load(f)["files"]


_ORACLE = _load_oracle()


@pytest.fixture(scope="module")
def runners() -> dict:
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if not anthropic_key or not gemini_key:
        pytest.skip("ANTHROPIC_API_KEY + GEMINI_API_KEY required")
    return {
        "triage_runner": make_gemini_triage_runner(gemini_key),
        "sonnet_runner": make_sonnet_runner(anthropic_key),
        "opus_runner": make_opus_runner(anthropic_key),
        "dast_runner": None,
    }


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("filename", list(_ORACLE.keys()))
async def test_phase1_oracle(filename: str, runners: dict) -> None:
    """Each regression file must verdict within its oracle's expected
    set and surface the expected vulnerability count range."""
    file_path = _SUITE_DIR / filename
    expected = _ORACLE[filename]
    content = file_path.read_bytes()

    result = await scan_file(filename=filename, content=content, **runners)

    actual_verdict = result.final_verdict
    n_vulns = len(result.vulnerabilities)
    print(
        f"\n  [{filename}] verdict={actual_verdict} "
        f"(expected {expected['expected_verdicts']}) "
        f"vulns={n_vulns} "
        f"path={' -> '.join(result.scan_path)} "
        f"cost=${result.total_cost_usd:.4f} "
        f"time={result.total_duration_ms}ms"
    )

    assert result.error is None, f"scan errored: {result.error}"
    assert actual_verdict in expected["expected_verdicts"], (
        f"{filename}: verdict {actual_verdict!r} not in expected set "
        f"{expected['expected_verdicts']}; reason: {expected.get('description', '')}"
    )

    min_vulns = expected.get("min_vulnerabilities", 0)
    max_vulns = expected.get("max_vulnerabilities")
    assert n_vulns >= min_vulns, (
        f"{filename}: {n_vulns} vulns reported, expected ≥ {min_vulns}"
    )
    if max_vulns is not None:
        assert n_vulns <= max_vulns, (
            f"{filename}: {n_vulns} vulns reported, expected ≤ {max_vulns}"
        )
