"""INF-002 smoke test: GoogleAdapter end-to-end against live Gemini API.

Verifies the lifted CNAPPPOC GoogleAdapter works against
gemini-3.1-flash-lite-preview (the triage tier of Argus's cascade).

Asserts the round-trip response carries non-empty text, valid token
counts, and parseable JSON output.

Run:
    uv run pytest tests/integration/test_inference_gemini_smoke.py -v -s
"""

from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

from inference.adapters import GoogleAdapter

load_dotenv(override=True)


def _config(model_id: str) -> dict:
    return {
        "name": f"smoke-{model_id}",
        "model_id": model_id,
        "api_key_encrypted": os.environ.get("GEMINI_API_KEY", ""),
        "provider": "google",
        "config": {
            "thinking_budget": 0,
            "max_tokens": 4096,
        },
    }


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("model_id", ["gemini-3.1-flash-lite-preview"])
async def test_gemini_adapter_round_trip(model_id: str) -> None:
    if not os.environ.get("GEMINI_API_KEY"):
        pytest.skip("GEMINI_API_KEY not set")

    adapter = GoogleAdapter(_config(model_id))

    system_prompt = (
        "You are a JSON-only responder. Respond with exactly this JSON object "
        "and nothing else: "
        '{"ok": true, "echo": "<the filename you were given>"}.'
    )
    result = await adapter.scan(
        content="print('hello world')\n",
        filename="hello.py",
        system_prompt=system_prompt,
    )

    print(
        f"\n  [{model_id}] tokens in/out={result['input_tokens']}/"
        f"{result['output_tokens']} time={result['response_time_ms']}ms "
        f"json_valid={result['json_valid']}"
    )

    assert result["error"] is None, f"API call failed: {result['error']}"
    assert result["raw_response"], "empty raw_response"
    assert result["input_tokens"] > 0, "no input_tokens reported"
    assert result["output_tokens"] > 0, "no output_tokens reported"
    assert result["json_valid"], f"adapter could not parse JSON: {result['raw_response']!r}"
    assert result["parsed"] is not None
    assert result["parsed"].get("ok") is True
