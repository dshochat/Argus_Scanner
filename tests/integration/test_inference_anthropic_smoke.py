"""INF-001 smoke test: AnthropicAdapter end-to-end against live API.

Verifies the lifted CNAPPPOC adapter works against the model IDs declared
in CLAUDE.md (claude-sonnet-4-6, claude-opus-4-6) using the production
shape: streaming + extended thinking enabled.

Asserts the round-trip response carries non-empty text, valid token
counts, and parseable JSON output.

Run:
    uv run pytest tests/integration/test_inference_anthropic_smoke.py -v -s
"""

from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

from inference.adapters import AnthropicAdapter

load_dotenv(override=True)


def _config(model_id: str) -> dict:
    return {
        "name": f"smoke-{model_id}",
        "model_id": model_id,
        "api_key_encrypted": os.environ.get("ANTHROPIC_API_KEY", ""),
        "provider": "anthropic",
        "config": {
            "effort": "low",
            "max_tokens": 4096,
        },
    }


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("model_id", ["claude-sonnet-4-6", "claude-opus-4-6"])
async def test_anthropic_adapter_round_trip(model_id: str) -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set")

    adapter = AnthropicAdapter(_config(model_id))

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
