"""SCAN-011 Slice 1 — hunter runner unit tests.

Verifies the hunter runner's fan-out shape, dedup merge, and back-
compat fallback to the split runner when the adapter lacks
``scan_with_prefix_body`` support.

No live API calls — uses stubbed adapters that match the
AnthropicAdapter.scan_with_prefix_body shape.
"""

from __future__ import annotations

from typing import Any

import pytest

from prompts.scanner import (
    ATTACK_CLASS_HUNTERS,
    SCAN_PROMPT_BEHAVIORAL_BODY,
    SCAN_PROMPT_CHAINS_BODY,
    SCAN_PROMPT_SYSTEM,
)
from scanner.runners import (
    make_anthropic_hunter_runner_from_adapter,
)


class _FakeHunterAdapter:
    """Adapter stub that exposes ``scan_with_prefix_body`` and returns
    canned per-body responses. Tracks every (prefix, body) pair so
    tests can assert the fan-out shape."""

    def __init__(self, responses_by_body_marker: dict[str, dict]) -> None:
        self._responses = responses_by_body_marker
        self.calls: list[dict[str, str]] = []

    async def scan_with_prefix_body(
        self,
        content: str,
        filename: str,
        system_prefix: str,
        system_body: str,
    ) -> dict:
        self.calls.append(
            {
                "filename": filename,
                "prefix": system_prefix,
                "body_head": system_body[:120],
            }
        )
        for marker, response in self._responses.items():
            if marker in system_body:
                return response
        raise AssertionError(
            f"FakeHunterAdapter has no response for body prefix "
            f"{system_body[:200]!r}"
        )


def _hunter_response(
    *,
    n_findings: int = 1,
    type_: str = "ssrf",
    score: int = 60,
    in_tokens: int = 1500,
    out_tokens: int = 1200,
    duration_ms: int = 1800,
    cache_read_input_tokens: int = 0,
) -> dict:
    findings = [
        {
            "type": type_,
            "severity": "high",
            "line": 7 + i,
            "code": f"urlopen(url{i})",
            "explanation": "User-controlled URL flows to urlopen.",
            "fix": "Validate scheme + host.",
            "cwe": "CWE-918",
            "confidence": 0.9,
            "data_flow_trace": "url -> urlopen",
            "proof_of_concept": "http://169.254.169.254/",
            "intent_check": "Not by-design.",
        }
        for i in range(n_findings)
    ]
    return {
        "parsed": {
            "file_intent_analysis": {
                "purpose": "fetch URL",
                "deployment_context": "library",
                "trust_boundary": "any caller",
                "powerful_by_design": [],
            },
            "vulnerabilities": findings,
            "composite_risk": {
                "score": score,
                "reasoning": "SSRF",
                "exploitability": "high",
            },
        },
        "json_valid": True,
        "input_tokens": in_tokens,
        "output_tokens": out_tokens,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": cache_read_input_tokens,
        "response_time_ms": duration_ms,
        "error": None,
    }


def _behav_response() -> dict:
    return {
        "parsed": {
            "behavioral_profile": {
                "actual_capabilities": {"network_calls": ["GET"]},
                "shield_policy": "block private IPs",
            }
        },
        "json_valid": True,
        "input_tokens": 800,
        "output_tokens": 500,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "response_time_ms": 1500,
        "error": None,
    }


def _chains_response() -> dict:
    return {
        "parsed": {
            "ai_tool_analysis": {"mcp_servers": [], "agent_configs": []},
            "attack_chains": [],
        },
        "json_valid": True,
        "input_tokens": 600,
        "output_tokens": 400,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "response_time_ms": 1300,
        "error": None,
    }


def _full_response_map() -> dict[str, dict]:
    """Slice 2 — 10 hunters + behavioral + chains. The 3 slice-1
    hunters return interesting findings (so the merge / dedup /
    verdict tests have signal); the 7 slice-2 hunters return empty
    findings by default — most tests in this module don't need them
    to fire."""
    return {
        # Slice-1 hunters with interesting findings.
        "Hunt for INJECTION-class vulnerabilities": _hunter_response(
            n_findings=1, type_="command_injection", score=55
        ),
        "Hunt for SSRF (CWE-918) vulnerabilities": _hunter_response(
            n_findings=1, type_="ssrf", score=70
        ),
        "Hunt for MALICIOUS-INTENT vulnerabilities": _hunter_response(
            n_findings=0, type_="data_exfiltration", score=20
        ),
        # Slice-2 hunters return empty findings (most tests don't need
        # them; tests that DO can override the response map).
        "Hunt for PATH-TRAVERSAL": _hunter_response(n_findings=0, score=0),
        "Hunt for INSECURE DESERIALIZATION": _hunter_response(n_findings=0, score=0),
        "Hunt for PROMPT INJECTION": _hunter_response(n_findings=0, score=0),
        "Hunt for CREDENTIAL-related": _hunter_response(n_findings=0, score=0),
        "Hunt for AUTHORIZATION": _hunter_response(n_findings=0, score=0),
        "Hunt for CRYPTOGRAPHIC": _hunter_response(n_findings=0, score=0),
        "Hunt for DATA-EXFILTRATION": _hunter_response(n_findings=0, score=0),
        # Behavioral + chains slots.
        "Analyze this file's runtime behavior": _behav_response(),
        "AI tool security issues and multi-step": _chains_response(),
    }


def _build_runner(adapter: Any, **kwargs: Any) -> Any:
    return make_anthropic_hunter_runner_from_adapter(
        adapter,
        model_label="test-sonnet",
        cost_per_m_input=3.0,
        cost_per_m_output=15.0,
        **kwargs,
    )


@pytest.mark.asyncio
async def test_hunter_runner_fans_out_full_taxonomy_plus_behav_chains() -> None:
    """Slice 2 ships 10 hunters (full taxonomy). Plus BEHAVIORAL +
    CHAINS = 12 total calls per HIGH-triage file."""
    adapter = _FakeHunterAdapter(_full_response_map())
    runner = _build_runner(adapter)
    await runner("app.py", b"import urllib.request\n", None, "HIGH")
    # 10 hunters + behavioral + chains = 12 calls
    assert len(adapter.calls) == 12


@pytest.mark.asyncio
async def test_hunter_runner_all_calls_share_same_prefix() -> None:
    """Critical for SCAN-010.1 cache prefix-sharing: every call's
    ``system_prefix`` MUST be exactly ``SCAN_PROMPT_SYSTEM``. The
    cache key keys on the prefix block; drift = no cache hit = cost
    explosion."""
    adapter = _FakeHunterAdapter(_full_response_map())
    runner = _build_runner(adapter)
    await runner("app.py", b"x = 1\n", None, "HIGH")

    prefixes = {c["prefix"] for c in adapter.calls}
    assert prefixes == {SCAN_PROMPT_SYSTEM}, (
        f"Hunter calls used {len(prefixes)} distinct prefixes — "
        f"cache prefix-sharing won't work. All calls must send the "
        f"same SCAN_PROMPT_SYSTEM block."
    )


@pytest.mark.asyncio
async def test_hunter_runner_merges_findings_with_dedup() -> None:
    """When two hunters flag the SAME (type, line, code) triple, the
    merge dedups and the collision is counted in telemetry. This is
    the load-bearing guarantee that 10 specialized hunters don't
    produce 10× redundant findings."""
    # Both ssrf and injection hunters return findings on line 7 of the
    # same file — but different types. The dedup key is
    # (type, line, code) so distinct types DON'T collide; the test
    # confirms both findings survive.
    adapter = _FakeHunterAdapter(_full_response_map())
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x = 1\n", None, "HIGH")

    # Injection hunter (1 finding) + ssrf hunter (1 finding) +
    # malicious_intent (0 findings) = 2 unique findings
    assert len(out["vulnerabilities"]) == 2
    types = {v["type"] for v in out["vulnerabilities"]}
    assert "ssrf" in types
    assert "command_injection" in types
    # No collisions because finding types differ.
    assert out["hunter_telemetry"]["n_dedup_collisions"] == 0


@pytest.mark.asyncio
async def test_hunter_runner_dedup_collapses_same_type_line_code() -> None:
    """If two hunters both emit a finding with the SAME (type, line,
    code) triple, only one survives + collision count increments."""
    # Override the injection hunter to ALSO emit an ssrf finding at
    # the same line as the ssrf hunter — manufactured collision.
    responses = _full_response_map()
    responses["Hunt for INJECTION-class vulnerabilities"] = _hunter_response(
        n_findings=1, type_="ssrf", score=55  # same type as ssrf hunter
    )
    # Both hunters' responses now have a finding at line=7, type=ssrf,
    # code="urlopen(url0)" — dedup key collision.

    adapter = _FakeHunterAdapter(responses)
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x = 1\n", None, "HIGH")

    # Only one survives.
    assert len(out["vulnerabilities"]) == 1
    assert out["hunter_telemetry"]["n_dedup_collisions"] == 1


@pytest.mark.asyncio
async def test_hunter_runner_telemetry_block_per_hunter() -> None:
    """``hunter_telemetry.per_hunter`` carries per-hunter validity +
    finding count so operators + bench tooling can see which hunters
    contributed what."""
    adapter = _FakeHunterAdapter(_full_response_map())
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x = 1\n", None, "HIGH")

    tel = out["hunter_telemetry"]
    # Slice 2: full 10-hunter taxonomy is active by default.
    assert tel["n_hunters_active"] == 10
    assert tel["n_hunters_valid"] == 10
    per = tel["per_hunter"]
    # Per-hunter entries present for all 10 hunters.
    expected_keys = {
        "injection",
        "ssrf",
        "malicious_intent",
        "path_traversal",
        "deserialization",
        "prompt_injection",
        "credentials",
        "authz",
        "crypto",
        "exfiltration",
    }
    assert set(per.keys()) == expected_keys
    assert per["ssrf"]["valid"] is True
    assert per["ssrf"]["n_findings"] == 1
    assert per["malicious_intent"]["n_findings"] == 0
    # Slice-2 hunters return 0 findings by default in _full_response_map.
    assert per["path_traversal"]["n_findings"] == 0
    assert per["crypto"]["n_findings"] == 0


@pytest.mark.asyncio
async def test_hunter_runner_picks_max_composite_across_hunters() -> None:
    """Verdict comes from the MAX composite score across hunters —
    the most-confident hunter wins. injection=55, ssrf=70 →
    composite=70 → malicious verdict."""
    adapter = _FakeHunterAdapter(_full_response_map())
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x = 1\n", None, "HIGH")

    # Score 70 → malicious band (50-74)
    assert out["verdict_label"] == "malicious"


@pytest.mark.asyncio
async def test_hunter_runner_model_label_marks_hunter() -> None:
    """Telemetry signal — operators distinguishing hunter runs from
    split / combined runs need a clear label."""
    adapter = _FakeHunterAdapter(_full_response_map())
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x = 1\n", None, "HIGH")
    assert out["model"] == "test-sonnet-hunter"


@pytest.mark.asyncio
async def test_hunter_runner_falls_back_to_split_when_adapter_lacks_prefix_body() -> None:
    """Adapters without ``scan_with_prefix_body`` (test stubs, non-
    Anthropic) get the SCAN-010 split runner — running hunters without
    cache prefix-sharing is economically unsound."""

    class _NoPrefixAdapter:
        """Lacks scan_with_prefix_body — only single-block scan."""

        async def scan(self, content: str, filename: str, system_prompt: str) -> dict:
            return _hunter_response()

    adapter = _NoPrefixAdapter()
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x = 1\n", None, "HIGH")
    # No hunter_telemetry — fell back to split runner.
    assert "hunter_telemetry" not in out
    # Split runner produces split_telemetry instead.
    assert "split_telemetry" in out


@pytest.mark.asyncio
async def test_hunter_runner_subset_via_hunter_set() -> None:
    """``hunter_set=("ssrf",)`` runs only the SSRF hunter, not all 3.
    Operators with targeted threat models reduce cost this way."""
    adapter = _FakeHunterAdapter(_full_response_map())
    runner = _build_runner(adapter, hunter_set=("ssrf",))
    await runner("app.py", b"x = 1\n", None, "HIGH")

    # 1 hunter + behavioral + chains = 3 calls
    assert len(adapter.calls) == 3
    # The one hunter call uses the SSRF body.
    hunter_bodies = [
        c["body_head"] for c in adapter.calls
        if "Hunt for" in c["body_head"]
    ]
    assert len(hunter_bodies) == 1
    assert "SSRF" in hunter_bodies[0]


@pytest.mark.asyncio
async def test_hunter_runner_systemic_failure_when_majority_invalid() -> None:
    """If fewer than 50% of hunters produce valid JSON, surface a
    systemic_failure error rather than ship sparse/empty results."""
    # All 3 hunters return invalid JSON.
    bad = {
        "parsed": None,
        "json_valid": False,
        "input_tokens": 100,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "response_time_ms": 800,
        "error": None,
    }
    responses = {
        "Hunt for INJECTION-class vulnerabilities": bad,
        "Hunt for SSRF (CWE-918) vulnerabilities": bad,
        "Hunt for MALICIOUS-INTENT vulnerabilities": bad,
        "Analyze this file's runtime behavior": _behav_response(),
        "AI tool security issues and multi-step": _chains_response(),
    }
    adapter = _FakeHunterAdapter(responses)
    runner = _build_runner(adapter)
    out = await runner("app.py", b"x = 1\n", None, "HIGH")
    assert out["error"] is not None
    assert "hunter_systemic_failure" in out["error"]


@pytest.mark.asyncio
async def test_hunter_runner_empty_hunter_set_raises() -> None:
    """Passing ``hunter_set=("nonexistent_key",)`` should raise at
    factory construction — fail loudly rather than silently fall
    back to zero hunters."""
    adapter = _FakeHunterAdapter(_full_response_map())
    with pytest.raises(ValueError, match="zero active hunters"):
        _build_runner(adapter, hunter_set=("nonexistent_key",))


def test_attack_class_hunters_dict_has_full_slice_2_taxonomy() -> None:
    """Slice 2 ships the full 10-hunter taxonomy. Catches accidental
    hunter-removal regressions."""
    assert set(ATTACK_CLASS_HUNTERS.keys()) == {
        "injection",
        "ssrf",
        "malicious_intent",
        "path_traversal",
        "deserialization",
        "prompt_injection",
        "credentials",
        "authz",
        "crypto",
        "exfiltration",
    }
    # Each hunter body is non-empty + distinguishable.
    for key, body in ATTACK_CLASS_HUNTERS.items():
        assert len(body) > 500, f"{key} hunter body suspiciously short"
        # Hunter bodies should NOT contain SCAN_PROMPT_SYSTEM text —
        # that's in the cacheable prefix, not duplicated here.
        assert "INTENT-AWARE REASONING" not in body, (
            f"{key} hunter body duplicates SCAN_REASONING_RULES content"
        )
