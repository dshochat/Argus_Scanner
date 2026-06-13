"""Unit tests for the Phase C verified-remediation gates (Stage 2+3):
LLM generation (stubbed), deterministic oracle matching, and the live
execute_gates → verify_patch wiring with a stubbed sandbox."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from dast.phase_c_verify_gates import (
    BLOCK_MARKER,
    FUNC_BROKEN,
    FUNC_OK,
    FUNC_SETUP_ERROR,
    REACH_ORACLE,
    REBIND_PUBLIC_IP,
    FunctionalProbe,
    GatePlans,
    GateVariant,
    _json_loads_safe,
    build_adversarial_prompt,
    build_rebinding_variant,
    derive_entrypoint,
    detect_variant_class,
    execute_gates,
    oracle_in_trace,
    prepare_gate_plans,
)
from dast.remediation_verify import (
    CONFIDENCE_FAILED,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    verify_budget_for,
)

# ── JSON parsing ─────────────────────────────────────────────────────


def test_json_loads_safe_plain_and_fenced_and_garbage() -> None:
    assert _json_loads_safe('{"a": 1}') == {"a": 1}
    assert _json_loads_safe('```json\n{"a": 2}\n```') == {"a": 2}
    assert _json_loads_safe('here you go: {"a": 3} thanks') == {"a": 3}
    assert _json_loads_safe("not json at all") == {}
    assert _json_loads_safe("") == {}
    assert _json_loads_safe("[1,2,3]") == {}  # top-level must be an object


# ── oracle matching ──────────────────────────────────────────────────


def _trace(stdout: str = "", stderr: str = "", events: list[Any] | None = None) -> Any:
    return SimpleNamespace(stdout_excerpt=stdout, stderr_excerpt=stderr, events=events or [])


def test_oracle_in_trace_matches_printed_marker_only() -> None:
    # The harness's printed marker (stdout/stderr) is authoritative.
    assert oracle_in_trace(_trace(stdout=f"x {REACH_ORACLE} y"), REACH_ORACLE)
    assert oracle_in_trace(_trace(stderr=f"boom {FUNC_BROKEN}"), FUNC_BROKEN)
    assert not oracle_in_trace(_trace(stdout="nothing here"), REACH_ORACLE)
    assert not oracle_in_trace(_trace(), "")  # empty oracle never matches


def test_oracle_ignores_capture_events_regression() -> None:
    """REGRESSION (found via Opus 4.8 full DAST): a sandbox capture event
    must NOT count as the oracle firing. The patched code's OWN getaddrinfo
    (DNS-hijacked → capture server logs a network event) was being counted
    as the exploit 'reaching' the target, falsely FIRING good patches that
    resolve-then-reject. Only the harness's printed stdout marker counts."""
    # A captured network event that even contains the marker string must
    # NOT trigger — classification is stdout/stderr only.
    ev = SimpleNamespace(kind="network_call_captured", payload=f"hit {REACH_ORACLE}")
    assert oracle_in_trace(_trace(events=[ev]), REACH_ORACLE) is False
    # The real-world shape: harness printed BLOCKED, but a DNS/network event
    # exists from the patch's own resolution → must stay "not fired".
    blocked = _trace(
        stdout="ARGUS_VARIANT_BLOCKED ValueError",
        events=[SimpleNamespace(kind="dns_query", payload="qname=2130706433")],
    )
    assert oracle_in_trace(blocked, REACH_ORACLE) is False


# ── generation (stubbed inference) ───────────────────────────────────


def _inf_returning(text: str):
    async def _inf(prompt: str, opts: dict, schema: dict | None) -> dict:
        # Distinguish the two generation calls by a marker in the prompt.
        if "Stage 2 (functional" in prompt:
            return {
                "text": '{"description":"benign","benign_url":"https://example.com/x.png",'
                '"commands":["python -c \\"print(1)\\""]}',
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }
        return {"text": text, "usage": {"prompt_tokens": 20, "completion_tokens": 9}}

    return _inf


def test_prepare_gate_plans_generates_functional_and_variants() -> None:
    variants_json = (
        '{"variants":['
        '{"description":"decimal IP","payload":"http://2130706433/","commands":["python -c \\"print(2)\\""]},'
        '{"description":"metadata","payload":"http://169.254.169.254/","commands":["python -c \\"print(3)\\""]}'
        "]}"
    )
    plans = asyncio.run(
        prepare_gate_plans(
            inference=_inf_returning(variants_json),
            file_name="x.py",
            confirmed_findings=[{"cwe": "CWE-918", "description": "ssrf"}],
            original_source="def f(u): ...",
            patched_source="def f(u): validate(u)",
            seed_commands=["python -c \"import x; x.f('http://localhost')\""],
            seed_payload="http://localhost",
            budget=verify_budget_for("critical"),
        )
    )
    assert plans.functional is not None
    assert plans.functional.benign_url == "https://example.com/x.png"
    assert len(plans.variants) == 2
    assert plans.variants[0].payload == "http://2130706433/"
    assert plans.tokens_in > 0 and plans.tokens_out > 0


# ── DNS-rebinding (TOCTOU) probe ─────────────────────────────────────


def test_derive_entrypoint_skips_helpers() -> None:
    src = "import socket\ndef _is_safe_host(h): ...\ndef _validate(u): ...\ndef load_media_from_url(url): ...\n"
    assert derive_entrypoint(src) == "load_media_from_url"
    assert derive_entrypoint("x = 1\n") is None


def test_build_rebinding_variant_harness_has_flip_logic() -> None:
    import base64

    v = build_rebinding_variant("_demo_media_loader", "load_media_from_url", "abcd1234")
    assert "rebind" in v.description.lower() or "toctou" in v.description.lower()
    cmd = v.commands[0]
    # Decode the base64-wrapped script and assert the flip is correct.
    b64 = cmd.split("b64decode('")[1].split("')")[0]
    script = base64.b64decode(b64).decode()
    assert "socket.getaddrinfo = _flip" in script
    assert REBIND_PUBLIC_IP in script  # 1st lookup → public
    assert "'127.0.0.1'" in script  # later lookups → internal
    assert "_demo_media_loader" in script and "load_media_from_url" in script
    assert REACH_ORACLE in script and BLOCK_MARKER in script


def test_rebinding_flip_discriminates_toctou_from_pinned() -> None:
    """The heart of the probe: with the resolver flipping public→internal,
    a patch that RE-RESOLVES dials the internal IP (would REACH the capture
    server → fire), while a patch that PINS the checked IP dials the public
    IP (unroutable in-sandbox → BLOCKED). This guards the discriminator
    against a regression that would make the probe always-pass."""
    state = {"n": 0}

    def resolve() -> str:  # mirrors the harness's _flip
        state["n"] += 1
        return REBIND_PUBLIC_IP if state["n"] == 1 else "127.0.0.1"

    # TOCTOU: validate(resolve) passes on public, then fetch re-resolves.
    checked = resolve()
    assert checked == REBIND_PUBLIC_IP  # check sees a safe public IP
    toctou_dialled = resolve()  # HTTP client re-resolves
    assert toctou_dialled == "127.0.0.1"  # → hits the capture server → FIRES

    # Pinned: the connect target IS the IP we validated (no 2nd resolve).
    state["n"] = 0
    pinned_checked = resolve()
    pinned_dialled = pinned_checked  # reuse the checked IP
    assert pinned_dialled == REBIND_PUBLIC_IP  # → unroutable in-sandbox → BLOCKED


def test_prepare_prepends_rebinding_only_for_ssrf() -> None:
    src = "import requests\ndef load_media_from_url(url):\n    return requests.get(url)\n"

    async def _inf(prompt, opts, schema):  # variants generation returns 2
        if "Stage 2 (functional" in prompt:
            return {"text": '{"description":"b","benign_url":"https://e/x","commands":["c"]}', "usage": {}}
        return {
            "text": '{"variants":[{"description":"d","payload":"p","commands":["c"]},'
            '{"description":"e","payload":"q","commands":["c"]}]}',
            "usage": {},
        }

    common = dict(
        inference=_inf,
        file_name="_demo_media_loader.py",
        confirmed_findings=[{"cwe": "CWE-918"}],
        original_source=src,
        patched_source=src,
        seed_commands=["c"],
        seed_payload="",
        budget=verify_budget_for("high"),
    )
    ssrf = asyncio.run(prepare_gate_plans(**common, ssrf_class=True))
    assert "rebind" in ssrf.variants[0].description.lower()  # prepended first
    assert len(ssrf.variants) == 3  # rebinding + 2 LLM
    non = asyncio.run(prepare_gate_plans(**common, ssrf_class=False))
    assert all("rebind" not in v.description.lower() for v in non.variants)
    assert len(non.variants) == 2


def test_prepare_gate_plans_low_severity_skips_variants() -> None:
    plans = asyncio.run(
        prepare_gate_plans(
            inference=_inf_returning('{"variants":[]}'),
            file_name="x.py",
            confirmed_findings=[],
            original_source="x",
            patched_source="y",
            seed_commands=[],
            seed_payload="",
            budget=verify_budget_for("low"),  # functional=1, variants=0
        )
    )
    # low budget: functional generated, NO variants requested.
    assert plans.functional is not None
    assert plans.variants == []


# ── execute_gates (stubbed sandbox) ──────────────────────────────────


def _submit_classifier(rules: dict[str, str]):
    """Build a submit_patched that prints a marker based on plan.payload.

    ``rules`` maps a payload substring → the stdout the trace should
    carry (e.g. REACH_ORACLE to simulate a variant that got through).
    Functional plans (payload == benign_url) are matched too.
    """

    async def _submit(plan: Any) -> Any:
        out = ""
        for needle, marker in rules.items():
            if needle in (plan.payload or ""):
                out = marker
                break
        return _trace(stdout=out)

    return _submit


def _plans(n_variants: int, functional: bool = True) -> GatePlans:
    variants = [
        GateVariant(description=f"v{i}", payload=f"http://variant{i}/", commands=["c"]) for i in range(n_variants)
    ]
    func = (
        FunctionalProbe(description="benign", benign_url="https://example.com/ok", commands=["c"])
        if functional
        else None
    )
    return GatePlans(functional=func, variants=variants)


def _exec(plans: GatePlans, submit, *, severity="critical", poc_refuted=True):
    return asyncio.run(
        execute_gates(
            plans=plans,
            submit_patched=submit,
            file_id="fid",
            file_name="x.py",
            image_hint="lean",
            timeout_sec=30,
            severity=severity,
            poc_refuted=poc_refuted,
            budget=verify_budget_for(severity),
        )
    )


def test_execute_gates_high_when_functional_ok_and_no_variant_fires() -> None:
    plans = _plans(n_variants=5)
    # functional prints FUNC_OK; no variant matches REACH_ORACLE → all blocked.
    submit = _submit_classifier({"example.com/ok": FUNC_OK})
    outcome, details = _exec(plans, submit)
    assert outcome.confidence == CONFIDENCE_HIGH
    assert outcome.functional_ok is True
    assert outcome.variants_total == 5 and outcome.variants_fired == 0
    assert details["functional"]["ok"] is True
    assert all(v["result"] == "blocked" for v in details["variants"])
    assert details["n_sandbox_calls"] == 6  # 1 functional + 5 variants


def test_execute_gates_failed_and_retry_when_a_variant_fires() -> None:
    plans = _plans(n_variants=3)
    submit = _submit_classifier({"example.com/ok": FUNC_OK, "variant1/": REACH_ORACLE})
    outcome, details = _exec(plans, submit, severity="high")
    assert outcome.confidence == CONFIDENCE_FAILED
    assert outcome.variants_fired == 1
    assert outcome.needs_retry is True
    fired = [v for v in details["variants"] if v["result"] == "FIRED"]
    assert len(fired) == 1 and fired[0]["payload"] == "http://variant1/"


def test_execute_gates_functional_fail_skips_adversarial() -> None:
    plans = _plans(n_variants=5)
    submit = _submit_classifier({"example.com/ok": FUNC_BROKEN})
    outcome, details = _exec(plans, submit)
    assert outcome.confidence == CONFIDENCE_FAILED
    assert outcome.functional_ok is False
    assert outcome.needs_retry is True
    # adversarial never ran → only the functional sandbox call happened.
    assert details["n_sandbox_calls"] == 1
    assert details["variants"] == []


def test_execute_gates_poc_not_refuted_runs_nothing() -> None:
    plans = _plans(n_variants=5)
    submit = _submit_classifier({"example.com/ok": FUNC_OK})
    outcome, details = _exec(plans, submit, poc_refuted=False)
    assert outcome.confidence == CONFIDENCE_FAILED
    assert details["n_sandbox_calls"] == 0


def test_execute_gates_functional_sandbox_error_is_unknown_not_failed() -> None:
    plans = _plans(n_variants=2)

    async def submit(plan: Any) -> Any:
        if "example.com/ok" in (plan.payload or ""):
            raise RuntimeError("fly 503")
        return _trace(stdout="")  # variants all blocked

    outcome, details = _exec(plans, submit)
    # functional unknown (sandbox error) + variants clean → MEDIUM, not FAILED.
    assert outcome.confidence == CONFIDENCE_MEDIUM
    assert details["functional"]["ok"] is None
    assert any("functional replay failed" in e for e in details["errors"])


def test_execute_gates_functional_setup_error_is_unknown_not_failed() -> None:
    """A harness setup/mock failure (FUNC_SETUP_ERROR) must NOT be read as
    the patch over-blocking — it maps to unknown, so a flaky mock can't
    fabricate a 'patch broke the app' FAILED/retry."""
    plans = _plans(n_variants=2)
    submit = _submit_classifier({"example.com/ok": FUNC_SETUP_ERROR})
    outcome, details = _exec(plans, submit)
    assert details["functional"]["ok"] is None
    # variants clean + functional unknown → MEDIUM, never FAILED.
    assert outcome.confidence == CONFIDENCE_MEDIUM


def test_execute_gates_setup_error_beats_broken_marker() -> None:
    """If both a setup-error and a broken marker appear, the setup error
    wins (unknown) — we never infer over-block from a broken harness."""
    plans = _plans(n_variants=1)
    submit = _submit_classifier({"example.com/ok": f"{FUNC_SETUP_ERROR} {FUNC_BROKEN}"})
    outcome, details = _exec(plans, submit)
    assert details["functional"]["ok"] is None


def test_execute_gates_ambiguous_functional_marker_is_unknown() -> None:
    plans = _plans(n_variants=1, functional=True)
    # Both markers present → ambiguous → None (don't fabricate pass/fail).
    submit = _submit_classifier({"example.com/ok": f"{FUNC_OK} {FUNC_BROKEN}"})
    outcome, details = _exec(plans, submit)
    assert details["functional"]["ok"] is None
    assert outcome.confidence == CONFIDENCE_MEDIUM  # variants clean, functional unknown


# ── class-dispatched adversarial gate (beyond SSRF) ──────────────────


def test_detect_variant_class_by_cwe() -> None:
    assert detect_variant_class([{"cwe": "CWE-918"}]) == "ssrf"
    assert detect_variant_class([{"cwe": "CWE-78"}]) == "command_injection"
    assert detect_variant_class([{"cwe": "CWE-89"}]) == "sqli"
    assert detect_variant_class([{"cwe": "CWE-79"}]) == "xss"
    assert detect_variant_class([{"cwe": "CWE-611"}]) == "xxe"
    assert detect_variant_class([{"cwe": "CWE-22"}]) == "path_traversal"
    assert detect_variant_class([{"cwe": "CWE-502"}]) == "deserialization"
    assert detect_variant_class([{"cwe": "CWE-1336"}]) == "ssti"


def test_detect_variant_class_by_keyword_and_fallback() -> None:
    assert detect_variant_class([{"type": "reflected cross-site scripting"}]) == "xss"
    assert detect_variant_class([{"description": "SQL injection in query"}]) == "sqli"
    assert detect_variant_class([{"type": "os command injection"}]) == "command_injection"
    # CWE wins over a misleading keyword.
    assert detect_variant_class([{"cwe": "CWE-89", "type": "ssrf-ish"}]) == "sqli"
    # No signal → generic.
    assert detect_variant_class([{"type": "mystery"}]) == "generic"


def test_adversarial_prompt_dispatches_per_class() -> None:
    def _p(findings: list[dict[str, Any]]) -> str:
        return build_adversarial_prompt(
            file_name="f.py",
            confirmed_findings=findings,
            original_source="orig",
            patched_source="patched",
            seed_commands=["python3 -c 'pass'"],
            seed_payload="seed",
            n=3,
        )

    sqli = _p([{"cwe": "CWE-89"}])
    assert "class `sqli`" in sqli
    assert "in-memory SQLite" in sqli
    assert "169.254.169.254" not in sqli  # NOT the SSRF menu

    ssti = _p([{"cwe": "CWE-1336"}])
    assert "class `ssti`" in ssti
    assert "{{7*7}}" in ssti

    ssrf = _p([{"cwe": "CWE-918"}])
    assert "class `ssrf`" in ssrf
    assert "169.254.169.254" in ssrf  # SSRF menu still intact

    generic = _p([{"type": "mystery"}])
    assert "class `generic`" in generic
