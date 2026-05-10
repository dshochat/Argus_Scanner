"""Unit tests for dast/runtime_probe.py — Phase B+ runtime exploit probing.

Covers:
* Attack-class → CWE / severity mapping (fallbacks for unknown classes)
* Python harness generation (module-name derivation, getattr walk for
  ``Class.method``, args/kwargs decoding)
* Plan builder (returns None on non-Python files, embeds payload b64,
  generates HRP_<idx>_<idx> hypothesis IDs)
* Trace parser (RESULT_JSON / SIDE_EFFECTS marker recovery, defensive
  on truncated / broken-JSON stdout)
* Trace interpreter rules (rule 1: function returned ok on attack
  input; rule 2: canary tmp file observed; both fire = finding; neither
  fires = None)
* Schema validation (probe-candidate schema enforces shape +
  attack_class enum)

No live API; no sandbox booted. Uses synthetic SandboxTrace-shape
objects for the trace path.
"""

from __future__ import annotations

import base64
import json

import pytest

from dast import prompts as dast_prompts
from dast.runtime_probe import (
    DEFAULT_PROBE_TIMEOUT_SEC,
    MAX_CANDIDATES,
    MAX_INPUTS_PER_CANDIDATE,
    MAX_PROBE_RUNS_PER_FILE,
    RuntimeProbeCandidate,
    RuntimeProbeInput,
    _build_python_probe_harness,
    _python_module_name_for_file,
    build_runtime_probe_plan,
    cwe_for_attack_class,
    interpret_probe_trace,
    parse_probe_trace,
    severity_for_attack_class,
)

# ── Attack-class mapping ───────────────────────────────────────────────


def test_cwe_for_known_attack_classes() -> None:
    """Each documented attack class maps to a real CWE id."""
    assert cwe_for_attack_class("path_traversal") == "CWE-22"
    assert cwe_for_attack_class("command_injection") == "CWE-78"
    assert cwe_for_attack_class("code_injection") == "CWE-94"
    assert cwe_for_attack_class("deserialization") == "CWE-502"
    assert cwe_for_attack_class("sql_injection") == "CWE-89"
    assert cwe_for_attack_class("ssrf") == "CWE-918"


def test_cwe_for_unknown_attack_class_falls_back() -> None:
    """Unknown attack classes fall back to CWE-1035 (improper input
    validation) so finding emission never crashes on model-generated
    unknown class strings."""
    assert cwe_for_attack_class("alien_invasion") == "CWE-1035"
    assert cwe_for_attack_class("") == "CWE-1035"


def test_severity_for_known_attack_classes() -> None:
    assert severity_for_attack_class("code_injection") == "critical"
    assert severity_for_attack_class("command_injection") == "critical"
    assert severity_for_attack_class("path_traversal") == "high"
    assert severity_for_attack_class("xss") == "medium"


def test_severity_for_unknown_attack_class_falls_back_to_medium() -> None:
    assert severity_for_attack_class("alien_invasion") == "medium"


# ── Module-name derivation ─────────────────────────────────────────────


def test_module_name_strips_py_extension() -> None:
    assert _python_module_name_for_file("vulnerable_lib.py") == "vulnerable_lib"
    assert _python_module_name_for_file("foo.py") == "foo"


def test_module_name_uses_basename_for_path_inputs() -> None:
    """Sandbox stages files at /workspace/<basename>, so module name
    must derive from the basename, not the full path."""
    assert _python_module_name_for_file("mypkg/io_utils.py") == "io_utils"
    assert _python_module_name_for_file("/abs/path/to/module.py") == "module"


def test_module_name_replaces_illegal_chars() -> None:
    """Hyphens / dots aren't valid in Python module names — replaced
    with underscores so the harness ``import`` succeeds."""
    assert _python_module_name_for_file("foo-bar-baz.py") == "foo_bar_baz"
    assert _python_module_name_for_file("dotted.file.name.py") == "dotted_file_name"


# ── Harness generation ─────────────────────────────────────────────────


def test_harness_contains_module_import_and_function_call() -> None:
    """Generated harness should import the target module, walk the
    function path with getattr, then call with decoded args/kwargs."""
    h = _build_python_probe_harness(
        module_name="vulnerable_lib",
        function_name="read_file",
        args_json='["../etc/passwd"]',
        kwargs_json="{}",
    )
    assert "import vulnerable_lib as _target" in h
    assert "for part in 'read_file'.split('.'):" in h
    assert "fn = getattr(fn, part)" in h
    # Args / kwargs JSON literals embedded as Python string repr (not
    # f-substituted to avoid shell-quote hell)
    assert "args = json.loads(" in h
    assert "kwargs = json.loads(" in h


def test_harness_supports_class_method_path() -> None:
    """For ``Class.method`` paths the harness's getattr walk recovers
    both segments."""
    h = _build_python_probe_harness(
        module_name="evil_mod",
        function_name="SafeLoader.load",
        args_json='["data"]',
        kwargs_json="{}",
    )
    assert "for part in 'SafeLoader.load'.split('.'):" in h


def test_harness_emits_result_json_and_side_effects_markers() -> None:
    """Harness output is parsed via the ``RESULT_JSON:`` / ``SIDE_EFFECTS:``
    line markers — they must be in the generated code."""
    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    assert "RESULT_JSON:" in h
    assert "SIDE_EFFECTS:" in h
    # Side-effect diff = post-call /tmp listing minus baseline
    assert "tmp_files_added" in h


def test_harness_captures_exceptions_without_crashing() -> None:
    """Harness wraps the call in try/except so a raised exception
    still produces a marker line."""
    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    assert "except BaseException" in h or "except SystemExit" in h
    assert "exception_type" in h


# ── Plan builder ──────────────────────────────────────────────────────


def _mk_candidate(**kwargs):
    """Convenience: build a RuntimeProbeCandidate with one input."""
    defaults = dict(
        function_name="read_file",
        attack_class="path_traversal",
        rationale="reads filesystem path from user input",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["../etc/passwd"]',
                kwargs_json="{}",
                expected_observable="reads /etc/passwd content",
                exploit_proof_if_observed="path traversal — reads files outside intended dir",
            )
        ],
    )
    defaults.update(kwargs)
    return RuntimeProbeCandidate(**defaults)


def test_build_plan_basic_shape() -> None:
    plan = build_runtime_probe_plan(
        file_name="vuln.py",
        file_bytes=b"def read_file(p):\n    return open(p).read()\n",
        candidate=_mk_candidate(),
        test_input=_mk_candidate().test_inputs[0],
        candidate_idx=0,
        input_idx=0,
    )
    assert plan is not None
    assert plan["hypothesis_id"] == "HRP_0_0"
    assert plan["plan_status"] == "executable"
    assert plan["oracle"] == "execution_output_with_side_effect_observation"
    assert plan["payload_encoding"] == "base64"
    assert plan["timeout_sec"] == DEFAULT_PROBE_TIMEOUT_SEC
    # Payload decodes back to the original file bytes
    assert base64.b64decode(plan["payload"]) == b"def read_file(p):\n    return open(p).read()\n"


def test_build_plan_returns_none_for_non_python_file() -> None:
    """v1.5 MVP scope — Python only. Non-Python files should produce
    None so the orchestrator skips them gracefully."""
    plan = build_runtime_probe_plan(
        file_name="foo.js",
        file_bytes=b"function f(p) {}",
        candidate=_mk_candidate(),
        test_input=_mk_candidate().test_inputs[0],
        candidate_idx=0,
        input_idx=0,
    )
    assert plan is None


def test_build_plan_commands_write_then_run_harness() -> None:
    """The plan's two commands should (a) decode the b64 harness into
    /workspace and (b) invoke python3 against it. Avoids shell-quoting
    the harness inline."""
    plan = build_runtime_probe_plan(
        file_name="vuln.py",
        file_bytes=b"# stub",
        candidate=_mk_candidate(),
        test_input=_mk_candidate().test_inputs[0],
        candidate_idx=0,
        input_idx=0,
    )
    assert plan is not None
    assert len(plan["commands"]) == 2
    # First command writes the harness to /workspace
    assert "base64.b64decode" in plan["commands"][0]
    assert "/workspace/_argus_probe_0_0.py" in plan["commands"][0]
    # Second runs it
    assert "python3 /workspace/_argus_probe_0_0.py" in plan["commands"][1]


def test_build_plan_hypothesis_id_uses_candidate_input_indices() -> None:
    plan = build_runtime_probe_plan(
        file_name="x.py",
        file_bytes=b"",
        candidate=_mk_candidate(),
        test_input=_mk_candidate().test_inputs[0],
        candidate_idx=2,
        input_idx=1,
    )
    assert plan is not None
    assert plan["hypothesis_id"] == "HRP_2_1"
    assert "_argus_probe_2_1.py" in plan["commands"][0]


# ── Trace parsing ──────────────────────────────────────────────────────


def test_parse_trace_recovers_result_json_marker() -> None:
    stdout = (
        "some warning to stderr-but-on-stdout\n"
        'RESULT_JSON:{"ok": true, "type": "str", "value_preview": "root:x:0:0"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": []}\n'
    )
    trace = parse_probe_trace(
        candidate_function="read_file",
        input_args_json='["../etc/passwd"]',
        exit_code=0,
        stdout=stdout,
        stderr="",
        elapsed_ms=120,
    )
    assert trace.parsed_result is not None
    assert trace.parsed_result["ok"] is True
    assert trace.parsed_result["value_preview"] == "root:x:0:0"
    assert trace.side_effects == {"tmp_files_added": []}


def test_parse_trace_recovers_canary_files_in_side_effects() -> None:
    stdout = (
        'RESULT_JSON:{"ok": false, "exception_type": "OSError"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned", "other.tmp"]}\n'
    )
    trace = parse_probe_trace(
        candidate_function="write_file",
        input_args_json='["/tmp/argus_probe_pwned", "data"]',
        exit_code=1,
        stdout=stdout,
        stderr="",
        elapsed_ms=50,
    )
    assert trace.side_effects["tmp_files_added"] == ["argus_probe_pwned", "other.tmp"]


def test_parse_trace_tolerates_broken_json_in_markers() -> None:
    """A truncated or malformed RESULT_JSON line must not crash the
    parser — the trace just has parsed_result=None and we move on."""
    stdout = "RESULT_JSON:{this is not valid json}\nSIDE_EFFECTS:also broken\n"
    trace = parse_probe_trace(
        candidate_function="f",
        input_args_json="[]",
        exit_code=0,
        stdout=stdout,
        stderr="",
        elapsed_ms=10,
    )
    assert trace.parsed_result is None
    assert trace.side_effects == {}


def test_parse_trace_handles_empty_stdout() -> None:
    """No markers at all = harness crashed pre-print. Trace fields stay
    at their sentinels."""
    trace = parse_probe_trace(
        candidate_function="f",
        input_args_json="[]",
        exit_code=137,  # killed
        stdout="",
        stderr="Segmentation fault",
        elapsed_ms=5,
    )
    assert trace.parsed_result is None
    assert trace.side_effects == {}
    assert trace.exit_code == 137


# ── Trace interpretation rules ─────────────────────────────────────────


def test_interpret_rule1_function_returned_ok_on_attack_input_emits_finding() -> None:
    """Rule 1: function succeeded on attack input the model said
    should be rejected → CONFIRMED finding via runtime evidence."""
    candidate = _mk_candidate()
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": true, "type": "str", '
            '"value_preview": "root:x:0:0:root:/root:/bin/bash..."}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=80,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    assert finding.finding_id == "HRP_0_0"
    assert finding.attack_class == "path_traversal"
    assert finding.cwe == "CWE-22"
    assert finding.severity == "high"
    assert "Function returned without raising" in finding.runtime_evidence
    # The attack input gets pasted into the proof for repro
    assert finding.test_input_args == '["../etc/passwd"]'


def test_interpret_rule2_canary_tmp_file_emits_finding() -> None:
    """Rule 2: harness raised, but the sandbox observed a canary file
    materialize in /tmp → exploit fired via side effects → finding."""
    candidate = _mk_candidate(
        attack_class="code_injection",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["__import__(\\"os\\").system(\\"touch /tmp/argus_probe_pwned\\")"]',
                kwargs_json="{}",
                expected_observable="canary file /tmp/argus_probe_pwned appears",
                exploit_proof_if_observed="eval injection — runs arbitrary code",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "SyntaxError"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned"]}\n'
        ),
        stderr="SyntaxError: invalid syntax",
        elapsed_ms=30,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    assert finding.attack_class == "code_injection"
    assert finding.cwe == "CWE-94"
    assert finding.severity == "critical"
    assert "argus_probe_pwned" in finding.runtime_evidence


def test_interpret_function_raised_no_canary_returns_none() -> None:
    """Function raised an exception AND no side-effect canary observed
    = BLOCKED-equivalent. No finding emitted."""
    candidate = _mk_candidate()
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "PermissionError", '
            '"exception_msg": "[Errno 13] Permission denied: \'../etc/passwd\'"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=20,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None


def test_interpret_no_parsed_result_returns_none() -> None:
    """Harness crashed before printing the marker. Inconclusive — no
    finding (we don't claim exploit on garbage traces)."""
    candidate = _mk_candidate()
    test_in = candidate.test_inputs[0]
    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=137,
        stdout="",
        stderr="Killed",
        elapsed_ms=5,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None


def test_interpret_both_rules_fire_emits_single_finding() -> None:
    """If function returned ok AND canary appeared, we emit ONE finding
    with both evidence parts (not two findings — same probe = same
    vulnerability)."""
    candidate = _mk_candidate(
        attack_class="command_injection",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["touch /tmp/argus_probe_pwned"]',
                kwargs_json="{}",
                expected_observable="canary file appears AND function returns successfully",
                exploit_proof_if_observed="command injection — both signals fire",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": true, "type": "int", "value_preview": "0"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned"]}\n'
        ),
        stderr="",
        elapsed_ms=40,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    # Both evidence parts in the runtime_evidence string
    assert "Function returned without raising" in finding.runtime_evidence
    assert "argus_probe_pwned" in finding.runtime_evidence


# ── Schema validation ──────────────────────────────────────────────────


def test_runtime_probe_schema_has_required_top_level() -> None:
    schema = dast_prompts.phase_b_runtime_probe_schema()
    assert schema["type"] == "object"
    assert set(schema["required"]) == {"candidates", "non_probable_reason"}
    assert schema["additionalProperties"] is False


def test_runtime_probe_schema_bounds_candidate_count() -> None:
    schema = dast_prompts.phase_b_runtime_probe_schema()
    assert schema["properties"]["candidates"]["maxItems"] == 3


def test_runtime_probe_schema_bounds_inputs_per_candidate() -> None:
    schema = dast_prompts.phase_b_runtime_probe_schema()
    candidate_schema = schema["properties"]["candidates"]["items"]
    assert candidate_schema["properties"]["test_inputs"]["maxItems"] == 3


def test_runtime_probe_schema_function_name_regex_blocks_bad_names() -> None:
    """The schema's regex must reject pathological function names a
    model might invent — newlines, shell metacharacters, etc."""
    import re

    schema = dast_prompts.phase_b_runtime_probe_schema()
    pattern = schema["properties"]["candidates"]["items"]["properties"]["function_name"]["pattern"]
    regex = re.compile(pattern)
    # Accepted
    assert regex.match("read_file")
    assert regex.match("MyClass.method")
    assert regex.match("_private_fn")
    # Rejected — would be a security issue if Sonnet emitted these
    assert not regex.match("foo;rm -rf /")
    assert not regex.match("foo`bar`")
    assert not regex.match("foo$(touch /tmp/pwn)")
    assert not regex.match("foo\nbar")
    # Note: ``__import__`` IS a valid identifier under the regex and
    # therefore allowed through. That's safe — the harness's getattr
    # walk would resolve it to the builtin, but invoking it doesn't
    # leak the way shell metacharacter injection would. The regex's
    # job is to block injection chars, not philosophical name choices.


def test_runtime_probe_schema_attack_class_enum() -> None:
    """attack_class is an enum — model can't invent random strings."""
    schema = dast_prompts.phase_b_runtime_probe_schema()
    attack_class_schema = schema["properties"]["candidates"]["items"]["properties"]["attack_class"]
    assert "path_traversal" in attack_class_schema["enum"]
    assert "command_injection" in attack_class_schema["enum"]
    assert "code_injection" in attack_class_schema["enum"]
    assert "deserialization" in attack_class_schema["enum"]


# ── Prompt builder ─────────────────────────────────────────────────────


def test_build_phase_b_runtime_probe_prompt_includes_file_text() -> None:
    """The probe prompt embeds the file contents so the model can see
    the function signatures it's nominating."""
    file_text = "def vulnerable(p):\n    return open(p).read()\n"
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}
    prompt = dast_prompts.build_phase_b_runtime_probe_prompt(
        file_text=file_text,
        l1_output=l1_output,
        journal_summary={},
    )
    assert file_text in prompt
    # The prompt's design-principle sections are present
    assert "adversarial penetration tester" in prompt
    assert "RESULT_JSON" in prompt or "expected_observable" in prompt
    # Caps surfaced from the runtime_probe constants
    assert str(MAX_CANDIDATES) in prompt
    assert str(MAX_INPUTS_PER_CANDIDATE) in prompt


# ── Constants sanity ───────────────────────────────────────────────────


def test_max_probe_runs_equals_candidates_times_inputs() -> None:
    """The bound should hold so the orchestrator's hard cap is consistent."""
    assert MAX_PROBE_RUNS_PER_FILE == MAX_CANDIDATES * MAX_INPUTS_PER_CANDIDATE


# ── Orchestrator integration (stub sandbox + fake inference) ──────────


from dataclasses import dataclass  # noqa: E402
from dataclasses import field as dc_field
from pathlib import Path  # noqa: E402

from dast.orchestrator import run_dast  # noqa: E402
from dast.sandbox.client import SandboxEvent, SandboxPlan, SandboxTrace  # noqa: E402
from dast.validator import HypothesisValidator  # noqa: E402


@dataclass
class _CapturingProbeSandbox:
    """Stub sandbox that captures every submitted plan and returns a
    canned trace per (candidate_idx, input_idx) pair.

    ``traces_by_hypothesis`` is a map from ``HRP_<c>_<i>`` → dict shape
    ``{stdout, stderr, exit_code, elapsed_ms}`` that drives the
    response. Plans for non-HRP hypothesis_ids return a benign default
    trace (used for normal Phase A plans the orchestrator also emits)."""

    submitted_plans: list[SandboxPlan] = dc_field(default_factory=list)
    file_content_map: dict[str, bytes] = dc_field(default_factory=dict)
    traces_by_hypothesis: dict[str, dict] = dc_field(default_factory=dict)

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        self.submitted_plans.append(plan)
        cfg = self.traces_by_hypothesis.get(plan.hypothesis_id, {})
        evt = SandboxEvent(
            event_id=f"evt-{plan.hypothesis_id}",
            kind="execution_output",
            payload={"hypothesis_id": plan.hypothesis_id},
        )
        return SandboxTrace(
            plan_id=plan.plan_id,
            file_id=plan.file_id,
            hypothesis_id=plan.hypothesis_id,
            events=[evt],
            exit_code=cfg.get("exit_code", 0),
            stdout_excerpt=cfg.get("stdout", ""),
            stderr_excerpt=cfg.get("stderr", ""),
            elapsed_ms=cfg.get("elapsed_ms", 10),
        )


def _phase_b_probe_response(candidates: list[dict]) -> str:
    """Stub Sonnet response shape for Phase B+ candidate generation."""
    return json.dumps(
        {
            "non_probable_reason": "" if candidates else "no probe-attractive functions",
            "candidates": candidates,
        }
    )


def _phase_a_verdict_response() -> str:
    """Minimal Phase A verdict JSON the orchestrator's parser accepts."""
    return json.dumps(
        {
            "verdict_label": "malicious",
            "log_summary": "stub",
            "validated_findings": [],
            "confirmed_categories": [],
        }
    )


def _phase_b_response() -> str:
    """Minimal Phase B JSON — zero new hypotheses → loop terminates."""
    return json.dumps(
        {
            "stop_reason": "no_new_hypotheses",
            "non_code_regions_inspected": [],
            "new_hypotheses": [],
        }
    )


@pytest.mark.asyncio
async def test_runtime_probe_skipped_when_flag_disabled(tmp_path) -> None:
    """``enable_runtime_probe=False`` (default) → the probe stage never
    fires, no candidate-generation inference call. Sanity guard so
    existing v1.3.x install runs don't suddenly start paying probe cost."""
    sandbox = _CapturingProbeSandbox()
    inference_calls: list[tuple] = []

    async def fake_inference(prompt, options, schema):
        inference_calls.append((prompt[:50], schema.get("required", [])))
        # Detect whether this is the probe schema (would be wrong here)
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            raise AssertionError(
                "runtime probe inference should not be called when enable_runtime_probe is False"
            )
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "py-hash",
        "source_text": "def read_file_safely(p): return open(p).read()\n",
        "file_name": "vuln.py",
        "ml_format": None,
        "original_bytes": b"def read_file_safely(p): return open(p).read()\n",
    }
    l1_output = {
        "verdict": {"verdict_label": "malicious"},
        "hypotheses": [],  # no L1 findings → no Phase A plans either
    }

    await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=False,
    )
    assert not any("adversarial penetration tester" in c[0] for c in inference_calls), (
        "probe prompt should not have been issued"
    )


@pytest.mark.asyncio
async def test_runtime_probe_skipped_for_non_python_file(tmp_path) -> None:
    """Even with the flag on, non-Python files skip the probe stage —
    v1.5 MVP scope. JS / shell probing is future work."""
    sandbox = _CapturingProbeSandbox()

    async def fake_inference(prompt, options, schema):
        # If probe inference fires on a .js file, that's a bug.
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            raise AssertionError("probe inference must not fire on .js files")
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "js-hash",
        "source_text": "function f(p) {}",
        "file_name": "vuln.js",
        "ml_format": None,
        "original_bytes": b"function f(p) {}",
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
    )


@pytest.mark.asyncio
async def test_runtime_probe_fires_and_finds_exploit_via_canary(tmp_path) -> None:
    """End-to-end: probe enabled + Python file + model emits a
    candidate + sandbox returns a trace with a canary file appearing
    → finding lands in the journal + flows into l1_output.hypotheses
    for downstream Phase A pickup."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "str", '
                    '"value_preview": "root:x:0:0:..."}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 120,
            },
        },
    )

    inference_call_count = {"n": 0}

    async def fake_inference(prompt, options, schema):
        inference_call_count["n"] += 1
        required = schema.get("required", [])
        if required == ["candidates", "non_probable_reason"]:
            # Phase B+ probe candidates
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "read_file_safely",
                            "attack_class": "path_traversal",
                            "rationale": "function takes user path",
                            "test_inputs": [
                                {
                                    "args_json": '["../etc/passwd"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "returns /etc/passwd content",
                                    "exploit_proof_if_observed": "path traversal — reads outside data dir",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        # Phase A verdict / Phase B (standard) — return benign defaults
        text = _phase_a_verdict_response()
        if "Phase B" in prompt and "adversarial" not in prompt:
            text = _phase_b_response()
        return {"text": text, "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "vuln-hash",
        "source_text": "def read_file_safely(p):\n    return open(p).read()\n",
        "file_name": "vuln.py",
        "ml_format": None,
        "original_bytes": b"def read_file_safely(p):\n    return open(p).read()\n",
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
    )

    # The HRP probe plan reached the sandbox
    hrp_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id.startswith("HRP_")]
    assert len(hrp_plans) >= 1, "expected at least one HRP probe plan"
    assert hrp_plans[0].image_hint == "minimal"
    assert "python3 /workspace/_argus_probe_0_0.py" in hrp_plans[0].commands[1]

    # Fix #2 contract: HRP findings are NOT appended to l1_output.hypotheses.
    # The probe IS the test — Phase A re-testing them would (a) double the
    # sandbox cost and (b) produce contradictory NOT_TESTED verdicts when
    # Fly returns stub traces. Probe findings surface only via
    # findings_validated (and from there → engine's dast_findings).
    assert not any(
        h.get("id", "").startswith("HRP_") for h in (l1_output.get("hypotheses") or [])
    ), "Fix #2: HRP findings should NOT pollute l1_output.hypotheses"

    # Fix #3 (surfacing) contract: confirmed HRPs reach findings_validated
    # so engine.py picks them up as result.dast_findings.
    assert any(fid.startswith("HRP_") for fid in result.findings_validated), (
        f"expected HRP_ in findings_validated; got {result.findings_validated}"
    )

    # And the journal has a phase_b_hypothesis record with verdict=confirmed
    journal_records = result.journal_records
    confirmed_probes = [
        r
        for r in journal_records
        if r.get("claim_id", "").startswith("HRP_") and r.get("verdict") == "confirmed"
    ]
    assert len(confirmed_probes) >= 1, (
        f"expected at least one confirmed runtime probe; got {journal_records}"
    )

    # Fix #1 contract: probe-confirmed path_traversal at severity=high
    # should bump the DAST max-verdict floor to "malicious".
    assert result.final_verdict.get("verdict_label") == "malicious", (
        f"Fix #1: expected verdict bumped to malicious; got {result.final_verdict}"
    )


@pytest.mark.asyncio
async def test_runtime_probe_blocked_when_sandbox_shows_no_exploit(tmp_path) -> None:
    """Negative case: probe runs, function raises PermissionError, no
    canary appears → no finding, journal records as rejected (BLOCKED-
    equivalent for runtime probes)."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": false, "exception_type": "PermissionError", '
                    '"exception_msg": "Permission denied"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 30,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "read_file_safely",
                            "attack_class": "path_traversal",
                            "rationale": "x",
                            "test_inputs": [
                                {
                                    "args_json": '["../etc/passwd"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "returns content",
                                    "exploit_proof_if_observed": "path traversal",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "def f(p): return open(p).read()\n",
        "file_name": "v.py",
        "original_bytes": b"def f(p): return open(p).read()\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
    )

    # Probe ran but no exploit was confirmed
    rejected_probes = [
        r
        for r in result.journal_records
        if r.get("claim_id", "").startswith("HRP_") and r.get("verdict") == "rejected"
    ]
    assert len(rejected_probes) >= 1
    # No new HRP hypothesis added to l1_output (no exploit to forward)
    assert not any(h.get("id", "").startswith("HRP_") for h in (l1_output.get("hypotheses") or []))


@pytest.mark.asyncio
async def test_runtime_probe_critical_code_injection_bumps_to_critical_malicious(
    tmp_path,
) -> None:
    """Fix #1: probe-confirmed CRITICAL severity in
    {code_injection, command_injection, deserialization} → verdict
    bumped to critical_malicious (not just malicious)."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "int", "value_preview": "0"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned"]}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 50,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "exec_user_code",
                            "attack_class": "code_injection",
                            "rationale": "calls exec() on user input",
                            "test_inputs": [
                                {
                                    "args_json": '["__import__(\\"os\\").system(\\"touch /tmp/argus_probe_pwned\\")"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "canary file appears",
                                    "exploit_proof_if_observed": "code injection via exec",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {
            "text": _phase_a_verdict_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "def exec_user_code(s):\n    exec(s)\n",
        "file_name": "evil.py",
        "original_bytes": b"def exec_user_code(s):\n    exec(s)\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "suspicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
    )
    # Critical + code_injection → critical_malicious (one tier higher
    # than vanilla malicious bump)
    assert result.final_verdict.get("verdict_label") == "critical_malicious"


@pytest.mark.asyncio
async def test_runtime_probe_medium_severity_does_not_bump_verdict(
    tmp_path,
) -> None:
    """Fix #1 safety: probe-confirmed MEDIUM severity (e.g., xss,
    crypto_weakness) does NOT bump the verdict — those FP-prone classes
    need stronger evidence than one runtime observation."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "str", '
                    '"value_preview": "<script>alert(1)</script>"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 20,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "render_template",
                            "attack_class": "xss",  # severity = medium
                            "rationale": "echoes user input into HTML",
                            "test_inputs": [
                                {
                                    "args_json": '["<script>alert(1)</script>"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "script tag in return value",
                                    "exploit_proof_if_observed": "xss",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {
            "text": _phase_a_verdict_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "def render(s): return s\n",
        "file_name": "view.py",
        "original_bytes": b"def render(s): return s\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "suspicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
    )
    # Medium severity → verdict NOT bumped. The probe finding still
    # surfaces in findings_validated (the user sees it), but the verdict
    # tier stays where Phase A left it.
    label = result.final_verdict.get("verdict_label", "")
    assert label != "malicious" and label != "critical_malicious", (
        f"Fix #1 safety: medium-severity probe should not bump verdict; got {label}"
    )
    # But the finding still surfaces:
    assert any(fid.startswith("HRP_") for fid in result.findings_validated)


@pytest.mark.asyncio
async def test_runtime_probe_does_not_re_test_hrp_via_phase_a(tmp_path) -> None:
    """Fix #2: when the probe stage emits HRP_ findings, Phase A in
    iter 1 should NOT see them in its pending_hypotheses (otherwise we
    pay 2× sandbox cost and risk contradictory verdicts). Probe-only
    findings reach the engine via findings_validated, not via the
    iteration loop."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "value_preview": "exfil"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 50,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "read_file",
                            "attack_class": "path_traversal",
                            "rationale": "x",
                            "test_inputs": [
                                {
                                    "args_json": '["../etc/passwd"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "returns content",
                                    "exploit_proof_if_observed": "path traversal",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {
            "text": _phase_a_verdict_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "def read_file(p): return open(p).read()\n",
        "file_name": "io.py",
        "original_bytes": b"def read_file(p): return open(p).read()\n",
        "ml_format": None,
    }
    # Start with ONE L1 hypothesis. Phase A should plan against ONLY this
    # one — NOT against the HRP_0_0 finding the probe will discover.
    l1_output = {
        "verdict": {"verdict_label": "malicious"},
        "hypotheses": [
            {
                "id": "H001",
                "finding_ref": "H001",
                "cwe": "CWE-22",
                "severity": "critical",
                "type": "path_traversal",
                "explanation": "",
                "code_snippet": "",
                "line": 1,
                "data_flow_trace": "",
                "proof_of_concept": "",
                "confidence": 0.9,
            }
        ],
    }

    await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
    )

    # Plans submitted to sandbox: the probe's HRP_0_0 (1 plan) + Phase A's
    # plan for H001 (if any). Critical: Phase A should NOT have submitted
    # a plan with hypothesis_id="HRP_0_0" (that would mean re-testing).
    hrp_phase_a_resubmits = [
        p
        for p in sandbox.submitted_plans
        if p.hypothesis_id.startswith("HRP_")
        and p.plan_id.startswith("i1-")
        and "_argus_probe_" not in (p.commands[1] if len(p.commands) > 1 else "")
    ]
    # The probe plan's commands have ``_argus_probe_`` in them; a Phase A
    # re-test would NOT (it'd be a model-generated plan). So we filter on
    # commands shape: any HRP_ plan WITHOUT the _argus_probe_ marker is
    # a Phase A re-test.
    assert hrp_phase_a_resubmits == [], (
        f"Fix #2: Phase A re-tested HRP findings (cost doubled): "
        f"{[p.plan_id for p in hrp_phase_a_resubmits]}"
    )


@pytest.mark.asyncio
async def test_runtime_probe_model_declines_journal_records_rationale(tmp_path) -> None:
    """When the model declines (empty candidates + non_probable_reason),
    the orchestrator records the rationale in the journal as a rejected
    'HRP_NONE' record so downstream telemetry sees the decline."""
    sandbox = _CapturingProbeSandbox()

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": json.dumps(
                    {
                        "candidates": [],
                        "non_probable_reason": "file only contains data constants",
                    }
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "X = 1\nY = 'literal'\n",
        "file_name": "consts.py",
        "original_bytes": b"X = 1\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
    )

    declines = [r for r in result.journal_records if r.get("claim_id") == "HRP_NONE"]
    assert len(declines) == 1
    assert "declined" in declines[0].get("rationale", "").lower()
    assert "data constants" in declines[0].get("rationale", "")
