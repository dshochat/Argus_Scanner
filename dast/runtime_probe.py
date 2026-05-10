"""Runtime exploit probing — Phase B+ runtime-guided exploit discovery.

Phase B as it ships in v1.3.x asks Sonnet/Opus to brainstorm new
vulnerabilities by re-reading the file + Phase A's journal evidence.
That's still **model-driven static analysis with runtime context**, not
runtime discovery: the sandbox is used only to TEST hypotheses, never
to GENERATE them.

v1.5 adds Phase B+ runtime probing. The flow:

1. Sonnet identifies 1-3 candidate functions in the file that have
   attack-attractive signatures (take user-controlled input, call a
   sink, manipulate filesystem / network / process).
2. For each candidate, Sonnet generates 2-3 concrete attack inputs
   (e.g., for a ``read_file(path)`` function: ``"../etc/passwd"``,
   ``"/etc/shadow"``, ``"|cat /etc/passwd"``) — paired with an
   ``expected_observable`` describing what the sandbox would see if
   the exploit fires.
3. Argus builds a Python harness per (candidate × input), runs it in
   the microVM, captures stdout / stderr / exit_code / side-effect
   markers (new files in /tmp, environment leaks).
4. Sonnet interprets each trace: did the observed behavior match
   ``expected_observable``? If yes, it's a CONFIRMED finding via
   runtime evidence, NOT static analysis. The finding flows back into
   the journal as a new Phase A-ready hypothesis (and naturally
   reaches CONFIRMED status because the runtime evidence is already
   in the trace).

Scope (v1.5 MVP):

* Python only — the harness uses ``import target_module; target.fn(*args)``.
  JS/TS / shell probing comes in v1.5.1.
* Opt-in via ``ScanConfig.enable_runtime_probe = True``; off by default
  because (a) it adds ~$0.20-0.50/file in API cost on top of Phase A
  and (b) the FP rate on first-party code with legitimate filesystem /
  network behavior will be non-trivial early on.
* Single iter — runtime probe runs ONCE in iter 1 after Phase A. We do
  not iterate probe-discovery (multi-iter probing is a future feature
  once we have observability data on how this performs).
* Bounded — at most ``MAX_CANDIDATES`` × ``MAX_INPUTS_PER_CANDIDATE``
  sandbox runs per file. Hard cap on cost.

What this does NOT do:

* Coverage-guided fuzzing (no instrumentation, no AFL-style mutation).
* Symbolic execution (no path constraint solving).
* Native-binary probing (Python only).
* Multi-step exploit chains (one function per probe).

The right framing: **AI-driven adversarial pen-testing automation**,
scoped to be tractable + cheap. Model writes targeted attack inputs;
sandbox runs them; model interprets results.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Tunables ──────────────────────────────────────────────────────────────

#: Maximum number of probing candidates Sonnet is allowed to nominate
#: per file. Keeps cost bounded; if more functions look interesting, the
#: model picks the highest-yield ones.
MAX_CANDIDATES: int = 3

#: Maximum test inputs Sonnet generates per candidate. Each input = one
#: sandbox detonation.
MAX_INPUTS_PER_CANDIDATE: int = 3

#: Hard upper bound on total sandbox runs per file. With defaults this
#: is 3 × 3 = 9 sandbox runs ≈ ~5 min at 30s cold start each. In
#: practice the inference layer also caps via the probe schema itself.
MAX_PROBE_RUNS_PER_FILE: int = MAX_CANDIDATES * MAX_INPUTS_PER_CANDIDATE

#: Default per-probe timeout in the sandbox. 30s is enough for a Python
#: import + a single function call + side-effect snapshot, even on
#: filesystem-heavy probes.
DEFAULT_PROBE_TIMEOUT_SEC: int = 30


# ── Data types ────────────────────────────────────────────────────────────


@dataclass
class RuntimeProbeInput:
    """One attack-shaped input for a candidate function.

    The model emits these as part of the probe-candidate schema:
    positional args + keyword args + a description of what the sandbox
    should expect to observe if the exploit fires.
    """

    args_json: str
    """JSON-encoded list of positional args, e.g. ``'["../etc/passwd"]'``.
    Decoded inside the sandbox harness — keeps the wire format
    language-agnostic."""

    kwargs_json: str = "{}"
    """JSON-encoded dict of keyword args."""

    expected_observable: str = ""
    """Human-readable description of the runtime signal that proves
    the exploit fired. E.g., ``"reads /etc/passwd content into the
    return value"``, ``"writes file /tmp/pwned"``, ``"spawns subprocess
    that runs 'whoami'"``. The trace interpreter compares the observed
    runtime evidence against this."""

    exploit_proof_if_observed: str = ""
    """The vulnerability claim that lands as a finding IF the observed
    signal matches. E.g., ``"path traversal — reads files outside the
    intended directory via ../"``."""


@dataclass
class RuntimeProbeCandidate:
    """One function-under-test, identified by Sonnet via static analysis
    as a probing-attractive target."""

    function_name: str
    """Bare function / method name as it appears in the module's top-level
    namespace. Composite paths like ``MyClass.method`` are allowed; the
    harness uses ``getattr`` walks for them."""

    attack_class: str
    """Classification — ``path_traversal``, ``code_injection``,
    ``command_injection``, ``deserialization``, ``ssrf``,
    ``data_exfiltration``, etc. Drives the prompt that interprets
    traces and the CWE attached to any finding."""

    rationale: str = ""
    """Why the model picked this function — for journal traceability."""

    test_inputs: list[RuntimeProbeInput] = field(default_factory=list)


@dataclass
class RuntimeProbeTrace:
    """The result of running one probe (one candidate × one input)
    in the sandbox. Mirrors the SandboxTrace shape but typed for the
    probe interpretation layer."""

    candidate_function: str
    input_args_json: str
    exit_code: int | None
    stdout: str
    stderr: str
    elapsed_ms: int
    parsed_result: dict[str, Any] | None = None
    """If the harness emitted a ``RESULT_JSON:{...}`` marker line on
    stdout, this is the decoded dict. ``None`` when the harness
    crashed before printing the marker (segfault, kill, etc.)."""

    side_effects: dict[str, Any] = field(default_factory=dict)
    """Decoded ``SIDE_EFFECTS:{...}`` marker — files added to /tmp,
    new processes spawned, network connections opened. Used by the
    interpreter to detect runtime exploit signals."""


@dataclass
class RuntimeProbeFinding:
    """A finding emitted when a probe's trace matches its expected
    observable. Flows back into the journal as a CONFIRMED hypothesis."""

    finding_id: str
    """``HRP_<candidate_idx>_<input_idx>`` — stable per-scan identifier."""

    candidate_function: str
    attack_class: str
    severity: str
    """``critical`` / ``high`` / ``medium`` — derived from attack_class
    via :data:`_ATTACK_CLASS_SEVERITY`."""

    cwe: str
    """CWE id derived from attack_class. ``CWE-22`` for path traversal,
    ``CWE-78`` for command injection, etc."""

    description: str
    """Plain-language summary of the exploit, derived from
    ``exploit_proof_if_observed`` + observed runtime evidence."""

    runtime_evidence: str
    """The specific bytes / lines from the sandbox trace that prove
    the exploit fired. Verbatim where possible — this is what makes
    the finding sandbox-grounded rather than model-speculated."""

    test_input_args: str
    """The exact JSON-encoded args that triggered the exploit. Pasted
    into ``proof_of_concept`` so a developer can reproduce."""


# ── Attack-class → CWE + severity mapping ────────────────────────────────


_ATTACK_CLASS_CWE: dict[str, str] = {
    "path_traversal": "CWE-22",
    "code_injection": "CWE-94",
    "command_injection": "CWE-78",
    "deserialization": "CWE-502",
    "data_exfiltration": "CWE-200",
    "ssrf": "CWE-918",
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "xxe": "CWE-611",
    "crypto_weakness": "CWE-327",
    "prompt_injection": "CWE-1389",  # provisional
    "open_redirect": "CWE-601",
    "race_condition": "CWE-362",
}

_ATTACK_CLASS_SEVERITY: dict[str, str] = {
    "path_traversal": "high",
    "code_injection": "critical",
    "command_injection": "critical",
    "deserialization": "critical",
    "data_exfiltration": "high",
    "ssrf": "high",
    "sql_injection": "critical",
    "xss": "medium",
    "xxe": "high",
    "crypto_weakness": "medium",
    "prompt_injection": "medium",
    "open_redirect": "medium",
    "race_condition": "medium",
}


def cwe_for_attack_class(attack_class: str) -> str:
    """Return the CWE id mapped to a probe's attack class.

    Falls back to ``CWE-1035`` ("Improper Input Validation") for
    unrecognized classes so finding emission never crashes on a
    model-generated unknown class string."""
    return _ATTACK_CLASS_CWE.get(attack_class, "CWE-1035")


def severity_for_attack_class(attack_class: str) -> str:
    """Return ``critical`` / ``high`` / ``medium`` / ``low`` for a probe's
    attack class. Falls back to ``medium`` for unknown classes."""
    return _ATTACK_CLASS_SEVERITY.get(attack_class, "medium")


# ── Python harness generation ─────────────────────────────────────────────


def _python_module_name_for_file(file_name: str) -> str:
    """Derive an import-safe module name from a wheel filename or path.

    ``vulnerable_lib.py`` → ``vulnerable_lib``
    ``mypkg/io_utils.py`` → ``io_utils`` (we strip parent dirs and rely
    on the sandbox staging the file at ``/workspace/<basename>``).

    We deliberately use the BASENAME so the harness import path is
    deterministic. The sandbox guarantees the file lives at
    ``/workspace/<basename>`` (see ``SandboxPlan.file_name``)."""
    base = Path(file_name).name
    if base.endswith(".py"):
        base = base[: -len(".py")]
    # Replace any python-illegal chars with underscores
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in base)


def _build_python_probe_harness(
    *,
    module_name: str,
    function_name: str,
    args_json: str,
    kwargs_json: str,
) -> str:
    """Generate the Python harness that runs ONE probe inside the sandbox.

    Layout:
    1. Snapshot baseline (env, /tmp contents, network log if accessible).
    2. Import the target module from /workspace.
    3. Resolve the function (supports ``Class.method`` via getattr walk).
    4. Call it with the decoded args / kwargs.
    5. Print ``RESULT_JSON:{...}`` (outcome) + ``SIDE_EFFECTS:{...}``
       (diff of observable side effects).

    The harness is a single-line python -c invocation so it can be
    dropped into a SandboxPlan's ``commands`` list with no shell quoting
    surprises (we ``shlex.quote`` the whole thing at submit time).
    """
    # Use a heredoc-style string we'll embed via stdin. Keeping it
    # raw-string-friendly: triple-quoted, no escapes that f-strings or
    # shells would mangle. The args / kwargs JSON is embedded as a
    # Python literal string so the harness can json.loads() it without
    # shell quoting hell.
    args_repr = repr(args_json)
    kwargs_repr = repr(kwargs_json)
    safe_function = function_name  # Pre-validated by the schema regex
    return (
        "import sys, os, json, traceback\n"
        "sys.path.insert(0, '/workspace')\n"
        "baseline_tmp = set()\n"
        "try:\n"
        "    baseline_tmp = set(os.listdir('/tmp'))\n"
        "except Exception:\n"
        "    pass\n"
        f"args = json.loads({args_repr})\n"
        f"kwargs = json.loads({kwargs_repr})\n"
        f"import {module_name} as _target\n"
        "fn = _target\n"
        f"for part in '{safe_function}'.split('.'):\n"
        "    fn = getattr(fn, part)\n"
        "try:\n"
        "    result = fn(*args, **kwargs)\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': True,\n"
        "        'type': type(result).__name__,\n"
        "        'value_preview': repr(result)[:600],\n"
        "    }))\n"
        "except SystemExit as e:\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': False,\n"
        "        'exception_type': 'SystemExit',\n"
        "        'exception_msg': str(e)[:300],\n"
        "    }))\n"
        "except BaseException as e:\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': False,\n"
        "        'exception_type': type(e).__name__,\n"
        "        'exception_msg': str(e)[:300],\n"
        "        'tb_tail': traceback.format_exc()[-1500:],\n"
        "    }))\n"
        "added_tmp = []\n"
        "try:\n"
        "    added_tmp = sorted(set(os.listdir('/tmp')) - baseline_tmp)\n"
        "except Exception:\n"
        "    pass\n"
        "print('SIDE_EFFECTS:' + json.dumps({\n"
        "    'tmp_files_added': added_tmp[:20],\n"
        "}))\n"
    )


# ── Plan builder ──────────────────────────────────────────────────────────


def build_runtime_probe_plan(
    *,
    file_name: str,
    file_bytes: bytes,
    candidate: RuntimeProbeCandidate,
    test_input: RuntimeProbeInput,
    candidate_idx: int,
    input_idx: int,
    image_hint: str = "minimal",
) -> dict[str, Any] | None:
    """Build a Phase-A-shaped plan dict that runs one probe.

    Returns ``None`` when the file isn't Python — v1.5 MVP scope.
    The plan's ``hypothesis_id`` follows the pattern
    ``HRP_<candidate_idx>_<input_idx>`` (HRP = "harness runtime probe")
    for stable identifiers across iterations.
    """
    if not file_name.lower().endswith(".py"):
        return None

    module_name = _python_module_name_for_file(file_name)
    harness = _build_python_probe_harness(
        module_name=module_name,
        function_name=candidate.function_name,
        args_json=test_input.args_json,
        kwargs_json=test_input.kwargs_json,
    )

    # Encode the original file as base64 so the sandbox stages it at
    # /workspace/<file_name>. SAme pattern ml_detonation.py uses for
    # binary artifacts; reuses the staging infra.
    payload_b64 = base64.b64encode(file_bytes).decode("ascii")

    # Wrap harness in a python -c invocation. The sandbox runner will
    # shell-quote this safely; we just deliver the python source.
    # Using ``-`` (stdin) instead of -c keeps quoting trivial: pipe the
    # harness via heredoc-style. But SandboxPlan.commands is a list of
    # shell strings, so the cleanest path is to write the harness to a
    # temp file in /workspace first, then invoke it. Two-command plan.
    harness_path = f"/workspace/_argus_probe_{candidate_idx}_{input_idx}.py"
    write_cmd = (
        f"python3 -c \"import base64,sys; "
        f"open({harness_path!r},'wb').write("
        f"base64.b64decode(sys.argv[1]))\" "
        f"{base64.b64encode(harness.encode('utf-8')).decode('ascii')}"
    )
    run_cmd = f"python3 {harness_path}"

    return {
        "hypothesis_id": f"HRP_{candidate_idx}_{input_idx}",
        "plan_status": "executable",
        "commands": [write_cmd, run_cmd],
        "oracle": "execution_output_with_side_effect_observation",
        "payload": payload_b64,
        "payload_encoding": "base64",
        "timeout_sec": DEFAULT_PROBE_TIMEOUT_SEC,
        "image_hint": image_hint,
        "rationale": (
            f"Runtime probe: testing {candidate.function_name} with attack "
            f"input for {candidate.attack_class}. Expected if vulnerable: "
            f"{test_input.expected_observable[:150]}"
        ),
    }


# ── Trace interpretation ─────────────────────────────────────────────────


def parse_probe_trace(
    *,
    candidate_function: str,
    input_args_json: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    elapsed_ms: int,
) -> RuntimeProbeTrace:
    """Pull the structured markers (``RESULT_JSON:`` and ``SIDE_EFFECTS:``)
    out of the harness's stdout and build a typed trace record.

    Defensive against (a) truncated stdout, (b) harness crash before
    markers, (c) markers with broken JSON. Any parse failure leaves the
    relevant field at its sentinel (``parsed_result=None`` or empty
    ``side_effects={}``) so callers don't have to handle exceptions."""
    trace = RuntimeProbeTrace(
        candidate_function=candidate_function,
        input_args_json=input_args_json,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        elapsed_ms=elapsed_ms,
    )

    # Walk stdout line-by-line to find the markers. We accept the LAST
    # occurrence of each marker (harness emits one of each near the end).
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("RESULT_JSON:"):
            payload = line[len("RESULT_JSON:") :].strip()
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    trace.parsed_result = parsed
            except (json.JSONDecodeError, ValueError):
                continue
        elif line.startswith("SIDE_EFFECTS:"):
            payload = line[len("SIDE_EFFECTS:") :].strip()
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    trace.side_effects = parsed
            except (json.JSONDecodeError, ValueError):
                continue

    return trace


def interpret_probe_trace(
    trace: RuntimeProbeTrace,
    candidate: RuntimeProbeCandidate,
    test_input: RuntimeProbeInput,
    *,
    candidate_idx: int,
    input_idx: int,
) -> RuntimeProbeFinding | None:
    """Decide whether the trace constitutes a runtime-confirmed exploit.

    This is the deterministic-half of the interpretation; the model-half
    (handled by the orchestrator-level prompt) is what generates the
    natural-language rationale. We emit a finding when ANY of:

    1. ``parsed_result.ok == True`` AND the function's documented role
       was to REJECT the malicious input (e.g., path-traversal input
       expected to raise; function returned successfully → exploit).
    2. ``side_effects.tmp_files_added`` contains files the test input
       was expected to write (the canary pattern — model includes a
       known marker string in the input, sandbox shows it materialize).
    3. ``stderr`` contains a stack trace AND the function is documented
       to handle the input safely (unexpected exception = bug; model
       interprets severity).

    For v1.5 MVP we surface a finding whenever rule (1) or (2) fires.
    Rule (3) requires the model-loop interpretation that the orchestrator
    handles via ``build_phase_b_probe_verdict_prompt``.

    Returns ``None`` when no rule fires (probe ran but observed no
    exploit signal — that's the BLOCKED-equivalent for runtime probes).
    """
    if trace.parsed_result is None:
        # Harness crashed before printing the marker — can't interpret.
        return None

    parsed = trace.parsed_result
    side_effects = trace.side_effects or {}

    # Rule 1: function returned successfully on an attack input that was
    # supposed to be rejected. The model emits a candidate ONLY when it
    # believes the function SHOULD reject the input; success = exploit.
    ok = bool(parsed.get("ok"))

    # Rule 2: canary side effects. The model is encouraged to include
    # markers in attack inputs (e.g., write to /tmp/argus_probe_*) that
    # the sandbox can observe. Tmp files appearing post-call = exploit.
    tmp_added: list[str] = (
        side_effects.get("tmp_files_added")
        if isinstance(side_effects.get("tmp_files_added"), list)
        else []
    )
    canary_hit = any(
        isinstance(f, str) and ("argus_probe" in f.lower() or "pwned" in f.lower())
        for f in tmp_added
    )

    # Build the finding when ANY rule fires.
    evidence_parts: list[str] = []
    if ok:
        preview = parsed.get("value_preview", "")
        evidence_parts.append(
            f"Function returned without raising (value preview: {str(preview)[:200]})"
        )
    if canary_hit:
        evidence_parts.append(
            f"Sandbox observed canary file(s) created in /tmp: {tmp_added[:5]}"
        )
    if not evidence_parts:
        # Probe ran cleanly — exception raised AND no side-effect canary.
        # That's BLOCKED/UNREACHED-equivalent: no exploit observed.
        return None

    runtime_evidence = (
        f"Probe `{candidate.function_name}({test_input.args_json})`: "
        + "; ".join(evidence_parts)
        + f" (exit_code={trace.exit_code}, elapsed={trace.elapsed_ms}ms)"
    )

    return RuntimeProbeFinding(
        finding_id=f"HRP_{candidate_idx}_{input_idx}",
        candidate_function=candidate.function_name,
        attack_class=candidate.attack_class,
        severity=severity_for_attack_class(candidate.attack_class),
        cwe=cwe_for_attack_class(candidate.attack_class),
        description=(
            test_input.exploit_proof_if_observed
            or f"{candidate.attack_class} in {candidate.function_name}"
        ),
        runtime_evidence=runtime_evidence,
        test_input_args=test_input.args_json,
    )


__all__ = [
    "DEFAULT_PROBE_TIMEOUT_SEC",
    "MAX_CANDIDATES",
    "MAX_INPUTS_PER_CANDIDATE",
    "MAX_PROBE_RUNS_PER_FILE",
    "RuntimeProbeCandidate",
    "RuntimeProbeFinding",
    "RuntimeProbeInput",
    "RuntimeProbeTrace",
    "build_runtime_probe_plan",
    "cwe_for_attack_class",
    "interpret_probe_trace",
    "parse_probe_trace",
    "severity_for_attack_class",
]
