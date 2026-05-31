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

import ast
import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def normalize_kwargs_json(s: str) -> str:
    """Coerce a model-emitted kwargs spec into valid JSON-encoded dict.

    Mirror of :func:`normalize_args_json` but for kwargs (must decode to
    a dict, not a list). Same auto-repair flow:

    1. Try ``json.loads(s)`` — if it parses to a dict, re-serialize.
    2. Try ``ast.literal_eval(s)`` — if it returns a dict, re-serialize.
    3. Fallback to ``"{}"`` (empty dict) so the harness's ``**kwargs``
       expansion doesn't blow up with ``TypeError: argument after ** must
       be a mapping``.

    Using ``normalize_args_json`` for kwargs was a real bug — list-shape
    fallback ``"[]"`` ended up at ``**`` and crashed the harness. This
    helper guarantees the right shape.
    """
    if not isinstance(s, str) or not s.strip():
        return "{}"
    try:
        parsed = json.loads(s)
        if isinstance(parsed, dict):
            return json.dumps(parsed)
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        parsed = ast.literal_eval(s)
        if isinstance(parsed, dict):
            return json.dumps(parsed)
    except (ValueError, SyntaxError, MemoryError, TypeError):
        pass
    return "{}"


def normalize_args_json(s: str) -> str:
    """Coerce a model-emitted args spec into valid JSON.

    Phase 1a live validation surfaced a model-bug: Sonnet sometimes emits
    ``args_json`` as a Python-syntax string (single-quoted strings inside
    a list literal) rather than valid JSON. Example:

        emitted:  "['payload with \\'quotes\\'']"
        valid:    "[\\"payload with \\\\'quotes\\\\'\\"]"

    The harness's ``JSON.parse`` (or ``json.loads``) rejects Python syntax,
    which:

    * crashes the JS harness inside the sandbox (Mode 1 safety net catches
      it but the probe is wasted), and
    * makes the mutator return empty (it ``json.loads`` first, gets an
      error, returns []) — so mutation expansion silently doesn't fire.

    Auto-repair flow:

    1. Try ``json.loads(s)``. If it parses to a list, re-serialize and
       return — guarantees canonical JSON shape for downstream consumers.
    2. On failure, try ``ast.literal_eval(s)`` — this safely parses
       Python list/dict/string literals (no code execution). If the
       result is a list, re-serialize as JSON and return.
    3. On all failures, return ``"[]"`` (safe fallback — the probe will
       run with no args, the harness will likely error cleanly).

    This is intentionally permissive — the alternative (rejecting
    malformed input) wastes the model's candidate generation budget.
    """
    if not isinstance(s, str) or not s.strip():
        return "[]"
    # Path 1: already valid JSON
    try:
        parsed = json.loads(s)
        if isinstance(parsed, list):
            return json.dumps(parsed)
    except (json.JSONDecodeError, ValueError):
        pass
    # Path 2: Python-syntax repair via ast.literal_eval (safe — no eval)
    try:
        parsed = ast.literal_eval(s)
        if isinstance(parsed, list):
            return json.dumps(parsed)
    except (ValueError, SyntaxError, MemoryError, TypeError):
        pass
    # Path 3: safe fallback. The probe will run with no args; the harness
    # will surface a meaningful error (most likely a TypeError from the
    # target function rejecting zero-arg calls), better than a SyntaxError.
    return "[]"


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

#: Phase 1b — Iterative refinement. Maximum number of REFINED inputs
#: per candidate when the initial fan-out blocks but the function was
#: reached (i.e., recoverable exception, not ImportError /
#: AttributeError). Each refinement = 1 inference call to ask the
#: model "what's the next-shape input given THIS failure" + 1 sandbox
#: probe. Capped at 2 so total cost per candidate stays bounded:
#: ~2 × ($0.05 inference + $0.05 sandbox) = $0.20 added when refinement
#: actually fires.
MAX_REFINEMENT_ATTEMPTS: int = 2

#: Default per-probe timeout in the sandbox.
#:
#: Tuning history:
#:   * 30 (initial): enough for Python import + single function call +
#:     side-effect snapshot in the common case.
#:   * 60 (current): bumped after sandbox_runner.js diagnostic showed
#:     JS probes against sandboxjs's Sandbox.eval() taking >30s on
#:     prototype-pollution payloads (sandboxjs's input parser is CPU-
#:     heavy on adversarial input). At 30s the harness was being killed
#:     by the entrypoint's per-command timer before it could emit any
#:     RESULT_JSON marker — silent failure mode that looked like
#:     "machine never ran" but was actually "machine ran, computed for
#:     >30s, got killed mid-eval". 60s leaves room for slow eval cases
#:     without bloating per-probe cost (most probes still complete in
#:     2-10s; only the pathological adversarial-payload cases use the
#:     full budget).
DEFAULT_PROBE_TIMEOUT_SEC: int = 60

#: Phase 2 — Cross-function exploit chains. Maximum number of chain
#: candidates the model can nominate per file. A chain is an ordered
#: sequence of function calls where each step's args can reference prior
#: steps' return values via ``<<_stepN_result>>`` placeholders. The
#: final step's runtime evidence is what determines exploit confirmation.
#: Chains catch the class of bugs where no single function is exploitable
#: but a sequence is — e.g., ``config_parse(user_input) → eval(parsed)``
#: where parse alone returns a safe-looking dict and eval alone is fine,
#: but the chain produces RCE.
MAX_CHAINS_PER_FILE: int = 3

#: Maximum steps in a single chain. 2 is the minimum useful chain
#: (otherwise it's just a single-function probe). 3 covers most
#: real-world multi-stage exploit patterns (parse → store → trigger);
#: deeper chains are rare and exponentially costlier to probe.
MAX_CHAIN_STEPS: int = 3

#: Phase 2 v1.0 confidence calibration for chain confirmations. Different
#: oracles have empirically different FP rates; surfacing this as a
#: ``confidence`` field on every chain finding lets the adjudicator /
#: report layer / human operator filter accordingly without per-class
#: signature tuning.
#:
#: * ``CHAIN_CONFIDENCE_CANARY`` (1.0) — Rule 2 canary side-effect fired.
#:   A file with ``argus_probe_`` / ``pwned`` substring landed in /tmp
#:   during chain execution. By construction this is causal evidence —
#:   the file can only appear if some chain step actually wrote it.
#:   Empirically 0 FPs across all observed runs.
#: * ``CHAIN_CONFIDENCE_CLASS_SIGNATURE`` (0.7) — Rule 1 high-specificity
#:   path. The final step's runtime evidence contains an attack-class-
#:   specific distinctive substring (e.g., ``root:x:0:0:`` for
#:   path_traversal). These substrings don't appear in benign code; FP
#:   risk is moderate when the chain hits a function whose normal output
#:   coincidentally contains the substring.
#: * ``CHAIN_CONFIDENCE_OBSERVABLE_KEYWORD`` (0.4) — Rule 1 low-specificity
#:   path. The evidence contains a 5+ char token extracted from the
#:   model's ``expected_observable`` text. Empirically the FP source —
#:   the db2_query_health_check.py regression confirmed this oracle fires
#:   on simulation-branch stub output that happens to contain the
#:   keyword. Adjudicator should treat as operator-review, not as a
#:   ship-it finding.
CHAIN_CONFIDENCE_CANARY: float = 1.0
CHAIN_CONFIDENCE_CLASS_SIGNATURE: float = 0.7
CHAIN_CONFIDENCE_OBSERVABLE_KEYWORD: float = 0.4


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

    assertion_expr: str = ""
    """Phase 1 (SCAN-016, 2026-05-21) — STRUCTURED assertion expression.

    Optional Python predicate evaluated in the sandbox AGAINST THE LIVE
    return value after the function call completes. When non-empty, the
    harness evaluates ``eval(assertion_expr)`` in a restricted namespace
    where these names are bound:

      * ``result`` — the function's return value (untouched object)
      * ``args``   — the decoded positional args list
      * ``kwargs`` — the decoded keyword args dict

    Examples (per attack class):

      * SSRF / open_redirect with URL:
          ``getattr(result, 'scheme', None) == 'file'``
          ``str(getattr(result, 'host', '')).startswith('169.254.')``
      * Path traversal:
          ``'/etc/passwd' in result``
          ``'..' in str(result)``
      * Data exfiltration / pass-through detection:
          ``args[0] not in result.values() if isinstance(result, dict) else True``
      * DoS amplification:
          ``isinstance(result, (int, float)) and result > 60``

    Restricted namespace — these are the ONLY builtins available inside
    the assertion: ``len, isinstance, hasattr, getattr, str, int,
    float, bool, list, dict, tuple, set, any, all, type, repr,
    True, False, None``. No imports, no subprocess, no I/O. The
    expression must terminate quickly (the harness does NOT enforce a
    timeout on eval — the model should keep expressions simple).

    Why this exists: the v15.27 ``observable_keyword`` oracle does
    substring matching against ``str(result)``, which produces false
    positives like ``URL('https://api.openai.com/v1/etc/passwd').scheme``
    matching the keyword ``'scheme'`` from ``expected_observable`` text
    even though the URL was correctly NORMALIZED (the file:// scheme
    was rejected, the result is the SAFE outcome). A structured
    assertion ``getattr(result, 'scheme', None) == 'file'`` would
    correctly evaluate to ``False`` on the safe outcome.

    Back-compat: empty string disables structured-assertion oracle and
    falls back to the existing string-based oracles (class_signature,
    class_signature_causal, observable_keyword). All NEW Phase B+ /
    Phase 3 hypotheses should populate this field."""

    rejection_signature: str = ""
    """Counter-evidence: runtime signal that would indicate the
    application correctly REJECTED the attack input (defense fired).
    E.g., ``"ValueError raised with message containing 'invalid'"``,
    ``"UnsupportedProtocol exception"``, ``"ZoneInfo keys may not contain
    up-level references"``. Required defense against the v1.6 FP class
    where ``expected_observable`` substring-matches an error message
    that's actually evidence of rejection rather than exploit success.

    Interpretation rule (see :func:`interpret_probe_trace`): exploit is
    marked CONFIRMED only if ``expected_observable`` matches AND
    ``rejection_signature`` does NOT match. When both match, rejection
    wins (REFUTED). Empty string disables the negative check (legacy
    behavior). All NEW hypotheses should populate this."""

    exploit_proof_if_observed: str = ""
    """The vulnerability claim that lands as a finding IF the observed
    signal matches. E.g., ``"path traversal — reads files outside the
    intended directory via ../"``."""

    instance_init_args_json: str = "[]"
    """v15.18: constructor positional args when the parent candidate has
    ``target_kind="instance_method"``. JSON-encoded list, decoded inside
    the harness. Ignored for ``function`` / ``class_constructor`` /
    ``classmethod`` / ``staticmethod`` kinds. Default ``"[]"`` matches the
    no-arg-constructor case (e.g., ``CredentialsFile()``)."""

    instance_init_kwargs_json: str = "{}"
    """v15.18: constructor keyword args when the parent candidate has
    ``target_kind="instance_method"``. JSON-encoded dict. Required when
    the class's ``__init__`` has non-default positional or keyword args
    that the harness can't synthesize blindly. Example for
    ``IdentityTokenFile``: ``'{"path": "/tmp/token"}'``."""


@dataclass
class RuntimeProbeCandidate:
    """One function-under-test, identified by Sonnet via static analysis
    as a probing-attractive target."""

    function_name: str
    """Bare function / method name as it appears in the module's top-level
    namespace. Composite paths like ``MyClass.method`` are allowed; the
    harness uses ``getattr`` walks for them (kind-aware as of v15.18 —
    see ``target_kind``)."""

    attack_class: str
    """Classification — ``path_traversal``, ``code_injection``,
    ``command_injection``, ``deserialization``, ``ssrf``,
    ``data_exfiltration``, etc. Drives the prompt that interprets
    traces and the CWE attached to any finding."""

    rationale: str = ""
    """Why the model picked this function — for journal traceability."""

    test_inputs: list[RuntimeProbeInput] = field(default_factory=list)

    target_kind: str = "function"
    """v15.18: callable kind for the harness's resolution strategy.

    * ``"function"`` — module-level function. Resolved via getattr walk
      and called directly. (Default — backwards-compat with legacy
      candidates that don't set this field.)
    * ``"class_constructor"`` — ``MyClass.__init__`` style target. The
      harness calls ``MyClass(*args, **kwargs)`` directly (passing through
      the test_input args as constructor args). Avoids the
      ``TypeError: __init__ missing 1 required positional argument: 'self'``
      that the pre-v15.18 blind getattr walk produced.
    * ``"instance_method"`` — bound-method target like
      ``CredentialsFile._read_credentials``. The harness instantiates the
      class with ``test_input.instance_init_args_json`` /
      ``instance_init_kwargs_json``, then calls ``instance.method(*args,
      **kwargs)``. Required for stateful targets where the model wants to
      attack a specific method, not the constructor.
    * ``"classmethod"`` / ``"staticmethod"`` — decorator-marked targets.
      The harness calls them directly on the class (no instance needed)
      — same call shape as ``function`` but kind-tracked for clarity in
      the trace.

    When the model doesn't set this field (legacy candidates / smaller
    models), the harness's runtime autodetect at call time falls back
    safely to ``function`` and degrades to the pre-v15.18 behavior. See
    ``_build_python_probe_harness`` for the dispatch logic."""


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

    baseline_parsed: dict[str, Any] | None = None
    """v15.26 — decoded ``BASELINE_RESULT_JSON:{...}`` marker. The
    harness runs the function with semantically-stripped inputs
    BEFORE the attack input; this captures that outcome so the
    matcher can detect uniform-validation false positives. ``None``
    when differential fuzzing was disabled or the marker was absent."""

    assertion_passed: bool | None = None
    """Phase 1 (SCAN-016, 2026-05-21) — structured-assertion outcome.

    * ``True``  — the model-supplied ``assertion_expr`` evaluated to
                  truthy against the live return value. STRONGEST
                  oracle signal: confirms the exploit shape demanded
                  by the assertion is materialized in the result.
    * ``False`` — the assertion evaluated to falsy. STRONG REFUTAL
                  signal: the structured invariant the exploit needs
                  is NOT present in the result.
    * ``None``  — no assertion was provided OR the assertion failed
                  to evaluate (syntax error, undefined name, restricted-
                  builtin violation, exception during eval). Falls
                  back to the string-based oracles.
    """

    assertion_error: str = ""
    """Phase 1 — empty when ``assertion_passed`` was set cleanly to
    True/False. Populated with ``type(e).__name__: msg`` when eval
    raised, so the audit trail explains why ``assertion_passed`` is
    ``None`` despite an ``assertion_expr`` being provided."""


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

    oracle_type: str = ""
    """v1.6 Fix #4b: which evidence oracle fired to produce this
    finding. One of:

    * ``"class_signature"`` — runtime evidence matched the attack-class
      signature library (e.g., ``root:x:0:0:`` for path_traversal).
      HIGH confidence: the evidence specifically demonstrates the
      claimed CWE class.
    * ``"canary"`` — sandbox observed a marker file in /tmp created
      during execution. HIGH confidence the exploit fired, but
      DOES NOT verify the firing demonstrates the claimed CWE class
      (canary creation can come from any code-execution primitive).
    * ``"canary+class_signature"`` — both fired. Strongest oracle.
    * ``"observable_keyword"`` — evidence matched the model's
      ``expected_observable`` text. LOW confidence: prone to FPs when
      the function legitimately returns content overlapping keywords.
    * ``""`` — backward-compat default for pre-Fix-4b call sites.

    Used by ``_run_single_function`` in ``adversarial_loop_runner`` to
    downgrade ``confidence`` on canary-only oracles (no class-signature
    backup) — addresses the 1/16 CWE mis-attribution case from the
    v1.5.1 adjudication where the canary fired but the actual exploit
    primitive didn't match the L1-claimed CWE class."""


# ── Phase 3 Stage 2: probe-kind observation (v1.6) ────────────────────────


@dataclass
class RuntimeProbeObservation:
    """Descriptive snapshot of one ``probe``-kind hypothesis execution.

    Phase 3 Stage 2's adversarial loop emits hypotheses in three kinds
    (``probe``, ``single_function``, ``stateful_sequence``). The
    ``probe`` kind is exploratory: the model invokes a function just
    to SEE what happens, with no attack interpretation. The resulting
    observation feeds the next turn's context so the model can design
    targeted attacks from concrete runtime evidence rather than from a
    static reading of the source.

    Distinct from :class:`RuntimeProbeFinding`: a probe observation
    never asserts exploit confirmation. It's the runtime-evidence half
    of "investigate before attacking" — the loop's analogue of an
    interactive REPL session for the model. Outcomes built from it
    carry ``verdict = VERDICT_PROBE_OBSERVED`` (defined in
    :mod:`dast.adversarial_loop`).
    """

    function_called: str
    """The probe's target function name, verbatim from the hypothesis."""

    input_args_json: str
    """JSON-encoded positional args used in the call."""

    input_kwargs_json: str
    """JSON-encoded kwargs used in the call."""

    returned_cleanly: bool
    """True iff the function returned without raising. Maps to
    ``parsed_result["ok"] == True`` in the harness output."""

    return_value_type: str
    """The Python type name of the return value (e.g. ``"dict"``,
    ``"str"``, ``"NoneType"``). Empty when the function raised."""

    return_value_preview: str
    """``repr(return_value)`` truncated by the harness. Empty when
    ``returned_cleanly == False`` (no value to preview)."""

    exception_class: str
    """Exception class name when the function raised (e.g.
    ``"ValueError"``, ``"FileNotFoundError"``). Empty when
    ``returned_cleanly == True``."""

    exception_message: str
    """``str(exception)`` truncated by the harness. Empty when
    ``returned_cleanly == True``."""

    stdout_excerpt: str
    """First 800 chars of raw stdout from the sandbox. Useful when the
    function prints diagnostic info or leaks data via stdout."""

    stderr_excerpt: str
    """First 800 chars of raw stderr from the sandbox. Often carries
    the most informative runtime signal — system warnings, library
    deprecation messages, import errors."""

    side_effects: dict[str, Any]
    """Decoded ``SIDE_EFFECTS:{...}`` marker (e.g.
    ``{"tmp_files_added": ["/tmp/argus_probe_x"]}``). The model uses
    these to plan follow-up attacks (e.g., "this probe wrote
    /tmp/argus_probe_x — try state-poisoning the loader that reads
    it")."""

    exit_code: int | None
    """Sandbox process exit code. ``None`` when the sandbox couldn't
    deliver the result (network failure, hang, killed). Distinct from
    the function raising an exception, which keeps exit_code at 0."""

    elapsed_ms: int
    """Wall-clock time spent running the probe in the sandbox."""

    summary: str
    """One-paragraph natural-language description of what happened,
    formatted for inclusion in the next turn's prompt. The single most
    important field — this is the model-facing observation that drives
    subsequent attack-hypothesis design."""


# ── Phase 2: cross-function exploit chains ────────────────────────────────


@dataclass
class RuntimeProbeChainStep:
    """One step in a multi-function exploit chain.

    Each step is a single function call. The model emits these as an
    ordered list. Args may contain ``<<_stepN_result>>`` placeholders
    (1-indexed) that the harness substitutes with the actual return
    value of step N at runtime. Example: a 2-step chain where step 1's
    return value is the entire input to step 2 emits:

        step 1: function_name="parse_config",  args_json='["__import__(\\'os\\').system(\\'id\\')"]'
        step 2: function_name="apply_config",  args_json='["<<_step1_result>>"]'
    """

    function_name: str
    """Bare function or method name. Same regex validation as
    :class:`RuntimeProbeCandidate.function_name` — dotted-paths allowed
    for ``Class.method`` lookups."""

    args_json: str
    """JSON-encoded list of positional args. May contain literal
    ``<<_stepN_result>>`` placeholder strings (N is 1-indexed and
    refers to a PRIOR step's return value)."""

    kwargs_json: str = "{}"
    """JSON-encoded dict of keyword args. Same placeholder rules as
    args_json — values may reference prior steps."""


@dataclass
class RuntimeProbeChain:
    """An ordered sequence of function calls that together form an
    exploit pattern. Catches the class of bugs where no single function
    is exploitable but a sequence is — e.g., ``config_parse(user_input)``
    returns a safe-looking dict, ``eval_config(parsed)`` is fine on
    arbitrary dicts, but the chain ``eval_config(config_parse(input))``
    produces RCE because parse-then-eval misses the sanitization step.

    The final step's runtime evidence (return value + side effects) is
    what determines exploit confirmation — intermediate steps are
    plumbing. Rule 1 (evidence-signature match) and Rule 2 (canary
    side effect) apply to the FINAL step only.

    Chain inference happens in a separate model call from single-
    function candidate generation: the model is shown the file + Phase A
    journal and asked specifically for chain hypotheses where the
    multi-step structure matters."""

    steps: list[RuntimeProbeChainStep]
    """Ordered list of function calls. Length is bounded by
    :data:`MAX_CHAIN_STEPS`. Must be at least 2 to qualify as a chain
    (a 1-step "chain" is just a single-function probe)."""

    attack_class: str
    """Same taxonomy as :class:`RuntimeProbeCandidate.attack_class`.
    Drives evidence-signature matching against the FINAL step's trace."""

    rationale: str = ""
    """Why the model thinks this chain is exploitable — what each step
    contributes to the overall exploit. Journaled for traceability."""

    expected_observable: str = ""
    """Description of the runtime signal at the FINAL step that proves
    the chain exploit fired. Same shape as
    :class:`RuntimeProbeInput.expected_observable`."""

    exploit_proof_if_observed: str = ""
    """Vulnerability claim that lands as a finding IF the final step's
    observed signal matches. E.g., ``"RCE via parse-then-eval chain:
    parser deserializes attacker payload into callable, eval invokes
    it"``."""


@dataclass
class RuntimeProbeChainTrace:
    """The result of running one chain (ordered steps) in the sandbox.

    Mirrors :class:`RuntimeProbeTrace` but per-chain: only the FINAL
    step's parsed_result + side_effects participate in
    interpretation. Earlier-step results are journaled for debug + audit
    but never feed Rule 1 / Rule 2.

    The harness emits a single ``CHAIN_RESULT_JSON:{...}`` marker with
    the per-step outcome list, and a ``SIDE_EFFECTS:{...}`` marker at
    end-of-chain. If an early step throws, the chain short-circuits and
    the final step's result is None — the chain didn't reach the
    exploit-trigger position."""

    chain_idx: int
    steps_summary: list[str]
    """One human-readable line per step, e.g.
    ``"step1: parse_config([...]) -> ok type=dict"``."""

    exit_code: int | None
    stdout: str
    stderr: str
    elapsed_ms: int

    per_step_results: list[dict[str, Any]] = field(default_factory=list)
    """One dict per step actually executed (so this can be SHORTER than
    the chain's step count if an early step threw). Each dict carries
    the same shape as :attr:`RuntimeProbeTrace.parsed_result`
    (``ok``, ``type``, ``value_preview``, or ``exception_type`` /
    ``exception_msg``). The LAST entry is what Rule 1 evaluates."""

    side_effects: dict[str, Any] = field(default_factory=dict)
    """End-of-chain ``/tmp`` diff. Same shape as
    :attr:`RuntimeProbeTrace.side_effects`. Rule 2 evaluates this for
    canary markers."""

    short_circuited: bool = False
    """True when an EARLY step (not the last) threw an exception, so
    the chain never reached the exploit-trigger position. Distinct from
    "final step threw" which is a normal chain outcome (the exploit
    raised — still potentially a finding via Rule 2)."""


@dataclass
class RuntimeProbeChainFinding:
    """A finding emitted when a chain's FINAL-step trace matches its
    expected observable. Flows back into the journal as a CONFIRMED
    hypothesis exactly like :class:`RuntimeProbeFinding`, but the
    `description` + `runtime_evidence` make the multi-step structure
    explicit so downstream consumers (journal, report writer,
    adjudicator) can render it correctly."""

    finding_id: str
    """``HRP_C<chain_idx>`` — distinct namespace from single-function
    ``HRP_<c>_<i>`` so chain findings don't collide with candidate
    findings in the same scan."""

    chain_steps: list[str]
    """Per-step ``"function(args_json)"`` strings, in order. Used to
    render the chain in human-readable form in the report."""

    attack_class: str
    severity: str
    cwe: str
    description: str
    runtime_evidence: str
    """Final-step evidence (same shape as
    :attr:`RuntimeProbeFinding.runtime_evidence`) PLUS a brief
    per-step summary so a reviewer can reconstruct the chain without
    digging through the raw trace."""

    chain_inputs_json: str
    """The chain's initial input (step 1's args_json) — the
    attacker-controlled value that flows through the chain."""

    confidence: float = 1.0
    """Confidence score in [0.0, 1.0]. Phase 2 v1.0 calibration:

    * ``1.0`` — Rule 2 canary fired (causal evidence; 0 observed FPs).
    * ``0.7`` — Rule 1 class-signature match (distinctive substring;
      moderate FP risk).
    * ``0.4`` — Rule 1 expected-observable keyword match (low specificity;
      FP source on simulation-branch outputs).

    See :data:`CHAIN_CONFIDENCE_CANARY` /
    :data:`CHAIN_CONFIDENCE_CLASS_SIGNATURE` /
    :data:`CHAIN_CONFIDENCE_OBSERVABLE_KEYWORD` for the constants. The
    adjudicator + report writer filter by confidence threshold to keep
    high-confidence findings prominent and route low-confidence ones to
    operator review."""

    oracle_type: str = "canary"
    """Which oracle confirmed the finding — used for journal traceability.
    One of: ``"canary"`` (Rule 2), ``"class_signature"`` (Rule 1a),
    ``"observable_keyword"`` (Rule 1b). Empty string when interpretation
    didn't return a finding."""


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
    # v15.22 — closes Gemini's Issue 3 (CWE-319 → cleartext probe).
    # Cleartext transmission means credentials / sensitive bytes
    # flowing over plain HTTP instead of HTTPS. Distinct from SSRF
    # (which is about controlling the URL target) — this is about
    # the PROTOCOL the client uses regardless of target.
    "cleartext_transmission": "CWE-319",
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
    "cleartext_transmission": "high",
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


def _python_module_name_for_file(
    file_name: str,
    entry_rel_path: str = "",
) -> str:
    """Derive an import-safe module name for the probe harness.

    Without ``entry_rel_path`` (flat single-file scan):

      ``vulnerable_lib.py`` → ``vulnerable_lib``
      ``mypkg/io_utils.py`` → ``io_utils`` (basename only)

    With ``entry_rel_path`` set (Python package member — sibling
    resolver detected ``from . import`` etc., staged the whole
    package tree under /workspace preserving layout):

      file_name=``unpickler.py``, entry_rel_path=``jsonpickle/unpickler.py``
        → ``jsonpickle.unpickler``
      file_name=``__init__.py``, entry_rel_path=``docutils/__init__.py``
        → ``docutils`` (drop the ``__init__`` suffix — idiomatic
        package import, avoids harness-import ambiguity)

    The dotted name lets the harness ``import jsonpickle.unpickler``
    correctly load the package member from /workspace/jsonpickle/ —
    which is necessary whenever the target file contains relative
    imports (``from .backend import X``). Importing the flat copy at
    /workspace/unpickler.py would fail with
    ``ImportError: attempted relative import with no known parent
    package``.

    Defensive: when any segment of the dotted name is an invalid
    Python identifier (digit-first, hyphen, etc.) we fall back to
    the basename rather than emit a broken ``import`` statement.
    """
    base = Path(file_name).name
    if base.endswith(".py"):
        base = base[: -len(".py")]
    basename_module = "".join(
        ch if ch.isalnum() or ch == "_" else "_" for ch in base
    )

    posix = (entry_rel_path or "").replace("\\", "/").strip().lstrip("./")
    if not posix or not posix.endswith(".py") or "/" not in posix:
        return basename_module

    stem = posix[: -len(".py")]
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    parts = stem.split("/")
    if not parts:
        return basename_module
    # v15.16 (2026-05-20): strip leading ``src/`` segment. Modern Python
    # packages adopting the PEP 518 src-layout (anthropic-sdk-python,
    # most pypa-style projects) put their installable source under
    # ``src/<pkg>/...``. When project_root is detected at the repo
    # root (where pyproject.toml lives), the entry_rel_path becomes
    # ``src/<pkg>/foo/bar.py`` and the dotted module name resolves to
    # ``src.<pkg>.foo.bar`` — which does NOT match the pip-installed
    # ``<pkg>.foo.bar``. The BP harness's ``import <pkg>.foo.bar``
    # then can't find the module via the installed copy.
    #
    # Stripping the leading ``src`` segment when present aligns the
    # harness import with the pip-installed name. This matches the
    # setuptools / hatchling / poetry src-layout convention — the
    # build tools strip ``src/`` exactly the same way when packaging.
    if parts and parts[0] == "src":
        parts = parts[1:]
        if not parts:
            return basename_module
    for seg in parts:
        if not seg or seg[0].isdigit():
            return basename_module
        if not all(ch.isalnum() or ch == "_" for ch in seg):
            return basename_module
    return ".".join(parts)


# ── Path-prep preamble (v1.5 env fix) ────────────────────────────────────
#
# Functions rooted at hard-coded directory prefixes (e.g.,
# ``open("/data/" + user_input)``) need that prefix dir to EXIST in the
# sandbox before path-traversal exploits can fire. Linux's pathname
# resolver requires every intermediate component to exist (and be
# searchable) before it will resolve ``..`` traversals — so an attack
# input like ``../../etc/passwd`` against ``open("/data/" + path)``
# raises ``FileNotFoundError`` BEFORE the traversal can resolve to
# ``/etc/passwd`` if ``/data`` doesn't exist.
#
# Layered defense:
#   * Sandbox Dockerfile pre-creates a curated set of common prefixes
#     (``/data``, ``/srv/app``, ``/var/lib/app``, …) at mode 1777.
#   * This harness preamble auto-detects ANY absolute-path string
#     literal in the target module's source and ``mkdir -p``'s the
#     corresponding parent dir (or the path itself if it looks like a
#     dir prefix). Catches unusual prefixes the Dockerfile list misses.
#
# The deny-list skips well-known read-only/system dirs so we never
# attempt to mkdir at e.g. ``/etc`` (would fail anyway as non-root,
# but explicit skip is safer + cheaper). All exceptions are swallowed
# — a failed mkdir is a no-op, never blocks the probe call itself.

#: Directory prefixes the harness will NOT attempt to create or mutate.
#: System dirs (read-only at runtime, owned by root, sometimes read-only
#: filesystem mounts) — we don't want noise in stderr from PermissionError.
#: Harness-injected helper that decodes bytes-sentinel dicts inside
#: model-emitted args / kwargs. Convention: model emits
#: ``{"__b64__": "<base64-str>"}`` anywhere bytes are needed (XML
#: parsers, network sinks, binary deserializers). Harness post-
#: processes after ``json.loads`` and replaces those sentinels with
#: actual ``bytes``.
#:
#: Why this exists (Gap 2 fix, v1.6): ``json.loads(args_json)`` returns
#: only str / int / float / bool / None / list / dict. Functions that
#: expect ``bytes`` (e.g., ``parse_invoice_xml(xml_bytes: bytes)`` in
#: xrechnung) immediately fail with ValueError / AttributeError at the
#: function-call boundary -- the exploit never reaches the vuln logic.
#: This convention gives the model a way to pass bytes through JSON.
#:
#: Defensive: per-element try/except so a malformed sentinel doesn't
#: take down the harness. A dict with ``__b64__`` and other keys is
#: NOT a sentinel (preserved as a regular dict) -- the model emits
#: pure ``{"__b64__": "..."}`` to opt in.
_BYTES_SENTINEL_HELPER_PY: str = (
    "import base64 as _b64\n"
    "def _decode_bytes_sentinels(obj):\n"
    "    if isinstance(obj, dict):\n"
    "        if list(obj.keys()) == ['__b64__'] and isinstance(obj.get('__b64__'), str):\n"
    "            try:\n"
    "                return _b64.b64decode(obj['__b64__'])\n"
    "            except Exception:\n"
    "                return obj\n"
    "        return {k: _decode_bytes_sentinels(v) for k, v in obj.items()}\n"
    "    if isinstance(obj, list):\n"
    "        return [_decode_bytes_sentinels(x) for x in obj]\n"
    "    return obj\n"
)


_PROBE_PREP_DENY_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/dev",
    "/proc",
    "/sys",
    "/root",
    "/boot",
    "/run",
    "/tmp",  # already exists + canary detection mutates here
)


def _build_python_probe_harness(
    *,
    module_name: str,
    function_name: str,
    args_json: str,
    kwargs_json: str,
    module_file_path: str = "",
    target_kind: str = "function",
    instance_init_args_json: str = "[]",
    instance_init_kwargs_json: str = "{}",
    attack_class: str = "",
    baseline_args_json: str = "",
    baseline_kwargs_json: str = "",
    assertion_expr: str = "",
) -> str:
    """Generate the Python harness that runs ONE probe inside the sandbox.

    Layout:
    1. Snapshot baseline (env, /tmp contents, network log if accessible).
    2. Path-prep preamble: regex-extract absolute-path string literals
       from the target module's source and ``mkdir -p`` the prefix dirs
       so path-traversal exploits can resolve through them.
    3. Import the target module from /workspace.
    4. **v15.18**: Resolve the target via ``target_kind``-aware dispatch
       (function / class_constructor / instance_method / classmethod /
       staticmethod). Falls back to autodetect at call time when the
       caller passed the default ``function`` but the resolved object is
       actually a class or unbound instance method.
    5. Call with the decoded args / kwargs (constructing the instance
       first when target_kind is ``instance_method``).
    6. Print ``RESULT_JSON:{...}`` (outcome) + ``SIDE_EFFECTS:{...}``
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
    deny_repr = repr(_PROBE_PREP_DENY_PREFIXES)
    # v15.18 — kind-aware resolution. Sanitize target_kind to the
    # known set; anything else falls back to "function" (the legacy
    # blind getattr-walk path). This guards against typos or older
    # cached Sonnet outputs landing on the new harness.
    if target_kind not in {
        "function",
        "class_constructor",
        "instance_method",
        "classmethod",
        "staticmethod",
    }:
        target_kind = "function"
    target_kind_repr = repr(target_kind)
    init_args_repr = repr(instance_init_args_json or "[]")
    init_kwargs_repr = repr(instance_init_kwargs_json or "{}")
    # v15.26 — differential fuzzing baseline. When non-empty,
    # ``baseline_args_json`` + ``baseline_kwargs_json`` carry a
    # semantically-stripped version of the attack input (every string
    # replaced with a fixed sentinel). The harness invokes the function
    # with the baseline FIRST, captures the outcome, then invokes with
    # the attack input. The matcher uses the baseline outcome to detect
    # uniform-validation false positives — when both raise the same
    # exception class with structurally-identical messages, the
    # function rejected both identically and the attack payload wasn't
    # special. Disabled when the JSON params are empty (back-compat
    # with callers that don't pass baseline).
    _differential_enabled = bool(baseline_args_json and baseline_kwargs_json)
    differential_enabled_repr = repr(_differential_enabled)
    baseline_args_repr = repr(baseline_args_json or "[]")
    baseline_kwargs_repr = repr(baseline_kwargs_json or "{}")
    # v15.22 — wiretap mode for cleartext_transmission probes. When
    # active, the harness starts a local HTTP listener on a fixed port,
    # substitutes ``__ARGUS_WIRETAP_URL__`` placeholders in args/kwargs
    # with the listener URL, then captures any bytes the function-under-
    # test transmits. Captured bytes (headers, body) are emitted as a
    # WIRETAP block inside RESULT_JSON.value_preview so the existing
    # class-signature oracle can fire on the v15.22 signatures
    # (ARGUS_WIRETAP_CLEARTEXT_OBSERVED, Authorization: Bearer, etc).
    _wiretap_enabled = (attack_class == "cleartext_transmission")
    wiretap_enabled_repr = repr(_wiretap_enabled)
    return (
        "import sys, os, json, traceback, re\n"
        "sys.path.insert(0, '/workspace')\n"
        # ── Deep value preview helper (v1.6 Path 2 oracle fix) ───────────
        # repr() on complex objects hides the actual content -- e.g.
        # lxml.Element renders as '<Element Invoice at 0x...>', not the
        # entity-resolved text. Rule 1's substring oracle (matching
        # 'root:x:0:0:' for path_traversal, etc.) can't fire on hidden
        # data. This helper surfaces the inner content from lxml.Element,
        # dict, list/tuple/set, and class instances with __dict__ so the
        # oracle has something to match against. Per-branch try/except
        # so a misbehaving __repr__ never crashes the harness.
        "def _deep_value_preview(result, max_len=2500):\n"
        "    parts = []\n"
        "    try:\n"
        "        parts.append(repr(result)[:600])\n"
        "    except Exception:\n"
        "        parts.append('<repr failed>')\n"
        "    try:\n"
        "        _is_elem_like = (\n"
        "            hasattr(result, 'iter') and hasattr(result, 'tag')\n"
        "            and not isinstance(result, (str, bytes, list, dict, tuple, set))\n"
        "        )\n"
        "        if _is_elem_like:\n"
        "            try:\n"
        "                from lxml import etree as _etree\n"
        "                txt = _etree.tostring(result, method='text', encoding='unicode')\n"
        "                parts.append('TEXT:' + txt[:1200])\n"
        "            except Exception:\n"
        "                pass\n"
        "    except Exception:\n"
        "        pass\n"
        "    if isinstance(result, dict):\n"
        "        try:\n"
        "            items = list(result.items())[:50]\n"
        "            parts.append('DICT:' + str(dict(items))[:800])\n"
        "        except Exception:\n"
        "            pass\n"
        "    elif isinstance(result, (list, tuple, set)):\n"
        "        try:\n"
        "            seq = list(result)[:30]\n"
        "            parts.append('SEQ:' + str(seq)[:800])\n"
        "        except Exception:\n"
        "            pass\n"
        "    elif hasattr(result, '__dict__'):\n"
        "        try:\n"
        "            attrs = vars(result)\n"
        "            if attrs:\n"
        "                items = list(attrs.items())[:30]\n"
        "                parts.append('ATTRS:' + str(dict(items))[:800])\n"
        "        except Exception:\n"
        "            pass\n"
        "    return ' | '.join(parts)[:max_len]\n"
        "baseline_tmp = set()\n"
        "try:\n"
        "    baseline_tmp = set(os.listdir('/tmp'))\n"
        "except Exception:\n"
        "    pass\n"
        # ── Path-prep preamble ─────────────────────────────────────────────
        # Regex picks up '/letter[\\w./-]*' string literals from source.
        # For each, mkdir-p the dirname (or the path itself if it ends in '/'
        # or has no extension — i.e., looks like a dir prefix not a file).
        # Skips system prefixes; swallows OSError/PermissionError silently.
        f"_DENY = {deny_repr}\n"
        # When ``module_file_path`` is supplied (package members staged
        # with their package layout, e.g. ``/workspace/jsonpickle/
        # unpickler.py``), use the explicit on-disk path. Otherwise fall
        # back to the flat-module convention (``/workspace/<basename>.py``).
        f"_module_path = {(module_file_path or f'/workspace/{module_name}.py')!r}\n"
        "_paths_to_prep = set()\n"
        "try:\n"
        "    _src = open(_module_path).read()\n"
        "    _paths_to_prep = set(re.findall("
        "r'''[\"\\']((?:/[A-Za-z_][\\w./-]*))[\"\\']''', _src))\n"
        "except Exception:\n"
        "    pass\n"
        "_abs_dir_prefixes = set()\n"
        "for _p in _paths_to_prep:\n"
        "    if any(_p == d or _p.startswith(d + '/') for d in _DENY):\n"
        "        continue\n"
        "    try:\n"
        "        _bn = os.path.basename(_p.rstrip('/'))\n"
        "        # If it looks like a file (basename has '.'), mkdir parent;\n"
        "        # else (looks like a dir prefix), mkdir the path itself.\n"
        "        _looks_like_file = '.' in _bn and not _p.endswith('/')\n"
        "        _to_mk = os.path.dirname(_p) if _looks_like_file else _p.rstrip('/')\n"
        "        if _to_mk and _to_mk != '/':\n"
        "            os.makedirs(_to_mk, exist_ok=True)\n"
        "            _abs_dir_prefixes.add(_to_mk)\n"
        "    except (OSError, PermissionError):\n"
        "        pass\n"
        # ── End source path-prep ──────────────────────────────────────────
        + _BYTES_SENTINEL_HELPER_PY
        + f"args = _decode_bytes_sentinels(json.loads({args_repr}))\n"
        f"kwargs = _decode_bytes_sentinels(json.loads({kwargs_repr}))\n"
        # ── v15.22 wiretap preamble (cleartext_transmission only) ─────────
        # Sets up a local HTTP listener that captures any outbound bytes
        # the function-under-test transmits, then substitutes the listener
        # URL into any ``__ARGUS_WIRETAP_URL__`` placeholders in args/
        # kwargs. The listener runs in a daemon thread and is reaped at
        # postamble time. Closed-over by the dispatch block below.
        f"_argus_wiretap_enabled = {wiretap_enabled_repr}\n"
        "_argus_wiretap_capture = []\n"
        "_argus_wiretap_stop = [False]  # mutable for thread comms\n"
        "_argus_wiretap_url = ''\n"
        "_argus_wiretap_thread = None\n"
        "if _argus_wiretap_enabled:\n"
        "    import socket as _argus_socket\n"
        "    import threading as _argus_threading\n"
        # Try ports 47888..47898 — handle bind clash from leftover
        # sockets across rapid re-runs.
        "    _argus_wiretap_port = 0\n"
        "    _argus_wiretap_sock = None\n"
        "    for _p in range(47888, 47898):\n"
        "        try:\n"
        "            _s = _argus_socket.socket(_argus_socket.AF_INET, _argus_socket.SOCK_STREAM)\n"
        "            _s.setsockopt(_argus_socket.SOL_SOCKET, _argus_socket.SO_REUSEADDR, 1)\n"
        "            _s.bind(('127.0.0.1', _p))\n"
        "            _s.listen(5)\n"
        "            _s.settimeout(0.3)\n"
        "            _argus_wiretap_sock = _s\n"
        "            _argus_wiretap_port = _p\n"
        "            break\n"
        "        except OSError:\n"
        "            continue\n"
        "    if _argus_wiretap_sock is not None:\n"
        "        _argus_wiretap_url = 'http://127.0.0.1:' + str(_argus_wiretap_port) + '/argus_probe_cleartext'\n"
        "        def _argus_wiretap_loop(srv):\n"
        "            while not _argus_wiretap_stop[0]:\n"
        "                try:\n"
        "                    conn, _ = srv.accept()\n"
        "                    conn.settimeout(1.5)\n"
        "                    buf = b''\n"
        "                    while True:\n"
        "                        try:\n"
        "                            chunk = conn.recv(4096)\n"
        "                        except Exception:\n"
        "                            break\n"
        "                        if not chunk: break\n"
        "                        buf += chunk\n"
        "                        if b'\\r\\n\\r\\n' in buf or len(buf) > 32768: break\n"
        "                    try:\n"
        "                        decoded = buf.decode('utf-8', errors='replace')\n"
        "                    except Exception:\n"
        "                        decoded = repr(buf[:2000])\n"
        "                    _argus_wiretap_capture.append(\n"
        "                        'ARGUS_WIRETAP_CLEARTEXT_OBSERVED: ' + decoded[:1800]\n"
        "                    )\n"
        "                    try:\n"
        "                        conn.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n')\n"
        "                    except Exception: pass\n"
        "                    try:\n"
        "                        conn.close()\n"
        "                    except Exception: pass\n"
        "                except _argus_socket.timeout:\n"
        "                    continue\n"
        "                except Exception:\n"
        "                    continue\n"
        "        _argus_wiretap_thread = _argus_threading.Thread(\n"
        "            target=_argus_wiretap_loop, args=(_argus_wiretap_sock,), daemon=True\n"
        "        )\n"
        "        _argus_wiretap_thread.start()\n"
        # Substitute __ARGUS_WIRETAP_URL__ placeholders in args/kwargs.
        "        def _argus_subst(o):\n"
        "            if isinstance(o, str):\n"
        "                return o.replace('__ARGUS_WIRETAP_URL__', _argus_wiretap_url)\n"
        "            if isinstance(o, dict):\n"
        "                return {k: _argus_subst(v) for k, v in o.items()}\n"
        "            if isinstance(o, list):\n"
        "                return [_argus_subst(v) for v in o]\n"
        "            return o\n"
        "        args = _argus_subst(args)\n"
        "        kwargs = _argus_subst(kwargs)\n"
        # ── End v15.22 wiretap preamble ───────────────────────────────────
        # ── Input-derived path-prep ───────────────────────────────────────
        # When the function is rooted at hard-coded prefix dirs (e.g.
        # ``open("/data/" + path)``) and the attack input contains DIRECT
        # path components (not just ``..``/``.``), Linux's path resolver
        # needs ``<prefix>/<components>/...`` to exist before traversal
        # can resolve through it. Example: input ``subdir/../../etc/passwd``
        # against ``open("/data/" + path)`` resolves only when
        # ``/data/subdir/`` exists. mkdir-p the cartesian product of
        # source prefixes × input direct-component prefixes.
        "_skip = {'..', '.', ''}\n"
        "for _arg in args + list(kwargs.values()):\n"
        "    if not (isinstance(_arg, str) and '/' in _arg):\n"
        "        continue\n"
        "    _comps = [c for c in _arg.split('/') if c not in _skip]\n"
        "    if not _comps:\n"
        "        continue\n"
        # last component assumed to be the target file; build under
        # progressively-deeper prefixes for each preceding component.
        "    for _depth in range(1, len(_comps)):\n"
        "        _rel = '/'.join(_comps[:_depth])\n"
        "        for _src_dir in _abs_dir_prefixes:\n"
        "            try:\n"
        "                _full = _src_dir.rstrip('/') + '/' + _rel\n"
        "                if any(_full == d or _full.startswith(d + '/') for d in _DENY):\n"
        "                    continue\n"
        "                os.makedirs(_full, exist_ok=True)\n"
        "            except (OSError, PermissionError):\n"
        "                pass\n"
        # ── End input path-prep ───────────────────────────────────────────
        # v15.1 (2026-05-20): graceful degradation. Primary import
        # via the qualified module name. If that fails (pip install of
        # own dist failed, network outage, package pulled from PyPI),
        # fall back to importlib.util.spec_from_file_location on the
        # on-disk file path. The fallback handles offline / private
        # / deprecated-package cases without losing the entire scan.
        # Both failures emit a structured RESULT_JSON so the trace
        # parser sees a clear exception_type rather than the harness
        # crashing silently at the top level.
        "try:\n"
        f"    import {module_name} as _target\n"
        "except BaseException as _argus_primary_import_err:\n"
        "    import importlib.util as _argus_ilu\n"
        f"    _argus_spec = _argus_ilu.spec_from_file_location(\n"
        f"        '_argus_target', _module_path\n"
        "    )\n"
        "    if _argus_spec is None or _argus_spec.loader is None:\n"
        "        print('RESULT_JSON:' + json.dumps({\n"
        "            'ok': False,\n"
        "            'exception_type': type(_argus_primary_import_err).__name__,\n"
        "            'exception_msg': (\n"
        "                f'primary import failed ({_argus_primary_import_err!r}); '\n"
        "                f'file-path fallback unavailable for {_module_path!r}'\n"
        "            )[:300],\n"
        "        }))\n"
        "        print('SIDE_EFFECTS:' + json.dumps({'tmp_files_added': []}))\n"
        "        sys.exit(0)\n"
        "    _target = _argus_ilu.module_from_spec(_argus_spec)\n"
        "    try:\n"
        "        _argus_spec.loader.exec_module(_target)\n"
        "    except BaseException as _argus_fallback_err:\n"
        "        print('RESULT_JSON:' + json.dumps({\n"
        "            'ok': False,\n"
        "            'exception_type': type(_argus_fallback_err).__name__,\n"
        "            'exception_msg': (\n"
        "                f'primary import failed ({_argus_primary_import_err!r}); '\n"
        "                f'file-path fallback also failed: {_argus_fallback_err!r}'\n"
        "            )[:300],\n"
        "            'tb_tail': traceback.format_exc()[-1500:],\n"
        "        }))\n"
        "        print('SIDE_EFFECTS:' + json.dumps({'tmp_files_added': []}))\n"
        "        sys.exit(0)\n"
        # ── v15.18: kind-aware target resolution ──────────────────────────
        # Pre-v15.18 blind getattr walk produced TypeError on instance
        # methods (missing self) and __init__ targets (missing self +
        # positional args). The anthropic-sdk-python credentials/_providers
        # campaign showed 7/8 HRP probes failing with this exact TypeError
        # shape. v15.18 dispatches by target_kind:
        #   * function          — walk + call (legacy)
        #   * class_constructor — call the class directly with test args
        #                         (parts[:-1] resolves the class; ignore
        #                         the __init__ suffix entirely)
        #   * instance_method   — instantiate the class with init args,
        #                         then call instance.method(*args, **kwargs)
        #   * classmethod /     — walk + call (semantically equivalent to
        #     staticmethod        function — kind kept for trace clarity)
        #
        # Autodetect fallback: when target_kind=="function" but the
        # walked-to parent is actually a class (i.e., the schema-emitter
        # forgot to set target_kind for a method target), we promote at
        # runtime — final segment ``__init__`` becomes class_constructor,
        # anything else becomes instance_method with empty init args.
        # Degrades gracefully on legacy candidates without breaking the
        # well-classified happy path.
        f"_argus_target_kind = {target_kind_repr}\n"
        f"_argus_init_args = _decode_bytes_sentinels(json.loads({init_args_repr}))\n"
        f"_argus_init_kwargs = _decode_bytes_sentinels(json.loads({init_kwargs_repr}))\n"
        "import inspect as _argus_inspect\n"
        f"_argus_parts = {safe_function!r}.split('.')\n"
        "_argus_parent = _target\n"
        "for _argus_p in _argus_parts[:-1]:\n"
        "    _argus_parent = getattr(_argus_parent, _argus_p)\n"
        "_argus_tail = _argus_parts[-1] if _argus_parts else ''\n"
        # Autodetect: legacy candidates with target_kind=='function' but
        # the parent of the tail is a class. Promote to the right kind.
        "if _argus_target_kind == 'function' and _argus_inspect.isclass(_argus_parent):\n"
        "    if _argus_tail == '__init__':\n"
        "        _argus_target_kind = 'class_constructor'\n"
        "    else:\n"
        "        _argus_descriptor = _argus_parent.__dict__.get(_argus_tail)\n"
        "        if isinstance(_argus_descriptor, staticmethod):\n"
        "            _argus_target_kind = 'staticmethod'\n"
        "        elif isinstance(_argus_descriptor, classmethod):\n"
        "            _argus_target_kind = 'classmethod'\n"
        "        else:\n"
        "            _argus_target_kind = 'instance_method'\n"
        # v15.20 — Constructor dependency injection.
        # When Sonnet provides ``instance_init_args/kwargs`` they win.
        # When Sonnet doesn't (or provides incomplete args), introspect
        # the class's __init__ via inspect.signature and synthesize
        # default values matching each parameter's annotated type. This
        # closes Gemini's Issue 1c: complex constructors like
        # ``__init__(self, db: Connection, config: AppConfig)`` no
        # longer TypeError when Sonnet passes ``{}``. The fallback is
        # defensive — when synthesis can't determine a value, leave
        # the parameter unset and let the constructor's natural error
        # surface (preserves diagnostic fidelity).
        "def _argus_synth_default(annotation):\n"
        "    '''Map a type annotation to a safe default value.'''\n"
        "    if annotation is _argus_inspect.Parameter.empty:\n"
        "        return None\n"
        "    try:\n"
        "        if annotation is str: return ''\n"
        "        if annotation is int: return 0\n"
        "        if annotation is float: return 0.0\n"
        "        if annotation is bool: return False\n"
        "        if annotation is bytes: return b''\n"
        "        if annotation is dict: return {}\n"
        "        if annotation is list: return []\n"
        "        if annotation is tuple: return ()\n"
        "        if annotation is set: return set()\n"
        "        if annotation is type(None): return None\n"
        "        if isinstance(annotation, str):\n"
        "            n = annotation.lower()\n"
        "            if 'str' in n: return ''\n"
        "            if 'path' in n: return '/tmp/argus_mock_path'\n"
        "            if 'int' in n: return 0\n"
        "            if 'bool' in n: return False\n"
        "            if 'dict' in n: return {}\n"
        "            if 'list' in n: return []\n"
        "        try:\n"
        "            from pathlib import Path as _P\n"
        "            if annotation is _P: return _P('/tmp/argus_mock_path')\n"
        "        except Exception: pass\n"
        "        origin = getattr(annotation, '__origin__', None)\n"
        "        if origin is dict: return {}\n"
        "        if origin in (list, set, tuple): return origin()\n"
        "        try:\n"
        "            return annotation()\n"
        "        except Exception:\n"
        "            return object.__new__(annotation) if isinstance(annotation, type) else None\n"
        "    except Exception:\n"
        "        return None\n"
        "def _argus_construct(cls, supplied_args, supplied_kwargs):\n"
        "    '''Build an instance of cls, filling __init__ gaps via synth.'''\n"
        "    try:\n"
        "        sig = _argus_inspect.signature(cls.__init__)\n"
        "    except (ValueError, TypeError):\n"
        "        return cls(*supplied_args, **supplied_kwargs)\n"
        "    params = [p for n, p in sig.parameters.items() if n != 'self']\n"
        "    n_supplied_pos = len(supplied_args)\n"
        "    final_args = list(supplied_args)\n"
        "    final_kwargs = dict(supplied_kwargs)\n"
        "    for i, p in enumerate(params):\n"
        "        if p.kind in (\n"
        "            _argus_inspect.Parameter.VAR_POSITIONAL,\n"
        "            _argus_inspect.Parameter.VAR_KEYWORD,\n"
        "        ):\n"
        "            continue\n"
        "        if p.default is not _argus_inspect.Parameter.empty:\n"
        "            continue  # has a default; leave for cls to use\n"
        "        if p.name in final_kwargs:\n"
        "            continue\n"
        "        if p.kind == _argus_inspect.Parameter.POSITIONAL_OR_KEYWORD and i < n_supplied_pos:\n"
        "            continue\n"
        "        synth = _argus_synth_default(p.annotation)\n"
        "        final_kwargs[p.name] = synth\n"
        "    return cls(*final_args, **final_kwargs)\n"
        # ── v15.26: differential fuzzing baseline ─────────────────────────
        # Invoke the function with semantically-stripped baseline args
        # BEFORE the attack call. Outcome captured as
        # ``_argus_baseline_outcome`` and emitted via the
        # BASELINE_RESULT_JSON marker so the matcher can compare
        # baseline-vs-attack and refute uniform-validation FPs.
        # Exceptions during baseline are EXPECTED — the baseline is
        # garbage by design — and don't propagate to the attack call.
        f"_argus_differential_enabled = {differential_enabled_repr}\n"
        "_argus_baseline_outcome = None\n"
        "if _argus_differential_enabled:\n"
        f"    _argus_baseline_args = _decode_bytes_sentinels(json.loads({baseline_args_repr}))\n"
        f"    _argus_baseline_kwargs = _decode_bytes_sentinels(json.loads({baseline_kwargs_repr}))\n"
        "    try:\n"
        "        if _argus_target_kind == 'class_constructor':\n"
        "            _argus_baseline_result = _argus_construct(\n"
        "                _argus_parent, _argus_baseline_args, _argus_baseline_kwargs\n"
        "            )\n"
        "        elif _argus_target_kind == 'instance_method':\n"
        "            _argus_baseline_instance = _argus_construct(\n"
        "                _argus_parent, _argus_init_args, _argus_init_kwargs\n"
        "            )\n"
        "            _argus_baseline_method = getattr(_argus_baseline_instance, _argus_tail)\n"
        "            _argus_baseline_result = _argus_baseline_method(\n"
        "                *_argus_baseline_args, **_argus_baseline_kwargs\n"
        "            )\n"
        "        else:\n"
        "            _argus_baseline_fn = _argus_parent if _argus_target_kind != 'function' else _target\n"
        "            if _argus_target_kind == 'function':\n"
        "                for _argus_bp in _argus_parts:\n"
        "                    _argus_baseline_fn = getattr(_argus_baseline_fn, _argus_bp)\n"
        "            else:\n"
        "                _argus_baseline_fn = getattr(_argus_parent, _argus_tail)\n"
        "            _argus_baseline_result = _argus_baseline_fn(\n"
        "                *_argus_baseline_args, **_argus_baseline_kwargs\n"
        "            )\n"
        "        _argus_baseline_outcome = {\n"
        "            'ok': True,\n"
        "            'exception_type': '',\n"
        "            'exception_msg': '',\n"
        "            'type': type(_argus_baseline_result).__name__,\n"
        "        }\n"
        "    except BaseException as _argus_baseline_err:\n"
        "        _argus_baseline_outcome = {\n"
        "            'ok': False,\n"
        "            'exception_type': type(_argus_baseline_err).__name__,\n"
        "            'exception_msg': str(_argus_baseline_err)[:300],\n"
        "            'type': None,\n"
        "        }\n"
        "print('BASELINE_RESULT_JSON:' + json.dumps(_argus_baseline_outcome or {}))\n"
        # ── End v15.26 baseline ───────────────────────────────────────────
        "try:\n"
        "    if _argus_target_kind == 'class_constructor':\n"
        "        result = _argus_construct(_argus_parent, args, kwargs)\n"
        "    elif _argus_target_kind == 'instance_method':\n"
        "        _argus_instance = _argus_construct(_argus_parent, _argus_init_args, _argus_init_kwargs)\n"
        "        _argus_method = getattr(_argus_instance, _argus_tail)\n"
        "        result = _argus_method(*args, **kwargs)\n"
        "    else:\n"
        "        # function / classmethod / staticmethod — walk + call\n"
        "        fn = _argus_parent if _argus_target_kind != 'function' else _target\n"
        "        if _argus_target_kind == 'function':\n"
        "            for _argus_p in _argus_parts:\n"
        "                fn = getattr(fn, _argus_p)\n"
        "        else:\n"
        "            fn = getattr(_argus_parent, _argus_tail)\n"
        "        result = fn(*args, **kwargs)\n"
        # v15.22 — build the value_preview, appending wiretap capture
        # when present. The class-signature oracle scans value_preview
        # for the cleartext_transmission signatures
        # (ARGUS_WIRETAP_CLEARTEXT_OBSERVED, Authorization: Bearer, etc).
        "    _argus_vp = _deep_value_preview(result)\n"
        "    if _argus_wiretap_enabled and _argus_wiretap_capture:\n"
        "        _argus_vp = _argus_vp + ' | argus_wiretap_scheme=http | ' + ' | '.join(_argus_wiretap_capture)\n"
        "    elif _argus_wiretap_enabled:\n"
        "        _argus_vp = _argus_vp + ' | argus_wiretap_no_capture'\n"
        # Phase 1 (SCAN-016) — structured-assertion oracle.
        # When ``assertion_expr`` is non-empty, evaluate it against the
        # live ``result`` object in a restricted namespace. The harness
        # itself does the eval — that way the assertion sees the un-
        # stringified object (with all its attributes, methods, type),
        # which is the whole point of moving away from substring oracles.
        f"    _argus_assertion_expr = {repr(assertion_expr)}\n"
        "    _argus_assertion_passed = None\n"
        "    _argus_assertion_error = ''\n"
        "    if _argus_assertion_expr:\n"
        "        try:\n"
        "            _argus_assert_globals = {\n"
        "                '__builtins__': {\n"
        "                    'len': len, 'isinstance': isinstance,\n"
        "                    'hasattr': hasattr, 'getattr': getattr,\n"
        "                    'str': str, 'int': int, 'float': float,\n"
        "                    'bool': bool, 'list': list, 'dict': dict,\n"
        "                    'tuple': tuple, 'set': set,\n"
        "                    'any': any, 'all': all, 'type': type,\n"
        "                    'repr': repr, 'abs': abs, 'min': min, 'max': max,\n"
        "                    'True': True, 'False': False, 'None': None,\n"
        "                },\n"
        "            }\n"
        "            _argus_assert_locals = {\n"
        "                'result': result,\n"
        "                'args': args,\n"
        "                'kwargs': kwargs,\n"
        "            }\n"
        "            _argus_assertion_passed = bool(\n"
        "                eval(_argus_assertion_expr, _argus_assert_globals, _argus_assert_locals)\n"
        "            )\n"
        "        except BaseException as _argus_assert_e:\n"
        "            _argus_assertion_passed = None\n"
        "            _argus_assertion_error = (\n"
        "                type(_argus_assert_e).__name__ + ': ' + str(_argus_assert_e)[:200]\n"
        "            )\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': True,\n"
        "        'type': type(result).__name__,\n"
        "        'value_preview': _argus_vp,\n"
        "        'target_kind': _argus_target_kind,\n"
        "        'wiretap_active': _argus_wiretap_enabled,\n"
        "        'wiretap_captures': len(_argus_wiretap_capture),\n"
        "        'assertion_passed': _argus_assertion_passed,\n"
        "        'assertion_error': _argus_assertion_error,\n"
        "        'assertion_expr': _argus_assertion_expr,\n"
        "    }))\n"
        "except SystemExit as e:\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': False,\n"
        "        'exception_type': 'SystemExit',\n"
        "        'exception_msg': str(e)[:300],\n"
        "    }))\n"
        "except BaseException as e:\n"
        # v15.22 — when an SSL/TLS error fired (function refused to
        # transmit over plain HTTP), surface that as REFUTED evidence
        # by including the captured-vs-uncaptured state in the message.
        # When wiretap captured bytes BEFORE the exception was raised,
        # those bytes still represent a real cleartext transmission and
        # must surface in exception_msg so Rule 1b can fire.
        "    _argus_exc_msg = str(e)[:300]\n"
        "    if _argus_wiretap_enabled and _argus_wiretap_capture:\n"
        "        _argus_exc_msg = (\n"
        "            _argus_exc_msg + ' | argus_wiretap_scheme=http | ' +\n"
        "            ' | '.join(_argus_wiretap_capture)[:1500]\n"
        "        )\n"
        "    elif _argus_wiretap_enabled:\n"
        # Exception path with no capture = function refused to transmit
        # (TLS-required ValueError, SSL error, etc). Emit the REFUTED-
        # equivalent marker so the matcher / operator sees clean refusal.
        "        _argus_exc_msg = _argus_exc_msg + ' | argus_wiretap_no_capture'\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': False,\n"
        "        'exception_type': type(e).__name__,\n"
        "        'exception_msg': _argus_exc_msg,\n"
        "        'tb_tail': traceback.format_exc()[-1500:],\n"
        "        'wiretap_active': _argus_wiretap_enabled,\n"
        "        'wiretap_captures': len(_argus_wiretap_capture),\n"
        "    }))\n"
        # Wiretap teardown (regardless of try/except outcome).
        "if _argus_wiretap_enabled and _argus_wiretap_thread is not None:\n"
        "    _argus_wiretap_stop[0] = True\n"
        "    try:\n"
        "        _argus_wiretap_thread.join(timeout=1.0)\n"
        "    except Exception: pass\n"
        "added_tmp = []\n"
        "try:\n"
        "    added_tmp = sorted(set(os.listdir('/tmp')) - baseline_tmp)\n"
        "except Exception:\n"
        "    pass\n"
        "print('SIDE_EFFECTS:' + json.dumps({\n"
        "    'tmp_files_added': added_tmp[:20],\n"
        "}))\n"
    )


# ── JavaScript harness generation ────────────────────────────────────────


def _javascript_module_path_for_file(file_name: str) -> str:
    """The absolute path Node should ``import()`` to load the staged
    module. Sandbox guarantees the file lives at ``/workspace/<basename>``.

    Unlike Python (where we strip the extension and rely on the import
    machinery), Node's dynamic ``import()`` takes a path — extension
    included — and figures out the loader from there. Trailing chars
    that would break a path import are not legal in Node module specifiers
    anyway, so we just pass the basename verbatim.
    """
    return f"/workspace/{Path(file_name).name}"


def _build_javascript_probe_harness(
    *,
    module_path: str,
    function_name: str,
    args_json: str,
    kwargs_json: str,
) -> str:
    """Generate the Node.js harness that runs ONE probe inside the sandbox.

    Layout (mirrors the Python harness for symmetry):
    1. Snapshot baseline (/tmp listing).
    2. Path-prep preamble — extract absolute-path string literals from
       source and from input args, ``fs.mkdirSync(..., {recursive: true})``
       each.
    3. Dynamic ``import()`` the target module.
    4. Resolve the function with a dotted-path walk supporting both
       CommonJS (``module.exports``) and ES-module (``export default``)
       layouts.
    5. Call with decoded args / kwargs. Async functions are awaited.
    6. Print ``RESULT_JSON:{...}`` + ``SIDE_EFFECTS:{...}`` markers — the
       deterministic interpreter rules then run on these the same way
       they do for Python.

    Wrapped in an async IIFE so top-level ``await`` works on Node 18+.
    """
    # Embed args/kwargs as JSON-in-JS-string-literal — JSON.parse handles
    # the unwrap. Use JSON.stringify to safely encode the args_json /
    # kwargs_json strings into JS string literals.
    args_json_lit = json.dumps(args_json)
    kwargs_json_lit = json.dumps(kwargs_json)
    function_name_lit = json.dumps(function_name)
    module_path_lit = json.dumps(module_path)
    deny_lit = json.dumps(list(_PROBE_PREP_DENY_PREFIXES))
    return (
        # ── Catastrophic-failure safety net ─────────────────────────────────
        # Real-fixture runs surfaced a class of failure where Node exited
        # code 1 without emitting any RESULT_JSON marker — the harness
        # crashed before its try/catch around the import block could fire
        # (e.g., JSON.parse on a malformed payload, or an unhandled
        # rejection from an async path-prep call). The interpreter then
        # got parsed_result=None and journaled "no exploit observed" with
        # an empty exception_type — a silent failure that looks identical
        # to "probe ran cleanly, no exploit found".
        #
        # Fix: install process-level handlers FIRST so any exception or
        # unhandled rejection is converted into a RESULT_JSON marker
        # before Node exits. Idempotency-safe: the markers are emitted by
        # the normal-path code below when execution reaches it.
        "let _markerEmitted = false;\n"
        "function _emitFatal(label, err) {\n"
        "  if (_markerEmitted) return;\n"
        "  _markerEmitted = true;\n"
        "  const msg = err && (err.message || err.toString) "
        "? String(err.message || err).slice(0, 300) : String(err).slice(0, 300);\n"
        "  const stack = err && err.stack ? String(err.stack).slice(-1500) : '';\n"
        "  const ctor = err && err.constructor && err.constructor.name "
        "? err.constructor.name : 'Error';\n"
        "  try {\n"
        "    console.log('RESULT_JSON:' + JSON.stringify({\n"
        "      ok: false,\n"
        "      exception_type: ctor,\n"
        "      exception_msg: '[' + label + '] ' + msg,\n"
        "      tb_tail: stack,\n"
        "    }));\n"
        "    console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: [] }));\n"
        "  } catch (e) {}\n"
        "}\n"
        "process.on('uncaughtException', (e) => _emitFatal('uncaughtException', e));\n"
        "process.on('unhandledRejection', (e) => _emitFatal('unhandledRejection', e));\n"
        # Harness-level inner timeout (45s, well under the entrypoint's
        # per-command timer). If the harness is still alive at this
        # point, the target function call has been hanging — emit a
        # RESULT_JSON marker with exception_type=HarnessTimeout so the
        # orchestrator gets actionable evidence ("call exceeded budget")
        # rather than a silent stdout_len=0 failure. Note this ONLY
        # fires for ASYNC-blocking hangs; synchronous CPU-bound hangs
        # (where the event loop never returns to schedule callbacks)
        # bypass setTimeout and require the outer probe timeout to be
        # large enough for the work to actually complete.
        "setTimeout(() => _emitFatal('innerHarnessTimeout', "
        "new Error('function call exceeded 45s inner budget')), 45000).unref();\n"
        "(async () => {\n"
        # Wrap the entire body in try/catch so SYNC throws at the IIFE
        # top level (JSON.parse failures, ReferenceErrors before the
        # import block, etc.) still get reported as RESULT_JSON. The
        # individual try/catch blocks below remain — they emit more
        # specific exception_type labels for the common cases.
        "  try {\n"
        "  const fs = require('fs');\n"
        "  const path = require('path');\n"
        "  let baselineTmp = new Set();\n"
        "  try {\n"
        "    baselineTmp = new Set(fs.readdirSync('/tmp'));\n"
        "  } catch (e) {}\n"
        "  const args = JSON.parse(" + args_json_lit + ");\n"
        "  const kwargs = JSON.parse(" + kwargs_json_lit + ");\n"
        "  const fnName = " + function_name_lit + ";\n"
        # ── Path-prep preamble ──────────────────────────────────────────
        "  const DENY = " + deny_lit + ";\n"
        "  const absDirPrefixes = new Set();\n"
        "  try {\n"
        "    const src = fs.readFileSync(" + module_path_lit + ", 'utf8');\n"
        "    const re = /['\"](\\/[A-Za-z_][\\w./-]*)['\"]/g;\n"
        "    const matches = new Set();\n"
        "    let m;\n"
        "    while ((m = re.exec(src)) !== null) matches.add(m[1]);\n"
        "    for (const p of matches) {\n"
        "      if (DENY.some(d => p === d || p.startsWith(d + '/'))) continue;\n"
        "      try {\n"
        "        const bn = path.basename(p.replace(/\\/$/, ''));\n"
        "        const looksLikeFile = bn.includes('.') && !p.endsWith('/');\n"
        "        const toMk = looksLikeFile ? path.dirname(p) : p.replace(/\\/$/, '');\n"
        "        if (toMk && toMk !== '/') {\n"
        "          fs.mkdirSync(toMk, { recursive: true });\n"
        "          absDirPrefixes.add(toMk);\n"
        "        }\n"
        "      } catch (e) {}\n"
        "    }\n"
        "  } catch (e) {}\n"
        # ── Input-derived path-prep ─────────────────────────────────────
        "  const SKIP = new Set(['..', '.', '']);\n"
        "  const allInputs = [...args, ...Object.values(kwargs)];\n"
        "  for (const a of allInputs) {\n"
        "    if (typeof a !== 'string' || !a.includes('/')) continue;\n"
        "    const comps = a.split('/').filter(c => !SKIP.has(c));\n"
        "    if (comps.length === 0) continue;\n"
        "    for (let depth = 1; depth < comps.length; depth++) {\n"
        "      const rel = comps.slice(0, depth).join('/');\n"
        "      for (const srcDir of absDirPrefixes) {\n"
        "        try {\n"
        "          const full = srcDir.replace(/\\/$/, '') + '/' + rel;\n"
        "          if (DENY.some(d => full === d || full.startsWith(d + '/'))) continue;\n"
        "          fs.mkdirSync(full, { recursive: true });\n"
        "        } catch (e) {}\n"
        "      }\n"
        "    }\n"
        "  }\n"
        # ── Module resolution ───────────────────────────────────────────
        # Dynamic import() supports both CJS and ESM. For CJS modules
        # the named exports appear directly on the module namespace;
        # for ESM-default-export they appear on .default.
        "  let mod;\n"
        "  try {\n"
        "    mod = await import(" + module_path_lit + ");\n"
        "  } catch (e) {\n"
        "    _markerEmitted = true;\n"
        "    console.log('RESULT_JSON:' + JSON.stringify({\n"
        "      ok: false,\n"
        "      exception_type: 'ImportError',\n"
        "      exception_msg: String(e.message || e).slice(0, 300),\n"
        "    }));\n"
        "    console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: [] }));\n"
        "    return;\n"
        "  }\n"
        # Dotted-path resolver — try direct attr walk, then .default.
        "  function resolveFn(modObj, dotted) {\n"
        "    const parts = dotted.split('.');\n"
        "    let cur = modObj;\n"
        "    for (const p of parts) {\n"
        "      if (cur != null && typeof cur === 'object' && p in cur) {\n"
        "        cur = cur[p];\n"
        "      } else {\n"
        "        return undefined;\n"
        "      }\n"
        "    }\n"
        "    return cur;\n"
        "  }\n"
        "  let fn = resolveFn(mod, fnName);\n"
        "  if (typeof fn !== 'function' && mod.default != null) {\n"
        "    fn = resolveFn(mod.default, fnName);\n"
        "  }\n"
        "  if (typeof fn !== 'function') {\n"
        "    _markerEmitted = true;\n"
        "    console.log('RESULT_JSON:' + JSON.stringify({\n"
        "      ok: false,\n"
        "      exception_type: 'AttributeError',\n"
        "      exception_msg: 'function not found: ' + fnName,\n"
        "    }));\n"
        "    console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: [] }));\n"
        "    return;\n"
        "  }\n"
        # ── Invocation + result capture ─────────────────────────────────
        # Pass kwargs as a trailing object arg if non-empty — common JS
        # convention. If the function doesn't accept that signature it
        # just ignores the extra arg.
        "  const kwKeys = Object.keys(kwargs);\n"
        "  const callArgs = kwKeys.length > 0 ? [...args, kwargs] : args;\n"
        "  try {\n"
        "    let result = fn(...callArgs);\n"
        "    if (result && typeof result.then === 'function') {\n"
        "      result = await result;\n"
        "    }\n"
        "    let preview;\n"
        "    try {\n"
        "      preview = (typeof result === 'string' ? result : JSON.stringify(result));\n"
        "      preview = String(preview).slice(0, 600);\n"
        "    } catch (e) {\n"
        "      preview = String(result).slice(0, 600);\n"
        "    }\n"
        "    _markerEmitted = true;\n"
        "    console.log('RESULT_JSON:' + JSON.stringify({\n"
        "      ok: true,\n"
        "      type: typeof result,\n"
        "      value_preview: preview,\n"
        "    }));\n"
        "  } catch (e) {\n"
        "    const stack = e && e.stack ? String(e.stack).slice(-1500) : '';\n"
        "    _markerEmitted = true;\n"
        "    console.log('RESULT_JSON:' + JSON.stringify({\n"
        "      ok: false,\n"
        "      exception_type: e && e.constructor ? e.constructor.name : 'Error',\n"
        "      exception_msg: String((e && e.message) || e).slice(0, 300),\n"
        "      tb_tail: stack,\n"
        "    }));\n"
        "  }\n"
        # ── Side-effect snapshot ───────────────────────────────────────
        "  let added = [];\n"
        "  try {\n"
        "    added = fs.readdirSync('/tmp').filter(f => !baselineTmp.has(f)).sort();\n"
        "  } catch (e) {}\n"
        "  console.log('SIDE_EFFECTS:' + JSON.stringify({\n"
        "    tmp_files_added: added.slice(0, 20),\n"
        "  }));\n"
        # Close the outer try that wraps the entire IIFE body. Sync
        # throws (e.g., JSON.parse on a malformed payload, ReferenceError
        # in path-prep, TypeError in input enumeration) bubble here and
        # get reported as a fatal marker. _markerEmitted guards against
        # double-emission if a partial-success path already reported.
        "  } catch (e) {\n"
        "    _emitFatal('iifeBody', e);\n"
        "  }\n"
        "})();\n"
    )


# ── Shell harness generation ─────────────────────────────────────────────


def _build_shell_probe_harness(
    *,
    script_path: str,
    args_json: str,
    kwargs_json: str,
) -> str:
    """Generate the Python harness that drives ONE shell-script probe.

    Shell scripts are entry-points, not function libraries — the
    ``function_name`` field is conceptually "the script itself" for
    shell. We invoke ``bash <script_path> <args...>`` with:

    * ``args_json`` decoded as POSITIONAL ARGS ($1, $2, ...)
    * ``kwargs_json`` decoded as ENVIRONMENT VARS (exported before exec)

    The harness is written in Python (not bash) because pure-bash JSON
    parsing is treacherous and Python is already in every sandbox image.
    Same RESULT_JSON / SIDE_EFFECTS markers as Python + JS so the
    deterministic interpreter rules apply uniformly.

    Path-prep preamble runs the same way as Python — regex-extract
    absolute-path string literals from the shell source and from input
    args, ``mkdir -p`` each. The shell deny list is identical to
    Python's (no ``/etc``, ``/usr``, etc.).
    """
    args_repr = repr(args_json)
    kwargs_repr = repr(kwargs_json)
    deny_repr = repr(_PROBE_PREP_DENY_PREFIXES)
    script_path_repr = repr(script_path)
    return (
        "import sys, os, json, traceback, re, subprocess\n"
        "baseline_tmp = set()\n"
        "try:\n"
        "    baseline_tmp = set(os.listdir('/tmp'))\n"
        "except Exception:\n"
        "    pass\n"
        + _BYTES_SENTINEL_HELPER_PY
        + f"args = _decode_bytes_sentinels(json.loads({args_repr}))\n"
        f"kwargs = _decode_bytes_sentinels(json.loads({kwargs_repr}))\n"
        f"_DENY = {deny_repr}\n"
        f"_script_path = {script_path_repr}\n"
        "_paths_to_prep = set()\n"
        "try:\n"
        "    _src = open(_script_path).read()\n"
        "    _paths_to_prep = set(re.findall("
        "r'''[\"\\']((?:/[A-Za-z_][\\w./-]*))[\"\\']''', _src))\n"
        "except Exception:\n"
        "    pass\n"
        "_abs_dir_prefixes = set()\n"
        "for _p in _paths_to_prep:\n"
        "    if any(_p == d or _p.startswith(d + '/') for d in _DENY):\n"
        "        continue\n"
        "    try:\n"
        "        _bn = os.path.basename(_p.rstrip('/'))\n"
        "        _looks_like_file = '.' in _bn and not _p.endswith('/')\n"
        "        _to_mk = os.path.dirname(_p) if _looks_like_file else _p.rstrip('/')\n"
        "        if _to_mk and _to_mk != '/':\n"
        "            os.makedirs(_to_mk, exist_ok=True)\n"
        "            _abs_dir_prefixes.add(_to_mk)\n"
        "    except (OSError, PermissionError):\n"
        "        pass\n"
        "_skip = {'..', '.', ''}\n"
        "for _arg in args + list(kwargs.values()):\n"
        "    if not (isinstance(_arg, str) and '/' in _arg):\n"
        "        continue\n"
        "    _comps = [c for c in _arg.split('/') if c not in _skip]\n"
        "    if not _comps:\n"
        "        continue\n"
        "    for _depth in range(1, len(_comps)):\n"
        "        _rel = '/'.join(_comps[:_depth])\n"
        "        for _src_dir in _abs_dir_prefixes:\n"
        "            try:\n"
        "                _full = _src_dir.rstrip('/') + '/' + _rel\n"
        "                if any(_full == d or _full.startswith(d + '/') for d in _DENY):\n"
        "                    continue\n"
        "                os.makedirs(_full, exist_ok=True)\n"
        "            except (OSError, PermissionError):\n"
        "                pass\n"
        # Build env from kwargs (string-coerced), prepend the existing env.
        "env = os.environ.copy()\n"
        "for k, v in kwargs.items():\n"
        "    env[str(k)] = str(v)\n"
        # Invoke bash <script> <args...>. Shell scripts return their own
        # exit code; we map that to ok = (returncode == 0). Vulnerable
        # behavior on attack input usually = exit 0 (the script ran the
        # attack to completion) rather than the defensive exit != 0.
        f"_argv = ['bash', _script_path] + [str(a) for a in args]\n"
        "try:\n"
        "    _proc = subprocess.run(\n"
        "        _argv,\n"
        "        env=env,\n"
        "        capture_output=True,\n"
        "        text=True,\n"
        "        timeout=20,\n"
        "    )\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': _proc.returncode == 0,\n"
        "        'exit_code': _proc.returncode,\n"
        "        'type': 'shell_exit',\n"
        "        'value_preview': (_proc.stdout or '')[:600],\n"
        "        'stderr_preview': (_proc.stderr or '')[:300],\n"
        "    }))\n"
        "except subprocess.TimeoutExpired:\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': False,\n"
        "        'exception_type': 'TimeoutExpired',\n"
        "        'exception_msg': 'shell script exceeded timeout',\n"
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


# ── Language detection + plan dispatch ───────────────────────────────────


#: Map of probe-supported languages to file extensions. The plan builder
#: dispatches harness generation by walking this table.
#:
#: v10 (2026-05-16): TypeScript added. The JS harness body is reused
#: verbatim (no TS types in the harness itself), launched via ``tsx``
#: which transparently transpiles the user's .ts target on dynamic
#: ``import()``. See the typescript branch in :func:`build_runtime_probe_plan`
#: for the runner shape. (v9 originally shipped with ts-node but had
#: 100% TS-file failure due to a loader-hook cycle bug — tsx is the
#: production runner.)
_SUPPORTED_EXTS_BY_LANG: dict[str, tuple[str, ...]] = {
    "python": (".py",),
    "javascript": (".js", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "shell": (".sh", ".bash"),
}


def detect_probe_language(file_name: str) -> str | None:
    """Return the probe language for ``file_name`` based on its extension,
    or ``None`` if the file isn't probe-supported.

    Returns one of: ``"python"``, ``"javascript"``, ``"typescript"``,
    ``"shell"``, or ``None``. Used by both the plan builder (to dispatch
    harness generation) and the orchestrator's probe-stage entry gate
    (to skip files we can't probe).

    TypeScript support (v10) routes .ts / .tsx files through ``tsx``
    on the same JS harness — the harness itself stays plain JS, tsx
    transpiles only the user's target on ``await import(...)``. tsx
    skips type-check by default so type errors in user code don't
    block runtime probing — DAST cares about behavior, not type
    safety. (v9 originally shipped with ts-node but had 100%
    TS-file failure due to a loader-hook cycle bug.)
    """
    fn_lower = file_name.lower()
    for lang, exts in _SUPPORTED_EXTS_BY_LANG.items():
        if any(fn_lower.endswith(e) for e in exts):
            return lang
    return None


# ── Plan builder ──────────────────────────────────────────────────────────


def build_runtime_probe_plan(
    *,
    file_name: str,
    file_bytes: bytes,
    candidate: RuntimeProbeCandidate,
    test_input: RuntimeProbeInput,
    candidate_idx: int,
    input_idx: int,
    image_hint: str = "lean",
    entry_rel_path: str = "",
) -> dict[str, Any] | None:
    """Build a Phase-A-shaped plan dict that runs one probe.

    Returns ``None`` when the file's extension isn't in
    :data:`_SUPPORTED_EXTS_BY_LANG` (probe is a no-op for that file).
    The plan's ``hypothesis_id`` follows the pattern
    ``HRP_<candidate_idx>_<input_idx>`` (HRP = "harness runtime probe")
    for stable identifiers across iterations.

    Dispatches harness construction by file extension:

    * ``.py`` → Python harness (import + getattr walk + call)
    * ``.js`` / ``.mjs`` / ``.cjs`` → Node harness (dynamic import +
      CJS/ESM-tolerant function resolver + async-await invocation)
    * ``.ts`` / ``.tsx`` → Same JS harness, launched via ``tsx`` so
      dynamic ``import()`` of the user's TS target transpiles on-the-fly
      (v10, 2026-05-16). tsx skips type-check by default — we care
      about runtime behavior, not type errors in user code blocking
      probes. Replaced v9's ``node --loader ts-node/esm`` which had
      100% TS-file failure due to a CJS-entry+ESM-dynamic-import
      cycle bug in ts-node's loader hook.
    * ``.sh`` / ``.bash`` → Python-orchestrated shell harness
      (subprocess.run with args as positional and kwargs as env vars;
      script-level probing, not function-level, since shell scripts
      are usually entry points)

    All harnesses emit the same ``RESULT_JSON:`` / ``SIDE_EFFECTS:``
    markers and route through :func:`interpret_probe_trace` identically.

    Multi-file project support (v12, 2026-05-17): when
    ``entry_rel_path`` is non-empty, it's the entry file's path
    relative to its detected project root (e.g.,
    ``"src/tools/sql.ts"``). The plan's run_cmd then:

      1. ``mkdir -p`` the rel path's parent directories
      2. ``mv`` the staged entry from ``/workspace/<basename>`` to
         ``/workspace/<entry_rel_path>``
      3. Harness's ``module_path`` uses
         ``/workspace/<entry_rel_path>`` so dynamic ``import()``
         hits the file at its real subdir location
      4. Entry's parent-dir imports (``import "../chains/foo.js"``
         in LangChain.js's ``src/tools/sql.ts``) now resolve to real
         siblings staged under ``/workspace/src/chains/foo.ts`` via
         the additional_files tarball

    When ``entry_rel_path`` is empty, single-file behavior (entry at
    ``/workspace/<basename>``) is preserved.
    """
    lang = detect_probe_language(file_name)
    if lang is None:
        return None

    file_base = Path(file_name).name
    # v12 (2026-05-17): multi-file project staging. When the entry
    # file lives in a subdir of its project root (e.g.,
    # ``src/tools/sql.ts`` in LangChain.js), the resolver staged the
    # entry at /workspace/<entry_rel_path> via the additional_files
    # tarball (which dast-init extracts AS ROOT before dropping
    # privileges — so root-owned /workspace can hold the subdir
    # tree). The harness's module_path uses this rel-from-root path
    # so dynamic ``import()`` hits the right file and parent-dir
    # imports (``import "../chains/foo.js"``) in the entry resolve
    # to staged siblings under /workspace/src/chains/foo.ts etc.
    # No runtime mkdir + mv needed — the file is already where it
    # should be when the runner user starts executing PLAN_COMMANDS.
    entry_rel_path = (entry_rel_path or "").replace("\\", "/").strip()
    entry_target_path = (
        f"/workspace/{entry_rel_path}" if entry_rel_path else f"/workspace/{file_base}"
    )

    if lang == "python":
        module_name = _python_module_name_for_file(file_name, entry_rel_path)
        # v15.26: generate the differential-fuzzing baseline args by
        # replacing every string in the attack inputs with a fixed
        # sentinel. The harness runs the baseline FIRST and emits a
        # BASELINE_RESULT_JSON marker. The matcher uses that outcome
        # to detect uniform-validation false positives.
        _baseline_args, _baseline_kwargs = _generate_baseline_args(
            test_input.args_json, test_input.kwargs_json
        )
        harness = _build_python_probe_harness(
            module_name=module_name,
            function_name=candidate.function_name,
            args_json=test_input.args_json,
            kwargs_json=test_input.kwargs_json,
            module_file_path=entry_target_path,
            # v15.18: pass through target_kind + init args so the harness
            # dispatches correctly on class methods / constructors. The
            # candidate's target_kind defaults to ``"function"`` for
            # backwards-compat with pre-v15.18 schema emissions.
            target_kind=getattr(candidate, "target_kind", "function"),
            instance_init_args_json=getattr(test_input, "instance_init_args_json", "[]"),
            instance_init_kwargs_json=getattr(test_input, "instance_init_kwargs_json", "{}"),
            # v15.22: pass attack_class so the wiretap preamble fires
            # for cleartext_transmission probes (in-VM listener +
            # __ARGUS_WIRETAP_URL__ placeholder substitution).
            attack_class=candidate.attack_class,
            # v15.26: differential-fuzzing baseline.
            baseline_args_json=_baseline_args,
            baseline_kwargs_json=_baseline_kwargs,
            # Phase 1 (SCAN-016, v15.31): structured-assertion expression
            # evaluated against the live return value. See
            # ``RuntimeProbeInput.assertion_expr`` docstring.
            assertion_expr=getattr(test_input, "assertion_expr", ""),
        )
        runner = "python3"
        harness_ext = "py"
    elif lang == "javascript":
        # v12: use entry_target_path so /workspace/src/foo.js works
        # too. For single-file scans entry_target_path is
        # /workspace/<basename> — same as the v10 path.
        module_path = entry_target_path
        harness = _build_javascript_probe_harness(
            module_path=module_path,
            function_name=candidate.function_name,
            args_json=test_input.args_json,
            kwargs_json=test_input.kwargs_json,
        )
        # v12: cd /workspace so npm-installed deps + sibling tree
        # resolution work. The entry is pre-staged at entry_target_path
        # by the additional_files tarball (no runtime move needed).
        runner = "cd /workspace && node"
        # Use .cjs so dynamic import() of either CJS or ESM works
        # without "type":"module" gymnastics in /workspace.
        harness_ext = "cjs"
    elif lang == "typescript":
        # TS support (v10, 2026-05-16). Harness body is plain JS — only
        # the user's target is .ts/.tsx. tsx hooks Node's module loader
        # so the harness's ``await import('/workspace/index.ts')``
        # transparently transpiles on-the-fly.
        #
        # Runner: ``tsx``
        #   * Skips type-check by default (DAST cares about runtime
        #     behavior, not type safety).
        #   * Uses Node's modern register() API + ESM hooks — works
        #     correctly with CJS-entry + ESM-dynamic-import (unlike
        #     v9's ts-node which had 100% TS-file failure on this
        #     pattern).
        #
        # Harness file extension stays ``.cjs`` for the same reasons as
        # JS (CJS mode lets the harness use ``require('fs')`` for
        # path-prep without "type":"module" gymnastics). tsx handles
        # CJS-entry transparently.
        #
        # The run command below writes TWO config files into /workspace
        # before tsx runs:
        #   * package.json with ``{"type":"module"}`` — needed for
        #     ESM features in user .ts files (top-level await etc.).
        #   * tsconfig.json with ``moduleResolution:"bundler"`` —
        #     standard TS-ecosystem pattern (Vite/Next/Astro/tsx) so
        #     ``import './foo.js'`` correctly resolves to ``./foo.ts``
        #     source on disk. Without this, multi-file TS projects
        #     fail with ``Cannot find module './foo.js'``.
        #
        # v12 multi-file: when entry_rel_path is set, the entry file
        # moves to /workspace/<entry_rel_path> first, so the harness
        # imports from a subdir and parent-dir imports (``../chains/
        # foo.js``) resolve correctly against siblings staged via
        # ADDITIONAL_FILES_TARGZ_B64.
        module_path = entry_target_path
        harness = _build_javascript_probe_harness(
            module_path=module_path,
            function_name=candidate.function_name,
            args_json=test_input.args_json,
            kwargs_json=test_input.kwargs_json,
        )
        # tsx prefixed with package.json + tsconfig.json writes; see
        # plan docstring for the full reasoning. v12: entry is
        # pre-staged at entry_target_path via additional_files tar
        # (extracted as root by dast-init). No runtime move needed.
        runner = (
            "cd /workspace && "
            "echo '{\"type\":\"module\"}' > package.json && "
            "echo '{\"compilerOptions\":"
            "{\"moduleResolution\":\"bundler\","
            "\"allowImportingTsExtensions\":true,"
            "\"target\":\"esnext\",\"module\":\"esnext\","
            "\"isolatedModules\":true,\"skipLibCheck\":true}}'"
            " > tsconfig.json && "
            "tsx"
        )
        harness_ext = "cjs"
    elif lang == "shell":
        script_path = f"/workspace/{file_base}"
        harness = _build_shell_probe_harness(
            script_path=script_path,
            args_json=test_input.args_json,
            kwargs_json=test_input.kwargs_json,
        )
        runner = "python3"
        harness_ext = "py"
    else:  # pragma: no cover — detect_probe_language guarantees coverage
        return None

    # Encode the original file as base64 so the sandbox stages it at
    # /workspace/<file_name>. Same pattern ml_detonation.py uses for
    # binary artifacts; reuses the staging infra.
    payload_b64 = base64.b64encode(file_bytes).decode("ascii")

    # Wrap harness in a python -c invocation. The sandbox runner will
    # shell-quote this safely; we just deliver the harness source.
    # SandboxPlan.commands is a list of shell strings, so the cleanest
    # path is to write the harness to a temp file in /workspace first,
    # then invoke it. Two-command plan. The bootstrap is always python3
    # (always present in every sandbox image) — only the harness runner
    # varies by language.
    harness_path = f"/workspace/_argus_probe_{candidate_idx}_{input_idx}.{harness_ext}"
    write_cmd = (
        f'python3 -c "import base64,sys; '
        f"open({harness_path!r},'wb').write("
        f'base64.b64decode(sys.argv[1]))" '
        f"{base64.b64encode(harness.encode('utf-8')).decode('ascii')}"
    )
    run_cmd = f"{runner} {harness_path}"

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
            f"Runtime probe ({lang}): testing {candidate.function_name} with attack "
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
    # v15.26 adds BASELINE_RESULT_JSON: emitted BEFORE RESULT_JSON for
    # differential fuzzing.
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("BASELINE_RESULT_JSON:"):
            payload = line[len("BASELINE_RESULT_JSON:") :].strip()
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    trace.baseline_parsed = parsed
            except (json.JSONDecodeError, ValueError):
                continue
        elif line.startswith("RESULT_JSON:"):
            payload = line[len("RESULT_JSON:") :].strip()
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    trace.parsed_result = parsed
                    # Phase 1 (SCAN-016) — pull the structured-assertion
                    # outcome onto top-level RuntimeProbeTrace fields so
                    # downstream callers don't have to dig through the
                    # parsed_result dict shape. ``assertion_passed`` is
                    # either True / False / None, mirroring the harness
                    # eval state (None = no assertion or eval errored;
                    # ``assertion_error`` carries the eval-error string
                    # when the latter case fired).
                    _ap = parsed.get("assertion_passed")
                    if isinstance(_ap, bool):
                        trace.assertion_passed = _ap
                    elif _ap is None:
                        trace.assertion_passed = None
                    trace.assertion_error = str(parsed.get("assertion_error") or "")
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


# ── Phase 0: attack-class evidence signatures (FP defense) ───────────────
#
# Rule 1 ("function returned ok on attack input") used to fire on any
# parsed_result.ok == True. That's too broad — a function that returns
# empty string / null / an error code on attack input also produces
# ok=True. Real-world fixture validation surfaced this: a probe could
# emit a finding without the return value actually demonstrating the
# claimed exploit (e.g., path_traversal "confirmed" with value_preview
# being a benign string that happens to not be /etc/passwd content).
#
# Fix: each attack class declares a list of POSITIVE-MATCH SIGNATURES
# that the runtime evidence (value_preview + stderr_preview) MUST
# contain for Rule 1 to fire. The model's `expected_observable` field
# is additionally extracted into a per-input oracle: any expected-
# observable-keyword found in the runtime evidence is a confirming
# match. If neither hits, the probe is BLOCKED — runtime evidence
# didn't concretely demonstrate the exploit.
#
# Substring match, not regex. Case-insensitive. Cheap, deterministic,
# evidence-grounded. Same shape as Rule 2's canary-marker matching
# already in place for /tmp file emergence.

#: Per-attack-class signature library. Each entry is a list of
#: case-insensitive substrings the runtime evidence MUST contain for
#: Rule 1 to confirm an exploit of that class. Multiple substrings =
#: OR (any one match is enough). Empty list means Rule 1 is gated
#: ENTIRELY on the per-input ``expected_observable`` oracle for that
#: attack class.
#:
#: Signatures err toward distinctive runtime artifacts — file-system
#: layout markers, command-output identifiers, version banners — that
#: don't appear in benign return values.
_ATTACK_CLASS_EVIDENCE_SIGNATURES: dict[str, list[str]] = {
    "path_traversal": [
        # Sensitive-file content markers — passwd/shadow line shapes
        "root:x:0:0:",
        "root:x:0:",
        "daemon:x:",
        # SSH key markers
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN DSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        # Known sensitive-path content
        "[client]",  # /etc/mysql/my.cnf style
        "[mysqld]",
        # /proc artifacts
        "Linux version ",
        "MemTotal:",
        # Sensitive AWS/cloud secrets
        "AKIA",
        "aws_access_key_id",
        # NOTE: 'localhost' used to live here as an /etc/hosts marker
        # but was too noisy (any URL containing localhost would match).
        # Moved to _CAUSAL_CLASS_SIGNATURES which requires the matched
        # string be ABSENT from the probe's input args (i.e., function
        # introduced the marker, not the caller).
    ],
    "command_injection": [
        # uid output from `id`
        "uid=",
        "gid=",
        "groups=",
        # `whoami` returns root/runner; not distinctive on its own — pair
        # with shell-pipe markers via canary instead. Listed for
        # completeness when the model targets whoami specifically.
        "uname",
        # `pwd` output marker — distinctive when subshell fires
        "/workspace",
        # Common shell-exec stdout
        "Linux ",
        # `env` exfil
        "PATH=/",
        "HOME=/",
        # `ls /` style markers
        "bin\nboot\ndev\n",
    ],
    "code_injection": [
        # eval / exec firing typically produces canary tmp files (Rule 2)
        # or returns a value embedded with marker strings. Keep narrow.
        "__builtins__",
        "<module '",
        "/proc/self",
    ],
    "deserialization": [
        # pickle.__reduce__ / yaml.unsafe_load typically fire via canary
        # (Rule 2). Distinctive return markers when payload echos back:
        "Reduce executed",
        "<class 'os.system'>",
        "command executed via",
    ],
    "ssrf": [
        # Distinctive cloud-metadata service responses — content the
        # target should never return absent a real SSRF exploit.
        "169.254.169.254",  # AWS IMDS
        "metadata.google.internal",
        "metadata.google",
        "metadata.azure.com",
        # IMDS response shape (only present in real metadata content)
        "iam/security-credentials",
        "AccessKeyId",
        # NOTE: "localhost" and "127.0.0.1" used to be here but were
        # empirically false-positive-prone — Argus's mcp-server-fetch
        # eval (2026-05-16) saw a function legitimately return
        # 'http://evil.com@localhost/robots.txt' as part of its normal
        # URL-rewriting logic, and the bare 'localhost' substring match
        # confirmed an SSRF that wasn't actually demonstrated. Those
        # strings now live in _CAUSAL_CLASS_SIGNATURES (below) which
        # require attacker-input causality before they can fire.
    ],
    "sql_injection": [
        # Distinctive db-introspection output
        "version()",
        "@@version",
        "sqlite_master",
        "information_schema",
        "PostgreSQL",
        "MariaDB",
        "MySQL",
        # Union-injection telltale: error containing SQL keywords
        "SQL syntax",
        "syntax error",
        "ORA-",  # Oracle
    ],
    "data_exfiltration": [
        # HTTP/network artifacts in return value indicating outbound
        "HTTP/1",
        "200 OK",
        "Set-Cookie:",
        "Authorization:",
        # Base64 of common secret prefixes (rough heuristic)
        "ZWNyZXQ",  # base64 of "ecret"
    ],
    "xxe": [
        # File-content disclosure via XML external entity
        "root:x:0:",
        "<?xml",
        "<!DOCTYPE",
        'SYSTEM "file:',
    ],
    "xss": [
        "<script",
        "alert(",
        "onerror=",
        "javascript:",
    ],
    "crypto_weakness": [
        # MD5/SHA1 collisions, predictable PRNG — these often surface as
        # specific known-bad output strings. Keep narrow until we see
        # concrete cases.
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty string
    ],
    "open_redirect": [
        "Location: http",
        "Location: //",
    ],
    "prompt_injection": [
        # Hard to gate purely on substrings — typically caught via canary
        "ignore previous",
        "ignore all",
        "system prompt:",
    ],
    "race_condition": [
        # Timing-based; defer to model-loop interpretation for v1.5.
    ],
    "cleartext_transmission": [
        # v15.22 — class signatures emitted by the wiretap harness when
        # the function-under-test sends bytes to the local listener over
        # plain HTTP. The harness sets up a server on 127.0.0.1, captures
        # any inbound bytes, and surfaces them in the trace payload
        # prefixed with one of these markers (so the matcher can fire
        # without ambiguity).
        "ARGUS_WIRETAP_CLEARTEXT_OBSERVED",
        # Token / credential headers showing up on plain HTTP. Matcher
        # fires when these substrings appear in wiretap capture (i.e.,
        # they were transmitted in clear).
        "Authorization: Bearer",
        "Authorization: Basic",
        "X-API-Key:",
        "X-Auth-Token:",
        # Wiretap-explicit: harness records the URL scheme it observed
        # — "scheme=http" without "scheme=https" is the canonical hit.
        "argus_wiretap_scheme=http",
    ],
}


#: Exception types that almost always indicate the function REJECTED
#: the input at its boundary (type mismatch, permission denied, missing
#: file) rather than processing it. Rule 1b (exception path) suppresses
#: these to prevent FPs where an exception merely echoes the attack
#: input (e.g., PermissionError mentioning '../etc/passwd' would
#: otherwise match the model's observable_keyword "passwd").
#:
#: Whitelist by exclusion: any OTHER exception type (XMLSyntaxError,
#: SyntaxError, JSONDecodeError, lxml parser errors, SQL errors,
#: DeserializationError, etc.) indicates the function processed the
#: input far enough to fail at the content level -- that's exploit
#: signal. xrechnung's XSLT load raising XMLSyntaxError on /etc/passwd
#: content is the canonical kept-case.
_EXCEPTION_REJECTED_AT_BOUNDARY: frozenset[str] = frozenset(
    {
        "PermissionError",
        "FileNotFoundError",
        "IsADirectoryError",
        "NotADirectoryError",
        "TypeError",
        "AttributeError",
        # Note: ValueError is intentionally NOT here. ValueError covers
        # both legitimate input rejection AND content-level failures
        # (e.g., 'invalid XML' raised from a parser after access).
        # Substring match against class signatures + observable
        # keywords is more discriminating than the exception type alone.
    }
)


#: Exception types that indicate the sandbox infrastructure failed before
#: the function-under-test could execute its vulnerable logic. Distinct
#: from ``_EXCEPTION_REJECTED_AT_BOUNDARY`` (which is "function refused
#: input"): infra failures mean the function was *never reached at all*.
#:
#: Treating these as exploit evidence would be a categorical error -- the
#: code path being attacked wasn't executed. The keyword-match oracle is
#: especially prone to firing here because import-machinery error messages
#: echo the target module/function name, which often matches the model's
#: declared ``expected_observable``.
#:
#: Real-world failure mode (anthropic-sdk-python campaign, 2026-05-20):
#: Phase B+ Stage 2 harness threw ``ImportError: No module named
#: 'anthropic'`` on every HRP_X_Y probe because the package wasn't
#: importable in the sub-process sandbox. The matcher's keyword check
#: matched the function name "CredentialResult" appearing in the import
#: error and inflated to CONFIRMED at confidence 1.0. Across 7 SDK
#: files, 24/35 CONFIRMs (69%) were spurious infra-failure matches.
_EXCEPTION_INFRA_FAILURE: frozenset[str] = frozenset(
    {
        "ImportError",
        "ModuleNotFoundError",
    }
)


#: Oracle identifiers returned by :func:`_evidence_signature_match`.
#: Used by callers to confidence-score the resulting finding.
#: ``"class_signature"`` — distinctive class-specific substring matched
#:   (e.g., ``root:x:0:0:`` for path_traversal). High specificity oracle.
#: ``"observable_keyword"`` — model's expected_observable text contained
#:   a token that appears in the runtime evidence. Lower specificity;
#:   prone to FPs when the function naturally returns content overlapping
#:   the keyword (db2 simulation-branch case).
#: ``""`` (empty) — no oracle matched.
EvidenceOracleType = str  # one of: "assertion", "class_signature", "class_signature_causal", "observable_keyword", ""


#: Attack-class signatures that are too noisy to fire on bare substring
#: presence (they appear naturally in many legitimate inputs/outputs) —
#: but ARE meaningful when the function INTRODUCED the marker, i.e.,
#: when the matched string was NOT present in the function's input args.
#:
#: Mechanism: oracle requires causality. If "localhost" was in
#: args_json, its presence in the return value is a pass-through, not
#: exploit evidence. If "localhost" was NOT in args_json but IS in the
#: return, the function produced it — a real signal.
#:
#: History: added 2026-05-16 after the mcp-server-fetch eval, where
#: ``get_robots_txt_url("http://evil.com@localhost/secret")`` returned
#: ``"http://evil.com@localhost/robots.txt"`` and the bare-substring
#: 'localhost' match in the ssrf class-signature list confirmed an
#: SSRF that wasn't demonstrated (the function's job is to manipulate
#: URLs; localhost in/localhost out is pass-through, not exploit).
_CAUSAL_CLASS_SIGNATURES: dict[str, list[str]] = {
    "ssrf": [
        "localhost",
        "127.0.0.1",
    ],
    "path_traversal": [
        # /etc/hosts line shape — only meaningful when function
        # introduced it (e.g., target ran ``open("/etc/hosts")`` and
        # echoed contents, NOT when user passed a path containing the
        # string "localhost").
        "localhost",
    ],
}


# v15.25 — Purpose-aware oracle suppression (Gemini Issue Fix A).
#
# Functions whose name DECLARES they return sensitive material (auth
# headers, credentials, signed requests, tokens) are by-design supposed
# to return those values to their internal caller. Flagging that
# behavior as CWE-200 data_exfiltration is a false positive — the
# exfiltration only matters if the return value crosses a trust boundary
# (e.g., gets sent back over HTTP to an external caller). For library
# utility functions, the return IS the contract.
#
# Patterns matched are intentionally narrow: getters/builders/signers
# in the credentials/auth domain. Functions like ``get_user_data``
# wouldn't match — they're not declared-purpose getters in this sense.
#
# Suppression fires ONLY when:
#   * attack_class == "data_exfiltration" (CWE-200)
#   * function name matches one of the regex patterns below
# Other CWEs (path_traversal, code_injection, deserialization, etc.)
# are unaffected — those describe content the function shouldn't have
# returned regardless of declared purpose.

import re as _re  # noqa: E402

# Function-name patterns for module-level getter / builder / signer
# style functions whose name declares they return sensitive material.
_PURPOSE_DECLARED_RETURN_PATTERNS: tuple[_re.Pattern[str], ...] = tuple(
    _re.compile(p) for p in (
        # Getter for auth/credential material:
        r"^(?:.*\.)?get_(?:auth_?headers?|credentials?|session|token|"
        r"signature|signed_(?:request|headers?|url)|api_?key|"
        r"secret|password|cookie|bearer|access_?token|refresh_?token)$",
        # Signer / builder / encoder of auth material:
        r"^(?:.*\.)?(?:sign|create|build|make|prepare|generate|"
        r"format|encode|render)_"
        r"(?:auth|credentials?|token|session|signature|request|"
        r"headers?|cookie|bearer)(?:s?_[a-z_]+)?$",
        # Serializer/converter naming patterns:
        r"^(?:.*\.)?to_(?:headers?|dict|json|str|repr)$",
    )
)

# Class-instance-call match: ``<Class>.__call__`` where ``<Class>``
# contains an auth-domain keyword. Captures SDK convention where
# ``IdentityTokenFile``, ``WorkloadIdentityCredentials``,
# ``StaticToken`` etc. are AccessTokenProvider callables. The pattern
# is checked via a two-step match (does the function look like
# ``<Class>.__call__``? does ``<Class>`` contain the keyword?) to
# avoid greedy-regex backtracking subtleties.
_DUNDER_CALL_RE: _re.Pattern[str] = _re.compile(
    r"^(?:[^.]+\.)*([A-Z]\w*)\.__call__$"
)
_AUTH_DOMAIN_KEYWORD_RE: _re.Pattern[str] = _re.compile(
    r"Token|Credential|Provider|Signer|Authenticator|ApiKey|Secret|Bearer|Cookie|Auth"
)


def _function_name_declares_purpose(
    function_name: str,
    attack_class: str,
) -> tuple[bool, str]:
    """v15.25 — return ``(True, reason)`` when the function's NAME
    declares it returns the kind of material the matcher just flagged
    as exfiltration.

    Only fires for ``data_exfiltration``-class probes (CWE-200) — other
    attack classes describe content the function shouldn't have
    returned regardless of purpose.

    The Gemini-named example: ``get_auth_headers`` returning a dict
    with an Authorization header is CWE-200 by substring but not by
    intent. Function name declares the return; matching is by-design.
    """
    if attack_class != "data_exfiltration":
        return False, ""
    # Pattern 1: function-style purpose-declared names (get_*, sign_*,
    # to_headers, etc.).
    for pat in _PURPOSE_DECLARED_RETURN_PATTERNS:
        if pat.match(function_name):
            return (
                True,
                f"function_name '{function_name}' declares the returned material is "
                "the contract (matched function-naming pattern)",
            )
    # Pattern 2: class-instance __call__ where the class name contains
    # an auth-domain keyword.
    m = _DUNDER_CALL_RE.match(function_name)
    if m:
        class_name = m.group(1)
        if _AUTH_DOMAIN_KEYWORD_RE.search(class_name):
            return (
                True,
                f"function_name '{function_name}' is a class-callable on "
                f"'{class_name}' which contains an auth-domain keyword — "
                "the class exists to produce the material it returns",
            )
    return False, ""


# v15.25 — I/O-bearing function check (Gemini Issue Fix B).
#
# URL/protocol-related CWEs (ssrf, cleartext_transmission, open_redirect)
# require the function to ACTUALLY DISPATCH I/O — a pure
# string-manipulation utility that signs/prepares a request is not
# exploitable for SSRF even if it lacks URL validation. The actual
# vulnerability would live in the HTTP client that USES the signed
# headers, not in the signer.
#
# We have ``behavioral_profile.actual_capabilities.network_calls``
# produced by L1's static analysis. When that list is empty for a
# file, NONE of the functions in the file dispatch I/O — URL-shaped
# probes against any of them are theoretical, not actual.

_NETWORK_IO_REQUIRED_ATTACK_CLASSES: frozenset[str] = frozenset(
    {
        "ssrf",
        "cleartext_transmission",
        "open_redirect",
    }
)


def _file_has_network_io(behavioral_profile: dict | None) -> bool:
    """v15.25 — does the L1 behavioral_profile show any network calls?

    Returns ``True`` when the file is observed to dispatch network I/O
    (one or more entries in ``actual_capabilities.network_calls``).
    Returns ``True`` defensively when the profile is missing entirely —
    we don't have evidence either way, so don't suppress.
    """
    if not isinstance(behavioral_profile, dict):
        return True  # defensive default
    caps = behavioral_profile.get("actual_capabilities")
    if not isinstance(caps, dict):
        return True  # no capability data — defensive
    net = caps.get("network_calls")
    if not isinstance(net, list):
        return True  # malformed — defensive
    return len(net) > 0


# v15.26 — Exception message pattern refutation (Gemini Suggestion #1).
#
# When the matcher's Rule 1b (exception-path oracle) fires, also check
# the exception MESSAGE for patterns that indicate the application's
# native validation correctly rejected the input. The
# ``_EXCEPTION_REJECTED_AT_BOUNDARY`` set only checks exception TYPE
# (PermissionError, TypeError, etc) and misses cases where a custom
# error class (e.g. ``WorkloadIdentityError``, ``AnthropicError``)
# raises with a "must use https" / "scheme required" / "not found"
# message — that's clearly a validation block, not exploit signal.
#
# The patterns are intentionally precise — they match phrases that
# only appear in validation rejections, not in exploit-bearing
# exceptions like XMLSyntaxError("Entity 'xxe' SYSTEM file:...").

_VALIDATION_REJECTION_MSG_PATTERNS: tuple[_re.Pattern[str], ...] = tuple(
    _re.compile(p, _re.IGNORECASE) for p in (
        # Scheme / protocol rejection
        r"\b(?:scheme|protocol|tls|https?)\s+(?:required|must|enforced|missing|invalid)",
        r"\b(?:must|should|need)\s+(?:use|provide|be)\s+https?",
        r"\bhttps?://\s+(?:required|only|expected)",
        # Generic "invalid X" / "X not allowed" patterns
        r"\b(?:in)?valid\s+(?:input|format|argument|value|url|path|"
        r"scheme|protocol|key|token|credential|certificate)",
        r"\bnot\s+(?:allowed|permitted|supported|recognized)",
        # Missing required field
        r"\bmissing\s+(?:required\s+)?(?:argument|field|parameter|value|key)",
        r"\brequired\s+(?:argument|field|parameter|value|key)\s+(?:missing|not\s+set)",
        # Application-level refusal (NOT bare "refused" — that matches
        # ConnectionRefusedError which is real network signal in SSRF
        # context. Require an action verb explaining what's being
        # refused.)
        r"\brefus(?:ed|ing)\s+(?:to\s+)?(?:process|accept|sign|"
        r"authenticate|continue|parse|load|the|because|with|"
        r"input|url|scheme|payload|signature|request)",
        r"\b(?:rejected|rejecting|forbidden|unauthorized)",
        r"\b(?:unsupported|not\s+supported)\s+(?:type|format|scheme|protocol)",
        # Size / range bounds — accept "exceeds <number> bytes/chars"
        # in addition to size/length/limit/maximum keywords.
        r"\bexceeds?\s+(?:size|length|limit|maximum|the\s+\d+|"
        r"\d+\s*(?:bytes?|chars?|characters?|kb|mb|gb))",
        r"\b(?:out\s+of\s+range|too\s+(?:large|long|big|small|short))",
        # Not found / does not exist
        r"\b(?:not\s+found|does\s+not\s+exist|no\s+such\s+file)",
        # Authentication / authorization rejection
        r"\b(?:authentication|authorization)\s+(?:failed|required|missing)",
    )
)


# v15.26 — Differential fuzzing baseline (Gemini Suggestion #3).
#
# Before invoking the function with the model's attack-shaped input,
# the harness runs a BASELINE call with semantically-stripped garbage
# (every string value replaced with a fixed sentinel). If the baseline
# raises the same exception class with a similar message structure as
# the attack call, the function applies uniform input validation —
# the attack-shaped input wasn't special, and the matcher's
# CONFIRMED is a false positive.
#
# Implementation: this helper is called at plan-build time to produce
# the baseline args/kwargs JSON alongside the attack JSON. The harness
# runs both and emits a BASELINE_RESULT_JSON marker before
# RESULT_JSON. The matcher reads both and applies the uniformity
# check in interpret_probe_trace.

_BASELINE_GARBAGE_SENTINEL: str = "__ARGUS_DIFFERENTIAL_BASELINE_GARBAGE_VALUE__"


def _generate_baseline_args(args_json: str, kwargs_json: str) -> tuple[str, str]:
    """Walk an attack args/kwargs JSON and replace every string value
    with a fixed garbage sentinel. Preserves type structure (dicts,
    lists, nesting), strips attack semantics.

    Returns ``(baseline_args_json, baseline_kwargs_json)``. The
    sentinel is intentionally LONG + UNIQUE so the matcher can
    identify baseline-derived behaviour distinct from attack-derived.
    """
    import json as _json

    def _strip(o: object) -> object:
        if isinstance(o, str):
            return _BASELINE_GARBAGE_SENTINEL
        if isinstance(o, dict):
            return {k: _strip(v) for k, v in o.items()}
        if isinstance(o, list):
            return [_strip(v) for v in o]
        # ints, floats, bools, None stay as-is
        return o

    try:
        args_obj = _json.loads(args_json) if args_json else []
        kwargs_obj = _json.loads(kwargs_json) if kwargs_json else {}
    except (ValueError, TypeError):
        # Malformed input — return safe defaults so the harness still
        # has SOMETHING to call as baseline.
        return "[]", "{}"

    return (
        _json.dumps(_strip(args_obj)),
        _json.dumps(_strip(kwargs_obj)),
    )


def _normalize_exception_msg_for_comparison(msg: str) -> str:
    """v15.26 — strip variable content from an exception message so
    structurally-similar messages compare equal.

    Removes:
      * The baseline sentinel (always present in baseline messages)
      * Numbers (line counts, byte counts, addresses, etc.)
      * Quoted strings (variable content the message echoes back)
      * Whitespace runs collapse to single space

    The goal is to detect when baseline and attack exceptions are
    "the same exception with different variable parts" — that's the
    signal for uniform validation.

    Example normalizations:
      Attack:   "Identity token file not found at /etc/passwd"
      Baseline: "Identity token file not found at __ARGUS_DIFFERENTIAL_BASELINE_GARBAGE_VALUE__"
      → Both normalize to: "identity token file not found at"
    """
    if not msg:
        return ""
    s = str(msg)
    # Drop baseline sentinel
    s = s.replace(_BASELINE_GARBAGE_SENTINEL, "")
    # Strip quoted strings (single + double quotes)
    s = _re.sub(r"'[^']*'", "", s)
    s = _re.sub(r'"[^"]*"', "", s)
    # Strip numeric values
    s = _re.sub(r"\b\d+(?:\.\d+)?\b", "", s)
    # Collapse whitespace
    s = _re.sub(r"\s+", " ", s).strip().lower()
    # Drop trailing punctuation
    s = s.rstrip(".,;:")
    return s


def _is_differential_uniform_validation(
    attack_parsed: dict[str, object] | None,
    baseline_parsed: dict[str, object] | None,
) -> tuple[bool, str]:
    """v15.26 — does the function apply uniform validation?

    Returns ``(True, rationale)`` when BOTH outcomes raised AND
    the exception type + normalized message match between baseline
    and attack — meaning the function rejected both identically,
    independent of attack semantics.

    Returns ``(False, "")`` when:
      * Baseline outcome missing or didn't raise
      * Attack outcome missing or didn't raise
      * Exception classes differ
      * Normalized messages differ (attack-specific content visible)
    """
    if not isinstance(attack_parsed, dict) or not isinstance(baseline_parsed, dict):
        return False, ""

    a_ok = bool(attack_parsed.get("ok"))
    b_ok = bool(baseline_parsed.get("ok"))
    # Uniform validation requires BOTH to have raised.
    if a_ok or b_ok:
        return False, ""

    a_type = str(attack_parsed.get("exception_type") or "")
    b_type = str(baseline_parsed.get("exception_type") or "")
    if not a_type or a_type != b_type:
        return False, ""

    a_msg_norm = _normalize_exception_msg_for_comparison(
        str(attack_parsed.get("exception_msg") or "")
    )
    b_msg_norm = _normalize_exception_msg_for_comparison(
        str(baseline_parsed.get("exception_msg") or "")
    )
    # Empty-after-normalization means the message was entirely
    # quoted/numeric/sentinel — treat that as a degenerate match
    # only if both were empty too (both said only the variable
    # content).
    if not a_msg_norm and not b_msg_norm:
        return True, f"both raised {a_type} with messages that were entirely variable content"
    if a_msg_norm == b_msg_norm:
        return (
            True,
            f"both raised {a_type} with identical normalized message: {a_msg_norm[:120]!r}",
        )
    return False, ""


def _exception_message_indicates_validation(
    exception_msg: str,
) -> tuple[bool, str]:
    """v15.26 — does the exception message signal validation block?

    Returns ``(True, matched_pattern)`` when the message matches one
    of the validation-rejection phrases. The matcher uses this to
    suppress CWE confirms where the function's NATIVE validation
    correctly rejected the attack input (vs. processing it and
    leaking exploit signal).

    Example matches (REFUTED):
      * ``WorkloadIdentityError("Token endpoint must use HTTPS")``
      * ``ValueError("invalid URL scheme")``
      * ``RuntimeError("authorization required")``
      * ``KeyError("missing required argument 'session_id'")``

    Example NON-matches (still CONFIRMED if Rule 1b matched):
      * ``XMLSyntaxError("Entity 'xxe' not defined")`` — content
        processing failure, not validation
      * ``ConnectionRefusedError("Connection refused 169.254.169.254")``
        — real SSRF signal
      * ``ValueError("checksum mismatch root:x:0:0...")`` — exception
        carries leaked file content; refute would be wrong
    """
    if not exception_msg:
        return False, ""
    for pat in _VALIDATION_REJECTION_MSG_PATTERNS:
        m = pat.search(exception_msg)
        if m:
            return True, m.group(0)
    return False, ""


def _evidence_signature_match(
    *,
    attack_class: str,
    value_preview: str,
    stderr_preview: str,
    expected_observable: str,
    args_json: str = "",
) -> tuple[bool, str, EvidenceOracleType]:
    """Check whether the runtime evidence concretely demonstrates an
    exploit of the declared attack class.

    Three oracles, evaluated in order of specificity:

    1. **Class signature** (``oracle_type="class_signature"``): the
       evidence contains any of the attack-class-specific positive-
       match substrings (e.g., ``root:x:0:0:`` for path_traversal —
       distinctive sensitive-file content). High-specificity oracle;
       MEDIUM confidence (0.7) for chain findings.
    2. **Causal class signature** (``oracle_type="class_signature_causal"``):
       same as #1 but for signatures known to be noisy (``localhost``,
       ``127.0.0.1`` — common in legitimate I/O). Requires the matched
       string to be ABSENT from ``args_json`` — i.e., the FUNCTION
       introduced the marker, not the CALLER. Closes a false-positive
       class hit empirically on the mcp-server-fetch scan.
       Same MEDIUM confidence (0.7) as the non-causal variant when it
       fires.
    3. **Expected-observable keyword** (``oracle_type="observable_keyword"``):
       extracted from the model's ``expected_observable`` text, any
       5+ char alphanumeric token appears in the evidence (e.g., model
       said "returns /etc/passwd content" → extract ``etc/passwd`` /
       ``passwd`` → check if value_preview contains either). Lower
       specificity; LOW confidence (0.4) for chain findings — prone to
       FPs when function naturally returns content overlapping keywords
       (the db2_query_health_check.py simulation-branch case).

    Returns ``(matched, rationale, oracle_type)``. The rationale is
    journaled; the oracle_type lets callers map to a confidence score.

    Case-insensitive substring match. If both haystacks are empty,
    return ``(False, ..., "")`` to avoid false-positive on a no-content
    return.

    Args:
        args_json: the probe's args_json — used by the causal-signature
            oracle to check whether the matched string was supplied by
            the caller (pass-through) vs. produced by the function
            (actual signal). Optional for callers that don't have the
            input handy; absence means causal signatures degrade to
            the conservative "skip" path (won't fire). New 2026-05-16.
    """
    haystack = (value_preview + " " + stderr_preview).lower()
    if not haystack.strip():
        return False, "empty runtime evidence", ""

    # Oracle 1: class signature (high-specificity)
    #
    # v15.27 — cleartext_transmission signatures (``Authorization:
    # Bearer``, ``X-API-Key:``, etc.) were ALWAYS designed to fire on
    # wiretap-captured bytes (bytes the function actually sent over
    # plain HTTP via the in-VM listener). They were incorrectly
    # matching against function RETURN VALUES (e.g., ``get_auth_headers``
    # returning a dict with an Authorization key — which is by-design,
    # not cleartext transmission). Gate the cleartext signatures on
    # the wiretap markers being present in the haystack: if neither
    # ``ARGUS_WIRETAP_CLEARTEXT_OBSERVED`` nor ``argus_wiretap_scheme``
    # appears, the function didn't actually transmit anything — the
    # listener observed nothing — so the credential-header substring
    # is just a returned-dict pattern, not exploit evidence.
    class_sigs = _ATTACK_CLASS_EVIDENCE_SIGNATURES.get(attack_class, [])
    _cleartext_requires_wiretap = (attack_class == "cleartext_transmission")
    _wiretap_present_in_haystack = (
        "argus_wiretap_cleartext_observed" in haystack
        or "argus_wiretap_scheme" in haystack
    )
    for sig in class_sigs:
        if sig.lower() in haystack:
            # v15.27 — wiretap gate. Skip credential-header style
            # signatures when no wiretap marker is present. The two
            # wiretap markers themselves ALWAYS fire when matched
            # (they only appear in wiretap-captured output).
            if (
                _cleartext_requires_wiretap
                and not _wiretap_present_in_haystack
                and "argus_wiretap" not in sig.lower()
            ):
                continue
            return True, f"class-signature match: '{sig}'", "class_signature"

    # Oracle 2: causal class signature (high-specificity but only when
    # the function introduced the marker — not when it's pass-through
    # from the caller's input).
    causal_sigs = _CAUSAL_CLASS_SIGNATURES.get(attack_class, [])
    if causal_sigs:
        input_lower = (args_json or "").lower()
        # Conservative: when caller didn't supply args_json (default
        # empty string), we cannot verify causality. Refuse to fire —
        # better to miss a real signal than to false-positive on
        # something we can't verify. All production call sites do
        # supply args_json; only unit-test fixtures and edge-case
        # callers hit this guard.
        if input_lower:
            for sig in causal_sigs:
                sig_lower = sig.lower()
                if sig_lower in haystack:
                    if sig_lower in input_lower:
                        # Pass-through; not exploit evidence.
                        continue
                    # Function introduced the marker. Real signal.
                    return (
                        True,
                        f"class-signature match (causal): '{sig}' "
                        "in output but NOT in input",
                        "class_signature_causal",
                    )

    # Oracle 3: expected_observable keyword extraction (lower-specificity).
    # Pull 5+-char alphanumeric tokens from the model's expected_observable
    # text, strip noise words, and see if any appear in the haystack.
    #
    # v15.27 — Causality check (Gemini-named pass-through FP). When a
    # keyword from expected_observable also appears in args_json /
    # kwargs_json, its presence in the return value is PASS-THROUGH,
    # not new exploit-bearing content the function PRODUCED. Skip
    # those matches.
    #
    # This generalizes the v15.16 _CAUSAL_CLASS_SIGNATURES mechanism
    # (which was specific to "localhost"/"127.0.0.1" tokens). Closes
    # the bedrock/_auth FP class where the model's expected_observable
    # was the session token itself (a string we sent in as an input),
    # and the keyword oracle confirmed because the function included
    # that token in its signed-headers output by-design.
    args_haystack = (args_json or "").lower()
    for t in _extract_observable_keywords(expected_observable):
        if t.lower() in haystack:
            # v15.27 — causality check.
            if t.lower() in args_haystack:
                # The keyword was in the function's INPUT. Its presence
                # in the output is pass-through. Don't fire.
                continue
            # v15.27 — wiretap gate on Oracle 3 for cleartext_transmission.
            # The keyword oracle is generic enough that words like
            # "authorization" / "bearer" / "credential" trivially match
            # against function return values that contain auth headers
            # — even when no wiretap capture occurred. For
            # cleartext_transmission specifically, require the wiretap
            # marker as a precondition (consistent with the Oracle 1
            # gate above).
            if (
                _cleartext_requires_wiretap
                and not _wiretap_present_in_haystack
            ):
                continue
            return True, f"expected-observable keyword match: '{t}'", "observable_keyword"

    return False, "no evidence-signature match", ""


_OBSERVABLE_NOISE_WORDS: frozenset[str] = frozenset(
    {
        "function",
        "returns",
        "returned",
        "contains",
        "value",
        "string",
        "should",
        "would",
        "exploit",
        "attack",
        "input",
        "output",
        "passes",
        "fails",
    }
)


def _extract_observable_keywords(text: str) -> list[str]:
    """Pull 5+-char alphanumeric tokens out of a model-emitted
    ``expected_observable`` string, dropping common noise words.

    Used by both single-function probe interpretation and chain
    interpretation — Oracle 2 (the keyword-extraction path) is shared
    so the same model text matches the same way regardless of probe
    shape.
    """
    tokens: list[str] = []
    for raw_token in re.findall(r"[A-Za-z0-9_/.\-]{5,}", text):
        t = raw_token.strip("/.-_")
        if not t or t.lower() in _OBSERVABLE_NOISE_WORDS:
            continue
        tokens.append(t)
    return tokens


def _rejection_signature_matches(rejection_signature: str, haystack: str) -> bool:
    """Strategy B rejection-signature oracle (v1.7 FP defense).

    Model-declared ``rejection_signature`` describes what defensive code
    output looks like (e.g., ``"UnsupportedProtocol exception caught"``,
    ``"ZoneInfo keys may not contain up-level references"``,
    ``"ValueError raised before any side effect"``).

    Match strategy is intentionally lenient — the model's wording will
    rarely be byte-identical to the actual exception. We extract 5+-char
    distinctive tokens (same logic as the positive-evidence oracle) and
    require at least ONE token to appear in the haystack. That mirrors
    Rule 1's positive-match shape and shares its FP characteristics
    inverted: if the rejection-pattern model imagined matches the
    actual trace, we trust it.

    Returns True iff at least one distinctive 5+-char token from
    ``rejection_signature`` appears in ``haystack``.
    """
    if not rejection_signature or not haystack:
        return False
    tokens = _extract_observable_keywords(rejection_signature)
    if not tokens:
        return False
    haystack_lower = haystack.lower()
    return any(t.lower() in haystack_lower for t in tokens)


def interpret_probe_trace(
    trace: RuntimeProbeTrace,
    candidate: RuntimeProbeCandidate,
    test_input: RuntimeProbeInput,
    *,
    candidate_idx: int,
    input_idx: int,
) -> RuntimeProbeFinding | None:
    """Decide whether the trace constitutes a runtime-confirmed exploit.

    Three complementary rules:

    **Rule 1a (return path, FP-hardened):** ``parsed_result.ok == True``
    AND the runtime evidence (value_preview + stderr_preview) matches
    at least one of:

      * The attack-class signature library
        (:data:`_ATTACK_CLASS_EVIDENCE_SIGNATURES`) — distinctive runtime
        artifacts that don't appear in benign return values (e.g.,
        ``root:x:0:0:`` for path_traversal, ``uid=`` for
        command_injection, ``200 OK`` for ssrf).
      * Keywords extracted from the model's ``expected_observable`` text
        — substrings 5+ chars that appear verbatim in the evidence.

    Without the evidence match, Rule 1a does NOT fire — even if the
    function returned ok. This kills the class of FPs where a function
    legitimately returned an empty string / null / error code on attack
    input and the probe used to report it as an exploit anyway.

    **Rule 1b (exception path, Gap 1 v1.6):** ``parsed_result.ok ==
    False`` AND the exception evidence (exception_type + exception_msg
    + tb_tail) matches the same class-signature or observable-keyword
    oracles. Many real exploits prove themselves by raising — XXE
    parsing of a resolved external entity, path traversal hitting an
    unparseable file, FileNotFoundError on a protected path. The
    exception IS the signal. xrechnung diagnostic (commit 78c6be1):
    hypothesis raised ``XMLSyntaxError: "...passwd, line 1..."`` —
    the function actually read /etc/passwd and tried to parse it as
    XSLT; oracle was blind to this before. Same FP defense as Rule
    1a — substring match against class signature / model-declared
    observable. A benign function raising ValueError on bad input
    won't match any signature.

    **Rule 2 (unchanged):** ``side_effects.tmp_files_added`` contains
    files matching the canary marker pattern (``argus_probe`` / ``pwned``
    substrings). Evidence-gated by the marker requirement, no FP
    exposure.

    Returns ``None`` when no rule fires (probe ran but observed no
    exploit signal — that's the BLOCKED-equivalent for runtime probes).
    """
    if trace.parsed_result is None:
        # Harness crashed before printing the marker — can't interpret.
        return None

    parsed = trace.parsed_result
    side_effects = trace.side_effects or {}

    ok = bool(parsed.get("ok"))
    value_preview = str(parsed.get("value_preview", "") or "")
    stderr_preview = str(parsed.get("stderr_preview", "") or "")
    exception_type = str(parsed.get("exception_type", "") or "")
    exception_msg = str(parsed.get("exception_msg", "") or "")
    tb_tail = str(parsed.get("tb_tail", "") or "")

    # Strategy B (v1.7 FP defense): model-declared rejection_signature
    # gate. If the model gave us a description of "what rejection looks
    # like" and the trace matches THAT, the application defended itself
    # and any positive-evidence match below is an FP. Hardcoded boundary-
    # exception filtering (``_EXCEPTION_REJECTED_AT_BOUNDARY``) only
    # covers a fixed list; this is the content-aware, per-hypothesis
    # version. Caught real FPs in 2/2 cases during the 2026-05-14 hunt
    # (mcp-server-fetch file:// LFI, mcp-server-time path traversal).
    rejection_signature = (test_input.rejection_signature or "").strip()
    if rejection_signature:
        rejection_haystack = (
            f"{value_preview}\n{stderr_preview}\n{exception_type}: {exception_msg}\n{tb_tail}"
        )
        if _rejection_signature_matches(rejection_signature, rejection_haystack):
            # Rejection wins. Treat as REFUTED — even if positive-evidence
            # matching below WOULD have fired (which on FPs it does, because
            # error messages echo the attacker payload). Return None =
            # no finding = REFUTED at the outcome layer.
            return None

    rule1_match = False
    rule1_rationale = ""
    rule1_path = ""  # "return" | "exception" | ""
    rule1_oracle_type: EvidenceOracleType = ""

    # ── Phase 1 (SCAN-016, v15.31): structured-assertion short-circuit ──
    # When the model emitted an ``assertion_expr`` and the harness
    # evaluated it cleanly (True or False — not None / error), the
    # assertion is decisive. It overrides BOTH directions of the
    # string-based oracles:
    #
    #   * assertion_passed == True  → CONFIRMED via "assertion" oracle.
    #     The model's structured invariant holds on the live result.
    #     Highest-precision oracle: confidence 0.9 (same as canary).
    #   * assertion_passed == False → REFUTED. Return None at the
    #     outcome layer regardless of what substring oracles might
    #     have matched. This is the false-positive shield: when the
    #     model says "the exploit requires parsed_url.scheme == 'file'"
    #     and the live result has scheme == 'https', the keyword
    #     oracle's accidental match on the literal word "scheme" in
    #     repr() doesn't matter — the structured assertion refuted.
    #   * assertion_passed is None  → no assertion provided OR eval
    #     errored. Fall through to existing string oracles for
    #     back-compat with pre-v15.31 callers and the borderline
    #     cases where the model couldn't author a clean assertion.
    if trace.assertion_passed is True:
        rule1_match = True
        rule1_rationale = (
            f"assertion oracle: "
            f"{(test_input.assertion_expr or '')[:240]} → True"
        )
        rule1_oracle_type = "assertion"
        rule1_path = "return"
    elif trace.assertion_passed is False:
        # Structured refutation. The model declared the invariant
        # the exploit needs; the sandbox evaluated it against the
        # live object; the invariant doesn't hold. Done.
        return None
    elif ok:
        # Rule 1a: return-path oracle. Function returned without raising
        # AND runtime evidence concretely matches the declared attack class.
        # Pass args_json so causal-signature oracle can refuse to fire on
        # pass-through matches (e.g., 'localhost' in -> 'localhost' out).
        rule1_match, rule1_rationale, rule1_oracle_type = _evidence_signature_match(
            attack_class=candidate.attack_class,
            value_preview=value_preview,
            stderr_preview=stderr_preview,
            expected_observable=test_input.expected_observable,
            args_json=test_input.args_json,
        )
        if rule1_match:
            rule1_path = "return"
    elif exception_type in _EXCEPTION_INFRA_FAILURE:
        # Sandbox couldn't load the function-under-test. The vulnerable
        # code path was never reached, so there is no evidence in either
        # direction -- treat as UNREACHED (return None at outcome layer).
        # Without this guard, the exception text (which echoes the
        # target module/function name) trivially satisfies the keyword
        # oracle and the matcher reports a fake CONFIRMED at conf=1.0.
        # See ``_EXCEPTION_INFRA_FAILURE`` docstring for the
        # anthropic-sdk campaign data that motivated this guard.
        return None
    elif exception_type in _EXCEPTION_REJECTED_AT_BOUNDARY:
        # Function rejected the input at its boundary (permission/type/
        # access). The exception isn't evidence of an exploit; it's
        # evidence the function refused to process the input. Even if
        # the exception text echoes the attack input (e.g.,
        # PermissionError mentioning '../etc/passwd'), substring
        # matching would FP. Suppress Rule 1b entirely.
        rule1_rationale = (
            f"Rule 1b suppressed: exception type {exception_type!r} "
            "indicates input-boundary rejection (no exploit fired)."
        )
    else:
        # Rule 1b: exception-path oracle. Function raised AFTER reaching
        # content-level processing; check whether the exception
        # class/message/traceback contains the same signatures we'd
        # accept on a return. xrechnung-class fix: XXE / arbitrary
        # read / SSRF often manifest as a parser raising on the
        # resolved content (e.g., XMLSyntaxError mentioning the
        # exfiltrated path). The exception IS proof of exploitation.
        exception_haystack = f"{exception_type}: {exception_msg}\n{tb_tail}"
        rule1_match, rule1_rationale, rule1_oracle_type = _evidence_signature_match(
            attack_class=candidate.attack_class,
            value_preview=exception_haystack,
            stderr_preview=stderr_preview,
            expected_observable=test_input.expected_observable,
            args_json=test_input.args_json,
        )
        if rule1_match:
            # v15.26 — message-pattern refutation. Before accepting
            # Rule 1b's substring match, check whether the exception
            # MESSAGE phrases a validation rejection (e.g., "must use
            # HTTPS", "missing required argument"). If so, the
            # function's native validation correctly blocked the
            # input — not an exploit. The exception type alone is
            # insufficient signal here (a custom error class like
            # WorkloadIdentityError isn't in _EXCEPTION_REJECTED_AT_
            # BOUNDARY but its "Token endpoint must use HTTPS"
            # message is clearly a validation block).
            _validation_msg, _matched_phrase = (
                _exception_message_indicates_validation(exception_msg)
            )
            if _validation_msg:
                # Override Rule 1b — message says validation, not
                # exploit. Set rule1_match=False with diagnostic.
                rule1_match = False
                rule1_rationale = (
                    f"Rule 1b suppressed by v15.26 message-pattern check: "
                    f"matched validation phrase {_matched_phrase!r} in "
                    f"exception message — function applied native "
                    f"input validation rather than processing the "
                    f"attack payload."
                )
                rule1_oracle_type = ""
            else:
                rule1_path = "exception"

    # Rule 2: canary side effects. The model is encouraged to include
    # markers in attack inputs (e.g., write to /tmp/argus_probe_*) that
    # the sandbox can observe. Tmp files appearing post-call = exploit.
    _raw_tmp = side_effects.get("tmp_files_added")
    tmp_added: list[str] = (
        [f for f in _raw_tmp if isinstance(f, str)] if isinstance(_raw_tmp, list) else []
    )
    canary_hit = any(
        isinstance(f, str) and ("argus_probe" in f.lower() or "pwned" in f.lower())
        for f in tmp_added
    )

    # v15.26 — Differential fuzzing uniformity check (Gemini Suggestion
    # #3). When Rule 1 fires AND the harness captured a baseline
    # outcome AND the baseline raised the same exception class with a
    # structurally-identical message, the function applies uniform
    # input validation. The attack-shaped payload wasn't special — both
    # garbage and attack inputs were rejected at the same point.
    # Suppress Rule 1's confirm to prevent the false positive.
    #
    # Only fires on Rule 1b (exception path). Return-path matches (Rule
    # 1a) compare value previews, which the baseline doesn't have in
    # the same shape — keep those live.
    if rule1_match and rule1_path == "exception" and trace.baseline_parsed:
        _uniform, _why = _is_differential_uniform_validation(
            trace.parsed_result, trace.baseline_parsed
        )
        if _uniform:
            rule1_match = False
            rule1_rationale = (
                f"Rule 1b suppressed by v15.26 differential-fuzzing "
                f"uniformity check: {_why}. Function applied identical "
                f"validation to both baseline garbage and attack input — "
                f"the attack-shaped payload wasn't special."
            )
            rule1_path = ""
            rule1_oracle_type = ""

    # Build the finding when ANY rule fires.
    evidence_parts: list[str] = []
    if rule1_match and rule1_path == "return":
        evidence_parts.append(
            f"Function returned without raising AND evidence matches: {rule1_rationale}. "
            f"Value preview: {value_preview[:200]}"
        )
    elif rule1_match and rule1_path == "exception":
        evidence_parts.append(
            f"Function raised AND exception evidence matches: {rule1_rationale}. "
            f"Exception: {exception_type}: {exception_msg[:200]}"
        )
    if canary_hit:
        evidence_parts.append(f"Sandbox observed canary file(s) created in /tmp: {tmp_added[:5]}")
    if not evidence_parts:
        # Probe ran cleanly — either ok=True but evidence didn't match,
        # OR raised but exception text didn't match the class signature
        # (e.g., benign ValueError on malformed input that didn't reach
        # the vuln logic). That's BLOCKED/UNREACHED-equivalent.
        return None

    # v15.12 (2026-05-20): include kwargs_json in the probe display so
    # the runtime_evidence string is unambiguous. Pre-v15.12 the format
    # was `Probe \`fn(args_json)\`` — hiding kwargs entirely. On the
    # mako Phase 3 case (HRP_AL_T0_H0), the actual call was
    # ``Template(text="<%! os.system('touch /tmp/argus_pwned_...')%>")``
    # but args_json was ``"[]"`` (no positional args), so the display
    # read ``Probe `Template([])`'' and an external reviewer (Gemini)
    # concluded the canary file must be stale state from a prior probe.
    # The kwargs WERE the attack payload; just invisible in the
    # rendered evidence. Now we always include kwargs_json when it's
    # non-empty/non-default so the trace tells the full story.
    _kwargs = (test_input.kwargs_json or "").strip()
    _has_kwargs = _kwargs and _kwargs not in ("{}", "")
    if _has_kwargs:
        _call_repr = (
            f"{candidate.function_name}({test_input.args_json}, "
            f"**{_kwargs})"
        )
    else:
        _call_repr = f"{candidate.function_name}({test_input.args_json})"
    runtime_evidence = (
        f"Probe `{_call_repr}`: "
        + "; ".join(evidence_parts)
        + f" (exit_code={trace.exit_code}, elapsed={trace.elapsed_ms}ms)"
    )

    # v1.6 Fix #4b: tag which oracle(s) fired so the runner can
    # downgrade confidence on canary-only CONFIRMED (no class-signature
    # backup → CWE class is unverified by sandbox evidence).
    if canary_hit and rule1_oracle_type == "class_signature":
        finding_oracle = "canary+class_signature"
    elif canary_hit:
        finding_oracle = "canary"
    elif rule1_oracle_type:
        finding_oracle = rule1_oracle_type  # "class_signature" | "observable_keyword"
    else:
        finding_oracle = ""

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
        oracle_type=finding_oracle,
    )


def interpret_probe_observation(
    trace: RuntimeProbeTrace,
    *,
    function_name: str,
    kwargs_json: str = "{}",
) -> RuntimeProbeObservation:
    """Convert a ``probe``-kind hypothesis's sandbox trace into a
    descriptive :class:`RuntimeProbeObservation`.

    Unlike :func:`interpret_probe_trace`, this function never asserts
    exploit confirmation. Its job is to package the runtime evidence
    in a model-readable form so the next adversarial-loop turn can
    decide whether (and how) to escalate to an attack hypothesis.

    Three signal axes the model cares about:

    * **Did the function execute at all?** ``parsed_result is None``
      means the harness crashed before printing markers — usually a
      sandbox infra issue or a SIGKILL from a hang.
    * **Did it return or raise?** ``parsed_result["ok"]`` distinguishes
      a clean return (with ``type`` + ``value_preview``) from an
      exception (with ``exception_type`` + ``exception_msg``).
    * **Were there side effects?** ``side_effects.tmp_files_added``
      shows whether canary files materialized — distinct from the
      return path, often the more informative signal for attack design.

    The ``summary`` field is the model-facing one-paragraph view; the
    structured fields are for telemetry + downstream analysis.

    ``kwargs_json`` is plumbed in from the hypothesis (the trace itself
    only records ``input_args_json``) so the observation can echo the
    full call signature back to the model.
    """
    parsed = trace.parsed_result or {}
    side_effects = trace.side_effects or {}

    # Three states: harness crashed / clean return / raised.
    if not parsed:
        returned_cleanly = False
        return_value_type = ""
        return_value_preview = ""
        exception_class = ""
        exception_message = ""
        stderr_tail = (trace.stderr or "")[-200:] or "<empty>"
        summary = (
            f"Probe `{function_name}({trace.input_args_json})` produced no "
            f"RESULT_JSON marker (exit_code={trace.exit_code}). Likely "
            f"sandbox infra issue or process killed before completion. "
            f"Stderr tail: {stderr_tail}"
        )
    else:
        returned_cleanly = bool(parsed.get("ok"))
        if returned_cleanly:
            return_value_type = str(parsed.get("type", "") or "")
            return_value_preview = str(parsed.get("value_preview", "") or "")
            exception_class = ""
            exception_message = ""
            type_part = f" → {return_value_type}" if return_value_type else ""
            preview_part = f" ({return_value_preview[:300]})" if return_value_preview else ""
            summary = (
                f"Probe `{function_name}({trace.input_args_json})` returned "
                f"cleanly{type_part}{preview_part}."
            )
        else:
            return_value_type = ""
            return_value_preview = ""
            exception_class = str(parsed.get("exception_type", "") or "")
            exception_message = str(parsed.get("exception_msg", "") or "")
            exc_part = exception_class or "<unknown exception>"
            msg_part = f": {exception_message[:300]}" if exception_message else ""
            summary = (
                f"Probe `{function_name}({trace.input_args_json})` raised {exc_part}{msg_part}."
            )

    # Side-effect annotation. Canary hits (argus_probe / pwned markers)
    # are the highest-signal observation for the model — they prove the
    # probe actually reached deep enough into the function to materialize
    # observable state. Surfaced explicitly in the summary so the model
    # doesn't have to dig through structured fields to spot them.
    raw_tmp = side_effects.get("tmp_files_added")
    tmp_added: list[str] = (
        [f for f in raw_tmp if isinstance(f, str)] if isinstance(raw_tmp, list) else []
    )
    if tmp_added:
        canary_hits = [f for f in tmp_added if "argus_probe" in f.lower() or "pwned" in f.lower()]
        if canary_hits:
            summary += f" Canary side-effect: created {canary_hits[:3]}."
        else:
            summary += f" Side-effect: tmp files added {tmp_added[:5]}."

    return RuntimeProbeObservation(
        function_called=function_name,
        input_args_json=trace.input_args_json,
        input_kwargs_json=kwargs_json,
        returned_cleanly=returned_cleanly,
        return_value_type=return_value_type,
        return_value_preview=return_value_preview,
        exception_class=exception_class,
        exception_message=exception_message,
        stdout_excerpt=(trace.stdout or "")[:800],
        stderr_excerpt=(trace.stderr or "")[:800],
        side_effects=dict(side_effects),
        exit_code=trace.exit_code,
        elapsed_ms=trace.elapsed_ms,
        summary=summary,
    )


# ── Phase 2: chain harness + plan + interpretation ───────────────────────
#
# Chain harness execution model:
#
# 1. For each step, decode args_json + kwargs_json.
# 2. Walk args/kwargs recursively; any string matching the placeholder
#    pattern ``<<_stepN_result>>`` is replaced with the captured return
#    value of step N (1-indexed, must reference a prior step).
# 3. Resolve the step's function via the same getattr walk as single-
#    function probes.
# 4. Call the function with substituted args. On exception:
#       * if it's NOT the last step → short_circuited=True, emit
#         CHAIN_RESULT_JSON with per_step_results truncated at this step,
#         no SIDE_EFFECTS-side rules will fire for that finding.
#       * if it IS the last step → record the exception in
#         per_step_results AND continue to side-effect snapshot (Rule 2
#         may still fire via canary markers).
# 5. After the loop, emit CHAIN_RESULT_JSON (list of per-step outcomes)
#    and SIDE_EFFECTS markers.
#
# Rule 1/Rule 2 interpretation:
#   * Rule 1 (evidence signature) — operates on the LAST step's
#     value_preview only. Earlier steps' previews are intentionally
#     ignored (they're plumbing). short_circuited=True automatically
#     fails Rule 1 (the chain didn't reach the exploit trigger).
#   * Rule 2 (canary side effect) — operates on the end-of-chain /tmp
#     diff. Fires regardless of which step created the canary file
#     (could be plumbing or exploit; the marker presence is the signal).


#: Placeholder regex. ``<<_step1_result>>``, ``<<_step2_result>>``, etc.
#: Anchored at start/end of string — full-value substitution only, no
#: partial in-string interpolation. Keeps semantics simple and predictable.
_CHAIN_PLACEHOLDER_RE = re.compile(r"^<<_step(\d+)_result>>$")


def _build_python_chain_harness(
    *,
    module_name: str,
    steps: list[RuntimeProbeChainStep],
    module_file_path: str = "",
) -> str:
    """Generate the Python harness that runs ONE chain inside the sandbox.

    Layout:
    1. Snapshot baseline (/tmp listing).
    2. Path-prep preamble (same as single-function harness, but scanning
       both module source AND all step inputs for path components).
    3. Import the target module from /workspace.
    4. For each step (in order):
       a. Resolve the function via getattr walk.
       b. Decode args_json / kwargs_json.
       c. Walk values; substitute ``<<_stepN_result>>`` placeholders with
          the captured prior step results (full-value substitution).
       d. Call the function, capture the return value into a per-step
          slot, record outcome (ok/type/value_preview or exception).
       e. On exception at a non-last step: break out of the loop, mark
          short_circuited=True, skip later steps.
    5. Emit ``CHAIN_RESULT_JSON:{...}`` (per_step_results list +
       short_circuited flag) and ``SIDE_EFFECTS:{...}``.

    The harness embeds the steps' args / kwargs as JSON literals so it
    works under ``shlex.quote`` without escape-hell.
    """
    # Serialize the steps as a JSON list the harness can json.loads().
    steps_payload = [
        {
            "function_name": s.function_name,
            "args_json": s.args_json,
            "kwargs_json": s.kwargs_json,
        }
        for s in steps
    ]
    steps_repr = repr(json.dumps(steps_payload))
    deny_repr = repr(_PROBE_PREP_DENY_PREFIXES)
    # NOTE on v1.0 harness rewrite (reverted): the more-defensive harness
    # (top-level try/except wrap + atexit safety + socket.setdefaulttimeout)
    # was correct in isolation (local subprocess.run + 121 unit tests pass)
    # but EMPIRICALLY broke event delivery in the Fly sandbox — the
    # post-rewrite chain probes silently fail with ``per_step=(no steps)``
    # even on files where the v0 harness produced valid per-step output.
    # Diagnosis pending. Until the Fly-side delivery issue is understood,
    # the harness is back to the v0 shape (kept minimal so it doesn't
    # introduce its own delivery regressions). Interpreter-side defenses
    # (NoneType-intermediate guard + confidence scoring) are retained
    # because they don't depend on harness shape.
    return (
        "import sys, os, json, traceback, re\n"
        "sys.path.insert(0, '/workspace')\n"
        "baseline_tmp = set()\n"
        "try:\n"
        "    baseline_tmp = set(os.listdir('/tmp'))\n"
        "except Exception:\n"
        "    pass\n"
        # Decode the chain spec.
        f"_steps = json.loads({steps_repr})\n"
        # Path-prep preamble (mirrors single-function harness).
        f"_DENY = {deny_repr}\n"
        # When ``module_file_path`` is supplied (package members staged
        # with their package layout, e.g. ``/workspace/jsonpickle/
        # unpickler.py``), use the explicit on-disk path. Otherwise fall
        # back to the flat-module convention (``/workspace/<basename>.py``).
        f"_module_path = {(module_file_path or f'/workspace/{module_name}.py')!r}\n"
        "_paths_to_prep = set()\n"
        "try:\n"
        "    _src = open(_module_path).read()\n"
        "    _paths_to_prep = set(re.findall("
        "r'''[\"\\']((?:/[A-Za-z_][\\w./-]*))[\"\\']''', _src))\n"
        "except Exception:\n"
        "    pass\n"
        "_abs_dir_prefixes = set()\n"
        "for _p in _paths_to_prep:\n"
        "    if any(_p == d or _p.startswith(d + '/') for d in _DENY):\n"
        "        continue\n"
        "    try:\n"
        "        _bn = os.path.basename(_p.rstrip('/'))\n"
        "        _looks_like_file = '.' in _bn and not _p.endswith('/')\n"
        "        _to_mk = os.path.dirname(_p) if _looks_like_file else _p.rstrip('/')\n"
        "        if _to_mk and _to_mk != '/':\n"
        "            os.makedirs(_to_mk, exist_ok=True)\n"
        "            _abs_dir_prefixes.add(_to_mk)\n"
        "    except (OSError, PermissionError):\n"
        "        pass\n"
        # Aggregate step inputs for input-derived path-prep.
        "_all_input_strs = []\n"
        "for _s in _steps:\n"
        "    try:\n"
        "        _all_input_strs.extend(json.loads(_s.get('args_json', '[]')))\n"
        "        _all_input_strs.extend(list(json.loads(_s.get('kwargs_json', '{}')).values()))\n"
        "    except Exception:\n"
        "        pass\n"
        "_skip = {'..', '.', ''}\n"
        "for _arg in _all_input_strs:\n"
        "    if not (isinstance(_arg, str) and '/' in _arg):\n"
        "        continue\n"
        "    _comps = [c for c in _arg.split('/') if c not in _skip]\n"
        "    if not _comps:\n"
        "        continue\n"
        "    for _depth in range(1, len(_comps)):\n"
        "        _rel = '/'.join(_comps[:_depth])\n"
        "        for _src_dir in _abs_dir_prefixes:\n"
        "            try:\n"
        "                _full = _src_dir.rstrip('/') + '/' + _rel\n"
        "                if any(_full == d or _full.startswith(d + '/') for d in _DENY):\n"
        "                    continue\n"
        "                os.makedirs(_full, exist_ok=True)\n"
        "            except (OSError, PermissionError):\n"
        "                pass\n"
        # Module import — wrapped so an ImportError (missing sandbox dep,
        # syntax error in target file, etc.) produces a structured
        # CHAIN_RESULT_JSON marker instead of a silent harness crash.
        "try:\n"
        f"    import {module_name} as _target\n"
        "except BaseException as _imp_e:\n"
        "    print('CHAIN_RESULT_JSON:' + json.dumps({\n"
        "        'per_step_results': [{\n"
        "            'step': 1,\n"
        "            'function_name': (_steps[0]['function_name'] if _steps else ''),\n"
        "            'ok': False,\n"
        "            'exception_type': type(_imp_e).__name__,\n"
        "            'exception_msg': str(_imp_e)[:300],\n"
        "        }],\n"
        "        'short_circuited': True,\n"
        "    }))\n"
        "    print('SIDE_EFFECTS:' + json.dumps({'tmp_files_added': []}))\n"
        "    sys.exit(0)\n"
        # Chain execution loop.
        "_results = []  # captured return values per step, 1-indexed via index+1\n"
        "_per_step = []\n"
        "_short_circuited = False\n"
        "_PLACEHOLDER_RE = re.compile(r'^<<_step(\\d+)_result>>$')\n"
        "def _substitute(v, results):\n"
        "    if isinstance(v, str):\n"
        "        m = _PLACEHOLDER_RE.match(v)\n"
        "        if m:\n"
        "            idx = int(m.group(1)) - 1\n"
        "            if 0 <= idx < len(results):\n"
        "                return results[idx]\n"
        "        return v\n"
        "    if isinstance(v, list):\n"
        "        return [_substitute(x, results) for x in v]\n"
        "    if isinstance(v, dict):\n"
        "        return {k: _substitute(x, results) for k, x in v.items()}\n"
        "    return v\n"
        "for _i, _spec in enumerate(_steps):\n"
        "    _fn_name = _spec.get('function_name', '')\n"
        "    try:\n"
        "        _fn = _target\n"
        "        for _part in _fn_name.split('.'):\n"
        "            _fn = getattr(_fn, _part)\n"
        "    except AttributeError as e:\n"
        "        _per_step.append({\n"
        "            'step': _i + 1,\n"
        "            'function_name': _fn_name,\n"
        "            'ok': False,\n"
        "            'exception_type': 'AttributeError',\n"
        "            'exception_msg': str(e)[:300],\n"
        "        })\n"
        "        _short_circuited = (_i < len(_steps) - 1)\n"
        "        break\n"
        "    try:\n"
        "        _raw_args = json.loads(_spec.get('args_json', '[]'))\n"
        "        _raw_kwargs = json.loads(_spec.get('kwargs_json', '{}'))\n"
        "    except (json.JSONDecodeError, ValueError) as e:\n"
        "        _per_step.append({\n"
        "            'step': _i + 1,\n"
        "            'function_name': _fn_name,\n"
        "            'ok': False,\n"
        "            'exception_type': 'JSONDecodeError',\n"
        "            'exception_msg': str(e)[:300],\n"
        "        })\n"
        "        _short_circuited = (_i < len(_steps) - 1)\n"
        "        break\n"
        "    _args = _substitute(_raw_args, _results)\n"
        "    _kwargs = _substitute(_raw_kwargs, _results)\n"
        "    try:\n"
        "        _ret = _fn(*_args, **_kwargs)\n"
        "        _results.append(_ret)\n"
        "        _per_step.append({\n"
        "            'step': _i + 1,\n"
        "            'function_name': _fn_name,\n"
        "            'ok': True,\n"
        "            'type': type(_ret).__name__,\n"
        "            'value_preview': repr(_ret)[:600],\n"
        "        })\n"
        "    except BaseException as e:\n"
        "        _per_step.append({\n"
        "            'step': _i + 1,\n"
        "            'function_name': _fn_name,\n"
        "            'ok': False,\n"
        "            'exception_type': type(e).__name__,\n"
        "            'exception_msg': str(e)[:300],\n"
        "            'tb_tail': traceback.format_exc()[-1500:],\n"
        "        })\n"
        "        _short_circuited = (_i < len(_steps) - 1)\n"
        "        if _short_circuited:\n"
        "            break\n"
        # Emit chain result + side effects.
        # File-based transport: write the combined payload to a known
        # path so the entrypoint can chunk it past Fly's per-log-line
        # ~4KB truncation cap. stdout markers below are retained as a
        # backward-compat fallback for small chains on older images
        # that don't yet have the entrypoint drain step.
        "added_tmp = []\n"
        "try:\n"
        "    added_tmp = sorted(set(os.listdir('/tmp')) - baseline_tmp)\n"
        "except Exception:\n"
        "    pass\n"
        "_chain_payload = {\n"
        "    'per_step_results': _per_step,\n"
        "    'short_circuited': _short_circuited,\n"
        "    'side_effects': {'tmp_files_added': added_tmp[:20]},\n"
        "}\n"
        "_chain_payload_json = json.dumps(_chain_payload)\n"
        "try:\n"
        "    with open('/workspace/argus_probe_result.json', 'w') as _f:\n"
        "        _f.write(_chain_payload_json)\n"
        "except Exception:\n"
        "    pass\n"
        "print('CHAIN_RESULT_JSON:' + json.dumps({\n"
        "    'per_step_results': _per_step,\n"
        "    'short_circuited': _short_circuited,\n"
        "}))\n"
        "print('SIDE_EFFECTS:' + json.dumps({\n"
        "    'tmp_files_added': added_tmp[:20],\n"
        "}))\n"
    )


def _build_javascript_chain_harness(
    *,
    module_path: str,
    steps: list[RuntimeProbeChainStep],
) -> str:
    """Generate the Node.js harness that runs ONE chain inside the sandbox.

    JS parallel of :func:`_build_python_chain_harness`. Same output
    contract (``CHAIN_RESULT_JSON:`` + ``SIDE_EFFECTS:`` markers),
    same per-step result schema, so the interpreter
    (``interpret_probe_chain_trace``) works uniformly across languages.

    Layout:
      1. Process-level fatal-error handlers — any catastrophic failure
         still emits a CHAIN_RESULT_JSON marker rather than silent
         exit-1.
      2. Snapshot /tmp baseline for side-effect diff.
      3. Dynamic ``import()`` the target (works for CJS + ESM).
      4. For each step:
         a. Resolve function via dotted-path walk on the namespace
            (CJS module.exports or ESM named/default exports).
         b. Decode args / kwargs JSON.
         c. Substitute ``<<_stepN_result>>`` placeholders with prior
            step return values (full-value substitution; nested
            objects/arrays walked recursively).
         d. Call function (await if returns a Promise).
         e. Capture per-step outcome; short-circuit on non-last-step
            exception.
      5. Emit ``CHAIN_RESULT_JSON:{per_step_results, short_circuited}``
         and ``SIDE_EFFECTS:{tmp_files_added}``.
      6. Also write the payload to ``/workspace/argus_probe_result.json``
         to bypass Fly's per-log-line ~4KB stdout cap.

    Wrapped in an async IIFE so top-level ``await`` works.
    """
    steps_payload = [
        {
            "function_name": s.function_name,
            "args_json": s.args_json,
            "kwargs_json": s.kwargs_json,
        }
        for s in steps
    ]
    steps_lit = json.dumps(json.dumps(steps_payload))
    module_path_lit = json.dumps(module_path)
    return (
        # ── Fatal-error safety net ──────────────────────────────────────
        "let _markerEmitted = false;\n"
        "function _emitFatal(label, err) {\n"
        "  if (_markerEmitted) return;\n"
        "  _markerEmitted = true;\n"
        "  const msg = err && (err.message || err.toString) "
        "? String(err.message || err).slice(0, 300) : String(err).slice(0, 300);\n"
        "  const ctor = err && err.constructor && err.constructor.name "
        "? err.constructor.name : 'Error';\n"
        "  try {\n"
        "    console.log('CHAIN_RESULT_JSON:' + JSON.stringify({\n"
        "      per_step_results: [{\n"
        "        step: 1,\n"
        "        function_name: '',\n"
        "        ok: false,\n"
        "        exception_type: ctor,\n"
        "        exception_msg: '[' + label + '] ' + msg,\n"
        "      }],\n"
        "      short_circuited: true,\n"
        "    }));\n"
        "    console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: [] }));\n"
        "  } catch (e) {}\n"
        "}\n"
        "process.on('uncaughtException', (e) => _emitFatal('uncaughtException', e));\n"
        "process.on('unhandledRejection', (e) => _emitFatal('unhandledRejection', e));\n"
        "setTimeout(() => _emitFatal('innerHarnessTimeout', "
        "new Error('chain harness exceeded 45s inner budget')), 45000).unref();\n"
        "\n"
        "(async () => {\n"
        "  const fs = require('fs');\n"
        "  const path = require('path');\n"
        "  const { pathToFileURL } = require('url');\n"
        "  const steps = JSON.parse(" + steps_lit + ");\n"
        "  let baselineTmp = new Set();\n"
        "  try { baselineTmp = new Set(fs.readdirSync('/tmp')); } catch (e) {}\n"
        # ── Dynamic import target ──────────────────────────────────────
        "  let mod;\n"
        "  try {\n"
        "    mod = await import(pathToFileURL(" + module_path_lit + ").href);\n"
        "  } catch (e) {\n"
        "    _markerEmitted = true;\n"
        "    console.log('CHAIN_RESULT_JSON:' + JSON.stringify({\n"
        "      per_step_results: [{\n"
        "        step: 1,\n"
        "        function_name: steps[0] ? steps[0].function_name : '',\n"
        "        ok: false,\n"
        "        exception_type: (e && e.constructor ? e.constructor.name : 'Error'),\n"
        "        exception_msg: String((e && e.message) || e).slice(0, 300),\n"
        "      }],\n"
        "      short_circuited: true,\n"
        "    }));\n"
        "    console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: [] }));\n"
        "    return;\n"
        "  }\n"
        # ── Dotted-path resolver (CJS module.exports + ESM default) ────
        "  function resolveFn(modObj, dotted) {\n"
        "    const parts = dotted.split('.');\n"
        "    let cur = modObj;\n"
        "    for (const p of parts) {\n"
        "      if (cur != null && typeof cur === 'object' && p in cur) {\n"
        "        cur = cur[p];\n"
        "      } else {\n"
        "        return undefined;\n"
        "      }\n"
        "    }\n"
        "    return cur;\n"
        "  }\n"
        # ── Placeholder substitution ───────────────────────────────────
        "  const PLACEHOLDER_RE = /^<<_step(\\d+)_result>>$/;\n"
        "  function substitute(v, results) {\n"
        "    if (typeof v === 'string') {\n"
        "      const m = PLACEHOLDER_RE.exec(v);\n"
        "      if (m) {\n"
        "        const idx = parseInt(m[1], 10) - 1;\n"
        "        if (idx >= 0 && idx < results.length) return results[idx];\n"
        "      }\n"
        "      return v;\n"
        "    }\n"
        "    if (Array.isArray(v)) return v.map(x => substitute(x, results));\n"
        "    if (v && typeof v === 'object') {\n"
        "      const out = {};\n"
        "      for (const k of Object.keys(v)) out[k] = substitute(v[k], results);\n"
        "      return out;\n"
        "    }\n"
        "    return v;\n"
        "  }\n"
        # ── Per-step execution loop ────────────────────────────────────
        "  const results = [];\n"
        "  const perStep = [];\n"
        "  let shortCircuited = false;\n"
        "  for (let i = 0; i < steps.length; i++) {\n"
        "    const spec = steps[i];\n"
        "    const fnName = spec.function_name || '';\n"
        "    let fn = resolveFn(mod, fnName);\n"
        "    if (typeof fn !== 'function' && mod && mod.default != null) {\n"
        "      fn = resolveFn(mod.default, fnName);\n"
        "    }\n"
        "    if (typeof fn !== 'function') {\n"
        "      perStep.push({\n"
        "        step: i + 1,\n"
        "        function_name: fnName,\n"
        "        ok: false,\n"
        "        exception_type: 'AttributeError',\n"
        "        exception_msg: 'function not found: ' + fnName,\n"
        "      });\n"
        "      shortCircuited = (i < steps.length - 1);\n"
        "      break;\n"
        "    }\n"
        "    let rawArgs, rawKwargs;\n"
        "    try {\n"
        "      rawArgs = JSON.parse(spec.args_json || '[]');\n"
        "      rawKwargs = JSON.parse(spec.kwargs_json || '{}');\n"
        "    } catch (e) {\n"
        "      perStep.push({\n"
        "        step: i + 1,\n"
        "        function_name: fnName,\n"
        "        ok: false,\n"
        "        exception_type: 'JSONDecodeError',\n"
        "        exception_msg: String((e && e.message) || e).slice(0, 300),\n"
        "      });\n"
        "      shortCircuited = (i < steps.length - 1);\n"
        "      break;\n"
        "    }\n"
        "    const args = substitute(rawArgs, results);\n"
        "    const kwargs = substitute(rawKwargs, results);\n"
        # Pass kwargs as a trailing object arg if non-empty (JS convention).
        "    const kwKeys = Object.keys(kwargs);\n"
        "    const callArgs = kwKeys.length > 0 ? [...args, kwargs] : args;\n"
        "    try {\n"
        "      let ret = fn(...callArgs);\n"
        "      if (ret && typeof ret.then === 'function') {\n"
        "        ret = await ret;\n"
        "      }\n"
        "      results.push(ret);\n"
        "      let preview;\n"
        "      try {\n"
        "        preview = (typeof ret === 'string') ? ret : JSON.stringify(ret);\n"
        "        preview = String(preview || '').slice(0, 600);\n"
        "      } catch (e) {\n"
        "        preview = String(ret).slice(0, 600);\n"
        "      }\n"
        "      perStep.push({\n"
        "        step: i + 1,\n"
        "        function_name: fnName,\n"
        "        ok: true,\n"
        "        type: (ret === null) ? 'null' : (Array.isArray(ret) ? 'array' : typeof ret),\n"
        "        value_preview: preview,\n"
        "      });\n"
        "    } catch (e) {\n"
        "      const stack = e && e.stack ? String(e.stack).slice(-1500) : '';\n"
        "      perStep.push({\n"
        "        step: i + 1,\n"
        "        function_name: fnName,\n"
        "        ok: false,\n"
        "        exception_type: e && e.constructor ? e.constructor.name : 'Error',\n"
        "        exception_msg: String((e && e.message) || e).slice(0, 300),\n"
        "        tb_tail: stack,\n"
        "      });\n"
        "      shortCircuited = (i < steps.length - 1);\n"
        "      if (shortCircuited) break;\n"
        "    }\n"
        "  }\n"
        # ── Emit chain result + side effects ────────────────────────────
        "  let addedTmp = [];\n"
        "  try {\n"
        "    addedTmp = fs.readdirSync('/tmp').filter(f => !baselineTmp.has(f)).sort().slice(0, 20);\n"
        "  } catch (e) {}\n"
        "  const payload = {\n"
        "    per_step_results: perStep,\n"
        "    short_circuited: shortCircuited,\n"
        "    side_effects: { tmp_files_added: addedTmp },\n"
        "  };\n"
        "  try {\n"
        "    fs.writeFileSync('/workspace/argus_probe_result.json', JSON.stringify(payload));\n"
        "  } catch (e) {}\n"
        "  _markerEmitted = true;\n"
        "  console.log('CHAIN_RESULT_JSON:' + JSON.stringify({\n"
        "    per_step_results: perStep,\n"
        "    short_circuited: shortCircuited,\n"
        "  }));\n"
        "  console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: addedTmp }));\n"
        "})().catch(e => _emitFatal('iifeBody', e));\n"
    )


def build_runtime_probe_chain_plan(
    *,
    file_name: str,
    file_bytes: bytes,
    chain: RuntimeProbeChain,
    chain_idx: int,
    image_hint: str = "lean",
    entry_rel_path: str = "",
) -> dict[str, Any] | None:
    """Build a Phase-A-shaped plan dict that runs one chain.

    Dispatches by language:
      * ``.py`` / ``.pth`` → Python chain harness (v1.6)
      * ``.js`` / ``.mjs`` / ``.cjs`` → JS chain harness (v1.8 JS DAST parity)
      * ``.ts`` / ``.tsx`` → Same JS chain harness, launched via ``tsx``
        so dynamic ``import()`` of the user's TS target transpiles
        on-the-fly (v10, 2026-05-16 — replaced v9's ts-node loader
        which had 100% TS-file failure due to a CJS-entry+ESM-dynamic-
        import cycle bug)
      * shell / other → ``None`` (no chain harness for these)

    Returns ``None`` when the chain is structurally invalid (< 2 steps,
    > :data:`MAX_CHAIN_STEPS`) regardless of language.

    Plan's ``hypothesis_id`` is ``HRP_C<chain_idx>`` — distinct namespace
    from single-function ``HRP_<c>_<i>`` so cross-feature findings don't
    collide in journal lookups.
    """
    lang = detect_probe_language(file_name)
    if lang not in ("python", "javascript", "typescript"):
        return None
    if len(chain.steps) < 2 or len(chain.steps) > MAX_CHAIN_STEPS:
        return None

    payload_b64 = base64.b64encode(file_bytes).decode("ascii")

    # v12 (2026-05-17): multi-file project staging. See
    # build_runtime_probe_plan docstring for the full architecture
    # explanation. Entry is pre-staged at entry_target_path via the
    # additional_files tarball (no runtime mkdir + mv needed).
    file_base = Path(file_name).name
    entry_rel_path = (entry_rel_path or "").replace("\\", "/").strip()
    entry_target_path = (
        f"/workspace/{entry_rel_path}" if entry_rel_path else f"/workspace/{file_base}"
    )

    if lang == "python":
        module_name = _python_module_name_for_file(file_name, entry_rel_path)
        harness = _build_python_chain_harness(
            module_name=module_name,
            steps=chain.steps,
            module_file_path=entry_target_path,
        )
        harness_path = f"/workspace/_argus_chain_{chain_idx}.py"
        write_cmd = (
            f'python3 -c "import base64,sys; '
            f"open({harness_path!r},'wb').write("
            f'base64.b64decode(sys.argv[1]))" '
            f"{base64.b64encode(harness.encode('utf-8')).decode('ascii')}"
        )
        run_cmd = f"python3 {harness_path}"
    else:  # javascript or typescript — same chain harness, runner differs
        # v12: module_path uses entry_target_path so chains on
        # multi-file projects import from /workspace/<entry_rel_path>
        # and parent-dir imports in the entry resolve to staged siblings.
        module_path = entry_target_path
        harness = _build_javascript_chain_harness(module_path=module_path, steps=chain.steps)
        harness_path = f"/workspace/_argus_chain_{chain_idx}.cjs"
        write_cmd = (
            f'python3 -c "import base64,sys; '
            f"open({harness_path!r},'wb').write("
            f'base64.b64decode(sys.argv[1]))" '
            f"{base64.b64encode(harness.encode('utf-8')).decode('ascii')}"
        )
        # cd /workspace so npm-installed deps (from P2a-JS) resolve via
        # Node's standard module lookup.
        #
        # TS variant (v11): launch via ``tsx`` so dynamic import() of
        # user .ts targets transpiles on-the-fly. tsx skips type-check
        # by default — user-code type errors must not block DAST runtime
        # probing. Replaces v9's ``node --loader ts-node/esm`` which had
        # 100% TS-file failure due to a CJS-entry+ESM-dynamic-import
        # cycle in ts-node's loader hook.
        #
        # Two config files written before tsx runs:
        #   * package.json with ``{"type":"module"}`` — ESM features in
        #     user .ts files (top-level await, etc.).
        #   * tsconfig.json with ``moduleResolution:"bundler"`` — TS
        #     ecosystem standard so ``import './foo.js'`` resolves to
        #     ``./foo.ts`` source on disk for multi-file TS projects.
        #
        # v12: entry pre-staged at entry_target_path via tarball.
        # Plan run_cmd just configures tsx (TS) or runs node (JS).
        if lang == "typescript":
            run_cmd = (
                f"cd /workspace && "
                f"echo '{{\"type\":\"module\"}}' > package.json && "
                f"echo '{{\"compilerOptions\":"
                f"{{\"moduleResolution\":\"bundler\","
                f"\"allowImportingTsExtensions\":true,"
                f"\"target\":\"esnext\",\"module\":\"esnext\","
                f"\"isolatedModules\":true,\"skipLibCheck\":true}}}}'"
                f" > tsconfig.json && "
                f"tsx {harness_path}"
            )
        else:  # javascript
            run_cmd = f"cd /workspace && node {harness_path}"

    chain_summary = " -> ".join(s.function_name for s in chain.steps)
    return {
        "hypothesis_id": f"HRP_C{chain_idx}",
        "plan_status": "executable",
        "commands": [write_cmd, run_cmd],
        "oracle": "execution_output_with_side_effect_observation",
        "payload": payload_b64,
        "payload_encoding": "base64",
        "timeout_sec": DEFAULT_PROBE_TIMEOUT_SEC,
        "image_hint": image_hint,
        "rationale": (
            f"Runtime probe chain ({lang}, {len(chain.steps)} steps): "
            f"{chain_summary}. Attack class: {chain.attack_class}. "
            f"Expected if vulnerable: {chain.expected_observable[:150]}"
        ),
    }


def parse_probe_chain_trace(
    *,
    chain_idx: int,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    elapsed_ms: int,
    probe_result_json: str = "",
) -> RuntimeProbeChainTrace:
    """Pull the structured markers out of the chain harness output and
    build a typed trace record.

    Prefers the file-based transport (``probe_result_json``) when
    populated — bypasses Fly's per-log-line ~4KB cap that truncates
    large multi-step chain markers. Falls back to scanning ``stdout``
    for ``CHAIN_RESULT_JSON:`` and ``SIDE_EFFECTS:`` marker lines when
    ``probe_result_json`` is empty (older sandbox image without
    entrypoint drain, or chain harness didn't write to the result file).

    Defensive against truncated stdout / harness crash before markers /
    broken JSON in either channel. Any parse failure leaves
    ``per_step_results=[]`` so the interpreter can treat the chain as
    observed-but-not-confirmed rather than crashing the orchestrator.
    """
    trace = RuntimeProbeChainTrace(
        chain_idx=chain_idx,
        steps_summary=[],
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        elapsed_ms=elapsed_ms,
    )

    # First try the file-based channel — bypasses Fly log truncation.
    if probe_result_json:
        try:
            parsed = json.loads(probe_result_json)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            per_step = parsed.get("per_step_results", [])
            if isinstance(per_step, list):
                trace.per_step_results = [x for x in per_step if isinstance(x, dict)]
            trace.short_circuited = bool(parsed.get("short_circuited"))
            # Chain harness writes side_effects into the file payload too.
            se = parsed.get("side_effects") or {}
            if isinstance(se, dict):
                trace.side_effects = se
            _populate_chain_steps_summary(trace)
            return trace

    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("CHAIN_RESULT_JSON:"):
            payload = line[len("CHAIN_RESULT_JSON:") :].strip()
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    per_step = parsed.get("per_step_results", [])
                    if isinstance(per_step, list):
                        trace.per_step_results = [x for x in per_step if isinstance(x, dict)]
                    trace.short_circuited = bool(parsed.get("short_circuited"))
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

    _populate_chain_steps_summary(trace)
    return trace


def _populate_chain_steps_summary(trace: RuntimeProbeChainTrace) -> None:
    """Build a human-readable per-step summary line list on the trace.
    Shared by both the file-based-transport path and the stdout-
    marker-fallback path in :func:`parse_probe_chain_trace`."""
    summary: list[str] = []
    for step_res in trace.per_step_results:
        step_num = step_res.get("step", "?")
        fn_name = step_res.get("function_name", "?")
        if step_res.get("ok"):
            summary.append(f"step{step_num}: {fn_name} -> ok type={step_res.get('type', '?')}")
        else:
            exc = step_res.get("exception_type", "?")
            msg = str(step_res.get("exception_msg", ""))[:120]
            summary.append(f"step{step_num}: {fn_name} -> {exc}: {msg}")
    trace.steps_summary = summary


def interpret_probe_chain_trace(
    trace: RuntimeProbeChainTrace,
    chain: RuntimeProbeChain,
    *,
    chain_idx: int,
) -> RuntimeProbeChainFinding | None:
    """Decide whether the chain trace constitutes a runtime-confirmed
    exploit. Rules mirror :func:`interpret_probe_trace` but apply to
    the FINAL step's outcome only:

    **Rule 1 (chain-FP-hardened):** the chain did NOT short-circuit
    AND no INTERMEDIATE step returned ``NoneType`` (FP defense — see
    below) AND the final step returned ``ok=True`` AND the final step's
    ``value_preview`` matches the attack-class evidence signature OR
    the chain's expected_observable keyword extraction.

    *NoneType intermediate guard rationale:* a non-final step returning
    ``NoneType`` is a strong signal the chain fell into a fallback /
    simulation / no-effect branch (e.g., ``connect()`` returns ``None``
    when its driver isn't installed). The function then walks a code
    path that wasn't actually exercised by the attack input, and any
    keyword the model predicted that happens to appear in the stub
    output produces a Rule 1 false-positive. Refusing Rule 1
    confirmation when an intermediate step is ``NoneType`` kills this
    FP class without affecting:
      * legitimate exploits where the FINAL step returns ``None`` (a
        write-only sink — Rule 2 fires via canary instead);
      * exploits without any NoneType-returning intermediate;
      * Rule 2 confirmations (canary side-effect path is unaffected).

    **Rule 2 (chain-aware):** ``side_effects.tmp_files_added`` contains
    canary-marker files. Fires regardless of short_circuited / final
    step outcome / intermediate NoneType — the file appearing IS the
    signal that some step executed an exploit. Strongest oracle by
    construction: a canary file can only land in /tmp if some step
    actually wrote it, so causation is established.

    Returns ``None`` when no rule fires.
    """
    if not trace.per_step_results:
        # Harness crashed before emitting markers — can't interpret.
        return None

    # Rule 1: requires reaching final step + ok=True + evidence match +
    # NO intermediate NoneType (FP defense against simulation branches).
    final_step = trace.per_step_results[-1] if trace.per_step_results else {}
    reached_final = not trace.short_circuited and len(trace.per_step_results) == len(chain.steps)
    intermediate_results = trace.per_step_results[:-1]
    intermediate_none_step = next(
        (s for s in intermediate_results if isinstance(s, dict) and s.get("type") == "NoneType"),
        None,
    )
    rule1_match = False
    rule1_rationale = ""
    rule1_oracle_type: EvidenceOracleType = ""
    # NoneType-intermediate suppression: when any non-final step
    # returned NoneType, Rule 1 doesn't fire. The intermediate NoneType
    # signals a fallback/simulation path; any keyword the model
    # predicted that happens to appear in stub output is a FP, not
    # exploit evidence. The journal entry's per_step summary already
    # shows the NoneType return, so operators can see why Rule 1 stayed
    # silent. Rule 2 (canary) below is unaffected — canary is causal
    # evidence regardless of intermediate types.
    if intermediate_none_step is None and reached_final and bool(final_step.get("ok")):
        value_preview = str(final_step.get("value_preview", "") or "")
        stderr_preview = str(final_step.get("stderr_preview", "") or "")
        # Concatenate all step args for the causal-signature check.
        # If any signature in the final-step evidence was already in
        # the chain's input args (any step), treat as pass-through.
        chain_args_json = " ".join(
            str(getattr(step, "args_json", "") or "") for step in chain.steps
        )
        rule1_match, rule1_rationale, rule1_oracle_type = _evidence_signature_match(
            attack_class=chain.attack_class,
            value_preview=value_preview,
            stderr_preview=stderr_preview,
            expected_observable=chain.expected_observable,
            args_json=chain_args_json,
        )

    # Rule 2: canary side effects (chain-aware — fires anywhere in chain).
    side_effects = trace.side_effects or {}
    _raw_tmp = side_effects.get("tmp_files_added")
    tmp_added: list[str] = (
        [f for f in _raw_tmp if isinstance(f, str)] if isinstance(_raw_tmp, list) else []
    )
    canary_hit = any(
        isinstance(f, str) and ("argus_probe" in f.lower() or "pwned" in f.lower())
        for f in tmp_added
    )

    evidence_parts: list[str] = []
    if rule1_match:
        final_preview = str(final_step.get("value_preview", "") or "")[:200]
        evidence_parts.append(
            f"Chain reached final step ({chain.steps[-1].function_name}) which returned "
            f"without raising AND evidence matches: {rule1_rationale}. "
            f"Final value preview: {final_preview}"
        )
    if canary_hit:
        evidence_parts.append(
            f"Sandbox observed canary file(s) created in /tmp during chain execution: "
            f"{tmp_added[:5]}"
        )
    if not evidence_parts:
        return None

    # Phase 2 v1.0 confidence calibration: Rule 2 canary > Rule 1 class
    # signature > Rule 1 observable keyword. When multiple oracles fire
    # for the same chain, we take the MAXIMUM (Rule 2 wins). This
    # surfaces structural FP risk to downstream consumers (adjudicator,
    # report writer) without removing detection.
    if canary_hit:
        confidence = CHAIN_CONFIDENCE_CANARY
        oracle_type = "canary"
    elif rule1_oracle_type == "class_signature":
        confidence = CHAIN_CONFIDENCE_CLASS_SIGNATURE
        oracle_type = "class_signature"
    elif rule1_oracle_type == "observable_keyword":
        confidence = CHAIN_CONFIDENCE_OBSERVABLE_KEYWORD
        oracle_type = "observable_keyword"
    else:
        # Shouldn't reach here (evidence_parts must be empty if no oracle
        # fired and we'd have returned None above), but guard for safety.
        confidence = CHAIN_CONFIDENCE_OBSERVABLE_KEYWORD
        oracle_type = ""

    chain_steps_human = [f"{s.function_name}({s.args_json})" for s in chain.steps]
    steps_summary_str = " | ".join(trace.steps_summary) if trace.steps_summary else "(no steps)"
    runtime_evidence = (
        f"Chain probe ({' -> '.join(s.function_name for s in chain.steps)}, "
        f"oracle={oracle_type}, confidence={confidence}): "
        + "; ".join(evidence_parts)
        + f" | Per-step: {steps_summary_str}"
        + f" (exit_code={trace.exit_code}, elapsed={trace.elapsed_ms}ms)"
    )

    return RuntimeProbeChainFinding(
        finding_id=f"HRP_C{chain_idx}",
        chain_steps=chain_steps_human,
        attack_class=chain.attack_class,
        severity=severity_for_attack_class(chain.attack_class),
        cwe=cwe_for_attack_class(chain.attack_class),
        description=(
            chain.exploit_proof_if_observed
            or f"{chain.attack_class} via {len(chain.steps)}-step chain in "
            f"{chain.steps[-1].function_name}"
        ),
        runtime_evidence=runtime_evidence,
        chain_inputs_json=chain.steps[0].args_json if chain.steps else "[]",
        confidence=confidence,
        oracle_type=oracle_type,
    )


# ── Phase 3 Stage 2: stateful sequence harness (v1.6) ────────────────────
#
# Generalization of the chain harness to support state-poisoning attacks.
# Chains are pure "call(args) → call(args)" sequences. Real exploits often
# need stateful setup BETWEEN calls:
#
#   1. Write a malicious config to /tmp/cfg.json (fs_write op)
#   2. Set an env var that switches the target into vulnerable mode (env_set op)
#   3. Call a function that reads the config + acts on it (call op)
#   4. Verify the canary side-effect (fs_read op)
#
# Each op runs in the SAME sandbox machine so filesystem + env state
# propagates between them. Reuses chain harness's
# placeholder-substitution machinery for ``<<_stepN_result>>`` between
# call ops; non-call ops can also reference prior call returns via the
# same placeholders (e.g., fs_write's ``content`` field).
#
# Supported op types (see also dast.adversarial_loop.SEQ_OP_*):
#   * ``call``      — invoke a function: function_name + args_json + kwargs_json
#   * ``fs_write``  — write a file: path + content
#   * ``env_set``   — set env var: name + value (logged, not echoed)
#   * ``fs_read``   — read a file: path. Records first 600 chars as preview
#
# Backward compat: a sequence with all ops = "call" is equivalent to a
# RuntimeProbeChain. Same interpretation rules apply (Rule 1 evidence-
# signature on final call's value_preview, Rule 2 canary on /tmp diff,
# NoneType-intermediate guard for FP defense).


def _build_python_stateful_sequence_harness(
    *,
    module_name: str,
    ops: list[dict[str, Any]],
    module_file_path: str = "",
) -> str:
    """Generate the Python harness that runs ONE stateful sequence.

    Layout (mirrors the chain harness):
    1. Snapshot baseline /tmp listing.
    2. Defensive sandboxing (socket timeout + no_proxy).
    3. Path-prep preamble — scan source AND op args for /-prefixed
       string literals; mkdir-p the dir prefixes so traversal probes
       can resolve through them.
    4. Module import — wrapped in try/except. On ImportError, emit a
       structured failure result and exit cleanly.
    5. Op execution loop:
       a. fs_write — write content to path (under /tmp or /workspace).
       b. env_set — os.environ[name] = value.
       c. call — resolve function, substitute placeholders, invoke.
          Capture return for use by later placeholder references.
       d. fs_read — read path, capture first 600 chars as preview.
       Each op records ``{op_index, op_type, ok, ...op-specific fields}``.
       Failed call ops at non-final positions short-circuit the
       sequence (no further ops run).
    6. Emit STATEFUL_SEQ_RESULT_JSON marker + write to
       /workspace/argus_probe_result.json (file-based transport).

    Returns the harness source as a Python string ready to be base64-
    encoded into a SandboxPlan command.
    """
    ops_payload = json.dumps(ops)
    ops_repr = repr(ops_payload)
    deny_repr = repr(_PROBE_PREP_DENY_PREFIXES)
    return (
        # ── Imports + setup ──────────────────────────────────────────────
        "import sys, os, json, traceback, re, socket\n"
        "sys.path.insert(0, '/workspace')\n"
        # Defensive: socket timeout + no_proxy. Stops accidental network
        # hangs in target functions; the audit hook still records the
        # attempt for observation.
        "try:\n"
        "    socket.setdefaulttimeout(3.0)\n"
        "except Exception:\n"
        "    pass\n"
        "for _k in ('no_proxy', 'NO_PROXY'):\n"
        "    os.environ[_k] = '*'\n"
        "baseline_tmp = set()\n"
        "try:\n"
        "    baseline_tmp = set(os.listdir('/tmp'))\n"
        "except Exception:\n"
        "    pass\n"
        # Decode the op sequence.
        f"_ops = json.loads({ops_repr})\n"
        # Path-prep preamble (mirrors chain harness).
        f"_DENY = {deny_repr}\n"
        # When ``module_file_path`` is supplied (package members staged
        # with their package layout, e.g. ``/workspace/jsonpickle/
        # unpickler.py``), use the explicit on-disk path. Otherwise fall
        # back to the flat-module convention (``/workspace/<basename>.py``).
        f"_module_path = {(module_file_path or f'/workspace/{module_name}.py')!r}\n"
        "_paths_to_prep = set()\n"
        "try:\n"
        "    _src = open(_module_path).read()\n"
        "    _paths_to_prep = set(re.findall("
        "r'''[\"\\']((?:/[A-Za-z_][\\w./-]*))[\"\\']''', _src))\n"
        "except Exception:\n"
        "    pass\n"
        "_abs_dir_prefixes = set()\n"
        "for _p in _paths_to_prep:\n"
        "    if any(_p == d or _p.startswith(d + '/') for d in _DENY):\n"
        "        continue\n"
        "    try:\n"
        "        _bn = os.path.basename(_p.rstrip('/'))\n"
        "        _looks_like_file = '.' in _bn and not _p.endswith('/')\n"
        "        _to_mk = os.path.dirname(_p) if _looks_like_file else _p.rstrip('/')\n"
        "        if _to_mk and _to_mk != '/':\n"
        "            os.makedirs(_to_mk, exist_ok=True)\n"
        "            _abs_dir_prefixes.add(_to_mk)\n"
        "    except (OSError, PermissionError):\n"
        "        pass\n"
        # Module import — wrapped so ImportError surfaces as a
        # structured result instead of a silent crash.
        "try:\n"
        f"    import {module_name} as _target\n"
        "except BaseException as _imp_e:\n"
        "    _payload = {\n"
        "        'per_op_results': [{\n"
        "            'op_index': 0,\n"
        "            'op_type': 'module_import',\n"
        "            'ok': False,\n"
        "            'exception_type': type(_imp_e).__name__,\n"
        "            'exception_msg': str(_imp_e)[:300],\n"
        "        }],\n"
        "        'short_circuited': True,\n"
        "        'side_effects': {'tmp_files_added': []},\n"
        "    }\n"
        "    print('STATEFUL_SEQ_RESULT_JSON:' + json.dumps(_payload))\n"
        "    try:\n"
        "        with open('/workspace/argus_probe_result.json', 'w') as _f:\n"
        "            _f.write(json.dumps(_payload))\n"
        "    except Exception:\n"
        "        pass\n"
        "    print('SIDE_EFFECTS:' + json.dumps({'tmp_files_added': []}))\n"
        "    sys.exit(0)\n"
        # Op execution loop.
        "_per_op = []\n"
        # captured return values from call ops, 1-indexed via _stepN placeholders
        "_call_returns = []\n"
        "_short_circuited = False\n"
        "_PLACEHOLDER_RE = re.compile(r'^<<_step(\\d+)_result>>$')\n"
        "def _substitute(v, returns):\n"
        "    if isinstance(v, str):\n"
        "        m = _PLACEHOLDER_RE.match(v)\n"
        "        if m:\n"
        "            idx = int(m.group(1)) - 1\n"
        "            if 0 <= idx < len(returns):\n"
        "                return returns[idx]\n"
        "        return v\n"
        "    if isinstance(v, list):\n"
        "        return [_substitute(x, returns) for x in v]\n"
        "    if isinstance(v, dict):\n"
        "        return {k: _substitute(x, returns) for k, x in v.items()}\n"
        "    return v\n"
        "for _op_idx, _op_spec in enumerate(_ops):\n"
        "    _op_type = _op_spec.get('op', 'call')  # backward compat: missing 'op' = call\n"
        "    _result = {'op_index': _op_idx, 'op_type': _op_type, 'ok': False}\n"
        # fs_write
        "    if _op_type == 'fs_write':\n"
        "        try:\n"
        "            _path = str(_op_spec.get('path', ''))\n"
        "            _content = str(_substitute(_op_spec.get('content', ''), _call_returns))\n"
        "            with open(_path, 'w') as _f:\n"
        "                _bytes = _f.write(_content)\n"
        "            _result['ok'] = True\n"
        "            _result['path'] = _path\n"
        "            _result['bytes_written'] = _bytes\n"
        "        except BaseException as e:\n"
        "            _result['exception_type'] = type(e).__name__\n"
        "            _result['exception_msg'] = str(e)[:300]\n"
        # env_set
        "    elif _op_type == 'env_set':\n"
        "        try:\n"
        "            _name = str(_op_spec.get('name', ''))\n"
        "            _value = str(_substitute(_op_spec.get('value', ''), _call_returns))\n"
        "            if _name:\n"
        "                os.environ[_name] = _value\n"
        "                _result['ok'] = True\n"
        "                _result['name'] = _name\n"
        "                # NB: deliberately NOT echoing _value — may carry secrets\n"
        "        except BaseException as e:\n"
        "            _result['exception_type'] = type(e).__name__\n"
        "            _result['exception_msg'] = str(e)[:300]\n"
        # fs_read
        "    elif _op_type == 'fs_read':\n"
        "        try:\n"
        "            _path = str(_op_spec.get('path', ''))\n"
        "            with open(_path) as _f:\n"
        "                _data = _f.read(2000)\n"
        "            _result['ok'] = True\n"
        "            _result['path'] = _path\n"
        "            _result['content_preview'] = _data[:600]\n"
        "            _result['bytes_read'] = len(_data)\n"
        "        except BaseException as e:\n"
        "            _result['exception_type'] = type(e).__name__\n"
        "            _result['exception_msg'] = str(e)[:300]\n"
        # call (default / explicit)
        "    elif _op_type == 'call':\n"
        "        _fn_name = _op_spec.get('function_name', '')\n"
        "        _result['function_name'] = _fn_name\n"
        "        try:\n"
        "            _fn = _target\n"
        "            for _part in _fn_name.split('.'):\n"
        "                _fn = getattr(_fn, _part)\n"
        "        except AttributeError as e:\n"
        "            _result['exception_type'] = 'AttributeError'\n"
        "            _result['exception_msg'] = str(e)[:300]\n"
        "            _per_op.append(_result)\n"
        "            _short_circuited = (_op_idx < len(_ops) - 1)\n"
        "            if _short_circuited:\n"
        "                break\n"
        "            else:\n"
        "                continue\n"
        "        try:\n"
        "            _raw_args = json.loads(_op_spec.get('args_json', '[]'))\n"
        "            _raw_kwargs = json.loads(_op_spec.get('kwargs_json', '{}'))\n"
        "        except (json.JSONDecodeError, ValueError) as e:\n"
        "            _result['exception_type'] = 'JSONDecodeError'\n"
        "            _result['exception_msg'] = str(e)[:300]\n"
        "            _per_op.append(_result)\n"
        "            _short_circuited = (_op_idx < len(_ops) - 1)\n"
        "            if _short_circuited:\n"
        "                break\n"
        "            else:\n"
        "                continue\n"
        "        _args = _substitute(_raw_args, _call_returns)\n"
        "        _kwargs = _substitute(_raw_kwargs, _call_returns)\n"
        "        try:\n"
        "            _ret = _fn(*_args, **_kwargs)\n"
        "            _call_returns.append(_ret)\n"
        "            _result['ok'] = True\n"
        "            _result['type'] = type(_ret).__name__\n"
        "            _result['value_preview'] = repr(_ret)[:600]\n"
        "        except BaseException as e:\n"
        "            _result['exception_type'] = type(e).__name__\n"
        "            _result['exception_msg'] = str(e)[:300]\n"
        "            _result['tb_tail'] = traceback.format_exc()[-1500:]\n"
        "            _short_circuited = (_op_idx < len(_ops) - 1)\n"
        "            _per_op.append(_result)\n"
        "            if _short_circuited:\n"
        "                break\n"
        "            else:\n"
        "                continue\n"
        # unknown op type
        "    else:\n"
        "        _result['exception_type'] = 'UnknownOpType'\n"
        "        _result['exception_msg'] = f'unsupported op type: {_op_type}'\n"
        "    _per_op.append(_result)\n"
        # Side-effects snapshot.
        "added_tmp = []\n"
        "try:\n"
        "    added_tmp = sorted(set(os.listdir('/tmp')) - baseline_tmp)\n"
        "except Exception:\n"
        "    pass\n"
        # Emit unified payload via both channels (stdout + file).
        "_payload = {\n"
        "    'per_op_results': _per_op,\n"
        "    'short_circuited': _short_circuited,\n"
        "    'side_effects': {'tmp_files_added': added_tmp[:20]},\n"
        "}\n"
        "_payload_json = json.dumps(_payload)\n"
        "try:\n"
        "    with open('/workspace/argus_probe_result.json', 'w') as _f:\n"
        "        _f.write(_payload_json)\n"
        "except Exception:\n"
        "    pass\n"
        "print('STATEFUL_SEQ_RESULT_JSON:' + _payload_json)\n"
        "print('SIDE_EFFECTS:' + json.dumps({'tmp_files_added': added_tmp[:20]}))\n"
    )


def _build_javascript_stateful_sequence_harness(
    *,
    module_path: str,
    ops: list[dict[str, Any]],
) -> str:
    """Generate the Node.js harness that runs ONE stateful sequence
    against a JS/TS target.

    Direct port of :func:`_build_python_stateful_sequence_harness` —
    same op shapes (fs_write / env_set / call / fs_read), same
    ``<<_stepN_result>>`` placeholder substitution rules, same
    ``STATEFUL_SEQ_RESULT_JSON`` + ``SIDE_EFFECTS`` markers, same
    short-circuit semantics (failed call op at non-final position
    halts the sequence). The interpreter (``interpret_stateful_sequence_trace``)
    is language-agnostic and reads either harness's output identically.

    Layout:
    1. Catastrophic-failure safety net — process-level handlers emit
       STATEFUL_SEQ_RESULT_JSON marker if anything explodes before the
       normal-path emission.
    2. Snapshot /tmp baseline.
    3. Path-prep preamble — scan source AND op args for /-prefixed
       string literals; ``fs.mkdirSync({recursive: true})`` each.
    4. Dynamic ``await import(pathToFileURL(module_path).href)`` —
       wrapped in try/catch. On ImportError, emit structured failure.
    5. Op execution loop — sequential, captures call returns into
       ``_callReturns`` for placeholder substitution in later ops.
    6. Emit STATEFUL_SEQ_RESULT_JSON + write to
       /workspace/argus_probe_result.json (file-based transport).

    Wrapped in async IIFE for top-level await (Node 18+, tsx all
    versions). Harness file extension is .cjs so it runs in CJS mode
    regardless of package.json; tsx hooks dynamic import() of the
    user's .ts/.js target transparently.
    """
    ops_lit = json.dumps(json.dumps(ops))  # JS-string-literal-safe
    module_path_lit = json.dumps(module_path)
    deny_lit = json.dumps(list(_PROBE_PREP_DENY_PREFIXES))
    return (
        # ── Catastrophic-failure safety net (same pattern as JS probe harness) ──
        "let _markerEmitted = false;\n"
        "function _emitFatal(label, err) {\n"
        "  if (_markerEmitted) return;\n"
        "  _markerEmitted = true;\n"
        "  const msg = err && (err.message || err.toString) "
        "? String(err.message || err).slice(0, 300) : String(err).slice(0, 300);\n"
        "  const stack = err && err.stack ? String(err.stack).slice(-1500) : '';\n"
        "  const ctor = err && err.constructor && err.constructor.name "
        "? err.constructor.name : 'Error';\n"
        "  try {\n"
        "    const _payload = {\n"
        "      per_op_results: [{ op_index: 0, op_type: 'harness_init',\n"
        "        ok: false, exception_type: ctor,\n"
        "        exception_msg: '[' + label + '] ' + msg, tb_tail: stack }],\n"
        "      short_circuited: true,\n"
        "      side_effects: { tmp_files_added: [] },\n"
        "    };\n"
        "    console.log('STATEFUL_SEQ_RESULT_JSON:' + JSON.stringify(_payload));\n"
        "    try {\n"
        "      const fs = require('fs');\n"
        "      fs.writeFileSync('/workspace/argus_probe_result.json',\n"
        "        JSON.stringify(_payload));\n"
        "    } catch (e) {}\n"
        "    console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: [] }));\n"
        "  } catch (e) {}\n"
        "}\n"
        "process.on('uncaughtException', (e) => _emitFatal('uncaughtException', e));\n"
        "process.on('unhandledRejection', (e) => _emitFatal('unhandledRejection', e));\n"
        # Inner harness timeout — same 45s budget as single-function probe.
        "setTimeout(() => _emitFatal('innerHarnessTimeout', "
        "new Error('stateful sequence exceeded 45s inner budget')), 45000).unref();\n"
        "(async () => {\n"
        "  try {\n"
        "  const fs = require('fs');\n"
        "  const path = require('path');\n"
        "  const { pathToFileURL } = require('url');\n"
        # ── Baseline /tmp snapshot ────────────────────────────────────
        "  let baselineTmp = new Set();\n"
        "  try { baselineTmp = new Set(fs.readdirSync('/tmp')); } catch (e) {}\n"
        # ── Decode op sequence ────────────────────────────────────────
        "  const _ops = JSON.parse(" + ops_lit + ");\n"
        # ── Path-prep preamble ────────────────────────────────────────
        "  const DENY = " + deny_lit + ";\n"
        "  const absDirPrefixes = new Set();\n"
        "  const sourcePath = " + module_path_lit + ";\n"
        "  try {\n"
        "    const src = fs.readFileSync(sourcePath, 'utf8');\n"
        # Same regex pattern as JS probe harness — pull /-prefixed
        # string literals from source.
        "    const re = /[\"'](\\/[A-Za-z_][\\w./-]*)[\"']/g;\n"
        "    let m;\n"
        "    while ((m = re.exec(src)) !== null) {\n"
        "      const p = m[1];\n"
        "      if (DENY.some(d => p === d || p.startsWith(d + '/'))) continue;\n"
        "      try {\n"
        "        const bn = path.basename(p.replace(/\\/+$/, ''));\n"
        "        const looksLikeFile = bn.includes('.') && !p.endsWith('/');\n"
        "        const toMk = looksLikeFile ? path.dirname(p) : p.replace(/\\/+$/, '');\n"
        "        if (toMk && toMk !== '/') {\n"
        "          fs.mkdirSync(toMk, { recursive: true });\n"
        "          absDirPrefixes.add(toMk);\n"
        "        }\n"
        "      } catch (e) {}\n"
        "    }\n"
        "  } catch (e) {}\n"
        # Also scan op args for path literals (covers paths the user
        # supplies in op args but doesn't reference in source).
        "  for (const op of _ops) {\n"
        "    for (const key of ['path', 'args_json', 'kwargs_json', 'content']) {\n"
        "      const v = op[key];\n"
        "      if (typeof v !== 'string') continue;\n"
        "      const re2 = /(\\/[A-Za-z_][\\w./-]*)/g;\n"
        "      let m2;\n"
        "      while ((m2 = re2.exec(v)) !== null) {\n"
        "        const p = m2[1];\n"
        "        if (DENY.some(d => p === d || p.startsWith(d + '/'))) continue;\n"
        "        try {\n"
        "          const bn = path.basename(p.replace(/\\/+$/, ''));\n"
        "          const looksLikeFile = bn.includes('.') && !p.endsWith('/');\n"
        "          const toMk = looksLikeFile ? path.dirname(p) : p.replace(/\\/+$/, '');\n"
        "          if (toMk && toMk !== '/') {\n"
        "            try { fs.mkdirSync(toMk, { recursive: true }); } catch (e2) {}\n"
        "          }\n"
        "        } catch (e) {}\n"
        "      }\n"
        "    }\n"
        "  }\n"
        # ── Module import ─────────────────────────────────────────────
        "  let _target;\n"
        "  let _importError = '';\n"
        "  try {\n"
        "    const url = pathToFileURL(sourcePath).href;\n"
        "    _target = await import(url);\n"
        "  } catch (e) {\n"
        "    _importError = (e && e.constructor ? e.constructor.name : 'Error')\n"
        "      + ': ' + String((e && e.message) || e).slice(0, 300);\n"
        "  }\n"
        "  if (_importError) {\n"
        "    const _payload = {\n"
        "      per_op_results: [{ op_index: 0, op_type: 'module_import',\n"
        "        ok: false, exception_type: 'ImportError', exception_msg: _importError }],\n"
        "      short_circuited: true,\n"
        "      side_effects: { tmp_files_added: [] },\n"
        "    };\n"
        "    _markerEmitted = true;\n"
        "    console.log('STATEFUL_SEQ_RESULT_JSON:' + JSON.stringify(_payload));\n"
        "    try {\n"
        "      fs.writeFileSync('/workspace/argus_probe_result.json',\n"
        "        JSON.stringify(_payload));\n"
        "    } catch (e) {}\n"
        "    console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: [] }));\n"
        "    return;\n"
        "  }\n"
        # ── Dotted-path resolver (reused from JS probe harness shape) ──
        "  function resolveFn(modObj, dotted) {\n"
        "    let cur = modObj;\n"
        "    if (cur && typeof cur === 'object' && cur.default != null) {\n"
        "      const head = dotted.split('.')[0];\n"
        "      if (typeof cur[head] === 'undefined' && cur.default[head] !== undefined) {\n"
        "        cur = cur.default;\n"
        "      }\n"
        "    }\n"
        "    for (const part of dotted.split('.')) {\n"
        "      if (cur == null) return undefined;\n"
        "      cur = cur[part];\n"
        "    }\n"
        "    return cur;\n"
        "  }\n"
        # ── Placeholder substitution ──────────────────────────────────
        "  const PLACEHOLDER_RE = /^<<_step(\\d+)_result>>$/;\n"
        "  function _substitute(v, returns) {\n"
        "    if (typeof v === 'string') {\n"
        "      const m = PLACEHOLDER_RE.exec(v);\n"
        "      if (m) {\n"
        "        const idx = parseInt(m[1], 10) - 1;\n"
        "        if (idx >= 0 && idx < returns.length) return returns[idx];\n"
        "      }\n"
        "      return v;\n"
        "    }\n"
        "    if (Array.isArray(v)) return v.map(x => _substitute(x, returns));\n"
        "    if (v && typeof v === 'object') {\n"
        "      const out = {};\n"
        "      for (const k of Object.keys(v)) out[k] = _substitute(v[k], returns);\n"
        "      return out;\n"
        "    }\n"
        "    return v;\n"
        "  }\n"
        # ── Op execution loop ─────────────────────────────────────────
        "  const _perOp = [];\n"
        "  const _callReturns = [];\n"
        "  let _shortCircuited = false;\n"
        "  for (let _opIdx = 0; _opIdx < _ops.length; _opIdx++) {\n"
        "    const _opSpec = _ops[_opIdx];\n"
        "    const _opType = _opSpec.op || 'call';  // backward compat\n"
        "    const _result = { op_index: _opIdx, op_type: _opType, ok: false };\n"
        # fs_write
        "    if (_opType === 'fs_write') {\n"
        "      try {\n"
        "        const _path = String(_opSpec.path || '');\n"
        "        const _content = String(_substitute(_opSpec.content || '', _callReturns));\n"
        "        fs.writeFileSync(_path, _content);\n"
        "        _result.ok = true;\n"
        "        _result.path = _path;\n"
        "        _result.bytes_written = Buffer.byteLength(_content, 'utf8');\n"
        "      } catch (e) {\n"
        "        _result.exception_type = e && e.constructor ? e.constructor.name : 'Error';\n"
        "        _result.exception_msg = String(e && e.message || e).slice(0, 300);\n"
        "      }\n"
        # env_set
        "    } else if (_opType === 'env_set') {\n"
        "      try {\n"
        "        const _name = String(_opSpec.name || '');\n"
        "        const _value = String(_substitute(_opSpec.value || '', _callReturns));\n"
        "        if (_name) {\n"
        "          process.env[_name] = _value;\n"
        "          _result.ok = true;\n"
        "          _result.name = _name;\n"
        # NB: deliberately NOT echoing _value — may carry secrets
        "        }\n"
        "      } catch (e) {\n"
        "        _result.exception_type = e && e.constructor ? e.constructor.name : 'Error';\n"
        "        _result.exception_msg = String(e && e.message || e).slice(0, 300);\n"
        "      }\n"
        # fs_read
        "    } else if (_opType === 'fs_read') {\n"
        "      try {\n"
        "        const _path = String(_opSpec.path || '');\n"
        "        const _data = fs.readFileSync(_path, 'utf8').slice(0, 2000);\n"
        "        _result.ok = true;\n"
        "        _result.path = _path;\n"
        "        _result.content_preview = _data.slice(0, 600);\n"
        "        _result.bytes_read = _data.length;\n"
        "      } catch (e) {\n"
        "        _result.exception_type = e && e.constructor ? e.constructor.name : 'Error';\n"
        "        _result.exception_msg = String(e && e.message || e).slice(0, 300);\n"
        "      }\n"
        # call
        "    } else if (_opType === 'call') {\n"
        "      const _fnName = _opSpec.function_name || '';\n"
        "      _result.function_name = _fnName;\n"
        "      const _fn = resolveFn(_target, _fnName);\n"
        "      if (typeof _fn !== 'function') {\n"
        "        _result.exception_type = 'AttributeError';\n"
        "        _result.exception_msg = 'function not found: ' + _fnName;\n"
        "        _perOp.push(_result);\n"
        "        _shortCircuited = (_opIdx < _ops.length - 1);\n"
        "        if (_shortCircuited) break;\n"
        "        else continue;\n"
        "      }\n"
        "      let _rawArgs, _rawKwargs;\n"
        "      try {\n"
        "        _rawArgs = JSON.parse(_opSpec.args_json || '[]');\n"
        "        _rawKwargs = JSON.parse(_opSpec.kwargs_json || '{}');\n"
        "      } catch (e) {\n"
        "        _result.exception_type = 'JSONDecodeError';\n"
        "        _result.exception_msg = String(e.message || e).slice(0, 300);\n"
        "        _perOp.push(_result);\n"
        "        _shortCircuited = (_opIdx < _ops.length - 1);\n"
        "        if (_shortCircuited) break;\n"
        "        else continue;\n"
        "      }\n"
        "      const _args = _substitute(_rawArgs, _callReturns);\n"
        "      const _kwargs = _substitute(_rawKwargs, _callReturns);\n"
        "      try {\n"
        # JS doesn't have true kwargs — pass as final-object arg if non-empty
        # (matches the JS single-function probe harness convention).
        "        const _callArgs = (_kwargs && typeof _kwargs === 'object' "
        "&& !Array.isArray(_kwargs) && Object.keys(_kwargs).length > 0)\n"
        "          ? [..._args, _kwargs]\n"
        "          : _args;\n"
        "        let _ret = _fn.apply(null, _callArgs);\n"
        "        if (_ret && typeof _ret.then === 'function') {\n"
        "          _ret = await _ret;\n"
        "        }\n"
        "        _callReturns.push(_ret);\n"
        "        _result.ok = true;\n"
        "        _result.type = typeof _ret;\n"
        "        let _preview;\n"
        "        try { _preview = JSON.stringify(_ret); } catch (e) { _preview = String(_ret); }\n"
        "        _result.value_preview = String(_preview || '').slice(0, 600);\n"
        "      } catch (e) {\n"
        "        _result.exception_type = e && e.constructor ? e.constructor.name : 'Error';\n"
        "        _result.exception_msg = String(e && e.message || e).slice(0, 300);\n"
        "        _result.tb_tail = e && e.stack ? String(e.stack).slice(-1500) : '';\n"
        "        _shortCircuited = (_opIdx < _ops.length - 1);\n"
        "        _perOp.push(_result);\n"
        "        if (_shortCircuited) break;\n"
        "        else continue;\n"
        "      }\n"
        # unknown op type
        "    } else {\n"
        "      _result.exception_type = 'UnknownOpType';\n"
        "      _result.exception_msg = 'unsupported op type: ' + _opType;\n"
        "    }\n"
        "    _perOp.push(_result);\n"
        "  }\n"
        # ── Side-effects snapshot + emit payload ──────────────────────
        "  let _addedTmp = [];\n"
        "  try {\n"
        "    _addedTmp = fs.readdirSync('/tmp').filter(f => !baselineTmp.has(f)).sort();\n"
        "  } catch (e) {}\n"
        "  const _payload = {\n"
        "    per_op_results: _perOp,\n"
        "    short_circuited: _shortCircuited,\n"
        "    side_effects: { tmp_files_added: _addedTmp.slice(0, 20) },\n"
        "  };\n"
        "  const _payloadJson = JSON.stringify(_payload);\n"
        "  try {\n"
        "    fs.writeFileSync('/workspace/argus_probe_result.json', _payloadJson);\n"
        "  } catch (e) {}\n"
        "  _markerEmitted = true;\n"
        "  console.log('STATEFUL_SEQ_RESULT_JSON:' + _payloadJson);\n"
        "  console.log('SIDE_EFFECTS:' + JSON.stringify({\n"
        "    tmp_files_added: _addedTmp.slice(0, 20),\n"
        "  }));\n"
        "  } catch (e) {\n"
        "    _emitFatal('iifeBody', e);\n"
        "  }\n"
        "})().catch(e => _emitFatal('iifeCatch', e));\n"
    )


def build_runtime_stateful_sequence_plan(
    *,
    file_name: str,
    file_bytes: bytes,
    ops: list[dict[str, Any]],
    hypothesis_id: str,
    image_hint: str = "lean",
    entry_rel_path: str = "",
) -> dict[str, Any] | None:
    """Build a Phase-A-shaped plan dict that runs a stateful sequence.

    Dispatches by language:
      * ``.py`` / ``.pth``        → Python harness (v1.6)
      * ``.js`` / ``.mjs`` / ``.cjs`` → JS harness (v11, 2026-05-17)
      * ``.ts`` / ``.tsx``        → JS harness via tsx (v11, 2026-05-17)

    Returns ``None`` for shell or other unsupported languages, and for
    empty ``ops`` lists. The caller passes the full ``hypothesis_id``
    (typically ``HRP_AL_<turn>_<idx>`` for the adversarial loop) so
    plan IDs stay unique across the scan.

    JS/TS harness reuses the same op shapes + markers as Python so the
    interpreter (``interpret_stateful_sequence_trace``) is language-
    agnostic. .ts targets ride the same tsx + package.json{type:module}
    + tsconfig.json{moduleResolution:bundler} runner-cmd pattern as
    single-function probes.
    """
    lang = detect_probe_language(file_name)
    if lang not in ("python", "javascript", "typescript"):
        return None
    if not ops:
        return None

    payload_b64 = base64.b64encode(file_bytes).decode("ascii")
    # Use the hypothesis ID's last 16 chars as the harness file suffix
    # so concurrent sequences don't collide on the same workspace path.
    safe_suffix = re.sub(r"[^A-Za-z0-9_]", "_", hypothesis_id)[-16:]

    # v12 multi-file: see build_runtime_probe_plan for the architecture.
    # Entry pre-staged at entry_target_path via the additional_files
    # tarball (extracted as root before privilege drop).
    file_base = Path(file_name).name
    entry_rel_path = (entry_rel_path or "").replace("\\", "/").strip()
    entry_target_path = (
        f"/workspace/{entry_rel_path}" if entry_rel_path else f"/workspace/{file_base}"
    )

    if lang == "python":
        module_name = _python_module_name_for_file(file_name, entry_rel_path)
        harness = _build_python_stateful_sequence_harness(
            module_name=module_name,
            ops=ops,
            module_file_path=entry_target_path,
        )
        harness_path = f"/workspace/_argus_seq_{safe_suffix}.py"
        write_cmd = (
            f'python3 -c "import base64,sys; '
            f"open({harness_path!r},'wb').write("
            f'base64.b64decode(sys.argv[1]))" '
            f"{base64.b64encode(harness.encode('utf-8')).decode('ascii')}"
        )
        run_cmd = f"python3 {harness_path}"
    else:
        # JavaScript or TypeScript. Same harness body — only the runner
        # cmd differs (TS gets tsx + ESM package.json + bundler tsconfig).
        # v12: module_path uses entry_target_path. Entry is pre-staged
        # at that path via the additional_files tarball — no runtime
        # mkdir + mv needed.
        module_path = entry_target_path
        harness = _build_javascript_stateful_sequence_harness(
            module_path=module_path, ops=ops
        )
        harness_path = f"/workspace/_argus_seq_{safe_suffix}.cjs"
        write_cmd = (
            f'python3 -c "import base64,sys; '
            f"open({harness_path!r},'wb').write("
            f'base64.b64decode(sys.argv[1]))" '
            f"{base64.b64encode(harness.encode('utf-8')).decode('ascii')}"
        )
        if lang == "typescript":
            # Same pattern as runtime_probe.py + behavioral_probe.py TS
            # branches: package.json type=module + tsconfig.json bundler.
            run_cmd = (
                f"cd /workspace && "
                f"echo '{{\"type\":\"module\"}}' > package.json && "
                f"echo '{{\"compilerOptions\":"
                f"{{\"moduleResolution\":\"bundler\","
                f"\"allowImportingTsExtensions\":true,"
                f"\"target\":\"esnext\",\"module\":\"esnext\","
                f"\"isolatedModules\":true,\"skipLibCheck\":true}}}}'"
                f" > tsconfig.json && "
                f"tsx {harness_path}"
            )
        else:  # javascript
            run_cmd = f"cd /workspace && node {harness_path}"

    op_types = [str(o.get("op", "call")) for o in ops]
    op_summary = " | ".join(op_types)

    return {
        "hypothesis_id": hypothesis_id,
        "plan_status": "executable",
        "commands": [write_cmd, run_cmd],
        "oracle": "execution_output_with_side_effect_observation",
        "payload": payload_b64,
        "payload_encoding": "base64",
        "timeout_sec": DEFAULT_PROBE_TIMEOUT_SEC,
        "image_hint": image_hint,
        "rationale": (
            f"Stateful sequence ({lang}, {len(ops)} ops: {op_summary[:120]}). "
            f"Mixed fs_write / env_set / call / fs_read ops in one sandbox "
            f"machine with state propagation."
        ),
    }


@dataclass
class RuntimeStatefulSequenceTrace:
    """Parsed result of running a stateful sequence in the sandbox.

    Mirrors :class:`RuntimeProbeChainTrace` but with the richer
    ``per_op_results`` shape (each entry has ``op_type`` and op-
    specific fields). The interpreter projects this onto the chain-
    interpretation pattern by treating call ops as the "steps" that
    Rule 1/Rule 2 apply to.
    """

    hypothesis_id: str
    per_op_results: list[dict[str, Any]] = field(default_factory=list)
    short_circuited: bool = False
    side_effects: dict[str, Any] = field(default_factory=dict)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    elapsed_ms: int = 0
    ops_summary: list[str] = field(default_factory=list)


def parse_stateful_sequence_trace(
    *,
    hypothesis_id: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    elapsed_ms: int,
    probe_result_json: str = "",
) -> RuntimeStatefulSequenceTrace:
    """Extract a stateful-sequence trace from sandbox output.

    Prefers the file-based transport (``probe_result_json``) over
    stdout marker scanning — same rationale as chain trace parser.
    Falls back to stdout ``STATEFUL_SEQ_RESULT_JSON:`` line on older
    images without the entrypoint drain step.
    """
    trace = RuntimeStatefulSequenceTrace(
        hypothesis_id=hypothesis_id,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        elapsed_ms=elapsed_ms,
    )

    def _apply(parsed: dict[str, Any]) -> None:
        per_op = parsed.get("per_op_results", [])
        if isinstance(per_op, list):
            trace.per_op_results = [x for x in per_op if isinstance(x, dict)]
        trace.short_circuited = bool(parsed.get("short_circuited"))
        se = parsed.get("side_effects") or {}
        if isinstance(se, dict):
            trace.side_effects = se

    # File-based channel preferred — bypasses Fly truncation.
    if probe_result_json:
        try:
            parsed = json.loads(probe_result_json)
            if isinstance(parsed, dict):
                _apply(parsed)
                _populate_stateful_ops_summary(trace)
                return trace
        except (json.JSONDecodeError, ValueError):
            pass

    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("STATEFUL_SEQ_RESULT_JSON:"):
            continue
        payload = line[len("STATEFUL_SEQ_RESULT_JSON:") :].strip()
        try:
            parsed = json.loads(payload)
            if isinstance(parsed, dict):
                _apply(parsed)
                break
        except (json.JSONDecodeError, ValueError):
            continue

    _populate_stateful_ops_summary(trace)
    return trace


def _populate_stateful_ops_summary(trace: RuntimeStatefulSequenceTrace) -> None:
    """Build a human-readable per-op summary for the journal rationale."""
    summary: list[str] = []
    for r in trace.per_op_results:
        idx = r.get("op_index", "?")
        op_type = r.get("op_type", "?")
        if r.get("ok"):
            if op_type == "call":
                summary.append(
                    f"op{idx}:call {r.get('function_name', '?')} -> ok type={r.get('type', '?')}"
                )
            elif op_type == "fs_write":
                summary.append(
                    f"op{idx}:fs_write {r.get('path', '?')} ({r.get('bytes_written', 0)}B)"
                )
            elif op_type == "env_set":
                summary.append(f"op{idx}:env_set {r.get('name', '?')}")
            elif op_type == "fs_read":
                summary.append(f"op{idx}:fs_read {r.get('path', '?')} ({r.get('bytes_read', 0)}B)")
            else:
                summary.append(f"op{idx}:{op_type} ok")
        else:
            exc = r.get("exception_type", "?")
            msg = str(r.get("exception_msg", ""))[:80]
            summary.append(f"op{idx}:{op_type} -> {exc}: {msg}")
    trace.ops_summary = summary


@dataclass
class RuntimeStatefulSequenceFinding:
    """Finding emitted by a confirmed stateful sequence. Same shape as
    :class:`RuntimeProbeChainFinding` but namespaced to stateful
    sequences. Flows into the journal + scan output as a
    CONFIRMED hypothesis with sandbox-grounded runtime evidence."""

    finding_id: str
    """Hypothesis ID passed in by the caller (e.g.,
    ``HRP_AL_<turn>_<idx>`` for adversarial-loop sequences)."""

    op_summaries: list[str]
    """Per-op human-readable summary lines for the report."""

    attack_class: str
    severity: str
    cwe: str
    description: str
    runtime_evidence: str
    initial_op_json: str
    """The first op's JSON representation — the attacker-controlled
    entry point that flows through the sequence."""

    confidence: float = 1.0
    oracle_type: str = "canary"


def interpret_stateful_sequence_trace(
    trace: RuntimeStatefulSequenceTrace,
    *,
    attack_class: str,
    expected_observable: str,
    exploit_proof_if_observed: str,
    hypothesis_id: str,
) -> RuntimeStatefulSequenceFinding | None:
    """Decide whether a stateful sequence trace constitutes a runtime-
    confirmed exploit. Same Rule 1 / Rule 2 / NoneType-intermediate
    guard as :func:`interpret_probe_chain_trace`, projected onto the
    op-list shape:

    * Rule 1 (call op evidence): applies to the FINAL CALL op's
      ``value_preview``. Non-call ops at the end are ignored for
      Rule 1 purposes. If any INTERMEDIATE call op returned
      ``NoneType``, Rule 1 is suppressed (FP defense — same as chain
      interpretation).
    * Rule 2 (canary): unchanged — any ``argus_probe_*`` /  ``pwned``
      file appearing in /tmp post-sequence is causal evidence.

    Returns ``None`` when no rule fires. Otherwise returns a
    :class:`RuntimeStatefulSequenceFinding` ready to be journaled +
    surfaced.
    """
    if not trace.per_op_results:
        return None

    call_ops = [r for r in trace.per_op_results if r.get("op_type") == "call"]
    final_call = call_ops[-1] if call_ops else None
    intermediate_calls = call_ops[:-1] if call_ops else []

    # NoneType intermediate guard.
    intermediate_none = next(
        (r for r in intermediate_calls if isinstance(r, dict) and r.get("type") == "NoneType"),
        None,
    )

    rule1_match = False
    rule1_rationale = ""
    rule1_oracle_type: EvidenceOracleType = ""

    # Rule 1 only fires when:
    #   - No intermediate call returned NoneType (fallback signal)
    #   - There IS a final call op
    #   - The sequence wasn't short-circuited before the final call
    #   - The final call returned ok=True
    if (
        intermediate_none is None
        and final_call is not None
        and not trace.short_circuited
        and bool(final_call.get("ok"))
    ):
        value_preview = str(final_call.get("value_preview", "") or "")
        stderr_preview = str(final_call.get("stderr_preview", "") or "")
        # Concatenate all call-op args for the causal-signature check.
        # Causal signatures (localhost, 127.0.0.1) only fire when the
        # signature is in the output but NOT in any of the inputs that
        # produced it.
        seq_args_json = " ".join(
            str(r.get("args_json", "") or "")
            for r in call_ops
            if isinstance(r, dict)
        )
        rule1_match, rule1_rationale, rule1_oracle_type = _evidence_signature_match(
            attack_class=attack_class,
            value_preview=value_preview,
            stderr_preview=stderr_preview,
            expected_observable=expected_observable,
            args_json=seq_args_json,
        )

    # Rule 2: canary side-effect. Fires anywhere in the sequence —
    # could be from a call op invoking a sink, an fs_write op writing
    # to /tmp directly, etc. By construction, the canary file appearing
    # in /tmp is causal evidence of execution.
    side_effects = trace.side_effects or {}
    _raw_tmp = side_effects.get("tmp_files_added")
    tmp_added: list[str] = (
        [f for f in _raw_tmp if isinstance(f, str)] if isinstance(_raw_tmp, list) else []
    )
    canary_hit = any(
        isinstance(f, str) and ("argus_probe" in f.lower() or "pwned" in f.lower())
        for f in tmp_added
    )

    evidence_parts: list[str] = []
    if rule1_match and final_call is not None:
        final_preview = str(final_call.get("value_preview", "") or "")[:200]
        evidence_parts.append(
            f"Sequence reached final call op ({final_call.get('function_name', '?')}) "
            f"which returned without raising AND evidence matches: "
            f"{rule1_rationale}. Final value preview: {final_preview}"
        )
    if canary_hit:
        evidence_parts.append(
            f"Sandbox observed canary file(s) created in /tmp during sequence "
            f"execution: {tmp_added[:5]}"
        )

    if not evidence_parts:
        return None

    # Confidence calibration (same as chain interpretation).
    if canary_hit:
        confidence = CHAIN_CONFIDENCE_CANARY
        oracle_type = "canary"
    elif rule1_oracle_type == "class_signature":
        confidence = CHAIN_CONFIDENCE_CLASS_SIGNATURE
        oracle_type = "class_signature"
    elif rule1_oracle_type == "observable_keyword":
        confidence = CHAIN_CONFIDENCE_OBSERVABLE_KEYWORD
        oracle_type = "observable_keyword"
    else:
        confidence = CHAIN_CONFIDENCE_OBSERVABLE_KEYWORD
        oracle_type = ""

    ops_summary_str = " | ".join(trace.ops_summary) if trace.ops_summary else "(no ops)"

    # First op's JSON repr for proof-of-concept.
    initial_op_json = json.dumps(trace.per_op_results[0]) if trace.per_op_results else "{}"

    runtime_evidence = (
        f"Stateful sequence (oracle={oracle_type}, confidence={confidence}): "
        + "; ".join(evidence_parts)
        + f" | Per-op: {ops_summary_str}"
        + f" (exit_code={trace.exit_code}, elapsed={trace.elapsed_ms}ms)"
    )

    description = (
        exploit_proof_if_observed
        or f"{attack_class} via {len(trace.per_op_results)}-op stateful sequence"
    )

    return RuntimeStatefulSequenceFinding(
        finding_id=hypothesis_id,
        op_summaries=list(trace.ops_summary),
        attack_class=attack_class,
        severity=severity_for_attack_class(attack_class),
        cwe=cwe_for_attack_class(attack_class),
        description=description,
        runtime_evidence=runtime_evidence,
        initial_op_json=initial_op_json,
        confidence=confidence,
        oracle_type=oracle_type,
    )


__all__ = [
    "DEFAULT_PROBE_TIMEOUT_SEC",
    "MAX_CANDIDATES",
    "MAX_CHAINS_PER_FILE",
    "MAX_CHAIN_STEPS",
    "MAX_INPUTS_PER_CANDIDATE",
    "MAX_PROBE_RUNS_PER_FILE",
    "MAX_REFINEMENT_ATTEMPTS",
    "RuntimeProbeCandidate",
    "RuntimeProbeChain",
    "RuntimeProbeChainFinding",
    "RuntimeProbeChainStep",
    "RuntimeProbeChainTrace",
    "RuntimeProbeFinding",
    "RuntimeProbeInput",
    "RuntimeProbeObservation",
    "RuntimeProbeTrace",
    "RuntimeStatefulSequenceFinding",
    "RuntimeStatefulSequenceTrace",
    "build_runtime_probe_chain_plan",
    "build_runtime_probe_plan",
    "build_runtime_stateful_sequence_plan",
    "cwe_for_attack_class",
    "detect_probe_language",
    "interpret_probe_chain_trace",
    "interpret_probe_observation",
    "interpret_probe_trace",
    "interpret_stateful_sequence_trace",
    "normalize_args_json",
    "normalize_kwargs_json",
    "parse_probe_chain_trace",
    "parse_probe_trace",
    "parse_stateful_sequence_trace",
    "severity_for_attack_class",
]
