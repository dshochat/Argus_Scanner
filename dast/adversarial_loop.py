"""Phase 3 Stage 2 — Adversarial reasoning loop (v1.6).

This is the cutting-edge piece. Stage 1's behavioral probe gave us
a structured profile of what the code actually does at runtime
(callables, dangerous-builtin reach, file/network attempts,
dataflow hints). Stage 2 puts a reasoning model in an adversarial
loop with the sandbox:

  Turn 0: model reads source + behavioral profile → proposes 1-3
          attack hypotheses targeting OBSERVED behavior.
  Sandbox tests each hypothesis in parallel.
  Turn N: model sees previous hypotheses + their traces → refines,
          drops dead ends, proposes new hypotheses.
  Loop until termination (no_new_hypotheses, budget, wall-clock).

Distinct from prior phases:
* Phase A validates STATIC hypotheses from L1. Stage 2 generates
  hypotheses from RUNTIME behavior — model can disagree with L1.
* Phase B+ single-function probing picks targets from STATIC source.
  Stage 2 picks targets from OBSERVED behavior (e.g., "the audit
  hook caught subprocess.Popen in check_node_version — let me test
  whether I can inject into it").
* Phase 2 chain probing nominates fixed chains from static reading.
  Stage 2's ``stateful_sequence`` kind generalizes chains: arbitrary
  ordered ops (fs_write, env_set, call, fs_read) with state buildup
  between them.

Three hypothesis kinds:

* ``probe`` — exploratory query. Model invokes a function with some
  args, just to see what happens. Not interpreted as attack. Lets
  the model investigate before committing to an attack hypothesis.
* ``single_function`` — single attack: ``fn(*args, **kwargs)`` with
  the existing single-function probe harness. Confidence-scored
  via canary/class-signature/keyword oracles.
* ``stateful_sequence`` — multi-op sequence: file writes, env
  mutations, function calls in order. Generalization of chains —
  state-poisoning attacks (write malicious config → trigger
  vulnerable loader) are expressible. Runs in ONE sandbox machine
  so state propagates.

Language-polymorphic schema: every hypothesis carries
``language: "python" | "javascript" | "shell"`` so the same loop
machinery handles future JS/shell expansion in v1.7 without rework.
JS adds a JS plan builder + harness; the loop logic stays the same.

L1 short-circuit (cost optimization at scale): when L1 already has
HIGH confidence (>= 0.95) AND the behavioral profile confirms the
suspect pattern AND no contradictory signal, skip the adversarial
loop entirely. Emit findings from L1+Stage 1 directly. For big-team
CI runs scanning many files, this saves 60-80% of Stage 2 cost.

Result caching by ``(file_hash, behavioral_profile_hash, l1_verdict)``
so re-scans on unchanged files don't re-run the loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ── Tunables ──────────────────────────────────────────────────────────────

#: Maximum loop turns before forced termination. One turn = one model
#: inference + parallel sandbox tests of all hypotheses emitted that
#: turn. 5 is the empirical sweet spot — enough for the model to refine
#: 2-3 times beyond the initial proposal, not so many that cost blows
#: up. Configurable per-scan via :class:`scanner.engine.ScanConfig`.
MAX_TURNS: int = 5

#: Maximum hypotheses per turn. Caps parallelism + sandbox cost per
#: turn. 3 lets the model propose alternatives + complements; 1 forces
#: tight focus but loses parallel-test efficiency. 3 is the default;
#: turns where the model proposes more are truncated.
MAX_HYPOTHESES_PER_TURN: int = 3

#: Maximum exploratory ``probe``-kind hypotheses across the entire
#: loop. Separate budget from attack hypotheses so the model can
#: investigate before committing without burning the attack budget.
#: Counted globally, not per-turn — the model can spend all 5 probes
#: in turn 0 if it wants to map the surface first, then design attacks.
MAX_EXPLORE_CALLS: int = 5

#: Maximum cumulative cost in USD across the loop (inference +
#: sandbox). Hard cap — when exceeded the loop terminates with
#: ``terminated_by="max_cost"`` regardless of how many turns have run.
#: Bounds per-file cost for big-team CI economics: ~$0.50/file × 100
#: HIGH-triaged files = $50/scan budget for Stage 2.
MAX_COST_USD: float = 0.50

#: Wall-clock timeout in seconds. Safety net against runaway loops
#: (model proposing infinite duplicates, sandbox hanging, etc.).
#: 5-minute budget is generous — most scans terminate via
#: ``no_new_hypotheses`` or budget cap well before this.
WALL_CLOCK_TIMEOUT_S: float = 300.0

#: L1 confidence threshold above which Stage 2 is short-circuited
#: (skipped) when the behavioral profile also confirms the pattern.
#: Tunable via ``--phase3-shortcircuit-confidence`` CLI flag. 0.95 is
#: conservative — only skip when L1 is very sure AND independent
#: runtime signal agrees. Lower thresholds save more cost but risk
#: missing the model loop's refinements on borderline cases.
L1_SHORTCIRCUIT_CONFIDENCE: float = 0.95

#: Minimum turn before ``no_new_hypotheses`` can early-terminate. The
#: model sometimes converges in turn 1 with weak confidence; forcing
#: at least one refinement turn surfaces deeper signal. Set to 0 to
#: allow turn-0 termination.
MIN_TURNS_BEFORE_EARLY_EXIT: int = 1


# ── Constants ─────────────────────────────────────────────────────────────


#: Hypothesis kinds (string-typed so the model emits them in JSON).
HYPOTHESIS_KIND_PROBE: str = "probe"
HYPOTHESIS_KIND_SINGLE_FUNCTION: str = "single_function"
HYPOTHESIS_KIND_STATEFUL_SEQUENCE: str = "stateful_sequence"

#: Languages supported by the adversarial loop. v1.6 ships Python;
#: v1.7 added JavaScript; v9 (2026-05-16) adds TypeScript (reuses JS
#: harness via ts-node ESM loader). Shell still future.
LANGUAGE_PYTHON: str = "python"
LANGUAGE_JAVASCRIPT: str = "javascript"  # v1.7
LANGUAGE_TYPESCRIPT: str = "typescript"  # v9
LANGUAGE_SHELL: str = "shell"  # future

#: Stateful-sequence op types. Each op is a ``{"op": "...", ...}``
#: dict. The sequence-runner harness applies them in order; state
#: (filesystem, env vars) propagates between ops in the SAME sandbox
#: machine.
SEQ_OP_CALL: str = "call"
"""Call a function: ``{"op": "call", "function_name": "...",
"args_json": "[...]", "kwargs_json": "{...}"}``. Reuses chain-harness
placeholder substitution (``<<_stepN_result>>``) for prior return
values."""

SEQ_OP_FS_WRITE: str = "fs_write"
"""Write a file: ``{"op": "fs_write", "path": "/tmp/X", "content":
"..."}``. Lets the model design state-poisoning attacks (write a
config, then call a function that reads it)."""

SEQ_OP_ENV_SET: str = "env_set"
"""Set an env var: ``{"op": "env_set", "name": "X", "value": "..."}``.
For env-controlled-behavior attacks."""

SEQ_OP_FS_READ: str = "fs_read"
"""Read a file + record contents in observations: ``{"op": "fs_read",
"path": "/tmp/X"}``. Lets the model verify whether earlier ops
produced the expected side effects."""

#: Outcome verdicts for hypothesis testing. ``probe_observed`` is the
#: probe-kind specific outcome — never interpreted as exploit, just
#: informational.
VERDICT_CONFIRMED: str = "confirmed"
VERDICT_REFUTED: str = "refuted"
VERDICT_BLOCKED: str = "blocked"  # env failure, sandbox didn't deliver
VERDICT_PROBE_OBSERVED: str = "probe_observed"

#: Loop termination reasons (recorded in the result for journaling +
#: downstream analysis).
TERMINATED_BY_NO_NEW: str = "no_new_hypotheses"
TERMINATED_BY_MAX_TURNS: str = "max_turns"
TERMINATED_BY_MAX_COST: str = "max_cost"
TERMINATED_BY_WALL_CLOCK: str = "wall_clock"
TERMINATED_BY_ALL_CONFIRMED: str = "all_confirmed"
TERMINATED_BY_L1_SHORTCIRCUIT: str = "l1_shortcircuit"


# ── Data types ────────────────────────────────────────────────────────────


@dataclass
class AdversarialHypothesis:
    """One model-proposed hypothesis emitted in a turn.

    Three kinds are supported (see :data:`HYPOTHESIS_KIND_*`). Each
    kind uses a subset of the fields below; the JSON schema rejects
    invalid combinations at the model-output gate.

    Language-polymorphic: every hypothesis carries ``language`` so the
    same loop logic dispatches to language-specific plan builders +
    harnesses. v1.6 ships Python only; ``language`` is the seam JS/
    shell expansion plugs into in v1.7+.
    """

    language: str
    """One of :data:`LANGUAGE_PYTHON`, :data:`LANGUAGE_JAVASCRIPT`,
    :data:`LANGUAGE_SHELL`. Dispatches to language-specific plan
    builders."""

    kind: str
    """One of :data:`HYPOTHESIS_KIND_PROBE`,
    :data:`HYPOTHESIS_KIND_SINGLE_FUNCTION`,
    :data:`HYPOTHESIS_KIND_STATEFUL_SEQUENCE`."""

    # ── Common fields (all kinds) ─────────────────────────────────────────

    rationale: str = ""
    """Why the model proposed this hypothesis. Journaled for
    traceability. Should reference specific behavioral-profile
    observations or source-code patterns the hypothesis targets."""

    attack_class: str = ""
    """For probe-kind: empty (no attack class — exploratory). For
    single_function / stateful_sequence: one of the documented attack
    class enum values (code_injection, command_injection,
    path_traversal, deserialization, ssrf, etc.). Drives CWE / severity
    mapping at confirmation time."""

    expected_observable: str = ""
    """Concrete description of what the sandbox will see if the
    exploit fires. E.g., ``"/tmp/argus_probe_X file created"``,
    ``"function returns dict containing __builtins__"``,
    ``"network attempt to attacker-controlled host"``. Used by the
    Rule 1 keyword-match oracle."""

    assertion_expr: str = ""
    """Phase 1 (SCAN-016, 2026-05-21) — STRUCTURED Python predicate
    expression evaluated against the live return value inside the
    sandbox. Eval namespace binds ``result`` (live object), ``args``
    (decoded list), ``kwargs`` (decoded dict); restricted-builtin
    namespace (no imports, no I/O — see
    ``dast/runtime_probe.RuntimeProbeInput.assertion_expr`` docstring
    for the full whitelist).

    When non-empty AND the eval cleanly returns True/False, the
    assertion oracle is decisive — it overrides the legacy keyword /
    class-signature oracles. Strongly preferred for new
    ``single_function`` hypotheses because it directly tests the
    structural invariant the exploit needs rather than substring-
    matching ``str(result)`` (which is the v15.27 FP source).

    Empty string disables structured assertions for this hypothesis
    and falls back to the legacy oracles — back-compat with pre-
    Phase-1 cached hypotheses."""

    rejection_signature: str = ""
    """Counter-evidence: what the sandbox would see if the application
    correctly REJECTED the attack input. E.g., ``"ValueError raised
    with message containing 'invalid' before any side effect"``,
    ``"UnsupportedProtocol exception caught and re-raised as McpError"``,
    ``"ZoneInfo keys may not contain up-level references"``.

    Required defense against the v1.6 FP class where ``expected_observable``
    matches a substring inside an error message that's actually evidence
    of the input being rejected. The interpreter only marks
    :data:`VERDICT_CONFIRMED` when ``expected_observable`` matches AND
    ``rejection_signature`` does NOT match. When both match, rejection
    wins and the outcome is :data:`VERDICT_REFUTED`.

    Empty string means "no rejection pattern declared" — interpreter
    falls back to the legacy substring-only rule for backward compat,
    but new hypotheses should always populate this.
    """

    exploit_proof_if_observed: str = ""
    """The finding-level claim that lands IF the observable matches.
    E.g., ``"RCE via parse-then-eval chain"``. Surfaces in the
    finding's ``description`` field."""

    confidence_prior: str = "MEDIUM"
    """Model's a-priori confidence: ``HIGH`` | ``MEDIUM`` | ``LOW``.
    Independent of the runtime-evidence confidence (see
    :class:`AdversarialHypothesisOutcome`). Used to prioritize which
    hypotheses to test first if budget gets tight."""

    # ── probe / single_function fields ────────────────────────────────────

    function_name: str = ""
    """Bare function or method name to invoke. Same regex constraints
    as Phase B+ single-function probes
    (``^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)?$``).
    Required for ``probe`` and ``single_function`` kinds; ignored
    for ``stateful_sequence``."""

    args_json: str = "[]"
    """JSON-encoded list of positional args. Required for ``probe``
    and ``single_function``; ignored for ``stateful_sequence``."""

    kwargs_json: str = "{}"
    """JSON-encoded dict of keyword args. Required for ``probe`` and
    ``single_function``; ignored for ``stateful_sequence``."""

    # ── stateful_sequence fields ──────────────────────────────────────────

    sequence: list[dict[str, Any]] = field(default_factory=list)
    """Ordered list of ops for ``stateful_sequence`` kind. Each op is
    ``{"op": "<type>", ...kind-specific fields}``. See
    :data:`SEQ_OP_*` for the supported op types.

    Example state-poisoning attack::

        [
          {"op": "fs_write", "path": "/tmp/cfg.json",
           "content": "{\\"hook\\": \\"__import__('os').system('id')\\"}"},
          {"op": "call", "function_name": "load_and_apply_config",
           "args_json": "[\\"/tmp/cfg.json\\"]", "kwargs_json": "{}"},
          {"op": "fs_read", "path": "/tmp/argus_probe_canary"},
        ]
    """


@dataclass
class AdversarialHypothesisOutcome:
    """Result of testing one hypothesis in the sandbox.

    The interpretation rules mirror Phase 2 chain confidence scoring:
    Rule 2 canary side-effect = 1.0 confidence; Rule 1 class-signature
    = 0.7; Rule 1 observable-keyword = 0.4. NoneType-intermediate guard
    still applies. probe-kind hypotheses skip interpretation entirely
    and report ``verdict=VERDICT_PROBE_OBSERVED``.
    """

    hypothesis: AdversarialHypothesis
    """The hypothesis this outcome attests to. Carried for journal
    + transcript completeness."""

    verdict: str
    """One of :data:`VERDICT_CONFIRMED`, :data:`VERDICT_REFUTED`,
    :data:`VERDICT_BLOCKED`, :data:`VERDICT_PROBE_OBSERVED`."""

    confidence: float = 0.0
    """Confidence in the verdict, in [0.0, 1.0]. Only meaningful for
    ``VERDICT_CONFIRMED``. Maps to:

    * ``1.0`` — Rule 2 canary side-effect (0 observed FPs by construction)
    * ``0.7`` — Rule 1 class-signature substring match
    * ``0.4`` — Rule 1 observable-keyword match (FP-prone — see
      Phase 2 NoneType guard)

    For ``VERDICT_REFUTED`` / ``VERDICT_BLOCKED`` /
    ``VERDICT_PROBE_OBSERVED``: 0.0."""

    oracle_type: str = ""
    """Which oracle confirmed (when ``VERDICT_CONFIRMED``). One of:
    ``"canary"``, ``"class_signature"``, ``"observable_keyword"``,
    or ``""`` for non-confirmed verdicts."""

    runtime_evidence: str = ""
    """Verbatim trace lines / per-step summary that justify the
    verdict. The exploit-grounding signal for findings."""

    trace_ref: str = ""
    """Sandbox event ID (``evt-...``) for the underlying trace. Lets
    downstream consumers fetch the full trace from the journal."""

    elapsed_ms: int = 0
    """Wall-clock time spent testing this hypothesis."""

    fixture_context: bool = False
    """v1.6 Fix #4: set ``True`` when the source file is detected as
    a test fixture / scrubbed reproduction / neutered demo (markers
    like ``# fixture``, ``# scrubbed``, ``# neutered`` in the file
    header). CONFIRMED outcomes on fixture files are downgraded to
    ``confidence <= 0.5`` and prefixed with ``FIXTURE_CONTEXT:`` in
    ``runtime_evidence`` so the customer sees the finding pattern
    was detected but cannot be promoted to a production-grade
    zero-day claim. Adjudication on the v1.5.1 23-file bench found
    8/16 W1 over-claims were fixture files Argus treated as real
    exploits."""

    judge_verdict: str = ""
    """v1.8 Strategy C: post-trace LLM judge verdict. Populated only on
    interpreter=CONFIRMED outcomes when ``enable_strategy_c_judge`` is
    True. One of:

    * ``"CONFIRMED"`` — judge agrees the exploit fired
    * ``"REFUTED"`` — judge says the trace shows defense; outcome.verdict
      is flipped to ``VERDICT_REFUTED`` by the runner (the FP defense)
    * ``"INCONCLUSIVE"`` — judge couldn't decide; CONFIRMED kept
      unchanged, but the verdict is surfaced in the output so the
      operator can see the uncertainty
    * ``""`` (empty) — judge wasn't called (interpreter said REFUTED,
      or feature flag was off, or call errored — fail-open keeps
      interpreter's verdict)

    Catches the FP class Strategy B can't: when the model wrote a
    poor / missing ``rejection_signature``, the substring oracle
    falsely confirms because the application's error message echoed
    the attacker payload (path-traversal "PermissionError on
    '../../../etc/passwd'" pattern)."""

    judge_reasoning: str = ""
    """v1.8 Strategy C: 1-2 sentence justification from the judge
    citing specific trace evidence (parsed_result.ok, canary, exception
    type, etc.). Surfaced in the report so the operator can see WHY
    the judge agreed/disagreed with the interpreter. Empty when judge
    wasn't called."""


@dataclass
class AdversarialTurn:
    """One turn of the adversarial loop: model proposes hypotheses +
    sandbox tests them.

    Captured as a record so the journal carries the full transcript
    for operator audit + replay. The conversation history (used to
    build the next turn's prompt) is reconstructed from this list
    rather than maintained as a separate object."""

    turn_idx: int
    """0-indexed turn counter. Turn 0 is the initial proposal; turns
    1+ are refinements with prior-turn context."""

    hypotheses: list[AdversarialHypothesis] = field(default_factory=list)
    """Hypotheses the model emitted in this turn. Bounded by
    :data:`MAX_HYPOTHESES_PER_TURN`. May be empty when the model
    emits ``no_new_hypotheses=True``."""

    outcomes: list[AdversarialHypothesisOutcome] = field(default_factory=list)
    """One outcome per hypothesis, in declaration order. Empty when
    hypotheses is empty."""

    inference_tokens_in: int = 0
    inference_tokens_out: int = 0
    inference_cost_usd: float = 0.0
    """Model call cost for THIS turn's hypothesis-proposal call. The
    turn's sandbox cost is computed from outcomes + per-call rates."""

    no_new_hypotheses_flag: bool = False
    """True iff the model signaled it has no further hypotheses to
    propose. The loop respects this (subject to
    :data:`MIN_TURNS_BEFORE_EARLY_EXIT`)."""

    code_intent_analysis: dict[str, Any] | None = None
    """v15.8 (2026-05-20): the model's structured intent analysis for
    this turn (purpose / deployment_context / trust_boundary /
    powerful_by_design). Required field in
    :func:`dast.prompts.phase_3_loop_hypothesis_batch_schema` so the
    model has to reason about file intent BEFORE deciding whether to
    emit hypotheses.

    Gap 2 from the WCtesting audit: shopify-api / homebridge files
    came back with ``hypotheses_total=0`` and there was no signal in
    the scan JSON for WHY. Capturing the model's own intent analysis
    on each turn turns the silent ``no_hypotheses`` outcome into a
    diagnosable one: operators can see "deployment_context=library +
    trust_boundary=internal => model correctly declined" vs.
    "deployment_context=admin_endpoint + L1 found CWE-94 => model
    SHOULD have proposed something but didn't" → flag for review."""

    elapsed_ms: int = 0
    """Total wall-clock time for this turn (inference + parallel
    sandbox tests + interpretation)."""


@dataclass
class AdversarialLoopResult:
    """End-of-loop result. Returned by the Stage 2 orchestrator helper
    and surfaced on :class:`dast.orchestrator.DastResult`.

    Coverage metric (``hypotheses_tested / hypotheses_total``) feeds
    the Phase 3 verdict resolver's 4-state outcome:

    * coverage >= 0.80 + any confirmed → ``confirmed_high_confidence``
    * coverage >= 0.80 + 0 confirmed → ``clean_run``
    * 0.30 <= coverage < 0.80 → ``partial_run`` (blend with L1)
    * coverage < 0.30 → ``unreachable`` (L1 verdict authoritative)
    """

    file_id: str
    file_name: str
    language: str

    turns: list[AdversarialTurn] = field(default_factory=list)
    """All turns executed. Length 0 when the loop was short-circuited
    (see ``terminated_by``)."""

    terminated_by: str = ""
    """Reason the loop ended. One of :data:`TERMINATED_BY_*`."""

    # ── Aggregate counts (computed at end-of-loop) ────────────────────────

    hypotheses_total: int = 0
    """Total hypotheses proposed across all turns (including
    duplicates skipped via dedup — counted but not re-tested)."""

    hypotheses_tested: int = 0
    """Hypotheses that produced a usable sandbox trace (success or
    refutation). Excludes blocked-by-env failures. Numerator of the
    coverage ratio."""

    hypotheses_confirmed: int = 0
    """Outcomes with ``verdict == VERDICT_CONFIRMED``."""

    hypotheses_refuted: int = 0
    """Outcomes with ``verdict == VERDICT_REFUTED`` (sandbox ran but
    no exploit signal)."""

    hypotheses_blocked: int = 0
    """Outcomes with ``verdict == VERDICT_BLOCKED`` (env failure,
    sandbox event-capture loss, etc.). Excluded from coverage
    numerator."""

    explore_calls_used: int = 0
    """Probe-kind hypotheses tested. Bounded by
    :data:`MAX_EXPLORE_CALLS`."""

    # ── Cost + duration ──────────────────────────────────────────────────

    total_cost_usd: float = 0.0
    total_elapsed_ms: int = 0
    inference_tokens_in: int = 0
    inference_tokens_out: int = 0

    # ── Outputs flowing to the engine ─────────────────────────────────────

    findings: list[dict[str, Any]] = field(default_factory=list)
    """Confirmed findings serialized in the same shape as Phase 2
    chain findings (``id``, ``finding_ref``, ``finding_type``,
    ``severity``, ``cwe``, ``confidence``, ``oracle_type``,
    ``runtime_evidence``, etc.). Engine appends these to
    ``ScanResult.dast_findings``."""

    @property
    def coverage_ratio(self) -> float:
        """Fraction of proposed hypotheses that produced a usable
        trace. Used by the verdict resolver."""
        if self.hypotheses_total == 0:
            return 0.0
        return self.hypotheses_tested / self.hypotheses_total


@dataclass
class L1ShortcircuitInput:
    """Inputs the short-circuit gate consults before running the
    adversarial loop. Surfaces here as a dataclass for testability."""

    l1_max_confidence: float
    """Highest confidence across L1's hypotheses for this file."""

    behavioral_profile_confirms_pattern: bool
    """True iff the Stage 1 profile contains a signal consistent with
    L1's high-confidence finding (e.g., L1 says SQL injection at
    line 113 AND profile shows ``get_table_stats`` opens DB
    connection)."""

    behavioral_profile_contradicts: bool
    """True iff Stage 1 profile contains a signal that contradicts
    L1 (e.g., L1 says ``apply_config`` is RCE-prone but profile shows
    the function only calls ``str()`` on its input)."""


def should_short_circuit(
    inputs: L1ShortcircuitInput,
    threshold: float = L1_SHORTCIRCUIT_CONFIDENCE,
) -> bool:
    """Return True iff the adversarial loop should be skipped for this
    file: L1 is very confident, behavioral profile agrees, and there's
    no contradictory signal.

    Tuned for big-team CI scanning many files: ~60-80% of HIGH-triaged
    files satisfy this when L1 is mature. Saves $0.50/file × those
    files = real money at scale.

    Override at the CLI via ``--always-run-adversarial-loop`` for
    benchmark mode or high-rigor security review.
    """
    if inputs.behavioral_profile_contradicts:
        return False
    if inputs.l1_max_confidence < threshold:
        return False
    return inputs.behavioral_profile_confirms_pattern


__all__ = [
    "AdversarialHypothesis",
    "AdversarialHypothesisOutcome",
    "AdversarialLoopResult",
    "AdversarialTurn",
    "HYPOTHESIS_KIND_PROBE",
    "HYPOTHESIS_KIND_SINGLE_FUNCTION",
    "HYPOTHESIS_KIND_STATEFUL_SEQUENCE",
    "L1ShortcircuitInput",
    "L1_SHORTCIRCUIT_CONFIDENCE",
    "LANGUAGE_JAVASCRIPT",
    "LANGUAGE_PYTHON",
    "LANGUAGE_SHELL",
    "MAX_COST_USD",
    "MAX_EXPLORE_CALLS",
    "MAX_HYPOTHESES_PER_TURN",
    "MAX_TURNS",
    "MIN_TURNS_BEFORE_EARLY_EXIT",
    "SEQ_OP_CALL",
    "SEQ_OP_ENV_SET",
    "SEQ_OP_FS_READ",
    "SEQ_OP_FS_WRITE",
    "TERMINATED_BY_ALL_CONFIRMED",
    "TERMINATED_BY_L1_SHORTCIRCUIT",
    "TERMINATED_BY_MAX_COST",
    "TERMINATED_BY_MAX_TURNS",
    "TERMINATED_BY_NO_NEW",
    "TERMINATED_BY_WALL_CLOCK",
    "VERDICT_BLOCKED",
    "VERDICT_CONFIRMED",
    "VERDICT_PROBE_OBSERVED",
    "VERDICT_REFUTED",
    "WALL_CLOCK_TIMEOUT_S",
    "should_short_circuit",
]
