"""Argus engine — orchestrates the full scan flow.

Replaces CNAPPPOC's ``scan_file_routed`` with a richer pipeline that
adds Argus-specific stages:

  1. Deterministic preprocessing (lifted from echoDefense) — hash,
     deobfuscation, dependency parsing, attack-vector flags
  2. Gemini Flash-Lite triage (CLEAN | LOW | HIGH) — kept from CNAPPPOC
  3. Deterministic safety net — lifts CLEAN→HIGH when preprocessing
     flags fire (imperative_install, attack_vector_extension,
     crypto_sensitivity, ai_file_match)
  4. Cascade analysis:
       CLEAN → return immediately ($0)
       LOW   → Gemini Flash combined call
       HIGH  → Sonnet 4.6 combined call (default)
              ↳ if borderline OR high-stakes → escalate to Opus 4.6
  5. L1 ensemble (N=3 Sonnet) on borderline files
  6. DAST verification on confirmed-malicious + poc_feasible files
  7. Adjudication (Opus tie-breaker) when ensemble or scanner sources
     disagree

This module is the integration point. It does not implement the model
calls themselves — those live in ``inference/adapters.py`` (lifted from
CNAPPPOC). It does not implement preprocessing — that lives in
``preprocessing/`` (lifted from echoDefense). It glues them together.

Usage::

    from scanner.engine import scan_file
    result = await scan_file(
        filename="suspect.py",
        content=raw_bytes,
        config=ScanConfig(...),
    )

State of build (2026-05-05):
  * Preprocessing pipeline: integrated
  * Triage layer: STUB (placeholder until adapter-based call wired)
  * Cascade routing: STUB (decision tree implemented; model calls TBD)
  * DAST trigger: STUB (decision logic implemented; orchestrator wired
    to dast.orchestrator.run_dast as a function call)
  * Ensemble + adjudicator: STUB
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from preprocessing import preprocess_file
from shared.types.preprocessing import Preprocessing

log = logging.getLogger("argus.engine")


# ─── Configuration ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ScanConfig:
    """Per-scan configuration. Defaults are tuned for SaaS realtime.

    All thresholds are env-overridable downstream; this dataclass is
    the canonical default.
    """

    # ── Anthropic model overrides (SCAN-020, v1.11.1) ────────────────────
    # Per-tier model IDs Argus sends to the Anthropic API. Defaults match
    # the v1.11 pin (Sonnet 4.6 / Opus 4.6) — operators who want to
    # upgrade (Opus 4.8, etc.) or swap one tier entirely (use Opus for
    # everything, or use a future Anthropic-compatible model in either
    # slot) override via --scan-model / --reasoning-model on the CLI
    # without code edits.
    #
    # Role-based naming (not family-based) so the slot doesn't lock you
    # into a particular model family:
    #
    #   * scan_model     — the "workhorse" tier. Runs triage, L1
    #                      analysis (split + combined paths), and
    #                      DAST probe-inference. Sees most files.
    #                      Default: Sonnet 4.6 (cheap, fast, deterministic).
    #
    #   * reasoning_model — the "deep reasoning" tier. Runs L1
    #                       escalation on borderline-uncertainty files,
    #                       DAST iter-3 escalation, Adversarial
    #                       Reasoning (Phase 3 Stage 2), the
    #                       adjudicator, and methodology benches.
    #                       Default: Opus 4.6 (extended thinking).
    #
    # The value is the literal model_id sent to the Anthropic API; no
    # validation beyond non-empty. Anthropic returns a 404 on unknown
    # IDs which surfaces as an Argus runner error.
    #
    # Caveats:
    #   * Some Anthropic models (notably claude-opus-4-7) refuse Argus's
    #     live-payload fixtures and produce empty responses. v1.11.1
    #     doesn't try to guess compatibility; operators pick the model_id
    #     and own the compatibility risk. Always run a smoke scan after
    #     overriding.
    #   * Both slots can be set to the same model_id (e.g., Opus 4.8
    #     everywhere for a high-precision audit mode).
    scan_model: str = "claude-sonnet-4-6"
    reasoning_model: str = "claude-opus-4-6"

    # Triage layer
    enable_pre_triage_regex: bool = True
    enable_triage_safety_net: bool = True

    # Cascade routing
    enable_cascade: bool = True  # if False, all files go to Sonnet directly
    sonnet_uncertainty_threshold: float = 0.4  # above this, escalate to Opus
    # imperative_install_detected was removed (2026-05-05): the detector
    # was broadened in echoDefense's 2026-05-04 audit to fire on any .py
    # file using subprocess / urllib / requests / eval / exec — i.e. most
    # production code. In echoDefense's pipeline this only added a $0.02
    # L1 call, but in Argus it routes to Opus 4.6, costing ~$0.15 vs
    # Sonnet's ~$0.05 (3-7× the spend on every benign utility script).
    # Triage HIGH + Sonnet's own escalation handle these adequately; the
    # high-stakes tier is reserved for narrower signals.
    high_stakes_categories: tuple[str, ...] = (
        "attack_vector_extension",
        "crypto_sensitivity_detected",
        "ai_file_match",
        "obfuscation_detected",
    )

    # Ensemble
    ensemble_size_borderline: int = 3  # N for borderline-file ensemble
    ensemble_size_default: int = 1  # N for non-borderline (no ensemble)

    # DAST verification
    enable_dast: bool = True
    # v1.7 default — keep DAST tight to high-confidence verdicts.
    #
    # History (Fix #11 -> revert): v1.7-dev tried including 'suspicious'
    # in the default trigger to catch missed bugs in suspicious-verdict
    # files (e.g., load_distributed_checkpoint.py where L1 said
    # suspicious but oracle said malicious). The full 23-file bench
    # showed this was a net-negative tradeoff:
    #
    #   * Caught +1 real zero-day (sandbox_runner.js CWE-306)
    #   * BUT added +5 over-claims that Gemini overruled
    #   * Verdict-exact dropped from 82.6% -> 73.9% (-8.7pp)
    #   * Argus lift over Opus flipped from +4.35pp to -4.35pp
    #
    # Conclusion: the cheap 'fire DAST on more files' approach
    # produces noise faster than signal because suspicious-verdict
    # files often have ambiguous code where DAST's CONFIRMED status
    # escalates verdicts past what's actually warranted.
    #
    # Customers wanting broader coverage can still opt in via CLI:
    #   ``--dast-trigger-verdicts suspicious,malicious,critical_malicious``
    # (~30-50% more per-scan cost; trade-off documented in
    # docs/dast-setup.md).
    #
    # A smarter way to catch the load_distributed_checkpoint.py-style
    # cases is to improve L1's prompt so it doesn't under-claim
    # suspicious verdicts on real deserialization bugs — that's a v1.8
    # L1-prompt task, not a DAST-trigger-gate widening.
    dast_trigger_verdicts: tuple[str, ...] = (
        "suspicious",
        "malicious",
        "critical_malicious",
    )
    # v1.9 — finding-based DAST trigger override.
    #
    # The verdict-only gate above is rolled up from per-finding
    # severity + confidence; aggregation can collapse 3 medium-conf
    # mediums into a "clean" verdict even when each individual
    # finding has a clear PoC. That's the right policy for normal
    # scans (we don't want to burn DAST on weakly-signaled noise),
    # but it blocks the cross-repo Phase D / DAST-303 flow where an
    # operator has hand-curated the candidate and wants runtime
    # confirmation regardless of rolled-up verdict.
    #
    # When ``dast_trigger_on_finding_confidence`` is set (non-None),
    # DAST also fires if ANY L1 vulnerability has
    # ``confidence >= threshold`` — independent of the verdict gate.
    # Operators wanting "DAST every file with a real lead" pass
    # ``--dast-trigger-on-finding-confidence 0.6``. None = disabled
    # (default), preserving the v1.7-v1.8 verdict-only behavior.
    dast_trigger_on_finding_confidence: float | None = None
    dast_max_iterations: int = 3
    # v1.9 — anti-undercall backstop. Engine-side defense-in-depth
    # against the SCAN-010 split-L1 regression where the VULNS
    # sub-call would emit findings + score=0 (verdict=clean) because
    # it couldn't see behavioral context for intent scoring. After
    # the runner-side max-aggregation and the system-prompt's
    # anti-undercall rule, this is the third layer: if any finding
    # has severity ≥ medium AND confidence ≥ ``undercall_backstop_
    # min_confidence``, the verdict cannot remain ``clean`` — gets
    # promoted to ``suspicious``. Never lifts past suspicious — that
    # requires intent evidence the model is best positioned to score.
    #
    # v1.9.2 (2026-05-20) — threshold lowered 0.5 → 0.4. Sonnet 4.6
    # with adaptive thinking varies its confidence calls by ~±0.05-
    # 0.10 between runs on the same finding. The mako/template.py
    # WCtesting case had a medium-severity SSTI finding landing at
    # conf=0.45 on one run and conf≥0.5 on another — the gate at
    # exactly 0.5 sat on top of the variance band, producing a
    # flip-flop between verdict=clean and verdict=critical_malicious
    # for byte-identical input. Widening the catch radius to 0.4
    # absorbs the variance without crossing into low-confidence
    # finding territory (model still owns the 0.0-0.4 calibration
    # band as legitimate "model isn't sure"). The system-prompt
    # ANTI-UNDERCALL FLOOR keeps its 0.5 ask — defense-in-depth: the
    # model is told to lift at 0.5, the backstop catches at 0.4.
    enable_undercall_backstop: bool = True
    undercall_backstop_min_confidence: float = 0.4
    # v1.9.1 — coverage-dedupe across DAST stages. When ON (default),
    # the orchestrator builds a coverage tracker pre-DAST seeded from
    # L1's high-confidence findings, then Phase B+ candidates that
    # would re-probe a covered (function, attack_class) pair are
    # filtered out before they hit the sandbox. Confirmed Phase B+
    # findings feed back into the tracker so downstream stages can
    # also dedupe. Net effect: Phase B+'s fixed budget redirects to
    # NEW exploits / NEW callables.
    #
    # Operator overrides to ``False`` via ``--disable-coverage-dedupe``
    # restore v1.9.0 behavior (every stage runs unconstrained). Useful
    # when investigating a suspected dedupe false-positive.
    enable_coverage_dedupe: bool = True
    # P3a (v1.8) — report-layer DAST policy. Controls how Phase A's
    # per-finding evidence is mapped onto the published verdict and
    # vulnerability list.
    #
    #   "downgrade_cap" (default, legacy behavior):
    #       When DAST proposes a lower verdict than L1, downgrade by at
    #       most 1 tier (the severity-driven rule in scan_file). This is
    #       the v1.1-v1.7 default. Risk: real exploits that DAST can't
    #       reproduce in the sandbox (SSRF needing real internal endpoints,
    #       ML-detonation needing GPU, etc.) get verdict-downgraded from
    #       malicious → suspicious purely because the sandbox couldn't
    #       reach the necessary infrastructure.
    #
    #   "strict":
    #       Preserve L1 verdict — never downgrade. Phase A can only
    #       UPGRADE the verdict (if DAST proves the exploit fires
    #       worse than L1 thought). Additionally, findings with
    #       per_finding_validation status in {BLOCKED, UNREACHED, REJECTED}
    #       — i.e. Phase A actively ran AND proved non-exploitability —
    #       are suppressed from result.vulnerabilities. NOT_TESTED
    #       findings (including all sub-reasons: infra_stub,
    #       dast_not_attempted, budget_exceeded, non_python_file,
    #       unfireable_pattern_cwe, unreachable_function, inconclusive,
    #       not_planned) are NEVER suppressed — those represent "DAST
    #       didn't conclusively run", not "DAST proved safe", so we
    #       trust L1.
    #
    #       Designed for security teams that prefer L1 transparency
    #       over DAST-driven verdict massaging. Catches the mcp-server-
    #       fetch SSRF class where infra-limited sandboxes can't reach
    #       internal endpoints to confirm.
    #
    # Opt-in via --dast-required-policy on the CLI. Default stays
    # "downgrade_cap" — strict mode changes scan output shape and
    # would invalidate the v1.7 bench numbers without a re-run.
    dast_required_policy: str = "downgrade_cap"  # "downgrade_cap" | "strict"
    # v1.2 Phase C — fix-and-verify. When True, DAST attempts to
    # generate a patch for CONFIRMED findings and replays the original
    # exploit against the patched source in the same sandbox.
    #
    # v1.8 (2026-05-15): flipped from default True → False (opt-in).
    # Phase C is purely remediation — it doesn't change verdicts or
    # add findings. Default-on charged every user $0.05/file for patch
    # generation they may not want. Compliance scans, CI gates that
    # don't allow source modifications, and read-only audits all want
    # this off. Now users explicitly opt in via --enable-remediation
    # when they want a patched source + exploit replay.
    #
    # v1.11 (2026-05-21): RE-FLIPPED False → True. Repositioning:
    # Argus's pitch is runtime-grade FP reduction + fast verified
    # remediation. Validation (intrinsic to DAST) + Remediation
    # (this flag) are now the two default-on stages that make that
    # pitch concrete: every CONFIRMED finding ships with a verified
    # patch out of the box. The expensive zero-day-hunting stages
    # (Exploit Discovery, Behavioral Profiling, Adversarial Reasoning)
    # are now opt-in for users who want deeper coverage. Compliance /
    # read-only audits opt out via --no-enable-remediation.
    enable_phase_c: bool = True
    # v1.5 Phase B+ — runtime exploit probing. When True AND DAST is
    # configured AND the file is Python, the orchestrator asks the
    # model to generate concrete attack inputs, runs each in the
    # sandbox, and emits findings from observed runtime evidence rather
    # than from static analysis speculation.
    #
    # v1.8 (2026-05-15): flipped from default False → True. Phase 3
    # Stage 2 (adversarial reasoning loop) requires this sandbox
    # machinery, and Stage 2 is now default-on. Phase B+ base alone
    # adds ~$0.20-0.50/file on Python HIGH files. The opt-in variants
    # (mutation / iterative / chains) stay opt-in — their cost
    # multipliers (3-5x sandbox) earn opt-in scrutiny.
    #
    # v1.11 (2026-05-21): RE-FLIPPED True → False. Repositioning:
    # the default cascade is now Validation + Remediation focused
    # (runtime-grade FP reduction + verified patches). Exploit
    # Discovery (this flag) is the heavier zero-day-hunting stage —
    # users who want broader coverage opt in via
    # --enable-runtime-probe. Cuts default scan cost
    # ~$0.20-0.50/file on Python HIGH files.
    enable_runtime_probe: bool = False
    # Phase 1a — deterministic mutation expansion of runtime-probe inputs.
    # When ``enable_runtime_probe`` is True AND this is True, each
    # model-generated attack input fans out to N mutated variants
    # drawn from known-bypass families (URL-encode, double-encode,
    # ....// path-traversal, `; id` command-injection, `' OR 1=1--`
    # SQLi, etc.). Catches exploits the model's first input shape
    # didn't hit. Adds ~5x sandbox-run cost on top of the base probe.
    # Off by default; opt-in via ``--enable-runtime-probe-mutation``.
    enable_runtime_probe_mutation: bool = False
    # Phase 1b — iterative refinement on BLOCKED probes. When all probes
    # for a candidate function failed but at least one reached the
    # function (recoverable exception like TypeError / SyntaxError),
    # ask Sonnet to generate refined inputs that specifically address
    # those failure modes. Up to MAX_REFINEMENT_ATTEMPTS retries per
    # candidate. Adds ~1 inference call + ~2 sandbox runs per refined
    # candidate (~$0.20-0.40/file when refinement actually fires). Off
    # by default; opt-in via --enable-runtime-probe-iterative.
    enable_runtime_probe_iterative: bool = False
    # Phase 2 — Cross-function exploit chains. Asks Sonnet for 2-3 step
    # call sequences where each step's args may reference prior steps'
    # return values via ``<<_stepN_result>>`` placeholders. Catches the
    # class of bugs where no single function is exploitable but the
    # sequence is (parse → eval, store → load, sanitize → render).
    # Adds ~1 inference call + up to MAX_CHAINS_PER_FILE sandbox runs
    # per file (~$0.15-0.35/file when chains land). Off by default; opt-
    # in via --enable-runtime-probe-chains. Independent of mutation and
    # iterative — chains can fire with or without those phases.
    enable_runtime_probe_chains: bool = False
    # P2a v0.1 (v1.8) — per-scan dependency installer. When True AND
    # the orchestrator routes a plan to a non-lean image tier
    # (``rich_python`` or ``ml_tools``), the target file's imports
    # are parsed; missing packages are pip-installed inside the
    # sandbox before plan commands run.
    #
    # Security: approach A only — packages are extracted from
    # ``import X`` AST nodes; ``pip install --no-deps`` refuses
    # transitive deps. See ``preprocessing.imports`` module
    # docstring for the full security contract.
    #
    # Cost: adds ~5-30s sandbox time when packages are missing from
    # the image (network + pip install). Lean plans skip the install
    # phase entirely (lean is the floor — the model only routes
    # there when it expects no extras).
    #
    # Default is ON because the orchestrator's tier choice already
    # gates this: rich_python / ml_tools are the only tiers that
    # admit dep install, and the model only picks those when the
    # file imports beyond lean's preinstalled set.
    enable_per_scan_dep_install: bool = True
    # v15 debug flag: force the full L1+DAST cascade even when triage
    # returns CLEAN. Normal scan flow short-circuits on CLEAN to save
    # the API spend (the bulk of files in any real corpus are clean
    # library helpers / type stubs / re-export barrels). When this
    # flag is set, CLEAN classifications are promoted to LOW for
    # routing purposes ONLY (the original ``triage_classification``
    # field is preserved verbatim in the result for observability).
    # Use case: validating that DAST infrastructure works end-to-end
    # on a known-uninteresting file (e.g. integration smokes that
    # need to exercise the sandbox path regardless of what the model
    # said about the file's risk surface). NOT for production scans
    # — wastes ~$0.05-0.50 per file when triage was correctly clean.
    force_dast_through_clean: bool = False
    # Phase 3 — Behavioral exploration probe + adversarial reasoning
    # loop. Stage 1 (this flag, v1.6) runs a deterministic introspection
    # pass: imports the module, exercises every public callable with
    # benign discovery inputs, captures runtime observations (eval/exec/
    # subprocess/pickle reach, file opens, network attempts) into a
    # structured behavioral profile. Stage 2 (separate flag, future)
    # consumes the profile and runs an adversarial reasoning loop.
    # Stage 1 alone is non-destructive: it doesn't generate findings or
    # bump verdicts; just surfaces the profile in the scan JSON.
    # Adds ~1 sandbox run (~$0.05-0.10/file).
    #
    # v1.8 (2026-05-15): flipped from default False → True. Stage 2
    # (adversarial reasoning loop) consumes Stage 1's behavioral profile;
    # Stage 2 is now default-on, so Stage 1 must also be on.
    #
    # v1.11 (2026-05-21): RE-FLIPPED True → False. Repositioning:
    # Adversarial Reasoning (Stage 2) is now opt-in, so its dependency
    # (Behavioral Profiling, this flag) also defaults OFF. Users who
    # opt into --enable-phase-3-loop should also pass
    # --enable-phase-3-discovery (or rely on the orchestrator's gating
    # which won't fire Stage 2 without Stage 1's profile).
    enable_phase_3_discovery: bool = False
    # Phase 3 Stage 2 (v1.6) — adversarial reasoning loop. When True
    # AND ``enable_phase_3_discovery`` is also True (Stage 2 needs
    # Stage 1's behavioral profile), the orchestrator runs a multi-turn
    # adversarial loop where the model designs attack hypotheses
    # targeted to OBSERVED runtime behavior rather than static reading.
    # Each hypothesis dispatches to the right plan-builder + sandbox +
    # interpreter (probe / single_function / stateful_sequence kinds).
    # Default max_turns=1 — measured to close the gap on 4/5 vuln files
    # in the thin-slice regression slice (commit 7d42813). Multi-turn
    # refinement is hardening; expand only if production data demands.
    # Adds ~$0.05/file in API spend plus 3 sandbox runs.
    #
    # v1.8 (2026-05-15): flipped from default False → True. This is
    # the headline pipeline flip. Stage 2 is where the "agentic DAST"
    # value lands — model designs attack hypotheses anchored on
    # observed runtime behavior. Strategy C (post-trace LLM judge,
    # shipped in a8dffe2) gates FP risk on CONFIRMED outcomes.
    # Stage 2 implies Stage 1 (behavioral profile) + Phase B+ runtime
    # probe (sandbox machinery), both also flipped on this release.
    # Opt-out via `argus scan --no-enable-phase-3-loop` per scan.
    #
    # v1.11 (2026-05-21): RE-FLIPPED True → False. Repositioning:
    # the default cascade is now Validation + Remediation focused
    # (runtime-grade FP reduction + verified patches). Adversarial
    # Reasoning is the zero-day-hunting stage — users who want it
    # opt in via --enable-phase-3-loop (also enable
    # --enable-phase-3-discovery for Stage 1, and
    # --enable-runtime-probe for the sandbox-probe machinery
    # Stage 2 dispatches into).
    enable_phase_3_loop: bool = False
    # Phase 3 Stage 2 loop turn cap. Default 1 — the model gets one shot
    # at hypothesis generation, after which the loop terminates. Bumping
    # to 2+ lets Opus iterate when turn-1 declined to design hypotheses
    # (e.g. classified the file as ``deployment_context: library``) but
    # Phase B+ already surfaced findings worth a closer adversarial look.
    # Empirically: SDK auth/credentials modules where L1 flags SSRF-shape
    # risks return 0 hypotheses at turn-1 ("library trust boundary") and
    # leave the L1 verdict unrefuted; a second turn forces Opus to either
    # refute the existing findings or design adversarial inputs.
    # Adds ~$0.05–0.10/file per additional turn on borderline files.
    phase_3_loop_max_turns: int = 1
    # DAST-301 (v1.0): Phase D Variant Analysis. When Phase A confirms
    # a finding, abstract the exploit into a semantic signature, hunt
    # for variants in the same file via AST, verify each variant in
    # the sandbox. Surfaces confirmed variants as L1+PhaseA-shaped
    # findings that flow into Phase C remediation. v1 MVP is same-file
    # only and feature-flagged OFF by default — flip ON in v1.1 after
    # measurement. See docs/dast_301_variant_analysis.md.
    enable_phase_d: bool = False
    # v15 verified remediation: after Phase C neutralizes the reported
    # exploit, run the functional-preservation + adversarial-variant gates
    # (and budget-capped retry) to upgrade a bare NEUTRALIZED into a
    # CONFIDENCE-rated, class-complete fix. Only runs when remediation
    # (Phase C) is enabled AND a finding was neutralized, so leaving it ON
    # by default costs nothing on scans that don't produce a patch.
    enable_remediation_verify: bool = True
    # SCAN-010 (v1.1): split L1 into three specialized prompts (VULNS /
    # BEHAVIORAL / CHAINS) fired in parallel on HIGH-triage routings.
    # When True (current default) HIGH-classified files dispatch to the
    # split runner; LOW + CLEAN paths still use the combined prompt
    # (cost preservation on the cheap path).
    #
    # Default flipped to True 2026-05-18 after Gate 1 validation:
    #   * Gate 1 cache spike (live API) showed cost ratio 0.93× warm /
    #     1.66× cold. Bulk scans converge toward warm-cache numbers
    #     once the cache fills (file 1 warms, files 2+ amortize).
    #   * Gate 1 + Gemini adjudication on findings confirmed 100%
    #     recall overlap on the malicious-sample test — split mode
    #     produces equivalent findings to combined, with less label-
    #     duplication noise (combined emitted same bug under two CWE
    #     labels on one run; split emitted once).
    # See docs/scan_010_split_l1_design.md + .argus_local/
    # scan_010_validation/gate_1_cache_spike.json for the validation
    # data. Operators can revert per-scan via ``--l1-mode combined``
    # or ``ScanConfig(l1_split_enabled=False)``.
    l1_split_enabled: bool = True
    # Which triage classifications get split mode when enabled.
    # Default fires only on HIGH (matching the Cloudflare-comparison
    # insight that narrower prompts pay off most on already-flagged
    # files). Operators can broaden to ``("HIGH", "LOW")`` for an
    # aggressive A/B but expect ~3× per-file cost on LOW files.
    l1_split_on_triage: tuple[str, ...] = ("HIGH",)
    # SCAN-011 (slice 1 shipped 2026-05-18): per-attack-class parallel
    # hunters within HIGH-triage scans. Layers on top of SCAN-010 split:
    # the VULNS slot is replaced by N specialized hunters (injection /
    # ssrf / malicious_intent in slice 1; full 10-hunter taxonomy in
    # slice 2). BEHAVIORAL + CHAINS slots are unchanged.
    #
    # Default OFF for slice 1 — cost increase is ~2× SCAN-010 baseline
    # (10 hunter calls + 2 split calls = 12 vs SCAN-010's 3) and the
    # quality lift hasn't been measured on the regression suite yet.
    # See docs/scan_011_attack_class_hunters_design.md for the full
    # validation plan; default flip lands after Gate measurements.
    # Operators can opt in via ``--l1-hunters all`` (slice 2 CLI) or
    # by setting this flag programmatically.
    l1_hunter_enabled: bool = False
    # Semaphore-bounded concurrency for hunter fan-out. 10 = matches
    # the full SCAN-011 taxonomy. Lower values reduce Anthropic rate-
    # limit pressure at the cost of higher wall-clock per file.
    l1_hunter_max_concurrent: int = 10
    # Hunter subset selector. Empty tuple = all hunters in
    # prompts.scanner.ATTACK_CLASS_HUNTERS. Operators with targeted
    # threat models (e.g., "only run injection + ssrf on this codebase")
    # can narrow the set to reduce cost.
    l1_hunter_set: tuple[str, ...] = ()
    # DAST-204 v0.0 (v1.1): proactive vulnerability discovery via the
    # hardcoded payload library in dast/discovery.py. Runs alongside
    # the standard DAST orchestrator (which only validates L1's
    # findings). When enabled, discovered findings get appended to
    # ``result.dast_findings`` with ``discovered_by="dast_discovery_v0"``.
    # Off by default — opt-in for users willing to spend extra DAST
    # cost (~$0.25/file) on top of the per-finding validation cost.
    enable_discovery: bool = False
    # Same trigger verdicts as DAST itself by default — only run
    # discovery on files L1 already found suspicious enough to test.
    discovery_trigger_verdicts: tuple[str, ...] = ("malicious", "critical_malicious")

    # Adjudication
    enable_adjudicator: bool = True
    adjudicator_model: str = "opus"  # only used on disagreement

    # v1.6 Fix #6: deterministic placeholder-value filter. When True
    # (default), drops L1 credential-class findings (CWE-798 / 312 /
    # 321 / 522 / 256) whose literal value matches universal developer
    # placeholder conventions (REPLACE_ME / TODO / DEMO_PLACEHOLDER /
    # ``<your-api-key>`` / ``${VAR}`` / changeme / etc.).
    # Pure pattern-match on the FINDING VALUE, not on file context —
    # generalizes to real customer codebases. Set False to disable
    # (e.g., on a codebase audit where you DO want every literal
    # surfaced, even if it looks like a placeholder).
    enable_placeholder_filter: bool = True

    # Cost guardrail
    max_cost_per_file_usd: float = 1.00  # safety cap; aborts if exceeded
    max_cost_per_scan_usd: float = 50.00


# ─── Scan result ──────────────────────────────────────────────────────────────


@dataclass
class ScanResult:
    """End-to-end scan result. Self-contained — caller doesn't need any
    other Argus module to interpret it.
    """

    filename: str
    file_hash: str
    language: str | None
    triage_classification: str  # CLEAN | LOW | HIGH
    triage_reason: str
    final_verdict: str  # clean | informational | suspicious | malicious | critical_malicious
    risk_score: int  # 0-100
    risk_level: str  # none | low | medium | high | critical

    # SCAN-013 v15.19 (2026-05-20) — file intent classification.
    #
    # Splits the verdict signal into two orthogonal axes that the
    # pre-v15.19 single-tier ladder conflated:
    #   * intent (this field): is the code itself a legitimate target,
    #     unknown-provenance, or an actively-malicious payload?
    #   * impact_severity (the existing risk_score / risk_level fields):
    #     how dangerous is the surface area?
    #
    # Values:
    #   * "legitimate" — library / glue / app code with no malware
    #     indicators. Phase 3 classified deployment_context as 'library'
    #     OR no malicious signals fired in behavioral_profile.
    #   * "malicious" — supply-chain attack / typosquat / obfuscated
    #     payload / reverse shell. Fired by obfuscation_signals,
    #     exfiltration_risk=high+, or future preprocessing flags.
    #   * "unknown" — signals insufficient to classify. Default when
    #     Phase 3 didn't run (file routed CLEAN/LOW from triage), or
    #     when neither legitimate nor malicious indicators fire.
    #
    # The adjudicator (engine.py final stage) consumes this field as a
    # CAP on final_verdict: when intent="legitimate", final_verdict
    # cannot land at malicious/critical_malicious regardless of L1 or
    # DAST CONFIRMs — those CONFIRMs become hardening-grade signal, not
    # exploitation evidence (the trust boundary makes them
    # developer-supplied / non-attacker-reachable).
    #
    # See SCAN-013 in tasks.md for the full split-ladder design. v15.19
    # is the Option-2 minimal-viable: ship the intent field + cap
    # without breaking final_verdict's existing format. The full
    # (intent, impact_severity) tuple landing in final_verdict's value
    # is a v1.0 release event.
    intent: str = "unknown"

    # Findings (vulnerabilities, behavioral observations)
    vulnerabilities: list[dict] = field(default_factory=list)
    behavioral_profile: dict = field(default_factory=dict)
    attack_chains: list[dict] = field(default_factory=list)
    ai_tool_analysis: dict = field(default_factory=dict)

    # v1.6 Fix #8a: L1's structured reasoning about the file's deployment
    # context, trust boundary, and powerful-by-design operations. Populated
    # when the L1 runner emits the new ``file_intent_analysis`` block.
    # Shape:
    #   {"purpose": str, "deployment_context": str, "trust_boundary": str,
    #    "powerful_by_design": list[str]}
    # Empty dict when the L1 output didn't populate it (older runs, models
    # that ignore the new schema field).
    file_intent_analysis: dict = field(default_factory=dict)

    # DAST
    dast_attempted: bool = False
    dast_findings: list[dict] = field(default_factory=list)
    dast_iterations: list[dict] = field(default_factory=list)
    # Tier 1 (v1.1): per-finding validation list — one entry per L1
    # vulnerability with status CONFIRMED | UNTESTED, derived from
    # dast_findings. Lets the launch report compute "Effective CWE F1"
    # by filtering to CONFIRMED-only findings.
    per_finding_validation: list[dict] = field(default_factory=list)

    # v1.2: Phase C — fix-and-verify result. None when DAST didn't run or
    # had no confirmed findings; otherwise a dict with patched_source,
    # fix_summary, post_patch_verdict, per_finding[NEUTRALIZED|STILL_EXPLOITABLE
    # |UNVERIFIABLE], n_neutralized, n_still_exploitable. See
    # dast.orchestrator._run_phase_c_fix_verify for the schema.
    phase_c: dict | None = None

    # Phase 3 Stage 1 (v1.6): RUNTIME behavioral exploration profile.
    # None when --enable-phase-3-discovery is off, the file is
    # non-Python, or the probe failed to produce a usable profile.
    # When populated, contains the serialized BehavioralProfile —
    # ``callables`` (per-callable observations), ``dataflow_hints``,
    # ``import_error``, ``callables_total/explored``, ``elapsed_ms``.
    # See dast.behavioral_probe.BehavioralProfile for the schema.
    # Stage 2 (adversarial reasoning loop) will consume this profile
    # to drive attack hypothesis generation; Stage 1 alone surfaces it
    # informationally so downstream tooling can see runtime behavior.
    #
    # Named ``runtime_behavioral_profile`` to disambiguate from the
    # pre-existing ``behavioral_profile`` field above (which holds
    # the STATIC-analysis behavioral profile produced by the Sonnet/
    # Opus cascade — different concept, different schema).
    runtime_behavioral_profile: dict | None = None

    # Phase 3 Stage 2 — adversarial reasoning loop summary. Populated by
    # the orchestrator when ``enable_phase_3_loop=True`` and the loop ran
    # (which requires Stage 1's behavioral profile to be present). Shape
    # matches DastResult.phase_3_loop — see dast.orchestrator for keys.
    # ``None`` when the loop didn't run (flag off, non-Python file, no
    # behavioral profile, or Stage 1 failed).
    phase_3_loop: dict | None = None

    # Phase 3 verdict resolver decision. Pure-function output combining
    # L1's static verdict with Phase 3's adversarial-loop summary using
    # sandbox coverage as the deciding signal. See
    # dast.verdict_resolver.VerdictResolverOutput.
    phase_3_resolver_decision: dict | None = None

    # Phase D (DAST-301/302) — variant analysis output. List of per-seed
    # PhaseDResult dicts (one entry per Phase-A-confirmed seed that ran
    # through the variant pipeline). Empty when Phase D was off, no
    # seeds were confirmed, or every seed skipped. See
    # dast.variant_runner.run_phase_d for entry shape.
    variant_analysis: list[dict] = field(default_factory=list)

    # Phase C multi-file patch (DAST-304) — coordinated remediation
    # across seed + confirmed variants. ``None`` when Phase D produced
    # no confirmed variants or multi-file patch was skipped.
    variant_remediation: dict | None = None

    # Telemetry
    scan_path: list[str] = field(default_factory=list)  # sequence of stages traversed
    model_calls: list[dict] = field(default_factory=list)  # per-call cost + latency
    total_cost_usd: float = 0.0
    total_duration_ms: int = 0
    ensemble_telemetry: dict | None = None

    status: int = 200
    error: str | None = None

    def to_dict(self) -> dict:
        """Serialize for JSON output / DB storage."""
        return {
            "filename": self.filename,
            "file_hash": self.file_hash,
            "language": self.language,
            "triage_classification": self.triage_classification,
            "triage_reason": self.triage_reason,
            "final_verdict": self.final_verdict,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            # SCAN-013 v15.19: file intent (legitimate / unknown /
            # malicious). See ScanResult.intent docstring.
            "intent": self.intent,
            "vulnerabilities": self.vulnerabilities,
            "behavioral_profile": self.behavioral_profile,
            "attack_chains": self.attack_chains,
            "ai_tool_analysis": self.ai_tool_analysis,
            "dast_attempted": self.dast_attempted,
            "dast_findings": self.dast_findings,
            "dast_iterations": self.dast_iterations,
            "per_finding_validation": self.per_finding_validation,
            "phase_c": self.phase_c,
            "runtime_behavioral_profile": self.runtime_behavioral_profile,
            "phase_3_loop": self.phase_3_loop,
            "phase_3_resolver_decision": self.phase_3_resolver_decision,
            "variant_analysis": self.variant_analysis,
            "variant_remediation": self.variant_remediation,
            "scan_path": self.scan_path,
            "model_calls": self.model_calls,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "total_duration_ms": self.total_duration_ms,
            "ensemble_telemetry": self.ensemble_telemetry,
            "status": self.status,
            "error": self.error,
        }


# ─── Helper: high-stakes detection ───────────────────────────────────────────


def is_high_stakes(pp: Preprocessing, categories: tuple[str, ...]) -> tuple[bool, list[str]]:
    """Return (is_high_stakes, list_of_triggered_categories).

    The categories tuple lists Preprocessing field names that, when
    truthy, indicate a high-stakes file — Opus is justified.
    """
    triggered: list[str] = []
    for cat in categories:
        v = getattr(pp, cat, None)
        # Treat any truthy field as a trigger:
        # bool True, non-empty str, non-empty list/dict
        if v:
            triggered.append(cat)
    # ``obfuscation_detected`` is nested in pp.obfuscation — special-case it
    if "obfuscation_detected" in categories:
        ob = getattr(pp, "obfuscation", None)
        if ob and getattr(ob, "detected", False):
            if "obfuscation_detected" not in triggered:
                triggered.append("obfuscation_detected")
    return bool(triggered), triggered


# ─── Helper: verdict mapping ─────────────────────────────────────────────────


_VERDICT_TO_RISK = {
    "clean": (0, "none"),
    "informational": (15, "low"),
    "suspicious": (45, "medium"),
    "malicious": (75, "high"),
    "critical_malicious": (95, "critical"),
}


def verdict_to_risk(verdict: str) -> tuple[int, str]:
    return _VERDICT_TO_RISK.get(verdict, (50, "medium"))


# SCAN-013 v15.19 — intent classification & cap.
#
# These helpers derive the file's intent (legitimate / unknown /
# malicious) from signals already produced by the cascade, then apply
# a verdict cap that prevents legitimate library code from landing as
# malicious/critical_malicious. See ScanResult.intent docstring for the
# axis split and tasks.md SCAN-013 for the full design (Option 2
# minimal-viable: intent field + adjudicator cap, no final_verdict
# format change yet).


def _has_external_network_dataflow(result: ScanResult) -> bool:
    """v15.21 data-flow gate.

    Returns True when the cascade has evidence that the file makes
    network calls OUT to external hosts — meaning the trust boundary
    isn't purely developer-controlled even if Phase 3 said
    ``LIBRARY_CONSUMER``. In that case the intent cap should not
    apply: the network egress could be the attack vector itself, and
    silently downgrading hides exposure.

    Sources of network-flow evidence:
      * behavioral_profile.network_attempts — L1 sets this when
        static analysis spots outbound calls (requests.get, httpx,
        urllib, socket.connect, etc.). Could be a dict (count >0),
        list (non-empty), or bool (True).
      * behavioral_profile.exfiltration_risk.level — already used
        for the malicious-intent signal at higher levels; medium
        also counts as "external data flow present" for the cap
        gate (worth surfacing, not capping).
      * runtime_behavioral_profile.network_attempts — Phase A's
        observed runtime calls. Strongest signal because it's the
        sandbox actually attempting egress.

    Loopback / localhost calls don't count — those are internal
    plumbing, not external surface. The detector accepts an explicit
    ``external=True`` field on the network_attempts entries when
    present; otherwise treats any non-empty network_attempts as
    "potentially external" (conservative — defaults to NOT capping).
    """
    bp = result.behavioral_profile or {}
    rbp = result.runtime_behavioral_profile or {}

    for src in (bp, rbp):
        na = src.get("network_attempts")
        if isinstance(na, bool) and na:
            return True
        if isinstance(na, (list, tuple)) and len(na) > 0:
            return True
        if isinstance(na, dict):
            if na.get("count") and int(na.get("count") or 0) > 0:
                return True
            if na.get("attempts") and len(na["attempts"]) > 0:
                return True

    exf = bp.get("exfiltration_risk")
    if isinstance(exf, dict):
        exf_level = str(exf.get("level") or "").lower()
    else:
        exf_level = str(exf or "").lower()
    if exf_level in ("medium", "high", "critical"):
        return True

    return False


def _classify_file_intent(result: ScanResult) -> str:
    """Derive intent ∈ {legitimate, unknown, malicious} from cascade
    signals.

    Decision tree (highest priority first):

    1. Malicious-intent signals (override everything else): explicit
       behavioral_profile fields that the L1 prompts populate when they
       detect supply-chain / typosquat / payload patterns. These are
       precision-tuned — if any fires, the file is treated as malicious
       intent regardless of Phase 3's later "library" classification.
       (Defensive: a real-malware payload that pretends to be library
       code shouldn't escape via the legitimate cap.)

    2. v15.21 — Explicit ``trust_boundary_class`` enum from Phase 3:
         * EXTERNAL_UNTRUSTED → "unknown" (full attack surface; don't cap)
         * INTERNAL_DEVELOPER → "legitimate" (admin/CLI/setup code)
         * LIBRARY_CONSUMER   → "legitimate" (library API surface)
       AND v15.21 data-flow gate: even when Phase 3 says
       INTERNAL_DEVELOPER / LIBRARY_CONSUMER, if behavioral_profile
       shows external network egress evidence the cap is suppressed
       (intent flips back to "unknown" — keep the verdict). Closes
       Gemini's Issue 2d: "if TrustBoundary == INTERNAL_DEVELOPER (and
       no network-facing data flow exists), apply the cap."

    3. Backwards-compat fallback (pre-v15.21 scans without the explicit
       enum): use ``deployment_context == 'library'`` as a soft
       proxy. Same data-flow gate applies.

    4. Otherwise: "unknown". Triage-CLEAN files that never reach Phase
       3 land here by default — preserves existing verdict behavior
       (no cap applied; intent is informational only).

    Strict ordering matters: a file that Phase 3 calls "library" but
    ALSO has obfuscation_signals firing is treated as malicious intent.
    The model's intent classification doesn't get to override
    deterministic supply-chain signals.
    """
    # --- 1. Malicious-intent signals (deterministic) ---------------------
    bp = result.behavioral_profile or {}
    obf = bp.get("obfuscation_signals")
    if isinstance(obf, dict) and obf.get("present") is True:
        return "malicious"
    if isinstance(obf, list) and len(obf) > 0:
        return "malicious"
    exf = bp.get("exfiltration_risk")
    if isinstance(exf, dict):
        exf_level = str(exf.get("level") or "").lower()
    else:
        exf_level = str(exf or "").lower()
    if exf_level in ("high", "critical"):
        return "malicious"

    # --- 2/3. Phase 3 intent (explicit enum first, deployment_context
    # fallback). Both paths subject to the v15.21 data-flow gate.
    p3 = result.phase_3_loop or {}
    intents = p3.get("code_intent_analysis_per_turn") or []
    last_intent = None
    for entry in reversed(intents):
        if isinstance(entry, dict):
            last_intent = entry
            break

    if last_intent is not None:
        # v15.21 — explicit TrustBoundary enum (preferred).
        tb_class = str(last_intent.get("trust_boundary_class") or "").upper()
        if tb_class == "EXTERNAL_UNTRUSTED":
            # Full attack surface — don't cap.
            return "unknown"
        if tb_class in ("INTERNAL_DEVELOPER", "LIBRARY_CONSUMER"):
            # Gate the legitimate classification on the absence of
            # external network-facing data flow. If the file is
            # library-looking BUT has confirmed network egress, the
            # cap is suppressed (data could be exfiltrating).
            if _has_external_network_dataflow(result):
                return "unknown"
            return "legitimate"

        # Backwards-compat fallback: pre-v15.21 schema (no explicit
        # ``trust_boundary_class``). Use ``deployment_context``
        # proxy with the same data-flow gate.
        dep_ctx = str(last_intent.get("deployment_context") or "").lower()
        if dep_ctx == "library":
            if _has_external_network_dataflow(result):
                return "unknown"
            return "legitimate"

    # --- 4. Default ------------------------------------------------------
    return "unknown"


def _apply_intent_cap(result: ScanResult) -> None:
    """Apply the intent cap to final_verdict in place.

    Rules:
    * intent="legitimate":
        - cap final_verdict at "suspicious" (no malicious/
          critical_malicious for library code).
        - if no CONFIRMED runtime evidence (Phase A/B+/3 produced no
          CONFIRMED finding), further downgrade suspicious to
          "informational" — pure static hardening signal.
    * intent="unknown" / "malicious": no cap applied (pre-v15.19
      behavior preserved).

    Mutates ``result.final_verdict``, ``result.risk_score``,
    ``result.risk_level``, and appends a scan_path entry documenting
    the cap.
    """
    if result.intent != "legitimate":
        return

    original = result.final_verdict
    if original not in ("malicious", "critical_malicious", "suspicious"):
        return  # already clean/informational — nothing to cap

    # Runtime evidence = DAST-discovered findings (HRP_*, HRP_AL_*,
    # HRP_C*) that landed CONFIRMED. L1's H### CONFIRMED status comes
    # from journal-logic auto-confirms that don't always mean DAST
    # actually probed the finding; for library-trust-boundary code we
    # only treat genuine DAST discoveries as runtime evidence worth
    # holding suspicious for. Pure-static H### CONFIRMs collapse to
    # informational under intent=legitimate.
    has_confirmed_runtime = any(
        isinstance(pf, dict)
        and str(pf.get("status") or "") == "CONFIRMED"
        and str(pf.get("finding_id") or "").startswith("HRP")
        for pf in (result.per_finding_validation or [])
    )
    # Also check dast_findings as a fallback signal — pre-v15.17 paths
    # populated dast_findings even when per_finding_validation didn't
    # carry CONFIRMED entries for them.
    if not has_confirmed_runtime:
        has_confirmed_runtime = any(
            isinstance(f, dict)
            and str(f.get("status") or "").upper() == "CONFIRMED"
            for f in (result.dast_findings or [])
        )

    if original in ("malicious", "critical_malicious"):
        # Always cap library code at suspicious — even with confirmed
        # runtime evidence. The CONFIRMs become "exploit primitive
        # exists when developer passes attacker-controlled input" =
        # hardening signal, not malware classification.
        new_verdict = "suspicious"
    elif original == "suspicious":
        # If no runtime CONFIRM backs the suspicion → it's a static
        # hardening flag on library code. Downgrade to informational.
        new_verdict = "suspicious" if has_confirmed_runtime else "informational"
    else:
        return

    if new_verdict != original:
        result.final_verdict = new_verdict
        result.risk_score, result.risk_level = verdict_to_risk(new_verdict)
        result.scan_path.append(
            f"intent_cap:legitimate:{original}->{new_verdict}"
            f"{':confirmed_runtime' if has_confirmed_runtime else ':static_only'}"
        )


# SCAN-014 v15.29 — findings-floor invariant.
#
# Closes the "clean + findings" UX contradiction caught on
# openai-python's lib/azure.py (2026-05-20):
#
#     triage=HIGH, 3 L1 findings (CWE-22 path_traversal conf=0.38,
#     CWE-918 ssrf conf=0.35, CWE-209 data_exfil conf=0.45), all
#     NOT_TESTED, intent=unknown → final_verdict=clean.
#
# Root cause: v1.9.2's undercall_backstop only promotes clean->
# suspicious when severity>=medium AND confidence>=0.4. Findings with
# 0.35-0.39 confidence fall through, leaving the user looking at a
# verdict that says "no risk" alongside three CWE findings the
# report still renders.
#
# Invariant: ``final_verdict == "clean"`` MUST mean the report shows
# zero ACTIVE findings. An active finding is one DAST hasn't refuted:
# CONFIRMED or NOT_TESTED (we genuinely don't know) — REJECTED /
# BLOCKED / UNREACHED / SUPPRESSED count as inactive because the
# cascade produced sandbox-grounded evidence the finding doesn't fire.
#
# Cost discipline: the floor lifts the verdict label only — it does
# NOT auto-trigger DAST. Operators who want DAST verification on these
# files can set ``--dast-trigger-verdicts informational,suspicious``
# OR use the confidence gate from cfg.dast_trigger_on_finding_confidence.
def _apply_finding_floor(result: ScanResult) -> None:
    """Lift final_verdict so ``clean`` always means zero active findings.

    Rules:
      * 0 active findings → no change.
      * Any active finding with severity in {medium, high, critical}
        AND verdict in {clean, informational} → bump to ``suspicious``.
      * Any active finding (severity=low only) AND verdict == clean
        → bump to ``informational``.
      * Never downgrades.

    Skipped when ``intent == "legitimate"`` — ``_apply_intent_cap`` is
    authoritative for library code and its informational/clean
    downgrades reflect a deliberate "static-only on legitimate library"
    decision the floor would otherwise undo.

    Runs as Stage 9.5 — after Stage 9's per_finding_validation
    backfill so every vulnerability carries a status label the floor
    can read.
    """
    if result.intent == "legitimate":
        return  # intent_cap is the boss for library code

    vulns = result.vulnerabilities or []
    if not vulns:
        return

    inactive_statuses = {"REJECTED", "BLOCKED", "UNREACHED", "SUPPRESSED"}
    pfv = result.per_finding_validation or []
    status_by_idx = {
        i: str((p or {}).get("status") or "") for i, p in enumerate(pfv)
    }

    severity_ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    max_active_sev = 0
    n_active = 0

    for i, v in enumerate(vulns):
        status = status_by_idx.get(i, "")
        if status in inactive_statuses:
            continue
        n_active += 1
        if isinstance(v, dict):
            sev = (v.get("severity") or "").lower().strip()
        else:
            sev = (getattr(v, "severity", "") or "").lower().strip()
        max_active_sev = max(max_active_sev, severity_ranks.get(sev, 0))

    if n_active == 0:
        return

    original = result.final_verdict
    new_verdict = original

    if max_active_sev >= 2 and original in ("clean", "informational"):
        new_verdict = "suspicious"
    elif original == "clean":
        new_verdict = "informational"

    if new_verdict != original:
        result.final_verdict = new_verdict
        result.risk_score, result.risk_level = verdict_to_risk(new_verdict)
        result.scan_path.append(
            f"finding_floor:{original}->{new_verdict}:"
            f"{n_active}_active_max_sev={max_active_sev}"
        )


# ─── Helper: cost guardrail ──────────────────────────────────────────────────


def _check_cost_cap(
    result: ScanResult,
    cfg: ScanConfig,
    stage_just_completed: str,
) -> bool:
    """Return True if the per-file cost cap was just breached.

    Inspects ``result.total_cost_usd`` against ``cfg.max_cost_per_file_usd``
    after each model-call's cost has been added. On breach, records the
    abort in ``result.error`` and ``result.scan_path``; caller should
    short-circuit. Telemetry stays intact — partial results are still
    returnable so the user sees what was paid for.

    Per-scan caps (multi-file) are enforced one layer up; ``scan_file``
    only sees one file at a time.
    """
    cap = cfg.max_cost_per_file_usd
    if cap is None or cap <= 0:
        return False
    if result.total_cost_usd <= cap:
        return False
    result.scan_path.append(
        f"cost_cap_exceeded_after:{stage_just_completed}({result.total_cost_usd:.4f}>{cap:.2f})"
    )
    result.error = (
        f"cost_cap_exceeded: ${result.total_cost_usd:.4f} > "
        f"${cap:.2f} after {stage_just_completed} stage"
    )
    result.status = 402  # Payment Required — fits the semantics
    return True


# ─── Main entry point ─────────────────────────────────────────────────────────


async def scan_file(
    filename: str,
    content: bytes,
    *,
    config: ScanConfig | None = None,
    triage_runner: Any = None,
    sonnet_runner: Any = None,
    opus_runner: Any = None,
    sonnet_runner_split: Any = None,
    opus_runner_split: Any = None,
    sonnet_runner_hunter: Any = None,
    opus_runner_hunter: Any = None,
    dast_runner: Any = None,
    host_path: str | None = None,
) -> ScanResult:
    """Argus end-to-end scan. Returns a ``ScanResult`` regardless of
    success/failure — failures populate ``error`` and ``status``.

    The four ``*_runner`` parameters are injected callables that wrap the
    actual model / sandbox calls. This keeps ``engine.py`` model-agnostic
    and unit-testable. Production callers wire them to:

      * ``triage_runner``: ``inference.adapters.GoogleAdapter.scan(...)``
        with TRIAGE_PROMPT (Gemini Flash-Lite)
      * ``sonnet_runner``: ``AnthropicAdapter.scan(...)`` with the
        combined SCAN_PROMPT_VULNS + BEHAVIORAL + CHAINS
      * ``opus_runner``:   same shape, claude-opus-4-6 model_id
      * ``dast_runner``:   ``dast.orchestrator.run_dast(...)`` with a
        constructed sandbox client + validator + journal

    ``host_path`` (v11, 2026-05-17): optional full filesystem path to
    the entry file on the host. ``filename`` itself is conventionally
    a basename (used as result display name + sandbox staging path),
    so it can't be used to read sibling files for multi-file project
    staging. CLI callers pass ``host_path=str(file_path)`` so the
    DAST runner's sibling-file resolver can walk the project tree on
    disk. When unset (default), multi-file staging is skipped — single-
    file behavior matches v10.

    During scaffolding, callers pass stubs that return canned results.
    See ``tests/unit/test_engine_smoke.py`` for the stub pattern.
    """
    cfg = config or ScanConfig()
    import time

    t_start = time.time()

    result = ScanResult(
        filename=filename,
        file_hash="",
        language=None,
        triage_classification="",
        triage_reason="",
        final_verdict="suspicious",  # safe default; overwritten below
        risk_score=50,
        risk_level="medium",
    )

    # ── Stage 1: preprocessing ────────────────────────────────────────
    try:
        bundle = preprocess_file(filename, content)
        pp = bundle.preprocessing
        result.file_hash = pp.file_hash or ""
        result.language = pp.detected_language
        result.scan_path.append("preprocessing")

        # JS string-array deobfuscation (PREP-014, public sync): swap the
        # raw obfuscator.io payload for webcrack's deobfuscated output
        # before the model sees it. Narrow gate — only on this technique
        # — so existing Python deobfuscation behavior is untouched.
        # Without this swap the model still receives the 1.5 M-token
        # obfuscated blob and rejects it past the 1 M context cap.
        # Lazy import to avoid circular dependency at module import time.
        from shared.types.enums import ObfuscationTechnique  # noqa: PLC0415

        if ObfuscationTechnique.JS_STRING_ARRAY in bundle.obfuscation_techniques:
            content = bundle.decoded_content.encode("utf-8")
            result.scan_path.append("js_string_array_deobfuscation")

        # Short-circuit on known-malware hash
        if pp.known_malware_match:
            result.triage_classification = "HIGH"
            result.triage_reason = f"Known-malware hash match: {pp.known_malware_match}"
            result.final_verdict = "critical_malicious"
            result.risk_score, result.risk_level = verdict_to_risk("critical_malicious")
            result.scan_path.append("known_malware_short_circuit")
            result.total_duration_ms = int((time.time() - t_start) * 1000)
            return result
    except Exception as e:  # noqa: BLE001
        result.error = f"preprocessing_failure: {type(e).__name__}: {e}"
        result.status = 500
        result.total_duration_ms = int((time.time() - t_start) * 1000)
        return result

    # ── Stage 2: high-stakes detection (informs cascade routing) ──────
    high_stakes, triggered_cats = is_high_stakes(pp, cfg.high_stakes_categories)
    result.scan_path.append(
        f"high_stakes={high_stakes}{(':' + ','.join(triggered_cats)) if triggered_cats else ''}"
    )

    # ── Stage 3: triage ────────────────────────────────────────────────
    if triage_runner is None:
        # No triage wired — default to HIGH so we always get deep analysis.
        # Production wiring should always provide a triage_runner.
        classification = "HIGH"
        triage_reason = "No triage_runner wired — defaulting to HIGH"
    else:
        try:
            # Caller-provided runner returns dict with 'classification' and 'reason'
            triage_out = await triage_runner(filename, content, pp)
            classification = (triage_out or {}).get("classification", "HIGH")
            triage_reason = (triage_out or {}).get("reason", "")
            result.scan_path.append(f"triage:{classification}")
            result.model_calls.append(
                {
                    "stage": "triage",
                    "model": (triage_out or {}).get("model", "unknown"),
                    "input_tokens": (triage_out or {}).get("input_tokens", 0),
                    "output_tokens": (triage_out or {}).get("output_tokens", 0),
                    "cost_usd": (triage_out or {}).get("cost_usd", 0.0),
                    "duration_ms": (triage_out or {}).get("duration_ms", 0),
                }
            )
            result.total_cost_usd += (triage_out or {}).get("cost_usd", 0.0)
            if _check_cost_cap(result, cfg, "triage"):
                result.total_duration_ms = int((time.time() - t_start) * 1000)
                return result
        except Exception as e:  # noqa: BLE001
            log.warning("Triage failed on %s: %s — defaulting to HIGH", filename, e)
            classification = "HIGH"
            triage_reason = f"Triage failed ({type(e).__name__}); defaulting to HIGH"

    # ── Stage 4: deterministic safety net ──────────────────────────────
    # If preprocessing flagged a high-stakes category but triage said
    # CLEAN or LOW, override to HIGH. False-negative cost > false-
    # positive cost; the cascade still keeps cheap files cheap.
    if cfg.enable_triage_safety_net and high_stakes and classification != "HIGH":
        original = classification
        classification = "HIGH"
        triage_reason = (
            f"{triage_reason} [safety_net: {original}→HIGH triggered by {','.join(triggered_cats)}]"
        )
        result.scan_path.append(f"safety_net_override:{original}->HIGH")

    result.triage_classification = classification
    result.triage_reason = triage_reason

    # ── Stage 5: cascade routing ───────────────────────────────────────
    # v15 debug bypass: when ``force_dast_through_clean`` is set, treat
    # CLEAN as LOW for routing so the full L1 + DAST cascade runs. The
    # triage_classification field is preserved (still reports CLEAN)
    # so observability isn't lost. Costs ~$0.05-0.50 per file vs the
    # normal short-circuit's $0.001.
    if classification == "CLEAN" and cfg.force_dast_through_clean:
        result.scan_path.append("force_dast:CLEAN->LOW")
        classification = "LOW"  # local routing only; result field unchanged

    if classification == "CLEAN":
        result.final_verdict = "clean"
        result.risk_score, result.risk_level = verdict_to_risk("clean")
        result.scan_path.append("clean_short_circuit")
        result.total_duration_ms = int((time.time() - t_start) * 1000)
        return result

    # LOW: route to a cheap model (Gemini Flash in production)
    # HIGH: route to Sonnet, escalate to Opus on borderline / high-stakes
    chosen_runner: Any = None
    chosen_model_label: str = ""

    if classification == "LOW":
        chosen_runner = sonnet_runner  # falls back to Sonnet if no separate Flash runner; production wires Gemini Flash here
        chosen_model_label = "low_path"
    else:  # HIGH
        if high_stakes and opus_runner is not None:
            # high-stakes goes directly to Opus for the deep behavioral
            chosen_runner = opus_runner
            chosen_model_label = "opus_high_stakes"
        else:
            chosen_runner = sonnet_runner
            chosen_model_label = "sonnet_default"

    # SCAN-010: split-L1 dispatch. When the operator opted into split
    # mode AND the current triage classification matches the gate set
    # AND the corresponding split runner is wired, swap the combined
    # runner for its split sibling. Falls through silently to combined
    # when no split runner is wired (older callers / tests) — preserves
    # back-compat for every code path that doesn't opt in.
    if (
        cfg.l1_split_enabled
        and classification in cfg.l1_split_on_triage
    ):
        if chosen_runner is opus_runner and opus_runner_split is not None:
            chosen_runner = opus_runner_split
            chosen_model_label = chosen_model_label.replace("opus", "opus_split")
        elif chosen_runner is sonnet_runner and sonnet_runner_split is not None:
            chosen_runner = sonnet_runner_split
            chosen_model_label = chosen_model_label.replace("sonnet", "sonnet_split")

    # SCAN-011 hunter dispatch. Layered on top of SCAN-010: when
    # l1_hunter_enabled=True AND the triage classification is in the
    # gate set AND a hunter runner is wired, the hunter runner takes
    # priority over both combined and split runners. The hunter runner
    # internally still calls BEHAVIORAL + CHAINS via the SCAN-010 split
    # path; it ONLY replaces the single VULNS slot with N parallel
    # attack-class hunters. Falls through to split (or combined) when
    # no hunter runner is wired.
    if (
        cfg.l1_hunter_enabled
        and classification in cfg.l1_split_on_triage  # same gate set as split
    ):
        if chosen_runner is opus_runner_split and opus_runner_hunter is not None:
            chosen_runner = opus_runner_hunter
            chosen_model_label = chosen_model_label.replace("opus_split", "opus_hunter")
        elif chosen_runner is sonnet_runner_split and sonnet_runner_hunter is not None:
            chosen_runner = sonnet_runner_hunter
            chosen_model_label = chosen_model_label.replace("sonnet_split", "sonnet_hunter")
        elif chosen_runner is opus_runner and opus_runner_hunter is not None:
            # Hunter enabled but split not — promote directly from
            # combined to hunter. Edge case (operator set hunter flag
            # but not split flag); hunter internally does the split
            # call shape so this works.
            chosen_runner = opus_runner_hunter
            chosen_model_label = chosen_model_label.replace("opus", "opus_hunter")
        elif chosen_runner is sonnet_runner and sonnet_runner_hunter is not None:
            chosen_runner = sonnet_runner_hunter
            chosen_model_label = chosen_model_label.replace("sonnet", "sonnet_hunter")

    if chosen_runner is None:
        result.error = "no_analysis_runner_wired"
        result.status = 503
        result.total_duration_ms = int((time.time() - t_start) * 1000)
        return result

    try:
        analysis_out = await chosen_runner(filename, content, pp, classification)
        result.scan_path.append(f"analysis:{chosen_model_label}")
        result.vulnerabilities = (analysis_out or {}).get("vulnerabilities", [])
        result.behavioral_profile = (analysis_out or {}).get("behavioral_profile", {})
        result.attack_chains = (analysis_out or {}).get("attack_chains", [])
        result.ai_tool_analysis = (analysis_out or {}).get("ai_tool_analysis", {})
        result.file_intent_analysis = (analysis_out or {}).get(
            "file_intent_analysis", {}
        )  # v1.6 Fix #8a
        result.final_verdict = (analysis_out or {}).get("verdict_label", "suspicious")
        result.risk_score, result.risk_level = verdict_to_risk(result.final_verdict)

        result.model_calls.append(
            {
                "stage": "analysis",
                "model": (analysis_out or {}).get("model", chosen_model_label),
                "input_tokens": (analysis_out or {}).get("input_tokens", 0),
                "output_tokens": (analysis_out or {}).get("output_tokens", 0),
                "cost_usd": (analysis_out or {}).get("cost_usd", 0.0),
                "duration_ms": (analysis_out or {}).get("duration_ms", 0),
                "uncertainty": (analysis_out or {}).get("uncertainty", 0.0),
            }
        )
        result.total_cost_usd += (analysis_out or {}).get("cost_usd", 0.0)
        if _check_cost_cap(result, cfg, "analysis"):
            result.total_duration_ms = int((time.time() - t_start) * 1000)
            return result
    except Exception as e:  # noqa: BLE001
        result.error = f"analysis_failure: {type(e).__name__}: {e}"
        result.status = 500
        result.total_duration_ms = int((time.time() - t_start) * 1000)
        return result

    # ── Stage 6: ensemble re-verdict on borderline ────────────────────
    # If Sonnet's uncertainty is high AND it didn't already escalate to
    # Opus, run an N=3 ensemble.
    uncertainty = result.model_calls[-1].get("uncertainty", 0.0)
    if (
        cfg.enable_cascade
        and uncertainty > cfg.sonnet_uncertainty_threshold
        and chosen_model_label != "opus_high_stakes"
        and opus_runner is not None
    ):
        result.scan_path.append("escalate_to_opus")
        try:
            opus_out = await opus_runner(filename, content, pp, classification)
            # Opus's verdict overrides Sonnet's
            result.final_verdict = (opus_out or {}).get("verdict_label", result.final_verdict)
            result.risk_score, result.risk_level = verdict_to_risk(result.final_verdict)
            # Merge findings — Opus's are authoritative if present
            if (opus_out or {}).get("vulnerabilities"):
                result.vulnerabilities = opus_out["vulnerabilities"]
            if (opus_out or {}).get("behavioral_profile"):
                result.behavioral_profile = opus_out["behavioral_profile"]
            if (opus_out or {}).get("file_intent_analysis"):
                # v1.6 Fix #8a: Opus override propagates intent analysis too.
                result.file_intent_analysis = opus_out["file_intent_analysis"]
            result.model_calls.append(
                {
                    "stage": "analysis_escalation",
                    "model": "opus",
                    "input_tokens": (opus_out or {}).get("input_tokens", 0),
                    "output_tokens": (opus_out or {}).get("output_tokens", 0),
                    "cost_usd": (opus_out or {}).get("cost_usd", 0.0),
                    "duration_ms": (opus_out or {}).get("duration_ms", 0),
                }
            )
            result.total_cost_usd += (opus_out or {}).get("cost_usd", 0.0)
            if _check_cost_cap(result, cfg, "opus_escalation"):
                result.total_duration_ms = int((time.time() - t_start) * 1000)
                return result
        except Exception as e:  # noqa: BLE001
            log.warning("Opus escalation failed for %s: %s", filename, e)
            # Keep Sonnet's verdict; record the failure
            result.scan_path.append(f"opus_escalation_failed:{type(e).__name__}")

    # ── Stage 6.5: placeholder-value filter (v1.6 Fix #6) ──────────────
    # Drop credential-class findings whose literal value is a developer
    # placeholder (REPLACE_ME / TODO / DEMO_PLACEHOLDER / your-api-key /
    # ${VAR} / etc.). Gemini 3.1 Pro adjudication of the v1.6 bench
    # called out 3+ over-claims where L1 flagged DEMO_PLACEHOLDER_TOKEN
    # or similar as a hardcoded credential.
    #
    # Deterministic + conservative: only fires on credential-class CWEs
    # (CWE-798/312/321/522/256). Non-credential findings pass through
    # untouched. Pattern-matches on universal developer conventions
    # that appear in every codebase — not bench-specific markers.
    if cfg.enable_placeholder_filter and result.vulnerabilities:
        from scanner.placeholder_filter import filter_placeholder_findings

        kept, dropped = filter_placeholder_findings(result.vulnerabilities)
        if dropped:
            result.vulnerabilities = kept
            result.scan_path.append(f"placeholder_filter:dropped_{len(dropped)}")

    # ── Stage 6.6: anti-undercall backstop (v1.9) ──────────────────────
    # Defense-in-depth against the SCAN-010 split-L1 regression where the
    # VULNS sub-call would emit vulnerabilities + composite_risk.score=0
    # because it didn't see the behavioral context needed to score INTENT.
    # The runner-side max-aggregation (scanner/runners.py) and the
    # anti-undercall rule in the system prompt are the first two layers;
    # this is the third, contract-level check.
    #
    # Rule: if any surviving vulnerability has severity in
    # {critical, high, medium} AND confidence >= 0.4 (default —
    # configurable via ``undercall_backstop_min_confidence``), the
    # file CANNOT be verdict=clean. Promote to ``suspicious`` (lower-
    # mid of the vulnerable-but-not-malicious band, per
    # SCAN_REASONING_RULES).
    # Never promotes past suspicious — that requires intent evidence
    # the model is best positioned to score.
    #
    # Deterministic + idempotent — safe to run alongside any future
    # verdict-adjudication code in DAST or remediation. Logs to
    # scan_path so the upgrade is auditable.
    if cfg.enable_undercall_backstop and result.final_verdict == "clean":
        _MEDIUM_PLUS = {"critical", "high", "medium"}
        backstop_threshold = cfg.undercall_backstop_min_confidence
        for v in (result.vulnerabilities or []):
            if isinstance(v, dict):
                raw_sev = (v.get("severity") or "").lower().strip()
                raw_conf = v.get("confidence", 0)
            else:
                raw_sev = (getattr(v, "severity", "") or "").lower().strip()
                raw_conf = getattr(v, "confidence", 0)
            try:
                conf = float(raw_conf or 0)
            except (TypeError, ValueError):
                conf = 0.0
            if raw_sev in _MEDIUM_PLUS and conf >= backstop_threshold:
                result.final_verdict = "suspicious"
                result.risk_score, result.risk_level = verdict_to_risk("suspicious")
                result.scan_path.append(
                    f"undercall_backstop:promoted_clean->suspicious"
                    f"_on_{raw_sev}_finding"
                )
                break

    # ── Stage 7: DAST verification ─────────────────────────────────────
    # DAST fires when either:
    #   (a) the rolled-up verdict is in ``dast_trigger_verdicts``
    #       (the default v1.7-v1.8 gate), OR
    #   (b) ``dast_trigger_on_finding_confidence`` is set AND any L1
    #       vulnerability has confidence >= that threshold. Lets
    #       operators run DAST on hand-curated leads (DAST-303 cross-
    #       repo flow, manual audits) even when verdict aggregation
    #       rolled down to ``suspicious`` or ``clean``.
    _verdict_gate = result.final_verdict in cfg.dast_trigger_verdicts
    _finding_gate = False
    if cfg.dast_trigger_on_finding_confidence is not None:
        threshold = float(cfg.dast_trigger_on_finding_confidence)
        for v in (result.vulnerabilities or []):
            # vulnerabilities come in as either Vulnerability
            # dataclass instances OR raw dicts (test stubs +
            # serialised cache hits). Handle both.
            if isinstance(v, dict):
                raw_conf = v.get("confidence", 0)
            else:
                raw_conf = getattr(v, "confidence", 0)
            try:
                conf = float(raw_conf or 0)
            except (TypeError, ValueError):
                conf = 0.0
            if conf >= threshold:
                _finding_gate = True
                break
    if (
        cfg.enable_dast
        and (_verdict_gate or _finding_gate)
        and dast_runner is not None
    ):
        if _finding_gate and not _verdict_gate:
            result.scan_path.append("dast_trigger:finding_confidence")
        try:
            l1_verdict = result.final_verdict
            dast_out = await dast_runner(
                filename,
                content,
                pp,
                result,
                enable_phase_c=cfg.enable_phase_c,
                enable_runtime_probe=cfg.enable_runtime_probe,
                enable_runtime_probe_mutation=cfg.enable_runtime_probe_mutation,
                enable_runtime_probe_iterative=cfg.enable_runtime_probe_iterative,
                enable_runtime_probe_chains=cfg.enable_runtime_probe_chains,
                enable_phase_3_discovery=cfg.enable_phase_3_discovery,
                enable_phase_3_loop=cfg.enable_phase_3_loop,
                phase_3_loop_max_turns=cfg.phase_3_loop_max_turns,
                enable_phase_d=cfg.enable_phase_d,
                enable_remediation_verify=cfg.enable_remediation_verify,
                enable_per_scan_dep_install=cfg.enable_per_scan_dep_install,
                enable_coverage_dedupe=cfg.enable_coverage_dedupe,
                host_path=host_path,
            )
            result.dast_attempted = True
            result.dast_findings = (dast_out or {}).get("validated_findings", [])
            result.dast_iterations = (dast_out or {}).get("iterations", [])
            # v1.2: Phase C — fix-and-verify result, surfaced from
            # dast.orchestrator. None if Phase C didn't run.
            result.phase_c = (dast_out or {}).get("phase_c")
            # Phase 3 Stage 1 (v1.6): RUNTIME behavioral profile,
            # surfaced from dast.orchestrator. None if
            # --enable-phase-3-discovery was off, the file was
            # non-Python, or the probe didn't produce a usable profile.
            # Note: distinct field from ``behavioral_profile`` which
            # holds the STATIC-analysis output from the cascade.
            result.runtime_behavioral_profile = (dast_out or {}).get("runtime_behavioral_profile")
            # Phase 3 Stage 2 (v1.6): adversarial reasoning loop summary
            # + verdict-resolver decision. Both forwarded verbatim from
            # DastResult so downstream consumers (report, SARIF, bench)
            # can attribute verdicts to phase_3_confirmed/clean/etc and
            # inspect each hypothesis's outcome.
            result.phase_3_loop = (dast_out or {}).get("phase_3_loop")
            result.phase_3_resolver_decision = (dast_out or {}).get("phase_3_resolver_decision")
            # Phase D (DAST-301/302) + multi-file Phase C patch
            # (DAST-304). ``variant_analysis`` is a list of per-seed
            # PhaseDResult dicts; empty when the flag was off or no
            # confirmed seeds. ``variant_remediation`` is the multi-file
            # patch result; None when Phase D didn't confirm variants.
            result.variant_analysis = list((dast_out or {}).get("variant_analysis") or [])
            result.variant_remediation = (dast_out or {}).get("variant_remediation")
            dast_verdict = (dast_out or {}).get("final_verdict", {}).get("verdict_label")

            # Tier 1.5 (v1.1): derive per-finding validation by zipping
            # L1 vulnerabilities with DAST's validated_findings list AND
            # the journal records (for classification of rejected
            # hypotheses into BLOCKED / UNREACHED via rationale text).
            # Each L1 finding gets status CONFIRMED (DAST hypothesis
            # accepted) / BLOCKED (rejected with sanitization reasoning)
            # / UNREACHED (rejected with unreachable reasoning) /
            # NOT_TESTED (no journal entry or other rejection).
            from dast.per_finding import derive_per_finding_validation

            journal_records = (dast_out or {}).get("journal_records") or []
            findings_validated_meta = (
                (dast_out or {}).get("findings_validated_meta") or {}
            )
            result.per_finding_validation = [
                pf.to_dict()
                for pf in derive_per_finding_validation(
                    result.vulnerabilities,
                    result.dast_findings,
                    journal_records,
                    # v1.6: pass file_name + dast_attempted so the
                    # builder can emit granular NOT_TESTED reasons
                    # (non_python_file / dast_not_attempted) instead
                    # of collapsing every miss to "inconclusive".
                    file_name=filename,
                    dast_attempted=True,
                    # v1.9: rich detail for DAST-discovered findings
                    # (HRP_*/HRP_AL_*/HRP_C*) that have no L1
                    # hypothesis backing. The builder uses this to
                    # emit extra per_finding_validation rows so the
                    # user sees PoC + runtime evidence for findings
                    # DAST surfaced net-new.
                    findings_validated_meta=findings_validated_meta,
                )
            ]

            # P3a (v1.8) strict mode: suppress findings that Phase A
            # actively tested AND proved non-exploitable. Status semantics
            # (per dast/per_finding.py):
            #
            #   * BLOCKED   — sandbox tested + file's own code defended
            #   * UNREACHED — sandbox tested + code path not reachable
            #   * REJECTED  — sandbox tested + no exploit + no defense
            #                 (L1 claim looks wrong)
            #
            # Everything else (CONFIRMED + all NOT_TESTED sub-reasons:
            # infra_stub / dast_not_attempted / budget_exceeded /
            # non_python_file / unfireable_pattern_cwe / unreachable_function
            # / inconclusive / not_planned) is KEPT — those represent
            # "DAST didn't conclusively run", not "DAST proved safe".
            #
            # Critical: never suppress on infra failure. The whole point
            # of strict mode is to trust L1 unless Phase A *actively*
            # refuted. PFV itself is left intact so audit trails still
            # show what Phase A said about every original L1 finding.
            if cfg.dast_required_policy == "strict":
                refuted_statuses = {"BLOCKED", "UNREACHED", "REJECTED"}
                pre_suppress_count = len(result.vulnerabilities)
                # Per-finding validation is built in the same order as
                # result.vulnerabilities (see derive_per_finding_validation
                # signature), so positional indexing is safe.
                status_by_idx = {
                    i: (pf or {}).get("status")
                    for i, pf in enumerate(result.per_finding_validation)
                }
                result.vulnerabilities = [
                    v
                    for i, v in enumerate(result.vulnerabilities)
                    if status_by_idx.get(i) not in refuted_statuses
                ]
                suppressed_count = pre_suppress_count - len(result.vulnerabilities)
                if suppressed_count > 0:
                    result.scan_path.append(
                        f"dast_required_policy:strict:"
                        f"suppressed_{suppressed_count}_refuted_findings"
                    )

            # DAST-105 v2 (v1.1): adjudicate L1-vs-DAST verdict
            # disagreements using per-finding evidence.
            #
            # v1 behavior: DAST could only UPGRADE L1's verdict (never
            # downgrade) because we couldn't tell apart "DAST failed
            # to confirm" from "DAST refuted". This was protective but
            # cost accuracy when L1 over-called.
            #
            # v2 (this version): with Tier 1.5 per-finding statuses
            # available, we can safely downgrade IFF every L1 finding
            # has status BLOCKED or UNREACHED. This represents
            # sandbox-grounded refutation — every claimed vulnerability
            # has been observed defended by the code OR observed
            # unreachable. If even ONE finding remains CONFIRMED or
            # NOT_TESTED, we keep L1's verdict (uncertainty: maybe DAST
            # didn't see it, but it might still be exploitable).
            if dast_verdict:
                l1_rank = _VERDICT_TO_RISK.get(l1_verdict, (50, "medium"))[0]
                dast_rank = _VERDICT_TO_RISK.get(dast_verdict, (50, "medium"))[0]

                if dast_rank >= l1_rank:
                    # Upgrade or same — always accept (v1 behavior).
                    # Strict mode also allows upgrades; only downgrades
                    # are blocked.
                    result.final_verdict = dast_verdict
                    result.risk_score, result.risk_level = verdict_to_risk(dast_verdict)
                    if dast_rank > l1_rank:
                        result.scan_path.append(f"dast_upgrade:{l1_verdict}->{dast_verdict}")
                elif cfg.dast_required_policy == "strict":
                    # P3a (v1.8) strict mode: refuse the downgrade.
                    # Preserve L1's verdict. Phase A's refuted findings
                    # have already been suppressed from result.vulnerabilities
                    # above (PFV-status-based filter). The downgrade-cap
                    # severity rule that would otherwise fire here is the
                    # exact thing strict mode exists to disable — it
                    # downgrades on infra-can't-reproduce-this evidence
                    # (e.g., SSRF where sandbox has no internal endpoint
                    # to attack), which is the mcp-server-fetch class of
                    # bug we want to keep escalated.
                    result.scan_path.append(
                        f"dast_required_policy:strict:l1_verdict_preserved:"
                        f"declined_downgrade_to_{dast_verdict}"
                    )
                else:
                    # DAST wants to downgrade. v1.2: severity-driven rule.
                    #
                    # The previous (v1.1) rule required EVERY L1 finding to
                    # be BLOCKED or UNREACHED before allowing any downgrade.
                    # That's strictly conservative but loses real signal
                    # when DAST refutes most-but-not-all findings: e.g.,
                    # 4 findings all medium-severity, 3 BLOCKED + 1
                    # NOT_TESTED → previous rule kept malicious;
                    # severity-driven rule downgrades to suspicious because
                    # nothing critical remains confirmed.
                    #
                    # New rule: look at the MAX severity of findings that
                    # are still CONFIRMED post-DAST. The verdict the engine
                    # is willing to reach is bounded by that severity:
                    #
                    #   any CONFIRMED critical → keep L1 (no downgrade safe)
                    #   any CONFIRMED high     → downgrade by 1 tier max
                    #   only CONFIRMED med/low → downgrade to suspicious
                    #   nothing CONFIRMED      → accept full DAST downgrade
                    #
                    # Final verdict is the higher of (severity-permitted
                    # downgrade, DAST's proposed verdict) — DAST is never
                    # forced to over-downgrade beyond what it asked for.
                    pf_list = result.per_finding_validation or []
                    # Edge case: no per-finding evidence at all (e.g., DAST
                    # didn't populate pf_list — test stubs, errors, or
                    # legacy runs). Without per-finding data we have no
                    # basis for a severity-driven decision; fall back to
                    # conservative v1.1 behavior — keep L1.
                    if not pf_list:
                        result.scan_path.append(
                            f"dast_keep_l1:{l1_verdict}_over_{dast_verdict}:no_per_finding_evidence"
                        )
                        # Skip the rest of the severity-driven path.
                        confirmed: list[dict] = []
                        skip_severity_decision = True
                    else:
                        skip_severity_decision = False

                    if not skip_severity_decision:
                        # Bucket findings by sandbox status:
                        #   CONFIRMED:  sandbox proved exploit fires — real risk
                        #   NOT_TESTED: sandbox didn't run the test — unknown risk
                        #   BLOCKED:    sandbox tested, code defended → refuted
                        #   UNREACHED:  sandbox tested, code path not reachable → refuted
                        # CONFIRMED and NOT_TESTED both count as "uncertain"
                        # (could still be exploitable). Only BLOCKED/UNREACHED
                        # count as actually refuted — driving downgrade.
                        uncertain = [
                            pf for pf in pf_list if pf.get("status") in {"CONFIRMED", "NOT_TESTED"}
                        ]
                        confirmed_count = sum(
                            1 for pf in pf_list if pf.get("status") == "CONFIRMED"
                        )
                        refuted_count = sum(
                            1 for pf in pf_list if pf.get("status") in {"BLOCKED", "UNREACHED"}
                        )

                        SEV_RANK = {
                            "info": 0,
                            "low": 0,
                            "medium": 1,
                            "high": 2,
                            "critical": 3,
                        }
                        # Max severity of UNCERTAIN findings (incl. NOT_TESTED).
                        # If any uncertain finding could be critical, we
                        # cannot safely downgrade below L1.
                        max_uncertain_sev = max(
                            (
                                SEV_RANK.get(str(pf.get("severity", "")).lower(), 1)
                                for pf in uncertain
                            ),
                            default=-1,  # -1 = no uncertain findings
                        )

                        VERDICT_ORDER = (
                            "clean",
                            "suspicious",
                            "malicious",
                            "critical_malicious",
                        )
                        l1_idx = (
                            VERDICT_ORDER.index(l1_verdict) if l1_verdict in VERDICT_ORDER else 2
                        )
                        dast_idx = (
                            VERDICT_ORDER.index(dast_verdict)
                            if dast_verdict in VERDICT_ORDER
                            else l1_idx
                        )

                        if max_uncertain_sev >= 3:
                            # Critical confirmed/untested remains — refuse downgrade.
                            new_idx = l1_idx
                            reason = (
                                f"critical_uncertain_remains:"
                                f"{len(uncertain)}/{len(pf_list)}"
                                f"_confirmed={confirmed_count}"
                            )
                        elif max_uncertain_sev >= 2:
                            # High uncertain remains — downgrade by 1 tier max.
                            new_idx = max(dast_idx, l1_idx - 1)
                            reason = "high_uncertain_remains:downgrade_capped_1tier"
                        elif max_uncertain_sev >= 0:
                            # Only med/low uncertain — at most suspicious.
                            new_idx = max(dast_idx, 1)  # 1 = suspicious
                            reason = "med_low_uncertain_only:cap_at_suspicious"
                        else:
                            # All findings refuted (BLOCKED/UNREACHED) — full downgrade.
                            new_idx = dast_idx
                            reason = f"all_refuted:{refuted_count}/{len(pf_list)}"

                        new_verdict = VERDICT_ORDER[new_idx]
                        if new_idx < l1_idx:
                            result.final_verdict = new_verdict
                            result.risk_score, result.risk_level = verdict_to_risk(new_verdict)
                            result.scan_path.append(
                                f"dast_severity_downgrade:{l1_verdict}->{new_verdict}:{reason}"
                            )
                        else:
                            # Severity rule kept us at L1 (no downgrade).
                            result.scan_path.append(
                                f"dast_keep_l1:{l1_verdict}_over_{dast_verdict}:{reason}"
                            )
            result.scan_path.append("dast_verification")
            result.model_calls.append(
                {
                    "stage": "dast",
                    "iterations": len(result.dast_iterations),
                    "cost_usd": (dast_out or {}).get("total_cost_usd", 0.0),
                    "duration_ms": (dast_out or {}).get("elapsed_ms", 0),
                }
            )
            result.total_cost_usd += (dast_out or {}).get("total_cost_usd", 0.0)
            if _check_cost_cap(result, cfg, "dast"):
                result.total_duration_ms = int((time.time() - t_start) * 1000)
                return result
        except Exception as e:  # noqa: BLE001
            log.warning("DAST failed for %s: %s", filename, e)
            result.dast_attempted = True
            result.scan_path.append(f"dast_failed:{type(e).__name__}")
            # v1.6 Fix #10: log infra gaps from top-level DAST failures
            # (sandbox unreachable, image missing, etc.). Fire-and-forget.
            try:
                from dast.infra_telemetry import log_infra_gap

                log_infra_gap(
                    file_name=filename,
                    phase="dast_orchestrator",
                    error_message=f"{type(e).__name__}: {e}",
                )
            except Exception:  # noqa: BLE001
                pass  # never block scan on telemetry failures

    # ── Stage 8: DAST Discovery (v1.1, DAST-204 v0.0) ─────────────────
    # Proactive payload sweep against the file using a hardcoded library
    # of top-CWE attack patterns. Runs only when:
    #   * ``cfg.enable_discovery`` is True (opt-in — adds ~$0.25/file)
    #   * the file's verdict is in ``cfg.discovery_trigger_verdicts``
    #     (default: same as DAST — malicious / critical_malicious)
    #   * ``dast_runner`` was provided (we need its sandbox client)
    # Discovered findings are appended to ``result.dast_findings`` with
    # ``discovered_by="dast_discovery_v0"`` and ``status="CONFIRMED"``
    # (every emitted discovery is sandbox-validated by construction).
    if (
        cfg.enable_discovery
        and result.final_verdict in cfg.discovery_trigger_verdicts
        and dast_runner is not None
    ):
        try:
            from dast.discovery import run_discovery
            from dast.runner import _resolve_sandbox_client_for_engine

            sandbox = _resolve_sandbox_client_for_engine(dast_runner)
            if sandbox is None:
                result.scan_path.append("discovery_skipped:no_sandbox_handle")
            else:
                t_disc = time.time()
                discovered, traces = await run_discovery(
                    file_id=filename,
                    sandbox=sandbox,
                    file_name=Path(filename).name or filename,
                )
                disc_elapsed_ms = int((time.time() - t_disc) * 1000)
                # Append discovered findings to dast_findings as dicts
                # so downstream consumers see a uniform shape.
                for f in discovered:
                    result.dast_findings.append(f.to_dict())
                result.scan_path.append(
                    f"discovery:{len(discovered)}_findings_from_{len(traces)}_payloads"
                )
                result.model_calls.append(
                    {
                        "stage": "dast_discovery",
                        "n_payloads": len(traces),
                        "n_discovered": len(discovered),
                        "duration_ms": disc_elapsed_ms,
                    }
                )
        except Exception as e:  # noqa: BLE001
            log.warning("DAST discovery failed for %s: %s", filename, e)
            result.scan_path.append(f"discovery_failed:{type(e).__name__}")

    # ── Stage 8.5: SCAN-013 intent classification + cap (v15.19) ───────
    # Derive file intent (legitimate / unknown / malicious) from
    # cascade signals already present, then cap final_verdict so
    # legitimate library code can't land as malicious/critical_malicious
    # regardless of L1's static-shape findings or Phase B+ CONFIRMs.
    #
    # Runs AFTER all DAST adjudication so the cap operates on the
    # final composed verdict — not on intermediate L1/DAST states.
    # Runs BEFORE per_finding_validation backfill so the backfill
    # sees the final capped verdict if anything reads from it.
    #
    # Behavior preserved when intent is unknown/malicious: no cap,
    # final_verdict keeps whatever the adjudicator decided.
    result.intent = _classify_file_intent(result)
    _apply_intent_cap(result)

    # ── Stage 9: per-finding validation backfill (v1.6 Fix #9) ─────────
    # When DAST didn't run (verdict below trigger gate, file errored, etc.),
    # the per_finding_validation list stays empty — the customer-facing
    # output has L1 findings with NO honest "did we test this?" label.
    # That's 44% of L1 findings in the v1.6 bench going unlabeled.
    #
    # Fix #9: always invoke derive_per_finding_validation so every L1
    # finding gets a label. When DAST didn't run, pass dast_attempted=False
    # so the builder tags each finding with NOT_TESTED + reason=
    # dast_not_attempted (the granular reason added in Fix #3 but never
    # exercised because the function was only called inside the DAST block).
    #
    # Pure relabeling — no extra API calls, no extra cost. Just honesty.
    if not result.per_finding_validation and result.vulnerabilities and not result.error:
        from dast.per_finding import derive_per_finding_validation

        result.per_finding_validation = [
            pf.to_dict()
            for pf in derive_per_finding_validation(
                result.vulnerabilities,
                [],  # dast_validated_findings — DAST didn't run
                [],  # journal_records — DAST didn't run
                file_name=filename,
                dast_attempted=False,
            )
        ]

    # ── Stage 9.5: SCAN-014 findings-floor invariant (v15.29) ──────────
    # Enforce: ``clean`` must mean zero active findings. Runs AFTER PFV
    # backfill so every vulnerability carries a status label the floor
    # can use to distinguish active (CONFIRMED, NOT_TESTED) from
    # refuted (REJECTED, BLOCKED, UNREACHED, SUPPRESSED). See helper
    # docstring for the full rationale.
    _apply_finding_floor(result)

    result.total_duration_ms = int((time.time() - t_start) * 1000)
    return result


__all__ = [
    "ScanConfig",
    "ScanResult",
    "is_high_stakes",
    "scan_file",
    "verdict_to_risk",
]
