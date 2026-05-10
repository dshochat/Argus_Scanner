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
    dast_trigger_verdicts: tuple[str, ...] = ("malicious", "critical_malicious")
    dast_max_iterations: int = 3
    # v1.2 Phase C — fix-and-verify. When True (default), DAST attempts
    # to generate a patch for CONFIRMED findings and replays the
    # original exploit against the patched source in the same sandbox.
    # Set to False for compliance scans, CI gates that don't want any
    # source modification, read-only audits, or cost reduction (Phase C
    # adds ~$0.05/file in patch-generation tokens).
    enable_phase_c: bool = True
    # v1.5 Phase B+ — runtime exploit probing. When True AND DAST is
    # configured AND the file is Python, the orchestrator asks the
    # model to generate concrete attack inputs, runs each in the
    # sandbox, and emits findings from observed runtime evidence rather
    # than from static analysis speculation. Off by default because
    # (a) it adds ~$0.20-0.50/file in API cost on top of Phase A and
    # (b) FP rate on first-party code with legitimate filesystem /
    # network behavior will be non-trivial in v1.5. Opt-in via
    # ``argus scan --enable-runtime-probe`` or
    # ``argus install --enable-runtime-probe``.
    enable_runtime_probe: bool = False
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

    # Findings (vulnerabilities, behavioral observations)
    vulnerabilities: list[dict] = field(default_factory=list)
    behavioral_profile: dict = field(default_factory=dict)
    attack_chains: list[dict] = field(default_factory=list)
    ai_tool_analysis: dict = field(default_factory=dict)

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
            "vulnerabilities": self.vulnerabilities,
            "behavioral_profile": self.behavioral_profile,
            "attack_chains": self.attack_chains,
            "ai_tool_analysis": self.ai_tool_analysis,
            "dast_attempted": self.dast_attempted,
            "dast_findings": self.dast_findings,
            "dast_iterations": self.dast_iterations,
            "per_finding_validation": self.per_finding_validation,
            "phase_c": self.phase_c,
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
    result.scan_path.append(f"cost_cap_exceeded_after:{stage_just_completed}({result.total_cost_usd:.4f}>{cap:.2f})")
    result.error = f"cost_cap_exceeded: ${result.total_cost_usd:.4f} > ${cap:.2f} after {stage_just_completed} stage"
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
    dast_runner: Any = None,
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
    result.scan_path.append(f"high_stakes={high_stakes}{(':' + ','.join(triggered_cats)) if triggered_cats else ''}")

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
        triage_reason = f"{triage_reason} [safety_net: {original}→HIGH triggered by {','.join(triggered_cats)}]"
        result.scan_path.append(f"safety_net_override:{original}->HIGH")

    result.triage_classification = classification
    result.triage_reason = triage_reason

    # ── Stage 5: cascade routing ───────────────────────────────────────
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
        chosen_runner = (
            sonnet_runner  # falls back to Sonnet if no separate Flash runner; production wires Gemini Flash here
        )
        chosen_model_label = "low_path"
    else:  # HIGH
        if high_stakes and opus_runner is not None:
            # high-stakes goes directly to Opus for the deep behavioral
            chosen_runner = opus_runner
            chosen_model_label = "opus_high_stakes"
        else:
            chosen_runner = sonnet_runner
            chosen_model_label = "sonnet_default"

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

    # ── Stage 7: DAST verification ─────────────────────────────────────
    if cfg.enable_dast and result.final_verdict in cfg.dast_trigger_verdicts and dast_runner is not None:
        try:
            l1_verdict = result.final_verdict
            dast_out = await dast_runner(
                filename,
                content,
                pp,
                result,
                enable_phase_c=cfg.enable_phase_c,
                enable_runtime_probe=cfg.enable_runtime_probe,
            )
            result.dast_attempted = True
            result.dast_findings = (dast_out or {}).get("validated_findings", [])
            result.dast_iterations = (dast_out or {}).get("iterations", [])
            # v1.2: Phase C — fix-and-verify result, surfaced from
            # dast.orchestrator. None if Phase C didn't run.
            result.phase_c = (dast_out or {}).get("phase_c")
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
            result.per_finding_validation = [
                pf.to_dict()
                for pf in derive_per_finding_validation(
                    result.vulnerabilities,
                    result.dast_findings,
                    journal_records,
                )
            ]

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
                    result.final_verdict = dast_verdict
                    result.risk_score, result.risk_level = verdict_to_risk(dast_verdict)
                    if dast_rank > l1_rank:
                        result.scan_path.append(f"dast_upgrade:{l1_verdict}->{dast_verdict}")
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
                        uncertain = [pf for pf in pf_list if pf.get("status") in {"CONFIRMED", "NOT_TESTED"}]
                        confirmed_count = sum(1 for pf in pf_list if pf.get("status") == "CONFIRMED")
                        refuted_count = sum(1 for pf in pf_list if pf.get("status") in {"BLOCKED", "UNREACHED"})

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
                            (SEV_RANK.get(str(pf.get("severity", "")).lower(), 1) for pf in uncertain),
                            default=-1,  # -1 = no uncertain findings
                        )

                        VERDICT_ORDER = (
                            "clean",
                            "suspicious",
                            "malicious",
                            "critical_malicious",
                        )
                        l1_idx = VERDICT_ORDER.index(l1_verdict) if l1_verdict in VERDICT_ORDER else 2
                        dast_idx = VERDICT_ORDER.index(dast_verdict) if dast_verdict in VERDICT_ORDER else l1_idx

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
                            result.scan_path.append(f"dast_severity_downgrade:{l1_verdict}->{new_verdict}:{reason}")
                        else:
                            # Severity rule kept us at L1 (no downgrade).
                            result.scan_path.append(f"dast_keep_l1:{l1_verdict}_over_{dast_verdict}:{reason}")
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
    if cfg.enable_discovery and result.final_verdict in cfg.discovery_trigger_verdicts and dast_runner is not None:
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
                result.scan_path.append(f"discovery:{len(discovered)}_findings_from_{len(traces)}_payloads")
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

    result.total_duration_ms = int((time.time() - t_start) * 1000)
    return result


__all__ = [
    "ScanConfig",
    "ScanResult",
    "is_high_stakes",
    "scan_file",
    "verdict_to_risk",
]
