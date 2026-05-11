"""DAST iteration loop. Hard cap = 3 iterations.

Pipeline
--------
S models → L1 (existing, frozen) → DAST (this module) → final verdict.

Each iteration is three model calls + N sandbox calls:
  Phase A plan      (1 call)  — emit executable sandbox plans for the
                                pending hypothesis pool
  Phase A verdict   (1 call)  — score per-claim + emit current_verdict
  Phase B explore   (1 call)  — propose new hypotheses for next iter

Stop conditions (whichever fires first)
---------------------------------------
S1  ``iter > MAX_ITERATIONS``                        (hard cap = 3)
S2  iteration produced 0 new confirmed findings
S3  iteration produced 0 hypotheses passing the validator gate
TC  per-file token count exceeded ``TOKEN_CAP_PER_FILE``  (1M)

Final verdict = the last iteration's Phase-A ``current_verdict``. There
is no L2 stage.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import prompts as dast_prompts
from .journal import (
    Journal,
    JournalPhase,
    JournalRecord,
)
from .sandbox.client import SandboxClient, SandboxPlan, SandboxTrace
from .validator import HypothesisValidator

MAX_ITERATIONS: int = 3
TOKEN_CAP_PER_FILE: int = 1_000_000

# One inference call returns this dict shape (matches our streaming
# helper output): { text, usage{prompt_tokens, completion_tokens, ...},
# finish_reason, ... }
InferenceFn = Callable[[str, dict[str, Any], dict[str, Any] | None], Awaitable[dict[str, Any]]]


@dataclass
class IterationStats:
    iter: int
    phase_a_plan_in: int = 0
    phase_a_plan_out: int = 0
    phase_a_verdict_in: int = 0
    phase_a_verdict_out: int = 0
    phase_b_in: int = 0
    phase_b_out: int = 0
    # v1.5: Phase B+ runtime exploit probing — token usage from the
    # candidate-generation inference call. Zero when the probe stage
    # doesn't fire (default path).
    phase_b_runtime_probe_in: int = 0
    phase_b_runtime_probe_out: int = 0
    new_confirmed_findings: int = 0
    hypotheses_proposed: int = 0
    hypotheses_accepted: int = 0
    hypotheses_rejected: int = 0
    sandbox_calls: int = 0
    iter_erosion_guard_fired: bool = False  # Phase 2b: clamped a downgrade
    journal_input_tokens: int = 0  # tokens read from journal at iter start
    elapsed_s: float = 0.0
    current_verdict_label: str = "clean"
    finish_reasons: dict[str, str] = field(default_factory=dict)


@dataclass
class DastResult:
    file_id: str
    iterations: list[IterationStats]
    final_verdict: dict[str, Any]
    findings_validated: list[str]
    total_tokens_in: int
    total_tokens_out: int
    total_sandbox_calls: int
    elapsed_s: float
    stop_reason: str
    journal_path: Path
    diagnostics: dict[str, Any] = field(default_factory=dict)
    # Tier 1.5 (v1.1): per-record journal dump (claim_id, verdict,
    # rationale per hypothesis). Lets downstream consumers classify
    # rejected hypotheses into BLOCKED / UNREACHED / NOT_TESTED.
    # Populated at end-of-run from journal.read_all().
    journal_records: list[dict[str, Any]] = field(default_factory=list)

    # v1.2: Phase C — fix-and-verify result. None if Phase C didn't run
    # (no confirmed findings, or skipped). When populated, contains:
    #   {
    #     "attempted": bool,
    #     "patched_source": str | None,
    #     "fix_summary": str,
    #     "post_patch_verdict": "clean|suspicious|malicious|critical_malicious",
    #     "per_finding": [{finding_ref, post_patch_status:
    #         NEUTRALIZED|STILL_EXPLOITABLE|UNVERIFIABLE}, ...],
    #     "n_neutralized": int, "n_still_exploitable": int,
    #     "tokens_in": int, "tokens_out": int, "n_replays": int,
    #     "elapsed_s": float, "error": str | None,
    #   }
    phase_c: dict[str, Any] | None = None


def _parse_json_or_empty(text: str) -> dict:
    if not text or not text.strip():
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


# Phase 2b: iter-erosion guard.
# Verdict labels ordered low → high. The orchestrator tracks the highest
# DAST-emitted verdict reached and refuses downgrades that aren't
# grounded in explicit sandbox refutation of a previously confirmed
# finding. Without this, a follow-up iter that fails to re-confirm an
# already-confirmed exploit (e.g. environmental: "curl missing in
# image") is given the same weight as actual disconfirmation, eroding a
# correct verdict. See campaign_summary.md → litellm_obfuscated case.
_VERDICT_RANK: dict[str, int] = {
    "clean": 0,
    "informational": 1,
    "suspicious": 2,
    "malicious": 3,
    "critical_malicious": 4,
}


def _has_refutation_of_prior_confirmed(
    claim_verdicts: list,
    hyp_index: dict,
    prev_confirmed: set[str],
) -> bool:
    """Did this iteration produce a sandbox-grounded refutation of a
    previously confirmed finding?

    A refutation counts only when ALL of:
      * ``cv["verdict"] == "refuted"``
      * ``cv["sandbox_event_ids"]`` is non-empty (real evidence, not
        a freelance verdict)
      * The refuted hypothesis's finding_ref (or upstream chain
        confirmed_finding_ref) is in ``prev_confirmed`` — i.e. it
        targets something a prior iter actually confirmed.
    """
    for cv in claim_verdicts:
        if not isinstance(cv, dict):
            continue
        if cv.get("verdict") != "refuted":
            continue
        ev_ids = cv.get("sandbox_event_ids") or []
        if not (isinstance(ev_ids, list) and ev_ids):
            continue
        hyp = hyp_index.get(cv.get("hypothesis_id", "")) or {}
        fref = hyp.get("finding_ref") or (
            (hyp.get("upstream_chain") or {}).get("confirmed_finding_ref")
        )
        if fref and fref in prev_confirmed:
            return True
    return False


async def run_dast(
    *,
    file_record: dict,
    l1_output: dict,
    sandbox: SandboxClient,
    validator: HypothesisValidator,
    journal_dir: Path,
    inference: InferenceFn,
    enable_phase_c: bool = True,
    enable_runtime_probe: bool = False,
) -> DastResult:
    """Run the DAST loop on one file.

    ``file_record`` carries ``file_id``, ``source_text``, plus optional
    diagnostics. ``l1_output`` is the frozen Pass-1 ``scan_report`` block
    (after sanitization to compact form). ``inference`` is a coroutine
    that takes (prompt, sampling_params, json_schema) and returns the
    dict shape produced by ``_run_capability_bundles.stream_call``.
    """
    file_id = file_record["file_id"]
    source_text = file_record["source_text"]
    # Real basename (with extension) used to stage the file at
    # /workspace/<file_name> in the sandbox. Falls back to file_id so
    # legacy callers without name plumbing still produce a non-empty
    # value, but extension-routed languages (Node, Java) need this set
    # to the real basename for require()/class-loader resolution.
    file_name = file_record.get("file_name", "") or file_id
    started = time.time()

    journal = Journal(file_id=file_id, base_dir=journal_dir)
    iterations: list[IterationStats] = []
    total_in = 0
    total_out = 0
    total_sb = 0
    last_verdict: dict[str, Any] = {
        "verdict_label": (l1_output.get("verdict") or {}).get("verdict_label", "suspicious"),
        "log_summary": "no DAST iteration completed yet",
        "validated_findings": [],
        "confirmed_categories": [],
    }
    findings_validated: list[str] = []
    stop_reason = "unknown"

    # Phase 2b: max DAST verdict reached so far (NOT counting the
    # initial L1 verdict). Iters can only downgrade below this with
    # sandbox-grounded refutation evidence.
    max_dast_verdict_rank = -1
    max_dast_verdict_label: str | None = None

    # iter 1 starts with L1 hypotheses; iter ≥ 2 starts with the previous
    # iteration's validator-accepted Phase B hypotheses
    pending_hypotheses: list[dict] = list(l1_output.get("hypotheses") or [])

    # v1.2: capture iter-1 plans for Phase C replay (fix-and-verify).
    # Iter 1 is the natural plan set for re-testing the patched file because
    # iter ≥ 2 plans target Phase B hypotheses that wouldn't exist on a
    # patched (presumed-safe) file. We only need plans; Phase C generates
    # fresh traces against the patched source.
    iter1_plan_records: list[dict] | None = None

    # v1.5 Phase B+ — runtime exploit probing. Runs ONCE before the
    # iteration loop, so even files where L1 found nothing get a probe
    # pass when the flag is on. Findings are surfaced via
    # ``findings_validated`` (NOT via l1_output.hypotheses — see Fix #2).
    #
    # Pre-create iter-1 stats here so the probe's token-usage
    # accounting (Fix #4) goes into the actual stats record the iter
    # loop will pick up — not a throwaway. The loop below detects this
    # pre-init via ``iterations`` non-empty + iter==1 and reuses.
    probe_pre_init_stats: IterationStats | None = None
    # Probe-supported language gate: Python / JavaScript (.js, .mjs, .cjs)
    # / shell (.sh, .bash). detect_probe_language is the single source of
    # truth; plan builder dispatches by the same function.
    from dast.runtime_probe import detect_probe_language  # noqa: PLC0415

    _probe_lang = detect_probe_language(file_name) if enable_runtime_probe else None
    if (
        enable_runtime_probe
        and _probe_lang is not None
        and isinstance(file_record.get("original_bytes"), (bytes, bytearray))
    ):
        probe_pre_init_stats = IterationStats(iter=1)
        iterations.append(probe_pre_init_stats)
        try:
            probe_findings = await _run_phase_b_runtime_probe(
                file_record=file_record,
                l1_output=l1_output,
                journal=journal,
                journal_summary=journal.summarize(up_to_iter=0),
                inference=inference,
                sandbox=sandbox,
                iter_num=1,
                stats=probe_pre_init_stats,
            )
            # Fix #2: HRPs are NOT appended to l1_output.hypotheses (would
            # cause Phase A re-test + contradiction). They flow only via
            # findings_validated. pending_hypotheses stays as the original
            # L1 set.

            # Fix #3 (surfacing): every confirmed HRP id reaches engine.py
            # via findings_validated → ScanResult.dast_findings.
            for f in probe_findings:
                fid = f.get("finding_ref")
                if fid and fid not in findings_validated:
                    findings_validated.append(fid)

            # Fix #1 (verdict bump): a probe-CONFIRMED finding at
            # severity >= high is GROUNDED runtime evidence of a real
            # exploit. Bump the DAST max-verdict floor so the
            # iter-erosion guard (which clamps downgrades to within
            # ``max_dast_verdict_rank``) protects this signal against
            # later iterations downgrading.
            #
            # Safety: only bump UP, never down. Only by one tier max.
            # Only on high/critical severity. medium/low don't bump.
            # Critical+code-exec attack class → critical_malicious;
            # everything else high/critical → malicious.
            _CRITICAL_EXEC_CLASSES = {"code_injection", "command_injection", "deserialization"}
            for f in probe_findings:
                sev = (f.get("severity") or "").lower()
                if sev not in {"high", "critical"}:
                    continue
                if sev == "critical" and f.get("finding_type") in _CRITICAL_EXEC_CLASSES:
                    target_label = "critical_malicious"
                else:
                    target_label = "malicious"
                target_rank = _VERDICT_RANK.get(target_label, -1)
                if target_rank > max_dast_verdict_rank:
                    max_dast_verdict_rank = target_rank
                    max_dast_verdict_label = target_label
            # If the probe established a floor higher than the current
            # last_verdict, lift last_verdict to the floor so the
            # downstream verdict logic sees the probe-grounded evidence.
            current_rank = _VERDICT_RANK.get(
                str(last_verdict.get("verdict_label", "suspicious")), -1
            )
            if max_dast_verdict_rank > current_rank and max_dast_verdict_label:
                last_verdict["verdict_label"] = max_dast_verdict_label
                last_verdict["log_summary"] = (
                    f"runtime probe CONFIRMED {len([f for f in probe_findings if f.get('severity') in {'high', 'critical'}])} "
                    f"high/critical exploit(s); verdict raised to {max_dast_verdict_label}"
                )
        except Exception as exc:  # noqa: BLE001
            journal.append(
                JournalRecord(
                    iter=1,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id="HRP_ERROR",
                    verdict="rejected",
                    rationale=f"runtime probe stage failed: {type(exc).__name__}: {str(exc)[:240]}",
                    evidence_refs=[],
                )
            )

    for it in range(1, MAX_ITERATIONS + 1):
        it_started = time.time()
        # Fix #4 ordering: when the v1.5 probe stage pre-created iter-1
        # stats, reuse that record so probe token usage isn't orphaned.
        # All later iters create fresh stats normally.
        if it == 1 and probe_pre_init_stats is not None:
            st = probe_pre_init_stats
        else:
            st = IterationStats(iter=it)
            iterations.append(st)

        prior_summary = journal.summarize(up_to_iter=it - 1)
        st.journal_input_tokens = prior_summary.token_count

        if not pending_hypotheses:
            stop_reason = "no_pending_hypotheses_for_iter"
            st.elapsed_s = round(time.time() - it_started, 2)
            break

        # ---- Phase A — Plan ------------------------------------------
        # For iter 1 the pending pool IS the L1 hypotheses (already in
        # l1_output). For iter ≥ 2 the pool is the Phase B hypotheses
        # accepted by the validator in iter N-1 — we replace l1_output's
        # ``hypotheses`` block so the prompt sees only the new pool and
        # the model doesn't re-plan already-verdicted L1 claims.
        if it == 1:
            l1_output_for_plan = l1_output
            pending_for_kwarg = None
        else:
            l1_output_for_plan = {**l1_output, "hypotheses": pending_hypotheses}
            pending_for_kwarg = pending_hypotheses
        plan_prompt = dast_prompts.build_phase_a_plan_prompt(
            file_text=source_text,
            l1_output=l1_output_for_plan,
            journal_summary=prior_summary.to_dict(),
            pending_hypotheses=pending_for_kwarg,
        )
        plan_resp = await inference(
            plan_prompt,
            {"temperature": 0.0, "max_tokens": 6144, "seed": 0},
            dast_prompts.phase_a_plan_schema(),
        )
        st.phase_a_plan_in = (plan_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
        st.phase_a_plan_out = (plan_resp.get("usage") or {}).get("completion_tokens", 0) or 0
        st.finish_reasons["plan"] = plan_resp.get("finish_reason") or "?"
        plans_obj = _parse_json_or_empty(plan_resp.get("text", ""))
        plans = (plans_obj.get("plans") or []) if isinstance(plans_obj, dict) else []

        # ML-artifact deterministic detonation: when iter 1 starts on a
        # recognized model file (.pkl/.pt/.bin/.safetensors/.h5/.onnx),
        # we PREPEND a fixed load plan so the sandbox detonates the
        # artifact regardless of what the model-driven planner emits.
        # The plan template lives in dast.ml_detonation; it produces a
        # python-c oneliner that calls pickle.load / torch.load / etc.
        # — i.e., the canonical "load = execution" attack surface.
        if it == 1 and file_record.get("ml_format"):
            from dast.ml_detonation import build_ml_load_plan  # noqa: PLC0415

            ml_bytes = file_record.get("original_bytes")
            if isinstance(ml_bytes, (bytes, bytearray)):
                ml_plan = build_ml_load_plan(
                    file_name=file_name,
                    file_id=file_id,
                    hypothesis_id="HML_LOAD",
                    original_bytes=bytes(ml_bytes),
                )
                if ml_plan is not None:
                    plans = [ml_plan, *plans]

        # Cross-reference hypothesis_id → hypothesis dict so the stub
        # sandbox can resolve Phase B upstream context.
        hyp_index = {h.get("id"): h for h in pending_hypotheses}

        # ---- Sandbox ------------------------------------------------
        plan_records: list[dict] = []
        trace_records: list[dict] = []
        for p in plans:
            if not isinstance(p, dict):
                continue
            hid = p.get("hypothesis_id", "")
            if p.get("plan_status") != "executable":
                # Not_testable plans are journaled but no sandbox call.
                journal.append(
                    JournalRecord(
                        iter=it,
                        phase=JournalPhase.PHASE_A_PLAN,
                        claim_id=hid,
                        verdict=None,
                        rationale=f"not_testable: {p.get('rationale', '')[:200]}",
                        evidence_refs=[],
                        sandbox_event_id=None,
                    )
                )
                plan_records.append(p)
                continue
            # DAST-005: pass through image_hint. Default to "minimal" so
            # plans from older planners (no field) and stub clients are
            # unaffected. MultiImageSandboxClient routes; single-image
            # clients ignore.
            raw_hint = p.get("image_hint")
            image_hint = raw_hint if isinstance(raw_hint, str) and raw_hint else "minimal"
            plan = SandboxPlan(
                plan_id=f"i{it}-{hid}",
                file_id=file_id,
                hypothesis_id=hid,
                commands=p.get("commands") or [],
                expected_oracle=p.get("oracle") or "",
                payload=p.get("payload") or "",
                timeout_sec=int(p.get("timeout_sec") or 30),
                image_hint=image_hint,
                file_name=file_name,
                synthesis_context={
                    "upstream_chain": (hyp_index.get(hid) or {}).get("upstream_chain") or {},
                    "hypothesis": hyp_index.get(hid) or {},
                },
            )
            try:
                trace: SandboxTrace = await sandbox.submit(plan)
            except Exception as e:
                trace = SandboxTrace(
                    plan_id=plan.plan_id,
                    file_id=plan.file_id,
                    hypothesis_id=plan.hypothesis_id,
                    events=[],
                    exit_code=None,
                    stdout_excerpt="",
                    stderr_excerpt=f"sandbox_error: {type(e).__name__}: {e}",
                    elapsed_ms=0,
                    is_stub_no_trace=True,
                    stub_synthesis_note=f"exception: {type(e).__name__}",
                )
            st.sandbox_calls += 1
            total_sb += 1
            plan_records.append(p)
            trace_records.append(trace.model_dump())
            journal.append(
                JournalRecord(
                    iter=it,
                    phase=JournalPhase.SANDBOX_EXEC,
                    claim_id=hid,
                    verdict=None,
                    rationale=trace.stub_synthesis_note or "",
                    evidence_refs=[e.event_id for e in trace.events],
                    sandbox_event_id=(trace.events[0].event_id if trace.events else None),
                )
            )

        # v1.2: snapshot iter-1 plans for Phase C replay (fix-and-verify)
        if it == 1:
            iter1_plan_records = list(plan_records)

        # ---- Phase A — Verdict --------------------------------------
        verdict_prompt = dast_prompts.build_phase_a_verdict_prompt(
            file_text=source_text,
            l1_output=l1_output,
            plans=plan_records,
            traces=trace_records,
            journal_summary=prior_summary.to_dict(),
        )
        verdict_resp = await inference(
            verdict_prompt,
            {"temperature": 0.0, "max_tokens": 6144, "seed": 0},
            dast_prompts.phase_a_verdict_schema(),
        )
        st.phase_a_verdict_in = (verdict_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
        st.phase_a_verdict_out = (verdict_resp.get("usage") or {}).get("completion_tokens", 0) or 0
        st.finish_reasons["verdict"] = verdict_resp.get("finish_reason") or "?"
        verdict_obj = _parse_json_or_empty(verdict_resp.get("text", ""))
        claim_verdicts = (
            (verdict_obj.get("claim_verdicts") or []) if isinstance(verdict_obj, dict) else []
        )
        cur = (verdict_obj.get("current_verdict") or {}) if isinstance(verdict_obj, dict) else {}

        prev_confirmed = set(prior_summary.confirmed_findings)
        new_confirmed_count = 0
        for cv in claim_verdicts:
            if not isinstance(cv, dict):
                continue
            hid = cv.get("hypothesis_id", "")
            v = cv.get("verdict") or "inconclusive"
            ev_ids = cv.get("sandbox_event_ids") or []
            rationale = cv.get("rationale", "")[:300]
            evidence_refs: list[str] = []
            # If we can map back to a finding ID via the L1 hypothesis,
            # record it as a Finding in the journal.
            hyp = hyp_index.get(hid) or {}
            # L1 hypotheses use ``finding_ref``; Phase B hypotheses use
            # ``upstream_chain.confirmed_finding_ref``. Try both.
            fref = hyp.get("finding_ref") or (
                (hyp.get("upstream_chain") or {}).get("confirmed_finding_ref")
            )
            if fref:
                evidence_refs.append(fref)
            evidence_refs.extend(ev_ids if isinstance(ev_ids, list) else [])
            journal.append(
                JournalRecord(
                    iter=it,
                    phase=JournalPhase.PHASE_A_VERDICT,
                    claim_id=hid,
                    verdict=v,
                    rationale=rationale,
                    evidence_refs=evidence_refs,
                    sandbox_event_id=(ev_ids[0] if isinstance(ev_ids, list) and ev_ids else None),
                )
            )
            if v == "confirmed" and fref and fref not in prev_confirmed:
                new_confirmed_count += 1
                if fref not in findings_validated:
                    findings_validated.append(fref)
        st.new_confirmed_findings = new_confirmed_count

        if cur.get("verdict_label"):
            new_label = cur.get("verdict_label") or "suspicious"
            new_rank = _VERDICT_RANK.get(new_label, -1)

            # Phase 2b: iter-erosion guard. If a prior DAST iter reached
            # a higher verdict and this iter wants to downgrade WITHOUT
            # producing a sandbox-grounded refutation of a previously
            # confirmed finding, clamp the verdict back up. This blocks
            # the litellm_obfuscated-style erosion where iter 2's failed
            # re-confirmation (curl missing in image) was treated as
            # disconfirmation.
            log_summary = cur.get("log_summary", "")
            if (
                max_dast_verdict_rank >= 0
                and new_rank < max_dast_verdict_rank
                and max_dast_verdict_label is not None
                and not _has_refutation_of_prior_confirmed(
                    claim_verdicts, hyp_index, prev_confirmed
                )
            ):
                clamp_msg = (
                    f"[iter_erosion_guard] iter {it} model emitted "
                    f"'{new_label}' but no sandbox-grounded refutation of "
                    f"prior confirmed findings; clamped to prior max "
                    f"'{max_dast_verdict_label}'."
                )
                if log_summary:
                    clamp_msg = f"{clamp_msg} Original: {log_summary[:120]}"
                new_label = max_dast_verdict_label
                new_rank = max_dast_verdict_rank
                log_summary = clamp_msg
                st.iter_erosion_guard_fired = True

            last_verdict = {
                "verdict_label": new_label,
                "log_summary": log_summary,
                "validated_findings": list(cur.get("validated_findings") or []),
                "confirmed_categories": list(cur.get("confirmed_categories") or []),
            }
            st.current_verdict_label = new_label

            if new_rank > max_dast_verdict_rank:
                max_dast_verdict_rank = new_rank
                max_dast_verdict_label = new_label
        else:
            st.current_verdict_label = last_verdict.get("verdict_label", "suspicious")

        # Phase B+ runtime probing already ran ONCE before the iter loop
        # (see ``_run_phase_b_runtime_probe`` call above the for-loop).
        # Its findings — if any — were appended to ``l1_output`` /
        # ``pending_hypotheses`` and have already been planned + verified
        # by Phase A this iter. No per-iter probe call.

        # ---- Phase B — Exploration ----------------------------------
        # Re-summarize the journal so the explore prompt sees the *just-
        # written* iteration's evidence.
        live_summary = journal.summarize(up_to_iter=it)
        explore_prompt = dast_prompts.build_phase_b_prompt(
            file_text=source_text,
            l1_output=l1_output,
            journal_summary=live_summary.to_dict(),
        )
        explore_resp = await inference(
            explore_prompt,
            {"temperature": 0.0, "max_tokens": 6144, "seed": 0},
            dast_prompts.phase_b_schema(),
        )
        st.phase_b_in = (explore_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
        st.phase_b_out = (explore_resp.get("usage") or {}).get("completion_tokens", 0) or 0
        st.finish_reasons["explore"] = explore_resp.get("finish_reason") or "?"
        explore_obj = _parse_json_or_empty(explore_resp.get("text", ""))
        new_hyps = (
            (explore_obj.get("new_hypotheses") or []) if isinstance(explore_obj, dict) else []
        )
        st.hypotheses_proposed = len(new_hyps)

        # Validator gate
        accepted_hyps: list[dict] = []
        rejected_hyps: list[dict] = []
        l1_findings_for_validator = list(l1_output.get("findings") or [])
        for h in new_hyps:
            if not isinstance(h, dict):
                continue
            v = validator.validate(h, l1_findings_for_validator, live_summary)
            hid = h.get("id") or "H???"
            if v.accepted:
                accepted_hyps.append(h)
                journal.append(
                    JournalRecord(
                        iter=it,
                        phase=JournalPhase.PHASE_B_HYPOTHESIS,
                        claim_id=hid,
                        verdict="confirmed" if v.is_borderline else "confirmed",
                        rationale=f"validator accepted{' (borderline)' if v.is_borderline else ''}: {v.reasoning[:240]}",
                        evidence_refs=[],
                    )
                )
            else:
                rejected_hyps.append(h)
                journal.append(
                    JournalRecord(
                        iter=it,
                        phase=JournalPhase.PHASE_B_HYPOTHESIS,
                        claim_id=hid,
                        verdict="rejected",
                        rationale=f"validator rejected: {v.reasoning[:240]}",
                        evidence_refs=[],
                    )
                )
        st.hypotheses_accepted = len(accepted_hyps)
        st.hypotheses_rejected = len(rejected_hyps)

        # Per-iteration totals
        iter_in = (
            st.phase_a_plan_in
            + st.phase_a_verdict_in
            + st.phase_b_in
            # v1.5 Fix #4: include probe inference tokens in the iter
            # roll-up so they reach total_tokens_in → DAST cost → install
            # path's aggregate cost cap.
            + st.phase_b_runtime_probe_in
        )
        iter_out = (
            st.phase_a_plan_out
            + st.phase_a_verdict_out
            + st.phase_b_out
            + st.phase_b_runtime_probe_out
        )
        total_in += iter_in
        total_out += iter_out
        st.elapsed_s = round(time.time() - it_started, 2)

        # Token-cap check
        if total_in + total_out > TOKEN_CAP_PER_FILE:
            stop_reason = "token_cap"
            break

        # Stop-condition checks for next iter (OR semantics per spec —
        # whichever fires first ends the loop)
        if new_confirmed_count == 0:
            stop_reason = "no_new_confirmed_findings"
            break
        if st.hypotheses_accepted == 0:
            stop_reason = "no_valid_hypotheses_remaining"
            break
        if it == MAX_ITERATIONS:
            stop_reason = "max_iter"
            break

        # Hand-off to next iteration: pending hypotheses are this iter's
        # validator-accepted Phase B output.
        pending_hypotheses = accepted_hyps

    # Snapshot the journal as a list of dicts so downstream consumers
    # (engine -> per_finding derivation) can classify rejected hypotheses
    # without having to re-read the file. JournalRecord is a Pydantic
    # model — model_dump() gives a JSON-serializable dict.
    try:
        journal_dump: list[dict[str, Any]] = [r.model_dump(mode="json") for r in journal.read_all()]
    except Exception:  # noqa: BLE001
        journal_dump = []

    # ──── Phase C — Fix-and-verify (v1.2) ────────────────────────────
    # If DAST confirmed any L1 findings, generate a patch and re-test
    # the iter-1 plans against the patched source. Output: patched
    # source, post-patch verdict, per-finding NEUTRALIZED/STILL/UNVERIFIABLE.
    #
    # Trigger gate (v1.2.1): orchestrator's `findings_validated` only
    # captures hypotheses where claim_verdict="confirmed" AND finding_ref
    # was tied back to an L1 finding. The journal often contains broader
    # CONFIRMED evidence (sandbox events showing the exploit fired) that
    # didn't get tied via finding_ref. Phase C should fire on either —
    # so we union findings_validated with journal-derived confirmations.
    phase_c_findings: list[str] = list(findings_validated)
    for rec in journal_dump:
        if rec.get("phase") != "phase_a_verdict":
            continue
        if rec.get("verdict") != "confirmed":
            continue
        ev = rec.get("evidence_refs") or []
        if not (isinstance(ev, list) and ev):
            continue
        cid = rec.get("claim_id")
        if cid and cid not in phase_c_findings:
            phase_c_findings.append(cid)

    phase_c_result: dict[str, Any] | None = None
    if not enable_phase_c:
        # User opted out of remediation (compliance / CI gate / cost
        # control). ALWAYS surface the opt-out as a structured Phase C
        # marker — consumers parsing the report shouldn't have to infer
        # "is Phase C off, or did it run and find nothing to fix?" from
        # an absent field. ``n_confirmed_findings`` tells them what
        # WOULD have been remediated.
        phase_c_result = {
            "attempted": False,
            "skipped_reason": "phase_c_disabled_by_config",
            "n_confirmed_findings": len(phase_c_findings),
        }
    elif phase_c_findings and iter1_plan_records:
        try:
            phase_c_result = await _run_phase_c_fix_verify(
                file_record=file_record,
                findings_validated=phase_c_findings,
                l1_output=l1_output,
                iter1_plans=iter1_plan_records,
                inference=inference,
                sandbox=sandbox,
                journal=journal,
            )
            if phase_c_result:
                total_in += phase_c_result.get("tokens_in", 0)
                total_out += phase_c_result.get("tokens_out", 0)
                total_sb += phase_c_result.get("n_replays", 0)
        except Exception as e:  # noqa: BLE001
            phase_c_result = {
                "attempted": True,
                "error": f"{type(e).__name__}: {str(e)[:300]}",
            }

    return DastResult(
        file_id=file_id,
        iterations=iterations,
        final_verdict=last_verdict,
        findings_validated=findings_validated,
        total_tokens_in=total_in,
        total_tokens_out=total_out,
        total_sandbox_calls=total_sb,
        elapsed_s=round(time.time() - started, 2),
        stop_reason=stop_reason,
        journal_path=journal.path,
        diagnostics={
            "max_iterations": MAX_ITERATIONS,
            "token_cap": TOKEN_CAP_PER_FILE,
        },
        journal_records=journal_dump,
        phase_c=phase_c_result,
    )


async def _run_phase_b_runtime_probe(
    *,
    file_record: dict,
    l1_output: dict,
    journal: Journal,
    journal_summary: Any,
    inference: InferenceFn,
    sandbox: SandboxClient,
    iter_num: int,
    stats: IterationStats,
) -> list[dict]:
    """Phase B+ — runtime-guided exploit discovery (v1.5).

    Three steps:
    1. Ask Sonnet for probe candidates + attack inputs (one LLM call).
    2. For each (candidate × input), build a Phase-A-shaped harness plan
       and submit to the sandbox.
    3. Interpret each trace via the deterministic
       :func:`dast.runtime_probe.interpret_probe_trace` rules; any
       finding gets journaled as a CONFIRMED phase_b_hypothesis with
       sandbox-grounded runtime evidence.

    Mutates the passed-in ``journal`` and ``stats`` in place — no return.
    Errors during candidate generation or trace interpretation are
    captured into rejected-hypothesis journal records so the caller's
    outer try/except has something to surface.
    """
    from dast.runtime_probe import (  # noqa: PLC0415
        MAX_CANDIDATES,
        MAX_INPUTS_PER_CANDIDATE,
        RuntimeProbeCandidate,
        RuntimeProbeInput,
        build_runtime_probe_plan,
        interpret_probe_trace,
        parse_probe_trace,
    )

    source_text = file_record.get("source_text", "") or ""
    original_bytes = file_record.get("original_bytes")
    if not isinstance(original_bytes, (bytes, bytearray)):
        # No original bytes available — can't stage the file for execution.
        # Skip silently; orchestrator will fall through to standard Phase B.
        return []
    original_bytes = bytes(original_bytes)
    file_name = file_record.get("file_name") or "module.py"
    file_id = file_record.get("file_id", "")

    # ── Step 1: candidate generation ─────────────────────────────────────
    probe_prompt = dast_prompts.build_phase_b_runtime_probe_prompt(
        file_text=source_text,
        l1_output=l1_output,
        journal_summary=journal_summary.to_dict()
        if hasattr(journal_summary, "to_dict")
        else journal_summary,
    )
    probe_resp = await inference(
        probe_prompt,
        {"temperature": 0.0, "max_tokens": 4096, "seed": 0},
        dast_prompts.phase_b_runtime_probe_schema(),
    )
    # Fix #4: track probe inference tokens on the iteration stats so
    # they roll into total_tokens_in/out → DAST cost_usd → engine
    # ScanResult.total_cost_usd → install path's aggregate cost cap.
    # Without this, probe tokens leak out of cost accounting and the
    # aggregate cap can be silently exceeded.
    stats.phase_b_runtime_probe_in = (probe_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
    stats.phase_b_runtime_probe_out = (probe_resp.get("usage") or {}).get(
        "completion_tokens", 0
    ) or 0
    probe_obj = _parse_json_or_empty(probe_resp.get("text", ""))
    if not isinstance(probe_obj, dict):
        return []
    raw_candidates = probe_obj.get("candidates") or []
    if not isinstance(raw_candidates, list) or not raw_candidates:
        # Model legitimately declined to probe (file has no probe-attractive
        # functions). Journal the rationale so downstream telemetry sees it.
        rationale = str(probe_obj.get("non_probable_reason") or "no candidates")
        journal.append(
            JournalRecord(
                iter=iter_num,
                phase=JournalPhase.PHASE_B_HYPOTHESIS,
                claim_id="HRP_NONE",
                verdict="rejected",
                rationale=f"runtime probe declined: {rationale[:200]}",
                evidence_refs=[],
            )
        )
        return []

    # Decode + cap to bounded sizes (schema enforces but defense-in-depth)
    candidates: list[RuntimeProbeCandidate] = []
    for c in raw_candidates[:MAX_CANDIDATES]:
        if not isinstance(c, dict):
            continue
        inputs_raw = c.get("test_inputs") or []
        inputs: list[RuntimeProbeInput] = []
        for i in (inputs_raw if isinstance(inputs_raw, list) else [])[:MAX_INPUTS_PER_CANDIDATE]:
            if not isinstance(i, dict):
                continue
            inputs.append(
                RuntimeProbeInput(
                    args_json=str(i.get("args_json") or "[]"),
                    kwargs_json=str(i.get("kwargs_json") or "{}"),
                    expected_observable=str(i.get("expected_observable") or ""),
                    exploit_proof_if_observed=str(i.get("exploit_proof_if_observed") or ""),
                )
            )
        candidates.append(
            RuntimeProbeCandidate(
                function_name=str(c.get("function_name") or ""),
                attack_class=str(c.get("attack_class") or "code_injection"),
                rationale=str(c.get("rationale") or ""),
                test_inputs=inputs,
            )
        )

    # ── Step 2: per-probe sandbox submission ─────────────────────────────
    findings_from_probes: list[dict[str, Any]] = []
    n_probes_run = 0
    for c_idx, cand in enumerate(candidates):
        if not cand.function_name or not cand.test_inputs:
            continue
        for i_idx, test_in in enumerate(cand.test_inputs):
            plan_dict = build_runtime_probe_plan(
                file_name=file_name,
                file_bytes=original_bytes,
                candidate=cand,
                test_input=test_in,
                candidate_idx=c_idx,
                input_idx=i_idx,
            )
            if plan_dict is None:
                continue
            hid = plan_dict["hypothesis_id"]
            plan = SandboxPlan(
                plan_id=f"i{iter_num}-{hid}",
                file_id=file_id,
                hypothesis_id=hid,
                commands=plan_dict["commands"],
                expected_oracle=plan_dict["oracle"],
                payload=plan_dict["payload"],
                timeout_sec=plan_dict["timeout_sec"],
                image_hint=plan_dict["image_hint"],
                file_name=file_name,
                synthesis_context={
                    "runtime_probe": True,
                    "candidate_idx": c_idx,
                    "input_idx": i_idx,
                    "attack_class": cand.attack_class,
                },
            )
            n_probes_run += 1
            try:
                trace: SandboxTrace = await sandbox.submit(plan)
            except Exception as exc:  # noqa: BLE001
                journal.append(
                    JournalRecord(
                        iter=iter_num,
                        phase=JournalPhase.PHASE_B_HYPOTHESIS,
                        claim_id=hid,
                        verdict="rejected",
                        rationale=f"sandbox submit failed: {type(exc).__name__}: {str(exc)[:200]}",
                        evidence_refs=[],
                    )
                )
                continue

            # ── Step 3: trace interpretation ─────────────────────────────
            parsed_trace = parse_probe_trace(
                candidate_function=cand.function_name,
                input_args_json=test_in.args_json,
                exit_code=trace.exit_code,
                stdout=trace.stdout_excerpt,
                stderr=trace.stderr_excerpt,
                elapsed_ms=trace.elapsed_ms,
            )
            finding = interpret_probe_trace(
                parsed_trace,
                cand,
                test_in,
                candidate_idx=c_idx,
                input_idx=i_idx,
            )
            if finding is None:
                # Probe ran cleanly — exception raised AND no canary
                # observed. BLOCKED-equivalent for runtime probes.
                # v1.5: surface the exception type/message so debugging
                # the "why didn't this exploit fire" question doesn't
                # require pulling the raw sandbox event from Fly.
                _pr = parsed_trace.parsed_result or {}
                _exc_type = _pr.get("exception_type", "")
                _exc_msg = (_pr.get("exception_msg") or "")[:160]
                _ok = bool(_pr.get("ok"))
                journal.append(
                    JournalRecord(
                        iter=iter_num,
                        phase=JournalPhase.PHASE_B_HYPOTHESIS,
                        claim_id=hid,
                        verdict="rejected",
                        rationale=(
                            f"runtime probe ran; no exploit observed. "
                            f"Function={cand.function_name}, class={cand.attack_class}, "
                            f"input={test_in.args_json[:100]}, "
                            f"exit_code={parsed_trace.exit_code}, "
                            f"call_ok={_ok}, "
                            f"exc={_exc_type}: {_exc_msg}"
                        ),
                        evidence_refs=[trace.events[0].event_id] if trace.events else [],
                    )
                )
                continue

            # CONFIRMED via runtime evidence.
            evidence_ref = trace.events[0].event_id if trace.events else ""
            journal.append(
                JournalRecord(
                    iter=iter_num,
                    phase=JournalPhase.PHASE_B_HYPOTHESIS,
                    claim_id=hid,
                    verdict="confirmed",
                    rationale=(
                        f"runtime probe CONFIRMED {finding.attack_class} in "
                        f"{cand.function_name}: {finding.runtime_evidence[:280]}"
                    ),
                    evidence_refs=[evidence_ref] if evidence_ref else [],
                )
            )
            findings_from_probes.append(
                {
                    "id": hid,
                    "finding_ref": hid,
                    "finding_type": finding.attack_class,
                    "severity": finding.severity,
                    "cwe": finding.cwe,
                    "line": None,
                    "code_snippet": cand.function_name,
                    "explanation": finding.description,
                    "data_flow_trace": f"runtime probe via Phase B+: {finding.runtime_evidence}",
                    "proof_of_concept": (f"{cand.function_name}(*{finding.test_input_args})"),
                    "confidence": 1.0,
                    "runtime_evidence": finding.runtime_evidence,
                }
            )

    stats.sandbox_calls += n_probes_run

    # v1.5 design choice (Fix #2): probe-confirmed HRP findings are
    # SURFACED via findings_validated (engine → ScanResult.dast_findings)
    # but are NOT appended to ``l1_output["hypotheses"]``. The probe
    # stage IS the test — re-running them through Phase A in iter 1
    # would (a) double the sandbox cost, (b) produce contradictory
    # NOT_TESTED verdicts when Fly returns stub traces, (c) make the
    # journal a mess of duplicate records.
    #
    # Phase B (iter ≥ 2, model-driven exploration) still has visibility
    # of HRP findings via journal_summary — it sees the
    # ``phase_b_hypothesis verdict=confirmed`` records and won't re-
    # propose them as new hypotheses.

    # Return the confirmed HRP_ finding dicts so run_dast can:
    # 1. Extend findings_validated with their IDs (→ engine surfacing).
    # 2. Decide whether to bump max_dast_verdict_rank (Fix #1).
    return findings_from_probes


def _iter_inner_sandbox_clients(sandbox: SandboxClient):
    """Yield each underlying SandboxClient — for MultiImageSandboxClient
    iterate the per-hint inners; for any other client yield itself.

    Phase C uses this to mutate file_content_map across all backing
    Firecracker clients when injecting the patched source.
    """
    inner_by_hint = getattr(sandbox, "inner_by_hint", None)
    if isinstance(inner_by_hint, dict):
        yield from inner_by_hint.values()
    else:
        yield sandbox


async def _run_phase_c_fix_verify(
    *,
    file_record: dict,
    findings_validated: list[str],
    l1_output: dict,
    iter1_plans: list[dict],
    inference: InferenceFn,
    sandbox: SandboxClient,
    journal: Journal,
) -> dict[str, Any]:
    """Phase C (v1.2): generate a patch for confirmed findings, then re-test
    iter-1 sandbox plans against the patched source.

    Returns a dict with patched_source, fix_summary, post-patch verdict,
    and per-finding neutralization status. Caller is expected to surface
    this in DastResult.phase_c — no journal records are written to keep
    Phase C effects visible only in the structured result.
    """
    started = time.time()
    file_id = file_record.get("file_id", "")
    file_name = file_record.get("file_name", "unknown")
    original_text = file_record.get("source_text", "") or ""
    original_bytes = original_text.encode("utf-8", errors="replace")

    # Find the L1 hypothesis dicts that correspond to confirmed findings,
    # so we can hand the patcher the L1-suggested fix as a starting point.
    # Index by both id and finding_ref since journal claim_id ↔ hypothesis
    # id, but findings_validated may use either form.
    hyp_by_ref: dict[str, dict] = {}
    for h in l1_output.get("hypotheses") or []:
        if not isinstance(h, dict):
            continue
        h_id = h.get("id")
        h_ref = h.get("finding_ref")
        if h_id:
            hyp_by_ref[h_id] = h
        if h_ref and h_ref != h_id:
            hyp_by_ref[h_ref] = h
    confirmed = [hyp_by_ref[ref] for ref in findings_validated if ref in hyp_by_ref]

    if not confirmed:
        return {
            "attempted": False,
            "skipped_reason": "no_confirmed_findings_with_finding_ref",
            "elapsed_s": round(time.time() - started, 2),
        }

    # ── Binary-artifact guard ────────────────────────────────────────
    # Phase C's patch generator produces a ``patched_source`` text blob
    # which the replay step writes back as the "fixed" file. That works
    # for source-code artifacts but is WRONG for binary ML files
    # (.pkl/.pt/.bin/.safetensors/.h5/.onnx) — the model can't emit
    # valid binary bytes, so a text "patch" of a pickle is corrupt and
    # the replay would load garbage. Instead we emit structured
    # remediation guidance: replace the artifact with safetensors,
    # don't auto-patch. Phase C status is UNVERIFIABLE because we did
    # NOT run a sandbox replay against a synthetic fix — we declined.
    ml_format = file_record.get("ml_format")
    if ml_format:
        guidance_summary = (
            f"Argus does not auto-patch {ml_format} artifacts in v1.2: "
            "binary model files cannot be safely text-edited and a "
            "model-emitted byte-level patch would not be verifiable. "
            "Recommended remediation: regenerate the model from a clean "
            "training pipeline and serialize using `safetensors` instead "
            "of pickle / torch.save() — safetensors is structurally "
            "incapable of carrying executable __reduce__ payloads. If a "
            "safetensors version isn't available, treat the artifact as "
            "discardable."
        )
        return {
            "attempted": False,
            "skipped_reason": "binary_artifact_remediation_is_replacement_not_patch",
            "ml_format": ml_format,
            "fix_summary": guidance_summary,
            "post_patch_verdict": "UNVERIFIABLE",
            "per_finding": [
                {
                    "finding_id": h.get("id") or h.get("finding_ref"),
                    "post_patch_status": "UNVERIFIABLE",
                    "rationale": (
                        "Binary ML artifact — Argus declined to auto-patch. "
                        "See fix_summary for remediation guidance."
                    ),
                }
                for h in confirmed
            ],
            "n_neutralized": 0,
            "n_still_exploitable": 0,
            "elapsed_s": round(time.time() - started, 2),
        }

    # ── Step 1: generate patch ────────────────────────────────────────
    fix_prompt = dast_prompts.build_phase_c_fix_prompt(
        file_name=file_name,
        original_source=original_text,
        confirmed_findings=confirmed,
    )
    fix_resp = await inference(
        fix_prompt,
        {"temperature": 0.0, "max_tokens": 8192, "seed": 0},
        dast_prompts.phase_c_fix_schema(),
    )
    fix_obj = _parse_json_or_empty(fix_resp.get("text", ""))
    patched_source = (fix_obj.get("patched_source") or "").strip()
    fix_summary = (fix_obj.get("fix_summary") or "").strip()
    per_finding_fixes = fix_obj.get("per_finding_fixes") or []
    fix_in = (fix_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
    fix_out = (fix_resp.get("usage") or {}).get("completion_tokens", 0) or 0

    if not patched_source:
        return {
            "attempted": True,
            "patched_source": None,
            "fix_summary": fix_summary,
            "skipped_reason": "patch_generation_returned_empty",
            "tokens_in": fix_in,
            "tokens_out": fix_out,
            "elapsed_s": round(time.time() - started, 2),
        }

    # ── Step 2: replay iter-1 plans against the patched source ────────
    patched_bytes = patched_source.encode("utf-8", errors="replace")
    re_traces: list[dict] = []
    re_plans: list[dict] = []
    n_replays = 0
    try:
        # Inject patched content into every backing sandbox's content map
        for client in _iter_inner_sandbox_clients(sandbox):
            cmap = getattr(client, "file_content_map", None)
            if isinstance(cmap, dict):
                cmap[file_id] = patched_bytes

        # Re-submit each iter-1 plan with a fresh plan_id so the journal
        # can distinguish Phase C runs from the original iter-1 ones.
        for p in iter1_plans:
            if not isinstance(p, dict):
                continue
            if p.get("plan_status") != "executable":
                continue
            hid = p.get("hypothesis_id", "")
            raw_hint = p.get("image_hint")
            image_hint = raw_hint if isinstance(raw_hint, str) and raw_hint else "minimal"
            plan = SandboxPlan(
                plan_id=f"phaseC-{hid}",
                file_id=file_id,
                hypothesis_id=hid,
                commands=p.get("commands") or [],
                expected_oracle=p.get("oracle") or "",
                payload=p.get("payload") or "",
                timeout_sec=int(p.get("timeout_sec") or 30),
                image_hint=image_hint,
                file_name=file_name,
                synthesis_context={
                    "phase": "C",
                    "purpose": "fix_verify",
                    "patched": True,
                },
            )
            try:
                trace = await sandbox.submit(plan)
                re_traces.append(trace.model_dump())
                re_plans.append(p)
                n_replays += 1
            except Exception:  # noqa: BLE001
                continue
    finally:
        # ALWAYS restore original content so subsequent operations
        # (e.g., engine post-DAST hooks) see the unpatched file.
        for client in _iter_inner_sandbox_clients(sandbox):
            cmap = getattr(client, "file_content_map", None)
            if isinstance(cmap, dict):
                cmap[file_id] = original_bytes

    # ── Step 3: re-run Phase A verdict against the new traces ────────
    # Use patched_source as file_text so the verdict-judge sees the
    # actual code that was tested. Empty journal_summary because Phase C
    # is a fresh evaluation, not a continuation of prior iters.
    if not re_traces:
        return {
            "attempted": True,
            "patched_source": patched_source,
            "fix_summary": fix_summary,
            "per_finding_fixes": per_finding_fixes,
            "skipped_reason": "all_replays_failed",
            "tokens_in": fix_in,
            "tokens_out": fix_out,
            "n_replays": 0,
            "elapsed_s": round(time.time() - started, 2),
        }

    verdict_prompt = dast_prompts.build_phase_a_verdict_prompt(
        file_text=patched_source,
        l1_output=l1_output,
        plans=re_plans,
        traces=re_traces,
        journal_summary={
            "phase_c_replay": True,
            "note": (
                "These traces are from re-running the original "
                "iter-1 plans against a PATCHED version of the file. "
                "If the patch neutralized the exploit, the traces should "
                "show no oracle hits."
            ),
        },
    )
    verdict_resp = await inference(
        verdict_prompt,
        {"temperature": 0.0, "max_tokens": 6144, "seed": 0},
        dast_prompts.phase_a_verdict_schema(),
    )
    verdict_obj = _parse_json_or_empty(verdict_resp.get("text", ""))
    cur = (verdict_obj.get("current_verdict") or {}) if isinstance(verdict_obj, dict) else {}
    post_patch_verdict = cur.get("verdict_label", "unknown")
    new_claim_verdicts = (
        (verdict_obj.get("claim_verdicts") or []) if isinstance(verdict_obj, dict) else []
    )
    new_v_by_hid = {
        cv.get("hypothesis_id"): cv.get("verdict")
        for cv in new_claim_verdicts
        if isinstance(cv, dict)
    }

    verdict_in = (verdict_resp.get("usage") or {}).get("prompt_tokens", 0) or 0
    verdict_out = (verdict_resp.get("usage") or {}).get("completion_tokens", 0) or 0

    # ── Step 4: per-finding NEUTRALIZED / STILL_EXPLOITABLE / UNVERIFIABLE
    per_finding: list[dict] = []
    for ref in findings_validated:
        h = hyp_by_ref.get(ref) or {}
        hid = h.get("id") or ref
        new_v = new_v_by_hid.get(hid)
        if new_v == "confirmed":
            status = "STILL_EXPLOITABLE"
        elif new_v in ("rejected", "inconclusive"):
            status = "NEUTRALIZED"
        else:
            status = "UNVERIFIABLE"
        per_finding.append(
            {
                "finding_ref": ref,
                "hypothesis_id": hid,
                "original_status": "CONFIRMED",
                "post_patch_status": status,
                "post_patch_verdict": new_v or "unknown",
            }
        )

    n_neutralized = sum(1 for pf in per_finding if pf["post_patch_status"] == "NEUTRALIZED")
    n_still_exploitable = sum(
        1 for pf in per_finding if pf["post_patch_status"] == "STILL_EXPLOITABLE"
    )

    return {
        "attempted": True,
        "patched_source": patched_source,
        "fix_summary": fix_summary,
        "per_finding_fixes": per_finding_fixes,
        "post_patch_verdict": post_patch_verdict,
        "per_finding": per_finding,
        "n_neutralized": n_neutralized,
        "n_still_exploitable": n_still_exploitable,
        "n_unverifiable": len(per_finding) - n_neutralized - n_still_exploitable,
        "n_replays": n_replays,
        "tokens_in": fix_in + verdict_in,
        "tokens_out": fix_out + verdict_out,
        "elapsed_s": round(time.time() - started, 2),
    }
