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
        fref = hyp.get("finding_ref") or ((hyp.get("upstream_chain") or {}).get("confirmed_finding_ref"))
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

    for it in range(1, MAX_ITERATIONS + 1):
        it_started = time.time()
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
        claim_verdicts = (verdict_obj.get("claim_verdicts") or []) if isinstance(verdict_obj, dict) else []
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
            fref = hyp.get("finding_ref") or ((hyp.get("upstream_chain") or {}).get("confirmed_finding_ref"))
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
                and not _has_refutation_of_prior_confirmed(claim_verdicts, hyp_index, prev_confirmed)
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
        new_hyps = (explore_obj.get("new_hypotheses") or []) if isinstance(explore_obj, dict) else []
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
        iter_in = st.phase_a_plan_in + st.phase_a_verdict_in + st.phase_b_in
        iter_out = st.phase_a_plan_out + st.phase_a_verdict_out + st.phase_b_out
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
    )
