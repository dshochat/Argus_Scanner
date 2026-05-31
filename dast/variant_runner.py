"""DAST-301 — Phase D Variant Analysis runner (v1 MVP).

Owns the async pipeline that takes a confirmed Phase A finding and
produces a :class:`PhaseDResult`:

  1. Extract semantic signature (Opus call).
  2. Enumerate AST candidates in the same file (deterministic).
  3. Rank candidates via the variant judge (single Opus call).
  4. For each ranked candidate above threshold, retarget the seed
     harness and submit to the sandbox.
  5. Aggregate outcomes; surface confirmed variants for Phase C.

Cost gate: aborts when running cost exceeds
``PHASE_D_MAX_COST_PER_SEED_USD``. The gate is checked BEFORE each
sandbox submission (the expensive step), so the runner never
overshoots by more than one variant's worth of spend.

Failure mode: any step's exception is captured into the result dict's
``skipped_reason`` field. Phase D never blocks the broader DAST loop.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict
from typing import Any

from dast.inference import InferenceFn, validate_against_schema
from dast.sandbox.client import SandboxClient, SandboxPlan
from dast.variant_analysis import (
    DEFAULT_VARIANT_TIMEOUT_SEC,
    MAX_VARIANT_CANDIDATES_PER_SEED,
    MIN_VARIANT_SIMILARITY_THRESHOLD,
    PHASE_D_MAX_COST_PER_SEED_USD,
    PhaseDResult,
    SemanticSignature,
    VariantCandidate,
    VariantOutcome,
    extract_variant_candidates,
    extract_variant_candidates_from_graph,
    resolve_seed_qualname_from_ast,
    retarget_harness_for_cross_file_variant,
    retarget_harness_for_variant,
)

log = logging.getLogger("argus.dast.variant_runner")


# Verdict constants (mirror existing Phase A vocabulary).
VERDICT_CONFIRMED = "confirmed"
VERDICT_REFUTED = "refuted"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_NOT_TESTABLE = "not_testable"


async def run_phase_d(
    *,
    file_record: dict[str, Any],
    seed_finding: dict[str, Any],
    seed_phase_a_validation: dict[str, Any],
    seed_plan: dict[str, Any] | None,
    inference: InferenceFn,
    sandbox: SandboxClient,
    language: str = "python",
    max_cost_per_seed_usd: float = PHASE_D_MAX_COST_PER_SEED_USD,
    judge_threshold: float = MIN_VARIANT_SIMILARITY_THRESHOLD,
    project_root: str | None = None,
    entry_rel_path: str | None = None,
) -> PhaseDResult:
    """Run Phase D variant analysis on ONE confirmed seed finding.

    Returns a :class:`PhaseDResult` regardless of outcome. Callers
    surface this in ``DastResult.variant_analysis`` and feed the
    ``confirmed_variant_ids`` back into ``findings_validated`` so
    Phase C remediates the variants alongside the seed.

    Args:
      file_record: the orchestrator's file_record dict (carries
        source_text, file_name, file_id).
      seed_finding: the L1 vulnerability dict (carries cwe, type,
        line, code, explanation, fix).
      seed_phase_a_validation: the matching ``per_finding_validation``
        entry (carries proof_of_concept + runtime_evidence).
      seed_plan: the seed finding's Phase A plan record (commands,
        oracle, payload). Used as the harness template for variants.
        When None, Phase D extracts variants but cannot verify them
        and they stay UNVERIFIED (still surfaced for human review).
      inference: the Opus inference function (Phase D wants the
        deep-thinking model — variant analysis is high-stakes
        reasoning).
      sandbox: the sandbox client for variant verification.
      language: file language (``"python"`` for v1). Other values
        return ``unsupported_language`` skip.
      max_cost_per_seed_usd: per-seed budget cap.
      judge_threshold: minimum similarity score (0.0–1.0) to keep
        a candidate for harness verification.
    """
    started = time.time()
    seed_finding_id = (
        seed_finding.get("id")
        or seed_finding.get("finding_id")
        or seed_phase_a_validation.get("finding_id")
        or f"seed-{seed_finding.get('line', '0')}"
    )

    file_source = file_record.get("source_text") or ""
    file_name = file_record.get("file_name") or "module.py"
    file_id = file_record.get("file_id") or ""

    result = PhaseDResult(seed_finding_id=str(seed_finding_id), attempted=True)

    if language != "python":
        # v1.1 (DAST-302) will add tree-sitter for TS/JS.
        result.attempted = False
        result.skipped_reason = "unsupported_language"
        result.elapsed_ms = int((time.time() - started) * 1000)
        return result

    if not file_source.strip():
        result.attempted = False
        result.skipped_reason = "no_source_text"
        result.elapsed_ms = int((time.time() - started) * 1000)
        return result

    cost_used = 0.0

    # ── Step 1: signature extraction ──────────────────────────────────
    try:
        signature, sig_in, sig_out, sig_cost = await _extract_signature(
            file_name=file_name,
            file_source=file_source,
            seed_finding=seed_finding,
            seed_phase_a_validation=seed_phase_a_validation,
            inference=inference,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("Phase D signature extraction failed: %s", exc)
        result.skipped_reason = "signature_extraction_failed"
        result.elapsed_ms = int((time.time() - started) * 1000)
        return result

    if signature is None:
        result.skipped_reason = "signature_extraction_failed"
        result.elapsed_ms = int((time.time() - started) * 1000)
        return result

    result.signature = signature
    result.tokens_in += sig_in
    result.tokens_out += sig_out
    cost_used += sig_cost

    # ── Step 2: AST candidate hunt ────────────────────────────────────
    # v1.1 (DAST-302): when ``project_root`` is supplied AND the
    # language is Python, build a cross-file code graph and hunt
    # variants across the WHOLE project. Otherwise fall back to v1's
    # same-file behavior.
    #
    # Seed exclusion: try sources in decreasing reliability —
    #   1. LLM-extracted ``signature.seed_function`` (most semantic
    #      context; can drift if the signature prompt isn't sharp)
    #   2. Structured field on the L1 hypothesis dict (function_name,
    #      function, callable) or a ``def <name>`` regex in ``code``
    #   3. AST walk of file source by seed line (deterministic,
    #      doesn't depend on LLM/L1 schema — the backstop)
    # ``seed_line`` is ALSO passed to the extractors as a defense-in-
    # depth filter: even if all three qualname sources fail, no
    # candidate whose body encloses the seed line can surface.
    seed_line = int(seed_finding.get("line") or 0)
    seed_function = (
        signature.seed_function
        or _guess_seed_function(seed_finding)
        or resolve_seed_qualname_from_ast(file_source, seed_line)
    )
    if seed_function and not signature.seed_function:
        # Keep the signature dict consistent with what we actually
        # used for exclusion (helps disclosure tooling + report).
        signature.seed_function = seed_function
    candidates: list[VariantCandidate] = []
    cross_file_graph = None
    seed_rel_path = entry_rel_path or ""

    if language == "python" and project_root:
        # Build cross-file graph; fall back to same-file on failure.
        try:
            from pathlib import Path as _Path  # noqa: PLC0415

            from dast.code_graph import build_python_code_graph  # noqa: PLC0415

            root_path = _Path(project_root)
            entry_abs = root_path / (seed_rel_path or file_name)
            cross_file_graph = build_python_code_graph(
                project_root=root_path,
                entry_file=entry_abs,
            )
            if cross_file_graph.nodes:
                candidates = extract_variant_candidates_from_graph(
                    graph=cross_file_graph,
                    signature=signature,
                    exclude_qualname=seed_function,
                    exclude_file_path=cross_file_graph.entry_file or seed_rel_path,
                    exclude_seed_line=seed_line,
                )
                log.info(
                    "Phase D cross-file: %d candidates across %d files "
                    "(seed_rel=%s)",
                    len(candidates),
                    cross_file_graph.files_scanned,
                    cross_file_graph.entry_file,
                )
            else:
                log.info(
                    "Phase D cross-file: graph empty (root=%s) — falling "
                    "back to same-file hunt",
                    project_root,
                )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Phase D cross-file graph build failed: %s — falling "
                "back to same-file hunt",
                exc,
            )
            cross_file_graph = None

    # Fall back to same-file behavior when:
    #   - language isn't Python (TS/JS still v1 same-file in v1.1)
    #   - no project_root supplied (single-file scan)
    #   - graph build failed
    #   - graph yielded zero candidates
    if not candidates:
        candidates = extract_variant_candidates(
            source_code=file_source,
            signature=signature,
            language=language,
            exclude_qualname=seed_function,
            exclude_seed_line=seed_line,
        )

    result.candidates_total = len(candidates)
    if not candidates:
        result.skipped_reason = "no_candidates"
        result.elapsed_ms = int((time.time() - started) * 1000)
        result.cost_usd = cost_used
        return result

    # ── Step 3: LLM ranking ───────────────────────────────────────────
    if cost_used >= max_cost_per_seed_usd:
        result.skipped_reason = "budget_exhausted"
        result.elapsed_ms = int((time.time() - started) * 1000)
        result.cost_usd = cost_used
        return result

    try:
        ranked, judge_in, judge_out, judge_cost = await _rank_candidates(
            signature=signature,
            candidates=candidates,
            inference=inference,
            threshold=judge_threshold,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("Phase D variant judge failed: %s", exc)
        result.skipped_reason = "variant_judge_failed"
        result.elapsed_ms = int((time.time() - started) * 1000)
        result.cost_usd = cost_used
        return result

    result.tokens_in += judge_in
    result.tokens_out += judge_out
    cost_used += judge_cost
    result.candidates_ranked = len(ranked)

    if not ranked:
        # Judge filtered all candidates below threshold.
        result.cost_usd = cost_used
        result.elapsed_ms = int((time.time() - started) * 1000)
        return result

    # Cap to MAX_VARIANT_CANDIDATES_PER_SEED to bound sandbox spend.
    ranked = sorted(
        ranked, key=lambda c: c.similarity_score, reverse=True
    )[:MAX_VARIANT_CANDIDATES_PER_SEED]

    # ── Step 4: harness retarget + sandbox verify ─────────────────────
    if seed_plan is None or not isinstance(seed_plan, dict):
        # Without a seed plan we can't retarget. Record candidates
        # but classify them as not_testable for human review.
        for cand in ranked:
            result.outcomes.append(
                VariantOutcome(
                    candidate=cand,
                    verdict=VERDICT_NOT_TESTABLE,
                    rationale="No seed plan available to retarget for variant verification.",
                )
            )
        result.cost_usd = cost_used
        result.elapsed_ms = int((time.time() - started) * 1000)
        return result

    seed_plan_commands = list(seed_plan.get("commands") or [])
    seed_plan_oracle = str(seed_plan.get("oracle") or "")
    seed_plan_payload = str(seed_plan.get("payload") or "")
    seed_plan_image_hint = str(seed_plan.get("image_hint") or "lean")
    seed_plan_timeout = int(seed_plan.get("timeout_sec") or DEFAULT_VARIANT_TIMEOUT_SEC)

    for idx, cand in enumerate(ranked):
        # Cost gate: check BEFORE each sandbox submission. The next
        # submission costs ~$0.05 — abort cleanly if it would put us
        # over budget.
        if cost_used >= max_cost_per_seed_usd:
            log.info(
                "Phase D: budget exhausted (%.4f >= %.4f); skipping "
                "remaining %d variants",
                cost_used,
                max_cost_per_seed_usd,
                len(ranked) - idx,
            )
            # Remaining candidates surface as not_testable so the
            # operator sees them.
            for remaining in ranked[idx:]:
                result.outcomes.append(
                    VariantOutcome(
                        candidate=remaining,
                        verdict=VERDICT_NOT_TESTABLE,
                        rationale=(
                            f"Phase D budget exhausted at "
                            f"${cost_used:.4f}; variant not verified."
                        ),
                    )
                )
            result.skipped_reason = "budget_exhausted"
            break

        outcome, sandbox_cost = await _verify_variant(
            file_id=file_id,
            file_name=file_name,
            seed_function=seed_function,
            seed_plan_commands=seed_plan_commands,
            seed_plan_oracle=seed_plan_oracle,
            seed_plan_payload=seed_plan_payload,
            seed_plan_image_hint=seed_plan_image_hint,
            seed_plan_timeout=seed_plan_timeout,
            signature=signature,
            candidate=cand,
            sandbox=sandbox,
            seed_file_rel_path=seed_rel_path
            or (cross_file_graph.entry_file if cross_file_graph else ""),
        )
        cost_used += sandbox_cost
        result.outcomes.append(outcome)
        if outcome.verdict == VERDICT_CONFIRMED:
            variant_id = f"D-{seed_finding_id}-{idx + 1}"
            result.confirmed_variant_ids.append(variant_id)

    result.cost_usd = cost_used
    result.elapsed_ms = int((time.time() - started) * 1000)
    return result


# ── Step 1 helper: signature extraction ──────────────────────────────


async def _extract_signature(
    *,
    file_name: str,
    file_source: str,
    seed_finding: dict[str, Any],
    seed_phase_a_validation: dict[str, Any],
    inference: InferenceFn,
) -> tuple[SemanticSignature | None, int, int, float]:
    """Call the signature-extraction model. Returns
    ``(signature, tokens_in, tokens_out, cost_usd)``."""
    from dast.prompts import (  # noqa: PLC0415
        build_phase_d_signature_prompt,
        phase_d_signature_schema,
    )

    prompt = build_phase_d_signature_prompt(
        file_name=file_name,
        file_source=file_source,
        seed_finding=seed_finding,
        proof_of_concept=str(seed_phase_a_validation.get("proof_of_concept") or ""),
        runtime_evidence=str(seed_phase_a_validation.get("runtime_evidence") or ""),
    )
    schema = phase_d_signature_schema()

    resp = await inference(
        prompt,
        {"temperature": 0.0, "max_tokens": 2048, "seed": 0},
        schema,
    )

    tokens_in = (resp.get("usage") or {}).get("prompt_tokens", 0) or 0
    tokens_out = (resp.get("usage") or {}).get("completion_tokens", 0) or 0
    # Rough Opus 4.6 input + output rate. Refined later via the
    # engine's actual cost-tracking.
    cost_usd = (tokens_in / 1_000_000) * 15.0 + (tokens_out / 1_000_000) * 75.0

    if not resp.get("schema_valid", True):
        log.warning(
            "Phase D signature extraction returned invalid schema: %s",
            resp.get("schema_error", ""),
        )
        return None, tokens_in, tokens_out, cost_usd

    try:
        parsed = json.loads(resp.get("text") or "{}")
    except json.JSONDecodeError as exc:
        log.warning("Phase D signature JSON decode failed: %s", exc)
        return None, tokens_in, tokens_out, cost_usd

    # Defense-in-depth: re-validate even if the model claimed schema_valid.
    ok, err = validate_against_schema(parsed, schema)
    if not ok:
        log.warning("Phase D signature re-validation failed: %s", err)
        return None, tokens_in, tokens_out, cost_usd

    sig = SemanticSignature(
        attack_class=str(parsed.get("attack_class", "")),
        cwe=str(parsed.get("cwe", seed_finding.get("cwe", ""))),
        source_shape=str(parsed.get("source_shape", "")),
        transformations=[
            str(t) for t in (parsed.get("transformations") or []) if isinstance(t, str)
        ],
        sink_kind=str(parsed.get("sink_kind", "")),
        sink_callee=str(parsed.get("sink_callee", "")),
        missing_guards=[
            str(g) for g in (parsed.get("missing_guards") or []) if isinstance(g, str)
        ],
        seed_finding_id=str(
            seed_finding.get("id") or seed_finding.get("finding_id") or ""
        ),
    )
    # The seed function's name is purely a function of (source code,
    # line). The LLM has no information advantage here — resolve it
    # deterministically from the AST so candidate exclusion is reliable
    # regardless of how the signature prompt evolves. Falls back to
    # ``_guess_seed_function`` (structured L1 fields / regex) when the
    # AST walk returns empty (e.g., the seed line is at module scope).
    seed_line = int(seed_finding.get("line") or 0)
    sig.seed_function = resolve_seed_qualname_from_ast(
        file_source, seed_line
    ) or _guess_seed_function(seed_finding)
    return sig, tokens_in, tokens_out, cost_usd


# ── Step 3 helper: variant judge ─────────────────────────────────────


async def _rank_candidates(
    *,
    signature: SemanticSignature,
    candidates: list[VariantCandidate],
    inference: InferenceFn,
    threshold: float,
) -> tuple[list[VariantCandidate], int, int, float]:
    """Call the variant judge with the full candidate batch. Returns
    candidates whose score >= threshold, sorted by score desc.
    Tuple is ``(kept, tokens_in, tokens_out, cost_usd)``."""
    from dast.prompts import (  # noqa: PLC0415
        build_phase_d_variant_judge_prompt,
        phase_d_variant_judge_schema,
    )

    cand_dicts = [
        {
            "function_name": c.qualname or c.function_name,
            "line_number": c.line_number,
            "source_snippet": c.source_snippet,
            "sink_callees_observed": c.sink_callees_observed,
        }
        for c in candidates
    ]
    sig_dict = asdict(signature)
    prompt = build_phase_d_variant_judge_prompt(
        signature=sig_dict,
        candidates=cand_dicts,
    )
    schema = phase_d_variant_judge_schema()

    resp = await inference(
        prompt,
        {"temperature": 0.0, "max_tokens": 2048, "seed": 0},
        schema,
    )
    tokens_in = (resp.get("usage") or {}).get("prompt_tokens", 0) or 0
    tokens_out = (resp.get("usage") or {}).get("completion_tokens", 0) or 0
    cost_usd = (tokens_in / 1_000_000) * 15.0 + (tokens_out / 1_000_000) * 75.0

    if not resp.get("schema_valid", True):
        log.warning(
            "Phase D variant judge returned invalid schema: %s",
            resp.get("schema_error", ""),
        )
        return [], tokens_in, tokens_out, cost_usd

    try:
        parsed = json.loads(resp.get("text") or "{}")
    except json.JSONDecodeError as exc:
        log.warning("Phase D judge JSON decode failed: %s", exc)
        return [], tokens_in, tokens_out, cost_usd

    rankings = parsed.get("rankings") or []
    # Build a name → (score, rationale) lookup.
    by_name: dict[str, tuple[float, str]] = {}
    for r in rankings:
        if not isinstance(r, dict):
            continue
        name = str(r.get("function_name") or "")
        try:
            score = float(r.get("similarity_score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        rationale = str(r.get("rationale") or "")
        if name:
            by_name[name] = (max(0.0, min(1.0, score)), rationale)

    # Annotate + filter.
    kept: list[VariantCandidate] = []
    for cand in candidates:
        lookup_key = cand.qualname or cand.function_name
        score, _rationale = by_name.get(lookup_key, (0.0, ""))
        cand.similarity_score = score
        if score >= threshold:
            kept.append(cand)
    return kept, tokens_in, tokens_out, cost_usd


# ── Step 4 helper: variant verification ──────────────────────────────


async def _verify_variant(
    *,
    file_id: str,
    file_name: str,
    seed_function: str,
    seed_plan_commands: list[str],
    seed_plan_oracle: str,
    seed_plan_payload: str,
    seed_plan_image_hint: str,
    seed_plan_timeout: int,
    signature: SemanticSignature,
    candidate: VariantCandidate,
    sandbox: SandboxClient,
    seed_file_rel_path: str = "",
) -> tuple[VariantOutcome, float]:
    """Retarget the seed harness to ``candidate``, submit, classify.

    Returns ``(outcome, sandbox_cost_usd)``. The sandbox cost is
    approximate — refined by the engine's actual cost-tracker.
    """
    started = time.time()
    # v1.1: use cross-file retargeter when the variant has a file_path
    # attribute (set by extract_variant_candidates_from_graph). The
    # cross-file retargeter internally falls back to same-file
    # behavior when the variant's file_path matches ``seed_file_rel_path``.
    variant_file_path = candidate.file_path or ""
    if variant_file_path:
        retargeted_commands = retarget_harness_for_cross_file_variant(
            seed_plan_commands=seed_plan_commands,
            seed_function=seed_function,
            variant=candidate,
            signature=signature,
            seed_file_rel_path=seed_file_rel_path,
        )
    else:
        retargeted_commands = retarget_harness_for_variant(
            seed_plan_commands=seed_plan_commands,
            seed_function=seed_function,
            variant=candidate,
            signature=signature,
        )

    hyp_id = f"PhaseD-{candidate.function_name}-{uuid.uuid4().hex[:6]}"
    plan = SandboxPlan(
        plan_id=f"PhaseD-{file_id[:8]}-{uuid.uuid4().hex[:8]}",
        file_id=file_id,
        hypothesis_id=hyp_id,
        commands=retargeted_commands,
        expected_oracle=seed_plan_oracle,
        payload=seed_plan_payload,
        timeout_sec=seed_plan_timeout,
        image_hint=seed_plan_image_hint,
        file_name=file_name,
        synthesis_context={
            "phase": "D",
            "purpose": "variant_verify",
            "seed_finding_id": signature.seed_finding_id,
            "variant_function": candidate.function_name,
            "similarity_score": candidate.similarity_score,
        },
    )

    sandbox_cost = 0.05  # rough per-microVM submission cost on Fly

    try:
        trace = await sandbox.submit(plan)
    except Exception as exc:  # noqa: BLE001
        log.warning("Phase D sandbox.submit failed for %s: %s", candidate.function_name, exc)
        return (
            VariantOutcome(
                candidate=candidate,
                verdict=VERDICT_INCONCLUSIVE,
                rationale=f"Sandbox submission failed: {type(exc).__name__}: {str(exc)[:200]}",
                sandbox_plan_id=plan.plan_id,
                elapsed_ms=int((time.time() - started) * 1000),
            ),
            sandbox_cost,
        )

    # Classify via the same oracle approach as Phase A: if the seed's
    # oracle string appears in stdout/events, the variant is confirmed.
    # For the v1 MVP we use literal substring match against
    # stdout_excerpt + stderr_excerpt + event payloads.
    oracle = seed_plan_oracle or signature.sink_callee
    matched = False
    matched_signal = ""
    if oracle:
        # Check stdout + stderr.
        for field_name in ("stdout_excerpt", "stderr_excerpt"):
            field_val = getattr(trace, field_name, None)
            if isinstance(field_val, str) and oracle.lower() in field_val.lower():
                matched = True
                matched_signal = f"{field_name}: {oracle}"
                break
        # Check event payloads (network captures, etc.)
        if not matched:
            for ev in trace.events or []:
                payload_str = str(getattr(ev, "payload", "") or "")
                if oracle.lower() in payload_str.lower():
                    matched = True
                    matched_signal = f"event:{ev.kind}: {oracle}"
                    break

    if matched:
        return (
            VariantOutcome(
                candidate=candidate,
                verdict=VERDICT_CONFIRMED,
                rationale=(
                    f"Variant exhibits the same {signature.attack_class} "
                    f"flaw as the seed (similarity={candidate.similarity_score:.2f}). "
                    f"Oracle matched in {matched_signal}."
                ),
                sandbox_plan_id=plan.plan_id,
                runtime_evidence=matched_signal,
                elapsed_ms=int((time.time() - started) * 1000),
            ),
            sandbox_cost,
        )

    return (
        VariantOutcome(
            candidate=candidate,
            verdict=VERDICT_REFUTED,
            rationale=(
                f"No oracle signal observed for {signature.attack_class} "
                f"in candidate's sandbox trace (similarity={candidate.similarity_score:.2f})."
            ),
            sandbox_plan_id=plan.plan_id,
            elapsed_ms=int((time.time() - started) * 1000),
        ),
        sandbox_cost,
    )


def _guess_seed_function(seed_finding: dict[str, Any]) -> str:
    """Best-effort extraction of the seed function's name from the L1
    finding dict. Used to exclude the seed from candidate hunting."""
    # Some L1 outputs surface the function in a structured field.
    for key in ("function_name", "function", "callable"):
        val = seed_finding.get(key)
        if isinstance(val, str) and val:
            return val
    # Fallback: parse the code snippet for ``def <name>``.
    code = str(seed_finding.get("code") or "")
    import re  # noqa: PLC0415

    m = re.search(r"\bdef\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(", code)
    if m:
        return m.group(1)
    return ""


__all__ = [
    "VERDICT_CONFIRMED",
    "VERDICT_INCONCLUSIVE",
    "VERDICT_NOT_TESTABLE",
    "VERDICT_REFUTED",
    "run_phase_d",
]
