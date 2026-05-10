"""DAST-102 — DAST runner wrapper for engine.scan_file.

The engine's :func:`scanner.engine.scan_file` accepts a ``dast_runner``
callable with shape::

    async def runner(filename: str, content: bytes, pp: Preprocessing,
                     scan_result: ScanResult) -> dict

This module produces such a callable. It bridges between the engine's
analysis-output shape (vulnerabilities + behavioral_profile + chains)
and the orchestrator's expected ``l1_output`` (verdict + hypotheses),
constructs the sandbox / validator / journal, calls
:func:`dast.orchestrator.run_dast`, and maps the
:class:`~dast.orchestrator.DastResult` back to the dict the engine
consumes.

Public API:

  :func:`make_dast_runner`
    Generic factory — pass an inference fn, a sandbox client, optionally
    a validator + journal dir. Used by tests with stubs and by
    :func:`make_dast_runner_from_env` with the production stack.

  :func:`make_dast_runner_from_env`
    Reads ``ANTHROPIC_API_KEY``, ``FLY_API_TOKEN``, and the
    ``ECHO_DAST_IMAGE_*`` env vars; returns the wired runner or
    ``None`` if any required config is missing. Engine handles
    ``dast_runner=None`` as "skip DAST," so a missing Fly setup
    degrades gracefully to L1-only scans.

The Fly sandbox stack itself is stood up by DAST-106 (separate task).
Until then, this runner builds correctly but ``make_dast_runner_from_env``
returns ``None`` on any dev machine that hasn't set ``FLY_API_TOKEN``
+ image tags.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from dast.inference import InferenceFn, make_dast_sonnet_inference
from dast.orchestrator import DastResult, run_dast
from dast.sandbox.client import (
    FirecrackerSandboxClient,
    FlyMachinesClient,
    MultiImageSandboxClient,
    SandboxClient,
)
from dast.validator import HypothesisValidator

log = logging.getLogger("argus.dast.runner")

DastRunner = Callable[..., Awaitable[dict]]

DEFAULT_FLY_APP = "argus-dast-sandbox"
DEFAULT_FLY_REGION = "iad"

# Sonnet 4.6 pricing for cost estimation. DAST-103 will mix in Opus
# (iter-3 escalation); refine the cost calc when that lands.
_DAST_COST_IN_PER_M = 3.0
_DAST_COST_OUT_PER_M = 15.0


# ── Translation helpers (pure) ─────────────────────────────────────────────


def _scan_result_to_l1_output(scan_result: Any) -> dict:
    """Translate Argus engine ScanResult to the l1_output dict run_dast expects.

    Each vulnerability becomes a hypothesis the orchestrator can plan
    against. Hypothesis IDs are zero-padded H001/H002/... to match
    the schema's expected format and stay sortable in journals.
    """
    # finding_ref is what the orchestrator uses to count confirmed
    # hypotheses into IterationStats.new_confirmed_findings + the
    # DastResult.findings_validated list. Without it, even confirmed
    # Phase A verdicts don't flow to the engine telemetry. We use the
    # hypothesis id as a stable per-scan identifier (1:1 with the
    # vulnerability index in scan_result.vulnerabilities).
    return {
        "verdict": {"verdict_label": scan_result.final_verdict},
        "hypotheses": [
            {
                "id": f"H{i + 1:03d}",
                "finding_ref": f"H{i + 1:03d}",
                "finding_type": v.get("type", "unknown"),
                "severity": v.get("severity", "medium"),
                "explanation": v.get("explanation", ""),
                "code_snippet": v.get("code", ""),
                "line": v.get("line"),
                "data_flow_trace": v.get("data_flow_trace", ""),
                "proof_of_concept": v.get("proof_of_concept", ""),
                "cwe": v.get("cwe", ""),
                "confidence": v.get("confidence", 0.5),
            }
            for i, v in enumerate(scan_result.vulnerabilities or [])
        ],
        "behavioral_profile": scan_result.behavioral_profile or {},
        "attack_chains": scan_result.attack_chains or [],
    }


def _dast_result_to_engine_dict(result: DastResult, elapsed_ms: int) -> dict:
    """Map a DastResult to the dict shape engine.scan_file expects from
    its dast_runner. Cost is computed naively from total tokens × Sonnet
    rates; DAST-103 (Opus iter-3) will make this provider-aware."""
    cost_usd = (
        result.total_tokens_in / 1_000_000 * _DAST_COST_IN_PER_M
        + result.total_tokens_out / 1_000_000 * _DAST_COST_OUT_PER_M
    )
    return {
        "validated_findings": list(result.findings_validated),
        "iterations": [
            {
                "iter": s.iter,
                "verdict_label": s.current_verdict_label,
                "new_confirmed_findings": s.new_confirmed_findings,
                "hypotheses_proposed": s.hypotheses_proposed,
                "hypotheses_accepted": s.hypotheses_accepted,
                "hypotheses_rejected": s.hypotheses_rejected,
                "sandbox_calls": s.sandbox_calls,
                "iter_erosion_guard_fired": s.iter_erosion_guard_fired,
                "elapsed_s": s.elapsed_s,
            }
            for s in result.iterations
        ],
        "final_verdict": result.final_verdict,
        "total_cost_usd": round(cost_usd, 6),
        "elapsed_ms": elapsed_ms,
        "stop_reason": result.stop_reason,
        # Tier 1.5: pass-through for per-finding classification.
        "journal_records": list(result.journal_records),
        # v1.2: Phase C — fix-and-verify result. None when DAST didn't
        # confirm any findings or Phase C was skipped/failed.
        "phase_c": result.phase_c,
    }


# ── Generic factory (testable) ─────────────────────────────────────────────


def make_dast_runner(
    *,
    inference: InferenceFn,
    sandbox: SandboxClient,
    validator: HypothesisValidator | None = None,
    journal_dir: Path | None = None,
) -> DastRunner:
    """Build a DAST runner satisfying engine.scan_file's dast_runner contract.

    The ``inference`` callable + ``sandbox`` client are injected so
    tests can supply stubs. Production callers use
    :func:`make_dast_runner_from_env` which constructs a Sonnet-backed
    inference + a Fly-Firecracker sandbox stack.
    """
    val = validator or HypothesisValidator()
    journal_root = journal_dir or Path(tempfile.gettempdir()) / "argus" / "dast_journals"
    journal_root.mkdir(parents=True, exist_ok=True)

    async def runner(
        filename: str,
        content: bytes,
        pp: Any,
        scan_result: Any,
        *,
        enable_phase_c: bool = True,
    ) -> dict:
        text = content.decode("utf-8", errors="replace")
        file_id = (getattr(pp, "file_hash", None) if pp is not None else None) or filename

        l1_output = _scan_result_to_l1_output(scan_result)
        # The basename (with extension) is what the sandbox stages at
        # /workspace/<basename>. Strip any path components so a
        # caller-supplied "samples/foo.js" still lands as "foo.js".
        file_name = Path(filename).name or filename

        # ML-artifact detonation: when the file is a recognized model
        # format (.pkl/.pt/.bin/.safetensors/.h5/.onnx), prepend a
        # synthetic L1 hypothesis so the orchestrator plans a load
        # against it even when the static cascade emitted zero findings.
        # The deterministic load plan is the cleanest "load = detonation"
        # demo Argus has — pickle.load() / torch.load() runs __reduce__
        # opcodes that may not surface in static analysis at all.
        from .ml_detonation import (  # noqa: PLC0415
            detect_format as _detect_ml_format,
        )
        from .ml_detonation import (
            synthesize_ml_load_hypothesis,
        )

        ml_format = _detect_ml_format(file_name, content[:32])
        if ml_format is not None:
            ml_hyp = synthesize_ml_load_hypothesis(file_format=ml_format)
            existing = list(l1_output.get("hypotheses") or [])
            l1_output = {
                **l1_output,
                "hypotheses": [ml_hyp, *existing],
            }

        file_record = {
            "file_id": file_id,
            "source_text": text,
            "file_name": file_name,
            "ml_format": ml_format,  # None for non-ML files
            # Original raw bytes (pre-decode) — needed for ML detonation
            # plans which must stage the *binary* in the sandbox, not the
            # synthesized text representation. Non-ML callers ignore.
            "original_bytes": content if ml_format else None,
        }

        # Populate the file content map so FirecrackerSandboxClient can
        # ship the file into the VM via its env-var path. For stub
        # sandboxes this is a harmless attribute write.
        for client in _iter_inner_sandbox_clients(sandbox):
            content_map = getattr(client, "file_content_map", None)
            if isinstance(content_map, dict):
                content_map[file_id] = content

        t0 = time.time()
        result = await run_dast(
            file_record=file_record,
            l1_output=l1_output,
            sandbox=sandbox,
            validator=val,
            journal_dir=journal_root,
            inference=inference,
            enable_phase_c=enable_phase_c,
        )
        elapsed_ms = int((time.time() - t0) * 1000)
        return _dast_result_to_engine_dict(result, elapsed_ms)

    # Expose the sandbox client as a runner attribute so callers (engine
    # discovery stage, replay tools) can submit additional plans through
    # the same sandbox without rebuilding the runner. Read-only — anyone
    # mutating it is doing it wrong.
    runner.sandbox = sandbox  # type: ignore[attr-defined]
    return runner


def _resolve_sandbox_client_for_engine(dast_runner: Any) -> SandboxClient | None:
    """Pull the SandboxClient out of a dast_runner closure for callers
    (DAST-204 discovery) that want to submit additional plans without
    rebuilding the runner. Returns None when the runner doesn't expose
    the sandbox attribute (older or test-stub runners)."""
    sandbox = getattr(dast_runner, "sandbox", None)
    if sandbox is None:
        return None
    return sandbox  # type: ignore[no-any-return]


def _iter_inner_sandbox_clients(sandbox: SandboxClient):
    """Yield each underlying SandboxClient — for MultiImageSandboxClient
    iterate the per-hint inners; for any other client yield itself."""
    inner_by_hint = getattr(sandbox, "inner_by_hint", None)
    if isinstance(inner_by_hint, dict):
        yield from inner_by_hint.values()
    else:
        yield sandbox


# ── Production factory ─────────────────────────────────────────────────────


def make_dast_runner_from_env(api_key: str | None = None) -> DastRunner | None:
    """Build the production DAST runner from environment variables.

    Returns ``None`` if any required config is missing — engine.scan_file
    treats that as "skip DAST" gracefully.

    Required:
        ANTHROPIC_API_KEY (or pass via ``api_key`` argument)
        FLY_API_TOKEN
        ECHO_DAST_IMAGE_MINIMAL

    Optional:
        ECHO_DAST_IMAGE_NETWORKED — falls back to MINIMAL if unset
        ECHO_DAST_IMAGE_ML_TOOLS  — falls back to MINIMAL if unset
        ARGUS_DAST_FLY_APP        — default: ``argus-dast-sandbox``
        ARGUS_DAST_FLY_REGION     — default: ``iad``
    """
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    fly_token = os.environ.get("FLY_API_TOKEN", "")
    image_minimal = os.environ.get("ECHO_DAST_IMAGE_MINIMAL", "")

    missing: list[str] = []
    if not api_key:
        missing.append("ANTHROPIC_API_KEY")
    if not fly_token:
        missing.append("FLY_API_TOKEN")
    if not image_minimal:
        missing.append("ECHO_DAST_IMAGE_MINIMAL")
    if missing:
        log.info(
            "DAST runner not configured (missing: %s); engine will skip DAST",
            ", ".join(missing),
        )
        return None

    image_networked = os.environ.get("ECHO_DAST_IMAGE_NETWORKED") or image_minimal
    image_ml_tools = os.environ.get("ECHO_DAST_IMAGE_ML_TOOLS") or image_minimal
    fly_app = os.environ.get("ARGUS_DAST_FLY_APP", DEFAULT_FLY_APP)
    fly_region = os.environ.get("ARGUS_DAST_FLY_REGION", DEFAULT_FLY_REGION)

    fly_client = FlyMachinesClient(
        app_name=fly_app,
        api_token=fly_token,
        region=fly_region,
    )

    sandbox = MultiImageSandboxClient(
        inner_by_hint={
            "minimal": FirecrackerSandboxClient(fly_client=fly_client, image=image_minimal),
            "networked": FirecrackerSandboxClient(fly_client=fly_client, image=image_networked),
            "ml_tools": FirecrackerSandboxClient(fly_client=fly_client, image=image_ml_tools),
        },
        fallback_hint="minimal",
    )

    inference = make_dast_sonnet_inference(api_key)

    return make_dast_runner(inference=inference, sandbox=sandbox)


__all__ = [
    "DEFAULT_FLY_APP",
    "DEFAULT_FLY_REGION",
    "DastRunner",
    "make_dast_runner",
    "make_dast_runner_from_env",
]
