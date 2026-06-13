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

from dast.inference import (
    InferenceFn,
    make_dast_opus_inference,
    make_dast_sonnet_inference,
)
from dast.orchestrator import DastResult, run_dast
from dast.sandbox.client import (
    FirecrackerSandboxClient,
    FlyMachinesClient,
    MultiImageSandboxClient,
    SandboxClient,
)
from dast.sandbox.gvisor import DockerGvisorSandboxClient, find_docker
from dast.validator import HypothesisValidator

log = logging.getLogger("argus.dast.runner")

DastRunner = Callable[..., Awaitable[dict]]

DEFAULT_FLY_APP = "argus-dast-sandbox"
DEFAULT_FLY_REGION = "iad"

# Self-hosted (gVisor / local Docker) substrate defaults. Used when
# ARGUS_DAST_RUNTIME selects the gVisor path — no Fly dependency. Image
# tags refer to LOCAL docker images the operator built with
# dast/sandbox/firecracker/build_local.sh (or pulled into the local
# daemon).
DEFAULT_GVISOR_RUNTIME = "runsc"
DEFAULT_GVISOR_NETWORK = "none"
DEFAULT_GVISOR_IMAGE_LEAN = "argus-dast-sandbox:lean"
DEFAULT_GVISOR_IMAGE_RICH_PYTHON = "argus-dast-sandbox:rich_python"
DEFAULT_GVISOR_IMAGE_ML_TOOLS = "argus-dast-sandbox:ml_tools"
# ARGUS_DAST_RUNTIME values that select the self-hosted gVisor substrate.
_GVISOR_RUNTIME_ALIASES = frozenset({"gvisor", "local", "docker", "runsc", "self-hosted"})

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
                # v1.10 SCAN-009: Phase A schema-retry telemetry. Counts
                # retry firings + retry-exhausted failures across both
                # Phase A plan and verdict calls in this iter. Surfaced
                # so operators + benchmark tooling can detect malformed-
                # response cascades (silent scan degradation under
                # SCAN-008 fail-open).
                "phase_a_schema_validation_retries": s.phase_a_schema_validation_retries,
                "phase_a_schema_validation_failed": s.phase_a_schema_validation_failed,
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
        # v1.9: rich detail for DAST-discovered findings (HRP_*/HRP_AL_*/
        # HRP_C*) that have no L1 hypothesis backing. Engine reads
        # this map to extend per_finding_validation with rows the
        # L1-iteration loop can't produce. dict of finding_ref →
        # full finding dict (finding_type, severity, cwe, line,
        # proof_of_concept, runtime_evidence, ...).
        "findings_validated_meta": dict(result.findings_validated_meta),
        # v1.2: Phase C — fix-and-verify result. None when DAST didn't
        # confirm any findings or Phase C was skipped/failed.
        "phase_c": result.phase_c,
        # Phase 3 Stage 1 (v1.6): RUNTIME behavioral exploration
        # profile. None when --enable-phase-3-discovery is off, the
        # file is non-Python, or the probe failed to produce a usable
        # profile. When populated, contains the serialized
        # BehavioralProfile (see dast.behavioral_probe). Engine.scan_file
        # surfaces this on ScanResult.runtime_behavioral_profile so
        # downstream consumers can see runtime behavior. The "runtime_"
        # prefix disambiguates from the static-analysis cascade's
        # ``behavioral_profile`` field, which has a different schema.
        "runtime_behavioral_profile": result.runtime_behavioral_profile,
        # Phase 3 Stage 2 (v1.6): adversarial-loop summary. None when
        # ``--enable-phase-3-loop`` was off, the file was non-Python,
        # or Stage 1 didn't produce a behavioral profile to anchor
        # against. See DastResult.phase_3_loop for shape.
        "phase_3_loop": result.phase_3_loop,
        # Phase 3 verdict resolver decision (always populated). Currently
        # observation-only -- engine.final_verdict still flows from the
        # existing cascade logic. Promoted to canonical in the JSON v3
        # schema follow-on once the 23-file live validation lands.
        "phase_3_resolver_decision": result.phase_3_resolver_decision,
        # Phase D (DAST-301/302): variant-analysis pipeline output. List
        # of per-seed PhaseDResult dicts (one entry per Phase-A-confirmed
        # seed that ran through Phase D). Empty when ``enable_phase_d``
        # was off, no seeds were confirmed, or every seed skipped (e.g.,
        # unsupported language, no candidates). See dast.variant_runner.
        "variant_analysis": list(result.variant_analysis),
        # Phase C multi-file patch (DAST-304): coordinated remediation
        # across seed + confirmed variants. None when Phase D produced
        # no confirmed variants or multi-file patch was skipped.
        "variant_remediation": result.variant_remediation,
    }


# ── Generic factory (testable) ─────────────────────────────────────────────


def make_dast_runner(
    *,
    inference: InferenceFn,
    sandbox: SandboxClient,
    validator: HypothesisValidator | None = None,
    journal_dir: Path | None = None,
    phase_3_inference: InferenceFn | None = None,
) -> DastRunner:
    """Build a DAST runner satisfying engine.scan_file's dast_runner contract.

    The ``inference`` callable + ``sandbox`` client are injected so
    tests can supply stubs. Production callers use
    :func:`make_dast_runner_from_env` which constructs a Sonnet-backed
    inference + a Fly-Firecracker sandbox stack.

    ``phase_3_inference`` (v12, 2026-05-17): optional separate
    inference function for Phase 3 Stage 2's adversarial loop. When
    provided, the orchestrator passes THIS inference to
    ``run_adversarial_loop`` instead of the main ``inference``. Used
    in production to put **Opus 4.6** behind hypothesis generation
    specifically — that's the model that needs the deepest reasoning
    (creative attack design, multi-step chains, novel zero-day class)
    while Sonnet stays on L1 / Phase A / Phase B+ where the model is
    validating L1 findings or testing single-function probes (lower
    reasoning bar). When None, falls back to the main ``inference``
    everywhere (back-compat / tests).
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
        enable_runtime_probe: bool = False,
        enable_runtime_probe_mutation: bool = False,
        enable_runtime_probe_iterative: bool = False,
        enable_runtime_probe_chains: bool = False,
        enable_phase_3_discovery: bool = False,
        enable_phase_3_loop: bool = False,
        phase_3_loop_max_turns: int = 1,
        enable_phase_d: bool = False,
        enable_remediation_verify: bool = False,
        enable_per_scan_dep_install: bool = False,
        enable_coverage_dedupe: bool = True,
        host_path: str | None = None,
        max_cost_usd: float | None = None,
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
            # v12 (2026-05-17): multi-file project staging path. When
            # the entry file lives in a subdirectory of its detected
            # project root (e.g., ``src/tools/sql.ts`` in LangChain.js),
            # this string is the rel-from-project-root path the plan
            # builders should use to construct ``module_path`` AND the
            # ``run_cmd`` that moves the staged entry into the right
            # subdir of /workspace. Empty for single-file scans (entry
            # at /workspace/<basename>, v11 behavior unchanged).
            "entry_rel_path": "",  # populated below when sibling resolver runs
            # DAST-302 v1.1 (2026-05-17): full host paths for cross-file
            # Phase D code-graph construction. ``host_path`` is the
            # entry file on disk; ``project_root`` is the resolved root
            # (walks up looking for tsconfig.json/pyproject.toml/etc.
            # via dast.code_graph.resolve_project_root_for_file).
            # Empty when called without a host path (legacy single-file
            # path, tests with no fs context); Phase D then falls back
            # to same-file behavior.
            "host_path": host_path or "",
            "project_root": "",  # populated below alongside sibling resolver
        }

        # Populate the file content map so FirecrackerSandboxClient can
        # ship the file into the VM via its env-var path. For stub
        # sandboxes this is a harmless attribute write.
        for client in _iter_inner_sandbox_clients(sandbox):
            content_map = getattr(client, "file_content_map", None)
            if isinstance(content_map, dict):
                content_map[file_id] = content

        # Multi-file project staging (v11, 2026-05-17): resolve sibling
        # files referenced by the entry file's relative imports
        # (``import './foo'``, ``from .bar import baz``, etc.) and
        # populate the sandbox's additional_files_map so they ship
        # alongside the entry file via the ADDITIONAL_FILES_TARGZ_B64
        # env var. Without this, multi-file projects (mcp-server-
        # filesystem, mcp-server-time, langchain modules, etc.) hit
        # ``Cannot find module './sibling'`` at harness import time —
        # Stage 1's behavioral profile comes back empty.
        #
        # Resolver is bounded (50 files, 5 levels deep, 512 KB/file)
        # and applies path-traversal defense so ``../../../etc/passwd``
        # in an import string can't escape the entry's directory.
        # Empty dict for standalone files (no relative imports) —
        # single-file behavior unchanged.
        from preprocessing.language import detect_language  # noqa: PLC0415
        from preprocessing.sibling_files import (  # noqa: PLC0415
            compute_entry_rel_path,
            resolve_sibling_files,
        )

        # Multi-file sibling resolution needs the FULL host path so we
        # can walk the project tree on disk. ``filename`` is conventionally
        # the basename (used for sandbox staging path + result display);
        # the CLI threads ``host_path`` through scan_file → here. When
        # host_path is None (older callers, tests, or the engine running
        # without a CLI), we fall back to ``filename`` — if it happens to
        # be an absolute path the resolver still works; if it's a bare
        # basename the resolver returns an empty dict (no sibling staging,
        # single-file behavior unchanged).
        entry_path_for_resolver = host_path or filename
        sibling_lang = detect_language(file_name) or ""
        # Defensive init so downstream gates (Phase D project-tree
        # staging) can reference sibling_files unconditionally without
        # NameError when sibling_lang isn't supported.
        sibling_files: dict[str, bytes] = {}
        if sibling_lang in ("python", "javascript", "typescript"):
            try:
                sibling_files = resolve_sibling_files(
                    entry_file_path=entry_path_for_resolver,
                    entry_file_bytes=content,
                    language=sibling_lang,
                )
            except Exception as exc:  # noqa: BLE001
                # Fail-open: never block a scan because the resolver
                # tripped on an exotic filesystem. The single-file
                # path still works.
                logging.getLogger("argus.dast.runner").warning(
                    "sibling resolver failed for %s: %s — proceeding single-file",
                    entry_path_for_resolver,
                    exc,
                )
                sibling_files = {}
            # v12 (2026-05-17): compute the entry file's rel-from-project-root
            # path. Plan builders use this for ``$ENTRY_REL_PATH`` env var
            # and MODULE_NAME derivation. Only set when the rel path
            # actually differs from the basename — single-file scans where
            # entry IS at the project root keep v11 behavior.
            #
            # v15.1 (2026-05-20): compute entry_rel_path EVEN WHEN
            # sibling_files is empty. For namespace packages (ruamel.yaml,
            # backports.zoneinfo) the v15.1 resolver intentionally
            # returns empty siblings (pip-install of the own dist is the
            # primary path; overlay would shadow it). But MODULE_NAME
            # still needs to come from compute_entry_rel_path's
            # namespace-prefixed rel ('ruamel/yaml/loader.py' →
            # 'ruamel.yaml.loader') so the planner + harness use the
            # qualified import. Previously this block was gated by
            # ``if sibling_files:``, silently dropping MODULE_NAME for
            # every namespace package.
            try:
                entry_rel_path = compute_entry_rel_path(entry_path_for_resolver)
            except Exception:  # noqa: BLE001
                entry_rel_path = ""
            entry_rel_path = entry_rel_path.replace("\\", "/")
            if entry_rel_path == file_name:
                entry_rel_path = ""
            file_record["entry_rel_path"] = entry_rel_path

            if sibling_files or entry_rel_path:
                for client in _iter_inner_sandbox_clients(sandbox):
                    addl_map = getattr(client, "additional_files_map", None)
                    if isinstance(addl_map, dict) and sibling_files:
                        addl_map[file_id] = sibling_files
                    # Populate entry_rel_path_map even with empty siblings —
                    # namespace packages depend on the qualified MODULE_NAME
                    # derived from this rel-path for in-sandbox imports
                    # against the pip-installed package.
                    entry_map = getattr(client, "entry_rel_path_map", None)
                    if isinstance(entry_map, dict) and entry_rel_path:
                        entry_map[file_id] = entry_rel_path

        # DAST-302 v1.1 — Blast Radius project_root resolution.
        # ``resolve_project_root_for_file`` runs UNCONDITIONALLY for
        # Python entry files (independent of the sibling resolver),
        # because Phase D's cross-file code graph hunts the WHOLE
        # project tree — it doesn't depend on the entry file having
        # relative imports. A project whose seed file imports only
        # stdlib (e.g. ``import urllib.request``) still has variants
        # in sibling modules that the graph builder needs to enumerate.
        #
        # Gated on Python only because ``build_python_code_graph`` is
        # the only graph builder today (DAST-302.5 will add TS/JS).
        # Requires an absolute existing path so we never accidentally
        # walk up from cwd when the caller passed a bare basename
        # (tests, programmatic callers without a CLI).
        if sibling_lang == "python" and host_path:
            from pathlib import Path as _Path_local  # noqa: PLC0415

            host_path_obj = _Path_local(host_path)
            if host_path_obj.is_absolute() and host_path_obj.exists():
                try:
                    from dast.code_graph import (  # noqa: PLC0415
                        resolve_project_root_for_file,
                    )

                    resolved_root = resolve_project_root_for_file(host_path_obj)
                    if resolved_root is not None:
                        file_record["project_root"] = str(resolved_root)
                    else:
                        logging.getLogger("argus.dast.runner").info(
                            "Phase D project_root: no marker file found "
                            "walking up from %s — Phase D will use "
                            "same-file behavior",
                            host_path,
                        )
                except Exception as exc:  # noqa: BLE001
                    # Non-fatal — Phase D falls back to same-file. Log
                    # so operators can diagnose unexpected resolver
                    # failures (permissions, race with rm -rf, etc).
                    logging.getLogger("argus.dast.runner").warning(
                        "Phase D project_root resolution failed for %s: %s — falling back to same-file",
                        host_path,
                        exc,
                    )

        # DAST-302 v1.1 — Blast Radius sandbox staging (Bug #5).
        #
        # Phase D cross-file confirms variants by running a retargeted
        # harness that imports the variant's module (e.g.
        # ``import lib.downloaders``) inside the sandbox. The sibling-
        # file resolver above only stages files reached via RELATIVE
        # imports in the seed — but cross-file variants typically live
        # in modules that the seed doesn't import. Without this block,
        # every cross-file variant harness hits ``ModuleNotFoundError``
        # and the variant gets deterministically refuted on missing
        # oracle signal.
        #
        # Fix: when Phase D is enabled AND project_root resolved AND
        # language is Python, enumerate every .py file under
        # project_root (bounded by code_graph's existing 200-file ×
        # 256-KB caps + EXCLUDED_DIR_NAMES) and bundle them into
        # additional_files_map. Sibling-resolved entries take
        # precedence on overlap (they may have applied special
        # handling). Skip the entry file itself — already loaded via
        # file_content_map.
        if enable_phase_d and sibling_lang == "python" and file_record["project_root"]:
            from pathlib import Path as _Path_local  # noqa: PLC0415

            _stage_project_tree_for_phase_d(
                project_root=_Path_local(file_record["project_root"]),
                file_id=file_id,
                entry_file_name=file_name,
                entry_rel_path=file_record.get("entry_rel_path", ""),
                sibling_files=sibling_files,
                sandbox=sandbox,
            )

        t0 = time.time()
        # v1.5 Phase B+ runtime probing requires the file's original
        # bytes (not just the synthesized text representation) so the
        # sandbox can stage the actual Python module. Thread them
        # through unconditionally — the orchestrator only acts on them
        # when ``enable_runtime_probe`` is True.
        file_record["original_bytes"] = file_record.get("original_bytes") or content
        result = await run_dast(
            file_record=file_record,
            l1_output=l1_output,
            sandbox=sandbox,
            validator=val,
            journal_dir=journal_root,
            inference=inference,
            phase_3_inference=phase_3_inference,
            enable_phase_c=enable_phase_c,
            enable_runtime_probe=enable_runtime_probe,
            enable_runtime_probe_mutation=enable_runtime_probe_mutation,
            enable_runtime_probe_iterative=enable_runtime_probe_iterative,
            enable_runtime_probe_chains=enable_runtime_probe_chains,
            enable_phase_3_discovery=enable_phase_3_discovery,
            enable_phase_3_loop=enable_phase_3_loop,
            phase_3_loop_max_turns=phase_3_loop_max_turns,
            enable_phase_d=enable_phase_d,
            enable_remediation_verify=enable_remediation_verify,
            enable_per_scan_dep_install=enable_per_scan_dep_install,
            enable_coverage_dedupe=enable_coverage_dedupe,
            max_cost_usd=max_cost_usd,
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


# DAST-302 Bug #5 staging cap. Total bytes across all project-tree
# files staged per scan, in ADDITION to the per-file size cap inherited
# from ``code_graph.MAX_BYTES_PER_GRAPH_FILE`` (256 KB). Defensive
# upper bound to prevent a project with 200 × 256 KB files (~50 MB) from
# bloating sandbox uploads. Real Python projects rarely exceed 4-8 MB
# of source so this leaves comfortable headroom.
_PHASE_D_STAGING_MAX_TOTAL_BYTES: int = 16 * 1024 * 1024  # 16 MiB


def _stage_project_tree_for_phase_d(
    *,
    project_root: Path,
    file_id: str,
    entry_file_name: str,
    entry_rel_path: str,
    sibling_files: dict[str, bytes],
    sandbox: SandboxClient,
) -> None:
    """Stage every Python file under ``project_root`` into the sandbox's
    ``additional_files_map`` so DAST-302 cross-file variant harnesses
    can import the variant's module at sandbox runtime.

    Fixes Bug #5 — without this, ``import lib.downloaders`` inside a
    retargeted Phase D harness hits ``ModuleNotFoundError`` because the
    sibling resolver only ships files reached via RELATIVE imports in
    the seed file. Cross-file variants typically live in modules not
    relatively imported by the seed.

    Bounds (inherited from ``dast.code_graph.enumerate_project_files``):

    * Max 200 files per scan (mtime-sorted; recently-edited wins on cap)
    * Max 256 KB per file (oversized files skipped)
    * Excludes ``node_modules``, ``__pycache__``, ``.git``, ``.venv``,
      ``venv``, ``site-packages``, ``dist``, ``build``, ``.tox``,
      etc. (see ``code_graph.EXCLUDED_DIR_NAMES``)
    * Defensive ``_PHASE_D_STAGING_MAX_TOTAL_BYTES`` (16 MiB) cap
      across all staged files combined

    Path-traversal defense: ``_is_excluded_path`` resolves symlinks and
    rejects any path falling outside ``project_root`` before staging.

    Coexists with the sibling resolver: when a file appears in both
    ``sibling_files`` (relative-import-resolved) and the project tree
    walk, the sibling version wins because it represents the seed's
    actual dependency graph and may have applied entry-relative path
    normalization the broader walk doesn't.

    Skips the entry file itself — already staged via
    ``SandboxClient.file_content_map[file_id]``. Including it in
    ``additional_files_map`` would cause dast-init to extract it twice
    and possibly overwrite the entry-rel-path-staged copy with the
    project-root-relative path.

    Fails open: any I/O error (permissions, race with rm -rf, etc.)
    logs a warning and the staging block is skipped. Phase D then
    runs same-file only — back-compat with pre-Fix-#5 behavior.
    """
    runner_log = logging.getLogger("argus.dast.runner")

    try:
        from dast.code_graph import enumerate_project_files  # noqa: PLC0415
    except ImportError as exc:
        runner_log.warning(
            "Phase D project-tree staging: code_graph import failed: %s — falling back to same-file variants only",
            exc,
        )
        return

    try:
        project_files = enumerate_project_files(project_root)
    except Exception as exc:  # noqa: BLE001
        runner_log.warning(
            "Phase D project-tree staging: enumeration failed under %s: %s — falling back to same-file variants only",
            project_root,
            exc,
        )
        return

    # Compute the set of POSIX rel paths we should NOT overwrite. These
    # are sibling-resolved files (entry's relative-import dependency
    # graph) AND the entry file itself. Both are already correctly
    # staged elsewhere.
    sibling_paths = {p.replace("\\", "/") for p in sibling_files.keys()}
    entry_skip_paths = {entry_file_name.replace("\\", "/")}
    if entry_rel_path:
        entry_skip_paths.add(entry_rel_path.replace("\\", "/"))

    # Build the staging dict, merging with any existing entries on
    # this file_id (some callers pre-populate it; defensive merge).
    existing_for_file_id: dict[str, bytes] = {}
    for client in _iter_inner_sandbox_clients(sandbox):
        addl_map = getattr(client, "additional_files_map", None)
        if isinstance(addl_map, dict):
            existing_for_file_id = dict(addl_map.get(file_id, {}))
            break

    staged: dict[str, bytes] = dict(existing_for_file_id)
    total_bytes = sum(len(b) for b in staged.values())
    files_added = 0
    files_skipped_size = 0

    for abs_path in project_files:
        try:
            rel_path = abs_path.resolve().relative_to(project_root.resolve())
        except (ValueError, OSError):
            # Symlink escaping project_root or transient FS error —
            # already filtered by _is_excluded_path, but defensive.
            continue
        rel_posix = str(rel_path).replace("\\", "/")
        if rel_posix in entry_skip_paths:
            continue
        if rel_posix in sibling_paths:
            # Sibling version wins — already in additional_files_map
            # via the sibling staging block.
            continue
        if rel_posix in staged:
            # Pre-populated by an earlier caller — don't clobber.
            continue
        try:
            data = abs_path.read_bytes()
        except OSError as exc:
            runner_log.warning(
                "Phase D project-tree staging: failed to read %s: %s — skipping this file, continuing with the rest",
                abs_path,
                exc,
            )
            continue
        if total_bytes + len(data) > _PHASE_D_STAGING_MAX_TOTAL_BYTES:
            files_skipped_size += 1
            continue
        staged[rel_posix] = data
        total_bytes += len(data)
        files_added += 1

    # Sibling-resolved entries take precedence on overlap. Re-insert
    # them at the end so they overwrite any project-walk version (which
    # shouldn't happen given the skip above, but defensive).
    for sibling_rel, sibling_bytes in sibling_files.items():
        staged[sibling_rel.replace("\\", "/")] = sibling_bytes

    # Push the merged map back to every inner sandbox client.
    if staged:
        for client in _iter_inner_sandbox_clients(sandbox):
            addl_map = getattr(client, "additional_files_map", None)
            if isinstance(addl_map, dict):
                addl_map[file_id] = staged

    runner_log.info(
        "Phase D project-tree staging: %d files added (%d bytes total), "
        "%d skipped on total-byte cap, sibling-resolved=%d, root=%s",
        files_added,
        total_bytes,
        files_skipped_size,
        len(sibling_files),
        project_root,
    )


# ── Production factory ─────────────────────────────────────────────────────


def _make_gvisor_dast_runner_from_env(
    api_key: str | None = None,
    *,
    scan_model: str = "claude-sonnet-4-6",
    reasoning_model: str = "claude-opus-4-6",
) -> DastRunner | None:
    """Build the self-hosted DAST runner on the gVisor / local-Docker substrate.

    Selected by ``ARGUS_DAST_RUNTIME`` ∈ {gvisor, local, docker,
    self-hosted}. Needs NO Fly.io credentials — sandboxes run as local
    containers under a gVisor (``runsc``) runtime. Returns ``None`` (so
    the engine skips DAST gracefully) when prerequisites are missing.

    Required:
        ANTHROPIC_API_KEY (or pass via ``api_key``)
        docker on PATH, with the gVisor runtime registered (``runsc
        install``). The runtime registration is validated lazily — the
        first plan surfaces a clear ``docker run`` error if it's absent.

    Optional env:
        ARGUS_DAST_GVISOR_RUNTIME   — OCI runtime name (default ``runsc``)
        ARGUS_DAST_GVISOR_NETWORK   — docker network mode (default
                                      ``none`` = no egress; capture server
                                      on loopback intercepts all hostnames)
        ARGUS_DAST_GVISOR_IMAGE_LEAN / _RICH_PYTHON / _ML_TOOLS —
                                      LOCAL image tags (defaults
                                      ``argus-dast-sandbox:<tier>``).
                                      RICH_PYTHON / ML_TOOLS fall back to
                                      LEAN when unset.
    """
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    missing: list[str] = []
    if not api_key:
        missing.append("ANTHROPIC_API_KEY")
    docker_path = find_docker()
    if not docker_path:
        missing.append("docker (not found on PATH)")
    if missing:
        log.info(
            "DAST runner (gVisor) not configured (missing: %s); engine will skip DAST",
            ", ".join(missing),
        )
        return None

    runtime = os.environ.get("ARGUS_DAST_GVISOR_RUNTIME", DEFAULT_GVISOR_RUNTIME)
    network = os.environ.get("ARGUS_DAST_GVISOR_NETWORK", DEFAULT_GVISOR_NETWORK)
    image_lean = os.environ.get("ARGUS_DAST_GVISOR_IMAGE_LEAN", DEFAULT_GVISOR_IMAGE_LEAN)
    image_rich_python = os.environ.get("ARGUS_DAST_GVISOR_IMAGE_RICH_PYTHON") or image_lean
    image_ml_tools = os.environ.get("ARGUS_DAST_GVISOR_IMAGE_ML_TOOLS") or image_lean

    log.info(
        "DAST runner: gVisor substrate (runtime=%s, network=%s, images: lean=%s rich_python=%s ml_tools=%s)",
        runtime,
        network,
        image_lean,
        image_rich_python,
        image_ml_tools,
    )

    def _mk(image: str) -> DockerGvisorSandboxClient:
        return DockerGvisorSandboxClient(
            image=image,
            docker_path=docker_path,
            runtime=runtime,
            network=network,
        )

    sandbox = MultiImageSandboxClient(
        inner_by_hint={
            "lean": _mk(image_lean),
            "rich_python": _mk(image_rich_python),
            "ml_tools": _mk(image_ml_tools),
        },
        fallback_hint="lean",
    )

    inference = make_dast_sonnet_inference(api_key, model_id=scan_model)
    phase_3_inference = make_dast_opus_inference(api_key, model_id=reasoning_model)

    return make_dast_runner(
        inference=inference,
        sandbox=sandbox,
        phase_3_inference=phase_3_inference,
    )


def make_dast_runner_from_env(
    api_key: str | None = None,
    *,
    scan_model: str = "claude-sonnet-4-6",
    reasoning_model: str = "claude-opus-4-6",
) -> DastRunner | None:
    """Build the production DAST runner from environment variables.

    Returns ``None`` if any required config is missing — engine.scan_file
    treats that as "skip DAST" gracefully.

    Required:
        ANTHROPIC_API_KEY (or pass via ``api_key`` argument)
        FLY_API_TOKEN
        ECHO_DAST_IMAGE_LEAN

    Optional:
        ECHO_DAST_IMAGE_RICH_PYTHON — falls back to LEAN if unset
        ECHO_DAST_IMAGE_ML_TOOLS    — falls back to LEAN if unset
        ARGUS_DAST_FLY_APP          — default: ``argus-dast-sandbox``
        ARGUS_DAST_FLY_REGION       — default: ``iad``

    SCAN-020 v1.11.1: ``scan_model`` + ``reasoning_model`` plumb the
    role-based model overrides through to DAST's Sonnet (Phase A /
    Phase B+) and Opus (Phase 3 Stage 2 Adversarial Reasoning,
    iter-3 escalation) inference functions. Defaults match the
    v1.11 pin; CLI's ``--scan-model`` / ``--reasoning-model`` flags
    propagate via ScanConfig.

    v1.8 P2b: env vars renamed from ECHO_DAST_IMAGE_MINIMAL/NETWORKED
    to ECHO_DAST_IMAGE_LEAN/RICH_PYTHON. If old names are still set
    when LEAN isn't, a migration error is logged.

    Substrate selection (DAST-107): ``ARGUS_DAST_RUNTIME`` chooses where
    sandboxes run. Default ``fly`` keeps the managed Firecracker path.
    Any of ``gvisor`` / ``local`` / ``docker`` / ``self-hosted`` routes
    to the local-Docker + gVisor substrate (see
    :func:`_make_gvisor_dast_runner_from_env`) — the recommended default
    for self-hosted deployments, which needs no ``FLY_API_TOKEN`` and no
    managed cloud.
    """
    runtime_mode = os.environ.get("ARGUS_DAST_RUNTIME", "fly").strip().lower()
    if runtime_mode in _GVISOR_RUNTIME_ALIASES:
        return _make_gvisor_dast_runner_from_env(api_key, scan_model=scan_model, reasoning_model=reasoning_model)

    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    fly_token = os.environ.get("FLY_API_TOKEN", "")
    image_lean = os.environ.get("ECHO_DAST_IMAGE_LEAN", "")

    missing: list[str] = []
    if not api_key:
        missing.append("ANTHROPIC_API_KEY")
    if not fly_token:
        missing.append("FLY_API_TOKEN")
    if not image_lean:
        # v1.8 P2b migration aid: surface the deprecation if user
        # still has v1.7-era env vars set.
        deprecated = []
        if os.environ.get("ECHO_DAST_IMAGE_MINIMAL"):
            deprecated.append("ECHO_DAST_IMAGE_MINIMAL → ECHO_DAST_IMAGE_LEAN")
        if os.environ.get("ECHO_DAST_IMAGE_NETWORKED"):
            deprecated.append("ECHO_DAST_IMAGE_NETWORKED → ECHO_DAST_IMAGE_RICH_PYTHON")
        if deprecated:
            log.warning(
                "DAST runner: ECHO_DAST_IMAGE_LEAN not set, but found v1.7 env "
                "var(s): %s. v1.8 P2b renamed sandbox images. Rebuild via "
                "dast/sandbox/firecracker/build_and_push_multi.sh and update "
                "your .env. See docs/dast-setup.md.",
                "; ".join(deprecated),
            )
        missing.append("ECHO_DAST_IMAGE_LEAN")
    if missing:
        log.info(
            "DAST runner not configured (missing: %s); engine will skip DAST",
            ", ".join(missing),
        )
        return None

    image_rich_python = os.environ.get("ECHO_DAST_IMAGE_RICH_PYTHON") or image_lean
    image_ml_tools = os.environ.get("ECHO_DAST_IMAGE_ML_TOOLS") or image_lean
    fly_app = os.environ.get("ARGUS_DAST_FLY_APP", DEFAULT_FLY_APP)
    fly_region = os.environ.get("ARGUS_DAST_FLY_REGION", DEFAULT_FLY_REGION)

    fly_client = FlyMachinesClient(
        app_name=fly_app,
        api_token=fly_token,
        region=fly_region,
    )

    sandbox = MultiImageSandboxClient(
        inner_by_hint={
            "lean": FirecrackerSandboxClient(fly_client=fly_client, image=image_lean),
            "rich_python": FirecrackerSandboxClient(fly_client=fly_client, image=image_rich_python),
            "ml_tools": FirecrackerSandboxClient(fly_client=fly_client, image=image_ml_tools),
        },
        fallback_hint="lean",
    )

    inference = make_dast_sonnet_inference(api_key, model_id=scan_model)
    # v12 (2026-05-17): reasoning-tier specifically for Phase 3 Stage 2
    # (Adversarial Reasoning) hypothesis generation. The adversarial
    # loop's reasoning bar is the highest in the pipeline — designing
    # novel zero-day-class attack chains anchored on observed runtime
    # behavior, picking between probe / single_function /
    # stateful_sequence kinds, crafting argument shapes that bypass
    # real-world validation. Scan-tier is fine for L1 / Phase A /
    # Phase B+ (validating L1's findings, simpler reasoning);
    # reasoning-tier is the right model for novel attack design.
    # ~$0.30-0.40/file added cost vs the zero-day catch quality lift.
    phase_3_inference = make_dast_opus_inference(api_key, model_id=reasoning_model)

    return make_dast_runner(
        inference=inference,
        sandbox=sandbox,
        phase_3_inference=phase_3_inference,
    )


__all__ = [
    "DEFAULT_FLY_APP",
    "DEFAULT_FLY_REGION",
    "DastRunner",
    "make_dast_runner",
    "make_dast_runner_from_env",
]
