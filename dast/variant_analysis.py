"""DAST-301 — Variant Analysis (Phase D).

When Phase A confirms a vulnerability finding, the next question every
human security researcher asks is "where else does this same flaw
exist?" Phase D automates that intuition at machine speed:

  1. Extract a structured ``SemanticSignature`` from the confirmed
     finding (source → transformations → sink + missing guards).
  2. Enumerate candidate callables in the same file via deterministic
     AST analysis.
  3. LLM-rank candidates by signature-match similarity.
  4. Retarget the seed harness for each ranked candidate; verify in
     the sandbox.
  5. Surface confirmed variants as L1+PhaseA-shaped findings that
     flow into Phase C remediation alongside the seed.

The v1 MVP is **scoped to same-file variants**. Cross-file + cross-repo
hunting is DAST-302 (v1.1) and DAST-303 (v2) — see
``docs/dast_301_variant_analysis.md``.

This module owns the **data types**, **deterministic AST hunter**, and
**harness retargeter**. The async pipeline (signature LLM call →
hunt → harness submit → verify) lives in :mod:`dast.variant_runner`
to mirror the runtime_probe / adversarial_loop split.

Cost gate: ``PHASE_D_MAX_COST_PER_SEED_USD = 0.50``. Each Phase D run
on a single seed is budget-capped; aborted runs surface
``budget_exhausted`` in the result. Per-scan caps inherit from
``ScanConfig.max_cost_per_scan_usd`` (SCAN-007).
"""

from __future__ import annotations

import ast
import json
import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("argus.dast.variant_analysis")


# ── Tunables ─────────────────────────────────────────────────────────


#: Hard cap on per-seed Phase D spend. When the running cost exceeds
#: this, the runner aborts with ``budget_exhausted``. Computed from
#: the design doc's per-step budget envelope (sig + rank + 5 variants
#: × $0.10).
PHASE_D_MAX_COST_PER_SEED_USD: float = 0.50

#: Maximum candidates passed to the variant judge per seed. Bounds
#: inference cost (the judge call is single-shot, batched across all
#: candidates). Higher values dilute the judge's attention.
MAX_VARIANT_CANDIDATES_PER_SEED: int = 5

#: Minimum signature-similarity score (0.0–1.0) required before
#: harness retargeting. The judge returns a calibrated score per
#: candidate; below this threshold, the candidate is dropped.
MIN_VARIANT_SIMILARITY_THRESHOLD: float = 0.7

#: Per-variant sandbox timeout. Same as Phase A's per-finding default.
DEFAULT_VARIANT_TIMEOUT_SEC: int = 30


# ── Data types ────────────────────────────────────────────────────────


@dataclass
class SemanticSignature:
    """Structured abstraction of a confirmed Phase A exploit.

    Replaces variable names, file paths, and language-specific syntax
    with a portable source→sink skeleton. This is what Phase D feeds
    into the candidate hunter + judge.

    Example (LangChain WebBrowser SSRF seed)::

        SemanticSignature(
            attack_class="ssrf",
            cwe="CWE-918",
            source_shape="LLM-supplied URL string (untrusted)",
            transformations=["string-concat with prefix", "URL.parse"],
            sink_kind="network_fetch",
            sink_callee="fetch",
            missing_guards=[
                "URL.protocol allowlist",
                "private-IP rejection",
                "redirect re-validation",
            ],
            seed_finding_id="H001",
            seed_function="getRequestUrl",
        )
    """

    attack_class: str
    """e.g., ``ssrf``, ``sql_injection``, ``command_injection``,
    ``path_traversal``, ``prompt_injection``."""

    cwe: str = ""
    """CWE identifier; carried through from the seed finding."""

    source_shape: str = ""
    """Plain-English description of the untrusted-input shape that
    drives the exploit. e.g., ``LLM-supplied URL string``,
    ``user-controlled file path``, ``HTTP request body``."""

    transformations: list[str] = field(default_factory=list)
    """Ordered list of transformations applied to the source between
    entry and sink. Empty when source goes directly to sink."""

    sink_kind: str = ""
    """Semantic class of the dangerous operation. One of
    ``network_fetch``, ``shell_exec``, ``sql_query``, ``file_read``,
    ``file_write``, ``eval``, ``deserialize``, ``llm_prompt_inject``,
    ``other``."""

    sink_callee: str = ""
    """The specific function/method name. e.g., ``fetch``, ``urlopen``,
    ``subprocess.run``, ``cursor.execute``, ``open``."""

    missing_guards: list[str] = field(default_factory=list)
    """Validation steps absent from the seed code path that, if
    present, would close the vulnerability. e.g., ``URL.protocol
    allowlist``, ``parametrized SQL bind``, ``path canonicalization``."""

    seed_finding_id: str = ""
    """The L1 finding_id whose Phase A confirmation seeded this
    signature (for traceability + dedup)."""

    seed_function: str = ""
    """The function name of the seed finding's location, when
    extractable. Used to skip the seed itself during candidate
    hunting."""


@dataclass
class VariantCandidate:
    """A candidate function in the same file that MIGHT match the
    signature. Produced by the deterministic AST hunter before
    LLM ranking.
    """

    function_name: str
    """Bare name (no class prefix) of the candidate callable."""

    qualname: str = ""
    """Dotted qualname (e.g., ``WebBrowser._call``) when the candidate
    is an instance method."""

    line_number: int = 0
    """Start line of the function definition. Used in diagnostic
    output + journal evidence."""

    source_snippet: str = ""
    """First N lines of the function body, for the judge prompt.
    Bounded to ~30 lines / ~1200 chars per candidate."""

    sink_callees_observed: list[str] = field(default_factory=list)
    """Function names called inside the body that match the
    signature's ``sink_kind`` family. e.g., for ``sink_kind=
    network_fetch``, this lists every ``fetch``/``urlopen``/
    ``requests.get`` callsite."""

    file_path: str = ""
    """Rel-from-project-root path of the file containing this candidate.
    DAST-302 (cross-file) populates this so DAST-304 (multi-file Phase C
    patch) can group confirmed variants by file and patch them
    coherently. Empty for same-file v1 candidates — they share the
    seed's file and Phase C v14 handles them. MUST be a real dataclass
    field (not a ``__dict__`` extra) so ``dataclasses.asdict()``
    captures it when the orchestrator serializes PhaseDResult into
    the engine dict."""

    is_async: bool = False
    """``True`` when the candidate is an ``AsyncFunctionDef``. The
    cross-file retargeter uses this to emit ``await`` in the variant
    harness when needed."""

    node_kind: str = ""
    """``function`` or ``method`` — used by the cross-file retargeter
    to decide whether to instantiate a class before invoking the
    callable. Empty for same-file v1 candidates."""

    similarity_score: float = 0.0
    """Set by the LLM judge in step 3 (0.0–1.0). 0.0 means "judge has
    not scored yet"."""


@dataclass
class VariantOutcome:
    """Result of sandbox verification on a ranked variant candidate."""

    candidate: VariantCandidate
    verdict: str
    """One of ``confirmed``, ``refuted``, ``inconclusive``,
    ``not_testable``."""

    rationale: str = ""
    """Short human-readable summary of why the variant got this
    verdict. Drawn from sandbox events + the judge's reasoning."""

    sandbox_plan_id: str = ""
    """For traceability — the SandboxPlan id submitted."""

    runtime_evidence: str = ""
    """The specific signal that proved (or refuted) the variant.
    For confirmed: the oracle match. For refuted: the missing
    expected signal."""

    elapsed_ms: int = 0


@dataclass
class PhaseDResult:
    """Output of one Phase D run on one seed finding.

    Attached to ``DastResult.variant_analysis`` as a list — one entry
    per seed finding that triggered Phase D. The engine surfaces
    confirmed variants in the final scan JSON's ``vulnerabilities``
    list alongside the seed.
    """

    seed_finding_id: str
    """The L1 finding_id that seeded this run."""

    attempted: bool
    """True iff Phase D actually executed (vs. skipped due to flag,
    no signature, etc.)."""

    skipped_reason: str = ""
    """When ``attempted=False``: one of ``phase_d_disabled``,
    ``signature_extraction_failed``, ``no_candidates``,
    ``budget_exhausted``, ``ast_parse_failed``,
    ``unsupported_language``."""

    signature: SemanticSignature | None = None
    """The signature produced in step 1. None on early skip."""

    candidates_total: int = 0
    """Count of AST-enumerated candidates (before ranking)."""

    candidates_ranked: int = 0
    """Count of candidates that passed the similarity threshold."""

    outcomes: list[VariantOutcome] = field(default_factory=list)
    """One entry per harness-verified variant. May be shorter than
    ``candidates_ranked`` if the budget was exhausted mid-run."""

    confirmed_variant_ids: list[str] = field(default_factory=list)
    """``finding_id`` strings (``D-<seed>-<idx>``) for each confirmed
    variant. These flow back into ``findings_validated`` so Phase C
    patches them alongside the seed."""

    cost_usd: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    elapsed_ms: int = 0


# ── Deterministic AST candidate hunter (Python) ──────────────────────


def _python_extract_callable_candidates(
    source_code: str,
    signature: SemanticSignature,
    *,
    exclude_qualname: str = "",
    exclude_seed_line: int = 0,
) -> list[VariantCandidate]:
    """Walk the Python AST, return one ``VariantCandidate`` per
    public callable whose body calls a function matching the
    signature's ``sink_kind``.

    Filter rules:
    * Skip ``exclude_qualname`` (the seed function — we don't want to
      "find a variant" of the function that already produced the seed).
    * Skip any function whose ``lineno..end_lineno`` range contains
      ``exclude_seed_line`` (defense-in-depth — protects against the
      seed surfacing as its own variant when ``exclude_qualname`` is
      empty or doesn't match the AST qualname we'd emit).
    * Skip private functions (name starts with ``_``) UNLESS they're
      agentic-convention names (``_call``).
    * Skip method bodies with no callsite matching the sink family.
    * Bound candidate count to ``MAX_VARIANT_CANDIDATES_PER_SEED * 2``
      (the LLM judge then prunes further). Excess silently dropped.
    """
    candidates: list[VariantCandidate] = []
    try:
        tree = ast.parse(source_code)
    except SyntaxError as exc:
        log.warning("Phase D AST parse failed: %s", exc)
        return []

    sink_callee_names = _sink_callee_names_for(signature.sink_kind)
    if not sink_callee_names:
        # Fall back to literal callee match from the signature itself.
        sink_callee_names = {signature.sink_callee.split(".")[-1]}

    src_lines = source_code.splitlines()

    def _walk_class(cls: ast.ClassDef) -> None:
        for child in cls.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _consider_function(child, parent_class=cls.name)

    def _consider_function(
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        parent_class: str = "",
    ) -> None:
        qualname = (
            f"{parent_class}.{fn.name}" if parent_class else fn.name
        )
        start_line = fn.lineno
        end_line = getattr(fn, "end_lineno", start_line + 30) or start_line + 30
        # Skip the seed function itself — by qualname …
        if exclude_qualname and qualname == exclude_qualname:
            return
        # … or by line range (defense in depth: the seed's L1-reported
        # line falls inside this function's body, regardless of what
        # qualname the LLM signature / regex guesser produced).
        if exclude_seed_line and start_line <= exclude_seed_line <= end_line:
            return
        # Skip private unless agentic-convention.
        if fn.name.startswith("_") and fn.name not in (
            "_call",
            "_arun",
            "_aexecute",
        ):
            return

        sink_callees_in_body: list[str] = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                callee = _callee_name(node)
                if callee and any(
                    callee == s or callee.endswith("." + s)
                    for s in sink_callee_names
                ):
                    sink_callees_in_body.append(callee)
        if not sink_callees_in_body:
            return  # no sink in this function — skip
        snippet_lines = src_lines[
            max(0, start_line - 1) : min(len(src_lines), end_line)
        ]
        snippet = "\n".join(snippet_lines)[:1200]

        candidates.append(
            VariantCandidate(
                function_name=fn.name,
                qualname=qualname,
                line_number=start_line,
                source_snippet=snippet,
                sink_callees_observed=sorted(set(sink_callees_in_body))[:8],
            )
        )

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _consider_function(node)
        elif isinstance(node, ast.ClassDef):
            _walk_class(node)

    # Bound candidate set to keep the judge prompt small.
    cap = MAX_VARIANT_CANDIDATES_PER_SEED * 2
    return candidates[:cap]


def _sink_callee_names_for(sink_kind: str) -> set[str]:
    """Map a signature ``sink_kind`` to the set of plausible callee
    names whose presence in a candidate body promotes it for ranking.

    Keep this list focused — broad matching dilutes Phase D's signal.
    Returns ``set()`` for unrecognised sink_kinds so the caller falls
    back to the literal ``sink_callee`` from the signature.
    """
    mapping: dict[str, set[str]] = {
        "network_fetch": {
            "fetch",
            "urlopen",
            "request",
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "head",
        },
        "shell_exec": {
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "system",
        },
        "sql_query": {
            "execute",
            "executemany",
            "run",
            "query",
            "raw_query",
            "exec_driver_sql",
        },
        "file_read": {
            "open",
            "read",
            "read_text",
            "read_bytes",
            "load",
        },
        "file_write": {
            "open",
            "write",
            "write_text",
            "write_bytes",
            "writelines",
            "save",
            "dump",
        },
        "eval": {
            "eval",
            "exec",
            "compile",
            "Function",  # JS new Function()
        },
        "deserialize": {
            "loads",
            "load",
            "unpickle",
            "deserialize",
            "from_json",
            "from_yaml",
        },
        "llm_prompt_inject": {
            "invoke",
            "ainvoke",
            "complete",
            "chat",
            "generate",
            "call",
        },
    }
    return mapping.get(sink_kind, set())


def _callee_name(node: ast.Call) -> str:
    """Extract the callee's name from an ``ast.Call`` node.

    Returns the bare ``name`` for ``Name`` nodes, the dotted
    ``a.b.c`` for ``Attribute`` chains, or empty string for other
    callable forms (lambda, subscript, etc.).
    """
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = [func.attr]
        node_curs: Any = func.value
        while isinstance(node_curs, ast.Attribute):
            parts.append(node_curs.attr)
            node_curs = node_curs.value
        if isinstance(node_curs, ast.Name):
            parts.append(node_curs.id)
        return ".".join(reversed(parts))
    return ""


def extract_variant_candidates(
    *,
    source_code: str,
    signature: SemanticSignature,
    language: str,
    exclude_qualname: str = "",
    exclude_seed_line: int = 0,
) -> list[VariantCandidate]:
    """Top-level candidate hunter. Dispatches by language.

    v1 supports Python only via AST. TS/JS will get a tree-sitter
    based hunter in v1.1 (DAST-302).

    Returns ``[]`` for unsupported languages — Phase D's
    ``unsupported_language`` skip path activates in that case.

    ``exclude_seed_line`` defends against the seed surfacing as its
    own variant when ``exclude_qualname`` extraction fails (e.g., the
    LLM signature returned empty ``seed_function`` and the L1
    hypothesis dict lacks a function_name field).
    """
    if language == "python":
        return _python_extract_callable_candidates(
            source_code,
            signature,
            exclude_qualname=exclude_qualname,
            exclude_seed_line=exclude_seed_line,
        )
    log.info("Phase D: language %s not yet supported (v1 = Python only)", language)
    return []


# ── Harness retargeter ────────────────────────────────────────────────


def retarget_harness_for_variant(
    *,
    seed_plan_commands: list[str],
    seed_function: str,
    variant: VariantCandidate,
    signature: SemanticSignature,
) -> list[str]:
    """Adapt the seed finding's Phase A sandbox commands to target the
    variant's function name instead of the seed's.

    v1 implements simple textual substitution: every occurrence of
    ``seed_function`` in the seed plan's commands is replaced with
    ``variant.function_name``. This works because Phase A's harness
    embedding wraps the call site in a single recognisable pattern
    (e.g., ``await target.fetch_url(...)``).

    Limitations of v1:
    * Doesn't handle differing arg shapes (variant takes 2 args, seed
      took 3). Future v1.1 will inspect ``inspect.signature(variant)``
      and adapt args.
    * Doesn't inject signature.missing_guards as test predicates —
      the variant's verdict relies on the seed's oracle.

    These limitations are acceptable for v1 because the AST hunter
    only surfaces candidates whose sink-callee matches the signature;
    the seed oracle catches the same exploit class on those candidates.
    """
    if not seed_function or not variant.function_name:
        return list(seed_plan_commands)
    if seed_function == variant.function_name:
        return list(seed_plan_commands)
    retargeted: list[str] = []
    for cmd in seed_plan_commands:
        # Whole-word replacement only — don't substitute inside
        # longer identifiers (e.g., 'fetch_url_old' must NOT match
        # 'fetch_url').
        retargeted.append(_whole_word_replace(cmd, seed_function, variant.function_name))
    return retargeted


def _whole_word_replace(text: str, old: str, new: str) -> str:
    """Replace whole-word occurrences of ``old`` with ``new`` in
    ``text``. Word boundaries are characters in
    ``[^A-Za-z0-9_]`` (or string start/end).
    """
    if not old or old not in text:
        return text
    import re  # noqa: PLC0415

    pattern = r"(?<![A-Za-z0-9_])" + re.escape(old) + r"(?![A-Za-z0-9_])"
    return re.sub(pattern, new, text)


# ── DAST-302: cross-file extension ────────────────────────────────────


def extract_variant_candidates_from_graph(
    *,
    graph: Any,  # CodeGraph — annotated as Any to avoid circular import
    signature: SemanticSignature,
    exclude_qualname: str = "",
    exclude_file_path: str = "",
    exclude_seed_line: int = 0,
) -> list[VariantCandidate]:
    """Cross-file variant hunter for DAST-302 v1.1.

    Walks every node in the supplied :class:`CodeGraph` and emits a
    :class:`VariantCandidate` for every node whose callsites include
    at least one match against the signature's ``sink_kind`` family.

    Unlike v1's ``extract_variant_candidates``, this function:
    * Iterates ALL files in the graph (not just one).
    * Carries the candidate's ``file_path`` (rel-from-project-root)
      so the cross-file retargeter knows where to import from.
    * Excludes the seed function by ``(exclude_file_path,
      exclude_qualname)`` tuple to avoid finding the seed as its
      own variant.
    * Defense-in-depth: also excludes any same-file node whose
      ``[line_number, end_line_number]`` range contains the seed's
      L1-reported ``exclude_seed_line``. Fires even when the qualname
      tuple match fails (LLM signature returned empty seed_function,
      or AST graph builder used a different qualname convention).

    Returns up to ``MAX_VARIANT_CANDIDATES_PER_SEED * 2`` candidates
    (the LLM judge prunes further).
    """
    sink_callee_names = _sink_callee_names_for(signature.sink_kind)
    if not sink_callee_names:
        sink_callee_names = {signature.sink_callee.split(".")[-1]}

    candidates: list[VariantCandidate] = []
    cap = MAX_VARIANT_CANDIDATES_PER_SEED * 2

    for node in graph.nodes:
        if len(candidates) >= cap:
            break
        # Exclude seed: same file AND same qualname.
        if (
            exclude_file_path
            and exclude_qualname
            and node.file_path == exclude_file_path
            and node.qualname == exclude_qualname
        ):
            continue
        # Defense-in-depth: same file AND line range encloses seed line.
        if (
            exclude_file_path
            and exclude_seed_line
            and node.file_path == exclude_file_path
            and node.line_number
            <= exclude_seed_line
            <= (node.end_line_number or node.line_number)
        ):
            continue
        # Filter to candidates whose callsites include at least one
        # name in the signature's sink-family.
        observed = [
            c.callee_name
            for c in node.callsites
            if any(
                c.callee_name == s or c.callee_name.endswith("." + s)
                for s in sink_callee_names
            )
        ]
        if not observed:
            continue

        # Read a snippet of the source — re-read the file (already
        # bounded by MAX_BYTES_PER_GRAPH_FILE so this is cheap).
        snippet = _safe_slice_function_source(
            file_path=node.file_path,
            project_root=getattr(graph, "project_root", ""),
            start_line=node.line_number,
            end_line=node.end_line_number or (node.line_number + 30),
        )

        candidate = VariantCandidate(
            function_name=node.function_name,
            qualname=node.qualname,
            line_number=node.line_number,
            source_snippet=snippet,
            sink_callees_observed=sorted(set(observed))[:8],
            file_path=node.file_path,
            is_async=bool(node.is_async),
            node_kind=str(node.node_kind or ""),
        )
        candidates.append(candidate)
    return candidates


def _safe_slice_function_source(
    *,
    file_path: str,
    project_root: str,
    start_line: int,
    end_line: int,
) -> str:
    """Read the source lines [start_line, end_line] from
    ``project_root/file_path``. Returns an empty string on any I/O
    error. Bounded to 1200 chars to keep the judge prompt small."""
    if not project_root or not file_path:
        return ""
    from pathlib import Path  # noqa: PLC0415

    full = Path(project_root) / file_path
    try:
        text = full.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    s = max(0, start_line - 1)
    e = min(len(lines), end_line)
    return "\n".join(lines[s:e])[:1200]


def retarget_harness_for_cross_file_variant(
    *,
    seed_plan_commands: list[str],
    seed_function: str,
    variant: VariantCandidate,
    signature: SemanticSignature,
    seed_file_rel_path: str = "",
) -> list[str]:
    """Cross-file analogue of :func:`retarget_harness_for_variant`.

    For a variant living in a different file from the seed, the
    harness must:
    1. Import the variant's module (sibling file staged at
       ``/workspace/<rel>`` by the v12 tarball).
    2. Call the variant's function via its module path, not the
       entry's module.

    Implementation: substitute the seed_function name with a
    module-qualified path ``<module>.<function_name>`` where module
    is derived from the variant's file_path (e.g.,
    ``lib/helpers.py`` → ``lib.helpers``).

    For SAME-file variants (variant.file_path matches the seed's
    file_path), falls through to plain whole-word substitution
    (the v1 behavior).

    v1.1 limitation: handles Python only. The TS/JS pathway falls
    back to same-file behavior in v1.1; v1.2 will add
    ``import { variantFn } from './lib/helpers'`` syntax for ESM.
    """
    variant_file_path = variant.file_path or ""

    if not variant_file_path or variant_file_path == seed_file_rel_path:
        # Same file as seed — v1 whole-word retarget is correct.
        return retarget_harness_for_variant(
            seed_plan_commands=seed_plan_commands,
            seed_function=seed_function,
            variant=variant,
            signature=signature,
        )

    # Cross-file: derive Python module path from rel file path.
    # ``lib/helpers.py`` → ``lib.helpers``. Drop leading subdir if it
    # matches the file's package (e.g., ``src/myproj/lib/helpers.py``
    # could be either ``src.myproj.lib.helpers`` or, more commonly,
    # ``myproj.lib.helpers``). v1.1 takes the literal rel path
    # converted to a dotted path; users with custom package layouts
    # may see import failures — that's an explicit v1.2 follow-on.
    if not variant_file_path.endswith(".py"):
        # Not a Python file — fall back to same-file retarget.
        return retarget_harness_for_variant(
            seed_plan_commands=seed_plan_commands,
            seed_function=seed_function,
            variant=variant,
            signature=signature,
        )
    module_dotted = variant_file_path[:-3].replace("/", ".").replace("\\", ".")
    # AST-aware harness rewriting (Bug #6). Whole-word substitution
    # would mangle realistic Phase A command shapes — e.g.,
    # ``import app; app.fetch_url(...)`` becomes
    # ``import app; app.lib.downloaders.download_image(...)`` (an
    # AttributeError at runtime), and ``from app import fetch_url``
    # becomes invalid Python. The new ``_retarget_python_c_command``
    # parses the ``python3 -c '<body>'`` argument as Python, walks the
    # AST, redirects every seed callsite (bare ``seed_function(...)``
    # AND ``<any>.seed_function(...)``) to
    # ``<variant_module>.<variant_function>(...)``, strips
    # ``from <X> import seed_function`` stanzas (now redundant), and
    # idempotently prepends ``import <variant_module>``. Non-``-c``
    # commands (script harnesses) fall through to the same whole-word
    # substitution as before — preserves existing behavior for the
    # rare shape Phase A plans don't typically emit.
    retargeted: list[str] = []
    for cmd in seed_plan_commands:
        retargeted.append(
            _retarget_python_c_command(
                cmd=cmd,
                seed_function=seed_function,
                variant_module_dotted=module_dotted,
                variant_function_name=variant.function_name,
            )
        )
    return retargeted


def _retarget_python_c_command(
    *,
    cmd: str,
    seed_function: str,
    variant_module_dotted: str,
    variant_function_name: str,
) -> str:
    """Find a ``-c '<body>'`` (or ``-c "<body>"``) form in ``cmd``,
    AST-rewrite the Python body to invoke the cross-file variant, then
    re-emit the full command with shell-safe quoting.

    Returns ``cmd`` unchanged for commands without a ``-c`` form (script
    harnesses, raw curl/etc.) — Fix #6 v1 scope is the dominant Phase A
    harness shape. Returns ``cmd`` unchanged on AST parse failure
    (fail-open: variant verification produces "no oracle signal"
    refute instead of crashing the whole Phase D pipeline).
    """
    import re  # noqa: PLC0415

    # Match ``-c`` followed by a quoted argument. Non-greedy — bodies
    # are not expected to contain the outer quote character (Phase A
    # plans use single-quoted bodies with double quotes inside, or
    # vice versa). A trailing whitespace or end-of-string boundary
    # prevents partial matches.
    pattern = re.compile(r"-c\s+(['\"])(.*?)\1(?=\s|$)", re.DOTALL)
    m = pattern.search(cmd)
    if not m:
        # No -c form found — preserve the original command. Variant
        # verification will produce a refute for non-`-c` shapes,
        # which matches today's behavior; v1 doesn't regress.
        return cmd

    body = m.group(2)
    new_body = _retarget_python_c_body(
        body=body,
        seed_function=seed_function,
        variant_module_dotted=variant_module_dotted,
        variant_function_name=variant_function_name,
    )
    if new_body == body:
        # AST walk found nothing to rewrite (idempotent re-application
        # or body had no seed callsites) — leave the original command.
        return cmd

    # Choose the outer quote character. Prefer single quotes (no shell
    # interpolation of $, backticks, etc.). When ``ast.unparse``
    # produces a body containing single-quoted string literals (the
    # default in Python 3.12), fall back to double-quote wrapping with
    # shell-escaping of ``$``, ``"``, ``\``, and backticks.
    if "'" not in new_body:
        new_quoted = "'" + new_body + "'"
    else:
        escaped = (
            new_body.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("$", "\\$")
            .replace("`", "\\`")
        )
        new_quoted = '"' + escaped + '"'

    return cmd[: m.start()] + "-c " + new_quoted + cmd[m.end() :]


def _retarget_python_c_body(
    *,
    body: str,
    seed_function: str,
    variant_module_dotted: str,
    variant_function_name: str,
) -> str:
    """AST-rewrite a ``python3 -c '<body>'`` body to invoke a cross-file
    variant. Idempotent. Fails open on ``SyntaxError`` (returns the
    body unchanged).

    Transformations:

    * Every ``Call`` whose ``func`` is ``Name(seed_function)`` or
      ``Attribute(... .seed_function)`` is redirected to
      ``Attribute(<variant_module_dotted>.<variant_function_name>)``.
    * Every ``ImportFrom`` ``from <X> import <seed_function>`` is
      stripped (the bare name now resolves to a module path; the import
      is redundant and would shadow the redirected call).
    * ``import <variant_module_dotted>`` is prepended once, idempotent
      (subsequent calls don't double-add it).

    Stdlib + unrelated imports are left intact. The seed's own
    ``import <seed_module>`` line is also left intact — it's harmless
    dead code post-rewrite and stripping it would require knowing the
    seed's module name (not threaded through the retargeter today).
    """
    try:
        tree = ast.parse(body)
    except SyntaxError:
        log.warning(
            "Phase D cross-file retarget: AST parse failed on seed "
            "harness body — variant verification will fall through "
            "to unmodified command and likely refute on missing "
            "oracle signal."
        )
        return body

    def _build_attribute_chain(dotted: str) -> ast.expr:
        """``a.b.c`` → ``Attribute(Attribute(Name('a'), 'b'), 'c')``."""
        parts = dotted.split(".")
        node: ast.expr = ast.Name(id=parts[0], ctx=ast.Load())
        for part in parts[1:]:
            node = ast.Attribute(value=node, attr=part, ctx=ast.Load())
        return node

    class _RewriteCallsites(ast.NodeTransformer):
        def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
            # Strip ``from <any_module> import <seed_function>`` — the
            # rewritten body calls via the variant's module path, so
            # the seed-function name being bound at module scope would
            # shadow nothing useful (and risks aliasing if the variant
            # function shares the same bare name).
            new_names = [a for a in node.names if a.name != seed_function]
            if not new_names:
                return None  # drop the whole statement
            node.names = new_names
            return node

        def visit_Call(self, node: ast.Call) -> ast.AST:
            self.generic_visit(node)
            func = node.func
            should_rewrite = (
                isinstance(func, ast.Name) and func.id == seed_function
            ) or (
                isinstance(func, ast.Attribute) and func.attr == seed_function
            )
            if should_rewrite:
                node.func = _build_attribute_chain(
                    f"{variant_module_dotted}.{variant_function_name}"
                )
            return node

    new_tree = _RewriteCallsites().visit(tree)
    ast.fix_missing_locations(new_tree)

    # Idempotent variant-module import: skip if already present at the
    # top level. ``import lib.downloaders`` matches; an alias like
    # ``import lib.downloaders as ld`` does not — but that's fine; the
    # variant's call site uses the canonical dotted path either way.
    has_variant_import = False
    for stmt in new_tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.name == variant_module_dotted and alias.asname is None:
                    has_variant_import = True
                    break
        if has_variant_import:
            break
    if not has_variant_import:
        import_stmt = ast.parse(f"import {variant_module_dotted}").body[0]
        new_tree.body = [import_stmt] + new_tree.body

    return ast.unparse(new_tree)


def resolve_seed_qualname_from_ast(source_code: str, line: int) -> str:
    """Resolve the seed function's class-qualified qualname by AST-walk.

    Given the seed file's source + the L1-reported line number, return
    the deepest enclosing function/method's qualname using the same
    convention as ``_python_extract_callable_candidates``:
    ``ClassName.method`` for methods, bare ``function`` for module-
    level fns. Handles ``FunctionDef``, ``AsyncFunctionDef``, and
    nested classes/functions.

    Returns empty string when:
    * ``line`` is non-positive (caller has no line info)
    * the source has a syntax error
    * no function/method body encloses ``line`` (module-level code)

    This is the deterministic backstop for the LLM-extracted
    ``signature.seed_function`` field when it comes back empty —
    without it the variant hunter can't exclude the seed and reports
    the seed itself as its own variant (real bug observed in v4 scan
    of /tmp/argus_phase_d_test/app.py).
    """
    if line <= 0:
        return ""
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return ""

    deepest_qualname = ""

    def walk(node: ast.AST, class_stack: list[str]) -> None:
        nonlocal deepest_qualname
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                walk(child, class_stack + [node.name])
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", start) or start
            if start <= line <= end:
                qualname = ".".join([*class_stack, node.name])
                deepest_qualname = qualname  # innermost wins (walked depth-first)
                for child in node.body:
                    walk(child, class_stack)
            return
        for child in ast.iter_child_nodes(node):
            walk(child, class_stack)

    for top in tree.body:
        walk(top, [])
    return deepest_qualname


__all__ = [
    "DEFAULT_VARIANT_TIMEOUT_SEC",
    "MAX_VARIANT_CANDIDATES_PER_SEED",
    "MIN_VARIANT_SIMILARITY_THRESHOLD",
    "PHASE_D_MAX_COST_PER_SEED_USD",
    "PhaseDResult",
    "SemanticSignature",
    "VariantCandidate",
    "VariantOutcome",
    "extract_variant_candidates",
    "extract_variant_candidates_from_graph",
    "resolve_seed_qualname_from_ast",
    "retarget_harness_for_cross_file_variant",
    "retarget_harness_for_variant",
]
