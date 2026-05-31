"""DAST-302 — Cross-file code graph for variant analysis (v1.1).

Phase D v1 (DAST-301) hunted variants only in the seed's own file.
v1.1 extends to cross-file: walk every function in every project file,
index each function's callsites, then hunt for variants matching the
seed's semantic signature across the WHOLE project.

The graph is built from Python's stdlib ``ast`` module for Python
files (zero new deps). Tree-sitter integration for TS/JS is deferred
to v1.2 — most real targets have one dominant language, and Argus's
own evals (LangChain TS, MCP Python, mcp-server-fetch Python) split
roughly evenly. v1.1 ships Python-only cross-file; TS/JS still uses
v1's same-file behavior.

Project-root resolution reuses ``preprocessing.sibling_files``'s
``_find_project_root`` (the same marker-file walk that v12 sibling
staging uses). Bounded enumeration: max 200 files, 256 KB per file,
5000 graph nodes total. Excludes ``node_modules``, ``.git``,
``__pycache__``, ``.venv``, ``venv``, ``site-packages``,
``dist``, ``build``.

Public API::

    build_python_code_graph(project_root, entry_file_path)
        Walk the project, parse every .py file's AST, return a
        :class:`CodeGraph` with one :class:`GraphNode` per function.

    find_candidates_in_graph(graph, signature, exclude_qualname)
        Filter graph nodes to those whose callsites include the
        signature's sink-callee family. Returns a list of
        :class:`VariantCandidate` shapes ready for the LLM judge.

Cost: zero model calls. Graph build is deterministic; bounded to
seconds even on large projects.

Failure modes: any single-file parse failure is logged and skipped;
the graph still surfaces every successfully-parsed file's nodes.
A graph with zero nodes triggers the runner's ``no_candidates`` skip
path.
"""

from __future__ import annotations

import ast
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("argus.dast.code_graph")


# ── Tunables ─────────────────────────────────────────────────────────


#: Hard cap on files enumerated when walking the project root. A
#: monorepo with 10k files would otherwise stall Phase D graph build.
MAX_FILES_PER_GRAPH: int = 200

#: Hard cap on per-file source size. Files larger than this get
#: skipped (the variant judge's source-snippet block is bounded to
#: ~1200 chars per candidate; gigantic files rarely contain
#: attack-attractive callables outside the bounded subset).
MAX_BYTES_PER_GRAPH_FILE: int = 256 * 1024

#: Hard cap on total graph nodes. Bounds memory + downstream judge
#: prompt cost. Defensive — most real projects have <500 functions.
MAX_GRAPH_NODES: int = 5000

#: Directory names excluded from the project walk. These are bytecode
#: caches, vendored dependencies, build outputs, version-control
#: internals — anything except the project's own source.
EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".venv",
        "venv",
        "env",
        "site-packages",
        "dist",
        "build",
        ".tox",
        "target",  # rust/maven build dir
        ".argus_local",  # Argus's own scratch dir — never graph our own outputs
    }
)


# ── Data types ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Callsite:
    """One call expression observed inside a graph node's body.

    Frozen so multiple nodes can share callsite references safely;
    callsites are immutable observations of the AST.
    """

    callee_name: str
    """Dotted name of the callee. e.g., ``urlopen``,
    ``urllib.request.urlopen``, ``self.client.fetch``."""

    line_number: int = 0
    """Source line of the call. Used in diagnostic output."""


@dataclass
class GraphNode:
    """One function-shaped node in the code graph.

    Cross-file analogue to v1's :class:`VariantCandidate` but
    decoupled from the LLM-judging step. The variant analyzer
    converts a filtered subset of nodes into ``VariantCandidate``s
    for the judge prompt.
    """

    file_path: str
    """Relative path from the project root (e.g. ``lib/helpers.py``).
    Stays relative so the graph is portable across host environments
    + the v12 sibling-staging tarball that lays files under
    ``/workspace/<rel>``."""

    qualname: str
    """Function qualname. Bare name for module-level functions;
    ``ClassName.method`` for instance methods. Class-nested
    functions get ``ClassName.method`` form too — we don't dig into
    nested-function-inside-method shapes (rare + low signal)."""

    function_name: str
    """Bare function name without class prefix. Used by the harness
    retargeter for substitution."""

    node_kind: str
    """One of ``function``, ``method``. Used by the retargeter to
    decide whether to dispatch via instance or module."""

    line_number: int = 0
    """Source line of ``def``."""

    end_line_number: int = 0
    """Source line of the function's last statement, when extractable.
    Used to slice source snippets for the judge prompt."""

    callsites: list[Callsite] = field(default_factory=list)
    """Every call expression observed inside the body (bounded — see
    parser code for cap)."""

    is_async: bool = False
    """True for ``async def``. Affects harness retargeting (the
    harness must ``await`` async variants)."""


@dataclass
class CodeGraph:
    """Aggregated graph for one Phase D run.

    The graph is throwaway: built per-seed when Phase D fires, used
    once for cross-file variant hunting, then discarded. We don't
    persist across files because cache invalidation on a live
    project is hairier than the rebuild cost.
    """

    project_root: str
    """Absolute path to the resolved project root. Empty when the
    runner couldn't resolve a root (single-file scan)."""

    entry_file: str
    """Relative path from ``project_root`` to the seed's entry file.
    Empty when project_root is empty."""

    nodes: list[GraphNode] = field(default_factory=list)

    files_scanned: int = 0
    """Count of project files actually parsed (after exclusion +
    size + cap filters)."""

    files_skipped: int = 0
    """Count of files excluded by directory filter, size cap, parse
    failure, or node cap. Surfaced for telemetry."""

    elapsed_ms: int = 0


# ── Project file enumeration ─────────────────────────────────────────


def _is_excluded_path(path: Path, project_root: Path) -> bool:
    """True iff any path component (relative to project_root) is in
    :data:`EXCLUDED_DIR_NAMES`."""
    try:
        rel = path.resolve().relative_to(project_root.resolve())
    except (ValueError, OSError):
        return True  # path outside project root — exclude defensively
    for part in rel.parts:
        if part in EXCLUDED_DIR_NAMES:
            return True
    return False


def enumerate_project_files(
    project_root: Path,
    *,
    extensions: tuple[str, ...] = (".py",),
    max_files: int = MAX_FILES_PER_GRAPH,
    max_bytes_per_file: int = MAX_BYTES_PER_GRAPH_FILE,
) -> list[Path]:
    """Walk ``project_root`` and return every same-language file
    eligible for graph building.

    Bounded by ``max_files`` (default 200) and per-file size cap.
    Excludes directories named in :data:`EXCLUDED_DIR_NAMES`.

    Returns absolute paths. The caller computes relative paths for
    ``GraphNode.file_path``.
    """
    if not project_root.is_dir():
        return []
    out: list[Path] = []
    # Sort by mtime descending so recently-edited files (more likely
    # to contain the seed + related variants) get priority when we
    # hit the cap. ``rglob`` returns files in walk order which is
    # filesystem-dependent + not deterministic across runs; we sort
    # after collection.
    candidates: list[Path] = []
    try:
        for ext in extensions:
            for p in project_root.rglob(f"*{ext}"):
                if not p.is_file():
                    continue
                if _is_excluded_path(p, project_root):
                    continue
                try:
                    size = p.stat().st_size
                except OSError:
                    continue
                if size > max_bytes_per_file:
                    continue
                candidates.append(p)
    except OSError as exc:
        log.warning("Phase D graph: rglob failed under %s: %s", project_root, exc)
        return []

    # Sort by mtime descending — recently-edited files first.
    try:
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        pass

    return candidates[:max_files]


# ── Python AST graph builder ─────────────────────────────────────────


class _CallsiteVisitor(ast.NodeVisitor):
    """Collect every ``ast.Call`` callee within one function body.

    Bounded to MAX_CALLSITES_PER_NODE to keep per-node memory + the
    candidate-judge prompt size in check.
    """

    MAX_CALLSITES_PER_NODE: int = 50

    def __init__(self) -> None:
        self.callsites: list[Callsite] = []

    def visit_Call(self, node: ast.Call) -> None:
        if len(self.callsites) >= self.MAX_CALLSITES_PER_NODE:
            return
        name = _callee_name_from_ast(node)
        if name:
            self.callsites.append(
                Callsite(callee_name=name, line_number=getattr(node, "lineno", 0))
            )
        # Continue descending — nested calls also get captured.
        self.generic_visit(node)


def _callee_name_from_ast(node: ast.Call) -> str:
    """Mirror of variant_analysis._callee_name. Kept inline here so
    code_graph stays standalone (Argus's policy: phase modules don't
    cross-import private helpers)."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = [func.attr]
        cur: Any = func.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _build_python_nodes_for_file(
    *,
    file_path: Path,
    project_root: Path,
) -> list[GraphNode]:
    """Parse one Python file's AST and emit one :class:`GraphNode` per
    function definition (module-level + class methods, one tier deep).

    Returns an empty list on parse failure (logged at WARNING).
    """
    try:
        rel_path = str(file_path.resolve().relative_to(project_root.resolve())).replace(
            "\\", "/"
        )
    except (ValueError, OSError):
        rel_path = file_path.name

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.debug("Phase D graph: read failed for %s: %s", file_path, exc)
        return []

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        log.debug("Phase D graph: SyntaxError in %s: %s", file_path, exc)
        return []

    nodes: list[GraphNode] = []

    def _emit(fn: ast.FunctionDef | ast.AsyncFunctionDef, parent_class: str = "") -> None:
        # Skip private non-agentic names — same rule as v1's
        # variant_analysis._python_extract_callable_candidates.
        if fn.name.startswith("_") and fn.name not in (
            "_call",
            "_arun",
            "_aexecute",
        ):
            return
        # Walk body for callsites.
        visitor = _CallsiteVisitor()
        for stmt in fn.body:
            visitor.visit(stmt)
        qualname = f"{parent_class}.{fn.name}" if parent_class else fn.name
        nodes.append(
            GraphNode(
                file_path=rel_path,
                qualname=qualname,
                function_name=fn.name,
                node_kind="method" if parent_class else "function",
                line_number=fn.lineno,
                end_line_number=getattr(fn, "end_lineno", fn.lineno) or fn.lineno,
                callsites=list(visitor.callsites),
                is_async=isinstance(fn, ast.AsyncFunctionDef),
            )
        )

    for top_node in tree.body:
        if isinstance(top_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _emit(top_node)
        elif isinstance(top_node, ast.ClassDef):
            for child in top_node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _emit(child, parent_class=top_node.name)

    return nodes


def build_python_code_graph(
    *,
    project_root: Path,
    entry_file: Path,
    max_files: int = MAX_FILES_PER_GRAPH,
    max_bytes_per_file: int = MAX_BYTES_PER_GRAPH_FILE,
    max_nodes: int = MAX_GRAPH_NODES,
) -> CodeGraph:
    """Build a :class:`CodeGraph` for every ``.py`` file under
    ``project_root``.

    The graph is throwaway and bounded. Per-file parse failures are
    logged + skipped; the resulting graph contains every successfully-
    parsed file's nodes up to ``max_nodes``.

    Returns a graph with ``files_scanned=0`` when ``project_root``
    isn't a directory — the runner skips with ``no_candidates`` in
    that case.
    """
    started = time.time()
    graph = CodeGraph(
        project_root=str(project_root),
        entry_file="",
    )
    if not project_root.is_dir():
        graph.elapsed_ms = int((time.time() - started) * 1000)
        return graph

    # Compute entry_file as rel-from-project-root for the orchestrator's
    # debug visibility.
    try:
        graph.entry_file = str(
            entry_file.resolve().relative_to(project_root.resolve())
        ).replace("\\", "/")
    except (ValueError, OSError):
        graph.entry_file = entry_file.name

    files = enumerate_project_files(
        project_root,
        extensions=(".py",),
        max_files=max_files,
        max_bytes_per_file=max_bytes_per_file,
    )

    seen_qualnames: set[tuple[str, str]] = set()
    for fp in files:
        if len(graph.nodes) >= max_nodes:
            graph.files_skipped += len(files) - graph.files_scanned
            break
        try:
            file_nodes = _build_python_nodes_for_file(
                file_path=fp,
                project_root=project_root,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Phase D graph: unexpected parse failure for %s: %s", fp, exc)
            graph.files_skipped += 1
            continue
        if not file_nodes:
            graph.files_skipped += 1
            continue
        # Dedup by (file_path, qualname) — defensive, shouldn't happen
        # but cheap to guard.
        for node in file_nodes:
            key = (node.file_path, node.qualname)
            if key in seen_qualnames:
                continue
            seen_qualnames.add(key)
            graph.nodes.append(node)
            if len(graph.nodes) >= max_nodes:
                break
        graph.files_scanned += 1

    graph.elapsed_ms = int((time.time() - started) * 1000)
    log.info(
        "Phase D graph built: %d nodes across %d files (%d skipped) in %d ms",
        len(graph.nodes),
        graph.files_scanned,
        graph.files_skipped,
        graph.elapsed_ms,
    )
    return graph


# ── Project root resolution ──────────────────────────────────────────


def resolve_project_root_for_file(file_path: Path) -> Path | None:
    """Walk upward from ``file_path`` looking for project-root marker
    files, the same as v12 sibling-file staging
    (preprocessing/sibling_files._find_project_root).

    Returns the resolved root, or ``None`` when no marker is found
    (single-file scan with no surrounding project context).

    We re-use the same marker set as v12 so Phase D's cross-file
    graph stays consistent with what the sandbox sees in
    ``/workspace`` after the sibling tarball extracts.
    """
    try:
        # Avoid cross-importing preprocessing internals; re-implement
        # the small walk inline. The marker set MUST stay in sync with
        # preprocessing.sibling_files._PROJECT_ROOT_MARKERS.
        _markers = (
            "tsconfig.json",
            "package.json",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "Cargo.toml",
            "go.mod",
            "Gemfile",
            "build.gradle",
            "build.gradle.kts",
            "pom.xml",
            "composer.json",
            ".git",
        )
        cur = file_path.resolve().parent
        for _ in range(8):  # bounded ancestor walk
            for marker in _markers:
                if (cur / marker).exists():
                    return cur
            if cur.parent == cur:
                return None
            cur = cur.parent
        return None
    except OSError:
        return None


__all__ = [
    "Callsite",
    "CodeGraph",
    "EXCLUDED_DIR_NAMES",
    "GraphNode",
    "MAX_BYTES_PER_GRAPH_FILE",
    "MAX_FILES_PER_GRAPH",
    "MAX_GRAPH_NODES",
    "build_python_code_graph",
    "enumerate_project_files",
    "resolve_project_root_for_file",
]
