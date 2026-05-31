"""Sibling-file resolver for multi-file project DAST scans.

When Argus scans a single entry file from a multi-file project (e.g.,
``index.ts`` that imports ``./path-utils``, or ``module.py`` that uses
``from .utils import bar``), the sandbox needs ALL referenced sibling
files staged at the same relative paths the entry file expects.
Without that, runtime probes hit ``ImportError`` / ``Cannot find
module`` at harness import time and Stage 1's behavioral profile
comes back empty — exactly the gap the v9/v10 mcp-server-filesystem
smoke surfaced.

This module produces the set of (relative_path → file_bytes) pairs to
stage. The orchestrator attaches them to the SandboxPlan, the sandbox
client packs them into a tar.gz, and ``dast-init.sh`` extracts them
into ``/workspace`` preserving the directory layout the entry file
sees.

Design contract
===============

  * **Input**: entry file's absolute host path + bytes + language.
  * **Output**: dict[relative_path_under_entry_dir, bytes] — does NOT
    include the entry file itself (caller already stages that).
  * **Scope**: same-directory + descendant directories only. Imports
    that resolve to paths ABOVE the entry file's directory (``../``
    escapes) are REJECTED — same security stance as ``--exclude``
    in scan-repo. Operators wanting "whole-project" coverage should
    scan from the project root.
  * **Languages**: TypeScript (.ts/.tsx), JavaScript (.js/.mjs/.cjs),
    Python (.py). Cross-language imports not supported (TS importing
    .py won't resolve — fail closed).

Security
========

  * **Path-traversal defense**: every resolved path is absolute, then
    checked to ensure it stays inside the entry file's directory. Any
    escape (``../foo`` resolving above the entry dir) is dropped with
    a structured log entry, not silently accepted.
  * **File-count cap**: ``MAX_SIBLING_FILES = 200`` per scan
    (v15, 2026-05-19; was 50). Bounds pathological recursion + memory
    cost while keeping pace with Phase D's
    ``code_graph.MAX_FILES_PER_GRAPH``. The 50 cap dropped
    transitively-required modules on real-world npm SDKs (Shopify,
    NestJS, Saleor, …) — the behavioral probe then aborted with
    "Cannot find module" before enumerating a single callable, killing
    Phase B+ + Phase 3 yield on the entire Cat-1 class of targets.
  * **Per-file size cap**: ``MAX_SIBLING_BYTES = 512 * 1024`` (512 KB).
    Files larger than this are dropped (real source files are
    typically <50 KB; >512 KB is almost certainly a vendored bundle
    we don't want to ship).
  * **Recursion depth cap**: ``MAX_RECURSION_DEPTH = 8`` (v15; was 5).
    Transitive sibling walks stop at this depth. Bumped because
    modern TS SDKs hit a deeper graph than the original 5-depth cap
    accommodated (e.g., shopify-api routes from ``rest/base.ts`` →
    ``runtime/index.ts`` → ``runtime/crypto.ts`` → … at depth 6+).
  * **Symlink rejection**: only regular files are accepted. Symlinks
    are dropped (host-filesystem leak vector).

The walker is BFS so the closest-to-entry files always get priority
when the cap is hit.
"""

from __future__ import annotations

import ast
import logging
from collections import deque
from pathlib import Path

from preprocessing.js_imports import (
    _RE_EXPORT_FROM,
    _RE_IMPORT_BARE,
    _RE_IMPORT_DYNAMIC,
    _RE_IMPORT_FROM,
    _RE_REQUIRE,
    _is_relative,
    _strip_comments,
)

log = logging.getLogger("argus.preprocessing.sibling_files")


# ── Tunables ──────────────────────────────────────────────────────────────


#: Maximum number of sibling files we'll stage per scan. Bounds attack
#: surface (no runaway recursion into a giant repo) and memory cost
#: (every sibling rides as bytes in the SandboxPlan). v15 (2026-05-19)
#: bumped 50 → 200 to keep pace with Phase D's MAX_FILES_PER_GRAPH and
#: stop dropping transitive deps on real-world npm SDK targets where
#: the behavioral probe was aborting with "Cannot find module" before
#: any callable could be enumerated. 200 × 512 KB = 100 MB worst-case
#: per scan, but the practical case stays under a few MB.
MAX_SIBLING_FILES: int = 200

#: Per-file size cap. Files larger than this are dropped silently.
#: Real source files are typically <50 KB; >512 KB is almost certainly
#: a vendored bundle (.min.js, generated.ts) that shouldn't ship.
MAX_SIBLING_BYTES: int = 512 * 1024

#: Recursion depth for the transitive walk. Stops at depth N. v15
#: (2026-05-19) bumped 5 → 8 because modern TS SDKs route through
#: deeper transitive graphs (shopify-api: rest/base.ts → runtime/
#: index.ts → runtime/crypto.ts → … hits depth 6+). Larger trees
#: that need depth > 8 likely indicate a project structure that
#: needs ``scan-repo`` from a higher root.
MAX_RECURSION_DEPTH: int = 8

#: TypeScript / JavaScript module-resolution extension precedence.
#: Mirrors Node + tsx behavior: try .ts first (most specific), then
#: .tsx, then .js / .mjs / .cjs. ``./foo`` with no extension on disk
#: tries each in turn.
_TS_EXTENSIONS: tuple[str, ...] = (".ts", ".tsx", ".js", ".mjs", ".cjs")

#: JavaScript module-resolution extension precedence (no .ts/.tsx —
#: a .js file's relative import shouldn't pull in TS siblings; the
#: harness can't transpile them without ``import.ts`` being explicit).
_JS_EXTENSIONS: tuple[str, ...] = (".js", ".mjs", ".cjs")

#: Index-file fallbacks tried when a relative import resolves to a
#: directory (e.g., ``./utils`` matches ``./utils/index.ts``).
_TS_INDEX_FILES: tuple[str, ...] = tuple(f"index{ext}" for ext in _TS_EXTENSIONS)
_JS_INDEX_FILES: tuple[str, ...] = tuple(f"index{ext}" for ext in _JS_EXTENSIONS)


# ── Project-root detection ─────────────────────────────────────────────────


def _detect_python_namespace_package(project_root: Path) -> str | None:
    """Detect whether the project declares a Python namespace package
    whose import path doesn't match the on-disk tarball layout.

    Sdists for namespace packages (e.g. ``ruamel.yaml``,
    ``ruamel.yaml.clib``, ``zope.interface``, ``backports.zoneinfo``)
    ship a FLAT directory: ``ruamel.yaml-0.19.1/loader.py`` instead of
    ``ruamel.yaml-0.19.1/ruamel/yaml/loader.py``. The sources still
    use ABSOLUTE imports like ``from ruamel.yaml.reader import Reader``
    because Python's import system resolves those against the
    installed package layout. When we stage the sdist flat under
    /workspace, those absolute imports break with
    ``ModuleNotFoundError: No module named 'ruamel'`` and Phase B+ /
    Phase A both fail before the L1 findings can be validated.

    Detection order:
      1. ``PKG-INFO`` ``Name:`` line — most reliable for sdists.
      2. ``pyproject.toml`` ``[project] name``.
      3. ``setup.cfg`` ``[metadata] name``.

    Returns:
        The dotted package name (e.g. ``"ruamel.yaml"``) when:
          * The declared name contains a ``.`` (namespace indicator), AND
          * The corresponding directory layout (``ruamel/yaml/``)
            does NOT already exist at the project root (which would
            mean the tarball IS structured correctly and no staging
            adjustment is needed).
        ``None`` for traditional flat-named packages
        (``jsonpickle``, ``markdown_it``, ``jinja2`` — all of which
        already ship their code under ``<name>/`` subdirs).

    Conservative: if the detected name is invalid as a Python import
    path (hyphens, digit-leading segments), returns None to avoid
    creating a broken staging layout.
    """
    declared: str | None = None

    # 1. PKG-INFO (RFC822-ish format, present in every sdist).
    pkg_info = project_root / "PKG-INFO"
    if pkg_info.is_file():
        try:
            for line in pkg_info.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()[:50]:  # name is always near the top
                if line.startswith("Name:"):
                    declared = line[len("Name:"):].strip()
                    break
        except OSError:
            pass

    # 2. pyproject.toml [project] name.
    if not declared:
        py_proj = project_root / "pyproject.toml"
        if py_proj.is_file():
            try:
                import tomllib  # noqa: PLC0415
                with open(py_proj, "rb") as fh:
                    data = tomllib.load(fh)
                declared = (data.get("project") or {}).get("name") or None
            except Exception:  # noqa: BLE001
                declared = None

    # 3. setup.cfg [metadata] name.
    if not declared:
        setup_cfg = project_root / "setup.cfg"
        if setup_cfg.is_file():
            try:
                import configparser  # noqa: PLC0415
                cp = configparser.ConfigParser()
                cp.read(setup_cfg, encoding="utf-8")
                declared = cp.get("metadata", "name", fallback=None)
            except Exception:  # noqa: BLE001
                declared = None

    if not declared:
        return None

    declared = declared.strip()
    if "." not in declared:
        # Traditional flat-name package — ships under <name>/ subdir,
        # no namespace adjustment needed. (We also catch the hyphenated
        # dist-name vs underscored import-name mismatch here: e.g.
        # ``markdown-it-py`` ships under ``markdown_it/``.)
        return None

    # Validate every segment is a Python identifier — paranoia against
    # creating a layout we can't actually import.
    segments = declared.split(".")
    for seg in segments:
        if not seg or seg[0].isdigit():
            return None
        if not all(ch.isalnum() or ch == "_" for ch in seg):
            return None

    # Final sanity: if the tarball ALREADY has the namespace dir
    # (e.g. ``project_root/ruamel/yaml/`` exists), the source layout
    # already matches and we should NOT prepend it again — that would
    # produce a doubly-nested staging tree.
    expected_dir = project_root
    for seg in segments:
        expected_dir = expected_dir / seg
    if expected_dir.is_dir():
        return None  # already correctly structured

    return declared


def _find_project_root(entry_file_path: Path) -> Path:
    """Walk up from the entry file looking for project-root markers.

    Returns the first directory containing any of
    :data:`_PROJECT_ROOT_MARKERS` (``tsconfig.json``, ``package.json``,
    ``pyproject.toml``, ``setup.py``, ``go.mod``, ``Cargo.toml``,
    ``.git``, etc.). Falls back to the entry file's immediate parent
    directory when no marker is found within
    :data:`_MAX_PROJECT_ROOT_WALK_DEPTH` levels.

    Why the fallback isn't entry_dir.parent: a standalone file
    scanned outside any project tree should NOT have its sibling
    boundary widened. Falling back to entry_dir preserves the v11
    single-file behavior — same as if no marker exists, the staging
    radius stays narrow.

    Walks up at most :data:`_MAX_PROJECT_ROOT_WALK_DEPTH` levels.
    This caps the search so a pathological deep nesting can't cause
    a slow scan; in practice, real projects' markers are within
    2-5 levels of any file.
    """
    cur = entry_file_path.parent
    for _ in range(_MAX_PROJECT_ROOT_WALK_DEPTH):
        for marker in _PROJECT_ROOT_MARKERS:
            try:
                if (cur / marker).exists():
                    return cur
            except OSError:
                # Permission denied / unreachable mount — give up
                # walking further; fall back to entry_dir.
                return entry_file_path.parent
        parent = cur.parent
        if parent == cur:
            # Filesystem root reached; no marker found.
            break
        cur = parent
    # No marker found — fall back to entry's immediate dir (v11
    # behavior). Narrow boundary, no parent-dir staging.
    return entry_file_path.parent


# ── Path-resolution helpers ────────────────────────────────────────────────


#: TS-to-source extension rewrite map. Modern TS code under ESM
#: convention writes ``import './foo.js'`` even when the source file
#: is ``foo.ts`` — the .js suffix matches what the COMPILED output
#: would be. tsx (and Node's --experimental-specifier-resolution=node)
#: handle this transparently at runtime; the resolver needs the same
#: trick to find the on-disk source. See e.g. mcp-server-filesystem's
#: ``import './path-utils.js'`` resolving to ``path-utils.ts``.
_TS_REWRITE_MAP: dict[str, tuple[str, ...]] = {
    ".js": (".ts", ".tsx", ".js"),
    ".mjs": (".mts", ".mjs"),
    ".cjs": (".cts", ".cjs"),
    ".jsx": (".tsx", ".jsx"),
}

#: Project-root marker files. The resolver walks UP from the entry
#: file looking for any of these; the first directory containing one
#: is treated as the project root + the staging boundary for sibling
#: file resolution. Real-world TS/JS/Python projects all leave at
#: least one of these at their root.
#:
#: Why this matters: LangChain.js and similar monorepos use
#: ``../sibling`` parent-directory imports that escape the entry
#: file's immediate dir. v11's pre-project-root behavior rejected
#: these via the path-traversal defense (preventing
#: ``../../../etc/passwd`` exploits in import strings). v12 widens
#: the boundary to the project root: parent-dir imports that stay
#: WITHIN the project root are accepted; ones that escape are still
#: rejected.
_PROJECT_ROOT_MARKERS: tuple[str, ...] = (
    # JS / TS — most common
    "tsconfig.json",
    "package.json",
    # Python
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "poetry.lock",
    # Other languages we don't fully support yet but might in future
    "go.mod",
    "Cargo.toml",
    "build.gradle",
    "pom.xml",
    # Fallback — every git repo has this at its root
    ".git",
)

#: Maximum number of parent directories to walk when looking for a
#: project-root marker. Bounds the search if no marker is found
#: (e.g., scanning a single file outside any project tree).
_MAX_PROJECT_ROOT_WALK_DEPTH: int = 12


def _resolve_ts_js_import(
    *,
    import_str: str,
    importing_file_path: Path,
    extensions: tuple[str, ...],
    index_files: tuple[str, ...],
    allow_ts_rewrite: bool = True,
) -> Path | None:
    """Resolve a JS/TS relative import to an absolute host path.

    Mirrors Node + tsx module-resolution order:
      1. ``./foo.ts``         — exact match (extension already in import)
      2. ``./foo.js`` → ``./foo.ts`` — TS ESM-convention rewrite (when
         ``allow_ts_rewrite`` is True). Required for modern TS where
         imports are written with the .js suffix that the COMPILED
         output would have, even though the source is .ts. The
         runtime side of this rewrite lives in the harness runner cmd
         (writes /workspace/tsconfig.json with
         ``moduleResolution: bundler``); the resolver side just makes
         sure we FIND the .ts file on disk so we can stage it.
      3. ``./foo`` + ``.ts``  — append extension (.ts, .tsx, .js, etc.)
      4. ``./foo/index.ts``   — directory + index file

    Returns ``None`` when nothing resolves. The resolver returns a
    single Path because we stage at the disk-relative name; the
    tsconfig.json the harness writes tells tsx to do the .js → .ts
    rewrite at runtime (standard TS-ecosystem pattern; used by
    Vite/Next/Astro/tsx).
    """
    base_dir = importing_file_path.parent

    # TS ESM-convention rewrite (TS-mode only): when the import has a
    # ``.js``/``.mjs``/``.cjs``/``.jsx`` suffix, try the corresponding
    # source extension FIRST (.ts/.mts/.cts/.tsx). This must come
    # before the literal-match branch so a stray compiled .js sitting
    # next to a fresh .ts source doesn't shadow the real source. tsx
    # (configured with moduleResolution=bundler) has the same
    # precedence: source wins over compiled output.
    if allow_ts_rewrite:
        import_suffix = Path(import_str).suffix
        if import_suffix in _TS_REWRITE_MAP:
            stem = import_str[: -len(import_suffix)]
            for alt_ext in _TS_REWRITE_MAP[import_suffix]:
                c = (base_dir / (stem + alt_ext)).resolve()
                if c.is_file():
                    return c

    # If import_str already has an extension we recognise, try as-is.
    candidate = (base_dir / import_str).resolve()
    if candidate.is_file() and candidate.suffix in extensions:
        return candidate

    # Try appending each extension.
    for ext in extensions:
        c = (base_dir / (import_str + ext)).resolve()
        if c.is_file():
            return c

    # Try directory + index file.
    if candidate.is_dir():
        for index_name in index_files:
            c = (candidate / index_name).resolve()
            if c.is_file():
                return c

    return None


def _resolve_python_import(
    *,
    module_path: str,
    level: int,
    importing_file_path: Path,
    imported_names: tuple[str, ...] = (),
) -> list[Path]:
    """Resolve a Python relative import to absolute host paths.

    Python relative imports take a ``level`` (number of leading dots)
    and an optional ``module`` name:
      * ``from . import x``         → level=1, module=None  → siblings of importing_file
      * ``from .foo import x``      → level=1, module="foo" → ./foo.py or ./foo/__init__.py
      * ``from ..pkg.foo import x`` → level=2, module="pkg.foo" → ../pkg/foo.py
      * ``from ..pkg import x``     → level=2, module="pkg" → ../pkg.py or ../pkg/__init__.py

    Returns a list of candidate paths — may be 0, 1, or 2 (the .py file
    AND its sibling __init__.py if the import names a subpackage too).
    """
    if level < 1:
        # Absolute import (level=0). Not a sibling, not our concern.
        return []

    # Walk up ``level - 1`` directories from importing_file_path.parent.
    # level=1 → same dir; level=2 → parent; level=3 → grandparent; etc.
    base = importing_file_path.parent
    for _ in range(level - 1):
        base = base.parent

    resolved: list[Path] = []
    if module_path:
        # Translate dotted module path to a filesystem path.
        sub_parts = module_path.split(".")
        target_dir_or_file = base
        for part in sub_parts:
            target_dir_or_file = target_dir_or_file / part
        # ``foo.py`` form
        f = (target_dir_or_file.with_suffix(".py")).resolve()
        if f.is_file():
            resolved.append(f)
        # ``foo/__init__.py`` form
        init = (target_dir_or_file / "__init__.py").resolve()
        if init.is_file():
            resolved.append(init)
        # ``from .foo import x, y, z`` — also resolve sibling modules
        # exposed by foo (foo/x.py, foo/y.py, foo/z.py) so a package
        # that re-exports submodules from its __init__ doesn't miss
        # the actual implementation files.
        for name in imported_names:
            cand = (target_dir_or_file / f"{name}.py").resolve()
            if cand.is_file() and cand not in resolved:
                resolved.append(cand)
            cand_init = (target_dir_or_file / name / "__init__.py").resolve()
            if cand_init.is_file() and cand_init not in resolved:
                resolved.append(cand_init)
    else:
        # ``from . import x, y, z`` — stage __init__.py AND each
        # explicitly-named sibling. Before v1.9.2 we only staged
        # __init__.py, which silently dropped util.py/errors.py/tags.py
        # for any file using the common ``from . import a, b, c``
        # pattern. Result: ``ImportError: cannot import name 'util'``
        # at sandbox runtime even though the resolver reported success.
        init = (base / "__init__.py").resolve()
        if init.is_file():
            resolved.append(init)
        for name in imported_names:
            # Each imported name can be either a submodule (foo.py)
            # or a subpackage (foo/__init__.py). Try both.
            cand = (base / f"{name}.py").resolve()
            if cand.is_file() and cand not in resolved:
                resolved.append(cand)
            cand_init = (base / name / "__init__.py").resolve()
            if cand_init.is_file() and cand_init not in resolved:
                resolved.append(cand_init)

    return resolved


# ── Source-side extraction ─────────────────────────────────────────────────


def _extract_ts_js_relative_imports(source: str) -> set[str]:
    """Return the set of RELATIVE import strings from JS/TS source.

    The inverse of ``js_imports.extract_js_imports`` — that one drops
    relative imports (they're not npm packages); we KEEP only them
    (they're sibling files we need to stage).

    Handles ``require()``, ``import ... from``, ``import 'X'``, and
    dynamic ``import('X')`` forms via the same regex set
    ``js_imports`` uses, so behavior stays in sync if those patterns
    evolve.
    """
    if not source:
        return set()
    try:
        cleaned = _strip_comments(source)
    except Exception:  # noqa: BLE001
        return set()

    names: set[str] = set()
    for pattern in (
        _RE_REQUIRE,
        _RE_IMPORT_FROM,
        _RE_IMPORT_BARE,
        _RE_IMPORT_DYNAMIC,
        # v15 (2026-05-19): catch barrel files' `export * from './x'`
        # and `export { Y } from './z'` re-exports. Previously dropped,
        # which made the resolver miss every transitive dep behind a
        # re-export hub (e.g. shopify-api's runtime/index.ts re-exports
        # http/crypto/platform — without this, none of those land in
        # the sibling tarball and behavioral probe aborts at import).
        _RE_EXPORT_FROM,
    ):
        for match in pattern.finditer(cleaned):
            raw = match.group(2)
            if _is_relative(raw):
                names.add(raw)
    return names


def _extract_python_absolute_namespace_imports(
    source: str,
    namespace_pkg: str,
) -> list[tuple[str, tuple[str, ...]]]:
    """Return absolute imports that target the project's own
    namespace package.

    For a project declaring itself as namespace ``ruamel.yaml``, this
    catches:

      * ``from ruamel.yaml.reader import Reader``      → (``"reader"``,    ("Reader",))
      * ``from ruamel.yaml import scanner``            → (``""``,          ("scanner",))
      * ``from ruamel.yaml.constructor import (A, B)`` → (``"constructor"``, ("A", "B"))
      * ``import ruamel.yaml.X``                        → (``"X"``,         ())
      * ``import ruamel.yaml.X.Y``                      → (``"X.Y"``,       ())

    The first element of the tuple is the SUBPATH inside the namespace
    package (i.e. what comes after the ``namespace_pkg.`` prefix). The
    second element is the imported names, parallel to
    :func:`_extract_python_relative_imports`.

    Treating these as project-root-relative siblings is what makes
    self-import-from-flat-tarball patterns
    (``ruamel.yaml-0.19.1/loader.py`` referring to
    ``ruamel.yaml.reader``) resolvable. Without this, the relative-
    import resolver misses every absolute self-import and Phase B+ /
    Phase A both fail at import time with ``ModuleNotFoundError``.

    Returns ``[]`` for parse failures or for files that don't import
    the namespace.
    """
    if not source or not namespace_pkg:
        return []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    results: list[tuple[str, tuple[str, ...]]] = []
    ns_prefix = namespace_pkg + "."
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.level or 0) == 0:
            mod = node.module or ""
            if mod == namespace_pkg:
                # ``from ruamel.yaml import scanner, parser``
                names = tuple(
                    a.name for a in (node.names or [])
                    if a.name and a.name != "*"
                )
                results.append(("", names))
            elif mod.startswith(ns_prefix):
                sub = mod[len(ns_prefix):]  # "reader" / "constructor"
                names = tuple(
                    a.name for a in (node.names or [])
                    if a.name and a.name != "*"
                )
                results.append((sub, names))
        elif isinstance(node, ast.Import):
            for alias in node.names or []:
                fq = alias.name or ""
                if fq == namespace_pkg:
                    results.append(("", ()))
                elif fq.startswith(ns_prefix):
                    sub = fq[len(ns_prefix):]
                    results.append((sub, ()))
    return results


def _resolve_namespace_subpath(
    *,
    subpath: str,
    project_root: Path,
    imported_names: tuple[str, ...] = (),
) -> list[Path]:
    """Resolve a dotted SUBPATH inside the project's namespace
    package to host file paths.

    ``subpath`` is what comes after the namespace prefix (e.g. for
    ``from ruamel.yaml.reader import Reader``, subpath is ``"reader"``).
    Returns up to 1 + len(imported_names) paths:

      * The subpath itself (``project_root/reader.py`` or
        ``project_root/reader/__init__.py``).
      * For ``from ruamel.yaml import scanner, parser`` (subpath=""),
        each imported name resolves to ``project_root/<name>.py`` or
        ``project_root/<name>/__init__.py`` — same logic as the
        relative-import ``from . import a, b, c`` pattern.
    """
    resolved: list[Path] = []

    def _add_candidates_for(rel_dotted: str) -> None:
        if not rel_dotted:
            return
        parts = rel_dotted.split(".")
        target = project_root
        for part in parts:
            target = target / part
        f = target.with_suffix(".py").resolve()
        if f.is_file() and f not in resolved:
            resolved.append(f)
        init = (target / "__init__.py").resolve()
        if init.is_file() and init not in resolved:
            resolved.append(init)

    if subpath:
        _add_candidates_for(subpath)
        # Also walk per-name: subpath might be a SUBPACKAGE and the
        # imported names are submodules of it.
        for name in imported_names:
            _add_candidates_for(f"{subpath}.{name}")
    else:
        # ``from <namespace> import a, b, c`` — each name is a
        # sibling submodule at project_root level.
        for name in imported_names:
            _add_candidates_for(name)

    return resolved


def _extract_python_relative_imports(
    source: str,
) -> list[tuple[str, int, tuple[str, ...]]]:
    """Return ``[(module_path, level, names), ...]`` for each relative import.

    Uses Python's AST so we get exact ``level`` semantics (number of
    leading dots) without regex hazards.

    Returned tuples capture both the import target AND the imported
    names so the resolver can walk every imported sibling, not just
    the package ``__init__.py``:

      * ``from . import x``           → ``("", 1, ("x",))``
      * ``from . import x, y, z``     → ``("", 1, ("x", "y", "z"))``
      * ``from .foo import y``        → ``("foo", 1, ("y",))``
      * ``from ..pkg.foo import z``   → ``("pkg.foo", 2, ("z",))``
      * ``from .foo import *``        → ``("foo", 1, ())`` (star import; names empty)

    Returns ``[]`` on any parse failure — malformed source must not
    crash preprocessing.
    """
    if not source:
        return []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    results: list[tuple[str, int, tuple[str, ...]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level and node.level >= 1:
            # node.names is list[alias]; alias.name="*" for `from x import *`.
            names = tuple(
                alias.name for alias in (node.names or [])
                if alias.name and alias.name != "*"
            )
            results.append((node.module or "", node.level, names))
    return results


# ── Safety checks ──────────────────────────────────────────────────────────


def _is_safe_sibling_path(
    *,
    candidate: Path,
    project_root: Path,
) -> bool:
    """True iff ``candidate`` is inside ``project_root``, is a regular
    file (not a symlink), and is under the size cap.

    Path-traversal defense: rejects any resolved path that escapes
    the detected project root (e.g., ``../../../etc/passwd`` baked
    into an import string). v11 used the entry file's immediate dir
    as the boundary; v12 widens it to project_root so legitimate
    parent-directory imports under the same project work (e.g.,
    ``import "../chains/llm_chain.js"`` in LangChain.js's tools/),
    while still blocking escapes ABOVE the project root.
    """
    try:
        # Reject symlinks explicitly — even if they resolve under
        # project_root, they might point outside.
        if candidate.is_symlink():
            log.warning("Rejecting symlink sibling: %s", candidate)
            return False
        if not candidate.is_file():
            return False
        # is_relative_to was added in Python 3.9; the project pins 3.12+.
        if not candidate.is_relative_to(project_root):
            log.warning(
                "Rejecting sibling outside project root: %s (project_root=%s)",
                candidate,
                project_root,
            )
            return False
        size = candidate.stat().st_size
        if size > MAX_SIBLING_BYTES:
            log.warning(
                "Rejecting oversized sibling (%d > %d bytes): %s",
                size,
                MAX_SIBLING_BYTES,
                candidate,
            )
            return False
        return True
    except OSError as exc:
        log.warning("OSError stat'ing sibling %s: %s", candidate, exc)
        return False


# ── Public entry point ─────────────────────────────────────────────────────


def resolve_sibling_files(
    *,
    entry_file_path: Path | str,
    entry_file_bytes: bytes,
    language: str,
    max_files: int = MAX_SIBLING_FILES,
    max_depth: int = MAX_RECURSION_DEPTH,
    skip_own_dist_when_installable: bool = True,
) -> dict[str, bytes]:
    """Resolve transitively-referenced sibling files for a multi-file
    project entry point.

    Args:
        entry_file_path: Absolute or resolvable host path to the entry
            file. Used to determine the project root for relative
            imports and as the path-traversal boundary.
        entry_file_bytes: Raw bytes of the entry file. The entry's
            imports drive the BFS walk.
        language: ``"python"`` | ``"javascript"`` | ``"typescript"``.
            Drives which extractor + extension-precedence is used.
            Other values (``"shell"``, ``None``) return ``{}``.
        max_files: Cap on returned dict size. BFS order — closest
            siblings win.
        max_depth: Cap on transitive recursion depth.

    Returns:
        ``{rel_path_from_project_root: bytes}`` — keyed by path RELATIVE
        to the detected project root (v12) instead of entry_dir (v11).
        This lets the sandbox stage files at ``/workspace/<rel_path>``
        preserving the project layout, so the entry file's
        ``import "../chains/foo.js"`` style imports resolve correctly
        at runtime.

        DOES include the entry file's rel-from-root path (caller can
        identify it via :func:`compute_entry_rel_path` for sandbox
        staging). Empty dict when nothing resolves or when the language
        is unsupported.

    Boundary behavior:
        * v12 detects the project root via marker files (tsconfig.json,
          package.json, pyproject.toml, .git/, etc.) walking up from
          the entry file.
        * When no marker is found, project root falls back to entry's
          immediate parent dir — same as v11 single-file behavior.
        * Resolved siblings must be UNDER the project root; escapes
          above it are rejected (same security stance as v11, just
          with a wider boundary).
    """
    if language not in ("python", "javascript", "typescript"):
        return {}

    try:
        entry_path = Path(entry_file_path).resolve()
    except (OSError, RuntimeError) as exc:
        log.warning("Could not resolve entry path %s: %s", entry_file_path, exc)
        return {}

    project_root = _find_project_root(entry_path)

    # v15.16 (2026-05-20): for Python projects with an installable
    # own_dist (PKG-INFO / pyproject.toml present), cap siblings far
    # more aggressively. Rationale: the orchestrator separately
    # pip-installs the own_dist (v15.4 / v15.10), so the harness's
    # ``import <pkg>.<module>`` resolves via site-packages with full
    # transitive deps. Shipping every staged sibling on top of that
    # is double-cost — and on large packages (anthropic-sdk-python
    # has 900+ .py files), the sibling tarball overhead times out
    # the Firecracker VM before any harness can produce signal.
    # Anthropic SDK campaign observed 200 siblings (the cap) → BP=0
    # + Phase A all NOT_TESTED stub-no-trace on every Bedrock / AWS /
    # credentials file.
    #
    # Cap of 30 keeps the tarball small enough that VM setup stays
    # under a few seconds, while still covering the entry's direct
    # neighbors (same dir + one level up) — enough for the relative-
    # import resolution the sibling resolver was originally
    # designed for.
    if language == "python":
        from preprocessing.imports import (  # noqa: PLC0415
            _detect_distribution_name_for_install,
        )
        if _detect_distribution_name_for_install(str(project_root)):
            max_files = min(max_files, 30)

    # v15-namespace (2026-05-19): detect Python namespace-package
    # tarballs whose declared name has a `.` (e.g. ``ruamel.yaml``)
    # but ships its source flat at the tarball root.
    #
    # v15.1 (2026-05-20): when a namespace package is detected AND
    # ``skip_own_dist_when_installable`` is True, SKIP the namespace-
    # prefix staging entirely. The orchestrator separately pip-installs
    # the file's own distribution (via ``runtime_packages_for_plan`` +
    # ``_detect_distribution_name_for_install``), and the pip-installed
    # version lives in site-packages with a working __init__ chain
    # (including any C extensions). Without skipping, the file-staged
    # copy at /workspace/<ns>/ would shadow the pip-installed version
    # (Python's sys.path puts cwd at index 0) and we'd be back at the
    # original circular-__init__ bug. Caller opts out by setting the
    # flag to False (when pip install of the own dist is known to fail
    # — offline scans, deprecated packages, etc.).
    namespace_pkg: str | None = None
    namespace_dir_prefix = ""
    if language == "python":
        candidate = _detect_python_namespace_package(project_root)
        if candidate:
            if skip_own_dist_when_installable:
                # Pip install is the primary path for namespace packages;
                # don't stage a shadowing copy at /workspace.
                pass
            else:
                namespace_pkg = candidate
                namespace_dir_prefix = candidate.replace(".", "/")

    visited: set[Path] = set()
    queue: deque[tuple[Path, bytes, int]] = deque()
    queue.append((entry_path, entry_file_bytes, 0))
    visited.add(entry_path)

    staged: dict[str, bytes] = {}

    def _rel_key(host_path: Path) -> str:
        """Compute the in-sandbox key for a host file. Applies the
        namespace prefix when the project is a namespace package
        whose source ships flat at the tarball root."""
        rel = str(host_path.relative_to(project_root)).replace("\\", "/")
        if namespace_dir_prefix and "/" not in rel:
            # File is at the project root — wrap under the namespace.
            return f"{namespace_dir_prefix}/{rel}"
        return rel

    # v12 (2026-05-17): include the entry file ITSELF in the staged
    # dict under its rel-from-project-root key when it lives in a
    # subdir of the project root. dast-init.sh extracts the
    # additional_files tarball AS ROOT (before dropping to the
    # runner user), which means the subdir + file land at the right
    # path even though /workspace is root-owned. Without this, the
    # plan builders would have to mkdir + mv at runtime under the
    # runner user → ``mkdir: cannot create directory ...
    # Permission denied``. Caller still ships the entry via
    # FILE_CONTENT_B64GZ → /workspace/<basename> for back-compat
    # (single-file flow + entrypoint.py contract). Two on-disk
    # copies but plan builders use the rel-from-root path so tsx
    # resolves parent-dir imports against the staged sibling tree.
    try:
        entry_key = _rel_key(entry_path)
        # Stage the entry under its rel-from-root key when it lives in
        # a subdir (always true under the namespace-prefix path or when
        # already in a subdir). Skip the duplicate when entry is at
        # /workspace/<basename> AND no namespace adjustment applies.
        if "/" in entry_key:
            staged[entry_key] = entry_file_bytes
    except ValueError:
        # entry not under project_root — shouldn't happen because
        # _find_project_root falls back to entry.parent, but be safe.
        pass

    # v15.13 (2026-05-20): for JS/TS projects, also stage the root
    # package.json. Many npm packages do ``require('./package.json')``
    # at module load to read their own version metadata (homebridge-
    # syntex, electron-forge, lots of CLIs follow this pattern). When
    # the sibling resolver only walked .js/.mjs/.cjs imports, the
    # package.json wasn't staged and Node raised "Cannot find module
    # './package.json'" at harness import time, killing the entire
    # BP enumeration with a 0-callable result.
    #
    # Threat model: project_root/package.json is manifest-declared and
    # we got the project_root from a marker-file walk on the user's
    # local filesystem — it's not attacker-controlled.
    # Sandbox-contained either way. Same trust stance as the v15.10
    # own_dist install path on the Python side.
    if language in ("javascript", "typescript"):
        pkg_json_path = project_root / "package.json"
        try:
            if pkg_json_path.is_file():
                pkg_bytes = pkg_json_path.read_bytes()
                # Cap at 1MB — package.json should be tiny; if it's
                # larger, skip (could indicate something malicious like
                # a 100MB JSON bomb). Common real-world max ~ 20-50KB.
                if len(pkg_bytes) <= 1_048_576:
                    staged["package.json"] = pkg_bytes
        except (OSError, ValueError) as exc:
            log.info(
                "Could not stage package.json from project_root %s: %s",
                project_root,
                exc,
            )

    while queue:
        cur_path, cur_bytes, depth = queue.popleft()
        if depth >= max_depth:
            continue
        if len(staged) >= max_files:
            log.info("Sibling cap reached (%d files) — stopping walk", max_files)
            break

        try:
            source = cur_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Binary file — can't extract imports, skip.
            continue

        # Pull out relative imports + resolve to host paths.
        resolved: list[Path] = []
        if language in ("javascript", "typescript"):
            extensions = _TS_EXTENSIONS if language == "typescript" else _JS_EXTENSIONS
            index_files = _TS_INDEX_FILES if language == "typescript" else _JS_INDEX_FILES
            # TS-only: rewrite ``./foo.js`` imports to ``./foo.ts``
            # source files (modern ESM-convention TS pattern). Pure JS
            # projects shouldn't pull in TS siblings, so the rewrite
            # is gated to TypeScript-language scans.
            allow_ts_rewrite = language == "typescript"
            for imp in _extract_ts_js_relative_imports(source):
                r = _resolve_ts_js_import(
                    import_str=imp,
                    importing_file_path=cur_path,
                    extensions=extensions,
                    index_files=index_files,
                    allow_ts_rewrite=allow_ts_rewrite,
                )
                if r:
                    resolved.append(r)
        else:  # python
            for module_path, level, names in _extract_python_relative_imports(source):
                resolved.extend(
                    _resolve_python_import(
                        module_path=module_path,
                        level=level,
                        importing_file_path=cur_path,
                        imported_names=names,
                    )
                )
            # v15-namespace: also walk absolute imports that target
            # the project's own namespace package. Without this, a
            # flat-tarball namespace package (ruamel.yaml,
            # backports.zoneinfo, zope.interface, ...) leaves its
            # transitive deps unstaged and the in-sandbox import
            # graph breaks at the first absolute self-import.
            if namespace_pkg:
                for subpath, abs_names in _extract_python_absolute_namespace_imports(
                    source, namespace_pkg
                ):
                    resolved.extend(
                        _resolve_namespace_subpath(
                            subpath=subpath,
                            project_root=project_root,
                            imported_names=abs_names,
                        )
                    )

        for r in resolved:
            if r in visited:
                continue
            visited.add(r)
            if not _is_safe_sibling_path(candidate=r, project_root=project_root):
                continue
            try:
                rb = r.read_bytes()
            except OSError as exc:
                log.warning("Could not read sibling %s: %s", r, exc)
                continue
            # Key under the path RELATIVE TO PROJECT ROOT so the
            # sandbox stages it at /workspace/<rel_from_root> and the
            # entry file's parent-dir imports (``../chains/foo.js``)
            # resolve correctly at runtime when the harness runs
            # from /workspace/<entry-subdir-from-root>. For namespace
            # packages (v15), _rel_key prepends the namespace dir
            # prefix so flat-tarball siblings land at
            # /workspace/<ns>/<file> instead of /workspace/<file>.
            rel_path = _rel_key(r)
            staged[rel_path] = rb
            if len(staged) >= max_files:
                log.info("Sibling cap reached (%d files) — stopping enqueue", max_files)
                break
            queue.append((r, rb, depth + 1))

    return staged


def compute_entry_rel_path(entry_file_path: Path | str) -> str:
    """Return the entry file's path RELATIVE to its detected project
    root, in forward-slash form (safe for sandbox path use).

    Used by the runner + sandbox plumbing to stage the entry file at
    ``/workspace/<entry_rel_path>`` so the project layout is mirrored
    and the entry file's relative imports (including ``../sibling``
    parent-dir style) resolve correctly.

    Falls back to the bare basename when project-root detection fails
    or returns the entry's own directory — single-file behavior
    preserved.
    """
    try:
        entry_path = Path(entry_file_path).resolve()
    except (OSError, RuntimeError):
        return Path(str(entry_file_path)).name

    project_root = _find_project_root(entry_path)
    try:
        rel = str(entry_path.relative_to(project_root)).replace("\\", "/")
    except ValueError:
        # entry_path not under project_root (shouldn't happen because
        # _find_project_root falls back to entry.parent, but be safe).
        return entry_path.name

    # v15-namespace: if this is a flat-tarball namespace package
    # (ruamel.yaml-style), wrap the entry's basename under the
    # namespace-derived directory prefix. MODULE_NAME (computed
    # elsewhere from this rel_path) becomes ``ruamel.yaml.loader``
    # — the qualified import name the harness uses to load the
    # pip-installed copy of the package from site-packages.
    #
    # v15.1 (2026-05-20): the SIBLING STAGING is skipped for the
    # namespace's own files (see resolve_sibling_files'
    # skip_own_dist_when_installable path) so /workspace/ruamel/yaml/
    # doesn't shadow the pip-installed version. But we still PREFIX
    # the entry_rel_path so MODULE_NAME drives a qualified import
    # — ``import ruamel.yaml.loader`` then resolves cleanly to
    # site-packages where the real package lives with its working
    # __init__ chain + C extensions.
    if "/" not in rel:
        namespace_pkg = _detect_python_namespace_package(project_root)
        if namespace_pkg:
            ns_prefix = namespace_pkg.replace(".", "/")
            return f"{ns_prefix}/{rel}"
    return rel


__all__ = [
    "MAX_RECURSION_DEPTH",
    "MAX_SIBLING_BYTES",
    "MAX_SIBLING_FILES",
    "compute_entry_rel_path",
    "resolve_sibling_files",
]
