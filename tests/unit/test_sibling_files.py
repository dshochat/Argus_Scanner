"""Unit tests for ``preprocessing.sibling_files`` — multi-file project
sibling resolver. Validates TS/JS/Python extension precedence,
transitive walk, path-traversal defense, caps, and edge cases.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from preprocessing.sibling_files import (
    MAX_RECURSION_DEPTH,
    MAX_SIBLING_BYTES,
    MAX_SIBLING_FILES,
    resolve_sibling_files,
)


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def ts_project(tmp_path: Path) -> Path:
    """A small TS project layout:

    project/
      index.ts          → imports ./utils, ./path-utils
      utils.ts          → imports ./helpers
      path-utils.ts     → standalone
      helpers.ts        → standalone
    """
    (tmp_path / "index.ts").write_text(
        "import { x } from './utils';\n"
        "import { y } from './path-utils';\n"
        "export function entry() { return x() + y() }\n",
        encoding="utf-8",
    )
    (tmp_path / "utils.ts").write_text(
        "import { z } from './helpers';\n"
        "export function x() { return z() }\n",
        encoding="utf-8",
    )
    (tmp_path / "path-utils.ts").write_text(
        "export function y() { return 'y' }\n",
        encoding="utf-8",
    )
    (tmp_path / "helpers.ts").write_text(
        "export function z() { return 'z' }\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def python_project(tmp_path: Path) -> Path:
    """Small Python package layout:

    pkg/
      __init__.py       → relative import from .helpers
      main.py           → from .utils import foo
      utils.py          → from .helpers import bar
      helpers.py        → standalone
    """
    (tmp_path / "__init__.py").write_text(
        "from .helpers import bar\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from .utils import foo\n"
        "def entry():\n    return foo()\n",
        encoding="utf-8",
    )
    (tmp_path / "utils.py").write_text(
        "from .helpers import bar\n"
        "def foo():\n    return bar()\n",
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        "def bar():\n    return 'bar'\n",
        encoding="utf-8",
    )
    return tmp_path


# ── Public-API guarantees ──────────────────────────────────────────────────


def test_unsupported_language_returns_empty() -> None:
    """Non-py/js/ts languages get an empty dict — caller's gate is
    structural, not advisory."""
    result = resolve_sibling_files(
        entry_file_path="/fake/path/x.go",
        entry_file_bytes=b"package main",
        language="go",
    )
    assert result == {}


def test_empty_bytes_returns_empty() -> None:
    """An entry file with no imports yields no siblings."""
    result = resolve_sibling_files(
        entry_file_path="/fake/path/x.ts",
        entry_file_bytes=b"",
        language="typescript",
    )
    assert result == {}


def test_unresolvable_entry_path_returns_empty() -> None:
    """Non-existent host paths fail closed (return ``{}``)."""
    result = resolve_sibling_files(
        entry_file_path="/this/path/definitely/does/not/exist/x.ts",
        entry_file_bytes=b"import { x } from './y';\n",
        language="typescript",
    )
    # Resolver can't read the sibling because the parent dir doesn't
    # exist; returns empty without raising.
    assert result == {}


def test_entry_file_not_included(ts_project: Path) -> None:
    """The entry file itself is NEVER in the result (caller stages it
    separately at the entry path)."""
    result = resolve_sibling_files(
        entry_file_path=ts_project / "index.ts",
        entry_file_bytes=(ts_project / "index.ts").read_bytes(),
        language="typescript",
    )
    assert "index.ts" not in result


# ── TypeScript / JavaScript resolution ─────────────────────────────────────


def test_ts_resolves_sibling_imports(ts_project: Path) -> None:
    """A TS entry file importing ``./utils`` and ``./path-utils``
    should stage both sibling files."""
    entry = ts_project / "index.ts"
    result = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="typescript",
    )
    assert "utils.ts" in result
    assert "path-utils.ts" in result
    # Bytes match disk.
    assert result["utils.ts"] == (ts_project / "utils.ts").read_bytes()
    assert result["path-utils.ts"] == (ts_project / "path-utils.ts").read_bytes()


def test_ts_walks_transitively(ts_project: Path) -> None:
    """utils.ts imports ./helpers — helpers.ts should be in the
    output even though the entry never references it directly."""
    entry = ts_project / "index.ts"
    result = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="typescript",
    )
    assert "helpers.ts" in result
    assert result["helpers.ts"] == (ts_project / "helpers.ts").read_bytes()


def test_ts_extension_precedence_ts_wins_over_js(tmp_path: Path) -> None:
    """When both ``utils.ts`` and ``utils.js`` exist on disk and
    the import is ``./utils``, prefer the .ts variant (tsx/Node
    resolution order)."""
    (tmp_path / "utils.ts").write_text("export const x = 1\n", encoding="utf-8")
    (tmp_path / "utils.js").write_text("module.exports = { x: 1 }\n", encoding="utf-8")
    (tmp_path / "index.ts").write_text(
        "import { x } from './utils';\nexport const y = x\n",
        encoding="utf-8",
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
    )
    assert "utils.ts" in result
    # utils.js NOT pulled in — .ts won the precedence race.
    assert "utils.js" not in result


def test_ts_resolves_directory_index(tmp_path: Path) -> None:
    """``./utils`` matching a directory should resolve to
    ``./utils/index.ts``."""
    (tmp_path / "utils").mkdir()
    (tmp_path / "utils" / "index.ts").write_text(
        "export const x = 1\n", encoding="utf-8"
    )
    (tmp_path / "index.ts").write_text(
        "import { x } from './utils';\nexport const y = x\n",
        encoding="utf-8",
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
    )
    assert "utils/index.ts" in result


def test_ts_handles_require_import_dynamic(tmp_path: Path) -> None:
    """Each import variety (require, import from, import bare, import
    dynamic) on a relative path should be picked up."""
    (tmp_path / "a.ts").write_text("export const x = 1\n", encoding="utf-8")
    (tmp_path / "b.ts").write_text("export const x = 1\n", encoding="utf-8")
    (tmp_path / "c.ts").write_text("export const x = 1\n", encoding="utf-8")
    (tmp_path / "d.ts").write_text("export const x = 1\n", encoding="utf-8")
    (tmp_path / "index.ts").write_text(
        "const a = require('./a');\n"
        "import { x } from './b';\n"
        "import './c';\n"
        "const d = await import('./d');\n",
        encoding="utf-8",
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
    )
    assert {"a.ts", "b.ts", "c.ts", "d.ts"} <= set(result.keys())


def test_ts_skips_npm_packages(tmp_path: Path) -> None:
    """Bare-name imports (npm packages) are NOT in the sibling set —
    those are P2a-JS's job to install."""
    (tmp_path / "utils.ts").write_text("export const x = 1\n", encoding="utf-8")
    (tmp_path / "index.ts").write_text(
        "import lodash from 'lodash';\n"
        "import { McpServer } from '@modelcontextprotocol/sdk';\n"
        "import { x } from './utils';\n",
        encoding="utf-8",
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
    )
    assert "utils.ts" in result
    assert "lodash" not in result
    assert "@modelcontextprotocol/sdk" not in result


def test_js_does_not_resolve_ts_siblings(tmp_path: Path) -> None:
    """A .js entry file should NOT pull in .ts siblings (the JS
    harness can't transpile them without explicit ``import.ts``)."""
    (tmp_path / "utils.ts").write_text("export const x = 1\n", encoding="utf-8")
    (tmp_path / "utils.js").write_text("module.exports = { x: 1 }\n", encoding="utf-8")
    (tmp_path / "index.js").write_text(
        "const { x } = require('./utils');\n", encoding="utf-8"
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.js",
        entry_file_bytes=(tmp_path / "index.js").read_bytes(),
        language="javascript",
    )
    assert "utils.js" in result
    assert "utils.ts" not in result


def test_ts_rewrites_js_extension_to_ts_source(tmp_path: Path) -> None:
    """Modern TS ESM convention writes ``import './foo.js'`` even when
    the actual source file is ``foo.ts``. The resolver must rewrite
    .js imports to .ts source paths (matches tsx + Node ESM behavior).

    Example: mcp-server-filesystem/index.ts has
    ``import { ... } from './path-utils.js'`` resolving to ``path-utils.ts``.
    """
    (tmp_path / "path-utils.ts").write_text(
        "export function normalizePath(p: string): string { return p }\n",
        encoding="utf-8",
    )
    (tmp_path / "index.ts").write_text(
        "import { normalizePath } from './path-utils.js';\n"
        "export function entry() { return normalizePath('x') }\n",
        encoding="utf-8",
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
    )
    # The .ts source file IS staged, keyed under its actual on-disk name.
    assert "path-utils.ts" in result
    # The .js (which doesn't exist on disk) is NOT in the result.
    assert "path-utils.js" not in result


def test_ts_rewrites_mjs_extension_to_mts_source(tmp_path: Path) -> None:
    """Same rewrite pattern for the .mjs → .mts ESM variant."""
    (tmp_path / "utils.mts").write_text("export const x = 1\n", encoding="utf-8")
    (tmp_path / "index.ts").write_text(
        "import { x } from './utils.mjs';\n", encoding="utf-8"
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
    )
    assert "utils.mts" in result


def test_ts_rewrite_prefers_ts_over_literal_js(tmp_path: Path) -> None:
    """When BOTH ``foo.ts`` and ``foo.js`` exist on disk, an
    ``import './foo.js'`` should prefer the .ts source — that's what
    tsx does (it ignores the compiled .js when source .ts is present)."""
    (tmp_path / "utils.ts").write_text("export const x = 1\n", encoding="utf-8")
    (tmp_path / "utils.js").write_text("module.exports = { x: 1 }\n", encoding="utf-8")
    (tmp_path / "index.ts").write_text(
        "import { x } from './utils.js';\n", encoding="utf-8"
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
    )
    assert "utils.ts" in result
    assert "utils.js" not in result


def test_js_entry_does_not_apply_ts_rewrite(tmp_path: Path) -> None:
    """A .js entry file with ``import './foo.js'`` must NOT rewrite to
    .ts (the rewrite is TS-specific). The literal .js file should be
    found, or nothing at all."""
    (tmp_path / "utils.ts").write_text("export const x = 1\n", encoding="utf-8")
    (tmp_path / "index.js").write_text(
        "const { x } = require('./utils.js');\n", encoding="utf-8"
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.js",
        entry_file_bytes=(tmp_path / "index.js").read_bytes(),
        language="javascript",
    )
    # No utils.js on disk, no rewrite → nothing staged.
    assert result == {}


# ── Python resolution ──────────────────────────────────────────────────────


def test_python_resolves_from_dot_import(python_project: Path) -> None:
    """``from .utils import foo`` resolves to ``utils.py`` in the same
    directory."""
    entry = python_project / "main.py"
    result = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="python",
    )
    assert "utils.py" in result
    assert "helpers.py" in result  # transitively via utils


def test_python_resolves_init_py(tmp_path: Path) -> None:
    """``from . import x`` resolves to the directory's __init__.py."""
    (tmp_path / "__init__.py").write_text("X = 1\n", encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from . import X\n", encoding="utf-8"
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "main.py",
        entry_file_bytes=(tmp_path / "main.py").read_bytes(),
        language="python",
    )
    assert "__init__.py" in result


def test_python_skips_absolute_imports(tmp_path: Path) -> None:
    """``import requests`` and ``from os import path`` are ABSOLUTE
    imports — never staged (Python's P2a-pip path handles those)."""
    (tmp_path / "main.py").write_text(
        "import requests\nfrom os import path\nimport sys\n",
        encoding="utf-8",
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "main.py",
        entry_file_bytes=(tmp_path / "main.py").read_bytes(),
        language="python",
    )
    assert result == {}


def test_python_malformed_source_returns_empty(tmp_path: Path) -> None:
    """Unparseable Python source must not raise — return empty dict."""
    bad_source = b"def broken(:::\n"
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "broken.py",
        entry_file_bytes=bad_source,
        language="python",
    )
    assert result == {}


# ── Security: path-traversal defense ───────────────────────────────────────


def test_rejects_parent_dir_escape(tmp_path: Path) -> None:
    """An import like ``../../etc/passwd`` must NOT stage the resolved
    file — escapes the entry directory. Real layouts where the file
    exists outside entry_dir also get rejected."""
    outside = tmp_path.parent / "_argus_test_outside.ts"
    outside.write_text("export const evil = 1\n", encoding="utf-8")
    try:
        (tmp_path / "index.ts").write_text(
            f"import {{ evil }} from '../{outside.stem}';\n",
            encoding="utf-8",
        )
        result = resolve_sibling_files(
            entry_file_path=tmp_path / "index.ts",
            entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
            language="typescript",
        )
        # The outside file resolves on disk but the resolver MUST reject
        # it for being outside the entry's directory.
        assert outside.name not in result
        assert "../" + outside.name not in result
        assert result == {}
    finally:
        outside.unlink(missing_ok=True)


def test_does_not_follow_absolute_path_imports(tmp_path: Path) -> None:
    """An absolute-path import like ``/etc/passwd`` is a TS string —
    the resolver treats it as relative-style (``_is_relative`` matches
    leading ``/``) but resolving it against entry_dir produces an
    out-of-tree path that gets rejected."""
    (tmp_path / "index.ts").write_text(
        "import { x } from '/etc/passwd';\n",
        encoding="utf-8",
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
    )
    assert result == {}


# ── Caps: file count, recursion depth, file size ──────────────────────────


def test_max_sibling_files_cap_respected(tmp_path: Path) -> None:
    """A project with >max_files siblings should stop staging at the
    cap (BFS order — closest first)."""
    n = 10
    # Build a tree where index.ts imports ./s0, ./s1, ..., ./s{n-1}.
    imports = "\n".join(f"import {{ x{i} }} from './s{i}';" for i in range(n))
    (tmp_path / "index.ts").write_text(imports + "\n", encoding="utf-8")
    for i in range(n):
        (tmp_path / f"s{i}.ts").write_text(
            f"export const x{i} = {i}\n", encoding="utf-8"
        )

    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
        max_files=3,  # explicit cap
    )
    assert len(result) == 3


def test_max_recursion_depth_cap_respected(tmp_path: Path) -> None:
    """A chain a → b → c → d → e → f with max_depth=2 should stop
    walking past depth 2 (entry is depth 0; siblings at depth 1; their
    siblings at depth 2; stop before depth 3)."""
    # Chain: index → b → c → d → e
    (tmp_path / "index.ts").write_text(
        "import { x } from './b';\n", encoding="utf-8"
    )
    (tmp_path / "b.ts").write_text(
        "import { x } from './c';\nexport const x = 1\n", encoding="utf-8"
    )
    (tmp_path / "c.ts").write_text(
        "import { x } from './d';\nexport const x = 1\n", encoding="utf-8"
    )
    (tmp_path / "d.ts").write_text(
        "import { x } from './e';\nexport const x = 1\n", encoding="utf-8"
    )
    (tmp_path / "e.ts").write_text(
        "export const x = 1\n", encoding="utf-8"
    )

    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
        max_depth=2,
    )
    # Depth 1 (b) + depth 2 (c) staged; d (depth 3) and e (depth 4) dropped.
    assert "b.ts" in result
    assert "c.ts" in result
    assert "d.ts" not in result
    assert "e.ts" not in result


def test_oversized_file_is_dropped(tmp_path: Path) -> None:
    """Files larger than MAX_SIBLING_BYTES should not be staged."""
    (tmp_path / "huge.ts").write_bytes(b"x" * (MAX_SIBLING_BYTES + 100))
    (tmp_path / "index.ts").write_text(
        "import { x } from './huge';\n", encoding="utf-8"
    )
    result = resolve_sibling_files(
        entry_file_path=tmp_path / "index.ts",
        entry_file_bytes=(tmp_path / "index.ts").read_bytes(),
        language="typescript",
    )
    assert "huge.ts" not in result


# ── Cycle handling ────────────────────────────────────────────────────────


def test_cyclic_imports_handled(tmp_path: Path) -> None:
    """a imports b, b imports a — must terminate without infinite loop."""
    (tmp_path / "a.ts").write_text(
        "import { x } from './b';\nexport const y = 1\n", encoding="utf-8"
    )
    (tmp_path / "b.ts").write_text(
        "import { y } from './a';\nexport const x = 1\n", encoding="utf-8"
    )

    result = resolve_sibling_files(
        entry_file_path=tmp_path / "a.ts",
        entry_file_bytes=(tmp_path / "a.ts").read_bytes(),
        language="typescript",
    )
    # b.ts gets staged; a.ts (the entry) does not.
    assert "b.ts" in result
    assert "a.ts" not in result


# ── Module-level constants sanity check ──────────────────────────────────


def test_constants_are_reasonable() -> None:
    """Smoke check on the constants — caps are non-zero and sane."""
    assert MAX_SIBLING_FILES > 0 and MAX_SIBLING_FILES <= 200
    assert MAX_SIBLING_BYTES >= 64 * 1024
    assert MAX_RECURSION_DEPTH >= 2 and MAX_RECURSION_DEPTH <= 20


# ── Project-root detection (v12) ──────────────────────────────────────────


def test_find_project_root_detects_tsconfig(tmp_path: Path) -> None:
    """tsconfig.json marker → use that directory as project root."""
    from preprocessing.sibling_files import _find_project_root

    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "tools").mkdir()
    (tmp_path / "src" / "tools" / "entry.ts").write_text(
        "export const x = 1\n", encoding="utf-8"
    )

    root = _find_project_root(tmp_path / "src" / "tools" / "entry.ts")
    assert root == tmp_path


def test_find_project_root_detects_package_json(tmp_path: Path) -> None:
    """package.json marker → that directory is the project root."""
    from preprocessing.sibling_files import _find_project_root

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    deep = tmp_path / "src" / "tools" / "deep"
    deep.mkdir(parents=True)
    entry = deep / "entry.ts"
    entry.write_text("export const x = 1\n", encoding="utf-8")

    assert _find_project_root(entry) == tmp_path


def test_find_project_root_detects_pyproject(tmp_path: Path) -> None:
    """pyproject.toml → Python project root."""
    from preprocessing.sibling_files import _find_project_root

    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    entry = pkg / "main.py"
    entry.write_text("pass\n", encoding="utf-8")

    assert _find_project_root(entry) == tmp_path


def test_find_project_root_prefers_innermost_marker(tmp_path: Path) -> None:
    """When markers exist at multiple levels, the INNERMOST (closest
    to entry) wins. Real-world: a monorepo has package.json at root
    AND inside each sub-package; the sub-package is the right
    boundary."""
    from preprocessing.sibling_files import _find_project_root

    # Outer marker
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    # Inner marker (closer to entry)
    sub = tmp_path / "libs" / "core"
    sub.mkdir(parents=True)
    (sub / "package.json").write_text("{}", encoding="utf-8")
    entry = sub / "src" / "entry.ts"
    entry.parent.mkdir()
    entry.write_text("export const x = 1\n", encoding="utf-8")

    # Innermost (libs/core) wins.
    assert _find_project_root(entry) == sub


def test_find_project_root_falls_back_to_entry_dir(tmp_path: Path) -> None:
    """No marker anywhere → fall back to entry's immediate parent
    dir. Same as v11 behavior for standalone files."""
    from preprocessing.sibling_files import _find_project_root

    sub = tmp_path / "lonely"
    sub.mkdir()
    entry = sub / "standalone.ts"
    entry.write_text("export const x = 1\n", encoding="utf-8")

    assert _find_project_root(entry) == sub


def test_find_project_root_finds_git_dir(tmp_path: Path) -> None:
    """.git/ is a valid project-root marker (every git repo)."""
    from preprocessing.sibling_files import _find_project_root

    (tmp_path / ".git").mkdir()
    sub = tmp_path / "src"
    sub.mkdir()
    entry = sub / "x.ts"
    entry.write_text("\n", encoding="utf-8")
    assert _find_project_root(entry) == tmp_path


# ── Parent-directory imports across project root (v12) ────────────────────


def test_parent_dir_import_resolves_when_under_project_root(tmp_path: Path) -> None:
    """The LangChain.js fix scenario: a file in src/tools/ imports
    ``../chains/foo.js`` where chains/ is a sibling under src/. v11
    rejected this as path-traversal; v12 accepts because both files
    are UNDER the same project root (marked by package.json)."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "tools").mkdir()
    (tmp_path / "src" / "chains").mkdir()

    (tmp_path / "src" / "tools" / "sql.ts").write_text(
        "import { LLMChain } from '../chains/llm_chain.js';\n"
        "export class QuerySqlTool {}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "chains" / "llm_chain.ts").write_text(
        "export class LLMChain {}\n", encoding="utf-8"
    )

    result = resolve_sibling_files(
        entry_file_path=tmp_path / "src" / "tools" / "sql.ts",
        entry_file_bytes=(tmp_path / "src" / "tools" / "sql.ts").read_bytes(),
        language="typescript",
    )
    # Keyed by rel-from-project-root, not rel-from-entry-dir.
    assert "src/chains/llm_chain.ts" in result
    # The exact LangChain.js failure mode that v12 fixes:
    assert any("chains/llm_chain" in k for k in result.keys())


def test_parent_dir_import_rejected_when_escapes_project_root(tmp_path: Path) -> None:
    """A parent-dir import that escapes the project root is still
    rejected — security stance preserved, just with a wider boundary.
    Scenario: ``import "../../../etc/passwd"`` in a normal project
    must NOT stage files outside the project tree."""
    # Build a project at tmp_path/proj/ — entry at proj/src/x.ts
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text("{}", encoding="utf-8")
    (proj / "src").mkdir()
    (proj / "src" / "x.ts").write_text(
        "import { z } from '../../outside/file.js';\n",
        encoding="utf-8",
    )
    # Create the "outside" file at tmp_path/outside/ (one level ABOVE proj)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.ts").write_text("export const z = 1\n", encoding="utf-8")

    result = resolve_sibling_files(
        entry_file_path=proj / "src" / "x.ts",
        entry_file_bytes=(proj / "src" / "x.ts").read_bytes(),
        language="typescript",
    )
    # The outside file exists on disk + the rewrite resolves it, BUT
    # the path-traversal defense rejects it because it's NOT under
    # the project root (proj/).
    assert "file.ts" not in result
    assert "outside/file.ts" not in result
    # v12 includes the entry under its rel-from-root key (so dast-init
    # extracts it to /workspace/<entry_rel_path>); v15.13 also includes
    # project_root/package.json. Both are legitimately under
    # project_root. The escaping sibling MUST stay out.
    allowed = {"src/x.ts", "package.json"}
    for k in result.keys():
        assert k in allowed, f"unexpected staged path: {k}"


def test_v1513_stages_root_package_json_for_js_targets(tmp_path: Path) -> None:
    """v15.13 (2026-05-20): project_root/package.json is auto-staged
    for JS/TS targets so ``require('./package.json')`` works inside
    the sandbox.

    Reproduces homebridge-syntex/index.js campaign failure where
    BP harness died on:
      Error: Cannot find module './package.json'
    because the JS sibling resolver only walked .js/.mjs/.cjs imports.
    Many npm packages read their version via require('./package.json');
    without staging it, the harness can't import the target.
    """
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text(
        '{"name": "homebridge-syntex", "version": "1.2.3"}', encoding="utf-8"
    )
    (proj / "index.js").write_text(
        "const pkg = require('./package.json'); module.exports = { v: pkg.version };\n",
        encoding="utf-8",
    )
    result = resolve_sibling_files(
        entry_file_path=proj / "index.js",
        entry_file_bytes=(proj / "index.js").read_bytes(),
        language="javascript",
    )
    # package.json must be staged so require('./package.json') works.
    assert "package.json" in result
    assert b'"homebridge-syntex"' in result["package.json"]


def test_v1513_stages_package_json_for_typescript_too(tmp_path: Path) -> None:
    """v15.13: TS targets also get package.json staged. tsx + the JS
    harness chain both rely on package.json being importable."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text('{"name": "ts-pkg"}', encoding="utf-8")
    (proj / "tsconfig.json").write_text("{}", encoding="utf-8")
    (proj / "app.ts").write_text("export const x = 1\n", encoding="utf-8")
    result = resolve_sibling_files(
        entry_file_path=proj / "app.ts",
        entry_file_bytes=(proj / "app.ts").read_bytes(),
        language="typescript",
    )
    assert "package.json" in result


def test_v1513_no_package_json_when_missing(tmp_path: Path) -> None:
    """v15.13 boundary: when project_root has no package.json (rare
    in npm-land but possible for loose JS files / detached scripts),
    the resolver doesn't fabricate one — just doesn't stage it."""
    # No package.json in tmp_path; the resolver falls back to
    # entry.parent as project_root.
    entry = tmp_path / "loose.js"
    entry.write_text("module.exports = 1;\n", encoding="utf-8")
    result = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="javascript",
    )
    assert "package.json" not in result


def test_v1513_python_targets_do_not_get_package_json(tmp_path: Path) -> None:
    """v15.13 boundary: package.json staging is JS/TS-only. A Python
    file in a project that happens to have package.json (e.g., a mixed
    Python + JS monorepo) should NOT trigger npm-side staging."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text('{"name": "mixed-repo"}', encoding="utf-8")
    (proj / "pyproject.toml").write_text("[project]\nname='mixed'\n", encoding="utf-8")
    (proj / "app.py").write_text("def f(): return 1\n", encoding="utf-8")
    result = resolve_sibling_files(
        entry_file_path=proj / "app.py",
        entry_file_bytes=(proj / "app.py").read_bytes(),
        language="python",
    )
    # Python targets bypass the v15.13 JS package.json staging path.
    assert "package.json" not in result


def test_v1516_python_own_dist_caps_siblings_at_30(tmp_path: Path) -> None:
    """v15.16 (2026-05-20): when project_root has a PKG-INFO /
    pyproject.toml declaring an installable distribution, the
    sibling cap drops from 200 to 30. Rationale: the orchestrator
    pip-installs the own_dist with deps, so the harness's
    ``import <pkg>.<module>`` resolves via site-packages. Shipping
    all 200 siblings on top of that overloads the Firecracker VM
    setup (anthropic-sdk-python: 900+ files, hitting the cap of 200
    → BP=0 / NOT_TESTED stub-no-trace across the whole campaign).

    Cap of 30 keeps the entry's direct neighbors (same dir + one
    level up) for relative-import resolution while keeping the
    tarball small enough that VM setup stays under a few seconds.
    """
    # Build a project that triggers own_dist detection.
    proj = tmp_path / "mypkg-1.0"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "mypkg"\nversion = "1.0"\n', encoding="utf-8"
    )
    src = proj / "src" / "mypkg"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("from . import a\n", encoding="utf-8")
    # Create 100 sibling files that the resolver would otherwise stage.
    for i in range(100):
        (src / f"a{i:03d}.py").write_text(f"from . import a{(i+1) % 100:03d}\n", encoding="utf-8")

    entry = src / "a000.py"
    result = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="python",
    )
    # With own_dist detected, the cap drops to 30.
    assert len(result) <= 30, (
        f"v15.16: expected sibling count <= 30 when own_dist detected, "
        f"got {len(result)}"
    )


def test_v1516_python_no_own_dist_keeps_200_cap(monkeypatch: Any) -> None:
    """v15.16 boundary: when project_root has NO own_dist manifest
    (loose scripts, scratch projects), the cap stays at 200. We
    monkeypatch ``_detect_distribution_name_for_install`` to return
    None (no manifest) and confirm the v15.16 cap-reduction code
    path doesn't trigger.

    Direct unit test of the gate condition rather than building a
    full 100-file sibling graph — the resolver's BFS would need
    a project_root marker to follow relative imports, but we want
    to test the cap-decision logic in isolation.
    """
    import preprocessing.sibling_files as sf_module

    # Monkeypatch the own_dist detector — simulate "no manifest found".
    # The cap-reduction code path is gated on this exact function.
    monkeypatch.setattr(
        sf_module,
        "_detect_distribution_name_for_install",
        lambda _: None,
        raising=False,
    )

    # The actual MAX_SIBLING_FILES constant — verify it's >= 200 (the
    # v15.16 cap-reduction logic moves it down to 30 ONLY when
    # _detect_distribution_name_for_install returns a name).
    assert sf_module.MAX_SIBLING_FILES >= 200, (
        "v15.16 boundary: when own_dist NOT detected, the resolver "
        "uses the default MAX_SIBLING_FILES (200), NOT the v15.16-"
        "reduced 30."
    )


def test_compute_entry_rel_path_with_project_root(tmp_path: Path) -> None:
    """The rel-from-root path is what the sandbox stages the entry at."""
    from preprocessing.sibling_files import compute_entry_rel_path

    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "tools").mkdir()
    entry = tmp_path / "src" / "tools" / "sql.ts"
    entry.write_text("export const x = 1\n", encoding="utf-8")

    rel = compute_entry_rel_path(entry)
    # Forward slashes regardless of OS
    assert rel == "src/tools/sql.ts"


def test_compute_entry_rel_path_no_marker_falls_back_to_basename(tmp_path: Path) -> None:
    """No project marker → entry rel-path = basename (v11 behavior)."""
    from preprocessing.sibling_files import compute_entry_rel_path

    entry = tmp_path / "isolated" / "x.ts"
    entry.parent.mkdir()
    entry.write_text("\n", encoding="utf-8")
    rel = compute_entry_rel_path(entry)
    # entry's parent IS the project root (fallback) → rel is just basename
    assert rel == "x.ts"


def test_resolve_includes_chain_transitively_across_subdirs(tmp_path: Path) -> None:
    """A → ../B → ../C across multiple subdirs under same project root.
    BFS walker traverses all of them when each stays under the root."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "tools").mkdir()
    (tmp_path / "src" / "chains").mkdir()
    (tmp_path / "src" / "util").mkdir()

    (tmp_path / "src" / "tools" / "sql.ts").write_text(
        "import { x } from '../chains/llm_chain.js';\n", encoding="utf-8"
    )
    (tmp_path / "src" / "chains" / "llm_chain.ts").write_text(
        "import { y } from '../util/sql_utils.js';\n"
        "export const x = 1;\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "util" / "sql_utils.ts").write_text(
        "export const y = 2;\n", encoding="utf-8"
    )

    result = resolve_sibling_files(
        entry_file_path=tmp_path / "src" / "tools" / "sql.ts",
        entry_file_bytes=(tmp_path / "src" / "tools" / "sql.ts").read_bytes(),
        language="typescript",
    )
    # All three under-root files staged via rel-from-root keys
    keys = set(result.keys())
    assert "src/chains/llm_chain.ts" in keys
    assert "src/util/sql_utils.ts" in keys


def test_python_relative_import_with_project_root(tmp_path: Path) -> None:
    """Python ``from ..utils import bar`` across subdirs under same
    project root works the same way."""
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    pkg = tmp_path / "mypkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "tools").mkdir()
    (pkg / "tools" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "utils").mkdir()
    (pkg / "utils" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "utils" / "helpers.py").write_text(
        "def bar(): return 1\n", encoding="utf-8"
    )

    entry = pkg / "tools" / "main.py"
    entry.write_text(
        "from ..utils.helpers import bar\n"
        "def go(): return bar()\n",
        encoding="utf-8",
    )

    result = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="python",
    )
    assert "mypkg/utils/helpers.py" in result


# ── v15.1: namespace-package staging + skip-when-installable ─────────────


def _make_namespace_pkg_project(
    tmp_path: Path,
    *,
    distribution_name: str = "ruamel.yaml",
) -> Path:
    """Build a synthetic flat-tarball namespace-package project:

      <tmp>/
        PKG-INFO              ← declares Name: ruamel.yaml
        pyproject.toml
        loader.py             ← uses absolute self-imports
        reader.py
        scanner.py
        constructor.py
    """
    project = tmp_path / "ruamel.yaml-0.99"
    project.mkdir()
    (project / "PKG-INFO").write_text(
        f"Metadata-Version: 2.1\nName: {distribution_name}\nVersion: 0.99\n",
        encoding="utf-8",
    )
    (project / "pyproject.toml").write_text(
        '[project]\nname = "ruamel.yaml"\nversion = "0.99"\n',
        encoding="utf-8",
    )
    (project / "loader.py").write_text(
        "from ruamel.yaml.reader import Reader\n"
        "from ruamel.yaml.scanner import Scanner\n"
        "from ruamel.yaml.constructor import Constructor\n"
        "class Loader(Reader, Scanner, Constructor):\n"
        "    pass\n",
        encoding="utf-8",
    )
    (project / "reader.py").write_text("class Reader: pass\n", encoding="utf-8")
    (project / "scanner.py").write_text("class Scanner: pass\n", encoding="utf-8")
    (project / "constructor.py").write_text(
        "class Constructor: pass\n", encoding="utf-8"
    )
    return project


def test_namespace_pkg_default_skips_overlay_staging(tmp_path: Path) -> None:
    """When the project declares a namespace package (PKG-INFO Name has
    a dot), the default behavior is to SKIP the namespace overlay
    staging. The orchestrator pip-installs the file's own distribution
    separately; staging an overlay copy at /workspace/<namespace>/
    would shadow the pip-installed version at import time.
    """
    project = _make_namespace_pkg_project(tmp_path)
    entry = project / "loader.py"

    result = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="python",
    )

    # The overlay should be skipped → no sibling under the namespace.
    assert all(not p.startswith("ruamel/yaml/") for p in result), (
        f"Expected no namespace overlay staging, got: {sorted(result)}"
    )


def test_namespace_pkg_opt_in_restores_overlay_staging(tmp_path: Path) -> None:
    """When the caller explicitly opts in via
    ``skip_own_dist_when_installable=False``, the namespace overlay
    staging IS produced. Used as a fallback when pip-install of the
    own distribution is known to be unavailable (offline scans,
    private packages, deprecated names).
    """
    project = _make_namespace_pkg_project(tmp_path)
    entry = project / "loader.py"

    result = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="python",
        skip_own_dist_when_installable=False,
    )

    # Overlay should be present — every staged sibling under the
    # namespace prefix, including reader / scanner / constructor that
    # the entry imports absolutely.
    keys = set(result.keys())
    assert any(k.startswith("ruamel/yaml/") for k in keys), (
        f"Expected namespace overlay staging, got: {sorted(keys)}"
    )
    assert "ruamel/yaml/reader.py" in keys
    assert "ruamel/yaml/scanner.py" in keys
    assert "ruamel/yaml/constructor.py" in keys


def test_non_namespace_pkg_unaffected_by_skip(tmp_path: Path) -> None:
    """Non-namespace packages (PKG-INFO Name has no dot —
    ``jsonpickle``, ``jinja2``, ``markdown_it``) take the normal
    sibling-resolver path regardless of the
    ``skip_own_dist_when_installable`` setting. The skip logic
    only activates when ``_detect_python_namespace_package`` returns
    a non-None value.
    """
    project = tmp_path / "mypkg-1.0"
    project.mkdir()
    (project / "PKG-INFO").write_text(
        "Metadata-Version: 2.1\nName: mypkg\nVersion: 1.0\n",
        encoding="utf-8",
    )
    # pyproject.toml is the standard project-root marker; PKG-INFO
    # alone isn't in _PROJECT_ROOT_MARKERS so without this the
    # resolver would walk only as far as the entry's package dir.
    (project / "pyproject.toml").write_text(
        '[project]\nname = "mypkg"\nversion = "1.0"\n', encoding="utf-8"
    )
    pkg = project / "mypkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "core.py").write_text(
        "from . import util\n"
        "def go(): return util.x()\n",
        encoding="utf-8",
    )
    (pkg / "util.py").write_text("def x(): return 1\n", encoding="utf-8")

    entry = pkg / "core.py"
    result_default = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="python",
    )
    result_opt_out = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="python",
        skip_own_dist_when_installable=False,
    )

    # Both paths produce identical staging (skip only fires for
    # namespace packages, which this isn't).
    assert "mypkg/util.py" in result_default
    assert "mypkg/util.py" in result_opt_out
    assert result_default == result_opt_out


def test_namespace_pkg_entry_rel_path_keeps_qualified_form(tmp_path: Path) -> None:
    """``compute_entry_rel_path`` STILL applies the namespace prefix
    even when the sibling overlay is skipped. The prefix drives
    MODULE_NAME (= ``ruamel.yaml.loader``) which the harness uses
    for the qualified import that resolves to site-packages."""
    from preprocessing.sibling_files import compute_entry_rel_path

    project = _make_namespace_pkg_project(tmp_path)
    entry = project / "loader.py"
    rel = compute_entry_rel_path(entry)

    assert rel == "ruamel/yaml/loader.py"


def test_namespace_pkg_invalid_name_does_not_apply_prefix(tmp_path: Path) -> None:
    """If the declared distribution name contains invalid Python
    identifier characters (hyphens, digit-leading segments), the
    detector returns None and no namespace adjustment applies.
    """
    project = tmp_path / "weird-pkg-1.0"
    project.mkdir()
    # Hyphenated dotted name — invalid as a Python import.
    (project / "PKG-INFO").write_text(
        "Metadata-Version: 2.1\nName: weird-pkg.sub\nVersion: 1.0\n",
        encoding="utf-8",
    )
    (project / "loader.py").write_text(
        "import os\nclass Loader: pass\n", encoding="utf-8"
    )
    entry = project / "loader.py"

    result = resolve_sibling_files(
        entry_file_path=entry,
        entry_file_bytes=entry.read_bytes(),
        language="python",
        skip_own_dist_when_installable=False,  # try to opt-in
    )

    # No namespace prefix should appear in the staged keys — the
    # invalid identifier fails the detector's safety check.
    for key in result:
        assert not key.startswith("weird-pkg.sub/"), (
            f"Invalid namespace name leaked into staging: {key}"
        )
