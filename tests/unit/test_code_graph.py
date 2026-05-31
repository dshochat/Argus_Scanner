"""Unit tests for DAST-302 cross-file code graph (v1.1).

Covers:

* :func:`build_python_code_graph` — walks a multi-file project root,
  emits one :class:`GraphNode` per public callable, captures callsites.
* :func:`enumerate_project_files` — bounded walk respecting excluded
  directory names + size cap.
* :func:`resolve_project_root_for_file` — marker-file walk.
* :func:`extract_variant_candidates_from_graph` — cross-file
  candidate filter using the signature's sink-kind family.
* :func:`retarget_harness_for_cross_file_variant` — import-path-aware
  harness substitution.

All tests use ``tmp_path`` fixtures rather than the real filesystem —
no fs pollution outside pytest's temp dirs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dast.code_graph import (
    EXCLUDED_DIR_NAMES,
    MAX_FILES_PER_GRAPH,
    Callsite,
    CodeGraph,
    GraphNode,
    build_python_code_graph,
    enumerate_project_files,
    resolve_project_root_for_file,
)
from dast.variant_analysis import (
    SemanticSignature,
    VariantCandidate,
    extract_variant_candidates_from_graph,
    retarget_harness_for_cross_file_variant,
)


# ── Fixture: a tiny multi-file Python project ─────────────────────────


def _make_project(tmp_path: Path) -> Path:
    """Create a temp project root with a small but realistic shape::

      myproj/
        pyproject.toml      # marker file
        app.py              # entry — has the seed SSRF
        lib/
          __init__.py
          helpers.py        # variant — same sink, different file
          safe.py           # NOT a variant — uses open(), not urlopen
        tests/
          test_app.py       # excluded? no — but private fn so filtered
        node_modules/       # EXCLUDED by name
          junk.py
    """
    root = tmp_path / "myproj"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "myproj"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    (root / "app.py").write_text(
        "import urllib.request\n"
        "\n"
        "def fetch_url(url: str) -> str:\n"
        "    return urllib.request.urlopen(url).read().decode()\n"
        "\n"
        "def harmless():\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    lib = root / "lib"
    lib.mkdir()
    (lib / "__init__.py").write_text("", encoding="utf-8")
    (lib / "helpers.py").write_text(
        "import urllib.request\n"
        "\n"
        "def download_image(url: str) -> bytes:\n"
        "    return urllib.request.urlopen(url).read()\n"
        "\n"
        "def _private_helper(url):\n"
        "    return urllib.request.urlopen(url)\n",
        encoding="utf-8",
    )
    (lib / "safe.py").write_text(
        "def render_path(path: str) -> str:\n"
        "    with open(path) as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text(
        "def test_harmless():\n"
        "    pass\n",
        encoding="utf-8",
    )
    # Excluded — should NEVER be graphed.
    nm = root / "node_modules"
    nm.mkdir()
    (nm / "junk.py").write_text(
        "def vulnerable_fetch(url):\n"
        "    import urllib.request\n"
        "    return urllib.request.urlopen(url).read()\n",
        encoding="utf-8",
    )
    return root


# ── enumerate_project_files ──────────────────────────────────────────


def test_enumerate_skips_excluded_directory_names(tmp_path: Path) -> None:
    """node_modules / __pycache__ / etc. must NEVER show up."""
    root = _make_project(tmp_path)
    files = enumerate_project_files(root, extensions=(".py",))
    rels = {str(p.relative_to(root)).replace("\\", "/") for p in files}
    # Excluded
    assert not any("node_modules" in r for r in rels), rels
    # Included
    assert "app.py" in rels
    assert "lib/helpers.py" in rels


def test_enumerate_respects_max_files_cap(tmp_path: Path) -> None:
    """When the project has more files than the cap, the cap wins."""
    root = _make_project(tmp_path)
    files = enumerate_project_files(root, extensions=(".py",), max_files=2)
    assert len(files) == 2


def test_enumerate_skips_oversized_files(tmp_path: Path) -> None:
    """Files exceeding the per-file size cap are excluded."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "small.py").write_text("x = 1\n", encoding="utf-8")
    (root / "huge.py").write_text("x = 1\n" * 100000, encoding="utf-8")  # ~700KB
    files = enumerate_project_files(
        root, extensions=(".py",), max_bytes_per_file=10_000
    )
    names = {p.name for p in files}
    assert "small.py" in names
    assert "huge.py" not in names


def test_enumerate_returns_empty_when_root_missing(tmp_path: Path) -> None:
    """Nonexistent root yields empty list, not exception."""
    files = enumerate_project_files(tmp_path / "does_not_exist")
    assert files == []


def test_enumerate_returns_empty_when_root_is_a_file(tmp_path: Path) -> None:
    """root must be a directory."""
    f = tmp_path / "single.py"
    f.write_text("x = 1\n")
    files = enumerate_project_files(f)
    assert files == []


def test_excluded_dir_names_contains_essential_entries() -> None:
    """Sanity check: the standard exclusion set covers the obvious
    ones. Regression guard against accidental removal."""
    for name in (
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "site-packages",
    ):
        assert name in EXCLUDED_DIR_NAMES


# ── build_python_code_graph ──────────────────────────────────────────


def test_build_graph_yields_nodes_across_multiple_files(tmp_path: Path) -> None:
    """The graph spans every file under the project root (not just
    one). Both ``app.py`` and ``lib/helpers.py`` contribute nodes."""
    root = _make_project(tmp_path)
    graph = build_python_code_graph(
        project_root=root,
        entry_file=root / "app.py",
    )
    rels = {n.file_path for n in graph.nodes}
    assert "app.py" in rels
    assert "lib/helpers.py" in rels
    # node_modules excluded by name
    assert not any("node_modules" in r for r in rels)


def test_build_graph_records_function_qualname_and_callsites(
    tmp_path: Path,
) -> None:
    """Each graph node carries qualname + callsites for the LLM
    judge."""
    root = _make_project(tmp_path)
    graph = build_python_code_graph(
        project_root=root,
        entry_file=root / "app.py",
    )
    fetch_node = next(
        (n for n in graph.nodes if n.qualname == "fetch_url"),
        None,
    )
    assert fetch_node is not None
    assert fetch_node.file_path == "app.py"
    # The body calls urllib.request.urlopen — the dotted form lands
    # in callsites.
    callees = [c.callee_name for c in fetch_node.callsites]
    assert any("urlopen" in c for c in callees)


def test_build_graph_skips_private_non_agentic_functions(tmp_path: Path) -> None:
    """``_private_helper`` starts with `_` and isn't in the agentic
    allowlist — should not appear as a node."""
    root = _make_project(tmp_path)
    graph = build_python_code_graph(
        project_root=root,
        entry_file=root / "app.py",
    )
    qualnames = {n.qualname for n in graph.nodes}
    assert "_private_helper" not in qualnames


def test_build_graph_skips_parse_errors_gracefully(tmp_path: Path) -> None:
    """A malformed file is logged + skipped; other files still graph."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname='x'\n")
    (root / "good.py").write_text("def good():\n    pass\n")
    (root / "bad.py").write_text("def bad(:\n    invalid")
    graph = build_python_code_graph(
        project_root=root,
        entry_file=root / "good.py",
    )
    qualnames = {n.qualname for n in graph.nodes}
    assert "good" in qualnames
    # bad.py was attempted but skipped; total nodes = just 'good'.
    assert "bad" not in qualnames


def test_build_graph_empty_when_root_invalid(tmp_path: Path) -> None:
    """Nonexistent project_root → empty graph, not exception."""
    graph = build_python_code_graph(
        project_root=tmp_path / "does_not_exist",
        entry_file=tmp_path / "x.py",
    )
    assert graph.nodes == []
    assert graph.files_scanned == 0


def test_build_graph_populates_entry_file_rel_path(tmp_path: Path) -> None:
    """``graph.entry_file`` is the rel-from-root path so cross-file
    candidate filter can exclude the seed's file."""
    root = _make_project(tmp_path)
    graph = build_python_code_graph(
        project_root=root,
        entry_file=root / "app.py",
    )
    assert graph.entry_file == "app.py"


# ── resolve_project_root_for_file ────────────────────────────────────


def test_resolve_project_root_finds_pyproject_marker(tmp_path: Path) -> None:
    """Walking up from ``app.py`` hits pyproject.toml at the root."""
    root = _make_project(tmp_path)
    resolved = resolve_project_root_for_file(root / "app.py")
    assert resolved is not None
    assert resolved.resolve() == root.resolve()


def test_resolve_project_root_walks_up_through_subdirs(
    tmp_path: Path,
) -> None:
    """From a deep file (``lib/helpers.py``), the walk still finds
    the same project root."""
    root = _make_project(tmp_path)
    resolved = resolve_project_root_for_file(root / "lib" / "helpers.py")
    assert resolved is not None
    assert resolved.resolve() == root.resolve()


def test_resolve_project_root_returns_none_when_no_marker(
    tmp_path: Path,
) -> None:
    """No marker file anywhere up the chain → None."""
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    f = deep / "lonely.py"
    f.write_text("x = 1\n")
    # tmp_path itself doesn't have pyproject/.git — should return None.
    resolved = resolve_project_root_for_file(f)
    assert resolved is None


# ── extract_variant_candidates_from_graph ────────────────────────────


def test_cross_file_hunter_surfaces_variant_in_sibling_file(
    tmp_path: Path,
) -> None:
    """The killer test: with `fetch_url` (in app.py) as seed,
    Phase D's cross-file hunter must surface `download_image`
    (in lib/helpers.py) as a candidate."""
    root = _make_project(tmp_path)
    graph = build_python_code_graph(
        project_root=root, entry_file=root / "app.py"
    )
    sig = SemanticSignature(
        attack_class="ssrf",
        cwe="CWE-918",
        source_shape="LLM-supplied URL",
        sink_kind="network_fetch",
        sink_callee="urlopen",
        seed_finding_id="H001",
        seed_function="fetch_url",
    )
    candidates = extract_variant_candidates_from_graph(
        graph=graph,
        signature=sig,
        exclude_qualname="fetch_url",
        exclude_file_path="app.py",
    )
    names = {c.function_name for c in candidates}
    assert "download_image" in names, (
        f"Cross-file variant download_image missing from candidates: {names}"
    )


def test_cross_file_hunter_excludes_seed_function(tmp_path: Path) -> None:
    """The seed itself MUST NOT appear in candidate list."""
    root = _make_project(tmp_path)
    graph = build_python_code_graph(
        project_root=root, entry_file=root / "app.py"
    )
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="urlopen",
        seed_function="fetch_url",
    )
    candidates = extract_variant_candidates_from_graph(
        graph=graph,
        signature=sig,
        exclude_qualname="fetch_url",
        exclude_file_path="app.py",
    )
    # download_image is in candidates; fetch_url is not.
    assert "fetch_url" not in {c.function_name for c in candidates}


def test_cross_file_hunter_excludes_seed_by_line_when_qualname_empty(
    tmp_path: Path,
) -> None:
    """Defense-in-depth: when ``exclude_qualname`` is empty (LLM
    signature drift / L1 schema gap), the seed must still be excluded
    via ``exclude_seed_line`` matching the body line range in the
    same file. Regression for the v4 synthetic scan bug where the
    seed surfaced as its own variant."""
    root = _make_project(tmp_path)
    graph = build_python_code_graph(
        project_root=root, entry_file=root / "app.py"
    )
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="urlopen",
        seed_function="",  # the bug scenario
    )
    # In _make_project's app.py: fetch_url def at line 3, urlopen
    # call at line 4. Line 4 is inside fetch_url's body.
    candidates = extract_variant_candidates_from_graph(
        graph=graph,
        signature=sig,
        exclude_qualname="",
        exclude_file_path="app.py",
        exclude_seed_line=4,
    )
    assert "fetch_url" not in {c.function_name for c in candidates}
    # download_image (sibling file, lib/helpers.py) MUST still surface.
    assert "download_image" in {c.function_name for c in candidates}


def test_cross_file_hunter_filters_by_sink_kind(tmp_path: Path) -> None:
    """`render_path` uses `open` (file_read sink) — must NOT surface
    for an SSRF signature (network_fetch sink)."""
    root = _make_project(tmp_path)
    graph = build_python_code_graph(
        project_root=root, entry_file=root / "app.py"
    )
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="urlopen",
        seed_function="fetch_url",
    )
    candidates = extract_variant_candidates_from_graph(
        graph=graph,
        signature=sig,
        exclude_qualname="fetch_url",
        exclude_file_path="app.py",
    )
    assert "render_path" not in {c.function_name for c in candidates}


def test_cross_file_candidate_carries_file_path_attribute(
    tmp_path: Path,
) -> None:
    """The cross-file hunter stashes the variant's file_path on the
    candidate so the retargeter can build the import path."""
    root = _make_project(tmp_path)
    graph = build_python_code_graph(
        project_root=root, entry_file=root / "app.py"
    )
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="urlopen",
        seed_function="fetch_url",
    )
    candidates = extract_variant_candidates_from_graph(
        graph=graph,
        signature=sig,
        exclude_qualname="fetch_url",
        exclude_file_path="app.py",
    )
    for cand in candidates:
        if cand.function_name == "download_image":
            assert cand.file_path == "lib/helpers.py"
            return
    pytest.fail("download_image not in candidates — earlier test should have caught this")


def test_cross_file_candidate_file_path_survives_asdict_roundtrip(
    tmp_path: Path,
) -> None:
    """DAST-304 regression: cross-file candidates MUST carry their
    ``file_path`` through ``dataclasses.asdict()``. Earlier versions
    stashed it on ``__dict__`` which ``asdict`` drops, so Phase C
    multi-file's ``_group_confirmed_variants_by_file`` silently
    skipped every cross-file variant (variant_remediation always
    None even when DAST-302 confirmed sibling-file variants)."""
    from dataclasses import asdict

    root = _make_project(tmp_path)
    graph = build_python_code_graph(
        project_root=root, entry_file=root / "app.py"
    )
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="urlopen",
        seed_function="fetch_url",
    )
    candidates = extract_variant_candidates_from_graph(
        graph=graph,
        signature=sig,
        exclude_qualname="fetch_url",
        exclude_file_path="app.py",
    )
    for cand in candidates:
        if cand.function_name == "download_image":
            serialized = asdict(cand)
            assert serialized.get("file_path") == "lib/helpers.py"
            assert "file_path" in serialized
            return
    pytest.fail("download_image not in candidates")


def test_cross_file_candidate_carries_async_flag(tmp_path: Path) -> None:
    """For async variants, the harness retargeter needs the
    ``is_async`` hint."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname='p'\n")
    (root / "async_app.py").write_text(
        "import urllib.request\n"
        "async def afetch(url):\n"
        "    return urllib.request.urlopen(url).read()\n",
        encoding="utf-8",
    )
    graph = build_python_code_graph(
        project_root=root, entry_file=root / "async_app.py"
    )
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="urlopen",
    )
    cands = extract_variant_candidates_from_graph(
        graph=graph,
        signature=sig,
        exclude_qualname="",
        exclude_file_path="",
    )
    afetch = next((c for c in cands if c.function_name == "afetch"), None)
    assert afetch is not None
    assert afetch.__dict__.get("is_async") is True


# ── retarget_harness_for_cross_file_variant ──────────────────────────


def test_retarget_cross_file_substitutes_module_qualified_path() -> None:
    """For a variant in `lib/helpers.py`, the retargeter replaces
    seed-function references with `lib.helpers.variant_fn`."""
    variant = VariantCandidate(
        function_name="download_image",
        qualname="download_image",
        file_path="lib/helpers.py",
    )
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="urlopen",
    )
    seed_cmds = ["python3 -c 'import app; app.fetch_url(\"http://imds/...\")'"]
    out = retarget_harness_for_cross_file_variant(
        seed_plan_commands=seed_cmds,
        seed_function="fetch_url",
        variant=variant,
        signature=sig,
        seed_file_rel_path="app.py",
    )
    cmd = out[0]
    # Cross-file: seed_function replaced with full module path.
    assert "lib.helpers.download_image" in cmd
    # Bare seed_function reference is gone.
    assert "fetch_url" not in cmd


def test_retarget_cross_file_falls_back_to_same_file_when_paths_match() -> None:
    """When variant.file_path == seed_file_rel_path, the retargeter
    routes to the v1 same-file substitutor (no module path)."""
    variant = VariantCandidate(function_name="harmless_variant", file_path="app.py")
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="urlopen",
    )
    out = retarget_harness_for_cross_file_variant(
        seed_plan_commands=["echo fetch_url"],
        seed_function="fetch_url",
        variant=variant,
        signature=sig,
        seed_file_rel_path="app.py",
    )
    # Same-file: simple substitution, NO dotted path.
    assert "harmless_variant" in out[0]
    assert "." not in out[0].replace("./", "").replace(".py", "")  # no module dots


def test_retarget_cross_file_handles_nested_subdir() -> None:
    """A variant in `src/myproj/lib/helpers.py` should map to
    `src.myproj.lib.helpers.variant`."""
    variant = VariantCandidate(function_name="vfn", file_path="src/myproj/lib/helpers.py")
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="urlopen",
    )
    # Realistic Phase A command shape — ``python3 -c '<body>'`` with the
    # seed callsite ``app.fetch_url(...)``. Bug #6's AST rewriter must
    # emit the module-qualified variant call.
    out = retarget_harness_for_cross_file_variant(
        seed_plan_commands=[
            "python3 -c 'import app; app.fetch_url(\"http://imds/...\")'"
        ],
        seed_function="fetch_url",
        variant=variant,
        signature=sig,
        seed_file_rel_path="app.py",
    )
    assert "src.myproj.lib.helpers.vfn" in out[0]
    # The dotted import must be prepended too — without it, Python
    # would NameError on `src` before reaching the call.
    assert "import src.myproj.lib.helpers" in out[0]


# ── Bug #6 regression: AST-aware harness retargeting ─────────────────


def _retarget_one_cmd(cmd: str, variant_file: str = "lib/downloaders.py") -> str:
    """Helper — retarget a single seed command for a download_image
    variant in lib/downloaders.py and return the result."""
    variant = VariantCandidate(
        function_name="download_image",
        qualname="download_image",
        file_path=variant_file,
    )
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="urllib.request.urlopen",
        seed_function="fetch_url",
    )
    out = retarget_harness_for_cross_file_variant(
        seed_plan_commands=[cmd],
        seed_function="fetch_url",
        variant=variant,
        signature=sig,
        seed_file_rel_path="app.py",
    )
    return out[0]


def test_bug6_rewrites_module_dot_callsite() -> None:
    """`app.fetch_url(...)` becomes `lib.downloaders.download_image(...)`
    — NOT `app.lib.downloaders.download_image(...)` (the broken
    whole-word substitution behavior before Fix #6)."""
    out = _retarget_one_cmd(
        "python3 -c 'import app; app.fetch_url(\"data:text/plain,SSRF_PROOF\")'"
    )
    assert "lib.downloaders.download_image" in out
    # The pre-Fix-#6 bug: chained `app.lib...` attribute access.
    assert "app.lib.downloaders" not in out
    # The dotted variant module is imported.
    assert "import lib.downloaders" in out


def test_bug6_strips_from_import_of_seed() -> None:
    """`from app import fetch_url` was being mangled into
    `from app import lib.downloaders.download_image` (SyntaxError).
    Fix #6 strips the import entirely — the variant call site now
    resolves via the variant's module path."""
    out = _retarget_one_cmd(
        "python3 -c 'from app import fetch_url; fetch_url(\"data:foo\")'"
    )
    # The broken pre-Fix-#6 emission would contain a `from app import`
    # line with dotted name — invalid Python.
    assert "from app import lib" not in out
    # The variant call site is module-qualified.
    assert "lib.downloaders.download_image" in out
    # The variant module is imported.
    assert "import lib.downloaders" in out


def test_bug6_rewrites_bare_callsite() -> None:
    """When the seed callsite is bare (no module prefix) — e.g.,
    inside a function body that already imported `fetch_url` — Fix #6
    still redirects to the variant's module path."""
    out = _retarget_one_cmd(
        "python3 -c 'fetch_url(\"data:foo\")'"
    )
    assert "lib.downloaders.download_image('data:foo')" in out or \
        'lib.downloaders.download_image("data:foo")' in out


def test_bug6_preserves_print_wrapper() -> None:
    """Common Phase A shape: ``print(seed_function(...))``. The print
    wrapper must survive the rewrite — the variant's return value
    needs to land in stdout for the oracle substring check."""
    out = _retarget_one_cmd(
        "python3 -c 'import app; print(app.fetch_url(\"data:foo\"))'"
    )
    assert "print(lib.downloaders.download_image" in out


def test_bug6_falls_through_for_non_dash_c_commands() -> None:
    """Script harnesses (`python3 /workspace/harness.py`) don't have a
    `-c` body to AST-rewrite. Pass them through unchanged — that's the
    pre-Fix-#6 behavior for these forms, and changing them blindly via
    whole-word substitution would risk regressions."""
    out = _retarget_one_cmd("python3 /workspace/harness.py --target fetch_url")
    assert out == "python3 /workspace/harness.py --target fetch_url"


def test_bug6_idempotent() -> None:
    """Calling the retargeter twice on the same command must produce
    the same output (no double-imports, no double-rewrites)."""
    once = _retarget_one_cmd(
        "python3 -c 'import app; app.fetch_url(\"data:foo\")'"
    )
    # Re-feed the already-retargeted command through. We have to wrap
    # back into the helper, which expects the seed shape — so do it
    # via a direct second call.
    twice = _retarget_one_cmd(once)
    # The variant module appears exactly once.
    assert twice.count("import lib.downloaders") == 1


def test_bug6_handles_double_quoted_dash_c_body() -> None:
    """Some seed shapes use double quotes around the -c body.
    Rewriter must handle both quote styles."""
    out = _retarget_one_cmd(
        'python3 -c "import app; app.fetch_url(\'data:foo\')"'
    )
    assert "lib.downloaders.download_image" in out
    assert "import lib.downloaders" in out


def test_bug6_handles_nested_subdir_module_path() -> None:
    """Variants in deeply nested project subdirs map to the full
    dotted Python module path."""
    out = _retarget_one_cmd(
        "python3 -c 'import app; app.fetch_url(\"data:foo\")'",
        variant_file="src/myproj/lib/helpers.py",
    )
    assert "src.myproj.lib.helpers.download_image" in out
    assert "import src.myproj.lib.helpers" in out


def test_bug6_syntax_error_in_body_fails_open() -> None:
    """A malformed Python body must NOT crash Phase D — the variant
    verification produces a refute on missing oracle signal (existing
    pre-Fix-#6 behavior), the command stays unchanged."""
    out = _retarget_one_cmd("python3 -c 'this is not valid python'")
    # Unchanged — fail-open.
    assert out == "python3 -c 'this is not valid python'"


def test_bug6_emitted_python_is_runnable() -> None:
    """End-to-end sanity: ast.compile the body of the retargeted -c
    command — it must be valid Python. This catches any regression
    where the rewriter emits a malformed AST."""
    import ast as _ast
    import re

    out = _retarget_one_cmd(
        "python3 -c 'import app; app.fetch_url(\"data:foo\")'"
    )
    # Extract the body from the -c argument.
    m = re.search(r"-c\s+(['\"])(.*?)\1(?=\s|$)", out, re.DOTALL)
    assert m is not None, f"-c arg not found in retargeted command: {out}"
    body = m.group(2)
    # ast.parse raises SyntaxError if the body is malformed.
    _ast.parse(body)


def test_retarget_cross_file_with_non_python_file_falls_back() -> None:
    """A `.ts` variant_file_path triggers the same-file fallback
    (v1.1 doesn't yet build ESM imports for TS cross-file)."""
    variant = VariantCandidate(function_name="tsVariant", file_path="lib/helpers.ts")
    sig = SemanticSignature(
        attack_class="ssrf",
        sink_kind="network_fetch",
        sink_callee="fetch",
    )
    out = retarget_harness_for_cross_file_variant(
        seed_plan_commands=["npx tsx app.ts fetch_url"],
        seed_function="fetch_url",
        variant=variant,
        signature=sig,
        seed_file_rel_path="app.ts",
    )
    # Falls back to whole-word substitution.
    assert "tsVariant" in out[0]
    # No module-qualified dotted path emitted.
    assert "lib.helpers.tsVariant" not in out[0]
