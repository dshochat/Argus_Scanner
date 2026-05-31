"""Unit tests for preprocessing.imports (P2a v0.1).

Covers the two public entry points (``extract_python_imports`` and
``compute_runtime_packages``) and the orchestrator-facing wrapper
``runtime_packages_for_plan``. No live sandbox; pure AST + filtering
logic.
"""

from __future__ import annotations

import pytest

from preprocessing.imports import (
    IMPORT_TO_PKG,
    LEAN_PREINSTALLED,
    ML_TOOLS_PREINSTALLED,
    PREINSTALLED_BY_TIER,
    RICH_PYTHON_PREINSTALLED,
    compute_runtime_packages,
    extract_python_imports,
    runtime_packages_for_plan,
)


# ── extract_python_imports ─────────────────────────────────────────────────


def test_extract_imports_basic_import() -> None:
    """`import X` yields top-level name X."""
    assert extract_python_imports("import requests") == {"requests"}


def test_extract_imports_dotted_import_keeps_root() -> None:
    """`import X.y.z` yields just X — that's the pip-installable name."""
    assert extract_python_imports("import langchain.chains.llm") == {"langchain"}


def test_extract_imports_aliased() -> None:
    """`import X as Y` still yields X (the actual package)."""
    assert extract_python_imports("import numpy as np") == {"numpy"}


def test_extract_imports_from_import() -> None:
    """`from X import y` yields X."""
    src = "from requests import Session\nfrom bs4 import BeautifulSoup"
    assert extract_python_imports(src) == {"requests", "bs4"}


def test_extract_imports_from_dotted() -> None:
    """`from X.y import z` yields X."""
    src = "from selenium.webdriver import Chrome"
    assert extract_python_imports(src) == {"selenium"}


def test_extract_imports_skips_relative_imports() -> None:
    """Relative imports point at sibling modules, not pip-installable
    distributions. We must NOT try to pip-install them."""
    src = "from . import helpers\nfrom .sibling import thing\nfrom ..parent import x"
    assert extract_python_imports(src) == set()


def test_extract_imports_mixed_real_world_example() -> None:
    """End-to-end on a realistic preinstall.py-shaped source."""
    src = """
import os
import json
import requests
import numpy as np
from bs4 import BeautifulSoup
from selenium.webdriver import Chrome
from . import helpers
import langchain.chains
"""
    assert extract_python_imports(src) == {
        "os",
        "json",
        "requests",
        "numpy",
        "bs4",
        "selenium",
        "langchain",
    }


def test_extract_imports_syntax_error_returns_empty() -> None:
    """Malformed source must NEVER crash — we return empty set."""
    assert extract_python_imports("def x(:::") == set()
    # Truly invalid syntax: unmatched brackets.
    assert extract_python_imports("x = [[[") == set()


def test_extract_imports_empty_source() -> None:
    assert extract_python_imports("") == set()


# ── compute_runtime_packages: filter pipeline ──────────────────────────────


def test_compute_drops_stdlib_modules() -> None:
    """`os`, `json`, etc. are stdlib — must be filtered out."""
    src = "import os\nimport json\nimport requests\nimport selenium"
    result = compute_runtime_packages(src, "lean")
    # Expected: requests is preinstalled in lean (filtered), os/json are
    # stdlib (filtered); only selenium remains.
    assert "os" not in result
    assert "json" not in result


def test_compute_drops_lean_preinstalled() -> None:
    """Packages already in the lean image's pip layer must be filtered."""
    src = "import requests\nimport pandas\nimport selenium"
    result = compute_runtime_packages(src, "lean")
    # requests + pandas are preinstalled in lean, selenium isn't.
    assert "requests" not in result
    assert "pandas" not in result
    assert "selenium" in result


def test_compute_rich_python_drops_more() -> None:
    """rich_python tier has more preinstalled (scipy, sklearn, etc.).
    Names that survive lean filter but are in rich_python should be
    dropped for the rich_python tier."""
    src = "import scipy\nimport sklearn\nimport selenium"
    lean_result = compute_runtime_packages(src, "lean")
    rich_result = compute_runtime_packages(src, "rich_python")
    # scipy + sklearn missing from lean (would be installed)
    assert "scipy" in lean_result
    assert "scikit-learn" in lean_result  # sklearn → scikit-learn mapping
    # But preinstalled in rich_python (dropped)
    assert "scipy" not in rich_result
    assert "scikit-learn" not in rich_result
    # selenium still survives both
    assert "selenium" in lean_result
    assert "selenium" in rich_result


def test_compute_ml_tools_drops_torch_etc() -> None:
    """ml_tools tier has torch/transformers/safetensors preinstalled."""
    src = "import torch\nimport transformers\nimport selenium"
    result = compute_runtime_packages(src, "ml_tools")
    assert "torch" not in result
    assert "transformers" not in result
    assert "selenium" in result


def test_compute_maps_import_to_pip_name() -> None:
    """Import name → pip name mapping (e.g., sklearn → scikit-learn).
    Critical because `pip install sklearn` is deprecated; pip rejects it."""
    src = "import sklearn"
    # On lean tier, sklearn isn't preinstalled.
    result = compute_runtime_packages(src, "lean")
    assert "scikit-learn" in result
    assert "sklearn" not in result  # must be MAPPED, not raw


def test_compute_rejects_unsafe_pkg_names() -> None:
    """The filter must reject names with shell metacharacters even if
    they sneak through the import parser somehow. (Hard to inject via
    Python source code, but defensive.)"""
    # Verified via _is_safe_pkg_name helper through compute pipeline.
    # If an attacker somehow got an unsafe name into IMPORT_TO_PKG (e.g.,
    # via supply-chain attack on this codebase), the safety filter
    # catches it.
    from preprocessing.imports import _is_safe_pkg_name

    assert _is_safe_pkg_name("requests")
    assert _is_safe_pkg_name("python-dateutil")
    assert not _is_safe_pkg_name("req; rm -rf /")
    assert not _is_safe_pkg_name("-r requirements.txt")
    assert not _is_safe_pkg_name("")
    assert not _is_safe_pkg_name("a" * 65)  # too long


def test_compute_caps_at_max_packages() -> None:
    """Bounded count — 20 packages max per scan by default."""
    # Generate 30 unique non-stdlib non-preinstalled imports.
    src = "\n".join(f"import unique_pkg_{i}" for i in range(30))
    result = compute_runtime_packages(src, "lean", max_packages=20)
    assert len(result) == 20


def test_compute_sorts_deterministically() -> None:
    """Stable ordering means plan IDs hash deterministically across
    runs (important for bench reproducibility + caching downstream)."""
    src = "import zzz_pkg\nimport aaa_pkg\nimport mmm_pkg"
    result = compute_runtime_packages(src, "lean")
    assert result == sorted(result)


def test_compute_empty_for_malformed_source() -> None:
    assert compute_runtime_packages("def x(:::", "lean") == []
    assert compute_runtime_packages("", "lean") == []


def test_compute_unknown_tier_falls_back_to_lean() -> None:
    """An unknown image_hint falls back to lean's preinstalled set —
    wasteful re-install but functionally correct."""
    src = "import requests"  # preinstalled in lean
    # Unknown tier
    result = compute_runtime_packages(src, "future_tier_xyz")
    # Should be filtered by lean's preinstalled set (defensive default)
    assert "requests" not in result


# ── runtime_packages_for_plan: orchestrator-facing wrapper ──────────────────


def test_runtime_packages_for_plan_disabled_returns_empty() -> None:
    """When enabled=False, always returns empty regardless of imports."""
    result = runtime_packages_for_plan(
        file_bytes=b"import selenium",
        file_name="x.py",
        image_hint="rich_python",
        enabled=False,
    )
    assert result == []


def test_runtime_packages_for_plan_lean_tier_skips_imported_deps() -> None:
    """lean tier never installs ARBITRARY imports — the model picked
    lean because it expected no extras. (v0.1 contract, preserved by
    v15.4 for the imports-side.)

    When no own-dist is detectable, the original v0.1 behavior holds:
    ``[]`` regardless of imports.
    """
    result = runtime_packages_for_plan(
        file_bytes=b"import selenium",
        file_name="x.py",
        image_hint="lean",
        enabled=True,
        project_root="",  # no manifest → no own-dist
    )
    assert result == []


def test_runtime_packages_for_plan_lean_tier_installs_own_dist(
    tmp_path: pytest.TempPathFactory,
) -> None:
    """v15.4: lean tier DOES install the file's own distribution when
    a PKG-INFO/pyproject.toml is present in ``project_root``.

    Why: every file inside a Python sdist needs its own package
    importable for Phase B Stage 1 / Phase A runtime probes to load
    the target module's package context. Without this, callables=0
    on lean tier for every package-internal file.
    """
    root = tmp_path / "ruamel.yaml-0.19.1"  # type: ignore[attr-defined]
    root.mkdir()
    (root / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: ruamel.yaml\n")
    # Arbitrary imports SHOULD NOT make it through on lean — only own_dist.
    result = runtime_packages_for_plan(
        file_bytes=b"import selenium\nimport ruamel.yaml.constructor",
        file_name="loader.py",
        image_hint="lean",
        enabled=True,
        project_root=str(root),
    )
    assert result == ["ruamel.yaml"]


def test_runtime_packages_for_plan_lean_no_manifest_still_empty(
    tmp_path: pytest.TempPathFactory,
) -> None:
    """v15.4 boundary: lean tier + ``project_root`` that has no
    manifest (no PKG-INFO / pyproject.toml / setup.cfg) → still ``[]``.

    The own-dist install is manifest-anchored — without a declared
    distribution name, we don't guess.
    """
    root = tmp_path / "loose_files"  # type: ignore[attr-defined]
    root.mkdir()
    (root / "scratch.py").write_text("x = 1\n")
    result = runtime_packages_for_plan(
        file_bytes=b"import selenium",
        file_name="x.py",
        image_hint="lean",
        enabled=True,
        project_root=str(root),
    )
    assert result == []


def test_runtime_packages_for_plan_own_dist_dedups_against_imports(
    tmp_path: pytest.TempPathFactory,
) -> None:
    """v15.4: when own_dist normalizes to the same name as an
    imported package, don't list it twice — and own_dist comes first."""
    root = tmp_path / "mako-1.3.0"  # type: ignore[attr-defined]
    root.mkdir()
    (root / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: Mako\n")
    # rich_python so imports-side activates; `mako` also appears in imports.
    result = runtime_packages_for_plan(
        file_bytes=b"import mako\nimport selenium",
        file_name="template.py",
        image_hint="rich_python",
        enabled=True,
        project_root=str(root),
    )
    # Mako appears once, leading; selenium follows.
    assert result[0] == "Mako"
    # No duplicate of mako/Mako under any casing.
    lowered = [p.lower() for p in result]
    assert lowered.count("mako") == 1
    assert "selenium" in result


def test_runtime_packages_for_plan_non_python_skipped() -> None:
    """Non-Python files don't get Python deps installed."""
    result = runtime_packages_for_plan(
        file_bytes=b"console.log('js')",
        file_name="attack.js",
        image_hint="rich_python",
        enabled=True,
    )
    assert result == []


def test_runtime_packages_for_plan_pth_file_supported() -> None:
    """.pth (Python path) files are Python — supported."""
    result = runtime_packages_for_plan(
        file_bytes=b"import selenium",
        file_name="compat_hooks.pth",
        image_hint="rich_python",
        enabled=True,
    )
    assert "selenium" in result


def test_runtime_packages_for_plan_invalid_utf8_returns_empty() -> None:
    """Bytes that don't decode as UTF-8 → return empty (don't crash)."""
    result = runtime_packages_for_plan(
        file_bytes=b"\xff\xfe invalid utf8",
        file_name="x.py",
        image_hint="rich_python",
        enabled=True,
    )
    assert result == []


def test_runtime_packages_for_plan_rich_python_filters_preinstalled() -> None:
    """End-to-end: rich_python tier filters out its own preinstalled set."""
    src = b"import scipy\nimport openai\nimport selenium"
    result = runtime_packages_for_plan(
        file_bytes=src,
        file_name="x.py",
        image_hint="rich_python",
        enabled=True,
    )
    # scipy + openai preinstalled in rich_python
    assert "scipy" not in result
    assert "openai" not in result
    # selenium isn't preinstalled — gets installed
    assert "selenium" in result


# ── Preinstalled set inheritance ───────────────────────────────────────────


def test_preinstalled_sets_inherit_hierarchically() -> None:
    """Each tier is a strict superset of the previous: ml_tools ⊇
    rich_python ⊇ lean. Critical for the orchestrator's tier-selection
    logic (model picks the smallest sufficient tier; we must believe
    that 'sufficient' actually means everything below is included)."""
    assert LEAN_PREINSTALLED <= RICH_PYTHON_PREINSTALLED
    assert RICH_PYTHON_PREINSTALLED <= ML_TOOLS_PREINSTALLED


def test_preinstalled_by_tier_keys_match_image_hints() -> None:
    """PREINSTALLED_BY_TIER keys must match the canonical
    SANDBOX_IMAGE_HINTS tuple. Divergence would cause `compute` to
    fall back to lean's set for unknown tiers, even when those tiers
    are valid."""
    from dast.sandbox.client import SANDBOX_IMAGE_HINTS

    assert set(PREINSTALLED_BY_TIER.keys()) == set(SANDBOX_IMAGE_HINTS)


def test_import_to_pkg_mappings_only_target_real_pypi_names() -> None:
    """Sanity: every mapping in IMPORT_TO_PKG points to a name
    that passes the safety regex. Catches accidental typos that
    would inject shell metacharacters."""
    from preprocessing.imports import _is_safe_pkg_name

    for import_name, pip_name in IMPORT_TO_PKG.items():
        assert _is_safe_pkg_name(pip_name), (
            f"Unsafe pip name in IMPORT_TO_PKG: {import_name} -> {pip_name}"
        )


# ── PEP-503 normalization (P2a v0.3) ───────────────────────────────────────


def test_normalize_pypi_name_lowercases() -> None:
    """Pillow → pillow."""
    from preprocessing.imports import normalize_pypi_name

    assert normalize_pypi_name("Pillow") == "pillow"
    assert normalize_pypi_name("PyJWT") == "pyjwt"


def test_normalize_pypi_name_collapses_separators() -> None:
    """``-``, ``_``, ``.`` (and runs of them) all collapse to a single ``-``."""
    from preprocessing.imports import normalize_pypi_name

    assert normalize_pypi_name("scikit_learn") == "scikit-learn"
    assert normalize_pypi_name("scikit-learn") == "scikit-learn"
    assert normalize_pypi_name("zope.interface") == "zope-interface"
    assert normalize_pypi_name("foo__bar") == "foo-bar"
    assert normalize_pypi_name("foo-_-bar") == "foo-bar"


def test_normalize_pypi_name_empty() -> None:
    """Empty / None-ish input safely returns empty string."""
    from preprocessing.imports import normalize_pypi_name

    assert normalize_pypi_name("") == ""


# ── Allowlist + partition (P2a v0.3) ───────────────────────────────────────


def test_allowlist_entries_are_normalized() -> None:
    """Every entry in PYPI_TOP_ALLOWLIST must already be PEP-503
    normalized. Otherwise the membership check after normalize_pypi_name
    would silently miss entries."""
    from preprocessing.imports import PYPI_TOP_ALLOWLIST, normalize_pypi_name

    for entry in PYPI_TOP_ALLOWLIST:
        assert normalize_pypi_name(entry) == entry, (
            f"Allowlist entry {entry!r} is not normalized "
            f"(should be {normalize_pypi_name(entry)!r})"
        )


def test_partition_empty() -> None:
    """Empty input → two empty lists."""
    from preprocessing.imports import partition_runtime_packages

    assert partition_runtime_packages([]) == ([], [])


def test_partition_allowlisted_only() -> None:
    """All inputs in the allowlist → all in with_deps, none in no_deps."""
    from preprocessing.imports import partition_runtime_packages

    no_deps, with_deps = partition_runtime_packages(["requests", "selenium"])
    assert no_deps == []
    assert with_deps == ["requests", "selenium"]


def test_partition_non_allowlisted_only() -> None:
    """No input in the allowlist → all in no_deps, none in with_deps.

    Uses fake names that definitely aren't in the curated list.
    """
    from preprocessing.imports import partition_runtime_packages

    no_deps, with_deps = partition_runtime_packages(["acme-corp-internal", "xyz-payload"])
    assert no_deps == ["acme-corp-internal", "xyz-payload"]
    assert with_deps == []


def test_partition_mixed() -> None:
    """Mixed input goes to the right side based on allowlist membership."""
    from preprocessing.imports import partition_runtime_packages

    no_deps, with_deps = partition_runtime_packages(
        ["selenium", "acme-corp-internal", "requests", "xyz-payload"]
    )
    assert no_deps == ["acme-corp-internal", "xyz-payload"]
    assert with_deps == ["requests", "selenium"]


def test_partition_normalization_round_trip() -> None:
    """Inputs that need normalization should still match the allowlist.

    ``scikit_learn`` (underscore) normalizes to ``scikit-learn``, which
    is in the allowlist — so the with_deps side should pick it up.
    """
    from preprocessing.imports import partition_runtime_packages

    no_deps, with_deps = partition_runtime_packages(["scikit_learn", "Pillow"])
    # Original casing preserved in the output (pip normalizes on its end).
    assert no_deps == []
    assert sorted(with_deps) == ["Pillow", "scikit_learn"]


def test_partition_preserves_original_casing() -> None:
    """The function returns the original-case names; pip does its own
    normalization on the sandbox side, so callers don't lose info."""
    from preprocessing.imports import partition_runtime_packages

    _, with_deps = partition_runtime_packages(["Selenium"])
    assert "Selenium" in with_deps  # original casing preserved


def test_partition_sorts_deterministically() -> None:
    """Both output lists are sorted for stable plan hashing."""
    from preprocessing.imports import partition_runtime_packages

    no_deps, with_deps = partition_runtime_packages(
        ["selenium", "requests", "zzz-payload", "aaa-payload"]
    )
    assert no_deps == sorted(no_deps)
    assert with_deps == sorted(with_deps)


def test_partition_own_dist_routed_to_with_deps_v1510() -> None:
    """v15.10 (2026-05-20): own_dist_name routes the matching pkg to
    the with-deps bucket so its transitive deps actually install.

    Reproduces the WCtesting failure: ``pip install --no-deps
    readme-renderer`` succeeded but the BP harness died on
    ``ModuleNotFoundError: No module named 'pygments'`` because
    pygments wasn't installed alongside. With v15.10, when own_dist
    matches readme-renderer the install goes through the with-deps
    path and pygments comes along.
    """
    from preprocessing.imports import partition_runtime_packages

    # readme-renderer is NOT in PYPI_TOP_ALLOWLIST, so without
    # own_dist_name it goes to no_deps.
    no_deps, with_deps = partition_runtime_packages(["readme-renderer"])
    assert no_deps == ["readme-renderer"]
    assert with_deps == []

    # With own_dist_name matching, it routes to with_deps.
    no_deps, with_deps = partition_runtime_packages(
        ["readme-renderer"], own_dist_name="readme-renderer"
    )
    assert no_deps == []
    assert with_deps == ["readme-renderer"]


def test_partition_own_dist_normalizes_when_routing() -> None:
    """v15.10: name normalization applies to own_dist matching.

    ``readme_renderer`` (underscore) and ``readme-renderer`` (dash)
    are PEP-503 equivalent; either form should match own_dist."""
    from preprocessing.imports import partition_runtime_packages

    no_deps, with_deps = partition_runtime_packages(
        ["readme_renderer"], own_dist_name="readme-renderer"
    )
    assert no_deps == []
    assert with_deps == ["readme_renderer"]


def test_partition_own_dist_does_not_promote_others() -> None:
    """v15.10 boundary: only the pkg matching own_dist gets promoted;
    other non-allowlisted pkgs in the list still go no-deps."""
    from preprocessing.imports import partition_runtime_packages

    no_deps, with_deps = partition_runtime_packages(
        ["readme-renderer", "selenium", "zzz-attacker"],
        own_dist_name="readme-renderer",
    )
    # readme-renderer -> own_dist match -> with_deps
    # selenium -> in allowlist -> with_deps
    # zzz-attacker -> neither -> no_deps
    assert no_deps == ["zzz-attacker"]
    assert sorted(with_deps) == ["readme-renderer", "selenium"]


# ── _build_env env var emission (P2a v0.3) ─────────────────────────────────


def test_partition_env_helper_empty() -> None:
    """No runtime packages → both env vars are empty strings (caller's
    filter drops them from the final env block)."""
    from dast.sandbox.client import _partition_env

    out = _partition_env([])
    assert out == {"RUNTIME_PACKAGES": "", "RUNTIME_PACKAGES_ALLOWLISTED": ""}


def test_partition_env_helper_mixed() -> None:
    """Mixed list emits both env vars correctly populated."""
    from dast.sandbox.client import _partition_env

    out = _partition_env(["selenium", "acme-corp-internal", "requests"])
    assert out["RUNTIME_PACKAGES"] == "acme-corp-internal"
    # with_deps is sorted: requests then selenium
    assert out["RUNTIME_PACKAGES_ALLOWLISTED"] == "requests selenium"


def test_partition_env_helper_only_allowlisted() -> None:
    """All allowlisted → RUNTIME_PACKAGES empty, _ALLOWLISTED populated."""
    from dast.sandbox.client import _partition_env

    out = _partition_env(["selenium"])
    assert out["RUNTIME_PACKAGES"] == ""
    assert out["RUNTIME_PACKAGES_ALLOWLISTED"] == "selenium"


def test_partition_env_helper_only_no_deps() -> None:
    """All non-allowlisted → RUNTIME_PACKAGES populated, _ALLOWLISTED empty."""
    from dast.sandbox.client import _partition_env

    out = _partition_env(["acme-corp-internal"])
    assert out["RUNTIME_PACKAGES"] == "acme-corp-internal"
    assert out["RUNTIME_PACKAGES_ALLOWLISTED"] == ""
