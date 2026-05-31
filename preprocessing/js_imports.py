"""Extract JS / Node imports for per-scan sandbox dep installation.

JS analogue of :mod:`preprocessing.imports`. When the target ``.js`` /
``.mjs`` / ``.cjs`` file under DAST scan ``require()``s or ``import``s
third-party npm packages that aren't preinstalled, Phase B+ runtime
probe and Phase 3 hypotheses fail with module-not-found errors at
harness import time. This module parses the target's actual imports
and produces a deterministic list of npm package names to install in
the sandbox before plan execution.

Security contract
-----------------
We ``npm install`` packages NAMED by the malicious file we're
scanning. The threat surface is DIFFERENT from pip's:

  * pip's primary risk is "transitive deps pull in surprise payloads"
    → mitigated with ``--no-deps`` (refuses transitives entirely).
  * npm's primary risk is "postinstall script runs arbitrary code
    during ``npm install``" → mitigated with ``--ignore-scripts``
    (kills ALL package lifecycle hooks: preinstall, install,
    postinstall, prepare).

For npm, transitives without scripts are essentially benign — pip's
allowlist-vs-no-deps split (P2a v0.3) doesn't have a clean analogue.
We install with ``--ignore-scripts`` + transitive resolution; the
single switch covers the realistic threat.

Additional defenses:

  * **Imports only** — packages extracted from ``require()`` /
    ``import`` syntax in the file's source. We do NOT read
    ``package.json`` (attacker-controlled), ``yarn.lock``,
    ``pnpm-lock.yaml``, etc.
  * **Built-ins filter** — Node 20 LTS built-ins (bare names + ``node:``
    prefix + ``/promises`` / ``/strict`` subpaths) and relative paths
    are dropped. Cuts pointless installs and the attack surface.
  * **Bounded count + name validation** — cap at 20 packages per
    scan; reject names that fail npm's name regex or look like shell
    metacharacters.

API
---
  * ``extract_js_imports(source: str) -> set[str]`` — top-level npm
    package names referenced by ``require`` / ``import`` statements.
  * ``compute_npm_packages(source, *, max_packages) -> list[str]`` —
    full filter pipeline; the canonical entry point for the
    orchestrator.
  * ``npm_packages_for_plan(file_bytes, file_name, enabled) ->
    list[str]`` — orchestrator-facing helper analogous to
    ``runtime_packages_for_plan``.

All return empty / empty list on any parse failure (malformed input
must never crash the cascade).
"""

from __future__ import annotations

import os
import re

# ── Node 20 LTS built-in modules ──────────────────────────────────────────
#
# Source: https://nodejs.org/docs/latest-v20.x/api/modules.html#core-modules
# (exhaustive list as of Node 20). Each appears here in three forms we
# need to filter:
#
#   1. The bare name (e.g., ``fs``)
#   2. The ``node:`` prefix form (e.g., ``node:fs``) — explicit
#      built-in syntax, available since Node 16
#   3. The subpath promise / strict / web / consumers / posix / win32
#      variants (e.g., ``fs/promises``, ``assert/strict``)
#
# We materialize all three forms into a single set so the filter is a
# constant-time check. Lookup uses the import string EXACTLY as it
# appeared in source (after we strip quotes / unwrap the require()
# call), so we don't need to re-strip anything here.
_NODE_BUILTINS_BASE: frozenset[str] = frozenset(
    {
        "assert",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "constants",
        "crypto",
        "dgram",
        "diagnostics_channel",
        "dns",
        "domain",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "inspector",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "repl",
        "stream",
        "string_decoder",
        "sys",
        "timers",
        "tls",
        "trace_events",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
    }
)

# Subpath variants that are documented as part of the built-in surface.
# Generated combinatorially rather than enumerated, since the set is
# stable and the rule is "<base>/<subpath>".
_NODE_BUILTIN_SUBPATHS: frozenset[str] = frozenset(
    {
        "assert/strict",
        "dns/promises",
        "fs/promises",
        "path/posix",
        "path/win32",
        "readline/promises",
        "stream/consumers",
        "stream/promises",
        "stream/web",
        "timers/promises",
        "util/types",
    }
)


def _build_builtin_set() -> frozenset[str]:
    """Return the full set of strings that should match as Node built-ins
    against an import source.

    Three forms per base:
      * ``X``         — bare name
      * ``node:X``    — explicit prefix
      * (if applicable) subpath variants
    """
    out: set[str] = set()
    for base in _NODE_BUILTINS_BASE:
        out.add(base)
        out.add(f"node:{base}")
    for sp in _NODE_BUILTIN_SUBPATHS:
        out.add(sp)
        out.add(f"node:{sp}")
    return frozenset(out)


NODE_BUILTINS: frozenset[str] = _build_builtin_set()


# ── Image-preinstalled npm packages ───────────────────────────────────────
#
# Currently EMPTY. The sandbox images (lean / rich_python / ml_tools as
# of v1.8 P2b) have Node.js + npm but no preinstalled npm packages.
# All non-built-in imports go through the per-scan installer.
#
# If profiling shows certain packages installing on a large fraction of
# scans, add them here AND to the Dockerfile npm install block. The
# filter saves a few seconds per scan; trade against image-size cost.
PREINSTALLED_NPM: frozenset[str] = frozenset()


# ── Heavy-package denylist (v1.9) ─────────────────────────────────────────
#
# Empirically observed to exceed the 180s ``timeout npm install ...``
# budget in ``dast-init.sh``. Each of these monorepo / workspace-style
# packages pulls a transitive tree (hundreds of nested deps) that does
# NOT finish on a cold Firecracker machine even with the v1.9 long-poll
# extending wait to 300s + boot/harness budget. Result before this
# denylist: machines reached the wait budget, got killed mid-install,
# produced ``is_stub_no_trace=true`` for every hypothesis.
#
# Policy: **refuse fast** instead of timing out. When a file imports
# any of these, ``compute_npm_packages`` raises ``HeavyDepRefused``
# which the orchestrator catches and translates into a ``not_testable``
# plan with reason ``heavy_dependency_refused``. Operator sees a clear
# rejection (~50 ms after triage) instead of a 10-minute wait followed
# by a confusing FlyMachinesError.
#
# Entries here should ONLY be packages where the install reliably
# exceeds budget — not packages we dislike. Adding a package to this
# list permanently disables DAST runtime probing for any file that
# imports it (L1 + Phase A planning still run; only sandbox execution
# is skipped). Operators wanting to override pass
# ``ARGUS_NPM_HEAVY_DENYLIST_DISABLE=true`` or remove specific entries
# via ``ARGUS_NPM_HEAVY_DENYLIST_REMOVE=pkg1,pkg2``.
#
# Sources of entries (each verified to time out at 180s):
#   * ``flowise-components`` — Flowise's internal components package;
#     pulls langchain + many integration SDKs (~1500 transitive deps).
#   * ``n8n-workflow`` / ``@n8n/n8n-workflow`` — n8n's core workflow
#     engine package; pulls the full n8n integration set.
#   * ``@n8n/client-oauth2`` / ``@n8n/ai-utilities`` — n8n monorepo
#     workspace packages; trigger npm to fall through to the public
#     registry which doesn't have them in the published form they need.
#   * ``@modelcontextprotocol/sdk`` — heavy SDK with optional deps tree.
_HEAVY_NPM_DENYLIST_BASE: frozenset[str] = frozenset({
    "flowise-components",
    "n8n-workflow",
    "@n8n/n8n-workflow",
    "@n8n/client-oauth2",
    "@n8n/ai-utilities",
    "@modelcontextprotocol/sdk",
})


def _resolve_heavy_denylist() -> frozenset[str]:
    """Compute the active heavy-package denylist at call time.

    Reads env vars for operator overrides:
      * ``ARGUS_NPM_HEAVY_DENYLIST_DISABLE=true`` — disables the whole
        list (DAST will attempt heavy installs and likely time out).
      * ``ARGUS_NPM_HEAVY_DENYLIST_REMOVE=pkg1,pkg2`` — removes specific
        entries from the base list (useful when an operator's setup
        has a fast mirror / pre-cached layer).
      * ``ARGUS_NPM_HEAVY_DENYLIST_ADD=pkg1,pkg2`` — adds operator-
        discovered heavy packages.

    Resolved fresh on each call so tests can monkeypatch env without
    module-level cache invalidation.
    """
    if os.environ.get("ARGUS_NPM_HEAVY_DENYLIST_DISABLE", "").lower() in (
        "true", "1", "yes",
    ):
        return frozenset()
    base = set(_HEAVY_NPM_DENYLIST_BASE)
    remove_raw = os.environ.get("ARGUS_NPM_HEAVY_DENYLIST_REMOVE", "")
    if remove_raw:
        for name in remove_raw.split(","):
            base.discard(name.strip())
    add_raw = os.environ.get("ARGUS_NPM_HEAVY_DENYLIST_ADD", "")
    if add_raw:
        for name in add_raw.split(","):
            stripped = name.strip()
            if stripped and _is_safe_npm_name(stripped):
                base.add(stripped)
    return frozenset(base)


class HeavyDepRefused(Exception):
    """Raised by ``compute_npm_packages`` when the import set contains a
    package on the heavy-denylist.

    Carries the offending package name(s) on the ``packages`` attribute
    so the orchestrator can surface them in the ``not_testable`` plan's
    rationale (operator sees exactly WHY DAST refused).
    """

    def __init__(self, packages: list[str]) -> None:
        self.packages = sorted(packages)
        msg = (
            f"DAST refusing npm install: file imports {self.packages} "
            f"which exceed the 180s install budget. Override with "
            f"ARGUS_NPM_HEAVY_DENYLIST_DISABLE=true or "
            f"ARGUS_NPM_HEAVY_DENYLIST_REMOVE={','.join(self.packages)}."
        )
        super().__init__(msg)


# ── npm package name validation ───────────────────────────────────────────
#
# npm's actual spec (https://github.com/npm/validate-npm-package-name):
#   * Length 1-214
#   * Lowercase letters / digits / hyphens / underscores / dots
#   * Optional ``@scope/`` prefix (scoped packages)
#   * Cannot start with ``.`` or ``_``
#   * Cannot contain spaces or special chars except ``-_.``
#
# We're STRICTER — defense against shell metacharacters in the
# RUNTIME_NPM_PACKAGES env var that gets word-split by bash before
# being passed to ``npm install``. No ``;``, no ``$``, no backtick,
# no ``--`` (which npm would interpret as a flag).
_VALID_NPM_NAME = re.compile(
    r"^(?:@[a-z0-9][a-z0-9\-_]{0,213}\/)?[a-z0-9][a-z0-9\-_.]{0,213}$"
)


def _is_safe_npm_name(name: str) -> bool:
    """True iff ``name`` is shell-safe and matches npm naming conventions."""
    if not name or len(name) > 214:
        return False
    if name.startswith("-"):
        return False  # never let a name look like an npm flag
    if name.startswith(".") or name.startswith("_"):
        return False  # npm refuses these too
    return bool(_VALID_NPM_NAME.match(name))


# ── Comment stripping ─────────────────────────────────────────────────────
#
# Production-grade JS parsing in pure Python is hard (esprima-python /
# pyjsparser are abandoned, and shelling out to Node adds infrastructure
# we don't want in the preprocessing pipeline). We use a regex-based
# extractor instead, but FIRST strip comments — that eliminates the
# largest class of import false matches (commented-out ``require``
# lines).
#
# DESIGN DECISION — we deliberately do NOT strip the CONTENTS of string
# literals. Reasoning:
#
#   * The import-target string IS itself a string literal (``'axios'``).
#     Blanking string contents would erase the package name we're
#     trying to extract.
#   * False positives from package names embedded in unrelated string
#     literals (e.g., a docstring containing the literal text
#     ``require('extra-pkg')``) are SECURITY-NEUTRAL given the npm
#     installer uses ``--ignore-scripts``. The "extra-pkg" gets
#     installed but no postinstall fires, no code runs. Worst case:
#     wasted install time + disk space.
#   * A real parser (acorn via subprocess) would eliminate even this
#     false-positive class, but the complexity isn't justified.
#
# Strategy: walk the source character-by-character, tracking whether
# we're inside a comment. Replace comment regions with spaces
# (preserving offsets / newlines). Strings pass through untouched.
# Then run import regexes against the cleaned source.


def _strip_comments(source: str) -> str:
    """Return ``source`` with all comment contents replaced by spaces,
    preserving offsets.

    Handles:
      * Line comments ``// ...``
      * Block comments ``/* ... */``

    String literals (``'...'`` / ``"..."`` / ``` `...` ```) pass
    through untouched so their interior is available for import-target
    matching. The walker tracks string-literal regions ONLY to avoid
    spuriously interpreting ``/`` inside a string as the start of a
    comment.

    Always succeeds — malformed input (unterminated comment, etc.)
    just leaves the rest of the buffer as spaces, which is still safe
    for downstream consumption.
    """
    if not source:
        return ""
    out: list[str] = []
    n = len(source)
    i = 0
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        # Line comment
        if ch == "/" and nxt == "/":
            out.append("  ")
            i += 2
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # Block comment
        if ch == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n - 1 and not (source[i] == "*" and source[i + 1] == "/"):
                # Preserve newlines so line numbers don't drift in
                # downstream diagnostics.
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            if i < n - 1:
                out.append("  ")
                i += 2
            else:
                # Unterminated block comment — bail safely.
                while i < n:
                    out.append(" ")
                    i += 1
            continue
        # String literal — copy through verbatim. We track the region
        # only so that a ``//`` or ``/*`` inside a string doesn't
        # trigger comment stripping.
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(quote)
            i += 1
            while i < n:
                if source[i] == "\\":
                    # Escape sequence: copy both chars verbatim.
                    out.append(source[i])
                    if i + 1 < n:
                        out.append(source[i + 1])
                    i += 2
                    continue
                if source[i] == quote:
                    out.append(quote)
                    i += 1
                    break
                out.append(source[i])
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# ── Import-extraction regexes ─────────────────────────────────────────────
#
# These run against the cleaned source (no comments, no string-literal
# contents — but the STRING DELIMITERS themselves are preserved so we
# can match the literal-quote-then-name pattern).
#
# Capture groups (each regex): group 1 is the import target.
#
# We do NOT try to handle:
#   * Dynamic ``require(varname)`` / ``import(varname)`` (can't
#     statically resolve)
#   * Template literals with interpolation: ``require(`foo${x}`)``
#   * Computed property reads: ``require['foo']``
# Those represent <1% of real-world packages and graceful failure
# means the harness fails at import time, not at preprocessing.
_RE_REQUIRE = re.compile(
    r"""(?<![A-Za-z0-9_$])require\s*\(\s*(['"])([^'"\n]+)\1\s*\)"""
)
_RE_IMPORT_FROM = re.compile(
    r"""(?m)^\s*import\s+(?:[^;'"]*\s+from\s+)?(['"])([^'"\n]+)\1"""
)
_RE_IMPORT_BARE = re.compile(
    r"""(?m)^\s*import\s+(['"])([^'"\n]+)\1"""
)
_RE_IMPORT_DYNAMIC = re.compile(
    r"""(?<![A-Za-z0-9_$])import\s*\(\s*(['"])([^'"\n]+)\1\s*\)"""
)
# v15 (2026-05-19): re-export form. Modern TS/JS barrel files
# (``runtime/index.ts`` patterns) commonly do:
#     export * from './http';
#     export { Base } from './rest/base';
#     export { default as Crypto } from './crypto';
# Pre-v15 the extractor missed all of these, dropping transitive
# deps that the runtime probe needs to load the target — Phase B+
# then aborted with "Cannot find module './crypto'" before
# enumerating any callable. This regex catches all three forms.
_RE_EXPORT_FROM = re.compile(
    r"""(?m)^\s*export\s+(?:\*|\{[^}]*\})\s+(?:as\s+\w+\s+)?from\s+(['"])([^'"\n]+)\1"""
)


def _is_relative(import_str: str) -> bool:
    """True iff the import is a relative or absolute path, not a
    package reference.

    Examples:
      ``./foo``, ``../foo``, ``/abs/path`` → True (skip)
      ``foo``, ``@scope/foo``, ``foo/bar`` → False (package)
    """
    if not import_str:
        return True
    if import_str.startswith(("./", "../", "/", ".\\", "..\\")):
        return True
    if import_str in (".", ".."):
        return True
    return False


def _extract_package_name(import_str: str) -> str:
    """Reduce an import path to its top-level package name.

    Examples:
      ``foo``               → ``foo``
      ``foo/bar``           → ``foo``
      ``foo/bar/baz``       → ``foo``
      ``@scope/foo``        → ``@scope/foo``  (scoped — keep full)
      ``@scope/foo/bar``    → ``@scope/foo``

    Returns ``""`` on malformed input (caller filters).
    """
    if not import_str:
        return ""
    if import_str.startswith("@"):
        # Scoped: keep ``@scope/name``, drop everything after the
        # second slash.
        parts = import_str.split("/", 2)
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return ""  # ``@scope`` alone is malformed
    return import_str.split("/", 1)[0]


# ── Public API ────────────────────────────────────────────────────────────


def extract_js_imports(source: str) -> set[str]:
    """Return top-level npm package names referenced by ``require`` /
    ``import`` statements in JS source.

    Pipeline:
      1. Strip comments + string-literal contents (false-positive
         elimination).
      2. Apply ``require()`` + ``import ... from`` + ``import 'X'`` +
         ``import('X')`` regexes.
      3. Filter Node built-ins + relative / absolute paths.
      4. Reduce subpaths to top-level (scoped packages keep ``@scope/``).

    Returns an empty set on any parse failure (malformed input must
    never crash the cascade).
    """
    if not source:
        return set()
    try:
        cleaned = _strip_comments(source)
    except Exception:  # noqa: BLE001
        # Defensive — _strip_comments should never raise on valid str input.
        return set()

    names: set[str] = set()
    for pattern in (_RE_REQUIRE, _RE_IMPORT_FROM, _RE_IMPORT_BARE, _RE_IMPORT_DYNAMIC):
        for match in pattern.finditer(cleaned):
            raw = match.group(2)
            if _is_relative(raw):
                continue
            if raw in NODE_BUILTINS:
                continue
            pkg = _extract_package_name(raw)
            if not pkg:
                continue
            # Re-check: the top-level name itself might also be a
            # built-in (e.g., ``fs/foo`` → ``fs`` → built-in).
            if pkg in NODE_BUILTINS:
                continue
            names.add(pkg)
    return names


def compute_npm_packages(
    source: str,
    *,
    max_packages: int = 20,
) -> list[str]:
    """Produce the list of npm package names to install at sandbox
    runtime for a JS target.

    Pipeline:
      1. Extract imports via ``extract_js_imports``.
      2. **Heavy-denylist check** (v1.9): if ANY import is on the
         denylist of known-too-heavy packages
         (``_resolve_heavy_denylist``), raise :class:`HeavyDepRefused`
         so the orchestrator can mark the plan ``not_testable`` with
         reason ``heavy_dependency_refused`` instead of letting the
         sandbox burn the full wait budget on a doomed install.
      3. Drop names already preinstalled in the image
         (``PREINSTALLED_NPM`` — currently empty; reserved for future
         baseline preinstalls).
      4. Reject names that fail ``_is_safe_npm_name`` (npm spec +
         shell-safety defense).
      5. Sort deterministically (stable plan-ID hashing).
      6. Cap at ``max_packages``.

    Args:
        source: JS source text of the target file. Empty / malformed
            input returns ``[]``.
        max_packages: Upper bound on the returned list. Defaults to 20
            — empirically enough for ~95% of real-world JS files and
            bounds the install-phase cost.

    Returns:
        Sorted list of npm package names (each shell-safe, each
        passing the validation regex).

    Raises:
        HeavyDepRefused: when the import set contains any package on
            the heavy-denylist. Carries the offending packages on
            ``HeavyDepRefused.packages`` so callers can surface them.
    """
    imports = extract_js_imports(source)
    if not imports:
        return []
    # Heavy-denylist check BEFORE filtering — we want the operator
    # message to reference the actual import they used, not a
    # post-filter version.
    denylist = _resolve_heavy_denylist()
    matched = sorted(imports & denylist)
    if matched:
        raise HeavyDepRefused(packages=matched)
    imports -= PREINSTALLED_NPM
    safe = {n for n in imports if _is_safe_npm_name(n)}
    return sorted(safe)[:max_packages]


def npm_packages_for_plan(
    *,
    file_bytes: bytes,
    file_name: str,
    enabled: bool,
) -> list[str]:
    """Convenience wrapper for plan-build sites: returns the
    ``SandboxPlan.runtime_npm_packages`` value given the orchestrator's
    state.

    Returns an empty list (= no install) when any gate fails:
      * ``enabled`` is False (config opt-out)
      * file is not JS (``.js`` / ``.mjs`` / ``.cjs`` suffix)
      * source can't be decoded as UTF-8

    Otherwise computes packages via ``compute_npm_packages``.

    Distinct from the Python helper:
      * No image_hint gate — npm install runs in any tier (the sandbox
        images all have Node + npm in ``lean`` and inherit upward).
        Tier auto-bump for JS targets happens in
        ``MultiImageSandboxClient.submit`` based on the same signal
        the Python path uses (non-empty install list → bump lean →
        rich_python). TS targets do NOT auto-bump (rich_python has no
        tsx; the sandbox-client suppresses the bump for .ts/.tsx).
      * TypeScript supported as of v10 (2026-05-16): .ts/.tsx files
        use the same ``import ... from`` regex extraction (TS uses
        identical syntax), so ``extract_js_imports`` works on TS
        source unchanged. tsx (in lean image) handles transpilation
        at runtime; missing npm deps install via the same dast-init.sh
        ``RUNTIME_NPM_PACKAGES`` hook.
    """
    if not enabled:
        return []
    fn_lower = (file_name or "").lower()
    # v10: .ts/.tsx added. Same ``import ... from`` syntax → same
    # extractor → same npm install hook.
    if not (
        fn_lower.endswith(".js")
        or fn_lower.endswith(".mjs")
        or fn_lower.endswith(".cjs")
        or fn_lower.endswith(".ts")
        or fn_lower.endswith(".tsx")
    ):
        return []
    try:
        source = file_bytes.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return []
    # NOTE: HeavyDepRefused propagates up to the orchestrator on
    # purpose. Callers that want a "best-effort list" instead should
    # catch and continue; the orchestrator catches and translates to
    # a not_testable plan with rationale referencing the refused
    # packages. We don't swallow it here because that would silently
    # downgrade the plan to "no deps" and let the sandbox try to
    # run a harness against unsatisfied imports — strictly worse
    # than the explicit refusal.
    return compute_npm_packages(source)


__all__ = [
    "HeavyDepRefused",
    "NODE_BUILTINS",
    "PREINSTALLED_NPM",
    "compute_npm_packages",
    "extract_js_imports",
    "npm_packages_for_plan",
]
