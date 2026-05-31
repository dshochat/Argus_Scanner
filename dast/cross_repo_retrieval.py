"""DAST-303 Slice 2 — cross-repo tarball download + variant-judge triage.

Phase B of the cross-repo hunt: given a list of :class:`CandidateFile`
records returned by :mod:`dast.code_index.github_search` (Slice 1.7),
download each containing repo as a tarball pinned to the commit the
search indexed, extract to a local cache, and feed the candidate
file PLUS its resolved imports into the existing Phase D variant
judge so the LLM can reason about cross-file dataflow (e.g., guards
that live in a service or utility module the candidate imports).

Why tarball instead of per-file raw fetch (v1 of Slice 2):

  Single-file fetches couldn't see cross-file guards. The Flowise
  ``/fetch-links`` controller scored 0.60 as a false positive because
  the judge couldn't see ``checkDenyList`` living in
  ``flowise-components/httpSecurity.ts`` two imports away. Downloading
  the full repo once gives the judge whole-file context plus the
  source of relative imports referenced near the sink line.

Pipeline::

    CandidateFile (from cross-repo discovery)
        ↓ group by (repo_full_name, ref)
    download_repo_tarball()          GET /repos/{o}/{r}/tarball/{sha}
        ↓ extract to .argus_local/cross_repo_cache/<owner>__<repo>__<sha>/
    RepoWorkspace.read_file()        reads candidate file + relative imports
        ↓
    _build_judge_context()           candidate file + resolved imports
        ↓
    Phase D variant judge            same prompt + schema as in-project
        ↓
    CrossRepoTriageResult            per-file is_match / score / rationale

Public API::

    fetch_and_triage(signature, candidates, *, inference) ->
        list[CrossRepoTriageResult]

Cost: 1 batched judge call + N tarball downloads (one per unique
repo, NOT per file — co-located candidates share a download).
Cached by commit SHA so re-runs against the same candidate set hit
the disk cache instead of re-downloading.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import tarfile
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from dast.code_index import CandidateFile

log = logging.getLogger("argus.dast.cross_repo_retrieval")


# Inference-function shape matches dast.inference.InferenceFn; we
# accept the callable structurally so this module doesn't import
# inference (which pulls in anthropic). Tests can pass a stub.
InferenceFn = Callable[
    [str, dict[str, Any], dict[str, Any] | None], Awaitable[dict[str, Any]]
]


# ── Tunables ─────────────────────────────────────────────────────────


#: Per-repo tarball size cap (compressed bytes). 100 MB is enough for
#: any real production repo's source tree without .git history;
#: filtered-out repos are typically monorepos hosting compiled
#: artifacts in-tree.
DEFAULT_MAX_TARBALL_BYTES: int = 100 * 1024 * 1024

#: Per-file size cap when reading from the extracted tree. Protects
#: against minified bundles or generated files inflating the judge
#: prompt. Larger than the v1 256 KB single-file fetch cap because
#: tarball-derived reads only run for candidate paths + their direct
#: imports — bounded set, not the whole repo.
DEFAULT_MAX_FILE_BYTES: int = 512 * 1024

#: Max snippet chars per candidate passed to the judge. The judge
#: prompt also wraps at this limit so we don't truncate twice.
MAX_SNIPPET_CHARS: int = 1200

#: Max chars of an imported-module's content to include per import.
#: Tighter than MAX_SNIPPET_CHARS because we're including N imports
#: not just one candidate — keeps the prompt bounded.
MAX_IMPORT_CHARS: int = 1500

#: Max number of resolved imports to include per candidate. Imports
#: past this limit are dropped silently (judge gets the closest N).
MAX_IMPORTS_PER_CANDIDATE: int = 4

#: Lines of context to keep on either side of a sink-callee match
#: when extracting the focused snippet for the judge's positional
#: pointer (in addition to the whole-file inclusion).
SNIPPET_CONTEXT_LINES: int = 30

#: Threshold the Slice 3 verifier will use to decide whether a
#: candidate is worth a sandbox run. Operators can override at the
#: caller. 0.5 = "partial match worth investigation" per the judge
#: rubric.
DEFAULT_TRIAGE_THRESHOLD: float = 0.5

#: HTTP timeout per tarball download.
DOWNLOAD_TIMEOUT_SEC: float = 120.0

#: Max retry attempts for transient download failures.
MAX_RETRIES: int = 3

#: Initial backoff (doubles per retry + jitter).
INITIAL_BACKOFF_SEC: float = 1.5

#: Default cache directory for downloaded tarballs + extracted trees.
#: Relative path resolved against the current working directory at
#: ``fetch_and_triage`` call time.
DEFAULT_CACHE_DIR: Path = Path(".argus_local") / "cross_repo_cache"

#: TypeScript / JavaScript file extensions resolved during import
#: lookup. Ordered by precedence (TS preferred when ambiguous).
_TS_JS_EXTENSIONS: tuple[str, ...] = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

#: Workspace package directory roots. Monorepos commonly use one of
#: these to host internal packages a candidate file can import by
#: package name (e.g., ``from 'flowise-components'``).
_WORKSPACE_DIRS: tuple[str, ...] = ("packages", "apps", "libs")

#: Regex matching ES module import statements that reference a
#: specifier. Handles both ``import x from 'spec'`` and
#: ``import 'spec'`` shapes, plus dynamic ``await import('spec')``.
_IMPORT_RE = re.compile(
    r"""
    (?:^|\s)                                # start of line or whitespace
    (?:                                     # one of:
        import\s+(?:.+?\s+from\s+)?           #   import [name from]
        |require\s*\(                         #   require(
        |import\s*\(                          #   import(
    )
    \s*['"]                                 # opening quote
    (?P<spec>[^'"\n]+?)                     # specifier
    ['"]                                    # closing quote
    """,
    re.VERBOSE | re.MULTILINE,
)


# ── Result types ─────────────────────────────────────────────────────


@dataclass
class CrossRepoFetched:
    """Slice 2 intermediate — a candidate file that's been resolved
    from a downloaded repo workspace.

    Separating workspace setup from judge invocation lets unit tests
    exercise context-building without the LLM, and lets future slices
    cache fetched content across multiple judge runs.
    """

    #: Source candidate (carries repo + path + URLs + metadata).
    candidate: CandidateFile
    #: Full candidate-file content (capped at ``DEFAULT_MAX_FILE_BYTES``).
    content: str = ""
    #: Length of the candidate-file source in bytes (pre-decode).
    content_bytes: int = 0
    #: Composed text handed to the judge: whole candidate file +
    #: resolved imports, with section headers. Empty when the
    #: ``sink_callee`` never appears in the candidate file (no
    #: positional anchor for the judge).
    snippet: str = ""
    #: 1-indexed line number of the first sink-callee occurrence in
    #: the CANDIDATE file (not the merged snippet). 0 when no
    #: occurrence found.
    first_sink_line: int = 0
    #: Imports we successfully resolved + inlined into ``snippet``.
    #: Useful for operator inspection of "did the judge actually see
    #: the guard module?"
    resolved_imports: list[str] = field(default_factory=list)
    #: Reason this candidate was NOT successfully resolved.
    #: Empty when ``snippet`` is populated; one of:
    #: ``download_failed``, ``file_not_in_tarball``, ``too_large``,
    #: ``empty_file``, ``binary_content``, ``sink_not_found``.
    skipped_reason: str = ""


@dataclass
class CrossRepoTriageResult:
    """Slice 2 output — one cross-repo candidate after triage.

    Operators see a list of these and decide which to sandbox-verify
    (Slice 3) or which to report as disclosure-worthy directly.
    """

    #: The resolved intermediate. Always populated, even on skip —
    #: the candidate field is the durable handle to the file.
    fetched: CrossRepoFetched
    #: Judge's similarity score, [0.0, 1.0]. 0.0 when the candidate
    #: was skipped before the judge ran.
    similarity_score: float = 0.0
    #: Judge's 1-sentence rationale. Empty on skip.
    rationale: str = ""
    #: Convenience: ``similarity_score >= threshold``. Set by the
    #: caller via ``triage_threshold`` arg.
    is_match: bool = False
    #: When non-empty, the judge / fetch didn't produce a verdict for
    #: this candidate. Mirrors ``CrossRepoFetched.skipped_reason`` at
    #: the top level for caller convenience.
    skipped_reason: str = ""


# ── RepoWorkspace: downloaded + extracted repo tree ──────────────────


@dataclass
class RepoWorkspace:
    """A repo tarball downloaded + extracted to local disk.

    Pinned to ``ref`` (commit SHA from the GitHub search hit), so the
    extracted tree is byte-for-byte reproducible: re-running the same
    cross-repo hunt hits the disk cache instead of re-downloading.
    """

    repo_full_name: str
    ref: str  # commit SHA or branch name pinned at download time
    root: Path  # directory where the extracted tree lives

    def read_file(
        self, repo_relative_path: str, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES
    ) -> str | None:
        """Read a file from the workspace. Returns its decoded text
        or ``None`` when:

          * The path doesn't exist in the workspace (file deleted or
            renamed since the search was indexed).
          * The file is larger than ``max_bytes`` (too big for LLM).
          * The file looks binary (NUL bytes / high non-printable
            ratio).
        """
        # Normalize the path. GitHub returns forward-slash paths even
        # on Windows; Path handles both.
        candidate = self.root / repo_relative_path
        if not candidate.is_file():
            return None
        try:
            size = candidate.stat().st_size
        except OSError:
            return None
        if size > max_bytes:
            log.debug(
                "RepoWorkspace.read_file: skipping oversize %s (%d > %d)",
                repo_relative_path,
                size,
                max_bytes,
            )
            return None
        try:
            data = candidate.read_bytes()
        except OSError as exc:
            log.warning(
                "RepoWorkspace.read_file: I/O error reading %s: %s",
                repo_relative_path,
                exc,
            )
            return None
        if _is_likely_binary(data[:2048]):
            return None
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — pathological encodings
            return None

    def resolve_import(
        self, from_file: str, specifier: str
    ) -> str | None:
        """Resolve a JS/TS import specifier from ``from_file`` to a
        workspace-relative file path.

        Handles:
          * Relative imports (``./xyz``, ``../xyz``) — resolved
            against the importing file's directory; tries each of
            :data:`_TS_JS_EXTENSIONS` plus ``index.<ext>`` for
            directory imports.
          * Monorepo-workspace imports (e.g., ``flowise-components``,
            ``@n8n/nodes-langchain``) — resolved by scanning
            :data:`_WORKSPACE_DIRS` for a package whose ``name`` field
            in ``package.json`` matches, then mapping to its ``main``
            / ``module`` / ``src/index.<ext>``.

        Returns ``None`` for:
          * Bare external imports (``axios``, ``express``, etc.) —
            third-party deps would explode the context window.
          * Anything that doesn't resolve to a real file.

        The return value is suitable for passing back to
        :meth:`read_file`.
        """
        spec = (specifier or "").strip()
        if not spec:
            return None

        if spec.startswith("./") or spec.startswith("../") or spec.startswith("/"):
            return self._resolve_relative(from_file, spec)

        return self._resolve_workspace_package(spec)

    def _resolve_relative(self, from_file: str, spec: str) -> str | None:
        """Resolve a ``./`` or ``../`` import specifier. Tries each
        of _TS_JS_EXTENSIONS, then index.<ext> for directory imports.
        """
        from_path = Path(from_file)
        base_dir = (self.root / from_path.parent).resolve()
        target = (base_dir / spec).resolve()

        # Guard against escape from the workspace root (defensive —
        # specifier could be a pathological ``../../../etc/passwd``).
        try:
            target.relative_to(self.root.resolve())
        except ValueError:
            return None

        # If the target is a file with an extension already, use it.
        if target.is_file():
            return self._workspace_relative(target)

        # Try each extension.
        for ext in _TS_JS_EXTENSIONS:
            cand = target.with_suffix(ext)
            if cand.is_file():
                return self._workspace_relative(cand)
            cand = Path(str(target) + ext)
            if cand.is_file():
                return self._workspace_relative(cand)

        # Try directory-style imports: <spec>/index.<ext>.
        if target.is_dir():
            for ext in _TS_JS_EXTENSIONS:
                cand = target / f"index{ext}"
                if cand.is_file():
                    return self._workspace_relative(cand)

        return None

    def _resolve_workspace_package(self, spec: str) -> str | None:
        """Resolve a monorepo-internal package by looking up
        ``packages/*/package.json`` files with matching ``name``.

        Returns the package's entry file (``main`` / ``module`` /
        ``src/index.<ext>``) workspace-relative path or None.
        """
        # Speed gate: only look up packages with names that exist as
        # directory entries under one of the workspace roots — this
        # avoids walking every package.json for external imports.
        for ws_dir in _WORKSPACE_DIRS:
            ws_root = self.root / ws_dir
            if not ws_root.is_dir():
                continue
            try:
                pkg_dirs = list(ws_root.iterdir())
            except OSError:
                continue
            for pkg_dir in pkg_dirs:
                if not pkg_dir.is_dir():
                    continue
                pkg_json = pkg_dir / "package.json"
                if not pkg_json.is_file():
                    continue
                try:
                    raw = pkg_json.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                # Match the name FIELD, not directory name — workspace
                # packages can have scoped names (e.g.,
                # ``@n8n/computer-use``) different from the dir.
                if f'"name": "{spec}"' not in raw and f"'name': '{spec}'" not in raw:
                    continue
                # Pick entry: ``main`` > ``module`` > ``src/index.<ext>``.
                entry = self._extract_pkg_entry(raw)
                candidates = []
                if entry:
                    candidates.append(pkg_dir / entry)
                for ext in _TS_JS_EXTENSIONS:
                    candidates.append(pkg_dir / "src" / f"index{ext}")
                    candidates.append(pkg_dir / f"index{ext}")
                for cand in candidates:
                    if cand.is_file():
                        return self._workspace_relative(cand)
        return None

    @staticmethod
    def _extract_pkg_entry(pkg_json_text: str) -> str | None:
        """Pull ``main`` / ``module`` from a package.json text blob.
        Avoids depending on json parsing being lenient about
        comments / trailing commas seen in some monorepos."""
        for key in ("module", "main"):
            m = re.search(
                rf'"{key}"\s*:\s*"([^"]+)"', pkg_json_text
            )
            if m:
                return m.group(1)
        return None

    def _workspace_relative(self, path: Path) -> str:
        """Convert an absolute workspace path to repo-relative
        forward-slash form (matching GitHub's ``file_path``)."""
        rel = path.resolve().relative_to(self.root.resolve())
        return str(rel).replace("\\", "/")


# ── Tarball download ─────────────────────────────────────────────────


async def download_repo_tarball(
    repo_full_name: str,
    ref: str,
    *,
    client: httpx.AsyncClient,
    cache_dir: Path,
    github_token: str = "",
    max_bytes: int = DEFAULT_MAX_TARBALL_BYTES,
) -> RepoWorkspace | None:
    """Download a GitHub tarball at the given ``ref`` and extract to
    a deterministic subdirectory under ``cache_dir``.

    Cache key: ``<cache_dir>/<owner>__<repo>__<ref>/`` (a directory
    tree). When the cache hit is detected (directory exists and
    non-empty), the download is skipped — subsequent runs against
    the same candidate set are free after the first.

    Uses ``GET /repos/{owner}/{name}/tarball/{ref}``. The response
    streams a single gzipped tarball; we cap at ``max_bytes`` to
    abort gigantic monorepos before they fill the cache.

    GitHub tarball convention: the archive has a single top-level
    directory named ``<owner>-<repo>-<short-sha>/``; we strip it
    during extraction so the workspace root maps directly to repo
    paths.

    Returns ``None`` on download / extraction failure (logs the
    cause). Callers propagate to ``CrossRepoFetched.skipped_reason=
    'download_failed'``.

    Auth: pass ``github_token`` to lift the rate limit from
    60 req/hour (unauth) to 5000 req/hour (auth). Without auth a
    cross-repo batch of >60 repos hits the cap quickly.
    """
    if not repo_full_name or not ref:
        log.warning(
            "download_repo_tarball: refusing download with empty "
            "repo_full_name=%r ref=%r",
            repo_full_name,
            ref,
        )
        return None

    cache_root = _workspace_dir(cache_dir, repo_full_name, ref)
    if cache_root.is_dir() and any(cache_root.iterdir()):
        log.debug(
            "download_repo_tarball: cache hit for %s@%s at %s",
            repo_full_name,
            ref,
            cache_root,
        )
        return RepoWorkspace(
            repo_full_name=repo_full_name, ref=ref, root=cache_root
        )

    cache_dir.mkdir(parents=True, exist_ok=True)
    # Stage tar to a sibling temp path so a half-downloaded archive
    # doesn't leave the cache in a broken state.
    tar_path = cache_root.with_suffix(".staging.tar.gz")
    tar_path.parent.mkdir(parents=True, exist_ok=True)

    url = f"https://api.github.com/repos/{repo_full_name}/tarball/{ref}"
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    for attempt in range(MAX_RETRIES + 1):
        try:
            async with client.stream(
                "GET",
                url,
                headers=headers,
                follow_redirects=True,
                timeout=DOWNLOAD_TIMEOUT_SEC,
            ) as resp:
                if resp.status_code == 404:
                    log.warning(
                        "download_repo_tarball: 404 for %s@%s — repo "
                        "or ref doesn't exist",
                        repo_full_name,
                        ref,
                    )
                    return None
                if resp.status_code == 401:
                    log.warning(
                        "download_repo_tarball: 401 for %s@%s — "
                        "regenerate GITHUB_TOKEN",
                        repo_full_name,
                        ref,
                    )
                    return None
                if resp.status_code != 200:
                    if attempt < MAX_RETRIES:
                        backoff = INITIAL_BACKOFF_SEC * (2**attempt) + random.uniform(0, 1)
                        log.warning(
                            "download_repo_tarball: status %d for %s@%s "
                            "(attempt %d); backing off %.1fs",
                            resp.status_code,
                            repo_full_name,
                            ref,
                            attempt + 1,
                            backoff,
                        )
                        await asyncio.sleep(backoff)
                        continue
                    log.warning(
                        "download_repo_tarball: status %d for %s@%s "
                        "exhausted retries",
                        resp.status_code,
                        repo_full_name,
                        ref,
                    )
                    return None

                total = 0
                with open(tar_path, "wb") as f:
                    async for chunk in resp.aiter_bytes(64 * 1024):
                        f.write(chunk)
                        total += len(chunk)
                        if total > max_bytes:
                            log.warning(
                                "download_repo_tarball: %s@%s exceeds "
                                "max_bytes=%d, aborting",
                                repo_full_name,
                                ref,
                                max_bytes,
                            )
                            f.close()
                            tar_path.unlink(missing_ok=True)
                            return None
                # Success — break out of retry loop.
                break
        except (
            httpx.ConnectError,
            httpx.ReadError,
            httpx.TimeoutException,
        ) as exc:
            if attempt < MAX_RETRIES:
                backoff = INITIAL_BACKOFF_SEC * (2**attempt) + random.uniform(0, 1)
                log.warning(
                    "download_repo_tarball: transient error for %s@%s "
                    "(attempt %d): %s; backing off %.1fs",
                    repo_full_name,
                    ref,
                    attempt + 1,
                    exc,
                    backoff,
                )
                await asyncio.sleep(backoff)
                continue
            log.warning(
                "download_repo_tarball: connection failed for %s@%s "
                "after retries: %s",
                repo_full_name,
                ref,
                exc,
            )
            tar_path.unlink(missing_ok=True)
            return None
    else:
        tar_path.unlink(missing_ok=True)
        return None

    # Extract. GitHub tarballs nest everything under a single
    # top-level directory; strip it for cleaner workspace paths.
    cache_root.mkdir(parents=True, exist_ok=True)
    try:
        _extract_strip_top(tar_path, cache_root)
    except (tarfile.TarError, OSError) as exc:
        log.warning(
            "download_repo_tarball: extract failed for %s@%s: %s",
            repo_full_name,
            ref,
            exc,
        )
        # Clean up half-extracted state so the next run re-downloads
        # from scratch instead of seeing the populated cache dir.
        _rmtree_quiet(cache_root)
        tar_path.unlink(missing_ok=True)
        return None
    tar_path.unlink(missing_ok=True)

    log.info(
        "download_repo_tarball: %s@%s -> %s",
        repo_full_name,
        ref,
        cache_root,
    )
    return RepoWorkspace(
        repo_full_name=repo_full_name, ref=ref, root=cache_root
    )


def _workspace_dir(cache_dir: Path, repo_full_name: str, ref: str) -> Path:
    """Deterministic cache subdirectory for a (repo, ref) pair.

    ``owner/repo`` → ``owner__repo``; ref kept as-is (commit SHAs are
    safe in filenames; branch names like ``main`` are also safe).
    """
    safe_name = repo_full_name.replace("/", "__")
    return cache_dir / f"{safe_name}__{ref}"


def _extract_strip_top(tar_path: Path, dest_root: Path) -> None:
    """Extract a GitHub-style tarball, stripping the single top-
    level directory entry. Refuses any member whose normalized path
    escapes ``dest_root`` (tar slip defense).

    Per-file failures are LOGGED + SKIPPED rather than fatal. Windows
    in particular hits ``OSError`` on:

      * Paths exceeding MAX_PATH (260 chars) without long-path support
        enabled (e.g., deep monorepo paths like
        ``web/app/(commonLayout)/.../some-very-long-test-file.tsx``).
      * Reserved file names (``CON``, ``AUX``, etc.) — rare but real.
      * Special-char issues with ``[`` / ``(`` in some FS drivers.

    Skipping those files is safe for cross-repo triage: the candidate
    paths we care about are typically short (``src/services/x.ts``),
    while the failures are usually deep test fixtures. The extract is
    successful as long as the candidate files themselves land.
    """
    skipped = 0
    extracted = 0
    sample_errors: list[str] = []
    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf.getmembers():
            # GitHub's tarball nests everything under ``<owner>-
            # <repo>-<short-sha>/``. Strip the first path component.
            parts = member.name.split("/", 1)
            if len(parts) < 2:
                # The top-level directory entry itself — skip it.
                continue
            stripped = parts[1]
            if not stripped:
                continue
            # Defense in depth against tar slip: refuse absolute paths
            # + parent-directory escapes.
            if stripped.startswith("/") or ".." in stripped.split("/"):
                log.warning(
                    "_extract_strip_top: refusing suspicious tar "
                    "entry %r",
                    member.name,
                )
                continue
            member.name = stripped
            try:
                tf.extract(member, dest_root, filter="data")
                extracted += 1
            except (OSError, tarfile.TarError) as exc:
                skipped += 1
                if len(sample_errors) < 3:
                    sample_errors.append(f"{member.name!r}: {exc}")
    if skipped:
        log.info(
            "_extract_strip_top: %d extracted, %d skipped due to per-"
            "file errors (first %d samples: %s)",
            extracted,
            skipped,
            len(sample_errors),
            sample_errors,
        )


def _rmtree_quiet(path: Path) -> None:
    """Best-effort recursive delete. Logs but never raises."""
    if not path.exists():
        return
    try:
        for entry in path.iterdir():
            if entry.is_dir():
                _rmtree_quiet(entry)
            else:
                entry.unlink(missing_ok=True)
        path.rmdir()
    except OSError as exc:
        log.debug("_rmtree_quiet: failed to delete %s: %s", path, exc)


# ── Binary heuristic (shared with workspace.read_file) ───────────────


def _is_likely_binary(sample: bytes) -> bool:
    """Heuristic: bytes contain NUL or > 15% non-printable chars → binary.

    Tarball extracts may include images, compiled wasm, or other
    binary assets. We refuse to pass binary garbage to the LLM."""
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    text_chars = bytes(range(32, 127)) + b"\t\n\r\f\b"
    n_nontext = sum(1 for b in sample if b not in text_chars)
    return n_nontext / len(sample) > 0.15


# ── Sink-line + import extraction ────────────────────────────────────


def _find_first_sink_line(content: str, sink_callee: str) -> int:
    """Return the 1-indexed line number of the first occurrence of
    ``sink_callee`` in ``content``, or 0 if absent."""
    needle = (sink_callee or "").strip()
    if not needle:
        return 0
    for i, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return i
    return 0


def _extract_imports_near_sink(
    content: str, sink_line: int, *, max_imports: int = MAX_IMPORTS_PER_CANDIDATE
) -> list[str]:
    """Extract import specifiers from the candidate file, prioritized
    by proximity to the sink line.

    Strategy:
      1. Scan all imports + their line numbers.
      2. Sort by absolute line-distance from ``sink_line`` ascending
         (closest first).
      3. Return the top ``max_imports`` specifiers.

    Closeness matters: in a long file with 30 imports, the ones
    referenced in the function containing the sink are far more
    likely to participate in the dataflow than imports at the top
    of an unrelated module.
    """
    if not content:
        return []
    matches: list[tuple[int, str]] = []
    for m in _IMPORT_RE.finditer(content):
        spec = m.group("spec")
        if not spec:
            continue
        # Line number of the match.
        line_no = content.count("\n", 0, m.start()) + 1
        matches.append((line_no, spec))
    if not matches:
        return []
    # Sort by distance from sink_line; preserve original order for
    # ties so the first match wins.
    matches.sort(
        key=lambda lm: (abs(lm[0] - sink_line) if sink_line else lm[0], lm[0])
    )
    # Dedupe by specifier while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for _, spec in matches:
        if spec in seen:
            continue
        seen.add(spec)
        out.append(spec)
        if len(out) >= max_imports:
            break
    return out


def _build_judge_context(
    *,
    candidate_file_path: str,
    candidate_content: str,
    sink_line: int,
    workspace: RepoWorkspace,
    sink_callee: str,
) -> tuple[str, list[str]]:
    """Compose the judge-facing context blob for one candidate.

    Sections (separated by clear headers):
      1. The candidate file (whole, or capped at ``MAX_SNIPPET_CHARS``
         around the sink line if too large).
      2. Each resolved import's source (capped at ``MAX_IMPORT_CHARS``
         each), labeled with the import specifier + resolved path.

    Returns ``(composed_text, resolved_import_paths)`` — the second
    element is the list of repo-relative paths the workspace
    successfully resolved.
    """
    parts: list[str] = []

    candidate_section = _focused_candidate_section(
        candidate_file_path, candidate_content, sink_line, sink_callee
    )
    parts.append(candidate_section)

    resolved_paths: list[str] = []
    if sink_line > 0:
        specs = _extract_imports_near_sink(candidate_content, sink_line)
        for spec in specs:
            resolved_path = workspace.resolve_import(
                candidate_file_path, spec
            )
            if not resolved_path:
                continue
            imp_content = workspace.read_file(resolved_path)
            if not imp_content:
                continue
            # Truncate per-import to bound the prompt.
            if len(imp_content) > MAX_IMPORT_CHARS:
                imp_content = (
                    imp_content[:MAX_IMPORT_CHARS]
                    + "\n# ... [truncated]"
                )
            parts.append(
                f"\n--- Import: {spec!r} (resolved to {resolved_path}) ---\n"
                f"{imp_content}"
            )
            resolved_paths.append(resolved_path)

    return "\n".join(parts), resolved_paths


def _focused_candidate_section(
    path: str, content: str, sink_line: int, sink_callee: str
) -> str:
    """Emit the candidate-file section of the judge prompt.

    Strategy: if the full file fits within ``MAX_SNIPPET_CHARS`` we
    include all of it (judge gets max context). Otherwise we extract
    a window around the sink line.

    The header is a comment-style marker so the judge knows what
    portion of which file it's looking at.
    """
    header = f"--- Candidate file: {path} ---"
    if len(content) <= MAX_SNIPPET_CHARS or sink_line <= 0:
        # Small file or no sink anchor — include verbatim (or
        # truncated at the start if we somehow got here with content >
        # cap but no anchor).
        body = content if len(content) <= MAX_SNIPPET_CHARS else content[:MAX_SNIPPET_CHARS]
        return f"{header}\n{body}"

    # Windowed extraction around sink_line.
    lines = content.splitlines()
    # Pull a generous window then trim by chars.
    start = max(0, sink_line - 1 - SNIPPET_CONTEXT_LINES)
    end = min(len(lines), sink_line + SNIPPET_CONTEXT_LINES)
    window = "\n".join(lines[start:end])
    if len(window) > MAX_SNIPPET_CHARS:
        # Trim from the leading end (sink line + guards matter more
        # than imports at the top).
        window = window[-MAX_SNIPPET_CHARS:]
    note = (
        f"# Note: file is {len(content)} chars; showing window around "
        f"sink_callee {sink_callee!r} at line {sink_line}."
    )
    return f"{header}\n{note}\n{window}"


# ── Judge orchestration ──────────────────────────────────────────────


def _build_judge_candidates(
    fetched: list[CrossRepoFetched], signature: Any
) -> list[dict[str, Any]]:
    """Project resolved fetched records into the dict shape the
    Phase D variant judge expects.

    Each fetched candidate with a non-empty ``snippet`` becomes one
    judge candidate; skipped / empty records are dropped.
    """
    sink_callee_for_obs = (signature.sink_callee or "").strip()
    out: list[dict[str, Any]] = []
    for f in fetched:
        if f.skipped_reason or not f.snippet:
            continue
        identifier = f"{f.candidate.repo_full_name}/{f.candidate.file_path}"
        out.append(
            {
                "function_name": identifier,
                "line_number": f.first_sink_line,
                "source_snippet": f.snippet,
                "sink_callees_observed": (
                    [sink_callee_for_obs] if sink_callee_for_obs else []
                ),
            }
        )
    return out


async def _invoke_variant_judge(
    *,
    signature: Any,
    judge_inputs: list[dict[str, Any]],
    inference: InferenceFn,
) -> dict[str, tuple[float, str]]:
    """Run the Phase D variant judge over ``judge_inputs`` and return
    a ``{identifier: (score, rationale)}`` map.

    Reuses the existing prompt + schema from :mod:`dast.prompts`.
    Schema/JSON failures degrade gracefully — empty dict so the
    caller marks every candidate skipped rather than treating 0.0 as
    a real verdict.
    """
    if not judge_inputs:
        return {}

    from dast.prompts import (  # noqa: PLC0415
        build_phase_d_variant_judge_prompt,
        phase_d_variant_judge_schema,
    )

    sig_dict = asdict(signature) if not isinstance(signature, dict) else signature
    prompt = build_phase_d_variant_judge_prompt(
        signature=sig_dict, candidates=judge_inputs
    )
    schema = phase_d_variant_judge_schema()
    # Scale max_tokens with batch size: each ranking is ~200 tokens
    # (function_name + score + rationale + JSON framing). Hard floor
    # 2048, hard ceiling 8192 (Sonnet's output max).
    per_cand_tokens = 200
    max_tokens = max(
        2048, min(8192, 1024 + per_cand_tokens * len(judge_inputs))
    )
    resp = await inference(
        prompt,
        {"temperature": 0.0, "max_tokens": max_tokens, "seed": 0},
        schema,
    )

    if not resp.get("schema_valid", True):
        log.warning(
            "Cross-repo variant judge returned invalid schema: %s",
            resp.get("schema_error", ""),
        )
        return {}

    import json as _json  # noqa: PLC0415

    try:
        parsed = _json.loads(resp.get("text") or "{}")
    except _json.JSONDecodeError as exc:
        log.warning("Cross-repo variant judge JSON decode failed: %s", exc)
        return {}

    by_name: dict[str, tuple[float, str]] = {}
    for r in parsed.get("rankings") or []:
        if not isinstance(r, dict):
            continue
        name = str(r.get("function_name") or "")
        try:
            score = float(r.get("similarity_score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        rationale = str(r.get("rationale") or "")
        if name:
            by_name[name] = (max(0.0, min(1.0, score)), rationale)
    return by_name


# ── Public API ───────────────────────────────────────────────────────


async def fetch_and_triage(
    signature: Any,
    candidates: list[CandidateFile],
    *,
    inference: InferenceFn,
    cache_dir: Path | str | None = None,
    triage_threshold: float = DEFAULT_TRIAGE_THRESHOLD,
    github_token: str = "",
    max_concurrent_downloads: int = 4,
    max_tarball_bytes: int = DEFAULT_MAX_TARBALL_BYTES,
) -> list[CrossRepoTriageResult]:
    """Slice 2 entry point — tarball download + cross-file triage.

    Pipeline:

      1. Group candidates by ``(repo_full_name, ref)``.
      2. For each unique repo+ref, download the tarball at the pinned
         commit and extract to ``cache_dir`` (defaults to
         ``.argus_local/cross_repo_cache``). Cache hits skip the
         download.
      3. For each candidate, read its full source from the workspace
         + resolve up to ``MAX_IMPORTS_PER_CANDIDATE`` imports near
         the sink line. Each resolved import's source is inlined into
         the judge context, labeled with its specifier + resolved
         path.
      4. ONE batched LLM call runs the Phase D variant judge with the
         enriched context, returning per-candidate similarity scores.

    Args:
      signature: a :class:`SemanticSignature`. The judge uses every
        field to score candidates.
      candidates: cross-repo candidate files (typically the output of
        :meth:`GitHubCodeSearchClient.discover_and_search`).
      inference: async callable matching :data:`InferenceFn`. Wrap a
        production model via :func:`dast.inference.
        make_dast_sonnet_inference`.
      cache_dir: tarball cache root. ``None`` resolves to
        ``DEFAULT_CACHE_DIR``. Accepts ``str`` or ``Path``.
      triage_threshold: similarity-score threshold for
        ``is_match=True``.
      github_token: GitHub PAT for tarball downloads. Strongly
        recommended — unauth caps at 60/hour, auth at 5000/hour.
      max_concurrent_downloads: parallelism cap for tarball downloads
        (each is ~5-50 MB). Default 4 = sane balance of speed and
        disk pressure.
      max_tarball_bytes: per-repo compressed-size cap. Default
        100 MB; bump for monorepos that include vendored deps.

    Returns one :class:`CrossRepoTriageResult` per input candidate,
    in input order. Failures (download error, missing file, judge
    schema error) populate ``skipped_reason`` without taking down
    the batch.
    """
    if not candidates:
        return []

    resolved_cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
    resolved_cache_dir.mkdir(parents=True, exist_ok=True)

    # Group candidates by (repo, ref) so each unique repo+commit gets
    # ONE tarball download, regardless of how many of its files were
    # surfaced as candidates.
    by_repo: dict[tuple[str, str], list[CandidateFile]] = {}
    for c in candidates:
        key = (c.repo_full_name, c.ref)
        by_repo.setdefault(key, []).append(c)

    log.info(
        "Slice 2 fetch_and_triage: %d candidates across %d unique repos",
        len(candidates),
        len(by_repo),
    )

    # Download workspaces in parallel.
    sem = asyncio.Semaphore(max(1, max_concurrent_downloads))
    workspaces: dict[tuple[str, str], RepoWorkspace | None] = {}
    async with httpx.AsyncClient() as client:

        async def _dl(repo: str, ref: str) -> RepoWorkspace | None:
            async with sem:
                return await download_repo_tarball(
                    repo,
                    ref,
                    client=client,
                    cache_dir=resolved_cache_dir,
                    github_token=github_token,
                    max_bytes=max_tarball_bytes,
                )

        keys = list(by_repo)
        results = await asyncio.gather(*(_dl(r, s) for (r, s) in keys))
        workspaces = dict(zip(keys, results, strict=True))

    sink_callee = (signature.sink_callee or "").strip()

    # Build per-candidate fetched records (CPU work, no I/O).
    fetched: list[CrossRepoFetched] = []
    for cand in candidates:
        ws = workspaces.get((cand.repo_full_name, cand.ref))
        f = CrossRepoFetched(candidate=cand)
        if ws is None:
            f.skipped_reason = "download_failed"
            fetched.append(f)
            continue

        content = ws.read_file(cand.file_path)
        if content is None:
            f.skipped_reason = "file_not_in_tarball"
            fetched.append(f)
            continue

        f.content = content
        f.content_bytes = len(content.encode("utf-8", errors="replace"))

        sink_line = _find_first_sink_line(content, sink_callee)
        if sink_line == 0:
            f.skipped_reason = "sink_not_found"
            fetched.append(f)
            continue
        f.first_sink_line = sink_line

        composed, resolved_imports = _build_judge_context(
            candidate_file_path=cand.file_path,
            candidate_content=content,
            sink_line=sink_line,
            workspace=ws,
            sink_callee=sink_callee,
        )
        f.snippet = composed
        f.resolved_imports = resolved_imports
        fetched.append(f)

    # Run the variant judge once over the surviving batch.
    judge_inputs = _build_judge_candidates(fetched, signature)
    judge_results = await _invoke_variant_judge(
        signature=signature,
        judge_inputs=judge_inputs,
        inference=inference,
    )

    out: list[CrossRepoTriageResult] = []
    judge_attempted = bool(judge_inputs)
    for f in fetched:
        result = CrossRepoTriageResult(
            fetched=f, skipped_reason=f.skipped_reason
        )
        if f.skipped_reason or not f.snippet:
            out.append(result)
            continue
        identifier = f"{f.candidate.repo_full_name}/{f.candidate.file_path}"
        score, rationale = judge_results.get(identifier, (0.0, ""))
        result.similarity_score = score
        result.rationale = rationale
        result.is_match = score >= triage_threshold
        if judge_attempted and not judge_results:
            # Judge failed mid-batch — mark every survivor skipped so
            # the caller doesn't silently treat 0.0 as "judge said no."
            result.skipped_reason = "judge_failed"
        out.append(result)

    return out


__all__ = [
    "CrossRepoFetched",
    "CrossRepoTriageResult",
    "DEFAULT_CACHE_DIR",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_TARBALL_BYTES",
    "DEFAULT_TRIAGE_THRESHOLD",
    "MAX_IMPORTS_PER_CANDIDATE",
    "MAX_IMPORT_CHARS",
    "MAX_SNIPPET_CHARS",
    "RepoWorkspace",
    "download_repo_tarball",
    "fetch_and_triage",
]
