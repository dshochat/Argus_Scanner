"""Argus repo-scan mode (AI-101 MVP).

Walks a directory tree, applies file-type and gitignore filters, dispatches
each match to :func:`scanner.engine.scan_file`, and aggregates results.

Design choices for the MVP:

  * **Sequential scan** by default — async-but-serial. A worker pool comes
    in v1.2; sequential is simpler, more observable, and our cost guardrail
    is easier to reason about over a serial stream.
  * **Aggregate cost cap** — ``--max-cost <USD>`` is rolled across the
    whole run; when cumulative spend exceeds the cap, the remaining files
    are skipped with reason ``cost_cap_reached`` and the partial report
    is returned.
  * **gitignore-aware** — uses ``pathspec.GitWildMatchPattern`` to honor
    every ``.gitignore`` walked through (root → leaf). Plus a small
    built-in always-ignore list (``.git``, ``node_modules``,
    ``__pycache__``, ``.venv``, etc.) so a fresh clone scans cleanly
    even without a ``.gitignore``.
  * **File-type filter** — extension allowlist (``.py``, ``.js``, ``.ts``,
    ``.sh``, ``.pth``, ``Dockerfile``, ``package.json``, etc.). Files
    outside the allowlist are skipped with reason ``unsupported_filetype``.
  * **Per-file robustness** — one file failing doesn't kill the run; the
    failure is recorded in ``RepoScanReport.errors`` and we keep going.

This module does **not** know about CLI argument shapes. The CLI in
``scanner.cli`` translates user flags into kwargs here. That keeps
``repo_scanner`` testable without subprocess-launching the CLI.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import time
import warnings
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# pathspec 1.x prints a DeprecationWarning every time GitWildMatchPattern
# is used, recommending GitIgnoreSpecPattern — but that class isn't yet
# exported in our pinned version. Silence the warning at import; revisit
# when pathspec ships GitIgnoreSpecPattern in the patterns module.
with warnings.catch_warnings():
    warnings.filterwarnings(
        "ignore",
        category=DeprecationWarning,
        message=r".*GitWildMatchPattern.*",
    )
    from pathspec import PathSpec
    from pathspec.patterns import GitWildMatchPattern

from scanner.engine import ScanConfig, ScanResult, scan_file

log = logging.getLogger("argus.repo_scanner")


# ── Filter defaults ──────────────────────────────────────────────────────────


# File extensions Argus knows how to analyse. Matches the language/format
# coverage of the cascade prompts + the DAST sandbox runtimes (multi-image
# v1.1 already supports Python, JS/TS, bash, Java bytecode).
SUPPORTED_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Python
        ".py",
        ".pth",
        ".pyi",
        ".pkl",
        ".pickle",
        # JavaScript / TypeScript
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        # Shell
        ".sh",
        ".bash",
        ".zsh",
        # Config / supply-chain surface
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        # Java bytecode
        ".class",
        ".jar",
        # AI-agent attack surface — markdown and AI-config docs are prime
        # vectors for prompt injection, zero-width / homoglyph attacks, and
        # malicious instruction sets aimed at coding agents.
        ".md",
        ".mdx",
        ".markdown",
        # Documentation formats AI agents commonly read
        ".rst",
        ".adoc",
        ".asciidoc",
        # Web / browser attack surface — XSS, XXE, hidden iframes, inline
        # script tags. Also where prompt-injection often lives in static
        # docs sites (e.g., a malicious doc-site README that targets agents).
        ".html",
        ".htm",
        ".svg",
        ".xml",
    }
)

# Filenames (no extension or sentinel-named) that Argus also analyses.
# Supply-chain configs that frequently host malicious lifecycle scripts,
# plus AI-agent config files known to be prompt-injection vectors.
SUPPORTED_FILENAMES: frozenset[str] = frozenset(
    {
        # Build / containers
        "Dockerfile",
        "Containerfile",
        "Makefile",
        "Jenkinsfile",
        # Supply-chain manifests (most ecosystems)
        "package.json",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "Pipfile",
        "Pipfile.lock",
        "Cargo.lock",  # .toml extension covers Cargo.toml
        "go.mod",
        "go.sum",
        "Gemfile",
        "composer.json",
        "composer.lock",
        # Auth / config files commonly leaked or hijacked
        ".env.example",
        ".npmrc",
        ".pypirc",
        ".envrc",  # direnv
        # AI-agent config sentinels — malicious instructions silently
        # steer downstream coding agents.
        "CLAUDE.md",
        "AGENTS.md",
        "AGENT.md",
        "CURSOR.md",
        ".cursorrules",
        "WINDSURF.md",
        ".windsurfrules",
        "GEMINI.md",
        "AIDER.md",
        ".aider.conf.yml",
        ".aider.model.metadata.json",
        ".aiderignore",
        ".continuerules",
        ".copilot-instructions.md",
        "copilot-instructions.md",
        "instructions.md",
        "system_prompt.md",
        "system-prompt.md",
        # MCP (Model Context Protocol) — server configs loaded by AI
        # desktop apps; a malicious entry can register a hostile tool that
        # any agent in that workspace then sees.
        "mcp.json",
        ".mcp.json",
        "claude_desktop_config.json",
        # Other AI-tooling configs — Tabnine, ad-hoc agent metadata
        ".tabnine.json",
        # Browser-extension / mobile-webview / PaaS manifests. These can
        # grant broad permissions (content scripts, all-URLs hosts), embed
        # external script URLs, or chain into Heroku/Expo deploy hooks.
        "manifest.json",
        "app.json",
        # IDE workspace configs that can execute commands on open / load
        # — VS Code dev containers run arbitrary setup steps; tasks.json /
        # launch.json under .vscode/ are already covered via the .json
        # extension.
        "devcontainer.json",
    }
)

# Directories we always skip — common build artifacts, VCS metadata,
# virtual environments. These dominate noise in real repos and our
# scanner produces no useful signal on them.
ALWAYS_IGNORE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        "site",  # mkdocs
        "_site",  # jekyll/mkdocs
        "target",  # rust/maven
        ".next",
        ".nuxt",
        "coverage",
        ".coverage",
        "htmlcov",
    }
)

# Default file size cap — files larger than this are skipped. Argus's
# prompts are tuned for files up to a few thousand lines; a 5 MB JS
# bundle would blow the prompt budget and produce noise. Override via
# ``RepoScanConfig.max_file_bytes``.
DEFAULT_MAX_FILE_BYTES = 1_048_576  # 1 MiB


# ── Public types ─────────────────────────────────────────────────────────────


@dataclass
class RepoScanConfig:
    """User-facing configuration for one repo-scan run.

    Construct in the CLI from argparse args; pass into :func:`scan_repo`.
    """

    root: Path
    """Directory to walk."""

    # Filters
    extra_excludes: tuple[str, ...] = ()
    """Additional gitignore-style patterns to exclude (--exclude flag)."""

    respect_gitignore: bool = True
    """If True, every ``.gitignore`` encountered during the walk is
    honoured. If False, only ``ALWAYS_IGNORE_DIRS`` + ``extra_excludes``
    apply."""

    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES

    # Incremental
    diff_ref: str | None = None
    """If set, scan only files that differ vs ``diff_ref`` per
    ``git diff --name-only <diff_ref>...HEAD`` against ``root``."""

    # Cost
    max_cost_run_usd: float | None = None
    """Aggregate cost cap across the whole run (rolled total). When the
    cumulative spend on completed files exceeds this, remaining files
    are skipped with reason ``cost_cap_reached``. None disables."""

    # Per-file scan config (forwarded to :func:`scan_file`)
    scan_config: ScanConfig | None = None

    # Resilience
    continue_on_error: bool = True
    """If True (default), one file's exception is recorded but the run
    continues. If False, the first error aborts the run."""


@dataclass
class FileSkip:
    """A file the walker found but did not scan."""

    path: Path
    reason: str
    """One of: ``unsupported_filetype``, ``gitignored``, ``too_large``,
    ``cost_cap_reached``, ``not_in_diff``, ``read_error``."""

    detail: str = ""


@dataclass
class FileError:
    """A file the scanner attempted but failed on."""

    path: Path
    error_type: str
    error_msg: str


@dataclass
class RepoScanReport:
    """Aggregated result from one ``scan_repo`` invocation."""

    root: Path
    started_at: float
    elapsed_s: float = 0.0

    # Per-file outcomes
    results: list[ScanResult] = field(default_factory=list)
    """One ScanResult per file Argus successfully processed."""

    skips: list[FileSkip] = field(default_factory=list)
    """Files seen by the walker but not scanned (reason recorded)."""

    errors: list[FileError] = field(default_factory=list)
    """Files attempted but failed during ``scan_file``."""

    # Totals
    total_cost_usd: float = 0.0
    cost_cap_hit: bool = False

    # Verdict counts (rolled up across results)
    verdict_counts: dict[str, int] = field(default_factory=dict)


# ── Walker ───────────────────────────────────────────────────────────────────


def _build_default_pathspec() -> PathSpec:
    """Pathspec excluding our always-ignore dirs."""
    patterns = [f"{d}/" for d in ALWAYS_IGNORE_DIRS]
    return PathSpec.from_lines(GitWildMatchPattern, patterns)


def _read_gitignore(path: Path) -> PathSpec | None:
    """Load gitignore patterns from ``path``, returning None on failure."""
    try:
        with path.open(encoding="utf-8") as f:
            return PathSpec.from_lines(GitWildMatchPattern, f)
    except (OSError, UnicodeDecodeError):
        return None


def _is_supported(path: Path) -> bool:
    """Return True if Argus has prompts/runtime support for this filetype."""
    if path.name in SUPPORTED_FILENAMES:
        return True
    return path.suffix.lower() in SUPPORTED_EXTENSIONS


def _list_diff_files(root: Path, ref: str) -> set[Path] | None:
    """Run ``git diff --name-only <ref>...HEAD`` from ``root`` and return
    the set of files (as absolute Paths under ``root``).

    Returns None if git isn't available or the command fails. Caller can
    fall back to a full walk in that case.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{ref}...HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        log.warning("git diff failed for ref %r: %s", ref, e)
        return None

    files: set[Path] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        absolute = (root / line).resolve()
        if absolute.is_file():
            files.add(absolute)
    return files


def walk_files(
    cfg: RepoScanConfig,
) -> Iterable[tuple[Path, str | None]]:
    """Yield ``(path, skip_reason_or_None)`` for every regular file under
    ``cfg.root``.

    ``skip_reason_or_None`` is ``None`` if the file should be scanned, or
    a string from :class:`FileSkip.reason` if it should be skipped (callers
    record the skip but don't dispatch the file).

    Order is deterministic (sorted). Symlinks are not followed.
    """
    root = cfg.root.resolve()

    # Pre-compute the diff set once if --diff was passed.
    diff_set: set[Path] | None = None
    if cfg.diff_ref:
        diff_set = _list_diff_files(root, cfg.diff_ref)
        if diff_set is None:
            log.warning("--diff %s failed; falling back to full walk", cfg.diff_ref)

    # Combine always-ignore dirs + user --exclude patterns + (later) any
    # .gitignore files we discover during the walk.
    base_spec = _build_default_pathspec()
    extra_spec: PathSpec | None = None
    if cfg.extra_excludes:
        extra_spec = PathSpec.from_lines(GitWildMatchPattern, cfg.extra_excludes)

    # Stack of (.gitignore-loaded PathSpec, the dir it applies in).
    # Walked top-down; each dir's gitignore applies to itself + descendants.
    gitignore_stack: list[tuple[Path, PathSpec]] = []

    def _is_excluded(rel: str, *, is_dir: bool = False) -> bool:
        check = rel + ("/" if is_dir else "")
        if base_spec.match_file(check):
            return True
        if extra_spec and extra_spec.match_file(check):
            return True
        if cfg.respect_gitignore:
            for _, spec in gitignore_stack:
                if spec.match_file(check):
                    return True
        return False

    # iterative DFS so we can update the gitignore stack as we descend.
    todo: list[Path] = [root]
    while todo:
        current = todo.pop()
        if not current.is_dir() or current.is_symlink():
            continue

        # Pop stack entries that no longer apply (we've left their subtree).
        while gitignore_stack and not _is_under(current, gitignore_stack[-1][0]):
            gitignore_stack.pop()

        # Load this dir's .gitignore if present.
        if cfg.respect_gitignore:
            gi = current / ".gitignore"
            if gi.is_file():
                spec = _read_gitignore(gi)
                if spec is not None:
                    gitignore_stack.append((current, spec))

        # Sort entries deterministically; descend into dirs after files
        # so output order is alphabetical-files-first.
        try:
            entries = sorted(current.iterdir())
        except (OSError, PermissionError) as e:
            log.warning("can't read directory %s: %s", current, e)
            continue

        children_dirs: list[Path] = []
        for entry in entries:
            if entry.is_symlink():
                continue
            try:
                rel = str(entry.relative_to(root)).replace("\\", "/")
            except ValueError:
                continue

            if entry.is_dir():
                if _is_excluded(rel, is_dir=True):
                    continue
                children_dirs.append(entry)
                continue

            if not entry.is_file():
                continue

            if _is_excluded(rel):
                yield entry, "gitignored"
                continue

            if not _is_supported(entry):
                yield entry, "unsupported_filetype"
                continue

            try:
                size = entry.stat().st_size
            except OSError:
                yield entry, "read_error"
                continue
            if size > cfg.max_file_bytes:
                yield entry, "too_large"
                continue

            if diff_set is not None and entry.resolve() not in diff_set:
                yield entry, "not_in_diff"
                continue

            yield entry, None

        # DFS — push dirs in reverse so alphabetical children come out
        # in order on the next iteration.
        todo.extend(reversed(children_dirs))


def _is_under(path: Path, ancestor: Path) -> bool:
    """True if ``path`` is ``ancestor`` or a descendant."""
    try:
        path.resolve().relative_to(ancestor.resolve())
        return True
    except ValueError:
        return False


# ── Runner ───────────────────────────────────────────────────────────────────


# A scan-runner is a callable matching scan_file's contract; tests inject
# a stub that doesn't hit live APIs.
ScanFn = Callable[..., Awaitable[ScanResult]]


async def scan_repo(
    cfg: RepoScanConfig,
    *,
    scan_fn: ScanFn = scan_file,
    triage_runner: Any = None,
    sonnet_runner: Any = None,
    opus_runner: Any = None,
    dast_runner: Any = None,
    progress_cb: Callable[[int, int, Path, ScanResult | None, str | None], None] | None = None,
) -> RepoScanReport:
    """Walk ``cfg.root``, scan every supported file, return aggregated report.

    ``scan_fn`` is the per-file scan function — production calls use
    :func:`scanner.engine.scan_file`; unit tests inject a stub that returns
    canned ScanResults so the runner logic can be tested without API spend.

    ``progress_cb(idx, total, path, result, skip_reason)`` is invoked once
    per file (or skip). ``result`` is the ScanResult on success, None on skip.
    ``skip_reason`` is None on success, a string on skip.
    """
    started = time.time()
    report = RepoScanReport(root=cfg.root, started_at=started)

    # First pass — enumerate everything so we can show "i/N" progress.
    enumerated = list(walk_files(cfg))
    total = len(enumerated)

    for idx, (path, skip_reason) in enumerate(enumerated, start=1):
        if skip_reason is not None:
            report.skips.append(FileSkip(path=path, reason=skip_reason))
            if progress_cb:
                progress_cb(idx, total, path, None, skip_reason)
            continue

        # Cost-cap gate: if we'd exceed the run cap, skip.
        if (
            cfg.max_cost_run_usd is not None
            and cfg.max_cost_run_usd > 0
            and report.total_cost_usd >= cfg.max_cost_run_usd
        ):
            report.cost_cap_hit = True
            report.skips.append(
                FileSkip(
                    path=path,
                    reason="cost_cap_reached",
                    detail=(f"cumulative ${report.total_cost_usd:.4f} >= cap ${cfg.max_cost_run_usd:.2f}"),
                )
            )
            if progress_cb:
                progress_cb(idx, total, path, None, "cost_cap_reached")
            continue

        try:
            content = path.read_bytes()
        except OSError as e:
            err = FileError(path=path, error_type="read_error", error_msg=str(e))
            report.errors.append(err)
            if progress_cb:
                progress_cb(idx, total, path, None, "read_error")
            if not cfg.continue_on_error:
                break
            continue

        try:
            result = await scan_fn(
                filename=str(path.relative_to(cfg.root.resolve())),
                content=content,
                config=cfg.scan_config,
                triage_runner=triage_runner,
                sonnet_runner=sonnet_runner,
                opus_runner=opus_runner,
                dast_runner=dast_runner,
            )
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception as e:  # noqa: BLE001 — boundary
            err = FileError(
                path=path,
                error_type=type(e).__name__,
                error_msg=str(e)[:500],
            )
            report.errors.append(err)
            if progress_cb:
                progress_cb(idx, total, path, None, type(e).__name__)
            if not cfg.continue_on_error:
                break
            continue

        report.results.append(result)
        report.total_cost_usd += result.total_cost_usd
        verdict = result.final_verdict or "unknown"
        report.verdict_counts[verdict] = report.verdict_counts.get(verdict, 0) + 1
        if progress_cb:
            progress_cb(idx, total, path, result, None)

    report.elapsed_s = time.time() - started
    return report


__all__ = [
    "RepoScanConfig",
    "RepoScanReport",
    "FileSkip",
    "FileError",
    "scan_repo",
    "walk_files",
    "SUPPORTED_EXTENSIONS",
    "SUPPORTED_FILENAMES",
    "ALWAYS_IGNORE_DIRS",
]
