"""Unit tests for scanner.repo_scanner — AI-101 MVP.

These tests stub :func:`scanner.engine.scan_file` so the suite never
makes a live API call. They cover:

  * walk_files: filter behavior (extension allowlist, filename allowlist,
    gitignore semantics, always-ignore dirs, file-size cap, --diff)
  * scan_repo: aggregate cost cap, error handling, progress callback,
    verdict counting
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from scanner.engine import ScanResult
from scanner.repo_scanner import (
    ALWAYS_IGNORE_DIRS,
    SUPPORTED_EXTENSIONS,
    SUPPORTED_FILENAMES,
    RepoScanConfig,
    scan_repo,
    walk_files,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def _mk_result(
    filename: str,
    *,
    verdict: str = "clean",
    cost: float = 0.0,
    risk_score: int = 0,
    risk_level: str = "low",
    vulns: list[dict] | None = None,
) -> ScanResult:
    """Build a minimal valid ScanResult for tests."""
    return ScanResult(
        filename=filename,
        file_hash="0" * 64,
        language=None,
        triage_classification="CLEAN",
        triage_reason="stub",
        final_verdict=verdict,
        risk_score=risk_score,
        risk_level=risk_level,
        vulnerabilities=vulns or [],
        total_cost_usd=cost,
    )


def _make_stub_scan_fn(*, cost_per_file: float = 0.10, verdict: str = "clean"):
    """Build a stub scan_fn that returns a canned ScanResult."""

    async def stub(
        *,
        filename: str,
        content: bytes,
        config: Any = None,
        triage_runner: Any = None,
        sonnet_runner: Any = None,
        opus_runner: Any = None,
        dast_runner: Any = None,
    ) -> ScanResult:
        return _mk_result(filename, verdict=verdict, cost=cost_per_file)

    return stub


# ── walk_files: filtering ────────────────────────────────────────────────────


def test_walk_files_extension_allowlist(tmp_path: Path) -> None:
    """Files with extensions in SUPPORTED_EXTENSIONS yield with skip=None,
    others yield with skip='unsupported_filetype'."""
    (tmp_path / "ok.py").write_text("print('hi')")
    (tmp_path / "ok.js").write_text("console.log(1)")
    (tmp_path / "skip.exe").write_bytes(b"\x00\x01")
    (tmp_path / "skip.bin").write_bytes(b"\x00\x02")

    cfg = RepoScanConfig(root=tmp_path)
    out = list(walk_files(cfg))
    by_name = {p.name: skip for p, skip in out}

    assert by_name["ok.py"] is None
    assert by_name["ok.js"] is None
    assert by_name["skip.exe"] == "unsupported_filetype"
    assert by_name["skip.bin"] == "unsupported_filetype"


def test_walk_files_filename_allowlist(tmp_path: Path) -> None:
    """Files matched by SUPPORTED_FILENAMES (no extension or sentinel-named)
    yield with skip=None."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.12")
    (tmp_path / "Jenkinsfile").write_text("pipeline {}")
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "go.mod").write_text("module x")

    cfg = RepoScanConfig(root=tmp_path)
    out = list(walk_files(cfg))
    by_name = {p.name: skip for p, skip in out}

    assert by_name["Dockerfile"] is None
    assert by_name["Jenkinsfile"] is None
    assert by_name["package.json"] is None
    assert by_name["go.mod"] is None


def test_walk_files_md_and_ai_agent_configs_supported(tmp_path: Path) -> None:
    """AI-attack-surface files (.md, CLAUDE.md, .cursorrules, mcp.json,
    devcontainer.json) all match the supported allowlists."""
    (tmp_path / "README.md").write_text("# hi")
    (tmp_path / "CLAUDE.md").write_text("instructions")
    (tmp_path / ".cursorrules").write_text("rules")
    (tmp_path / "mcp.json").write_text("{}")
    (tmp_path / "devcontainer.json").write_text("{}")
    (tmp_path / ".aider.conf.yml").write_text("x: 1")

    cfg = RepoScanConfig(root=tmp_path)
    out = list(walk_files(cfg))
    by_name = {p.name: skip for p, skip in out}

    assert by_name["README.md"] is None
    assert by_name["CLAUDE.md"] is None
    assert by_name[".cursorrules"] is None
    assert by_name["mcp.json"] is None
    assert by_name["devcontainer.json"] is None
    assert by_name[".aider.conf.yml"] is None


def test_walk_files_always_ignore_dirs(tmp_path: Path) -> None:
    """ALWAYS_IGNORE_DIRS subtrees are entirely skipped — files inside
    them never appear in the output at all."""
    (tmp_path / "main.py").write_text("x = 1")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("config")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "foo.js").write_text("x")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.pyc").write_text("compiled")

    cfg = RepoScanConfig(root=tmp_path)
    out = list(walk_files(cfg))
    paths = {p.name for p, _ in out}

    assert "main.py" in paths
    assert "config" not in paths
    assert "foo.js" not in paths
    assert "x.pyc" not in paths


def test_walk_files_gitignore_respected(tmp_path: Path) -> None:
    """A .gitignore in the root excludes matching files; they appear with
    skip='gitignored'."""
    (tmp_path / ".gitignore").write_text("secret.py\nbuild/\n")
    (tmp_path / "main.py").write_text("ok")
    (tmp_path / "secret.py").write_text("hidden")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "out.py").write_text("artifact")

    cfg = RepoScanConfig(root=tmp_path)
    out = list(walk_files(cfg))
    by_name = {p.name: skip for p, skip in out}

    assert by_name["main.py"] is None
    assert by_name.get("secret.py") == "gitignored"
    # build/ is a gitignored *dir* — the dir is pruned, so out.py never appears.
    assert "out.py" not in by_name


def test_walk_files_no_gitignore_flag(tmp_path: Path) -> None:
    """When respect_gitignore=False, .gitignore is ignored entirely."""
    (tmp_path / ".gitignore").write_text("secret.py\n")
    (tmp_path / "secret.py").write_text("hidden")

    cfg = RepoScanConfig(root=tmp_path, respect_gitignore=False)
    out = list(walk_files(cfg))
    by_name = {p.name: skip for p, skip in out}

    assert by_name["secret.py"] is None  # not skipped


def test_walk_files_file_size_cap(tmp_path: Path) -> None:
    """Files larger than max_file_bytes are skipped with reason 'too_large'."""
    (tmp_path / "small.py").write_text("x")
    (tmp_path / "big.py").write_bytes(b"a" * 10_000)

    cfg = RepoScanConfig(root=tmp_path, max_file_bytes=1000)
    out = list(walk_files(cfg))
    by_name = {p.name: skip for p, skip in out}

    assert by_name["small.py"] is None
    assert by_name["big.py"] == "too_large"


def test_walk_files_extra_excludes(tmp_path: Path) -> None:
    """User --exclude patterns work like additional gitignore entries."""
    (tmp_path / "a.py").write_text("x")
    (tmp_path / "b.py").write_text("y")

    cfg = RepoScanConfig(root=tmp_path, extra_excludes=("a.py",))
    out = list(walk_files(cfg))
    by_name = {p.name: skip for p, skip in out}

    assert by_name["a.py"] == "gitignored"
    assert by_name["b.py"] is None


def test_walk_files_symlinks_skipped(tmp_path: Path) -> None:
    """Symlinks are not followed (avoids infinite loops + scanning host
    filesystem)."""
    (tmp_path / "real.py").write_text("x")
    target = tmp_path / "elsewhere.py"
    target.write_text("not in root")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported on this platform")

    cfg = RepoScanConfig(root=tmp_path)
    out = list(walk_files(cfg))
    paths = {p.name for p, skip in out if skip is None}

    assert "real.py" in paths
    assert "link.py" not in paths


# ── scan_repo: end-to-end with stub ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_repo_basic_aggregation(tmp_path: Path) -> None:
    """scan_repo dispatches each scannable file and aggregates results."""
    (tmp_path / "a.py").write_text("x")
    (tmp_path / "b.js").write_text("y")
    (tmp_path / "skip.exe").write_bytes(b"\x00")

    cfg = RepoScanConfig(root=tmp_path)
    stub = _make_stub_scan_fn(cost_per_file=0.05, verdict="suspicious")

    report = await scan_repo(cfg, scan_fn=stub)

    assert len(report.results) == 2
    assert len(report.skips) == 1
    assert report.skips[0].reason == "unsupported_filetype"
    assert report.total_cost_usd == pytest.approx(0.10)
    assert report.verdict_counts == {"suspicious": 2}
    assert report.elapsed_s >= 0
    assert not report.cost_cap_hit


@pytest.mark.asyncio
async def test_scan_repo_cost_cap_hit(tmp_path: Path) -> None:
    """When cumulative cost exceeds max_cost_run_usd, remaining files are
    skipped with reason 'cost_cap_reached' and cost_cap_hit=True."""
    for i in range(5):
        (tmp_path / f"f{i}.py").write_text(f"x={i}")

    cfg = RepoScanConfig(root=tmp_path, max_cost_run_usd=0.15)
    stub = _make_stub_scan_fn(cost_per_file=0.10, verdict="clean")

    report = await scan_repo(cfg, scan_fn=stub)

    # First file costs $0.10 → under cap; second pushes to $0.20 → also
    # passes the gate (gate is "before-call cumulative >= cap"), then
    # cost goes to $0.20; third sees cumulative $0.20 >= $0.15 → skip.
    assert len(report.results) == 2
    assert report.cost_cap_hit
    skip_reasons = [s.reason for s in report.skips]
    assert skip_reasons.count("cost_cap_reached") == 3


@pytest.mark.asyncio
async def test_scan_repo_continue_on_error(tmp_path: Path) -> None:
    """One file's exception is recorded as a FileError; other files continue."""
    (tmp_path / "a.py").write_text("ok")
    (tmp_path / "b.py").write_text("explode")
    (tmp_path / "c.py").write_text("ok")

    async def stub(*, filename: str, content: bytes, **_: Any) -> ScanResult:
        if "b.py" in filename:
            raise RuntimeError("kaboom")
        return _mk_result(filename, verdict="clean", cost=0.01)

    cfg = RepoScanConfig(root=tmp_path, continue_on_error=True)
    report = await scan_repo(cfg, scan_fn=stub)

    assert len(report.results) == 2
    assert len(report.errors) == 1
    err = report.errors[0]
    assert err.error_type == "RuntimeError"
    assert "kaboom" in err.error_msg


@pytest.mark.asyncio
async def test_scan_repo_abort_on_error(tmp_path: Path) -> None:
    """When continue_on_error=False, the first error halts the run."""
    # iteration order is alphabetical, so a.py runs first, b.py errors, c.py never runs
    (tmp_path / "a.py").write_text("ok")
    (tmp_path / "b.py").write_text("explode")
    (tmp_path / "c.py").write_text("ok")

    async def stub(*, filename: str, content: bytes, **_: Any) -> ScanResult:
        if "b.py" in filename:
            raise RuntimeError("kaboom")
        return _mk_result(filename, verdict="clean", cost=0.01)

    cfg = RepoScanConfig(root=tmp_path, continue_on_error=False)
    report = await scan_repo(cfg, scan_fn=stub)

    assert len(report.results) == 1  # only a.py
    assert len(report.errors) == 1


@pytest.mark.asyncio
async def test_scan_repo_progress_callback(tmp_path: Path) -> None:
    """progress_cb fires once per file (success + skip)."""
    (tmp_path / "a.py").write_text("x")
    (tmp_path / "b.exe").write_bytes(b"\x00")

    seen: list[tuple[int, int, str, str | None]] = []

    def cb(idx: int, total: int, path: Path, result: Any, skip: str | None) -> None:
        seen.append((idx, total, path.name, skip))

    cfg = RepoScanConfig(root=tmp_path)
    await scan_repo(cfg, scan_fn=_make_stub_scan_fn(), progress_cb=cb)

    # 2 files seen; the .exe one came as a skip.
    assert len(seen) == 2
    skip_event = next(s for s in seen if s[3] is not None)
    assert skip_event[2] == "b.exe"
    assert skip_event[3] == "unsupported_filetype"


@pytest.mark.asyncio
async def test_scan_repo_verdict_counts(tmp_path: Path) -> None:
    """verdict_counts tally rolls up correctly."""
    for i in range(3):
        (tmp_path / f"f{i}.py").write_text("x")

    verdicts = ["clean", "suspicious", "suspicious"]

    async def stub(*, filename: str, content: bytes, **_: Any) -> ScanResult:
        # Use index parsed from filename so order doesn't matter.
        idx = int(Path(filename).stem.removeprefix("f"))
        return _mk_result(filename, verdict=verdicts[idx], cost=0.01)

    cfg = RepoScanConfig(root=tmp_path)
    report = await scan_repo(cfg, scan_fn=stub)

    assert report.verdict_counts == {"clean": 1, "suspicious": 2}


# ── Sanity checks on the constants ───────────────────────────────────────────


def test_supported_extensions_lowercase() -> None:
    """All extension entries lowercase + start with a dot — the matcher
    lowercases ``path.suffix`` so case-insensitive matching works only
    if the constants are normalized."""
    for ext in SUPPORTED_EXTENSIONS:
        assert ext.startswith("."), ext
        assert ext == ext.lower(), ext


def test_always_ignore_includes_critical_dirs() -> None:
    """Sanity: critical noise dirs are in the always-ignore list."""
    must_ignore = {".git", "node_modules", "__pycache__", ".venv"}
    assert must_ignore.issubset(ALWAYS_IGNORE_DIRS)


def test_supported_filenames_includes_ai_configs() -> None:
    """Sanity: the AI-agent config sentinels are in the filenames list."""
    must_have = {"CLAUDE.md", "AGENTS.md", ".cursorrules", "mcp.json"}
    assert must_have.issubset(SUPPORTED_FILENAMES)
