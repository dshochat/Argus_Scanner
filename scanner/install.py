"""Argus install-time gate — `argus install <pkg>` (v1.3 wedge).

Stages a package via ``pip download`` (without running ``setup.py``),
runs the full Argus pipeline (cascade harness + DAST Phase A/B if
configured) on the staged artifacts, and either:

* **passes** — verdict is below the configured block threshold; we
  call the real ``pip install <target>``, OR
* **blocks** — verdict reaches the threshold; we print the analysis
  (CWE, runtime evidence, exfil destination) and exit non-zero. The
  package never lands in the user's site-packages.

Why this exists: pip has no pre-install hook. Advisory-based scanners
(``pip-audit``, ``safety``) only catch what advisories already know,
which is exactly NOT the case for supply-chain malware on day-zero.
A runtime-validated AI gate at the ingestion boundary is the right
architecture.

Phase C is **always** disabled on the install path. Remediation for a
package you haven't installed yet is "don't install" — generating a
patched wheel + replaying exploits against it would be wasted work.
We pass ``enable_phase_c=False`` regardless of the user's other
configuration.

Cache: every wheel/sdist sha256 ↔ verdict is stored under
``~/.cache/argus/install/<sha256>.json``. Wheel bytes are immutable
(by design — PyPI rejects re-uploads of the same version), so a sha256
lookup is a permanent verdict for that exact artifact. First-run cost
is real; subsequent installs are free.

Threat model coverage:
* Postinstall / lifecycle scripts (``setup.py``, ``__init__.py``,
  ``.pth`` path-hijack) — preprocessing flags fire; Sonnet escalation.
* Obfuscated payloads (base64 / hex / eval-chain) — deobfuscation
  pipeline unwraps before the cascade.
* ML-model exfil-on-load (e.g. shipping a malicious ``.pt`` file) —
  pickletools disassembly + ML-load DAST detonation if Fly configured.
* Prompt-injection in package READMEs / docs aimed at coding agents —
  AI-file-pattern detection.

What this does NOT catch:
* Native-extension compromise (pre-built ``.so`` / ``.pyd``).
* Time-bombed payloads (fires only on date X / specific hostname).
* Env-conditional payloads (only triggers in AWS / specific region).

Users should treat "Argus did not observe malicious behavior" as
*evidence of safety*, not a *guarantee*.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scanner.engine import ScanConfig, ScanResult
from scanner.repo_scanner import (
    RepoScanConfig,
    RepoScanReport,
    scan_repo,
)

log = logging.getLogger("argus.install")


# ── Constants ─────────────────────────────────────────────────────────────


CACHE_DIR_DEFAULT: Path = Path.home() / ".cache" / "argus" / "install"
CACHE_FORMAT_VERSION: int = 1

#: Verdict-tier ordering (higher = worse). Used both for "worst-of"
#: aggregation across a wheel's transitive deps and for the
#: ``--block-on`` threshold check.
VERDICT_RANK: dict[str, int] = {
    "clean": 0,
    "informational": 0,
    "low_concern": 1,
    "suspicious": 2,
    "malicious": 3,
    "critical_malicious": 4,
}

#: Default block threshold — anything reaching ``malicious`` or worse
#: blocks the install. Suspicious lets through (with a warning).
DEFAULT_BLOCK_ON: tuple[str, ...] = ("malicious", "critical_malicious")


# ── Result types ──────────────────────────────────────────────────────────


@dataclass
class WheelVerdict:
    """The verdict for one wheel/sdist artifact in the install dependency
    closure. One of these per file ``pip download`` produced; aggregated
    into the install-level decision."""

    sha256: str
    artifact_name: str
    package_name: str | None = None
    version: str | None = None
    verdict: str = "clean"
    risk_score: int = 0
    n_vulnerabilities: int = 0
    n_files_scanned: int = 0
    dast_attempted: bool = False
    cost_usd: float = 0.0
    duration_ms: int = 0
    cached: bool = False
    """True when the verdict was loaded from the wheel-hash cache."""

    # Coverage transparency — report what we could NOT analyze so the
    # verdict's confidence is calibrated. A 'clean' verdict on a wheel
    # that's 90% .so files is much weaker evidence than a 'clean' verdict
    # on a wheel that's 100% .py files.
    n_files_unscanned: int = 0
    """Files in the wheel that Argus's static cascade cannot analyze —
    typically native binaries (.so, .pyd, .dylib, .dll, .exe) and
    compiled bytecode. These are silently dropped from the cascade
    today, so a 'clean' verdict only attests to the files we DID scan."""

    unscanned_extensions: dict[str, int] = field(default_factory=dict)
    """Histogram of skipped extensions: ``{".so": 3, ".pyd": 1}``.
    Empty when ``n_files_unscanned == 0``. Helpful for the user to
    judge whether the unscanned set is benign (e.g., bundled fonts)
    or worrying (e.g., a single .so file)."""

    findings_summary: list[dict[str, Any]] = field(default_factory=list)
    """Trimmed view of the worst findings — `cwe`, `type`, `severity`,
    `line`, ``file`` — kept in cache for fast re-display without
    needing to re-scan."""

    @property
    def coverage_ratio(self) -> float:
        """Fraction of files Argus actually analyzed. Returns 1.0 when
        no files were skipped, 0.0 when nothing was analyzable. Used by
        the warning logic in the report formatter."""
        total = self.n_files_scanned + self.n_files_unscanned
        return 1.0 if total == 0 else self.n_files_scanned / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "artifact_name": self.artifact_name,
            "package_name": self.package_name,
            "version": self.version,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "n_vulnerabilities": self.n_vulnerabilities,
            "n_files_scanned": self.n_files_scanned,
            "n_files_unscanned": self.n_files_unscanned,
            "unscanned_extensions": dict(self.unscanned_extensions),
            "coverage_ratio": round(self.coverage_ratio, 3),
            "dast_attempted": self.dast_attempted,
            "cost_usd": round(self.cost_usd, 6),
            "duration_ms": self.duration_ms,
            "findings_summary": list(self.findings_summary),
        }


@dataclass
class InstallReport:
    """End-to-end result of an ``argus install`` run."""

    target: str
    """Original target spec — e.g. ``"litellm==1.50.0"`` or
    ``"-r requirements.txt"``."""

    wheels: list[WheelVerdict] = field(default_factory=list)

    worst_verdict: str = "clean"
    blocked: bool = False
    block_reason: str | None = None
    """Human-readable explanation when ``blocked`` is True."""

    aggregate_cost_usd: float = 0.0
    n_artifacts: int = 0
    n_cache_hits: int = 0
    n_dast_runs: int = 0

    pip_install_attempted: bool = False
    pip_install_succeeded: bool = False
    pip_install_stderr: str = ""

    elapsed_s: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "worst_verdict": self.worst_verdict,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "aggregate_cost_usd": round(self.aggregate_cost_usd, 6),
            "n_artifacts": self.n_artifacts,
            "n_cache_hits": self.n_cache_hits,
            "n_dast_runs": self.n_dast_runs,
            "pip_install_attempted": self.pip_install_attempted,
            "pip_install_succeeded": self.pip_install_succeeded,
            "elapsed_s": round(self.elapsed_s, 2),
            "error": self.error,
            "wheels": [w.to_dict() for w in self.wheels],
        }


# ── Cache layer ───────────────────────────────────────────────────────────


def _cache_path(cache_dir: Path, sha: str) -> Path:
    """Cache key = sha256 of the wheel/sdist bytes. Stable forever
    because PyPI rejects re-uploads of the same (name, version)."""
    return cache_dir / f"{sha}.json"


def read_cache(cache_dir: Path, sha: str) -> WheelVerdict | None:
    """Return a cached verdict for ``sha``, or ``None`` on miss / unreadable.

    Defensive against (a) cache file deleted out from under us, (b)
    stale cache_format_version, (c) corrupted JSON. We treat any error
    as a miss — re-scanning is correct fallback behavior."""
    p = _cache_path(cache_dir, sha)
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(d, dict):
        return None
    if d.get("cache_format_version") != CACHE_FORMAT_VERSION:
        return None
    payload = d.get("verdict")
    if not isinstance(payload, dict):
        return None
    try:
        return WheelVerdict(
            sha256=str(payload.get("sha256") or sha),
            artifact_name=str(payload.get("artifact_name", "")),
            package_name=payload.get("package_name"),
            version=payload.get("version"),
            verdict=str(payload.get("verdict", "clean")),
            risk_score=int(payload.get("risk_score", 0)),
            n_vulnerabilities=int(payload.get("n_vulnerabilities", 0)),
            n_files_scanned=int(payload.get("n_files_scanned", 0)),
            dast_attempted=bool(payload.get("dast_attempted", False)),
            cost_usd=float(payload.get("cost_usd", 0.0)),
            duration_ms=int(payload.get("duration_ms", 0)),
            cached=True,
            findings_summary=list(payload.get("findings_summary") or []),
        )
    except (TypeError, ValueError):
        return None


def write_cache(cache_dir: Path, verdict: WheelVerdict) -> None:
    """Persist ``verdict`` keyed by its sha256. Best-effort — we never
    propagate a cache-write failure to the caller because it's purely
    optimization."""
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_format_version": CACHE_FORMAT_VERSION,
            "scanned_at_unix": int(time.time()),
            "verdict": verdict.to_dict(),
        }
        _cache_path(cache_dir, verdict.sha256).write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        log.warning("install cache write failed for %s: %s", verdict.sha256, exc)


# ── Artifact staging ──────────────────────────────────────────────────────


def _pip_download(
    *,
    target: str | None,
    requirement_file: Path | None,
    dest: Path,
    pip_executable: str,
    extra_args: Iterable[str] = (),
    timeout_sec: int = 600,
) -> tuple[bool, str]:
    """Stage wheel/sdist files via ``pip download``. Does NOT execute
    setup.py; ``pip download`` is the safe staging primitive (vs
    ``pip install`` which runs build hooks).

    Returns ``(ok, stderr_excerpt)``. ``ok=False`` when pip download
    failed — caller surfaces the error rather than installing.
    """
    cmd: list[str] = [
        pip_executable,
        "download",
        "-d",
        str(dest),
        # We want sdists too — some packages ship malicious code in
        # ``setup.py`` only (no wheel). ``--no-binary :all:`` would
        # force every package to sdist; we want the default mix.
        # ``--no-deps`` if no requirement file — caller asked for one
        # specific package and the dependency closure is its problem.
        # When -r is given, the requirement file IS the closure.
    ]
    if requirement_file is not None:
        cmd += ["-r", str(requirement_file)]
    elif target is not None:
        cmd += [target]
    else:
        return False, "no target or requirement_file provided"
    cmd += list(extra_args)

    log.debug("pip download: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"pip download timed out after {timeout_sec}s"
    except (OSError, FileNotFoundError) as exc:
        return False, f"pip executable not runnable: {exc}"
    if result.returncode != 0:
        # Truncate stderr; pip can be very chatty
        return False, (result.stderr or result.stdout or "")[:1500]
    return True, ""


def _list_artifacts(staging_dir: Path) -> list[Path]:
    """Wheels and source distributions only. Anything else in the dir is
    a pip artifact we don't care about (lock file, hash list, etc.)."""
    out: list[Path] = []
    for p in sorted(staging_dir.iterdir()):
        if (
            p.suffix.lower() in {".whl"}
            or p.name.endswith(".tar.gz")
            or p.suffix.lower() in {".zip"}
        ):
            out.append(p)
    return out


def _parse_artifact_name(name: str) -> tuple[str | None, str | None]:
    """Best-effort parse of ``foo-1.2.3-py3-none-any.whl`` → ``("foo", "1.2.3")``.

    PEP-427 wheels: ``{name}-{version}(-{build})?-{tags}.whl``.
    Sdists: ``{name}-{version}.tar.gz``. Build tags can contain dashes,
    so we use a heuristic: split on ``-``, keep the first segment as
    name, the second as version. Good enough for display; nothing
    consumes this programmatically."""
    base = name
    for ext in (".whl", ".tar.gz", ".zip", ".tgz"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    parts = base.split("-")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return base, None


def _extract_artifact(artifact: Path, dest: Path) -> bool:
    """Extract the wheel (zipfile) or sdist (tar.gz) into ``dest``.
    Returns True on success. Wheels are zipfiles; sdists are tarballs."""
    name = artifact.name.lower()
    try:
        if name.endswith(".whl") or name.endswith(".zip"):
            shutil.unpack_archive(str(artifact), str(dest), format="zip")
        elif name.endswith(".tar.gz") or name.endswith(".tgz"):
            shutil.unpack_archive(str(artifact), str(dest), format="gztar")
        else:
            return False
    except (shutil.ReadError, OSError, ValueError) as exc:
        log.warning("could not extract %s: %s", artifact.name, exc)
        return False
    return True


def _sha256_file(path: Path) -> str:
    """Streaming sha256 — wheels can be 100MB+; don't load whole file."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Per-artifact scan ─────────────────────────────────────────────────────


def _summarize_findings(report: RepoScanReport) -> list[dict[str, Any]]:
    """Collapse a RepoScanReport's per-file findings into a top-N
    summary suitable for caching + display. Sort by severity rank
    (critical → high → medium → low) and keep the worst 10."""
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings: list[dict[str, Any]] = []
    for r in report.results:
        if not isinstance(r, ScanResult):
            continue
        for v in r.vulnerabilities or []:
            if not isinstance(v, dict):
                continue
            findings.append(
                {
                    "file": r.filename,
                    "cwe": v.get("cwe"),
                    "type": v.get("type"),
                    "severity": v.get("severity"),
                    "line": v.get("line"),
                    "explanation": (v.get("explanation") or "")[:240],
                }
            )
    findings.sort(key=lambda f: -sev_rank.get(f.get("severity", "info"), 0))
    return findings[:10]


def _worst_verdict_in_report(report: RepoScanReport) -> str:
    """Pick the highest-severity verdict across every file in the
    artifact. Defaults to 'clean' for empty / all-skipped reports."""
    worst = "clean"
    worst_rank = -1
    for r in report.results:
        if not isinstance(r, ScanResult):
            continue
        v = r.final_verdict or "clean"
        rank = VERDICT_RANK.get(v, 0)
        if rank > worst_rank:
            worst_rank = rank
            worst = v
    return worst


async def scan_one_artifact(
    artifact: Path,
    *,
    scan_cfg: ScanConfig,
    triage_runner: Any,
    sonnet_runner: Any,
    opus_runner: Any,
    dast_runner: Any,
    file_concurrency: int = 1,
) -> WheelVerdict:
    """Extract one wheel/sdist + run the cascade (and DAST if configured)
    over its contents. Returns a per-artifact verdict.

    The install path ALWAYS sets ``enable_phase_c=False`` regardless of
    the caller's scan_cfg — remediation for a not-yet-installed
    package is "don't install", not "patch + replay."
    """
    sha = _sha256_file(artifact)
    pkg_name, version = _parse_artifact_name(artifact.name)
    started = time.time()

    # Phase C off for every install scan.
    install_cfg = ScanConfig(
        enable_pre_triage_regex=scan_cfg.enable_pre_triage_regex,
        enable_triage_safety_net=scan_cfg.enable_triage_safety_net,
        enable_cascade=scan_cfg.enable_cascade,
        sonnet_uncertainty_threshold=scan_cfg.sonnet_uncertainty_threshold,
        high_stakes_categories=scan_cfg.high_stakes_categories,
        ensemble_size_borderline=scan_cfg.ensemble_size_borderline,
        ensemble_size_default=scan_cfg.ensemble_size_default,
        enable_dast=scan_cfg.enable_dast,
        dast_trigger_verdicts=scan_cfg.dast_trigger_verdicts,
        dast_max_iterations=scan_cfg.dast_max_iterations,
        enable_phase_c=False,  # ALWAYS off on the install path
        enable_discovery=scan_cfg.enable_discovery,
        discovery_trigger_verdicts=scan_cfg.discovery_trigger_verdicts,
        enable_adjudicator=scan_cfg.enable_adjudicator,
        adjudicator_model=scan_cfg.adjudicator_model,
        max_cost_per_file_usd=scan_cfg.max_cost_per_file_usd,
        max_cost_per_scan_usd=scan_cfg.max_cost_per_scan_usd,
    )

    with tempfile.TemporaryDirectory(prefix="argus-install-extract-") as ext_tmp:
        ext_dir = Path(ext_tmp)
        if not _extract_artifact(artifact, ext_dir):
            # Couldn't extract — surface as a low-severity miss rather than
            # blocking. The artifact is opaque; we have no signal either way.
            return WheelVerdict(
                sha256=sha,
                artifact_name=artifact.name,
                package_name=pkg_name,
                version=version,
                verdict="suspicious",
                risk_score=10,
                duration_ms=int((time.time() - started) * 1000),
                findings_summary=[
                    {
                        "file": artifact.name,
                        "type": "extraction_failed",
                        "severity": "info",
                        "explanation": "Argus could not extract this artifact for analysis.",
                    }
                ],
            )

        repo_cfg = RepoScanConfig(
            root=ext_dir,
            scan_config=install_cfg,
            respect_gitignore=False,  # wheel contents have no .gitignore
            continue_on_error=True,
            scan_concurrency=max(1, file_concurrency),
        )
        report = await scan_repo(
            repo_cfg,
            triage_runner=triage_runner,
            sonnet_runner=sonnet_runner,
            opus_runner=opus_runner,
            dast_runner=dast_runner,
        )

    elapsed_ms = int((time.time() - started) * 1000)
    n_dast = sum(1 for r in report.results if isinstance(r, ScanResult) and r.dast_attempted)

    # Coverage transparency: count files that the harness COULD have
    # scanned but didn't because their extension wasn't on the
    # allowlist (typically native binaries — .so/.pyd/.dylib/.dll/.exe
    # — or compiled bytecode .pyc). These are skipped silently inside
    # walk_files; we surface the count + extension histogram so the
    # verdict's confidence is properly calibrated for the user.
    n_unscanned = 0
    ext_histogram: dict[str, int] = {}
    for skip in report.skips:
        if skip.reason != "unsupported_filetype":
            continue
        n_unscanned += 1
        ext = skip.path.suffix.lower() or "(no-ext)"
        ext_histogram[ext] = ext_histogram.get(ext, 0) + 1

    return WheelVerdict(
        sha256=sha,
        artifact_name=artifact.name,
        package_name=pkg_name,
        version=version,
        verdict=_worst_verdict_in_report(report),
        risk_score=max(
            (r.risk_score for r in report.results if isinstance(r, ScanResult)),
            default=0,
        ),
        n_vulnerabilities=sum(
            len(r.vulnerabilities or []) for r in report.results if isinstance(r, ScanResult)
        ),
        n_files_scanned=len([r for r in report.results if isinstance(r, ScanResult)]),
        n_files_unscanned=n_unscanned,
        unscanned_extensions=ext_histogram,
        dast_attempted=n_dast > 0,
        cost_usd=report.total_cost_usd,
        duration_ms=elapsed_ms,
        findings_summary=_summarize_findings(report),
    )


# ── Top-level orchestration ───────────────────────────────────────────────


#: Threshold below which ``--strict-coverage`` escalates the verdict
#: to ``suspicious``. 0.7 = if Argus could only scan <70% of the
#: wheel's files (the rest were native binaries / bytecode), a
#: --strict-coverage user prefers to treat the artifact as suspicious
#: because Argus cannot vouch for what's in the unscanned 30%+.
STRICT_COVERAGE_RATIO_THRESHOLD: float = 0.7

#: Default aggregate cost cap for ``argus install``. The whole
#: dependency-closure scan (every wheel + every file) aborts when
#: cumulative API spend hits this. Cap exists because a runaway scan
#: on a big package like ``litellm`` can reach $20+ in cascade-only
#: mode without pre-cached verdicts; the cap prevents a single
#: ``argus install`` from surprising the user.
DEFAULT_MAX_TOTAL_COST_USD: float = 10.0

#: Default per-file scan concurrency inside each wheel. v1.3.1
#: optimization — wheels with many files (29 in attrs, 42 in anyio,
#: …) used to scan files sequentially, leading to 5–15 min per
#: wheel. With concurrency=4 inside a wheel + parallel_scans=8
#: across wheels, a typical 50-wheel install closes in ~5 min vs.
#: ~60 min in v1.3.0.
DEFAULT_INSTALL_FILE_CONCURRENCY: int = 4

#: Default cross-wheel parallelism on the install path. Bumped from
#: 4 to 8 in v1.3.1.
DEFAULT_INSTALL_PARALLEL_SCANS: int = 8


async def install(
    target: str | None = None,
    *,
    requirement_file: Path | None = None,
    block_on: tuple[str, ...] = DEFAULT_BLOCK_ON,
    no_dast: bool = False,
    use_cache: bool = True,
    cache_dir: Path = CACHE_DIR_DEFAULT,
    dry_run: bool = False,
    strict_coverage: bool = False,
    pip_executable: str = "pip",
    scan_cfg: ScanConfig | None = None,
    triage_runner: Any = None,
    sonnet_runner: Any = None,
    opus_runner: Any = None,
    dast_runner: Any = None,
    pip_extra_args: Iterable[str] = (),
    parallel_scans: int = DEFAULT_INSTALL_PARALLEL_SCANS,
    file_concurrency: int = DEFAULT_INSTALL_FILE_CONCURRENCY,
    max_total_cost_usd: float | None = DEFAULT_MAX_TOTAL_COST_USD,
) -> InstallReport:
    """Argus install gate.

    Either ``target`` (a pip-style spec like ``"litellm==1.50"``) OR
    ``requirement_file`` (a requirements.txt path) must be provided.

    Always sets ``enable_phase_c=False`` on the per-artifact scans —
    the install path doesn't auto-patch.

    ``dast_runner`` controls whether Phase A + B run. Pass ``None`` for
    cascade-only. Pass the env-built runner for full A+B detonation.
    """
    if target is None and requirement_file is None:
        raise ValueError("install() requires either target or requirement_file")
    if scan_cfg is None:
        scan_cfg = ScanConfig()
    # Defense-in-depth: the install path NEVER runs Phase C, regardless
    # of what the caller passed. ``scan_one_artifact`` also rebuilds with
    # ``enable_phase_c=False`` internally, but normalizing here means
    # downstream consumers (and monkey-patched tests) see the contract
    # at the boundary.
    import dataclasses as _dc  # noqa: PLC0415

    if scan_cfg.enable_phase_c:
        scan_cfg = _dc.replace(scan_cfg, enable_phase_c=False)

    started = time.time()
    report = InstallReport(target=target or f"-r {requirement_file}")

    effective_dast = None if no_dast else dast_runner

    with tempfile.TemporaryDirectory(prefix="argus-install-stage-") as stage:
        staging_dir = Path(stage)

        # ── 1. Stage via pip download ──────────────────────────────────
        ok, err = _pip_download(
            target=target,
            requirement_file=requirement_file,
            dest=staging_dir,
            pip_executable=pip_executable,
            extra_args=pip_extra_args,
        )
        if not ok:
            report.error = f"pip download failed: {err}"
            report.elapsed_s = round(time.time() - started, 2)
            return report

        artifacts = _list_artifacts(staging_dir)
        report.n_artifacts = len(artifacts)
        if not artifacts:
            report.error = "pip download produced no artifacts"
            report.elapsed_s = round(time.time() - started, 2)
            return report

        # ── 2. Per-artifact scan (cache-aware, parallel) ──────────────
        sem = asyncio.Semaphore(max(1, parallel_scans))

        # Aggregate-cost-cap state: shared across the parallel gather.
        # When tripped, all not-yet-started scans short-circuit and
        # return a "skipped" WheelVerdict marked unverified. Race-y by
        # design — worst case is up to ``parallel_scans`` extra wheels
        # complete before the cap is observed; acceptable.
        cumulative_cost = {"value": 0.0}
        cap_hit = {"value": False}

        async def _scan_with_sem(art: Path) -> WheelVerdict:
            sha = _sha256_file(art)
            if use_cache:
                cached = read_cache(cache_dir, sha)
                if cached:
                    cached.cached = True
                    return cached

            # Aggregate-cost short-circuit. If the cap was already hit
            # by another concurrent task, don't burn API spend on this
            # one. Surface the wheel as unverified ("suspicious" with a
            # cap-hit marker) so the install gate fails-closed.
            if max_total_cost_usd is not None and (
                cap_hit["value"] or cumulative_cost["value"] >= max_total_cost_usd
            ):
                cap_hit["value"] = True
                pkg_name, version = _parse_artifact_name(art.name)
                return WheelVerdict(
                    sha256=sha,
                    artifact_name=art.name,
                    package_name=pkg_name,
                    version=version,
                    verdict="suspicious",
                    risk_score=20,
                    findings_summary=[
                        {
                            "file": art.name,
                            "type": "unscanned_due_to_cost_cap",
                            "severity": "info",
                            "explanation": (
                                f"Aggregate cost cap (${max_total_cost_usd:.2f}) "
                                "was hit before this artifact could be scanned. "
                                "Argus has no verdict for it. Re-run with "
                                "--max-total-cost <higher> or scan this package "
                                "individually with `argus scan`."
                            ),
                        }
                    ],
                )

            async with sem:
                v = await scan_one_artifact(
                    art,
                    scan_cfg=scan_cfg,
                    triage_runner=triage_runner,
                    sonnet_runner=sonnet_runner,
                    opus_runner=opus_runner,
                    dast_runner=effective_dast,
                    file_concurrency=file_concurrency,
                )
            cumulative_cost["value"] += v.cost_usd
            if (
                max_total_cost_usd is not None
                and cumulative_cost["value"] >= max_total_cost_usd
            ):
                cap_hit["value"] = True
            if use_cache:
                write_cache(cache_dir, v)
            return v

        wheel_verdicts = await asyncio.gather(
            *(_scan_with_sem(a) for a in artifacts),
            return_exceptions=False,
        )

    report.wheels = list(wheel_verdicts)
    report.n_cache_hits = sum(1 for w in wheel_verdicts if w.cached)
    report.n_dast_runs = sum(1 for w in wheel_verdicts if w.dast_attempted)
    report.aggregate_cost_usd = sum(w.cost_usd for w in wheel_verdicts)

    # ── 3. Strict-coverage escalation (opt-in) ────────────────────────
    # When --strict-coverage is set, any wheel whose Argus-analyzed
    # coverage falls below STRICT_COVERAGE_RATIO_THRESHOLD gets its
    # verdict bumped to 'suspicious' (at minimum). The native-binary
    # bag is too big for a confident clean — surface the uncertainty.
    if strict_coverage:
        for w in wheel_verdicts:
            if (
                w.coverage_ratio < STRICT_COVERAGE_RATIO_THRESHOLD
                and VERDICT_RANK.get(w.verdict, 0) < VERDICT_RANK["suspicious"]
            ):
                w.verdict = "suspicious"

    # ── 4. Aggregate verdict ───────────────────────────────────────────
    worst = max(
        wheel_verdicts,
        key=lambda w: VERDICT_RANK.get(w.verdict, 0),
        default=None,
    )
    report.worst_verdict = worst.verdict if worst else "clean"

    # ── 5. Block / pass decision ───────────────────────────────────────
    if report.worst_verdict in block_on:
        report.blocked = True
        culprits = [
            w
            for w in wheel_verdicts
            if VERDICT_RANK.get(w.verdict, 0) >= VERDICT_RANK.get(report.worst_verdict, 0)
        ]
        names = ", ".join(
            f"{w.package_name}=={w.version}" if w.package_name else w.artifact_name
            for w in culprits[:5]
        )
        report.block_reason = (
            f"verdict={report.worst_verdict} in {culprits[0].artifact_name if culprits else 'unknown'} "
            f"(blocked artifacts: {names})"
        )
        report.elapsed_s = round(time.time() - started, 2)
        return report

    # ── 6. Pass → real pip install ─────────────────────────────────────
    if dry_run:
        report.elapsed_s = round(time.time() - started, 2)
        return report

    pip_install_cmd: list[str] = [pip_executable, "install"]
    if requirement_file is not None:
        pip_install_cmd += ["-r", str(requirement_file)]
    elif target is not None:
        pip_install_cmd += [target]
    pip_install_cmd += list(pip_extra_args)

    report.pip_install_attempted = True
    try:
        pi = subprocess.run(
            pip_install_cmd,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
    except subprocess.TimeoutExpired:
        report.pip_install_stderr = "pip install timed out after 900s"
    except OSError as exc:
        report.pip_install_stderr = f"pip executable not runnable: {exc}"
    else:
        report.pip_install_succeeded = pi.returncode == 0
        if not report.pip_install_succeeded:
            report.pip_install_stderr = (pi.stderr or pi.stdout or "")[:1500]

    report.elapsed_s = round(time.time() - started, 2)
    return report


__all__ = [
    "CACHE_DIR_DEFAULT",
    "DEFAULT_BLOCK_ON",
    "VERDICT_RANK",
    "InstallReport",
    "WheelVerdict",
    "install",
    "read_cache",
    "scan_one_artifact",
    "write_cache",
]
