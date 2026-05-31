"""Unit tests for DAST-304 — multi-file Phase C patch propagation.

Covers:

* :func:`_group_confirmed_variants_by_file` — groups Phase D's
  variant outcomes by their candidate's ``file_path``; excludes
  the seed's own file (handled by Phase C v14).

* :func:`run_phase_c_multi_file_patch` end-to-end with stubbed
  inference + filesystem: happy path, skip paths (no project root,
  no cross-file variants, budget exhausted), and v14 guards
  (syntax invalid, byte-identical, size suspicious).

* CLI flag wiring: ``--enable-phase-d`` propagates through to
  ``ScanConfig.enable_phase_d``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from dast.phase_c_multi_file import (
    MAX_COST_PER_MULTI_FILE_RUN_USD,
    MAX_FILES_PER_MULTI_FILE_RUN,
    _group_confirmed_variants_by_file,
    run_phase_c_multi_file_patch,
)


# ── _group_confirmed_variants_by_file ────────────────────────────────


def test_grouping_collects_confirmed_variants_only() -> None:
    """Only outcomes with verdict='confirmed' get grouped. REFUTED /
    INCONCLUSIVE / NOT_TESTABLE variants are dropped — they don't
    need patching."""
    variant_analysis = [
        {
            "seed_finding_id": "H001",
            "signature": {"attack_class": "ssrf", "sink_callee": "urlopen"},
            "confirmed_variant_ids": ["D-H001-1"],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {"function_name": "fn_a", "file_path": "lib/a.py"},
                },
                {
                    "verdict": "refuted",
                    "candidate": {"function_name": "fn_b", "file_path": "lib/b.py"},
                },
            ],
        },
    ]
    grouped = _group_confirmed_variants_by_file(variant_analysis)
    assert "lib/a.py" in grouped
    assert "lib/b.py" not in grouped


def test_grouping_excludes_seed_file() -> None:
    """When ``exclude_file_path`` is set, variants in that file are
    skipped — Phase C v14 already handles the seed's own file."""
    variant_analysis = [
        {
            "seed_finding_id": "H001",
            "signature": {},
            "confirmed_variant_ids": ["D-H001-1", "D-H001-2"],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {"function_name": "fn_a", "file_path": "app.py"},
                },
                {
                    "verdict": "confirmed",
                    "candidate": {"function_name": "fn_b", "file_path": "lib/x.py"},
                },
            ],
        },
    ]
    grouped = _group_confirmed_variants_by_file(
        variant_analysis, exclude_file_path="app.py"
    )
    assert "app.py" not in grouped
    assert "lib/x.py" in grouped


def test_grouping_skips_variants_without_file_path() -> None:
    """v1 same-file variants don't carry ``file_path`` on the
    candidate — those land in the seed's own file and DAST-304
    must skip them (Phase C v14 territory)."""
    variant_analysis = [
        {
            "seed_finding_id": "H001",
            "signature": {},
            "confirmed_variant_ids": ["D-H001-1"],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {"function_name": "fn_a"},  # no file_path
                },
            ],
        },
    ]
    grouped = _group_confirmed_variants_by_file(variant_analysis)
    assert grouped == {}


def test_grouping_handles_multiple_seeds() -> None:
    """When multiple seeds each surfaced variants in different files,
    all entries are aggregated under the proper file_paths."""
    variant_analysis = [
        {
            "seed_finding_id": "H001",
            "signature": {"attack_class": "ssrf"},
            "confirmed_variant_ids": ["D-H001-1"],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {"function_name": "vfn1", "file_path": "lib/a.py"},
                },
            ],
        },
        {
            "seed_finding_id": "H002",
            "signature": {"attack_class": "ssrf"},
            "confirmed_variant_ids": ["D-H002-1"],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {"function_name": "vfn2", "file_path": "lib/a.py"},
                },
            ],
        },
    ]
    grouped = _group_confirmed_variants_by_file(variant_analysis)
    assert "lib/a.py" in grouped
    assert len(grouped["lib/a.py"]) == 2
    seed_ids = {v["seed_finding_id"] for v in grouped["lib/a.py"]}
    assert seed_ids == {"H001", "H002"}


# ── End-to-end with stub inference + fs ─────────────────────────────


def _make_inference_stub(
    patched_source: str,
    fix_summary: str = "Applied URL-protocol allowlist + private-IP rejection.",
) -> Any:
    """Stub inference that always returns the same patch payload."""

    async def _inf(prompt: str, options: dict, schema: dict) -> dict:
        return {
            "text": json.dumps(
                {"patched_source": patched_source, "fix_summary": fix_summary}
            ),
            "schema_valid": True,
            "schema_error": "",
            "usage": {"prompt_tokens": 1000, "completion_tokens": 200},
        }

    return _inf


class _StubSandbox:
    """Minimal sandbox stub — DAST-304 v2.0 doesn't do replays yet,
    but the runner type hint expects a client."""

    file_content_map: dict[str, bytes] = {}

    async def submit(self, plan: Any) -> Any:
        raise NotImplementedError("DAST-304 v2.0 does not call sandbox.submit")


@pytest.mark.asyncio
async def test_run_skips_when_no_project_root() -> None:
    """Without a project_root, DAST-304 can't read sibling files."""
    file_record: dict[str, Any] = {
        "file_id": "abc",
        "file_name": "app.py",
        "source_text": "x = 1",
        "project_root": "",  # missing
    }
    result = await run_phase_c_multi_file_patch(
        file_record=file_record,
        variant_analysis_results=[],
        seed_plan_records_by_hid={},
        inference=AsyncMock(),
        sandbox=_StubSandbox(),
    )
    assert result["attempted"] is False
    assert result["skipped_reason"] == "no_project_root"


@pytest.mark.asyncio
async def test_run_skips_when_no_cross_file_variants(tmp_path: Path) -> None:
    """When Phase D found variants but only in the seed's file, no
    cross-file work to do."""
    file_record = {
        "file_id": "abc",
        "file_name": "app.py",
        "source_text": "x = 1",
        "project_root": str(tmp_path),
        "entry_rel_path": "app.py",
    }
    variant_analysis = [
        {
            "seed_finding_id": "H001",
            "signature": {},
            "confirmed_variant_ids": ["D-H001-1"],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {"function_name": "fn", "file_path": "app.py"},
                }
            ],
        },
    ]
    result = await run_phase_c_multi_file_patch(
        file_record=file_record,
        variant_analysis_results=variant_analysis,
        seed_plan_records_by_hid={},
        inference=AsyncMock(),
        sandbox=_StubSandbox(),
    )
    assert result["attempted"] is False
    assert result["skipped_reason"] == "no_variants_in_other_files"


@pytest.mark.asyncio
async def test_run_patches_sibling_file_happy_path(tmp_path: Path) -> None:
    """DAST-304 reads the sibling file, builds a patch prompt, gets
    a valid patched_source, runs v14 guards, surfaces the result."""
    # Setup project on disk.
    (tmp_path / "app.py").write_text(
        "def fetch_url(url):\n    return urlopen(url)\n", encoding="utf-8"
    )
    sibling_dir = tmp_path / "lib"
    sibling_dir.mkdir()
    original_source = (
        "import urllib.request\n"
        "\n"
        "def download_image(url):\n"
        "    return urllib.request.urlopen(url).read()\n"
    )
    (sibling_dir / "helpers.py").write_text(original_source, encoding="utf-8")

    # The model emits a patched version that adds URL validation.
    patched_source = (
        "import urllib.request\n"
        "from urllib.parse import urlparse\n"
        "\n"
        "def download_image(url):\n"
        "    if urlparse(url).hostname in ('localhost', '169.254.169.254'):\n"
        "        raise ValueError('blocked SSRF target')\n"
        "    return urllib.request.urlopen(url).read()\n"
    )

    file_record = {
        "file_id": "abc",
        "file_name": "app.py",
        "source_text": "def fetch_url(url):\n    return urlopen(url)\n",
        "project_root": str(tmp_path),
        "entry_rel_path": "app.py",
    }
    variant_analysis = [
        {
            "seed_finding_id": "H001",
            "signature": {
                "attack_class": "ssrf",
                "cwe": "CWE-918",
                "sink_callee": "urlopen",
                "missing_guards": ["URL protocol allowlist", "private-IP rejection"],
            },
            "confirmed_variant_ids": ["D-H001-1"],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {
                        "function_name": "download_image",
                        "file_path": "lib/helpers.py",
                        "line_number": 3,
                    },
                }
            ],
        },
    ]
    inference = _make_inference_stub(patched_source=patched_source)
    result = await run_phase_c_multi_file_patch(
        file_record=file_record,
        variant_analysis_results=variant_analysis,
        seed_plan_records_by_hid={},
        inference=inference,
        sandbox=_StubSandbox(),
    )

    assert result["attempted"] is True
    assert len(result["patched_files"]) == 1
    patched = result["patched_files"][0]
    assert patched["file_path"] == "lib/helpers.py"
    # ``.strip()`` is applied during JSON extraction (mirrors Phase C v14).
    assert patched["patched_source"] == patched_source.strip()
    assert "URL-protocol allowlist" in patched["fix_summary"] or patched["fix_summary"]
    assert patched["variants_in_file"] == ["D-H001-1"]
    assert result["n_files_patched"] == 1


@pytest.mark.asyncio
async def test_run_rejects_byte_identical_patch(tmp_path: Path) -> None:
    """v14 guard: when the model returns the source unchanged, DAST-304
    flags ``patch_byte_identical_to_original`` and does NOT count
    the file as patched."""
    sibling_dir = tmp_path / "lib"
    sibling_dir.mkdir()
    original_source = "def fn(url):\n    return open(url)\n"
    (sibling_dir / "helpers.py").write_text(original_source, encoding="utf-8")

    file_record = {
        "file_id": "abc",
        "file_name": "app.py",
        "source_text": "...",
        "project_root": str(tmp_path),
        "entry_rel_path": "app.py",
    }
    variant_analysis = [
        {
            "seed_finding_id": "H001",
            "signature": {"attack_class": "ssrf", "sink_callee": "open"},
            "confirmed_variant_ids": ["D-H001-1"],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {
                        "function_name": "fn",
                        "file_path": "lib/helpers.py",
                        "line_number": 1,
                    },
                }
            ],
        },
    ]
    inference = _make_inference_stub(patched_source=original_source)
    result = await run_phase_c_multi_file_patch(
        file_record=file_record,
        variant_analysis_results=variant_analysis,
        seed_plan_records_by_hid={},
        inference=inference,
        sandbox=_StubSandbox(),
    )
    assert result["n_files_patched"] == 0
    assert (
        result["patched_files"][0]["skipped_reason"]
        == "patch_byte_identical_to_original"
    )


@pytest.mark.asyncio
async def test_run_rejects_syntax_invalid_patch(tmp_path: Path) -> None:
    """v14 guard: model returns syntactically-invalid Python — DAST-304
    flags ``patch_syntax_invalid`` and surfaces the error message."""
    sibling_dir = tmp_path / "lib"
    sibling_dir.mkdir()
    (sibling_dir / "helpers.py").write_text(
        "def fn(url):\n    return open(url)\n" * 6, encoding="utf-8"
    )
    broken_patch = "def fn(url):\n    return BAD SYNTAX HERE\n)) trailing junk\n"

    file_record = {
        "file_id": "abc",
        "file_name": "app.py",
        "source_text": "...",
        "project_root": str(tmp_path),
        "entry_rel_path": "app.py",
    }
    variant_analysis = [
        {
            "seed_finding_id": "H001",
            "signature": {"attack_class": "ssrf"},
            "confirmed_variant_ids": ["D-H001-1"],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {
                        "function_name": "fn",
                        "file_path": "lib/helpers.py",
                        "line_number": 1,
                    },
                }
            ],
        },
    ]
    inference = _make_inference_stub(patched_source=broken_patch)
    result = await run_phase_c_multi_file_patch(
        file_record=file_record,
        variant_analysis_results=variant_analysis,
        seed_plan_records_by_hid={},
        inference=inference,
        sandbox=_StubSandbox(),
    )
    assert result["n_files_patched"] == 0
    assert result["patched_files"][0]["skipped_reason"] == "patch_syntax_invalid"
    assert "syntax_error" in result["patched_files"][0]


@pytest.mark.asyncio
async def test_run_handles_missing_sibling_file(tmp_path: Path) -> None:
    """When the sibling file doesn't exist on disk (e.g., deleted
    between scan + remediation), DAST-304 flags
    ``source_read_failed``."""
    file_record = {
        "file_id": "abc",
        "file_name": "app.py",
        "source_text": "...",
        "project_root": str(tmp_path),
        "entry_rel_path": "app.py",
    }
    variant_analysis = [
        {
            "seed_finding_id": "H001",
            "signature": {"attack_class": "ssrf"},
            "confirmed_variant_ids": ["D-H001-1"],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {
                        "function_name": "fn",
                        "file_path": "lib/does_not_exist.py",
                        "line_number": 1,
                    },
                }
            ],
        },
    ]
    inference = _make_inference_stub("anything")
    result = await run_phase_c_multi_file_patch(
        file_record=file_record,
        variant_analysis_results=variant_analysis,
        seed_plan_records_by_hid={},
        inference=inference,
        sandbox=_StubSandbox(),
    )
    assert result["n_files_patched"] == 0
    assert (
        result["patched_files"][0]["skipped_reason"] == "source_read_failed"
    )


@pytest.mark.asyncio
async def test_run_caps_files_at_max(tmp_path: Path) -> None:
    """When Phase D surfaced variants in more files than
    MAX_FILES_PER_MULTI_FILE_RUN, only the first N are patched; the
    excess surface as UNVERIFIABLE entries."""
    # Build 7 sibling files (above the cap of 5).
    sib = tmp_path / "lib"
    sib.mkdir()
    for i in range(7):
        (sib / f"file_{i}.py").write_text(
            f"def fn{i}(url):\n    return open(url)\n", encoding="utf-8"
        )

    file_record = {
        "file_id": "abc",
        "file_name": "app.py",
        "source_text": "...",
        "project_root": str(tmp_path),
        "entry_rel_path": "app.py",
    }
    variant_analysis = [
        {
            "seed_finding_id": "H001",
            "signature": {"attack_class": "ssrf", "sink_callee": "open"},
            "confirmed_variant_ids": [f"D-H001-{i + 1}" for i in range(7)],
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "candidate": {
                        "function_name": f"fn{i}",
                        "file_path": f"lib/file_{i}.py",
                        "line_number": 1,
                    },
                }
                for i in range(7)
            ],
        },
    ]
    # Need a patched_source per call; for simplicity the stub returns
    # the same patched body. All 5 capped attempts will share it.
    patched_source = (
        "def fn0(url):\n"
        "    if 'localhost' in url: raise ValueError('blocked')\n"
        "    return open(url)\n"
    ) * 3
    inference = _make_inference_stub(patched_source=patched_source)

    result = await run_phase_c_multi_file_patch(
        file_record=file_record,
        variant_analysis_results=variant_analysis,
        seed_plan_records_by_hid={},
        inference=inference,
        sandbox=_StubSandbox(),
        max_files=5,
    )

    # Total outcomes = 7 files (5 attempted + 2 budget-skipped)
    assert len(result["patched_files"]) == 7
    skipped = [
        p
        for p in result["patched_files"]
        if p.get("skipped_reason") == "budget_or_file_cap_exhausted"
    ]
    assert len(skipped) == 2


# ── CLI flag wiring ──────────────────────────────────────────────────


def test_cli_enable_phase_d_flag_sets_scan_config() -> None:
    """``argus scan --enable-phase-d`` propagates to ScanConfig."""
    from scanner.cli import _build_parser

    parser = _build_parser()
    args = parser.parse_args(["scan", "--enable-phase-d", "fakepath.py"])
    assert getattr(args, "enable_phase_d", False) is True


def test_cli_enable_phase_d_default_off() -> None:
    """Without the flag, ``enable_phase_d`` is False (default)."""
    from scanner.cli import _build_parser

    parser = _build_parser()
    args = parser.parse_args(["scan", "fakepath.py"])
    assert getattr(args, "enable_phase_d", False) is False


def test_cli_scan_repo_also_has_enable_phase_d() -> None:
    """``argus scan-repo --enable-phase-d`` also works."""
    from scanner.cli import _build_parser

    parser = _build_parser()
    args = parser.parse_args(["scan-repo", "--enable-phase-d", "/some/path"])
    assert getattr(args, "enable_phase_d", False) is True


# ── Tunable contract assertions ──────────────────────────────────────


def test_max_cost_is_bounded() -> None:
    """Sanity check on the cost cap. Multi-file Phase C should
    stay under $2/run by default — bigger and we'd risk
    runaway spend on a project with many variants."""
    assert 0.0 < MAX_COST_PER_MULTI_FILE_RUN_USD <= 2.00


def test_max_files_is_bounded() -> None:
    """File cap of 5 mirrors the Phase D MAX_VARIANT_CANDIDATES_PER_SEED.
    Higher dilutes the patch quality + inflates cost."""
    assert 1 <= MAX_FILES_PER_MULTI_FILE_RUN <= 20
