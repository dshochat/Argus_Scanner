"""Unit tests for ``tools.extract_zero_days``.

Validates the zero-day filter, Gemini prompt emission, and the
summary writer. The tool itself reuses ``dast.cross_validation``'s
prompt builder for the actual prompt body — these tests focus on
the filter logic and file I/O contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.extract_zero_days import (
    _is_zero_day,
    _l1_attack_classes_for_file,
    _normalise_file_results,
    _safe_filename,
    main,
)


# ── Zero-day filter ────────────────────────────────────────────────────────


def test_zero_day_filter_keeps_confirmed_not_in_l1() -> None:
    """A CONFIRMED Phase 3 outcome with an attack class L1 didn't
    flag is the canonical zero-day class."""
    outcome = {
        "verdict": "confirmed",
        "hypothesis": {"attack_class": "ssrf"},
    }
    l1_covered: set[str] = set()  # L1 found nothing
    assert _is_zero_day(outcome, l1_covered) is True


def test_zero_day_filter_drops_refuted() -> None:
    """REFUTED outcomes are NOT zero-days — DAST disproved them."""
    outcome = {
        "verdict": "refuted",
        "hypothesis": {"attack_class": "ssrf"},
    }
    assert _is_zero_day(outcome, set()) is False


def test_zero_day_filter_drops_blocked() -> None:
    """BLOCKED outcomes (dispatch failed) are NOT zero-days."""
    outcome = {
        "verdict": "blocked",
        "hypothesis": {"attack_class": "command_injection"},
    }
    assert _is_zero_day(outcome, set()) is False


def test_zero_day_filter_drops_probe_observed() -> None:
    """probe_observed is informational, not a confirmed exploit."""
    outcome = {
        "verdict": "probe_observed",
        "hypothesis": {"attack_class": "exploratory"},
    }
    assert _is_zero_day(outcome, set()) is False


def test_zero_day_filter_drops_when_l1_already_covers_attack_class() -> None:
    """If L1 already flagged the same attack class, Phase 3 is just
    re-confirming — not zero-day."""
    outcome = {
        "verdict": "confirmed",
        "hypothesis": {"attack_class": "ssrf"},
    }
    l1_covered = {"ssrf"}
    assert _is_zero_day(outcome, l1_covered) is False


def test_zero_day_filter_normalises_dashes() -> None:
    """L1 may emit ``path-traversal`` while Phase 3 emits
    ``path_traversal`` — the filter should treat them as equivalent."""
    outcome = {
        "verdict": "confirmed",
        "hypothesis": {"attack_class": "path-traversal"},
    }
    l1_covered = {"path_traversal"}
    assert _is_zero_day(outcome, l1_covered) is False


def test_zero_day_filter_drops_empty_attack_class() -> None:
    """An outcome with no attack_class can't be classified — skip."""
    outcome = {
        "verdict": "confirmed",
        "hypothesis": {"attack_class": ""},
    }
    assert _is_zero_day(outcome, set()) is False


# ── L1 coverage extraction ─────────────────────────────────────────────────


def test_l1_covered_includes_cwe_id() -> None:
    """CWE ID is a primary correlation signal — both with and without
    the ``CWE-`` prefix get added."""
    file_result = {
        "vulnerabilities": [
            {"cwe": "CWE-918", "title": "SSRF in fetch"},
        ]
    }
    covered = _l1_attack_classes_for_file(file_result)
    assert "cwe-918" in covered
    assert "918" in covered


def test_l1_covered_includes_attack_class_field() -> None:
    """Explicit attack_class field on the finding is the cleanest
    correlation key."""
    file_result = {
        "vulnerabilities": [
            {"attack_class": "command_injection"},
        ]
    }
    covered = _l1_attack_classes_for_file(file_result)
    assert "command_injection" in covered


def test_l1_covered_keyword_match_in_title() -> None:
    """L1 findings worded as 'SSRF in foo()' suppress Phase 3 SSRF
    zero-day claims."""
    file_result = {
        "vulnerabilities": [
            {"cwe": "CWE-918", "title": "Server-Side Request Forgery (SSRF) via url param"},
        ]
    }
    covered = _l1_attack_classes_for_file(file_result)
    assert "ssrf" in covered


def test_l1_covered_keyword_normalises_path_traversal() -> None:
    """Dash/underscore variants must match. L1 title 'path-traversal'
    should add the underscore variant too."""
    file_result = {
        "vulnerabilities": [
            {"title": "path-traversal in readFile"},
        ]
    }
    covered = _l1_attack_classes_for_file(file_result)
    assert "path_traversal" in covered


def test_l1_covered_empty_for_no_findings() -> None:
    """A file with no L1 findings has empty coverage — every
    confirmed Phase 3 outcome is zero-day-class."""
    assert _l1_attack_classes_for_file({"vulnerabilities": []}) == set()
    assert _l1_attack_classes_for_file({}) == set()


# ── Schema normalisation ───────────────────────────────────────────────────


def test_normalise_single_file_scan() -> None:
    """A single-file scan output (the dict IS the file result)."""
    single = {"filename": "x.py", "vulnerabilities": [], "phase_3_loop": {}}
    assert _normalise_file_results(single) == [single]


def test_normalise_scan_repo_files_key() -> None:
    """scan-repo emits a list under 'files' (or 'results' /
    'file_results' / 'scans')."""
    envelope = {
        "files": [
            {"filename": "a.py", "vulnerabilities": []},
            {"filename": "b.py", "vulnerabilities": []},
        ]
    }
    out = _normalise_file_results(envelope)
    assert len(out) == 2
    assert out[0]["filename"] == "a.py"


def test_normalise_scan_repo_alt_keys() -> None:
    """Tolerant of 'results' (newer schema) too."""
    envelope = {"results": [{"filename": "x.py", "vulnerabilities": []}]}
    out = _normalise_file_results(envelope)
    assert len(out) == 1


def test_normalise_list_envelope() -> None:
    """Top-level list of file results — older scan-repo emitted this."""
    out = _normalise_file_results([{"filename": "x.py", "vulnerabilities": []}])
    assert len(out) == 1


def test_normalise_unrecognised_returns_empty() -> None:
    """Random dict without recognisable keys → empty list."""
    assert _normalise_file_results({"random": "garbage"}) == []
    assert _normalise_file_results("not even a dict") == []  # type: ignore[arg-type]


# ── Filename sanitiser ─────────────────────────────────────────────────────


def test_safe_filename_keeps_alphanum_dot_dash_underscore() -> None:
    assert _safe_filename("path-utils.ts") == "path-utils.ts"
    assert _safe_filename("MyClass_v2") == "MyClass_v2"


def test_safe_filename_replaces_unsafe_chars() -> None:
    assert _safe_filename("a/b/c") == "a_b_c"
    assert _safe_filename("foo?bar:baz") == "foo_bar_baz"
    assert _safe_filename("/leading/path") == "leading_path"


def test_safe_filename_handles_empty() -> None:
    assert _safe_filename("") == "unnamed"
    assert _safe_filename("///") == "unnamed"


# ── End-to-end CLI ────────────────────────────────────────────────────────


def test_cli_writes_summary_when_no_findings(tmp_path: Path) -> None:
    """A scan with Phase 3 outcomes but no zero-days still produces
    a summary file documenting that."""
    scan = {
        "filename": "x.py",
        "vulnerabilities": [{"cwe": "CWE-918", "title": "SSRF found"}],
        "phase_3_loop": {
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "hypothesis": {"attack_class": "ssrf"},  # already in L1 → skip
                    "oracle_type": "execution_output",
                }
            ]
        },
    }
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(json.dumps(scan), encoding="utf-8")
    out_dir = tmp_path / "out"
    rc = main([str(scan_path), "--output-dir", str(out_dir)])
    assert rc == 0
    assert (out_dir / "_summary.md").is_file()
    # No prompt files should exist
    txt_files = list(out_dir.glob("*.txt"))
    assert txt_files == []


def test_cli_emits_prompt_for_zero_day(tmp_path: Path) -> None:
    """A CONFIRMED Phase 3 outcome with attack_class not in L1's
    findings → one prompt .txt file emitted with non-empty body."""
    scan = {
        "filename": "vuln.py",
        "source_text": "def readFile(p): return open(p).read()\n",
        "file_intent_analysis": {"purpose": "Test target"},
        "vulnerabilities": [],  # L1 found nothing
        "phase_3_loop": {
            "outcomes": [
                {
                    "verdict": "confirmed",
                    "hypothesis": {
                        "kind": "single_function",
                        "function_name": "readFile",
                        "attack_class": "path_traversal",
                        "args_json": '["../etc/passwd"]',
                        "kwargs_json": "{}",
                        "rationale": "reads path directly",
                        "expected_observable": "reads /etc/passwd",
                        "rejection_signature": "",
                        "exploit_proof_if_observed": "",
                    },
                    "oracle_type": "execution_output",
                    "runtime_evidence": "stdout contains /etc/passwd content",
                    "judge_verdict": "CONFIRMED",
                    "judge_reasoning": "no rejection signature observed",
                    "elapsed_ms": 1234,
                }
            ]
        },
    }
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(json.dumps(scan), encoding="utf-8")
    out_dir = tmp_path / "out"
    rc = main([str(scan_path), "--output-dir", str(out_dir)])
    assert rc == 0

    txt_files = list(out_dir.glob("*.txt"))
    assert len(txt_files) == 1
    body = txt_files[0].read_text(encoding="utf-8")
    # Prompt structure landmarks (from build_cross_validation_prompt)
    assert "vuln.py" in body
    assert "def readFile" in body  # source code embedded
    assert "path_traversal" in body
    assert "readFile" in body
    assert "Test target" in body  # file purpose embedded
    assert "REFUTED" in body or "CONFIRMED" in body  # task instruction
    # Summary lists the finding
    summary = (out_dir / "_summary.md").read_text(encoding="utf-8")
    assert "vuln.py" in summary
    assert "readFile" in summary
    assert "path_traversal" in summary


def test_cli_missing_scan_output_returns_2(tmp_path: Path) -> None:
    """Bad input path → exit code 2 (not crash)."""
    rc = main([str(tmp_path / "nonexistent.json")])
    assert rc == 2


def test_cli_malformed_json_returns_2(tmp_path: Path) -> None:
    """Bad JSON → exit code 2."""
    bad = tmp_path / "bad.json"
    bad.write_text("not json at all", encoding="utf-8")
    rc = main([str(bad)])
    assert rc == 2


def test_cli_scan_repo_envelope_multiple_files(tmp_path: Path) -> None:
    """scan-repo envelope with multiple files — extractor walks all."""
    envelope = {
        "files": [
            {
                "filename": "a.py",
                "vulnerabilities": [],
                "source_text": "def f(p): pass\n",
                "phase_3_loop": {
                    "outcomes": [
                        {
                            "verdict": "confirmed",
                            "hypothesis": {
                                "function_name": "f",
                                "attack_class": "ssrf",
                                "kind": "probe",
                                "args_json": "[]",
                                "kwargs_json": "{}",
                                "rationale": "",
                                "expected_observable": "",
                            },
                            "oracle_type": "execution_output",
                            "runtime_evidence": "",
                        }
                    ]
                },
            },
            {
                "filename": "b.py",
                "vulnerabilities": [],
                "source_text": "def g(p): pass\n",
                "phase_3_loop": {
                    "outcomes": [
                        {
                            "verdict": "confirmed",
                            "hypothesis": {
                                "function_name": "g",
                                "attack_class": "command_injection",
                                "kind": "probe",
                                "args_json": "[]",
                                "kwargs_json": "{}",
                                "rationale": "",
                                "expected_observable": "",
                            },
                            "oracle_type": "execution_output",
                            "runtime_evidence": "",
                        }
                    ]
                },
            },
        ]
    }
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(json.dumps(envelope), encoding="utf-8")
    out_dir = tmp_path / "out"
    rc = main([str(scan_path), "--output-dir", str(out_dir)])
    assert rc == 0
    txt_files = sorted(p.name for p in out_dir.glob("*.txt"))
    assert len(txt_files) == 2
    # Both filename stems appear in some prompt file
    joined = " ".join(txt_files)
    assert "a__" in joined
    assert "b__" in joined
