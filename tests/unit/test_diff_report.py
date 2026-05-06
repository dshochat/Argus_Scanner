"""Unit tests for methodology.diff_report — BENCH-010 three-source comparison.

No live API; everything is constructed from synthetic BenchRows + dict fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path

from methodology.bench import BenchRow
from methodology.diff_report import (
    FindingRef,
    _is_refusal,
    _normalize_filename,
    build_diff_record,
    build_diff_report,
    build_judge_payload,
    compute_overlap,
    extract_capability_tags,
    load_baseline_oracle,
    load_rich_oracle,
    normalize_argus_vulnerability,
    normalize_oracle_finding,
    render_markdown,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def _row(
    file_name: str,
    predicted: str | None,
    *,
    config: str = "argus_full",
    vulns: list[dict] | None = None,
    behavioral: dict | None = None,
    chains: list[dict] | None = None,
    scan_path: list[str] | None = None,
    dast_attempted: bool = False,
    error: str | None = None,
) -> BenchRow:
    return BenchRow(
        file_name=file_name,
        oracle_verdict="critical_malicious",
        predicted_verdict=predicted,
        config=config,
        cost_usd=0.1,
        duration_ms=1000,
        vulnerabilities=vulns or [],
        behavioral_profile=behavioral or {},
        attack_chains=chains or [],
        scan_path=scan_path or [],
        dast_attempted=dast_attempted,
        error=error,
    )


# ── Filename normalization ────────────────────────────────────────────────────


def test_normalize_filename_strips_numeric_prefix() -> None:
    assert _normalize_filename("01_litellm_obfuscated.py") == "litellm_obfuscated.py"
    assert _normalize_filename("9_foo.py") == "foo.py"


def test_normalize_filename_strips_category_prefix() -> None:
    assert (
        _normalize_filename("supply_c__docker_entrypoint_init.py")
        == "docker_entrypoint_init.py"
    )
    assert _normalize_filename("vulnerab__sandbox_runner.js") == "sandbox_runner.js"
    assert _normalize_filename("attack_c__c2.py") == "c2.py"
    assert _normalize_filename("malware__beacon.py") == "beacon.py"


def test_normalize_filename_idempotent_on_canonical() -> None:
    assert _normalize_filename("litellm_obfuscated.py") == "litellm_obfuscated.py"
    assert _normalize_filename("plain.py") == "plain.py"


def test_normalize_filename_strips_both_prefixes() -> None:
    # Numeric stripped first, then category — order matters for chained prefixes.
    assert (
        _normalize_filename("01_supply_c__docker.py")
        == "docker.py"
    )


# ── FindingRef normalizers ────────────────────────────────────────────────────


def test_normalize_argus_vulnerability_full() -> None:
    v = {
        "cwe": "cwe-522",
        "type": "Credential Access",
        "severity": "Critical",
        "line": 42,
        "confidence": 0.92,
        "explanation": "Reads SSH private key and exfils via HTTP",
    }
    f = normalize_argus_vulnerability(v)
    assert f.cwe == "CWE-522"
    assert f.type == "credential access"
    assert f.severity == "critical"
    assert f.line == 42
    assert f.confidence == 0.92
    assert "exfils" in f.title


def test_normalize_argus_vulnerability_missing_fields() -> None:
    f = normalize_argus_vulnerability({})
    assert f.cwe == ""
    assert f.type == ""
    assert f.severity == ""
    assert f.line is None
    assert f.confidence is None
    assert f.title == ""


def test_normalize_argus_vulnerability_non_int_line_dropped() -> None:
    f = normalize_argus_vulnerability({"line": "42"})
    assert f.line is None


def test_normalize_oracle_finding_extracts_first_line() -> None:
    f = normalize_oracle_finding(
        {
            "cwe": "CWE-78",
            "type": "command_injection",
            "severity": "high",
            "title": "Shell exec from user input",
            "code_snippet": {"lines": [12, 13, 14]},
        }
    )
    assert f.cwe == "CWE-78"
    assert f.type == "command_injection"
    assert f.severity == "high"
    assert f.line == 12
    assert f.title == "Shell exec from user input"


def test_normalize_oracle_finding_handles_missing_snippet() -> None:
    f = normalize_oracle_finding({"cwe": "CWE-99"})
    assert f.cwe == "CWE-99"
    assert f.line is None


# ── load_baseline_oracle ──────────────────────────────────────────────────────


def test_load_baseline_oracle_round_trip(tmp_path: Path) -> None:
    payload = {
        "files": [
            {
                "file_name": "litellm_obfuscated.py",
                "oracle_verdict": "critical_malicious",
                "baseline_verdict": "critical_malicious",
                "source": "opus_confirmed",
                "tier": "tier1",
                "tracking": "tier1",
            },
            {
                "file_name": "benign.py",
                "oracle_verdict": "clean",
                "source": "variance_characterization",
                "tier": "tier3",
            },
        ]
    }
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps(payload))
    out = load_baseline_oracle(p)
    assert "litellm_obfuscated.py" in out
    assert out["litellm_obfuscated.py"]["oracle_verdict"] == "critical_malicious"
    assert out["litellm_obfuscated.py"]["source"] == "opus_confirmed"
    assert out["benign.py"]["oracle_verdict"] == "clean"


def test_load_baseline_oracle_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_baseline_oracle(tmp_path / "does_not_exist.json") == {}


# ── load_rich_oracle ──────────────────────────────────────────────────────────


def test_load_rich_oracle_normalizes_filename(tmp_path: Path) -> None:
    payload = [
        {
            "file_name": "01_litellm_obfuscated.py",
            "model": "claude-opus-4-7",
            "full_label": {
                "verdict": {"verdict_label": "critical_malicious"},
                "analysis": {
                    "findings": [
                        {
                            "cwe": "CWE-522",
                            "type": "credential_access",
                            "severity": "critical",
                            "title": "SSH key read",
                            "code_snippet": {"lines": [10, 11]},
                        }
                    ]
                },
                "extractions": {
                    "capabilities": {
                        "tags": ["credential_access", "data_exfiltration"],
                        "dangerous_apis": ["urllib.urlopen"],
                    }
                },
            },
        }
    ]
    p = tmp_path / "augmented.json"
    p.write_text(json.dumps(payload))
    out = load_rich_oracle(p)
    # Key should be normalized — prefix stripped.
    assert "litellm_obfuscated.py" in out
    assert "01_litellm_obfuscated.py" not in out
    entry = out["litellm_obfuscated.py"]
    assert entry["model"] == "claude-opus-4-7"
    assert entry["raw_filename"] == "01_litellm_obfuscated.py"
    assert entry["verdict_label"] == "critical_malicious"
    assert entry["capability_tags"] == ["credential_access", "data_exfiltration"]
    assert entry["dangerous_apis"] == ["urllib.urlopen"]
    assert len(entry["findings"]) == 1
    assert entry["findings"][0].cwe == "CWE-522"
    assert entry["findings"][0].line == 10


def test_load_rich_oracle_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_rich_oracle(tmp_path / "missing.json") == {}


def test_load_rich_oracle_handles_malformed_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("not json{")
    assert load_rich_oracle(p) == {}


# ── compute_overlap ───────────────────────────────────────────────────────────


def test_compute_overlap_perfect_match() -> None:
    m = compute_overlap({"CWE-78", "CWE-522"}, {"CWE-78", "CWE-522"})
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0
    assert m["jaccard"] == 1.0


def test_compute_overlap_partial() -> None:
    # scanner: {A,B}, oracle: {B,C}, intersection: {B}
    m = compute_overlap({"A", "B"}, {"B", "C"})
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5
    assert m["f1"] == 0.5
    assert m["jaccard"] == round(1 / 3, 3)


def test_compute_overlap_disjoint() -> None:
    m = compute_overlap({"A"}, {"B"})
    assert m["precision"] == 0.0
    assert m["recall"] == 0.0
    assert m["f1"] == 0.0
    assert m["jaccard"] == 0.0


def test_compute_overlap_both_empty_vacuously_perfect() -> None:
    m = compute_overlap(set(), set())
    assert m == {"precision": 1.0, "recall": 1.0, "f1": 1.0, "jaccard": 1.0}


def test_compute_overlap_one_empty() -> None:
    m = compute_overlap(set(), {"X"})
    assert m["precision"] == 0.0
    assert m["recall"] == 0.0
    m2 = compute_overlap({"X"}, set())
    assert m2["precision"] == 0.0
    assert m2["recall"] == 0.0


# ── extract_capability_tags ───────────────────────────────────────────────────


def test_extract_capability_tags_network_and_credentials() -> None:
    row = _row(
        "exfil.py",
        "critical_malicious",
        behavioral={
            "actual_capabilities": {
                "network_calls": ["urllib.urlopen"],
                "file_operations": ["read /etc/passwd"],
                "commands_executed": ["subprocess.run"],
            },
            "exfiltration_risk": {"external_network_calls": True},
            "obfuscation_signals": {"encoded_strings": True},
        },
        vulns=[{"type": "credential_access", "explanation": "Reads SSH key"}],
    )
    tags = extract_capability_tags(row)
    assert "network_outbound" in tags
    assert "file_read" in tags
    assert "process_spawn" in tags
    assert "dynamic_execution" in tags
    assert "credential_access" in tags
    assert "data_exfiltration" in tags
    assert "defense_evasion" in tags
    assert "data_encoding" in tags


def test_extract_capability_tags_empty_row_returns_empty() -> None:
    row = _row("clean.py", "clean")
    assert extract_capability_tags(row) == set()


def test_extract_capability_tags_c2_keyword_in_attack_chain() -> None:
    row = _row(
        "c2.py",
        "critical_malicious",
        chains=[{"name": "C2 beacon channel"}],
    )
    tags = extract_capability_tags(row)
    assert "c2_communication" in tags


# ── _is_refusal ───────────────────────────────────────────────────────────────


def test_is_refusal_detects_stop_reason_refusal() -> None:
    row = _row("foo.py", None, error="stop_reason=refusal")
    assert _is_refusal(row) is True


def test_is_refusal_detects_refused() -> None:
    row = _row("foo.py", None, error="model refused to comply")
    assert _is_refusal(row) is True


def test_is_refusal_none_for_no_error() -> None:
    assert _is_refusal(_row("foo.py", "clean")) is False
    assert _is_refusal(None) is False


# ── build_judge_payload ───────────────────────────────────────────────────────


def test_build_judge_payload_two_positions() -> None:
    argus = _row(
        "f.py",
        "critical_malicious",
        vulns=[{"cwe": "CWE-78", "type": "cmd_injection"}],
        scan_path=["triage", "sonnet", "dast_verification"],
        dast_attempted=True,
    )
    opus = _row("f.py", "suspicious", config="raw_opus")
    payload = build_judge_payload("f.py", argus, opus, "critical_malicious", "src=...")
    assert payload["file_name"] == "f.py"
    assert payload["file_content"] == "src=..."
    assert payload["oracle_verdict"] == "critical_malicious"
    assert len(payload["positions"]) == 2
    p_argus, p_opus = payload["positions"]
    assert p_argus["_label_internal"] == "argus"
    assert p_argus["verdict"] == "critical_malicious"
    assert p_argus["n_findings"] == 1
    assert p_argus["dast_attempted"] is True
    assert "dast_verification" in p_argus["scan_path"]
    assert p_opus["_label_internal"] == "opus"
    assert p_opus["verdict"] == "suspicious"
    assert p_opus["n_findings"] == 0


def test_build_judge_payload_handles_missing_row() -> None:
    payload = build_judge_payload("f.py", None, None, None, None)
    assert payload["positions"][0]["verdict"] is None
    assert payload["positions"][0]["n_findings"] == 0


# ── build_diff_record ─────────────────────────────────────────────────────────


def test_build_diff_record_all_match_no_disagreement() -> None:
    argus = _row(
        "litellm.py",
        "critical_malicious",
        vulns=[{"cwe": "CWE-522", "type": "cred_access", "severity": "critical"}],
    )
    opus = _row(
        "litellm.py",
        "critical_malicious",
        config="raw_opus",
        vulns=[{"cwe": "CWE-522", "type": "cred_access", "severity": "critical"}],
    )
    baseline = {
        "oracle_verdict": "critical_malicious",
        "source": "opus_confirmed",
    }
    rec = build_diff_record("litellm.py", argus, opus, baseline, None)

    assert rec["file_name"] == "litellm.py"
    vm = rec["verdict_match"]
    assert vm["argus"] == "critical_malicious"
    assert vm["opus"] == "critical_malicious"
    assert vm["oracle"] == "critical_malicious"
    assert vm["all_match"] is True
    assert vm["label_provenance"] == "opus_confirmed"
    # No rich oracle → no overlap fields, no judge.
    assert rec["cwe_overlap"] is None
    assert rec["capability_overlap"] is None
    assert rec["judge_payload"] is None
    assert rec["argus_refused"] is False
    assert rec["opus_refused"] is False
    assert len(rec["findings_per_source"]["argus"]) == 1
    assert rec["findings_per_source"]["oracle"] is None


def test_build_diff_record_disagreement_triggers_judge_payload() -> None:
    argus = _row("f.py", "critical_malicious")
    opus = _row("f.py", "suspicious", config="raw_opus")
    baseline = {"oracle_verdict": "critical_malicious", "source": "opus_confirmed"}
    rec = build_diff_record("f.py", argus, opus, baseline, None, file_content="x")

    assert rec["verdict_match"]["all_match"] is False
    assert rec["judge_payload"] is not None
    assert rec["judge_payload"]["file_name"] == "f.py"
    assert rec["judge_payload"]["file_content"] == "x"


def test_build_diff_record_with_rich_oracle_computes_cwe_overlap() -> None:
    argus = _row(
        "lit.py",
        "critical_malicious",
        vulns=[
            {"cwe": "CWE-522", "type": "cred", "severity": "critical"},
            {"cwe": "CWE-78", "type": "cmd_injection", "severity": "high"},
        ],
    )
    opus = _row(
        "lit.py",
        "critical_malicious",
        config="raw_opus",
        vulns=[{"cwe": "CWE-522", "type": "cred", "severity": "critical"}],
    )
    baseline = {"oracle_verdict": "critical_malicious", "source": "opus_confirmed"}
    rich = {
        "findings": [
            FindingRef(
                cwe="CWE-522",
                type="cred",
                severity="critical",
                line=10,
                confidence=None,
                title="ssh key read",
            )
        ],
        "capability_tags": ["credential_access"],
        "dangerous_apis": [],
        "verdict_label": "critical_malicious",
        "model": "claude-opus-4-7",
        "raw_filename": "01_lit.py",
    }
    rec = build_diff_record("lit.py", argus, opus, baseline, rich)

    # Rich-oracle present → provenance picked up from model.
    assert rec["verdict_match"]["label_provenance"] == "opus_confirmed"

    overlap = rec["cwe_overlap"]
    assert overlap is not None
    # Argus has {CWE-522, CWE-78}, oracle has {CWE-522}.
    # precision = 1/2 = 0.5, recall = 1/1 = 1.0
    assert overlap["argus_vs_oracle"]["precision"] == 0.5
    assert overlap["argus_vs_oracle"]["recall"] == 1.0
    # Opus has {CWE-522}, perfect match.
    assert overlap["opus_vs_oracle"]["precision"] == 1.0
    assert overlap["opus_vs_oracle"]["recall"] == 1.0


def test_build_diff_record_dast_artifacts_collected() -> None:
    argus = _row(
        "f.py",
        "critical_malicious",
        scan_path=["triage", "sonnet", "dast_verification", "dast_iter3_opus"],
        dast_attempted=True,
    )
    rec = build_diff_record(
        "f.py",
        argus,
        None,
        {"oracle_verdict": "critical_malicious", "source": "opus_confirmed"},
        None,
    )
    stages = [a["stage"] for a in rec["dast_artifacts_argus"]]
    assert "dast_verification" in stages
    assert "dast_iter3_opus" in stages


def test_build_diff_record_refusal_propagates() -> None:
    argus = _row("f.py", None, error="stop_reason=refusal")
    rec = build_diff_record(
        "f.py",
        argus,
        None,
        {"oracle_verdict": "critical_malicious", "source": "opus_confirmed"},
        None,
    )
    assert rec["argus_refused"] is True
    assert rec["opus_refused"] is False


# ── build_diff_report (aggregator) ────────────────────────────────────────────


def test_build_diff_report_iterates_all_baseline_files(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file_name": "a.py",
                        "oracle_verdict": "critical_malicious",
                        "source": "opus_confirmed",
                    },
                    {
                        "file_name": "b.py",
                        "oracle_verdict": "clean",
                        "source": "variance_characterization",
                    },
                ]
            }
        )
    )
    argus_rows = [
        _row("a.py", "critical_malicious"),
        _row("b.py", "clean"),
    ]
    opus_rows = [
        _row("a.py", "critical_malicious", config="raw_opus"),
        _row("b.py", "clean", config="raw_opus"),
    ]
    records = build_diff_report(argus_rows, opus_rows, baseline_path, None)
    assert len(records) == 2
    file_names = [r["file_name"] for r in records]
    assert file_names == ["a.py", "b.py"]
    # All match → no judge payloads.
    assert all(r["judge_payload"] is None for r in records)


def test_build_diff_report_handles_missing_runs(tmp_path: Path) -> None:
    """A file in the baseline but not in either run gets None verdicts."""
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file_name": "a.py",
                        "oracle_verdict": "critical_malicious",
                        "source": "opus_confirmed",
                    }
                ]
            }
        )
    )
    records = build_diff_report([], [], baseline_path, None)
    assert len(records) == 1
    assert records[0]["verdict_match"]["argus"] is None
    assert records[0]["verdict_match"]["opus"] is None


# ── render_markdown ───────────────────────────────────────────────────────────


def test_render_markdown_includes_aggregate_lines() -> None:
    records = [
        {
            "file_name": "a.py",
            "verdict_match": {
                "argus": "critical_malicious",
                "opus": "critical_malicious",
                "oracle": "critical_malicious",
                "label_provenance": "opus_confirmed",
                "all_match": True,
            },
            "findings_per_source": {"argus": [], "opus": [], "oracle": None},
            "cwe_overlap": None,
            "capability_overlap": None,
            "dast_artifacts_argus": [],
            "argus_refused": False,
            "opus_refused": False,
            "judge_payload": None,
        },
        {
            "file_name": "b.py",
            "verdict_match": {
                "argus": "suspicious",
                "opus": "clean",
                "oracle": "critical_malicious",
                "label_provenance": "variance_characterization",
                "all_match": False,
            },
            "findings_per_source": {"argus": [], "opus": [], "oracle": None},
            "cwe_overlap": None,
            "capability_overlap": None,
            "dast_artifacts_argus": [],
            "argus_refused": False,
            "opus_refused": False,
            "judge_payload": {"file_name": "b.py"},
        },
    ]
    md = render_markdown(records)
    assert "# BENCH-010" in md
    assert "Argus verdict matches oracle**: 1/2" in md
    assert "Vanilla Opus verdict matches oracle**: 1/2" in md
    assert "Disagreements" in md
    assert "1/2" in md  # disagreement count
    assert "`a.py`" in md
    assert "`b.py`" in md
