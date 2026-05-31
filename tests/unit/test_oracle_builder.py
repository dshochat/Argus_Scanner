"""Unit tests for methodology.oracle_builder — multi-vendor consensus oracle."""

from __future__ import annotations

import json
from pathlib import Path

from methodology.oracle_builder import (
    RANK_TO_VERDICT,
    VERDICT_RANK,
    build_consensus_oracle,
    build_consensus_record,
    compare_oracles,
    median_verdict,
    write_consensus_oracle,
)
from methodology.voters import VoterRecord


def _vr(
    *,
    file_name: str,
    voter_name: str,
    verdict: str | None,
    score: int | None = None,
    error: str | None = None,
    findings: list[dict] | None = None,
    raw_output: dict | None = None,
) -> VoterRecord:
    return VoterRecord(
        file_name=file_name,
        voter_name=voter_name,
        predicted_verdict=verdict,
        composite_score=score,
        cost_usd=0.01,
        duration_ms=100,
        error=error,
        raw_findings=findings or [],
        raw_output=raw_output or {},
    )


# ── VERDICT_RANK monotonic ────────────────────────────────────────────────────


def test_verdict_rank_monotonic() -> None:
    assert VERDICT_RANK["clean"] < VERDICT_RANK["suspicious"]
    assert VERDICT_RANK["suspicious"] < VERDICT_RANK["malicious"]
    assert VERDICT_RANK["malicious"] < VERDICT_RANK["critical_malicious"]
    # Round-trip through RANK_TO_VERDICT.
    for v, r in VERDICT_RANK.items():
        assert RANK_TO_VERDICT[r] == v


# ── median_verdict ───────────────────────────────────────────────────────────


def test_median_3_unanimous() -> None:
    assert median_verdict(["suspicious", "suspicious", "suspicious"]) == "suspicious"


def test_median_3_two_one_split() -> None:
    # 2 suspicious + 1 malicious → median is suspicious
    assert median_verdict(["suspicious", "suspicious", "malicious"]) == "suspicious"
    # 1 suspicious + 2 malicious → median is malicious
    assert median_verdict(["suspicious", "malicious", "malicious"]) == "malicious"


def test_median_3_three_way_split() -> None:
    # clean / suspicious / malicious → median is suspicious (middle)
    assert median_verdict(["clean", "suspicious", "malicious"]) == "suspicious"
    # suspicious / malicious / critical → median is malicious
    assert median_verdict(["suspicious", "malicious", "critical_malicious"]) == "malicious"


def test_median_even_count_breaks_low() -> None:
    # 4 votes: clean, suspicious, malicious, critical_malicious
    # ranks: 0, 1, 2, 3 → middle pair is (1, 2) → take lower (1) = suspicious
    assert (
        median_verdict(["clean", "suspicious", "malicious", "critical_malicious"]) == "suspicious"
    )


def test_median_drops_unknown_labels() -> None:
    # "informational" is not in VERDICT_RANK — should be ignored
    assert median_verdict(["informational", "suspicious", "malicious"]) == "suspicious"


def test_median_empty_returns_none() -> None:
    assert median_verdict([]) is None
    assert median_verdict(["unknown_label"]) is None


# ── build_consensus_record ───────────────────────────────────────────────────


def test_consensus_record_unanimous() -> None:
    voters = [
        _vr(file_name="a.py", voter_name="opus_4_6", verdict="critical_malicious"),
        _vr(file_name="a.py", voter_name="gemini_3_1_pro", verdict="critical_malicious"),
        _vr(file_name="a.py", voter_name="gpt_5_5", verdict="critical_malicious"),
    ]
    rec = build_consensus_record("a.py", voters)
    assert rec["oracle_verdict"] == "critical_malicious"
    assert rec["is_unanimous"] is True
    assert rec["is_majority"] is True
    assert rec["n_voters"] == 3
    assert rec["spread"] == 0
    assert rec["voter_verdicts"] == {
        "opus_4_6": "critical_malicious",
        "gemini_3_1_pro": "critical_malicious",
        "gpt_5_5": "critical_malicious",
    }


def test_consensus_record_two_one_split() -> None:
    voters = [
        _vr(file_name="b.py", voter_name="opus_4_6", verdict="suspicious"),
        _vr(file_name="b.py", voter_name="gemini_3_1_pro", verdict="suspicious"),
        _vr(file_name="b.py", voter_name="gpt_5_5", verdict="malicious"),
    ]
    rec = build_consensus_record("b.py", voters)
    assert rec["oracle_verdict"] == "suspicious"
    assert rec["is_unanimous"] is False
    assert rec["is_majority"] is True
    assert rec["spread"] == 1


def test_consensus_record_three_way_split() -> None:
    voters = [
        _vr(file_name="c.py", voter_name="opus_4_6", verdict="clean"),
        _vr(file_name="c.py", voter_name="gemini_3_1_pro", verdict="suspicious"),
        _vr(file_name="c.py", voter_name="gpt_5_5", verdict="malicious"),
    ]
    rec = build_consensus_record("c.py", voters)
    assert rec["oracle_verdict"] == "suspicious"  # ordinal median
    assert rec["is_unanimous"] is False
    assert rec["is_majority"] is False  # no single label has >1.5
    assert rec["spread"] == 2


def test_consensus_record_drops_errored_voters() -> None:
    voters = [
        _vr(file_name="d.py", voter_name="opus_4_6", verdict="critical_malicious"),
        _vr(file_name="d.py", voter_name="gemini_3_1_pro", verdict=None, error="api_failed"),
        _vr(file_name="d.py", voter_name="gpt_5_5", verdict="critical_malicious"),
    ]
    rec = build_consensus_record("d.py", voters)
    assert rec["oracle_verdict"] == "critical_malicious"
    assert rec["n_voters"] == 2  # gemini errored — not counted
    assert "gemini_3_1_pro" not in rec["voter_verdicts"]


def test_consensus_record_no_valid_voters() -> None:
    voters = [
        _vr(file_name="e.py", voter_name="opus_4_6", verdict=None, error="api_failed"),
    ]
    rec = build_consensus_record("e.py", voters)
    assert rec["oracle_verdict"] is None
    assert rec["n_voters"] == 0


# ── build_consensus_oracle (file-level orchestrator) ─────────────────────────


def test_build_consensus_oracle_end_to_end(tmp_path: Path) -> None:
    # Stage two voter files with overlapping but slightly disagreeing data.
    opus_data = [
        {
            "file_name": "a.py",
            "voter_name": "opus_4_6",
            "predicted_verdict": "critical_malicious",
            "composite_score": 90,
            "cost_usd": 0.30,
            "duration_ms": 60000,
            "raw_findings": [],
        },
        {
            "file_name": "b.py",
            "voter_name": "opus_4_6",
            "predicted_verdict": "suspicious",
            "composite_score": 30,
            "cost_usd": 0.20,
            "duration_ms": 50000,
            "raw_findings": [],
        },
    ]
    gemini_data = [
        {
            "file_name": "a.py",
            "voter_name": "gemini_3_1_pro",
            "predicted_verdict": "malicious",  # disagreement: opus said critical
            "composite_score": 60,
            "cost_usd": 0.10,
            "duration_ms": 30000,
            "raw_findings": [],
        },
        {
            "file_name": "b.py",
            "voter_name": "gemini_3_1_pro",
            "predicted_verdict": "suspicious",
            "composite_score": 35,
            "cost_usd": 0.10,
            "duration_ms": 30000,
            "raw_findings": [],
        },
    ]
    gpt_data = [
        {
            "file_name": "a.py",
            "voter_name": "gpt_5_5",
            "predicted_verdict": "critical_malicious",
            "composite_score": 80,
            "cost_usd": 0.05,
            "duration_ms": 15000,
            "raw_findings": [],
        },
        {
            "file_name": "b.py",
            "voter_name": "gpt_5_5",
            "predicted_verdict": "clean",  # disagreement: others said suspicious
            "composite_score": 0,
            "cost_usd": 0.04,
            "duration_ms": 12000,
            "raw_findings": [],
        },
    ]
    op = tmp_path / "opus.json"
    gp = tmp_path / "gemini.json"
    gt = tmp_path / "gpt.json"
    op.write_text(json.dumps(opus_data))
    gp.write_text(json.dumps(gemini_data))
    gt.write_text(json.dumps(gpt_data))

    voter_files = {
        "opus_4_6": op,
        "gemini_3_1_pro": gp,
        "gpt_5_5": gt,
    }
    oracle = build_consensus_oracle(voter_files, ["a.py", "b.py"])

    assert oracle["metadata"]["voters"] == ["opus_4_6", "gemini_3_1_pro", "gpt_5_5"]
    assert oracle["metadata"]["n_files"] == 2
    files = {f["file_name"]: f for f in oracle["files"]}

    # a.py: critical / malicious / critical → median = critical_malicious
    assert files["a.py"]["oracle_verdict"] == "critical_malicious"
    assert files["a.py"]["is_majority"] is True
    assert files["a.py"]["is_unanimous"] is False

    # b.py: suspicious / suspicious / clean → median = suspicious
    assert files["b.py"]["oracle_verdict"] == "suspicious"
    assert files["b.py"]["is_majority"] is True


def test_build_consensus_oracle_handles_missing_voter_records(tmp_path: Path) -> None:
    """If a voter has no record for a file, it just isn't counted —
    the consensus still computes from the remaining voters."""
    opus = [
        {
            "file_name": "a.py",
            "voter_name": "opus_4_6",
            "predicted_verdict": "critical_malicious",
            "composite_score": 80,
            "cost_usd": 0.0,
            "duration_ms": 0,
            "raw_findings": [],
        }
    ]
    op = tmp_path / "opus.json"
    op.write_text(json.dumps(opus))
    oracle = build_consensus_oracle({"opus_4_6": op}, ["a.py", "b.py"])
    files = {f["file_name"]: f for f in oracle["files"]}
    assert files["a.py"]["oracle_verdict"] == "critical_malicious"
    assert files["a.py"]["n_voters"] == 1
    assert files["b.py"]["oracle_verdict"] is None
    assert files["b.py"]["n_voters"] == 0


# ── write_consensus_oracle ───────────────────────────────────────────────────


def test_write_consensus_oracle_round_trip(tmp_path: Path) -> None:
    oracle = {
        "files": [{"file_name": "a.py", "oracle_verdict": "clean"}],
        "metadata": {"voters": ["opus_4_6"], "tie_break": "ordinal_median", "n_files": 1},
    }
    p = tmp_path / "oracle.json"
    write_consensus_oracle(oracle, p)
    assert p.exists()
    loaded = json.loads(p.read_text(encoding="utf-8"))
    assert loaded == oracle


# ── compare_oracles ──────────────────────────────────────────────────────────


def test_compare_oracles_identifies_changed_labels(tmp_path: Path) -> None:
    old = {
        "files": [
            {"file_name": "a.py", "oracle_verdict": "critical_malicious"},
            {"file_name": "b.py", "oracle_verdict": "suspicious"},
            {"file_name": "c.py", "oracle_verdict": "clean"},
        ]
    }
    new = {
        "files": [
            {
                "file_name": "a.py",
                "oracle_verdict": "critical_malicious",
                "voter_verdicts": {"opus_4_6": "critical_malicious"},
            },
            {
                "file_name": "b.py",
                "oracle_verdict": "malicious",  # changed!
                "voter_verdicts": {"opus_4_6": "malicious"},
            },
            {
                "file_name": "c.py",
                "oracle_verdict": "clean",
                "voter_verdicts": {"opus_4_6": "clean"},
            },
        ]
    }
    op = tmp_path / "old.json"
    np = tmp_path / "new.json"
    op.write_text(json.dumps(old))
    np.write_text(json.dumps(new))
    diff = compare_oracles(op, np)

    assert diff["n_shared"] == 3
    assert diff["n_changed"] == 1
    assert diff["changed_files"][0]["file_name"] == "b.py"
    assert diff["changed_files"][0]["old_verdict"] == "suspicious"
    assert diff["changed_files"][0]["new_verdict"] == "malicious"


def test_compare_oracles_handles_missing_paths(tmp_path: Path) -> None:
    diff = compare_oracles(tmp_path / "missing_old.json", tmp_path / "missing_new.json")
    assert diff["n_shared"] == 0
    assert diff["n_changed"] == 0


# ── Rich consensus (CWEs, capability tags, dangerous APIs, behaviors) ────────


def test_cwe_consensus_majority_2_of_3() -> None:
    voters = [
        _vr(
            file_name="x.py",
            voter_name="opus",
            verdict="malicious",
            findings=[{"cwe": "CWE-78"}, {"cwe": "CWE-22"}],
        ),
        _vr(
            file_name="x.py",
            voter_name="gemini",
            verdict="malicious",
            findings=[{"cwe": "CWE-78"}, {"cwe": "CWE-79"}],
        ),
        _vr(
            file_name="x.py",
            voter_name="gpt",
            verdict="malicious",
            findings=[{"cwe": "CWE-78"}],
        ),
    ]
    rec = build_consensus_record("x.py", voters)
    cwe = rec["cwe_consensus"]
    # CWE-78 appears in 3/3 voters -> consensus
    # CWE-22 in 1/3 -> NOT consensus
    # CWE-79 in 1/3 -> NOT consensus
    assert cwe["consensus"] == ["CWE-78"]
    assert cwe["votes_per"]["CWE-78"] == 3
    assert cwe["votes_per"]["CWE-22"] == 1


def test_cwe_consensus_4_voter_split() -> None:
    voters = [
        _vr(
            file_name="x.py",
            voter_name="opus",
            verdict="malicious",
            findings=[{"cwe": "CWE-78"}, {"cwe": "CWE-94"}],
        ),
        _vr(
            file_name="x.py",
            voter_name="gemini",
            verdict="malicious",
            findings=[{"cwe": "CWE-78"}, {"cwe": "CWE-22"}],
        ),
        _vr(file_name="x.py", voter_name="gpt", verdict="malicious", findings=[{"cwe": "CWE-94"}]),
        _vr(
            file_name="x.py",
            voter_name="grok",
            verdict="malicious",
            findings=[{"cwe": "CWE-94"}, {"cwe": "CWE-78"}],
        ),
    ]
    rec = build_consensus_record("x.py", voters)
    cwe = rec["cwe_consensus"]
    # Both CWE-78 (3 votes) and CWE-94 (3 votes) should be in consensus
    # CWE-22 only 1 vote -> not in consensus
    assert "CWE-78" in cwe["consensus"]
    assert "CWE-94" in cwe["consensus"]
    assert "CWE-22" not in cwe["consensus"]


def test_capability_tag_consensus_via_behavioral_profile() -> None:
    """Capability tags + dangerous APIs are derived from
    behavioral_profile.actual_capabilities (the actual schema field
    SECURITY_SCAN_PROMPT emits). The old ``extractions.capabilities``
    path was echoDefense-specific and isn't in the live schema."""
    voters = [
        _vr(
            file_name="a.py",
            voter_name="opus",
            verdict="critical_malicious",
            raw_output={
                "behavioral_profile": {
                    "actual_capabilities": {
                        "network_calls": [{"destination": "evil.com"}],
                        "commands_executed": ["subprocess.run"],
                    },
                    "exfiltration_risk": {"external_network_calls": ["evil.com"]},
                }
            },
        ),
        _vr(
            file_name="a.py",
            voter_name="gemini",
            verdict="critical_malicious",
            raw_output={
                "behavioral_profile": {
                    "actual_capabilities": {
                        "network_calls": [{"destination": "evil.com"}],
                        "dynamic_imports": ["importlib.import_module"],
                    },
                }
            },
        ),
        _vr(
            file_name="a.py",
            voter_name="gpt",
            verdict="critical_malicious",
            raw_output={
                "behavioral_profile": {
                    "actual_capabilities": {
                        "network_calls": [{"destination": "evil.com"}],
                        "commands_executed": ["subprocess.run", "os.system"],
                    },
                }
            },
        ),
    ]
    rec = build_consensus_record("a.py", voters)
    caps = rec["capability_tag_consensus"]
    apis = rec["dangerous_api_consensus"]
    # NETWORK_OUTBOUND: 3/3 voters -> consensus
    assert "NETWORK_OUTBOUND" in caps["consensus"]
    # PROCESS_SPAWN: 2/3 (opus + gpt) -> consensus
    assert "PROCESS_SPAWN" in caps["consensus"]
    # DYNAMIC_EXECUTION: 1/3 -> NOT in consensus
    assert "DYNAMIC_EXECUTION" not in caps["consensus"]
    # subprocess.run: 2/3 -> consensus dangerous API (normalized to upper)
    assert "SUBPROCESS.RUN" in apis["consensus"]
    # evil.com: 3/3 voters mention it -> consensus dangerous API
    assert "EVIL.COM" in apis["consensus"]
    # os.system: 1/3 -> NOT consensus
    assert "OS.SYSTEM" not in apis["consensus"]


def test_behavioral_category_consensus_from_behavioral_profile() -> None:
    voters = [
        _vr(
            file_name="b.py",
            voter_name="opus",
            verdict="critical_malicious",
            raw_output={
                "behavioral_profile": {
                    "actual_capabilities": {
                        "network_calls": [{"destination": "evil.com"}],
                        "commands_executed": ["subprocess.run"],
                    },
                    "exfiltration_risk": {"external_network_calls": ["evil.com"]},
                    "obfuscation_signals": {"encoded_strings": ["aGVsbG8="]},
                }
            },
        ),
        _vr(
            file_name="b.py",
            voter_name="gemini",
            verdict="critical_malicious",
            raw_output={
                "behavioral_profile": {
                    "actual_capabilities": {
                        "network_calls": [{"destination": "evil.com"}],
                    },
                    "exfiltration_risk": {"external_network_calls": ["evil.com"]},
                }
            },
        ),
    ]
    rec = build_consensus_record("b.py", voters)
    beh = rec["behavioral_category_consensus"]
    # 2/2 voters mention NETWORK_OUTBOUND and DATA_EXFILTRATION -> consensus
    assert "NETWORK_OUTBOUND" in beh["consensus"]
    assert "DATA_EXFILTRATION" in beh["consensus"]
    # Only opus has commands_executed -> 1/2 -> not consensus
    assert "PROCESS_SPAWN" not in beh["consensus"]


def test_rich_consensus_with_no_voters_returns_empty() -> None:
    rec = build_consensus_record("empty.py", [])
    assert rec["cwe_consensus"]["consensus"] == []
    assert rec["capability_tag_consensus"]["consensus"] == []
    assert rec["dangerous_api_consensus"]["consensus"] == []
    assert rec["behavioral_category_consensus"]["consensus"] == []


def test_rich_consensus_skips_errored_voters() -> None:
    voters = [
        _vr(file_name="x.py", voter_name="opus", verdict="malicious", findings=[{"cwe": "CWE-78"}]),
        _vr(
            file_name="x.py",
            voter_name="gemini",
            verdict=None,
            error="api_failed",
            findings=[{"cwe": "CWE-78"}, {"cwe": "CWE-22"}],
        ),
    ]
    rec = build_consensus_record("x.py", voters)
    # Errored voter doesn't contribute findings -> CWE-78 only has 1 vote
    assert rec["cwe_consensus"]["consensus"] == []  # min_voters=2 not reached
    assert rec["cwe_consensus"]["n_voters"] == 1
