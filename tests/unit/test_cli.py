"""Unit tests for scanner.cli — argparse, formatters, exit codes.

No live API. The scan command is exercised against a mocked
``scan_file`` so the runner factories aren't called.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from scanner import cli
from scanner.engine import ScanResult


def _sample_result(
    *,
    verdict: str = "malicious",
    error: str | None = None,
) -> ScanResult:
    r = ScanResult(
        filename="exfil.py",
        file_hash="abc123",
        language="python",
        triage_classification="HIGH",
        triage_reason="reads /etc/passwd, exfils via http",
        final_verdict=verdict,
        risk_score=85,
        risk_level="critical",
    )
    r.vulnerabilities = [
        {
            "type": "data_exfiltration",
            "severity": "critical",
            "line": 6,
            "explanation": "Sends /etc/passwd contents to remote attacker.",
            "fix": "Remove the network call.",
        }
    ]
    r.attack_chains = [
        {
            "name": "passwd_exfil",
            "steps": ["1. Read /etc/passwd", "2. Encode", "3. POST to attacker"],
        }
    ]
    r.behavioral_profile = {
        "sensitivity": "critical",
        "purpose_summary": "exfiltrates sensitive system files",
    }
    r.scan_path = ["preprocessing", "triage:HIGH", "analysis:sonnet_default"]
    r.total_cost_usd = 0.0512
    r.total_duration_ms = 4200
    r.error = error
    return r


# ── Formatters ─────────────────────────────────────────────────────────────


def test_format_json_round_trips() -> None:
    out = cli.format_json(_sample_result())
    parsed = json.loads(out)
    assert parsed["filename"] == "exfil.py"
    assert parsed["final_verdict"] == "malicious"
    assert parsed["risk_score"] == 85
    assert parsed["vulnerabilities"][0]["type"] == "data_exfiltration"


def test_format_markdown_includes_key_sections() -> None:
    out = cli.format_markdown(_sample_result())
    assert "# exfil.py" in out
    assert "`malicious`" in out
    assert "85/100" in out
    assert "## Vulnerabilities (1)" in out
    assert "data_exfiltration" in out
    assert "## Attack chains (1)" in out
    assert "passwd_exfil" in out
    assert "## Behavioral summary" in out
    assert "exfiltrates sensitive system files" in out
    assert "$0.0512" in out


def test_format_markdown_handles_clean_result() -> None:
    """Clean files have no vulns/chains — markdown shouldn't show empty sections."""
    r = _sample_result(verdict="clean")
    r.vulnerabilities = []
    r.attack_chains = []
    r.behavioral_profile = {}
    out = cli.format_markdown(r)
    assert "## Vulnerabilities" not in out
    assert "## Attack chains" not in out
    assert "## Behavioral summary" not in out


def test_format_markdown_includes_error() -> None:
    out = cli.format_markdown(_sample_result(error="analysis_failure: TimeoutError"))
    assert "## Error" in out
    assert "analysis_failure" in out


# ── argparse ───────────────────────────────────────────────────────────────


def test_parser_requires_subcommand() -> None:
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parser_scan_defaults() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py"])
    assert args.command == "scan"
    assert args.file == Path("foo.py")
    assert args.output == "json"
    assert args.no_dast is False
    assert args.max_cost is None  # default falls through to ScanConfig


def test_parser_scan_markdown_no_dast() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py", "--output", "markdown", "--no-dast"])
    assert args.output == "markdown"
    assert args.no_dast is True


def test_parser_scan_max_cost_override() -> None:
    """--max-cost USD flows through to args.max_cost as a float."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py", "--max-cost", "0.25"])
    assert args.max_cost == pytest.approx(0.25)


def test_parser_scan_max_cost_zero_disables() -> None:
    """--max-cost 0 is a valid sentinel for 'disable cap' (matches the
    SCAN-007 engine guard contract)."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py", "--max-cost", "0"])
    assert args.max_cost == pytest.approx(0.0)


# ── --dast-trigger-verdicts ────────────────────────────────────────────────


def test_parser_dast_trigger_verdicts_default_none() -> None:
    """Without the flag, args.dast_trigger_verdicts is None — engine
    falls through to ScanConfig's default ('malicious', 'critical_malicious')."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py"])
    assert args.dast_trigger_verdicts is None


def test_parser_dast_trigger_verdicts_accepts_csv() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "scan",
            "foo.py",
            "--dast-trigger-verdicts",
            "suspicious,malicious,critical_malicious",
        ]
    )
    assert args.dast_trigger_verdicts == "suspicious,malicious,critical_malicious"


def test_parser_dast_trigger_verdicts_strict_mode() -> None:
    """Single verdict for strictest cost-controlled mode."""
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "scan",
            "foo.py",
            "--dast-trigger-verdicts",
            "critical_malicious",
        ]
    )
    assert args.dast_trigger_verdicts == "critical_malicious"


# ── _run_scan with mocked engine ───────────────────────────────────────────


def test_run_scan_missing_anthropic_key_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    # Block .env load by chdir to tmp dir without one
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "load_dotenv", lambda **kwargs: None)
    f = tmp_path / "x.py"
    f.write_text("x = 1\n")
    args = cli._build_parser().parse_args(["scan", str(f)])
    rc = asyncio.run(cli._run_scan(args))
    assert rc == 2


def test_run_scan_missing_file_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("GEMINI_API_KEY", "AI-test")
    monkeypatch.setattr(cli, "load_dotenv", lambda **kwargs: None)
    args = cli._build_parser().parse_args(["scan", str(tmp_path / "nope.py")])
    rc = asyncio.run(cli._run_scan(args))
    assert rc == 2


def test_run_scan_invokes_engine_and_prints(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("GEMINI_API_KEY", "AI-test")
    monkeypatch.setattr(cli, "load_dotenv", lambda **kwargs: None)

    # Stub all three runner factories — just return marker objects.
    monkeypatch.setattr(cli, "make_gemini_triage_runner", lambda key: "TRIAGE")
    monkeypatch.setattr(cli, "make_sonnet_runner", lambda key: "SONNET")
    monkeypatch.setattr(cli, "make_opus_runner", lambda key: "OPUS")

    captured: dict[str, Any] = {}

    async def fake_scan_file(**kwargs: Any) -> ScanResult:
        captured.update(kwargs)
        return _sample_result()

    monkeypatch.setattr(cli, "scan_file", fake_scan_file)

    f = tmp_path / "evil.py"
    f.write_text("import os\nos.system('rm -rf /')\n")
    args = cli._build_parser().parse_args(["scan", str(f), "--output", "json"])
    rc = asyncio.run(cli._run_scan(args))

    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert rc == 0
    assert parsed["filename"] == "exfil.py"  # from sample result
    assert captured["filename"] == "evil.py"
    assert captured["triage_runner"] == "TRIAGE"
    assert captured["sonnet_runner"] == "SONNET"
    assert captured["opus_runner"] == "OPUS"
    assert captured["dast_runner"] is None  # phase 3 stays None for now
