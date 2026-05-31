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


# ── P3a: --dast-required-policy wiring ─────────────────────────────────────


def test_parser_dast_required_policy_default_none() -> None:
    """Without the flag, args.dast_required_policy is None — engine
    falls through to ScanConfig's default ('downgrade_cap'). This is
    the wiring contract: only override ScanConfig when the user
    explicitly passes the flag."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py"])
    assert args.dast_required_policy is None


def test_parser_dast_required_policy_strict() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "scan",
            "foo.py",
            "--dast-required-policy",
            "strict",
        ]
    )
    assert args.dast_required_policy == "strict"


def test_parser_dast_required_policy_downgrade_cap_explicit() -> None:
    """Explicitly opting back into the default is allowed (lets CI
    pipelines pin behavior even if the default changes later)."""
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "scan",
            "foo.py",
            "--dast-required-policy",
            "downgrade_cap",
        ]
    )
    assert args.dast_required_policy == "downgrade_cap"


def test_parser_dast_required_policy_rejects_unknown_value() -> None:
    """argparse choices guard against typos like 'strict_mode' or 'lenient'."""
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "scan",
                "foo.py",
                "--dast-required-policy",
                "lenient",
            ]
        )


def test_parser_scan_repo_dast_required_policy_propagates() -> None:
    """The flag is also wired to the scan-repo subcommand (--dast-required-policy
    has the same shape on argus scan-repo)."""
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "scan-repo",
            "some/repo",
            "--dast-required-policy",
            "strict",
        ]
    )
    assert args.dast_required_policy == "strict"


def test_p3a_cli_to_scanconfig_propagation_strict() -> None:
    """End-to-end wiring test: parse --dast-required-policy strict, run
    the same config_kwargs path _run_scan uses, build ScanConfig, and
    confirm the field landed.

    This catches the class of bug where the argparse field name doesn't
    match what _run_scan reads via getattr(args, ...) — silently
    ignoring the flag at runtime even though the parser accepts it."""
    from scanner.engine import ScanConfig

    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "scan",
            "foo.py",
            "--dast-required-policy",
            "strict",
        ]
    )

    # Mirror the relevant block from cli._run_scan exactly:
    config_kwargs: dict[str, object] = {}
    policy = getattr(args, "dast_required_policy", None)
    if policy is not None:
        config_kwargs["dast_required_policy"] = policy
    cfg = ScanConfig(**config_kwargs)  # type: ignore[arg-type]

    assert cfg.dast_required_policy == "strict", (
        "CLI flag must propagate to ScanConfig.dast_required_policy"
    )


def test_p3a_cli_to_scanconfig_propagation_default() -> None:
    """When the flag is not passed, ScanConfig keeps its default
    (downgrade_cap). Belt-and-braces against the silent-override bug
    where None could accidentally be stored as a string."""
    from scanner.engine import ScanConfig

    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py"])

    config_kwargs: dict[str, object] = {}
    policy = getattr(args, "dast_required_policy", None)
    if policy is not None:
        config_kwargs["dast_required_policy"] = policy
    cfg = ScanConfig(**config_kwargs)  # type: ignore[arg-type]

    assert cfg.dast_required_policy == "downgrade_cap"


# ── v1.11: --enable-remediation (Remediation default ON flip) ─────────────


def test_parser_enable_remediation_default_none_uses_scanconfig_default() -> None:
    """v1.11 (2026-05-21): the flag is now BooleanOptionalAction with
    default=None so we can distinguish 'user didn't pass the flag' from
    'user explicitly set it'. Without the flag, args.enable_remediation
    is None — the wire-up at _run_scan respects ScanConfig's default
    (which is enable_phase_c=True as of v1.11)."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py"])
    assert args.enable_remediation is None


def test_parser_enable_remediation_explicit_on() -> None:
    """--enable-remediation explicitly sets True (overrides default)."""
    from scanner.engine import ScanConfig

    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py", "--enable-remediation"])
    assert args.enable_remediation is True

    # Mirror _run_scan's wire-up (v1.11):
    config_kwargs: dict[str, object] = {}
    _rem_flag = getattr(args, "enable_remediation", None)
    if _rem_flag is not None:
        config_kwargs["enable_phase_c"] = bool(_rem_flag)
    cfg = ScanConfig(**config_kwargs)  # type: ignore[arg-type]
    assert cfg.enable_phase_c is True


def test_parser_no_enable_remediation_opt_out() -> None:
    """v1.11: --no-enable-remediation lets compliance / CI / read-only
    audit users opt out of the new default-on Remediation."""
    from scanner.engine import ScanConfig

    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py", "--no-enable-remediation"])
    assert args.enable_remediation is False

    # Mirror _run_scan's wire-up:
    config_kwargs: dict[str, object] = {}
    _rem_flag = getattr(args, "enable_remediation", None)
    if _rem_flag is not None:
        config_kwargs["enable_phase_c"] = bool(_rem_flag)
    cfg = ScanConfig(**config_kwargs)  # type: ignore[arg-type]
    assert cfg.enable_phase_c is False


def test_parser_default_remediation_uses_scanconfig_v1_11_default_on() -> None:
    """Round-trip: omit the flag → wire-up doesn't set enable_phase_c
    → ScanConfig dataclass default (True in v1.11) kicks in."""
    from scanner.engine import ScanConfig

    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py"])

    config_kwargs: dict[str, object] = {}
    _rem_flag = getattr(args, "enable_remediation", None)
    if _rem_flag is not None:
        config_kwargs["enable_phase_c"] = bool(_rem_flag)
    cfg = ScanConfig(**config_kwargs)  # type: ignore[arg-type]
    assert cfg.enable_phase_c is True, (
        "v1.11 contract: Remediation defaults to ON when the user "
        "doesn't pass the flag at all."
    )


def test_parser_no_remediation_flag_removed() -> None:
    """The historical --no-remediation (pre-v1.8) is still gone — v1.11
    uses --no-enable-remediation as the canonical opt-out form."""
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "foo.py", "--no-remediation"])


# ── v1.8 quick win: argus auto-load .env from any directory ───────────────


def test_load_argus_env_finds_via_cwd_walkup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When .env exists in CWD or any parent, find_dotenv resolves it.
    This is the new behavior: ``argus scan`` works from anywhere as
    long as some parent dir has .env.

    Implementation note: this test mocks load_dotenv to a no-op so it
    doesn't pollute the test process's os.environ with whatever's in
    the test's fake .env. The path-resolution logic is what we're
    actually verifying."""
    env_file = tmp_path / ".env"
    env_file.write_text("ARGUS_AUTOLOAD_TEST_KEY=found_via_walkup\n")
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    # No-op load_dotenv: we're testing path resolution, not env mutation
    calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        cli, "load_dotenv", lambda path, override: calls.append((str(path), override))
    )

    found = cli._load_argus_env()
    assert found is not None
    assert found.resolve() == env_file.resolve()
    # Confirm load_dotenv was called with override=True (the contract
    # — local file values must win over OS env).
    assert calls == [(str(env_file), True)] or calls[0][1] is True


def test_load_argus_env_falls_back_to_install_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When CWD walk-up finds nothing, fall back to Argus install
    dir's .env. If you're running tests in a fresh clone without
    a real .env, this test skips."""
    isolated = tmp_path / "no_env_dir"
    isolated.mkdir()
    monkeypatch.chdir(isolated)

    install_env = Path(cli.__file__).resolve().parent.parent / ".env"
    if not install_env.exists():
        pytest.skip("Argus install dir has no .env — clean clone")

    # Mock load_dotenv to no-op — we're testing path resolution, not
    # env mutation (which would pollute downstream tests' os.environ
    # state).
    monkeypatch.setattr(cli, "load_dotenv", lambda path, override: None)

    found = cli._load_argus_env()
    assert found is not None
    assert found.resolve() == install_env.resolve()


def test_load_argus_env_returns_none_when_nothing_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When neither CWD walk-up nor Argus install dir has .env, the
    helper returns None gracefully — the scan can still proceed if OS
    env vars are set."""
    isolated = tmp_path / "no_env_dir"
    isolated.mkdir()
    monkeypatch.chdir(isolated)

    # Mock load_dotenv to no-op (defensive against side effects).
    monkeypatch.setattr(cli, "load_dotenv", lambda path, override: None)

    # Temporarily move the Argus install dir's .env away if it exists.
    install_env = Path(cli.__file__).resolve().parent.parent / ".env"
    moved_to: Path | None = None
    if install_env.exists():
        moved_to = install_env.with_suffix(".env.test-backup")
        install_env.rename(moved_to)

    try:
        found = cli._load_argus_env()
        assert found is None
    finally:
        # Always restore the .env we moved.
        if moved_to is not None and moved_to.exists():
            moved_to.rename(install_env)


def test_parser_scan_repo_enable_remediation_propagates() -> None:
    """The flag exists on scan-repo too."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan-repo", "some/repo", "--enable-remediation"])
    assert args.enable_remediation is True


# ── _run_scan with mocked engine ───────────────────────────────────────────


def test_run_scan_missing_anthropic_key_exits_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    # Block .env load by chdir to tmp dir without one
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_load_argus_env", lambda: None)
    f = tmp_path / "x.py"
    f.write_text("x = 1\n")
    args = cli._build_parser().parse_args(["scan", str(f)])
    rc = asyncio.run(cli._run_scan(args))
    assert rc == 2


def test_run_scan_missing_file_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("GEMINI_API_KEY", "AI-test")
    monkeypatch.setattr(cli, "_load_argus_env", lambda: None)
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
    monkeypatch.setattr(cli, "_load_argus_env", lambda: None)

    # Stub all triage / analysis runner factories — just return marker
    # objects. v15.9 default triage is Sonnet; the gemini factory is
    # also stubbed in case --triage-model=gemini-flash-lite is exercised.
    monkeypatch.setattr(cli, "make_gemini_triage_runner", lambda key: "TRIAGE")
    monkeypatch.setattr(cli, "make_sonnet_triage_runner", lambda key: "TRIAGE")
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


# ── --enable-phase-3-loop flag plumbing ───────────────────────────────────


def test_parser_phase_3_loop_flag_off_by_default_v1_11() -> None:
    """v1.11 (2026-05-21): Adversarial Reasoning (Phase 3 Stage 2) is
    opt-in again. Default cascade is Validation + Remediation focused;
    operators wanting zero-day hunting opt in via
    --enable-phase-3-loop (and also --enable-phase-3-discovery for
    Stage 1 + --enable-runtime-probe for the sandbox-probe machinery).

    History: v1.7 opt-in → v1.8 default ON → v1.11 opt-in again."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py"])
    assert args.enable_phase_3_loop is False


def test_parser_phase_3_loop_flag_explicit_disable() -> None:
    """--no-enable-phase-3-loop opts out for a single scan (e.g., for
    cost-sensitive CI runs that want L1 + Phase A only)."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py", "--no-enable-phase-3-loop"])
    assert args.enable_phase_3_loop is False


def test_parser_phase_3_loop_flag_accepted_by_scan() -> None:
    """Explicit --enable-phase-3-loop still works (redundant with new
    default, but doesn't error)."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py", "--enable-phase-3-loop"])
    assert args.enable_phase_3_loop is True


def test_parser_phase_3_loop_flag_default_off_for_scan_repo_v1_11() -> None:
    """v1.11: scan-repo also defaults Phase 3 loop OFF — matches the
    per-file `argus scan` default to keep behavior consistent across
    invocation modes."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan-repo", "/some/path"])
    assert args.enable_phase_3_loop is False


def test_parser_phase_3_loop_flag_accepted_by_install_opt_in_path() -> None:
    """``argus install`` keeps Phase 3 OPT-IN even in v1.8 — scanning
    every wheel in a dep closure with Phase 3 would be a ~10x cost
    blowout. The install path is the one place the flag stays
    store_true (default False)."""
    parser = cli._build_parser()
    args = parser.parse_args(["install", "some-package"])
    assert args.enable_phase_3_loop is False  # install default stays opt-in

    args_explicit = parser.parse_args(["install", "some-package", "--enable-phase-3-loop"])
    assert args_explicit.enable_phase_3_loop is True


def test_parser_phase_3_max_turns_default_none() -> None:
    """``--phase-3-max-turns`` is absent by default so the ScanConfig
    default (1) wins; flag exists so operators can bump per scan."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py"])
    assert args.phase_3_max_turns is None


def test_parser_phase_3_max_turns_explicit() -> None:
    """``--phase-3-max-turns 3`` parses to int and lands on args."""
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "foo.py", "--phase-3-max-turns", "3"])
    assert args.phase_3_max_turns == 3


def test_scanconfig_phase_3_loop_max_turns_default_one() -> None:
    """ScanConfig default is 1 — preserves the v1.6 measured-sufficient
    cap. Bumping requires explicit opt-in via flag or config."""
    from scanner.engine import ScanConfig

    cfg = ScanConfig()
    assert cfg.phase_3_loop_max_turns == 1


def test_v1_11_zero_day_hunting_stages_default_off_in_scanconfig() -> None:
    """v1.11 (2026-05-21): Exploit Discovery / Behavioral Profiling /
    Adversarial Reasoning are all default OFF.

    Repositioning rationale: Argus's default cascade is now Validation
    + Remediation focused (runtime-grade FP reduction + verified
    patches). The zero-day hunting stages (Exploit Discovery, Phase 3
    Stage 1, Phase 3 Stage 2) are opt-in for users who want broader
    coverage. They unbundle: Stage 2 (Adversarial Reasoning) needs
    Stage 1 (Behavioral Profiling) + the runtime-probe sandbox
    machinery, so all three should be enabled together when desired.

    History: v1.7 opt-in → v1.8 default ON → v1.11 opt-in again."""
    from scanner.engine import ScanConfig

    cfg = ScanConfig()
    assert cfg.enable_runtime_probe is False
    assert cfg.enable_phase_3_discovery is False
    assert cfg.enable_phase_3_loop is False

    # Variants stay opt-in (unchanged)
    assert cfg.enable_runtime_probe_mutation is False
    assert cfg.enable_runtime_probe_iterative is False
    assert cfg.enable_runtime_probe_chains is False

    # And Remediation is default ON (the headline v1.11 flip).
    assert cfg.enable_phase_c is True


# ── Help-text rendering regression guard ──────────────────────────────────


def test_every_subparser_help_renders_cleanly() -> None:
    """argparse's ``--help`` formatter feeds each action's ``help``
    string through Python's ``%`` operator. A stray unescaped ``%``
    in a help string (e.g., ``~16%`` instead of ``~16%%``) crashes
    ``--help`` with ``TypeError: must be real number, not dict`` —
    a silent break that no normal parse_args-based test catches.

    This test invokes ``format_help`` on every subparser and every
    action it owns, so any future help-text edit that drops a ``%``
    escape fails CI before it lands.

    Surfaced during the v1.11.0 public-sync smoke test: the
    ``--l1-mode`` help string contained an unescaped ``~16%`` that
    had been in the repo for months but never tripped because the
    unit tests use ``parse_args`` (no help rendering)."""
    parser = cli._build_parser()
    # Top-level help.
    parser.format_help()
    # Each subparser's help.
    for action in parser._actions:
        if hasattr(action, "choices") and isinstance(action.choices, dict):
            for sub_name, subp in action.choices.items():
                subp.format_help()  # must not raise
                # Each action's help string individually (catches
                # rare cases where format_help survives but the
                # action's help fails on its own).
                for act in subp._actions:
                    if act.help:
                        try:
                            _ = act.help % {}
                        except (TypeError, ValueError, KeyError) as e:
                            opts = "|".join(act.option_strings) or act.dest
                            raise AssertionError(
                                f"help string for ``{sub_name} {opts}`` "
                                f"failed argparse %-formatting "
                                f"({type(e).__name__}: {e}). Look for "
                                f"unescaped ``%`` chars in the help text "
                                f"— literal percent signs must be "
                                f"written as ``%%``."
                            ) from e
