"""Smoke test for ``scanner.engine.scan_file`` using stub runners.

No live model calls. Verifies cascade routing decisions, scan_path
sequencing, and cost aggregation.
"""

from __future__ import annotations

import pytest

from preprocessing import preprocess_file
from scanner.engine import ScanConfig, ScanResult, is_high_stakes, scan_file, verdict_to_risk

# ─── Stub runners ─────────────────────────────────────────────────────────────


async def stub_triage_high(filename, content, pp):
    return {
        "classification": "HIGH",
        "reason": "stub HIGH",
        "model": "gemini-flash-lite-stub",
        "cost_usd": 0.001,
        "duration_ms": 50,
    }


async def stub_triage_clean(filename, content, pp):
    return {
        "classification": "CLEAN",
        "reason": "stub clean",
        "model": "gemini-flash-lite-stub",
        "cost_usd": 0.001,
        "duration_ms": 30,
    }


async def stub_triage_low(filename, content, pp):
    """LOW-routing stub for SCAN-010 split-vs-combined dispatch tests."""
    return {
        "classification": "LOW",
        "reason": "stub LOW",
        "model": "gemini-flash-lite-stub",
        "cost_usd": 0.001,
        "duration_ms": 40,
    }


async def stub_sonnet_low_uncertainty(filename, content, pp, classification):
    return {
        "verdict_label": "suspicious",
        "vulnerabilities": [],
        "behavioral_profile": {"purpose_summary": "stub-sonnet"},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "uncertainty": 0.2,  # below default threshold (0.4)
        "model": "sonnet-4.6-stub",
        "cost_usd": 0.05,
        "duration_ms": 1200,
    }


async def stub_sonnet_high_uncertainty(filename, content, pp, classification):
    return {
        "verdict_label": "suspicious",
        "vulnerabilities": [],
        "behavioral_profile": {},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "uncertainty": 0.6,  # ABOVE threshold; should escalate to Opus
        "model": "sonnet-4.6-stub",
        "cost_usd": 0.05,
        "duration_ms": 1200,
    }


async def stub_opus(filename, content, pp, classification):
    return {
        "verdict_label": "malicious",
        "vulnerabilities": [{"type": "crypto_weakness", "severity": "high"}],
        "behavioral_profile": {"purpose_summary": "stub-opus-deep"},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "model": "opus-4.7-stub",
        "cost_usd": 0.20,
        "duration_ms": 4000,
    }


async def stub_dast_confirms(filename, content, pp, scan_result, **kwargs):
    return {
        "final_verdict": {"verdict_label": "critical_malicious"},
        "validated_findings": ["F001"],
        "iterations": [{"iter": 1, "verdict": "critical_malicious"}],
        "total_cost_usd": 0.30,
        "elapsed_ms": 60000,
    }


async def stub_dast_attempts_downgrade(filename, content, pp, scan_result, **kwargs):
    """Mirrors the megatron / litellm-pre-fix pattern: DAST returns a
    lower verdict than L1 with no validated_findings (sandbox failed to
    confirm hypotheses). DAST-105 guard should ignore this."""
    return {
        "final_verdict": {"verdict_label": "suspicious"},
        "validated_findings": [],
        "iterations": [{"iter": 1, "verdict": "suspicious"}],
        "total_cost_usd": 0.20,
        "elapsed_ms": 30000,
    }


async def stub_dast_grounded_downgrade(filename, content, pp, scan_result, **kwargs):
    """DAST-105 v2: DAST returns a lower verdict AND has journal records
    showing every L1 finding is BLOCKED or UNREACHED (i.e., refuted with
    sandbox-grounded evidence). Engine should DOWNGRADE to DAST's
    verdict in this case (precision-aware adjudication)."""
    return {
        "final_verdict": {"verdict_label": "suspicious"},
        "validated_findings": [],
        "iterations": [{"iter": 1, "verdict": "suspicious"}],
        "journal_records": [
            {
                "claim_id": "H001",
                "verdict": "rejected",
                "rationale": "validator rejected: input is sanitized via shlex.quote",
            }
        ],
        "total_cost_usd": 0.20,
        "elapsed_ms": 30000,
    }


async def stub_dast_partial_grounded_downgrade(filename, content, pp, scan_result, **kwargs):
    """DAST-105 v2 negative case: DAST wants to downgrade but ONE finding
    is NOT_TESTED (no journal entry). Engine should KEEP L1's verdict
    because we don't have grounded evidence for every finding.

    Used with stub_sonnet_two_critical_vulns (returns 2 vulnerabilities)
    so finding count is > 1.
    """
    return {
        "final_verdict": {"verdict_label": "suspicious"},
        "validated_findings": [],
        "iterations": [{"iter": 1, "verdict": "suspicious"}],
        "journal_records": [
            {
                "claim_id": "H001",
                "verdict": "rejected",
                "rationale": "input is sanitized via shlex.quote",
            }
            # H002 has no journal record -> NOT_TESTED
        ],
        "total_cost_usd": 0.20,
        "elapsed_ms": 30000,
    }


async def stub_sonnet_two_critical_vulns(filename, content, pp, classification):
    """Like stub_sonnet_malicious but returns TWO vulnerabilities so we
    can test grounded-vs-partial downgrade scenarios."""
    return {
        "verdict_label": "malicious",
        "vulnerabilities": [
            {"type": "command_injection", "severity": "critical"},
            {"type": "sql_injection", "severity": "high"},
        ],
        "behavioral_profile": {},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "uncertainty": 0.1,
        "model": "sonnet-4.6-stub",
        "cost_usd": 0.05,
        "duration_ms": 1200,
    }


async def stub_sonnet_malicious(filename, content, pp, classification):
    """Sonnet returns malicious — triggers the DAST stage so we can
    exercise the L1 → DAST verdict-comparison path."""
    return {
        "verdict_label": "malicious",
        "vulnerabilities": [{"type": "code_injection", "severity": "critical"}],
        "behavioral_profile": {},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "uncertainty": 0.1,  # below threshold; no Opus escalation
        "model": "sonnet-4.6-stub",
        "cost_usd": 0.05,
        "duration_ms": 1200,
    }


# ─── Cases ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_clean_short_circuit_no_analysis():
    """Triage CLEAN → short-circuit, only triage call counted."""
    result = await scan_file(
        filename="clean.py",
        content=b"def add(x, y): return x + y\n",
        triage_runner=stub_triage_clean,
        sonnet_runner=stub_sonnet_low_uncertainty,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert result.final_verdict == "clean"
    assert "clean_short_circuit" in result.scan_path
    assert len(result.model_calls) == 1
    assert result.model_calls[0]["stage"] == "triage"
    assert result.dast_attempted is False
    assert result.total_cost_usd == pytest.approx(0.001, abs=0.0001)


@pytest.mark.asyncio
async def test_high_stakes_routes_to_opus_directly():
    """Preprocessing flag (attack_vector_extension on .pth) triggers
    high-stakes; cascade routes directly to Opus, skipping the Sonnet
    escalation step."""
    result = await scan_file(
        # .pth file → attack_vector_extension fires (narrow, file-shape
        # based — the routing tier reserved for files that are themselves
        # supply-chain attack surfaces)
        filename="suspect.pth",
        content=b"import malicious_module\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert "analysis:opus_high_stakes" in result.scan_path
    # No "escalate_to_opus" because we went straight to Opus
    assert "escalate_to_opus" not in result.scan_path


@pytest.mark.asyncio
async def test_imperative_install_alone_routes_to_sonnet_not_opus():
    """Regression for 2026-05-05 routing fix: a file that triggers ONLY
    imperative_install_detected (broad heuristic — fires on subprocess /
    urllib / eval / exec usage in any .py file) must route to Sonnet,
    not Opus. Previously this auto-routed to Opus and inflated cost
    ~3-7× on benign utility scripts."""
    result = await scan_file(
        filename="utility.py",
        # subprocess.run + urllib → imperative_install_detected fires;
        # but no .pth / .whl extension, no crypto_sensitivity, no
        # ai_file_match, no obfuscation. Sonnet is the right tier.
        content=(
            b"import subprocess\nimport urllib.request\n"
            b"def fetch(u):\n    return urllib.request.urlopen(u).read()\n"
            b"def run(cmd):\n    return subprocess.run(cmd, capture_output=True)\n"
        ),
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert "analysis:sonnet_default" in result.scan_path
    assert "analysis:opus_high_stakes" not in result.scan_path


@pytest.mark.asyncio
async def test_standard_high_routes_to_sonnet_no_escalation():
    """A regular HIGH file with no preprocessing flags + low uncertainty
    stays on Sonnet — no Opus call."""
    # File with no imperative_install / attack_vector / crypto_sensitivity
    result = await scan_file(
        filename="regular.py",
        content=b"def parse_user_input(s): return s.lower().strip()\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert "analysis:sonnet_default" in result.scan_path
    assert "escalate_to_opus" not in result.scan_path


@pytest.mark.asyncio
async def test_high_uncertainty_escalates_to_opus():
    """Sonnet emits high uncertainty on a non-high-stakes file → engine
    escalates to Opus, Opus's verdict overrides."""
    result = await scan_file(
        filename="ambiguous.py",
        content=b"def parse(x): return x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_high_uncertainty,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert "analysis:sonnet_default" in result.scan_path
    assert "escalate_to_opus" in result.scan_path
    # Opus verdict (malicious) overrides Sonnet's (suspicious)
    # Then DAST upgrades to critical_malicious
    assert result.final_verdict == "critical_malicious"


@pytest.mark.asyncio
async def test_dast_105_guard_keeps_l1_when_dast_attempts_downgrade():
    """DAST-105 guard: when DAST returns a verdict LOWER than L1's, the
    engine must keep L1's verdict. DAST has to improve L1, not the
    opposite. A failure to confirm in sandbox is not refutation."""
    result = await scan_file(
        filename="malicious_only.py",
        content=b"x = 1\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_malicious,  # L1 = malicious
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,  # DAST = suspicious
    )
    assert result.dast_attempted is True
    # L1's malicious must be kept; DAST's suspicious is rejected
    assert result.final_verdict == "malicious"
    assert any(p.startswith("dast_keep_l1:") for p in result.scan_path), (
        f"expected 'dast_keep_l1:' marker in scan_path, got {result.scan_path}"
    )
    # The downgrade marker must not also be a no-op upgrade marker
    assert not any(p.startswith("dast_upgrade:") for p in result.scan_path)


@pytest.mark.asyncio
async def test_dast_105_v2_grounded_downgrade_accepted():
    """DAST-105 v2 (v1.1): when DAST has sandbox-grounded evidence
    that EVERY L1 finding is BLOCKED or UNREACHED, the engine should
    accept DAST's downgrade. This fixes the case where L1 over-calls
    and DAST observes the file's mitigations."""
    result = await scan_file(
        filename="defended.py",
        content=b"x = 1\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_malicious,  # L1 = malicious, 1 vuln
        opus_runner=stub_opus,
        dast_runner=stub_dast_grounded_downgrade,  # DAST: suspicious + journal=BLOCKED
    )
    assert result.dast_attempted is True
    # Per-finding derivation should classify H001 as BLOCKED
    pf = result.per_finding_validation
    assert len(pf) == 1
    assert pf[0]["status"] == "BLOCKED"
    # v1.2: All findings refuted (BLOCKED/UNREACHED) -> full downgrade.
    assert result.final_verdict == "suspicious"
    assert any(
        p.startswith("dast_severity_downgrade:malicious->suspicious") and "all_refuted" in p
        for p in result.scan_path
    ), f"expected v1.2 severity_downgrade marker, got {result.scan_path}"


@pytest.mark.asyncio
async def test_dast_105_v2_partial_grounded_severity_driven_downgrade():
    """v1.2: severity-driven downgrade rule. When 1 of 2 findings is
    BLOCKED but the other is NOT_TESTED at severity HIGH, the engine
    issues a 1-tier downgrade (malicious -> suspicious) rather than the
    v1.1 binary keep-L1 behavior. Critical-severity uncertainty would
    block the downgrade entirely; high uncertainty caps it at 1 tier."""
    result = await scan_file(
        filename="partial.py",
        content=b"x = 1\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_two_critical_vulns,  # L1 = malicious, 2 vulns
        opus_runner=stub_opus,
        dast_runner=stub_dast_partial_grounded_downgrade,  # only H001 in journal
    )
    assert result.dast_attempted is True
    # H001 = BLOCKED (was severity critical), H002 = NOT_TESTED (severity high)
    pf = result.per_finding_validation
    assert len(pf) == 2
    assert pf[0]["status"] == "BLOCKED"
    assert pf[1]["status"] == "NOT_TESTED"
    # v1.2: high-severity uncertainty allows 1-tier downgrade (malicious
    # -> suspicious). DAST proposed suspicious; severity rule accepts it
    # capped at 1 tier max from L1.
    assert result.final_verdict == "suspicious"
    assert any(
        p.startswith("dast_severity_downgrade:malicious->suspicious")
        and "high_uncertain_remains" in p
        for p in result.scan_path
    ), f"expected v1.2 high_uncertain marker, got {result.scan_path}"


# ─── P3a strict-mode tests ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_p3a_strict_mode_preserves_l1_verdict_over_dast_downgrade():
    """P3a v1.8 strict mode: when DAST proposes a lower verdict than L1,
    strict mode REFUSES the downgrade. Compare with the default
    downgrade_cap test (test_dast_105_v2_partial_grounded_severity_driven_downgrade)
    which DOES accept the 1-tier downgrade with the same DAST input."""
    result = await scan_file(
        filename="partial.py",
        content=b"x = 1\n",
        config=ScanConfig(dast_required_policy="strict"),
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_two_critical_vulns,  # L1 = malicious, 2 vulns
        opus_runner=stub_opus,
        dast_runner=stub_dast_partial_grounded_downgrade,  # DAST wants suspicious
    )
    assert result.dast_attempted is True
    # L1's malicious verdict is preserved — never downgraded in strict mode.
    assert result.final_verdict == "malicious"
    assert any(
        p.startswith(
            "dast_required_policy:strict:l1_verdict_preserved:declined_downgrade_to_suspicious"
        )
        for p in result.scan_path
    ), f"expected strict-mode preservation marker, got {result.scan_path}"
    # And confirm the legacy downgrade marker did NOT fire.
    assert not any(p.startswith("dast_severity_downgrade:") for p in result.scan_path), (
        "strict mode must not emit the downgrade-cap marker"
    )


@pytest.mark.asyncio
async def test_p3a_strict_mode_suppresses_blocked_finding():
    """P3a v1.8 strict mode: a finding with PFV status BLOCKED gets
    suppressed from result.vulnerabilities. Phase A actively tested it
    AND proved the file's own code defended."""
    result = await scan_file(
        filename="defended.py",
        content=b"x = 1\n",
        config=ScanConfig(dast_required_policy="strict"),
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_malicious,  # L1 = malicious, 1 vuln
        opus_runner=stub_opus,
        dast_runner=stub_dast_grounded_downgrade,  # journal → BLOCKED
    )
    assert result.dast_attempted is True
    # PFV is preserved (audit trail) even though the vuln is suppressed.
    pf = result.per_finding_validation
    assert len(pf) == 1
    assert pf[0]["status"] == "BLOCKED"
    # The single L1 vuln should be filtered out of the user-facing list.
    assert result.vulnerabilities == [], (
        f"expected vulnerabilities filtered, got {result.vulnerabilities}"
    )
    # Suppression marker present with count.
    assert any(
        p == "dast_required_policy:strict:suppressed_1_refuted_findings" for p in result.scan_path
    ), f"expected strict-mode suppression marker, got {result.scan_path}"
    # Verdict preserved — no downgrade in strict mode.
    # (DAST proposed suspicious, but strict refuses.)
    assert result.final_verdict == "malicious"


@pytest.mark.asyncio
async def test_p3a_strict_mode_never_suppresses_not_tested():
    """P3a v1.8 strict mode contract: NOT_TESTED findings (sandbox didn't
    run conclusively — infra issue, budget, non-Python file, pattern-only
    CWE) are NEVER suppressed. This is the whole point of strict mode —
    we don't punish findings for infra limitations.

    Setup: 2 L1 vulns. H001 BLOCKED (journal entry), H002 NOT_TESTED
    (no journal). Strict mode should suppress H001 (BLOCKED) but keep
    H002 (NOT_TESTED). Verdict preserved at malicious."""
    result = await scan_file(
        filename="partial.py",
        content=b"x = 1\n",
        config=ScanConfig(dast_required_policy="strict"),
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_two_critical_vulns,  # L1 = malicious, 2 vulns
        opus_runner=stub_opus,
        dast_runner=stub_dast_partial_grounded_downgrade,  # only H001 journaled
    )
    pf = result.per_finding_validation
    assert len(pf) == 2
    assert pf[0]["status"] == "BLOCKED"
    assert pf[1]["status"] == "NOT_TESTED"
    # Only the BLOCKED vuln (idx 0) should be suppressed; NOT_TESTED kept.
    assert len(result.vulnerabilities) == 1, (
        f"NOT_TESTED finding must be kept; got vulns={result.vulnerabilities}"
    )
    # The surviving vuln is the second (sql_injection / high) — see
    # stub_sonnet_two_critical_vulns.
    assert result.vulnerabilities[0]["type"] == "sql_injection"
    # Marker reflects exactly one suppression.
    assert any(
        p == "dast_required_policy:strict:suppressed_1_refuted_findings" for p in result.scan_path
    ), f"expected suppressed_1 marker, got {result.scan_path}"
    # L1 verdict preserved (DAST proposed suspicious; strict refused).
    assert result.final_verdict == "malicious"


@pytest.mark.asyncio
async def test_p3a_strict_mode_allows_upgrade():
    """P3a v1.8 strict mode contract: strict mode only blocks DOWNGRADES.
    DAST upgrades (DAST proves the file is WORSE than L1 said) still
    apply. This is essential — strict mode should never veto sandbox-
    grounded confirmation of higher severity."""
    result = await scan_file(
        filename="malicious_only.py",
        content=b"x = 1\n",
        config=ScanConfig(dast_required_policy="strict"),
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_malicious,  # L1 = malicious
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,  # DAST upgrades to critical_malicious
    )
    assert result.dast_attempted is True
    # Upgrade should still happen even in strict mode.
    assert result.final_verdict == "critical_malicious"
    assert any(
        p.startswith("dast_upgrade:malicious->critical_malicious") for p in result.scan_path
    ), f"expected dast_upgrade marker, got {result.scan_path}"
    # No downgrade-related markers should be present.
    assert not any(
        p.startswith("dast_required_policy:strict:l1_verdict_preserved:") for p in result.scan_path
    )


@pytest.mark.asyncio
async def test_p3a_default_is_downgrade_cap_regression():
    """Ensure ScanConfig() with no explicit policy defaults to the
    legacy downgrade_cap behavior. Belt-and-braces: the default change
    would silently break v1.7 bench numbers."""
    cfg = ScanConfig()
    assert cfg.dast_required_policy == "downgrade_cap"


@pytest.mark.asyncio
async def test_v1_11_remediation_default_is_on():
    """v1.11 contract (2026-05-21): Remediation (Phase C, fix-and-verify)
    defaults to ON.

    Repositioning rationale: Argus's headline pitch is runtime-grade FP
    reduction + fast verified remediation. Validation (intrinsic to DAST)
    + Remediation (this flag) form the two default-on stages that
    deliver that pitch — every CONFIRMED finding ships with a verified
    patch out of the box. Compliance / CI / read-only audit users opt
    out via --no-enable-remediation.

    History: v1.8 had this OFF as the default. v1.11 flips it back ON
    as part of the Validation+Remediation product story.
    """
    cfg = ScanConfig()
    assert cfg.enable_phase_c is True, (
        "v1.11 contract: Remediation defaults to ON; "
        "operators wanting read-only behavior opt out via "
        "--no-enable-remediation"
    )
    # Explicit override to OFF still works (compliance / read-only path).
    cfg_off = ScanConfig(enable_phase_c=False)
    assert cfg_off.enable_phase_c is False


@pytest.mark.asyncio
async def test_dast_105_v2_no_findings_keeps_l1():
    """Edge case: DAST wants to downgrade but L1 produced zero
    vulnerabilities. There's no per-finding evidence in either direction.
    Conservative: keep L1's verdict."""

    async def stub_sonnet_no_vulns(filename, content, pp, classification):
        return {
            "verdict_label": "malicious",  # verdict without supporting findings
            "vulnerabilities": [],
            "behavioral_profile": {},
            "attack_chains": [],
            "ai_tool_analysis": {},
            "uncertainty": 0.1,
            "model": "sonnet-stub",
            "cost_usd": 0.05,
            "duration_ms": 1200,
        }

    result = await scan_file(
        filename="empty.py",
        content=b"x = 1\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_no_vulns,
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,  # downgrades, no journal
    )
    assert result.final_verdict == "malicious"  # L1 kept
    # 0 findings -> not grounded -> keep_l1
    assert any(p.startswith("dast_keep_l1") for p in result.scan_path)


@pytest.mark.asyncio
async def test_dast_105_guard_accepts_dast_upgrade():
    """DAST-105 guard does NOT block upgrades. When DAST's verdict is
    higher than L1's, the engine takes DAST's verdict and logs the
    upgrade in scan_path."""
    result = await scan_file(
        filename="malicious_only.py",
        content=b"x = 1\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_malicious,  # L1 = malicious
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,  # DAST = critical_malicious
    )
    assert result.dast_attempted is True
    assert result.final_verdict == "critical_malicious"
    assert any(
        p.startswith("dast_upgrade:malicious->critical_malicious") for p in result.scan_path
    ), f"expected dast_upgrade marker, got {result.scan_path}"


@pytest.mark.asyncio
async def test_scan_007_cost_cap_aborts_after_triage() -> None:
    """SCAN-007: per-file cost cap must abort the cascade as soon as
    cumulative cost exceeds it. Triage costs $0.001; cap at $0.0005
    forces an abort after triage, before analysis runs."""
    cfg = ScanConfig(max_cost_per_file_usd=0.0005)
    result = await scan_file(
        filename="x.py",
        content=b"x = 1\n",
        config=cfg,
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert result.status == 402
    assert result.error is not None
    assert "cost_cap_exceeded" in result.error
    assert any(p.startswith("cost_cap_exceeded_after:triage") for p in result.scan_path), (
        f"expected cost_cap_exceeded_after:triage marker, got {result.scan_path}"
    )
    # Analysis stage must NOT have run
    assert not any(p.startswith("analysis:") for p in result.scan_path)


@pytest.mark.asyncio
async def test_scan_007_cost_cap_aborts_after_analysis() -> None:
    """Cap at $0.10 — triage ($0.001) + sonnet ($0.05) fit, but adding
    DAST ($0.30) would exceed. Engine must abort after analysis cost is
    added, before any DAST stage. Sonnet returns malicious so DAST would
    otherwise trigger."""
    cfg = ScanConfig(max_cost_per_file_usd=0.04)  # triage + sonnet > 0.04
    result = await scan_file(
        filename="x.py",
        content=b"x = 1\n",
        config=cfg,
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_malicious,  # cost 0.05 → total 0.051 > 0.04
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert result.status == 402
    assert "cost_cap_exceeded" in (result.error or "")
    assert any(p.startswith("cost_cap_exceeded_after:analysis") for p in result.scan_path)
    # Sonnet did run and reported its verdict before the abort
    assert "analysis:sonnet_default" in result.scan_path
    # DAST stage must NOT have run
    assert result.dast_attempted is False


@pytest.mark.asyncio
async def test_scan_007_cost_cap_at_zero_disabled() -> None:
    """Sentinel: a cap of 0 (or negative) is treated as disabled, not
    'every scan aborts'."""
    cfg = ScanConfig(max_cost_per_file_usd=0.0)
    result = await scan_file(
        filename="ok.py",
        content=b"x = 1\n",
        config=cfg,
        triage_runner=stub_triage_clean,  # short-circuits cleanly
        sonnet_runner=stub_sonnet_low_uncertainty,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert result.error is None
    assert result.status == 200
    assert "clean_short_circuit" in result.scan_path


@pytest.mark.asyncio
async def test_scan_007_cap_not_exceeded_runs_full_cascade() -> None:
    """High cap allows all stages to run. Sanity check that the
    guardrail is opt-in / threshold-driven, not failing-closed."""
    cfg = ScanConfig(max_cost_per_file_usd=10.0)  # well above stub totals
    result = await scan_file(
        filename="x.py",
        content=b"x = 1\n",
        config=cfg,
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_malicious,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert result.error is None
    assert result.status == 200
    assert result.dast_attempted is True
    assert not any(p.startswith("cost_cap_exceeded_after:") for p in result.scan_path)


@pytest.mark.asyncio
async def test_dast_default_trigger_fires_on_suspicious_v1_10() -> None:
    """v1.10 (2026-05-21): DAST default trigger broadened to include
    'suspicious' alongside 'malicious' / 'critical_malicious'.

    History: v1.7-dev measured the 23-file bench with suspicious in
    the gate and found a net-negative tradeoff (+1 zero-day caught,
    +5 over-claims added; verdict-exact dropped 82.6% → 73.9%). The
    default was reverted to the narrow set.

    What changed in v1.10: Phases 1+2+3 of the FP-defense oracle
    stack (SCAN-016/017/018) suppress the over-claim FP class that
    drove the v1.7 measurement negative. The 4-file openai-python
    re-validation showed 6 SUPPRESSED FPs on base_client.py via the
    Phase 3 syscall-sink check — exactly the noise that previously
    killed verdict-exact. With the noise filtered, including
    suspicious in the gate is a net-positive trade: real findings
    surface (the azure.py 'clean+findings' UX contradiction Gemini
    flagged is now structurally impossible), FPs stay suppressed via
    the oracle stack."""
    result = await scan_file(
        filename="regular.py",
        content=b"def parse(x): return x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,  # → suspicious
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    # v1.10 default — suspicious IS in the gate; DAST fires.
    assert result.dast_attempted is True


@pytest.mark.asyncio
async def test_dast_narrow_trigger_skips_suspicious_v1_7_compat() -> None:
    """v1.7-compat path. Operators wanting the historical cost-controlled
    behavior (DAST only on malicious / critical_malicious, suspicious
    files skip DAST) pass the narrower trigger explicitly. Same code
    path that drove the v1.7 cost numbers."""
    custom_cfg = ScanConfig(
        dast_trigger_verdicts=("malicious", "critical_malicious"),
    )
    result = await scan_file(
        filename="regular.py",
        content=b"def parse(x): return x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,  # → suspicious
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
        config=custom_cfg,
    )
    # Suspicious NOT in custom gate → DAST does NOT fire.
    assert result.dast_attempted is False
    assert result.final_verdict == "suspicious"


@pytest.mark.asyncio
async def test_dast_fires_on_suspicious_when_gate_widened() -> None:
    """Customers wanting broader DAST coverage can opt in via the
    --dast-trigger-verdicts CLI flag (passes a custom ScanConfig
    .dast_trigger_verdicts). With ``suspicious`` added to the gate,
    DAST fires on suspicious-verdict files."""
    custom_cfg = ScanConfig(
        dast_trigger_verdicts=(
            "suspicious",
            "malicious",
            "critical_malicious",
        ),
    )
    result = await scan_file(
        filename="regular.py",
        content=b"def parse(x): return x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,  # → suspicious
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
        config=custom_cfg,
    )
    assert result.dast_attempted is True


# ── v1.9 finding-based DAST trigger ────────────────────────────────────


async def _stub_sonnet_clean_with_high_conf_finding(filename, content, pp, classification):
    """Suspicious verdict that aggregates DOWN to a verdict NOT in the
    default DAST trigger (e.g., ``suspicious`` not in default
    ``malicious,critical_malicious``), but still has a high-confidence
    finding worth runtime confirmation. Mirrors the n8n case from
    DAST-303 Slice 2 live runs."""
    return {
        "verdict_label": "suspicious",
        "vulnerabilities": [
            {
                "type": "crypto_weakness",
                "severity": "medium",
                "cwe": "CWE-319",
                "confidence": 0.85,
            }
        ],
        "behavioral_profile": {"purpose_summary": "stub"},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "uncertainty": 0.2,
        "model": "sonnet-4.6-stub",
        "cost_usd": 0.05,
        "duration_ms": 1200,
    }


@pytest.mark.asyncio
async def test_dast_fires_on_finding_confidence_when_verdict_below_gate() -> None:
    """v1.9: ``dast_trigger_on_finding_confidence`` widens the trigger
    to ANY finding above the threshold, regardless of rolled-up
    verdict. Use case: manual audits / DAST-303 cross-repo where a
    high-conf finding deserves runtime confirmation even when the
    verdict aggregator rolled down to a verdict outside the gate.

    v1.10 (2026-05-21): the default verdict gate now includes
    ``suspicious``. To preserve this test's original intent (verdict
    gate doesn't fire, finding gate forces DAST), explicitly pin the
    verdict gate to the narrow v1.7-compat set so suspicious-verdict
    files land below it."""
    cfg = ScanConfig(
        # Pin narrow verdict gate so suspicious lands BELOW it; the
        # finding-confidence gate then does the work.
        dast_trigger_verdicts=("malicious", "critical_malicious"),
        dast_trigger_on_finding_confidence=0.6,
    )
    result = await scan_file(
        filename="leak.ts",
        content=b"const fetch = require('node-fetch');\n",
        triage_runner=stub_triage_high,
        sonnet_runner=_stub_sonnet_clean_with_high_conf_finding,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
        config=cfg,
    )
    assert result.dast_attempted is True
    assert "dast_trigger:finding_confidence" in result.scan_path


@pytest.mark.asyncio
async def test_dast_does_not_fire_when_finding_below_threshold() -> None:
    """When ``dast_trigger_on_finding_confidence=0.9`` is stricter than
    every finding's confidence (here, max is 0.85), the finding gate
    stays closed and the (narrow) verdict-only gate keeps DAST off
    for suspicious verdicts.

    v1.10: explicit narrow verdict gate so suspicious lands below it
    (default v1.10 verdict gate now includes suspicious — would fire
    DAST and defeat the test's intent)."""
    cfg = ScanConfig(
        dast_trigger_verdicts=("malicious", "critical_malicious"),
        dast_trigger_on_finding_confidence=0.9,  # higher than the 0.85 finding
    )
    result = await scan_file(
        filename="leak.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=_stub_sonnet_clean_with_high_conf_finding,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
        config=cfg,
    )
    assert result.dast_attempted is False


@pytest.mark.asyncio
async def test_dast_finding_gate_disabled_by_default() -> None:
    """When ``dast_trigger_on_finding_confidence`` is None (default),
    the finding gate is OFF — back-compat with v1.7-v1.8 behavior.

    v1.10: with the default verdict gate now including ``suspicious``,
    the test pins the narrow verdict gate explicitly so suspicious
    lands BELOW it, then verifies DAST stays off because the finding
    gate is disabled."""
    cfg = ScanConfig(
        dast_trigger_verdicts=("malicious", "critical_malicious"),
    )
    assert cfg.dast_trigger_on_finding_confidence is None
    result = await scan_file(
        filename="leak.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=_stub_sonnet_clean_with_high_conf_finding,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
        config=cfg,
    )
    # Verdict is suspicious (below narrow gate), finding gate disabled
    # → DAST stays off.
    assert result.dast_attempted is False


@pytest.mark.asyncio
async def test_dast_finding_gate_zero_threshold_fires_on_any_finding() -> None:
    """``--dast-trigger-on-finding-confidence 0.0`` means "fire DAST
    whenever ANY finding exists, regardless of confidence." Useful
    for the most aggressive cross-repo / manual audit posture."""
    cfg = ScanConfig(dast_trigger_on_finding_confidence=0.0)
    result = await scan_file(
        filename="leak.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=_stub_sonnet_clean_with_high_conf_finding,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
        config=cfg,
    )
    assert result.dast_attempted is True


# ── v1.9 anti-undercall backstop ───────────────────────────────────────


async def _stub_sonnet_clean_with_high_severity_finding(
    filename, content, pp, classification
):
    """Mirrors the n8n / SCAN-010 regression: model emits findings
    (severity=high, confidence=0.85) but rolls up to verdict=clean
    because the split-L1 VULNS sub-call didn't see behavioral
    context for intent scoring. The engine-side backstop should
    catch this and promote to suspicious."""
    return {
        "verdict_label": "clean",
        "vulnerabilities": [
            {
                "type": "ssrf",
                "severity": "high",
                "cwe": "CWE-918",
                "confidence": 0.85,
            }
        ],
        "behavioral_profile": {"purpose_summary": "stub"},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "uncertainty": 0.2,
        "model": "sonnet-4.6-stub",
        "cost_usd": 0.05,
        "duration_ms": 1200,
    }


@pytest.mark.asyncio
async def test_undercall_backstop_promotes_clean_to_suspicious_on_high_finding() -> None:
    """The exact n8n regression in test form: L1 emits a high-severity
    finding at conf 0.85 but rolls up to ``clean``. The engine-side
    backstop must detect this contradiction and promote to suspicious
    so the DAST trigger gate fires naturally."""
    result = await scan_file(
        filename="vuln.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=_stub_sonnet_clean_with_high_severity_finding,
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,
    )
    assert result.final_verdict == "suspicious"
    # Auditable: the scan_path documents the upgrade source.
    assert any(
        "undercall_backstop:promoted_clean->suspicious" in step
        for step in result.scan_path
    )


@pytest.mark.asyncio
async def test_undercall_backstop_only_promotes_clean_not_suspicious() -> None:
    """The backstop NEVER lifts past ``suspicious``. A file already at
    ``suspicious`` with high-severity findings stays at suspicious —
    promoting to ``malicious`` requires intent evidence the model
    is best positioned to score."""
    async def stub(filename, content, pp, classification):
        return {
            "verdict_label": "suspicious",
            "vulnerabilities": [
                {"type": "ssrf", "severity": "high", "cwe": "CWE-918", "confidence": 0.9}
            ],
            "behavioral_profile": {},
            "attack_chains": [],
            "ai_tool_analysis": {},
            "uncertainty": 0.2,
            "model": "stub",
            "cost_usd": 0.05,
            "duration_ms": 100,
        }

    result = await scan_file(
        filename="vuln.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub,
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,
    )
    assert result.final_verdict == "suspicious"
    # No backstop log entry since the verdict was already at the
    # band the backstop would promote to.
    assert not any(
        "undercall_backstop" in step for step in result.scan_path
    )


@pytest.mark.asyncio
async def test_undercall_backstop_does_not_fire_on_low_confidence() -> None:
    """Threshold is conf ≥ 0.5 by default. A weak finding at conf=0.3
    doesn't trigger the BACKSTOP upgrade — the model's low-conf finding
    + clean rollup is internally consistent for the backstop.

    v15.29 update: although the backstop doesn't fire (still true), the
    new findings-floor invariant lifts clean→suspicious anyway because
    an active high-severity finding exists. ``clean`` cannot ship with
    any active finding present, regardless of confidence."""
    async def stub(filename, content, pp, classification):
        return {
            "verdict_label": "clean",
            "vulnerabilities": [
                {"type": "ssrf", "severity": "high", "cwe": "CWE-918", "confidence": 0.3}
            ],
            "behavioral_profile": {},
            "attack_chains": [],
            "ai_tool_analysis": {},
            "uncertainty": 0.2,
            "model": "stub",
            "cost_usd": 0.05,
            "duration_ms": 100,
        }

    result = await scan_file(
        filename="weak.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub,
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,
    )
    # Backstop didn't fire (this is the original assertion).
    assert not any(
        "undercall_backstop" in step for step in result.scan_path
    )
    # v15.29 floor did fire.
    assert result.final_verdict == "suspicious"
    assert any("finding_floor" in step for step in result.scan_path)


@pytest.mark.asyncio
async def test_undercall_backstop_does_not_fire_on_low_severity_only() -> None:
    """Low-severity findings (informational / hardening hints) at any
    confidence don't promote via the backstop. The backstop is for
    medium+ severities.

    v15.29 update: floor still kicks the verdict up to ``informational``
    because the finding exists — but it stops there (low severity →
    informational, not suspicious). The verdict label finally matches
    what the user sees in the report."""
    async def stub(filename, content, pp, classification):
        return {
            "verdict_label": "clean",
            "vulnerabilities": [
                {"type": "weak_crypto", "severity": "low", "cwe": "CWE-327", "confidence": 0.9}
            ],
            "behavioral_profile": {},
            "attack_chains": [],
            "ai_tool_analysis": {},
            "uncertainty": 0.2,
            "model": "stub",
            "cost_usd": 0.05,
            "duration_ms": 100,
        }

    result = await scan_file(
        filename="minor.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub,
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,
    )
    assert not any(
        "undercall_backstop" in step for step in result.scan_path
    )
    assert result.final_verdict == "informational"
    assert any(
        "finding_floor:clean->informational" in step for step in result.scan_path
    )


@pytest.mark.asyncio
async def test_undercall_backstop_can_be_disabled() -> None:
    """Operators who want strict back-compat with v1.8 backstop behavior
    pass ``enable_undercall_backstop=False`` and the BACKSTOP upgrade
    never fires.

    v15.29 update: the findings-floor invariant is NOT disable-able by
    design — ``clean`` must always mean zero active findings. Operators
    who disable the backstop still get the floor lift (suspicious here
    because the finding is high-severity)."""
    cfg = ScanConfig(enable_undercall_backstop=False)
    result = await scan_file(
        filename="vuln.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=_stub_sonnet_clean_with_high_severity_finding,
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,
        config=cfg,
    )
    # Backstop is disabled, so the backstop path can't have fired.
    assert not any("undercall_backstop" in step for step in result.scan_path)
    # Floor (non-optional, post-DAST stage) still enforces the invariant.
    assert result.final_verdict == "suspicious"
    assert any("finding_floor" in step for step in result.scan_path)


@pytest.mark.asyncio
async def test_undercall_backstop_threshold_configurable() -> None:
    """``undercall_backstop_min_confidence`` raises the bar for the
    BACKSTOP. With threshold=0.9, a 0.85-confidence finding is below
    the threshold so the backstop doesn't promote.

    v15.29 update: the findings-floor invariant has no confidence
    threshold by design — any active finding lifts the verdict. So
    even with backstop threshold raised, the floor still fires
    (high-severity → suspicious)."""
    cfg = ScanConfig(undercall_backstop_min_confidence=0.9)
    result = await scan_file(
        filename="vuln.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=_stub_sonnet_clean_with_high_severity_finding,
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,
        config=cfg,
    )
    # Backstop didn't fire (conf 0.85 < threshold 0.9).
    assert not any("undercall_backstop" in step for step in result.scan_path)
    # Floor still enforced the invariant.
    assert result.final_verdict == "suspicious"
    assert any("finding_floor" in step for step in result.scan_path)


@pytest.mark.asyncio
async def test_undercall_backstop_promotes_on_medium_severity() -> None:
    """Medium severity at >= 0.5 confidence is enough to promote.
    Catches the CWE-319 cleartext-creds class from the n8n scan."""
    async def stub(filename, content, pp, classification):
        return {
            "verdict_label": "clean",
            "vulnerabilities": [
                {
                    "type": "crypto_weakness",
                    "severity": "medium",
                    "cwe": "CWE-319",
                    "confidence": 0.65,
                }
            ],
            "behavioral_profile": {},
            "attack_chains": [],
            "ai_tool_analysis": {},
            "uncertainty": 0.2,
            "model": "stub",
            "cost_usd": 0.05,
            "duration_ms": 100,
        }

    result = await scan_file(
        filename="mcp.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub,
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,
    )
    assert result.final_verdict == "suspicious"


@pytest.mark.asyncio
async def test_undercall_backstop_unblocks_default_dast_gate() -> None:
    """End-to-end: with backstop ON (default), an n8n-style L1 output
    (clean + high finding) now triggers DAST via the default verdict
    gate — no need for the finding-confidence workaround. This is
    the integration win the v1.9 fix delivers."""
    cfg = ScanConfig(
        # Default DAST trigger only fires on malicious / critical_malicious,
        # so suspicious normally wouldn't fire it. But the user's intent
        # here is to confirm the backstop UNBLOCKS the path that v1.8
        # required ``--dast-trigger-on-finding-confidence`` to work around.
        # We widen to include suspicious — same setup as a production
        # operator running with broader coverage.
        dast_trigger_verdicts=("suspicious", "malicious", "critical_malicious"),
    )
    result = await scan_file(
        filename="vuln.ts",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=_stub_sonnet_clean_with_high_severity_finding,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
        config=cfg,
    )
    # The backstop promoted clean→suspicious; suspicious is in the
    # widened DAST gate, so DAST attempted.
    assert result.final_verdict in ("malicious", "critical_malicious")
    assert result.dast_attempted is True
    # Confirm the backstop fired (the scan_path entry should be visible
    # PRE-DAST since the backstop runs at Stage 6.6).
    assert any(
        "undercall_backstop:promoted_clean->suspicious" in step
        for step in result.scan_path
    )


@pytest.mark.asyncio
async def test_undercall_backstop_promotes_at_v192_boundary() -> None:
    """v1.9.2 (2026-05-20) — default threshold lowered 0.5 → 0.4.

    Reason: Sonnet 4.6 + adaptive thinking varies confidence by
    ~±0.05-0.10 between runs. The mako/template.py WCtesting case
    landed a medium-severity SSTI finding at conf=0.45 on one run
    and conf=0.55 on another — a flip-flop between clean and
    critical_malicious for byte-identical input. The default
    threshold now absorbs that variance band.

    This test pins both edges so a regression that bumps the
    default back up (or accidentally clips the band) fails loudly.
    """
    async def stub(filename, content, pp, classification):
        return {
            "verdict_label": "clean",
            "vulnerabilities": [
                {
                    "type": "ssti",
                    "severity": "medium",
                    "cwe": "CWE-94",
                    "confidence": 0.4,  # exactly at the new default
                }
            ],
            "behavioral_profile": {},
            "attack_chains": [],
            "ai_tool_analysis": {},
            "uncertainty": 0.2,
            "model": "stub",
            "cost_usd": 0.05,
            "duration_ms": 100,
        }

    result = await scan_file(
        filename="mako_like.py",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub,
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,
    )
    assert result.final_verdict == "suspicious"
    assert any(
        "undercall_backstop:promoted_clean->suspicious" in step
        for step in result.scan_path
    )


@pytest.mark.asyncio
async def test_undercall_backstop_does_not_fire_just_below_v192_threshold() -> None:
    """v1.9.2 BACKSTOP boundary lower bound — at conf=0.39, just under
    the new default, the BACKSTOP does NOT fire. Confirms the band
    [0.0, 0.4) remains the backstop's "model isn't sure" zone.

    v15.29 update: this is exactly the azure.py regression — medium
    severity at conf=0.39, below backstop. The new floor catches it
    (clean→suspicious) so the user no longer sees the "clean verdict
    + 3 NOT_TESTED CWE findings" contradiction the openai-python
    campaign surfaced."""
    async def stub(filename, content, pp, classification):
        return {
            "verdict_label": "clean",
            "vulnerabilities": [
                {
                    "type": "ssti",
                    "severity": "medium",
                    "cwe": "CWE-94",
                    "confidence": 0.39,
                }
            ],
            "behavioral_profile": {},
            "attack_chains": [],
            "ai_tool_analysis": {},
            "uncertainty": 0.2,
            "model": "stub",
            "cost_usd": 0.05,
            "duration_ms": 100,
        }

    result = await scan_file(
        filename="model_uncertain.py",
        content=b"x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub,
        opus_runner=stub_opus,
        dast_runner=stub_dast_attempts_downgrade,
    )
    # Backstop did NOT fire (this is what the test was originally pinning).
    assert not any(
        "undercall_backstop" in step for step in result.scan_path
    )
    # Floor caught it instead — the v15.29 fix for azure.py-style cases.
    assert result.final_verdict == "suspicious"
    assert any("finding_floor" in step for step in result.scan_path)


@pytest.mark.asyncio
async def test_known_malware_short_circuits_before_triage(monkeypatch):
    """If preprocessing finds a malware-hash match, scan returns
    critical_malicious immediately without any model calls."""
    from preprocessing import malware_hash

    class _FakeBackend:
        def lookup(self, file_hash: str) -> str | None:
            return "FAKE-MALWARE-FAMILY"

    # Replace the module-level singleton (read by `lookup()` directly)
    monkeypatch.setattr(malware_hash, "_default_backend", _FakeBackend())

    result = await scan_file(
        filename="bad.py",
        content=b"# any content\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert result.final_verdict == "critical_malicious"
    assert "known_malware_short_circuit" in result.scan_path
    # Zero model calls — preprocessing alone produced the verdict
    assert len(result.model_calls) == 0
    assert result.total_cost_usd == 0.0


# ─── Helper coverage ─────────────────────────────────────────────────────────


def test_is_high_stakes_fires_on_crypto_sensitivity():
    bundle = preprocess_file(
        "x.py",
        b"from cryptography.hazmat.primitives.ciphers import Cipher\n",
    )
    is_hs, cats = is_high_stakes(
        bundle.preprocessing,
        ScanConfig().high_stakes_categories,
    )
    assert is_hs is True
    assert "crypto_sensitivity_detected" in cats


def test_is_high_stakes_does_not_fire_on_clean_file():
    bundle = preprocess_file("x.py", b"def add(x, y): return x + y\n")
    is_hs, cats = is_high_stakes(
        bundle.preprocessing,
        ScanConfig().high_stakes_categories,
    )
    assert is_hs is False
    assert cats == []


def test_verdict_to_risk_mapping():
    assert verdict_to_risk("clean") == (0, "none")
    assert verdict_to_risk("informational") == (15, "low")
    assert verdict_to_risk("suspicious") == (45, "medium")
    assert verdict_to_risk("malicious") == (75, "high")
    assert verdict_to_risk("critical_malicious") == (95, "critical")


# ── SCAN-013 v15.19 — intent classifier + adjudicator cap ────────────────


def _mk_scan_result(**overrides) -> ScanResult:
    """Minimal ScanResult builder for intent / cap unit tests."""
    base = {
        "filename": "x.py",
        "file_hash": "h",
        "language": "python",
        "triage_classification": "HIGH",
        "triage_reason": "",
        "final_verdict": "suspicious",
        "risk_score": 45,
        "risk_level": "medium",
    }
    base.update(overrides)
    return ScanResult(**base)


def test_scan013_intent_classifier_library_via_phase_3() -> None:
    """Phase 3's last code_intent_analysis classifies deployment_context
    as 'library' → intent='legitimate'."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {
                    "deployment_context": "library",
                    "trust_boundary": "developer-controlled",
                }
            ]
        }
    )
    assert _classify_file_intent(r) == "legitimate"


def test_scan013_intent_uses_last_turn() -> None:
    """When Phase 3 ran multiple turns (e.g. borderline reinvocation),
    use the LAST non-None turn's classification."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {"deployment_context": "server", "trust_boundary": "untrusted"},
                None,  # Phase 3 turn that didn't emit analysis
                {"deployment_context": "library", "trust_boundary": "developer"},
            ]
        }
    )
    assert _classify_file_intent(r) == "legitimate"


def test_scan013_intent_malicious_overrides_phase_3_library() -> None:
    """Defensive: obfuscation_signals firing makes intent='malicious'
    EVEN IF Phase 3 said 'library'. Malware can claim to be library."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        behavioral_profile={"obfuscation_signals": {"present": True}},
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {"deployment_context": "library"}
            ]
        },
    )
    assert _classify_file_intent(r) == "malicious"


def test_scan013_intent_malicious_via_exfiltration_risk() -> None:
    """exfiltration_risk={'level': 'high'} → malicious intent."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        behavioral_profile={"exfiltration_risk": {"level": "high"}}
    )
    assert _classify_file_intent(r) == "malicious"


def test_scan013_intent_unknown_default() -> None:
    """No Phase 3 + no malicious signals → 'unknown' (preserves
    pre-v15.19 behavior — no cap applied)."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result()
    assert _classify_file_intent(r) == "unknown"


def test_scan013_intent_obfuscation_list_shape() -> None:
    """Defensive: accept list-shape obfuscation_signals too (some L1
    versions emit a list of detected obfuscation pattern names)."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        behavioral_profile={
            "obfuscation_signals": ["base64_decode_chain", "eval_at_runtime"]
        }
    )
    assert _classify_file_intent(r) == "malicious"


def test_scan013_cap_legitimate_malicious_to_suspicious() -> None:
    """Core cap: intent=legitimate + verdict=malicious → suspicious.
    Even WITH confirmed runtime findings, library code can't escalate
    past suspicious (hardening signal, not malware classification)."""
    from scanner.engine import _apply_intent_cap

    r = _mk_scan_result(
        final_verdict="malicious",
        risk_score=75,
        risk_level="high",
        intent="legitimate",
        per_finding_validation=[
            {"finding_id": "HRP_0_0", "status": "CONFIRMED"},
        ],
    )
    _apply_intent_cap(r)
    assert r.final_verdict == "suspicious"
    assert r.risk_score == 45
    assert r.risk_level == "medium"
    assert any("intent_cap:legitimate" in p for p in r.scan_path)


def test_scan013_cap_legitimate_critical_malicious_to_suspicious() -> None:
    """critical_malicious → suspicious. The intent cap collapses both
    severity-tiers into the same library-trust ceiling."""
    from scanner.engine import _apply_intent_cap

    r = _mk_scan_result(
        final_verdict="critical_malicious",
        risk_score=95,
        risk_level="critical",
        intent="legitimate",
    )
    _apply_intent_cap(r)
    assert r.final_verdict == "suspicious"


def test_scan013_cap_legitimate_suspicious_static_only_to_informational() -> None:
    """intent=legitimate + verdict=suspicious + NO runtime CONFIRM →
    informational. Pure static hardening flag on library code."""
    from scanner.engine import _apply_intent_cap

    r = _mk_scan_result(
        final_verdict="suspicious",
        intent="legitimate",
        per_finding_validation=[
            {"finding_id": "H001", "status": "REFUTED"},
            {"finding_id": "HRP_0_0", "status": "REFUTED"},
        ],
    )
    _apply_intent_cap(r)
    assert r.final_verdict == "informational"
    assert r.risk_score == 15
    assert r.risk_level == "low"


def test_scan013_cap_legitimate_suspicious_with_runtime_stays_suspicious() -> None:
    """intent=legitimate + verdict=suspicious + has runtime CONFIRM →
    stays suspicious. Real runtime evidence prevents the
    informational downgrade — there IS an exploit primitive worth
    surfacing, just not malicious-tier."""
    from scanner.engine import _apply_intent_cap

    r = _mk_scan_result(
        final_verdict="suspicious",
        intent="legitimate",
        per_finding_validation=[
            {"finding_id": "HRP_0_0", "status": "CONFIRMED"},
        ],
    )
    _apply_intent_cap(r)
    assert r.final_verdict == "suspicious"  # unchanged


def test_scan013_cap_unknown_intent_no_op() -> None:
    """intent=unknown → no cap applied (pre-v15.19 behavior)."""
    from scanner.engine import _apply_intent_cap

    r = _mk_scan_result(
        final_verdict="malicious",
        risk_score=75,
        risk_level="high",
        intent="unknown",
    )
    _apply_intent_cap(r)
    assert r.final_verdict == "malicious"  # unchanged


def test_scan013_cap_malicious_intent_no_op() -> None:
    """intent=malicious → no cap applied. Actual malware should be
    free to land at malicious/critical_malicious."""
    from scanner.engine import _apply_intent_cap

    r = _mk_scan_result(
        final_verdict="critical_malicious",
        risk_score=95,
        risk_level="critical",
        intent="malicious",
    )
    _apply_intent_cap(r)
    assert r.final_verdict == "critical_malicious"


def test_scan013_cap_legitimate_already_clean_no_op() -> None:
    """clean stays clean — the cap only kicks in for suspicious/+."""
    from scanner.engine import _apply_intent_cap

    r = _mk_scan_result(
        final_verdict="clean",
        risk_score=0,
        risk_level="none",
        intent="legitimate",
    )
    _apply_intent_cap(r)
    assert r.final_verdict == "clean"


def test_scan013_scan_result_default_intent_unknown() -> None:
    """ScanResult.intent defaults to 'unknown' — back-compat for code
    that constructs ScanResult without the new field."""
    r = _mk_scan_result()
    assert r.intent == "unknown"


# ── SCAN-013 v15.21 — explicit TrustBoundary enum + data-flow gate ───────


def test_scan013_v1521_external_untrusted_returns_unknown() -> None:
    """v15.21: trust_boundary_class=EXTERNAL_UNTRUSTED → intent=unknown."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {
                    "trust_boundary_class": "EXTERNAL_UNTRUSTED",
                    "deployment_context": "web_handler",
                }
            ]
        }
    )
    assert _classify_file_intent(r) == "unknown"


def test_scan013_v1521_internal_developer_returns_legitimate() -> None:
    """v15.21: INTERNAL_DEVELOPER → legitimate (no external network)."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {
                    "trust_boundary_class": "INTERNAL_DEVELOPER",
                    "deployment_context": "cli_tool",
                }
            ]
        }
    )
    assert _classify_file_intent(r) == "legitimate"


def test_scan013_v1521_library_consumer_returns_legitimate() -> None:
    """v15.21: LIBRARY_CONSUMER → legitimate (no external network)."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {
                    "trust_boundary_class": "LIBRARY_CONSUMER",
                    "deployment_context": "library",
                }
            ]
        }
    )
    assert _classify_file_intent(r) == "legitimate"


def test_scan013_v1521_dataflow_gate_suppresses_cap_with_network() -> None:
    """v15.21 data-flow gate: LIBRARY_CONSUMER but network_attempts
    non-empty → intent flips to 'unknown'. Gemini's Issue 2d."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {"trust_boundary_class": "LIBRARY_CONSUMER"}
            ]
        },
        behavioral_profile={
            "network_attempts": [
                {"target": "external-host.example.com", "method": "POST"}
            ]
        },
    )
    assert _classify_file_intent(r) == "unknown"


def test_scan013_v1521_dataflow_gate_dict_count_form() -> None:
    """Data-flow gate accepts the alternate ``{count: N}`` shape."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {"trust_boundary_class": "INTERNAL_DEVELOPER"}
            ]
        },
        behavioral_profile={"network_attempts": {"count": 3}},
    )
    assert _classify_file_intent(r) == "unknown"


def test_scan013_v1521_dataflow_gate_exfil_medium_suppresses() -> None:
    """exfiltration_risk=medium gates the cap (high+ → malicious)."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {"trust_boundary_class": "LIBRARY_CONSUMER"}
            ]
        },
        behavioral_profile={"exfiltration_risk": {"level": "medium"}},
    )
    assert _classify_file_intent(r) == "unknown"


def test_scan013_v1521_runtime_bp_network_also_gates() -> None:
    """Runtime behavioral profile's network_attempts (Phase A) also
    counts — strongest signal of actual network surface."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {"trust_boundary_class": "LIBRARY_CONSUMER"}
            ]
        },
        runtime_behavioral_profile={
            "network_attempts": [{"host": "evil.example.com", "port": 80}]
        },
    )
    assert _classify_file_intent(r) == "unknown"


def test_scan013_v1521_enum_takes_precedence_over_deployment_context() -> None:
    """Explicit enum overrides the deployment_context proxy."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {
                    "trust_boundary_class": "EXTERNAL_UNTRUSTED",
                    "deployment_context": "library",
                }
            ]
        }
    )
    assert _classify_file_intent(r) == "unknown"


def test_scan013_v1521_backcompat_no_enum_uses_deployment_context() -> None:
    """Pre-v15.21 results (no trust_boundary_class) still get the
    deployment_context=library fallback."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {"deployment_context": "library"}
            ]
        }
    )
    assert _classify_file_intent(r) == "legitimate"


def test_scan013_v1521_backcompat_proxy_subject_to_dataflow_gate() -> None:
    """Pre-v15.21 fallback also subject to the data-flow gate."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {"deployment_context": "library"}
            ]
        },
        behavioral_profile={"network_attempts": [{"host": "x.com"}]},
    )
    assert _classify_file_intent(r) == "unknown"


def test_scan013_v1521_malicious_overrides_enum() -> None:
    """obfuscation_signals firing wins over any TrustBoundary enum."""
    from scanner.engine import _classify_file_intent

    r = _mk_scan_result(
        phase_3_loop={
            "code_intent_analysis_per_turn": [
                {"trust_boundary_class": "LIBRARY_CONSUMER"}
            ]
        },
        behavioral_profile={"obfuscation_signals": {"present": True}},
    )
    assert _classify_file_intent(r) == "malicious"


def test_scan013_v1521_has_external_network_dataflow_helper() -> None:
    """Direct unit test for the data-flow detector — covers bool,
    list, dict-count, dict-attempts shapes."""
    from scanner.engine import _has_external_network_dataflow

    assert _has_external_network_dataflow(_mk_scan_result()) is False
    assert _has_external_network_dataflow(
        _mk_scan_result(behavioral_profile={"network_attempts": True})
    ) is True
    assert _has_external_network_dataflow(
        _mk_scan_result(behavioral_profile={"network_attempts": [{"x": 1}]})
    ) is True
    assert _has_external_network_dataflow(
        _mk_scan_result(behavioral_profile={"network_attempts": {"count": 5}})
    ) is True
    assert _has_external_network_dataflow(
        _mk_scan_result(behavioral_profile={"network_attempts": {"attempts": [1]}})
    ) is True


# ── SCAN-010 — engine-level split-L1 dispatcher ──────────────────────────


async def stub_sonnet_split(filename, content, pp, classification):
    """Stub the SPLIT runner. Distinguishable from stub_sonnet_low_uncertainty
    by the ``model`` label so the dispatcher decision can be verified."""
    return {
        "verdict_label": "malicious",
        "vulnerabilities": [{"type": "ssrf", "severity": "high"}],
        "behavioral_profile": {"purpose_summary": "stub-sonnet-split"},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "file_intent_analysis": {},
        "uncertainty": 0.2,
        "model": "sonnet-split-stub",
        "cost_usd": 0.07,
        "duration_ms": 1800,
        "error": None,
    }


async def stub_opus_split(filename, content, pp, classification):
    return {
        "verdict_label": "critical_malicious",
        "vulnerabilities": [{"type": "code_injection", "severity": "critical"}],
        "behavioral_profile": {"purpose_summary": "stub-opus-split"},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "file_intent_analysis": {},
        "uncertainty": 0.1,
        "model": "opus-split-stub",
        "cost_usd": 0.25,
        "duration_ms": 4500,
        "error": None,
    }


@pytest.mark.asyncio
async def test_scan_010_dispatcher_uses_split_on_high_when_enabled():
    """When ``l1_split_enabled=True`` AND triage is HIGH AND a split
    runner is wired, the engine MUST dispatch to the split runner
    instead of the combined one."""
    cfg = ScanConfig(l1_split_enabled=True)
    result = await scan_file(
        filename="regular.py",
        content=b"def fetch(u): import urllib.request as ur; return ur.urlopen(u).read()\n",
        config=cfg,
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,
        sonnet_runner_split=stub_sonnet_split,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    # The model_calls trace shows which runner actually fired.
    analysis_call = next(
        (c for c in result.model_calls if c["stage"] == "analysis"), None
    )
    assert analysis_call is not None
    assert analysis_call["model"] == "sonnet-split-stub", (
        f"Engine dispatched to combined runner instead of split. "
        f"model={analysis_call['model']!r}"
    )
    # scan_path picks up the split suffix so downstream telemetry
    # / reports can distinguish the two routes.
    assert any("split" in step for step in result.scan_path)


@pytest.mark.asyncio
async def test_scan_010_dispatcher_keeps_combined_on_low_even_when_split_enabled():
    """LOW-classified files MUST keep the combined runner — split mode
    fires only on the gate set (default ``("HIGH",)``). Preserves cost
    on the long tail of low-risk files."""
    cfg = ScanConfig(l1_split_enabled=True)
    result = await scan_file(
        filename="benign.py",
        content=b"def add(a, b): return a + b\n",
        config=cfg,
        triage_runner=stub_triage_low,
        sonnet_runner=stub_sonnet_low_uncertainty,
        sonnet_runner_split=stub_sonnet_split,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    analysis_call = next(
        (c for c in result.model_calls if c["stage"] == "analysis"), None
    )
    assert analysis_call is not None
    # LOW path → combined runner = sonnet-4.6-stub (NOT sonnet-split-stub).
    assert analysis_call["model"] == "sonnet-4.6-stub"


@pytest.mark.asyncio
async def test_scan_010_dispatcher_uses_opus_split_on_high_stakes_when_enabled():
    """HIGH-stakes files (preprocessing-flagged) bypass Sonnet and go
    direct to Opus. When split mode is on, that Opus call must be the
    split variant."""
    cfg = ScanConfig(l1_split_enabled=True)
    # Crypto sensitivity triggers is_high_stakes.
    crypto_content = (
        b"from cryptography.hazmat.primitives.asymmetric import rsa\n"
        b"key = rsa.generate_private_key(public_exponent=65537, key_size=512)\n"
    )
    result = await scan_file(
        filename="weak_crypto.py",
        content=crypto_content,
        config=cfg,
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,
        sonnet_runner_split=stub_sonnet_split,
        opus_runner=stub_opus,
        opus_runner_split=stub_opus_split,
        dast_runner=stub_dast_confirms,
    )
    analysis_call = next(
        (c for c in result.model_calls if c["stage"] == "analysis"), None
    )
    assert analysis_call is not None
    # HIGH-stakes + split-enabled → opus-split-stub.
    assert analysis_call["model"] == "opus-split-stub"


@pytest.mark.asyncio
async def test_scan_010_dispatcher_default_is_split_post_validation():
    """SCAN-010 default flipped 2026-05-18 after Gate 1 validation:
    ``l1_split_enabled`` defaults to True. HIGH-triage files now go
    through the split runner unless the operator explicitly opts out
    via ``--l1-mode combined`` or ``ScanConfig(l1_split_enabled=False)``.

    This test asserts the new default — paired with
    ``test_scan_010_dispatcher_explicit_opt_out_uses_combined`` below,
    which exercises the rollback path."""
    cfg = ScanConfig()  # defaults
    assert cfg.l1_split_enabled is True
    result = await scan_file(
        filename="regular.py",
        content=b"def f(x): return x\n",
        config=cfg,
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,
        sonnet_runner_split=stub_sonnet_split,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    analysis_call = next(
        (c for c in result.model_calls if c["stage"] == "analysis"), None
    )
    assert analysis_call is not None
    # Default behavior: dispatches to split when wired.
    assert analysis_call["model"] == "sonnet-split-stub"


@pytest.mark.asyncio
async def test_scan_010_dispatcher_explicit_opt_out_uses_combined():
    """Rollback path: operator sets ``l1_split_enabled=False`` (or
    passes ``--l1-mode combined``) → engine uses the combined runner
    even when the split runner is wired. Critical for the rollback
    story — no redeploy required to revert."""
    cfg = ScanConfig(l1_split_enabled=False)
    result = await scan_file(
        filename="regular.py",
        content=b"def f(x): return x\n",
        config=cfg,
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,
        sonnet_runner_split=stub_sonnet_split,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    analysis_call = next(
        (c for c in result.model_calls if c["stage"] == "analysis"), None
    )
    assert analysis_call is not None
    assert analysis_call["model"] == "sonnet-4.6-stub"


@pytest.mark.asyncio
async def test_scan_010_dispatcher_falls_through_when_split_runner_not_wired():
    """If the operator sets ``l1_split_enabled=True`` but no split
    runner is passed to ``scan_file`` (older callers, test fixtures
    without the new wiring), the engine MUST fall through to the
    combined runner — no crash, no error, just the legacy path."""
    cfg = ScanConfig(l1_split_enabled=True)
    result = await scan_file(
        filename="regular.py",
        content=b"def f(x): return x\n",
        config=cfg,
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,
        # sonnet_runner_split intentionally NOT wired
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    analysis_call = next(
        (c for c in result.model_calls if c["stage"] == "analysis"), None
    )
    assert analysis_call is not None
    # Fell through to combined; no AttributeError / no None-call.
    assert analysis_call["model"] == "sonnet-4.6-stub"
    assert result.error is None


# ── v1.6 Fix #9: always-label backfill ───────────────────────────────────


async def stub_sonnet_suspicious_with_findings(filename, content, pp, classification):
    """Sonnet returns suspicious + vulnerabilities. Suspicious is BELOW
    the default DAST trigger gate (malicious+) so DAST won't run — Fix #9
    is what builds per_finding_validation for these findings."""
    return {
        "verdict_label": "suspicious",
        "vulnerabilities": [
            {
                "type": "weak_crypto",
                "severity": "medium",
                "line": 12,
                "code": "hashlib.md5(...)",
                "explanation": "MD5 used",
                "fix": "use SHA-256",
                "cwe": "CWE-327",
                "confidence": 0.65,
                "data_flow_trace": "",
                "proof_of_concept": "",
            },
            {
                "type": "info_disclosure",
                "severity": "low",
                "line": 34,
                "code": "print(token)",
                "explanation": "Token printed",
                "fix": "remove print",
                "cwe": "CWE-532",
                "confidence": 0.45,
                "data_flow_trace": "",
                "proof_of_concept": "",
            },
        ],
        "behavioral_profile": {"purpose_summary": "stub"},
        "attack_chains": [],
        "ai_tool_analysis": {},
        "uncertainty": 0.2,
        "model": "sonnet-4.6-stub",
        "cost_usd": 0.05,
        "duration_ms": 1200,
    }


@pytest.mark.asyncio
async def test_fix9_suspicious_file_gets_per_finding_validation_backfilled():
    """Fix #9: when a file's verdict is BELOW the DAST trigger gate,
    L1 findings must still get per_finding_validation entries — each
    tagged NOT_TESTED with reason=dast_not_attempted. Pre-Fix-9 the
    list would be empty, hiding 44% of L1 findings from the customer.

    v1.10 (2026-05-21): the default verdict gate now includes
    suspicious, so we explicitly pin the v1.7-narrow gate to keep
    this test exercising the "verdict BELOW gate → NOT_TESTED
    backfill" path."""
    cfg = ScanConfig(
        dast_trigger_verdicts=("malicious", "critical_malicious"),
    )
    result = await scan_file(
        filename="medium_concern.py",
        content=b"import hashlib\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_suspicious_with_findings,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
        config=cfg,
    )
    # Narrow gate: suspicious doesn't trip DAST.
    assert result.final_verdict == "suspicious"
    assert not result.dast_attempted
    # Fix #9: per_finding_validation populated despite DAST not running.
    assert len(result.per_finding_validation) == 2
    for pf in result.per_finding_validation:
        assert pf["status"] == "NOT_TESTED"
        assert pf["not_tested_reason"] == "dast_not_attempted"


@pytest.mark.asyncio
async def test_fix9_clean_file_no_findings_no_backfill():
    """Fix #9 guard: a clean file with no L1 findings must still produce
    an empty per_finding_validation. The backfill only runs when there
    are findings to label."""
    result = await scan_file(
        filename="clean.py",
        content=b"def add(x, y): return x + y\n",
        triage_runner=stub_triage_clean,
        sonnet_runner=stub_sonnet_low_uncertainty,
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    assert result.final_verdict == "clean"
    assert result.per_finding_validation == []


# ── SCAN-014 v15.29 — findings-floor invariant ───────────────────────────


def test_scan014_floor_clean_with_medium_finding_lifts_to_suspicious() -> None:
    """The azure.py regression: clean verdict + NOT_TESTED medium-severity
    finding must lift to suspicious. ``clean`` cannot coexist with active
    findings — that's the contradiction v15.29 closes."""
    from scanner.engine import _apply_finding_floor

    r = _mk_scan_result(
        final_verdict="clean",
        risk_score=0,
        risk_level="none",
        intent="unknown",
        vulnerabilities=[
            {"id": "v1", "cwe": "CWE-22", "severity": "medium", "confidence": 0.38},
        ],
        per_finding_validation=[{"finding_id": "H001", "status": "NOT_TESTED"}],
    )
    _apply_finding_floor(r)
    assert r.final_verdict == "suspicious"
    assert r.risk_score == 45
    assert r.risk_level == "medium"
    assert any("finding_floor:clean->suspicious" in p for p in r.scan_path)


def test_scan014_floor_clean_with_low_only_lifts_to_informational() -> None:
    """Low-severity-only active findings → informational, not suspicious.
    The floor is severity-aware to preserve signal."""
    from scanner.engine import _apply_finding_floor

    r = _mk_scan_result(
        final_verdict="clean",
        risk_score=0,
        risk_level="none",
        intent="unknown",
        vulnerabilities=[
            {"id": "v1", "cwe": "CWE-209", "severity": "low", "confidence": 0.3},
        ],
        per_finding_validation=[{"finding_id": "H001", "status": "NOT_TESTED"}],
    )
    _apply_finding_floor(r)
    assert r.final_verdict == "informational"
    assert r.risk_score == 15
    assert r.risk_level == "low"


def test_scan014_floor_skips_legitimate_intent() -> None:
    """intent=legitimate is owned by _apply_intent_cap. The floor must
    NOT undo intent_cap's deliberate clean/informational downgrade for
    library code."""
    from scanner.engine import _apply_finding_floor

    r = _mk_scan_result(
        final_verdict="informational",
        risk_score=15,
        risk_level="low",
        intent="legitimate",
        vulnerabilities=[
            {"id": "v1", "cwe": "CWE-22", "severity": "high", "confidence": 0.7},
        ],
        per_finding_validation=[{"finding_id": "H001", "status": "NOT_TESTED"}],
    )
    _apply_finding_floor(r)
    assert r.final_verdict == "informational"  # unchanged — intent_cap owns this


def test_scan014_floor_all_refuted_no_lift() -> None:
    """Findings with REJECTED/BLOCKED/UNREACHED/SUPPRESSED status are
    inactive — DAST has evidence they don't fire. Floor must not lift
    on them."""
    from scanner.engine import _apply_finding_floor

    r = _mk_scan_result(
        final_verdict="clean",
        risk_score=0,
        risk_level="none",
        intent="unknown",
        vulnerabilities=[
            {"id": "v1", "severity": "high", "confidence": 0.7},
            {"id": "v2", "severity": "medium", "confidence": 0.5},
            {"id": "v3", "severity": "high", "confidence": 0.9},
            {"id": "v4", "severity": "medium", "confidence": 0.6},
        ],
        per_finding_validation=[
            {"finding_id": "H001", "status": "REJECTED"},
            {"finding_id": "H002", "status": "BLOCKED"},
            {"finding_id": "H003", "status": "UNREACHED"},
            {"finding_id": "H004", "status": "SUPPRESSED"},
        ],
    )
    _apply_finding_floor(r)
    assert r.final_verdict == "clean"  # all findings are refuted/suppressed


def test_scan014_floor_mixed_status_active_finding_lifts() -> None:
    """Among 3 findings (REJECTED, NOT_TESTED, BLOCKED), the single
    active NOT_TESTED medium finding is enough to lift clean→suspicious."""
    from scanner.engine import _apply_finding_floor

    r = _mk_scan_result(
        final_verdict="clean",
        risk_score=0,
        risk_level="none",
        intent="unknown",
        vulnerabilities=[
            {"id": "v1", "severity": "low"},
            {"id": "v2", "severity": "medium"},
            {"id": "v3", "severity": "high"},
        ],
        per_finding_validation=[
            {"finding_id": "H001", "status": "REJECTED"},
            {"finding_id": "H002", "status": "NOT_TESTED"},
            {"finding_id": "H003", "status": "BLOCKED"},
        ],
    )
    _apply_finding_floor(r)
    assert r.final_verdict == "suspicious"
    assert "finding_floor:clean->suspicious:1_active_max_sev=2" in r.scan_path


def test_scan014_floor_never_downgrades() -> None:
    """Floor only lifts upward. If the verdict is already malicious /
    critical_malicious / suspicious, the floor is a no-op."""
    from scanner.engine import _apply_finding_floor

    for verdict, risk in (
        ("suspicious", 45),
        ("malicious", 75),
        ("critical_malicious", 95),
    ):
        r = _mk_scan_result(
            final_verdict=verdict,
            risk_score=risk,
            intent="unknown",
            vulnerabilities=[{"id": "v1", "severity": "low"}],
            per_finding_validation=[{"finding_id": "H001", "status": "NOT_TESTED"}],
        )
        _apply_finding_floor(r)
        assert r.final_verdict == verdict  # unchanged


def test_scan014_floor_empty_vulnerabilities_no_op() -> None:
    """No vulnerabilities → floor is a no-op. clean remains clean."""
    from scanner.engine import _apply_finding_floor

    r = _mk_scan_result(
        final_verdict="clean",
        intent="unknown",
        vulnerabilities=[],
    )
    _apply_finding_floor(r)
    assert r.final_verdict == "clean"


def test_scan014_floor_missing_pfv_treats_as_active() -> None:
    """When PFV is empty (DAST didn't run, backfill skipped), all
    vulnerabilities are treated as active. This guards against the
    floor silently no-op-ing when status data is missing."""
    from scanner.engine import _apply_finding_floor

    r = _mk_scan_result(
        final_verdict="clean",
        intent="unknown",
        vulnerabilities=[
            {"id": "v1", "severity": "high", "confidence": 0.7},
        ],
        per_finding_validation=[],  # missing
    )
    _apply_finding_floor(r)
    assert r.final_verdict == "suspicious"


def test_scan014_floor_azure_py_regression() -> None:
    """End-to-end reproduction of the azure.py case:
    triage=HIGH, 3 L1 findings (path_traversal, ssrf, data_exfil) all
    NOT_TESTED with confidences 0.38/0.35/0.45 (below v1.9.2 backstop
    threshold 0.4), intent=unknown → must lift clean→suspicious."""
    from scanner.engine import _apply_finding_floor

    r = _mk_scan_result(
        final_verdict="clean",
        risk_score=0,
        risk_level="none",
        intent="unknown",
        vulnerabilities=[
            {"id": "v1", "cwe": "CWE-22", "severity": "medium", "confidence": 0.38},
            {"id": "v2", "cwe": "CWE-918", "severity": "medium", "confidence": 0.35},
            {"id": "v3", "cwe": "CWE-209", "severity": "low", "confidence": 0.45},
        ],
        per_finding_validation=[
            {"finding_id": "H001", "status": "NOT_TESTED"},
            {"finding_id": "H002", "status": "NOT_TESTED"},
            {"finding_id": "H003", "status": "NOT_TESTED"},
        ],
    )
    _apply_finding_floor(r)
    assert r.final_verdict == "suspicious"
    assert r.risk_score == 45
