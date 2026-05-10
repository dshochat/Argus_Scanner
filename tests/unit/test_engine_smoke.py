"""Smoke test for ``scanner.engine.scan_file`` using stub runners.

No live model calls. Verifies cascade routing decisions, scan_path
sequencing, and cost aggregation.
"""

from __future__ import annotations

import pytest

from preprocessing import preprocess_file
from scanner.engine import ScanConfig, is_high_stakes, scan_file, verdict_to_risk

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
        p.startswith("dast_severity_downgrade:malicious->suspicious") and "all_refuted" in p for p in result.scan_path
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
        p.startswith("dast_severity_downgrade:malicious->suspicious") and "high_uncertain_remains" in p
        for p in result.scan_path
    ), f"expected v1.2 high_uncertain marker, got {result.scan_path}"


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
    assert any(p.startswith("dast_upgrade:malicious->critical_malicious") for p in result.scan_path), (
        f"expected dast_upgrade marker, got {result.scan_path}"
    )


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
async def test_dast_triggers_only_on_malicious_verdicts():
    """Suspicious verdict alone shouldn't trigger DAST — only malicious /
    critical_malicious do."""
    result = await scan_file(
        filename="regular.py",
        content=b"def parse(x): return x\n",
        triage_runner=stub_triage_high,
        sonnet_runner=stub_sonnet_low_uncertainty,  # → suspicious
        opus_runner=stub_opus,
        dast_runner=stub_dast_confirms,
    )
    # Sonnet returns suspicious; no high-stakes, no escalation
    # DAST should NOT fire
    assert result.dast_attempted is False
    assert result.final_verdict == "suspicious"


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
