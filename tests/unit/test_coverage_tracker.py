"""DAST coverage tracker unit tests (v1.9.1).

Pin the dedupe behavior so Phase B+ / Phase 3 / Phase A can rely on a
predictable contract: function-name extraction, attack-class
normalization, L1 pre-population, suppression counting, and the
fail-soft posture when inputs are malformed.

No live API. The CoverageTracker is pure-Python state with deterministic
extraction heuristics."""

from __future__ import annotations

import pytest

from dast.coverage_tracker import (
    L1_TRUST_THRESHOLD,
    CoverageEntry,
    CoverageTracker,
    _extract_function_name,
    _normalize_attack_class,
)


# ── _normalize_attack_class ────────────────────────────────────────────


def test_normalize_attack_class_lowercases_and_dashes_to_underscores() -> None:
    assert _normalize_attack_class("Command-Injection") == "command_injection"
    assert _normalize_attack_class("path traversal") == "path_traversal"


def test_normalize_attack_class_handles_known_aliases() -> None:
    """Synonyms collapse to canonical forms."""
    assert _normalize_attack_class("os_command_injection") == "command_injection"
    assert _normalize_attack_class("shell_injection") == "command_injection"
    assert _normalize_attack_class("server_side_request_forgery") == "ssrf"
    assert _normalize_attack_class("deserialization") == "insecure_deserialization"
    assert _normalize_attack_class("cross_site_scripting") == "xss"


def test_normalize_attack_class_passes_unknown_through() -> None:
    """Unknown values stay as-is (lowercased) so future-added classes
    match themselves without code changes."""
    assert _normalize_attack_class("future_cwe_class") == "future_cwe_class"


def test_normalize_attack_class_handles_empty_and_none() -> None:
    assert _normalize_attack_class("") == ""
    assert _normalize_attack_class(None) == ""
    assert _normalize_attack_class("   ") == ""


# ── _extract_function_name ─────────────────────────────────────────────


def test_extract_uses_explicit_function_name_field() -> None:
    """When the dict already has function_name (Phase B+ findings do),
    use it directly — no regex fallback needed."""
    result = _extract_function_name({"function_name": "run_user_command"})
    assert result == "run_user_command"


def test_extract_from_def_line_in_code_snippet() -> None:
    """L1 hypothesis code_snippet often includes the `def name(...)`
    line — parse it out."""
    snippet = "def run_user_command(filename):\n    return subprocess.run(...)"
    assert _extract_function_name({"code_snippet": snippet}) == "run_user_command"


def test_extract_from_async_def() -> None:
    snippet = "async def fetch_remote_resource(url):\n    ..."
    assert _extract_function_name({"code_snippet": snippet}) == "fetch_remote_resource"


def test_extract_from_first_function_call_pattern() -> None:
    """When there's no def line, the first call pattern in the snippet
    is a reasonable proxy."""
    snippet = "subprocess.run(f'ls {user_input}', shell=True)"
    # ``subprocess`` would be skipped (built-in-like) — first usable
    # function name is ``run``.
    assert _extract_function_name({"code_snippet": snippet}) == "run"


def test_extract_from_data_flow_trace() -> None:
    """data_flow_trace is the L1 prompt's structured trace string;
    common pattern is ``urlopen(url)`` or ``url → urlopen``."""
    result = _extract_function_name({
        "code_snippet": "",
        "data_flow_trace": "url → urlopen(url)",
    })
    assert result == "urlopen"


def test_extract_skips_python_keywords_and_builtins() -> None:
    """``if (cond)`` shouldn't return ``if``; same for return / for /
    print / etc."""
    snippet = "if (cond): return something()"
    # ``if`` and ``return`` skipped; ``something`` is the first valid.
    assert _extract_function_name({"code_snippet": snippet}) == "something"


def test_extract_returns_empty_when_no_signal() -> None:
    """When the snippet has no recognizable function patterns, return
    empty string → caller skips dedupe for that finding."""
    assert _extract_function_name({"code_snippet": "x = 1 + 2"}) == ""
    assert _extract_function_name({}) == ""
    assert _extract_function_name({"code_snippet": ""}) == ""


def test_extract_handles_bare_identifier_as_function() -> None:
    """If the snippet is just a single identifier, treat it as the
    function name. Rare but happens when L1 emits very compact data."""
    assert _extract_function_name({"code_snippet": "evaluate_expr"}) == "evaluate_expr"


def test_extract_handles_non_dict_input() -> None:
    """Defensive: a malformed entry shouldn't crash, just returns
    empty."""
    assert _extract_function_name(None) == ""
    assert _extract_function_name("not a dict") == ""


# ── CoverageTracker — add + is_covered ─────────────────────────────────


def test_add_and_is_covered() -> None:
    t = CoverageTracker()
    assert t.add(
        function="run_user_command",
        attack_class="command_injection",
        source="l1",
        finding_id="H001",
    )
    entry = t.is_covered(
        function="run_user_command", attack_class="command_injection"
    )
    assert entry is not None
    assert entry.function == "run_user_command"
    assert entry.source == "l1"


def test_is_covered_returns_none_when_not_covered() -> None:
    t = CoverageTracker()
    t.add(
        function="foo", attack_class="command_injection",
        source="l1", finding_id="H001",
    )
    # Different function — not covered.
    assert t.is_covered(function="bar", attack_class="command_injection") is None
    # Same function, different attack class — not covered.
    assert t.is_covered(function="foo", attack_class="ssrf") is None


def test_is_covered_normalizes_attack_class() -> None:
    """The tracker stores attack_class normalized — lookup with raw
    synonym should still match."""
    t = CoverageTracker()
    t.add(
        function="fetch_url", attack_class="server_side_request_forgery",
        source="l1", finding_id="H001",
    )
    assert t.is_covered(function="fetch_url", attack_class="ssrf") is not None


def test_add_returns_false_on_duplicate() -> None:
    """Second add with same (function, attack_class) is a no-op,
    doesn't overwrite the first entry."""
    t = CoverageTracker()
    first = t.add(
        function="foo", attack_class="command_injection",
        source="l1", finding_id="H001",
    )
    second = t.add(
        function="foo", attack_class="command_injection",
        source="phase_b", finding_id="HRP_0_0",  # different source
    )
    assert first is True
    assert second is False
    # Original entry preserved (source still l1).
    entry = t.is_covered(function="foo", attack_class="command_injection")
    assert entry.source == "l1"


def test_add_skips_empty_inputs() -> None:
    """Defensive: missing function name or attack class → silently
    don't add. Matches the fail-soft posture for extraction failures."""
    t = CoverageTracker()
    assert not t.add(
        function="", attack_class="ssrf", source="l1", finding_id="H001"
    )
    assert not t.add(
        function="foo", attack_class="", source="l1", finding_id="H001"
    )
    assert len(t.entries()) == 0


def test_disabled_tracker_short_circuits() -> None:
    """When ``enabled=False`` (``--disable-coverage-dedupe``),
    is_covered always returns None — even for entries the tracker
    might have. add() still records (so telemetry stays meaningful)
    but lookups all miss → all probes run unconstrained.

    Equivalent to v1.9.0 baseline behavior."""
    t = CoverageTracker(enabled=False)
    t.add(
        function="foo", attack_class="ssrf", source="l1", finding_id="H001"
    )
    assert t.is_covered(function="foo", attack_class="ssrf") is None


# ── populate_from_l1_findings ──────────────────────────────────────────


def test_populate_loads_high_confidence_findings() -> None:
    """L1 vulnerabilities with confidence ≥ threshold land in the
    tracker; lower-confidence ones don't."""
    l1_vulns = [
        {
            "type": "command_injection",
            "cwe": "CWE-78",
            "confidence": 0.97,  # well above threshold
            "code_snippet": "def run_user_command(x):\n    subprocess.run(x, shell=True)",
        },
        {
            "type": "ssrf",
            "cwe": "CWE-918",
            "confidence": 0.3,  # below threshold — not loaded
            "code_snippet": "def fetch(u):\n    urlopen(u)",
        },
        {
            "type": "code_injection",
            "cwe": "CWE-95",
            "confidence": 0.85,
            "code_snippet": "def compute_expression(expr):\n    return eval(expr)",
        },
    ]
    t = CoverageTracker()
    added = t.populate_from_l1_findings(l1_vulns)
    assert added == 2  # 0.97 + 0.85, NOT the 0.3
    assert t.is_covered(
        function="run_user_command", attack_class="command_injection"
    ) is not None
    assert t.is_covered(
        function="compute_expression", attack_class="code_injection"
    ) is not None
    assert t.is_covered(function="fetch", attack_class="ssrf") is None


def test_populate_skips_when_function_name_extraction_fails() -> None:
    """High-conf finding with an unparseable code_snippet → silently
    skipped (no dedupe, but no crash)."""
    l1_vulns = [
        {
            "type": "ssrf",
            "cwe": "CWE-918",
            "confidence": 0.95,
            "code_snippet": "x = 1 + 2",  # no function pattern
        },
    ]
    t = CoverageTracker()
    added = t.populate_from_l1_findings(l1_vulns)
    assert added == 0


def test_populate_skips_findings_without_attack_class() -> None:
    """L1 hypothesis with empty / missing ``type`` field → can't dedupe
    by attack class → skip."""
    l1_vulns = [
        {
            "type": "",  # blank
            "cwe": "CWE-918",
            "confidence": 0.95,
            "code_snippet": "def fetch(u):\n    urlopen(u)",
        },
    ]
    t = CoverageTracker()
    added = t.populate_from_l1_findings(l1_vulns)
    assert added == 0


def test_populate_uses_h_index_finding_id_convention() -> None:
    """Finding IDs are H001-N, matching ``dast.runner._scan_result_to_l1_output``."""
    l1_vulns = [
        {
            "type": "ssrf",
            "cwe": "CWE-918",
            "confidence": 0.9,
            "code_snippet": "def fetch_first(u):\n    urlopen(u)",
        },
        {
            "type": "command_injection",
            "cwe": "CWE-78",
            "confidence": 0.9,
            "code_snippet": "def run_second(x):\n    subprocess.run(x, shell=True)",
        },
    ]
    t = CoverageTracker()
    t.populate_from_l1_findings(l1_vulns)
    assert t.is_covered(function="fetch_first", attack_class="ssrf").finding_id == "H001"
    assert t.is_covered(function="run_second", attack_class="command_injection").finding_id == "H002"


def test_populate_respects_explicit_min_confidence() -> None:
    """Operator can pass a custom threshold."""
    l1_vulns = [
        {
            "type": "ssrf",
            "confidence": 0.4,
            "code_snippet": "def fetch(u):\n    urlopen(u)",
        },
    ]
    t = CoverageTracker()
    # Default threshold (0.6) → not loaded.
    assert t.populate_from_l1_findings(l1_vulns) == 0
    # Lower threshold → loaded.
    t2 = CoverageTracker()
    assert t2.populate_from_l1_findings(l1_vulns, min_confidence=0.3) == 1


def test_populate_handles_empty_input() -> None:
    t = CoverageTracker()
    assert t.populate_from_l1_findings(None) == 0
    assert t.populate_from_l1_findings([]) == 0


def test_populate_no_op_when_disabled() -> None:
    """``--disable-coverage-dedupe`` → populate is a no-op even with
    valid input."""
    t = CoverageTracker(enabled=False)
    l1_vulns = [
        {
            "type": "ssrf", "cwe": "CWE-918", "confidence": 0.95,
            "code_snippet": "def fetch(u):\n    urlopen(u)",
        },
    ]
    assert t.populate_from_l1_findings(l1_vulns) == 0


# ── Suppression telemetry ──────────────────────────────────────────────


def test_record_suppression_counts_by_stage() -> None:
    t = CoverageTracker()
    t.record_suppression("phase_b")
    t.record_suppression("phase_b")
    t.record_suppression("phase_3")
    stats = t.stats()
    assert stats["suppressions_by_stage"] == {"phase_b": 2, "phase_3": 1}


def test_stats_groups_entries_by_source() -> None:
    t = CoverageTracker()
    t.add(
        function="f1", attack_class="ssrf",
        source="l1", finding_id="H001",
    )
    t.add(
        function="f2", attack_class="ssrf",
        source="l1", finding_id="H002",
    )
    t.add(
        function="f3", attack_class="ssrf",
        source="phase_b", finding_id="HRP_0_0",
    )
    stats = t.stats()
    assert stats["n_entries"] == 3
    assert stats["entries_by_source"] == {"l1": 2, "phase_b": 1}


def test_stats_reports_disabled_state() -> None:
    t_on = CoverageTracker(enabled=True)
    t_off = CoverageTracker(enabled=False)
    assert t_on.stats()["enabled"] is True
    assert t_off.stats()["enabled"] is False


# ── L1_TRUST_THRESHOLD constant ────────────────────────────────────────


def test_threshold_constant_sensible() -> None:
    """Sanity: the L1 trust threshold should be in a reasonable
    range — too low and we over-dedupe on weak claims; too high and
    nothing dedupes."""
    assert 0.4 <= L1_TRUST_THRESHOLD <= 0.9
