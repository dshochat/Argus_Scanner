"""Unit tests for dast/downstream_cap.py — SCAN-017 Phase 2.

Covers:

* AST-based cap detection across the four supported patterns
  (min_call, max_call, compare_le, compare_range).
* The retry-after exact regression — the openai-python ``BaseClient.
  _calculate_retry_timeout`` bounds ``_parse_retry_after_header``
  at 60s.
* Attack-class gate (ssrf / path_traversal / code_injection NOT
  suppressed by caps).
* Threshold gate (a "cap" at int.MAX doesn't actually bound enough).
* Defensive: SyntaxError sources return [], not raise.
* Defensive: caps in nested classes / async functions surface
  correctly.
* False-positive defense: a cap on function A doesn't suppress
  findings on function B even with similar names.
"""

from __future__ import annotations

import pytest

from dast.downstream_cap import (
    DownstreamCap,
    find_capping_for_function,
    find_downstream_caps,
)


# ─── AST detector — pattern coverage ────────────────────────────────────


def test_compare_range_pattern_matches_retry_after_regression() -> None:
    """The exact pattern from openai-python's _calculate_retry_timeout
    must be detected by find_downstream_caps. This is the Phase 2
    regression guard: if this stops working, the Gemini-flagged FP
    class regresses."""
    src = '''
class BaseClient:
    def _parse_retry_after_header(self, response_headers):
        return float(response_headers.get("retry-after-ms", 0)) / 1000

    def _calculate_retry_timeout(self, remaining_retries, options, response_headers):
        retry_after = self._parse_retry_after_header(response_headers)
        if retry_after is not None and 0 < retry_after <= 60:
            return retry_after
        return 1.0
'''
    caps = find_downstream_caps(src)
    matching = [c for c in caps if c.capped_function == "_parse_retry_after_header"]
    assert len(matching) >= 1, (
        f"expected at least one cap on _parse_retry_after_header, got {caps}"
    )
    cap = matching[0]
    assert cap.capper_function == "_calculate_retry_timeout"
    assert cap.pattern == "compare_range"
    assert cap.cap_value == 60.0


def test_min_call_wrap_pattern() -> None:
    """``min(parse_value(...), 60)`` — direct min-wrap cap."""
    src = '''
def parse_value(x):
    return int(x)

def use_value(x):
    return min(parse_value(x), 60)
'''
    caps = find_downstream_caps(src)
    matching = [c for c in caps if c.capped_function == "parse_value"]
    assert len(matching) == 1
    assert matching[0].pattern == "min_call"
    assert matching[0].cap_value == 60.0


def test_max_call_wrap_pattern() -> None:
    src = '''
def parse_value(x):
    return int(x)

def use_value(x):
    return max(parse_value(x), 0)
'''
    caps = find_downstream_caps(src)
    matching = [c for c in caps if c.capped_function == "parse_value"]
    assert len(matching) == 1
    assert matching[0].pattern == "max_call"
    assert matching[0].cap_value == 0.0


def test_compare_le_pattern_var_assigned_then_bounded() -> None:
    """Simple ``v = call(); if v <= N: return v`` — the bound is via
    a separate Compare statement, not a min/max wrap."""
    src = '''
def parse(x):
    return int(x)

def consume(x):
    v = parse(x)
    if v <= 100:
        return v
    return 100
'''
    caps = find_downstream_caps(src)
    matching = [c for c in caps if c.capped_function == "parse" and c.pattern == "compare_le"]
    assert len(matching) == 1
    assert matching[0].cap_value == 100.0


def test_compare_lt_pattern() -> None:
    src = '''
def parse(x):
    return int(x)

def consume(x):
    v = parse(x)
    if v < 60:
        return v
'''
    caps = find_downstream_caps(src)
    matching = [c for c in caps if c.pattern == "compare_lt"]
    assert len(matching) == 1
    assert matching[0].cap_value == 60.0


def test_caps_in_async_function_detected() -> None:
    """The detector must traverse AsyncFunctionDef bodies too — many
    SDK consumers are async."""
    src = '''
def parse(x):
    return int(x)

async def consume(x):
    v = parse(x)
    if v <= 30:
        return v
'''
    caps = find_downstream_caps(src)
    assert any(c.pattern == "compare_le" for c in caps), caps


def test_caps_in_nested_class_method_detected() -> None:
    """Method on a class nested inside another class still gets
    scanned — the AST walker descends through ClassDef."""
    src = '''
class Outer:
    class Inner:
        def parse(self, x):
            return int(x)

        def consume(self, x):
            v = self.parse(x)
            if v <= 60:
                return v
'''
    caps = find_downstream_caps(src)
    assert any(c.capped_function == "parse" for c in caps)


def test_negative_literal_cap_value() -> None:
    """``min(x, -10)`` — the unary-minus literal should resolve."""
    src = '''
def offset_calc(x):
    return x

def use_it(x):
    return min(offset_calc(x), -10)
'''
    caps = find_downstream_caps(src)
    matching = [c for c in caps if c.pattern == "min_call"]
    assert len(matching) == 1
    assert matching[0].cap_value == -10.0


def test_no_caps_when_no_calls() -> None:
    src = '''
def only_literal():
    return 60
'''
    assert find_downstream_caps(src) == []


def test_no_caps_when_call_not_assigned_or_bounded() -> None:
    """A call whose return goes straight to print() / non-bounded
    consumer doesn't constitute a cap."""
    src = '''
def parse(x):
    return int(x)

def consume(x):
    print(parse(x))
    return parse(x)
'''
    caps = find_downstream_caps(src)
    # No min/max wrap, no compare → no caps.
    assert caps == []


def test_syntax_error_returns_empty_list_not_raises() -> None:
    """Robustness: malformed source must not crash the detector.
    Stage 1's preamble runs this on user code that might be partially
    broken."""
    src = "def broken(:\n    pass"
    assert find_downstream_caps(src) == []


def test_compare_with_no_literals_skipped() -> None:
    """``if a <= b`` (both vars) is not a literal cap — skip."""
    src = '''
def parse(x):
    return int(x)

def consume(x, threshold):
    v = parse(x)
    if v <= threshold:
        return v
'''
    caps = find_downstream_caps(src)
    assert caps == []  # threshold is a Name not a literal


def test_method_call_on_self_resolves_to_tail_name() -> None:
    """``self._parse_X`` calls must be matched to ``_parse_X`` so the
    orchestrator's tail-name match works."""
    src = '''
class C:
    def _parse_X(self, x):
        return int(x)

    def consume(self, x):
        v = self._parse_X(x)
        if v <= 60:
            return v
'''
    caps = find_downstream_caps(src)
    matching = [c for c in caps if c.capped_function == "_parse_X"]
    assert len(matching) == 1


# ─── find_capping_for_function — gate logic ─────────────────────────────


def test_capping_lookup_returns_match_for_relevant_attack_class() -> None:
    """data_exfiltration + cap at 60 + threshold 120 → match."""
    caps = [
        DownstreamCap(
            capped_function="_parse_retry_after_header",
            capper_function="_calculate_retry_timeout",
            capper_line=10,
            pattern="compare_range",
            cap_value=60.0,
        )
    ]
    cap = find_capping_for_function(
        "_parse_retry_after_header", "data_exfiltration", caps
    )
    assert cap is not None
    assert cap.cap_value == 60.0


def test_capping_lookup_returns_none_for_ssrf_attack_class() -> None:
    """SSRF doesn't care about magnitude — a 60s retry cap doesn't
    invalidate an SSRF exploit (which is about destination, not
    duration). Must NOT suppress."""
    caps = [
        DownstreamCap(
            capped_function="_parse_url",
            capper_function="consumer",
            capper_line=5,
            pattern="compare_le",
            cap_value=60.0,
        )
    ]
    assert find_capping_for_function("_parse_url", "ssrf", caps) is None


def test_capping_lookup_returns_none_for_path_traversal() -> None:
    caps = [
        DownstreamCap(
            capped_function="_resolve_path",
            capper_function="open_file",
            capper_line=5,
            pattern="compare_le",
            cap_value=100.0,
        )
    ]
    assert find_capping_for_function("_resolve_path", "path_traversal", caps) is None


def test_capping_lookup_threshold_above_cap_doesnt_suppress() -> None:
    """A "cap" at 10,000 seconds isn't a real bound for the retry-
    amplification exploit (threshold is 120). Must NOT suppress."""
    caps = [
        DownstreamCap(
            capped_function="_parse_retry",
            capper_function="use_retry",
            capper_line=5,
            pattern="compare_le",
            cap_value=10_000.0,
        )
    ]
    cap = find_capping_for_function(
        "_parse_retry", "data_exfiltration", caps
    )
    assert cap is None


def test_capping_lookup_picks_most_restrictive_cap() -> None:
    """Multiple caps on the same function — pick the lowest (most
    restrictive). Useful when the function is called from several
    consumers, each with their own bound."""
    caps = [
        DownstreamCap(
            capped_function="parse",
            capper_function="a",
            capper_line=1,
            pattern="compare_le",
            cap_value=100.0,
        ),
        DownstreamCap(
            capped_function="parse",
            capper_function="b",
            capper_line=10,
            pattern="compare_le",
            cap_value=30.0,
        ),
    ]
    cap = find_capping_for_function("parse", "data_exfiltration", caps)
    assert cap is not None
    assert cap.cap_value == 30.0


def test_capping_lookup_tail_name_match() -> None:
    """The orchestrator passes ``ClassName.method`` for instance methods.
    The lookup must compare on the tail name only (``method``) since
    the AST visitor records the bare name."""
    caps = [
        DownstreamCap(
            capped_function="_parse_retry_after_header",
            capper_function="_calculate_retry_timeout",
            capper_line=10,
            pattern="compare_range",
            cap_value=60.0,
        )
    ]
    cap = find_capping_for_function(
        "BaseClient._parse_retry_after_header",
        "data_exfiltration",
        caps,
    )
    assert cap is not None


def test_capping_lookup_compare_ge_is_lower_bound_skipped() -> None:
    """``v >= 60`` is a LOWER bound (the cap allows v ≥ 60). That's
    not the magnitude protection we're checking for; the exploit is
    still possible. Must NOT suppress."""
    caps = [
        DownstreamCap(
            capped_function="parse",
            capper_function="use",
            capper_line=1,
            pattern="compare_ge",
            cap_value=60.0,
        )
    ]
    assert find_capping_for_function("parse", "data_exfiltration", caps) is None


def test_capping_lookup_unrelated_function_name_doesnt_match() -> None:
    """``parse_url`` cap shouldn't suppress findings on ``parse_xml``
    — the names happen to share a prefix but they're different
    functions. This is the FP-defense check on Phase 2 itself."""
    caps = [
        DownstreamCap(
            capped_function="parse_url",
            capper_function="consume",
            capper_line=1,
            pattern="compare_le",
            cap_value=60.0,
        )
    ]
    assert (
        find_capping_for_function("parse_xml", "data_exfiltration", caps)
        is None
    )


def test_capping_lookup_empty_caps_list() -> None:
    """Defensive: when the file produced no caps (empty file, pure
    constants, etc.), the lookup returns None cleanly."""
    assert find_capping_for_function("anything", "data_exfiltration", []) is None
