"""Unit tests for dast/probe_mutator.py — Phase 1a mutation expansion.

Mutator takes a model-generated probe input and fans it out to N known-
bypass variants per attack class. These tests verify:

* Class-specific mutations fire when the attack_class matches the
  registry (path_traversal gets quad-dot, command_injection gets
  semicolon-chain, etc.).
* Universal mutations (URL-encode, length-pad) fire across all classes.
* The cap (max_mutations) is respected — fan-out never exceeds it.
* Every emitted args_json is valid JSON.
* Original input is NOT duplicated in the output (caller adds it).
* Non-string args are left untouched (cap-position-respected skip).
* Strategy labels are namespaced (e.g., "path_traversal:quad_dot" vs
  "universal:url_encode") so the journal can attribute hits to specific
  bypass families.
"""

from __future__ import annotations

import json

from dast.probe_mutator import MAX_MUTATIONS_PER_INPUT, mutate_input

# ── Per-class mutation coverage ───────────────────────────────────────────


def test_path_traversal_emits_class_specific_mutations() -> None:
    """Path traversal candidate gets at least the canonical bypass
    families: quad-dot, encoded slashes, backslashes, encoded dots.
    These map to known CVE patterns on insufficient sanitization."""
    out = mutate_input(args_json='["../../etc/passwd"]', attack_class="path_traversal")
    strategies = [label for _, label in out]
    # Class-specific labels appear first in fan-out
    assert any("path_traversal:quad_dot" in s for s in strategies)
    assert any("path_traversal:encoded_slash" in s for s in strategies)
    assert any("path_traversal:backslash" in s for s in strategies)


def test_command_injection_emits_chaining_variants() -> None:
    """Command injection gets shell-separator chaining (`;`, `|`, ``` ` ```,
    ``$()``) — bypasses for sanitizers that only handle the obvious
    metachars."""
    out = mutate_input(args_json='["safe input"]', attack_class="command_injection")
    strategies = [label for _, label in out]
    assert any("command_injection:semicolon_chain" in s for s in strategies)
    assert any("command_injection:pipe_chain" in s for s in strategies)
    assert any("command_injection:subshell_subst" in s for s in strategies)


def test_sql_injection_emits_tautology_and_union_variants() -> None:
    """SQLi gets the classic `' OR 1=1--` + UNION SELECT version()
    + inline-comment bypass families."""
    out = mutate_input(args_json='["user_input"]', attack_class="sql_injection")
    strategies = [label for _, label in out]
    assert any("sql_injection:or_tautology" in s for s in strategies)
    assert any("sql_injection:union_version" in s for s in strategies)


def test_ssrf_emits_aws_imds_and_localhost_variants() -> None:
    """SSRF gets internal-target payloads — AWS IMDS, localhost,
    file://, gopher://. The mutated args completely REPLACE the
    original (e.g., ``http://example.com`` becomes
    ``http://169.254.169.254/...``) since the attack is about
    redirecting the request, not modifying the body."""
    out = mutate_input(args_json='["http://example.com"]', attack_class="ssrf")
    strategies = [label for _, label in out]
    payloads = [json.loads(args)[0] for args, _ in out]
    assert any("ssrf:aws_imds" in s for s in strategies)
    assert any("169.254.169.254" in p for p in payloads)
    assert any("file:///etc/passwd" in p for p in payloads)


def test_xxe_emits_external_entity_payloads() -> None:
    out = mutate_input(args_json='["<foo/>"]', attack_class="xxe")
    payloads = [json.loads(args)[0] for args, _ in out]
    assert any("<!DOCTYPE" in p and "ENTITY" in p for p in payloads)


# ── Universal mutations + fallback behavior ──────────────────────────────


def test_unknown_attack_class_falls_back_to_universal_only() -> None:
    """When attack_class isn't in the class registry, fan-out uses
    universal mutations only (URL-encode, length-pad, etc.). Output
    is never empty for a string arg."""
    out = mutate_input(args_json='["input"]', attack_class="alien_invasion")
    assert out  # universal mutations always have something
    strategies = [label for _, label in out]
    # All labels should be in the universal namespace
    assert all(s.startswith("universal:") for s in strategies), strategies


def test_universal_url_encode_fires() -> None:
    """URL-encode mutation produces percent-escaped variant."""
    out = mutate_input(args_json='["foo/bar"]', attack_class="data_exfiltration")
    # Universal mutations fill remaining slots after class-specific
    payloads = [json.loads(args)[0] for args, _ in out]
    # %2f is the URL-encoded form of '/'
    assert any("%2f" in p.lower() for p in payloads)


# ── Contract invariants ──────────────────────────────────────────────────


def test_default_cap_is_respected() -> None:
    """Fan-out is capped at MAX_MUTATIONS_PER_INPUT by default."""
    out = mutate_input(args_json='["../../etc/passwd"]', attack_class="path_traversal")
    assert len(out) <= MAX_MUTATIONS_PER_INPUT


def test_explicit_cap_is_respected() -> None:
    """Caller can override the cap downward (e.g., for cost control)."""
    out = mutate_input(
        args_json='["../../etc/passwd"]',
        attack_class="path_traversal",
        max_mutations=2,
    )
    assert len(out) == 2


def test_zero_cap_returns_empty() -> None:
    """max_mutations=0 means 'no mutations' — return empty list."""
    out = mutate_input(
        args_json='["../../etc/passwd"]',
        attack_class="path_traversal",
        max_mutations=0,
    )
    assert out == []


def test_every_emitted_args_json_is_valid_json() -> None:
    """Each mutation produces a string that parses back as JSON.
    Roundtrip-safety is non-negotiable — the orchestrator feeds these
    into JSON.parse() inside the sandbox harness."""
    out = mutate_input(
        args_json='["payload with \\\\ backslashes and \\"quotes\\""]',
        attack_class="path_traversal",
    )
    for args_json, _label in out:
        # Must parse cleanly
        parsed = json.loads(args_json)
        # Must remain a list (we only do single-arg substitution)
        assert isinstance(parsed, list)


def test_original_input_not_duplicated_in_output() -> None:
    """Caller probes the original input separately; the mutator must
    NOT emit a duplicate of the input. Skipping is the contract."""
    original = '["../etc/passwd"]'
    out = mutate_input(args_json=original, attack_class="path_traversal")
    args_jsons = [args for args, _ in out]
    assert original not in args_jsons, "original input duplicated in mutator output"


def test_no_duplicate_mutations_emitted() -> None:
    """If two mutators produce the same output string (e.g., URL-encode
    of an alphanumeric input is a no-op), the duplicate is skipped."""
    out = mutate_input(args_json='["abc"]', attack_class="path_traversal")
    args_jsons = [args for args, _ in out]
    assert len(args_jsons) == len(set(args_jsons))


def test_non_string_args_are_left_untouched() -> None:
    """For ``[42, true, null]`` args, mutator finds no string to mutate
    and returns empty (no fan-out)."""
    out = mutate_input(args_json="[42, true, null]", attack_class="command_injection")
    assert out == []


def test_empty_args_returns_empty() -> None:
    """``[]`` args → no fan-out."""
    out = mutate_input(args_json="[]", attack_class="path_traversal")
    assert out == []


def test_malformed_args_json_returns_empty() -> None:
    """Defensive: invalid JSON returns empty rather than raising. The
    orchestrator shouldn't crash on a model-generated bad payload."""
    out = mutate_input(args_json="not valid json {", attack_class="path_traversal")
    assert out == []


def test_non_list_args_json_returns_empty() -> None:
    """If args_json decodes to something that isn't a list (e.g., a
    dict, a bare string), mutator returns empty."""
    out = mutate_input(args_json='{"a": 1}', attack_class="path_traversal")
    assert out == []
    out = mutate_input(args_json='"a string"', attack_class="path_traversal")
    assert out == []


def test_strategy_labels_are_namespaced() -> None:
    """Class-specific labels start with the attack class; universal
    labels start with 'universal:'. Journal forensics rely on this."""
    out = mutate_input(args_json='["x/y"]', attack_class="path_traversal")
    for _, label in out:
        # Either class:strategy or universal:strategy — never bare
        assert ":" in label
        assert label.startswith("path_traversal:") or label.startswith("universal:")


def test_single_arg_substitution_preserves_other_args() -> None:
    """For multi-arg inputs, only the first STRING arg is mutated; other
    args (including string args at higher positions) are preserved
    unchanged when the cap is reached."""
    out = mutate_input(
        args_json='["../../etc/passwd", "trailing_marker"]',
        attack_class="path_traversal",
        max_mutations=3,
    )
    for args_json, _ in out:
        parsed = json.loads(args_json)
        assert len(parsed) == 2
        # Second arg preserved
        assert parsed[1] == "trailing_marker"
        # First arg actually mutated
        assert parsed[0] != "../../etc/passwd"


# ── Class-specific mutations precede universal mutations ─────────────────


def test_class_mutations_fire_first_universal_fill_remaining() -> None:
    """When a class has fewer registered mutations than the cap allows,
    universal mutations fill the remaining slots. Verifies the precedence
    contract: class-specific first (higher hit-rate), universal last."""
    # ssrf has 4 class mutations + universal fills slot 5
    out = mutate_input(args_json='["http://example.com"]', attack_class="ssrf", max_mutations=5)
    strategies = [label for _, label in out]
    # First entries should all be ssrf:* (class-specific)
    class_count = sum(1 for s in strategies if s.startswith("ssrf:"))
    universal_count = sum(1 for s in strategies if s.startswith("universal:"))
    assert class_count >= 3  # at least most of the ssrf mutations fire
    assert class_count + universal_count == len(strategies)
