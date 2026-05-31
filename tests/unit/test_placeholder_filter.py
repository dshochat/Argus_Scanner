"""Unit tests for scanner.placeholder_filter — v1.6 Fix #6.

Verifies the deterministic placeholder detector drops developer-
placeholder credential findings without over-firing on legitimate
non-credential findings.
"""

from __future__ import annotations

import pytest

from scanner.placeholder_filter import (
    filter_placeholder_findings,
    is_placeholder_credential_finding,
)

# ── _is_placeholder_credential_finding ─────────────────────────────────────


def _cred(cwe: str, code: str = "", poc: str = "") -> dict:
    """Helper to build a minimal credential-class finding."""
    return {
        "cwe": cwe,
        "type": "hardcoded_credentials",
        "severity": "high",
        "line": 10,
        "code": code,
        "explanation": "stub",
        "fix": "stub",
        "confidence": 0.8,
        "data_flow_trace": "",
        "proof_of_concept": poc,
    }


@pytest.mark.parametrize(
    "marker",
    [
        "REPLACE_ME",
        "replace-me",
        "REPLACEME",
        "TODO",
        "FIXME",
        "DEMO_PLACEHOLDER",
        "DEMO_PLACEHOLDER_TOKEN",
        "placeholder",
        "your-api-key",
        "<your-secret>",
        "changeme",
        "${SECRET_VAR}",
        "{{ secret }}",
        "<insert your token here>",
        "sk-test-FAKE_KEY",
        "fake-key-123",
        "xxxxxx",
    ],
)
def test_credential_finding_with_placeholder_marker_is_dropped(
    marker: str,
) -> None:
    """Every universal placeholder marker should trigger drop on a
    CWE-798 credential finding. These are developer conventions that
    appear in real customer codebases — not bench-specific."""
    vuln = _cred("CWE-798", code=f'password = "{marker}"')
    assert is_placeholder_credential_finding(vuln) is True


def test_real_hardcoded_password_is_kept() -> None:
    """A legitimate-looking hardcoded password (not matching any
    placeholder pattern) must NOT be dropped."""
    vuln = _cred("CWE-798", code='password = "hunter2"')
    assert is_placeholder_credential_finding(vuln) is False


def test_real_aws_access_key_is_kept() -> None:
    """A real-shaped AWS access key must NOT be dropped — only universal
    placeholder markers trigger the filter."""
    vuln = _cred(
        "CWE-798",
        code='aws_access_key = "AKIAIOSFODNN7EXAMPLE"',
    )
    # "EXAMPLE" alone isn't enough — that word isn't in the marker list.
    # The marker would need to be "example_key" / "example-key" / "<your".
    assert is_placeholder_credential_finding(vuln) is False


def test_non_credential_finding_with_placeholder_is_kept() -> None:
    """Critical: a NON-credential finding (e.g., command injection,
    path traversal) that happens to have placeholder text in nearby
    code must NOT be dropped. The filter only fires on credential CWEs."""
    # CWE-78 OS command injection — placeholder in adjacent code is
    # irrelevant to whether the command-injection bug is real.
    vuln = {
        "cwe": "CWE-78",
        "type": "command_injection",
        "severity": "critical",
        "line": 42,
        "code": "subprocess.run(user_input)  # TODO: validate",
        "explanation": "user input flows to subprocess",
        "fix": "use shlex.quote",
        "confidence": 0.9,
        "data_flow_trace": "",
        "proof_of_concept": "",
    }
    assert is_placeholder_credential_finding(vuln) is False


def test_placeholder_in_proof_of_concept_field_triggers_drop() -> None:
    """The check examines proof_of_concept as well as code. If the PoC
    field carries the placeholder text, that should still fire."""
    vuln = _cred(
        "CWE-798",
        code="api_key = secret_var",
        poc='secret_var = "REPLACE_ME_BEFORE_PROD"',
    )
    assert is_placeholder_credential_finding(vuln) is True


def test_placeholder_in_explanation_field_triggers_drop() -> None:
    """The explanation field is also examined — useful when L1's
    rationale text mentions the placeholder pattern explicitly."""
    vuln = _cred("CWE-798", code="token = X")
    vuln["explanation"] = "Hardcoded token equal to TODO placeholder string"
    assert is_placeholder_credential_finding(vuln) is True


@pytest.mark.parametrize(
    "cwe",
    ["CWE-798", "CWE-321", "CWE-312", "CWE-522", "CWE-256"],
)
def test_all_credential_cwes_are_covered(cwe: str) -> None:
    """All 5 credential-class CWEs should trigger the filter when
    the value matches a placeholder marker."""
    vuln = _cred(cwe, code='secret = "REPLACE_ME"')
    assert is_placeholder_credential_finding(vuln) is True


def test_cwe_normalization() -> None:
    """The normalizer handles ``798``, ``cwe-798``, ``CWE 798``,
    ``CWE-798`` equally."""
    for raw in ("798", "cwe-798", "CWE 798", "CWE-798"):
        vuln = _cred(raw, code='token = "REPLACE_ME"')
        assert is_placeholder_credential_finding(vuln) is True, f"normalization failed for {raw!r}"


def test_empty_finding_does_not_crash() -> None:
    """Defensive: an empty/malformed finding dict returns False."""
    assert is_placeholder_credential_finding({}) is False
    assert is_placeholder_credential_finding({"cwe": ""}) is False
    assert is_placeholder_credential_finding({"cwe": "CWE-798"}) is False


def test_non_dict_finding_does_not_crash() -> None:
    """Defensive: a non-dict value (e.g., None, string) returns False."""
    assert is_placeholder_credential_finding(None) is False  # type: ignore[arg-type]
    assert is_placeholder_credential_finding("string") is False  # type: ignore[arg-type]


# ── filter_placeholder_findings (the top-level API) ────────────────────────


def test_filter_separates_kept_from_dropped() -> None:
    """The list-level filter returns (kept, dropped) tuples."""
    vulns = [
        _cred("CWE-798", code='password = "REPLACE_ME"'),  # drop
        _cred("CWE-798", code='password = "hunter2"'),  # keep
        {  # keep — CWE-78 is not credential class
            "cwe": "CWE-78",
            "type": "command_injection",
            "severity": "critical",
            "line": 5,
            "code": "os.system(user_input)",
            "explanation": "",
            "fix": "",
            "confidence": 0.9,
            "data_flow_trace": "",
            "proof_of_concept": "",
        },
        _cred("CWE-312", code='log.info(f"token={DEMO_PLACEHOLDER_TOKEN}")'),  # drop
    ]
    kept, dropped = filter_placeholder_findings(vulns)
    assert len(kept) == 2
    assert len(dropped) == 2
    # Confirm CWE-78 finding is kept (non-credential)
    assert any(v["cwe"] == "CWE-78" for v in kept)
    # Confirm the kept credential is the real-looking one
    assert any("hunter2" in v["code"] for v in kept)


def test_filter_empty_input_returns_empty_lists() -> None:
    kept, dropped = filter_placeholder_findings([])
    assert kept == []
    assert dropped == []


def test_filter_none_input_returns_empty_lists() -> None:
    kept, dropped = filter_placeholder_findings(None)  # type: ignore[arg-type]
    assert kept == []
    assert dropped == []
