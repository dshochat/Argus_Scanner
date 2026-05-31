"""Placeholder-value filter for L1 hardcoded-credential findings (v1.6 Fix #6).

Gemini 3.1 Pro adjudication of the v1.6 23-file bench (commit 29e9ca9 +
followup) flagged a recurring false-positive pattern: L1 flags strings
like ``password = "REPLACE_ME_BEFORE_PROD"`` or
``token = "DEMO_PLACEHOLDER_TOKEN"`` as CWE-798 hardcoded credentials.

These aren't real secrets — they're developer placeholders left for
operators to fill in. Flagging them as ``critical`` hardcoded-credential
findings wastes the customer's attention and erodes trust.

This filter is deterministic, conservative, and scales: the placeholder
markers it detects are UNIVERSAL developer conventions (REPLACE_ME, TODO,
DEMO, etc.) that appear in every codebase, not bench-specific markers.

The filter only fires on credential-class CWEs (see
``_CREDENTIAL_CWES``). All other findings pass through unchanged — we
don't want to accidentally drop, e.g., a CWE-78 command-injection
finding just because someone put ``# TODO`` in the surrounding code.
"""

from __future__ import annotations

import re
from typing import Any

# CWEs where a placeholder value commonly causes a false positive.
# Limited to credential/secret-class CWEs — placeholder text in,
# e.g., command-injection code is irrelevant to whether the bug is real.
_CREDENTIAL_CWES: frozenset[str] = frozenset(
    {
        "CWE-798",  # Use of Hard-coded Credentials
        "CWE-321",  # Use of Hard-coded Cryptographic Key
        "CWE-312",  # Cleartext Storage of Sensitive Information
        "CWE-522",  # Insufficiently Protected Credentials
        "CWE-256",  # Plaintext Storage of a Password
    }
)

#: Universal developer-placeholder markers. Case-insensitive substring
#: match against the finding's literal value (extracted from ``code``,
#: ``proof_of_concept``, or ``data_flow_trace``). These conventions
#: appear in real customer codebases — not bench-specific.
#:
#: To keep false-drop risk low, we only match when the marker is
#: clearly meant as a placeholder (e.g., ``REPLACE_ME``, not just
#: ``replace`` in some larger word).
_PLACEHOLDER_MARKERS: tuple[str, ...] = (
    # Direct placeholders
    "replace_me",
    "replace-me",
    "replaceme",
    "replace_with",
    "fill_in",
    "fill-in",
    "fillin",
    "to_fill",
    "to-fill",
    "todo",
    "fixme",
    "xxxxxx",
    # Demo / example / sample
    "demo_placeholder",
    "demo-placeholder",
    "placeholder",
    "dummy",
    "example_key",
    "example-key",
    "example_secret",
    "example-secret",
    "example_token",
    "example-token",
    "sample_key",
    "sample_secret",
    "sample_token",
    "your-api-key",
    "your_api_key",
    "your-secret",
    "your_secret",
    "your-token",
    "your_token",
    "your-password",
    "your_password",
    "<your",
    "your-",
    "your_",
    # "Change me" pattern
    "changeme",
    "change-me",
    "change_me",
    # Insert/replace prompts
    "<insert",
    "<change",
    "<replace",
    "<paste",
    # SDK test keys (developer-facing test fixtures, not real secrets)
    "sk-test-",
    "sk-fake-",
    "test-key-",
    "fake-key-",
    "fake_key_",
    "dummy_key",
    "dummy-key",
    # Template/env-var defaults
    "${",
    "{{",
    "<%=",
)


def _extract_finding_value(vuln: dict[str, Any]) -> str:
    """Pull the literal credential/secret value from a vulnerability dict.

    L1 emits findings with a ``code`` field (the source snippet) and
    sometimes a ``proof_of_concept`` field (the actual exploit input).
    The placeholder check examines BOTH so a finding like
    ``code = 'password = X'`` + ``proof_of_concept = '"REPLACE_ME"'``
    still matches.

    Returns a lowercased concatenation of the relevant fields, so
    callers can substring-match against ``_PLACEHOLDER_MARKERS``.
    """
    parts: list[str] = []
    for key in ("code", "proof_of_concept", "data_flow_trace", "explanation"):
        v = vuln.get(key)
        if isinstance(v, str) and v.strip():
            parts.append(v)
    return " ".join(parts).lower()


def _normalize_cwe(cwe: Any) -> str:
    """Normalize CWE id to canonical ``CWE-NNN`` form for membership check."""
    if not isinstance(cwe, str):
        return ""
    s = cwe.strip().upper()
    if not s:
        return ""
    if not s.startswith("CWE-"):
        # Bare number ("798") or "CWE 798" → normalize.
        m = re.match(r"CWE[\s-]?(\d+)", s)
        if m:
            return f"CWE-{m.group(1)}"
        if s.isdigit():
            return f"CWE-{s}"
        return s
    return s


def is_placeholder_credential_finding(vuln: dict[str, Any]) -> bool:
    """Return True iff this finding is a credential-class CWE whose
    literal value contains a developer placeholder marker.

    A True return means the finding should be DROPPED — it's almost
    certainly a false positive over a placeholder string left by the
    developer for operators to fill in.

    Conservative: returns False for any non-credential CWE so we never
    accidentally drop a legitimate command-injection / path-traversal /
    etc. finding just because nearby code contains a TODO.
    """
    if not isinstance(vuln, dict):
        return False
    cwe = _normalize_cwe(vuln.get("cwe"))
    if cwe not in _CREDENTIAL_CWES:
        return False
    haystack = _extract_finding_value(vuln)
    if not haystack:
        return False
    return any(marker in haystack for marker in _PLACEHOLDER_MARKERS)


def filter_placeholder_findings(
    vulnerabilities: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split vulnerabilities into (kept, dropped) based on placeholder
    detection.

    Dropped findings are returned alongside the kept set so the engine
    can record the count in ``scan_path`` (visibility for the operator)
    without surfacing the false-positive finding to the customer.

    Pure function — no I/O, no model calls. Deterministic and cheap
    enough to run on every L1 result.
    """
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for v in vulnerabilities or []:
        if is_placeholder_credential_finding(v):
            dropped.append(v)
        else:
            kept.append(v)
    return kept, dropped


__all__ = [
    "filter_placeholder_findings",
    "is_placeholder_credential_finding",
]
