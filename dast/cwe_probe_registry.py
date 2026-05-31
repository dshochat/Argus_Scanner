"""v15.22 — CWE → DAST attack_class registry (Gemini Issue 3).

Static analysis (L1) emits CWE-formatted finding identifiers; Phase B+
needs to dispatch the right runtime probe per CWE. Pre-v15.22 the Sonnet
prompt picked an attack_class generically (often defaulting to ``ssrf``
when a URL was involved) — which meant a CWE-319 cleartext-transmission
finding got probed with SSRF payloads that aren't designed to detect
protocol-downgrade vulnerabilities.

This registry is the deterministic mapping. The Phase B+ prompt instructs
Sonnet to read it when picking ``attack_class`` for a candidate that
corresponds to a specific L1 CWE. Sonnet can still override (the prompt
is advisory, not constraint) but the default is now precise per CWE.

The registry is intentionally small + curated. Adding entries here is
the single change required to teach Phase B+ a new CWE↔probe pairing.
"""

from __future__ import annotations

# Deterministic mapping from L1's CWE identifier to the matching
# Phase B+ ``attack_class``. Multiple CWEs can map to the same attack
# class (we group functionally-equivalent runtime tests together).
#
# Format: bare CWE id (no leading "CWE-") -> attack_class string.
# The lookup helper normalizes both forms (with/without prefix).
CWE_TO_ATTACK_CLASS: dict[str, str] = {
    # Path / file disclosure
    "22": "path_traversal",
    "23": "path_traversal",
    "35": "path_traversal",
    "59": "path_traversal",  # symlink TOCTOU often produces traversal
    "73": "path_traversal",
    # Command / code injection
    "77": "command_injection",
    "78": "command_injection",
    "94": "code_injection",
    "95": "code_injection",
    "184": "code_injection",  # incomplete blocklist
    # SQL injection family
    "89": "sql_injection",
    "564": "sql_injection",  # SQL injection via untrusted ORM hibernate
    # Cross-site scripting family
    "79": "xss",
    "80": "xss",
    "83": "xss",
    "86": "xss",
    "87": "xss",
    # XML external entity / XXE family
    "611": "xxe",
    "776": "xxe",  # XXE via incomplete blocklist
    "827": "xxe",
    # Deserialization / pickle / unsafe yaml
    "502": "deserialization",
    "915": "deserialization",  # improperly controlled modification of object
    # SSRF — request to attacker-chosen target
    "918": "ssrf",
    "601": "open_redirect",  # related but distinct
    "1289": "ssrf",  # outbound network access
    # Data exfiltration / info disclosure
    "200": "data_exfiltration",
    "201": "data_exfiltration",
    "202": "data_exfiltration",  # info exposure via env vars
    "532": "data_exfiltration",  # log file info exposure
    "538": "data_exfiltration",
    "612": "data_exfiltration",  # info exposure via indexable resource
    # Crypto / cleartext family
    "319": "cleartext_transmission",  # the one Gemini explicitly called out
    "311": "cleartext_transmission",  # missing encryption of sensitive data
    "312": "cleartext_transmission",  # cleartext storage of sensitive info
    "316": "cleartext_transmission",  # cleartext storage in memory
    # Weak crypto / RNG
    "327": "crypto_weakness",
    "328": "crypto_weakness",  # use of weak hash
    "330": "crypto_weakness",  # insufficient randomness
    "338": "crypto_weakness",  # weak PRNG for cryptographic ops
    "335": "crypto_weakness",
    # Race conditions
    "362": "race_condition",
    "364": "race_condition",
    "366": "race_condition",
    "367": "race_condition",  # TOCTOU race
    # Prompt injection (v1.0-era classification)
    "1389": "prompt_injection",
}


def attack_class_for_cwe(cwe: str | None) -> str | None:
    """Look up the registered DAST attack_class for a given CWE id.

    Accepts both ``"CWE-319"`` and ``"319"`` shapes. Returns ``None``
    when the CWE has no registered probe — callers should fall back to
    the model's own attack_class choice (Sonnet still picks
    autonomously when the registry doesn't speak to a finding).

    >>> attack_class_for_cwe("CWE-319")
    'cleartext_transmission'
    >>> attack_class_for_cwe("319")
    'cleartext_transmission'
    >>> attack_class_for_cwe("CWE-9999") is None
    True
    >>> attack_class_for_cwe(None) is None
    True
    """
    if not cwe:
        return None
    s = str(cwe).strip().upper()
    if s.startswith("CWE-"):
        s = s[4:]
    return CWE_TO_ATTACK_CLASS.get(s)


def recommended_probes_for_l1_findings(
    vulnerabilities: list[dict] | None,
) -> dict[str, str]:
    """Bulk lookup: derive the recommended ``attack_class`` for each L1
    finding via its CWE. Returns ``{finding_id: attack_class}`` for
    findings where the registry has a match.

    The orchestrator can pass this dict into the Phase B+ prompt
    rendering so Sonnet sees "L1 flagged H001 with CWE-319 — use
    cleartext_transmission" explicitly.
    """
    out: dict[str, str] = {}
    if not vulnerabilities:
        return out
    for i, v in enumerate(vulnerabilities):
        if not isinstance(v, dict):
            continue
        cwe = v.get("cwe")
        ac = attack_class_for_cwe(cwe)
        if ac is None:
            continue
        # H001-shaped finding id, matching the H### convention used
        # elsewhere in the engine output.
        fid = f"H{i + 1:03d}"
        out[fid] = ac
    return out


__all__ = [
    "CWE_TO_ATTACK_CLASS",
    "attack_class_for_cwe",
    "recommended_probes_for_l1_findings",
]
