"""Cryptographic-sensitivity detection — PREP-020.

Recognizes files that import or invoke low-level cryptographic primitives
where misuse is high-blast-radius and where L1's default 2048-token
triage is most likely to miss subtle vulnerabilities (custom IV
handling, weak modes, hardcoded keys, padding oracles, etc.). When
detected, the orchestrator forces ``priority_score >= 4`` the same way
it does for ``imperative_install_detected`` and ``attack_vector_extension``,
which in turn triggers the SAST-ANALYSIS-007 attack-vector advisory in
the L1 prompt (broadened in Fix 6 to fire on any priority ≥ 4).

Why this, why now
-----------------
Surfaced by the DAST campaign closure (2026-05-04). The
``tpm_symmetric_cipher.py`` fixture has an `legacy_iv_mode` that
returns the initial IV instead of the last ciphertext block — a real
CBC IV-reuse pattern (CVE-2026-21444 family). Oracle says
``suspicious``; baseline L1 returns ``clean``, buying the file's
"compatibility shim for regression testing" cover-story comments.

Promoting this file to priority ≥ 4 triggers the Fix 6 advisory
("don't return clean based on cover-story narratives when priority
flags suggest attack-surface code") and gives L1 the prompting context
it needs to flag the cryptographic anti-pattern.

Detection strategy
------------------
Two-tier signal:

1. **Imports of crypto-sensitive packages** (high recall, low precision
   — files that *use* crypto, not necessarily *misuse* it):
     * ``cryptography.hazmat.*``  — low-level "hazmat" layer,
       explicitly named for its danger.
     * ``Crypto.*`` / ``Cryptodome.*`` — pycryptodome / pycrypto.
     * ``OpenSSL.*`` — pyOpenSSL.
     * ``nacl.*`` — PyNaCl.
     * ``passlib.hash.*`` — password-hashing primitives.
     * ``hashlib`` *combined with* a crypto-misuse pattern (see below).
     * ``hmac`` *combined with* a crypto-misuse pattern.

2. **Crypto-misuse pattern markers** (lower recall, higher precision):
     * ``MODE_ECB`` (any reference, regardless of import path)
     * Identifier names containing ``legacy_iv``, ``static_iv``,
       ``hardcoded_key``, ``insecure_mode``
     * Hardcoded byte-string assignment to a variable named ``key`` /
       ``iv`` / ``salt`` (literal bytes of length 16/24/32 — common
       AES key/IV lengths)
     * MD5/SHA1 used in a context that suggests crypto, not just
       checksumming (e.g. assigned to ``key_material``, ``mac``,
       ``signature``)

Either signal alone is enough to set ``crypto_sensitivity_detected =
True``. The detector returns a list of reasons so the orchestrator /
L1 prompt can include the trigger context.

Out of scope
------------
This detector does NOT attempt to determine whether the use IS misuse.
That's L1's job. The signal is "this file is in cryptographic-attack-
surface territory; treat it as priority ≥ 4 and run the advisory".
False positives here cost extra L1 inference but don't produce wrong
verdicts — L1 is free to return ``clean`` on a file that imports
cryptography but uses it correctly.

Returns
-------
``CryptoSensitivitySignal(detected: bool, reasons: list[str])``. The
reasons list is used in the LabelRecord telemetry and (if needed) in
the L1 advisory injection.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CryptoSensitivitySignal:
    detected: bool
    reasons: list[str] = field(default_factory=list)


# Module-name prefixes that mark crypto-sensitive territory by import alone.
# Match either ``import X.Y`` or ``from X.Y.Z import A`` shapes.
_CRYPTO_MODULE_PREFIXES: tuple[str, ...] = (
    "cryptography.hazmat",
    "Crypto",
    "Cryptodome",
    "OpenSSL",
    "nacl",
    "passlib.hash",
)

# Modules that are crypto-sensitive only when paired with misuse markers.
# ``hashlib`` and ``hmac`` are used legitimately for checksumming all the
# time; we don't auto-promote on the import alone.
_CRYPTO_MAYBE_MODULES: frozenset[str] = frozenset({"hashlib", "hmac"})

# Identifier substrings that indicate crypto-misuse intent.
_MISUSE_NAME_FRAGMENTS: tuple[str, ...] = (
    "legacy_iv",
    "static_iv",
    "hardcoded_key",
    "insecure_mode",
    "weak_iv",
)

# Sensitive variable names whose hardcoded literal assignment is a smell.
_SENSITIVE_VAR_NAMES: frozenset[str] = frozenset({"key", "iv", "salt", "secret", "token", "password"})

# AES-key / AES-IV byte-length anchors. A bytes literal of these lengths
# assigned to a variable in ``_SENSITIVE_VAR_NAMES`` is considered
# hardcoded crypto material.
_AES_BYTE_LENGTHS: frozenset[int] = frozenset({16, 24, 32})

# Pre-compiled token regex for cheap content scans (used as a backstop
# when AST parsing fails on partial / non-Python files that still
# contain Python-ish import statements).
# MODE_ECB may appear standalone (Crypto.Cipher.AES.MODE_ECB) or as a
# suffix on a constant name (e.g. AES_MODE_ECB in C bindings). Match
# both — drop the leading ``\b`` so trailing-suffix forms also catch.
_MODE_ECB_RE = re.compile(r"MODE_ECB\b|\b[Mm]odes\.ECB\b")
_LEGACY_IV_RE = re.compile(r"\blegacy_iv\b|\bstatic_iv\b|\bhardcoded_key\b")


def _module_chain(name: str | None) -> str:
    """Return the dotted module name or empty string."""
    return name or ""


def _import_starts_with(import_name: str, prefixes: tuple[str, ...]) -> bool:
    for p in prefixes:
        if import_name == p or import_name.startswith(p + "."):
            return True
    return False


def _walk_imports(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Return (sensitive_modules, maybe_modules) actually imported."""
    sensitive: set[str] = set()
    maybe: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = _module_chain(alias.name)
                if _import_starts_with(name, _CRYPTO_MODULE_PREFIXES):
                    sensitive.add(name)
                elif name in _CRYPTO_MAYBE_MODULES:
                    maybe.add(name)
        elif isinstance(node, ast.ImportFrom):
            mod = _module_chain(node.module)
            if _import_starts_with(mod, _CRYPTO_MODULE_PREFIXES):
                sensitive.add(mod)
            elif mod in _CRYPTO_MAYBE_MODULES:
                maybe.add(mod)
    return sensitive, maybe


def _walk_misuse_names(tree: ast.AST) -> set[str]:
    """Find identifiers whose name contains a misuse fragment."""
    hits: set[str] = set()
    for node in ast.walk(tree):
        # Variable / attribute names
        if isinstance(node, ast.Name):
            for frag in _MISUSE_NAME_FRAGMENTS:
                if frag in node.id.lower():
                    hits.add(node.id)
        elif isinstance(node, ast.arg):
            for frag in _MISUSE_NAME_FRAGMENTS:
                if frag in node.arg.lower():
                    hits.add(node.arg)
        elif isinstance(node, ast.Attribute):
            for frag in _MISUSE_NAME_FRAGMENTS:
                if frag in node.attr.lower():
                    hits.add(node.attr)
    return hits


def _walk_hardcoded_crypto_material(tree: ast.AST) -> list[str]:
    """Find ``key = b"..."``-style assignments where the value's length
    is an AES key/IV anchor and the target name is in the sensitive set.
    Returns descriptive strings for telemetry.
    """
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Constant):
            continue
        v = node.value.value
        if not isinstance(v, (bytes, str)) or len(v) not in _AES_BYTE_LENGTHS:
            continue
        for target in node.targets:
            tnames = _target_names(target)
            for tn in tnames:
                if tn.lower() in _SENSITIVE_VAR_NAMES:
                    hits.append(f"hardcoded_{tn.lower()}_{len(v)}b")
    return hits


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Tuple):
        out: list[str] = []
        for el in target.elts:
            out.extend(_target_names(el))
        return out
    if isinstance(target, ast.Attribute):
        return [target.attr]
    return []


def _content_scan(content: str) -> list[str]:
    """Regex backstop for non-Python or AST-failing inputs."""
    hits: list[str] = []
    if _MODE_ECB_RE.search(content):
        hits.append("MODE_ECB")
    if _LEGACY_IV_RE.search(content):
        hits.append("legacy_iv_pattern")
    return hits


def analyze_python_module(content: str) -> CryptoSensitivitySignal:
    """Detect crypto-sensitive imports + misuse markers in a Python module.

    Returns ``CryptoSensitivitySignal(detected=True, reasons=...)`` when
    EITHER:
      * any import lands inside ``_CRYPTO_MODULE_PREFIXES`` (high-blast-
        radius crypto packages — promote unconditionally), OR
      * a misuse-name identifier or hardcoded-crypto-material assignment
        is present, OR
      * a ``hashlib`` / ``hmac`` import combined with a misuse-name
        identifier is present.

    The reasons list always includes a stable, machine-readable token per
    finding (e.g. ``"import:cryptography.hazmat.primitives.ciphers"``,
    ``"misuse_name:legacy_iv_mode"``, ``"hardcoded_key_32b"``,
    ``"MODE_ECB"``).
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        # Fall back to regex backstop — we can still catch literal
        # ``MODE_ECB`` mentions in partial files / docstrings.
        backstop = _content_scan(content)
        return CryptoSensitivitySignal(
            detected=bool(backstop),
            reasons=sorted(backstop),
        )

    sensitive_imports, maybe_imports = _walk_imports(tree)
    misuse_names = _walk_misuse_names(tree)
    hardcoded = _walk_hardcoded_crypto_material(tree)
    content_hits = _content_scan(content)

    reasons: list[str] = []
    reasons.extend(f"import:{m}" for m in sorted(sensitive_imports))
    reasons.extend(f"misuse_name:{n}" for n in sorted(misuse_names))
    reasons.extend(sorted(hardcoded))
    reasons.extend(sorted(content_hits))
    if maybe_imports and (misuse_names or hardcoded or content_hits):
        # ``hashlib``/``hmac`` only counts when paired with misuse markers.
        reasons.extend(f"import:{m}" for m in sorted(maybe_imports))

    detected = bool(sensitive_imports or misuse_names or hardcoded or content_hits)
    return CryptoSensitivitySignal(detected=detected, reasons=sorted(set(reasons)))


def analyze_file(content: str, language: str | None) -> CryptoSensitivitySignal:
    """Public entry point. Routes Python files to the AST analyzer; uses
    the regex backstop for everything else.
    """
    if language and language.lower() == "python":
        return analyze_python_module(content)
    backstop = _content_scan(content)
    return CryptoSensitivitySignal(
        detected=bool(backstop),
        reasons=sorted(backstop),
    )
