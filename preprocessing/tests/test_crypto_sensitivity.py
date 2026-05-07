"""Tests for ``preprocessing.crypto_sensitivity`` — PREP-020.

Covers:
  * Crypto-sensitive imports trigger detection (high-blast-radius
    packages: cryptography.hazmat, Crypto, Cryptodome, OpenSSL, nacl,
    passlib.hash)
  * ``hashlib`` / ``hmac`` alone do NOT trigger (legitimate checksum use)
  * ``hashlib`` + misuse marker DOES trigger
  * Misuse-name identifiers (legacy_iv, static_iv, hardcoded_key) trigger
    on their own
  * Hardcoded crypto material (16/24/32-byte literals assigned to
    sensitive names) triggers
  * MODE_ECB content marker triggers via regex backstop
  * Non-Python files fall through to regex backstop
  * Syntax-error files fall through to regex backstop
  * Clean files (just hashlib for SHA-256 file checksumming) don't fire
  * The actual ``tpm_symmetric_cipher.py`` fixture fires
"""

from __future__ import annotations

from pathlib import Path

import pytest

from preprocessing.crypto_sensitivity import (
    analyze_file,
    analyze_python_module,
)

# ---------------------------------------------------------------------------
# Sensitive imports — fire on import alone
# ---------------------------------------------------------------------------


def test_cryptography_hazmat_import_fires() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher\n"
        "from cryptography.hazmat.backends import default_backend\n"
    )
    sig = analyze_python_module(src)
    assert sig.detected is True
    # Both imports are nested under cryptography.hazmat
    assert any(r.startswith("import:cryptography.hazmat") for r in sig.reasons)


def test_pycryptodome_import_fires() -> None:
    src = "from Cryptodome.Cipher import AES\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert "import:Cryptodome.Cipher" in sig.reasons


def test_pycrypto_import_fires() -> None:
    src = "from Crypto.Cipher import AES\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert "import:Crypto.Cipher" in sig.reasons


def test_pyopenssl_import_fires() -> None:
    src = "from OpenSSL import crypto\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert "import:OpenSSL" in sig.reasons


def test_pynacl_import_fires() -> None:
    src = "import nacl.secret\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert "import:nacl.secret" in sig.reasons


def test_passlib_hash_import_fires() -> None:
    src = "from passlib.hash import md5_crypt\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert any(r.startswith("import:passlib.hash") for r in sig.reasons)


# ---------------------------------------------------------------------------
# hashlib/hmac — only fire WITH misuse markers
# ---------------------------------------------------------------------------


def test_hashlib_alone_does_not_fire() -> None:
    """Legitimate use of hashlib for file checksumming."""
    src = (
        "import hashlib\n"
        "def file_sha256(path):\n"
        "    sha = hashlib.sha256()\n"
        "    with open(path, 'rb') as fh:\n"
        "        for chunk in iter(lambda: fh.read(4096), b''):\n"
        "            sha.update(chunk)\n"
        "    return sha.hexdigest()\n"
    )
    sig = analyze_python_module(src)
    assert sig.detected is False
    assert sig.reasons == []


def test_hmac_alone_does_not_fire() -> None:
    src = "import hmac\nh = hmac.new(b'key', b'data', 'sha256').digest()\n"
    sig = analyze_python_module(src)
    assert sig.detected is False


def test_hashlib_plus_misuse_name_fires() -> None:
    src = "import hashlib\ndef derive(legacy_iv_mode):\n    return hashlib.md5(legacy_iv_mode).digest()\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    # both the misuse name AND the hashlib import should be reported
    assert any("misuse_name:legacy_iv" in r for r in sig.reasons)
    assert "import:hashlib" in sig.reasons


# ---------------------------------------------------------------------------
# Misuse-name identifiers
# ---------------------------------------------------------------------------


def test_legacy_iv_identifier_fires() -> None:
    src = "def encrypt(legacy_iv_mode, plaintext):\n    return plaintext\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert any("misuse_name:legacy_iv" in r for r in sig.reasons)


def test_static_iv_identifier_fires() -> None:
    src = "static_iv = b'some bytes here'\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert any("misuse_name:static_iv" in r for r in sig.reasons)


def test_hardcoded_key_identifier_fires() -> None:
    src = "hardcoded_key = b'1234567890abcdef'\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    # both the misuse name AND the hardcoded literal should be reported
    assert any("misuse_name:hardcoded_key" in r for r in sig.reasons)


# ---------------------------------------------------------------------------
# Hardcoded crypto material
# ---------------------------------------------------------------------------


def test_hardcoded_aes_key_16b_fires() -> None:
    src = 'key = b"abcdef0123456789"\n'  # 16 bytes
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert "hardcoded_key_16b" in sig.reasons


def test_hardcoded_aes_key_32b_fires() -> None:
    src = 'key = b"' + "a" * 32 + '"\n'  # 32 bytes
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert "hardcoded_key_32b" in sig.reasons


def test_hardcoded_iv_16b_fires() -> None:
    src = 'iv = b"abcdef0123456789"\n'
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert "hardcoded_iv_16b" in sig.reasons


def test_hardcoded_short_value_does_not_fire() -> None:
    src = 'key = b"short"\n'
    sig = analyze_python_module(src)
    assert sig.detected is False


def test_hardcoded_unrelated_var_does_not_fire() -> None:
    """A 16-byte value assigned to an unrelated name doesn't fire."""
    src = 'magic_header = b"abcdef0123456789"\n'
    sig = analyze_python_module(src)
    assert sig.detected is False


# ---------------------------------------------------------------------------
# Content-marker regex backstop
# ---------------------------------------------------------------------------


def test_mode_ecb_marker_fires() -> None:
    src = "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_ECB)\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    # MODE_ECB content marker should appear alongside the import reason
    assert "MODE_ECB" in sig.reasons


def test_modes_ecb_attribute_fires() -> None:
    """``modes.ECB(...)`` form (cryptography hazmat) also matches."""
    src = "from cryptography.hazmat.primitives.ciphers import modes\nm = modes.ECB()\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert "MODE_ECB" in sig.reasons


# ---------------------------------------------------------------------------
# Fall-through paths
# ---------------------------------------------------------------------------


def test_syntax_error_falls_back_to_regex() -> None:
    """A file with a syntax error still gets a regex backstop scan."""
    src = "this is not python at all\nbut contains MODE_ECB somewhere\n"
    sig = analyze_python_module(src)
    assert sig.detected is True
    assert "MODE_ECB" in sig.reasons


def test_syntax_error_no_markers_does_not_fire() -> None:
    src = "this is not python at all\nsomething ordinary\n"
    sig = analyze_python_module(src)
    assert sig.detected is False


def test_analyze_file_routes_python_to_ast() -> None:
    src = "from cryptography.hazmat.primitives.ciphers import Cipher\n"
    sig = analyze_file(src, language="python")
    assert sig.detected is True


def test_analyze_file_non_python_uses_backstop() -> None:
    """A non-Python file with MODE_ECB in content still flags."""
    src = "/* C code */ AES_set_encrypt_key(); use AES_MODE_ECB;\n"
    sig = analyze_file(src, language="c")
    # Content backstop matches MODE_ECB substring
    assert sig.detected is True
    assert "MODE_ECB" in sig.reasons


def test_analyze_file_clean_python_does_not_fire() -> None:
    """A normal hashlib-checksum file routes through Python AST and
    correctly reports no detection."""
    src = "import hashlib\ndef sha(p):\n    return hashlib.sha256(p).hexdigest()\n"
    sig = analyze_file(src, language="python")
    assert sig.detected is False


# ---------------------------------------------------------------------------
# Real fixture — the campaign target file
# ---------------------------------------------------------------------------


def test_tpm_symmetric_cipher_fixture_fires() -> None:
    """The actual `tpm_symmetric_cipher.py` from the benchmark suite
    should fire (cryptography.hazmat imports + ``legacy_iv_mode``
    parameter + ``static_iv``-class identifiers)."""
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "fixtures"
        / "benchmark_v1_phase_c_supp"
        / "vulnerab__tpm_symmetric_cipher.py"
    )
    if not fixture_path.exists():
        pytest.skip(f"fixture not present: {fixture_path}")
    content = fixture_path.read_text(encoding="utf-8")
    sig = analyze_python_module(content)
    assert sig.detected is True, f"tpm_symmetric_cipher fixture should fire crypto-sensitivity; reasons={sig.reasons}"
    # Must include the cryptography.hazmat import signal
    assert any(r.startswith("import:cryptography.hazmat") for r in sig.reasons), (
        f"missing cryptography.hazmat in reasons={sig.reasons}"
    )
    # Must include the legacy_iv misuse-name signal
    assert any("misuse_name:legacy_iv" in r for r in sig.reasons), (
        f"missing legacy_iv misuse-name in reasons={sig.reasons}"
    )


def test_tenda_device_audit_fixture_does_not_fire() -> None:
    """``tenda_device_audit.py`` is a Tier 1 baseline=clean win. It
    imports only ``hashlib`` (for file checksumming) and ``crypt``
    (POSIX password helper, NOT in our high-blast-radius list). Forcing
    priority promotion here would risk breaking the tier-1 win — verify
    the detector does NOT fire on it.
    """
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "fixtures"
        / "benchmark_v1_phase_c_supp"
        / "vulnerab__tenda_device_audit.py"
    )
    if not fixture_path.exists():
        pytest.skip(f"fixture not present: {fixture_path}")
    content = fixture_path.read_text(encoding="utf-8")
    sig = analyze_python_module(content)
    assert sig.detected is False, (
        f"tenda_device_audit fixture should NOT fire (would risk "
        f"breaking tier-1 baseline=clean win); reasons={sig.reasons}"
    )
