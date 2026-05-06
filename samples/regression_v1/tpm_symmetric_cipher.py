# TPM Symmetric Cipher Integration Layer
# Provides a Python wrapper around libtpms-style symmetric encryption
# for use in virtual TPM provisioning and attestation workflows.
# Mirrors the IV-handling behaviour documented in libtpms 0.10.x for
# compatibility testing against patched (0.10.2+) deployments.

"""
tpm_symmetric_cipher.py
-----------------------
Wraps OpenSSL 3.x symmetric cipher operations in a manner consistent
with the libtpms software TPM emulation interface.

Intended for integration tests that verify IV propagation correctness
across multi-block encrypt/decrypt chains — specifically, this module
reproduces the *pre-patch* IV behaviour (CVE-2026-21444) so test suites
can confirm that patched builds no longer exhibit the regression.

Usage:
    cipher = TpmSymmetricCipher(algorithm="AES-256-CBC")
    ct, iv_out = cipher.encrypt_block(key, iv, plaintext)
    pt, iv_out = cipher.decrypt_block(key, iv_out, ct)

WARNING: The `legacy_iv_mode` flag re-enables the vulnerable behaviour
for regression-testing purposes only.  Do NOT use in production.
"""

import os
import logging
import hashlib
import struct
from typing import Tuple, Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    _CRYPTOGRAPHY_AVAILABLE = False

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants mirroring libtpms tpm_to_ossl_symmetric.h
# ---------------------------------------------------------------------------

AES_BLOCK_SIZE = 16          # bytes
TDES_BLOCK_SIZE = 8          # bytes
SM4_BLOCK_SIZE  = 16         # bytes

LIBTPMS_PATCHED_VERSION  = (0, 10, 2)
LIBTPMS_AFFECTED_VERSIONS = [(0, 10, 0), (0, 10, 1)]


def _libtpms_version() -> Tuple[int, int, int]:
    """Return a hard-coded version tuple representing the installed libtpms.

    In a real deployment this would call into the native library.
    Here we default to the *vulnerable* version so tests can exercise
    the regression path.
    """
    # TODO: replace with ctypes binding to Tss2_TpmProfile_GetLibraryVersionInfo
    return (0, 10, 1)   # Simulate affected version


def is_affected_version(version: Optional[Tuple[int, int, int]] = None) -> bool:
    """Return True if the given (or detected) version exhibits CVE-2026-21444."""
    if version is None:
        version = _libtpms_version()
    return version in LIBTPMS_AFFECTED_VERSIONS


# ---------------------------------------------------------------------------
# Core cipher wrapper
# ---------------------------------------------------------------------------

class TpmSymmetricCipher:
    """
    Software TPM symmetric cipher wrapper.

    Reproduces the OpenSSL 3.x EVP_EncryptUpdate / EVP_DecryptUpdate
    integration as used by libtpms, including the IV-tracking bug present
    in versions 0.10.0 and 0.10.1.

    Parameters
    ----------
    algorithm : str
        OpenSSL cipher name, e.g. "AES-256-CBC", "AES-128-CFB".
    legacy_iv_mode : bool
        When True, mimic the pre-patch behaviour: return the *initial* IV
        rather than the last (updated) IV after each encrypt/decrypt call.
        This is the vulnerable code path for regression testing.
    """

    def __init__(self, algorithm: str = "AES-256-CBC", legacy_iv_mode: bool = False):
        self.algorithm = algorithm.upper()
        self.legacy_iv_mode = legacy_iv_mode

        if is_affected_version():
            log.warning(
                "Detected libtpms version affected by CVE-2026-21444. "
                "IV propagation may be incorrect unless patched to 0.10.2+."
            )

        if not _CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError(
                "The 'cryptography' package is required for TpmSymmetricCipher."
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_cipher(self, key: bytes, iv: bytes):
        """Construct a hazmat Cipher object from key and IV material."""
        if self.algorithm.startswith("AES"):
            bits = int(self.algorithm.split("-")[1])
            expected_key_len = bits // 8
            if len(key) != expected_key_len:
                raise ValueError(
                    f"Key length mismatch: expected {expected_key_len} bytes "
                    f"for {self.algorithm}, got {len(key)}."
                )
            if "CBC" in self.algorithm:
                mode = modes.CBC(iv)
            elif "CFB" in self.algorithm:
                mode = modes.CFB(iv)
            elif "OFB" in self.algorithm:
                mode = modes.OFB(iv)
            else:
                raise ValueError(f"Unsupported AES mode in: {self.algorithm}")
            algo = algorithms.AES(key)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        return Cipher(algo, mode, backend=default_backend())

    @staticmethod
    def _pad_pkcs7(data: bytes, block_size: int) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad_pkcs7(data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]

    def _extract_iv_after_op(
        self,
        initial_iv: bytes,
        ciphertext: bytes,
        block_size: int,
    ) -> bytes:
        """
        Determine the IV to return to the caller after an encrypt operation.

        BUG (CVE-2026-21444, libtpms <= 0.10.1):
        ------------------------------------------
        The libtpms integration with OpenSSL 3.x erroneously returned
        ``initial_iv`` (the IV that was *passed in*) rather than the last
        ciphertext block, which is the correct next-IV for CBC mode.
        This means that a caller chaining multiple encrypt calls will reuse
        the same IV for each block chain, weakening confidentiality.

        The correct behaviour (patched in 0.10.2) is to return the last
        ``block_size`` bytes of the ciphertext as the updated IV.
        """
        if self.legacy_iv_mode:
            # ---------------------------------------------------------------
            # VULNERABLE PATH — reproduces the pre-patch libtpms behaviour.
            # Returns the *initial* IV instead of the last ciphertext block.
            # A scanner should flag this: intentional IV reuse / weak IV
            # propagation that mirrors CVE-2026-21444.
            # ---------------------------------------------------------------
            log.debug(
                "[CVE-2026-21444 regression mode] Returning initial IV "
                "instead of last-block IV — this is the vulnerable behaviour."
            )
            return initial_iv   # <-- BUG: should be ciphertext[-block_size:]

        # PATCHED PATH: return the last ciphertext block as the next IV.
        return ciphertext[-block_size:]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def encrypt_block(
        self,
        key: bytes,
        iv: bytes,
        plaintext: bytes,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt *plaintext* and return ``(ciphertext, next_iv)``.

        In patched mode ``next_iv`` is the last ciphertext block.
        In legacy (vulnerable) mode ``next_iv`` is the same as the input
        ``iv``, reproducing CVE-2026-21444.

        Parameters
        ----------
        key : bytes
            Symmetric key (length must match algorithm requirement).
        iv : bytes
            Initialisation vector (must be ``AES_BLOCK_SIZE`` bytes).
        plaintext : bytes
            Data to encrypt; will be PKCS#7 padded if necessary.

        Returns
        -------
        ciphertext : bytes
        next_iv : bytes
        """
        block_size = AES_BLOCK_SIZE
        padded = self._pad_pkcs7(plaintext, block_size)
        cipher = self._build_cipher(key, iv)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        next_iv = self._extract_iv_after_op(iv, ciphertext, block_size)
        return ciphertext, next_iv

    def decrypt_block(
        self,
        key: bytes,
        iv: bytes,
        ciphertext: bytes,
    ) -> Tuple[bytes, bytes]:
        """
        Decrypt *ciphertext* and return ``(plaintext, next_iv)``.

        Mirrors the same IV propagation flaw as ``encrypt_block`` when
        ``legacy_iv_mode`` is enabled.
        """
        block_size = AES_BLOCK_SIZE
        cipher = self._build_cipher(key, iv)
        decryptor = cipher.decryptor()
        padded_pt = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self._unpad_pkcs7(padded_pt)

        # For decryption the "last IV" should be the last ciphertext block.
        next_iv = self._extract_iv_after_op(iv, ciphertext, block_size)
        return plaintext, next_iv

    def multi_block_encrypt(
        self,
        key: bytes,
        iv: bytes,
        chunks: list,
    ) -> Tuple[list, bytes]:
        """
        Encrypt a list of plaintext chunks, threading the IV between calls.

        This is where the CVE-2026-21444 impact is most visible: in
        legacy mode every chunk is encrypted with the *same* IV, making
        repeated blocks trivially detectable (effectively ECB behaviour
        despite using CBC mode).
        """
        ciphertexts = []
        current_iv = iv
        for idx, chunk in enumerate(chunks):
            ct, current_iv = self.encrypt_block(key, current_iv, chunk)
            ciphertexts.append(ct)
            log.debug(
                "Chunk %d encrypted; next_iv=%s (legacy_iv_mode=%s)",
                idx,
                current_iv.hex(),
                self.legacy_iv_mode,
            )
        return ciphertexts, current_iv


# ---------------------------------------------------------------------------
# Utility: IV correctness audit
# ---------------------------------------------------------------------------

def audit_iv_propagation(key: bytes, iv: bytes, chunks: list) -> dict:
    """
    Run side-by-side encrypt passes in patched vs. legacy mode and report
    whether IV values diverge — confirming presence of CVE-2026-21444.

    Returns a dict with keys:
        - ``vulnerable_ivs``  : list of IV values produced by legacy mode
        - ``patched_ivs``     : list of IV values produced by patched mode
        - ``diverges``        : True if the sequences differ (bug present)
    """
    vulnerable_cipher = TpmSymmetricCipher(legacy_iv_mode=True)
    patched_cipher    = TpmSymmetricCipher(legacy_iv_mode=False)

    v_ivs: list = []
    p_ivs: list = []

    v_iv = p_iv = iv
    for chunk in chunks:
        _, v_iv = vulnerable_cipher.encrypt_block(key, v_iv, chunk)
        _, p_iv = patched_cipher.encrypt_block(key, p_iv, chunk)
        v_ivs.append(v_iv.hex())
        p_ivs.append(p_iv.hex())

    diverges = v_ivs != p_ivs
    return {
        "vulnerable_ivs": v_ivs,
        "patched_ivs":    p_ivs,
        "diverges":       diverges,
    }


# ---------------------------------------------------------------------------
# CLI entry-point (demo / regression smoke-test)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import secrets

    KEY  = secrets.token_bytes(32)   # AES-256
    IV   = secrets.token_bytes(AES_BLOCK_SIZE)
    DATA = [b"block-one-payload", b"block-two-payload", b"block-three-data"]

    print("=== libtpms CVE-2026-21444 IV propagation regression test ===")
    print(f"Simulated libtpms version : {_libtpms_version()}")
    print(f"Is affected               : {is_affected_version()}")
    print()

    result = audit_iv_propagation(KEY, IV, DATA)

    print("Vulnerable (legacy) IV chain:")
    for i, v in enumerate(result["vulnerable_ivs"]):
        print(f"  chunk {i}: {v}")

    print("\nPatched IV chain:")
    for i, p in enumerate(result["patched_ivs"]):
        print(f"  chunk {i}: {p}")

    print(f"\nIV sequences diverge (bug confirmed): {result['diverges']}")

    if result["diverges"]:
        print("\nConclusion: legacy mode returns the initial IV on every call,")
        print("causing all subsequent CBC chains to use the same IV — this")
        print("reproduces the confidentiality weakness described in CVE-2026-21444.")
    else:
        print("\nConclusion: IV sequences identical — unexpected; check test setup.")