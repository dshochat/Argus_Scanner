"""Cryptographic anti-patterns: hardcoded IV + MD5 password hashing."""

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-CBC using a fixed IV.

    VULNERABILITY: A static IV breaks AES-CBC's semantic security —
    identical plaintexts produce identical ciphertexts, leaking
    equality across messages.
    """
    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def hash_password(password: str) -> str:
    """Hash a password with MD5.

    VULNERABILITY: MD5 is fast and unsalted here, so an attacker with
    the hash can run a rainbow-table or GPU brute-force attack in
    minutes. Use a slow, salted KDF (argon2id, scrypt, bcrypt).
    """
    return hashlib.md5(password.encode()).hexdigest()
