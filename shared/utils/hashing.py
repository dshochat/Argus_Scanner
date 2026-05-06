"""Hashing helpers — file hashes, composite cache keys, pipeline fingerprint."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

CHUNK = 1 << 16


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def compute_pipeline_fingerprint_hash(fingerprint_components: dict[str, Any]) -> str:
    """Deterministic SHA-256 over every pipeline component version.

    Only components actually used for this file's scan depth should be passed
    — that's what makes granular invalidation work. Sort order matters.
    """
    canonical = json.dumps(fingerprint_components, sort_keys=True, separators=(",", ":"))
    return sha256_text(canonical)


def compute_cache_key(file_hash: str, pipeline_fingerprint_hash: str) -> str:
    """Tier 0 composite key: SHA-256(file_hash + pipeline_fingerprint_hash)."""
    return sha256_text(f"{file_hash}:{pipeline_fingerprint_hash}")
