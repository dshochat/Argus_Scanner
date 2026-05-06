"""Token counting helper.

S1 reads the first 2048 tokens; S2/S3/S4/L1 cap input at ~8K. Every pipeline
stage needs a cheap, consistent token estimator. We prefer tiktoken when
available and fall back to a char/4 heuristic for environments where it
isn't installed (e.g., air-gapped builds during initial bringup).
"""

from __future__ import annotations

from functools import lru_cache

try:
    import tiktoken  # type: ignore[import-not-found]
except ImportError:
    tiktoken = None  # type: ignore[assignment]


@lru_cache(maxsize=4)
def _encoder(model: str = "cl100k_base"):  # type: ignore[no-untyped-def]
    if tiktoken is None:
        return None
    try:
        return tiktoken.get_encoding(model)
    except Exception:  # unknown encoding → fall back
        return None


def approx_token_count(text: str, model: str = "cl100k_base") -> int:
    """Best-effort token count. Uses tiktoken when available, char/4 otherwise."""
    enc = _encoder(model)
    if enc is None:
        return max(1, len(text) // 4)
    return len(enc.encode(text))
