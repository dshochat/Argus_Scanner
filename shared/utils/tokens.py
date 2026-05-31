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
    """Best-effort token count. Uses tiktoken when available, char/4 otherwise.

    v15.28 (2026-05-21): pass ``disallowed_special=()`` to tiktoken's
    encode() so the encoder doesn't raise on source files that
    legitimately contain literal special-token strings like
    ``<|endoftext|>`` (e.g., openai-python's resources/completions.py
    documents these tokens in user-facing API reference comments).
    Without this guard, tiktoken raises ValueError and the entire
    preprocessing stage fails — the file gets a degenerate "status: 500"
    result with no triage, L1, or DAST. Treating special tokens as
    plain text is the right call for token-counting: the count for a
    file that happens to mention ``<|endoftext|>`` should reflect
    real document length, not refuse to count.
    """
    enc = _encoder(model)
    if enc is None:
        return max(1, len(text) // 4)
    return len(enc.encode(text, disallowed_special=()))
