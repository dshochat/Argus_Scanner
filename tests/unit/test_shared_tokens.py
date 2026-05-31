"""Tests for shared.utils.tokens.

The token helper is on the hot path of every scan — every file's
preprocessing calls ``approx_token_count``. A regression here breaks
the entire pipeline silently.
"""

from __future__ import annotations

import pytest

from shared.utils.tokens import approx_token_count


def test_approx_token_count_basic_ascii() -> None:
    """Token count is non-zero and reasonable for typical source code."""
    text = "def hello():\n    return 'world'\n"
    n = approx_token_count(text)
    assert n > 0
    assert n < 100  # short snippet shouldn't tokenize to hundreds


def test_approx_token_count_empty() -> None:
    """Empty input returns a positive minimum (avoids div-by-zero in
    downstream code that divides by token count)."""
    n = approx_token_count("")
    assert n >= 0


def test_approx_token_count_endoftext_literal_v1528() -> None:
    """v15.28 regression guard: source files containing the literal
    ``<|endoftext|>`` string (e.g., openai-python's
    ``resources/completions.py`` documents this special token in API
    reference comments) must NOT raise tiktoken's ValueError. Before
    the v15.28 fix, ``enc.encode(text)`` would raise:
        ``Encountered text corresponding to disallowed special token``
    and the entire preprocessing stage would fail with status=500.
    """
    text = (
        "def make_completion(prompt: str, stop=None):\n"
        '    """The model treats "<|endoftext|>" as a sentinel...\n"""\n'
        "    return openai.Completion.create(prompt=prompt, stop=stop)\n"
    )
    # Must not raise.
    n = approx_token_count(text)
    assert n > 0


def test_approx_token_count_handles_all_special_tokens_v1528() -> None:
    """Belt-and-suspenders: any of the common cl100k_base special
    token strings should also be treated as plain text, not raise."""
    for special in (
        "<|endoftext|>",
        "<|fim_prefix|>",
        "<|fim_middle|>",
        "<|fim_suffix|>",
        "<|endofprompt|>",
        "<|im_start|>",
        "<|im_end|>",
    ):
        text = f"# documentation mentions {special} here\n"
        n = approx_token_count(text)
        assert n > 0, f"failed for special: {special!r}"


def test_approx_token_count_fallback_when_tiktoken_missing(monkeypatch) -> None:
    """When tiktoken isn't available, char/4 heuristic kicks in."""
    import shared.utils.tokens as tokens_mod

    # Force the encoder cache to return None
    tokens_mod._encoder.cache_clear()
    monkeypatch.setattr(tokens_mod, "tiktoken", None)
    text = "x" * 40
    n = approx_token_count(text)
    # char/4 = 10
    assert n == 10
    # Reset cache so other tests get a fresh encoder
    tokens_mod._encoder.cache_clear()
