from __future__ import annotations

from preprocessing.binary_detect import classify_binary_or_empty


def test_classify_empty_bytes_returns_empty() -> None:
    verdict = classify_binary_or_empty(b"")
    assert verdict.should_skip is True
    assert verdict.skip_reason == "empty"


def test_classify_whitespace_only_returns_empty() -> None:
    verdict = classify_binary_or_empty(b"   \n\n\t  \r\n  ")
    assert verdict.should_skip is True
    assert verdict.skip_reason == "empty"


def test_classify_plain_python_not_flagged() -> None:
    verdict = classify_binary_or_empty(b"def add(x, y):\n    return x + y\n")
    assert verdict.should_skip is False
    assert verdict.skip_reason is None


def test_classify_nul_byte_in_sample_flags_binary() -> None:
    # NUL in the first 1000 bytes must trip the binary gate.
    verdict = classify_binary_or_empty(b"hello\x00world" + b"x" * 100)
    assert verdict.should_skip is True
    assert verdict.skip_reason == "binary"


def test_classify_nul_byte_outside_sample_not_flagged() -> None:
    # Legacy behavior: sampling is first 1000 bytes only, NULs past that
    # are not the pre-pass's job to catch.
    content = b"A" * 1200 + b"\x00"
    verdict = classify_binary_or_empty(content)
    assert verdict.should_skip is False


def test_classify_high_non_printable_ratio_flags_binary() -> None:
    # 40% non-printable bytes exceeds the 30% threshold.
    content = bytes([0x01] * 40) + b"A" * 60
    verdict = classify_binary_or_empty(content)
    assert verdict.should_skip is True
    assert verdict.skip_reason == "binary"


def test_classify_low_non_printable_ratio_passes() -> None:
    # 10% non-printable — legitimate source with a few control chars.
    content = bytes([0x01] * 10) + b"A" * 90
    verdict = classify_binary_or_empty(content)
    assert verdict.should_skip is False


def test_classify_allows_tab_lf_cr() -> None:
    # TAB/LF/CR should not count as non-printable per legacy whitelist.
    # Mix them with printable text so the "empty" branch doesn't fire —
    # the point of this test is the non-printable ratio, not the strip check.
    content = b"def f():\n\treturn 1\r\n" * 30
    verdict = classify_binary_or_empty(content)
    assert verdict.should_skip is False


def test_classify_utf8_source_passes() -> None:
    # Multi-byte UTF-8 chars have high bytes but no NULs and are all >=0x20.
    content = "def greet():\n    return 'héllo wörld'\n".encode()
    verdict = classify_binary_or_empty(content)
    assert verdict.should_skip is False


def test_classify_utf16_with_nul_bytes_flags_binary() -> None:
    # UTF-16LE emits a NUL byte per ASCII character — exactly the kind
    # of false-extension blob we want to skip.
    content = "def main(): pass".encode("utf-16-le")
    verdict = classify_binary_or_empty(content)
    assert verdict.should_skip is True
    assert verdict.skip_reason == "binary"


def test_classify_ratio_uses_sample_not_whole_file() -> None:
    # Pure binary prefix in the first 1000 bytes flags regardless of
    # any clean tail past the sample.
    content = bytes([0x01] * 400) + b"x" * 50_000
    verdict = classify_binary_or_empty(content)
    assert verdict.should_skip is True
    assert verdict.skip_reason == "binary"
