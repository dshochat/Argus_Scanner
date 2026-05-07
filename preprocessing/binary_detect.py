"""Binary / empty-file detection — PREP-010.

Determines whether a raw file should skip model stages because it either
has no content worth analyzing or is a binary blob the SLM stack can't
reason about. Ported from the legacy ``app/scanner/backend/scan_engine.py``
``should_scan`` heuristic, with the preservation principle intact: we
still emit the preprocessing block (hash + size + tier) so downstream
consumers know the file existed.

Thresholds match the legacy app implementation byte-for-byte:
  * **Empty**: file size == 0, OR decoded content is whitespace-only.
  * **Binary**: any NUL byte in the first 1000 bytes, OR non-printable
    (``ord < 32`` excluding ``\\n \\r \\t``) ratio in the first 1000 bytes
    is greater than 30 %.

Sampling is done on the first 1000 raw bytes — not the whole file — to
keep this O(1) per file regardless of size. Legitimate source code never
has NULs; mis-labeled extensions on binary blobs (``.py`` that's actually
a pickled payload) are the main target.
"""

from __future__ import annotations

from dataclasses import dataclass

# Legacy constants from ``app/scanner/backend/scan_engine.py:212``. DO NOT
# drift — keeping these in sync means inference-time skip decisions match
# labeling-time skip decisions and the fine-tuned model never sees a
# distribution of inputs that production would have filtered out.
_SAMPLE_BYTES = 1000
_NON_PRINTABLE_RATIO_MAX = 0.30
_PRINTABLE_WHITELIST = (0x09, 0x0A, 0x0D)  # tab, LF, CR


@dataclass(frozen=True)
class BinaryEmptyVerdict:
    """Result of the binary / empty probe.

    ``skip_reason`` is the value written onto ``Preprocessing.skip_reason``
    when ``should_skip`` is true — either ``"empty"`` or ``"binary"``.
    ``None`` when the file should flow through the normal pipeline.
    """

    should_skip: bool
    skip_reason: str | None = None


def classify_binary_or_empty(content: bytes) -> BinaryEmptyVerdict:
    """Return a verdict describing whether ``content`` should skip model stages."""
    if len(content) == 0:
        return BinaryEmptyVerdict(should_skip=True, skip_reason="empty")

    # Whitespace-only files match the legacy ``not content.strip()`` branch.
    if not content.strip():
        return BinaryEmptyVerdict(should_skip=True, skip_reason="empty")

    sample = content[:_SAMPLE_BYTES]

    if b"\x00" in sample:
        return BinaryEmptyVerdict(should_skip=True, skip_reason="binary")

    non_printable = sum(1 for b in sample if b < 0x20 and b not in _PRINTABLE_WHITELIST)
    if non_printable / len(sample) > _NON_PRINTABLE_RATIO_MAX:
        return BinaryEmptyVerdict(should_skip=True, skip_reason="binary")

    return BinaryEmptyVerdict(should_skip=False, skip_reason=None)
