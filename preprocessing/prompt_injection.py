"""Deterministic prompt-injection pattern detection.

Ports the pre-triage heuristics from ``app/saas/ai_tool_scanner.py``
into the scanner's pre-pass layer. These checks emit **guaranteed
indicators** that do not depend on L1 pattern-matching — L1 still sees
the same content and can calibrate severity / add narrative, but the
deterministic match itself is recorded in the preprocessing block per
the preservation principle.

Three pattern classes:

1. **Zero-width characters** (`U+200B`, `U+200C`, `U+200D`, `U+FEFF`) —
   steganographic channels used to hide instructions from human readers
   while remaining present in the rendered text the model reads.
2. **Hidden-instruction regex patterns** — "ignore previous
   instructions", identity-override ("you are now …"), secrecy directives
   ("do not mention / reveal / disclose"), exfiltration directives,
   HTML-comment-wrapped overrides.
3. **Encoded-suspicious-keywords** — base64 blobs ≥ 40 chars whose
   decoded plaintext contains any of the canonical adversarial keyword
   set (``exec``, ``eval``, ``subprocess``, ``os.system``, ``curl``,
   ``wget``, ``exfiltrate``, etc.).

All matches produce a ``PromptInjectionIndicator`` entry. This module
has zero side effects and performs no LLM calls; runtime is O(n) over
file size with a small regex constant plus the per-blob base64 decode
work capped by ``_MAX_B64_BLOB_SCANS``.

PR #18 review hardening:

* ``exfiltration_directive`` regex rewritten without lazy bounded
  quantifiers to remove ReDoS risk on adversarial input.
* ``html_comment_override`` uses a tempered pattern so comments
  containing a ``>`` inside don't prematurely close the match and
  evade detection.
* ``identity_override`` tightened with a role-noun anchor to cut
  prose false-positives like ``"You are now ready to deploy"``.
* ``base64`` blob scanning capped at ``_MAX_B64_BLOB_SCANS`` to
  prevent pathologically slow files with many legitimate blobs
  (PEM chains, JWT tokens, etc.) from exhausting CPU.
* ``_detect_hidden_instructions`` uses ``finditer`` with a per-
  pattern cap so multiple matches of the same class surface
  symmetrically to the zero-width detector.
* ``__post_decode`` label suffix bounded against
  ``pattern_label``'s max_length=80 so future longer labels can't
  crash the Pydantic validator.
"""

from __future__ import annotations

import base64
import binascii
import re

from shared.types.enums import Severity
from shared.types.preprocessing import (
    PromptInjectionIndicator,
    PromptInjectionPatternType,
)

# ── Module-level safety constants ────────────────────────────────────────

#: Per-pattern match cap. ``finditer`` stops after this many matches of
#: the same pattern in one document — prevents one adversarial
#: repetition from blowing up memory or output size.
_MAX_MATCHES_PER_PATTERN = 20

#: Per-scan cap on base64 blob processing. A file dominated by
#: legitimate long base64 strings (PEM chains, JWTs) could trigger
#: thousands of base64 decodes; cap at this count and emit a
#: "scan_capped" indicator so downstream knows the pass was partial.
_MAX_B64_BLOB_SCANS = 50

#: ``PromptInjectionIndicator.pattern_label`` carries ``max_length=80``
#: (see ``shared/types/preprocessing.py``). The ``__post_decode``
#: suffix is 13 chars; we cap the resulting string at the model's
#: max_length to prevent runtime ValidationError if a future label is
#: wider than 67 chars.
_PATTERN_LABEL_MAX = 80


# ── Zero-width / bidi-like invisibles ─────────────────────────────────────
_ZERO_WIDTH_CHARS: dict[str, str] = {
    "\u200b": "U+200B ZERO WIDTH SPACE",
    "\u200c": "U+200C ZERO WIDTH NON-JOINER",
    "\u200d": "U+200D ZERO WIDTH JOINER",
    "\ufeff": "U+FEFF ZERO WIDTH NO-BREAK SPACE / BOM",
}


# ── Hidden-instruction regex patterns ─────────────────────────────────────
# Each entry: (compiled_pattern, severity, short_label)
# Patterns port from ``app/saas/ai_tool_scanner.py:_check_hidden_instructions``
# with PR #18 review hardening applied — see module docstring for specifics.
# Known-over-firing patterns (sudo/root/admin bare matches) are NOT included —
# they produce too many false positives outside the AI-file context the prod
# scanner originally ran them on. Add a file-type-gated variant if needed.
_HIDDEN_INSTRUCTION_PATTERNS: list[tuple[re.Pattern[str], Severity, str]] = [
    (
        re.compile(
            r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules|prompts|directives)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "ignore_previous_instructions",
    ),
    (
        # PR #18 review: bare ``\byou\s+are\s+now\b`` false-positived on
        # prose like "You are now ready to deploy". Tightened with a
        # role/identity-noun anchor — matches only identity-override
        # attempts ("you are now a different AI", "you are now DAN",
        # "you are now unrestricted", etc.), not prose transitions.
        re.compile(
            r"\byou\s+are\s+now"
            r"(?:\s+(?:a|an|the))?"
            r"\s+(?:bot|assistant|chatbot|expert|admin|administrator"
            r"|unrestricted|uncensored|jailbroken|DAN|GPT|AI\b|SYSTEM"
            r"|root|different\s+AI|new\s+model)\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "identity_override",
    ),
    (
        re.compile(
            r"\bdo\s+not\s+(?:mention|reveal|tell|disclose|share|leak)\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "secrecy_directive",
    ),
    (
        # PR #18 review: original used lazy bounded ``\s+ + [^\n]{0,50}?``
        # combined with a long alternation, producing O(n²) backtracking
        # on crafted input (``"send " + "x" * 10000``). Rewritten with
        # greedy-bounded ``\S{0,60}`` separator — no lazy ambiguity, no
        # catastrophic backtrack path. Behaviour approximately equivalent
        # on real directives (gap between verb and object is typically
        # whitespace + a short noun phrase ≤ 60 chars).
        re.compile(
            r"(?:exfiltrate|leak|send|post|upload)"
            r"\s+\S{0,60}\s*"
            r"(?:data|secret|secrets|key|keys|token|tokens|password|passwords|credential|credentials)\b",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "exfiltration_directive",
    ),
    (
        # PR #18 review: original ``<!--[^>]*?(?:ignore|...)[^>]*?-->``
        # stops at the first ``>`` inside the comment, so
        # ``<!-- see https://evil.com/ignore -->`` evaded detection.
        # Tempered token ``(?:(?!-->).)*?`` + ``re.DOTALL`` matches any
        # char except the close-marker sequence, so embedded ``>`` is
        # tolerated.
        re.compile(
            r"<!--(?:(?!-->).)*?"
            r"(?:ignore|override|system|inject)"
            r"(?:(?!-->).)*?-->",
            re.IGNORECASE | re.DOTALL,
        ),
        Severity.HIGH,
        "html_comment_override",
    ),
]


# ── Encoded suspicious keywords (post base64 decode) ─────────────────────
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_SUSPICIOUS_KEYWORDS = (
    "ignore",
    "override",
    "you are now",
    "exec(",
    "eval(",
    "subprocess",
    "os.system",
    "curl ",
    "wget ",
    "exfiltrate",
    "send to",
    "hidden instruction",
)


def _line_for_offset(content: str, offset: int) -> int:
    """1-indexed line number containing ``offset`` in ``content``."""
    return content.count("\n", 0, offset) + 1


def _preview(text: str, limit: int = 120) -> str:
    """Single-line, length-capped preview for the match-context field."""
    collapsed = " ".join(text.split())
    if len(collapsed) > limit:
        return collapsed[: limit - 1] + "…"
    return collapsed


def _post_decode_label(base_label: str) -> str:
    """Bounded label for post-decode indicators.

    ``PromptInjectionIndicator.pattern_label`` has ``max_length=80``.
    Suffixing the base label with ``__post_decode`` could exceed the
    cap for any base >67 chars. Truncating the combined string keeps
    Pydantic validation happy without losing attribution (the
    ``__post_decode`` suffix always survives since it's at the end
    post-truncation).
    """
    return f"{base_label}__post_decode"[:_PATTERN_LABEL_MAX]


def _detect_zero_width(content: str) -> list[PromptInjectionIndicator]:
    """Emit one indicator per distinct zero-width char class present.

    Zero-width codepoints (``U+200B``, ``U+200C``, ``U+200D``,
    ``U+FEFF``) are invisible to humans reading rendered text but
    remain in the byte stream the model sees — a classic
    steganographic channel for hidden instructions. One indicator per
    class (not per occurrence); further analysis is L1's job.
    """
    indicators: list[PromptInjectionIndicator] = []
    for ch, label in _ZERO_WIDTH_CHARS.items():
        idx = content.find(ch)
        if idx < 0:
            continue
        line_num = _line_for_offset(content, idx)
        surrounding = content[max(0, idx - 40) : idx + 40]
        indicators.append(
            PromptInjectionIndicator(
                pattern_type=PromptInjectionPatternType.ZERO_WIDTH_CHAR,
                pattern_label=label,
                match_preview=_preview(surrounding),
                line=line_num,
                severity=Severity.MEDIUM,
            )
        )
    return indicators


def _detect_hidden_instructions(content: str) -> list[PromptInjectionIndicator]:
    """Emit indicators for each hidden-instruction pattern match.

    Iterates each entry in ``_HIDDEN_INSTRUCTION_PATTERNS`` across the
    full document. Uses ``finditer`` + ``_MAX_MATCHES_PER_PATTERN`` so
    repeated matches of the same pattern surface (up to the cap)
    instead of silently dropping all but the first (PR #18 review
    warning). Consistent with the zero-width detector, which reports
    all occurrences.
    """
    indicators: list[PromptInjectionIndicator] = []
    for pattern, severity, label in _HIDDEN_INSTRUCTION_PATTERNS:
        for i, m in enumerate(pattern.finditer(content)):
            if i >= _MAX_MATCHES_PER_PATTERN:
                break
            line_num = _line_for_offset(content, m.start())
            indicators.append(
                PromptInjectionIndicator(
                    pattern_type=PromptInjectionPatternType.HIDDEN_INSTRUCTION,
                    pattern_label=label,
                    match_preview=_preview(m.group(0)),
                    line=line_num,
                    severity=severity,
                )
            )
    return indicators


def _decoded_contains_suspicious(blob: str) -> tuple[bool, str | None]:
    """Return (True, decoded_preview) if base64 ``blob`` decodes to text
    containing any suspicious keyword; ``(False, None)`` otherwise."""
    try:
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except (binascii.Error, ValueError):
        return False, None
    try:
        text = decoded.decode("utf-8", errors="replace").lower()
    except (UnicodeDecodeError, AttributeError):
        # AttributeError covers the .lower() path on exotic subclasses;
        # both are "decode produced something unusable" → decline.
        return False, None
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in text:
            return True, text[:200]
    return False, None


def _detect_encoded_keywords(content: str) -> list[PromptInjectionIndicator]:
    """Emit indicators for base64 blobs that decode to suspicious keywords.

    Caps the scan at ``_MAX_B64_BLOB_SCANS`` per file (PR #18 review
    warning). A file dominated by legitimate long base64 (PEM key
    chains, JWT-heavy configs) would otherwise trigger thousands of
    b64 decodes and push CPU. When the cap is reached, a single
    indicator with ``pattern_label="scan_capped"`` is appended so the
    pass is visible as partial; further blobs are not scanned.
    """
    indicators: list[PromptInjectionIndicator] = []
    seen_previews: set[str] = set()
    scans = 0
    for m in _B64_BLOB.finditer(content):
        scans += 1
        if scans > _MAX_B64_BLOB_SCANS:
            indicators.append(
                PromptInjectionIndicator(
                    pattern_type=PromptInjectionPatternType.ENCODED_SUSPICIOUS_KEYWORD,
                    pattern_label="scan_capped",
                    match_preview=(f"base64 blob scan capped at {_MAX_B64_BLOB_SCANS}; further blobs not analysed"),
                    line=_line_for_offset(content, m.start()),
                    severity=Severity.LOW,
                )
            )
            break
        blob = m.group(0)
        hit, preview = _decoded_contains_suspicious(blob)
        if not hit or preview is None or preview in seen_previews:
            continue
        seen_previews.add(preview)
        line_num = _line_for_offset(content, m.start())
        indicators.append(
            PromptInjectionIndicator(
                pattern_type=PromptInjectionPatternType.ENCODED_SUSPICIOUS_KEYWORD,
                pattern_label="base64_encoded_suspicious_keyword",
                match_preview=_preview(preview),
                line=line_num,
                severity=Severity.HIGH,
            )
        )
    return indicators


def detect_prompt_injection(content: str, *, decoded_content: str | None = None) -> list[PromptInjectionIndicator]:
    """Run all three pattern classes against ``content`` (and optionally
    against deobfuscated ``decoded_content`` too, for hidden-instruction
    patterns that may appear only after the pre-pass peels encoding).

    Returns a list of indicators. Empty list when nothing matches.
    """
    indicators: list[PromptInjectionIndicator] = []
    indicators.extend(_detect_zero_width(content))
    indicators.extend(_detect_hidden_instructions(content))
    indicators.extend(_detect_encoded_keywords(content))
    if decoded_content and decoded_content != content:
        # Run the hidden-instruction check on decoded content too — an
        # adversarial payload may have lived inside a base64 blob that
        # the deobfuscation pre-pass has since unwrapped.
        for ind in _detect_hidden_instructions(decoded_content):
            # Tag these as found-after-decode so orchestrator can present
            # them clearly. Label bounded to the Pydantic field's
            # max_length so long base labels don't trigger
            # ValidationError (PR #18 review blocker).
            indicators.append(
                PromptInjectionIndicator(
                    pattern_type=ind.pattern_type,
                    pattern_label=_post_decode_label(ind.pattern_label),
                    match_preview=ind.match_preview,
                    line=None,  # line numbers don't correspond after decode
                    severity=ind.severity,
                )
            )
    return indicators
