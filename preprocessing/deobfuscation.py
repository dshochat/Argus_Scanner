"""Iterative deobfuscation — unwrap base64/hex/zlib/gzip/marshal/rot13/exec chains.

Deterministic. No models. Decoded content is what downstream models see.
Every successful layer is recorded by `ObfuscationTechnique` for the
schema's `obfuscation{}` block.

PREP-012 trigger discipline: the entry point is gated by
``_should_attempt_decode()``, ported byte-for-byte from
``data/labeling/deobfuscation/patterns.py`` so the fine-tuned models see
the same "decode vs. no-decode" classification at inference time that
they saw at labeling time. Plain base64 (JWTs, PEM keys, embedded
images, certificates, CI artifacts) no longer triggers decode — only
content paired with an explicit execution pattern
(``exec(base64.b64decode(…))``, ``marshal.loads(base64…)`` etc.) does.

Once the gate fires, iterative peeling proceeds as before: inner
layers can be bare base64 / hex / rot13 and will still be unwrapped,
mirroring labeling's nested-decode loop.

Safety: `marshal.loads` and decompression helpers are isolated to inert
bytes only — we never execute decoded code. `exec(...)` / `eval(...)`
chains are peeled by source-level regex, never evaluated.

ReDoS hardening (PR #24 review): both the outer body captures
(``_EXEC_WRAPPER`` / ``_DECOMPRESS_CALL`` / ``_MARSHAL_CALL``) and the
``_STR_LITERAL`` escape-chain pattern can backtrack catastrophically
on adversarial input. The fixes here are:

* Bound the ``_STR_LITERAL`` quantifiers so the backtrack space is
  linear in input length — each segment capped at 4096 chars, at most
  256 escape+segment pairs.
* Gate ``_peel_layer`` on ``_MAX_REGEX_INPUT`` — input over 64 KB
  short-circuits without running the vulnerable outer patterns. Real
  obfuscated payloads sit well under this; pathological attacker
  input skips the regex engine entirely.

Counting hardening (PR #24 review):

* ``failed_blob_count`` now reflects regex-match-then-decode-failure,
  not the permanent 0 the previous implementation set.
* The MARSHAL branch no longer bumps ``layers`` / ``decoded_blob_count``
  on unchanged content. Marshal is a detected-but-not-decoded signal —
  recording it as "decoded" inflated ``suspicion_score`` for files
  where we never actually unpacked anything. MARSHAL is now surfaced
  via a separate pre-scan that adds the technique without touching
  the counters.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import zlib
from dataclasses import dataclass, field

from shared.types.enums import ObfuscationTechnique
from shared.utils.logging import get_logger

_log = get_logger(__name__)

_MAX_LAYERS = 10
_MIN_PAYLOAD_LEN = 8

#: Cap decompressed output at 100 KB. Matches the labeling pipeline's
#: ``data/labeling/deobfuscation/safety.py:MAX_ZLIB_DECOMPRESSED``. A
#: crafted blob that would decompress beyond this cap (zlib / gzip /
#: raw-deflate) is rejected; the original encoded content is preserved
#: in the output and downstream stages see it unchanged. Prevents
#: decompression-bomb OOM on adversarial input.
_MAX_ZLIB_DECOMPRESSED = 100_000

#: Regex-engine safety cap. Inputs larger than this skip the outer
#: regex patterns (``_EXEC_WRAPPER``, ``_DECOMPRESS_CALL``,
#: ``_MARSHAL_CALL``) which use ``.+?`` and would backtrack
#: catastrophically on adversarial multi-KB strings. Real obfuscated
#: payloads are well under 64 KB; attackers targeting ReDoS would
#: send much larger strings and be skipped entirely.
_MAX_REGEX_INPUT = 65_536

# PREP-014: reject decoded output that's mostly non-printable (binary
# garbage from decoding something that wasn't actually an encoded payload).
# Ported byte-for-byte from ``data/labeling/deobfuscation/safety.py`` so
# the decoded content S1/L1 see at inference matches what labeling kept
# in training data — same threshold, same sample window, same allowlist.
_PRINTABILITY_THRESHOLD = 0.80
_PRINTABILITY_SAMPLE = 500


def _is_printable(text: str, threshold: float = _PRINTABILITY_THRESHOLD) -> bool:
    """True iff more than ``threshold`` fraction of the first 500 chars are printable.

    Byte-for-byte parity with
    ``data/labeling/deobfuscation/safety.py::is_printable``. TAB / LF / CR
    count as printable; other control chars and arbitrary binary bytes do not.

    U+FFFD (Unicode replacement character) is treated as **non-printable** —
    a pure-binary payload run through ``errors="replace"`` UTF-8 decode
    becomes a dense stream of U+FFFD codepoints that ``str.isprintable()``
    classifies as printable. PR #25 review caught this latent FP; all
    deobfuscate paths now use strict UTF-8 so U+FFFD can't appear in
    normal operation, but counting it as non-printable is a cheap belt-
    and-suspenders if any future path switches to ``errors="replace"``.
    """
    sample = text[:_PRINTABILITY_SAMPLE]
    if not sample:
        return False
    printable_count = sum(1 for c in sample if c != "\ufffd" and (c.isprintable() or c in "\n\r\t"))
    return printable_count / len(sample) > threshold


_EXEC_WRAPPER = re.compile(
    r"""(?:exec|eval)\s*\(\s*(?P<body>.+?)\s*\)\s*$""",
    re.DOTALL,
)
# b64decode(...), urlsafe_b64decode(...), base64.b64decode(...) — captures the
# full arg list; string literals are then pulled via _CONCAT_LITERALS so byte
# prefixes, multi-chunk concatenation, and adjacent-literal concat all work.
_B64_CALL = re.compile(
    r"""(?:base64\.)?(?:urlsafe_)?b64decode\s*\(\s*(?P<args>.+?)\s*\)""",
    re.DOTALL,
)
_HEX_CALL = re.compile(
    r"""(?:bytes\.fromhex|codecs\.decode)\s*\(\s*(?P<args>.+?)\s*\)""",
    re.DOTALL,
)
# Matches ``zlib.decompress(...)`` AND ``gzip.decompress(...)`` call
# sites. Both are routed through the same bomb-guarded decompressor
# helper that tries zlib, gzip, and raw-deflate (``wbits=-15``) formats
# in order. PR #17 review follow-up: the original ``_ZLIB_CALL``-only
# pattern missed ``gzip.decompress(...)`` and raw-deflate payloads
# wrapped in non-zlib containers.
_DECOMPRESS_CALL = re.compile(
    r"""(?:zlib|gzip)\.decompress\s*\(\s*(?P<body>.+?)\s*\)\s*$""",
    re.DOTALL,
)
_MARSHAL_CALL = re.compile(
    r"""marshal\.loads\s*\(\s*(?P<body>.+?)\s*\)\s*$""",
    re.DOTALL,
)
_ROT13_CALL = re.compile(
    r"""(?:codecs\.)?(?:decode|encode)\s*\(\s*(?P<args>.+?)\s*,\s*['"]rot[_-]?13['"]\s*\)""",
    re.DOTALL,
)

# String-literal capture with BOUNDED escape-chain quantifiers. Each
# non-escape segment capped at 4096 chars; at most 256 escape+segment
# pairs per literal. The original unbounded form
# ``[^'"\\]*(?:\\.[^'"\\]*)*`` is a classic polynomial-backtracking
# pattern (mismatched quote + long body → catastrophic work).
_STR_LITERAL = re.compile(
    r"""(?:[bBrRuU]{0,2})(?P<q>['"])(?P<chunk>[^'"\\]{0,4096}(?:\\.[^'"\\]{0,4096}){0,256})(?P=q)""",
    re.DOTALL,
)

_BARE_B64 = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")
_BARE_HEX = re.compile(r"^[0-9a-fA-F\s]+$")

# PREP-020: variable-assigned base64 payload. Captures both the
# variable name and the quoted string literal so ``_peel_layer`` can
# resolve ``exec(base64.b64decode(VAR))`` references by looking up
# ``VAR = "..."`` elsewhere in the file. Ports
# ``data/labeling/deobfuscation/decoder.py::_B64_VAR_PATTERN`` so
# preprocessing's decoded-content view matches what labeling produces.
# Length floor at 40 chars aligns with the shortest realistic encoded
# payload; shorter strings are likely tokens or config constants.
_B64_VAR_ASSIGNMENT = re.compile(
    r"""(?P<name>[_A-Za-z][_A-Za-z0-9]*)\s*=\s*["'](?P<blob>[A-Za-z0-9+/=]{40,})["']""",
)

# Identifier-only ``b64decode`` argument — the precise failure mode
# ``_join_literals`` returns ``None`` on. When we see this shape, fall
# back to variable-assignment resolution (``_resolve_b64_var``).
_BARE_IDENT = re.compile(r"^\s*(?P<name>[_A-Za-z][_A-Za-z0-9]*)\s*$")


# PREP-012: entry-point trigger discipline. Ported byte-for-byte from
# ``data/labeling/deobfuscation/patterns.py`` so that a file that does
# NOT trigger decoding at labeling time also does NOT trigger at
# inference. Plain base64 in JWTs / PEM / images / certs / CI artifacts
# must be paired with an execution sink before any decode fires.
_OBFUSCATION_EXECUTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.DOTALL | re.IGNORECASE)
    for p in (
        r"(exec|eval)\s*\(\s*(?:base64\.)?(?:urlsafe_)?b64decode",
        r"(exec|eval)\s*\(\s*__import__\s*\(.base64.\)",
        r"exec\s*\(\s*compile\s*\(\s*(?:base64\.)?(?:urlsafe_)?b64decode",
        r"subprocess\.\w+\s*\(.*(?:base64\.)?(?:urlsafe_)?b64decode",
        r"(exec|eval)\s*\(\s*codecs\.decode\s*\(",
        r"(exec|eval)\s*\(\s*bytes\.fromhex\s*\(",
        r"(exec|eval)\s*\(\s*(?:zlib|gzip)\.decompress\s*\(",
        r"marshal\.loads\s*\(.*base64",
    )
)


def _should_attempt_decode(content: str) -> bool:
    """True iff content contains an obfuscation execution pattern worth decoding.

    Byte-for-byte parity with
    ``data/labeling/deobfuscation/patterns.py::should_attempt_decode``.
    """
    return any(p.search(content) for p in _OBFUSCATION_EXECUTION_PATTERNS)


@dataclass
class DeobfuscationResult:
    content: str
    applied: bool
    layers: int
    techniques: list[ObfuscationTechnique] = field(default_factory=list)
    # PREP-013: output-shape parity with
    # ``data/labeling/deobfuscation/models.py:DecodeResult``. These fields
    # surface through ``extractions.obfuscation`` so L1 sees the same block
    # shape at inference that labeling produced at training time.
    #
    # ``blob_count`` = decoded_blob_count + failed_blob_count (total
    # pattern matches that advanced to the decode step).
    # ``decoded_blob_count`` = successful decodes (== ``layers``).
    # ``failed_blob_count`` = pattern matched but ``_try_*`` returned
    # ``None`` (unrecoverable payload shape). Non-zero after PR #24
    # review: the prior implementation always reported 0.
    blob_count: int = 0
    decoded_blob_count: int = 0
    failed_blob_count: int = 0
    suspicion_score: float = 0.0
    decoded_content_summary: str | None = None


@dataclass
class _PeelResult:
    """One iteration of ``_peel_layer``.

    Separate from ``DeobfuscationResult`` so the outer loop can
    accumulate both "this iteration produced a new layer" and "this
    iteration had N patterns match-but-fail-to-decode". Previously the
    peel function only returned the success case, so failures never
    made it to ``failed_blob_count`` (PR #24 review blocker).
    """

    peeled: tuple[str, ObfuscationTechnique] | None
    failed_attempts: int = 0


def _try_base64(payload: str) -> str | None:
    """Decode standard OR url-safe base64, padding-tolerant.

    PREP-014: rejects output that's not >=80% printable — prevents binary
    blobs that happen to decode as valid UTF-8 (embedded-image bytes,
    compressed payloads, random data) from being fed to S/L1 as "decoded
    text". Byte-for-byte parity with labeling.
    """
    stripped = "".join(payload.split())
    if len(stripped) < _MIN_PAYLOAD_LEN or not _BARE_B64.match(stripped):
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    is_urlsafe = "-" in padded or "_" in padded
    try:
        decoded = (base64.urlsafe_b64decode if is_urlsafe else base64.b64decode)(padded)
    except (binascii.Error, ValueError):
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not _is_printable(text):
        return None
    return text


def _try_hex(payload: str) -> str | None:
    stripped = "".join(payload.split())
    if len(stripped) < _MIN_PAYLOAD_LEN or len(stripped) % 2 or not _BARE_HEX.match(stripped):
        return None
    try:
        decoded = bytes.fromhex(stripped)
    except ValueError:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not _is_printable(text):
        return None
    return text


def _try_rot13(payload: str) -> str | None:
    try:
        text = codecs.decode(payload, "rot_13")
    except (LookupError, UnicodeDecodeError, ValueError):
        # Narrow: codecs raises LookupError for unknown encodings and
        # UnicodeDecodeError/ValueError on malformed input. MemoryError
        # etc. must propagate — they are not "rot13 declined this
        # payload" signals, they are process-level failures.
        return None
    # ROT13 over mostly-printable input always produces mostly-printable
    # output, but we run the check anyway for parity and in case the
    # input was non-ASCII / garbage-in-garbage-out.
    if not _is_printable(text):
        return None
    return text


def _decompress_with_bomb_guard(compressed: bytes) -> bytes | None:
    """Try zlib → gzip → raw-deflate; return decompressed bytes or ``None``.

    All three paths share a single ``_MAX_ZLIB_DECOMPRESSED`` cap.
    Return shape:

    * ``bytes`` — decompression succeeded, bounded output.
    * ``None`` — every format rejected the input OR the cap was hit
      before the compressed stream finished (bomb). A structlog
      ``warning`` is emitted on bomb trips with the compressed size
      and cap for production visibility; silent ``None`` was the
      PR #17 review blocker.

    ``MemoryError`` is deliberately **not** caught — the bomb guard
    exists to prevent it, but a MemoryError from elsewhere is a
    process-level condition that must propagate.
    """
    # zlib-wrapped data (wbits=15 — default).
    raw = _try_decompress_variant(compressed, wbits=15, source="zlib")
    if raw is not None:
        return raw
    # gzip-wrapped data (wbits=31 per zlib convention).
    raw = _try_decompress_variant(compressed, wbits=31, source="gzip")
    if raw is not None:
        return raw
    # Raw deflate — no zlib/gzip header (wbits=-15).
    return _try_decompress_variant(compressed, wbits=-15, source="raw_deflate")


def _try_decompress_variant(compressed: bytes, *, wbits: int, source: str) -> bytes | None:
    """Attempt one decompression format with the shared bomb-guard cap.

    Returns bytes on success, ``None`` on malformed input OR bomb trip.
    A structlog warning is emitted on a bomb trip so production can
    observe attack attempts; ordinary "wrong format" failures (the
    function is called speculatively for each format) are silent.
    """
    try:
        decompressor = zlib.decompressobj(wbits=wbits)
        raw = decompressor.decompress(compressed, _MAX_ZLIB_DECOMPRESSED)
    except zlib.error:
        return None
    if not decompressor.eof:
        # Cap hit before the compressed stream finished — at least
        # one byte beyond the cap would have been produced. Treat as
        # a decompression-bomb attempt and surface to the log.
        _log.warning(
            "deobfuscation.bomb_guard_tripped",
            source=source,
            compressed_size=len(compressed),
            cap=_MAX_ZLIB_DECOMPRESSED,
            decoded_so_far=len(raw),
        )
        return None
    return raw


def _try_decompress_of_b64(payload: str) -> str | None:
    """Base64-decode, then decompress (zlib/gzip/raw-deflate) under bomb guard.

    Cannot route through ``_try_base64`` because that helper applies a
    UTF-8 decode check on the decoded bytes — compressed data is binary
    and fails UTF-8 validation, which would reject every real decompress-
    of-b64 input before we ever reach the decompress step. We do base64
    inline here and preserve the raw bytes for decompression.

    Returns ``None`` either when the base64 / decompression step fails
    OR when the decompressed output would exceed the bomb-guard cap. The
    two cases are distinguished in the logs, not in the return value —
    callers only need "did this yield clean decoded text or not".

    PR #25 review fix: ``errors="strict"`` (rather than ``"replace"``)
    on the final decode prevents U+FFFD-masquerade — replacement
    characters from binary garbage would have passed
    ``str.isprintable()``. Combined with the U+FFFD exclusion in
    ``_is_printable``, this is belt-and-suspenders.
    """
    stripped = "".join(payload.split())
    if len(stripped) < _MIN_PAYLOAD_LEN or not _BARE_B64.match(stripped):
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    is_urlsafe = "-" in padded or "_" in padded
    try:
        compressed = (base64.urlsafe_b64decode if is_urlsafe else base64.b64decode)(padded)
    except (binascii.Error, ValueError):
        return None
    raw = _decompress_with_bomb_guard(compressed)
    if raw is None:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Decompression produced binary rather than text — reject rather
        # than feeding garbage to downstream S/L1 stages. This is a
        # narrow exception class; broad except Exception would swallow
        # MemoryError from upstream callers.
        return None
    # PREP-014: even a successfully UTF-8-decoded blob can still be mostly
    # non-printable garbage from decompressing something that wasn't a
    # real payload. The printability guard rejects those at parity with
    # labeling's safety filter.
    if not _is_printable(text):
        return None
    return text


# Back-compat alias. PR #17 review renamed the helper to signal that it
# now covers zlib + gzip + raw-deflate. Kept as an alias so any stale
# references turn up in grep rather than silently break.
_try_zlib_of_b64 = _try_decompress_of_b64


def _resolve_b64_var(args: str, full_text: str) -> str | None:
    """Resolve ``base64.b64decode(VAR)`` where ``VAR`` is defined earlier.

    When the ``b64decode(...)`` call site holds a bare identifier instead
    of a string literal, scan ``full_text`` for a matching
    ``VAR = "<b64 blob>"`` assignment and return the blob. Returns
    ``None`` when:

    * ``args`` is not a bare identifier (e.g. a compound expression, a
      function call, a subscript).
    * No matching assignment is found with a ≥40-char blob.
    * Multiple assignments exist for the same name (ambiguous — decline
      rather than guess).

    PREP-020. Mirrors
    ``data/labeling/deobfuscation/decoder.py::_B64_VAR_PATTERN`` so the
    preprocessing decoded-content view matches what labeling produces
    at training time.
    """
    ident_match = _BARE_IDENT.match(args)
    if ident_match is None:
        return None
    name = ident_match.group("name")
    candidates = [m.group("blob") for m in _B64_VAR_ASSIGNMENT.finditer(full_text) if m.group("name") == name]
    if len(candidates) != 1:
        # Zero assignments: unbound reference, can't resolve.
        # Two or more: the variable is reassigned — which value was
        # active at the decode call? We don't run an AST flow analysis,
        # so decline rather than risk decoding the wrong blob.
        return None
    return candidates[0]


def _join_literals(args: str) -> str | None:
    """Return the concatenated contents of every string literal in `args`, or None.

    Supports byte-prefix literals (`b"..."`), unicode/raw prefixes (`u`, `r`),
    adjacent-literal concatenation (`"abc" "def"`), and explicit `+` concatenation.
    If no literal is found, returns None (caller falls back to variable handling).
    """
    chunks = [m.group("chunk") for m in _STR_LITERAL.finditer(args)]
    if not chunks:
        return None
    return "".join(chunks)


def _peel_layer(text: str) -> _PeelResult:
    """Attempt one deobfuscation layer.

    Returns ``_PeelResult(peeled, failed_attempts)``. Pattern matches
    that advanced to a ``_try_*`` call which returned ``None`` count
    as failed attempts and are added to
    ``DeobfuscationResult.failed_blob_count`` by the caller. A pattern
    that did not match at all is not counted — we only count
    "attempted decode" failures.

    Inputs over ``_MAX_REGEX_INPUT`` short-circuit with
    ``peeled=None`` to avoid ReDoS on the outer ``.+?`` patterns.
    """
    stripped = text.strip()
    if len(stripped) > _MAX_REGEX_INPUT:
        return _PeelResult(peeled=None)

    failed = 0

    if m := _B64_CALL.search(stripped):
        args = m.group("args")
        # Happy path: the decode call inlines the base64 string literal.
        payload = _join_literals(args)
        # PREP-020 fallback: the decode call references a variable
        # (``base64.b64decode(_PAYLOAD)``). Resolve by scanning the
        # whole file for a ``_PAYLOAD = "<b64 blob>"`` assignment and
        # substituting the literal. Labeling-pipeline parity.
        if payload is None:
            payload = _resolve_b64_var(args, stripped)
        if payload is not None:
            decoded = _try_base64(payload)
            if decoded is not None:
                return _PeelResult(peeled=(decoded, ObfuscationTechnique.BASE64))
            failed += 1

    if m := _HEX_CALL.search(stripped):
        payload = _join_literals(m.group("args"))
        if payload is not None:
            decoded = _try_hex(payload)
            if decoded is not None:
                return _PeelResult(peeled=(decoded, ObfuscationTechnique.HEX))
            failed += 1

    if m := _ROT13_CALL.search(stripped):
        payload = _join_literals(m.group("args"))
        if payload is not None:
            decoded = _try_rot13(payload)
            if decoded is not None:
                return _PeelResult(peeled=(decoded, ObfuscationTechnique.ROT13))
            failed += 1

    # ``zlib.decompress(...)`` / ``gzip.decompress(...)`` paired with a
    # base64-decode on the SAME line. Narrower than it could be — a
    # ``zlib.decompress(some_var)`` where the b64 is stored in a bound
    # variable is silently skipped. Expanding to cross-line flow requires
    # an AST walker (tracked as future work); the regex path covers the
    # dominant real-world shape of obfuscated payloads.
    if _DECOMPRESS_CALL.search(stripped):
        if b := _B64_CALL.search(stripped):
            payload = _join_literals(b.group("args"))
            if payload is not None:
                decoded = _try_decompress_of_b64(payload)
                if decoded is not None:
                    return _PeelResult(peeled=(decoded, ObfuscationTechnique.ZLIB_COMPRESS))
                failed += 1

    # MARSHAL intentionally NOT handled here (PR #24 review): the old
    # branch ``return stripped, MARSHAL`` bumped layers + decoded blob
    # count on unchanged content, inflating ``suspicion_score``.
    # Marshal is detected in a pre-scan (``_detect_marshal``) and
    # recorded as a technique without counting toward decoded layers.

    if m := _EXEC_WRAPPER.search(stripped):
        inner = m.group("body")
        if _B64_CALL.search(inner) or _HEX_CALL.search(inner) or _ROT13_CALL.search(inner):
            return _PeelResult(peeled=(inner, ObfuscationTechnique.EXEC_CHAIN))

    if _BARE_B64.match(stripped) and len(stripped) >= _MIN_PAYLOAD_LEN:
        decoded = _try_base64(stripped)
        if decoded is not None and decoded != stripped:
            return _PeelResult(peeled=(decoded, ObfuscationTechnique.BASE64))

    return _PeelResult(peeled=None, failed_attempts=failed)


def _detect_marshal(text: str) -> bool:
    """Detected-but-not-decoded signal for ``marshal.loads(...)``.

    ``marshal.loads`` on untrusted bytes can trigger ``__reduce__``
    chains if the loaded code object is later ``exec``'d; we never run
    it ourselves, but a file that contains the call is still a strong
    obfuscation signal. Recorded in ``techniques`` without bumping
    ``layers`` / ``decoded_blob_count`` — the PREP-013 suspicion score
    no longer inflates on unchanged content (PR #24 review blocker).
    """
    if len(text) > _MAX_REGEX_INPUT:
        return False
    return _MARSHAL_CALL.search(text) is not None


def _suspicion_score(layers: int, decoded_blob_count: int) -> float:
    """Labeling-parity suspicion score formula.

    Ports ``data/labeling/deobfuscation/decoder.py`` exactly:
        suspicion = min(1.0, 0.5 + (max_layers * 0.2) + (total_decoded_count * 0.1))
    when anything was decoded; 0.0 otherwise.
    """
    if decoded_blob_count == 0:
        return 0.0
    return round(min(1.0, 0.5 + (layers * 0.2) + (decoded_blob_count * 0.1)), 2)


def _decoded_content_summary(
    *,
    decoded_blob_count: int,
    failed_blob_count: int,
    layers: int,
    techniques: list[ObfuscationTechnique],
) -> str | None:
    """Labeling-parity summary string.

    Mirrors ``decoder.py``'s "N blob(s) decoded across L layer(s); ...;
    techniques: a, b" format so L1 sees the same natural-language summary
    it saw during training.
    """
    if decoded_blob_count == 0:
        return None
    parts = [f"{decoded_blob_count} blob(s) decoded across {layers} layer(s)"]
    if failed_blob_count > 0:
        parts.append(f"{failed_blob_count} blob(s) failed to decode")
    if techniques:
        parts.append(f"techniques: {', '.join(t.value for t in techniques)}")
    return "; ".join(parts)


def deobfuscate(content: str | bytes, max_layers: int = _MAX_LAYERS) -> DeobfuscationResult:
    """Iteratively peel obfuscation layers. Capped at `max_layers` to bound work.

    PREP-012: gated at entry on ``_should_attempt_decode`` — files without an
    obfuscation execution pattern are returned unchanged and ``applied=False``.
    This matches the labeling pipeline's pre-triage so that the fine-tuned
    S1/L1 models see the same decode / no-decode classification at inference
    that they saw during training-data construction.

    PREP-013: emits shape fields (``blob_count``, ``decoded_blob_count``,
    ``failed_blob_count``, ``suspicion_score``, ``decoded_content_summary``)
    so the ``extractions.obfuscation`` block L1 sees at inference matches
    what labeling produced at training.
    """
    text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content

    if not _should_attempt_decode(text):
        return DeobfuscationResult(
            content=text,
            applied=False,
            layers=0,
            techniques=[],
        )

    decoded_techniques: list[ObfuscationTechnique] = []
    failed_blob_count = 0
    current = text
    for _ in range(max_layers):
        result = _peel_layer(current)
        failed_blob_count += result.failed_attempts
        if result.peeled is None:
            break
        current, technique = result.peeled
        decoded_techniques.append(technique)

    decoded_blob_count = len(decoded_techniques)
    layers = decoded_blob_count
    blob_count = decoded_blob_count + failed_blob_count

    # MARSHAL is a detected-but-not-decoded technique: recorded in the
    # techniques list so L1 sees the signal, but doesn't count toward
    # layers / decoded_blob_count / suspicion_score. Scanning the
    # original input catches marshal calls that weren't themselves
    # inside a decoded-payload chain.
    all_techniques = list(decoded_techniques)
    if _detect_marshal(text) and ObfuscationTechnique.MARSHAL not in all_techniques:
        all_techniques.append(ObfuscationTechnique.MARSHAL)

    return DeobfuscationResult(
        content=current,
        # ``applied`` reflects "did we produce decoded content" — MARSHAL-
        # only detection does not count because no content was decoded.
        applied=bool(decoded_techniques),
        layers=layers,
        techniques=all_techniques,
        blob_count=blob_count,
        decoded_blob_count=decoded_blob_count,
        failed_blob_count=failed_blob_count,
        suspicion_score=_suspicion_score(layers, decoded_blob_count),
        decoded_content_summary=_decoded_content_summary(
            decoded_blob_count=decoded_blob_count,
            failed_blob_count=failed_blob_count,
            layers=layers,
            techniques=decoded_techniques,
        ),
    )
