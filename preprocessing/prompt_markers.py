"""PREP-015: decoded-content prompt markers with nonce hardening.

When the pre-pass decoded obfuscated content, wrap it with labeling-shape
markers before inlining it into S/L1 prompts. Fine-tuned models saw these
exact markers in training data; carrying them at inference keeps the
"this is decoded content, not original source" signal aligned.

Marker conventions, ported from
``data/labeling/deobfuscation/decoder.py`` with a security-hardening
extension — a per-call nonce suffixed inside the marker:

```
# === DECODED BASE64 PAYLOAD [<nonce>] ===
<decoded content>
# === END DECODED PAYLOAD [<nonce>] ===
```

Why the nonce
-------------

Without a nonce the close-marker is predictable public knowledge (it
appears verbatim in training data and in this repo). An attacker whose
payload decodes to arbitrary text can embed the literal close-marker
followed by injection-style instructions, and a reader (human or model)
truncates the decoded block at the attacker's spoofed marker —
attacker-controlled text leaks into post-marker prompt context.

Fix: generate a 64-bit random nonce per wrap call, append it inside the
`===` delimiters, and tell the model in its prompt preamble that the
decoded block is delimited by markers bearing exactly this nonce.
Attacker cannot know the nonce in advance, so spoofing the real
delimiter is infeasible.

Defense in depth
----------------

We *also* scan decoded content for the literal close-marker substring
(with zero-width characters stripped) and set
``PreprocessingBundle.obfuscation_attack_attempt = "marker_spoofing"``
when the pattern appears. We do not reject the content — rejection would
hand the attacker a DoS primitive (poison a file with a marker string to
make it un-scannable). The signal is propagated into
``Obfuscation.attack_attempt`` for downstream awareness.

Distribution-shift note
-----------------------

The main marker prose (``# === DECODED BASE64 PAYLOAD``) is preserved
verbatim — the nonce is a suffix inside the ``===`` close. FT models
pattern-match on the prose prefix and tolerate the suffix. Full parity
with the labeling pipeline (which currently uses literal-only markers)
is tracked as ``LABELING-NONCE-001`` against the ``data/`` repo; until
that lands, the next training round bakes in the new shape.
"""

from __future__ import annotations

import secrets

from shared.types.enums import ObfuscationTechnique

from .pipeline import PreprocessingBundle

#: Marker-technique priority. First matching technique wins. The tuple is
#: the single source of truth — no parallel dict, no divergence risk.
#: Order matters: specific payload types (ZLIB, HEX) before generic
#: BASE64 before any chain technique that gets the BASE64 fallback.
_MARKER_PRIORITY: tuple[tuple[ObfuscationTechnique, str], ...] = (
    (ObfuscationTechnique.ZLIB_COMPRESS, "ZLIB"),
    (ObfuscationTechnique.HEX, "HEX"),
    (ObfuscationTechnique.BASE64, "BASE64"),
    (ObfuscationTechnique.MARSHAL, "MARSHAL"),
    (ObfuscationTechnique.ROT13, "ROT13"),
)

#: BASE64 is the catch-all fallback when no priority match fires — e.g.
#: EXEC_CHAIN / EVAL_CHAIN / STRING_CONCAT / UNICODE_ESCAPE / XOR /
#: CUSTOM_ENCODING with no inner-decode technique recorded. Historical
#: note: previous revisions duplicated this in a parallel dict that
#: could silently diverge.
_FALLBACK_LABEL = "BASE64"

#: Unicode zero-width codepoints stripped before spoof-detection so an
#: attacker can't evade the check by sprinkling U+200B into the marker.
_ZERO_WIDTH = "\u200b\u200c\u200d\ufeff"

#: Literal close-marker fragment that triggers the spoof indicator.
#: Matching the close is sufficient — an attacker only needs the close
#: to escape the decoded block; the open is merely decoration.
_SPOOF_ENDMARKER_PATTERN = "# === END DECODED PAYLOAD"


def _marker_label(techniques: list[ObfuscationTechnique]) -> str:
    """Return the marker label best describing the decoded payload."""
    for technique, label in _MARKER_PRIORITY:
        if technique in techniques:
            return label
    return _FALLBACK_LABEL


def _strip_zero_width(text: str) -> str:
    """Strip zero-width codepoints so spoof detection isn't evaded by
    sandwiching the marker between U+200B / U+200C / U+200D / U+FEFF.
    """
    if not text:
        return text
    if not any(ch in text for ch in _ZERO_WIDTH):
        return text
    return text.translate({ord(ch): None for ch in _ZERO_WIDTH})


def detect_marker_spoofing(decoded_content: str) -> bool:
    """Return True when ``decoded_content`` contains a literal close-marker.

    The check strips zero-width characters first so
    ``# === END DECODED PAYLOAD ===`` interspersed with U+200B is still
    flagged. The check is intentionally substring-based (not regex) — an
    attacker who embeds the literal bytes of the legacy close-marker is
    the spoof we care about. Unicode homoglyph variants (fullwidth
    ``＃``, box-drawing ``═``) are NOT flagged by this detector; nonce
    markers already make them unexploitable, and flagging them would
    false-positive on legitimate decorative content.
    """
    return _SPOOF_ENDMARKER_PATTERN in _strip_zero_width(decoded_content)


def wrap_decoded_for_prompt(bundle: PreprocessingBundle) -> tuple[str, str]:
    """Return ``(prompt_ready_content, nonce)``.

    * When ``deobfuscation_applied`` is ``False``, returns
      ``(bundle.decoded_content, "")`` — clean files cost zero marker
      tokens and there is no nonce to communicate.
    * When ``deobfuscation_applied`` is ``True``, wraps the decoded
      content with nonce-suffixed labeling-shape markers and returns
      the nonce so the caller can inform the model in its prompt
      preamble.

    The nonce is 16 hex chars (64 bits) sampled from ``secrets``; it is
    generated per call and must be passed to the prompt builder so the
    model is told which delimiter tokens to trust on this call.
    """
    if not bundle.preprocessing.deobfuscation_applied:
        return bundle.decoded_content, ""
    label = _marker_label(list(bundle.obfuscation_techniques))
    nonce = secrets.token_hex(8)
    wrapped = (
        f"# === DECODED {label} PAYLOAD [{nonce}] ===\n"
        f"{bundle.decoded_content}\n"
        f"# === END DECODED PAYLOAD [{nonce}] ==="
    )
    return wrapped, nonce
