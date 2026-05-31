"""Tolerant JSON decoding for model outputs.

Small models often loop on permissive schemas, truncating mid-string
when ``max_completion_tokens`` hits. This module exposes a single helper
that recovers a valid JSON object from such outputs:

1. Try strict ``json.loads`` — fast path for well-formed responses.
2. On failure, walk the bracket/quote state machine and produce the
   longest prefix that balances brackets and closes open strings.
3. Decode that prefix; if it still fails, return ``None``.

The recovered object is byte-identical to the original for well-formed
responses. Callers should dedup list fields afterward because the
recovered object may include the looping entries.
"""

from __future__ import annotations

import json
from typing import Any


def loads_tolerant(raw: str) -> Any | None:
    """Attempt strict decode, fall back to longest-valid-prefix decode."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    fixed = _repair(raw)
    if fixed is None:
        return None
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        return None


def _repair(raw: str) -> str | None:
    """Return the longest prefix of ``raw`` that balances brackets and quotes.

    Strategy: scan char by char tracking the bracket stack and string
    state. At every safe state (outside strings, stack non-empty),
    remember the position. At end, truncate to the last safe position
    and close any remaining open brackets in reverse order.
    """
    stack: list[str] = []
    in_string = False
    escape = False
    last_safe = -1

    for i, ch in enumerate(raw):
        if in_string:
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]":
            if not stack:
                continue
            expected = stack.pop()
            if expected != ch:
                # mismatched — bail
                continue

        # Safe state: between tokens, not in a string, stack represents
        # currently-open containers. Record the boundary.
        if ch in ",}]":
            last_safe = i
        elif ch.isspace() and not stack:
            last_safe = i

    if last_safe < 0:
        return None
    prefix = raw[: last_safe + 1]
    # Recompute stack over the truncated prefix so closers match.
    return _balance(prefix)


def _balance(prefix: str) -> str:
    """Append closers for any still-open brackets in ``prefix``."""
    stack: list[str] = []
    in_string = False
    escape = False
    for ch in prefix:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            stack.append("}")
        elif ch == "[":
            stack.append("]")
        elif ch in "}]":
            if stack and stack[-1] == ch:
                stack.pop()

    # Trim trailing commas before closing.
    trimmed = prefix.rstrip()
    if trimmed.endswith(","):
        trimmed = trimmed[:-1]
    return trimmed + "".join(reversed(stack))
