"""Param classifier — JSON-Schema + name → attack class.

Given an MCP tool's input-schema parameter ``(name, schema)``, return a
``ParamClass`` so the probe layer knows which payload family to seed.
Heuristic + curated; no LLM call.

Single source of truth for "tool param name says URL → seed an SSRF
payload" — the keyword list is lifted directly from
``dast.behavioral_probe._NAME_TO_ADVERSARIAL_HINT`` so existing
behavioral-probe seeds and MCP-mode SSRF probes agree on classification.

JSON-Schema signals (highest-priority → lowest):

  1. ``format: uri|url|uri-reference`` → URL
  2. ``format: ipv4|ipv6|hostname`` → HOST
  3. ``format: path|file`` → PATH
  4. ``pattern`` matching ``^https?://`` → URL
  5. Name keyword match (URL / HOST / PATH / COMMAND / QUERY family)
  6. ``type: string`` with no other signal → FUZZ
  7. ``type: integer|number`` → INTEGER
  8. ``type: boolean`` → BOOLEAN
  9. anything else → UNKNOWN
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any


class ParamClass(StrEnum):
    """Attack-class a parameter is a CANDIDATE for.

    The probe layer uses these to decide which payload family to seed.
    A param can only carry one class; ambiguous cases (a name that
    matches both URL and PATH keywords) fall through the classifier's
    priority order to the first match.
    """

    URL = "url"
    HOST = "host"
    PATH = "path"
    COMMAND = "command"
    QUERY = "query"
    FUZZ = "fuzz"  # generic string with no semantic hint
    INTEGER = "integer"
    BOOLEAN = "boolean"
    UNKNOWN = "unknown"  # non-string non-numeric, or unrecognised shape


# Curated name → ParamClass map. Lifted from
# ``dast.behavioral_probe._NAME_TO_ADVERSARIAL_HINT`` keys (which were
# themselves curated against a 200+ corpus of real Python / JS / MCP
# function-parameter names). Maintaining a single source of truth here
# means changes to one place auto-extend MCP probe coverage.
#
# Substring match (case-insensitive) — ``"target_url"`` matches both
# ``url`` (URL family) and is checked against URL before PATH.
_NAME_KEYWORDS: tuple[tuple[str, ParamClass], ...] = (
    # URL family — checked first because ``webhook_url`` should not
    # match ``hook`` first or anything generic. Order within a class
    # doesn't matter (first match wins).
    ("endpoint", ParamClass.URL),
    ("webhook", ParamClass.URL),
    ("callback", ParamClass.URL),
    ("link", ParamClass.URL),
    ("uri", ParamClass.URL),
    ("url", ParamClass.URL),
    # HOST family — ``host`` AFTER ``localhost`` would mis-bin
    # ``localhost_setting`` as HOST; ``localhost`` isn't a likely
    # MCP param name though, so we keep this simple.
    ("hostname", ParamClass.HOST),
    ("host", ParamClass.HOST),
    ("address", ParamClass.HOST),
    ("server", ParamClass.HOST),
    # PATH family — covers filesystem paths AND HTTP URI paths.
    # MCP fetch tools often take a URI ``path`` separately from the
    # base URL; we treat both as PATH (SSRF-via-path-segment is rare
    # but path-traversal still applies).
    ("filename", ParamClass.PATH),
    ("filepath", ParamClass.PATH),
    ("file_path", ParamClass.PATH),
    ("dirname", ParamClass.PATH),
    ("dirpath", ParamClass.PATH),
    ("template", ParamClass.PATH),
    ("file", ParamClass.PATH),
    ("path", ParamClass.PATH),
    # COMMAND family — anything that smells shell-shaped.
    ("command", ParamClass.COMMAND),
    ("cmd", ParamClass.COMMAND),
    ("argv", ParamClass.COMMAND),
    ("args", ParamClass.COMMAND),
    ("shell", ParamClass.COMMAND),
    ("exec", ParamClass.COMMAND),
    # QUERY family — SQL / search / filter inputs.
    ("query", ParamClass.QUERY),
    ("sql", ParamClass.QUERY),
    ("where", ParamClass.QUERY),
    ("filter", ParamClass.QUERY),
    ("search", ParamClass.QUERY),
)

# Format hint → ParamClass. JSON Schema's ``format`` is advisory but
# most MCP servers populate it correctly for HTTP-shaped params.
_FORMAT_TO_CLASS: dict[str, ParamClass] = {
    "uri": ParamClass.URL,
    "uri-reference": ParamClass.URL,
    "url": ParamClass.URL,
    "iri": ParamClass.URL,
    "iri-reference": ParamClass.URL,
    "hostname": ParamClass.HOST,
    "idn-hostname": ParamClass.HOST,
    "ipv4": ParamClass.HOST,
    "ipv6": ParamClass.HOST,
    "path": ParamClass.PATH,
    "file": ParamClass.PATH,
    "file-path": ParamClass.PATH,
}

# JSON-Schema ``type`` → fallback ParamClass when no name / format
# signal pinned down a more specific class.
_TYPE_TO_FALLBACK: dict[str, ParamClass] = {
    "string": ParamClass.FUZZ,
    "integer": ParamClass.INTEGER,
    "number": ParamClass.INTEGER,
    "boolean": ParamClass.BOOLEAN,
}

# Compiled once: regex hinting at a URL-typed schema via the
# ``pattern`` keyword. We're permissive — anyone writing
# ``"pattern": "^https?://.*"`` clearly means URL. The ``\??`` allows
# the schema's pattern to include an optional ``?`` between ``s`` and
# ``://`` (the canonical ``https?://`` shape).
_URL_PATTERN_RE = re.compile(r"\^https?\??(://|\\:\\/\\/)", re.IGNORECASE)


def classify_param(name: str, schema: dict[str, Any] | None) -> ParamClass:
    """Return the most likely attack class for an MCP tool parameter.

    >>> classify_param("url", {"type": "string"})
    <ParamClass.URL: 'url'>
    >>> classify_param("query", {"type": "string"})
    <ParamClass.QUERY: 'query'>
    >>> classify_param("count", {"type": "integer"})
    <ParamClass.INTEGER: 'integer'>
    >>> classify_param("payload", {"type": "string"})
    <ParamClass.FUZZ: 'fuzz'>
    >>> classify_param("flag", {"type": "boolean"})
    <ParamClass.BOOLEAN: 'boolean'>
    """
    if schema is None:
        schema = {}

    # 1. Explicit format hint — strongest signal.
    fmt = schema.get("format")
    if isinstance(fmt, str):
        hit = _FORMAT_TO_CLASS.get(fmt.lower())
        if hit is not None:
            return hit

    # 2. Pattern hint — caller wrote a URL-shaped regex.
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and _URL_PATTERN_RE.search(pattern):
        return ParamClass.URL

    # 3. Name keyword match — case-insensitive substring.
    name_lower = name.lower()
    for needle, cls in _NAME_KEYWORDS:
        if needle in name_lower:
            return cls

    # 4. Fallback by type.
    type_ = schema.get("type")
    if isinstance(type_, str):
        hit = _TYPE_TO_FALLBACK.get(type_)
        if hit is not None:
            return hit
    elif isinstance(type_, list):
        # JSON Schema allows ``type: ["string", "null"]``. Pick the
        # first non-null we recognise.
        for t in type_:
            if isinstance(t, str) and t != "null":
                fb = _TYPE_TO_FALLBACK.get(t)
                if fb is not None:
                    return fb

    return ParamClass.UNKNOWN
