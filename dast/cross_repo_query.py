"""DAST-303 — Signature → cross-repo search-query mapping.

Translates a :class:`dast.variant_analysis.SemanticSignature` (Phase D's
abstracted exploit shape) into a
:class:`dast.code_index.SearchQuery` that a code-index backend can
execute.

Pure function — no network. The translation is signature-class-aware:
each attack class has its own query template that captures the
distinctive sink + missing-guard pattern in a way the chosen backend
can match.

For v1, we ship mappings for:
  * ssrf — sink_kind=network_fetch, looking for bare URL → fetch calls
  * injection — sink_kind in {shell_exec, sql_query}, looking for
    user-input → eval / system / execute callsites
  * path_traversal — sink_kind=file_read|file_write with user-input
    path component

Remaining attack classes (deserialization / prompt_injection /
credentials / authz / crypto / exfiltration) get a generic-text
fallback query that targets the sink_callee literal — less precise
but better than no candidates. Phase 2 of DAST-303 adds dedicated
mappings.

Public API:

  build_search_query(
      signature: SemanticSignature,
      *,
      backend: str = "github",
      max_results: int = 30,
      repo_filter: str = "",
  ) -> SearchQuery

  build_search_query_unsupported_reason(signature) -> str | None
      Returns a human-readable reason when the signature is too
      under-specified for a useful cross-repo query. None means
      "go ahead and search."
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from dast.code_index import ReposSearchQuery, SearchQuery

log = logging.getLogger("argus.dast.cross_repo_query")


# ── Language inference ───────────────────────────────────────────────


@dataclass
class _LanguageHint:
    """Mapping from seed file extension to (GitHub language filter,
    file-extension constraint)."""

    github_language: str  # value for the language: filter
    file_extension: str = ""  # extension: filter; empty = don't constrain


_LANGUAGE_BY_EXT: dict[str, _LanguageHint] = {
    ".py": _LanguageHint("python", "py"),
    ".ts": _LanguageHint("typescript", "ts"),
    ".tsx": _LanguageHint("typescript", "tsx"),
    ".js": _LanguageHint("javascript", "js"),
    ".mjs": _LanguageHint("javascript", "mjs"),
    ".jsx": _LanguageHint("javascript", "jsx"),
    ".go": _LanguageHint("go", "go"),
    ".rb": _LanguageHint("ruby", "rb"),
    ".rs": _LanguageHint("rust", "rs"),
    ".java": _LanguageHint("java", "java"),
}


def _infer_language(seed_file_name: str) -> _LanguageHint | None:
    """Map seed filename to a language hint. Empty when the
    extension isn't in our supported list."""
    lower = seed_file_name.lower()
    for ext, hint in _LANGUAGE_BY_EXT.items():
        if lower.endswith(ext):
            return hint
    return None


# ── Query builders per attack class ──────────────────────────────────


def _ssrf_query_body(sig: Any) -> str:
    """SSRF: bare URL argument flowing into a network primitive.

    Strategy: search for the literal sink_callee (e.g., ``urlopen``
    or ``fetch``). GitHub's REST code search doesn't support regex,
    so we can't express "fetch(arg) where arg is a parameter" — we
    rely on the language filter + downstream L1 triage to reject
    non-vulnerable callsites (hardcoded URLs, validated inputs, etc.)
    """
    callee = (sig.sink_callee or "").split(".")[-1].strip()
    if not callee:
        # Fall back to the attack-class-level keyword search.
        return "ssrf url request"
    return callee


def _injection_query_body(sig: Any) -> str:
    """Injection: user input → eval/exec/system/execute. Search the
    sink callee literal."""
    callee = (sig.sink_callee or "").split(".")[-1].strip()
    if not callee:
        if sig.attack_class == "command_injection":
            return "subprocess shell"
        if sig.attack_class == "sql_injection":
            return "execute query"
        return "eval exec injection"
    return callee


def _path_traversal_query_body(sig: Any) -> str:
    """Path traversal: user-controlled path into filesystem op."""
    callee = (sig.sink_callee or "").split(".")[-1].strip()
    if not callee:
        return "open read_text path traversal"
    return callee


def _deserialization_query_body(sig: Any) -> str:
    """Untrusted bytes → deserializer."""
    callee = (sig.sink_callee or "").split(".")[-1].strip()
    if not callee:
        return "pickle loads yaml load"
    return callee


def _generic_query_body(sig: Any) -> str:
    """Fallback for attack classes without a dedicated query template.

    Uses the sink_callee literal if available, otherwise a small
    keyword bag derived from attack_class + cwe. Less precise than a
    dedicated template; downstream L1 triage will filter."""
    callee = (sig.sink_callee or "").split(".")[-1].strip()
    if callee:
        return callee
    return (sig.attack_class or "vulnerability").replace("_", " ")


_QUERY_BUILDERS = {
    "ssrf": _ssrf_query_body,
    "command_injection": _injection_query_body,
    "sql_injection": _injection_query_body,
    "code_injection": _injection_query_body,
    "path_traversal": _path_traversal_query_body,
    "insecure_deserialization": _deserialization_query_body,
    # Generic fallback covers prompt_injection / xss / hardcoded_credentials /
    # auth_bypass / crypto_weakness / data_exfiltration / other. The query
    # body is just the sink_callee literal; the downstream L1 triage does
    # the heavy lifting.
}


# ── SCAN-1.5 context-keyword inference ───────────────────────────────


#: Keyword bag biasing the search toward AI-tool packages. Used when
#: the signature's source_shape mentions LLM/agent/tool/MCP context —
#: covers the LangChain disclosure case and similar AI-tooling
#: ecosystems (LlamaIndex, agent toolkits, MCP servers).
_AI_TOOL_KEYWORDS: tuple[str, ...] = (
    "langchain",
    "llama",
    "agent",
    "openai",
    "anthropic",
    "mcp",
    "tool",
    "llm",
)

#: Markers in source_shape (case-insensitive substring) that trigger
#: the AI-tool keyword bag.
_AI_TOOL_MARKERS: tuple[str, ...] = (
    "llm",
    "agent",
    "tool",
    "mcp",
    "ai",
    "model",
    "chain",
)


def _infer_context_keywords(signature: Any) -> tuple[str, ...]:
    """Map a signature to a context-keyword bag for the search.
    Returns ``()`` when no biasing context is detectable — in that
    case the query stays broad.

    v1 heuristics:
      * If ``source_shape`` mentions LLM / agent / tool / MCP / model /
        chain → use AI-tool bag. Catches the LangChain SSRF case
        directly (its source_shape contains "LLM-supplied URL").
      * If ``attack_class`` is ``prompt_injection`` → also AI-tool bag
        (prompt injection requires an LLM consumer by definition).
      * Otherwise → ``()`` (no extra keywords).

    Operators who want a different bias pass ``context_keywords=``
    explicitly to ``build_search_query`` — the inferred bag is only
    used when the caller doesn't override.
    """
    if not signature:
        return ()
    if (signature.attack_class or "").strip() == "prompt_injection":
        return _AI_TOOL_KEYWORDS
    source = (signature.source_shape or "").lower()
    if any(marker in source for marker in _AI_TOOL_MARKERS):
        return _AI_TOOL_KEYWORDS
    return ()


def build_search_query_unsupported_reason(signature: Any) -> str | None:
    """Check whether the signature has enough fidelity for a useful
    cross-repo search. Returns a reason string if not, ``None`` if OK
    to proceed.

    We refuse to build a query when:
      * The signature has no sink_callee AND no attack_class (too
        generic — query would match nothing or everything).
      * The signature is for an attack class our backend can't
        constrain by language (e.g., a polyglot file).
    """
    if not signature:
        return "signature_missing"
    if not signature.sink_callee and not signature.attack_class:
        return "signature_too_generic"
    return None


def build_search_query(
    signature: Any,
    *,
    seed_file_name: str = "",
    backend: str = "github",
    max_results: int = 30,
    repo_filter: str = "",
    path_glob: str = "",
    min_stars: int = 0,
    context_keywords: tuple[str, ...] | None = None,
) -> SearchQuery:
    """Construct a code-search query from a Phase D signature.

    Args:
      signature: a :class:`dast.variant_analysis.SemanticSignature`.
      seed_file_name: the seed's filename, used to infer language +
        extension filters. When empty, the query goes language-
        agnostic (more candidates, more noise).
      backend: backend name. v1 only supports ``"github"``; the
        argument is here for v2 extension to Sourcegraph / npm.
      max_results: bound the candidate set.
      repo_filter: optional repo / org filter (passed verbatim to
        the backend — e.g., ``"user:langchain-ai"`` or
        ``"repo:facebook/react"``).
      path_glob: optional path filter (e.g., ``src/tools/**``).
      min_stars: SCAN-1.5 quality lift — minimum stars threshold for
        candidate repos. Default 10 weeds out one-person 0-star toy
        projects. Set to 0 to disable the filter (long-tail hunting
        e.g., for disclosure researchers wanting comprehensive
        coverage).
      context_keywords: SCAN-1.5 quality lift — explicit context bias
        keywords. When ``None`` (default), the function auto-infers
        from the signature: AI-tool keyword bag for prompt_injection
        and signatures whose ``source_shape`` mentions LLM / agent /
        tool / MCP / model / chain. Explicit ``()`` disables auto-
        inference (broad search). Operators with a specific ecosystem
        target pass their own tuple.

    Raises:
      ValueError: when ``build_search_query_unsupported_reason``
      would have returned non-None — callers should check first.
    """
    reason = build_search_query_unsupported_reason(signature)
    if reason:
        raise ValueError(
            f"DAST-303 cannot build a search query: {reason}. "
            f"Signature: attack_class={signature.attack_class!r}, "
            f"sink_callee={signature.sink_callee!r}"
        )

    if backend != "github":
        raise NotImplementedError(
            f"DAST-303 backend {backend!r} not implemented in v1. "
            f"Only 'github' is supported; see "
            f"docs/dast_303_cross_repo_design.md."
        )

    builder = _QUERY_BUILDERS.get(signature.attack_class, _generic_query_body)
    raw_query = builder(signature)

    language_hint = _infer_language(seed_file_name)
    language = language_hint.github_language if language_hint else ""

    # SCAN-1.5 context-keyword inference. Caller can override with
    # explicit ``context_keywords=`` (including ``()`` to disable).
    if context_keywords is None:
        effective_keywords = _infer_context_keywords(signature)
    else:
        effective_keywords = context_keywords

    # Defensive exclusions baked into every DAST-303 query.
    # These mirror dast.code_graph.EXCLUDED_DIR_NAMES — directories
    # we never want as DAST-303 candidates because they're vendored
    # or generated code.
    # Add them as -path: exclusions appended to raw_query.
    excludes = [
        "-path:node_modules",
        "-path:vendor",
        "-path:dist",
        "-path:build",
        "-path:test",
        "-path:tests",
        "-path:__tests__",
        "-path:spec",
        "-path:specs",
        "-path:__pycache__",
        "-path:.venv",
        "-path:venv",
        "-path:site-packages",
    ]
    raw_query_with_excludes = " ".join([raw_query, *excludes])

    return SearchQuery(
        raw_query=raw_query_with_excludes,
        language=language,
        path_glob=path_glob,
        repo_filter=repo_filter,
        max_results=max_results,
        include_text_matches=False,
        min_stars=min_stars,
        context_keywords=effective_keywords,
    )


# ── Slice 1.7 — signature → ReposSearchQuery inference ───────────────


#: AI-tool topic bag for ``/search/repositories``. Matches the
#: ``topics:`` qualifier (GitHub repos can tag themselves with these).
#: Different from ``_AI_TOOL_KEYWORDS`` (which is for substring
#: matching against repo names/descriptions) — topic tags are
#: explicit declarations by the maintainer, so the bag is tighter.
#:
#: HARD CAP: GitHub's ``/search/repositories`` allows AT MOST 5
#: AND/OR/NOT operators per query. We need: (N-1) ORs across topics +
#: 1 AND for language + 1 AND for min_stars. So topics ≤ 4 keeps us
#: at the limit with language + min_stars enabled. Beyond 4 topics,
#: GitHub returns HTTP 422 "More than five AND / OR / NOT operators
#: were used."
#:
#: Bag composition: ``llm`` + ``agent`` + ``langchain`` covers the
#: bulk of the AI-tool TS/JS ecosystem (LangChain.js, LlamaIndex.ts,
#: agent toolkits, etc.). ``mcp`` covers the Model Context Protocol
#: tooling ecosystem (Anthropic + community MCP server repos).
_AI_TOOL_TOPICS: tuple[str, ...] = (
    "llm",
    "agent",
    "langchain",
    "mcp",
)


#: AI-tool description-keyword bag — broader net than topics. Many
#: relevant repos don't tag themselves with topics but mention the
#: ecosystem in their description.
#:
#: NOT used by default in ``infer_discovery_query`` — adding a second
#: OR group blows the 5-operator budget. Operators wanting broader
#: discovery can pass their own ``ReposSearchQuery(description_
#: keywords=...)`` with topics=() to use this bag instead.
_AI_TOOL_DESCRIPTION_KEYWORDS: tuple[str, ...] = (
    "langchain",
    "agent",
    "llm",
)


def infer_discovery_query(
    signature: Any,
    *,
    seed_file_name: str = "",
    min_stars: int = 100,
    max_results: int = 10,
) -> ReposSearchQuery | None:
    """Slice 1.7 — map a Phase D signature to a ``ReposSearchQuery``.

    Used by the two-phase cross-repo discovery flow
    (``GitHubCodeSearchClient.discover_and_search``) to find
    high-star ecosystem repos relevant to the seed before code-
    searching within each.

    Returns ``None`` when the signature doesn't carry enough
    context-class signal to bias the repo search — in that case the
    caller should fall back to a plain ``search()`` (broad code
    search without ecosystem targeting) or require an explicit
    ``repo_filter``.

    v1 heuristics:
      * LLM/agent/tool/MCP context (via ``source_shape`` markers) OR
        ``prompt_injection`` attack_class → AI-tool topics +
        description keywords.
      * Other signatures → return ``None``. v2 will add web-framework
        topics for HTTP-form SSRF, ORM topics for SQL injection in
        web stacks, etc., once the LangChain SSRF flow is validated
        end-to-end.

    Args:
      signature: a :class:`SemanticSignature`.
      seed_file_name: used to derive the language filter.
      min_stars: minimum stars for target repos. Default 100 = real
        ecosystem repo, not toy project. Operators wanting tighter
        scoping bump to 1000+; long-tail hunters drop to 10.
      max_results: cap on target repos returned. Default 10 keeps
        the subsequent per-repo code search bounded.
    """
    if not signature:
        return None

    # Reuse the same AI-context detection as the code-search
    # context-keyword inference — keeps the two heuristics in sync.
    context_keywords = _infer_context_keywords(signature)
    if not context_keywords:
        # No AI-tool context AND no other ecosystem mapping yet → bail.
        # Caller can fall back to plain search() with an explicit
        # repo_filter, or skip cross-repo entirely.
        return None

    language_hint = _infer_language(seed_file_name)
    language = language_hint.github_language if language_hint else ""

    return ReposSearchQuery(
        topics=_AI_TOOL_TOPICS,
        language=language,
        min_stars=min_stars,
        # description_keywords stays empty by default: combining it
        # with topics overflows GitHub's 5-operator query budget.
        # Topics alone are precise enough for AI-tool discovery.
        description_keywords=(),
        max_results=max_results,
    )


__all__ = [
    "build_search_query",
    "build_search_query_unsupported_reason",
    "infer_discovery_query",
]
