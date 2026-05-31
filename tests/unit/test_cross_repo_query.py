"""DAST-303 Slice 1 — unit tests for the signature → search-query
mapping. Pure-function tests; no network."""

from __future__ import annotations

import pytest

from dast.code_index import ReposSearchQuery
from dast.cross_repo_query import (
    build_search_query,
    build_search_query_unsupported_reason,
    infer_discovery_query,
)
from dast.variant_analysis import SemanticSignature


def _sig(**kwargs) -> SemanticSignature:
    """Build a SemanticSignature with sensible test defaults."""
    defaults = dict(
        attack_class="ssrf",
        cwe="CWE-918",
        source_shape="LLM-supplied URL",
        sink_kind="network_fetch",
        sink_callee="fetch",
        missing_guards=["URL.protocol allowlist", "IP filter"],
        seed_function="fetch_url",
        seed_finding_id="H001",
    )
    defaults.update(kwargs)
    return SemanticSignature(**defaults)


# ── unsupported-reason gate ──────────────────────────────────────────


def test_unsupported_reason_returns_none_for_well_formed_signature() -> None:
    """A fully-populated SSRF signature is searchable."""
    assert build_search_query_unsupported_reason(_sig()) is None


def test_unsupported_reason_flags_missing_signature() -> None:
    """``None`` signature can't be searched — caller should bail."""
    assert build_search_query_unsupported_reason(None) == "signature_missing"


def test_unsupported_reason_flags_signature_too_generic() -> None:
    """No attack_class + no sink_callee = nothing to search for."""
    sig = _sig(attack_class="", sink_callee="")
    assert build_search_query_unsupported_reason(sig) == "signature_too_generic"


# ── SSRF mapping ─────────────────────────────────────────────────────


def test_ssrf_signature_emits_sink_callee_as_raw_query() -> None:
    """``fetch`` sink → query body starts with the sink callee.
    Downstream filtering happens via L1 triage; the query just needs
    to be specific enough to surface the right files."""
    q = build_search_query(_sig(), seed_file_name="webbrowser.ts", max_results=10)
    assert q.raw_query.startswith("fetch ")
    assert q.language == "typescript"
    assert q.max_results == 10


def test_ssrf_signature_with_dotted_sink_callee_uses_last_segment() -> None:
    """``urllib.request.urlopen`` should yield ``urlopen``, not the
    full dotted path (GitHub code search treats dots as token
    separators)."""
    sig = _sig(sink_callee="urllib.request.urlopen")
    q = build_search_query(sig, seed_file_name="app.py", max_results=5)
    assert q.raw_query.startswith("urlopen ")
    assert q.language == "python"


def test_ssrf_signature_with_empty_sink_callee_falls_back_to_keywords() -> None:
    """If the LLM's signature extraction returned an empty
    sink_callee, we still produce a query (using attack-class
    keywords as fallback)."""
    sig = _sig(sink_callee="")
    q = build_search_query(sig, seed_file_name="webbrowser.ts")
    # Falls back to ssrf-keyword bag — must include "ssrf"
    # to surface relevant candidates.
    assert "ssrf" in q.raw_query.lower()


# ── Injection / path-traversal mapping ───────────────────────────────


def test_command_injection_signature_emits_sink_callee() -> None:
    sig = _sig(
        attack_class="command_injection", sink_kind="shell_exec", sink_callee="run"
    )
    q = build_search_query(sig, seed_file_name="util.py")
    assert q.raw_query.startswith("run ")


def test_sql_injection_signature_falls_back_to_execute_query() -> None:
    """Without a sink_callee, sql_injection falls back to
    ``execute query`` keyword bag."""
    sig = _sig(
        attack_class="sql_injection", sink_kind="sql_query", sink_callee=""
    )
    q = build_search_query(sig, seed_file_name="db.py")
    assert "execute" in q.raw_query


def test_path_traversal_signature_uses_sink_callee() -> None:
    sig = _sig(
        attack_class="path_traversal",
        sink_kind="file_read",
        sink_callee="send_from_directory",
    )
    q = build_search_query(sig, seed_file_name="routes.py")
    assert q.raw_query.startswith("send_from_directory ")


def test_deserialization_signature_uses_sink_callee() -> None:
    sig = _sig(
        attack_class="insecure_deserialization",
        sink_kind="deserialize",
        sink_callee="loads",
    )
    q = build_search_query(sig, seed_file_name="rpc.py")
    assert q.raw_query.startswith("loads ")


def test_generic_fallback_for_unmapped_attack_class() -> None:
    """Attack classes without a dedicated mapping (e.g.,
    ``hardcoded_credentials``) use the sink_callee literal."""
    sig = _sig(
        attack_class="hardcoded_credentials",
        sink_kind="other",
        sink_callee="API_KEY",
    )
    q = build_search_query(sig, seed_file_name="settings.py")
    assert q.raw_query.startswith("API_KEY")


# ── Language inference ───────────────────────────────────────────────


def test_language_inferred_from_seed_filename() -> None:
    """Each supported extension maps to its GitHub language filter."""
    cases = [
        ("foo.py", "python"),
        ("bar.ts", "typescript"),
        ("baz.tsx", "typescript"),
        ("qux.js", "javascript"),
        ("quux.mjs", "javascript"),
        ("Service.java", "java"),
        ("main.go", "go"),
        ("script.rb", "ruby"),
        ("lib.rs", "rust"),
    ]
    for name, expected_lang in cases:
        q = build_search_query(_sig(), seed_file_name=name)
        assert q.language == expected_lang, (
            f"{name} should infer language={expected_lang!r}, "
            f"got {q.language!r}"
        )


def test_language_filter_empty_for_unknown_extension() -> None:
    """Unknown extensions don't constrain language — falls back to
    a broader cross-language search."""
    q = build_search_query(_sig(), seed_file_name="weird.zz")
    assert q.language == ""


def test_no_seed_filename_means_no_language_filter() -> None:
    """An empty seed_file_name produces a language-agnostic query."""
    q = build_search_query(_sig(), seed_file_name="")
    assert q.language == ""


# ── Exclusion patterns ───────────────────────────────────────────────


def test_query_always_excludes_node_modules_and_friends() -> None:
    """Every DAST-303 query must exclude vendored / build / test
    directories — they pollute the candidate set with non-disclosure-
    worthy duplicates."""
    q = build_search_query(_sig(), seed_file_name="app.py")
    for excluded in (
        "-path:node_modules",
        "-path:vendor",
        "-path:dist",
        "-path:build",
        "-path:test",
        "-path:__pycache__",
    ):
        assert excluded in q.raw_query, (
            f"Query is missing standard exclusion {excluded!r}: "
            f"{q.raw_query!r}"
        )


# ── Repo filter / path glob ──────────────────────────────────────────


def test_repo_filter_propagates() -> None:
    """``user:langchain-ai`` filter passed through to the SearchQuery
    so operators can restrict to one org."""
    q = build_search_query(
        _sig(),
        seed_file_name="webbrowser.ts",
        repo_filter="user:langchain-ai",
    )
    assert q.repo_filter == "user:langchain-ai"


def test_path_glob_propagates() -> None:
    q = build_search_query(
        _sig(),
        seed_file_name="webbrowser.ts",
        path_glob="src/tools/**",
    )
    assert q.path_glob == "src/tools/**"


def test_max_results_propagates() -> None:
    q = build_search_query(_sig(), seed_file_name="app.py", max_results=42)
    assert q.max_results == 42


# ── Backend selection ────────────────────────────────────────────────


def test_unsupported_backend_raises_not_implemented() -> None:
    """v1 only supports ``github``. Other backends are scoped for
    v2; explicit error keeps us honest."""
    with pytest.raises(NotImplementedError, match="not implemented in v1"):
        build_search_query(_sig(), backend="sourcegraph")


# ── Edge: signature gate ─────────────────────────────────────────────


def test_too_generic_signature_raises_value_error() -> None:
    """Caller failed to gate via unsupported_reason; build_search_query
    raises so the bug surfaces at the API boundary."""
    sig = _sig(attack_class="", sink_callee="")
    with pytest.raises(ValueError, match="signature_too_generic"):
        build_search_query(sig, seed_file_name="x.py")


# ── SCAN-1.5: min_stars threshold ────────────────────────────────────


def test_default_min_stars_is_0_pending_slice_1_6_enrichment() -> None:
    """min_stars defaults to 0 (no filtering) because GitHub's
    /search/code returns a truncated repository object without
    stargazers_count — every candidate has repo_stargazers=0
    regardless of true star count. Slice 1.6 will enrich via
    /repos/{owner}/{name} and then min_stars > 0 becomes meaningful;
    until then the default stays at 0 so the filter doesn't silently
    drop everything."""
    q = build_search_query(_sig(), seed_file_name="webbrowser.ts")
    assert q.min_stars == 0


def test_explicit_min_stars_propagates() -> None:
    """Operators who want long-tail coverage drop to 0; security-
    focused scans bump to 100 or 1000."""
    q = build_search_query(_sig(), seed_file_name="x.py", min_stars=0)
    assert q.min_stars == 0
    q2 = build_search_query(_sig(), seed_file_name="x.py", min_stars=500)
    assert q2.min_stars == 500


# ── SCAN-1.5: context-keyword inference ──────────────────────────────


def test_ssrf_signature_with_llm_source_shape_infers_ai_tool_keywords() -> None:
    """The LangChain SSRF signature has source_shape mentioning 'LLM'
    — should auto-infer AI-tool keywords to bias the search toward
    AI ecosystems."""
    sig = _sig(source_shape="LLM-supplied URL string passed via tool input")
    q = build_search_query(sig, seed_file_name="webbrowser.ts")
    # Auto-inferred bag includes langchain + the rest.
    assert "langchain" in q.context_keywords
    assert "agent" in q.context_keywords
    assert "openai" in q.context_keywords


def test_ssrf_signature_without_ai_context_has_no_keywords() -> None:
    """A generic SSRF (e.g., user-supplied URL from an HTTP form)
    shouldn't get the AI-tool bias — broad SSRF hunt is better
    when there's no AI context in the seed."""
    sig = _sig(source_shape="user-supplied URL from HTTP form parameter")
    q = build_search_query(sig, seed_file_name="form.py")
    assert q.context_keywords == ()


def test_prompt_injection_signature_always_gets_ai_keywords() -> None:
    """Prompt injection REQUIRES an LLM consumer by definition —
    every cross-repo hunt for this class should be ecosystem-
    biased even when source_shape is sparse."""
    sig = _sig(attack_class="prompt_injection", source_shape="")
    q = build_search_query(sig, seed_file_name="agent.py")
    assert "langchain" in q.context_keywords


def test_explicit_context_keywords_override_inference() -> None:
    """Operator passes their own ecosystem bias (e.g., specific
    framework). Inference is suppressed."""
    sig = _sig(source_shape="LLM-supplied URL")  # would auto-infer AI
    q = build_search_query(
        sig,
        seed_file_name="webbrowser.ts",
        context_keywords=("nextjs", "express"),
    )
    assert q.context_keywords == ("nextjs", "express")


def test_empty_context_keywords_disables_inference() -> None:
    """Passing ``()`` explicitly means 'no biasing keywords' even
    when the signature would otherwise auto-infer."""
    sig = _sig(source_shape="LLM-supplied URL")
    q = build_search_query(
        sig,
        seed_file_name="webbrowser.ts",
        context_keywords=(),
    )
    assert q.context_keywords == ()


def test_marker_match_is_case_insensitive() -> None:
    """source_shape uses arbitrary casing — inference must match
    'LLM', 'llm', 'Llm', etc."""
    for source_shape in (
        "LLM-supplied URL",
        "llm-supplied url",
        "Agent tool input",
        "MCP-derived path",
    ):
        sig = _sig(source_shape=source_shape)
        q = build_search_query(sig, seed_file_name="x.py")
        assert q.context_keywords, (
            f"Expected AI keywords inferred for source_shape={source_shape!r}"
        )


# ── Slice 1.7: infer_discovery_query (signature → ReposSearchQuery) ──


def test_infer_discovery_query_returns_none_for_no_signature() -> None:
    """No signature → no discovery hint. Caller falls back to a
    plain code search or skips cross-repo entirely."""
    assert infer_discovery_query(None) is None


def test_infer_discovery_query_returns_none_for_non_ai_signature() -> None:
    """A generic HTTP-form SSRF (no AI context) doesn't get a
    repos-query yet — v1 only ships AI-tool topic mapping. Returns
    None so the caller knows to fall back."""
    sig = _sig(source_shape="user-supplied URL from HTTP form parameter")
    result = infer_discovery_query(sig, seed_file_name="form.py")
    assert result is None


def test_infer_discovery_query_emits_ai_topics_for_llm_signature() -> None:
    """LangChain SSRF case: signature has LLM-context source_shape →
    inferred ReposSearchQuery targets AI-tool topics + language from
    seed filename. Description keywords stay empty by default (adding
    them would blow GitHub's 5-operator query budget)."""
    sig = _sig(
        source_shape="LLM-supplied URL string passed via the tool's input"
    )
    result = infer_discovery_query(sig, seed_file_name="webbrowser.ts")

    assert isinstance(result, ReposSearchQuery)
    # AI-tool topics include the LangChain ecosystem terms.
    assert "llm" in result.topics
    assert "langchain" in result.topics
    assert "agent" in result.topics
    # Topic bag must stay ≤ 4 (HARD CAP — GitHub's 5-operator limit
    # leaves 4 ORs once language + min_stars consume the 2 ANDs).
    assert len(result.topics) <= 4
    # No description keywords in the default — operators wanting them
    # construct a ReposSearchQuery manually.
    assert result.description_keywords == ()
    # Seed filename drives the language filter.
    assert result.language == "typescript"
    # Default min_stars (100) and max_results (10) for "real ecosystem
    # repo" scoping.
    assert result.min_stars == 100
    assert result.max_results == 10


def test_infer_discovery_query_emits_ai_topics_for_prompt_injection() -> None:
    """Prompt injection REQUIRES an LLM consumer by definition — get
    the AI-tool topic bag even when source_shape is sparse."""
    sig = _sig(attack_class="prompt_injection", source_shape="")
    result = infer_discovery_query(sig, seed_file_name="agent.py")
    assert result is not None
    assert "llm" in result.topics
    assert result.language == "python"


def test_infer_discovery_query_respects_explicit_min_stars() -> None:
    """Operators wanting tighter scoping pass min_stars=1000."""
    sig = _sig(source_shape="LLM-supplied URL")
    result = infer_discovery_query(
        sig, seed_file_name="x.ts", min_stars=1000
    )
    assert result is not None
    assert result.min_stars == 1000


def test_infer_discovery_query_respects_explicit_max_results() -> None:
    """Operators wanting broader / narrower hunts bump max_results."""
    sig = _sig(source_shape="LLM-supplied URL")
    result = infer_discovery_query(
        sig, seed_file_name="x.ts", max_results=25
    )
    assert result is not None
    assert result.max_results == 25


def test_infer_discovery_query_no_seed_filename_means_no_language() -> None:
    """No seed filename → language stays empty (language-agnostic
    discovery)."""
    sig = _sig(source_shape="LLM-supplied URL")
    result = infer_discovery_query(sig, seed_file_name="")
    assert result is not None
    assert result.language == ""
