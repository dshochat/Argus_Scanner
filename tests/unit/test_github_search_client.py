"""DAST-303 Slice 1 — unit tests for the GitHub Code Search client.
Verifies pure-function pieces: query-string composition, result
normalization, rate-limit timing math. No network calls — the live
search lives in tests/integration/."""

from __future__ import annotations

import pytest

from dast.code_index import CandidateFile
from dast.code_index.github_search import (
    GitHubCodeSearchClient,
    GitHubSearchError,
    ReposSearchQuery,
    SearchQuery,
)


def _client() -> GitHubCodeSearchClient:
    return GitHubCodeSearchClient(token="ghp_fake_test_token")


# ── Constructor / auth ───────────────────────────────────────────────


def test_constructor_requires_non_empty_token() -> None:
    with pytest.raises(GitHubSearchError, match="non-empty token"):
        GitHubCodeSearchClient(token="")


def test_from_env_raises_when_token_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(GitHubSearchError, match="GITHUB_TOKEN env var"):
        GitHubCodeSearchClient.from_env()


def test_from_env_raises_when_token_empty_string(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whitespace-only token is treated as unset — operators sometimes
    paste a literal space and don't notice."""
    monkeypatch.setenv("GITHUB_TOKEN", "   ")
    with pytest.raises(GitHubSearchError, match="GITHUB_TOKEN env var"):
        GitHubCodeSearchClient.from_env()


def test_from_env_succeeds_when_token_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_real_token")
    client = GitHubCodeSearchClient.from_env()
    # Token is stored privately; can't directly inspect but no exception
    # is the contract.
    assert client._token == "ghp_real_token"


# ── Query-string composition ─────────────────────────────────────────


def test_query_string_has_only_raw_when_no_filters() -> None:
    # min_stars=0 because the default 10 would emit ``stars:>10``; we
    # assert the raw_query is the entire output when nothing else set.
    q = SearchQuery(raw_query="fetch", min_stars=0)
    assert _client()._build_query_string(q) == "fetch"


def test_query_string_appends_language_filter() -> None:
    q = SearchQuery(raw_query="fetch", language="typescript", min_stars=0)
    assert _client()._build_query_string(q) == "fetch language:typescript"


def test_query_string_appends_path_filter() -> None:
    q = SearchQuery(raw_query="fetch", path_glob="src/tools/**", min_stars=0)
    assert _client()._build_query_string(q) == "fetch path:src/tools/**"


def test_query_string_appends_repo_filter() -> None:
    """``repo_filter`` is passed verbatim so callers can use any
    GitHub qualifier syntax (``user:org``, ``repo:owner/name``,
    ``org:foo``, etc.) without the client re-formatting it."""
    q = SearchQuery(
        raw_query="fetch", repo_filter="user:langchain-ai", min_stars=0
    )
    assert _client()._build_query_string(q) == "fetch user:langchain-ai"


def test_query_string_combines_all_filters() -> None:
    q = SearchQuery(
        raw_query="fetch",
        language="typescript",
        path_glob="src/**",
        repo_filter="org:langchain-ai",
    )
    out = _client()._build_query_string(q)
    assert "fetch" in out
    assert "language:typescript" in out
    assert "path:src/**" in out
    assert "org:langchain-ai" in out


def test_query_string_strips_whitespace_from_raw() -> None:
    q = SearchQuery(raw_query="  fetch  ", language="typescript", min_stars=0)
    out = _client()._build_query_string(q)
    # Leading/trailing whitespace on raw_query gets stripped so the
    # final query is clean.
    assert out == "fetch language:typescript"


# ── Result normalization ─────────────────────────────────────────────


def test_normalize_item_extracts_repo_and_path() -> None:
    item = {
        "path": "src/tools/web/webbrowser.ts",
        "sha": "abc123_blob_sha",
        "html_url": (
            "https://github.com/langchain-ai/langchainjs/blob/main/"
            "libs/langchain-community/src/tools/web/webbrowser.ts"
        ),
        "repository": {
            "full_name": "langchain-ai/langchainjs",
            "stargazers_count": 15000,
            "fork": False,
            "description": "JavaScript port of the LangChain framework",
        },
    }
    cf = _client()._normalize_item(item)
    assert cf.repo_full_name == "langchain-ai/langchainjs"
    assert cf.file_path == "src/tools/web/webbrowser.ts"
    # ref is the COMMIT ref parsed from html_url (``main`` here), NOT
    # the blob SHA. Needed for reproducible tarball downloads of the
    # repo at the same snapshot the search indexed.
    assert cf.ref == "main"
    assert cf.repo_stargazers == 15000
    assert cf.repo_is_fork is False
    assert "LangChain" in cf.repo_description


def test_normalize_item_extracts_commit_sha_from_html_url() -> None:
    """When GitHub's search index pins to a specific commit SHA (the
    common case for fresh searches), the ref is that commit — not
    the blob hash."""
    item = {
        "path": "src/x.ts",
        "sha": "blobshasomething",
        "html_url": (
            "https://github.com/owner/repo/blob/"
            "f2a86e9a1d4eee825692f56be284e17f852ac5a7/src/x.ts"
        ),
        "repository": {"full_name": "owner/repo"},
    }
    cf = _client()._normalize_item(item)
    assert cf.ref == "f2a86e9a1d4eee825692f56be284e17f852ac5a7"


def test_normalize_item_falls_back_to_blob_sha_when_html_url_malformed() -> None:
    """Defense in depth: a malformed html_url (no /blob/ segment)
    falls back to the blob SHA. Tarball download might fail with this
    ref but at least we don't return an empty string."""
    item = {
        "path": "x.ts",
        "sha": "deadbeef",
        "html_url": "https://example.com/no-blob-here",
        "repository": {"full_name": "owner/repo"},
    }
    cf = _client()._normalize_item(item)
    assert cf.ref == "deadbeef"


def test_normalize_item_builds_raw_url_from_html_url() -> None:
    """``raw_url`` is constructed from ``html_url`` because the
    API doesn't return it directly. Pattern: replace ``github.com``
    with ``raw.githubusercontent.com`` and drop the ``/blob/``
    segment so the URL points to the raw file content."""
    item = {
        "path": "x.py",
        "sha": "deadbeef",
        "html_url": "https://github.com/owner/repo/blob/main/x.py",
        "repository": {"full_name": "owner/repo"},
    }
    cf = _client()._normalize_item(item)
    assert cf.raw_url == "https://raw.githubusercontent.com/owner/repo/main/x.py"


def test_normalize_item_captures_text_matches_when_present() -> None:
    item = {
        "path": "app.py",
        "sha": "x",
        "html_url": "https://github.com/o/r/blob/m/app.py",
        "repository": {"full_name": "o/r"},
        "text_matches": [
            {"fragment": "def fetch_url(url):\n    return urlopen(url)"},
            {"fragment": "    response = fetch_url(target)"},
        ],
    }
    cf = _client()._normalize_item(item)
    assert len(cf.text_matches) == 2
    assert "urlopen" in cf.text_matches[0]


def test_normalize_item_handles_missing_repo_fields_gracefully() -> None:
    """Malformed / partial API responses shouldn't crash the
    normalizer — fields default to empty / 0 / False."""
    item = {"path": "x.py", "sha": "x", "html_url": "https://example/x"}
    cf = _client()._normalize_item(item)
    assert cf.repo_full_name == ""
    assert cf.repo_stargazers == 0
    assert cf.repo_is_fork is False


# ── Rate-limit math ──────────────────────────────────────────────────


def test_wait_for_rate_reset_returns_60_when_header_missing() -> None:
    import httpx

    headers = httpx.Headers({})
    wait = GitHubCodeSearchClient._wait_for_rate_reset(headers)
    assert wait == 60.0


def test_wait_for_rate_reset_returns_60_when_header_unparseable() -> None:
    import httpx

    headers = httpx.Headers({"X-RateLimit-Reset": "not-a-number"})
    wait = GitHubCodeSearchClient._wait_for_rate_reset(headers)
    assert wait == 60.0


def test_wait_for_rate_reset_caps_at_5_minutes() -> None:
    """Beyond 5 minutes of waiting, callers should abort rather than
    blocking the whole scan."""
    import time

    import httpx

    far_future = int(time.time()) + 3600  # 1 hour out
    headers = httpx.Headers({"X-RateLimit-Reset": str(far_future)})
    wait = GitHubCodeSearchClient._wait_for_rate_reset(headers)
    assert wait <= 300.0


def test_wait_for_rate_reset_returns_positive_for_imminent_reset() -> None:
    """Reset is 10s in the future → wait ~10s (+jitter)."""
    import time

    import httpx

    soon = int(time.time()) + 10
    headers = httpx.Headers({"X-RateLimit-Reset": str(soon)})
    wait = GitHubCodeSearchClient._wait_for_rate_reset(headers)
    assert 9.0 <= wait <= 12.0


# ── Empty query guardrail ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_rejects_empty_raw_query() -> None:
    """An empty raw_query means the signature mapper didn't produce
    a search term. Refuse — running with only stars:>N / language:
    filters would return the entire top-starred ecosystem (millions
    of results, no useful signal)."""
    client = _client()
    q = SearchQuery(raw_query="")
    with pytest.raises(GitHubSearchError, match="empty raw_query"):
        await client.search(q)


# ── SCAN-1.5: min_stars + context_keywords — CLIENT-SIDE filters ────
#
# GitHub's REST /search/code doesn't support ``stars:`` or boolean
# OR clauses (those are repos-search qualifiers). Trying to use them
# returns HTTP 422. So min_stars + context_keywords are applied
# CLIENT-SIDE in _post_filter_candidates after results are fetched.


def test_query_string_does_not_emit_stars_qualifier() -> None:
    """min_stars filtering is client-side; the query string MUST NOT
    include a ``stars:`` qualifier (GitHub returns 422 if it does)."""
    q = SearchQuery(raw_query="fetch", min_stars=10)
    out = _client()._build_query_string(q)
    assert "stars:" not in out


def test_query_string_does_not_emit_or_clauses() -> None:
    """Boolean OR isn't supported in code search; context_keywords
    filtering is client-side."""
    q = SearchQuery(
        raw_query="fetch",
        context_keywords=("langchain", "agent", "openai"),
    )
    out = _client()._build_query_string(q)
    assert " OR " not in out
    assert "(" not in out


def _cf(
    repo_full_name: str,
    stars: int,
    description: str = "",
    is_fork: bool = False,
) -> CandidateFile:
    """Helper to build a CandidateFile for post-filter tests."""
    return CandidateFile(
        repo_full_name=repo_full_name,
        file_path="x.ts",
        ref="abc",
        html_url=f"https://github.com/{repo_full_name}/blob/m/x.ts",
        raw_url=f"https://raw.githubusercontent.com/{repo_full_name}/m/x.ts",
        repo_stargazers=stars,
        repo_is_fork=is_fork,
        repo_description=description,
    )


def test_post_filter_drops_below_min_stars() -> None:
    """min_stars=10 drops everything < 10 stars, keeps everything >=."""
    candidates = [
        _cf("o/below", 0),
        _cf("o/mid", 9),
        _cf("o/at", 10),
        _cf("o/above", 100),
    ]
    q = SearchQuery(raw_query="fetch", min_stars=10)
    filtered = _client()._post_filter_candidates(candidates, q)
    assert [c.repo_full_name for c in filtered] == ["o/at", "o/above"]


def test_post_filter_min_stars_zero_keeps_everything() -> None:
    """min_stars=0 disables the stars filter (long-tail coverage)."""
    candidates = [_cf("o/zero", 0), _cf("o/some", 5)]
    q = SearchQuery(raw_query="fetch", min_stars=0)
    filtered = _client()._post_filter_candidates(candidates, q)
    assert len(filtered) == 2


def test_post_filter_context_keywords_match_repo_name() -> None:
    """Keyword in repo full_name → keep. Tests the LangChain case:
    a candidate from ``langchain-ai/langchainjs`` should match the
    keyword ``langchain``."""
    candidates = [
        _cf("langchain-ai/langchainjs", 15000, ""),  # matches name
        _cf("random/something", 5000, ""),  # no match
        _cf("run-llama/llamaindex", 8000, "LLM data framework"),  # matches name+desc
    ]
    q = SearchQuery(
        raw_query="fetch",
        min_stars=0,
        context_keywords=("langchain", "llama"),
    )
    filtered = _client()._post_filter_candidates(candidates, q)
    assert [c.repo_full_name for c in filtered] == [
        "langchain-ai/langchainjs",
        "run-llama/llamaindex",
    ]


def test_post_filter_context_keywords_match_description() -> None:
    """Repo name doesn't include the keyword but description does
    — still a match. Useful for repos with generic names but
    AI-tool descriptions."""
    candidates = [
        _cf("foo/bar", 100, "A LangChain plugin for fetching URLs"),
        _cf("baz/qux", 100, "A generic web scraper"),
    ]
    q = SearchQuery(
        raw_query="fetch", min_stars=0, context_keywords=("langchain",)
    )
    filtered = _client()._post_filter_candidates(candidates, q)
    assert [c.repo_full_name for c in filtered] == ["foo/bar"]


def test_post_filter_context_keywords_case_insensitive() -> None:
    """Repo names + descriptions have arbitrary casing; the match
    must be case-insensitive."""
    candidates = [
        _cf("Open-AI/sdk", 1000, "OpenAI SDK"),  # mixed case name
        _cf("MyOrg/repo", 1000, "LangChain helper"),  # description-based
    ]
    q = SearchQuery(
        raw_query="fetch", min_stars=0, context_keywords=("openai", "langchain")
    )
    filtered = _client()._post_filter_candidates(candidates, q)
    assert len(filtered) == 2


def test_post_filter_context_keywords_empty_means_no_filter() -> None:
    candidates = [_cf("a/b", 100), _cf("c/d", 100, "random")]
    q = SearchQuery(raw_query="fetch", min_stars=0, context_keywords=())
    filtered = _client()._post_filter_candidates(candidates, q)
    assert len(filtered) == 2


def test_post_filter_combines_stars_and_keywords() -> None:
    """Both filters apply together (AND): must meet stars threshold
    AND contain a context keyword."""
    candidates = [
        _cf("a/no-stars-but-langchain", 0, "uses langchain"),  # below stars
        _cf("b/stars-but-no-context", 1000, ""),  # below context
        _cf("c/both", 500, "langchain wrapper"),  # both match
    ]
    q = SearchQuery(
        raw_query="fetch",
        min_stars=10,
        context_keywords=("langchain",),
    )
    filtered = _client()._post_filter_candidates(candidates, q)
    assert [c.repo_full_name for c in filtered] == ["c/both"]


# ── SCAN-1.5: client-side star sort ──────────────────────────────────


def test_normalize_then_sort_orders_by_stars_desc() -> None:
    """Direct test of the sort-key tuple — exercising the actual
    list.sort() call via the helper."""
    cf_low = _client()._normalize_item(
        {
            "path": "a.ts",
            "sha": "x",
            "html_url": "https://github.com/o/r1/blob/m/a.ts",
            "repository": {"full_name": "o/r1", "stargazers_count": 5},
        }
    )
    cf_high = _client()._normalize_item(
        {
            "path": "b.ts",
            "sha": "x",
            "html_url": "https://github.com/o/r2/blob/m/b.ts",
            "repository": {"full_name": "o/r2", "stargazers_count": 5000},
        }
    )
    cf_mid_fork = _client()._normalize_item(
        {
            "path": "c.ts",
            "sha": "x",
            "html_url": "https://github.com/o/r3/blob/m/c.ts",
            "repository": {
                "full_name": "o/r3",
                "stargazers_count": 100,
                "fork": True,
            },
        }
    )
    cf_mid_origin = _client()._normalize_item(
        {
            "path": "d.ts",
            "sha": "x",
            "html_url": "https://github.com/o/r4/blob/m/d.ts",
            "repository": {
                "full_name": "o/r4",
                "stargazers_count": 100,
                "fork": False,
            },
        }
    )

    candidates = [cf_low, cf_high, cf_mid_fork, cf_mid_origin]
    # This is the sort key the client.search() method uses.
    candidates.sort(key=lambda c: (-c.repo_stargazers, c.repo_is_fork))

    # Expected order: 5000 > 100 (origin) > 100 (fork) > 5
    assert [c.repo_full_name for c in candidates] == [
        "o/r2",
        "o/r4",
        "o/r3",
        "o/r1",
    ]


@pytest.mark.asyncio
async def test_search_oversamples_then_sorts_when_oversample_gt_1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``oversample_for_star_sort=2``, search fetches 2× the
    target, sorts by stars desc, returns the top ``max_results``.
    Crucial for the LangChain SSRF case where GitHub's default sort
    buries high-star repos under recent 0-star matches."""
    from dast.code_index import github_search

    # Build 6 fake API items with varying star counts.
    def make_item(name: str, stars: int) -> dict:
        return {
            "path": f"{name}.ts",
            "sha": "x",
            "html_url": f"https://github.com/o/{name}/blob/m/{name}.ts",
            "repository": {
                "full_name": f"o/{name}",
                "stargazers_count": stars,
                "fork": False,
            },
        }

    page_items = [
        make_item("repo_a", 0),
        make_item("repo_b", 1000),
        make_item("repo_c", 5),
        make_item("repo_d", 50000),
        make_item("repo_e", 25),
        make_item("repo_f", 200),
    ]

    async def fake_request_page(self, **kwargs):
        return {"total_count": 6, "items": page_items}

    async def fake_enrich(self, candidates, *, client=None):
        # No-op — the fixture already provides star counts via
        # _normalize_item. Real enrichment would re-hit GitHub
        # which we don't want in unit tests.
        for c in candidates:
            c.is_enriched = True
        return candidates

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "_request_page",
        fake_request_page,
    )
    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "enrich_candidates",
        fake_enrich,
    )

    client = _client()
    # target_return=3, oversample=2 → fetch_target=6 (all items),
    # then post-sort truncate to top 3.
    q = SearchQuery(
        raw_query="fetch",
        max_results=3,
        oversample_for_star_sort=2,
    )
    out = await client.search(q)

    # Top 3 by stars: 50000 > 1000 > 200
    assert [c.repo_stargazers for c in out] == [50000, 1000, 200]


# ── Slice 1.6: enrichment ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enrich_candidates_populates_star_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point of Slice 1.6: enrichment fills in
    ``stargazers_count`` that ``/search/code`` strips out."""
    from dast.code_index import CandidateFile, github_search

    async def fake_get_metadata(self, client, full_name):
        return {
            "stargazers_count": 15000,
            "fork": False,
            "description": "The LangChain framework",
            "topics": ["llm", "agent", "framework"],
            "license": {"spdx_id": "MIT"},
            "archived": False,
        }

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "_get_repo_metadata",
        fake_get_metadata,
    )

    cand = CandidateFile(
        repo_full_name="langchain-ai/langchainjs",
        file_path="x.ts",
        ref="abc",
        html_url="https://github.com/langchain-ai/langchainjs/blob/m/x.ts",
        raw_url="https://raw.githubusercontent.com/langchain-ai/langchainjs/m/x.ts",
    )
    assert cand.repo_stargazers == 0  # pre-enrichment
    assert cand.is_enriched is False

    out = await _client().enrich_candidates([cand])

    assert out[0].repo_stargazers == 15000
    assert out[0].repo_topics == ["llm", "agent", "framework"]
    assert out[0].repo_license == "MIT"
    assert out[0].repo_archived is False
    assert out[0].is_enriched is True


@pytest.mark.asyncio
async def test_enrich_candidates_dedupes_by_unique_repo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two candidates from the same repo should result in ONE API
    call, not two. Critical for cost — 50 candidates from 10 unique
    repos = 10 enrichment calls, not 50."""
    from dast.code_index import CandidateFile, github_search

    calls: list[str] = []

    async def fake_get_metadata(self, client, full_name):
        calls.append(full_name)
        return {"stargazers_count": 100, "fork": False, "topics": []}

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "_get_repo_metadata",
        fake_get_metadata,
    )

    cands = [
        CandidateFile(
            repo_full_name="o/repo1",
            file_path=f"file_{i}.ts",
            ref="x",
            html_url=f"https://github.com/o/repo1/blob/m/file_{i}.ts",
            raw_url=f"https://raw.githubusercontent.com/o/repo1/m/file_{i}.ts",
        )
        for i in range(3)
    ] + [
        CandidateFile(
            repo_full_name="o/repo2",
            file_path="other.ts",
            ref="x",
            html_url="https://github.com/o/repo2/blob/m/other.ts",
            raw_url="https://raw.githubusercontent.com/o/repo2/m/other.ts",
        ),
    ]

    await _client().enrich_candidates(cands)

    # 4 candidates across 2 unique repos = 2 enrichment calls.
    assert sorted(calls) == ["o/repo1", "o/repo2"]


@pytest.mark.asyncio
async def test_enrich_candidates_leaves_404_repo_unenriched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a repo was deleted/renamed after the search, the
    enrichment call returns None. The candidate stays at its
    default values (stars=0, is_enriched=False) so the caller can
    see the gap explicitly."""
    from dast.code_index import CandidateFile, github_search

    async def fake_get_metadata(self, client, full_name):
        return None  # simulates 404

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "_get_repo_metadata",
        fake_get_metadata,
    )

    cand = CandidateFile(
        repo_full_name="ghost/deleted",
        file_path="x.ts",
        ref="x",
        html_url="https://example/x.ts",
        raw_url="https://example/x.ts",
    )
    await _client().enrich_candidates([cand])

    assert cand.is_enriched is False
    assert cand.repo_stargazers == 0


@pytest.mark.asyncio
async def test_enrich_candidates_handles_missing_license_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repos without a declared license return ``license: null``.
    Don't crash — leave repo_license as empty string."""
    from dast.code_index import CandidateFile, github_search

    async def fake_get_metadata(self, client, full_name):
        return {"stargazers_count": 100, "fork": False, "license": None}

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "_get_repo_metadata",
        fake_get_metadata,
    )

    cand = CandidateFile(
        repo_full_name="o/r",
        file_path="x.ts",
        ref="x",
        html_url="https://example/x.ts",
        raw_url="https://example/x.ts",
    )
    await _client().enrich_candidates([cand])
    assert cand.repo_license == ""
    assert cand.is_enriched is True


@pytest.mark.asyncio
async def test_search_triggers_enrichment_when_min_stars_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """min_stars=5 means the operator wants star filtering; search
    MUST enrich first or every candidate gets dropped (truncated
    /search/code response always reports 0 stars)."""
    from dast.code_index import github_search

    enriched_called = []

    async def fake_request_page(self, **kwargs):
        return {
            "total_count": 1,
            "items": [
                {
                    "path": "x.ts",
                    "sha": "x",
                    "html_url": "https://github.com/o/r/blob/m/x.ts",
                    "repository": {"full_name": "o/r"},
                }
            ],
        }

    async def fake_enrich(self, candidates, *, client=None):
        enriched_called.append(len(candidates))
        for c in candidates:
            c.repo_stargazers = 1000
            c.is_enriched = True
        return candidates

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "_request_page",
        fake_request_page,
    )
    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "enrich_candidates",
        fake_enrich,
    )

    q = SearchQuery(
        raw_query="fetch",
        max_results=1,
        min_stars=5,
        oversample_for_star_sort=1,
    )
    out = await _client().search(q)

    assert len(enriched_called) == 1  # enrichment was called once
    # And the result has post-enrich stars.
    assert out[0].repo_stargazers == 1000


@pytest.mark.asyncio
async def test_search_skips_enrichment_when_no_quality_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When min_stars=0 AND oversample_for_star_sort=1, the caller
    doesn't need stars — skip the enrichment to save API quota."""
    from dast.code_index import github_search

    enriched_called = []

    async def fake_request_page(self, **kwargs):
        return {
            "total_count": 1,
            "items": [
                {
                    "path": "x.ts",
                    "sha": "x",
                    "html_url": "https://github.com/o/r/blob/m/x.ts",
                    "repository": {"full_name": "o/r"},
                }
            ],
        }

    async def fake_enrich(self, candidates, *, client=None):
        enriched_called.append(1)
        return candidates

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "_request_page",
        fake_request_page,
    )
    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "enrich_candidates",
        fake_enrich,
    )

    q = SearchQuery(
        raw_query="fetch",
        max_results=1,
        min_stars=0,
        oversample_for_star_sort=1,
    )
    await _client().search(q)
    assert enriched_called == []  # not called


@pytest.mark.asyncio
async def test_search_preserves_default_order_when_no_quality_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the caller opts out of all quality filters
    (``min_stars=0, oversample_for_star_sort=1``), the result order
    matches GitHub's default — preserves back-compat for callers
    that don't want the SCAN-1.5 sorting."""
    from dast.code_index import github_search

    api_order = [
        {"path": f"{i}.ts", "sha": "x",
         "html_url": f"https://github.com/o/repo_{i}/blob/m/{i}.ts",
         "repository": {"full_name": f"o/repo_{i}", "stargazers_count": 100 - i}}
        for i in range(5)
    ]

    async def fake_request_page(self, **kwargs):
        return {"total_count": 5, "items": api_order}

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "_request_page",
        fake_request_page,
    )

    client = _client()
    q = SearchQuery(
        raw_query="fetch",
        max_results=5,
        min_stars=0,
        oversample_for_star_sort=1,
    )
    out = await client.search(q)
    # GitHub's order preserved (descending star counts because we
    # built the fixture that way) — point is the API order, not
    # sorted by stars.
    assert [c.repo_full_name for c in out] == [
        f"o/repo_{i}" for i in range(5)
    ]


# ── Slice 1.7: ReposSearchQuery + two-phase discovery ───────────────


def test_repos_query_string_emits_single_topic_clause() -> None:
    q = ReposSearchQuery(topics=("llm",), min_stars=0)
    out = _client()._build_repos_query_string(q)
    assert out == "topic:llm"


def test_repos_query_string_emits_first_topic_when_no_override() -> None:
    """GitHub's repos search doesn't actually combine topics with OR
    (despite docs). ``_build_repos_query_string`` emits ONE topic per
    call; ``find_target_repos`` runs the per-topic loop. When no
    ``single_topic`` override is passed, the FIRST topic from the
    query is used."""
    q = ReposSearchQuery(topics=("llm", "agent", "langchain"), min_stars=0)
    out = _client()._build_repos_query_string(q)
    assert out == "topic:llm"
    # The other topics are NOT present — find_target_repos will run
    # additional queries for them.
    assert "topic:agent" not in out
    assert "topic:langchain" not in out
    # No OR clauses (broken on GitHub's side).
    assert " OR " not in out


def test_repos_query_string_honors_single_topic_override() -> None:
    """find_target_repos uses ``single_topic=`` to drive the per-topic
    loop. Override picks the topic regardless of tuple order."""
    q = ReposSearchQuery(topics=("llm", "agent", "langchain"), min_stars=0)
    out = _client()._build_repos_query_string(q, single_topic="agent")
    assert out == "topic:agent"


def test_repos_query_string_appends_language_and_min_stars() -> None:
    q = ReposSearchQuery(
        topics=("llm",), language="typescript", min_stars=100,
    )
    out = _client()._build_repos_query_string(q)
    assert "topic:llm" in out
    assert "language:typescript" in out
    assert "stars:>100" in out
    # Total operators: 0 ORs + 2 ANDs = 2 (well under GitHub's 5-op
    # limit). One-topic-at-a-time keeps headroom for the operator's
    # other qualifiers.


def test_repos_query_string_uses_first_description_keyword() -> None:
    """OR'ing ``in:description`` clauses returns 0 results on GitHub
    (same parser limitation as topics). We use the FIRST keyword as a
    plain text clause — GitHub does an implicit name+description
    match on bare text, which is what we want."""
    q = ReposSearchQuery(
        topics=(),
        description_keywords=("langchain", "agent"),
        min_stars=0,
    )
    out = _client()._build_repos_query_string(q)
    assert out == "langchain"
    assert " OR " not in out


def test_repos_query_string_rejects_empty_query() -> None:
    """A ReposSearchQuery with no filters would match every repo on
    GitHub. Refuse — that's never what a caller intends."""
    q = ReposSearchQuery(min_stars=0)  # no topics, no language, no keywords
    with pytest.raises(GitHubSearchError, match="no filters"):
        _client()._build_repos_query_string(q)


def test_repos_query_string_skips_empty_topic_strings() -> None:
    """Defensive: an empty string in the topics tuple shouldn't emit
    ``topic:`` (which GitHub would 422 on). The first non-empty topic
    wins for the no-override call."""
    q = ReposSearchQuery(topics=("", "llm", "", "agent"), min_stars=0)
    out = _client()._build_repos_query_string(q)
    # First non-empty topic (``llm``) is emitted; empty entries
    # skipped without producing a bare ``topic:`` token.
    assert out == "topic:llm"
    assert "topic:agent" not in out


@pytest.mark.asyncio
async def test_find_target_repos_normalizes_repos_endpoint_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slice 1.7 phase A: ``/search/repositories`` returns rich repo
    metadata directly — no enrichment needed. find_target_repos maps
    each item to a CandidateFile with file_path='' (repo-level)."""
    import httpx

    def mock_get(url, headers=None, params=None, timeout=None):
        assert "search/repositories" in url
        assert params["sort"] == "stars"
        assert params["order"] == "desc"
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "full_name": "langchain-ai/langchainjs",
                        "html_url": "https://github.com/langchain-ai/langchainjs",
                        "stargazers_count": 15000,
                        "fork": False,
                        "description": "JS port of LangChain",
                        "topics": ["llm", "agent", "langchain"],
                        "license": {"spdx_id": "MIT"},
                        "archived": False,
                    },
                    {
                        "full_name": "run-llama/llamaindex",
                        "html_url": "https://github.com/run-llama/llamaindex",
                        "stargazers_count": 30000,
                        "fork": False,
                        "description": "LlamaIndex data framework",
                        "topics": ["llm", "rag"],
                        "license": {"spdx_id": "MIT"},
                        "archived": False,
                    },
                ]
            },
            request=httpx.Request("GET", url),
        )

    class _MockTransport(httpx.MockTransport):
        def __init__(self):
            super().__init__(handler=lambda req: mock_get(
                str(req.url), headers=dict(req.headers), params=dict(req.url.params)
            ))

    async with httpx.AsyncClient(transport=_MockTransport()) as ac:
        q = ReposSearchQuery(
            topics=("llm", "agent"),
            language="typescript",
            min_stars=100,
            max_results=10,
        )
        repos = await _client().find_target_repos(q, client=ac)

    # After find_target_repos: dedupe by full_name across the two
    # per-topic queries (both return the same 2 fixtures), then sort
    # by stars desc → llamaindex (30000) first, langchainjs (15000)
    # second.
    assert len(repos) == 2
    by_name = {r.repo_full_name: r for r in repos}
    assert by_name["langchain-ai/langchainjs"].repo_stargazers == 15000
    assert by_name["langchain-ai/langchainjs"].repo_topics == [
        "llm", "agent", "langchain",
    ]
    assert by_name["langchain-ai/langchainjs"].repo_license == "MIT"
    assert by_name["langchain-ai/langchainjs"].is_enriched is True
    assert by_name["langchain-ai/langchainjs"].file_path == ""  # repo-level
    assert by_name["run-llama/llamaindex"].repo_stargazers == 30000
    # Sort order: stars desc → llamaindex first.
    assert repos[0].repo_full_name == "run-llama/llamaindex"
    assert repos[1].repo_full_name == "langchain-ai/langchainjs"


@pytest.mark.asyncio
async def test_find_target_repos_handles_empty_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No matching repos → empty list, no exception."""
    import httpx

    def mock_get(url, headers=None, params=None, timeout=None):
        return httpx.Response(
            200,
            json={"items": []},
            request=httpx.Request("GET", url),
        )

    class _MockTransport(httpx.MockTransport):
        def __init__(self):
            super().__init__(handler=lambda req: mock_get(str(req.url)))

    async with httpx.AsyncClient(transport=_MockTransport()) as ac:
        q = ReposSearchQuery(topics=("nonexistent-topic-xyz",), min_stars=0)
        repos = await _client().find_target_repos(q, client=ac)

    assert repos == []


@pytest.mark.asyncio
async def test_find_target_repos_raises_on_422(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed query → 422 → GitHubSearchError with the raw body so
    operators can debug. Non-retriable."""
    import httpx

    def mock_get(url, headers=None, params=None, timeout=None):
        return httpx.Response(
            422,
            text='{"message":"Validation Failed"}',
            request=httpx.Request("GET", url),
        )

    class _MockTransport(httpx.MockTransport):
        def __init__(self):
            super().__init__(handler=lambda req: mock_get(str(req.url)))

    async with httpx.AsyncClient(transport=_MockTransport()) as ac:
        q = ReposSearchQuery(topics=("llm",), min_stars=0)
        with pytest.raises(GitHubSearchError, match="422"):
            await _client().find_target_repos(q, client=ac)


@pytest.mark.asyncio
async def test_discover_and_search_merges_phase_a_metadata_onto_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two-phase discovery: phase A's enriched repo metadata (stars,
    topics) MUST be propagated onto each file candidate returned by
    phase B — otherwise the file candidates carry truncated repo data
    from /search/code and the operator sees 0 stars."""
    from dast.code_index import CandidateFile, github_search

    async def fake_find_target_repos(self, query, *, client=None):
        return [
            CandidateFile(
                repo_full_name="langchain-ai/langchainjs",
                file_path="",
                ref="",
                html_url="https://github.com/langchain-ai/langchainjs",
                raw_url="",
                repo_stargazers=15000,
                repo_is_fork=False,
                repo_description="JS port of LangChain",
                repo_topics=["llm", "agent"],
                repo_license="MIT",
                is_enriched=True,
            ),
            CandidateFile(
                repo_full_name="run-llama/llamaindex",
                file_path="",
                ref="",
                html_url="https://github.com/run-llama/llamaindex",
                raw_url="",
                repo_stargazers=30000,
                repo_topics=["llm", "rag"],
                repo_license="MIT",
                is_enriched=True,
            ),
        ]

    async def fake_search(self, query):
        # Simulate code search returning files within the scoped
        # repo. The truncated repo info (stars=0) is what /search/
        # code returns — Phase A merge fixes it.
        assert "repo:" in query.repo_filter
        repo = query.repo_filter.replace("repo:", "")
        return [
            CandidateFile(
                repo_full_name=repo,
                file_path="src/tool.ts",
                ref="abc",
                html_url=f"https://github.com/{repo}/blob/m/src/tool.ts",
                raw_url=f"https://raw.githubusercontent.com/{repo}/m/src/tool.ts",
                repo_stargazers=0,  # truncated from /search/code
                repo_is_fork=False,
                repo_description="",  # also truncated
            ),
        ]

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "find_target_repos",
        fake_find_target_repos,
    )
    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "search",
        fake_search,
    )

    code_q = SearchQuery(raw_query="fetch", language="typescript")
    disc_q = ReposSearchQuery(topics=("llm",), language="typescript")

    out = await _client().discover_and_search(
        code_query=code_q, discovery=disc_q
    )

    # 2 repos × 1 file each = 2 candidate files.
    assert len(out) == 2

    # Each file inherits Phase A repo metadata.
    by_repo = {c.repo_full_name: c for c in out}
    assert by_repo["langchain-ai/langchainjs"].repo_stargazers == 15000
    assert by_repo["langchain-ai/langchainjs"].repo_topics == ["llm", "agent"]
    assert by_repo["langchain-ai/langchainjs"].is_enriched is True
    assert by_repo["run-llama/llamaindex"].repo_stargazers == 30000
    assert by_repo["run-llama/llamaindex"].repo_topics == ["llm", "rag"]


@pytest.mark.asyncio
async def test_discover_and_search_short_circuits_on_empty_phase_a(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If Phase A finds zero target repos, don't run Phase B at all.
    Saves N wasted code-search API calls."""
    from dast.code_index import github_search

    async def fake_find_target_repos(self, query, *, client=None):
        return []

    search_called = []

    async def fake_search(self, query):
        search_called.append(query)
        return []

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "find_target_repos",
        fake_find_target_repos,
    )
    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "search",
        fake_search,
    )

    out = await _client().discover_and_search(
        code_query=SearchQuery(raw_query="fetch"),
        discovery=ReposSearchQuery(topics=("xyz",)),
    )
    assert out == []
    assert search_called == []  # Phase B skipped


@pytest.mark.asyncio
async def test_discover_and_search_continues_when_one_repo_search_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One Phase B failure (e.g., a repo got renamed mid-query)
    shouldn't kill the whole hunt — log + skip that repo + keep
    processing the rest."""
    from dast.code_index import CandidateFile, github_search

    async def fake_find_target_repos(self, query, *, client=None):
        return [
            CandidateFile(
                repo_full_name="ok/repo",
                file_path="",
                ref="",
                html_url="https://github.com/ok/repo",
                raw_url="",
                repo_stargazers=1000,
                is_enriched=True,
            ),
            CandidateFile(
                repo_full_name="broken/repo",
                file_path="",
                ref="",
                html_url="https://github.com/broken/repo",
                raw_url="",
                repo_stargazers=2000,
                is_enriched=True,
            ),
        ]

    async def fake_search(self, query):
        repo = query.repo_filter.replace("repo:", "")
        if repo == "broken/repo":
            raise GitHubSearchError("simulated failure")
        return [
            CandidateFile(
                repo_full_name=repo,
                file_path="src/a.ts",
                ref="x",
                html_url=f"https://github.com/{repo}/blob/m/src/a.ts",
                raw_url=f"https://raw.githubusercontent.com/{repo}/m/src/a.ts",
            ),
        ]

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "find_target_repos",
        fake_find_target_repos,
    )
    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "search",
        fake_search,
    )

    out = await _client().discover_and_search(
        code_query=SearchQuery(raw_query="fetch"),
        discovery=ReposSearchQuery(topics=("llm",)),
    )
    # ok/repo's file present; broken/repo skipped silently.
    assert [c.repo_full_name for c in out] == ["ok/repo"]


@pytest.mark.asyncio
async def test_discover_and_search_caps_files_per_repo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``max_files_per_repo=3`` means the scoped per-repo SearchQuery
    gets max_results=3 — prevents one gigantic repo from dominating."""
    from dast.code_index import CandidateFile, github_search

    captured: list[int] = []

    async def fake_find_target_repos(self, query, *, client=None):
        return [
            CandidateFile(
                repo_full_name="o/r",
                file_path="",
                ref="",
                html_url="https://github.com/o/r",
                raw_url="",
                repo_stargazers=1000,
                is_enriched=True,
            ),
        ]

    async def fake_search(self, query):
        captured.append(query.max_results)
        return []

    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "find_target_repos",
        fake_find_target_repos,
    )
    monkeypatch.setattr(
        github_search.GitHubCodeSearchClient,
        "search",
        fake_search,
    )

    await _client().discover_and_search(
        code_query=SearchQuery(raw_query="fetch", max_results=99),
        discovery=ReposSearchQuery(topics=("llm",)),
        max_files_per_repo=5,
    )
    # Per-repo query is capped at max_files_per_repo, NOT the
    # caller's outer max_results (which is for total candidates).
    assert captured == [5]
