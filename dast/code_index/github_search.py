"""DAST-303 — GitHub Code Search backend.

Thin wrapper over GitHub's REST ``/search/code`` endpoint. Handles
the production-grade concerns:

  * Authenticated requests (PAT from ``GITHUB_TOKEN`` env).
  * Rate-limit aware (60 req/min for search endpoint; we log + back
    off when the rate-limit header drops, and circuit-break on 429).
  * Exponential backoff on transient 5xx / connection errors.
  * Pagination bounded (default 30 results, max 100 per page,
    hard cap 200 results per query to bound cost).
  * Result normalization to :class:`CandidateFile`.

Use:

    client = GitHubCodeSearchClient.from_env()
    query = SearchQuery(
        raw_query='fetch( in:file extension:ts',
        language="typescript",
        max_results=20,
    )
    candidates = await client.search(query)

GitHub Code Search has known limits we work within:

  * The new code search (https://github.blog/2023-02-08-new-and-
    improved-code-search/) supports regex via ``/pattern/`` syntax —
    but the REST API does NOT expose regex; only the website UI
    does. The REST API supports literal-string queries + filters
    (``language:``, ``path:``, ``user:``, ``repo:``, ``extension:``).
    So queries from :mod:`dast.cross_repo_query` must use the
    literal-string form, plus filters.

  * Total result cap: 1000 per query (API limit). We cap at 200 in
    code to keep latency + downstream triage cost bounded.

  * Per-page max 100 (``per_page=100``).

Failure modes:

  * 401: invalid / expired token → ``GitHubSearchError`` raised.
  * 403 (rate-limited): wait + retry once, then raise.
  * 422: malformed query → raised with the API's error detail; the
    query builder should ideally never emit one of these but we
    surface it explicitly so callers see exactly what failed.
  * 5xx: exponential backoff with jitter, up to 3 retries.

Environment:
  GITHUB_TOKEN — personal access token with ``public_repo`` scope
    (or ``repo`` if scanning private repos via ``user:`` filter).
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

log = logging.getLogger("argus.dast.code_index.github")


# ── Tunables ─────────────────────────────────────────────────────────


#: Default cap on results returned per search. Keeps downstream
#: Phase D triage spend bounded. Operators bump via SearchQuery.max_results.
DEFAULT_MAX_RESULTS: int = 30

#: Hard upper bound. Beyond this the GitHub API performance degrades AND
#: the downstream sandbox-verification cost gets unreasonable. The
#: design doc's bound is 50 candidates per seed; we double that for
#: search-result count because triage filters most of them out.
HARD_MAX_RESULTS: int = 200

#: GitHub's per-page max for the code search endpoint.
GITHUB_PER_PAGE_MAX: int = 100

#: Search endpoint rate limit (authenticated): 30 req/min.
#: ``X-RateLimit-Remaining`` header tracks remaining quota; when it
#: drops below this threshold we slow down preemptively.
RATE_LIMIT_SLOW_THRESHOLD: int = 3

#: Max retry attempts for transient errors (5xx, connection reset).
MAX_RETRIES: int = 3

#: Initial backoff in seconds; doubles per retry, plus jitter.
INITIAL_BACKOFF_SEC: float = 2.0

#: HTTP request timeout. Search is server-side query work — most
#: complete in <2s; 15s timeout protects against hanging connections.
REQUEST_TIMEOUT_SEC: float = 15.0


# ── Result types ─────────────────────────────────────────────────────


@dataclass
class CandidateFile:
    """One file returned from a code search, normalized.

    Carries enough metadata for the downstream Phase D pipeline to
    fetch the content (via ``html_url`` or ``raw_url``) and attribute
    findings (``repo_full_name`` + ``file_path`` + ``ref``).
    """

    #: ``owner/repo`` (e.g., ``langchain-ai/langchainjs``).
    repo_full_name: str
    #: File path relative to repo root.
    file_path: str
    #: Git ref the search matched against (typically default branch SHA).
    ref: str
    #: HTML URL to the file on GitHub (operator-readable).
    html_url: str
    #: Raw URL to the file content (raw.githubusercontent.com).
    raw_url: str
    #: Stars on the source repo. Slice 1.6: populated reliably via
    #: per-repo enrichment ``GET /repos/{owner}/{name}``. Before
    #: enrichment, ``/search/code`` returns 0 for every repo because
    #: the API response's repository object is truncated.
    repo_stargazers: int = 0
    #: Whether the source repo is a fork. Forks of the same upstream
    #: bug shouldn't each count as independent disclosure targets.
    repo_is_fork: bool = False
    #: Repo description (sometimes informative for triage).
    repo_description: str = ""
    #: Text fragments from the search match (when ``text_match`` is
    #: requested). Empty if not requested.
    text_matches: list[str] = field(default_factory=list)
    #: Slice 1.6 enrichment — repo topics. Useful for ecosystem-
    #: based filtering (e.g., ``llm`` / ``langchain`` / ``ai-tool``
    #: topics signal disclosure-relevant context). Populated via
    #: enrichment; empty before.
    repo_topics: list[str] = field(default_factory=list)
    #: Slice 1.6 enrichment — SPDX license id (e.g., ``MIT``,
    #: ``Apache-2.0``). Empty when the repo doesn't declare a
    #: license or before enrichment.
    repo_license: str = ""
    #: Slice 1.6 enrichment — whether the repo is archived.
    #: Archived repos shouldn't get disclosure reports — the
    #: maintainer can't act on them. Default False (also the safe
    #: default when enrichment hasn't run).
    repo_archived: bool = False
    #: Slice 1.6 telemetry — whether enrichment actually ran for
    #: this candidate. False means the star/topic/license/archived
    #: fields carry their defaults rather than real values. Operators
    #: + tests can distinguish "no stars" from "no enrichment yet."
    is_enriched: bool = False


@dataclass
class ReposSearchQuery:
    """Slice 1.7 — query for ``/search/repositories``.

    The repos endpoint supports a richer query language than code
    search: native ``stars:>N`` qualifier, ``topic:X`` (exact topic
    match), ``language:Y``, boolean ``OR`` clauses, and ``sort=stars``
    ordering. Used as the FIRST phase of two-phase cross-repo
    discovery — find high-star ecosystem repos, then code-search
    within each.

    Construction is signature-driven via
    :func:`dast.cross_repo_query.infer_discovery_query` — for
    LangChain SSRF (LLM-context signature) it produces a query
    targeting AI-tool topics; for HTTP-form SSRF (non-LLM source) it
    produces a web-framework topics query; etc.
    """

    #: Topics to match. Multiple = OR'd ``(topic:a OR topic:b)``.
    #: Empty = no topic constraint (less precise but broader).
    topics: tuple[str, ...] = ()
    #: GitHub language filter (e.g., ``typescript``).
    language: str = ""
    #: Minimum stars threshold. Default 100 = "real ecosystem repo,
    #: not toy project." Set higher for tighter scoping.
    min_stars: int = 100
    #: Substring keywords to match against the repo description.
    #: Multiple = OR'd. Less precise than topics but broader — many
    #: relevant repos don't add topic tags.
    description_keywords: tuple[str, ...] = ()
    #: Max number of target repos to return. Default 10 = bounds the
    #: subsequent per-repo code-search work to ~10 API calls.
    max_results: int = 10


@dataclass
class SearchQuery:
    """One code-search request. The query builder
    (:mod:`dast.cross_repo_query`) constructs these from signatures."""

    #: The literal-text portion of the query. May include phrase
    #: searches (in quotes), and the qualifier syntax GitHub
    #: supports (``in:file``, ``extension:py``, etc.) — though the
    #: structured filters below are preferred over inline qualifiers.
    raw_query: str
    #: Optional language filter (``python`` / ``typescript`` /
    #: ``javascript`` / ``go``). Mapped to ``language:`` qualifier.
    language: str = ""
    #: Optional path filter (e.g., ``src/tools/*`` — supports glob).
    #: Mapped to ``path:`` qualifier.
    path_glob: str = ""
    #: Optional repo filter (``user/repo`` or ``user:org``). Lets
    #: operators restrict to specific orgs (their own, or a target
    #: ecosystem like ``langchain-ai``).
    repo_filter: str = ""
    #: Bound the candidate set. Defaults to DEFAULT_MAX_RESULTS;
    #: hard-capped at HARD_MAX_RESULTS by the search method.
    max_results: int = DEFAULT_MAX_RESULTS
    #: Request text-match fragments in the result. Useful for
    #: debugging but adds ~50% to response size; default off.
    include_text_matches: bool = False
    #: SCAN-1.5 quality lift — minimum stars threshold, applied
    #: CLIENT-SIDE after results are fetched.
    #:
    #: KNOWN LIMITATION (resolves in Slice 1.6): GitHub's REST
    #: ``/search/code`` returns a truncated ``repository`` object
    #: that DOES NOT include ``stargazers_count``. So this filter is
    #: a no-op against /search/code results today — every candidate
    #: has ``repo_stargazers=0`` regardless of its true star count.
    #: Slice 1.6 will enrich candidates by calling ``/repos/{owner}/
    #: {name}`` per unique repo and populate the real star count.
    #: Until then, the field is reserved for future use; default 0
    #: explicitly disables the filter so a stale-design assumption
    #: doesn't silently drop everything.
    min_stars: int = 0
    #: SCAN-1.5 context-keyword OR clause. When non-empty, appended
    #: as ``(kw1 OR kw2 OR ...)`` to require the file mention one of
    #: the keywords — biases toward an ecosystem (AI tools, web
    #: frameworks, etc.) rather than every codebase that happens to
    #: use the sink. Typical values: AI-tool bag ``("langchain",
    #: "llama", "agent", "openai", "anthropic", "mcp")`` for AI-
    #: derived SSRF signatures. Empty = no context bias.
    context_keywords: tuple[str, ...] = ()
    #: SCAN-1.5 — client-side star-sort oversampling. When > 1, the
    #: client fetches ``max_results × this`` candidates, sorts by
    #: ``repo_stargazers`` desc, then truncates to ``max_results``.
    #: Burns more API quota but surfaces high-star ecosystem repos
    #: that the GitHub default-sort otherwise buries under recent
    #: zero-star matches. Default 2 (50% extra cost, big quality
    #: lift). Set to 1 to disable.
    oversample_for_star_sort: int = 2


class GitHubSearchError(Exception):
    """Raised when the GitHub search fails non-transiently
    (auth error, malformed query, exhausted retries)."""


# ── Client ───────────────────────────────────────────────────────────


class GitHubCodeSearchClient:
    """Async HTTP client for GitHub's code search REST endpoint."""

    def __init__(
        self, *, token: str, base_url: str = "https://api.github.com"
    ) -> None:
        if not token:
            raise GitHubSearchError(
                "GitHubCodeSearchClient requires a non-empty token. "
                "Set GITHUB_TOKEN env var or pass token= explicitly."
            )
        self._token = token
        self._base_url = base_url.rstrip("/")

    @classmethod
    def from_env(cls) -> GitHubCodeSearchClient:
        """Construct a client from ``GITHUB_TOKEN``. Raises a clear
        error if the env var is missing — production callers should
        never silently scan without auth (the unauth rate limit is
        10 req/hour, which makes DAST-303 unusable)."""
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if not token:
            raise GitHubSearchError(
                "GITHUB_TOKEN env var is not set or empty. DAST-303 "
                "requires an authenticated PAT — the unauthenticated "
                "rate limit is too tight for cross-repo hunting. "
                "Create a PAT with public_repo scope at "
                "https://github.com/settings/tokens."
            )
        return cls(token=token)

    def _build_query_string(self, query: SearchQuery) -> str:
        """Compose the final ``q=`` parameter from raw query + filters.
        Pure function — unit-testable without the network.

        GitHub's REST ``/search/code`` endpoint supports these
        qualifiers: ``language``, ``path``, ``extension``, ``in``,
        ``user``, ``repo``, ``org``, ``size``, ``filename``. It does
        NOT support ``stars:`` (that's a repos-search qualifier) or
        explicit boolean OR clauses (terms are AND-combined by
        default). Trying to use them returns HTTP 422
        ERROR_TYPE_QUERY_PARSING_FATAL.

        So ``min_stars`` and ``context_keywords`` are NOT placed in
        the query string here — they get applied client-side in
        :meth:`search` (see ``_post_filter_candidates``). The query
        string only carries qualifiers GitHub's code search actually
        understands.
        """
        parts: list[str] = [query.raw_query.strip()]
        if query.language:
            parts.append(f"language:{query.language}")
        if query.path_glob:
            parts.append(f"path:{query.path_glob}")
        if query.repo_filter:
            parts.append(query.repo_filter)
        return " ".join(p for p in parts if p)

    def _build_repos_query_string(
        self, query: ReposSearchQuery, *, single_topic: str | None = None
    ) -> str:
        """Compose the ``q=`` parameter for ``/search/repositories``.

        IMPORTANT: ``/search/repositories`` advertises support for
        boolean OR with the ``topic:`` qualifier, but empirically
        ``topic:A OR topic:B`` returns 0 results — the parser doesn't
        handle that pattern. So instead of OR'ing topics into one
        query, the caller (``find_target_repos``) runs ONE query PER
        topic and merges the results. This builder takes a single
        topic at a time.

        Description-keyword OR'ing has the same problem (the
        ``in:description`` qualifier doesn't combine with OR
        reliably). When ``description_keywords`` is non-empty, the
        first keyword is used as a plain text query (which DOES
        work and effectively does ``keyword in:name,description``
        matching).

        ``single_topic`` lets ``find_target_repos`` override which
        topic to emit when running its per-topic loop. When None,
        the first topic from the query (if any) is used.
        """
        parts: list[str] = []

        # Pick the topic for this query: caller override OR first
        # topic from the query OR nothing.
        topic_to_emit: str = ""
        if single_topic and single_topic.strip():
            topic_to_emit = single_topic.strip()
        elif query.topics:
            for t in query.topics:
                if t.strip():
                    topic_to_emit = t.strip()
                    break
        if topic_to_emit:
            parts.append(f"topic:{topic_to_emit}")

        # Description keyword: use just the first (OR'ing doesn't
        # work). Plain text matches against name + description.
        if query.description_keywords:
            for k in query.description_keywords:
                if k.strip():
                    parts.append(k.strip())
                    break

        if query.language:
            parts.append(f"language:{query.language}")
        if query.min_stars > 0:
            parts.append(f"stars:>{query.min_stars}")
        if not parts:
            raise GitHubSearchError(
                "ReposSearchQuery has no filters — would match every "
                "repo on GitHub. At least one of topics, description_"
                "keywords, language, or min_stars must be non-empty."
            )
        return " ".join(parts)

    async def _run_repos_query(
        self,
        q_string: str,
        per_page: int,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        """One ``/search/repositories`` request with the standard
        retry/backoff envelope. Returns the raw ``items`` list (or
        empty on irrecoverable errors). Used by ``find_target_repos``
        which may call this multiple times (once per topic) and
        merge the results.
        """
        url = f"{self._base_url}/search/repositories"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params = {
            "q": q_string,
            "sort": "stars",
            "order": "desc",
            "per_page": per_page,
            "page": 1,
        }
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = await client.get(
                    url, headers=headers, params=params,
                    timeout=REQUEST_TIMEOUT_SEC,
                )
            except (
                httpx.ConnectError,
                httpx.ReadError,
                httpx.TimeoutException,
            ) as exc:
                if attempt < MAX_RETRIES:
                    backoff = INITIAL_BACKOFF_SEC * (2**attempt)
                    backoff += random.uniform(0, 1)
                    log.warning(
                        "repos search transient error (attempt %d): "
                        "%s; backing off %.1fs",
                        attempt + 1,
                        exc,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise GitHubSearchError(
                    f"repos search connection failed: {exc}"
                ) from exc

            if resp.status_code == 200:
                self._maybe_warn_rate_limit(resp.headers)
                data = resp.json()
                return list(data.get("items") or [])
            if resp.status_code == 401:
                raise GitHubSearchError(
                    "repos search 401 Unauthorized — regenerate token."
                )
            if resp.status_code == 403:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(
                        self._wait_for_rate_reset(resp.headers)
                    )
                    continue
                raise GitHubSearchError(
                    "repos search 403 rate-limited after retries."
                )
            if resp.status_code == 422:
                raise GitHubSearchError(
                    f"repos search malformed query (422). "
                    f"q={q_string!r} body={resp.text[:200]}"
                )
            if 500 <= resp.status_code < 600 and attempt < MAX_RETRIES:
                backoff = INITIAL_BACKOFF_SEC * (2**attempt)
                backoff += random.uniform(0, 1)
                await asyncio.sleep(backoff)
                continue
            raise GitHubSearchError(
                f"repos search unexpected status {resp.status_code}: "
                f"{resp.text[:200]}"
            )
        raise GitHubSearchError("repos search retries exhausted")

    @staticmethod
    def _normalize_repo_item(item: dict[str, Any]) -> CandidateFile:
        """Map a /search/repositories item to a CandidateFile."""
        license_obj = item.get("license") or {}
        return CandidateFile(
            repo_full_name=item.get("full_name", ""),
            file_path="",  # repo-level, no file yet
            ref="",
            html_url=item.get("html_url", ""),
            raw_url="",
            repo_stargazers=int(item.get("stargazers_count", 0) or 0),
            repo_is_fork=bool(item.get("fork", False)),
            repo_description=(item.get("description") or "")[:300],
            repo_topics=list(item.get("topics") or []),
            repo_license=str((license_obj or {}).get("spdx_id") or ""),
            repo_archived=bool(item.get("archived", False)),
            is_enriched=True,  # repos endpoint already provides everything
        )

    async def find_target_repos(
        self,
        query: ReposSearchQuery,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> list[CandidateFile]:
        """Slice 1.7 — phase A of two-phase cross-repo discovery.

        Calls ``/search/repositories`` for EACH topic in
        ``query.topics`` (sorted by stars desc), merges + dedupes by
        ``full_name``, sorts the merged set by stars desc, and
        returns up to ``query.max_results`` repo summaries as
        :class:`CandidateFile` records WITH ``file_path=""`` (no
        file yet — these are repos, not files). When ``query.topics``
        is empty, a single query runs without a topic filter (uses
        only language / min_stars / description_keywords).

        WHY per-topic loop instead of OR: GitHub's repos search
        advertises ``topic:A OR topic:B`` but the parser returns 0
        for that pattern (verified empirically against the live API).
        Per-topic queries each return real results; we merge in
        client code.

        Cost: ``len(query.topics)`` API calls (or 1 when topics is
        empty). For the default 4-topic AI bag, that's 4 calls — still
        well under the 30 req/min search rate limit.

        Returns fully-enriched CandidateFile records (stars/topics/
        license/archived all populated from the repos endpoint —
        no extra enrichment needed) so the result is interchangeable
        with ``search()`` output.
        """
        target = max(1, min(query.max_results, HARD_MAX_RESULTS))
        # Each per-topic query asks for ``target`` rows so the merged
        # set has headroom; we truncate to ``target`` at the end.
        per_page = min(GITHUB_PER_PAGE_MAX, target)

        topics_to_run: list[str] = [
            t.strip() for t in query.topics if t.strip()
        ]
        if not topics_to_run:
            # No topics → single query without a topic constraint.
            topics_to_run = [""]

        owns_client = client is None
        client = client or httpx.AsyncClient()
        all_items: dict[str, dict[str, Any]] = {}  # dedupe by full_name
        try:
            for topic in topics_to_run:
                q_string = self._build_repos_query_string(
                    query, single_topic=topic if topic else None
                )
                items = await self._run_repos_query(
                    q_string, per_page, client
                )
                log.debug(
                    "repos search topic=%r returned %d items (q=%s)",
                    topic or "<none>",
                    len(items),
                    q_string[:120],
                )
                for item in items:
                    full_name = item.get("full_name", "")
                    if not full_name:
                        continue
                    # Last write wins; per-topic data is identical
                    # for the same repo so this is safe.
                    all_items[full_name] = item
        finally:
            if owns_client:
                await client.aclose()

        # Sort merged set by stargazers desc + non-forks first.
        merged = [self._normalize_repo_item(item) for item in all_items.values()]
        merged.sort(key=lambda c: (-c.repo_stargazers, c.repo_is_fork))
        merged = merged[:target]

        log.info(
            "repos search across %d topic(s) → %d unique repos "
            "(top star=%d, after merge+sort+truncate=%d)",
            len(topics_to_run),
            len(all_items),
            merged[0].repo_stargazers if merged else 0,
            len(merged),
        )
        return merged

    async def discover_and_search(
        self,
        *,
        code_query: SearchQuery,
        discovery: ReposSearchQuery,
        max_files_per_repo: int = 3,
    ) -> list[CandidateFile]:
        """Slice 1.7 — two-phase cross-repo discovery + code search.

        Phase A: ``find_target_repos(discovery)`` finds up to
        ``discovery.max_results`` high-star repos in the target
        ecosystem (e.g., AI-tool TS packages with topic:llm).

        Phase B: for each target repo, code-search the seed signature
        (``code_query``) WITHIN that repo via the ``repo:`` qualifier.
        Bounded by ``max_files_per_repo`` files per repo so a single
        gigantic repo can't dominate the result set.

        Returns the union — fully enriched (Phase A repos already
        carry star/topic data; the code-search candidates inherit
        the repo metadata via a merge step).

        Cost: 1 + N API calls where N = number of target repos
        actually code-searched. Typical: 1 + 10 = 11 calls per
        signature, well within rate limits.
        """
        async with httpx.AsyncClient() as client:
            # Phase A: discover target repos.
            target_repos = await self.find_target_repos(
                discovery, client=client
            )
            if not target_repos:
                log.info("Phase A returned 0 target repos — short-circuit")
                return []

            log.info(
                "Phase A target repos: %s",
                ", ".join(
                    f"{r.repo_full_name}({r.repo_stargazers})"
                    for r in target_repos
                ),
            )

            # Phase B: code-search within each target repo. We do
            # this SEQUENTIALLY (not parallel) to keep rate-limit
            # spend predictable + because each per-repo search is
            # tiny (max_files_per_repo files).
            all_candidates: list[CandidateFile] = []
            repos_by_name = {r.repo_full_name: r for r in target_repos}
            for target_repo in target_repos:
                # Build a per-repo SearchQuery — same as the caller's
                # code_query but scoped to repo:owner/name. Disable
                # enrichment (we already have stars + topics from
                # Phase A — re-fetching would burn quota).
                scoped = SearchQuery(
                    raw_query=code_query.raw_query,
                    language=code_query.language,
                    path_glob=code_query.path_glob,
                    repo_filter=f"repo:{target_repo.repo_full_name}",
                    max_results=max_files_per_repo,
                    include_text_matches=code_query.include_text_matches,
                    min_stars=0,  # already filtered by repo selection
                    context_keywords=(),  # already filtered by topic
                    oversample_for_star_sort=1,  # no oversample — narrow scope
                )
                try:
                    candidates = await self.search(scoped)
                except GitHubSearchError as exc:
                    log.warning(
                        "Phase B per-repo search failed for %s: %s — "
                        "skipping this repo, continuing with rest",
                        target_repo.repo_full_name,
                        exc,
                    )
                    continue

                # Merge repo metadata from Phase A into each candidate
                # (the search() result has truncated repo info from
                # /search/code; Phase A already has the full data).
                for c in candidates:
                    src = repos_by_name.get(c.repo_full_name)
                    if src:
                        c.repo_stargazers = src.repo_stargazers
                        c.repo_topics = list(src.repo_topics)
                        c.repo_license = src.repo_license
                        c.repo_archived = src.repo_archived
                        c.is_enriched = True
                        if not c.repo_description:
                            c.repo_description = src.repo_description
                all_candidates.extend(candidates)

        log.info(
            "Two-phase discovery: %d target repos → %d candidate files",
            len(target_repos),
            len(all_candidates),
        )
        return all_candidates

    async def enrich_candidates(
        self,
        candidates: list[CandidateFile],
        *,
        client: httpx.AsyncClient | None = None,
    ) -> list[CandidateFile]:
        """Slice 1.6 — populate the truncated repo metadata.

        GitHub's ``/search/code`` returns a stripped-down repository
        object missing ``stargazers_count`` / ``topics`` / ``license``
        / ``archived``. This method fetches the full repo metadata via
        ``GET /repos/{owner}/{name}`` for each UNIQUE repo across the
        candidate list and re-populates those fields in-place on every
        CandidateFile.

        Bounded by:
          * One enrichment call per unique repo (deduped via a set,
            then each repo is hit once). 50 candidates spread across
            10 distinct repos = 10 enrichment calls, not 50.
          * The core API rate limit is 5000 req/hour with auth — far
            above what DAST-303 will burn even at the 50-candidate cap.
          * Per-request timeout via REQUEST_TIMEOUT_SEC.

        Failure modes:
          * 404 (repo deleted / renamed) → that candidate stays at
            its un-enriched defaults but ``is_enriched`` stays False
            so callers can see the gap. No exception raised.
          * Other 4xx / 5xx → logged + candidate stays un-enriched.
            The enrichment is best-effort; one bad repo doesn't fail
            the batch.

        Returns the SAME list (mutated in place) for caller ergonomics
        — also lets ``await self.enrich_candidates(out)`` chain into
        an existing list reference.
        """
        # Optional shared client lets callers reuse connection pool
        # across search + enrichment when invoking both from the
        # same async context. Default: spin up a private client.
        owns_client = client is None
        client = client or httpx.AsyncClient()
        try:
            unique_repos = {c.repo_full_name for c in candidates if c.repo_full_name}
            metadata: dict[str, dict[str, Any] | None] = {}
            for repo in unique_repos:
                metadata[repo] = await self._get_repo_metadata(client, repo)

            # Apply enrichment in place.
            for cand in candidates:
                meta = metadata.get(cand.repo_full_name)
                if meta is None:
                    # Lookup failed; leave defaults, mark un-enriched.
                    continue
                cand.repo_stargazers = int(meta.get("stargazers_count", 0) or 0)
                cand.repo_is_fork = bool(meta.get("fork", False))
                # Description sometimes only present on the full
                # metadata; if so, fill it in (search endpoint may
                # have left it empty).
                desc = meta.get("description")
                if isinstance(desc, str) and desc and not cand.repo_description:
                    cand.repo_description = desc[:300]
                cand.repo_topics = list(meta.get("topics") or [])
                lic = meta.get("license") or {}
                cand.repo_license = str(
                    (lic or {}).get("spdx_id") or ""
                )
                cand.repo_archived = bool(meta.get("archived", False))
                cand.is_enriched = True
        finally:
            if owns_client:
                await client.aclose()

        log.info(
            "Enriched %d unique repos across %d candidates",
            sum(1 for v in metadata.values() if v is not None),
            len(candidates),
        )
        return candidates

    async def _get_repo_metadata(
        self, client: httpx.AsyncClient, full_name: str
    ) -> dict[str, Any] | None:
        """Fetch ``/repos/{owner}/{name}`` for one repo. Returns the
        parsed JSON dict on success, ``None`` on 404 or other
        non-recoverable response. Used by :meth:`enrich_candidates`.

        Retries on transient errors with exponential backoff, same
        pattern as ``_request_page``. We don't share that method
        because the search + repo endpoints have slightly different
        rate-limit headers + error semantics.
        """
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        url = f"{self._base_url}/repos/{full_name}"

        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = await client.get(
                    url, headers=headers, timeout=REQUEST_TIMEOUT_SEC
                )
            except (httpx.ConnectError, httpx.ReadError, httpx.TimeoutException) as exc:
                if attempt < MAX_RETRIES:
                    backoff = INITIAL_BACKOFF_SEC * (2**attempt) + random.uniform(0, 1)
                    log.warning(
                        "repo metadata transient error for %s (attempt %d/%d): "
                        "%s; backing off %.1fs",
                        full_name,
                        attempt + 1,
                        MAX_RETRIES + 1,
                        exc,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                log.warning(
                    "repo metadata fetch failed after retries for %s: %s",
                    full_name,
                    exc,
                )
                return None
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                log.info(
                    "repo metadata 404 for %s — repo deleted or "
                    "renamed; leaving candidate un-enriched",
                    full_name,
                )
                return None
            if resp.status_code == 401:
                # Re-raise as visible error: token is now bad, the
                # rest of the enrichment batch will fail too. Better
                # to abort the batch than silently mark every
                # candidate un-enriched.
                raise GitHubSearchError(
                    f"repo metadata 401 Unauthorized for {full_name}. "
                    "Token expired mid-batch."
                )
            if 500 <= resp.status_code < 600:
                if attempt < MAX_RETRIES:
                    backoff = INITIAL_BACKOFF_SEC * (2**attempt) + random.uniform(0, 1)
                    await asyncio.sleep(backoff)
                    continue
                log.warning(
                    "repo metadata server error %d for %s after retries",
                    resp.status_code,
                    full_name,
                )
                return None
            # 403 rate-limited / other — log + skip this repo.
            log.warning(
                "repo metadata unexpected status %d for %s: %s",
                resp.status_code,
                full_name,
                resp.text[:200],
            )
            return None
        return None

    @staticmethod
    def _post_filter_candidates(
        candidates: list[CandidateFile], query: SearchQuery
    ) -> list[CandidateFile]:
        """Apply SCAN-1.5 client-side quality filters that GitHub's
        code-search API can't express server-side.

        Two stages:

        1. ``min_stars > 0`` drops candidates whose source repo has
           fewer stars than the threshold. Equivalent semantic to
           ``stars:>N`` if GitHub supported it on /search/code.
        2. ``context_keywords`` non-empty requires at least one
           keyword to appear (case-insensitive substring match) in
           the candidate's ``repo_full_name`` OR
           ``repo_description``. Biases the result set toward
           ecosystem repos whose IDENTITY signals the context
           (e.g., a repo named ``langchain-community`` matches the
           ``langchain`` keyword) rather than any repo whose code
           happens to mention the keyword in a comment.

        Order: stars first, then keywords. Operators can tune via
        the SearchQuery fields without code changes.
        """
        filtered = candidates
        if query.min_stars and query.min_stars > 0:
            filtered = [
                c for c in filtered if c.repo_stargazers >= query.min_stars
            ]
        if query.context_keywords:
            kws_lower = tuple(
                k.strip().lower() for k in query.context_keywords if k.strip()
            )
            if kws_lower:
                filtered = [
                    c
                    for c in filtered
                    if any(
                        kw in c.repo_full_name.lower()
                        or kw in c.repo_description.lower()
                        for kw in kws_lower
                    )
                ]
        return filtered

    async def _request_page(
        self,
        *,
        client: httpx.AsyncClient,
        q_string: str,
        per_page: int,
        page: int,
        include_text_matches: bool,
    ) -> dict[str, Any]:
        """Single page request with exponential-backoff retry on
        transient failures. Raises GitHubSearchError on non-transient
        errors or exhausted retries."""
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if include_text_matches:
            # ``text-match+json`` requests fragment highlighting.
            headers["Accept"] = "application/vnd.github.text-match+json"

        params = {
            "q": q_string,
            "per_page": per_page,
            "page": page,
        }
        url = f"{self._base_url}/search/code"

        last_exc: Exception | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = await client.get(
                    url, headers=headers, params=params, timeout=REQUEST_TIMEOUT_SEC
                )
            except (httpx.ConnectError, httpx.ReadError, httpx.TimeoutException) as exc:
                last_exc = exc
                if attempt < MAX_RETRIES:
                    backoff = INITIAL_BACKOFF_SEC * (2**attempt) + random.uniform(0, 1)
                    log.warning(
                        "GitHub search transient error (attempt %d/%d): %s; "
                        "backing off %.1fs",
                        attempt + 1,
                        MAX_RETRIES + 1,
                        exc,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise GitHubSearchError(
                    f"GitHub search connection failed after {MAX_RETRIES + 1} "
                    f"attempts: {type(exc).__name__}: {exc}"
                ) from exc

            # 200 — success path.
            if resp.status_code == 200:
                self._maybe_warn_rate_limit(resp.headers)
                return resp.json()

            # 401 — auth error, non-recoverable.
            if resp.status_code == 401:
                raise GitHubSearchError(
                    "GitHub search returned 401 Unauthorized — token is "
                    "invalid or expired. Regenerate at "
                    "https://github.com/settings/tokens."
                )

            # 403 — rate-limited OR forbidden.
            if resp.status_code == 403:
                remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                reset = resp.headers.get("X-RateLimit-Reset", "?")
                if attempt < MAX_RETRIES:
                    # Compute wait from reset header when available.
                    backoff = self._wait_for_rate_reset(resp.headers)
                    log.warning(
                        "GitHub search rate-limited (remaining=%s reset=%s); "
                        "waiting %.1fs before retry",
                        remaining,
                        reset,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise GitHubSearchError(
                    f"GitHub search rate-limited and retries exhausted. "
                    f"X-RateLimit-Remaining={remaining}, reset={reset}. "
                    f"Lower scan throughput or upgrade to a higher tier."
                )

            # 422 — malformed query.
            if resp.status_code == 422:
                detail = resp.json() if resp.content else {}
                raise GitHubSearchError(
                    f"GitHub search rejected query as malformed (422). "
                    f"Query was: {q_string!r}. API response: {detail}"
                )

            # 5xx — transient server error.
            if 500 <= resp.status_code < 600:
                last_exc = httpx.HTTPStatusError(
                    f"GitHub search returned {resp.status_code}",
                    request=resp.request,
                    response=resp,
                )
                if attempt < MAX_RETRIES:
                    backoff = INITIAL_BACKOFF_SEC * (2**attempt) + random.uniform(0, 1)
                    log.warning(
                        "GitHub search server error %d (attempt %d/%d); "
                        "backing off %.1fs",
                        resp.status_code,
                        attempt + 1,
                        MAX_RETRIES + 1,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise GitHubSearchError(
                    f"GitHub search server error {resp.status_code} "
                    f"persisted after {MAX_RETRIES + 1} attempts."
                ) from last_exc

            # Anything else: raise with the status + body for debug.
            raise GitHubSearchError(
                f"GitHub search unexpected status {resp.status_code}: "
                f"{resp.text[:500]}"
            )

        # Should never reach here.
        raise GitHubSearchError(
            f"GitHub search exhausted retries without raising: "
            f"{type(last_exc).__name__}: {last_exc}"
        )

    def _maybe_warn_rate_limit(self, headers: httpx.Headers) -> None:
        """Log a warning when remaining quota dips below the
        slow-down threshold so operators see the budget tightening."""
        try:
            remaining = int(headers.get("X-RateLimit-Remaining", "100"))
        except (TypeError, ValueError):
            return
        if remaining < RATE_LIMIT_SLOW_THRESHOLD:
            reset = headers.get("X-RateLimit-Reset", "?")
            log.warning(
                "GitHub search rate-limit budget low: remaining=%d "
                "(reset epoch=%s). Subsequent searches may stall.",
                remaining,
                reset,
            )

    @staticmethod
    def _wait_for_rate_reset(headers: httpx.Headers) -> float:
        """Compute the seconds to wait until ``X-RateLimit-Reset``.
        Falls back to 60 seconds when the header is missing or
        unparseable. Adds 1s jitter to avoid thundering-herd reset.
        """
        raw = headers.get("X-RateLimit-Reset")
        # Distinguish "header absent" (be conservative — wait 60s)
        # from "header present but past" (wait briefly).
        if raw is None or raw == "":
            return 60.0
        try:
            reset_epoch = int(raw)
        except (TypeError, ValueError):
            return 60.0
        now = time.time()
        wait = max(1.0, reset_epoch - now) + random.uniform(0, 1)
        # Cap at 5 minutes — beyond that the operator should abort
        # rather than block the scan.
        return min(wait, 300.0)

    @staticmethod
    def _extract_commit_ref_from_html_url(html_url: str) -> str:
        """Pull the commit ref out of a GitHub blob URL.

        GitHub code search returns ``html_url`` of the form::

            https://github.com/<owner>/<repo>/blob/<ref>/<path/to/file>

        where ``<ref>`` is the commit SHA the index was pointing at when
        the file matched. Used by ``RepoWorkspace.download_tarball`` to
        pin the cross-repo download at exactly the snapshot the judge
        analyzed — without it, a later run could fetch a different
        version of the file as the default branch moves.

        Returns the empty string when the URL doesn't match the
        ``/blob/`` pattern (defensive against malformed inputs).
        """
        marker = "/blob/"
        if marker not in html_url:
            return ""
        after_blob = html_url.split(marker, 1)[1]
        ref = after_blob.split("/", 1)[0] if "/" in after_blob else after_blob
        return ref

    def _normalize_item(self, item: dict[str, Any]) -> CandidateFile:
        """Map one GitHub API search-result item to a CandidateFile."""
        repo = item.get("repository") or {}
        text_matches = []
        if "text_matches" in item:
            for tm in item["text_matches"]:
                fragment = (tm or {}).get("fragment", "")
                if fragment:
                    text_matches.append(fragment[:400])
        html_url = item.get("html_url", "")
        # ``item["sha"]`` is the BLOB sha (content hash). For
        # tarball downloads we need the COMMIT sha — extracted from
        # the html_url's ``/blob/<ref>/`` segment. Fall back to the
        # blob sha if html_url is malformed (defensive; should never
        # happen with real API responses).
        commit_ref = self._extract_commit_ref_from_html_url(html_url) or item.get(
            "sha", ""
        )
        return CandidateFile(
            repo_full_name=repo.get("full_name", ""),
            file_path=item.get("path", ""),
            ref=commit_ref,
            html_url=html_url,
            raw_url=html_url.replace("github.com", "raw.githubusercontent.com").replace(
                "/blob/", "/"
            ),
            repo_stargazers=int(repo.get("stargazers_count", 0) or 0),
            repo_is_fork=bool(repo.get("fork", False)),
            repo_description=str(repo.get("description") or "")[:300],
            text_matches=text_matches,
        )

    async def search(self, query: SearchQuery) -> list[CandidateFile]:
        """Execute the search and return normalized candidates.

        Pages through the API until ``max_results`` candidates are
        collected or the result set is exhausted. The total is
        hard-capped at :data:`HARD_MAX_RESULTS`.

        SCAN-1.5 oversampling: when ``query.oversample_for_star_sort``
        is > 1, the fetch target is ``max_results × oversample``,
        capped at ``HARD_MAX_RESULTS``. After collection, candidates
        are sorted by ``repo_stargazers`` desc + ``repo_is_fork`` asc
        (high-star non-fork wins) and truncated back to
        ``max_results``. The default 2× oversample doubles the
        per-search API spend in exchange for measurably better
        candidate quality on broad sink terms (e.g., ``fetch`` in
        TypeScript).
        """
        # Caller's intended return size — bounded by HARD_MAX_RESULTS.
        target_return = max(1, min(query.max_results, HARD_MAX_RESULTS))

        # Fetch target — possibly oversampled for client-side sort.
        # When oversample=1, the loop fetches exactly target_return.
        oversample = max(1, int(query.oversample_for_star_sort or 1))
        fetch_target = min(target_return * oversample, HARD_MAX_RESULTS)

        per_page = min(GITHUB_PER_PAGE_MAX, fetch_target)

        # Reject queries with empty raw_query — the signature didn't
        # produce search content, and a query made up only of
        # ``stars:>N`` / language filters would return the entire
        # top-starred ecosystem (millions of results). Guard at both
        # raw_query (semantic check) and composed-string (defensive
        # — covers future callers that bypass build_search_query).
        if not query.raw_query.strip():
            raise GitHubSearchError(
                "SearchQuery has empty raw_query. The signature → "
                "query mapper must populate raw_query with at least "
                "the sink callee or attack-class keyword bag."
            )
        q_string = self._build_query_string(query)
        if not q_string.strip():
            raise GitHubSearchError(
                "SearchQuery produced an empty query string. The query "
                "builder must populate raw_query or at least one filter."
            )

        candidates: list[CandidateFile] = []
        page = 1
        async with httpx.AsyncClient() as client:
            while len(candidates) < fetch_target:
                page_size = min(per_page, fetch_target - len(candidates))
                page_size = max(1, page_size)
                data = await self._request_page(
                    client=client,
                    q_string=q_string,
                    per_page=page_size,
                    page=page,
                    include_text_matches=query.include_text_matches,
                )
                items = data.get("items") or []
                if not items:
                    break
                for item in items:
                    if len(candidates) >= fetch_target:
                        break
                    candidates.append(self._normalize_item(item))
                total = int(data.get("total_count", 0) or 0)
                if len(candidates) >= total:
                    break
                page += 1
                if page > 10:
                    break

        n_fetched = len(candidates)

        # Slice 1.6 — enrich with real star counts BEFORE applying
        # min_stars filter. /search/code's truncated repository
        # object always reports 0 stars; the min_stars filter would
        # drop everything without enrichment. Trigger conditions:
        #   * min_stars > 0 (operator wants star filtering — they
        #     need the real numbers)
        #   * oversample > 1 (operator wants star-sorted output —
        #     sort key is meaningless without real numbers)
        # Skip enrichment when neither applies (saves N API calls
        # for callers who just want raw search results).
        if query.min_stars > 0 or oversample > 1:
            async with httpx.AsyncClient() as enrich_client:
                await self.enrich_candidates(candidates, client=enrich_client)

        # SCAN-1.5 client-side post-filter: stars threshold + context
        # keywords. GitHub's REST code search can't express these
        # server-side, so we filter here on the fetched batch. The
        # oversample fetch above is what makes this affordable —
        # we drop low-star + off-context candidates and still have
        # enough left to hit target_return.
        candidates = self._post_filter_candidates(candidates, query)
        n_after_filter = len(candidates)

        # SCAN-1.5 client-side sort: stars desc, non-forks first.
        # Applied when we oversampled OR when min_stars is set (both
        # signal the caller wants quality-prioritized output). When
        # neither applies, preserve GitHub's default order — that's
        # what existing callers expect.
        if oversample > 1 or query.min_stars > 0:
            candidates.sort(
                key=lambda c: (-c.repo_stargazers, c.repo_is_fork)
            )

        # Truncate to caller-requested size.
        candidates = candidates[:target_return]

        log.info(
            "GitHub search returned %d candidates (target=%d, fetched=%d, "
            "post_filter=%d, oversample=%d×): %s",
            len(candidates),
            target_return,
            n_fetched,
            n_after_filter,
            oversample,
            q_string[:120],
        )
        return candidates
