"""DAST-303 — Cross-repo code-index backends for variant hunting.

Backends:
  * ``github_search``: GitHub Code Search REST API. Free with a PAT
    (60 req/min). Covers public GitHub (a large majority of the
    open-source ecosystem). The v1 default.
  * (planned v2) ``sourcegraph``: structural + regex search across
    Sourcegraph's broader index (npm + pypi mirrors + private
    deployments).
  * (planned v3) ``npm_registry``: tarball-download fallback for
    npm-only ecosystem coverage when GitHub indexing lags.

Public API:

  search_candidates(query: SearchQuery, backend: str = "github")
      -> list[CandidateFile]

  Each backend implements the same protocol. Switching backends is
  a config change, not a code change.

The signature → query mapping (translating a SemanticSignature from
Phase D into a backend-specific search query) lives in
``dast/cross_repo_query.py``, NOT here. This module is pure I/O:
take a query, return candidate files. The mapping is signature-
class-aware and lives next to the signature schema.
"""

from __future__ import annotations

from dast.code_index.github_search import (
    CandidateFile,
    GitHubCodeSearchClient,
    GitHubSearchError,
    ReposSearchQuery,
    SearchQuery,
)

__all__ = [
    "CandidateFile",
    "GitHubCodeSearchClient",
    "GitHubSearchError",
    "ReposSearchQuery",
    "SearchQuery",
]
