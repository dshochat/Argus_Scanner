"""Hermetic tests for the dashboard app factory + persistence guard.

DB-backed API behavior is covered by the host integration smoke (real
Postgres); these run without a database.
"""

from __future__ import annotations

import pytest

from dashboard.persistence import persist_many


def test_create_app_exposes_api_routes() -> None:
    from dashboard.server.app import create_app

    app = create_app("postgresql://x:y@localhost:5432/z")  # no connection at build time
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/api/stats" in paths
    assert "/api/scans" in paths
    assert "/api/scans/{scan_id}" in paths
    assert "/api/runs" in paths
    assert "/api/health" in paths


@pytest.mark.asyncio
async def test_persist_many_empty_is_noop() -> None:
    # No rows → no engine, no connection, returns 0.
    assert await persist_many([], "postgresql://x:y@localhost:5432/z") == 0
