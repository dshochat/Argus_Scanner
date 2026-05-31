"""Shared fixtures for preprocessing integration tests.

Loads `.env`, opens a read-only psycopg2 connection to the Supabase
`files` table, and skips every test cleanly if no DB URL is configured.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[3] / ".env")

try:
    import psycopg2
except ImportError:
    psycopg2 = None


def _db_url() -> str | None:
    return (
        os.environ.get("ECHO_DATA_URL")
        or os.environ.get("SUPABASE_DIRECT_URL")
        or os.environ.get("DATABASE_URL")
    )


@pytest.fixture(scope="session")
def db_conn() -> Iterator[object]:
    if psycopg2 is None:
        pytest.skip("psycopg2 not installed")
    url = _db_url()
    if not url:
        pytest.skip("no SUPABASE_DIRECT_URL / DATABASE_URL / ECHO_DATA_URL in env")
    conn = psycopg2.connect(url)
    conn.set_session(readonly=True, autocommit=True)
    with conn.cursor() as cur:
        cur.execute("SET statement_timeout = '120s'")
    try:
        yield conn
    finally:
        conn.close()
