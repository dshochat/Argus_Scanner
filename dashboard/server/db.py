"""Async engine / session plumbing for the dashboard.

The dashboard talks to Postgres over the asyncpg driver. Both the FastAPI
API and the CLI persistence hook share this module so there is one place
that knows the connection contract.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models import Base


def normalize_db_url(db_url: str) -> str:
    """Coerce a plain Postgres URL to the asyncpg driver.

    Accepts the forms users naturally write (``postgresql://`` /
    ``postgres://``) and rewrites them to ``postgresql+asyncpg://`` so the
    async engine works without the caller having to know the driver. A URL
    that already names a driver (``+asyncpg``, ``+psycopg``) is left alone.
    """
    if "+" in db_url.split("://", 1)[0]:
        return db_url
    for prefix in ("postgresql://", "postgres://"):
        if db_url.startswith(prefix):
            return "postgresql+asyncpg://" + db_url[len(prefix) :]
    return db_url


def make_engine(db_url: str) -> AsyncEngine:
    """Create an async engine for ``db_url`` (pre-ping guards stale conns)."""
    return create_async_engine(normalize_db_url(db_url), pool_pre_ping=True, future=True)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Session factory bound to ``engine`` (objects usable after commit)."""
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_models(engine: AsyncEngine) -> None:
    """Create tables/indexes if absent (idempotent). Alembic is deferred."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
