"""FastAPI application factory for the Argus dashboard.

``create_app(db_url)`` wires the async engine + session factory into app
state, mounts the JSON API under ``/api``, and serves the pre-built React
SPA at ``/`` (with a history-fallback so client-side routes survive a hard
refresh). No auth — bind to localhost.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Scope

from .api import router as api_router
from .db import make_engine, make_session_factory

_STATIC_DIR = Path(__file__).parent / "static"


class SPAStaticFiles(StaticFiles):
    """StaticFiles that falls back to ``index.html`` for unknown paths.

    A single-page app owns its own routing (``/scans/42`` is a client
    route, not a file). On a 404 we serve ``index.html`` so deep links and
    hard refreshes work; real missing assets still 404 via index's loader.
    """

    async def get_response(self, path: str, scope: Scope) -> Any:
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            # Starlette raises 404 for a missing path; serve the SPA shell so
            # client-side routes (e.g. /scans/42) work on a hard refresh.
            if exc.status_code == 404:
                return await super().get_response("index.html", scope)
            raise
        if response.status_code == 404:
            return await super().get_response("index.html", scope)
        return response


def create_app(db_url: str) -> FastAPI:
    """Build the dashboard FastAPI app bound to ``db_url``."""
    engine = make_engine(db_url)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        await engine.dispose()

    app = FastAPI(title="Argus Dashboard", version="0.1.0", lifespan=lifespan)
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    app.include_router(api_router, prefix="/api")

    # Serve the built SPA last so /api/* matches first.
    if (_STATIC_DIR / "index.html").is_file():
        app.mount("/", SPAStaticFiles(directory=str(_STATIC_DIR), html=True), name="spa")
    else:

        @app.get("/")
        async def _no_ui() -> JSONResponse:
            return JSONResponse(
                {
                    "status": "ok",
                    "detail": "API is up but the dashboard UI is not built. "
                    "Build it with `npm --prefix dashboard/frontend install && "
                    "npm --prefix dashboard/frontend run build`, or use a wheel "
                    "(the UI ships pre-built). API docs: /docs",
                }
            )

    return app
