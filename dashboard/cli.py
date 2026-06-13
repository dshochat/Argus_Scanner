"""Handlers for ``argus dashboard {serve,init-db,ingest}``.

Heavy imports (fastapi, uvicorn, sqlalchemy) live HERE, not in
scanner/cli.py, so the base CLI never loads them. scanner/cli.py
lazy-imports ``run_dashboard`` only when the ``dashboard`` command runs,
and prints an install hint if the ``[dashboard]`` extra is missing.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

_INSTALL_HINT = "`pip install argus-ai-scanner[dashboard]`"
_DB_HINT = (
    "set --db-url or ARGUS_DB_URL "
    "(e.g. postgresql://argus:argus@localhost:5432/argus)"
)


def _resolve_db_url(args: argparse.Namespace) -> str | None:
    return getattr(args, "db_url", None) or os.environ.get("ARGUS_DB_URL")


def _load_results(path: Path) -> list[dict[str, Any]]:
    """Load scan-result dicts from a .json file, a JSON array, or a dir of either."""
    files: list[Path]
    if path.is_dir():
        files = sorted(path.glob("*.json"))
    elif path.is_file():
        files = [path]
    else:
        raise FileNotFoundError(f"no such file or directory: {path}")

    results: list[dict[str, Any]] = []
    for f in files:
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(f"argus: skipping {f.name} — not valid JSON ({exc})", file=sys.stderr)
            continue
        if isinstance(doc, list):
            results.extend(d for d in doc if isinstance(d, dict))
        elif isinstance(doc, dict):
            results.append(doc)
    return results


async def _init_db(db_url: str) -> None:
    from .server.db import init_models, make_engine

    engine = make_engine(db_url)
    try:
        await init_models(engine)
    finally:
        await engine.dispose()


async def _ingest(db_url: str, path: Path) -> int:
    from .persistence import persist_many

    results = _load_results(path)
    if not results:
        print(f"argus: no scan results found in {path}", file=sys.stderr)
        return 0
    return await persist_many(results, db_url, run_label=f"ingest:{path}", source="ingest")


def _missing_extra() -> list[str]:
    """Names of [dashboard] deps that aren't importable (without importing them)."""
    import importlib.util

    return [m for m in ("fastapi", "uvicorn", "sqlalchemy", "asyncpg") if importlib.util.find_spec(m) is None]


def run_dashboard(args: argparse.Namespace) -> int:
    """Dispatch the ``dashboard`` subcommand. Returns a process exit code."""
    db_url = _resolve_db_url(args)
    if not db_url:
        print(f"argus dashboard: {_DB_HINT}", file=sys.stderr)
        return 2

    missing = _missing_extra()
    if missing:
        print(
            f"argus dashboard: missing optional dependencies {missing} — {_INSTALL_HINT}",
            file=sys.stderr,
        )
        return 2

    command = getattr(args, "dashboard_command", None)

    if command == "init-db":
        asyncio.run(_init_db(db_url))
        print("argus dashboard: schema ready")
        return 0

    if command == "ingest":
        n = asyncio.run(_ingest(db_url, Path(args.path)))
        print(f"argus dashboard: ingested {n} scan result(s)")
        return 0

    if command == "serve":
        import uvicorn

        from .server.app import create_app

        host = getattr(args, "host", "127.0.0.1")
        port = int(getattr(args, "port", 8000))
        print(f"argus dashboard: serving on http://{host}:{port}  (Ctrl-C to stop)")
        uvicorn.run(create_app(db_url), host=host, port=port, log_level="info")
        return 0

    print(f"argus dashboard: unknown subcommand {command!r}", file=sys.stderr)
    return 2
