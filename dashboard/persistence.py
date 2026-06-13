"""Write scan results into the dashboard's Postgres store.

This is the producer side of the dashboard. It is imported LAZILY by the
scanner CLI (only when ``ARGUS_DB_URL`` is set), and every entry point
degrades gracefully: if the ``[dashboard]`` extra isn't installed, or the
DB is unreachable, it prints a one-line hint and returns 0 rather than
ever failing a scan. The scanner's exit code must not depend on the
dashboard being present.
"""

from __future__ import annotations

import sys
from typing import Any

_INSTALL_HINT = (
    "argus: dashboard persistence needs the optional extra — "
    "`pip install argus-ai-scanner[dashboard]`"
)


async def persist_many(
    result_dicts: list[dict[str, Any]],
    db_url: str,
    *,
    run_id: str | None = None,
    run_label: str | None = None,
    source: str = "scan",
) -> int:
    """Insert ``result_dicts`` (each a ``ScanResult.to_dict()``) into Postgres.

    Returns the number of rows written (0 on any failure). Never raises:
    a missing extra, a bad URL, or a DB outage must not break a scan.
    """
    if not result_dicts:
        return 0
    try:
        from .server.db import make_engine, make_session_factory
        from .server.models import Scan
        from .server.summaries import summary_cols
    except ImportError:
        print(_INSTALL_HINT, file=sys.stderr)
        return 0

    try:
        engine = make_engine(db_url)
    except Exception as exc:  # noqa: BLE001 — bad URL / missing driver
        print(f"argus: dashboard persistence skipped — {type(exc).__name__}: {exc}", file=sys.stderr)
        return 0

    try:
        factory = make_session_factory(engine)
        async with factory() as session:
            for raw in result_dicts:
                session.add(
                    Scan(run_id=run_id, run_label=run_label, source=source, raw=raw, **summary_cols(raw))
                )
            await session.commit()
        return len(result_dicts)
    except Exception as exc:  # noqa: BLE001 — connection / commit failure
        print(f"argus: dashboard persistence failed — {type(exc).__name__}: {exc}", file=sys.stderr)
        return 0
    finally:
        await engine.dispose()


async def persist_scan_result(
    result_dict: dict[str, Any],
    db_url: str,
    *,
    run_id: str | None = None,
    run_label: str | None = None,
    source: str = "scan",
) -> bool:
    """Persist a single scan result. Returns True if the row was written."""
    written = await persist_many(
        [result_dict], db_url, run_id=run_id, run_label=run_label, source=source
    )
    return written > 0
