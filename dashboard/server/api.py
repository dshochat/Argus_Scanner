"""REST API for the dashboard (mounted under ``/api``).

Read-only over the ``scans`` table. List/filter/sort use the summary
columns; aggregates that reach into the nested result (vulns by severity,
top vuln types) use Postgres JSONB functions over ``raw``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import asc, case, desc, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Scan
from .schemas import (
    CountItem,
    RunSummary,
    ScanDetail,
    ScansPage,
    ScanSummary,
    Stats,
    TimeBucket,
)

router = APIRouter()

# Verdict severity ordering (for "files at risk" + per-run worst verdict).
_VERDICT_RANK: dict[str, int] = {
    "clean": 0,
    "informational": 1,
    "suspicious": 2,
    "malicious": 3,
    "critical_malicious": 4,
}
_RANK_VERDICT = {v: k for k, v in _VERDICT_RANK.items()}
_AT_RISK = ("suspicious", "malicious", "critical_malicious")

# Whitelisted sort columns (avoid arbitrary ORDER BY injection).
_SORTABLE = {
    "created_at": Scan.created_at,
    "risk_score": Scan.risk_score,
    "total_cost_usd": Scan.total_cost_usd,
    "n_findings": Scan.n_findings,
    "n_confirmed": Scan.n_confirmed,
    "filename": Scan.filename,
    "final_verdict": Scan.final_verdict,
}


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield an async session from the app's session factory."""
    factory = request.app.state.session_factory
    async with factory() as session:
        yield session


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


async def _counts(session: AsyncSession, column: Any) -> list[CountItem]:
    """Grouped count over a summary column (NULLs dropped)."""
    stmt = select(column, func.count()).where(column.isnot(None)).group_by(column)
    rows = (await session.execute(stmt)).all()
    return [CountItem(key=str(k), count=int(c)) for k, c in rows]


async def _jsonb_counts(session: AsyncSession, field: str, limit: int | None = None) -> list[CountItem]:
    """Count a field across every element of ``raw->'vulnerabilities'``."""
    sql = (
        "SELECT lower(elem->>:field) AS k, count(*) AS c "
        "FROM scans, jsonb_array_elements(raw->'vulnerabilities') AS elem "
        "WHERE jsonb_typeof(raw->'vulnerabilities') = 'array' AND elem->>:field IS NOT NULL "
        "GROUP BY k ORDER BY c DESC"
    )
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = (await session.execute(text(sql), {"field": field})).all()
    return [CountItem(key=str(k), count=int(c)) for k, c in rows]


@router.get("/stats", response_model=Stats)
async def stats(session: AsyncSession = Depends(get_session)) -> Stats:
    total_scans = int((await session.execute(select(func.count()).select_from(Scan))).scalar_one())
    files_at_risk = int(
        (
            await session.execute(
                select(func.count()).select_from(Scan).where(Scan.final_verdict.in_(_AT_RISK))
            )
        ).scalar_one()
    )
    confirmed = int(
        (await session.execute(select(func.coalesce(func.sum(Scan.n_confirmed), 0)))).scalar_one()
    )
    remediated_high = int(
        (
            await session.execute(
                select(func.count()).select_from(Scan).where(Scan.remediation_confidence == "HIGH")
            )
        ).scalar_one()
    )
    total_cost = float(
        (await session.execute(select(func.coalesce(func.sum(Scan.total_cost_usd), 0.0)))).scalar_one() or 0.0
    )

    # Scans + spend per day.
    day = func.date_trunc("day", Scan.created_at).label("day")
    over_time_rows = (
        await session.execute(
            select(day, func.count(), func.coalesce(func.sum(Scan.total_cost_usd), 0.0)).group_by(day).order_by(day)
        )
    ).all()
    over_time = [
        TimeBucket(date=d.date().isoformat() if d else "", count=int(c), cost=round(float(cost or 0.0), 6))
        for d, c, cost in over_time_rows
    ]

    return Stats(
        total_scans=total_scans,
        files_at_risk=files_at_risk,
        confirmed_exploitable=confirmed,
        auto_remediated_high=remediated_high,
        total_cost_usd=round(total_cost, 6),
        by_verdict=await _counts(session, Scan.final_verdict),
        by_risk=await _counts(session, Scan.risk_level),
        by_severity=await _jsonb_counts(session, "severity"),
        by_remediation_confidence=await _counts(session, Scan.remediation_confidence),
        top_vuln_types=await _jsonb_counts(session, "type", limit=10),
        over_time=over_time,
    )


@router.get("/scans", response_model=ScansPage)
async def list_scans(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    verdict: str | None = None,
    risk_level: str | None = None,
    language: str | None = None,
    dast_attempted: bool | None = None,
    run_id: str | None = None,
    q: str | None = None,
    sort: str = "created_at",
    order: str = "desc",
) -> ScansPage:
    filters = []
    if verdict:
        filters.append(Scan.final_verdict == verdict)
    if risk_level:
        filters.append(Scan.risk_level == risk_level)
    if language:
        filters.append(Scan.language == language)
    if dast_attempted is not None:
        filters.append(Scan.dast_attempted.is_(dast_attempted))
    if run_id:
        filters.append(Scan.run_id == run_id)
    if q:
        filters.append(Scan.filename.ilike(f"%{q}%"))

    total = int(
        (await session.execute(select(func.count()).select_from(Scan).where(*filters))).scalar_one()
    )
    col = _SORTABLE.get(sort, Scan.created_at)
    direction = asc if order == "asc" else desc
    stmt = select(Scan).where(*filters).order_by(direction(col)).limit(limit).offset(offset)
    rows = (await session.execute(stmt)).scalars().all()
    return ScansPage(
        items=[ScanSummary.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: int, session: AsyncSession = Depends(get_session)) -> ScanDetail:
    row = await session.get(Scan, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return ScanDetail.model_validate(row)


@router.get("/runs", response_model=list[RunSummary])
async def list_runs(session: AsyncSession = Depends(get_session)) -> list[RunSummary]:
    rank = case(_VERDICT_RANK, value=Scan.final_verdict, else_=0)
    stmt = (
        select(
            Scan.run_id,
            func.max(Scan.run_label),
            func.count(),
            func.coalesce(func.sum(Scan.n_findings), 0),
            func.coalesce(func.sum(Scan.n_confirmed), 0),
            func.max(rank),
            func.coalesce(func.sum(Scan.total_cost_usd), 0.0),
            func.max(Scan.created_at),
        )
        .where(Scan.run_id.isnot(None))
        .group_by(Scan.run_id)
        .order_by(func.max(Scan.created_at).desc())
    )
    rows = (await session.execute(stmt)).all()
    out: list[RunSummary] = []
    for run_id, label, n_files, n_find, n_conf, worst_rank, cost, created in rows:
        out.append(
            RunSummary(
                run_id=str(run_id),
                run_label=label,
                n_files=int(n_files),
                n_findings=int(n_find),
                n_confirmed=int(n_conf),
                worst_verdict=_RANK_VERDICT.get(int(worst_rank)),
                total_cost_usd=round(float(cost), 6),
                created_at=created,
            )
        )
    return out
