"""SQLAlchemy 2.0 model for persisted scan results.

ONE table, ``scans``: a denormalized snapshot per ``ScanResult.to_dict()``.
We keep summary columns (the list/filter/sort axes) for fast queries AND
the full result in a JSONB ``raw`` column (the per-file flow detail). The
scanner's result schema grows almost every version, so normalizing the
nested blocks (vulnerabilities / per_finding_validation / phase_c / …)
into child tables would mean a brittle migration on every release. JSONB +
a GIN index gives queryability without that coupling; promoting findings
to a projection table is a non-breaking follow-up if cross-scan analytics
become a hard requirement.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all dashboard tables."""


class Scan(Base):
    """One persisted scan result (single-file scan or one file of a repo run)."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Grouping: a `scan-repo` invocation stamps every file with one run_id.
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    run_label: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="scan", nullable=False)

    # Summary columns (extracted from `raw` at write time by summaries.py).
    filename: Mapped[str] = mapped_column(String(2048), nullable=False)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    language: Mapped[str | None] = mapped_column(String(64), nullable=True)
    triage_classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    final_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    intent: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dast_attempted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    n_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    n_confirmed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    remediation_confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    total_cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    # Full ScanResult.to_dict() — the per-file flow detail.
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    __table_args__ = (
        # GIN on the JSONB doc enables containment queries (e.g. "scans whose
        # vulnerabilities contain CWE-918") without a normalized child table.
        Index("ix_scans_raw_gin", "raw", postgresql_using="gin"),
    )
