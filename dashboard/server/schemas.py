"""Pydantic v2 response models for the dashboard API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ScanSummary(BaseModel):
    """One row in the scans list (summary columns only — no heavy ``raw``)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: str | None
    run_label: str | None
    source: str
    filename: str
    file_hash: str | None
    language: str | None
    triage_classification: str | None
    final_verdict: str | None
    risk_score: int | None
    risk_level: str | None
    intent: str | None
    dast_attempted: bool
    n_findings: int
    n_confirmed: int
    remediation_confidence: str | None
    total_cost_usd: float | None
    total_duration_ms: int | None
    created_at: datetime


class ScanDetail(ScanSummary):
    """Full scan record incl. the raw ``ScanResult.to_dict()`` for the flow."""

    raw: dict[str, Any]


class ScansPage(BaseModel):
    """Paginated scans list."""

    items: list[ScanSummary]
    total: int
    limit: int
    offset: int


class CountItem(BaseModel):
    """A labeled count (verdict/severity/type/confidence distribution entry)."""

    key: str
    count: int


class TimeBucket(BaseModel):
    """Per-day scan volume + spend (for the cost/activity chart)."""

    date: str
    count: int
    cost: float


class Stats(BaseModel):
    """Aggregate KPIs + chart series for the Overview page."""

    total_scans: int
    files_at_risk: int
    confirmed_exploitable: int
    auto_remediated_high: int
    total_cost_usd: float
    by_verdict: list[CountItem]
    by_risk: list[CountItem]
    by_severity: list[CountItem]
    by_remediation_confidence: list[CountItem]
    top_vuln_types: list[CountItem]
    over_time: list[TimeBucket]


class RunSummary(BaseModel):
    """One grouped `scan-repo` run."""

    run_id: str
    run_label: str | None
    n_files: int
    n_findings: int
    n_confirmed: int
    worst_verdict: str | None
    total_cost_usd: float
    created_at: datetime
