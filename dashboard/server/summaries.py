"""Pure projections from a raw ``ScanResult.to_dict()`` payload.

No DB, no I/O — just dict→dict so these are trivially unit-testable and
reused by both the persistence hook (to fill the summary columns) and the
API (to compute the management one-liner). Everything is defensive: any
nested block may be ``None`` or missing (opt-in pipeline stages), so we
never assume shape.
"""

from __future__ import annotations

from typing import Any

# DAST per-finding status that means "sandbox observed the exploit fire".
_CONFIRMED = "CONFIRMED"


def _as_list(value: Any) -> list[dict[str, Any]]:
    """Coerce a possibly-missing field to a list of dicts (defensive)."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def flow_rollup(raw: dict[str, Any]) -> dict[str, Any]:
    """The three-stage headline: findings → confirmed → remediation confidence.

    * ``n_findings``  — L1/SAST vulnerabilities reported.
    * ``n_confirmed`` — findings DAST validated as actually exploitable.
    * ``remediation_confidence`` — the verified-remediation gate label
      (HIGH | MEDIUM | LOW | FAILED), or ``None`` if remediation/verification
      didn't run.
    """
    n_findings = len(_as_list(raw.get("vulnerabilities")))
    n_confirmed = sum(
        1
        for v in _as_list(raw.get("per_finding_validation"))
        if str(v.get("status") or "").upper() == _CONFIRMED
    )

    remediation_confidence: str | None = None
    phase_c = raw.get("phase_c")
    if isinstance(phase_c, dict):
        verification = phase_c.get("verification")
        if isinstance(verification, dict):
            conf = verification.get("confidence")
            remediation_confidence = str(conf) if conf else None

    return {
        "n_findings": n_findings,
        "n_confirmed": n_confirmed,
        "remediation_confidence": remediation_confidence,
    }


def summary_cols(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract the ``scans`` summary columns from a raw result dict.

    Returns exactly the keyword args the ``Scan`` model's summary columns
    expect (excluding ``raw`` / grouping / ``created_at``).
    """
    roll = flow_rollup(raw)
    cost = raw.get("total_cost_usd")
    return {
        "filename": str(raw.get("filename") or ""),
        "file_hash": raw.get("file_hash"),
        "language": raw.get("language"),
        "triage_classification": raw.get("triage_classification"),
        "final_verdict": raw.get("final_verdict"),
        "risk_score": raw.get("risk_score"),
        "risk_level": raw.get("risk_level"),
        "intent": raw.get("intent"),
        "dast_attempted": bool(raw.get("dast_attempted")),
        "n_findings": roll["n_findings"],
        "n_confirmed": roll["n_confirmed"],
        "remediation_confidence": roll["remediation_confidence"],
        "total_cost_usd": float(cost) if isinstance(cost, (int, float)) else None,
        "total_duration_ms": raw.get("total_duration_ms"),
    }
