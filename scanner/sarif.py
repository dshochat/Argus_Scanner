"""SARIF v2.1.0 output writer for Argus.

Renders a :class:`scanner.repo_scanner.RepoScanReport` as a SARIF document
that GitHub Code Scanning, Azure DevOps, and most CI dashboards understand.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/

Argus's data model maps to SARIF as:

  ScanResult                       → sarif.runs[*].results[*]
  ScanResult.vulnerabilities[*]    → one sarif result per vulnerability
  Vulnerability.cwe                → result.taxa (CWE taxonomy reference)
  Vulnerability.severity           → result.level + properties.severity
  Vulnerability.type               → result.ruleId
  Vulnerability.line               → result.locations[*].region.startLine
  Vulnerability.explanation        → result.message.text
  Vulnerability.runtime_evidence   → result.message.markdown (if present)
  Vulnerability.status             → result.properties.argus_status
  Vulnerability.proof_of_concept   → result.properties.argus_poc

We deliberately keep this output minimal and conformant rather than
populating every optional field. Consumers (GitHub Security tab, etc.)
display the basics; Argus-specific richness lives in `properties`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from scanner.engine import ScanResult
from scanner.repo_scanner import RepoScanReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
)
ARGUS_TOOL_URI = "https://github.com/dshochat/Argus_Scanner"


# SARIF "level" enum: "none" | "note" | "warning" | "error"
# Argus severity → SARIF level mapping.
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def _severity_to_level(severity: str | None) -> str:
    return _SEVERITY_TO_LEVEL.get((severity or "").lower(), "warning")


def _build_rule(rule_id: str, vuln: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF rule definition from a Vulnerability dict."""
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": vuln.get("type") or rule_id},
        "fullDescription": {
            "text": vuln.get("explanation") or vuln.get("type") or rule_id
        },
        "defaultConfiguration": {
            "level": _severity_to_level(vuln.get("severity")),
        },
        "properties": {
            "tags": ["security"],
        },
    }
    if vuln.get("cwe"):
        rule["properties"]["cwe"] = vuln["cwe"]
    if vuln.get("fix"):
        rule["help"] = {"text": vuln["fix"]}
    return rule


def _build_result(
    result: ScanResult, vuln: dict[str, Any], rule_id: str
) -> dict[str, Any]:
    """Build one SARIF result entry from one Vulnerability dict."""
    line = vuln.get("line")
    try:
        start_line = int(line) if line is not None else 1
    except (TypeError, ValueError):
        start_line = 1

    message_text = vuln.get("explanation") or vuln.get("type") or rule_id

    sarif_result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _severity_to_level(vuln.get("severity")),
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": result.filename,
                        "uriBaseId": "REPO_ROOT",
                    },
                    "region": {"startLine": max(1, start_line)},
                }
            }
        ],
        "properties": {
            "argus_status": vuln.get("status") or "L1_ONLY",
            "argus_severity": vuln.get("severity"),
            "argus_confidence": vuln.get("confidence"),
            "argus_verdict": result.final_verdict,
            "argus_risk_score": result.risk_score,
        },
    }

    if vuln.get("cwe"):
        sarif_result["properties"]["cwe"] = vuln["cwe"]
    if vuln.get("runtime_evidence"):
        sarif_result["properties"]["argus_runtime_evidence"] = vuln[
            "runtime_evidence"
        ]
    if vuln.get("proof_of_concept"):
        sarif_result["properties"]["argus_poc"] = vuln["proof_of_concept"]
    if vuln.get("not_tested_reason"):
        sarif_result["properties"]["argus_not_tested_reason"] = vuln[
            "not_tested_reason"
        ]
    if vuln.get("rejection_reason"):
        sarif_result["properties"]["argus_rejection_reason"] = vuln[
            "rejection_reason"
        ]
    return sarif_result


@dataclass
class SarifContext:
    """Build state for one SARIF document."""

    rules_by_id: dict[str, dict[str, Any]]
    results: list[dict[str, Any]]


def _new_context() -> SarifContext:
    return SarifContext(rules_by_id={}, results=[])


def _ingest_scan_result(ctx: SarifContext, result: ScanResult) -> None:
    """Add one ScanResult's vulnerabilities to the SARIF context."""
    for idx, vuln in enumerate(result.vulnerabilities or []):
        # SARIF rule IDs must be stable + meaningful. Prefer the CWE if
        # present (deterministic, cross-tool comparable); fall back to
        # the type field, then a synthetic id keyed off finding index.
        rule_id = (
            vuln.get("cwe")
            or vuln.get("type")
            or f"argus-finding-{idx}"
        )
        rule_id = str(rule_id)

        if rule_id not in ctx.rules_by_id:
            ctx.rules_by_id[rule_id] = _build_rule(rule_id, vuln)

        ctx.results.append(_build_result(result, vuln, rule_id))


def render_repo_scan_sarif(report: RepoScanReport) -> dict[str, Any]:
    """Build a SARIF v2.1.0 document from a :class:`RepoScanReport`.

    Returns a dict — caller serializes to JSON.
    """
    return _build_sarif_doc(report.results)


def render_scan_results_sarif(results: Iterable[ScanResult]) -> dict[str, Any]:
    """Build a SARIF v2.1.0 document from any iterable of ScanResults.

    Useful for single-file scans that still want SARIF output.
    """
    return _build_sarif_doc(list(results))


def _build_sarif_doc(results: list[ScanResult]) -> dict[str, Any]:
    ctx = _new_context()
    for r in results:
        _ingest_scan_result(ctx, r)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Argus",
                        "informationUri": ARGUS_TOOL_URI,
                        "rules": list(ctx.rules_by_id.values()),
                    }
                },
                "originalUriBaseIds": {
                    "REPO_ROOT": {"uri": "file:///"}
                },
                "results": ctx.results,
            }
        ],
    }


def to_sarif_string(doc: dict[str, Any]) -> str:
    """Serialize a SARIF document to a JSON string with stable formatting."""
    return json.dumps(doc, indent=2, sort_keys=False)


__all__ = [
    "SARIF_VERSION",
    "render_repo_scan_sarif",
    "render_scan_results_sarif",
    "to_sarif_string",
]
