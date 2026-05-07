"""BENCH-010 — three-source comparison report.

Per-file diff combining four signals:

  1. Argus output           (all 23 — vulnerabilities[], behavioral_profile,
                             attack_chains, ai_tool_analysis, dast artifacts)
  2. Vanilla Opus output    (all 23 — same shape via the combined SCAN_PROMPT)
  3. Rich oracle findings   (4-5 files only — augmented_final.json's
                             ``analysis.findings`` + ``extractions``)
  4. Verdict labels         (all 23 from regression_baseline.json, with
                             provenance flag — variance_characterization
                             vs Opus-confirmed)

Output shape (per file):

    {
      "file_name": "litellm_obfuscated.py",
      "verdict_match": {
        "argus": "critical_malicious", "opus": "critical_malicious",
        "oracle": "critical_malicious", "label_provenance": "opus_confirmed",
        "all_match": true
      },
      "findings_per_source": {
        "argus":  [{cwe, type, severity, line}, ...],
        "opus":   [{cwe, type, severity, line}, ...],
        "oracle": [{cwe, type, severity, line}, ...] | null
      },
      "cwe_overlap":         {argus_vs_oracle: {p,r,f1,jaccard}, opus_vs_oracle: {...}} | null,
      "capability_overlap":  {argus_vs_oracle: {...}, opus_vs_oracle: {...}} | null,
      "dast_artifacts_argus": [{stage, ...}],
      "argus_refused": false, "opus_refused": false,
      "judge_payload": {<framed question for BENCH-011>} | null
    }

Files outside the rich-oracle's 4-5-file subset get ``cwe_overlap`` and
``capability_overlap`` as ``null`` (we have label-only ground truth for
them — Tier 1 verdict-match still applies).

Filename normalization: ``augmented_final.json`` keys files as
``01_litellm_obfuscated.py`` (echoDefense's prefix convention);
``regression_baseline.json`` and on-disk samples use the stripped form
(``litellm_obfuscated.py``). ``_normalize_filename`` strips the
``^\\d+_`` and category prefixes (``supply_c__``, ``vulnerab__``,
``attack_c__``, ``malware__``) so lookups match.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from methodology.bench import BenchRow, _load_existing_rows

# ── Normalized cross-source finding shape ─────────────────────────────────


@dataclass(frozen=True)
class FindingRef:
    """One finding, common shape across Argus / vanilla Opus / oracle."""

    cwe: str  # "CWE-522" or "" if none
    type: str  # lowercase finding category, e.g. "code_injection"
    severity: str  # critical | high | medium | low | ""
    line: int | None
    confidence: float | None
    title: str  # short descriptor for the human-readable report

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "type": self.type,
            "severity": self.severity,
            "line": self.line,
            "confidence": self.confidence,
            "title": self.title,
        }


def normalize_argus_vulnerability(v: dict[str, Any]) -> FindingRef:
    return FindingRef(
        cwe=str(v.get("cwe") or "").strip().upper(),
        type=str(v.get("type") or "").strip().lower(),
        severity=str(v.get("severity") or "").strip().lower(),
        line=v.get("line") if isinstance(v.get("line"), int) else None,
        confidence=v.get("confidence") if isinstance(v.get("confidence"), (int, float)) else None,
        title=str(v.get("explanation") or v.get("type") or "")[:120],
    )


def normalize_oracle_finding(f: dict[str, Any]) -> FindingRef:
    snippet = f.get("code_snippet") or {}
    lines = snippet.get("lines") if isinstance(snippet, dict) else None
    line: int | None = None
    if isinstance(lines, list) and lines and isinstance(lines[0], int):
        line = lines[0]
    return FindingRef(
        cwe=str(f.get("cwe") or "").strip().upper(),
        type=str(f.get("type") or "").strip().lower(),
        severity=str(f.get("severity") or "").strip().lower(),
        line=line,
        confidence=f.get("confidence") if isinstance(f.get("confidence"), (int, float)) else None,
        title=str(f.get("title") or "")[:120],
    )


# ── Filename normalization ────────────────────────────────────────────────

_PREFIX_NUMERIC = re.compile(r"^\d+_")
_PREFIX_CATEGORY = re.compile(r"^(supply_c|vulnerab|attack_c|malware)_+")


def _normalize_filename(name: str) -> str:
    """Strip echoDefense's filename prefixes to canonical form.

    Examples::

        01_litellm_obfuscated.py            -> litellm_obfuscated.py
        supply_c__docker_entrypoint_init.py -> docker_entrypoint_init.py
        vulnerab__sandbox_runner.js         -> sandbox_runner.js

    Idempotent on already-stripped names (does nothing if no prefix).
    """
    n = _PREFIX_NUMERIC.sub("", name)
    n = _PREFIX_CATEGORY.sub("", n)
    return n


# ── Loaders ───────────────────────────────────────────────────────────────


def load_baseline_oracle(path: Path) -> dict[str, dict[str, Any]]:
    """Return ``{file_name: {oracle_verdict, baseline_verdict, source, tier,
    tracking}}`` from a regression_baseline.json. Keys are the canonical
    (already-stripped) names that match the on-disk fixture filenames.
    """
    if not path.exists():
        return {}
    with path.open() as f:
        data = json.load(f)
    out: dict[str, dict[str, Any]] = {}
    for entry in data.get("files", []) or []:
        if not isinstance(entry, dict):
            continue
        fn = entry.get("file_name")
        if not fn:
            continue
        out[fn] = {
            "oracle_verdict": entry.get("oracle_verdict"),
            "baseline_verdict": entry.get("baseline_verdict"),
            "source": entry.get("source", "variance_characterization"),
            "tier": entry.get("tier"),
            "tracking": entry.get("tracking"),
        }
    return out


def load_rich_oracle(path: Path) -> dict[str, dict[str, Any]]:
    """Return ``{normalized_file_name: {findings, capability_tags,
    dangerous_apis, verdict_label, model}}`` from
    eval_benchmark_v1_ground_truth_augmented_final.json.

    Keys are normalized via :func:`_normalize_filename` so they match the
    canonical names used in regression_baseline.json. Only entries with
    a known model (e.g., ``claude-opus-4-7``) get ``label_provenance =
    "opus_confirmed"``; others fall back to the baseline's source flag.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        raw_name = entry.get("file_name") or ""
        if not raw_name:
            continue
        canonical = _normalize_filename(raw_name)
        full_label = entry.get("full_label") or {}
        analysis = full_label.get("analysis") or {}
        extractions = full_label.get("extractions") or {}
        capabilities = extractions.get("capabilities") or {}
        verdict_block = full_label.get("verdict") or {}
        oracle_findings_raw = analysis.get("findings") or []

        out[canonical] = {
            "findings": [normalize_oracle_finding(f) for f in oracle_findings_raw if isinstance(f, dict)],
            "capability_tags": [str(t) for t in (capabilities.get("tags") or []) if t],
            "dangerous_apis": [str(a) for a in (capabilities.get("dangerous_apis") or []) if a],
            "verdict_label": verdict_block.get("verdict_label"),
            "model": entry.get("model"),
            "raw_filename": raw_name,
        }
    return out


def load_bench_rows(path: Path) -> list[BenchRow]:
    """Re-export the bench's row loader so callers can import everything
    from one module."""
    return _load_existing_rows(path)


# ── Capability extraction (heuristic mapping from scanner output) ─────────


def extract_capability_tags(row: BenchRow) -> set[str]:
    """Heuristically derive oracle-vocabulary capability tags from a
    scanner's behavioral_profile + vulnerabilities + attack_chains.

    The oracle's tag vocabulary (e.g., "network_outbound", "credential_access",
    "data_exfiltration") doesn't have a strict mapping to scanner output —
    this function is a best-effort heuristic for finding-coverage scoring
    on the rich-oracle subset.
    """
    tags: set[str] = set()
    bp = row.behavioral_profile or {}
    actual = bp.get("actual_capabilities") if isinstance(bp, dict) else None
    if isinstance(actual, dict):
        net = actual.get("network_calls") or []
        if isinstance(net, list) and net:
            tags.add("network_outbound")
        file_ops = actual.get("file_operations") or []
        if isinstance(file_ops, list):
            for op in file_ops:
                lo = str(op).lower()
                if "read" in lo:
                    tags.add("file_read")
                if "write" in lo:
                    tags.add("file_write")
        cmds = actual.get("commands_executed") or []
        if isinstance(cmds, list) and cmds:
            tags.add("process_spawn")
            for c in cmds:
                if any(k in str(c).lower() for k in ("exec", "eval", "subprocess", "os.system")):
                    tags.add("dynamic_execution")
        if actual.get("env_vars_accessed"):
            tags.add("env_access")
        if actual.get("crypto_operations"):
            tags.add("crypto_use")
        if actual.get("dynamic_imports"):
            tags.add("dynamic_execution")
    exfil = bp.get("exfiltration_risk") if isinstance(bp, dict) else None
    if isinstance(exfil, dict) and exfil.get("external_network_calls"):
        tags.add("data_exfiltration")
    obf = bp.get("obfuscation_signals") if isinstance(bp, dict) else None
    if isinstance(obf, dict):
        if obf.get("encoded_strings") or obf.get("dynamic_url_construction"):
            tags.add("defense_evasion")
        if obf.get("encoded_strings"):
            tags.add("data_encoding")

    # Vulnerability + attack-chain text-search for finer signals.
    blob_parts: list[str] = []
    for v in row.vulnerabilities:
        if not isinstance(v, dict):
            continue
        blob_parts.append(str(v.get("type") or ""))
        blob_parts.append(str(v.get("explanation") or ""))
    for c in row.attack_chains:
        if not isinstance(c, dict):
            continue
        blob_parts.append(str(c.get("name") or c.get("title") or ""))
    blob = " ".join(blob_parts).lower()
    if "credential" in blob or "ssh key" in blob or "password" in blob:
        tags.add("credential_access")
    if "exfil" in blob or "data exfiltration" in blob:
        tags.add("data_exfiltration")
    if "c2" in blob or "command and control" in blob or "beacon" in blob:
        tags.add("c2_communication")
    return tags


# ── Set-overlap metric ────────────────────────────────────────────────────


def compute_overlap(scanner: set[str], oracle: set[str]) -> dict[str, float]:
    """Precision / recall / F1 / Jaccard of two label sets.

    Edge cases: both empty → all 1.0 (perfectly aligned, vacuously);
    one empty → corresponding metric is 0.0.
    """
    if not scanner and not oracle:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "jaccard": 1.0}
    inter = scanner & oracle
    n_inter = len(inter)
    n_s = len(scanner)
    n_o = len(oracle)
    precision = n_inter / n_s if n_s else 0.0
    recall = n_inter / n_o if n_o else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    union = scanner | oracle
    jaccard = n_inter / len(union) if union else 0.0
    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "jaccard": round(jaccard, 3),
    }


# ── Refusal detection ─────────────────────────────────────────────────────


def _is_refusal(row: BenchRow | None) -> bool:
    if row is None:
        return False
    err = (row.error or "").lower()
    return "refus" in err  # matches "refusal", "refused"


# ── Judge payload framing (input for BENCH-011) ───────────────────────────


def _summarize_position(label: str, row: BenchRow | None) -> dict[str, Any]:
    """Brief structured summary of one scanner's position on a file.

    Note: ``label`` ("argus" or "opus") is INCLUDED here for diagnostic
    storage; BENCH-011 strips it before sending to the judge so the
    judge can't bias on which scanner produced which output.
    """
    if row is None:
        return {"_label_internal": label, "verdict": None, "n_findings": 0, "findings": []}
    findings = [normalize_argus_vulnerability(v).to_dict() for v in row.vulnerabilities if isinstance(v, dict)]
    return {
        "_label_internal": label,
        "verdict": row.predicted_verdict,
        "n_findings": len(findings),
        "findings": findings,
        "scan_path": list(row.scan_path),
        "dast_attempted": row.dast_attempted,
        "refused": _is_refusal(row),
    }


def build_judge_payload(
    file_name: str,
    argus_row: BenchRow | None,
    opus_row: BenchRow | None,
    oracle_verdict: str | None,
    file_content: str | None,
) -> dict[str, Any]:
    """Build the input the GPT-5 judge needs for one disagreement.

    The judge sees:
      * the file content (so it can reason about the actual code)
      * two unlabeled positions A and B (Argus's + vanilla Opus's
        outputs, randomized A/B mapping in BENCH-011)
      * the oracle verdict label (with its source caveat)

    Returns the structured payload that BENCH-011's randomizer +
    sender consume. The ``_label_internal`` fields let us decode A/B
    after the judge replies.
    """
    return {
        "file_name": file_name,
        "file_content": file_content,
        "oracle_verdict": oracle_verdict,
        "positions": [
            _summarize_position("argus", argus_row),
            _summarize_position("opus", opus_row),
        ],
    }


# ── Per-file diff record ──────────────────────────────────────────────────


def build_diff_record(
    file_name: str,
    argus_row: BenchRow | None,
    opus_row: BenchRow | None,
    baseline_entry: dict[str, Any] | None,
    rich_oracle_entry: dict[str, Any] | None,
    file_content: str | None = None,
) -> dict[str, Any]:
    """One file's full 3-source diff.

    ``rich_oracle_entry`` may be ``None`` for files outside the
    augmented oracle's 4-5-file subset; in that case CWE / capability
    overlap fields are ``None`` (Tier 1 verdict-match still applies
    for those files).
    """
    argus_v = argus_row.predicted_verdict if argus_row else None
    opus_v = opus_row.predicted_verdict if opus_row else None
    oracle_v = baseline_entry.get("oracle_verdict") if baseline_entry else None

    # Provenance: rich oracle's "model" field is most authoritative.
    # Fall back to baseline's "source" (variance_characterization etc.).
    label_provenance = "unknown"
    if rich_oracle_entry and rich_oracle_entry.get("model"):
        m = str(rich_oracle_entry["model"]).lower()
        label_provenance = "opus_confirmed" if "opus" in m else f"model:{m}"
    elif baseline_entry:
        label_provenance = baseline_entry.get("source", "variance_characterization")

    argus_findings = (
        [normalize_argus_vulnerability(v) for v in argus_row.vulnerabilities if isinstance(v, dict)]
        if argus_row
        else []
    )
    opus_findings = (
        [normalize_argus_vulnerability(v) for v in opus_row.vulnerabilities if isinstance(v, dict)] if opus_row else []
    )
    oracle_findings = list(rich_oracle_entry.get("findings") or []) if rich_oracle_entry else []

    cwe_overlap: dict[str, dict[str, Any]] | None = None
    capability_overlap: dict[str, dict[str, Any]] | None = None
    if rich_oracle_entry:
        oracle_cwes = {f.cwe for f in oracle_findings if f.cwe}
        if oracle_cwes:
            argus_cwes = {f.cwe for f in argus_findings if f.cwe}
            opus_cwes = {f.cwe for f in opus_findings if f.cwe}
            cwe_overlap = {
                "argus_vs_oracle": compute_overlap(argus_cwes, oracle_cwes),
                "opus_vs_oracle": compute_overlap(opus_cwes, oracle_cwes),
            }
        oracle_caps = set(rich_oracle_entry.get("capability_tags") or [])
        if oracle_caps:
            argus_caps = extract_capability_tags(argus_row) if argus_row else set()
            opus_caps = extract_capability_tags(opus_row) if opus_row else set()
            capability_overlap = {
                "argus_vs_oracle": compute_overlap(argus_caps, oracle_caps),
                "opus_vs_oracle": compute_overlap(opus_caps, oracle_caps),
            }

    dast_artifacts: list[dict[str, Any]] = []
    if argus_row and argus_row.dast_attempted:
        if "dast_verification" in (argus_row.scan_path or []):
            dast_artifacts.append({"stage": "dast_verification"})
        for marker in argus_row.scan_path or []:
            if marker.startswith("dast_") and marker != "dast_verification":
                dast_artifacts.append({"stage": marker})

    has_disagreement = len({v for v in [argus_v, opus_v, oracle_v] if v}) > 1
    judge_payload = (
        build_judge_payload(file_name, argus_row, opus_row, oracle_v, file_content) if has_disagreement else None
    )

    return {
        "file_name": file_name,
        "verdict_match": {
            "argus": argus_v,
            "opus": opus_v,
            "oracle": oracle_v,
            "label_provenance": label_provenance,
            "all_match": (argus_v == oracle_v == opus_v if (argus_v and opus_v and oracle_v) else None),
        },
        "findings_per_source": {
            "argus": [f.to_dict() for f in argus_findings],
            "opus": [f.to_dict() for f in opus_findings],
            "oracle": ([f.to_dict() for f in oracle_findings] if rich_oracle_entry else None),
        },
        "cwe_overlap": cwe_overlap,
        "capability_overlap": capability_overlap,
        "dast_artifacts_argus": dast_artifacts,
        "argus_refused": _is_refusal(argus_row),
        "opus_refused": _is_refusal(opus_row),
        "judge_payload": judge_payload,
    }


# ── Aggregate: full report ────────────────────────────────────────────────


def build_diff_report(
    argus_rows: list[BenchRow],
    opus_rows: list[BenchRow],
    baseline_path: Path,
    rich_oracle_path: Path | None,
    suite_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Build a per-file diff record for every file in the baseline.

    ``suite_dir`` is optional — when set, file content is loaded into
    each disagreement's ``judge_payload`` so BENCH-011 can ship it to
    GPT-5 directly without a second pass.
    """
    baseline = load_baseline_oracle(baseline_path)
    rich = load_rich_oracle(rich_oracle_path) if rich_oracle_path else {}

    argus_by_name = {r.file_name: r for r in argus_rows}
    opus_by_name = {r.file_name: r for r in opus_rows}

    records: list[dict[str, Any]] = []
    for file_name, baseline_entry in baseline.items():
        argus_row = argus_by_name.get(file_name)
        opus_row = opus_by_name.get(file_name)
        rich_entry = rich.get(file_name)
        file_content: str | None = None
        if suite_dir:
            p = suite_dir / file_name
            if p.exists():
                try:
                    file_content = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    file_content = None
        records.append(
            build_diff_record(
                file_name,
                argus_row,
                opus_row,
                baseline_entry,
                rich_entry,
                file_content=file_content,
            )
        )
    return records


def render_markdown(records: list[dict[str, Any]]) -> str:
    """Compact markdown rendering of a diff report.

    Sections: aggregate stats, refusals, disagreements, full per-file
    table. The launch report (BENCH-012) embeds this verbatim.
    """
    n = len(records)
    n_argus_match = sum(
        1
        for r in records
        if r["verdict_match"]["argus"] and r["verdict_match"]["argus"] == r["verdict_match"]["oracle"]
    )
    n_opus_match = sum(
        1 for r in records if r["verdict_match"]["opus"] and r["verdict_match"]["opus"] == r["verdict_match"]["oracle"]
    )
    n_argus_refused = sum(1 for r in records if r["argus_refused"])
    n_opus_refused = sum(1 for r in records if r["opus_refused"])
    n_disagreements = sum(1 for r in records if r["judge_payload"] is not None)
    n_with_rich = sum(1 for r in records if r["cwe_overlap"] is not None)

    lines: list[str] = []
    lines.append("# BENCH-010 — comparison report\n")
    lines.append(f"**Files**: {n}")
    lines.append(f"**Argus verdict matches oracle**: {n_argus_match}/{n}")
    lines.append(f"**Vanilla Opus verdict matches oracle**: {n_opus_match}/{n}")
    lines.append(f"**Argus refusals**: {n_argus_refused}/{n}")
    lines.append(f"**Vanilla Opus refusals**: {n_opus_refused}/{n}")
    lines.append(f"**Disagreements (sent to BENCH-011 judge)**: {n_disagreements}/{n}")
    lines.append(f"**Rich-oracle subset (CWE / capability overlap available)**: {n_with_rich}/{n}\n")

    # CWE / capability aggregate over rich-oracle subset
    rich_records = [r for r in records if r["cwe_overlap"] is not None]
    if rich_records:
        n_rich = len(rich_records)
        argus_f1 = sum(r["cwe_overlap"]["argus_vs_oracle"]["f1"] for r in rich_records) / n_rich
        opus_f1 = sum(r["cwe_overlap"]["opus_vs_oracle"]["f1"] for r in rich_records) / n_rich
        lines.append("## Tier 2 — CWE F1 (rich-oracle subset)")
        lines.append(f"- Argus mean CWE F1: **{argus_f1:.3f}**")
        lines.append(
            f"- Vanilla Opus mean CWE F1: **{opus_f1:.3f}** (sample size n={n_rich} — directional signal only)\n"
        )

    rich_caps = [r for r in records if r["capability_overlap"] is not None]
    if rich_caps:
        n_caps = len(rich_caps)
        argus_cap_f1 = sum(r["capability_overlap"]["argus_vs_oracle"]["f1"] for r in rich_caps) / n_caps
        opus_cap_f1 = sum(r["capability_overlap"]["opus_vs_oracle"]["f1"] for r in rich_caps) / n_caps
        lines.append("## Tier 2 — Capability tag F1 (rich-oracle subset)")
        lines.append(f"- Argus mean capability F1: **{argus_cap_f1:.3f}**")
        lines.append(f"- Vanilla Opus mean capability F1: **{opus_cap_f1:.3f}**\n")

    lines.append("## Per-file results\n")
    lines.append("| File | Argus | Opus | Oracle | Provenance | Argus refused | Opus refused | Disagreement |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in records:
        vm = r["verdict_match"]
        lines.append(
            f"| `{r['file_name']}` "
            f"| {vm['argus'] or '—'} "
            f"| {vm['opus'] or '—'} "
            f"| {vm['oracle'] or '—'} "
            f"| {vm['label_provenance']} "
            f"| {'**yes**' if r['argus_refused'] else 'no'} "
            f"| {'**yes**' if r['opus_refused'] else 'no'} "
            f"| {'**yes**' if r['judge_payload'] is not None else 'no'} |"
        )
    return "\n".join(lines) + "\n"


__all__ = [
    "FindingRef",
    "build_diff_record",
    "build_diff_report",
    "build_judge_payload",
    "compute_overlap",
    "extract_capability_tags",
    "load_baseline_oracle",
    "load_bench_rows",
    "load_rich_oracle",
    "normalize_argus_vulnerability",
    "normalize_oracle_finding",
    "render_markdown",
]
