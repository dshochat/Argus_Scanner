"""Score every scanner against the rich 3-voter consensus oracle.

For each scanner's saved JSON output (Argus runs, raw Opus runs, voter
files), extract their CWEs / capability tags / dangerous APIs /
behavioral categories using the same extractors that oracle_builder
uses, then compute precision/recall/F1 vs the consensus.

This is the "rich" complement to verdict-exact match: a scanner can
match the verdict label but miss the underlying findings, or vice
versa. The 4 axes (CWE / capability / dangerous_api / behavioral)
quantify the depth of analysis alignment with the multi-vendor
consensus.

Usage::

    uv run python -m methodology.score_rich \\
        --consensus bench_results/<ts>/consensus_oracle_no_opus.json \\
        --argus     bench_results/<ts>/argus_full_run1.json \\
        --opus      bench_results/<ts>/raw_opus_run1.json \\
        --voters-dir bench_results/<ts>/voters
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from methodology.oracle_builder import (
    _extract_behavioral_categories,
    _extract_capability_tags,
    _extract_cwes,
    _extract_dangerous_apis,
)
from methodology.voters import VoterRecord, _load_existing_voter_records


def _f1(pred: set[str], truth: set[str]) -> tuple[float, float, float]:
    """precision, recall, F1 — if both empty, returns (1.0, 1.0, 1.0) (vacuous match)."""
    if not pred and not truth:
        return 1.0, 1.0, 1.0
    inter = pred & truth
    p = len(inter) / len(pred) if pred else 0.0
    r = len(inter) / len(truth) if truth else 0.0
    return p, r, (2 * p * r / (p + r) if (p + r) else 0.0)


def _normalize(items: list[str], upper: bool = True) -> set[str]:
    return {
        (s.strip().upper() if upper else s.strip())
        for s in items
        if isinstance(s, str) and s.strip()
    }


def _bench_to_voter_records(path: Path) -> list[VoterRecord]:
    """Load a BenchRow JSON (Argus or raw_opus) and convert to VoterRecord
    shape so the same extractors work on it. Falls back to reconstructing
    raw_output from the typed fields when raw_output isn't present (older
    saves before the BenchRow.raw_output addition)."""
    rows = json.load(open(path))
    out: list[VoterRecord] = []
    for r in rows:
        raw_output = r.get("raw_output") or {}
        if not raw_output:
            raw_output = {
                "vulnerabilities": r.get("vulnerabilities") or [],
                "behavioral_profile": r.get("behavioral_profile") or {},
                "attack_chains": r.get("attack_chains") or [],
            }
        out.append(
            VoterRecord(
                file_name=r["file_name"],
                voter_name=r.get("config") or "unknown",
                predicted_verdict=r.get("predicted_verdict"),
                composite_score=None,
                cost_usd=r.get("cost_usd", 0),
                duration_ms=r.get("duration_ms", 0),
                error=r.get("error"),
                raw_findings=raw_output.get("vulnerabilities") or r.get("vulnerabilities") or [],
                raw_output=raw_output,
            )
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(prog="score_rich")
    parser.add_argument("--consensus", type=Path, required=True)
    parser.add_argument("--argus", type=Path, required=True, help="argus_full_run1.json (no-DAST)")
    parser.add_argument(
        "--argus-with-dast", type=Path, default=None, help="optional argus_full_run1.json (+DAST)"
    )
    parser.add_argument("--opus", type=Path, required=True, help="raw_opus_run1.json")
    parser.add_argument("--voters-dir", type=Path, required=True, help="dir containing voter JSONs")
    args = parser.parse_args()

    oracle = json.load(open(args.consensus))
    oracle_by = {f["file_name"]: f for f in oracle["files"]}

    scanners: dict[str, list[VoterRecord]] = {
        "argus_no_dast": _bench_to_voter_records(args.argus),
        "raw_opus_4_6": _bench_to_voter_records(args.opus),
    }
    if args.argus_with_dast and args.argus_with_dast.exists():
        scanners["argus_with_dast"] = _bench_to_voter_records(args.argus_with_dast)

    # Auto-pick voter JSONs
    for vp in sorted(args.voters_dir.glob("*.json")):
        scanners[vp.stem] = _load_existing_voter_records(vp)

    print(f"\n=== Rich F1 vs consensus oracle ({args.consensus.name}) ===\n")
    print(f"{'Scanner':<32} {'Verdict':>9} {'CWE F1':>8} {'CapTag':>8} {'DangAPI':>9} {'Behav':>8}")
    print("-" * 78)

    for name, records in scanners.items():
        by_fn = {r.file_name: r for r in records}
        verdict_match = 0
        verdict_n = 0
        cwe_scores: list[float] = []
        cap_scores: list[float] = []
        api_scores: list[float] = []
        beh_scores: list[float] = []

        for fn, oracle_f in oracle_by.items():
            r = by_fn.get(fn)
            if r is None or oracle_f.get("n_voters", 0) == 0:
                continue

            verdict_n += 1
            if r.predicted_verdict and r.predicted_verdict == oracle_f.get("oracle_verdict"):
                verdict_match += 1

            s_cwe = _normalize(_extract_cwes(r))
            s_cap = _normalize(_extract_capability_tags(r))
            s_api = _normalize(_extract_dangerous_apis(r))
            s_beh = _normalize(_extract_behavioral_categories(r))

            o_cwe = set(oracle_f.get("cwe_consensus", {}).get("consensus") or [])
            o_cap = set(oracle_f.get("capability_tag_consensus", {}).get("consensus") or [])
            o_api = set(oracle_f.get("dangerous_api_consensus", {}).get("consensus") or [])
            o_beh = set(oracle_f.get("behavioral_category_consensus", {}).get("consensus") or [])

            if o_cwe or s_cwe:
                cwe_scores.append(_f1(s_cwe, o_cwe)[2])
            if o_cap or s_cap:
                cap_scores.append(_f1(s_cap, o_cap)[2])
            if o_api or s_api:
                api_scores.append(_f1(s_api, o_api)[2])
            if o_beh or s_beh:
                beh_scores.append(_f1(s_beh, o_beh)[2])

        def avg(lst: list[float]) -> float:
            return sum(lst) / len(lst) if lst else 0.0

        verdict_pct = verdict_match / verdict_n * 100 if verdict_n else 0.0
        print(
            f"{name:<32} {verdict_pct:>8.1f}% "
            f"{avg(cwe_scores):>8.3f} "
            f"{avg(cap_scores):>8.3f} "
            f"{avg(api_scores):>9.3f} "
            f"{avg(beh_scores):>8.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
