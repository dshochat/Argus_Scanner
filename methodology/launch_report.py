"""BENCH-012 — v1 launch report aggregator.

Pulls together everything Phase A produces into one human-readable
markdown report — the public v1 number Argus launches with.

Sources:

  * ``BenchRow``\\s from ``raw_opus_run1.json`` (BENCH-002 baseline)
  * ``BenchRow``\\s from ``argus_pipeline_run1.json`` (BENCH-003 cascade)
  * Diff records from ``comparison_report.json`` (BENCH-010)
  * Judgments from ``gpt5_judgments.json`` (BENCH-011, optional)

Sections:

  1. Verdict-match table — 3-way (Argus / vanilla Opus / oracle), all 23
     files, label provenance flagged per file (opus_confirmed vs
     variance_characterization).
  2. Finding-count comparison — 3-way on the rich-oracle subset (4-5
     files); shows raw counts, NOT a precision/recall number.
  3. CWE overlap per scanner — Argus_vs_oracle and Opus_vs_oracle
     precision/recall/F1/Jaccard means on the rich subset.
  4. Capability-tag overlap — same shape, capability vocabulary.
  5. DAST evidence count — Argus only (runtime artifacts vanilla Opus
     cannot produce; included to characterize what cascade adds).
  6. GPT-5.5 judgment tally — when judge ran, counts per agree-with
     bucket + mean confidence + cost.
  7. Cost comparison — Argus pipeline $X / vanilla Opus $Y / documented
     expert-Opus labeling cost (qualitative).
  8. Sample-size honesty — CWE / capability overlap ran on n=4-5 files;
     directional signal only.
  9. Mythos footer — "deferred to v1.1, coming in 2-3 weeks".

The aggregator is deterministic given its inputs. It does NOT make
API calls; if a source file is missing, that section is reported as
"not available" rather than aborting.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from methodology.bench import BenchRow, _load_existing_rows
from methodology.diff_report import build_diff_report, render_markdown
from methodology.judge import JudgmentRecord, summarize_judgments

# ── Verdict ranking (for distance-style comparison) ──────────────────────────

VERDICT_RANK: dict[str, int] = {
    "clean": 0,
    "low_concern": 1,
    "suspicious": 2,
    "malicious": 3,
    "critical_malicious": 4,
}


# ── Loading helpers ──────────────────────────────────────────────────────────


def _load_judgments(path: Path) -> list[JudgmentRecord]:
    """Reconstruct ``JudgmentRecord``\\s from a saved gpt5_judgments.json."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    out: list[JudgmentRecord] = []
    for d in data:
        if not isinstance(d, dict):
            continue
        out.append(
            JudgmentRecord(
                file_name=d.get("file_name", ""),
                judge_model=d.get("judge_model", ""),
                oracle_verdict=d.get("oracle_verdict"),
                argus_verdict=d.get("argus_verdict"),
                opus_verdict=d.get("opus_verdict"),
                judgment=dict(d.get("judgment") or {}),
                ab_mapping=dict(d.get("ab_mapping") or {}),
                tokens_in=int(d.get("tokens_in", 0)),
                tokens_out=int(d.get("tokens_out", 0)),
                cost_usd=float(d.get("cost_usd", 0.0)),
                duration_ms=int(d.get("duration_ms", 0)),
                error=d.get("error"),
            )
        )
    return out


# ── Section builders ─────────────────────────────────────────────────────────


def _verdict_match_stats(rows: list[BenchRow]) -> dict[str, Any]:
    """Per-config exact-match + verdict-distance stats."""
    n = len(rows)
    if n == 0:
        return {"n": 0, "exact_match": 0, "exact_pct": 0.0, "mean_distance": None}
    exact = 0
    distances: list[int] = []
    for r in rows:
        if r.predicted_verdict and r.predicted_verdict == r.oracle_verdict:
            exact += 1
        pr = VERDICT_RANK.get(r.predicted_verdict or "")
        orr = VERDICT_RANK.get(r.oracle_verdict)
        if pr is not None and orr is not None:
            distances.append(abs(pr - orr))
    return {
        "n": n,
        "exact_match": exact,
        "exact_pct": round(exact / n * 100, 1),
        "mean_distance": round(sum(distances) / len(distances), 3) if distances else None,
    }


def _cost_total(rows: list[BenchRow]) -> float:
    return round(sum(r.cost_usd for r in rows), 4)


def _gate_lift_pp(argus_pct: float, opus_pct: float) -> float:
    return round(argus_pct - opus_pct, 1)


def _dast_evidence_count(rows: list[BenchRow]) -> dict[str, int]:
    """Tally how many Argus rows attempted DAST and how many added a
    DAST stage to the scan path.

    Falls back to ``per_finding_validation`` presence when the row's
    ``dast_attempted`` flag isn't populated — Tier 1 replay rows
    (``methodology.dast_replay``) carry per-finding validation but
    don't always set the legacy ``dast_attempted`` flag, so the flag
    alone undercounts.
    """
    n_attempted = sum(1 for r in rows if r.dast_attempted or r.per_finding_validation)
    n_with_dast_stage = sum(
        1 for r in rows if any(p.startswith("dast_") for p in (r.scan_path or [])) or r.per_finding_validation
    )
    return {
        "n_dast_attempted": n_attempted,
        "n_with_dast_stage": n_with_dast_stage,
    }


# ── Scoreboard rendering helpers ─────────────────────────────────────────────


_ORACLE_TIERS: tuple[str, ...] = (
    "clean",
    "suspicious",
    "malicious",
    "critical_malicious",
)


def _bar(value: float, *, max_value: float = 1.0, width: int = 20) -> str:
    """Render a unicode block bar: ``██████░░░░░░░░░░░░░░``.

    ``value`` is normalized against ``max_value``; clamped to [0, 1].
    """
    if max_value <= 0:
        ratio = 0.0
    else:
        ratio = max(0.0, min(1.0, value / max_value))
    filled = int(round(ratio * width))
    return "█" * filled + "░" * (width - filled)


def _per_tier_accuracy(rows: list[BenchRow]) -> dict[str, dict[str, Any]]:
    """For each oracle tier, return ``{n, correct, pct}``."""
    out: dict[str, dict[str, Any]] = {t: {"n": 0, "correct": 0, "pct": 0.0} for t in _ORACLE_TIERS}
    for r in rows:
        tier = r.oracle_verdict or ""
        if tier not in out:
            continue
        out[tier]["n"] += 1
        if r.predicted_verdict == r.oracle_verdict:
            out[tier]["correct"] += 1
    for _t, d in out.items():
        d["pct"] = round(d["correct"] / d["n"] * 100, 1) if d["n"] else 0.0
    return out


def _confusion_matrix(rows: list[BenchRow]) -> dict[str, dict[str, int]]:
    """4x4 grid: ``matrix[predicted][oracle] = count``.

    Predictions outside the standard 4-tier set (e.g., legacy
    ``informational`` / ``low_concern``) are folded into ``suspicious``
    for the matrix — the grid stays 4x4, matching the oracle vocabulary.
    """
    matrix: dict[str, dict[str, int]] = {p: {o: 0 for o in _ORACLE_TIERS} for p in _ORACLE_TIERS}
    for r in rows:
        oracle = r.oracle_verdict or ""
        if oracle not in matrix[_ORACLE_TIERS[0]]:
            continue
        predicted = r.predicted_verdict or ""
        if predicted not in matrix:
            # Map legacy / off-vocab labels to suspicious for the grid.
            predicted = "suspicious"
        matrix[predicted][oracle] += 1
    return matrix


def _judge_tally_from_path(judgments_path: Path | None) -> dict[str, int]:
    """Count agree_with buckets from a saved judgments file. Returns
    zeros if no judgments are available."""
    out = {"argus": 0, "opus": 0, "both": 0, "neither": 0, "errors": 0}
    if not judgments_path or not judgments_path.exists():
        return out
    try:
        data = json.loads(judgments_path.read_text())
    except (OSError, json.JSONDecodeError):
        return out
    if not isinstance(data, list):
        return out
    for d in data:
        if not isinstance(d, dict):
            continue
        if d.get("error"):
            out["errors"] += 1
            continue
        bucket = (d.get("judgment") or {}).get("agree_with")
        if bucket in out:
            out[bucket] = out.get(bucket, 0) + 1
    return out


def _render_scoreboard_headline(
    configs: list[tuple[str, list[BenchRow]]],
    diff_records: list[dict[str, Any]],
    judgments: list[JudgmentRecord],
) -> str:
    """Top-of-report at-a-glance scoreboard.

    ``configs`` is a list of ``(display_name, rows)`` pairs. The LAST
    entry is treated as the baseline (raw Opus) — every other config's
    lift is computed against it. Typically::

        [
            ("Argus (no DAST)", argus_no_dast_rows),
            ("Argus (+DAST)",   argus_with_dast_rows),  # optional
            ("Raw Opus 4.6",    opus_rows),
        ]
    """
    if not configs:
        return ""
    stats = [(name, _verdict_match_stats(rows), rows) for name, rows in configs]
    baseline_pct = stats[-1][1]["exact_pct"]

    judge_summary = summarize_judgments(judgments) if judgments else None

    lines: list[str] = []
    lines.append("## At-a-glance scoreboard\n")
    lines.append("```")
    lines.append("┌──────────────────────────────────────────────────────────────────────────┐")
    lines.append("│  ARGUS v1 — REGRESSION BENCH                                             │")
    lines.append("│                                                                          │")
    label_w = max(len(name) for name, _, _ in stats)
    for name, st, _rows in stats:
        bar = _bar(st["exact_pct"], max_value=100, width=20)
        lift = st["exact_pct"] - baseline_pct
        lift_str = f"{lift:+.1f}pp" if name != stats[-1][0] else "baseline"
        line = (
            f"│  {name:<{label_w}}  "
            f"{st['exact_match']:>2}/{st['n']:<2} = {st['exact_pct']:>5.1f}%  "
            f"{bar}  {lift_str:<10}"
        )
        # Pad to a fixed width and close the box.
        line = line.ljust(75) + "│"
        lines.append(line)
    lines.append("│                                                                          │")

    # Gate is the BEST config's lift over baseline (typically Argus +DAST).
    best_lift = max(st["exact_pct"] for _, st, _ in stats[:-1]) - baseline_pct if len(stats) > 1 else 0.0
    gate_pass = best_lift >= 15.0
    if gate_pass:
        gate_line = f"│  Gate (≥15pp lift):   PASS  [actual: +{best_lift:.1f}pp]"
    else:
        gap = 15.0 - best_lift
        gate_line = f"│  Gate (≥15pp lift):   FAIL  [needs +{gap:.1f}pp more]"
    gate_line = gate_line.ljust(75) + "│"
    lines.append(gate_line)

    # Cost rows for each non-baseline config.
    baseline_cost = _cost_total(stats[-1][2])
    for name, _, rows in stats[:-1]:
        cost = _cost_total(rows)
        ratio = cost / baseline_cost if baseline_cost else 0.0
        if ratio < 1:
            cost_msg = f"{ratio:.2f}x  ({(1 - ratio) * 100:.0f}% cheaper than baseline)"
        elif ratio > 1:
            cost_msg = f"{ratio:.2f}x  ({(ratio - 1) * 100:.0f}% more than baseline)"
        else:
            cost_msg = "1.00x  (same as baseline)"
        cost_line = f"│  Cost: {name:<{label_w}}  ${cost:>7.4f}  {cost_msg}"
        cost_line = cost_line.ljust(75) + "│"
        lines.append(cost_line)

    if judge_summary and judge_summary["n_disagreements"] > 0:
        n_dis = judge_summary["n_disagreements"]
        ja = judge_summary["judge_picked_argus"]
        jo = judge_summary["judge_picked_opus"]
        jb = judge_summary["judge_picked_both"]
        jn = judge_summary["judge_picked_neither"]
        lines.append("│                                                                          │")
        judge_line = f"│  Judge ({n_dis} disagreements):  Argus={ja}  Opus={jo}  both={jb}  neither={jn}"
        judge_line = judge_line.ljust(75) + "│"
        lines.append(judge_line)
    lines.append("└──────────────────────────────────────────────────────────────────────────┘")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _render_head_to_head(
    configs: list[tuple[str, list[BenchRow]]],
    diff_records: list[dict[str, Any]],
    judgments: list[JudgmentRecord],
) -> str:
    """Side-by-side metric table — one column per config, plus Winner.

    The first config's per-config CWE/capability F1 is read from
    ``diff_records`` (Argus side); for additional Argus configs (e.g.,
    "Argus +DAST"), CWE/capability F1 is omitted because diff_records
    only carries Argus-vs-Opus for one Argus config. The headline
    verdict-exact + cost work for any number of configs.
    """
    if not configs:
        return ""
    # Pre-compute stats per config.
    metrics: list[dict[str, Any]] = []
    for name, rows in configs:
        st = _verdict_match_stats(rows)
        metrics.append(
            {
                "name": name,
                "exact_pct": st["exact_pct"],
                "exact_match": st["exact_match"],
                "n": st["n"],
                "mean_distance": st["mean_distance"],
                "cost": _cost_total(rows),
            }
        )
    # CWE / capability F1 — only Argus (first) and Opus (last) carry these
    # in diff_records; middle configs (e.g., +DAST) get "—".
    rich = [r for r in diff_records if r.get("cwe_overlap") is not None]
    rich_caps = [r for r in diff_records if r.get("capability_overlap") is not None]
    n_rich = len(rich)
    n_caps = len(rich_caps)

    def _mean(rich_subset: list[dict[str, Any]], side: str, key: str) -> float | None:
        if not rich_subset:
            return None
        return round(sum(r["cwe_overlap"][side][key] for r in rich_subset) / len(rich_subset), 3)

    def _mean_caps(side: str, key: str) -> float | None:
        if not rich_caps:
            return None
        return round(
            sum(r["capability_overlap"][side][key] for r in rich_caps) / len(rich_caps),
            3,
        )

    judge_summary = summarize_judgments(judgments) if judgments else None
    n_configs = len(configs)
    is_three_way = n_configs == 3

    lines: list[str] = []
    title = "## Head-to-head (3-way comparison)" if is_three_way else "## Head-to-head (Argus vs raw Opus 4.6)"
    lines.append(title + "\n")

    # Table header
    header = "| Metric"
    for m in metrics:
        header += f" | {m['name']}"
    header += " | Winner |"
    lines.append(header)
    lines.append("|---" * (n_configs + 2) + "|")

    # Verdict-exact row
    row = f"| Verdict-exact (all {metrics[0]['n']} files)"
    best_idx = max(range(n_configs), key=lambda i: metrics[i]["exact_pct"])
    for i, m in enumerate(metrics):
        cell = f" | {m['exact_pct']:.1f}% ({m['exact_match']}/{m['n']})"
        if i == best_idx:
            cell = f" | **{m['exact_pct']:.1f}%** ({m['exact_match']}/{m['n']})"
        row += cell
    row += f" | **{metrics[best_idx]['name']}** |"
    lines.append(row)

    # Mean distance
    distances = [m["mean_distance"] for m in metrics if m["mean_distance"] is not None]
    if len(distances) == n_configs:
        row = "| Mean verdict-distance (lower=better)"
        best = min(range(n_configs), key=lambda i: metrics[i]["mean_distance"])
        for i, m in enumerate(metrics):
            cell = f" | {m['mean_distance']}"
            if i == best:
                cell = f" | **{m['mean_distance']}**"
            row += cell
        row += f" | **{metrics[best]['name']}** |"
        lines.append(row)

    # CWE F1 — first column is Argus's (could be no-DAST or +DAST depending on
    # which one was passed to build_diff_report); last column is Opus.
    a_cwe_f1 = _mean(rich, "argus_vs_oracle", "f1")
    o_cwe_f1 = _mean(rich, "opus_vs_oracle", "f1")
    if a_cwe_f1 is not None:
        if is_three_way:
            row = f"| CWE F1 (n={n_rich}) | {a_cwe_f1} | _(same as col 1)_ | {o_cwe_f1}"
        else:
            row = f"| CWE F1 (rich subset, n={n_rich}) | {a_cwe_f1} | {o_cwe_f1}"
        winner_idx = 0 if (a_cwe_f1 is not None and o_cwe_f1 is not None and a_cwe_f1 > o_cwe_f1) else (n_configs - 1)
        row += f" | **{configs[winner_idx][0]}** |"
        lines.append(row)

    a_cap = _mean_caps("argus_vs_oracle", "f1")
    o_cap = _mean_caps("opus_vs_oracle", "f1")
    if a_cap is not None:
        if is_three_way:
            row = f"| Capability F1 (n={n_caps}) | {a_cap} | _(same as col 1)_ | {o_cap}"
        else:
            row = f"| Capability F1 (n={n_caps}) | {a_cap} | {o_cap}"
        if abs((a_cap or 0) - (o_cap or 0)) < 1e-9:
            row += " | tied |"
        else:
            winner_idx = 0 if (a_cap or 0) > (o_cap or 0) else (n_configs - 1)
            row += f" | **{configs[winner_idx][0]}** |"
        lines.append(row)

    # Judge tally
    if judge_summary and judge_summary["n_disagreements"] > 0:
        ja = judge_summary["judge_picked_argus"]
        jo = judge_summary["judge_picked_opus"]
        if is_three_way:
            row = f"| Judge wins (disagreements) | {ja} | _(same as col 1)_ | {jo}"
        else:
            row = f"| Judge wins (disagreements) | {ja} | {jo}"
        if ja > jo:
            row += f" | **{configs[0][0]}** |"
        elif jo > ja:
            row += f" | **{configs[-1][0]}** |"
        else:
            row += " | tied |"
        lines.append(row)

    # Cost
    row = "| Total cost (lower=better)"
    best = min(range(n_configs), key=lambda i: metrics[i]["cost"])
    for i, m in enumerate(metrics):
        cell = f" | ${m['cost']:.4f}"
        if i == best:
            cell = f" | **${m['cost']:.4f}**"
        row += cell
    row += f" | **{metrics[best]['name']}** |"
    lines.append(row)
    lines.append("")
    return "\n".join(lines)


def _render_per_tier_breakdown(configs: list[tuple[str, list[BenchRow]]]) -> str:
    """Bar chart: accuracy per oracle tier for each config."""
    if not configs:
        return ""
    by_config = [(name, _per_tier_accuracy(rows)) for name, rows in configs]
    label_w = max(len(name) for name, _ in configs)

    lines: list[str] = []
    lines.append("## Per-tier accuracy (the diagnostic panel)\n")
    lines.append(
        "_Shows where each scanner gets it right or wrong, broken down by what the "
        "oracle says. The `suspicious` row is the over-calling indicator — high "
        "accuracy here means the scanner correctly distinguishes vulnerable code "
        "from active malware._\n"
    )
    lines.append("```")
    # Use n from the first config (all should agree)
    first_n = by_config[0][1]
    for tier in _ORACLE_TIERS:
        n = first_n[tier]["n"]
        if n == 0:
            continue
        lines.append(f"Oracle = {tier} (n={n})")
        for name, acc in by_config:
            pct = acc[tier]["pct"]
            correct = acc[tier]["correct"]
            bar = _bar(pct, max_value=100, width=20)
            lines.append(f"  {name:<{label_w}}  {bar}  {pct:>5.1f}% ({correct}/{n})")
        lines.append("")
    lines.append("```")
    return "\n".join(lines)


def _render_confusion_matrices(configs: list[tuple[str, list[BenchRow]]]) -> str:
    """One 4x4 grid per config showing where predictions land."""
    if not configs:
        return ""

    def _fmt(label: str, mat: dict[str, dict[str, int]]) -> list[str]:
        lines = [f"{label}"]
        header = "predicted ↓ / oracle →".ljust(28)
        for o in _ORACLE_TIERS:
            header += f"{o[:6]:>8}"
        lines.append(header)
        for p in _ORACLE_TIERS:
            row_total = sum(mat[p][o] for o in _ORACLE_TIERS)
            line = f"  {p:<26}"
            for o in _ORACLE_TIERS:
                cell = mat[p][o]
                if p == o:
                    line += f"{'[' + str(cell) + ']':>8}"
                else:
                    line += f"{cell:>8}"
            lines.append(line + f"   row={row_total}")
        return lines

    lines: list[str] = []
    lines.append("## Confusion matrices\n")
    lines.append(
        "_Rows are predicted verdict, columns are oracle. Diagonal cells "
        "(in `[brackets]`) are correct. Off-diagonal cells in the "
        "lower-left corner (predicted higher than oracle) = over-calling; "
        "upper-right = under-calling._\n"
    )
    lines.append("```")
    for i, (name, rows) in enumerate(configs):
        if i > 0:
            lines.append("")
        lines.extend(_fmt(name.upper(), _confusion_matrix(rows)))
    lines.append("```")
    return "\n".join(lines)


def _render_top_wins_losses(configs: list[tuple[str, list[BenchRow]]]) -> str:
    """Files where each non-baseline config uniquely beats the baseline (last).

    For 3-config layouts (Argus no-DAST, Argus +DAST, Raw Opus), shows
    two sections: "no-DAST wins over Opus" and "+DAST wins over Opus".
    For 2-config (Argus, Opus), shows the single comparison.
    """
    if len(configs) < 2:
        return ""
    baseline_name, baseline_rows = configs[-1]
    baseline_by = {r.file_name: r for r in baseline_rows}

    lines: list[str] = []
    lines.append("## Where each scanner wins\n")

    any_wins = False
    for name, rows in configs[:-1]:
        wins: list[tuple[str, str, str, str]] = []
        losses: list[tuple[str, str, str, str]] = []
        rows_by = {r.file_name: r for r in rows}
        for fn, ar in rows_by.items():
            br = baseline_by.get(fn)
            if br is None:
                continue
            a_match = ar.predicted_verdict == ar.oracle_verdict
            b_match = br.predicted_verdict == br.oracle_verdict
            if a_match and not b_match:
                wins.append((fn, ar.predicted_verdict or "", br.predicted_verdict or "", ar.oracle_verdict))
            elif b_match and not a_match:
                losses.append((fn, ar.predicted_verdict or "", br.predicted_verdict or "", ar.oracle_verdict))

        if wins:
            any_wins = True
            lines.append(f"### {name} wins over {baseline_name} ({len(wins)} files)\n")
            lines.append(f"| File | {name} | {baseline_name} | Oracle |")
            lines.append("|---|---|---|---|")
            for fn, av, ov, orv in wins:
                lines.append(f"| `{fn}` | **{av}** | {ov} | {orv} |")
            lines.append("")
        if losses:
            any_wins = True
            lines.append(f"### {baseline_name} wins over {name} ({len(losses)} files)\n")
            lines.append(f"| File | {name} | {baseline_name} | Oracle |")
            lines.append("|---|---|---|---|")
            for fn, av, ov, orv in losses:
                lines.append(f"| `{fn}` | {av} | **{ov}** | {orv} |")
            lines.append("")

    if not any_wins:
        lines.append("_(All scanners produce the same verdicts — no head-to-head differences.)_\n")

    return "\n".join(lines)


# ── Markdown rendering ───────────────────────────────────────────────────────


def _section_header(title: str) -> str:
    return f"\n## {title}\n"


def _render_section_1_verdict_match(
    diff_records: list[dict[str, Any]],
) -> str:
    """Reuses BENCH-010's render_markdown for the per-file table; adds a
    summary line for verdict-exact rates."""
    md = render_markdown(diff_records)
    return md


def _render_section_2_finding_counts(diff_records: list[dict[str, Any]]) -> str:
    """3-way finding count on the rich-oracle subset (where oracle has
    findings; outside that subset findings_per_source.oracle is None)."""
    rows: list[str] = []
    rows.append(_section_header("2. Finding-count comparison (rich-oracle subset)"))
    rich = [r for r in diff_records if r["findings_per_source"].get("oracle") is not None]
    if not rich:
        rows.append("_No rich-oracle subset available — section skipped._")
        return "\n".join(rows) + "\n"
    rows.append("| File | Argus | Vanilla Opus | Oracle |")
    rows.append("|---|---|---|---|")
    for r in rich:
        fps = r["findings_per_source"]
        rows.append(
            f"| `{r['file_name']}` "
            f"| {len(fps.get('argus') or [])} "
            f"| {len(fps.get('opus') or [])} "
            f"| {len(fps.get('oracle') or [])} |"
        )
    return "\n".join(rows) + "\n"


def _render_section_3_cwe_overlap(diff_records: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    rows.append(_section_header("3. CWE overlap (rich-oracle subset)"))
    rich = [r for r in diff_records if r.get("cwe_overlap") is not None]
    if not rich:
        rows.append("_No rich-oracle subset available — section skipped._")
        return "\n".join(rows) + "\n"
    n = len(rich)
    argus_means = {
        k: round(sum(r["cwe_overlap"]["argus_vs_oracle"][k] for r in rich) / n, 3)
        for k in ("precision", "recall", "f1", "jaccard")
    }
    opus_means = {
        k: round(sum(r["cwe_overlap"]["opus_vs_oracle"][k] for r in rich) / n, 3)
        for k in ("precision", "recall", "f1", "jaccard")
    }
    rows.append(f"Sample size: **n={n}** (directional signal only).\n")
    rows.append("| Scanner | Precision | Recall | F1 | Jaccard |")
    rows.append("|---|---|---|---|---|")
    rows.append(
        f"| Argus | {argus_means['precision']} | {argus_means['recall']} "
        f"| **{argus_means['f1']}** | {argus_means['jaccard']} |"
    )
    rows.append(
        f"| Vanilla Opus | {opus_means['precision']} | {opus_means['recall']} "
        f"| **{opus_means['f1']}** | {opus_means['jaccard']} |"
    )
    return "\n".join(rows) + "\n"


def _render_section_4_capability_overlap(diff_records: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    rows.append(_section_header("4. Capability-tag overlap (rich-oracle subset)"))
    rich = [r for r in diff_records if r.get("capability_overlap") is not None]
    if not rich:
        rows.append("_No rich-oracle subset available — section skipped._")
        return "\n".join(rows) + "\n"
    n = len(rich)
    argus_means = {
        k: round(sum(r["capability_overlap"]["argus_vs_oracle"][k] for r in rich) / n, 3)
        for k in ("precision", "recall", "f1", "jaccard")
    }
    opus_means = {
        k: round(sum(r["capability_overlap"]["opus_vs_oracle"][k] for r in rich) / n, 3)
        for k in ("precision", "recall", "f1", "jaccard")
    }
    rows.append(f"Sample size: **n={n}** (directional signal only).\n")
    rows.append("| Scanner | Precision | Recall | F1 | Jaccard |")
    rows.append("|---|---|---|---|---|")
    rows.append(
        f"| Argus | {argus_means['precision']} | {argus_means['recall']} "
        f"| **{argus_means['f1']}** | {argus_means['jaccard']} |"
    )
    rows.append(
        f"| Vanilla Opus | {opus_means['precision']} | {opus_means['recall']} "
        f"| **{opus_means['f1']}** | {opus_means['jaccard']} |"
    )
    rows.append(
        "\n_Capability tag extraction is heuristic — see "
        "`methodology.diff_report.extract_capability_tags`. The "
        "vocabulary is approximate; treat as a coarse signal._"
    )
    return "\n".join(rows) + "\n"


def _render_section_5_dast_evidence(argus_rows: list[BenchRow]) -> str:
    """DAST evidence panel — Argus-only capability claim.

    Two views:
      a) Top-level: how many files DAST fired on, total iterations,
         total runtime-validated findings.
      b) Per-finding (Tier 1, v1.1): aggregate CONFIRMED / UNTESTED
         counts across all rows that have ``per_finding_validation``.
         Shown as bar chart + per-file detail table.
    """
    rows: list[str] = []
    rows.append(_section_header("5. DAST runtime evidence (Argus only)"))
    counts = _dast_evidence_count(argus_rows)
    rows.append(f"- DAST attempted: **{counts['n_dast_attempted']}**/{len(argus_rows)} files")
    rows.append(f"- DAST stages reached scan path: **{counts['n_with_dast_stage']}**/{len(argus_rows)} files")

    # Tier 1.5: per-finding validation aggregate (4-status breakdown)
    rows_with_pf = [r for r in argus_rows if r.per_finding_validation]
    if rows_with_pf:
        total_findings = 0
        n_conf = 0
        n_blocked = 0
        n_unreached = 0
        n_not_tested = 0
        for r in rows_with_pf:
            for pf in r.per_finding_validation:
                total_findings += 1
                s = pf.get("status")
                if s == "CONFIRMED":
                    n_conf += 1
                elif s == "BLOCKED":
                    n_blocked += 1
                elif s == "UNREACHED":
                    n_unreached += 1
                else:
                    n_not_tested += 1

        def _pct(n: int) -> float:
            return round(n / total_findings * 100, 1) if total_findings else 0.0

        conf_pct = _pct(n_conf)
        blk_pct = _pct(n_blocked)
        unr_pct = _pct(n_unreached)
        nt_pct = _pct(n_not_tested)

        rows.append("")
        rows.append("### Per-finding validation (Tier 1.5, v1.1) — Argus only")
        rows.append("```")
        rows.append(f"Across {len(rows_with_pf)} files with DAST validation, {total_findings} L1 findings:")
        rows.append("")
        rows.append(
            f"  CONFIRMED   {_bar(conf_pct, max_value=100, width=20)}  {conf_pct:>5.1f}%  ({n_conf})  runtime-confirmed exploitable"
        )
        rows.append(
            f"  BLOCKED     {_bar(blk_pct, max_value=100, width=20)}  {blk_pct:>5.1f}%  ({n_blocked})  defended in-code (sanitization/validation)"
        )
        rows.append(
            f"  UNREACHED   {_bar(unr_pct, max_value=100, width=20)}  {unr_pct:>5.1f}%  ({n_unreached})  code path not reachable from tested input"
        )
        rows.append(
            f"  NOT_TESTED  {_bar(nt_pct, max_value=100, width=20)}  {nt_pct:>5.1f}%  ({n_not_tested})  DAST didn't generate a test or rejection inconclusive"
        )
        rows.append("```")
        rows.append("")
        rows.append(
            "_CONFIRMED + BLOCKED = real vulnerabilities in the code (BLOCKED "
            "ones are defended by mitigations — still worth reviewing for "
            "defense-in-depth). UNREACHED = vulnerabilities present but not "
            "exploitable from external input. NOT_TESTED = remaining "
            "uncertainty. Status is derived heuristically from validator "
            "rejection rationale; Tier 2 (future) will replace heuristics "
            "with structured rejection categories from the validator._"
        )

        # Per-file detail
        rows.append("")
        rows.append("### Per-file breakdown\n")
        rows.append("| File | L1 | CONFIRMED | BLOCKED | UNREACHED | NOT_TESTED |")
        rows.append("|---|---|---|---|---|---|")
        for r in rows_with_pf:
            n = len(r.per_finding_validation)
            c = sum(1 for pf in r.per_finding_validation if pf.get("status") == "CONFIRMED")
            b = sum(1 for pf in r.per_finding_validation if pf.get("status") == "BLOCKED")
            u = sum(1 for pf in r.per_finding_validation if pf.get("status") == "UNREACHED")
            nt = n - c - b - u
            rows.append(f"| `{r.file_name}` | {n} | **{c}** | {b} | {u} | {nt} |")

        # NOT_TESTED sub-reason breakdown (DAST-203 visibility).
        nt_reasons: dict[str, int] = {"infra_stub": 0, "inconclusive": 0, "not_planned": 0}
        for r in rows_with_pf:
            for pf in r.per_finding_validation:
                if pf.get("status") == "NOT_TESTED":
                    rsn = pf.get("not_tested_reason") or "not_planned"
                    nt_reasons[rsn] = nt_reasons.get(rsn, 0) + 1
        if any(nt_reasons.values()):
            rows.append("")
            rows.append("### NOT_TESTED breakdown (DAST-203 — why DAST didn't validate)\n")
            rows.append(
                f"- `not_planned` ({nt_reasons['not_planned']}): "
                "orchestrator's plan didn't pick this finding (typically low "
                "confidence or budget exhausted before reaching it)"
            )
            rows.append(
                f"- `infra_stub` ({nt_reasons['infra_stub']}): "
                "sandbox returned stub trace — usually because the planner "
                "generated a static-only hypothesis. v1.2 DAST-203 will "
                "filter these out pre-sandbox."
            )
            rows.append(
                f"- `inconclusive` ({nt_reasons['inconclusive']}): "
                "validator rejected with reasoning that didn't classify as "
                "BLOCKED, UNREACHED, or STUB. Treat as ambiguous."
            )

        # PoC export — show CONFIRMED findings with their exploit payload
        # and runtime evidence.
        confirmed_with_poc: list[tuple[str, dict[str, Any]]] = []
        for r in rows_with_pf:
            for pf in r.per_finding_validation:
                if pf.get("status") == "CONFIRMED" and (pf.get("proof_of_concept") or pf.get("runtime_evidence")):
                    confirmed_with_poc.append((r.file_name, pf))

        if confirmed_with_poc:
            rows.append("")
            rows.append("### Confirmed exploits — proof-of-concept + runtime evidence\n")
            rows.append(
                "_For each CONFIRMED finding, Argus surfaces the exploit "
                "payload that worked AND the sandbox-observed runtime "
                "behavior. No other scanner in the panel produces this — "
                "voters can describe vulnerabilities; only Argus can show "
                "you they're actually exploitable._\n"
            )
            for fname, pf in confirmed_with_poc[:30]:  # cap to 30 to keep readable
                rows.append(f"**`{fname}` — {pf.get('cwe')} / {pf.get('type')} (line {pf.get('line')})**")
                poc = pf.get("proof_of_concept")
                if poc:
                    rows.append(f"- Proof of concept: `{poc[:200]}`")
                ev = pf.get("runtime_evidence")
                if ev:
                    rows.append(f"- Runtime evidence: _{ev[:240]}_")
                rows.append("")
            if len(confirmed_with_poc) > 30:
                rows.append(
                    f"_({len(confirmed_with_poc) - 30} more CONFIRMED findings with PoCs omitted for brevity.)_"
                )

    rows.append(
        "\n_Vanilla Opus is a single static call and produces no runtime "
        "artifacts. This panel characterizes what the cascade adds — no "
        "other scanner in the panel produces this signal._"
    )
    return "\n".join(rows) + "\n"


def _render_section_5b_effective_cwe_f1(argus_rows: list[BenchRow]) -> str:
    """Effective CWE F1 panel — Argus's CWE F1 BEFORE vs AFTER per-finding
    DAST filtering. Demonstrates how runtime validation tightens precision.

    Only renders when ``argus_rows`` carry per_finding_validation data
    (Tier 1 enabled). Uses the same CWE consensus that build_diff_report
    + score_rich use, but as a self-contained calc here for the panel.
    """
    if not any(r.per_finding_validation for r in argus_rows):
        return ""

    # Compute total CWE counts: raw vs effective (CONFIRMED-only).
    n_raw_cwes = 0
    n_eff_cwes = 0
    for r in argus_rows:
        seen_raw: set[str] = set()
        seen_eff: set[str] = set()
        confirmed_ids = {pf.get("finding_id") for pf in r.per_finding_validation if pf.get("status") == "CONFIRMED"}
        for i, v in enumerate(r.vulnerabilities):
            if not isinstance(v, dict):
                continue
            cwe = (v.get("cwe") or "").strip().upper()
            if not cwe:
                continue
            seen_raw.add(cwe)
            fid = f"H{i + 1:03d}"
            if fid in confirmed_ids:
                seen_eff.add(cwe)
        n_raw_cwes += len(seen_raw)
        n_eff_cwes += len(seen_eff)

    lines: list[str] = []
    lines.append(_section_header("5b. Effective CWE coverage (Tier 1, v1.1)"))
    lines.append(
        "_When Argus's findings are filtered to runtime-confirmed ones only "
        "(Effective view), the CWE list tightens — fewer findings, but "
        "higher confidence per finding. Voters can't produce this view._\n"
    )
    lines.append(f"- Raw CWE count (all L1 findings): **{n_raw_cwes}**")
    lines.append(f"- Effective CWE count (CONFIRMED only): **{n_eff_cwes}**")
    if n_raw_cwes:
        retention = round(n_eff_cwes / n_raw_cwes * 100, 1)
        lines.append(f"- Retention rate: {retention}% ({n_eff_cwes}/{n_raw_cwes} CWEs survived runtime validation)")
    lines.append("")
    lines.append(
        "_Interpretation: The unconfirmed CWEs aren't necessarily false "
        "positives — they may be real but defended by sanitization (BLOCKED) "
        "or in unreachable code paths (UNREACHED). Tier 1.5 will distinguish "
        "these. For now, the Effective view represents the high-confidence "
        "subset Argus can stand behind with sandbox evidence._"
    )
    return "\n".join(lines) + "\n"


def _render_section_6_judge(judgments: list[JudgmentRecord]) -> str:
    rows: list[str] = []
    rows.append(_section_header("6. GPT-5.5 independent judge"))
    if not judgments:
        rows.append(
            "_No judgments available — set `OPENAI_API_KEY` and run "
            "`methodology.judge.run_judge` to populate this section._"
        )
        return "\n".join(rows) + "\n"
    s = summarize_judgments(judgments)
    rows.append(f"- Disagreements adjudicated: **{s['n_disagreements']}**")
    rows.append(f"- Judge picked Argus: **{s['judge_picked_argus']}**")
    rows.append(f"- Judge picked vanilla Opus: **{s['judge_picked_opus']}**")
    rows.append(f"- Judge picked both correct: {s['judge_picked_both']}")
    rows.append(f"- Judge picked neither: {s['judge_picked_neither']}")
    if s["judge_errors"]:
        rows.append(f"- Judge errors: {s['judge_errors']} (excluded from tally)")
    if s["mean_confidence"] is not None:
        rows.append(f"- Mean judge confidence: {s['mean_confidence']}")
    rows.append(f"- Judge cost: ${s['total_cost_usd']:.4f}")

    rows.append(
        "\n_Judge sees blinded positions A/B with randomized order — "
        "doesn't know which output came from which scanner. Mapping "
        "decoded post-hoc from the saved seed._"
    )

    if any(j.judgment.get("agree_with") for j in judgments):
        rows.append("\n### Per-file judgment\n")
        rows.append("| File | Oracle | Argus | Opus | Judge picked | Confidence |")
        rows.append("|---|---|---|---|---|---|")
        for j in judgments:
            picked = j.judgment.get("agree_with") or "?"
            conf = j.judgment.get("confidence")
            conf_s = f"{conf:.2f}" if isinstance(conf, (int, float)) else "—"
            rows.append(
                f"| `{j.file_name}` | {j.oracle_verdict or '—'} "
                f"| {j.argus_verdict or '—'} | {j.opus_verdict or '—'} "
                f"| **{picked}** | {conf_s} |"
            )
    return "\n".join(rows) + "\n"


def _render_section_7_cost(
    argus_rows: list[BenchRow],
    opus_rows: list[BenchRow],
    judgments: list[JudgmentRecord],
) -> str:
    rows: list[str] = []
    rows.append(_section_header("7. Cost comparison"))
    n_files = max(len(argus_rows), len(opus_rows), 1)
    argus_total = _cost_total(argus_rows)
    opus_total = _cost_total(opus_rows)
    judge_total = round(sum(j.cost_usd for j in judgments), 4)
    rows.append("| Run | Total | Per-file mean |")
    rows.append("|---|---|---|")
    rows.append(f"| Argus pipeline | ${argus_total:.4f} | ${argus_total / n_files:.4f} |")
    rows.append(f"| Vanilla Opus single-call | ${opus_total:.4f} | ${opus_total / n_files:.4f} |")
    if judge_total > 0:
        rows.append(f"| GPT-5.5 judge (BENCH-011) | ${judge_total:.4f} | — |")
    rows.append(
        "\n_Expert-Opus labeling — i.e., what it cost to produce the "
        "oracle in the first place — was significantly higher per file "
        "(human-in-the-loop expert review). Argus is BYOK, so these are "
        "your API bills, not Argus's revenue._"
    )
    return "\n".join(rows) + "\n"


def _render_section_8_sample_size(diff_records: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    rows.append(_section_header("8. Sample-size honesty"))
    n_total = len(diff_records)
    n_rich = sum(1 for r in diff_records if r.get("cwe_overlap") is not None)
    rows.append(f"- Verdict-match (Tier 1): **n={n_total}** files — primary signal.")
    rows.append(f"- CWE / capability overlap (Tier 2): **n={n_rich}** files — directional signal only.")
    rows.append(
        "- 18 of the 23 oracle labels are `variance_characterization` "
        "(reproduced via repeated runs); 5 are `opus_confirmed` (expert "
        "Opus review). Mismatches against `variance_characterization` "
        "labels are weaker evidence than mismatches against "
        "`opus_confirmed` labels."
    )
    rows.append(
        "- The judge (Section 6) is the strongest tiebreaker — it reads the actual code and casts an independent vote."
    )
    return "\n".join(rows) + "\n"


def _render_section_9_mythos_footer() -> str:
    rows: list[str] = []
    rows.append(_section_header("9. Mythos validation"))
    rows.append(
        "_Mythos validation is **deferred to v1.1**, coming in 2-3 weeks "
        "once C++/Rust detector coverage lands (PREP-026 + PREP-027). "
        "Argus's current scope is Python/JS/TS; expanding to native "
        "code without a corresponding scope expansion would be "
        "selection-bias by another name._"
    )
    return "\n".join(rows) + "\n"


# ── Top-level builder ────────────────────────────────────────────────────────


def render_launch_report(
    argus_rows: list[BenchRow],
    opus_rows: list[BenchRow],
    diff_records: list[dict[str, Any]],
    judgments: list[JudgmentRecord],
    *,
    argus_with_dast_rows: list[BenchRow] | None = None,
    argus_label: str = "Argus (no DAST)",
    argus_with_dast_label: str = "Argus (+DAST)",
    opus_label: str = "Raw Opus 4.6",
) -> str:
    """Assemble the markdown launch report.

    Two-config mode (default): pass ``argus_rows`` + ``opus_rows``.
    Three-config mode: also pass ``argus_with_dast_rows`` to show
    Argus no-DAST, Argus +DAST, and Raw Opus side-by-side. The
    ``argus_rows`` argument is treated as Argus's "no-DAST" run by
    convention (matches Plan A's run order).
    """
    # Build the configs list. Order matters: non-baseline first, baseline LAST.
    # Lift is computed against the last entry.
    configs: list[tuple[str, list[BenchRow]]] = [(argus_label, argus_rows)]
    if argus_with_dast_rows is not None:
        configs.append((argus_with_dast_label, argus_with_dast_rows))
    configs.append((opus_label, opus_rows))

    parts: list[str] = []
    parts.append("# Argus v1 — launch report\n")
    sources_note = (
        "_Generated by `methodology.launch_report`. Sources: "
        "`raw_opus_run1.json` (BENCH-002), `argus_pipeline_run1.json` "
        "(BENCH-003), `comparison_report.json` (BENCH-010), "
        "`gpt5_judgments.json` (BENCH-011)._"
    )
    if argus_with_dast_rows is not None:
        sources_note += "\n_Three-config mode: Argus no-DAST + Argus +DAST + Raw Opus side-by-side._"
    parts.append(sources_note + "\n")

    # ── Top-of-report scoreboard panels (visual, scannable) ────────────────
    parts.append(_render_scoreboard_headline(configs, diff_records, judgments))
    parts.append(_render_head_to_head(configs, diff_records, judgments))
    parts.append(_render_per_tier_breakdown(configs))
    parts.append(_render_confusion_matrices(configs))
    parts.append(_render_top_wins_losses(configs))

    # ── Detail sections (full per-file tables, methodology, etc.) ──────────
    parts.append("## 1. Verdict-match per file\n")
    parts.append(_render_section_1_verdict_match(diff_records))
    parts.append(_render_section_2_finding_counts(diff_records))
    parts.append(_render_section_3_cwe_overlap(diff_records))
    parts.append(_render_section_4_capability_overlap(diff_records))
    # Section 5 (DAST evidence) and 5b (Effective CWE F1) read
    # ``per_finding_validation`` and ``dast_*`` fields. Use the +DAST
    # rows when provided — the no-DAST run has no DAST artefacts to
    # report on.
    dast_rows_for_section_5 = argus_with_dast_rows if argus_with_dast_rows is not None else argus_rows
    parts.append(_render_section_5_dast_evidence(dast_rows_for_section_5))
    eff_panel = _render_section_5b_effective_cwe_f1(dast_rows_for_section_5)
    if eff_panel:
        parts.append(eff_panel)
    parts.append(_render_section_6_judge(judgments))
    parts.append(_render_section_7_cost(argus_rows, opus_rows, judgments))
    parts.append(_render_section_8_sample_size(diff_records))
    parts.append(_render_section_9_mythos_footer())
    return "\n".join(parts)


# ── End-to-end orchestrator ──────────────────────────────────────────────────


def build_launch_report(
    *,
    argus_rows_path: Path,
    opus_rows_path: Path,
    baseline_oracle_path: Path,
    rich_oracle_path: Path | None = None,
    suite_dir: Path | None = None,
    diff_records_path: Path | None = None,
    judgments_path: Path | None = None,
    output_path: Path,
    argus_with_dast_rows_path: Path | None = None,
) -> dict[str, Any]:
    """Load all sources, build the diff report (or load if cached),
    aggregate, and save markdown to ``output_path``.

    Returns a small summary dict (paths + headline numbers) for the
    CLI to print.

    When ``argus_with_dast_rows_path`` is provided, the report renders
    a 3-config layout: Argus (no DAST) + Argus (+DAST) + Raw Opus.
    """
    argus_rows = _load_existing_rows(argus_rows_path) if argus_rows_path.exists() else []
    opus_rows = _load_existing_rows(opus_rows_path) if opus_rows_path.exists() else []
    argus_with_dast_rows: list[BenchRow] | None = None
    if argus_with_dast_rows_path and argus_with_dast_rows_path.exists():
        argus_with_dast_rows = _load_existing_rows(argus_with_dast_rows_path)

    if diff_records_path and diff_records_path.exists():
        diff_records = json.loads(diff_records_path.read_text())
    else:
        diff_records = build_diff_report(
            argus_rows,
            opus_rows,
            baseline_oracle_path,
            rich_oracle_path,
            suite_dir=suite_dir,
        )
        if diff_records_path:
            diff_records_path.write_text(json.dumps(diff_records, indent=2))

    judgments: list[JudgmentRecord] = []
    if judgments_path:
        judgments = _load_judgments(judgments_path)

    md = render_launch_report(
        argus_rows,
        opus_rows,
        diff_records,
        judgments,
        argus_with_dast_rows=argus_with_dast_rows,
    )
    output_path.write_text(md, encoding="utf-8")

    argus_stats = _verdict_match_stats(argus_rows)
    opus_stats = _verdict_match_stats(opus_rows)
    summary: dict[str, Any] = {
        "output_path": str(output_path),
        "argus_exact_pct": argus_stats["exact_pct"],
        "opus_exact_pct": opus_stats["exact_pct"],
        "lift_pp": _gate_lift_pp(argus_stats["exact_pct"], opus_stats["exact_pct"]),
        "n_argus_rows": len(argus_rows),
        "n_opus_rows": len(opus_rows),
        "n_disagreements": sum(1 for r in diff_records if r.get("judge_payload") is not None),
        "n_judgments": len(judgments),
    }
    if argus_with_dast_rows is not None:
        with_dast_stats = _verdict_match_stats(argus_with_dast_rows)
        summary["argus_with_dast_exact_pct"] = with_dast_stats["exact_pct"]
        summary["lift_with_dast_pp"] = _gate_lift_pp(with_dast_stats["exact_pct"], opus_stats["exact_pct"])
        summary["n_argus_with_dast_rows"] = len(argus_with_dast_rows)
    return summary


__all__ = [
    "VERDICT_RANK",
    "build_launch_report",
    "render_launch_report",
]
