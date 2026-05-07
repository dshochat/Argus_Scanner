"""BENCH-002 + BENCH-003 + BENCH-004 — beat-Opus benchmark harness.

The launch hook: prove that Argus's full cascade beats raw Opus 4.6
(single call, no cascade, no DAST) by >=15pp verdict-exact AND
>=0.05 verdict-distance on the 23-file regression suite.

Two runners and a comparator:

  * :func:`make_raw_opus_baseline_runner` (BENCH-002)
    Single Opus 4.6 call per file with the combined SECURITY_SCAN_PROMPT.
    No preprocessing, no triage, no DAST, no ensemble. The honest
    answer to "how good is Opus alone?".

  * :func:`run_argus_pipeline_one` (BENCH-003)
    Full Argus cascade: preprocessing -> triage -> sonnet/opus -> DAST.
    Wraps :func:`scanner.engine.scan_file`.

  * :func:`compute_metrics` + :func:`compare_configs` (BENCH-005 prep)
    Reuses :func:`methodology.scoring.verdict_distance` + the
    ``VERDICT_ANCHORS`` table. Reports verdict-exact rate, mean
    distance, per-tier breakdown.

N=2 orchestration (BENCH-004) is the responsibility of the CLI
wrapper that loops over runs; this module exposes the per-run pieces.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from inference.adapters import AnthropicAdapter
from prompts.scanner import SECURITY_SCAN_PROMPT
from scanner.engine import scan_file
from scanner.runners import OPUS_46_COST_IN, OPUS_46_COST_OUT, score_to_verdict

log = logging.getLogger("argus.bench")


# ── Per-file row produced by either runner ────────────────────────────────


@dataclass
class BenchRow:
    """One file's result from a benchmark run.

    The dict form returned by ``to_dict()`` matches what
    :func:`methodology.scoring.aggregate_run` expects when called with
    ``predicted_field='predicted_verdict'`` and
    ``oracle_field='oracle_verdict'``.
    """

    file_name: str
    oracle_verdict: str
    predicted_verdict: str | None
    config: str  # "raw_opus" | "argus_full"
    cost_usd: float
    duration_ms: int
    input_tokens: int = 0
    output_tokens: int = 0
    error: str | None = None
    # Argus-only fields
    scan_path: list[str] = field(default_factory=list)
    dast_attempted: bool = False
    n_vulnerabilities: int = 0
    # For per-tier aggregation; ``baseline.tracking`` is what
    # methodology.scoring expects so we mirror it here.
    baseline: dict[str, Any] = field(default_factory=dict)
    # Tier 2 signals — full scanner output captured so finding-coverage
    # metrics can be computed post-hoc without re-scanning.
    vulnerabilities: list[dict] = field(default_factory=list)
    behavioral_profile: dict = field(default_factory=dict)
    attack_chains: list[dict] = field(default_factory=list)
    # Full parsed JSON from the model — every schema field, including
    # ai_tool_analysis / composite_risk / shield_policy that the typed
    # fields above don't break out individually. Mirrors VoterRecord's
    # raw_output. Populated by both raw_opus and argus runners when
    # available (older saved rows may omit it).
    raw_output: dict = field(default_factory=dict)
    # Tier 1 (v1.1): per-finding DAST validation status. One entry per
    # L1 vulnerability, ordered to match. Each entry is a dict with
    # finding_id / cwe / type / severity / line / status (CONFIRMED |
    # UNTESTED) / confidence. Enables "Effective CWE F1" in the launch
    # report (filter to CONFIRMED-only findings before scoring).
    per_finding_validation: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file_name": self.file_name,
            "oracle_verdict": self.oracle_verdict,
            "predicted_verdict": self.predicted_verdict,
            "config": self.config,
            "cost_usd": round(self.cost_usd, 6),
            "duration_ms": self.duration_ms,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "error": self.error,
            "scan_path": list(self.scan_path),
            "dast_attempted": self.dast_attempted,
            "n_vulnerabilities": self.n_vulnerabilities,
            "baseline": dict(self.baseline),
            "vulnerabilities": list(self.vulnerabilities),
            "behavioral_profile": dict(self.behavioral_profile),
            "attack_chains": list(self.attack_chains),
            "raw_output": dict(self.raw_output),
            "per_finding_validation": list(self.per_finding_validation),
        }


# ── BENCH-002 — vanilla Opus baseline runner ──────────────────────────────
#
# Per the post-pivot methodology, vanilla Opus output is NOT used for
# verdict-match comparison vs Argus (that has same-model circularity:
# the regression_baseline.json oracle was itself produced by expert-Opus,
# so judging vanilla-Opus-vs-expert-Opus is just measuring effort
# variance within the same family). Instead, vanilla Opus serves as
# the "what does a single Opus call surface as findings?" reference
# point in BENCH-010's three-way finding-count + CWE overlap report.


def make_raw_opus_baseline_runner(
    api_key: str,
) -> Callable[[str, bytes, dict], Awaitable[BenchRow]]:
    """Build the single-call Opus baseline runner.

    ``baseline_meta`` (third arg of the returned callable) is the
    per-file entry from ``regression_baseline.json`` — carries
    ``oracle_verdict`` + ``tracking`` for downstream aggregation.
    """
    adapter = AnthropicAdapter(
        {
            "name": "argus-bench-raw-opus",
            "model_id": "claude-opus-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": {
                "thinking_budget": 24000,
                "max_tokens": 32768,
                "enable_system_cache": True,
            },
        }
    )

    async def runner(filename: str, content: bytes, baseline_meta: dict) -> BenchRow:
        text = content.decode("utf-8", errors="replace")
        t0 = time.time()
        result = await adapter.scan(text, filename, SECURITY_SCAN_PROMPT)
        elapsed_ms = int((time.time() - t0) * 1000)

        parsed = result.get("parsed") or {}
        json_valid = result.get("json_valid", False)
        score = (parsed.get("composite_risk") or {}).get("score")
        verdict = score_to_verdict(score) if json_valid else "suspicious"

        in_tokens = int(result.get("input_tokens", 0))
        out_tokens = int(result.get("output_tokens", 0))
        cost = in_tokens / 1_000_000 * OPUS_46_COST_IN + out_tokens / 1_000_000 * OPUS_46_COST_OUT

        adapter_error = result.get("error")
        runner_error: str | None = None
        if adapter_error:
            runner_error = adapter_error
        elif not json_valid:
            runner_error = f"json_parse_failed: out_tokens={out_tokens}; possible truncation"

        return BenchRow(
            file_name=filename,
            oracle_verdict=baseline_meta.get("oracle_verdict", ""),
            predicted_verdict=verdict,
            config="raw_opus",
            cost_usd=round(cost, 6),
            duration_ms=elapsed_ms,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            n_vulnerabilities=len(parsed.get("vulnerabilities", [])),
            error=runner_error,
            baseline={"tracking": baseline_meta.get("tracking", "tier1")},
            vulnerabilities=parsed.get("vulnerabilities") or [],
            behavioral_profile=parsed.get("behavioral_profile") or {},
            attack_chains=parsed.get("attack_chains") or [],
            raw_output=parsed if isinstance(parsed, dict) else {},
        )

    return runner


# ── BENCH-003 — Argus full pipeline runner ────────────────────────────────


async def run_argus_pipeline_one(
    filename: str,
    content: bytes,
    baseline_meta: dict,
    *,
    triage_runner: Any,
    sonnet_runner: Any,
    opus_runner: Any,
    dast_runner: Any,
) -> BenchRow:
    """Run one file through the full Argus cascade and return a BenchRow."""
    scan_result = await scan_file(
        filename=filename,
        content=content,
        triage_runner=triage_runner,
        sonnet_runner=sonnet_runner,
        opus_runner=opus_runner,
        dast_runner=dast_runner,
    )
    return BenchRow(
        file_name=filename,
        oracle_verdict=baseline_meta.get("oracle_verdict", ""),
        predicted_verdict=scan_result.final_verdict,
        config="argus_full",
        cost_usd=round(scan_result.total_cost_usd, 6),
        duration_ms=scan_result.total_duration_ms,
        input_tokens=sum(int(c.get("input_tokens", 0) or 0) for c in scan_result.model_calls),
        output_tokens=sum(int(c.get("output_tokens", 0) or 0) for c in scan_result.model_calls),
        scan_path=list(scan_result.scan_path),
        dast_attempted=scan_result.dast_attempted,
        n_vulnerabilities=len(scan_result.vulnerabilities),
        error=scan_result.error,
        baseline={"tracking": baseline_meta.get("tracking", "tier1")},
        vulnerabilities=list(scan_result.vulnerabilities),
        behavioral_profile=dict(scan_result.behavioral_profile),
        attack_chains=list(scan_result.attack_chains),
        per_finding_validation=list(getattr(scan_result, "per_finding_validation", []) or []),
    )


# ── Suite-level orchestration ─────────────────────────────────────────────


class BenchAborted(RuntimeError):
    """Raised when run_suite auto-aborts due to consecutive errors."""


def _atomic_write_json(path: Path, payload: list[dict]) -> None:
    """Write JSON via tmp + rename so a mid-write inspector never sees
    partial JSON. Best-effort on Windows where rename can fail if the
    target is open by another process — we fall back to direct write."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    try:
        tmp.replace(path)
    except OSError:
        path.write_text(json.dumps(payload, indent=2))
        try:
            tmp.unlink()
        except OSError:
            pass


def _load_existing_rows(output_path: Path) -> list[BenchRow]:
    """Load any rows already serialized at output_path (resumability)."""
    if not output_path.exists():
        return []
    try:
        data = json.loads(output_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    rows: list[BenchRow] = []
    for d in data:
        if not isinstance(d, dict):
            continue
        rows.append(
            BenchRow(
                file_name=d.get("file_name", ""),
                oracle_verdict=d.get("oracle_verdict", ""),
                predicted_verdict=d.get("predicted_verdict"),
                config=d.get("config", ""),
                cost_usd=float(d.get("cost_usd", 0.0)),
                duration_ms=int(d.get("duration_ms", 0)),
                input_tokens=int(d.get("input_tokens", 0)),
                output_tokens=int(d.get("output_tokens", 0)),
                error=d.get("error"),
                scan_path=list(d.get("scan_path") or []),
                dast_attempted=bool(d.get("dast_attempted", False)),
                n_vulnerabilities=int(d.get("n_vulnerabilities", 0)),
                baseline=dict(d.get("baseline") or {}),
                vulnerabilities=list(d.get("vulnerabilities") or []),
                behavioral_profile=dict(d.get("behavioral_profile") or {}),
                attack_chains=list(d.get("attack_chains") or []),
                raw_output=dict(d.get("raw_output") or {}),
                per_finding_validation=list(d.get("per_finding_validation") or []),
            )
        )
    return rows


async def run_suite(
    suite_dir: Path,
    baseline_path: Path,
    runner_fn: Callable[..., Awaitable[BenchRow]],
    *,
    runner_kwargs: dict | None = None,
    output_path: Path | None = None,
    progress_callback: Callable[[int, int, BenchRow], None] | None = None,
    auto_abort_consecutive_errors: int | None = 3,
    resume: bool = True,
) -> list[BenchRow]:
    """Run ``runner_fn`` over every file referenced in
    ``regression_baseline.json``.

    Monitor-friendly options (v2):

    * ``output_path`` — if set, writes the cumulative rows list to this
      JSON file via atomic-replace after EVERY row. Allows external
      inspection mid-run (e.g., ``tail -f`` of a partial JSON snapshot).
    * ``progress_callback(idx, total, row)`` — invoked after each row
      with 1-based index, total file count, and the new row. CLI uses
      this to print a one-liner with verdict + oracle comparison.
    * ``auto_abort_consecutive_errors`` — if K consecutive rows have
      ``row.error is not None``, raise :class:`BenchAborted` to abort
      the run before burning more budget. Default 3; pass ``None`` to
      disable.
    * ``resume`` — if True (default) and ``output_path`` already
      contains rows, files already represented are skipped. Combined
      with ctrl-C-then-restart, gives bounded recovery from partial
      runs. Compares by ``file_name`` only (assumes config matches —
      caller's responsibility).

    Files are scanned sequentially (concurrency would cross-contaminate
    the orchestrator's journal_dir for files sharing a hash).
    """
    with baseline_path.open() as f:
        baseline = json.load(f)

    runner_kwargs = runner_kwargs or {}
    rows: list[BenchRow] = []
    already_done: set[str] = set()

    if resume and output_path is not None:
        existing = _load_existing_rows(output_path)
        rows.extend(existing)
        already_done = {r.file_name for r in existing}
        if existing:
            log.info(
                "BENCH resuming: %d existing rows in %s; skipping those files",
                len(existing),
                output_path,
            )

    consecutive_errors = 0
    files = baseline["files"]
    total = len(files)
    for idx, entry in enumerate(files, start=1):
        fn = entry["file_name"]
        if fn in already_done:
            continue
        path = suite_dir / fn
        if not path.exists():
            log.warning("BENCH skipping missing fixture: %s", fn)
            continue
        content = path.read_bytes()
        try:
            row = await runner_fn(fn, content, entry, **runner_kwargs)
        except Exception as e:  # noqa: BLE001
            log.exception("BENCH runner failed on %s: %s", fn, e)
            row = BenchRow(
                file_name=fn,
                oracle_verdict=entry.get("oracle_verdict", ""),
                predicted_verdict=None,
                config=runner_kwargs.get("config", "unknown"),
                cost_usd=0.0,
                duration_ms=0,
                error=f"{type(e).__name__}: {e}",
                baseline={"tracking": entry.get("tracking", "tier1")},
            )
        rows.append(row)

        if output_path is not None:
            _atomic_write_json(output_path, [r.to_dict() for r in rows])

        if progress_callback is not None:
            try:
                progress_callback(idx, total, row)
            except Exception:  # noqa: BLE001
                log.exception("progress_callback raised; continuing")

        if row.error is not None:
            consecutive_errors += 1
            if auto_abort_consecutive_errors is not None and consecutive_errors >= auto_abort_consecutive_errors:
                raise BenchAborted(
                    f"auto-aborted after {consecutive_errors} consecutive "
                    f"errors (last on {fn}: {row.error}). "
                    f"Cumulative rows: {len(rows)}/{total}. "
                    f"Re-run with --no-resume=False to continue."
                )
        else:
            consecutive_errors = 0

    return rows


# ── Comparison metrics (BENCH-005 prep) ───────────────────────────────────


def compute_metrics(rows: list[BenchRow]) -> dict[str, Any]:
    """Verdict-exact rate + verdict-distance mean over a row set.

    Reuses :func:`methodology.scoring.aggregate_run` for the
    standard helpers; this thin wrapper just builds the dict
    representation it expects.
    """
    from methodology.scoring import aggregate_run

    summary = aggregate_run(
        (r.to_dict() for r in rows),
        oracle_field="oracle_verdict",
        predicted_field="predicted_verdict",
        tier_path=("baseline", "tracking"),
    )
    n_total = len(rows)
    return {
        "n_total": n_total,
        "n_scored": summary.n_scored,
        "n_skipped": summary.n_skipped,
        "verdict_exact": summary.verdict_exact,
        "verdict_exact_pct": summary.verdict_exact_pct,
        "mean_distance": summary.mean_distance,
        "sum_distance": summary.sum_distance,
        "per_tier": summary.per_tier,
        "total_cost_usd": round(sum(r.cost_usd for r in rows), 4),
        "total_duration_ms": sum(r.duration_ms for r in rows),
        "n_errors": sum(1 for r in rows if r.error),
    }


def compare_configs(
    raw_opus: list[BenchRow],
    argus: list[BenchRow],
) -> dict[str, Any]:
    """Head-to-head: Argus minus raw-Opus baseline.

    The launch hook gate is in :func:`bench_pass_criteria` (BENCH-005).
    """
    opus_metrics = compute_metrics(raw_opus)
    argus_metrics = compute_metrics(argus)
    return {
        "raw_opus": opus_metrics,
        "argus_full": argus_metrics,
        "verdict_exact_pp_lift": (argus_metrics["verdict_exact_pct"] - opus_metrics["verdict_exact_pct"]),
        "mean_distance_improvement": (opus_metrics["mean_distance"] - argus_metrics["mean_distance"]),
        "cost_ratio": (
            argus_metrics["total_cost_usd"] / opus_metrics["total_cost_usd"]
            if opus_metrics["total_cost_usd"] > 0
            else None
        ),
    }


# ── BENCH-005 gate (Tier 1) ──────────────────────────────────────────────
#
# Note: Tier 2 finding-coverage logic moved to ``methodology/diff_report.py``
# (BENCH-010) — the post-pivot methodology produces a richer 3-way diff
# (Argus vs vanilla Opus vs rich oracle) than the original 2-way
# Argus-vs-oracle Tier 2 supported.


def bench_pass_criteria(
    comparison: dict,
    *,
    min_verdict_exact_lift_pp: float = 15.0,
    min_distance_improvement: float = 0.05,
) -> dict[str, Any]:
    """BENCH-005 pass criteria check.

    Returns a verdict + per-criterion pass/fail. The thresholds default
    to the values in CLAUDE.md / roadmap.md ("beat raw Opus 4.6 by
    >=15pp verdict-exact AND >=0.05 verdict-distance"). Passing both
    is the gate for v1.0 public release; failing either is recoverable
    by either dropping low-yield cascade branches or finding a harder
    benchmark corpus.
    """
    lift = comparison.get("verdict_exact_pp_lift") or 0.0
    dist_improve = comparison.get("mean_distance_improvement") or 0.0
    exact_pass = lift >= min_verdict_exact_lift_pp
    distance_pass = dist_improve >= min_distance_improvement
    return {
        "passed": exact_pass and distance_pass,
        "verdict_exact_pp_lift": lift,
        "verdict_exact_pp_lift_threshold": min_verdict_exact_lift_pp,
        "verdict_exact_pp_lift_pass": exact_pass,
        "mean_distance_improvement": dist_improve,
        "mean_distance_improvement_threshold": min_distance_improvement,
        "mean_distance_improvement_pass": distance_pass,
    }


__all__ = [
    "BenchAborted",
    "BenchRow",
    "bench_pass_criteria",
    "compare_configs",
    "compute_metrics",
    "make_raw_opus_baseline_runner",
    "run_argus_pipeline_one",
    "run_suite",
]
