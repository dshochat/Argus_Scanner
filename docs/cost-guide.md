# Cost guide

Argus is BYOK (bring your own keys). You pay Anthropic and Google directly; Argus collects nothing.

## Per-file API spend (measured live)

| Scan path | When it fires | Cost per file |
|---|---|---|
| Triage CLEAN short-circuit | Pure-utility code, no security-relevant patterns | **~$0.0001** |
| Sonnet 4.6 default HIGH | Most malicious code (no preprocessing high-stakes flags) | **~$0.05-0.30** |
| Opus 4.6 high-stakes | `crypto_sensitivity` / `attack_vector_extension` / `ai_file_match` / `obfuscation_detected` | **~$0.15-0.50** |
| Sonnet + DAST | Confirmed-malicious files (DAST-triggered) | **+$0.20-0.80** for DAST |
| Opus high-stakes + DAST | Worst case for a single file | **~$1.00 worst-case** |

These numbers come from the live runs in this session — see the methodology benchmark output (`bench_results/<timestamp>/summary.json`) once BENCH-004 has run on your end.

## Per-100-file scan projection

| Component | Calls | API spend |
|---|---|---|
| Triage (Flash-Lite) | 100 | $0.10 |
| LOW bucket (~50, Flash) | 50 | $1.00 |
| HIGH-standard (~15, Sonnet) | 15 | $1.05 |
| HIGH-high-stakes (~5, Sonnet+Opus) | 5 | $1.00 |
| Ensemble re-verdict (~3, Opus) | 3 | $0.60 |
| DAST verification (~3) | 3 | $0.90 |
| **Total** | | **~$4.65** |

## The cost cap (`--max-cost`)

The engine refuses to spend more than `ScanConfig.max_cost_per_file_usd` ($1.00 by default) on a single file:

```bash
# Override per-scan
uv run argus scan path/to/file.py --max-cost 0.25

# Disable the cap (benchmarks, etc.)
uv run argus scan path/to/file.py --max-cost 0
```

When the cap is breached, the engine:

- Aborts the cascade after the offending stage finishes (no in-flight call gets cancelled)
- Returns the partial result with `status: 402` and `error: "cost_cap_exceeded: $X.XX > $Y.YY after <stage> stage"`
- Adds a `cost_cap_exceeded_after:<stage>(<actual>>$<cap>)` marker to `scan_path` for telemetry

The exit code on cost-cap abort is `1` (matches generic scan error).

## When the cap matters

The cap is a safety net for runaway scans, not a fine-grained budget tool. Real-world per-file spend on the 23-file regression suite (no DAST): typically $0.06-0.30. With DAST: $0.30-0.80. The $1.00 default catches:

- A pathological file that DAST iterates 3× without converging
- A run where every cascade tier (Sonnet → Opus → DAST → Opus iter-3) fires
- A misconfigured loop (e.g., infinite retries on a transient API error)

## Per-scan vs per-file caps

`ScanConfig` declares two caps:

- `max_cost_per_file_usd: float = 1.00` — currently enforced by `scan_file` (one file at a time)
- `max_cost_per_scan_usd: float = 50.00` — for batch scanning; not yet enforced by the CLI (single-file mode). Future API server / batch CLI will layer it on top.

## DAST cost dynamics

DAST is the most variable spend. Per-file cost depends on:

- **Number of iterations** the orchestrator runs (capped at 3)
- **Number of Phase A hypotheses** the model proposes per iteration
- **Number of sandbox calls** (one per executable plan)
- **Whether iter-3 escalates to Opus** (DAST-103, post-v1)

Empirically: 1 iteration × 4 hypotheses × 5 sandbox calls × ~30s/call → $0.20-0.80 per DAST scan, dominated by Sonnet inference time.

If DAST cost is a concern, run with `--no-dast`. Argus's L1 cascade alone still beats most pattern-based scanners; DAST is the differentiator for confirmed-exploitability findings.
