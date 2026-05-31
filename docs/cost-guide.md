# Cost guide

Argus is BYOK. You pay Anthropic + Fly directly; Argus collects nothing. The default cascade is built to keep per-file cost predictable.

## Per-file cost by scan path (v1.11)

| Scan path | When it fires | Cost per file |
|---|---|---|
| Triage CLEAN short-circuit | Pure-utility code, no security-relevant patterns | **~$0.0001** |
| Triage LOW → Sonnet 4.6 | Most low-risk files | **~$0.02–$0.08** |
| Triage HIGH → Sonnet split L1 | Most security-relevant files | **~$0.05–$0.20** |
| Above + Opus 4.6 escalation | Borderline uncertainty / high-stakes preprocessing flags | **+$0.05–$0.30** |
| Above + **Finding Validation** (sandbox) | Verdict ≥ suspicious — runs by default | **+$0.05–$0.20** (Anthropic) + **$0.02–$0.10** (Fly) |
| Above + **Remediation** (auto-patch + replay) | Any CONFIRMED finding — runs by default | **+$0.05–$0.15** (Anthropic) + **$0.02–$0.10** (Fly) |
| All opt-in stages enabled | `--enable-runtime-probe` + `--enable-phase-3-discovery` + `--enable-phase-3-loop` | **+$0.30–$1.50** |

Default cascade (no opt-in flags) for a confirmed-suspicious file: **~$0.20–$0.60**. With all three opt-in stages: **~$0.50–$2.00**.

## Per-100-file scan projection

Typical mix on a real codebase, default v1.11 cascade:

| Slice | Files | Per-file | Subtotal |
|---|---:|---:|---:|
| Triage CLEAN short-circuit | ~70 | $0.0001 | ~$0.01 |
| LOW-bucket Sonnet | ~20 | $0.05 | $1.00 |
| HIGH-bucket Sonnet split L1 | ~7 | $0.15 | $1.05 |
| HIGH + Opus escalation | ~3 | $0.35 | $1.05 |
| Validation + Remediation (suspicious+) | ~5 | $0.30 | $1.50 |
| **Total** | 100 | | **~$4.60** |

Suspicious-file count varies by codebase. A typical OSS Python SDK scan we ran (32 files) cost $6.71 with full defaults engaged.

Opt-in zero-day hunting roughly **triples** the bill (the Exploit Discovery / Behavioral Profiling / Adversarial Reasoning stages each add ~$0.10-0.50/file when they engage).

## The cost cap

Argus refuses to spend more than `max_cost_per_file_usd` ($1.00 default) on a single file:

```bash
# Override per-scan
argus scan path/to/file.py --max-cost 0.50

# Disable (benchmarks / pathological-file investigation)
argus scan path/to/file.py --max-cost 0
```

On breach, the engine:

- Aborts after the in-flight stage completes (no calls cancelled)
- Returns the partial result with `status: 402`, `error: "cost_cap_exceeded: $X.XX > $Y.YY after <stage>"`
- Adds `cost_cap_exceeded_after:<stage>(<actual>>$<cap>)` to `scan_path`
- Exits with code `1`

The cap is a runaway-safety, not a fine-grained budget tool. Real-world per-file spend lands well under $1.00 except on files where Adversarial Reasoning hits multiple sandbox-iter cycles.

## DAST cost dynamics

DAST is the most variable spend. Per-file cost depends on:

- **Validation** ≈ 1 sandbox call per L1 finding. ~$0.05 + a few cents Fly.
- **Remediation** ≈ 1 patch-generation call + 1 sandbox replay per CONFIRMED finding. ~$0.05 + Fly.
- **Exploit Discovery** ≈ 1 Sonnet call + up to 3 sandbox probes per probe-attractive function. ~$0.20-0.50/file when fired.
- **Adversarial Reasoning** ≈ 1 Opus call + 1-3 sandbox runs per file. ~$0.05-0.15/file.

To cap Fly spend specifically, set per-machine limits via `flyctl scale` — Fly bills per-second on actual machine runtime.

## Three ways to cut cost

**Compliance / CI / read-only audits** (skip Remediation, keep Validation):

```bash
argus scan-repo . --no-enable-remediation
```

**Strictest cost-controlled mode** (DAST only on confirmed-malicious files):

```bash
argus scan-repo . --dast-trigger-verdicts "malicious,critical_malicious"
```

**Cheapest possible scan** (L1 only, no sandbox at all):

```bash
argus scan-repo . --no-dast
```

## Per-file vs per-scan caps

`ScanConfig` declares two caps:

- `max_cost_per_file_usd: float = 1.00` — enforced by `scan_file` (one file at a time)
- `max_cost_per_scan_usd: float = 50.00` — for batch scanning via `argus scan-repo`. Engine aborts the run and marks remaining files `cost_cap_reached`.

Both adjustable via `--max-cost` on the relevant subcommand.
