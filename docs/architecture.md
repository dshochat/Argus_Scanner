# Architecture

## The cascade

Every file goes through a deterministic pipeline that escalates only as much as it needs to.

```
File
  ↓
[$0]   Preprocessing      hash, deobfuscation, deps, attack-vector flags
  ↓
[Gemini Flash-Lite]   Triage  (CLEAN | LOW | HIGH)
  ↓
  ├─ CLEAN → return
  ├─ LOW  → Gemini Flash combined
  └─ HIGH → Sonnet 4.6 combined (default)
            ↳ borderline OR high-stakes → Opus 4.6 deep
  ↓
[N=3 Sonnet ensemble]  on borderline files (post-v1)
  ↓
[DAST verification]  Sonnet orchestrator + Firecracker sandbox
  ↓
[Engine guard]  DAST never lowers L1's verdict without sandbox-grounded
                 refutation (DAST-105)
```

## The four stages

### 1. Preprocessing — deterministic, free

Implemented in `preprocessing/`. No models. Hand-written, byte-deterministic. Produces:

- `file_hash` (sha256)
- `detected_language`
- `dependencies[]` (per-ecosystem manifest parsing)
- `deobfuscation_applied`, `deobfuscation_layers`
- `imperative_install_detected`
- `attack_vector_extension` (.pth / .whl / .egg / .spec)
- `crypto_sensitivity_detected`
- `ai_file_match`
- `known_malware_match` (sha256 lookup)

A known-malware hash short-circuits the whole pipeline with `critical_malicious` — no model calls.

### 2. Triage — Gemini Flash-Lite

One Flash-Lite call per file with a tight classification prompt: CLEAN / LOW / HIGH. Costs ~$0.0001 per file. CLEAN files return immediately.

A safety-net override fires when preprocessing flags a high-stakes category but triage said CLEAN or LOW — false-negative cost > false-positive cost.

### 3. Cascade analysis

The most-load-bearing stage:

- **HIGH + no preprocessing flags** → Sonnet 4.6 (default).
- **HIGH + high-stakes flag** → Opus 4.6 directly.
- **Sonnet uncertainty > threshold** → escalate to Opus.

Uncertainty (SCAN-004) is derived from per-finding confidence + composite-score boundary distance. A score 10 points from a verdict cutoff is "borderline" even with high-confidence findings.

### 4. DAST verification

Triggers only on `malicious` / `critical_malicious` verdicts. Runs an agentic loop (up to 3 iterations) of:

- **Phase A — Plan**: model proposes sandbox tests per hypothesis
- **Phase A — Verdict**: model reads sandbox traces, scores per-claim
- **Phase B — Explore**: model proposes new hypotheses for next iteration

Sandbox is a Firecracker microVM on Fly.io with one of three image variants (`minimal`, `networked`, `ml_tools`) selected by the planner.

The orchestrator's iter-erosion guard prevents within-DAST verdict erosion. DAST-105 (engine-side) prevents L1↔DAST erosion.

## Architecture invariants

These are non-negotiable in v1:

1. **Preprocessing is deterministic and free.** Never call models in `preprocessing/`.
2. **Cascade short-circuits cheap files cheap.** Clean files cost $0.0001, no Opus calls.
3. **Single-provider per agentic DAST loop.** Within one DAST scan, only Sonnet (or only Opus on iter-3) — never mixed.
4. **All runners injectable.** `scan_file(triage_runner=, sonnet_runner=, opus_runner=, dast_runner=)`. The engine never hard-codes provider calls.
5. **Methodology before lift claims.** Don't publish a verdict-exact lift number from a single regression run. N=2 minimum for cross-config comparisons.
6. **DAST is the technical differentiator.** Pattern scanners (Semgrep, deepsec) and Mythos at $50-200/scan don't combine cascade routing + sandbox verification at this price.

## Where the code lives

| Module | Role |
|---|---|
| `scanner/engine.py` | Orchestrates the cascade. Read this first. |
| `scanner/runners.py` | Triage / Sonnet / Opus runner factories |
| `scanner/sanitizer.py` | Strips provider-name + identity leaks from model output |
| `scanner/cli.py` | `argus scan` + `argus bench` entry points |
| `inference/adapters.py` | Anthropic + Google API adapters |
| `prompts/scanner.py` | Single source of truth for scan prompts |
| `preprocessing/` | Deterministic preprocessing (lifted from echoDefense) |
| `dast/orchestrator.py` | DAST iteration loop (lifted from echoDefense) |
| `dast/inference.py` | Sonnet inference function for DAST |
| `dast/runner.py` | DAST runner wrapper, integrates with `scan_file` |
| `dast/sandbox/` | Fly Firecracker sandbox client |
| `methodology/bench.py` | BENCH-002/003/005 — beat-Opus benchmark harness |
| `samples/regression_v1/` | 23-file regression suite + canonical baseline oracle |
