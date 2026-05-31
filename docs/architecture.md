# Architecture

## The cascade (v1.11)

Every file flows through a tiered pipeline that escalates only as much as it needs to. Default cascade is **Validation + Remediation focused**: confirm findings against the runtime, then auto-patch + re-test. Zero-day-hunting stages (Exploit Discovery, Behavioral Profiling, Adversarial Reasoning) are opt-in.

```
File
  ↓
[$0]   Preprocessing      hash, deobfuscation, deps, attack-vector flags
  ↓
[~$0.02 / file]   Triage (Sonnet 4.6 default; --triage-model gemini-flash-lite
                          to use Gemini)
  ↓
  ├─ CLEAN → return
  ├─ LOW   → Sonnet 4.6 (lightweight prompt)
  └─ HIGH  → Sonnet 4.6 (split L1: VULNS / BEHAVIORAL / CHAINS) → Opus 4.6
            escalation when uncertainty is borderline
  ↓
DAST triggers on suspicious / malicious / critical_malicious (default)
  ↓
[~$0.10 / file]   Finding Validation                              [default ON]
                  Re-runs each L1 finding in a Firecracker microVM.
                  Sandbox-grounded CONFIRMED / REFUTED / BLOCKED /
                  UNREACHED / NOT_TESTED per finding.
  ↓
[~$0.05 / file]   Remediation                                    [default ON]
                  Generates a patched source for CONFIRMED findings.
                  Replays the SAME exploit against the patched code
                  in the same sandbox. Per-finding result:
                  NEUTRALIZED / STILL_EXPLOITABLE / UNVERIFIABLE.
  ↓
[opt-in]          Exploit Discovery → Behavioral Profiling →
                  Adversarial Reasoning (zero-day hunting)
  ↓
[FP-defense]      Structured-assertion / downstream-cap / syscall-sink
                  oracles gate every CONFIRMED finding before it
                  lands. Suppressed findings carry a structured
                  rejection_reason.
  ↓
[Engine guards]   Intent cap (legitimate library code never lands
                  malicious); findings-floor invariant (clean never
                  ships with active findings).
```

## The five stages

### 1. Preprocessing — deterministic, free

`preprocessing/`. No model calls. Byte-deterministic. Produces:

- `file_hash` (sha256), `detected_language`
- `dependencies[]` (per-ecosystem manifest parsing)
- `deobfuscation_applied`, `deobfuscation_layers`
- `imperative_install_detected`
- `attack_vector_extension` (.pth / .whl / .egg / .spec)
- `crypto_sensitivity_detected`, `ai_file_match`
- `known_malware_match` (sha256 lookup) — short-circuits the whole
  pipeline with `critical_malicious` on hit; zero model spend

JS string-array deobfuscation via `webcrack` lives here too — closes the "obfuscated payload too big to read" evasion vector.

### 2. Triage — Sonnet 4.6 (default) or Gemini Flash-Lite (opt-in)

One LLM call per file with a tight classification prompt: CLEAN / LOW / HIGH. CLEAN files return immediately. A safety-net override fires when preprocessing flags a high-stakes category but triage said CLEAN/LOW.

Sonnet 4.6 triage default since v15.9 (more deterministic, ~$0.02/file). Gemini Flash-Lite available via `--triage-model gemini-flash-lite` for cost-sensitive batch scans (~$0.001/file, slightly higher variance).

### 3. L1 cascade analysis

The most-load-bearing stage:

- HIGH-triage default: **Sonnet 4.6 split L1** — three specialized prompts (`VULNS` / `BEHAVIORAL` / `CHAINS`) fan out in parallel
- `--l1-mode combined` reverts to v1.0's single-call shape (useful for A/B comparisons)
- LOW-triage: Sonnet 4.6 lightweight prompt
- **Borderline / high-stakes**: escalate to Opus 4.6 with extended thinking
- Output: structured findings list + verdict + uncertainty score

Uncertainty (SCAN-004) drives Opus escalation: a verdict 10 points from a tier boundary is "borderline" even with high-confidence findings.

### 4. DAST — Finding Validation + Remediation (default ON)

DAST triggers when the rolled-up L1 verdict ∈ `dast_trigger_verdicts` (default: `suspicious / malicious / critical_malicious`).

**Finding Validation** (internally "Phase A") runs each L1 finding in a Firecracker microVM, captures kernel-syscall observations via bpftrace, and labels each finding:

| Status | Meaning |
|---|---|
| `CONFIRMED` | Sandbox observed the exploit firing |
| `REFUTED` | Sandbox tested; the file's own validation rejected the attack |
| `BLOCKED` | Sandbox tested; the file's own code defended (sanitization, escaping) |
| `UNREACHED` | Sandbox tested; the code path is genuinely unreachable |
| `NOT_TESTED` | Sandbox couldn't conclusively validate. Sub-reason: `infra_stub` / `inconclusive` / etc. |
| `SUPPRESSED` | FP-defense oracle (assertion / downstream-cap / syscall-sink) refuted the static match |

**Remediation** (internally "Phase C") generates a patched source for every CONFIRMED finding, then replays the SAME exploit against the patched code in the same sandbox. Per-finding post-patch verdict:

| Status | Meaning |
|---|---|
| `NEUTRALIZED` | Sandbox replay shows the exploit no longer fires — ship the patch |
| `STILL_EXPLOITABLE` | Patch was insufficient; sandbox still observes the original exploit |
| `UNVERIFIABLE` | Sandbox couldn't decisively replay — manual review |

### 5. Opt-in zero-day hunting

Three additional stages for users who want broader coverage on top of the default Validation + Remediation cascade:

- **Exploit Discovery** (`--enable-runtime-probe`) — Sonnet enumerates the file's callables, generates fresh attack inputs for each, hunts for exploits L1 didn't see. New findings: `HRP_*_*`. Python/JS/shell only.
- **Behavioral Profiling** (`--enable-phase-3-discovery`) — sandbox imports the module with benign inputs, captures runtime behavior (syscalls, network, file IO, eval/exec/subprocess reach) into a structured profile. Non-destructive.
- **Adversarial Reasoning** (`--enable-phase-3-loop`) — Opus designs attack hypotheses anchored on the runtime profile; sandbox tests each. New findings: `HRP_AL_*`. Strategy C post-trace LLM judge gates FP risk.

Together they add ~$0.50-1.50/file. Opt-in stage-by-stage or all three together.

## FP-defense oracle stack

Every CONFIRMED finding passes three precision gates before landing in the report:

1. **Structured assertions** (`dast/runtime_probe.py`) — model emits a Python predicate (`getattr(result, 'scheme', None) == 'file'`); sandbox evaluates against the live return value. Highest-precision oracle.
2. **Static downstream-cap detector** (`dast/downstream_cap.py`) — AST finds same-file callers that bound a function's return below the attack-class threshold. Catches "unit return confirmed, but downstream caller caps the value" FPs.
3. **Sandbox-syscall sink observation** (`dast/sink_observation.py`) — consults bpftrace per-probe `syscall_observations` to verify the expected sink (execve / network connect / openat) actually fired.

Every SUPPRESSED finding carries a structured `rejection_reason` traceable to one of these.

## Engine-level invariants

Two final guards run after all DAST work:

- **Intent cap** (SCAN-013) — legitimate library code can never land `malicious` / `critical_malicious` regardless of L1's claims. Static-only confirmations on library code downgrade to `informational`.
- **Findings-floor** (SCAN-014) — `final_verdict == "clean"` is structurally impossible when L1 emitted active findings. Closes the "clean verdict + 3 NOT_TESTED findings" UX contradiction.

## The three sandbox images

| Tier | What's in it | Used for |
|---|---|---|
| `lean` | Python 3.13 + Node + JRE + bash + network CLI + ~30 common pip packages | Default. Most pickle/file/subprocess/exfil exploits. |
| `rich_python` | `lean` + scipy, scikit-learn, openai, anthropic, langchain-core, aiohttp, psutil, psycopg2-binary | Files importing AI SDKs / data libs |
| `ml_tools` | `rich_python` + torch (CPU) + transformers + safetensors + huggingface_hub | Model-loader exploits |

Orchestrator picks `image_hint` per probe. Unmatched hint → falls back to `lean`.

## Where the code lives

| Module | Role |
|---|---|
| `scanner/engine.py` | Orchestrates the cascade. Read this first. |
| `scanner/cli.py` | `argus scan` / `scan-repo` / `install` / `bench` entry points |
| `scanner/runners.py` | Triage / Sonnet / Opus runner factories |
| `scanner/sarif.py` | SARIF v2.1.0 output for GitHub Code Scanning |
| `inference/adapters.py` | Anthropic + Google API adapters |
| `prompts/scanner.py` | Single source of truth for scan prompts |
| `preprocessing/` | Deterministic preprocessing (no model calls) |
| `dast/orchestrator.py` | DAST iteration loop |
| `dast/runtime_probe.py` | Phase A + Phase B+ probe harnesses |
| `dast/behavioral_probe.py` | Phase 3 Stage 1 behavioral profiler |
| `dast/adversarial_loop_runner.py` | Phase 3 Stage 2 reasoning loop |
| `dast/downstream_cap.py` | Phase 2 FP-defense — same-file cap detector |
| `dast/sink_observation.py` | Phase 3 FP-defense — syscall sink observation |
| `dast/syscall_observability.py` | bpftrace sidecar parser |
| `dast/sandbox/` | Fly Firecracker sandbox client |
| `methodology/bench.py` | BENCH-002/003/005 — beat-Opus benchmark harness |
| `samples/regression_v1/` | Regression suite + canonical baseline oracle |
