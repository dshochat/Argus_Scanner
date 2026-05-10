# Argus Scanner

**We don't flag what we can't exploit.**

Argus is an AI-native code security scanner that runs every suspect path in a sandbox before it ships a verdict. Whether the bug is in code your team wrote (SQL injection, auth bypass, deserialization, command injection, crypto misuse) or in code your stack quietly pulled in (a malicious package, a poisoned `CLAUDE.md`, a backdoored `setup.py`, a tampered ML checkpoint loader about to run on someone's machine) — Argus detonates it in a Firecracker microVM, captures the exploit firing, generates a patch, replays the same exploit against the patched source, and ships the result as a CI gate.

It targets the gap between *"this looks suspicious"* (pattern-matching SAST) and *"this actually exploits something"* (manual reverse engineering).

**One scanner. Two threat models. Zero false-positive triage.**

Open source. BYOK. Apache 2.0.

You pay your providers directly — Anthropic + Google for the cascade, Fly.io for the optional DAST sandbox. Argus collects nothing.

---

## Architecture at a glance

```
                        ┌─────────────────────┐
                        │   source file       │
                        │   (any extension    │
                        │    we recognize)    │
                        └──────────┬──────────┘
                                   │
                                   ▼
   ┌────────────────────────────────────────────────────────────┐
   │  PILLAR 1 — Cascade harness                                │
   │  ──────────────────────────                                │
   │   Preprocessing (free, deterministic)                      │
   │     hash · deobfuscation · deps · attack-vector flags      │
   │     · AI-file pattern detection · .pth path-hijack guard   │
   │                  │                                         │
   │                  ▼                                         │
   │   Triage  ──  Gemini Flash-Lite  (~$0.001/file)            │
   │     ├─ CLEAN ────────────────────────────┐                 │
   │     ├─ LOW   ──  Gemini Flash    (~$0.02)│                 │
   │     ├─ HIGH  ──  Claude Sonnet 4.6 (~$0.07)                │
   │     └─ borderline / high-stakes  →  Claude Opus 4.6 (~$0.15)│
   │                  │                                         │
   │                  ▼                                         │
   │     findings: CWE · line · severity · code · explanation · │
   │     suggested fix · proof-of-concept · attack chains       │
   └─────────────────────┬──────────────────────────────────────┘
                         │
            verdict in {malicious, critical_malicious}?
                  yes ──┴── no  →  return result
                         │
                         ▼
   ┌────────────────────────────────────────────────────────────┐
   │  PILLAR 2 — DAST runtime detonation                        │
   │  ──────────────────────────────────                        │
   │   Firecracker microVM (minimal-v1 / networked-v1 / ml_tools-v1)│
   │                                                            │
   │   ITERATION  it ∈ [1, 3]                                   │
   │   ┌──────────────────┐    ┌──────────────────────┐         │
   │   │ Phase A — VERIFY │ →  │ Phase B — DISCOVER    │         │
   │   │ run exploit plan │    │ propose new hypotheses│         │
   │   │ in microVM       │    │ validator gates them  │         │
   │   │  → CONFIRMED     │    │  survivors → next iter│         │
   │   │  → BLOCKED       │    └──────────────────────┘         │
   │   │  → UNREACHED     │              │                      │
   │   │  → NOT_TESTED    │              ▼                      │
   │   └────────┬─────────┘   stop on convergence or it=3       │
   │            │                                               │
   │            ▼                                               │
   │   per-finding runtime evidence + sandbox-captured PoC      │
   └─────────────────────┬──────────────────────────────────────┘
                         │
              any finding CONFIRMED?  AND  --no-remediation NOT set?
                  yes ──┴── no  →  return result
                         │
                         ▼
   ┌────────────────────────────────────────────────────────────┐
   │  PILLAR 3 — Remediation (fix-and-verify)                   │
   │  ───────────────────────────────────────                   │
   │   text source:    generate patch  →  replay exploit on     │
   │                   patched code in same sandbox             │
   │                   →  NEUTRALIZED / STILL_EXPLOITABLE /     │
   │                      UNVERIFIABLE                          │
   │                                                            │
   │   binary artifact (.pkl/.pt/.bin/.safetensors/.h5/.onnx):  │
   │                   no auto-patch (would corrupt the file).  │
   │                   Emit structured guidance:                │
   │                   "regenerate from clean pipeline +        │
   │                    serialize using safetensors"            │
   │                   →  UNVERIFIABLE + fix_summary            │
   └─────────────────────┬──────────────────────────────────────┘
                         │
                         ▼
                  ScanResult JSON / SARIF
```

## How Argus works (the three pillars)

Argus has three pillars. The capability matrix below shows exactly what each pillar does for each file type.

### Pillar 1 — Cascade harness (static + AI analysis)

Every recognized file flows through a cost-tiered model cascade. Deterministic preprocessing first (free, no models): SHA-256, multi-stage deobfuscation (base64 / hex / eval-chain), dependency graphing, attack-vector flagging, AI-file-pattern detection. Files with no outbound intent get dropped before a single token is spent.

Survivors route through a model cascade:

| Cascade stage | Model | Cost / file | Decides |
|---|---|---|---|
| Triage | **Gemini Flash-Lite** | ~$0.001 | `CLEAN` / `LOW` / `HIGH` routing |
| Cheap analysis (LOW tier) | **Gemini Flash** | ~$0.02 | findings on low-priority files |
| Default deep analysis (HIGH tier) | **Anthropic Claude Sonnet 4.6** | ~$0.07 | findings on high-priority files |
| High-stakes / borderline escalation | **Anthropic Claude Opus 4.6** | ~$0.15 | ~20% of HIGH files |

The harness emits structured findings: CWE, line, severity, code, explanation, suggested fix, proof-of-concept, behavioral profile, attack chains, composite risk score. Aggregate cost is ~$4.65 per 100-file scan on a realistic workload mix; hard per-file + per-scan cost caps abort runs that exceed your declared budget.

### Pillar 2 — DAST runtime detonation

When the harness flags suspicion at sufficient verdict tier, the file moves to a Firecracker microVM (`minimal-v1`, `networked-v1`, or `ml_tools-v1` image profile) for two phases:

* **Phase A — exploit testing.** Plan an exploit per harness finding, run it in the sandbox, capture syscalls / egress / filesystem writes, classify each finding as `CONFIRMED` / `BLOCKED` / `UNREACHED` / `NOT_TESTED` based on what actually happened.
* **Phase B — exploit discovery.** Given accumulated evidence, propose NEW hypotheses the harness missed. A deterministic validator gates the proposals; survivors carry forward into the next iteration's Phase A. Up to 3 iterations or until convergence.

This is the layer that kills false positives — a "looks like SQL injection" pattern that the file's own escaping defends against gets `BLOCKED`, not flagged. And it surfaces what static analysis missed — Phase B has actually found new findings the harness didn't catch.

### Pillar 3 — Remediation (fix-and-verify)

When Phase A confirms an exploit on **text source** (Python, JS / TS, shell), Argus generates a patched version, replays the same exploit attempts against the patched code in the same sandbox, and emits per-finding `NEUTRALIZED` / `STILL_EXPLOITABLE` / `UNVERIFIABLE` with sandbox-grounded evidence. You don't get a remediation *suggestion*; you get a remediation that's been *tested*.

**Binary artifact policy.** For ML artifacts (`.pkl` / `.pt` / `.bin` / `.safetensors` / `.h5` / `.onnx`), Argus does NOT auto-patch the binary — the model can't emit valid bytecode-level patches and a corrupt patched pickle would mislead the replay. Instead, the remediation pillar emits structured guidance: regenerate the model from a clean training pipeline and serialize using `safetensors` (which is structurally incapable of carrying executable `__reduce__` payloads). Status is `UNVERIFIABLE` with the guidance in `fix_summary`.

**Opt-out:** pass `--no-remediation` to skip this pillar entirely while keeping the harness + DAST active. Use for compliance scans, CI gates that don't allow source-modification suggestions, read-only audits, or to save ~$0.05/file in patch-generation tokens. The result still includes a structured `phase_c` block with `skipped_reason: "phase_c_disabled_by_config"` so downstream consumers can distinguish "remediation off" from "ran and found nothing to fix."

---

## Coverage matrix

What each pillar does, per file type. ✅ = supported, ⚠️ = supported with policy nuance, ⏳ = roadmap, ❌ N/A = not applicable to this format.

| File type | Harness analysis | DAST exploit testing | DAST exploit discovery | Remediation |
|---|:-:|:-:|:-:|:-:|
| Python (`.py`, `.pyw`, `.pyi`, `.pth`) | ✅ | ✅ | ✅ | ✅ patch + replay |
| JavaScript / TypeScript (`.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`) | ✅ | ✅ | ✅ | ✅ patch + replay |
| Shell (`.sh`, `.bash`, `.zsh`) | ✅ | ✅ | ✅ | ✅ patch + replay |
| Jupyter notebooks (`.ipynb`) | ✅ cell-by-cell decomposition | ⏳ roadmap | ⏳ roadmap | ⏳ roadmap |
| ML model artifacts (`.pkl`, `.pickle`, `.pt`, `.bin`, `.safetensors`, `.h5`, `.hdf5`, `.keras`, `.onnx`) | ✅ pickletools disassembly | ✅ load-detonation in sandbox | ❌ | ⚠️ guidance only (no auto-patch — see binary policy) |
| GitHub Actions workflows (`.github/workflows/*.yml`) | ✅ deterministic CI-pattern sweep | ⏳ roadmap | ⏳ roadmap | ⏳ roadmap |
| Supply-chain manifests (`package.json`, `requirements.txt`, `Cargo.lock`, `go.mod`, `Gemfile`, `Pipfile`, `setup.py`, `pyproject.toml`, `pom.xml`, `build.gradle`, `*.csproj`, etc.) | ✅ parsed for deps + lifecycle hooks | ❌ N/A (no runtime to detonate) | ❌ N/A | ❌ N/A |
| AI-agent config sentinels (`CLAUDE.md`, `AGENTS.md`, `SKILL.md`, `.cursorrules`, `.clinerules`, `mcp.json`, `plugin.json`, `openapi.{yaml,json}`, `agent-config.{yaml,json,toml}`, etc.) | ✅ prompt-injection surface | ❌ N/A | ❌ N/A | ❌ N/A |
| Other languages tagged for harness (Java, Kotlin, Scala, Go, Rust, Ruby, PHP, C#, C/C++, PowerShell, Lua, Perl, R, Swift, Terraform, HCL) | ✅ generic harness analysis | ⏳ roadmap | ⏳ roadmap | ⏳ roadmap |

### Notes

* **Harness analysis** = preprocessing + LLM cascade. Always runs on recognized files unless the cost cap aborts.
* **DAST exploit testing (Phase A)** = sandbox-validates the harness's findings. Triggered by verdict tier (`malicious`, `critical_malicious` by default; configurable via `--dast-trigger-verdicts`).
* **DAST exploit discovery (Phase B)** = sandbox finds new exploits the harness missed. Runs alongside Phase A.
* **Remediation (fix-and-verify)** = generates patched source + replays exploits against the patch. Toggle off with `--no-remediation`.
* **`.pth` path-hijack** is force-elevated to priority-5 in the harness preprocessing layer regardless of model verdict — a classic Python supply-chain pattern that triage routinely misses.
* **ML-artifact load detonation** validated end-to-end: 3/3 L1 findings reached `CONFIRMED` with sandbox-captured runtime evidence on a malicious `subprocess.Popen` pickle (real Fly Firecracker microVM, $0.22, 253s, 5 sandbox calls).

### Roadmap (tracked in [ROADMAP.md](./ROADMAP.md))

1. **Jupyter notebook DAST** — convert + execute the synthesized script in a sandbox image (cell-by-cell), watch the same syscall / egress signals as Python source
2. **GitHub Actions workflow DAST** — run workflows under an `act`-shaped runner with adversarial event JSON, observe what gets exfiltrated
3. **Java bytecode** (`.class`, `.jar`) — decompiler preprocessing + JDK sandbox profile
4. **Go, Rust, .NET** — full DAST + remediation coverage
5. **k8s / Helm / Terraform** (niche-adjacent; deferred until demand)

## Per-finding verdicts (where the FP kill happens)

Every finding ships with one of these statuses:

| Status | Meaning |
|---|---|
| `CONFIRMED` | Sandbox observed the exploit firing. PoC + event trace surfaced with the finding. |
| `BLOCKED` | Attack was tested; the file's own code defended against it (sanitization, escaping, allowlist). |
| `UNREACHED` | Attack was tested; the code path is genuinely unreachable. |
| `NOT_TESTED` | Sandbox couldn't execute the test. Sub-reason: `infra_stub` / `inconclusive` / `not_planned`. |

A `CONFIRMED` finding looks like this:

```json
{
  "cwe": "CWE-200",
  "type": "data_exfiltration",
  "severity": "critical",
  "status": "CONFIRMED",
  "confidence": 1.0,
  "runtime_evidence": "Mock HTTP server at 127.0.0.1:8000 captured POST body containing 'FAKE_PRIVATE_KEY_CONTENT' and 'ssh-rsa AAAAFAKEKEY user@host'. The malware decoded its base64 payload and POSTed the contents of ~/.ssh/ to the rewritten C2 endpoint.",
  "proof_of_concept": "On any Unix host with SSH keys present, execution sends the full contents of ~/.ssh/ to the remote C2 server over HTTPS."
}
```

DAST cuts three ways: it **confirms** exploits with sandbox-captured evidence, **refutes** false positives with proof of non-exploitability, and **verifies remediations** by replaying the same exploits against the patched source.

## Benchmark Performance

Adversarial regression suite, labeled by a 4-LLM consensus oracle. Methodology, sample size, and per-file breakdown: [`bench_results/v1_1_launch/launch_report.md`](./bench_results/v1_1_launch/launch_report.md).

```
                       Verdict-exact (higher = better)
Argus (cascade + DAST) ████████████████████  91.3%
Gemini 3.1 Pro         █████████████████░░░  82.6%
Grok 4.3               █████████████████░░░  82.6%
Opus 4.6               █████████████████░░░  78.3%
GPT 5.4                ████████████████░░░░  73.9%
```

## Enterprise Invariants

Anthropic's Claude Security and OpenAI's Codex Security are enterprise-tier and vendor-cloud-only. Argus is the open alternative.

* **BYOK.** You control LLM access; bills go to your API meter, not ours.
* **Zero telemetry.** In cascade-only mode, nothing leaves your machine. In DAST mode, file content is sent only to a Fly.io app *you own and control* — never to Argus-operated infrastructure.
* **Local execution.** Fully self-contained pipeline; no SaaS dependency.

## Quick Start

Get from install to first scan in under 60 seconds:

```bash
pip install argus-ai-scanner
export ANTHROPIC_API_KEY="your-anthropic-key"
export GEMINI_API_KEY="your-gemini-key"

# Single file
argus scan path/to/suspicious.py

# Whole repo (current directory)
argus scan-repo .

# CI mode — only files changed vs main, SARIF for GitHub Code Scanning
argus scan-repo . --diff origin/main --output sarif --output-file findings.sarif
```

Without DAST configured the CLI gracefully degrades to cascade-only verdicts. DAST mode (Firecracker sandbox) requires a Fly.io account — see [docs/dast-setup.md](./docs/dast-setup.md).

## CLI Reference

### `argus scan <file>` — single-file scan

| Flag | Purpose |
|---|---|
| `--output {json,markdown}` | Output format (default: `json`) |
| `--no-dast` | Skip DAST verification (cascade-only) |
| `--no-remediation` | Skip Phase C (fix-and-verify). Phase A + B still run; no patch is generated. Compliance / CI-gate / read-only-audit use cases. Saves ~$0.05/file. |
| `--max-cost USD` | Abort this file's scan if **per-file** API spend exceeds USD (default: $1.00; pass `0` to disable) |
| `--enable-discovery` | Proactive payload sweep — runs library of attack payloads against the file in sandbox; surfaces runtime-confirmed CWEs as new findings (+~$0.25/file) |
| `--dast-trigger-verdicts LIST` | Comma-separated L1 verdicts that trigger DAST. Default: `malicious,critical_malicious`. Allowed: `clean,suspicious,malicious,critical_malicious` |

### `argus scan-repo <path>` — directory tree scan

| Flag | Purpose |
|---|---|
| `--diff REF` | Only scan files differing vs git ref (e.g., `--diff origin/main` for PR/CI) |
| `--output {markdown,json,sarif}` | Output format (default: `markdown`); `sarif` is SARIF v2.1.0 for GitHub Code Scanning |
| `--output-file PATH` | Write to file instead of stdout |
| `--max-cost USD` | Abort the run when **cumulative** API spend across all files exceeds USD; remaining files are marked `cost_cap_reached`. Pass `0` or omit to disable |
| `--exclude GLOB` | Additional gitignore-style exclude pattern (repeatable) |
| `--no-gitignore` | Ignore `.gitignore` during walk (default: respected) |
| `--max-file-bytes BYTES` | Skip files larger than BYTES (default: 1 MiB) |
| `--no-dast` | Skip DAST verification on every file |
| `--no-remediation` | Skip Phase C on every file. Phase A + B still run; no patches generated. |
| `--enable-discovery` | Proactive payload sweep on every DAST-eligible file |
| `--dast-trigger-verdicts LIST` | Same as `scan` |
| `--continue-on-error` / `--no-continue-on-error` | On per-file exception, record and continue (default) or abort run |

### `argus bench` — re-run the benchmark

| Flag | Purpose |
|---|---|
| `--suite PATH` | Regression-suite directory (default: `samples/regression_v1`) |
| `--n N` | Runs per config (default: 2) |
| `--no-dast` | Run Argus pipeline L1-only (compare L1-vs-Opus separately) |
| `--dry-run` | Print cost projection without making model calls |
| `--yes` / `-y` | Skip cost-projection confirmation prompt |

## Security & Isolation

Argus deliberately detonates potentially malicious code. Host protection is non-negotiable.

* **Hardware-level isolation.** Execution happens inside Firecracker microVMs using KVM hardware virtualization.
* **Ephemeral state.** Every detonation spins up a pristine microVM and is destroyed post-execution. Zero persistence.
* **Strict egress control.** Network profiles enforced at the hypervisor level prevent lateral movement during DAST verification.

## Documentation

| Topic | Page |
|---|---|
| Install guide | [docs/install.md](./docs/install.md) |
| API key sourcing | [docs/api-keys.md](./docs/api-keys.md) |
| Architecture deep dive | [docs/architecture.md](./docs/architecture.md) |
| DAST sandbox setup | [docs/dast-setup.md](./docs/dast-setup.md) |
| Cost guide | [docs/cost-guide.md](./docs/cost-guide.md) |
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Contributing | [CONTRIBUTING.md](./CONTRIBUTING.md) |
| Security disclosures | [SECURITY.md](./SECURITY.md) |

## License

[Apache License 2.0](./LICENSE).
