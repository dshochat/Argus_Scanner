# Argus Scanner

**We don't flag what we can't exploit.**

Argus is an AI-native code security scanner that runs every suspect path in a sandbox before it ships a verdict. Whether the bug is in code your team wrote (SQL injection, auth bypass, deserialization, command injection, crypto misuse) or in code your stack quietly pulled in (a malicious package, a poisoned `CLAUDE.md`, a backdoored `setup.py`, a tampered ML checkpoint loader about to run on someone's machine) — Argus detonates it in a Firecracker microVM, captures the exploit firing, generates a patch, replays the same exploit against the patched source, and ships the result as a CI gate.

It targets the gap between *"this looks suspicious"* (pattern-matching SAST) and *"this actually exploits something"* (manual reverse engineering).

**One scanner. Two threat models. Zero false-positive triage.**

Open source. BYOK. Apache 2.0.

**v1.2 adds Phase C — fix-and-verify.** When DAST confirms an exploit, Argus generates a patched version of the file, replays the same exploit attempts against the patched code in the same sandbox, and reports per-finding `NEUTRALIZED` / `STILL_EXPLOITABLE` / `UNVERIFIABLE` with sandbox-grounded evidence. You don't get a remediation *suggestion*; you get a remediation that's been *tested*. Validated end-to-end on adversarial fixtures: **5 of 5 confirmed exploits neutralized** across two distinct backdoor patterns.

You pay your providers directly — Anthropic + Google for the cascade, Fly.io for the optional DAST sandbox. Argus collects nothing.

---

## Coverage today

Argus operates at three depths depending on what a file is. Items below the line are roadmap, not implemented.

### Cascade analysis (static + LLM, runs on every recognized file)

**Executable code:** Python (`.py`, `.pyw`, `.pyi`, `.pth`), JavaScript / TypeScript (`.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`), shell (`.sh`, `.bash`, `.zsh`).

**Jupyter notebooks** (`.ipynb`) — decomposed cell-by-cell. Code cells are treated as Python with cell banners preserved; markdown cells are surfaced as prompt-injection surface; shell magic (`!pip install …`) and IPython magic (`%load_ext …`) lines pass through verbatim so the cascade flags installs from suspicious indices, malicious extension loads, and base64'd C2 payloads in the same pass.

**ML model artifacts** (`.pkl`, `.pickle`, `.pt`, `.bin`, `.safetensors`, `.h5`, `.hdf5`, `.keras`, `.onnx`) — disassembled WITHOUT execution via `pickletools`. Surfaces every `GLOBAL` / `STACK_GLOBAL` opcode whose target is a code-execution primitive (`os.system`, `subprocess.Popen`, `pty.spawn`, `builtins.eval`, …) plus the `REDUCE` / `BUILD` / `NEWOBJ` opcodes that turn a global into an invocation. PyTorch zip-of-pickles archives are walked across all members. Safetensors `__metadata__` blocks are extracted so attacker-controlled metadata is visible to the cascade.

**GitHub Actions workflows** (`.github/workflows/*.yml`) — deterministic sweep for the supply-chain CI patterns: `pull_request_target` triggers, third-party actions referenced without SHA pinning (`uses: foo/bar@main`), `${{ github.event.* }}` interpolations into `run:` shells (the GHSL command-injection class), `permissions: write-all`, and `secrets.*` references near network verbs (curl / wget / fetch) inside the same `run:` block.

**Supply-chain manifests** (parsed for dependency extraction + lifecycle-hook detection): `package.json`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py`, `Cargo.toml`, `Cargo.lock`, `go.mod`, `go.sum`, `Gemfile`, `Gemfile.lock`, `pom.xml`, `build.gradle`, `*.csproj`, `packages.config`.

**AI-agent config sentinels** (prompt-injection surface — the file your coding agent will load tomorrow): `CLAUDE.md`, `AGENTS.md`, `SKILL.md`, `.cursorrules`, `.cursorrc`, `.clinerules`, `.github/copilot-instructions.md`, `system_prompt.{md,txt,yaml}`, `mcp.json`, `mcp_*.json`, `plugin.json`, `ai-plugin.json`, `openapi.{yaml,json}`, `agent-config.{yaml,json,toml}`, `tools.{json,yaml}`.

**`.pth` path-hijack detection** — any line starting with `import` in a `.pth` file is force-elevated to priority-5 regardless of model verdict. Catches a classic Python supply-chain pattern that 2048-token triage routinely misses.

**Other languages tagged for cascade analysis** (language-detected; the model-driven cascade still applies, but no specialized per-language detectors yet): Java, Kotlin, Scala, Go, Rust, Ruby, PHP, C#, C / C++, PowerShell, Lua, Perl, R, Swift, Terraform, HCL; Markdown, HTML, XML, JSON, YAML, TOML; Dockerfile, Makefile.

### DAST runtime detonation

Phase A verification + Phase B discovery + Phase C fix-and-verify run on Python, JavaScript / TypeScript, and shell. Sandbox image profiles: `minimal-v1`, `networked-v1`, `ml_tools-v1`.

**ML-artifact load detonation (new):** for `.pkl` / `.pickle` / `.pt` / `.bin` / `.safetensors` / `.h5` / `.onnx`, Argus injects a deterministic load plan into iter 1 — `pickle.load()` / `torch.load(weights_only=False)` / `safe_open()` / `onnx.load()` runs against the original binary in the `ml_tools-v1` sandbox. Loading IS execution for these formats; if the artifact is malicious, the `__reduce__` payload fires and Argus captures the canary file, syscalls, and exit codes that prove it. **Validated end-to-end on a malicious `subprocess.Popen` pickle:** all 3 L1 findings (CWE-502, CWE-78, CWE-94) reached `CONFIRMED` with sandbox-captured runtime evidence — `$0.22` / 253s / 5 sandbox calls, real Fly Firecracker microVM.

Other languages reach DAST only when invoked transitively (e.g., a shell script calling `python`). Non-executable formats (manifests, Markdown, AI-agent configs, HTML / XML) are cascade-only by definition. The cascade still surfaces malicious payloads, prompt-injection content, and lifecycle-hook backdoors.

### Phase C — fix-and-verify (v1.2)

When DAST confirms an exploit on **text source** (Python, JS / TS, shell), Phase C generates a patched version of the file, replays the same exploit attempts against the patched code in the same sandbox, and emits per-finding `NEUTRALIZED` / `STILL_EXPLOITABLE` / `UNVERIFIABLE` with sandbox-grounded evidence. You don't get a remediation *suggestion*; you get a remediation that's been *tested*.

**Binary artifact policy.** For `.pkl` / `.pt` / `.bin` / `.safetensors` / `.h5` / `.onnx`, Argus does NOT auto-patch the binary — the model can't emit valid bytecode-level patches and a corrupt patched pickle would mislead the replay step. Instead, when an ML artifact is CONFIRMED malicious, Phase C emits structured remediation guidance: regenerate the model from a clean training pipeline and serialize using `safetensors` (which is structurally incapable of carrying executable `__reduce__` payloads). Phase C status for these cases is `UNVERIFIABLE` with the guidance in `fix_summary`.

**Opt-out: `--no-remediation`.** Pass this flag to skip Phase C entirely while keeping Phase A verification + Phase B discovery active. Use for compliance scans, CI gates that don't allow source modification suggestions, read-only audits, or to save ~$0.05/file in patch-generation tokens. The result still includes a structured `phase_c` block with `skipped_reason: "phase_c_disabled_by_config"` and the count of findings that would have been remediated, so downstream consumers can distinguish "remediation off" from "Phase C ran and found nothing to fix."

### Roadmap (tracked in [ROADMAP.md](./ROADMAP.md))

1. **Jupyter notebook DAST** — convert + execute the synthesized script in a sandbox image (cell-by-cell), watch for the same syscall/egress signals
2. **GitHub Actions workflow DAST** — run workflows under an `act`-shaped harness with adversarial event JSON, observe what gets exfiltrated
3. **Java bytecode** (`.class`, `.jar`) — decompiler preprocessing + JDK sandbox profile
4. **Go, Rust, .NET** — cascade + DAST coverage
5. **k8s / Helm / Terraform** (niche-adjacent; deferred until demand)

## The 4-Layer Moat

Argus eliminates the two structural failures of modern code analysis: **alert fatigue** and **token cost**.

* **Layer 1 — Deterministic Preprocessing (free, fast).** Hash dedup, multi-stage deobfuscation (base64, hex, eval-string unwrapping), dependency graphing, attack-vector flagging. Files with no outbound intent are dropped before a single token is spent.
* **Layer 2 — Cost-Tiered AI Cascade.** Survivors route through a triage model. CLEAN returns. LOW gets Flash. HIGH gets Sonnet 4.6. ~20% of borderline files escalate to Opus 4.6 deep analysis or a 3-model Sonnet ensemble for confidence calibration.
  * Net: **~$4.65 per 100-file scan** including DAST verification on the projected workload mix. Hard per-file cost caps abort runs that exceed your declared budget.
* **Layer 3 — DAST Verification (the proof).** When the cascade flags suspicion on executable code, Argus detonates the file inside a Firecracker microVM (`minimal`, `networked`, or `ml_tools` profile). The orchestrator runs the file, captures syscalls, monitors egress, and tracks filesystem writes. It either confirms exploitation with hard evidence or refutes the static finding — killing the false positive before it hits the report.
* **Layer 4 — Automated Fix & Verify (the patch). New in v1.2.** If a finding is confirmed, Argus generates a targeted patch and replays the *same* exploit against the patched source in the same sandbox. Per-finding post-patch verdict: **NEUTRALIZED**, **STILL_EXPLOITABLE**, or **UNVERIFIABLE**. You get a tested fix, not a ticket.

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
