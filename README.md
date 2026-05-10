# Argus Scanner

Argus is an AI-native security scanner that doesn't just flag "sinks" — it **proves exploitability at runtime**, then verifies the patch.

Existing scanners flag patterns. They can't tell you whether the pattern is reachable, exploitable, or already defended against by the file's own code. That gap was tolerable when the threat was SQL injection. It is not tolerable when your AI agent (or a human) `pip install`s something no advisory has flagged, or when an attacker plants malicious instructions in a `CLAUDE.md` or `.cursorrules` file your coding agent will load tomorrow.

Argus moves from pattern matching to **intent verification**: would this code, if executed, do something an attacker wants? Open source, BYOK, built for environments executing code they didn't write.

## Coverage today

**Cascade analysis (all listed formats)** — every file gets static + LLM analysis through the cost-tiered cascade:

* **Code:** Python, JavaScript / TypeScript, shell, Java bytecode (`.class`, `.jar`)
* **Supply-chain manifests:** `package.json`, `requirements.txt`, `Cargo.lock`, `go.mod`, `Gemfile`, `composer.json`, `pyproject.toml`, `Pipfile`, Dockerfile, Makefile, `.npmrc`, `.pypirc`
* **AI-agent config sentinels:** `CLAUDE.md`, `mcp.json`, `.cursorrules`, `claude_desktop_config.json`, `AGENTS.md`, `devcontainer.json`
* **Doc / web attack surface:** Markdown / RST / AsciiDoc (prompt-injection vectors), HTML / SVG / XML (XSS, XXE, hidden script tags)

**DAST runtime detonation (executable code only)** — Python, JavaScript / TypeScript, shell, Java bytecode. Non-executable formats (manifests, Markdown, AI-agent configs, HTML/XML) are cascade-only by definition — there is no runtime to detonate, but the LLM cascade still surfaces malicious payloads, prompt-injection content, and lifecycle-hook backdoors.

**Roadmap:** Go, Rust, .NET (cascade + DAST).

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
