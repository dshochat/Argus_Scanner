# Argus Scanner

**Verified vulnerability remediation at machine scale.** Argus runs every confirmed finding through a Firecracker sandbox, generates a patch, and replays the same exploit against the patched code — so you ship fixes that actually close the bug, not tickets that pile up.

Open source, BYOK, Apache 2.0.

## How Argus uses LLMs (the cutting edge)

Past sandbox-validated security tools treated the LLM as a triage step bolted onto a deterministic runtime: a pattern matcher up front, a fixed fuzzer in the middle, maybe a templated fix at the end. Argus inverts that. **The LLM is in the loop at every step that requires semantic reasoning; the sandbox is the ground-truth oracle.**

```
LLM reads the file                  → static findings + verdict
LLM designs the attack inputs       → executed in the sandbox
LLM interprets the sandbox trace    → CONFIRMED / REFUTED / BLOCKED / …
LLM writes the patch                → applied to a clean source copy
LLM designs the post-patch replay   → executed in the same sandbox
LLM judges the replay observation   → NEUTRALIZED / STILL_EXPLOITABLE / …
```

Every step that needs "is this exploit real / what does this trace mean / will this patch close the hole" goes through Sonnet 4.6 or Opus 4.6. Every step that needs ground truth — did the syscall fire, did the file actually open, did the patched code still leak — happens in a Firecracker microVM with kernel-syscall observation via bpftrace.

This composition is the differentiator. Static SAST tools have no runtime. Classic DAST tools have no semantic reasoning about the file under test. Pattern-based remediation tools generate patches without verification. Argus closes all three gaps with the LLM-in-the-loop running against a real sandbox.

The result: a CONFIRMED finding in an Argus report has both an AI-authored rationale **and** a kernel-level event trace proving the exploit fired. The Remediation block has a patch **and** sandbox-replay evidence that the original exploit no longer fires. Neither half is trustable alone; together they're a credible ship signal.

## The problem

Vulnerability throughput is up and to the right and it isn't slowing down. CVE counts, supply-chain advisories, AI-generated code, agent-authored PRs, agent-installed dependencies — the queue of "things to patch" grows every quarter while the team that has to patch them does not. CISOs aren't asking "can you find more bugs?" anymore. They're asking "**how do I close 10,000 open findings before next audit?**"

The bottleneck is not detection. It's two things:

1. **Triage paralysis.** Static scanners flag thousands of patterns that may or may not be real. Engineers spend 60-80% of their security time deciding which ones to fix instead of fixing them.
2. **Patch validation.** Even when you write a fix, you don't know if it actually closes the hole until something else (a pen-tester, a customer, an attacker) tells you it didn't. Most teams ship patches blind.

Static scanners give you more findings. Argus closes them.

## How Argus closes findings

```
File → L1 (AI static analysis) → Finding Validation → Remediation
                                  ────────────────    ──────────────
                                  Sandbox replays     Auto-patch +
                                  each finding to     replay same
                                  confirm/refute      exploit against
                                  with runtime        the patched
                                  evidence            code to verify
```

Two stages, both **default ON as of v1.11**:

* **Finding Validation** (the runtime FP killer). Every L1 finding is re-run against the file's real runtime in a Firecracker microVM. A "potential SSRF" the file's own validation rejects → `BLOCKED`. A path-traversal that never reaches `open()` → `UNREACHED`. A pattern that fires for real → `CONFIRMED` with sandbox-captured proof. Only what survives is real work.
* **Remediation** (the headline). For each `CONFIRMED` finding, Argus generates a targeted patch, applies it to a clean copy of the source, and **re-runs the original exploit against the patched code in the same sandbox**. Per-finding post-patch verdict:
  * `NEUTRALIZED` — sandbox replay shows the exploit no longer fires. Ship the patch.
  * `STILL_EXPLOITABLE` — patch was insufficient; Argus tells you what still fires.
  * `UNVERIFIABLE` — sandbox couldn't decisively replay; manual review.

You get a tested fix, not a ticket. At scan-repo scale, you get hundreds of tested fixes in one run — fanned out across your codebase, ready to PR.

## Why machine-level remediation is the only credible answer

CISOs in 2026 are choosing between three remediation postures:

1. **Hire your way out.** Doesn't scale. Security engineers don't materialize.
2. **AI-generate patches blind.** Cheap, fast, dangerous. Without runtime validation, every "fix" is a guess. You ship regressions or insufficient patches and find out the hard way.
3. **Machine-validated remediation.** Sandbox proves the bug. AI writes the patch. Sandbox proves the patch. Repeat at scale. This is Argus.

Sandbox validation is the difference between a remediation pipeline and a patch-ticket pipeline.

## Coverage today

**Static + LLM cascade** (all listed formats):

* **Code:** Python, JavaScript / TypeScript, shell, Java bytecode (`.class`, `.jar`)
* **Supply-chain manifests:** `package.json`, `requirements.txt`, `Cargo.lock`, `go.mod`, `Gemfile`, `composer.json`, `pyproject.toml`, `Pipfile`, Dockerfile, Makefile, `.npmrc`, `.pypirc`
* **AI-agent config sentinels:** `CLAUDE.md`, `mcp.json`, `.cursorrules`, `claude_desktop_config.json`, `AGENTS.md`, `devcontainer.json`
* **Doc / web attack surface:** Markdown / RST / AsciiDoc (prompt-injection vectors), HTML / SVG / XML

**Sandbox detonation + Remediation** (executable formats only): Python, JavaScript / TypeScript, shell, Java bytecode. Non-executable formats stay cascade-only by definition.

**Roadmap:** Go, Rust, .NET.

## Optional: deeper coverage

For zero-day hunting beyond Validation + Remediation, three opt-in stages are available:

| Stage | What it does | Flag |
|---|---|---|
| **Exploit Discovery** | Enumerates the file's callables, generates fresh attack inputs, hunts for exploits L1 didn't see | `--enable-runtime-probe` |
| **Behavioral Profiling** | Imports the module with benign inputs, captures runtime behavior (syscalls, network, file IO) | `--enable-phase-3-discovery` |
| **Adversarial Reasoning** | Model designs attack hypotheses anchored on the runtime profile, sandbox tests each | `--enable-phase-3-loop` |

Enable all three with the three flags together. Typical added cost: ~$0.50-1.50/file. Most operators don't need these — the default Validation + Remediation cascade handles 90% of the actual remediation workload.

## Per-finding verdicts

| Status | Meaning |
|---|---|
| `CONFIRMED` | Sandbox observed the exploit firing. Patch generated + re-validated by default. |
| `BLOCKED` | Attack was tested; the file's own code defended (sanitization, escaping, allowlist). |
| `UNREACHED` | Attack was tested; the code path is genuinely unreachable. |
| `NOT_TESTED` | Sandbox couldn't execute the test. Sub-reason: `infra_stub` / `inconclusive` / `not_planned`. |
| `SUPPRESSED` | Production-grade FP-defense oracle (structured assertion / downstream-cap / syscall-sink) refuted the static match. |

A typical `CONFIRMED` + `NEUTRALIZED` shipping bundle:

```json
{
  "cwe": "CWE-200",
  "type": "data_exfiltration",
  "severity": "critical",
  "status": "CONFIRMED",
  "runtime_evidence": "Mock HTTP server at 127.0.0.1:8000 captured POST body containing 'FAKE_PRIVATE_KEY_CONTENT'. The function decoded its base64 payload and POSTed the contents of ~/.ssh/ to the C2 endpoint.",
  "remediation": {
    "status": "NEUTRALIZED",
    "patch": "...unified diff...",
    "verification": "Same exploit re-run against patched source: no HTTP POST observed, no /tmp/canary creation, exception raised at line 47 before any I/O."
  }
}
```

This is what an SLA-grade remediation pipeline looks like.

## Enterprise invariants

* **BYOK.** You control LLM access; bills go to your API meter, not ours.
* **Zero telemetry.** Cascade-only mode: nothing leaves your machine. DAST mode: file content goes only to a Fly.io app *you own and control* — never to Argus-operated infrastructure.
* **Local execution.** Self-contained pipeline; no SaaS dependency.
* **Hardware isolation.** Detonation happens in Firecracker microVMs (KVM hardware virtualization), ephemeral per-run, strict egress control. Patch verification re-uses the same isolation primitives.

## Quick Start

```bash
pip install argus-ai-scanner
export ANTHROPIC_API_KEY="your-anthropic-key"

# Single file — Validation + Remediation by default
argus scan path/to/suspicious.py

# Whole repo — full remediation pipeline across every file
argus scan-repo .

# CI mode — only files changed vs main, SARIF for GitHub Code Scanning
argus scan-repo . --diff origin/main --output sarif --output-file findings.sarif

# Read-only audit (compliance scans / no source mods allowed)
argus scan-repo . --no-enable-remediation

# Full coverage including zero-day hunting
argus scan path/to/file.py \
  --enable-runtime-probe \
  --enable-phase-3-discovery \
  --enable-phase-3-loop
```

Without DAST configured (Fly.io app), Argus gracefully degrades to cascade-only verdicts — Remediation requires the sandbox.

## CLI reference

### `argus scan <file>` — single-file scan

| Flag | Purpose |
|---|---|
| `--output {json,markdown}` | Output format (default: `json`) |
| `--no-dast` | Skip all sandbox stages (cascade-only) |
| `--no-enable-remediation` | Skip patch generation (default ON) |
| `--enable-runtime-probe` | Opt in to Exploit Discovery |
| `--enable-phase-3-discovery` | Opt in to Behavioral Profiling |
| `--enable-phase-3-loop` | Opt in to Adversarial Reasoning |
| `--dast-trigger-verdicts LIST` | L1 verdicts that trigger DAST. Default: `suspicious,malicious,critical_malicious`. |
| `--max-cost USD` | Abort if per-file API spend exceeds USD (default: $1.00; `0` disables) |

### `argus scan-repo <path>` — directory tree scan

Same flags as `scan` plus:

| Flag | Purpose |
|---|---|
| `--diff REF` | Only scan files differing vs git ref (e.g., `--diff origin/main` for PR/CI) |
| `--output {markdown,json,sarif}` | Output format (default: `markdown`); `sarif` for GitHub Code Scanning |
| `--output-file PATH` | Write output to file instead of stdout |
| `--max-cost USD` | Abort run when cumulative API spend exceeds USD; remaining files marked `cost_cap_reached` |
| `--exclude GLOB` | Additional gitignore-style exclude pattern (repeatable) |
| `--no-gitignore` | Ignore `.gitignore` during walk (default: respected) |
| `--max-file-bytes BYTES` | Skip files larger than BYTES (default: 1 MiB) |
| `--continue-on-error` / `--no-continue-on-error` | On per-file exception, record and continue (default) or abort |

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
