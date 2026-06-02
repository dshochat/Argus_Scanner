# Argus Scanner

**Verified vulnerability remediation at machine scale.** Static scanners give security teams more findings to triage; Argus closes them. Argus stacks three layers — deterministic preprocessing, semantic LLM reasoning, runtime sandbox validation — each doing what it's fastest at, so a vulnerability goes from detection to verified, sandbox-tested patch in minutes instead of weeks. The LLM designs the exploit; a Firecracker microVM proves it fires. The LLM writes the patch; the same sandbox replays the same exploit against the patched code. You ship kernel-evidence-verified fixes, not tickets that pile up.

**Beyond code:** Argus also scans live **MCP servers** for runtime vulnerabilities — SSRF (incl. cloud metadata), redirect-to-internal, fail-open validation, and auth bypass — with the same sandbox-verified evidence, pointed at your AI tool surface.

Open source. BYOK. Apache 2.0.

## Install

**1. Install + run the static + LLM cascade** (1 minute):

```bash
pip install argus-ai-scanner
export ANTHROPIC_API_KEY=sk-ant-...

argus scan path/to/file.py            # single file
argus scan-repo .                     # whole repo
```

With just an Anthropic key you get fast static + LLM triage. Useful — but it stops at *"this looks vulnerable."*

**2. Turn on the runtime sandbox** (one-time, ~15 min — *this is the core of Argus*):

The sandbox is the moat: it runs the model-designed exploit in a Firecracker microVM, so a finding goes from *"looks vulnerable"* to a kernel-evidence-**`CONFIRMED`** exploit **plus** an auto-patch replay-tested against that same exploit. Set it up once; every scan afterward gets Validation + Remediation automatically.

You need a [Fly.io](https://fly.io) account (free tier covers it; Fly requires a card on file) and the `flyctl` CLI:

```bash
# Install flyctl:
#   macOS / Linux / WSL   →  curl -L https://fly.io/install.sh | sh
#   Windows PowerShell    →  iwr https://fly.io/install.ps1 -useb | iex

# The sandbox Dockerfiles + build scripts live in the repo, so clone it:
git clone https://github.com/dshochat/Argus_Scanner.git
cd Argus_Scanner/dast/sandbox/firecracker

# Pick a globally-unique Fly app name, then authenticate:
export ARGUS_DAST_FLY_APP=argus-dast-<your-handle>     # PowerShell: $env:ARGUS_DAST_FLY_APP="argus-dast-<your-handle>"
flyctl auth login

# Create the app + build & push the sandbox images (first build ~10-30 min, cached after):
bash preflight.sh                                      # PowerShell: ./preflight.ps1
flyctl tokens create deploy --app "$ARGUS_DAST_FLY_APP" --expiry 720h
bash build_and_push_multi.sh
```

`build_and_push_multi.sh` prints the exact env values to save. Add them to your `.env` (next to `ANTHROPIC_API_KEY`):

```env
FLY_API_TOKEN=<deploy token from the step above>
ARGUS_DAST_FLY_APP=argus-dast-<your-handle>
ECHO_DAST_IMAGE_LEAN=<ref printed by build_and_push_multi.sh>
ECHO_DAST_IMAGE_RICH_PYTHON=<ref printed by build_and_push_multi.sh>
ECHO_DAST_IMAGE_ML_TOOLS=<ref printed by build_and_push_multi.sh>
```

Verify (from the repo root) — a known-vulnerable file should come back **`CONFIRMED`** with a sandbox event trace:

```bash
argus scan samples/regression_v1/high_with_vuln.py
```

That's it — `argus scan` / `argus scan-repo` now run Validation + Remediation on every suspicious file. Full walkthrough + troubleshooting: [docs/dast-setup.md](docs/dast-setup.md).

## What a scan looks like

```text
$ argus scan samples/regression_v1/high_with_vuln.py

high_with_vuln.py  →  suspicious  (2 CONFIRMED, 0 NEUTRALIZED, 1 STILL_EXPLOITABLE, 1 UNVERIFIABLE)
                      cost: $0.31      time: 5m 50s

H001  CWE-78 command_injection  critical  CONFIRMED
  function: run_user_command (line 7)
  evidence: sandbox executed `; whoami` via shell=True interpolation
  ▼ Remediation: STILL_EXPLOITABLE
    patch swapped shell=True for sh -c -- "$input" — still shell injection
    manual review required

H002  CWE-78 command_injection  critical  CONFIRMED
  function: list_directory (line 16)
  evidence: sandbox executed `; cat /etc/passwd` via f-string interpolation
  ▼ Remediation: UNVERIFIABLE
    sandbox couldn't decisively replay; manual review
```

Every CONFIRMED row has a kernel-level event trace. Every Remediation row has a generated patch + a sandbox-replay verdict on whether the patch actually closed the bug. Verbose output, JSON, and SARIF for GitHub Code Scanning all available via `--output`.

## Architecture

The composition is the engineering. Each layer is structurally best-in-class for one job; skipping work the other layers can absorb is what makes the pipeline both fast and verified.

- **Deterministic preprocessing** — hash dedup, AST parsing, deobfuscation, known-malware hash lookup. Free, byte-deterministic. Argus never burns a token on what a hash match can decide.
- **Semantic LLM** — reads intent, designs exploits, writes patches, judges sandbox traces. The only layer that can answer *"is this function supposed to take untrusted input?"* Two role-based tiers: a **scan tier** (default Sonnet 4.6 — triage + L1 + DAST probe inference) and a **deep-reasoning tier** (default Opus 4.6 — borderline escalation, adversarial reasoning, adjudication). Both defaults are overridable to *any* model in the Anthropic ecosystem — bump to a newer Opus, run Opus in both slots for a high-precision audit, or point either tier at a future Anthropic-API-compatible model — via `--scan-model` / `--reasoning-model`. No code edits, no lock-in.
- **Runtime sandbox** (Firecracker microVM + kernel-syscall observation via bpftrace) — the ground-truth oracle. The only layer that can prove an exploit actually fired or a patch actually closed the hole.

Pure-SAST tools have no runtime. Classic DAST tools have no semantic reasoning. Pattern-based remediation tools generate patches without verification. Argus closes all three gaps in one pipeline.

```
File
  ↓
Preprocessing             (deterministic, free — hash, deobfuscation, attack-vector flags)
  ↓
Triage                    (Sonnet 4.6 default — CLEAN / LOW / HIGH)
  ↓
L1 analysis               (Sonnet 4.6 → Opus 4.6 escalation on borderline)
  ↓
[default ON]
Finding Validation        (each L1 finding re-run in Firecracker microVM)
  ↓
Remediation               (auto-patch + sandbox replay against original exploit)
  ↓
[opt-in]
Exploit Discovery         (hunts for exploits L1 didn't see — `--enable-runtime-probe`)
Behavioral Profiling      (runtime behavior capture — `--enable-phase-3-discovery`)
Adversarial Reasoning     (model-designed hypotheses anchored on the profile — `--enable-phase-3-loop`)
  ↓
FP-defense oracle stack   (structured assertions / downstream-cap / syscall-sink)
Engine guards             (intent cap, findings-floor invariant)
  ↓
Final verdict
```

Default cost on a typical scan: **$0.10–$0.40 per suspicious file**. Opt-in zero-day hunting adds ~$0.30–$1.50/file. Cap with `--max-cost`.

## Coverage

**Static + LLM cascade** (every supported format):

- **Code:** Python · JavaScript · TypeScript · shell · Java bytecode (`.class`, `.jar`)
- **Supply-chain manifests:** `package.json` · `requirements.txt` · `Cargo.lock` · `go.mod` · `Gemfile` · `composer.json` · `pyproject.toml` · `Pipfile` · Dockerfile · Makefile · `.npmrc` · `.pypirc`
- **AI-agent configs:** `CLAUDE.md` · `mcp.json` · `.cursorrules` · `claude_desktop_config.json` · `AGENTS.md` · `devcontainer.json`
- **Doc / web attack surface:** Markdown · RST · AsciiDoc · HTML · SVG · XML

**Sandbox (Validation + Remediation):** Python · JS/TS · shell · Java bytecode. Non-executable formats stay cascade-only.

**Dynamic MCP server scanning** (`argus mcp`): black-box probing of live Model Context Protocol servers over stdio (sandboxed) or HTTP / SSE — SSRF (incl. cloud IMDS + alt IP encodings), redirect-to-internal, fail-open validation, and authorization bypass. Findings come from runtime evidence (sandbox network captures or out-of-band callbacks), not static guesses. See [docs/mcp.md](docs/mcp.md).

**Roadmap:** Go · Rust · .NET.

## Per-finding statuses

| Status | Meaning |
|---|---|
| `CONFIRMED` | Sandbox observed the exploit firing. Patch generated by default. |
| `BLOCKED` | Attack was tested; the file's own code defended (sanitization, escaping). |
| `UNREACHED` | Attack was tested; the code path is genuinely unreachable. |
| `NOT_TESTED` | Sandbox couldn't execute the test. Sub-reason: `infra_stub` / `inconclusive` / `not_planned`. |
| `SUPPRESSED` | FP-defense oracle (structured assertion / downstream-cap / syscall-sink) refuted the static match. Audit trail preserved. |

For CONFIRMED findings, the Remediation block adds a post-patch status:

| Post-patch | Meaning |
|---|---|
| `NEUTRALIZED` | Sandbox replay shows the exploit no longer fires. Ship the patch. |
| `STILL_EXPLOITABLE` | Patch was insufficient. Sandbox still observes the original exploit firing. |
| `UNVERIFIABLE` | Sandbox couldn't decisively replay. Manual review. |

## Enterprise invariants

- **BYOK.** You pay Anthropic + Fly directly. Argus collects nothing.
- **Zero telemetry.** Cascade-only mode: nothing leaves your machine. DAST mode: file content goes only to a Fly.io app *you own and control* — never to Argus-operated infrastructure.
- **Hardware isolation.** Detonation happens in Firecracker microVMs (KVM hardware virtualization), ephemeral per-run, strict egress control.
- **Local execution.** Self-contained pipeline; no SaaS dependency.

## CLI essentials

```bash
# Skip patch generation (compliance / CI / read-only audits)
argus scan-repo . --no-enable-remediation

# Add zero-day hunting on top of the default cascade
argus scan path/to/file.py \
  --enable-runtime-probe \
  --enable-phase-3-discovery \
  --enable-phase-3-loop

# CI mode — only files changed vs main, SARIF for GitHub Code Scanning
argus scan-repo . --diff origin/main --output sarif --output-file argus.sarif

# Cap per-file API spend
argus scan path/to/file.py --max-cost 0.50

# Swap the model on either tier — defaults are Sonnet 4.6 (scan) + Opus 4.6 (reasoning).
# Pass any Anthropic-ecosystem model_id; same id on both = high-precision audit mode.
argus scan path/to/file.py --scan-model claude-opus-4-8 --reasoning-model claude-opus-4-8

# Scan a live MCP server (no API key needed — probes are deterministic)
argus mcp enumerate --stdio "python -m my_mcp_server"     # recon only
argus mcp scan --stdio "python3 -m my_mcp_server" --sandbox-pip my-mcp-pkg   # active probes; server runs in the Firecracker sandbox (needs Fly DAST config)
argus mcp scan --url https://mcp.example.com/mcp --authorized   # remote (consent-gated)
```

Full reference: `argus scan --help`, `argus scan-repo --help`, `argus install --help`, `argus mcp enumerate --help`.

## Documentation

| Topic | Page |
|---|---|
| Install + first scan | [docs/install.md](docs/install.md) |
| MCP server scanning | [docs/mcp.md](docs/mcp.md) |
| DAST sandbox setup (Fly.io) | [docs/dast-setup.md](docs/dast-setup.md) |
| Architecture deep dive | [docs/architecture.md](docs/architecture.md) |
| Cost guide | [docs/cost-guide.md](docs/cost-guide.md) |
| API key sourcing | [docs/api-keys.md](docs/api-keys.md) |
| Roadmap | [ROADMAP.md](ROADMAP.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Security disclosures | [SECURITY.md](SECURITY.md) |

## License

[Apache License 2.0](LICENSE).
