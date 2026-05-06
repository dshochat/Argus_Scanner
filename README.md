# Argus

**An AI-native code security scanner that proves exploitability at runtime.**

Argus combines a cost-graduated LLM cascade (Gemini Flash-Lite → Sonnet 4.6 → Opus 4.6) with a sandbox tier that *executes* suspect code in a Firecracker microVM and observes what it actually does. Static-analysis findings get promoted to **CONFIRMED** only when the sandbox captures concrete runtime evidence — a network call, a file write, a process spawn. Findings that cannot be triggered are marked **UNREACHED**; findings the file's own defenses block are **BLOCKED**. No more "the LLM said it might be malicious."

Open source, Apache 2.0, BYOK. You pay Anthropic and Google directly — Argus collects nothing.

---

## What makes it different

Most scanners stop at "this code matches a vulnerability pattern." Argus runs the code, watches what it does, and reports per-finding outcomes:

| Status | Meaning |
|---|---|
| `CONFIRMED` | The sandbox observed the exploit firing at runtime. PoC + event trace are surfaced with the finding. |
| `BLOCKED` | The attack was tested; the file's own code defended against it (sanitization, escaping, allowlist, etc.). |
| `UNREACHED` | The attack was tested; the code path is genuinely unreachable. |
| `NOT_TESTED` | Sandbox couldn't execute the test (with a sub-reason: `infra_stub` / `inconclusive` / `not_planned`). |

A `CONFIRMED` finding looks like this in `argus scan` output:

```json
{
  "cwe": "CWE-200",
  "type": "data_exfiltration",
  "severity": "critical",
  "status": "CONFIRMED",
  "confidence": 1.0,
  "runtime_evidence": "Mock HTTP server at 127.0.0.1:8000 captured POST body containing
    'FAKE_PRIVATE_KEY_CONTENT' and 'ssh-rsa AAAAFAKEKEY user@host'. The malware decoded
    its base64 payload (process_exit step=0) and POSTed the contents of ~/.ssh/ to the
    rewritten C2 endpoint, exactly as L1's hypothesis predicted.",
  "proof_of_concept": "On any Unix host with SSH keys present, execution sends the full
    contents of ~/.ssh/ to the remote C2 server over HTTPS."
}
```

This is the moat. Static scanners report *suspicion*; Argus reports *what the code actually did*.

---

## How the cascade keeps it cheap

Most files in a real codebase are clean. Argus is built around that observation: spend $0.0001 to dispatch a clean file in 1 second, $0.07 to deep-analyze a suspicious one, and only invoke the sandbox tier on the small subset of files where runtime confirmation actually matters.

```
File
  ↓
[$0]  Preprocessing               hash, deobfuscation, deps, attack-vector flags
  ↓
[Gemini Flash-Lite]  Triage       CLEAN | LOW | HIGH         ~$0.0001/file
  ↓
  ├─ CLEAN → return
  ├─ LOW   → Gemini Flash         combined analysis           ~$0.02/file
  └─ HIGH  → Sonnet 4.6           combined analysis           ~$0.07/file (default)
                ↓ borderline / high-stakes
              Opus 4.6            deep analysis                ~$0.15/file (~20% of HIGH)
  ↓
[N=3 Sonnet ensemble]             borderline-uncertainty path
  ↓
[DAST sandbox]                    Sonnet orchestrator + Firecracker microVM
                                   (minimal / networked / ml_tools images)
                                   ↓ inconclusive after 2 iterations
                                  Opus iter-3 escalation
  ↓
[Engine guard]                    DAST never lowers L1's verdict without
                                   sandbox-grounded refutation
```

### Cost projection per 100 files

| Stage | Calls | API spend |
|---|---|---|
| Triage (Flash-Lite) | 100 | $0.10 |
| LOW analysis (Flash, ~50 files) | 50 | $1.00 |
| HIGH analysis (Sonnet, ~15 files) | 15 | $1.05 |
| HIGH + Opus escalation (~5 files) | 5 | $1.00 |
| Borderline ensemble (Opus, ~3 files) | 3 | $0.60 |
| DAST verification (~3 files) | 3 | $0.90 |
| **Total** | | **~$4.65** |

Hard cost caps (`--max-cost <USD>` per file, or `ScanConfig.max_cost_per_file_usd`) abort scans that exceed your declared budget. You'll never get a surprise bill from Argus — the bill comes from your API providers, on a meter you control.

---

## Quick start

```bash
pip install argus-ai-scanner
export ANTHROPIC_API_KEY=...
export GEMINI_API_KEY=...
argus scan path/to/your/file.py
```

Or with Docker:

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY -e GEMINI_API_KEY \
  -v "$PWD:/workspace" \
  ghcr.io/dshochat/argus_scanner:latest \
  scan-repo /workspace
```

For development:

```bash
git clone git@github.com:dshochat/Argus_Scanner.git
cd Argus_Scanner
uv sync --extra dev
cp .env.example .env       # add ANTHROPIC_API_KEY + GEMINI_API_KEY
uv run argus scan path/to/your/file.py
```

Requirements:
- Python 3.12+
- An Anthropic API key — [console.anthropic.com](https://console.anthropic.com/settings/keys)
- A Google AI Studio key — [aistudio.google.com](https://aistudio.google.com/app/apikey)
- Optional: a Fly.io account if you want the DAST sandbox tier ([Fly setup runbook](docs/dast-setup.md))

### Single-file scan

```bash
# Default: cascade + DAST on confirmed-malicious verdicts
uv run argus scan suspicious_package.py

# Tunable DAST coverage — also DAST suspicious files (~30-50% more API spend)
uv run argus scan suspicious_package.py \
  --dast-trigger-verdicts suspicious,malicious,critical_malicious

# Strictest budget mode — DAST only the highest-severity verdict tier
uv run argus scan suspicious_package.py --dast-trigger-verdicts critical_malicious

# Hard cost cap, any verdict
uv run argus scan suspicious_package.py --max-cost 0.50

# Discovery mode — proactive payload sweep for CWEs L1 missed (+~$0.25/file)
uv run argus scan suspicious_package.py --enable-discovery

# Skip DAST entirely (no Fly setup required; cascade-only verdicts)
uv run argus scan suspicious_package.py --no-dast
```

### Repo scan (whole project)

`argus scan-repo PATH` walks a directory tree, applies file-type and `.gitignore` filters, and dispatches every supported file through the cascade. **For private repos, clone locally first using your existing git credentials, then point Argus at the local path** — Argus reads files from disk, not via the GitHub API.

```bash
# Whole project, current directory
cd ~/work/my-project
uv run argus scan-repo .

# PR / CI mode — only files changed vs main
uv run argus scan-repo . --diff origin/main

# CI with budget + SARIF output for GitHub Code Scanning
uv run argus scan-repo . \
  --diff origin/main \
  --max-cost 5.00 \
  --output sarif \
  --output-file findings.sarif

# Add a custom exclude pattern on top of .gitignore
uv run argus scan-repo . --exclude "vendor/**" --exclude "**/*.generated.*"
```

**What gets scanned:** the file-type allowlist covers Python, JavaScript / TypeScript, shell, Java bytecode, Markdown / RST / AsciiDoc (AI-injection surface), HTML / SVG / XML (XSS / XXE), and supply-chain manifests (`package.json`, `requirements.txt`, `Cargo.lock`, `go.mod`, `Gemfile`, `composer.json`, etc.). AI-agent config sentinels (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `mcp.json`, `claude_desktop_config.json`, `devcontainer.json`, …) are explicitly recognized — these are the prime vectors for malicious-instructions-in-config attacks against coding agents. Always-ignored: `.git`, `node_modules`, `__pycache__`, `.venv`, build dirs, etc.

**Output formats:** `--output markdown` (default; human summary) / `json` (full per-file results) / `sarif` (SARIF v2.1.0 JSON, uploadable to GitHub Code Scanning).

---

## DAST sandbox tier

DAST is **optional**. Without it, Argus ships verdicts using the L1 cascade alone. With it, you get per-finding `CONFIRMED` / `BLOCKED` / `UNREACHED` evidence backed by real runtime traces.

When enabled, every DAST plan runs in an ephemeral Firecracker microVM (Fly.io managed). The orchestrator:

1. Reads L1's hypotheses about *how* the file might be exploitable
2. Generates a concrete plan — sandbox commands, expected oracle, image hint
3. Submits to the microVM, which runs the file with file-content materialized at `/workspace/<basename>`, captures network calls via DNS hijack, and emits a structured event stream
4. Reads back the events, scores each hypothesis as `CONFIRMED` / `BLOCKED` / `UNREACHED` / `NOT_TESTED`
5. Surfaces the captured evidence (`runtime_evidence` field per finding)

Three sandbox images cover most workloads:

| Image | Contents | Use cases |
|---|---|---|
| `minimal-v1` | Python 3.13 + Node.js + npm + JRE + bash + curl | Pickle exploits, file I/O, subprocess, basic crypto |
| `networked-v1` | minimal + curl / wget / nc / dig / openssl | Exfiltration confirmation via real DNS / network captures |
| `ml_tools-v1` | networked + torch CPU + transformers + safetensors | Malicious model loaders, pickled `__reduce__` payloads |

Multi-language coverage today: Python, JavaScript / TypeScript, bash, Java bytecode. Roadmap: Go, Rust, Java source (compile required), .NET.

Full setup: [docs/dast-setup.md](docs/dast-setup.md).

---

## Privacy

Files you scan never leave your machine in two-tier (no DAST) mode. With DAST enabled, file content is shipped (gzip + base64) to **your own** Fly app over the Fly machines API — nothing is routed through any Argus-operated infrastructure.

Argus has no telemetry, no opt-in analytics, and no usage reporting. The CLI does not phone home.

---

## Architecture invariants

The non-negotiable design rules — break these in a PR and expect a long review:

1. **Preprocessing is deterministic and free.** No model calls in `preprocessing/`. If you're tempted, the change belongs in `analysis/`.
2. **The cascade short-circuits cheap files cheap.** A clean file costs $0.0001 (triage only). Don't add expensive defaults.
3. **All runners are injectable.** `scan_file(triage_runner=, sonnet_runner=, opus_runner=, dast_runner=)`. The engine never hard-codes provider calls — that's how unit tests run with no API spend.
4. **DAST never silently lowers an L1 verdict.** A `malicious` → `suspicious` downgrade only fires when *every* L1 finding is sandbox-grounded as `BLOCKED` or `UNREACHED`. Without that, L1's verdict stands and `dast_keep_l1` is recorded.
5. **Cost guardrails enforced before any user-facing release.** `max_cost_per_file_usd` aborts mid-scan rather than overrun.

---

## Documentation

| Topic | Page |
|---|---|
| Install + first scan | [docs/install.md](docs/install.md) |
| API key sourcing | [docs/api-keys.md](docs/api-keys.md) |
| Cascade architecture | [docs/architecture.md](docs/architecture.md) |
| Cost guide + budget knobs | [docs/cost-guide.md](docs/cost-guide.md) |
| DAST sandbox setup (Fly.io) | [docs/dast-setup.md](docs/dast-setup.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Security disclosures | [SECURITY.md](SECURITY.md) |

---

## Development

```bash
uv sync --extra dev
uv run pytest tests/unit -v           # always; no API spend
uv run ruff check . && uv run ruff format .
uv run mypy --strict .
uv run pytest tests/integration -v    # before runner / engine changes; spends API
```

Argus is Python 3.12+, mypy `--strict`, ruff for lint and format. Pydantic v2 for cross-boundary structures. `structlog` for logging — never `print()` outside the CLI. Tests are split into unit (mocked, mandatory) and integration (live API, optional + manual). CI runs unit + lint + types on every PR; integration tests stay local because nobody wants surprise API bills on their fork.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full PR process.

---

## Origin

Argus is a new project that lifts code from two prior codebases authored by the same team:

- **CNAPPPOC** — scanner core, prompts, multi-provider adapters, verdict adjudicator
- **echoDefense** — preprocessing pipeline, DAST sandbox + orchestrator, methodology runner

Full per-file lineage: [NOTICE.md](NOTICE.md).

---

## License

[Apache License 2.0](LICENSE).

Copyright © 2026 Dudy Shochat and contributors.
