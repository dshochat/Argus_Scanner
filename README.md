# Argus

**An AI-native code security scanner (Semantic Deep Analysis) <mark>that proves exploitability at runtime</mark>.**

Argus combines a cost-graduated LLM cascade (Gemini Flash-Lite → Sonnet 4.6 → Opus 4.6) with a sandbox tier that *executes* suspect code in a Firecracker microVM and observes what it actually does. Static-analysis findings get promoted to **CONFIRMED** only when the sandbox captures concrete runtime evidence — a network call, a file write, a process spawn. Findings that cannot be triggered are marked **UNREACHED**; findings the file's own defenses block are **BLOCKED**. No more "the LLM said it might be malicious."

Open source, Apache 2.0, BYOK. You pay your providers directly — Anthropic + Google for the cascade, Fly.io for the optional DAST sandbox. Argus collects nothing.

---

## Benchmark — Argus vs frontier single-call scanners

Scored against a ground-truth oracle derived from external security research and a multi-vendor LLM consensus (majority agreement):

```
                       Verdict-exact (higher = better)
Argus (cascade + DAST) ████████████████████  91.3%
Gemini 3.1 Pro         █████████████████░░░  82.6%
Grok 4.3               █████████████████░░░  82.6%
Opus 4.6               █████████████████░░░  78.3%
GPT 5.4                ████████████████░░░░  73.9%
```

Argus is **+13.0pp more accurate than Opus 4.6** and **+17.4pp more accurate than GPT-5.4**. On the rich-oracle subset Argus also leads on finding quality: **CWE F1 0.297 vs Opus 0.180** (+65% lift) and **capability F1 0.771 vs Opus 0.720**. Mean verdict-distance: **0.087 vs Opus 0.217**.

Methodology + per-file breakdown: [`bench_results/v1_1_launch/launch_report.md`](bench_results/v1_1_launch/launch_report.md). Re-run is one command: `python -m methodology.run_phase_a_report`.

---

## What makes it different

Most scanners stop at "this code matches a vulnerability pattern." Argus runs the code, watches what it does, and reports per-finding outcomes:

| Status | Meaning |
|---|---|
| `CONFIRMED` | The sandbox observed the exploit firing at runtime. PoC + event trace are surfaced with the finding. |
| `BLOCKED` | The attack was tested; the file's own code defended against it (sanitization, escaping, allowlist, etc.). |
| `UNREACHED` | The attack was tested; the code path is genuinely unreachable. |
| `NOT_TESTED` | Sandbox couldn't execute the test (with a sub-reason: `infra_stub` / `inconclusive` / `not_planned`). |

### vs. other approaches

| Approach | Output | False-positive burden | Evidence type |
|---|---|---|---|
| Pattern-match scanner (regex / AST) | Syntactic match | High | None |
| Single frontier LLM (single-call) | Probabilistic opinion (semantic) | Medium-high | LLM reasoning |
| **Argus** | **Runtime-verified verdict** | **Low** | **Sandbox traces** |

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

On the regression suite, Argus's DAST tier produced **25 CONFIRMED exploits + 1 BLOCKED** with concrete sandbox-captured artefacts — network calls, exfil POST bodies, process traces. By verifying which findings are **actually exploitable** versus mere pattern matches, Argus minimizes the false-positive flood that drowns security teams using static-only scanners. Unlike single-call LLMs that must guess exploitability, Argus's DAST tier tests it — turning many "maybe" findings into proven CONFIRMED exploits or clean UNREACHED / BLOCKED resolutions.

> **This is Argus's moat.**
> Static and single-LLM scanners report *suspicion*.
> Argus reports **what the code actually did** — with concrete evidence, or clear proof it didn't.

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

## What you get back

Argus produces three output formats — markdown for terminals, JSON for pipelines and tooling, SARIF v2.1.0 for GitHub Code Scanning. All three carry the same evidence, shaped for different consumers.

### Markdown summary (default)

Real output from `uv run argus scan samples/regression_v1/audit_log_compression.py --no-dast`:

```markdown
# audit_log_compression.py

**Verdict:** `critical_malicious`
**Risk:** 95/100 (critical)
**Language:** python
**Triage:** HIGH — The code contains an 'exec()' call that executes decompressed
base64-encoded data from a hardcoded string (_REGRESSION_FIXTURE), which
constitutes an arbitrary code execution pattern.

**Cost:** $0.4168  **Time:** 198811 ms

**Scan path:** preprocessing → high_stakes=False → triage:HIGH → analysis:sonnet_default → escalate_to_opus

## Vulnerabilities (3)

- **code_injection** (severity: critical, line 171)
  - An opaque, compressed, base64-encoded blob is decompressed and executed via
    `exec()`. The true contents of `_REGRESSION_FIXTURE` are hidden from static
    inspection. This is the canonical pattern for embedding obfuscated malicious
    payloads in otherwise-legitimate-looking utility code.
  - **Fix:** Remove the `exec()` call entirely. If a regression fixture is
    genuinely needed, store it as a plain-text Python module in the test
    directory and import it normally.
- **insecure_deserialization** (severity: critical, line 144)
  - A large opaque binary blob is embedded in source code with comments
    explicitly discouraging modification or inspection ("DO NOT modify the
    fixture literal below"). The blob's actual content is unverifiable without
    runtime decompression, providing ideal cover for arbitrary payload delivery.
  - **Fix:** Remove the embedded blob. Any test data should be stored as
    readable, version-controlled fixtures in a dedicated test-data directory.
- **prompt_injection** (severity: high, line 136)
  - Comments surrounding the obfuscated payload employ social engineering to
    deter code review. Phrases like "DO NOT modify," the elaborate backstory
    about "regression baselines" and "testing scaffolding," and the framing of
    `exec()` as routine maintenance are designed to make human and automated
    reviewers accept the hidden payload without inspection.
  - **Fix:** Remove the social-engineering comments and the obfuscated code
    they protect.

## Attack chains (3)

- Attacker invokes CLI with --regenerate-baseline flag (no privilege required
  beyond file access)
  - _regenerate_baseline() is called unconditionally
  - base64.b64decode(_REGRESSION_FIXTURE) decodes the embedded opaque blob
  - zlib.decompress() expands blob with no size cap
  - exec() executes the resulting Python code in the caller's process with full
    interpreter access
  - Payload may exfiltrate audit records, establish persistence, or pivot to
    connected systems
- ... (2 more chains: scheduled-job and path-traversal exfil)

## Behavioral summary

- Sensitivity: **critical**
- Purpose: Ostensibly a CSV audit-log compression utility, but contains an
  obfuscated Python payload executed via exec(). The legitimate compression
  functionality appears to serve as camouflage for the hidden payload.
```

### JSON output (full per-finding record)

Run with `--output json` for the full structured record. Each finding carries
the actual offending code, CWE code, model confidence, attacker data-flow
trace, and a concrete proof-of-concept payload:

```json
{
  "file_name": "audit_log_compression.py",
  "predicted_verdict": "critical_malicious",
  "cost_usd": 0.508,
  "duration_ms": 253958,
  "scan_path": [
    "preprocessing",
    "high_stakes=False",
    "triage:HIGH",
    "analysis:sonnet_default",
    "escalate_to_opus"
  ],
  "dast_attempted": false,
  "n_vulnerabilities": 3,
  "vulnerabilities": [
    {
      "type": "code_injection",
      "severity": "critical",
      "line": 164,
      "code": "exec(zlib.decompress(base64.b64decode(_REGRESSION_FIXTURE)))",
      "cwe": "CWE-94",
      "confidence": 0.97,
      "explanation": "Arbitrary Python code hidden inside a zlib-compressed, base64-encoded blob is executed via `exec()`. The payload contents cannot be audited by reading the source, and the surrounding comments actively misrepresent the behavior as a benign 'test harness'. This is the canonical supply-chain obfuscated-payload pattern.",
      "data_flow_trace": "_REGRESSION_FIXTURE (opaque blob) → base64.b64decode → zlib.decompress → exec() (arbitrary code execution)",
      "proof_of_concept": "python -m auditlog.compression --in /dev/null --out /dev/null --regenerate-baseline",
      "fix": "Remove the `exec()` call and the opaque blob entirely. If a regression fixture is genuinely needed, store it as readable Python source in a dedicated test module and import it normally."
    }
  ]
}
```

**What's in each finding:**

| Field | What it tells you |
|---|---|
| `type` | Vulnerability class (`code_injection`, `insecure_deserialization`, `prompt_injection`, `path_traversal`, …) |
| `severity` | `critical` / `high` / `medium` / `low` |
| `line` + `code` | Exact location and the offending snippet |
| `cwe` | Standard CWE identifier for tool integration |
| `confidence` | 0.0–1.0 model-reported confidence |
| `explanation` | Why this is a vulnerability, in plain prose |
| `data_flow_trace` | The actual attacker path through the code (input → sinks) |
| `proof_of_concept` | Concrete reproduction command/payload (when applicable) |
| `fix` | Recommended remediation |

**What's in each per-file record:**

| Field | What it tells you |
|---|---|
| `predicted_verdict` | 4-tier: `clean` / `suspicious` / `malicious` / `critical_malicious` |
| `scan_path` | Cascade trace — which stages this file went through (triage → cascade → DAST → adjudicator) |
| `dast_attempted` | Whether the file got sandbox detonation |
| `cost_usd` | Per-file API spend, fully traceable |
| `n_vulnerabilities` | Count of distinct findings |

### DAST evidence (when sandbox detonation runs)

When DAST verification fires, each L1 finding gains a `runtime_evidence` block
with concrete sandbox observations (syscalls, network egress, filesystem writes
captured in a Firecracker microVM). DAST cuts both ways: it confirms real
exploits with evidence and refutes false alarms with proof of non-exploitability.
See [docs/dast-setup.md](docs/dast-setup.md) for the full schema.

### SARIF v2.1.0 (CI integration)

Drop directly into GitHub Code Scanning, GitLab SAST, or any SARIF-aware
pipeline:

```bash
uv run argus scan-repo . --output sarif --output-file findings.sarif
```

Each finding becomes a SARIF result with stable `ruleId` (CWE), severity-mapped
`level`, and an `argus_*` property block preserving the data-flow trace, PoC,
and runtime evidence:

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Argus",
          "informationUri": "https://github.com/dshochat/Argus_Scanner",
          "rules": [
            {
              "id": "CWE-94",
              "shortDescription": { "text": "code_injection" },
              "fullDescription": { "text": "Arbitrary Python code hidden inside a zlib-compressed, base64-encoded blob is executed via `exec()`. ..." },
              "defaultConfiguration": { "level": "error" },
              "properties": { "tags": ["security"], "cwe": "CWE-94" },
              "help": { "text": "Remove the `exec()` call and the opaque blob entirely. ..." }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CWE-94",
          "level": "error",
          "message": { "text": "Arbitrary Python code hidden inside a zlib-compressed, base64-encoded blob is executed via `exec()`. ..." },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": { "uri": "audit_log_compression.py", "uriBaseId": "REPO_ROOT" },
              "region": { "startLine": 164 }
            }
          }],
          "properties": {
            "argus_status": "L1_ONLY",
            "argus_severity": "critical",
            "argus_confidence": 0.97,
            "argus_verdict": "critical_malicious",
            "argus_risk_score": 95,
            "cwe": "CWE-94"
          }
        }
      ]
    }
  ]
}
```

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
| Roadmap | [ROADMAP.md](ROADMAP.md) |
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

## License

[Apache License 2.0](LICENSE).

Copyright © 2026 David Shochat and contributors.
