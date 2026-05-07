# Changelog

All notable changes to Argus are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-05-06 — first public release

**An AI-native code security scanner that proves exploitability at runtime.**

Argus combines a cost-graduated LLM cascade (Gemini Flash-Lite triage → Sonnet 4.6 → Opus 4.6) with a Firecracker-microVM sandbox tier that *executes* suspect code and observes what it actually does. Static-analysis findings get promoted to **CONFIRMED** only when the sandbox captures concrete runtime evidence — a network call, a file write, a process spawn. Findings the file's own defenses block are marked **BLOCKED**; unreachable code paths are **UNREACHED**.

Open source under Apache 2.0. BYOK — Argus collects nothing.

## Why v1.1.0 is the launch number

| Metric | Argus (no DAST) | Argus (+DAST) | Raw Opus 4.6 |
|---|---|---|---|
| Verdict-exact (23 files) | **91.3%** | **91.3%** | 78.3% |
| Mean verdict-distance (lower better) | **0.087** | **0.087** | 0.217 |
| CWE F1 (n=5 rich oracles) | **0.297** | **0.297** | 0.180 |
| Capability F1 (n=5) | **0.771** | **0.771** | 0.720 |
| Total cost | **$4.20** | $7.22 | $7.56 |

**+13.0pp verdict-exact lift over single-call Opus 4.6**, on the regression suite. Argus +DAST matches no-DAST verdict accuracy AND adds 25 runtime-confirmed findings + 1 BLOCKED that no other open-source scanner produces.

Per-finding sandbox grounding (114 L1 findings examined across 22 DAST-validated files):

```
CONFIRMED   ████░░░░░░░░░░░░░░░░  21.9%  (25)  runtime-confirmed exploitable
BLOCKED     ░░░░░░░░░░░░░░░░░░░░   0.9%  (1)   defended in-code
UNREACHED   ░░░░░░░░░░░░░░░░░░░░   0.0%  (0)
NOT_TESTED  ███████████████░░░░░  77.2%  (88)  primarily static-only hypotheses
```

Full report: [`bench_results/v1_1_launch/launch_report.md`](bench_results/v1_1_launch/launch_report.md).

## Headline features

### `argus scan` — single-file scan with cascade + DAST

```bash
pip install argus-ai-scanner
argus scan suspicious_package.py
```

Cascade auto-routes: clean files cost ~$0.0001 (triage only); suspicious files run the full Sonnet 4.6 analysis (~$0.07); confirmed-malicious files trigger DAST sandbox validation that surfaces concrete runtime evidence per finding.

### `argus scan-repo` — whole-repo scanning

```bash
cd ~/work/my-project
argus scan-repo . --max-cost 5.00
argus scan-repo . --diff origin/main --output sarif --output-file findings.sarif
```

Walks a directory tree, applies file-type and `.gitignore` filters, dispatches every supported file through the cascade, aggregates results with cost budgeting. SARIF v2.1.0 output ready for upload to GitHub Code Scanning. Use `--diff <ref>` for PR / CI mode.

**For private repos**: clone locally first using your existing git credentials, then point Argus at the local path. Argus reads files from disk — no GitHub API integration required.

### Multi-language DAST sandbox (Python + JavaScript/TypeScript + bash + Java bytecode)

The DAST tier runs in your own ephemeral Firecracker microVM (Fly.io managed). File extensions dispatch to the right runtime — Node `require()` for `.js`/`.ts`, `python3` for `.py`/`.pth`, `java -cp` for `.class`/`.jar`, `bash` for `.sh`. Setup: [`docs/dast-setup.md`](docs/dast-setup.md).

### AI-coding-agent attack surface

Argus's file-type allowlist explicitly recognizes:
- `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `WINDSURF.md`, `GEMINI.md`, `AIDER.md`, `.continuerules`, `.copilot-instructions.md`
- `mcp.json`, `.mcp.json`, `claude_desktop_config.json` (Model Context Protocol servers — a malicious entry registers a hostile tool that any agent in the workspace then sees)
- `devcontainer.json`, `manifest.json`, `app.json`, `.tabnine.json`
- All `.md`, `.mdx`, `.markdown`, `.rst`, `.adoc` documentation that AI agents consume

These are prime vectors for prompt injection, zero-width / homoglyph attacks, and malicious-instruction-set attacks against coding agents — categories traditional scanners miss entirely.

### Hard cost guardrails

```bash
argus scan suspicious_package.py --max-cost 0.50
argus scan-repo . --max-cost 5.00
```

Aborts mid-scan when cumulative API spend exceeds your declared budget. No surprise bills — the bill comes from Anthropic and Google directly, on a meter you control.

## Privacy

Files you scan never leave your machine in cascade-only mode. With DAST enabled, file content is shipped to **your own** Fly.io microVM via the Fly machines API — nothing is routed through Argus-operated infrastructure. The CLI does not telemeter; there's no analytics or usage reporting.

## Install

```bash
# PyPI
pip install argus-ai-scanner

# Or via uv (recommended for development)
git clone https://github.com/dshochat/Argus_Scanner.git
cd Argus_Scanner
uv sync --extra dev
```

Required: Python 3.12+, an Anthropic API key, a Google AI Studio key. DAST sandbox tier is optional and requires a Fly.io account.

## What's next

- **v1.2** scope: `gh`-based PR shortcut (`--from-pr <num>`), per-finding cost cap with graceful degradation, structured DAST validator rejection categories (replaces today's regex heuristic), Go / Rust / .NET DAST support.
- **Active backlog**: tracked in [GitHub Issues](https://github.com/dshochat/Argus_Scanner/issues).

## License

Apache License 2.0 — [`LICENSE`](LICENSE).
