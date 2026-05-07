# Roadmap

Argus is shipped — and there's a clear set of things we're building next. This page captures the **themes**; concrete tasks live in [GitHub Issues](https://github.com/dshochat/Argus_Scanner/issues) tagged `roadmap`.

## v1.2 themes

We're investing in three directions for the next minor release.

### 1. Broader DAST language coverage

Today: Python, JavaScript / TypeScript, bash, Java bytecode. The DAST sandbox runtime needs each language pre-installed in the image. Next:

- **Go** — Go-module supply-chain attack surface
- **Rust** — `Cargo.toml` build scripts + procedural macros
- **.NET** — `*.csproj` PreBuildEvent + Roslyn analyzer hooks

Each new language unlocks runtime DAST validation for that ecosystem's malware patterns.

### 2. Higher-confidence per-finding validation

Today: ~22% of L1 findings reach `CONFIRMED` via DAST; ~77% land in `NOT_TESTED` because the validator's rejection rationale couldn't be classified as `BLOCKED` or `UNREACHED`. Next: replace the heuristic with **structured rejection categories** emitted directly by the validator (`SANITIZATION` / `UNREACHABILITY` / `INSUFFICIENT_EVIDENCE` / `SCOPE_INVALID`). Expected impact: roughly half of current `NOT_TESTED` entries should resolve to `BLOCKED` or `UNREACHED`, materially shrinking the ambiguity bucket.

### 3. Repo-scan parity with single-file scan

Today `argus scan-repo` walks files sequentially. Next:

- **Parallelism** — async worker pool, respecting per-file cost caps + aggregate run cap
- **`--from-pr <num>`** — shortcut that uses `gh pr diff` to scope the scan to changed files in a GitHub PR
- **Richer file-type filters** — per-language hints, custom config via `argus.toml`

Brings `scan-repo` up to the polish level of `argus scan`.

## How to influence the roadmap

- **Open an issue** describing your use case — even before any code work starts
- Pick up a [`good first issue`](https://github.com/dshochat/Argus_Scanner/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) if you want to ship something concrete
- For non-trivial work, **start a discussion** before opening a PR so we can align on shape

## What's explicitly NOT planned

To set expectations, these are things we've considered and deferred:

- **Non-Anthropic / non-Google model providers** — defer until benchmark mode resurrects in v2
- **Hosted SaaS tier** — reconsidered post-meaningful-traction; until then, pure FOSS / BYOK
- **Kernel / embedded C / C++ scope** — out of the AI-native code-security niche we target
- **GUI / web dashboard** — Argus is a CLI; integration with existing dashboards (GitHub Code Scanning via SARIF, etc.) is the path
