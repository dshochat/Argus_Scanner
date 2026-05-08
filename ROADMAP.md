# Roadmap

Argus is shipped — and there's a clear set of things we're building next. This page captures the **themes**; concrete tasks live in [GitHub Issues](https://github.com/dshochat/Argus_Scanner/issues) tagged `roadmap`.

## Shipped in v1.2 (2026-05-08)

- **Phase C — fix-and-verify.** Generates patched source for confirmed
  findings, replays iter-1 exploit plans against the patched code in the
  sandbox, and reports per-finding `NEUTRALIZED` / `STILL_EXPLOITABLE` /
  `UNVERIFIABLE`. End-to-end validated: 5 of 5 confirmed exploits
  neutralized across two adversarial fixtures. See [README.md](README.md#phase-c--fix-and-verify-v12)
  and [CHANGELOG.md](CHANGELOG.md#120--2026-05-08--fix-and-verify).
- **Severity-driven iter-erosion guard.** Replaces v1.1's binary
  all-grounded rule with a graded rule: max severity of remaining
  uncertain findings bounds the maximum safe downgrade. Closes the gap
  where DAST proposed a correct downgrade and the engine refused.

## v1.3 themes

### 1. Parallelize DAST sandbox calls within an iteration

Today the orchestrator submits sandbox plans **sequentially** within a Phase A iteration. Each Firecracker microVM cold-start is ~30s; 5 plans run one-after-another adds ~150s per iteration. Switching to `asyncio.gather()` over the per-plan submits would parallelize the cold-start cost. Cuts wall-clock per file by 30-60% on DAST runs without changing correctness (plans don't depend on each other within a single iteration). Affects `dast/orchestrator.py` Phase A loop + `dast/sandbox/client.py` rate limiting if needed.

### 2. Broader DAST language coverage

Today: Python, JavaScript / TypeScript, bash, Java bytecode. The DAST sandbox runtime needs each language pre-installed in the image. Next:

- **Go** — Go-module supply-chain attack surface
- **Rust** — `Cargo.toml` build scripts + procedural macros
- **.NET** — `*.csproj` PreBuildEvent + Roslyn analyzer hooks

Each new language unlocks runtime DAST validation for that ecosystem's malware patterns.

### 3. Higher-confidence per-finding validation

Today: ~22% of L1 findings reach `CONFIRMED` via DAST; ~77% land in `NOT_TESTED` because the validator's rejection rationale couldn't be classified as `BLOCKED` or `UNREACHED`. Next: replace the heuristic with **structured rejection categories** emitted directly by the validator (`SANITIZATION` / `UNREACHABILITY` / `INSUFFICIENT_EVIDENCE` / `SCOPE_INVALID`). Expected impact: roughly half of current `NOT_TESTED` entries should resolve to `BLOCKED` or `UNREACHED`, materially shrinking the ambiguity bucket.

### 4. Repo-scan parity with single-file scan

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
