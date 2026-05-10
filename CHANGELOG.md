# Changelog

All notable changes to Argus are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] — 2026-05-10 — `argus install`: pre-install supply-chain gate

**A new subcommand that scans every wheel/sdist in a pip install's dependency closure BEFORE pip touches site-packages. Blocks day-zero supply-chain malware (litellm-style attacks) at the ingestion boundary.**

### Added

- **`argus install <pkg>`** — stage via `pip download` (no `setup.py` execution), scan every artifact with the full Argus pipeline (cascade harness + DAST Phase A+B if Fly is configured), then either pass to real `pip install` or block with the analysis printed.
- **`-r requirements.txt`** support — scans the entire dependency closure.
- **Wheel-hash verdict cache** at `~/.cache/argus/install/<sha256>.json`. Wheel bytes are immutable on PyPI, so a verdict is permanently valid for that exact artifact. First-run cost is real; subsequent installs are free.
- **Parallel per-artifact scanning** (default 4 concurrent, `--parallel N` override).
- **`--block-on LIST`** — configurable verdict-tier threshold. Default: `malicious,critical_malicious`. Use `suspicious,malicious,critical_malicious` for stricter gating.
- **`--no-dast`** — cascade-only install gate, ~10x faster, ~10x cheaper.
- **`--dry-run`** — scan + report; do NOT call `pip install` at the end. For CI gating without side effects.
- **`--strict-coverage`** — escalate verdict to `suspicious` when Argus could only statically analyze <70% of files in a wheel (rest are typically native binaries: `.so`, `.pyd`, `.dylib`, `.dll`, `.exe`). For security-paranoid users / strict CI gates that prefer to block on uncertainty.
- **Coverage transparency** — every artifact verdict reports `n_files_unscanned` + extension histogram (`{".so": 3, ".pyd": 1}`). A "clean" verdict on a wheel that's 50% native binaries is honestly weaker evidence than a clean verdict on a wheel that's 100% Python — and the report says so.
- **`--max-cost USD`**, **`--cache-dir PATH`**, **`--no-cache`**, **`--pip EXEC`**, **`--output {text,json}`** — round out the CLI surface.
- **Phase C is always disabled on the install path** (defense-in-depth). Remediation for a not-yet-installed package is "don't install", not "patch + replay." The install code overrides `enable_phase_c=False` regardless of the caller's `ScanConfig`.

### Changed

- `scan-repo`'s `SUPPORTED_EXTENSIONS` now includes `.ipynb`, `.pt`, `.bin`, `.safetensors`, `.h5`, `.hdf5`, `.keras`, `.onnx` (the v1.2.1 file-type expansion). Means `argus install` and `argus scan-repo` now scan ML model artifacts inside wheels.

### Threat model coverage

Catches:
- Postinstall / lifecycle scripts (setup.py, __init__.py, .pth path-hijack)
- Obfuscated payloads (base64 / hex / eval-chain unwrapping)
- ML-model exfil-on-load (pickletools disassembly + ML-load DAST detonation)
- Prompt-injection in package READMEs / docs aimed at coding agents

Does NOT catch:
- Native-extension compromise (pre-built .so / .pyd) — surfaced as coverage warning instead
- Time-bombed payloads (fires only on date X / specific hostname)
- Env-conditional payloads (only triggers in AWS / specific region)

Users should treat "Argus did not observe malicious behavior" as *evidence of safety*, not a *guarantee*.

### Live smoke test

`argus install six==1.16.0 --dry-run --no-dast` against real PyPI:
- pip downloaded the wheel, cascade harness scanned the contents
- triage `CLEAN`, verdict `clean`, blocked `False`
- cost: $0.0011 / elapsed: 10.3s

### Tests

21 new unit tests covering cache roundtrip, miss/corrupt/version-mismatch, clean-passes-and-installs, malicious-blocks-and-skips-install, dry-run, --no-dast, --no-cache, parallel scanning, Phase C contract enforcement, worst-of aggregation across multi-wheel closures, pip download failure handling, --strict-coverage positive + negative cases, coverage_ratio property edge cases. Existing test_engine_smoke + test_repo_scanner unblocked. Full sweep green.

## [1.2.1] — 2026-05-10 — file-type expansion + ML-load DAST + remediation opt-out

**Three new file types in the cascade harness, deterministic ML-artifact load detonation in DAST, and a production opt-out for the remediation pillar.**

### Added

- **Jupyter notebooks (`.ipynb`).** Cell-by-cell decomposition. Code cells preserved verbatim with banner comments; markdown cells rendered as Python comments so the cascade sees prompt-injection surface in-line; shell magic (`!pip install …`) and IPython magic (`%load_ext …`) lines pass through verbatim.
- **ML model artifacts (`.pkl`, `.pickle`, `.pt`, `.bin`, `.safetensors`, `.h5`, `.hdf5`, `.keras`, `.onnx`).** `pickletools.genops` disassembly without execution. Surfaces every `GLOBAL` / `STACK_GLOBAL` opcode whose target is a code-execution primitive (`os.system`, `subprocess.Popen`, `pty.spawn`, `builtins.eval`, …) plus `REDUCE` / `BUILD` / `NEWOBJ` opcodes that turn a global into invocation. Walks PyTorch zip-of-pickles members. Extracts safetensors `__metadata__` so attacker-controlled metadata reaches the cascade.
- **GitHub Actions workflows (`.github/workflows/*.yml`).** Deterministic regex sweep for the supply-chain CI patterns: `pull_request_target` triggers, third-party actions referenced without SHA pinning, `${{ github.event.* }}` interpolations into `run:` shells, `permissions: write-all`, `secrets.*` references near network verbs (curl / wget / fetch) inside the same `run:` block.
- **ML-artifact load detonation in DAST.** When the file is a recognized ML artifact, the runner injects a synthetic `HML_LOAD` hypothesis and the orchestrator prepends a deterministic load plan into iter 1: `pickle.load()` / `torch.load(weights_only=False)` / `safe_open()` / `h5py.File()` / `onnx.load()` runs against the original binary in the `ml_tools-v1` sandbox. Loading IS execution for these formats — malicious `__reduce__` fires, sandbox captures the trace.

  **Validated end-to-end on a malicious `subprocess.Popen` pickle:** all 3 L1 findings (CWE-502, CWE-78, CWE-94) reached `CONFIRMED` with sandbox-captured runtime evidence. \$0.22 / 253s / 5 sandbox calls on a real Fly Firecracker microVM.
- **`--no-remediation` opt-out flag** on both `argus scan` and `argus scan-repo`. Skips Phase C (fix-and-verify) entirely while keeping Phase A verification + Phase B discovery active. Use cases: compliance scans, CI gates that don't allow source-modification suggestions, read-only audits, ~$0.05/file cost reduction. Output always carries a structured `phase_c` block with `skipped_reason: "phase_c_disabled_by_config"` so consumers can distinguish "remediation off" from "ran and found nothing to fix."
- **Phase C binary-artifact policy.** When an ML artifact is `CONFIRMED` malicious, Phase C does NOT call the patch generator (a model-emitted byte-level patch would corrupt the binary and mislead the replay step). Instead emits structured remediation guidance: regenerate the model from a clean training pipeline and serialize using `safetensors`. Phase C status = `UNVERIFIABLE` with the guidance in `fix_summary`.

### Changed

- README restructured around three pillars (cascade harness / DAST / remediation) with an explicit per-file-type capability matrix.
- `ScanConfig` adds `enable_phase_c: bool = True`. Threaded through `engine.scan_file` → `dast_runner` → `run_dast`.

### Implementation notes

- `preprocessing/notebook.py` — Jupyter decomposer.
- `preprocessing/ml_model.py` — Pickle / PyTorch / safetensors / HDF5 / ONNX inspector.
- `preprocessing/github_actions.py` — Workflow inspector.
- `dast/ml_detonation.py` — Deterministic load plan template.
- 90+ new unit tests across the new modules; full sweep green.

## [1.2.0] — 2026-05-08 — fix-and-verify

**Two production-grade additions that turn Argus from a detector into a verifier.**

### Added

- **Phase C — fix-and-verify.** When DAST CONFIRMS a finding, Argus generates
  a patched version of the source file (LLM call, schema-enforced), replays
  the *same* iter-1 exploit plans against the patched code in the sandbox,
  and reports per-finding **NEUTRALIZED** / **STILL_EXPLOITABLE** /
  **UNVERIFIABLE** with sandbox-grounded evidence.

  Output ships in `result.phase_c` as a structured object containing
  `patched_source`, `fix_summary`, `post_patch_verdict`, `per_finding[]`,
  and counts (`n_neutralized`, `n_still_exploitable`, `n_unverifiable`).

  **Validated end-to-end on adversarial fixtures: 5 of 5 confirmed exploits
  neutralized across two distinct backdoor patterns.** In one case the
  patcher caught a defense-in-depth issue (timing-oracle on a checksum
  comparison) that wasn't even in the listed findings.

  Implemented in `dast/orchestrator.py::_run_phase_c_fix_verify`,
  `dast/prompts.py::build_phase_c_fix_prompt` /
  `dast/prompts.py::phase_c_fix_schema`. Surfaced via `ScanResult.phase_c`
  and `DastResult.phase_c`.

- **Phase C trigger gate broadened.** Phase C now fires when EITHER
  `orchestrator.findings_validated` is non-empty OR the journal contains
  any `phase_a_verdict` record with `verdict="confirmed"` and non-empty
  `evidence_refs`. The journal-derived gate catches runtime-grounded
  confirmations that the narrow `finding_ref` path missed.

### Changed

- **Severity-driven iter-erosion guard** (replaces v1.1's binary
  all-grounded rule). Engine now bounds DAST's proposed downgrade by the
  max severity of remaining uncertain findings:

  - any CONFIRMED+NOT_TESTED critical remains → keep L1 (no downgrade)
  - any high uncertain remains → downgrade by 1 tier max
  - only med/low uncertain remains → cap downgrade at suspicious
  - everything refuted (BLOCKED/UNREACHED) → accept full DAST downgrade

  Final verdict is bounded by the severity-permitted ceiling AND DAST's
  proposal — DAST is never forced lower than what it asked for. Empty
  `per_finding_validation` falls back to v1.1 behavior (keep L1) so
  legacy/stub DAST runners aren't surprised.

  Visible in `scan_path` as
  `dast_severity_downgrade:<from>-><to>:<reason>` or
  `dast_keep_l1:<from>_over_<to>:<reason>`. Reasons are machine-readable.

  This addresses the v1.1 case where DAST proposed a correct downgrade
  but the engine refused (e.g., `backup_manager.py` was kept at malicious
  even though all findings were BLOCKED).

### Tests

- Two existing DAST-105 unit tests updated to reflect v1.2 severity-driven
  policy (markers + verdict expectations).
- All 319 unit tests pass; one pre-existing test remains skipped.

### Roadmap

- New `## v1.3 — post-launch performance & polish` section in
  [ROADMAP.md](ROADMAP.md). First v1.3 item: parallelize DAST sandbox calls
  within an iteration (currently sequential — would cut DAST wall-clock
  per file by ~30-60% via `asyncio.gather()` over per-plan submits).

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
