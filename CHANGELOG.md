# Changelog

All notable changes to Argus are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.12.0] — 2026-06-01 — MCP server scanning mode

Adds dynamic security testing for Model Context Protocol servers. A new `argus mcp` subcommand speaks MCP over stdio (sandboxed) and Streamable-HTTP / SSE (remote, opt-in), enumerates the tool / resource / prompt surface, classifies each parameter, and runs a black-box probe catalog. It's a self-contained plug-in that reuses the existing DAST sandbox, SSRF payload catalog, CWE→probe registry, and findings schema — the only change to the rest of the engine is one CLI subparser block.

### Added

* **`argus mcp enumerate <target>`** — recon only. Handshake, `tools/list` + `resources/list` + `prompts/list`, parameter classification (URL / HOST / PATH / COMMAND / QUERY / FUZZ), surface-map output. No attacks; always safe to run.
* **`argus mcp scan <target>`** — active probe catalog:
  * **SSRF** (CWE-918) — 8 canaries per URL/HOST param: AWS IMDSv1 + IMDSv2 token endpoint, GCP / Azure metadata, decimal + hex IP encodings, loopback variants.
  * **Redirect-to-internal** (CWE-601 → CWE-918) — external-looking URLs that 30x-redirect to internal targets; catches missing post-redirect re-validation.
  * **Fail-open** (CWE-755) — malformed inputs (NUL bytes, oversize, CRLF, garbage, wrong types) probe whether validation silently bypasses on exception.
  * **Authorization bypass** (CWE-862) — paired authed-vs-unauthed calls per tool with a response-shape diff.
* **Transports:** stdio (launched as a subprocess; sandboxed execution path wired through the existing Firecracker `SandboxClient`) and Streamable-HTTP / SSE via httpx.
* **Out-of-band listener** for blind-SSRF confirmation on remote HTTP targets — `--oob <url>` for a user-supplied interactsh / dnslog / webhook.site endpoint, or an Argus-managed local listener spawned automatically.
* **Reports:** `--report json` (stable `argus.mcp.scan-report` schema, `schema_version=1`) and `--report md` (human summary). Findings carry `confirmed` (runtime evidence) vs heuristic, CWE, CVSS estimate, payload, response excerpt, network evidence, and a copy-paste remediation + repro.
* **Flags:** `--stdio` / `--url`, `--transport`, `--auth none|token` + `--auth-token`, `--oob`, `--canary-config`, `--scope-deny <cidr>` (repeatable), `--tools <list>`, `--authorized`, `--report`, `--output-file`.
* Optional `[mcp]` extra (`pip install argus-ai-scanner[mcp]`) for users who also want the official Python MCP SDK in the same venv. Argus itself ships a minimal JSON-RPC client and does not depend on the SDK.

### Safety

* Remote URL scans **refuse to attack** without `--authorized`. Stdio scans skip the gate (sandbox-protected).
* `--scope-deny <cidr>` drops any probe whose canary URL targets a denied IP range.
* Exit codes for CI gating: `0` = no / heuristic-only findings, `1` = at least one confirmed finding, `2` = usage / consent error.

### Out of scope for v1.12 (clean extension points)

Prompt-injection / LLM testing, static MCP code analysis, continuous monitoring, advisory auto-generation.

See [docs/mcp.md](docs/mcp.md) for the operator guide.

## [1.11.1] — 2026-05-30 — Anthropic model overrides (SCAN-020)

Adds two new CLI flags so operators can pick the Anthropic model used in each tier without code edits — bump to a newer Opus version, run Opus in both slots for a high-precision audit, or swap a future Anthropic-compatible model into either slot.

### Added

* **`--scan-model MODEL_ID`** — overrides the workhorse tier (triage, L1 analysis, DAST probe-inference). Default: `claude-sonnet-4-6`.
* **`--reasoning-model MODEL_ID`** — overrides the deep-reasoning tier (L1 escalation, DAST iter-3, Adversarial Reasoning, adjudicator). Default: `claude-opus-4-6`.
* Both flags accepted on `argus scan`, `argus scan-repo`, and `argus install`.
* `ScanConfig.scan_model` + `ScanConfig.reasoning_model` fields surfaced for programmatic callers.

### Role-based naming, not family-based

Slots describe what the model does in the cascade, not which family it comes from. Set both flags to the same `model_id` (e.g., `claude-opus-4-8`) for a high-precision audit mode that runs the reasoning-tier model everywhere.

### Caveats (documented in `--help`)

* The `model_id` is sent verbatim to the Anthropic API. Unknown IDs surface as a runner error (Anthropic returns 404).
* Cost constants stay pinned to the default rate card. Overriding to a more expensive model means reported `cost_usd` undercounts — raise `--max-cost` accordingly.
* Some models (e.g. `claude-opus-4-7`) refuse Argus's live-payload fixtures and produce empty responses. Operators own the compatibility risk; always run a smoke scan after overriding.

### Examples

```bash
# Bump just the reasoning tier to Opus 4.8
argus scan --reasoning-model claude-opus-4-8 path/to/file.py

# Run Opus everywhere on a sensitive repo
argus scan-repo \
  --scan-model claude-opus-4-8 \
  --reasoning-model claude-opus-4-8 \
  path/to/repo

# Audit a dependency closure with bumped models before installing
argus install --reasoning-model claude-opus-4-8 fastapi
```

## [1.11.0] — 2026-05-21 — Remediation-first repositioning + production-grade FP defense

This release repositions Argus around **machine-scale verified remediation**: every CONFIRMED finding gets a patched source generated, then the original exploit is replayed against the patched code in the same sandbox. Finding Validation + Remediation are now the default cascade. Zero-day-hunting stages (Exploit Discovery, Behavioral Profiling, Adversarial Reasoning) become opt-in for users who want broader coverage.

### Headline

**Validated remediation is the answer to the modern vuln-throughput problem.** CISOs aren't asking for more findings — they're asking how to close 10,000 open findings before the next audit. Argus's pitch is: AI writes the patch, sandbox proves it works, repeat at scale. This release makes that the default behavior.

### Default cascade flips

| Stage | Default before (v1.5–v1.10) | Default now (v1.11) |
|---|:---:|:---:|
| Finding Validation (Phase A) | ON (intrinsic) | ON (intrinsic) |
| **Remediation (Phase C)** | OFF | **ON** |
| Exploit Discovery (Phase B+) | ON (since v1.8) | OFF (opt-in) |
| Behavioral Profiling (Phase 3 Stage 1) | ON (since v1.8) | OFF (opt-in) |
| Adversarial Reasoning (Phase 3 Stage 2) | ON (since v1.8) | OFF (opt-in) |

`--no-enable-remediation` opts out (compliance / CI / read-only audits). `--enable-runtime-probe --enable-phase-3-discovery --enable-phase-3-loop` restores the v1.10 broad-coverage posture.

### Cost impact

* **Before (v1.10):** ~$0.50–$2.00 per suspicious file (cascade ran all stages by default).
* **After (v1.11):** ~$0.10–$0.40 per suspicious file (Validation + Remediation only).

Operators who want deeper coverage opt in stage-by-stage.

### Production-grade FP-defense oracle stack (Phases 1+2+3)

Three new precision layers gate every CONFIRMED finding before it lands in the report:

1. **Structured assertions** (`dast/runtime_probe.py`) — model emits a Python predicate (`getattr(result, 'scheme', None) == 'file'`); sandbox evaluates against the live return value. Highest-precision oracle. Replaces the legacy substring-on-`repr()` keyword match for the file://-URL-scheme FP class.
2. **Static downstream-cap detector** (`dast/downstream_cap.py`) — AST visitor finds same-file callers that bound a function's return below the attack-class threshold. Catches the FP class where the unit-level return is confirmed but the downstream consumer caps the value (the `_parse_retry_after_header → _calculate_retry_timeout(≤60)` pattern).
3. **Sandbox-syscall sink observation** (`dast/sink_observation.py`) — consults the bpftrace per-probe `syscall_observations` to verify the expected dangerous sink (execve / network connect / openat) actually fired. Catches the FP class where the matcher's string oracle hits content the function didn't fresh-produce. Empirically suppressed 6 false positives on `openai-python/_base_client.py` during pre-release validation.

Every SUPPRESSED finding carries a structured `rejection_reason` traceable to one of the three oracles.

### Phase naming overhaul

Operator-facing labels now use action-noun names that describe what each stage does. Internal Python identifiers + CLI flag names unchanged for back-compat.

| Internal name (kept) | User-facing name (new) |
|---|---|
| Phase A | Finding Validation |
| Phase B+ | Exploit Discovery |
| Phase 3 Stage 1 | Behavioral Profiling |
| Phase 3 Stage 2 | Adversarial Reasoning |
| Phase C | Remediation |

Each rename keeps an "aka 'Phase X' in internal code/JSON" parenthetical in `--help` so anyone digging into source / scan JSON still maps cleanly.

### Other changes since v1.5.0

* **DAST default trigger broadened** to `suspicious,malicious,critical_malicious` (was `malicious,critical_malicious`). Suspicious-verdict files now get runtime confirmation by default; the FP-defense oracle stack absorbs the noise that previously made this trade negative.
* **SCAN-014 findings-floor invariant**: `final_verdict == "clean"` is now structurally impossible when L1 emitted active findings. Closes the openai-python `azure.py`-class "clean verdict + 3 NOT_TESTED findings" UX contradiction.
* **SCAN-013 intent classification + cap**: legitimate library code can no longer land as `malicious` / `critical_malicious` regardless of L1's static-shape claims. Static-only findings on library code downgrade to `informational`.
* **v15.28 tiktoken `<|endoftext|>` fix**: source files containing literal special-token strings (e.g., `openai-python/resources/completions.py`) no longer crash preprocessing with `ValueError: disallowed special token`.
* **F-A1 Stage-1 silent-failure diagnostic**: when the behavioral probe's BEHAVIORAL_PROFILE_JSON marker is absent (sandbox SIGKILL on heavy-import file, etc.), the harness now surfaces a structured `harness_error: marker_missing:<reason>` instead of returning an indistinguishable-from-clean empty profile.
* **F-B1 Phase 3 LIBRARY_CONSUMER prompt rewrite**: the adversarial-reasoning loop now correctly recognizes that library code consumes attacker-controllable DATA INPUTS (HTTP responses, parsed bodies, env vars) even when the function-call arguments are developer-controlled. Closes the "library trust boundary → decline to hypothesize" failure mode on SDK code.
* **Per-finding `SUPPRESSED` status** added to the PFV enum (alongside CONFIRMED/REFUTED/BLOCKED/UNREACHED/NOT_TESTED). Used by the new FP-defense oracle stack to mark findings the matcher confirmed but the precision gates refuted.
* **`jsonschema>=4.26.0`** added as a runtime dependency (prompt-schema validation paths require it).

### Reverted

* The v1.7-narrow default DAST trigger (`malicious,critical_malicious`) is restored as an opt-in via `--dast-trigger-verdicts "malicious,critical_malicious"` — pinned by `test_dast_narrow_trigger_skips_suspicious_v1_7_compat`.

### Migration notes

* **Operators on tight budgets** can restore the v1.10 default by passing `--no-enable-remediation` (most cost savings) or keeping defaults (Validation + Remediation only; biggest cost drop comes from the three opt-out zero-day-hunting stages).
* **Compliance / CI / read-only audit workflows**: pass `--no-enable-remediation` so Argus doesn't generate patches you can't apply.
* **Anyone scripting against `argus scan --help` output**: phase labels changed from "Phase A / B+ / 3" to descriptive names. Internal flag names (`--enable-runtime-probe`, `--enable-phase-3-loop`, `--enable-remediation`) are unchanged.

## [1.11.0] — Also in this release: JS string-array deobfuscation preprocessing

**Live-caught the Mini Shai-Hulud TanStack npm supply-chain attack (May 11, 2026).** The malicious `@tanstack/react-router@1.169.8` shipped a 2.3 MB obfuscator.io-encoded payload (`router_init.js`) at the package root — a deliberate evasion designed to overflow AI scanner context windows. At ~1.53 M tokens it was past every 1 M-context model's input cap; Argus fail-closed to `suspicious vulns=0` and the operator got no detail. This release introduces a preprocessing stage that deobfuscates obfuscator.io string-array payloads via `webcrack` BEFORE the model sees them. Token count on the same file: **1.53 M → 589 K**, fits with headroom. Re-scan verdict: `critical_malicious`, risk **95/100**, **8 enumerated CWEs** (data_exfiltration, code_injection, command_injection, prompt_injection, privilege_escalation, +3).

### The wedge

Obfuscation against AI scanners has shifted from "hide what the code does" to "make the code too big to read." Bloat a payload past every model's context window and semantic analysis dies regardless of provider. Static deobfuscation has to live in preprocessing — before the model sees a single token — or you get a silent detection gap on modern npm supply-chain malware.

### Added

- **`preprocessing/deobfuscation_js.py`** — new preprocessing stage that detects the obfuscator.io fingerprint (`_0x[a-f0-9]{4,}=_0x[a-f0-9]{4,}` in the first 4 KB) and shells out to `webcrack` to inline the string table, strip dead code, and unminify. Output replaces the raw text for the rest of the pipeline (token count, model invocation, prompt-injection scan). Safety budgets: 60 s subprocess timeout, 5 MB output cap, 20 % shrinkage threshold below which the deobfuscation is treated as a no-op.
- **`ObfuscationTechnique.JS_STRING_ARRAY`** enum value; surfaced in the schema via `obfuscation_techniques` and `deobfuscation_applied=True`.
- **`scanner/engine.py` content swap** — when `JS_STRING_ARRAY` fires, the engine substitutes `bundle.decoded_content` for `content` before runner dispatch so the model actually receives the deobfuscated source (the existing v1 runner contract takes `content: bytes` directly and ignored `bundle.decoded_content`; this was a real detection gap, not just an unused field). Narrowly scoped — only this technique triggers the swap; existing Python deobfuscation behavior is unchanged.
- **Top-level `--no-deobfuscation` CLI flag** — escape hatch for airgapped / locked-down environments that cannot install Node/webcrack. Files with obfuscator.io payloads will fall back to the model's fail-closed `suspicious` verdict.
- **Startup dependency probe** in `scanner/cli.py` — verifies `webcrack` is resolvable via `shutil.which("webcrack")` (or `ARGUS_WEBCRACK` for non-PATH installs). Fails fast with the install command for macOS / Debian / RHEL / Docker when missing, so operators install once and move on instead of getting silently degraded scans.
- **Unit tests** (`preprocessing/tests/test_deobfuscation_js.py`) covering: marker detection in obfuscator.io preamble, marker scan-window cap, no-op when webcrack missing, no-op on nonzero exit / timeout / non-shrinking output, applied-true happy path, PATH-vs-env-var precedence, `ARGUS_NO_DEOBFUSCATION` disable gate.

### Dependencies

- **New runtime dependency: Node 22 LTS + `webcrack`.** Installed via `brew install node@22 && npm install -g webcrack` (macOS), NodeSource setup + `npm install -g webcrack` (Linux), or `node:22-slim` base image (Docker). Full per-platform commands in the [README "Dependencies" section](./README.md#dependencies).

### Env vars

- **`ARGUS_WEBCRACK`** — override path to the `webcrack` binary for non-PATH installs (e.g. project-local `node_modules/.bin/webcrack`). Consulted only when `shutil.which("webcrack")` returns nothing.
- **`ARGUS_NO_DEOBFUSCATION`** — set by `--no-deobfuscation`; short-circuits the deobfuscation stage entirely for restricted environments.


## [1.5.0] — 2026-05-10 — Phase B+ runtime exploit probing

**DAST now finds new vulnerabilities by ACTUALLY EXECUTING the code, not by re-reading it. Sonnet generates concrete attack inputs; the Firecracker microVM runs them; runtime evidence becomes the finding. Live-validated end-to-end on multiple fixture classes — shell injection, command injection, path traversal — with exploits proven via the actual exfil bytes captured in the trace (e.g., `/etc/passwd` content returned by a vulnerable file-read function).**

### The wedge

Phase B as it shipped through v1.3.x asked Sonnet/Opus to brainstorm new vulnerabilities by re-reading the file + Phase A's journal evidence. That's still **model-driven static analysis with runtime context** — the sandbox was used only to TEST hypotheses, never to GENERATE them.

v1.5 closes that gap. New Phase B+ flow:

1. Sonnet identifies up to 3 candidate functions in the file with attack-attractive signatures (take user input, call a sink, manipulate filesystem/network/process).
2. For each candidate, Sonnet generates up to 3 concrete attack inputs paired with `expected_observable` + `exploit_proof_if_observed`.
3. Argus builds a Python harness per (candidate × input), stages the target file at `/workspace`, runs the harness in a fresh microVM, captures `stdout` / `stderr` / `exit_code` + a `/tmp` side-effect snapshot.
4. Deterministic interpreter rules decide if the exploit fired:
   - Rule 1: function returned successfully on an attack input that was supposed to be rejected → CONFIRMED via runtime evidence (the actual return value is captured).
   - Rule 2: canary file appeared in `/tmp` post-call → CONFIRMED via side-effect observation.
   - Neither = BLOCKED-equivalent; no finding emitted.
5. Confirmed `HRP_*` findings flow into `dast_findings` with full runtime evidence (attack input, return value preview, side effects).

### Added

- **`--enable-runtime-probe` CLI flag** on `argus scan`, `argus scan-repo`, and `argus install`. Off by default (~$0.20–0.50/file API cost on top of Phase A); opt-in for users who want runtime-grounded discovery.
- **`ScanConfig.enable_runtime_probe`** Python API equivalent.
- **Probe-confirmed findings drive verdict.** A probe-CONFIRMED finding at severity ≥ high contributes to the iter-erosion guard's `max_dast_verdict_rank` floor — so a file with runtime-proven exploits cannot be downgraded to `suspicious` by a later iter that fails to re-confirm. Safety: only bump UP, only by one tier max, only on high/critical severity. Critical + code-execution attack-class → `critical_malicious`; everything else high/critical → `malicious`.
- **Probe inference tokens accounted in iter total.** `IterationStats.phase_b_runtime_probe_in/out` rolls into `total_tokens_in/out` → DAST `cost_usd` → install path's aggregate cost cap (`--max-total-cost`). Probe cost can no longer leak past the cap.
- **Runtime probe rejection rationale now surfaces exception type/message.** Journal HRP rejections include `call_ok=...` and `exc=ExceptionType: msg` so debugging "why didn't this exploit fire" doesn't require pulling raw sandbox events from Fly.
- **Sandbox image v2** with pre-created common app data directories (`/data`, `/srv/app`, `/srv/data`, `/var/lib/app`, `/opt/app`, `/var/data`, `/app` at mode 1777). Path-traversal probes targeting hard-coded directory prefixes can now resolve through them — without this, functions rooted at `open("/data/" + path)` raised `FileNotFoundError` before the exploit could fire, silently masking real vulns.
- **Harness path-prep preamble.** The probe harness regex-extracts absolute-path string literals from the target module's source AND from the test input args, then `mkdir -p`'s the corresponding directory tree (combining each source-extracted prefix with each non-`..` component from the input). Layered defense: catches unusual prefixes the Dockerfile list misses (e.g., `/home/myapp/storage/`) and the cartesian product needed for inputs like `subdir/../../etc/passwd`.

### Changed

- **HRP findings flow via `findings_validated`, not via `l1_output.hypotheses`.** Probe-confirmed runtime findings are NOT re-tested through Phase A. The probe stage IS the test; re-running through Phase A would (a) double sandbox cost, (b) produce contradictory NOT_TESTED verdicts when Fly returned stub traces, (c) duplicate journal records. Phase B (iter ≥ 2) still sees confirmed HRPs via `journal_summary` and won't re-propose them.

### Live validation outcomes

Validated end-to-end on the v1.5 fixture suite. Sample evidence captured:

| Fixture | Probe-confirmed exploits | Runtime evidence |
|---|---|---|
| `runtime_probe_path_traversal.py` | 1 (`HRP_0_1`, `read_file_safely("../../etc/passwd")`) | Function returned `root:x:0:0:root:/root:/bin/bash\ndaemon:...` (literal `/etc/passwd` content) |
| `photoshow_ffmpeg_config.py` | 14 (shell injection: semicolon, subshell `$(...)`, backtick payloads, base64-decoded payloads) | Various process_exit traces showing payload execution |
| `backup_manager.py` | 7 (command injection via `os.system` argument concatenation) | Multiple traces showing canary tmp files created by injected commands |
| `audit_log_compression.py` (malware, not service) | 0 (probe correctly declined — file is malware not service) | Probe-decline rationale journaled |

### Internals

- `dast/runtime_probe.py` (NEW) — dataclasses, harness generator, plan builder, trace parser, deterministic interpreter rules, path-prep preamble (source + input-derived).
- `dast/prompts.py` — `build_phase_b_runtime_probe_prompt` + `phase_b_runtime_probe_schema` (enum-bounded `attack_class`, regex-validated `function_name` to block shell-metachar injection).
- `dast/orchestrator.py` — `_run_phase_b_runtime_probe` helper + `enable_runtime_probe` kwarg on `run_dast`. Probe runs ONCE before the iteration loop so it can populate findings even when L1 hypotheses are empty.
- `dast/sandbox/firecracker/Dockerfile{,.networked,.ml_tools}` — pre-create common app dirs at 1777.
- 46 new tests in `test_runtime_probe.py` covering: attack-class → CWE/severity mapping, harness generation (module import, getattr walk, exception capture, path-prep preamble), plan builder, trace parser, interpreter rules, schema validation, prompt builder, orchestrator integration (4 stub-sandbox tests including the 4 hardening fixes).

### Roadmap

- v1.5.1: JS/TS / shell harness templates + corresponding sandbox image profiles.
- v1.6: model-loop interpretation for tracebacks the deterministic rules can't classify ("did this `PermissionError` mean the function defended itself, or did it mean we hit the wrong code path?").

## [1.3.1] — 2026-05-10 — install-path performance + aggregate cost cap

**Performance + cost-control release for `argus install`. Live-validated on the litellm dependency closure: ~6× faster wall-clock, 3.5× faster on file-heavy wheels, $10 default aggregate cost cap fires fail-closed.**

### Added

- **Per-file scan concurrency inside each wheel.** `RepoScanConfig.scan_concurrency` (default 1 = sequential, preserves v1.3.0 cost-cap-before-each-file semantics for `argus scan-repo`). Install path bumps to 4 by default. ~3–4× speedup on file-heavy wheels (e.g., anyio 988s → 282s).
- **`thinking_budget` parameter on `make_sonnet_runner` / `make_opus_runner`.** Default 24000 preserves v1.3.0 behavior. Pass 0 to drop Anthropic extended thinking (~30% latency win, ~3–5pp accuracy loss on subtle multi-step exploits — recovered by deterministic preprocessing escalation flags).
- **Aggregate cost cap on `argus install`.** Default `$10`; configurable via `--max-total-cost USD` (pass 0 to disable). When cumulative API spend hits the cap, remaining wheels are flagged `suspicious / unscanned_due_to_cost_cap` and the install fails closed. Race-y by design (parallel tasks may complete) but bounded.
- **`--deep` flag on `argus install`.** Reverts to v1.3.0 fidelity: `thinking_budget=24000`, `file_concurrency=1`, `parallel_scans=4`. For users who want max accuracy at max cost.
- **`--no-thinking` flag.** Explicit way to set `thinking_budget=0` (already the install default; flag exists for script readability).
- **`--max-total-cost USD` flag.** Override the aggregate cost cap.

### Changed

- **`argus install` default parallelism: 4 → 8 wheels concurrent.**
- **`argus install` default thinking budget: 24000 → 0** (extended thinking disabled on the install path; use `--deep` to revert). Production safety preserved by deterministic preprocessing flags (`imperative_install_detected`, `attack_vector_extension`, `ai_file_match`, `crypto_sensitivity_detected`, `obfuscation_detected`) which still force-escalate flagged files to HIGH-tier scrutiny.

### Live measurements (litellm closure)

| Wheel | v1.3.0 | v1.3.1 | speedup |
|---|---|---|---|
| anyio-4.13.0 | 988s / $2.77 | 282s / $2.34 | **3.5×** |
| attrs-26.1.0 | 252s / $1.02 | 203s / $1.00 | 1.2× |
| Wall-clock, first 7 wheels | ~22 min | ~4 min | **5.5×** |

### Tests

3 new unit tests covering aggregate cap fail-closed behavior, `max_total_cost=None` disabling the cap, and `file_concurrency` threading through `scan_one_artifact`. All 169 unit tests pass.

### Deferred to v1.4

- Pre-cached trust list of top-1000 PyPI packages (sha256-keyed). The biggest cost reduction available — would skip 80%+ of a typical dep closure. Requires standing up an Argus-operated scan infra to produce + sign the trust list.

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
