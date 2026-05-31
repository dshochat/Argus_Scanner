# JS / TS DAST parity — FULL ✓ (v11, 2026-05-17)

**Status:** complete on origin/main as of `5f934cd`. All Phase 3
hypothesis kinds now land on JS + TS targets the same way they do
on Python. Multi-file project staging closes the final real-world
gap (mcp-server-filesystem, LangChain.js, Vercel AI SDK).

Brought `.js` / `.mjs` / `.cjs` + `.ts` / `.tsx` files to behavioral
parity with `.py` files through every DAST phase — no kind-specific
blocks, no language-specific limitations remaining at the harness
layer.

## Shipped commits

| Commit | Workstream | Description |
|---|---|---|
| `2f4438b` | Foundation | Plan doc + `preprocessing/js_imports.py` + 59 tests |
| `674dc16` | B1-B6 | npm dep installer + auto-bump + 14 tests |
| `6e8dd01` | A1-A2 | Orchestrator gates flipped + adversarial_loop_runner language derive + 3 tests |
| `a0d014d` | A3 | Phase 3 Stage 1 JS behavioral probe harness + 18 tests + empirical verification |
| `b8ca475` | A4-A5 | Phase B+ chains JS harness + 11 tests + empirical verification |

1030 unit tests pass (was 771 pre-effort). +259 tests for JS / TS /
multi-file parity.

TypeScript: shipped in v11 — `tsx@^4` (modern TS runner used by
Vite/Next/Astro/Nuxt CLIs) replaces v9's failed `ts-node` attempt.
Resolves the `.js`→`.ts` source rewrite at runtime so modern ESM-
convention TS code works natively.

## Per-phase support — final state (v11)

| Phase | Python | JS | TS | Notes |
|---|---|---|---|---|
| Phase A validation | ✓ | ✓ | ✓ | TS routes via tsx (v11) |
| Phase B+ single-function probe | ✓ | ✓ | ✓ | TS via tsx (v11) |
| Phase B+ mutation / iterative | ✓ | ✓ | ✓ | |
| Phase B+ chains | ✓ | ✓ | ✓ | TS via tsx (v11) |
| Phase 3 Stage 1 | ✓ | ✓ | ✓ | TS via tsx (v11) |
| Phase 3 Stage 2 (probe / single_function) | ✓ | ✓ | ✓ | TS via tsx (v11) |
| Phase 3 Stage 2 (stateful_sequence) | ✓ | ✓ | ✓ | **Added `5f934cd` (v11)** — JS/TS sequence harness, full parity |
| Phase C fix-and-verify | ✓ | ✓ | ✓ | |
| P2a per-scan dep installer | ✓ | ✓ | ✓ | TS uses same regex-based extractor as JS |
| Multi-file project staging | ✓ | ✓ | ✓ | **Added `ca77720` (v11)** — sibling-file resolver + sandbox staging via tar.gz env var; cross-cutting fix |

## Workstream A — wire JS through Phase B+ chains + Phase 3

### A1. Orchestrator gates (3-line flips)

`dast/orchestrator.py`:

- `L428` (Phase 3 Stage 1): `_probe_lang == "python"` → `_probe_lang in ("python", "javascript")`
- `L475` (Phase 3 Stage 2): same
- `L596` (Phase B+ chains): same

### A2. Adversarial loop language hardcode

`dast/adversarial_loop_runner.py:954` hardcodes `language=LANGUAGE_PYTHON`. Derive from `file_name` via `detect_probe_language` instead. Plan builders downstream already dispatch on `language` (per `_VALID_LANGUAGES` set in the runner — JS is included).

### A3. Phase 3 Stage 1 JS behavioral probe harness

`dast/behavioral_probe.py:712` returns `None` on non-Python. Parallel JS harness:

- `_build_javascript_behavioral_probe_script()`
- Monkey-patches built-ins BEFORE `require()`-ing the target:
  - `Module.prototype.require` — module reach map
  - global `eval`, `Function` constructor, `vm.runInNewContext` — eval reach
  - `child_process.exec/execSync/spawn/spawnSync` — subprocess reach
  - `fs.readFile`, `fs.writeFile`, `fs.createReadStream`, `fs.createWriteStream` — file I/O
  - `http.request`, `https.request`, `net.connect` — network attempts (also captured by DNS hijack at the TCP layer, but in-process gives us symbolic args)
- Enumerates exports: top-level functions + class methods + object methods on each exported value
- Calls each with benign placeholders (`""`, `0`, `null`, `{}`, `[]`) inside `try/catch` so one throwing callable doesn't kill the run
- Emits the same `RESULT_JSON:` markers as the Python probe so `interpret_probe_trace` reuses without changes

Dispatch in `run_phase_3_behavioral_probe`: if `detect_probe_language(file_name) == "javascript"`, build JS harness, run via `node` instead of `python3`.

### A4. Audit JS plan-builder paths

`adversarial_loop.py` declares `LANGUAGE_JAVASCRIPT` and `_VALID_LANGUAGES` includes JS, but plan-builder dispatch sites may have stub-only handling. Read each `if language == LANGUAGE_JAVASCRIPT` site, confirm there's a real implementation, fill any `raise NotImplementedError`.

### A5. Phase B+ chains JS

Audit `_run_phase_b_runtime_probe_chains` and its plan-builder. Flip orchestrator gate (A1 covers it) once we confirm the dispatch path exists, write a JS chain harness if not.

## Workstream B — npm dep installer (P2a analogue)

### B1. Parser — extract JS imports

New module `preprocessing/js_imports.py`. Comment- and string-aware regex parse (deterministic, no JS runtime needed):

- `require('X')` / `require("X")` (single + double quote)
- `import X from 'X'` (default)
- `import { y } from 'X'` (named)
- `import * as X from 'X'` (namespace)
- `import 'X'` (side-effect)
- `import('X')` (dynamic, static-string form only)

Skip:

- Node built-ins (full Node 20 LTS list: `assert`, `buffer`, `child_process`, `cluster`, `console`, `constants`, `crypto`, `dgram`, `dns`, `domain`, `events`, `fs`, `http`, `http2`, `https`, `inspector`, `module`, `net`, `os`, `path`, `perf_hooks`, `process`, `punycode`, `querystring`, `readline`, `repl`, `stream`, `string_decoder`, `sys`, `timers`, `tls`, `trace_events`, `tty`, `url`, `util`, `v8`, `vm`, `wasi`, `worker_threads`, `zlib`, plus their `/promises`, `/strict`, `/web`, `/consumers`, `/posix`, `/win32` subpaths, plus `node:`-prefixed forms)
- Relative imports (`./foo`, `../foo`, `/abs/foo`)
- Template literals with interpolation (can't statically resolve)

Extract package name from subpath:

- `foo/bar` → `foo`
- `foo/bar/baz` → `foo`
- `@scope/foo` → `@scope/foo` (scoped — keep full)
- `@scope/foo/bar` → `@scope/foo`

### B2. npm-specific filter

- Drop Node built-ins (above)
- Drop image-preinstalled set (start empty; populate later if profiling shows install bottleneck)
- Validate name against strict npm regex: `^(@[a-z0-9][a-z0-9-_]*\/)?[a-z0-9][a-z0-9-_.]{0,213}$`
- Cap at 20 packages, sort deterministically

### B3. Security model (different from pip)

| Concern | pip mitigation | npm mitigation |
|---|---|---|
| Attacker-named pkg installs | `--no-deps` (v0.1) | `--ignore-scripts` (kills postinstall RCE — the actual npm threat) |
| Surprise transitives | `--no-deps` / allowlist split (v0.3) | not needed — postinstall is the attack vector, not declared deps |
| Time bomb | 60s timeout | 90s timeout (npm slower) |

**No v0.3-style allowlist split for JS.** npm's threat surface is postinstall scripts, not transitive declaration. `--ignore-scripts` is a hard kill switch that covers both.

### B4. SandboxPlan + env wiring

`dast/sandbox/client.py`:

- Add `SandboxPlan.runtime_npm_packages: list[str] = []`
- `_build_env` emits `RUNTIME_NPM_PACKAGES` (space-separated)
- `MultiImageSandboxClient.submit` auto-bump extended to JS targets: if file is `.js/.mjs/.cjs` and `runtime_npm_packages` non-empty on a `lean` plan, bump to `rich_python` (same tier, since we don't add `rich_node` in v1)

`dast/orchestrator.py`: every plan-build site that handles `.js` files populates `runtime_npm_packages` via the new helper.

### B5. dast-init.sh — npm install block

After Python pip block (Step 0), before DNS hijack (Step 1):

```bash
if [ -n "${RUNTIME_NPM_PACKAGES:-}" ]; then
    echo "[dast-init] per-scan npm install: RUNTIME_NPM_PACKAGES=${RUNTIME_NPM_PACKAGES}" >&2
    mkdir -p /workspace
    cd /workspace || exit 0
    if timeout 90 npm install --ignore-scripts --no-save --no-package-lock \
        --no-audit --no-fund --silent $RUNTIME_NPM_PACKAGES 2>&1 | tail -20 >&2; then
        echo "[dast-init] per-scan npm install: ok" >&2
    else
        echo "[dast-init] per-scan npm install: FAILED (rc=$?), continuing" >&2
    fi
fi
```

Flags:

- `--ignore-scripts` — kills `postinstall` RCE (the primary npm threat vector)
- `--no-save` / `--no-package-lock` — don't write to nonexistent package.json
- `--no-audit --no-fund` — silence phone-home calls
- `--silent` — slim logs

Install lands in `/workspace/node_modules` — Node's resolution walks up from cwd, so harnesses running in `/workspace` find packages naturally.

### B6. Harness cwd

JS probe harnesses MUST set cwd to `/workspace` before `require()`-ing the target. Verify in `runtime_probe.py:_build_javascript_probe_harness` and the new `_build_javascript_behavioral_probe_script`.

## Workstream C — images

### State

`lean` already has Node.js + npm (from DAST-206). All three tiers inherit.

### Decisions

- **No new image tier.** Keep 3 tiers. `rich_node` doubles ops cost for marginal gain.
- **No npm baseline preinstall in v1.** Scan-time install via dep installer covers the case; measure if it's a bottleneck.
- **Dockerfile changes:** none beyond verifying `npm` is on PATH for the `runner` user (it should be).
- **Image version bump v2 → v3:** dast-init.sh has new content. Combine with the P2a v0.3 rebuild already pending so we burn one ~30-90 min build cycle.

## Rollout sequence

1. **Code ship (this effort):**
   - B1-B4 (npm parser + partition + env wiring)
   - B5-B6 (dast-init.sh + harness cwd)
   - A1-A2 (gate flips + adversarial_loop_runner language fix)
   - A4 (audit plan-builder JS paths, fix stubs)
   - A3 (Stage 1 JS harness — the meaty bit)
   - A5 (chains JS — verify or implement)
   - Unit tests at every layer

2. **Image rebuild** — `IMAGE_VERSION=v3 bash build_and_push_multi.sh` combined with P2a v0.3.

3. **E2E verify** — synthetic `.js` file with `axios` import + CWE-78/94/918, full scan, confirm Phase 3 Stage 1 + Stage 2 fire, Fly logs show `[dast-init] per-scan npm install: ok`.

## Test plan

Unit:

- `tests/unit/test_js_imports.py` — extract, filter, validate, partition
- `tests/unit/test_dast_runner.py` — JS auto-bump tests
- `tests/unit/test_runtime_probe.py` — JS behavioral probe builder snapshot
- `tests/unit/test_imports.py` — no regression in Python path

E2E (post image rebuild):

- `argus_jsdast_e2e_test.js` synthetic with niche `axios` + CWE-78/94/918
- Verify scan_path includes Phase 3 Stage 1 + Stage 2 entries
- Verify Fly logs show npm install firing
- Verify dast_findings has CONFIRMED entries

## Effort summary

| Workstream | Eng | Build | Total |
|---|---|---|---|
| A (gate flips, runner fix, audits) | ~1 day | — | ~1 day |
| A3 (Stage 1 JS harness) | ~0.5 day | — | included |
| B (npm parser + installer) | ~0.75 day | — | included |
| C (image rebuild) | 0 | 30-90 min | next rebuild window |
| **Total** | **~2.25 days eng** | **30-90 min build** | **~3 days end-to-end** |

## Open questions (resolved by user "go production-grade")

- Stage 1 behavioral signal scope → real monkey-patch instrumentation (require / eval / Function / child_process / fs / http / net / vm)
- npm preinstall baseline → defer to v2, measure first
- TypeScript → SHIPPED v11 (`ca77720` + `5f934cd`) — tsx + multi-file staging + stateful_sequence parity
- Image rebuild → combine with P2a v0.3 next rebuild window
