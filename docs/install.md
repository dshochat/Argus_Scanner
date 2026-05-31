# Install & first scan

Argus runs locally. You bring API keys; Argus calls Anthropic + Google
directly. Optional Fly.io account for DAST sandbox verification.

## Prerequisites

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) — the dependency manager Argus uses
- An Anthropic API key — [console.anthropic.com](https://console.anthropic.com/settings/keys)
- A Google AI Studio key — [aistudio.google.com](https://aistudio.google.com/app/apikey)
- **(Optional)** A Fly.io account for DAST. See [dast-setup.md](dast-setup.md).

## 1. Clone + install

```bash
git clone git@github.com:dshochat/Argus.git
cd Argus
uv sync --extra dev
```

This installs runtime deps (`anthropic`, `google-genai`, `pydantic`,
`httpx`, `tiktoken`, etc.) plus dev deps (pytest, ruff, mypy).

## 2. Configure API keys

```bash
cp .env.example .env
```

Edit `.env`:

```env
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=AIza...
# Optional, for DAST (v1.8 P2b tier names):
# FLY_API_TOKEN=fly_token_...
# ECHO_DAST_IMAGE_LEAN=registry.fly.io/argus-dast-sandbox:lean-vN
# ECHO_DAST_IMAGE_RICH_PYTHON=registry.fly.io/argus-dast-sandbox:rich_python-vN
# ECHO_DAST_IMAGE_ML_TOOLS=registry.fly.io/argus-dast-sandbox:ml_tools-vN
```

Argus reads `.env` with `override=True` — local file values always win
over OS environment. This is deliberate: a stale empty
`ANTHROPIC_API_KEY` in your shell can't silently shadow the file.

**v1.8 — `.env` is found from any directory.** Argus walks up from the
current directory looking for `.env` first, then falls back to the
Argus install directory's `.env`. You can `cd` into any target project
and run `argus scan path/to/file.py` without copying `.env` everywhere.

## 3. Verify with a sanity scan

A clean file should short-circuit at triage and cost ~$0.0001:

```bash
uv run argus scan samples/regression_v1/clean.py --output markdown
```

Expected output (abridged):

```
**Verdict:** `clean`
**Risk:** 0/100 (none)
**Triage:** CLEAN — pure utility functions...
**Cost:** $0.0001  **Time:** ~2s
**Scan path:** preprocessing → triage:CLEAN → clean_short_circuit
```

## 4. (Optional but recommended) Enable DAST sandbox verification

Without DAST, Argus runs L1 cascade analysis (Gemini Flash-Lite triage
→ Sonnet 4.6 → Opus 4.6) and returns verdicts based on static reasoning.
Findings get a `severity` and `confidence` from the model, but nothing
is sandbox-confirmed.

With DAST, on every `malicious` / `critical_malicious` verdict:

- **Phase A** validates every L1 finding in a Firecracker microVM
  (CONFIRMED / REJECTED / BLOCKED / UNREACHED / NOT_TESTED status)
- **Phase B+** (v1.8 default ON) — Sonnet generates concrete attack
  inputs per probe-attractive function, sandbox executes
- **Phase 3 Stage 1+2** (v1.8 default ON) — non-destructive behavioral
  profile + adversarial reasoning loop with Strategy B/C FP defenses

DAST is the differentiator over pattern-only scanners. Setup is one-time;
budget ~30-90 min the first time you build the sandbox images.

### Prerequisites for DAST

- A **Fly.io account** ([fly.io](https://fly.io)) — they run the
  Firecracker microVMs. Free tier covers DAST sandbox usage but Fly
  requires a payment method on file.
- The **`flyctl` CLI** installed locally:
  - macOS / Linux: `curl -L https://fly.io/install.sh | sh`
  - Windows PowerShell: `iwr https://fly.io/install.ps1 -useb | iex`

### One-time DAST setup

```bash
# 0. Pick a globally-unique Fly app name. The default
#    `argus-dast-sandbox` is taken on Fly's globally-unique namespace.
#    Self-hosters MUST set their own (convention: argus-dast-<handle>).
export ARGUS_DAST_FLY_APP=argus-dast-yourhandle
# Windows PowerShell:
#   $env:ARGUS_DAST_FLY_APP = "argus-dast-yourhandle"

# 1. Authenticate to Fly
flyctl auth login

# 2. Create the sandbox app + initial machine config
cd dast/sandbox/firecracker
bash preflight.sh                # macOS / Linux / WSL
# or on Windows PowerShell:
#   $env:ARGUS_DAST_FLY_ORG = "personal"  # or your org slug
#   ./preflight.ps1
# (Both scripts read $ARGUS_DAST_FLY_APP. If the name is taken on
#  another Fly account they print a clear actionable error pointing
#  back here.)

# 3. Generate a deploy-scoped API token (30-day expiry; renew when needed)
flyctl tokens create deploy --app "$ARGUS_DAST_FLY_APP" --expiry 720h
# → copy the token output

# 4. Build + push the three sandbox images (~30-90 min, mostly cached after first run)
bash build_and_push_multi.sh
# Build script defaults to IMAGE_VERSION=v1. To rebuild with a fresh
# version suffix (e.g., after editing a Dockerfile):
#   IMAGE_VERSION=v2 bash build_and_push_multi.sh
```

### Wire DAST into `.env`

Add these lines to your `.env` file (replace `<your-app>` with the
`ARGUS_DAST_FLY_APP` value you chose in step 0):

```env
# DAST sandbox (optional — Argus runs L1-only if these are absent)
ARGUS_DAST_FLY_APP=<your-app>
FLY_API_TOKEN=fly_token_from_step_3

# Image refs — use the version tag the build script emitted in step 4
# (default IMAGE_VERSION=v1). v1.8 P2b tier names below.
ECHO_DAST_IMAGE_LEAN=registry.fly.io/<your-app>:lean-v1
ECHO_DAST_IMAGE_RICH_PYTHON=registry.fly.io/<your-app>:rich_python-v1
ECHO_DAST_IMAGE_ML_TOOLS=registry.fly.io/<your-app>:ml_tools-v1
```

> **Migrating from v1.7?** Env var names changed (hard rename, no aliases):
> `ECHO_DAST_IMAGE_MINIMAL` → `ECHO_DAST_IMAGE_LEAN`,
> `ECHO_DAST_IMAGE_NETWORKED` → `ECHO_DAST_IMAGE_RICH_PYTHON`,
> `ECHO_DAST_IMAGE_ML_TOOLS` unchanged. Rebuild images via
> `build_and_push_multi.sh` (now defaults to building `lean / rich_python
> / ml_tools`) and update your `.env`. If only the old vars are set,
> Argus logs a deprecation hint and skips DAST.

### The three sandbox images (v1.8 P2b tiers)

| Image | Contents | Use cases |
|---|---|---|
| `lean` | Python 3.13 + Node.js + npm + JRE + bash + coreutils + network CLI (`curl`, `wget`, `nc`, `dig`, `nslookup`, `openssl`) + ~30 common pip packages (requests, flask, fastapi, sqlalchemy, pandas, numpy, boto3, paramiko, redis, pymongo, pillow, cryptography, pyyaml, etc.) | **Default** for most plans. Pickle exploits, file I/O, subprocess, exfil chains (curl/wget/nc), DNS-exfil patterns. This is the floor — has everything most malicious files need. |
| `rich_python` | lean + AI-fixture + data-adjacent libs: `scipy`, `scikit-learn`, `openai`, `anthropic`, `langchain-core`, `aiohttp`, `aiofiles`, `psutil`, `psycopg2-binary` | Files importing AI SDKs, numerical computing, async I/O, system introspection. Catches `ModuleNotFoundError:infra_stub` on these popular gaps. |
| `ml_tools` | rich_python + torch CPU + transformers + safetensors + huggingface_hub | Model-loader exploits: malicious safetensors, pickled `__reduce__` payloads in `torch.load()`, custom-loader RCE. |

The DAST orchestrator picks `image_hint` per hypothesis; if the model
picks an unsupported hint, it falls back to `lean`. Auto-routing by
file extension is implemented for Python / JS / TS / shell / Java
bytecode / Jupyter / ML-model formats.

### Verify DAST end-to-end

Scan a known-malicious sample with DAST enabled. It should produce a
`critical_malicious` verdict plus Phase A `CONFIRMED` findings:

```bash
uv run argus scan samples/regression_v1/preinstall.py --output markdown
```

Expected (abridged):

```
**Verdict:** `critical_malicious`
**Risk:** 100/100 (critical)
**Scan path:** preprocessing → triage:HIGH → analysis:sonnet_default
              → dast_verification
**Phase 3 loop:** ran (hypotheses_total=3, confirmed≥1)
**Cost:** ~$0.50-1.00
```

If you see `dast_attempted: False` or scan_path ends at
`analysis:sonnet_default`, DAST didn't fire — usually one of:

- `FLY_API_TOKEN` missing or expired (rotate with `flyctl tokens create
  deploy` again)
- Image refs in `.env` don't match the tags from `build_and_push_multi.sh`
- L1 verdict came back below the trigger gate
  (default: `malicious,critical_malicious`)

The full DAST runbook — sandbox internals, per-status semantics, image
build details, troubleshooting — is in
[dast-setup.md](dast-setup.md).

## CLI commands

Argus exposes four subcommands. Each has its own `--help`.

### `argus scan FILE` — single file

```bash
uv run argus scan path/to/file.py
uv run argus scan path/to/file.py --output markdown
uv run argus scan path/to/file.py --output json > result.json
```

Useful flags:

| Flag | Effect |
|---|---|
| `--output {json,markdown}` | Output format (default: `json`) |
| `--no-dast` | Skip DAST verification |
| `--enable-remediation` | **Opt in to Phase C** (fix-and-verify) — generate patched source for CONFIRMED findings and replay the original exploit against the patch. Off by default as of v1.8 (was on through v1.7). Adds ~$0.05/file. |
| `--enable-runtime-probe` / `--no-enable-runtime-probe` | Phase B+ runtime exploit probing (~$0.20-0.50/file). Python-only. **Default ON as of v1.8.** Pass `--no-enable-runtime-probe` to opt out. |
| `--enable-runtime-probe-mutation` | Fan probe inputs out to known-bypass variants (URL-encode, `....//`, `; id`, etc.). Implies `--enable-runtime-probe`. ~5× sandbox cost. Opt-in. |
| `--enable-runtime-probe-iterative` | Retry BLOCKED probes with refined inputs based on observed exceptions. Up to 2 retries per candidate. Opt-in. |
| `--enable-runtime-probe-chains` | Cross-function exploit chains (parse→eval, store→load, sanitize→render). ~$0.15-0.35/file. Opt-in. |
| `--enable-phase-3-discovery` / `--no-enable-phase-3-discovery` | Phase 3 Stage 1 — non-destructive behavioral profile (~$0.05-0.10/file). **Default ON as of v1.8.** |
| `--enable-phase-3-loop` / `--no-enable-phase-3-loop` | Phase 3 Stage 2 — adversarial reasoning loop. Implies Stage 1 + Phase B+ runtime probe. **Default ON as of v1.8.** Pass `--no-enable-phase-3-loop` to opt out. |
| `--enable-discovery` | DAST-204 proactive payload sweep (~$0.25/file). Finds CWEs L1 missed. |
| `--dast-trigger-verdicts LIST` | Which L1 verdicts trigger DAST. Default: `malicious,critical_malicious`. Use `suspicious,malicious,critical_malicious` for broader coverage. |
| `--dast-required-policy {downgrade_cap,strict}` | Report-layer DAST policy (v1.8). `downgrade_cap` (default) downgrades L1 by up to 1 tier when Phase A finds defenses. `strict` preserves L1 verdict and suppresses only findings Phase A actively proved safe (BLOCKED, UNREACHED, REJECTED), never on infra/NOT_TESTED. |
| `--max-cost USD` | Abort if file scan exceeds $USD. Default: $1.00. Pass `0` to disable. |

### `argus scan-repo PATH` — whole repo

```bash
uv run argus scan-repo .
uv run argus scan-repo ~/work/myrepo --output markdown
uv run argus scan-repo . --output sarif --output-file argus.sarif
uv run argus scan-repo . --diff origin/main           # PR / CI mode
```

Walks `PATH`, honors `.gitignore` + an always-ignore list (`.git`,
`node_modules`, `__pycache__`, `.venv`, etc.), dispatches each supported
file through the cascade, aggregates results.

Repo-specific flags (in addition to all `scan` flags):

| Flag | Effect |
|---|---|
| `--diff REF` | Only scan files different from git ref `REF` (e.g., `origin/main`). Useful for PR / CI gates. |
| `--exclude GLOB` | Additional gitignore-style pattern. Repeatable. |
| `--no-gitignore` | Ignore `.gitignore` during the walk. |
| `--max-file-bytes BYTES` | Skip files larger than BYTES (default: 1 MiB). |
| `--output {markdown,json,sarif}` | Default: `markdown`. **SARIF v2.1.0** suitable for upload to GitHub Code Scanning. |
| `--output-file PATH` | Write to file instead of stdout. |
| `--continue-on-error` / `--no-continue-on-error` | Per-file error handling (default: continue). |

**SARIF for CI**: pipe `argus scan-repo --output sarif --output-file argus.sarif`
then upload via the
[`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action#uploads)
action. Argus findings will surface in the GitHub Security tab.

### `argus install PACKAGE` — pre-install gate

```bash
uv run argus install requests
uv run argus install fastapi==0.115.0
uv run argus install -r requirements.txt
uv run argus install requests --block-on malicious,critical_malicious --dry-run
```

Stages the package via `pip download` (no `setup.py` execution), scans
every wheel/sdist in the dependency closure with the Argus cascade plus
DAST Phase A+B (if Fly is configured), then either installs or blocks.
Phase C (remediation) is always off here — for a not-yet-installed
package the right action is "don't install," not "patch."

Useful flags:

| Flag | Effect |
|---|---|
| `-r PATH` / `--requirement PATH` | Install from a requirements file. |
| `--block-on LIST` | Comma-separated verdict tiers that block (default: `malicious,critical_malicious`). |
| `--dry-run` | Scan + report; never call `pip install`. |
| `--strict-coverage` | Fail if any wheel can't be scanned. |
| `--max-total-cost USD` | Abort run if cumulative API spend exceeds USD. |
| `--deep` | Also runs runtime probe + Phase 3 loop for higher coverage. ~10× cost. |
| `--cache-dir PATH` | Cache scan results by wheel SHA. Default: `~/.cache/argus/install`. |
| `--no-cache` | Disable the cache (fresh scan every run). |
| `--pip EXEC` | Use a specific pip executable (default: detect). |
| `--parallel N` | Parallel wheel scans (default: 1). |

### `argus bench` — beat-Opus benchmark

```bash
uv run argus bench --suite samples/regression_v1
```

Methodology runner. Used for release-gate validation (BENCH-005). Not
typically run by end users.

## Common workflows

**Scan a single Python file**

```bash
uv run argus scan src/app.py --output markdown
```

**Scan a repo for CI (changed-files only)**

```bash
uv run argus scan-repo . \
  --diff origin/main \
  --output sarif \
  --output-file argus.sarif \
  --max-cost 0.50
```

**Strict mode — never downgrade L1 on infra-limited DAST runs**

```bash
uv run argus scan src/api/handler.py \
  --enable-phase-3-loop \
  --dast-required-policy strict
```

This is the policy mode for security teams that prefer L1 transparency
over DAST-driven verdict massaging. Findings Phase A actively proved safe
(BLOCKED / UNREACHED / REJECTED) get suppressed; findings Phase A
couldn't run (`NOT_TESTED`, including infra failures) stay.

**Gate a dependency install**

```bash
uv run argus install some-suspicious-pkg --dry-run --output text
# If it passes:
uv run argus install some-suspicious-pkg
```

## Troubleshooting

**`KeyError: 'ANTHROPIC_API_KEY'` on first run.**
As of v1.8, Argus auto-loads `.env` from the current directory (walking
up) or from its install directory — so this error usually means `.env`
exists nowhere on those paths AND `ANTHROPIC_API_KEY` isn't set in your
OS environment. Either:
1. Create `.env` in the Argus install dir (`cp .env.example .env` per
   step 2 above), OR
2. Export the key in your shell: `export ANTHROPIC_API_KEY=sk-ant-...`

A rarer cause: you have `ANTHROPIC_API_KEY` set as an *empty string* in
your OS env (which `find_dotenv` respects). Fix:
- bash/zsh: `unset ANTHROPIC_API_KEY`
- PowerShell: `Remove-Item env:ANTHROPIC_API_KEY`
- cmd: `set ANTHROPIC_API_KEY=`

Then re-run.

**`flyctl: command not found` during DAST.**
DAST is optional. If Fly env vars aren't set, the runner returns `None`
and Argus skips DAST silently with a log line. Force-disable per scan
with `--no-dast` to suppress the log entirely.

**Test failures referencing `samples/regression_v1/`.**
The regression suite is committed to the repo. If `git status` shows the
directory untracked, run `git fetch && git reset --hard origin/main`.

**`Cost cap exceeded: $X > $1.00 after <stage>`.**
A pathological file (e.g., DAST iterated 3 times without converging) hit
the per-file cap. Raise with `--max-cost 2.00` for that run, or disable
with `--max-cost 0`. Investigate the file separately if this keeps
firing — it usually means a real exploit chain that requires more
budget to validate.

**Phase 3 loop says `dast_required_policy:strict:l1_verdict_preserved` in
scan_path.**
This is strict mode working as designed: L1 said `malicious`, Phase A
couldn't conclusively reproduce (`NOT_TESTED:inconclusive` or similar),
strict mode refused the downgrade so the verdict stays `malicious`. See
[`dast-setup.md`](dast-setup.md) for the full status semantics.

## What's next

- [Architecture overview](architecture.md) — full cascade flow + module map
- [Cost guide](cost-guide.md) — per-file pricing + cost cap
- [DAST setup](dast-setup.md) — Fly + sandbox image setup
- [API keys](api-keys.md) — key sources + rotation
- [Contributing](contributing.md) — running tests + PR process
