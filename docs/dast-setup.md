# DAST setup

DAST verification is **optional**. If you skip it, Argus runs the L1
cascade and returns verdicts without sandbox-confirmed evidence.

DAST runs in Firecracker microVMs managed by Fly.io. You bring the Fly
account and pay Fly directly for sandbox time (~$0.05-0.20 per file
scanned). Argus's `SandboxClient` talks directly to your Fly machines API;
no scan content is ever routed through Argus infrastructure.

## What DAST does for you (v1.7)

Per L1 finding, Argus surfaces a Tier 1.5 validation status:

| Status | What it means |
|---|---|
| `CONFIRMED` | Sandbox observed the vulnerability actually being exploited. PoC + runtime evidence are surfaced. |
| `REJECTED` | Sandbox tested; no exploit fired AND no defense found — the L1 claim looks wrong. Strongest FP-reduction signal. |
| `BLOCKED` | Sandbox tested; the file's own code defended (sanitization, escaping, allowlist, etc.). |
| `UNREACHED` | Sandbox tested; the vulnerable code path can't be triggered from any tested input. |
| `NOT_TESTED` | Sandbox didn't conclusively validate. Sub-reason explains why: `infra_stub`, `inconclusive`, `not_planned`, `unfireable_pattern_cwe`, `budget_exceeded`, `non_python_file`, `unreachable_function`, `dast_not_attempted`. |

Plus opt-in extras:

- **Discovery** (`--enable-discovery`, v1.1+): proactive payload sweep —
  hardcoded library of attack payloads (CWE-78/89/22/79/502/918/611/94 +
  CWE-201/506 malware patterns). Finds CWEs L1 missed entirely.
- **Runtime probe** (Phase B+, v1.5; **default ON as of v1.8**): Sonnet
  generates concrete attack inputs per probe-attractive function; sandbox
  executes; findings come from observed runtime evidence rather than
  static analysis. Python-only. Opt out per scan with
  `--no-enable-runtime-probe`.
- **Phase 3 Stage 1** (v1.6; **default ON as of v1.8**): non-destructive
  behavioral exploration — imports the module, exercises every public
  callable with benign inputs, captures eval/exec/subprocess/pickle reach,
  file opens, network attempts. Opt out with
  `--no-enable-phase-3-discovery`.
- **Phase 3 Stage 2** (v1.6; **default ON as of v1.8**): adversarial
  reasoning loop. Model designs attack hypotheses anchored on Stage 1's
  observed behavior; sandbox tests them. Strategy B (rejection_signature)
  filters pre-declared rejection patterns; Strategy C (v1.8, post-trace
  LLM judge) gives a second opinion on CONFIRMED outcomes. Opt out with
  `--no-enable-phase-3-loop`.
- **Per-scan dep installer** (P2a v0.1, v1.8; **default ON**): parses
  the target file's `import X` statements, pip-installs missing
  packages into the sandbox before plan execution. Only fires when
  Phase A routes a plan to `rich_python` or `ml_tools` tier (lean
  stays minimal). Security contract: imports-only (NOT requirements.txt),
  `pip install --no-deps` (NO transitive deps installed). Eliminates
  the most common DAST failure mode — `NOT_TESTED:infra_stub` from
  missing modules. Opt out with `--no-enable-per-scan-dep-install`.

## Language coverage matrix

The Argus DAST sandbox image ships with multi-language runtimes
pre-installed. Discovery commands auto-dispatch by file extension:

| File extension | Runtime | Use case |
|---|---|---|
| `.py`, `.pth` | Python 3.13 | Python supply-chain (PyPI, sitecustomize, postinstall) |
| `.js`, `.mjs`, `.cjs` | Node.js (Debian default) | npm postinstall, malicious packages, AI tooling |
| `.ts`, `.jsx`, `.tsx` | Node.js (no transpile — runs as JS) | TypeScript supply-chain — security analysis on runtime behavior, not type checks |
| `.sh`, `.bash` | bash | Shell installer scripts |
| `.ipynb` | Python 3.13 (after Jupyter cell extraction) | Notebook supply-chain, embedded exploits |
| `.pkl`, `.pt`, `.safetensors`, `.h5`, `.onnx` | Python 3.13 + ML loaders | Model-loader exploits (pickled `__reduce__`, safetensors metadata) |
| `.class`, `.jar` | OpenJDK 17 JRE headless | Java/Kotlin/Scala — pre-compiled bytecode analysis |
| `.java` (source) | **Not yet** — needs JDK image rebuild | Java source files require `javac` |
| Other | python3 (fallback) | — |

**Not yet supported in DAST**: Go, Rust, C/C++, .NET, Java source. These
get **L1 cascade analysis** (verdict accuracy unaffected) but no runtime
DAST validation. Roadmap: `tasks.md` Phase E.

## What you need

- A Fly.io account ([fly.io](https://fly.io))
- `flyctl` CLI installed locally:
  - macOS / Linux: `curl -L https://fly.io/install.sh | sh`
  - Windows PowerShell: `iwr https://fly.io/install.ps1 -useb | iex`
- A payment method on file at [fly.io/dashboard/billing](https://fly.io/dashboard/billing).
  Free tier covers DAST sandbox usage but Fly requires a card.

## One-time setup

The full runbook with explanations is in
[`dast/sandbox/firecracker/MULTI_IMAGE.md`](https://github.com/dshochat/Argus/blob/main/dast/sandbox/firecracker/MULTI_IMAGE.md).
Short version:

```bash
# 0. Pick a globally-unique Fly app name. The default
#    `argus-dast-sandbox` is taken by the upstream project — Fly
#    app names are unique across ALL Fly accounts, so self-hosters
#    MUST pick their own. Convention: `argus-dast-<your-handle>`.
export ARGUS_DAST_FLY_APP=argus-dast-yourhandle
# Windows PowerShell:
#   $env:ARGUS_DAST_FLY_APP = "argus-dast-yourhandle"

# 1. Authenticate
flyctl auth login

# 2. Create the sandbox app + deploy initial machine config
cd dast/sandbox/firecracker
bash preflight.sh                # macOS / Linux / WSL
# or on Windows:
# $env:ARGUS_DAST_FLY_ORG = "personal"  # or your org slug
# ./preflight.ps1
# (Both scripts read $ARGUS_DAST_FLY_APP. If the name is taken on
#  another Fly account they print a clear actionable error.)

# 3. Generate a deploy-scoped token for Argus
flyctl tokens create deploy --app "$ARGUS_DAST_FLY_APP" --expiry 720h

# 4. Save the token in your .env (replace any existing value)
# FLY_API_TOKEN=<paste here>
# Also persist your app name choice so the scanner runtime can find it:
# ARGUS_DAST_FLY_APP=<your-app-name>

# 5. Build + push the three sandbox images (~10-90 min, mostly cached).
#    Reads $ARGUS_DAST_FLY_APP for the target app.
bash build_and_push_multi.sh

# 6. Set the image refs in .env (use the version tag the build script
#    emitted — defaults to v1, override with IMAGE_VERSION=vN).
#    Replace `<your-app>` below with your $ARGUS_DAST_FLY_APP value.
#    v1.8 P2b tier names — see "Migrating from v1.7" below if upgrading.
# ECHO_DAST_IMAGE_LEAN=registry.fly.io/<your-app>:lean-vN
# ECHO_DAST_IMAGE_RICH_PYTHON=registry.fly.io/<your-app>:rich_python-vN
# ECHO_DAST_IMAGE_ML_TOOLS=registry.fly.io/<your-app>:ml_tools-vN
```

After step 6, `argus scan` automatically invokes DAST on
`malicious` / `critical_malicious` verdicts. Use `--no-dast` to suppress
per scan.

### Image version tags

`build_and_push_multi.sh` uses `IMAGE_VERSION` (default `v1`) as the
tag suffix:

```bash
IMAGE_VERSION=v2 bash build_and_push_multi.sh
```

The three tags published per run are
`registry.fly.io/$ARGUS_DAST_FLY_APP:{lean,rich_python,ml_tools}-${IMAGE_VERSION}`.
Bump `IMAGE_VERSION` when you change a Dockerfile so old machines don't
silently pick up partial config from cache. Update the three
`ECHO_DAST_IMAGE_*` env vars in `.env` to match.

## The three sandbox images (v1.8 P2b tiers)

| Image | Contents | Use cases |
|---|---|---|
| `lean` | Python 3.13 + Node.js + npm + JRE + bash + coreutils + network CLI (`curl`, `wget`, `nc`, `dig`, `nslookup`, `openssl`) + ~30 common pip packages (requests, flask, fastapi, sqlalchemy, pandas, numpy, boto3, paramiko, redis, pymongo, pillow, cryptography, pyyaml, etc.) | **Default** for most plans. Pickle exploits, file I/O, subprocess, exfil chains (curl/wget/nc), DNS-exfil patterns. Floor tier with everything most malicious files need. |
| `rich_python` | lean + AI-fixture + data-adjacent libs: `scipy`, `scikit-learn`, `openai`, `anthropic`, `langchain-core`, `aiohttp`, `aiofiles`, `psutil`, `psycopg2-binary` | Files importing AI SDKs, numerical computing, async I/O, system introspection. Catches `ModuleNotFoundError:infra_stub` on popular gaps. |
| `ml_tools` | rich_python + torch (CPU) + transformers + safetensors + huggingface_hub | Model-loader exploits: malicious safetensors, pickled `__reduce__` payloads in `torch.load()`, custom-loader RCE. |

The orchestrator's plan generator picks `image_hint` per hypothesis. The
`MultiImageSandboxClient` routes accordingly; if the model picks an
unsupported hint (or omits one), it falls back to `lean`.

### Migrating from v1.7 (`minimal/networked` → `lean/rich_python`)

v1.8 P2b is a **hard rename** (no aliases):

| v1.7 → v1.8 | What changed |
|---|---|
| `minimal` → `lean` | Tier renamed. Network CLI tools (wget/nc/dnsutils/openssl) merged in from the retired `networked` image — they're available everywhere now since network egress is policy-layer, not image-layer. |
| `networked` → `rich_python` | Tier renamed + content shift. Network tools moved to `lean`. New pip packages added (scipy, scikit-learn, openai, anthropic, langchain-core, aiohttp, aiofiles, psutil, psycopg2-binary) to cover gaps surfaced in v1.7 zero-day hunting. |
| `ml_tools` → `ml_tools` | Unchanged. |
| `ECHO_DAST_IMAGE_MINIMAL` → `ECHO_DAST_IMAGE_LEAN` | Env var rename. |
| `ECHO_DAST_IMAGE_NETWORKED` → `ECHO_DAST_IMAGE_RICH_PYTHON` | Env var rename. |
| `Dockerfile` (was minimal) → `Dockerfile.lean` | File rename (git-tracked). |
| `Dockerfile.networked` → `Dockerfile.rich_python` | File rename (git-tracked). |
| `fly.toml` (was minimal) → `fly.lean.toml` | File rename. |
| `fly.networked.toml` → `fly.rich_python.toml` | File rename. |

Migration steps:

```bash
# 1. Rebuild + push under new tier names (~30-90 min — pulls fresh Python
#    base images and the rich_python new packages)
cd dast/sandbox/firecracker
bash build_and_push_multi.sh

# 2. Update .env: replace old env var names with new ones
#    (the build script prints the exact lines to paste at the end)

# 3. Verify with a sanity scan
uv run argus scan samples/regression_v1/preinstall.py --output markdown
```

If you forget to rebuild + update .env, Argus will log:
`DAST runner: ECHO_DAST_IMAGE_LEAN not set, but found v1.7 env var(s):
ECHO_DAST_IMAGE_MINIMAL → ECHO_DAST_IMAGE_LEAN; ...` and skip DAST.

## Per-scan flags

```bash
# Default: DAST runs on malicious / critical_malicious verdicts only
uv run argus scan path/to/file.py

# Trigger DAST on a broader set of L1 verdicts (~30-50% more API spend)
uv run argus scan path/to/file.py \
  --dast-trigger-verdicts suspicious,malicious,critical_malicious

# Strictest cost-controlled mode
uv run argus scan path/to/file.py --dast-trigger-verdicts critical_malicious

# DAST-204 proactive Discovery — runs payload library for new CWEs
uv run argus scan path/to/file.py --enable-discovery

# v1.8: Phase B+ + Phase 3 (Stage 1 + Stage 2) all default ON on
# `argus scan` and `argus scan-repo`. No flag needed — they fire
# whenever DAST itself fires (L1 verdict = malicious/critical_malicious).

# Opt out for a cost-sensitive scan (reverts to v1.7-equivalent
# L1 + Phase A only):
uv run argus scan path/to/file.py \
    --no-enable-runtime-probe \
    --no-enable-phase-3-discovery \
    --no-enable-phase-3-loop

# Or disable just Phase 3 Stage 2 but keep Phase B+ + Stage 1:
uv run argus scan path/to/file.py --no-enable-phase-3-loop

# Variants stay OPT-IN (still off by default):
uv run argus scan path/to/file.py --enable-runtime-probe-mutation  # 5x cost
uv run argus scan path/to/file.py --enable-runtime-probe-iterative
uv run argus scan path/to/file.py --enable-runtime-probe-chains

# v1.8: strict report-layer policy
# Never downgrades L1; suppresses only findings Phase A proved safe
# (BLOCKED/UNREACHED/REJECTED), never on infra/NOT_TESTED
uv run argus scan path/to/file.py --dast-required-policy strict

# Hard cost cap per file
uv run argus scan path/to/file.py --max-cost 0.50

# Skip DAST entirely (no Fly required)
uv run argus scan path/to/file.py --no-dast

# Phase C (fix-and-verify) — opt-in as of v1.8
# Generates patched source for CONFIRMED findings + replays original
# exploit against the patch. Was default-on through v1.7.
uv run argus scan path/to/file.py --enable-remediation
```

Most of these flags are also valid on `argus scan-repo` and `argus install`.
See `argus <subcommand> --help` for the exact list.

## Report-layer DAST policy (v1.8)

By default (`--dast-required-policy downgrade_cap`), DAST can downgrade
L1's verdict by up to 1 tier when its per-finding evidence suggests the
file is less severe than L1 claimed. This is the v1.1-v1.7 behavior.

`--dast-required-policy strict` (v1.8) inverts this:

- **Verdict**: L1's verdict is preserved unconditionally. DAST upgrades
  still apply; downgrades are refused.
- **Findings list**: only findings Phase A *actively proved safe* are
  suppressed (status `BLOCKED`, `UNREACHED`, or `REJECTED`).
- **Never suppressed in strict**: `NOT_TESTED` and all its sub-reasons.
  This is the contract — infra failures, budget exceeded, non-Python
  files, pattern-only CWEs the sandbox can't fire, etc. all keep their
  L1 finding visible because Phase A didn't conclusively run.

Use strict when you trust L1's static analysis and want to avoid sandbox
infra limitations downgrading real exploits (e.g., SSRF that needs a
real internal endpoint to demonstrate).

## Cost notes

- **Image storage + push**: $0.
- **Per-scan machine cost**: $0.05-0.20. Each plan creates one ephemeral
  microVM that runs for ~10-60 seconds, billed per second.
- **Anthropic inference**: dominates DAST cost (~$0.20-0.80 per scan,
  depends on iteration count + Phase B opt-ins).
- **Discovery additional cost** (`--enable-discovery`): ~$0.25/file.
- **Runtime probe additional cost** (`--enable-runtime-probe`):
  ~$0.20-0.50/file. With `--enable-runtime-probe-mutation` it can be
  ~5× higher (~$1.00-2.50/file). Use `--max-cost` to cap.
- **Phase 3 Stage 2** (`--enable-phase-3-loop`): ~$0.05-0.15/file +
  ~3 sandbox runs.

## Privacy / data flow

When DAST is enabled, your file content is shipped (gzip + base64) to
your own Fly app via the env-var protocol. The file is materialised at
`/workspace/<filename>` inside an ephemeral Firecracker microVM, executed,
observed via DNS hijack + capture server, and the VM is auto-destroyed
after the plan completes.

**Your code never leaves your Fly account.** Argus's SandboxClient talks
directly to your Fly machines API; nothing is routed through Argus
infrastructure.

For users without Fly accounts, run with `--no-dast` — Argus ships
meaningful verdicts via the L1 cascade alone.

## Telemetry & audit trails

DAST runs produce two local artifacts (gitignored, never uploaded):

| File | Purpose |
|---|---|
| `.argus_local/journal_records.jsonl` | Per-hypothesis log of accepted/rejected DAST claims with full rationale |
| `.argus_local/infra_gaps.jsonl` | When Phase A returned `NOT_TESTED:infra_stub`, the sub-cause (sandbox crash, image pull failure, etc.). Useful for diagnosing flaky sandbox runs. |

## Troubleshooting

**`flyctl: command not found` from Argus.**
flyctl is needed for log retrieval. If your Python process can't see it,
set `flyctl_path` explicitly when constructing `FirecrackerSandboxClient`,
or add flyctl's install dir to PATH.

**`organization <X> not found`** during `preflight.ps1`.
Your Fly org slug might not be `personal`. Run `flyctl orgs list` and
pass the right slug via `$env:ARGUS_DAST_FLY_ORG = "your-slug"`.

**`is_stub_no_trace=True` / "no events captured from machine"** in the
DAST journal.
The init script likely failed before the entrypoint ran. Most common
cause: CRLF line endings in `dast-init.sh` (Linux bash chokes on `\r`).
The repo's `.gitattributes` enforces LF on `*.sh` to prevent this; if
you've edited the script locally, verify with `file dast-init.sh`
(should NOT say "with CRLF line terminators"). You'll see this status in
the launch report as `NOT_TESTED:infra_stub`. Check
`.argus_local/infra_gaps.jsonl` for the specific failure reason.

**Verdict downgrade after DAST in default policy.**
The downgrade-cap rule (v1.2+) allows DAST to downgrade L1's verdict by
up to 1 tier when high-severity uncertain findings remain (severity-
driven). You'll see `dast_severity_downgrade:malicious->suspicious:<reason>`
in `scan_path`. If you don't want this — i.e., you want L1's verdict
preserved unconditionally — use `--dast-required-policy strict`.

**Discovery (CWE-204) finds 0 things on supply-chain malware files.**
Expected. Discovery v0.5's payload library targets web/app
vulnerabilities (CWE-78/89/22/79/502/918/611/94) plus malware patterns
(CWE-201/506). Pure data-exfil malware that doesn't take user input may
not match any CLI-injection pattern. The CWE-201 (any outbound network
call) and CWE-506 (persistence file writes) payloads will fire on most
active malware. If your file is benign-looking and no discovery payloads
fire, that's a correct outcome.

**Phase 3 Stage 2 produces `judge_verdict: REFUTED` on a CONFIRMED outcome.**
This is Strategy C (v1.8) working as designed. The post-trace LLM judge
gives a second opinion on each CONFIRMED hypothesis from the
single_function / stateful_sequence kinds. If the judge sees the trace
doesn't actually demonstrate the claim (e.g., a prep-step `fs_write`
failed, so the function returned empty data), it flips CONFIRMED to
REFUTED. The runtime_evidence is prefixed with `STRATEGY_C_REFUTED:` so
you can audit the judgment. Real L1 findings are still kept at the scan
level — Strategy C only affects Phase 3 Stage 2 sub-confirmations.

## Languages without DAST today

L1 cascade analysis works on any language Argus encounters. DAST per-
finding validation requires the file's runtime to be available in the
sandbox image. For files in unsupported languages:

- L1 verdict accuracy is unaffected
- `result.dast_attempted` will be `False` (gate didn't fire) or DAST
  runs but produces few traces
- `result.per_finding_validation` entries will mostly be
  `NOT_TESTED:not_planned` or `NOT_TESTED:non_python_file`

Roadmap (`tasks.md` Phase E):
- DAST-206 phase 2: Go runtime
- DAST-206 phase 3: Rust runtime
- DAST-206 phase 4: .NET / C#

For these languages today, treat L1 verdicts as the primary signal;
consult per-finding metadata for severity/confidence.
