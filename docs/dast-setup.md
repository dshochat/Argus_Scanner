# DAST sandbox setup

Enable Finding Validation + Remediation by standing up your own Fly.io
sandbox. **One-time, ~10-30 min.** After this, every suspicious /
malicious verdict triggers runtime confirmation + auto-patch +
exploit-replay against the patch.

Without DAST, Argus runs L1 cascade only — still useful, but no sandbox-
grounded `CONFIRMED` evidence and no Remediation.

## Prereqs

- A [Fly.io account](https://fly.io) with a payment method on file
  (free tier covers DAST usage; Fly requires a card)
- The `flyctl` CLI:
  - macOS / Linux / WSL: `curl -L https://fly.io/install.sh | sh`
  - Windows PowerShell: `iwr https://fly.io/install.ps1 -useb | iex`

## Setup (6 commands)

```bash
# 1. Pick your own globally-unique Fly app name. The default
#    `argus-dast-sandbox` is taken — self-hosters MUST pick their own.
#    Convention: argus-dast-<your-handle>
export ARGUS_DAST_FLY_APP=argus-dast-yourhandle
#  Windows PowerShell:
#    $env:ARGUS_DAST_FLY_APP = "argus-dast-yourhandle"

# 2. Authenticate
flyctl auth login

# 3. Create the sandbox app + initial machine config
cd dast/sandbox/firecracker
bash preflight.sh
#  Windows PowerShell:
#    $env:ARGUS_DAST_FLY_ORG = "personal"   # or your org slug
#    ./preflight.ps1

# 4. Generate a deploy-scoped Fly token (30-day expiry)
flyctl tokens create deploy --app "$ARGUS_DAST_FLY_APP" --expiry 720h

# 5. Build + push the three sandbox images
#    First run: ~10-30 min. Cached on rebuilds.
bash build_and_push_multi.sh

# 6. Verify with a known-vulnerable scan
cd ../../..
argus scan samples/regression_v1/high_with_vuln.py
```

If step 6 prints `dast_attempted: True` with `CONFIRMED` findings,
you're done.

## .env vars

Add these to your `.env` (the `.env.example` already has them — just
fill in the values from steps 1, 4, and 5):

```env
# Required for DAST
FLY_API_TOKEN=fly_token_from_step_4
ARGUS_DAST_FLY_APP=argus-dast-yourhandle
ECHO_DAST_IMAGE_LEAN=registry.fly.io/argus-dast-yourhandle:lean-v1
ECHO_DAST_IMAGE_RICH_PYTHON=registry.fly.io/argus-dast-yourhandle:rich_python-v1
ECHO_DAST_IMAGE_ML_TOOLS=registry.fly.io/argus-dast-yourhandle:ml_tools-v1
```

The image tags follow the pattern
`registry.fly.io/<your-app>:<tier>-v<N>` where `<N>` matches
`IMAGE_VERSION` from step 5 (default `v1`; override with
`IMAGE_VERSION=v2 bash build_and_push_multi.sh` when you change a
Dockerfile).

## The three sandbox tiers

The orchestrator picks one per probe; `lean` covers most cases.

| Tier | What's in it | Used for |
|---|---|---|
| `lean` | Python 3.13 + Node + JRE + bash + network CLI + ~30 common pip packages (requests, flask, sqlalchemy, pandas, numpy, boto3, cryptography, pyyaml, etc.) | Default. Most pickle/file/subprocess/exfil exploits. |
| `rich_python` | `lean` + scipy, scikit-learn, openai, anthropic, langchain-core, aiohttp, psutil, psycopg2-binary | Files importing AI SDKs / data libs |
| `ml_tools` | `rich_python` + torch (CPU) + transformers + safetensors + huggingface_hub | Model-loader exploits (malicious safetensors, pickled `__reduce__` in `torch.load()`) |

`ECHO_DAST_IMAGE_RICH_PYTHON` and `ECHO_DAST_IMAGE_ML_TOOLS` are
optional — if unset, the orchestrator falls back to `lean` for every
plan.

## Costs

| Item | Typical |
|---|---|
| Fly machine time per scan | $0.05–$0.20 (one ephemeral microVM, runs 10-60s, per-second billed) |
| Anthropic inference per scan | $0.20–$0.80 (default cascade) |
| Image storage + push | $0 |

Cap per-file spend with `--max-cost 1.00` (default is $1.00).

## Privacy

Your file content is shipped to **your own Fly app** via gzip+base64
env vars, materialized at `/workspace/<filename>` inside an ephemeral
microVM, executed under bpftrace observation, then the VM is destroyed.
**Argus has no infrastructure in the loop** — `SandboxClient` talks
directly to your Fly machines API.

## Troubleshooting

**`dast_attempted: False` even though my file landed suspicious.**
Almost always missing or stale env vars. Run this from your project dir:

```bash
python -c "
import os
from dotenv import load_dotenv
load_dotenv(override=True)
from dast.runner import make_dast_runner_from_env
print('dast_runner created:', make_dast_runner_from_env() is not None)
"
```

If False, check `FLY_API_TOKEN`, `ECHO_DAST_IMAGE_LEAN`, and
`ARGUS_DAST_FLY_APP` are all set with non-empty values.

**`name has already been taken`** during `preflight.sh` / `preflight.ps1`.
Fly app names are globally unique across all Fly accounts. The default
`argus-dast-sandbox` is taken. Pick your own via
`export ARGUS_DAST_FLY_APP=argus-dast-yourhandle` and re-run.

**`organization not found`** during `preflight.ps1`.
Your Fly org slug might not be `personal`. Run `flyctl orgs list` and
pass the right slug:
`$env:ARGUS_DAST_FLY_ORG = "your-slug"`.

**Old env var names from v1.7** (`ECHO_DAST_IMAGE_MINIMAL` /
`ECHO_DAST_IMAGE_NETWORKED`). Renamed in v1.8 to `LEAN` / `RICH_PYTHON`.
Rename in your `.env` and rebuild images via `build_and_push_multi.sh`.

**`is_stub_no_trace=True`** in scan output. The sandbox init script
failed before the entrypoint ran. Most common cause: CRLF line endings
in `dast-init.sh`. The repo's `.gitattributes` enforces LF on `*.sh`;
if you edited the script locally, verify with `file dast-init.sh`
(should NOT say "with CRLF line terminators").

**Bumping image versions.** When you change a Dockerfile, build with
a fresh tag suffix so Fly machines pick up the new digest:

```bash
IMAGE_VERSION=v2 bash build_and_push_multi.sh
# then update the three ECHO_DAST_IMAGE_* vars in .env to use :tier-v2
```
