# DAST sandbox setup

Enable Finding Validation + Remediation by standing up a sandbox. After
this, every suspicious / malicious verdict triggers runtime confirmation
+ auto-patch + exploit-replay against the patch.

Without DAST, Argus runs L1 cascade only — still useful, but no sandbox-
grounded `CONFIRMED` evidence and no Remediation.

## Choose a substrate

Argus runs each exploit in a throwaway sandbox. You pick **where** those
sandboxes run with the `ARGUS_DAST_RUNTIME` env var:

| Substrate | `ARGUS_DAST_RUNTIME` | Runs where | Best for |
|---|---|---|---|
| **gVisor (local)** | `gvisor` | Local Docker + the gVisor (`runsc`) runtime — your own host or k8s node | **Self-hosted default.** No cloud account, no egress, no per-VM bill. BYO compute. |
| **Fly.io (managed)** | `fly` *(default)* | Ephemeral Firecracker microVMs on your Fly account | Zero local infra; pay-per-VM; good for laptops / CI without Docker. |

Both run the **same image** and produce the **same evidence** — only the
launcher differs. gVisor is the recommended default for a self-hosted,
customer-friendly deployment: sandboxes execute as local `runsc`
containers with `--network=none`, so there's no managed cloud in the loop
and no real egress. Pick one and follow Option A or Option B below.

---

## Option A — Self-hosted (gVisor, recommended)

Run sandboxes as local Docker containers under the gVisor (`runsc`)
runtime. No Fly account, no `FLY_API_TOKEN`. Works on any Linux host or
Kubernetes node (via a `RuntimeClass`) with Docker + gVisor installed.

### Prereqs

- **Docker** (running).
- **gVisor** (`runsc`) installed and registered as a Docker runtime. On a
  stock Ubuntu host:

  ```bash
  # Install runsc from the gVisor apt repo
  curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
  sudo apt-get update && sudo apt-get install -y runsc
  # Register with Docker + restart, then verify
  sudo runsc install && sudo systemctl restart docker
  docker info --format '{{json .Runtimes}}'   # should list "runsc"
  ```

  No nested virtualization required (gVisor's `systrap` platform). On
  Kubernetes, install gVisor on the node and add a `RuntimeClass` named
  `runsc`.

### Setup (2 steps)

```bash
# 1. Build the sandbox images into your LOCAL Docker daemon.
#    First run ~10-20 min (apt/npm/pip layers); cached on rebuilds.
#    `lean` alone covers most exploits; build all three for full coverage.
cd dast/sandbox/firecracker
bash build_local.sh                 # or: bash build_local.sh lean

# 2. Verify with a known-vulnerable scan
cd ../../..
ARGUS_DAST_RUNTIME=gvisor argus scan samples/regression_v1/high_with_vuln.py
```

If the scan prints `dast_attempted: True` with `CONFIRMED` findings,
you're done.

### .env vars

```env
# Select the self-hosted substrate (no FLY_API_TOKEN needed)
ARGUS_DAST_RUNTIME=gvisor
# Local image tags (defaults shown — build_local.sh prints these).
# RICH_PYTHON / ML_TOOLS fall back to LEAN when unset.
ARGUS_DAST_GVISOR_IMAGE_LEAN=argus-dast-sandbox:lean
ARGUS_DAST_GVISOR_IMAGE_RICH_PYTHON=argus-dast-sandbox:rich_python
ARGUS_DAST_GVISOR_IMAGE_ML_TOOLS=argus-dast-sandbox:ml_tools
# Optional knobs:
#   ARGUS_DAST_GVISOR_RUNTIME=runsc   # OCI runtime name (default runsc)
#   ARGUS_DAST_GVISOR_NETWORK=none    # docker network mode; none = no egress
```

### Egress control

The default `ARGUS_DAST_GVISOR_NETWORK=none` gives each sandbox only a
loopback interface — **no real egress**. The in-VM capture server binds
`127.0.0.1:53/80/443` and the sandbox's DNS is hijacked to it, so every
hostname an exploit resolves is logged (and answered locally) while
nothing leaves the host — a stronger guarantee than the managed path
(the network interface is genuinely absent). Operators who need a
controlled egress allowlist can point `ARGUS_DAST_GVISOR_NETWORK` at a
custom Docker network.

### Notes

- **Privacy:** file content never leaves your host — it's passed to a
  local container via env var, materialized in `/workspace`, executed,
  then the container is removed. No cloud, no Argus infrastructure.
- **Syscall observability:** the bpftrace kernel-tracing layer is
  Firecracker-only (gVisor's user-space kernel has no kprobes); under
  gVisor it is skipped cleanly and validation falls back to
  language-level instrumentation. Verdicts are unaffected.
- **Rebuilds:** when you change a shared component (`dast-init.sh`,
  `dast-capture-server.py`, `entrypoint.py`) re-run `build_local.sh` to
  rebuild the affected tier(s).

---

## Option B — Managed (Fly.io)

**One-time, ~10-30 min.** Sandboxes run as ephemeral Firecracker microVMs
on your own Fly.io account.

### Prereqs

- A [Fly.io account](https://fly.io) with a payment method on file
  (free tier covers DAST usage; Fly requires a card)
- The `flyctl` CLI:
  - macOS / Linux / WSL: `curl -L https://fly.io/install.sh | sh`
  - Windows PowerShell: `iwr https://fly.io/install.ps1 -useb | iex`

### Setup (6 commands)

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

### .env vars

Add these to your `.env` (the `.env.example` already has them — just
fill in the values from steps 1, 4, and 5):

```env
# Required for DAST
FLY_API_TOKEN=fly_token_from_step_4
ARGUS_DAST_FLY_APP=argus-dast-yourhandle
# IMPORTANT: copy the EXACT image refs that build_and_push_multi.sh
# printed at the end of step 5 — do not hardcode the version below.
# The `-v1` here is only the default for a first build; `<N>` increments
# every time you rebuild a Dockerfile (so a re-run with IMAGE_VERSION=v2
# yields `:lean-v2`, etc.).
ECHO_DAST_IMAGE_LEAN=registry.fly.io/argus-dast-yourhandle:lean-v<N>
ECHO_DAST_IMAGE_RICH_PYTHON=registry.fly.io/argus-dast-yourhandle:rich_python-v<N>
ECHO_DAST_IMAGE_ML_TOOLS=registry.fly.io/argus-dast-yourhandle:ml_tools-v<N>
```

The image tags follow the pattern
`registry.fly.io/<your-app>:<tier>-v<N>` where `<N>` matches
`IMAGE_VERSION` from step 5 (default `v1`; override with
`IMAGE_VERSION=v2 bash build_and_push_multi.sh` when you change a
Dockerfile). The build script prints the exact `ECHO_DAST_IMAGE_*`
lines to paste — use those rather than guessing the version. **All
three tiers must be rebuilt together when you change a shared component
(e.g. `dast-capture-server.py` / `dast-init.sh` / `entrypoint.py`),
since they bake the same scripts.**

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
| Sandbox infra — **gVisor (self-hosted)** | **$0** — runs on your own host/node; no per-VM bill |
| Sandbox infra — **Fly** machine time per scan | $0.05–$0.20 (one ephemeral microVM, runs 10-60s, per-second billed) |
| Anthropic inference per scan | $0.20–$0.80 (default cascade) |
| Image storage / build | $0 |

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
