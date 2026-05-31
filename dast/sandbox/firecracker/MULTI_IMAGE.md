# Argus DAST sandbox deploy — runbook (DAST-106, v1.8 P2b)

Stand up the `argus-dast-sandbox` Fly app and push the three sandbox
images (`lean` / `rich_python` / `ml_tools`) for Phase 3 DAST verification.

> **v1.8 P2b note:** image tier names were renamed from
> `minimal / networked / ml_tools` (hard rename, no aliases). See the
> migration table in `docs/dast-setup.md` if you're upgrading from v1.7.

**Wall clock:** ~30 min active hands-on for first-time install + app
creation, plus ~50-90 minutes of unattended Fly remote-builder time
for the three image builds.

**Cost:** $0 for image storage + push. Machines are billed only when
running (Fly free tier covers light DAST usage).

**Why this is human-run, not agent-run:** the steps require local
toolchain installation (flyctl), interactive auth (`flyctl auth login`
in a browser), and Fly resource creation (the deploy-scoped token in
`.env` cannot create new apps — only an account-level session can).

---

## What this deploy does

Pushes three images to the existing `argus-dast-sandbox` Fly app under
explicit tags:

| Tag | Image | Size | Use cases |
|---|---|---|---|
| `:lean-v1` | Python stdlib + nodejs/java + base shell utils + network CLI (curl/wget/nc/dnsutils/openssl) + ~30 common pip pkgs | ~480 MB | Default. Floor tier — has everything most plans need. |
| `:rich_python-v1` | lean + AI-fixture + data-adjacent libs (scipy, scikit-learn, openai, anthropic, langchain-core, aiohttp, aiofiles, psutil, psycopg2-binary) | ~630 MB | Files importing AI SDKs, numerical computing, async I/O. |
| `:ml_tools-v1` | rich_python + torch CPU + transformers + safetensors + huggingface_hub | ~3 GB | ML-loader exploit confirmation (load_distributed_checkpoint, megatron_gpt2_loader, perceiver_model_loader) |

The orchestrator picks the right image per plan via the `image_hint`
field in each `SandboxPlan` (already plumbed in PR #52 — see
`scripts/dast_prototype/dast_005_design.md`).

---

## Prerequisites

If this is your first DAST deploy, do these once (~10 min total):

1. **Install flyctl**
   - macOS / Linux: `curl -L https://fly.io/install.sh | sh`
   - Windows PowerShell: `iwr https://fly.io/install.ps1 -useb | iex`
   - Verify: `flyctl version` should print >= 0.3.x
2. **Authenticate**: `flyctl auth login` (opens browser)
3. **Confirm payment method** is on file at
   [fly.io/dashboard/billing](https://fly.io/dashboard/billing). Free
   tier covers DAST sandbox usage but Fly requires a card on file.

Then for each fresh Argus install:

4. **Run preflight** to create the `argus-dast-sandbox` app and deploy
   the initial Dockerfile:

   ```bash
   cd dast/sandbox/firecracker
   bash preflight.sh           # macOS / Linux / WSL
   # or on Windows native:
   ./preflight.ps1
   ```

5. **Generate a deploy-scoped token** for the orchestrator:

   ```bash
   flyctl tokens create deploy --app argus-dast-sandbox --expiry 720h
   ```

6. **Save the token** to `C:/WEB/argus/.env`:

   ```env
   FLY_API_TOKEN=<paste here>
   ```

---

## Step 1 — Build + push all three images

From your dev workstation (Mac, Linux, or WSL):

```bash
cd C:/WEB/argus/dast/sandbox/firecracker
bash build_and_push_multi.sh
```

This sequentially:

1. Builds `Dockerfile.lean` on Fly's remote builder, pushes as
   `registry.fly.io/argus-dast-sandbox:lean-v1` (~5-10 min)
2. Builds `Dockerfile.rich_python`, pushes as `:rich_python-v1` (~5-10 min)
3. Builds `Dockerfile.ml_tools`, pushes as `:ml_tools-v1` (~30-60 min
   — torch CPU wheels are heavy)

**Total wall-clock: ~50-90 min.** You can let it run unattended; the
script is idempotent and `set -euo pipefail` so any failure aborts
cleanly.

If you want to build only one image (e.g. iterating on `ml_tools`):

```bash
bash build_and_push_multi.sh ml_tools
```

If you want to bump the version suffix (e.g. for a v2 rollout that
shouldn't displace v1):

```bash
IMAGE_VERSION=v2 bash build_and_push_multi.sh
```

The script emits the resulting image refs at the end. Save them.

---

## Step 2 — Set the image-tag env vars

The orchestrator reads three env vars (see
`dast/sandbox/multi_image_wiring.py`). Add them to
`C:/WEB/argus/.env`:

```env
ECHO_DAST_IMAGE_LEAN=registry.fly.io/argus-dast-sandbox:lean-v1
ECHO_DAST_IMAGE_RICH_PYTHON=registry.fly.io/argus-dast-sandbox:rich_python-v1
ECHO_DAST_IMAGE_ML_TOOLS=registry.fly.io/argus-dast-sandbox:ml_tools-v1
```

Use the exact tags emitted by `build_and_push_multi.sh` in case the
`IMAGE_VERSION` was overridden.

---

## Step 3 — Smoke-test each image

One-shot machine create + verify expected binaries exist + auto-destroy:

```bash
# lean — should see python + node + java + curl + wget + nc + dig + openssl
flyctl machines run \
  --app argus-dast-sandbox \
  --rm \
  "$ECHO_DAST_IMAGE_LEAN" \
  -- bash -c 'python --version && node --version && java -version 2>&1 && curl -V && wget -V && nc -h 2>&1 | head -1 && dig -v 2>&1 && openssl version'

# rich_python — should additionally import scipy + sklearn + openai + anthropic
flyctl machines run \
  --app argus-dast-sandbox \
  --rm \
  "$ECHO_DAST_IMAGE_RICH_PYTHON" \
  -- python -c "import scipy, sklearn, openai, anthropic, langchain_core; print('OK rich_python')"

# ml_tools — should additionally import torch + transformers + safetensors
flyctl machines run \
  --app argus-dast-sandbox \
  --rm \
  "$ECHO_DAST_IMAGE_ML_TOOLS" \
  -- python -c "import torch, transformers, safetensors, huggingface_hub; print('OK', torch.__version__)"
```

Each should print expected version output and exit 0. If `ml_tools`
imports fail, re-build with `bash build_and_push_multi.sh ml_tools`.

---

## Step 4 — Wire `MultiImageSandboxClient` into the production scanner

This is **DAST-015**. The plumbing in PR #52 exposes
`MultiImageSandboxClient` from `scripts/dast_prototype/sandbox_client`
and a config helper from `scripts/dast_prototype/_multi_image_wiring`.

When the production `dast/sandbox/` module is being built (separate
session):

```python
from scripts.dast_prototype._multi_image_wiring import (
    MultiImageWiringConfig,
    build_multi_image_sandbox,
)

# At scanner startup:
config = MultiImageWiringConfig.from_env(
    fly_app_name="argus-dast-sandbox",
    require_all_images=False,  # tolerate partial deployments
)
sandbox = build_multi_image_sandbox(config, file_content_map=file_contents)

# Drop into orchestrator like the existing single-image client:
result = await run_dast(
    file_record=file_record,
    l1_output=l1_output,
    sandbox=sandbox,                        # was FirecrackerSandboxClient
    validator=validator,
    journal_dir=journal_dir,
    inference=inference,
)
```

`MultiImageSandboxClient` satisfies the same `SandboxClient` Protocol
the orchestrator uses — no orchestrator changes needed.

---

## Step 5 — Validate against the campaign target files

After Steps 1-4 land, run the methodology N=3 evaluation:

```bash
# Baseline N=3 with multi-image plumbing dormant (image_hint=lean default
# — same effective behavior as single-image)
for i in 1 2 3; do
  uv run python scripts/dast_prototype/_run_full_regression_fireworks.py
  mv scripts/dast_prototype/results/_full_regression_fireworks.json \
     scripts/dast_prototype/results/_eval_before_$i.json
done

# After-state N=3 with multi-image active (planner now emits non-lean
# image_hint values per the prompt rule §9)
for i in 1 2 3; do
  uv run python scripts/dast_prototype/_run_full_regression_fireworks.py
  mv scripts/dast_prototype/results/_full_regression_fireworks.json \
     scripts/dast_prototype/results/_eval_after_$i.json
done

# Compare with confidence-interval gate
uv run python scripts/dast_prototype/_run_per_fix_evaluation.py \
    --before scripts/dast_prototype/results/_eval_before_*.json \
    --after  scripts/dast_prototype/results/_eval_after_*.json \
    --min-z 1.0
```

Expected unlocks (per the path-to-80% projection in `ROADMAP.md`):

- `litellm_obfuscated.py`     — exfil confirmation in `lean` (curl/wget/nc available)
- `audit_log_compression.py`  — same
- `event_stream_flatmap_compromise.js` — same
- `sandbox_runner.js`         — same
- `load_distributed_checkpoint.py` (probably) — ml_tools loader test
- `megatron_gpt2_loader.py` (probably)        — same
- `perceiver_model_loader.py` (probably)      — same

Pass criterion: `lift_detected: true` at `min_z=1.0` AND zero Tier 1/2
regressions in the `per_file_changes` block.

---

## Rollback

If `ml_tools` causes per-call latency to spike unacceptably (cold
boot of a 3 GB image is ~5-10 seconds extra):

1. Set `ECHO_DAST_IMAGE_ML_TOOLS` to the same value as
   `ECHO_DAST_IMAGE_RICH_PYTHON`. Plans requesting `ml_tools` will route
   to rich_python. Loses ML-loader confirmation but everything else
   works.
2. Or unset `ECHO_DAST_IMAGE_ML_TOOLS` entirely. The wiring config
   skips it; plans fall back to `lean`.

Either revert is configuration-only. No code change, no redeploy.

---

## Troubleshooting

**`flyctl deploy --build-only` not recognized.** Update flyctl: `flyctl version update`. Need >= 0.3.

**Build fails on `ml_tools` with "no space left on device".** Fly's remote builder has a per-build disk cap. Re-run; transient. If it persists, prune unused images: `flyctl image prune --app argus-dast-sandbox`.

**Smoke test ml_tools machine hangs at "import torch".** Cold boot — the import takes 4-8 seconds first time. Wait ~15s before assuming hang.

**`HF_HUB_OFFLINE=1` causing legitimate test plans to fail.** This is by design — sandbox is air-gapped. If a test plan genuinely needs to download a HF model, populate `/workspace/.cache/huggingface/` before invocation (e.g. via the entrypoint's `FILE_CONTENT_B64GZ` mechanism extended to arbitrary cache files). Out of scope for the v1 deploy.
