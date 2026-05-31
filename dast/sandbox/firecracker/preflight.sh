#!/usr/bin/env bash
# Argus DAST Firecracker preflight — runs from your dev workstation.
# Verifies Fly.io setup is ready for DAST verification.
#
# Usage (BYOK self-hosters MUST set ARGUS_DAST_FLY_APP first):
#   export ARGUS_DAST_FLY_APP=your-globally-unique-name
#   cd dast/sandbox/firecracker
#   bash preflight.sh
#
# Side effects:
#   * Creates the Fly.io app named $ARGUS_DAST_FLY_APP if it doesn't
#     exist (default: argus-dast-sandbox)
#   * Builds + pushes the Dockerfile to Fly's registry
#   * Does NOT start any machines — the orchestrator does that per call.
#
# Fly app-name collision:
#   Fly app names are GLOBALLY unique across all Fly accounts. The
#   default ``argus-dast-sandbox`` is already claimed by the upstream
#   Argus project. Self-hosters MUST pick their own name and set
#   ``ARGUS_DAST_FLY_APP`` before running this script — the same
#   value must then be set in your shell at scan time so the runtime
#   client points at YOUR app. See README "DAST setup".
#
# Cost: $0 (image build + registry push are free; machines are billed
# only when running)

set -euo pipefail

# Read app name from env var (preferred) with a sensible fallback for
# upstream-Argus contributors. Self-hosters MUST override — the
# default is taken on Fly's globally-unique namespace.
APP_NAME="${ARGUS_DAST_FLY_APP:-${APP_NAME:-argus-dast-sandbox}}"
REGION="${REGION:-iad}"
# Fly org slug. Defaults to "personal"; override via $ARGUS_DAST_FLY_ORG.
ORG="${ARGUS_DAST_FLY_ORG:-personal}"

echo "=== Argus DAST Firecracker preflight ==="
echo "App: ${APP_NAME}  Region: ${REGION}  Org: ${ORG}"
echo

# 1. flyctl present
if ! command -v flyctl &> /dev/null; then
    echo "FAIL flyctl not installed."
    echo "    Install: https://fly.io/docs/flyctl/install/"
    exit 1
fi
echo "ok  flyctl: $(flyctl version 2>&1 | head -n1)"

# 2. authenticated
if ! flyctl auth whoami &> /dev/null; then
    echo "FAIL not authenticated."
    echo "    Run: flyctl auth login"
    exit 1
fi
echo "ok  auth: $(flyctl auth whoami)"

# 3. payment method is on file (cannot easily check via CLI; document)
echo "??  payment method on file at https://fly.io/dashboard/billing"
echo "    (Cannot verify via CLI — check manually before proceeding)"

# 4. app exists in YOUR account, or create. Three cases:
#    a) app already in your account → reuse (idempotent)
#    b) app doesn't exist anywhere → create it
#    c) app exists in SOMEONE ELSE's account → flyctl create errors
#       with "name has already been taken". Catch + give a clear
#       actionable error explaining Fly's globally-unique namespace.
if flyctl apps list --json 2>&1 | grep -q "\"$APP_NAME\""; then
    echo "ok  app exists in your account: $APP_NAME"
else
    echo "→   creating app $APP_NAME in org $ORG..."
    if ! create_out=$(flyctl apps create "$APP_NAME" --org "$ORG" 2>&1); then
        if echo "$create_out" | grep -qiE "name has already been taken|name already in use|already exists"; then
            cat <<EOF >&2

FAIL Fly app name '$APP_NAME' is already taken on another account.

    Fly app names are GLOBALLY unique across all Fly accounts.
    The default 'argus-dast-sandbox' is claimed by the upstream
    Argus project — self-hosters need a different name.

    Pick a globally-unique name (e.g., 'argus-dast-<your-handle>')
    and re-run preflight with:

        export ARGUS_DAST_FLY_APP=argus-dast-<your-handle>
        bash preflight.sh

    The same name must then be exported in your scan-time shell
    so the orchestrator points at YOUR app:

        # in .env or your shell:
        ARGUS_DAST_FLY_APP=argus-dast-<your-handle>

    flyctl raw output:
$(echo "$create_out" | sed 's/^/      /')
EOF
            exit 2
        fi
        echo "FAIL flyctl apps create failed: $create_out" >&2
        exit 1
    fi
    echo "ok  app created"
fi

# 5. deploy image (remote build to avoid local Docker)
echo "→   deploying sandbox image..."
flyctl deploy \
    --app "$APP_NAME" \
    --remote-only \
    --no-public-ips \
    --strategy immediate \
    --auto-confirm
echo "ok  image deployed"

# 6. confirm no machines are running unexpectedly
echo "—   current machines (should be empty until orchestrator runs):"
flyctl machines list --app "$APP_NAME" || true

# 7. emit a token for the orchestrator to use
echo
echo "=== Preflight complete ==="
echo
echo "Next step: emit a deploy-scoped API token for the orchestrator."
echo "Run from your workstation:"
echo "    flyctl tokens create deploy --app $APP_NAME --expiry 720h"
echo "Save the token to C:/WEB/argus/.env as:"
echo "    FLY_API_TOKEN=<token>"
echo
echo "Then notify Claude that preflight passed."
