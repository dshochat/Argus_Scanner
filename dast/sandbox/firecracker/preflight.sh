#!/usr/bin/env bash
# Argus DAST Firecracker preflight — runs from your dev workstation.
# Verifies Fly.io setup is ready for Step 2 work.
#
# Usage:
#   cd scripts/dast_prototype/firecracker
#   bash preflight.sh
#
# Side effects:
#   * Creates the Fly.io app `argus-dast-sandbox` if it doesn't exist
#   * Builds + pushes the Dockerfile to Fly's registry
#   * Does NOT start any machines — the orchestrator does that per call.
#
# Cost: $0 (image build + registry push are free; machines are billed
# only when running)

set -euo pipefail

APP_NAME="${APP_NAME:-argus-dast-sandbox}"
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

# 4. app exists or create
if flyctl apps list --json 2>&1 | grep -q "\"$APP_NAME\""; then
    echo "ok  app exists: $APP_NAME"
else
    echo "→   creating app $APP_NAME..."
    flyctl apps create "$APP_NAME" --org "$ORG"
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
echo "Save the token to your .env as:"
echo "    FLY_API_TOKEN=<token>"
echo
echo "Preflight complete."
