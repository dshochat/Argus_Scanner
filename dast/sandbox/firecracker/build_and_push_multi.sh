#!/usr/bin/env bash
# Argus DAST multi-image build + push — DAST-014.
#
# Builds the three sandbox images (minimal / networked / ml_tools) and
# pushes them to the Fly.io registry under explicit tags. Idempotent —
# safe to re-run; only re-pushes images whose Dockerfile changed.
#
# Each image is a separate `flyctl deploy` against the SAME Fly app
# (`argus-dast-sandbox`). Different deploys produce different image
# refs in the registry, distinguished by the explicit `--image-label`
# tag. The orchestrator picks the right ref per plan via the
# ``ECHO_DAST_IMAGE_*`` env vars (see `_multi_image_wiring.py`).
#
# Why one app, three tags (vs three apps):
#   * Same auth token works for all three deploys
#   * Same fly.toml (no inbound services, no public IP, no mounts)
#   * Per-machine Fly API call selects the image ref independently of
#     the app's "current" deploy state
#   * Tagging is the natural Fly-native versioning unit
#
# Usage:
#   cd scripts/dast_prototype/firecracker
#   bash build_and_push_multi.sh                # build + push all three
#   bash build_and_push_multi.sh networked      # one image only
#   bash build_and_push_multi.sh ml_tools       # heavier — ~30-60 min
#   IMAGE_VERSION=v2 bash build_and_push_multi.sh   # override version suffix
#
# Side effects:
#   * Build happens on Fly's remote builder (no local Docker required)
#   * Each push tags `registry.fly.io/argus-dast-sandbox:<image>-<version>`
#   * Does NOT start any machines — the orchestrator does that per call
#
# Cost: $0 for the registry pushes themselves. Machines are billed only
# when running.
#
# Required state before running:
#   * `flyctl auth login` already done
#   * App `argus-dast-sandbox` exists (run `preflight.sh` once if not)
#   * `flyctl version` >= 0.3.x

set -euo pipefail

APP_NAME="${APP_NAME:-argus-dast-sandbox}"
IMAGE_VERSION="${IMAGE_VERSION:-v1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Image taxonomy → fly.toml config file (each pins its own Dockerfile).
# We need separate fly.toml files because flyctl deploy ignores the
# CLI ``--dockerfile`` flag when ``[build] dockerfile`` is set in the
# config — the config wins. Per-image config files unambiguously
# select the right Dockerfile.
declare -A IMAGES=(
    ["minimal"]="fly.toml"
    ["networked"]="fly.networked.toml"
    ["ml_tools"]="fly.ml_tools.toml"
)

# Allow building a single image when an arg is passed.
if [ $# -gt 0 ]; then
    REQUESTED="$1"
    if [ -z "${IMAGES[$REQUESTED]:-}" ]; then
        echo "FAIL unknown image: $REQUESTED"
        echo "    valid: minimal | networked | ml_tools"
        exit 2
    fi
    BUILD_LIST=("$REQUESTED")
else
    BUILD_LIST=("minimal" "networked" "ml_tools")
fi

echo "=== Argus DAST multi-image build + push ==="
echo "App:     ${APP_NAME}"
echo "Version: ${IMAGE_VERSION}"
echo "Images:  ${BUILD_LIST[*]}"
echo

# Preflight checks — same as preflight.sh but lighter (assumes app
# already exists; just verifies tools are wired).

if ! command -v flyctl &> /dev/null; then
    echo "FAIL flyctl not installed — see https://fly.io/docs/flyctl/install/"
    exit 1
fi

if ! flyctl auth whoami &> /dev/null; then
    echo "FAIL not authenticated — run 'flyctl auth login'"
    exit 1
fi

if ! flyctl apps list --json 2>&1 | grep -q "\"$APP_NAME\""; then
    echo "FAIL app '$APP_NAME' does not exist — run 'preflight.sh' first"
    exit 1
fi

# Build + push each image.
declare -A PUSHED_REFS
for IMG in "${BUILD_LIST[@]}"; do
    CONFIG="${IMAGES[$IMG]}"
    TAG="${IMG}-${IMAGE_VERSION}"
    REF="registry.fly.io/${APP_NAME}:${TAG}"

    echo
    echo "------------------------------------------------------------"
    echo "  Building: $IMG"
    echo "  Config:     $CONFIG"
    echo "  Tag:        $TAG"
    echo "------------------------------------------------------------"

    if [ ! -f "$SCRIPT_DIR/$CONFIG" ]; then
        echo "FAIL fly config not found: $SCRIPT_DIR/$CONFIG"
        exit 1
    fi

    # `flyctl deploy --build-only --push` builds the image on Fly's
    # remote builder and pushes it to the registry under the requested
    # tag, WITHOUT actually rolling out to running machines. The
    # ``--config`` flag selects the per-image fly.toml which pins
    # the correct Dockerfile.
    flyctl deploy \
        --app "$APP_NAME" \
        --config "$SCRIPT_DIR/$CONFIG" \
        --remote-only \
        --image-label "$TAG" \
        --build-only \
        --push \
        --auto-confirm

    echo "ok  pushed: $REF"
    PUSHED_REFS["$IMG"]="$REF"
done

echo
echo "============================================================"
echo "  All images built and pushed."
echo "============================================================"
echo
echo "Image refs (set as env vars for the orchestrator):"
for IMG in "${BUILD_LIST[@]}"; do
    REF_VAR="ECHO_DAST_IMAGE_$(echo "$IMG" | tr 'a-z' 'A-Z')"
    echo "  ${REF_VAR}=${PUSHED_REFS[$IMG]}"
done
echo
echo "Add to your Argus .env (or deployment env):"
echo
for IMG in "${BUILD_LIST[@]}"; do
    REF_VAR="ECHO_DAST_IMAGE_$(echo "$IMG" | tr 'a-z' 'A-Z')"
    echo "${REF_VAR}=${PUSHED_REFS[$IMG]}"
done
echo
echo "Smoke-test each image with a one-shot machine create+wait+destroy:"
echo "  flyctl machines run \\"
echo "    --app $APP_NAME \\"
echo "    --rm \\"
echo "    \"\${ECHO_DAST_IMAGE_NETWORKED}\" \\"
echo "    -- bash -c 'curl -V && nc -h 2>&1 | head -1'"
echo
echo "Done. Sandbox images built and pushed."
