#!/usr/bin/env bash
# Argus DAST multi-image build for SELF-HOSTED runtime (local Docker + gVisor).
#
# Builds the sandbox images into the LOCAL Docker daemon — no registry,
# no Fly.io, no auth. This is the build half of the self-hosted story;
# pair it with ``ARGUS_DAST_RUNTIME=gvisor`` (see dast/runner.py) so the
# orchestrator launches plans as local ``runsc`` containers instead of
# Fly machines.
#
# The images are byte-identical to the Fly ones (same Dockerfiles, same
# entrypoint.py / dast-init.sh / capture server). The ONLY difference
# between the hosted and self-hosted substrates is the launcher.
#
# Prereqs:
#   * Docker installed and running.
#   * gVisor installed + registered as the `runsc` runtime
#     (`runsc install` && restart docker). NOT required to BUILD — only
#     to RUN — but you'll want it before scanning. See _gvisor_setup.sh.
#
# Usage:
#   cd dast/sandbox/firecracker
#   bash build_local.sh                 # build all three tiers
#   bash build_local.sh lean            # one tier only (fast; ~470MB)
#   bash build_local.sh ml_tools        # heavy (torch); slow + ~GBs
#   ARGUS_DAST_IMAGE_PREFIX=myco/argus-dast bash build_local.sh   # custom repo
#
# Output: tags <prefix>:<tier> in the local daemon and prints the
# matching ARGUS_DAST_GVISOR_IMAGE_* env lines to paste into your .env.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Repository/name prefix for the built tags. The runner's defaults are
# ``argus-dast-sandbox:<tier>`` so the default here matches out of the box.
PREFIX="${ARGUS_DAST_IMAGE_PREFIX:-argus-dast-sandbox}"

# tier → Dockerfile. Each is an independent FROM python:3.13-slim build,
# so order does not matter and any single tier can be built alone.
declare -A DOCKERFILES=(
    ["lean"]="Dockerfile.lean"
    ["rich_python"]="Dockerfile.rich_python"
    ["ml_tools"]="Dockerfile.ml_tools"
)

if [ $# -gt 0 ]; then
    REQUESTED="$1"
    if [ -z "${DOCKERFILES[$REQUESTED]:-}" ]; then
        echo "FAIL unknown tier: $REQUESTED"
        echo "    valid: lean | rich_python | ml_tools"
        exit 2
    fi
    BUILD_LIST=("$REQUESTED")
else
    BUILD_LIST=("lean" "rich_python" "ml_tools")
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "FAIL docker not installed — install Docker first"
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "FAIL docker daemon not reachable — is it running? (need sudo?)"
    exit 1
fi

echo "=== Argus DAST local image build (self-hosted / gVisor) ==="
echo "Prefix: ${PREFIX}"
echo "Tiers:  ${BUILD_LIST[*]}"
echo

declare -A BUILT_TAGS
for TIER in "${BUILD_LIST[@]}"; do
    DOCKERFILE="${DOCKERFILES[$TIER]}"
    TAG="${PREFIX}:${TIER}"
    echo
    echo "------------------------------------------------------------"
    echo "  Building tier: $TIER"
    echo "  Dockerfile:    $DOCKERFILE"
    echo "  Tag:           $TAG"
    echo "------------------------------------------------------------"
    if [ ! -f "$SCRIPT_DIR/$DOCKERFILE" ]; then
        echo "FAIL dockerfile not found: $SCRIPT_DIR/$DOCKERFILE"
        exit 1
    fi
    # Build context is the firecracker dir (it holds entrypoint.py,
    # dast-init.sh, dast-capture-server.py, argus-syscalls.bt that the
    # Dockerfiles COPY).
    docker build -f "$SCRIPT_DIR/$DOCKERFILE" -t "$TAG" "$SCRIPT_DIR"
    echo "ok  built: $TAG"
    BUILT_TAGS["$TIER"]="$TAG"
done

echo
echo "============================================================"
echo "  Built ${#BUILT_TAGS[@]} image(s)."
echo "============================================================"
echo
echo "Add to your Argus .env (selects the self-hosted substrate):"
echo
echo "ARGUS_DAST_RUNTIME=gvisor"
for TIER in "${BUILD_LIST[@]}"; do
    VAR="ARGUS_DAST_GVISOR_IMAGE_$(echo "$TIER" | tr 'a-z' 'A-Z')"
    echo "${VAR}=${BUILT_TAGS[$TIER]}"
done
echo
echo "Verify gVisor actually runs the image (the ENTRYPOINT is dast-init.sh,"
echo "so use --entrypoint to run a bare command):"
echo "  docker run --rm --runtime=runsc --network=none --entrypoint python3 \\"
echo "    ${BUILT_TAGS[${BUILD_LIST[0]}]:-$PREFIX:lean} -c 'import platform; print(platform.release())'"
echo "  # prints a *-gvisor kernel release => runsc is intercepting"
echo
echo "Done."
