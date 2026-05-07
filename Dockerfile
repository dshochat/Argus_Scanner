# Argus CLI container image — published to GHCR on every release tag.
#
# Usage:
#   docker run --rm -it \
#     -e ANTHROPIC_API_KEY -e GEMINI_API_KEY \
#     -v "$PWD:/workspace" \
#     ghcr.io/dshochat/argus_scanner:latest \
#     scan-repo /workspace
#
# Note: the DAST sandbox tier requires a Fly.io account + flyctl auth that
# this container does NOT carry by default. Set FLY_API_TOKEN +
# ECHO_DAST_IMAGE_MINIMAL/NETWORKED/ML_TOOLS env vars (and optionally
# mount a flyctl binary) to enable DAST. Without those, Argus runs the
# L1 cascade only — `argus scan` and `argus scan-repo` work fine.

FROM python:3.12-slim AS builder

# uv for fast deterministic dep install. Using the official binary
# install rather than apt — apt's uv is sometimes stale.
COPY --from=ghcr.io/astral-sh/uv:0.4 /uv /usr/local/bin/uv

WORKDIR /build

# Copy lockfile + pyproject first so Docker can cache the dep install
# layer when only source changes.
COPY pyproject.toml uv.lock ./
COPY README.md LICENSE ./

# Copy the source tree.
COPY adjudicator/ ./adjudicator/
COPY analysis/ ./analysis/
COPY dast/ ./dast/
COPY inference/ ./inference/
COPY methodology/ ./methodology/
COPY preprocessing/ ./preprocessing/
COPY prompts/ ./prompts/
COPY scanner/ ./scanner/
COPY shared/ ./shared/

# Build wheel + install it into a fresh venv we'll copy across stages.
RUN uv venv /opt/venv \
    && VIRTUAL_ENV=/opt/venv uv pip install --no-cache .


FROM python:3.12-slim AS runtime

# git is needed for `argus scan-repo --diff <ref>` (uses git diff
# --name-only). Everything else is pure-Python. ca-certificates lets
# httpx/anthropic talk to API endpoints over TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Run as a non-root user; Argus reads scanned files via a bind mount,
# the container has no privileged work to do.
RUN groupadd -r argus && useradd -r -g argus -u 10001 argus

WORKDIR /workspace

# Image labels that go into the GHCR listing.
LABEL org.opencontainers.image.title="argus-ai-scanner" \
      org.opencontainers.image.description="AI-native code security scanner with cascade analysis + Firecracker DAST" \
      org.opencontainers.image.url="https://github.com/dshochat/Argus_Scanner" \
      org.opencontainers.image.source="https://github.com/dshochat/Argus_Scanner" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="David Shochat"

USER argus

ENTRYPOINT ["argus"]
CMD ["--help"]
