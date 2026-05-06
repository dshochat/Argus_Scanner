# Sandbox image for Argus DAST
# Path C — Fly.io managed Firecracker microvm
#
# Per-machine isolation: each plan execution creates a fresh ephemeral
# microvm via the Fly Machines API with auto_destroy=true.
#
# No SSH, no inbound services, no persistent volumes. The image only
# contains tooling that the entrypoint needs to execute and observe a
# plan. Tightly scoped attack surface.

FROM python:3.13-slim

# Multi-language toolchain. Step-3 finding: minimal Python image
# caused both smoke samples (preinstall.py via `node --version` check;
# docker-compose.yml via `docker` calls) to crash before reaching
# malicious code paths.
#
# Scope (Step-4 expansion):
#   * Node.js + npm — required for npm preinstall scripts in the corpus
#     (e.g., preinstall.py:46 runs subprocess.run(["node", "--version"]))
#   * OpenJDK 17 JRE headless — required for Java samples in the
#     supplement_malware / supplement_attack_chain strata (e.g.,
#     malware__FastjsonDeserializationDemo.java)
#   * Docker — DELIBERATELY EXCLUDED. Nested containerization inside
#     Firecracker microvms is non-trivial and out of prototype scope.
#     Plans needing docker (e.g. for docker-compose.yml files) will
#     fail with exit_code=127, which is documented expected behavior.
#
# Apt cache cleared inline to keep the image small (~270 MB compressed).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        inotify-tools \
        nodejs \
        npm \
        default-jre-headless \
        curl \
        util-linux \
        && rm -rf /var/lib/apt/lists/*

# Non-root runner. Plans execute as `runner`, never root. /workspace
# is the target directory; everything else is read-only at runtime.
RUN useradd -m -u 1000 -s /bin/bash runner && \
    mkdir -p /workspace && \
    chown runner:runner /workspace

COPY entrypoint.py /usr/local/bin/dast-entrypoint
RUN chmod 755 /usr/local/bin/dast-entrypoint

# Phase 2 capture infrastructure (iptables outbound redirect → local
# capture server). See dast-init.sh for the privilege boundary; the
# init script needs root to install iptables NAT rules and starts the
# capture server, then drops to user `runner` before plan execution.
COPY dast-capture-server.py /usr/local/bin/dast-capture-server
COPY dast-init.sh /usr/local/bin/dast-init.sh
RUN chmod 755 /usr/local/bin/dast-capture-server /usr/local/bin/dast-init.sh

# IMPORTANT: USER stays root for the init script. dast-init.sh installs
# iptables rules (needs CAP_NET_ADMIN) then drops to `runner` via
# `runuser` before exec'ing the entrypoint. Plan commands run as runner;
# they cannot modify iptables rules.
WORKDIR /workspace
ENTRYPOINT ["bash", "/usr/local/bin/dast-init.sh"]
