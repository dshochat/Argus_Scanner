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

# Pre-create common app data directories that filesystem-rooted code
# often references (e.g., open("/data/" + user_input)). Without these,
# functions targeting hard-coded paths like /data/, /srv/app/, etc.
# raise FileNotFoundError before path-traversal exploits can fire,
# silently masking real vulns. v1.5 runtime probe needs Linux's path
# resolver to be able to descend the prefix dir so ".." traversals
# can resolve correctly. Mode 1777 (sticky bit + world-writable, like
# /tmp) lets the unprivileged 'runner' user populate them safely.
RUN mkdir -p /data /srv/app /srv/data /var/lib/app /opt/app /var/data /app && \
    chmod 1777 /data /srv/app /srv/data /var/lib/app /opt/app /var/data /app

# Phase 1.x env-fix — pre-install common third-party packages so probe
# harnesses can `require()` / `import` them without runtime registry
# access. The sandbox's DNS hijack blocks all outbound network at runtime
# for exfil detection; build-time has network, so we install during image
# construction.
#
# Curated list covers (a) top supply-chain-relevant npm/pip packages by
# import frequency, and (b) intentionally-vulnerable libraries used by
# regression fixtures (e.g., sandboxjs for sandbox_runner.js —
# a known sandbox-escape used as a real-fixture validation target).
#
# Packages NOT on this list will still trigger an ImportError at probe
# time — that's documented as a known limitation; a selective-registry
# allowlist enabling on-demand install is the next env-fix step
# (post-Phase 3).

# npm packages — installed to /opt/node_packages, exposed via NODE_PATH
# so `require()` from /workspace falls back to the pre-installed set.
RUN mkdir -p /opt/node_packages && \
    cd /opt/node_packages && \
    npm init -y > /dev/null 2>&1 && \
    npm install --no-fund --no-audit --no-save --silent \
      sandboxjs \
      lodash@^4 \
      axios@^1 \
      express@^4 \
      body-parser@^1 \
      async@^3 \
      chalk@^5 \
      debug@^4 \
      semver@^7 \
      glob@^10 \
      minimist@^1 \
      fs-extra@^11 \
      yargs@^17 \
      commander@^11 \
      ws@^8 \
      cookie@^0 \
      qs@^6 \
      dotenv@^16 \
      uuid@^10 \
      node-fetch@^3 \
      && chmod -R a+rX /opt/node_packages

# Make pre-installed npm packages reachable from /workspace via two
# independent mechanisms:
#   1. NODE_PATH env var — works for any cwd; Node falls back to it after
#      walking up node_modules from cwd. May not survive `runuser -u
#      runner` (which clears the env) so we ALSO add (2).
#   2. /workspace/node_modules symlink — Node's standard require()
#      resolution checks the cwd's node_modules first. Symlinking here
#      makes require('pkg') work regardless of NODE_PATH, regardless of
#      env-var clearing during user-switch. Belt-and-suspenders.
ENV NODE_PATH=/opt/node_packages/node_modules
RUN ln -s /opt/node_packages/node_modules /workspace/node_modules

# pip packages — installed system-wide for global importability.
# Pinning is not strict here: minor-version latest is fine for runtime
# probing, where we want recent-enough surface to match real supply-
# chain code.
RUN pip install --no-cache-dir --quiet \
      requests \
      flask \
      fastapi \
      click \
      jinja2 \
      pyyaml \
      lxml \
      cryptography \
      pyjwt \
      sqlalchemy \
      pillow \
      gunicorn \
      python-dateutil \
      urllib3 \
      packaging \
      typing-extensions

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
