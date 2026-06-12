#!/usr/bin/env bash
# DAST sandbox init script — runs as PID 1 (root) at machine boot.
#
# Phase-2 strategy: DNS hijacking + multi-port capture server.
#
# (Originally we tried iptables NAT redirect, but Fly's stripped-down
# Firecracker kernel doesn't load the netfilter NAT modules:
# `RULE_APPEND failed (No such file or directory)`. DNS hijacking
# achieves the same end goal without requiring kernel modules — every
# outbound hostname resolves to 127.0.0.1, where the capture server
# listens on 80/443.)
#
# Responsibilities:
#   1. Override /etc/resolv.conf so the runner user's getaddrinfo()
#      returns 127.0.0.1 for any hostname.
#   2. Start the capture server (TCP on 80+443, UDP DNS on 53).
#   3. Drop to user `runner` and exec the existing dast-entrypoint.
#
# Privilege boundary:
#   * Init script needs root to:
#       - bind to ports 80, 443, 53 (privileged)
#       - rewrite /etc/resolv.conf
#   * After binding + writing resolv.conf, runs entrypoint as `runner`.
#     Plan commands (as runner) cannot rebind privileged ports or
#     modify resolv.conf.
#   * Capture server bound to 127.0.0.1 only — no inbound from outside
#     the VM.

set -euo pipefail

CAPTURE_LOG=/tmp/capture-server.log
CAPTURE_PID_FILE=/tmp/capture-server.pid

echo "[dast-init] starting" >&2

# 0. P2a (v1.8) — per-scan dep install hook.
#    Two groups of packages, both already validated shell-safe by
#    preprocessing.imports._is_safe_pkg_name on the orchestrator side.
#    Runs BEFORE the DNS hijack (Step 1) so pip can reach real PyPI.
#
#    Group 1 — RUNTIME_PACKAGES (v0.1 contract):
#      Packages NOT on the curated top-PyPI allowlist. Installed with
#      ``pip install --no-deps`` so even if an attacker names a malware
#      pkg, no shipped-as-dependency surprise payload.
#
#    Group 2 — RUNTIME_PACKAGES_ALLOWLISTED (v0.3 widening):
#      Packages whose PEP-503 normalized name is in the curated
#      ``PYPI_TOP_ALLOWLIST`` set. Installed WITH transitive resolution,
#      because the top-level name's dep graph is maintainer-vetted.
#      Cuts the common Phase B+ failure mode where ``selenium`` etc.
#      need their declared deps (urllib3, trio) to even import.
#
#    Both groups have a 60s wall clock cap. Empty vars (most plans —
#    orchestrator only populates when image_hint is rich_python/
#    ml_tools AND the target file imports beyond the tier's
#    preinstalled set) → skip entirely.
if [ -n "${RUNTIME_PACKAGES:-}" ]; then
    echo "[dast-init] per-scan dep install (no-deps): RUNTIME_PACKAGES=${RUNTIME_PACKAGES}" >&2
    if timeout 60 pip install --no-deps --quiet --disable-pip-version-check \
        --no-color $RUNTIME_PACKAGES 2>&1 | tail -20 >&2; then
        echo "[dast-init] per-scan dep install (no-deps): ok" >&2
    else
        # pip install failed — log and continue (plan might still work
        # if the missing import path isn't actually hit during exec).
        # Don't block the scan on telemetry / cosmetic install failures.
        echo "[dast-init] per-scan dep install (no-deps): FAILED (rc=$?), continuing" >&2
    fi
fi
if [ -n "${RUNTIME_PACKAGES_ALLOWLISTED:-}" ]; then
    echo "[dast-init] per-scan dep install (allowlisted): RUNTIME_PACKAGES_ALLOWLISTED=${RUNTIME_PACKAGES_ALLOWLISTED}" >&2
    if timeout 60 pip install --quiet --disable-pip-version-check \
        --no-color $RUNTIME_PACKAGES_ALLOWLISTED 2>&1 | tail -20 >&2; then
        echo "[dast-init] per-scan dep install (allowlisted): ok" >&2
    else
        echo "[dast-init] per-scan dep install (allowlisted): FAILED (rc=$?), continuing" >&2
    fi
fi

# 0b. JS DAST parity (v1.8) — per-scan npm install hook.
#
#    Reads RUNTIME_NPM_PACKAGES env (space-separated npm names — already
#    validated shell-safe by preprocessing.js_imports._is_safe_npm_name
#    on the orchestrator side). Runs BEFORE the DNS hijack (Step 1) so
#    npm can reach the registry.
#
#    Security model differs from pip:
#      * pip threat: surprise transitive installs → mitigated with
#        --no-deps + allowlist split.
#      * npm threat: lifecycle scripts (preinstall / install /
#        postinstall / prepare) execute arbitrary JS during install →
#        mitigated with --ignore-scripts, which kills ALL lifecycle
#        hooks. Transitives WITHOUT scripts are essentially benign.
#
#    Flags:
#      --ignore-scripts        — kills the npm RCE vector
#      --no-save               — don't touch package.json
#      --no-package-lock       — don't write package-lock.json
#      --no-audit / --no-fund  — silence phone-home calls
#      --silent                — slim logs
#
#    Install lands in /workspace/node_modules; Node's resolution walks
#    up from cwd, so harnesses running in /workspace find the modules
#    naturally via require().
#
#    Cap at 180s wall clock (npm slower than pip; first install seeds
#    the cache). Bumped from 90s on 2026-05-19 — large ecosystem
#    packages like ``flowise-components`` pull a heavy transitive
#    tree that consistently took 100-150s on a cold machine.
#    Paired with sandbox client ``long_poll_extra_s=240`` so the
#    orchestrator waits long enough for the install to finish.
if [ -n "${RUNTIME_NPM_PACKAGES:-}" ]; then
    echo "[dast-init] per-scan npm install: RUNTIME_NPM_PACKAGES=${RUNTIME_NPM_PACKAGES}" >&2
    mkdir -p /workspace
    # The Dockerfile (Dockerfile.lean line 153) sets up /workspace/
    # node_modules as a SYMLINK to /opt/node_packages/node_modules
    # (the read-only baseline). npm install into a symlinked-to
    # read-only path would fail. Replace the symlink with a real
    # directory so npm can write there.
    #
    # The baseline packages remain reachable via NODE_PATH (set by
    # Dockerfile ENV at line 152: NODE_PATH=/opt/node_packages/
    # node_modules), which Node's require() falls back to after
    # walking up from cwd. So `require('lodash')` still hits the
    # baseline, and `require('selenium')` (or whatever scan-time
    # niche import) hits the new /workspace/node_modules.
    if [ -L /workspace/node_modules ]; then
        rm /workspace/node_modules
        mkdir -p /workspace/node_modules
        echo "[dast-init] replaced /workspace/node_modules symlink with writable dir" >&2
    fi
    if cd /workspace && timeout 180 npm install \
        --ignore-scripts --no-save --no-package-lock \
        --no-audit --no-fund --silent \
        $RUNTIME_NPM_PACKAGES 2>&1 | tail -20 >&2; then
        echo "[dast-init] per-scan npm install: ok" >&2
    else
        echo "[dast-init] per-scan npm install: FAILED (rc=$?), continuing" >&2
    fi
fi

# 0c. Multi-file project staging (v11, 2026-05-17) — extract sibling
#     files from the entry file's project so relative imports
#     (``import './path-utils'``, ``from .helpers import bar``, etc.)
#     resolve at harness runtime.
#
#     ADDITIONAL_FILES_TARGZ_B64 is a base64-encoded tar.gz packed by
#     ``dast.sandbox.client._pack_additional_files`` from
#     ``SandboxPlan.additional_files`` (orchestrator populates it via
#     ``preprocessing.sibling_files.resolve_sibling_files``). Each
#     archive member is keyed by its path RELATIVE to the entry file's
#     directory, so extracting under /workspace mirrors the layout the
#     entry file's imports expect.
#
#     The entry file itself is NOT in this tar — it's staged separately
#     at /workspace/<FILE_NAME> by the entrypoint via FILE_CONTENT_B64GZ
#     (existing single-file path, unchanged).
#
#     Security: the resolver caps file count (50), per-file size
#     (512 KB), recursion depth (5), and rejects path-traversal
#     escapes BEFORE the tar is built. tar extraction here uses no
#     --absolute-names / --strip-components so member paths land
#     verbatim under /workspace. Empty env var → skip cleanly.
if [ -n "${ADDITIONAL_FILES_TARGZ_B64:-}" ]; then
    echo "[dast-init] multi-file staging: extracting ADDITIONAL_FILES_TARGZ_B64 to /workspace" >&2
    mkdir -p /workspace
    if printf '%s' "${ADDITIONAL_FILES_TARGZ_B64}" | base64 -d 2>/dev/null \
        | tar xzf - -C /workspace 2>&1 | tail -10 >&2; then
        # Count what landed (best-effort — find may fail if /workspace is
        # weirdly mounted, that's non-fatal).
        n_staged=$(find /workspace -type f ! -name "_argus_*" 2>/dev/null | wc -l)
        echo "[dast-init] multi-file staging: extracted (${n_staged} files now under /workspace)" >&2
    else
        echo "[dast-init] multi-file staging: extraction FAILED (rc=$?), continuing single-file" >&2
    fi
fi

# 1. Override /etc/resolv.conf — point runner's resolver at our local
#    DNS responder. The capture server's DNS thread answers any query
#    with 127.0.0.1, so urllib/curl/socket etc. all connect to our
#    capture servers on 80/443.
#
#    Fly's machine init may have written its own resolv.conf; we
#    overwrite it. The init runs once, before runner is exec'd, so
#    plan commands inherit the modified resolver.
cat > /etc/resolv.conf <<'EOF'
nameserver 127.0.0.1
options ndots:0
EOF
echo "[dast-init] /etc/resolv.conf set to 127.0.0.1" >&2

# 2. Start capture server in background. Needs root to bind 80/443/53.
python3 /usr/local/bin/dast-capture-server >"$CAPTURE_LOG" 2>&1 &
CAPTURE_PID=$!
echo "$CAPTURE_PID" >"$CAPTURE_PID_FILE"

# Give server a moment to bind all 3 ports
sleep 0.8

# Verify the server process is alive and at least one capture log entry
# has been written (server_start).
if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
    echo "[dast-init] FATAL: capture server died during startup" >&2
    cat "$CAPTURE_LOG" >&2 || true
    exit 1
fi

if [ ! -f /tmp/captured.jsonl ]; then
    echo "[dast-init] FATAL: capture server did not write /tmp/captured.jsonl" >&2
    cat "$CAPTURE_LOG" >&2 || true
    exit 1
fi

echo "[dast-init] capture server up (pid=$CAPTURE_PID, ports 80/443/53)" >&2

# 2b. Phase 2 — Launch bpftrace syscall observability sidecar.
#
#     Sandbox-observability-plan Phase 2 v0.1: kernel-level syscall
#     observability via bpftrace, closing the 6 named gaps in V0
#     (raw-syscall bypass, wide-fs writes, raw sockets, mprotect-exec,
#     process tree, capability ops).
#
#     Runs as root because BPF program loading needs CAP_SYS_ADMIN /
#     CAP_BPF. Self-terminates after 180s (script-internal timer)
#     because runner-uid can't kill a root-owned process.
#
#     Output: /tmp/syscalls.jsonl, one JSON object per line. Drained
#     by dast-entrypoint at end-of-run and emitted as syscall_*
#     SandboxEvent kinds.
#
#     Failure mode: if bpftrace is not installed or kernel doesn't
#     support tracepoints, log error and continue. Plan execution
#     still works; we just lose the kernel observability layer (fall
#     back to language-specific instrumentation alone).
SYSCALLS_LOG=/tmp/syscalls.jsonl
SYSCALLS_ERR=/tmp/bpftrace.err
SYSCALLS_PID_FILE=/tmp/bpftrace.pid
# gVisor (runsc) presents a user-space kernel with NO real kprobes /
# tracepoints, so bpftrace can never attach there. When running on the
# self-hosted gVisor substrate, skip the attempt cleanly (informational,
# NOT a syscall_observability_error) and let the orchestrator fall back
# to language-level instrumentation. On Firecracker (Fly) the kernel is
# real, uname won't match, and bpftrace runs exactly as before.
if uname -r 2>/dev/null | grep -qi gvisor; then
    echo "[dast-init] gVisor kernel detected — skipping bpftrace syscall observability (no kprobes under runsc)" >&2
elif command -v bpftrace >/dev/null 2>&1; then
    if [ -f /usr/local/lib/argus-syscalls.bt ]; then
        # Truncate prior run output (defense vs. machine reuse)
        : >"$SYSCALLS_LOG"
        : >"$SYSCALLS_ERR"
        # Start in background. bpftrace requires --unsafe for some
        # builtins; we don't use any of them — verifier-friendly
        # script only.
        bpftrace /usr/local/lib/argus-syscalls.bt \
            >"$SYSCALLS_LOG" 2>"$SYSCALLS_ERR" &
        BPFTRACE_PID=$!
        echo "$BPFTRACE_PID" >"$SYSCALLS_PID_FILE"
        # Brief wait for bpftrace to attach kprobes. If it's going to
        # fail (unsupported kernel, missing config), the failure
        # happens during this window.
        sleep 1
        if kill -0 "$BPFTRACE_PID" 2>/dev/null; then
            echo "[dast-init] bpftrace syscall observability up (pid=$BPFTRACE_PID)" >&2
        else
            echo "[dast-init] bpftrace died during attach — kernel may lack BPF/tracepoint support" >&2
            head -10 "$SYSCALLS_ERR" >&2 || true
        fi
    else
        echo "[dast-init] /usr/local/lib/argus-syscalls.bt not found — skipping kernel observability" >&2
    fi
else
    echo "[dast-init] bpftrace not installed — skipping kernel observability layer" >&2
fi

# 3. DAST-008 — reset HOME to a runner-owned path BEFORE the privilege drop.
#    `runuser --preserve-environment` preserves whatever HOME the calling
#    (root) shell has, which is `/root`. As uid 1000 (`runner`) the
#    target then can't `stat()` `/root/.npmrc`, `/root/.ssh`, etc., so
#    `pathlib.Path.home()` and `os.path.expanduser('~')` calls in
#    target code raise PermissionError before any malicious code path
#    runs.
#
#    Fix: ensure /home/runner exists with runner ownership, then export
#    HOME / USER / LOGNAME pointing there. `--preserve-environment`
#    then carries those forward into the runner-uid process, and Python's
#    `os.path.expanduser` resolves `~` to `/home/runner` (writable).
mkdir -p /home/runner
chown runner:runner /home/runner
chmod 700 /home/runner
export HOME=/home/runner
export USER=runner
export LOGNAME=runner

# 3b. v1.9 SCAN-009 (B8) — strip API-key env vars before the privilege
#     drop. A malicious target file running as uid 1000 could read
#     /proc/self/environ to exfiltrate Anthropic / Google / Fly tokens
#     if they were inherited from the Fly machine config. We don't
#     pass them in client._build_env() (the orchestrator only emits
#     PLAN_*/FILE_*/EXPECTED_*), but defense-in-depth: explicitly
#     unset every credentials env var we know of before runuser. If
#     the orchestrator path ever regresses or Fly's web UI sets one
#     of these globally on the app, this still blocks exfiltration.
#
#     Defense-in-depth list — anything an attacker could use to call
#     external APIs as Argus:
unset ANTHROPIC_API_KEY \
      ANTHROPIC_AUTH_TOKEN \
      ANTHROPIC_AI_KEY \
      ARGUS_ANTHROPIC_KEY \
      GOOGLE_API_KEY \
      GOOGLE_AI_KEY \
      GEMINI_API_KEY \
      FLY_API_TOKEN \
      FLY_API_KEY \
      OPENAI_API_KEY \
      AWS_ACCESS_KEY_ID \
      AWS_SECRET_ACCESS_KEY \
      AWS_SESSION_TOKEN \
      GITHUB_TOKEN \
      GH_TOKEN \
      || true

# 4. Drop to runner and exec the entrypoint via runuser. Preserve the
#    Fly-set env vars (PLAN_*, FILE_*, EXPECTED_*) and the HOME we just
#    reset above. v1.9: privilege drop is now verified — if runuser
#    fails (PAM error, missing user, etc.) we exit hard rather than
#    silently fall through and run target code as root.
exec runuser --preserve-environment -u runner -- python3 /usr/local/bin/dast-entrypoint
# If exec returned, runuser failed. Hard-exit to avoid running as root.
echo "[dast-init] FATAL: runuser failed — refusing to run target as root" >&2
exit 1
