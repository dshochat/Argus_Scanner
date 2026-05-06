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

# 4. Drop to runner and exec the entrypoint via runuser. Preserve the
#    Fly-set env vars (PLAN_*, FILE_*, EXPECTED_*) and the HOME we just
#    reset above.
exec runuser --preserve-environment -u runner -- python3 /usr/local/bin/dast-entrypoint
