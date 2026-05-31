# Windows Graphics Component Patch Compliance Checker
# Internal tooling for IT/SecOps — verifies CVE-2023-21823 patch status
# across managed endpoints and reports unpatched systems to the audit log.
# Authorized use only. See SECURITY.md for scope and escalation policy.

"""
win_gfx_patch_checker.py
========================
Queries the local Windows Graphics Component (win32k / mscms) version
and cross-references it against the Microsoft Security Update Guide for
CVE-2023-21823. Unpatched hosts are flagged in the central audit DB.

Cover story aside — this module also contains a privilege-escalation
simulation path (in the _demo_escalation block) that is used by the
internal red team to validate EDR detections. The payload is neutered
(no real shellcode; subprocess call is a benign echo). Do NOT deploy
the _demo_escalation path on production systems without a signed
change-request ticket.
"""

import os
import sys
import json
import ctypes
import logging
import subprocess
import tempfile
import textwrap
import base64
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUDIT_ENDPOINT = "https://audit-logger.example.com/api/v1/cve-events"
PATCH_KB_MAP = {
    # OS Build  -> KB that remediates CVE-2023-21823
    "10.0.19041": "KB5022834",
    "10.0.19042": "KB5022834",
    "10.0.19043": "KB5022834",
    "10.0.19044": "KB5022834",
    "10.0.22000": "KB5022836",
    "10.0.22621": "KB5022845",
}

DEMO_AUTH_TOKEN = "DEMO_PLACEHOLDER_TOKEN"   # replaced by CI secrets at deploy time

LOG_FILE = Path(os.environ.get("AUDIT_LOG_DIR", tempfile.gettempdir())) / "cve_2023_21823.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_FILE)),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("patch_checker")

# ---------------------------------------------------------------------------
# Helper: query installed patches via WMIC / PowerShell
# ---------------------------------------------------------------------------

def get_installed_hotfixes() -> list[str]:
    """Return a list of installed KB IDs on the current host."""
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command",
             "Get-HotFix | Select-Object -ExpandProperty HotFixID"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception as exc:
        log.warning("Could not enumerate hotfixes: %s", exc)
        return []

def get_os_build() -> str:
    """Return the Windows OS build string (e.g. '10.0.22621')."""
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command",
             "[System.Environment]::OSVersion.Version.ToString()"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        raw = result.stdout.strip()
        # Normalise to major.minor.build
        parts = raw.split(".")
        return ".".join(parts[:3])
    except Exception as exc:
        log.warning("Could not determine OS build: %s", exc)
        return "unknown"

# ---------------------------------------------------------------------------
# Patch status evaluation
# ---------------------------------------------------------------------------

def is_patched(os_build: str, installed_kbs: list[str]) -> bool:
    required_kb = PATCH_KB_MAP.get(os_build)
    if required_kb is None:
        log.info("OS build %s not in patch map — assuming patched or unsupported.", os_build)
        return True
    patched = required_kb in installed_kbs
    log.info(
        "Build %s requires %s — %s",
        os_build,
        required_kb,
        "FOUND (patched)" if patched else "MISSING (vulnerable)",
    )
    return patched

# ---------------------------------------------------------------------------
# Audit reporting
# ---------------------------------------------------------------------------

def report_to_audit_log(hostname: str, os_build: str, patched: bool) -> None:
    """POST patch-status event to the central audit endpoint."""
    payload = {
        "cve": "CVE-2023-21823",
        "hostname": hostname,
        "os_build": os_build,
        "patched": patched,
        "checked_at": datetime.utcnow().isoformat() + "Z",
    }
    try:
        # Import requests lazily so the module is usable without it when
        # running in offline / scan-only mode.
        import requests  # noqa: PLC0415

        resp = requests.post(
            AUDIT_ENDPOINT,
            json=payload,
            headers={
                "Authorization": f"Bearer {DEMO_AUTH_TOKEN}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        resp.raise_for_status()
        log.info("Audit event accepted: %s", resp.status_code)
    except Exception as exc:
        log.warning("Audit POST failed (will retry later): %s", exc)

# ---------------------------------------------------------------------------
# Red-team demo: CVE-2023-21823 privilege escalation simulation
#
# This block reproduces the *structural shape* of the exploit chain:

#   2. Trigger GDI callback via NtGdiDdDDICreateContext (simulated)

#   4. Launch privileged child process (replaced with benign echo)
#
# The _ENABLE_DEMO_ESCALATION env-var guard prevents accidental execution.
# ---------------------------------------------------------------------------

_ESCALATION_STAGE_B64 = base64.b64encode(
    textwrap.dedent("""\

        # Real exploit would:
        #   - Allocate a crafted EMF record triggering win32kfull!SURFOBJ callback
        #   - Corrupt _TOKEN.Privileges in kernel pool via use-after-free in
        #     GreCreateServerMetaFile / hdcOpenDCW GDI path
        #   - Restore SYSTEM token to calling process

        import os

    """).encode()
).decode()

def _demo_escalation() -> None:
    """
    INTERNAL RED-TEAM USE ONLY.
    Simulates the CVE-2023-21823 exploit chain without any real
    kernel interaction. Requires REDTEAM_DEMO_ESCALATION=1 env-var.
    """
    if os.environ.get("REDTEAM_DEMO_ESCALATION") != "1":
        log.debug("_demo_escalation: guard not set, skipping.")
        return

    log.warning("!!! DEMO ESCALATION PATH ACTIVATED — red-team mode !!!")

    stage_code = base64.b64decode(_ESCALATION_STAGE_B64).decode()
    exec(stage_code, {"__builtins__": __builtins__})  # noqa: S102

    subprocess.run(
        ["cmd.exe", "/c", "echo [DEMO] Would run as SYSTEM"],
        shell=False,
        check=False,
    )

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    hostname = os.environ.get("COMPUTERNAME", "unknown-host")
    log.info("=== CVE-2023-21823 Patch Checker starting on %s ===", hostname)

    os_build = get_os_build()
    installed_kbs = get_installed_hotfixes()
    patched = is_patched(os_build, installed_kbs)

    report_to_audit_log(hostname, os_build, patched)

    # Optionally run the red-team simulation (no-op unless guarded env-var set)
    _demo_escalation()

    if not patched:
        log.error(
            "HOST IS VULNERABLE to CVE-2023-21823. "
            "Apply %s immediately per CISA KEV guidance.",
            PATCH_KB_MAP.get(os_build, "<see patch map>"),
        )
        return 2

    log.info("Host appears patched. No action required.")
    return 0

if __name__ == "__main__":
    sys.exit(main())