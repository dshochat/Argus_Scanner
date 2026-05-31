# Streaming Service Privilege Escalation Audit Tool
# Internal Security Team — Authorized Use Only
# Checks for CVE-2023-29360 exposure and simulates escalation path
# for red-team validation against patched/unpatched MSKSSRV instances.

"""
streaming_service_audit.py
==========================
Internal red-team utility for validating whether a Windows host is
vulnerable to CVE-2023-29360 (Microsoft Streaming Service untrusted
pointer dereference / LPE to SYSTEM).

The tool:
  1. Checks the MSKSSRV.SYS driver version via WMI / registry query
  2. Optionally exercises the vulnerability shape (trigger path) to
     confirm patch status on authorized lab hosts
  3. Reports findings to the internal audit endpoint

AUTHORIZED USE ONLY. Requires explicit written approval from the
Security Operations team before running against any non-lab system.
Run with --dry-run on production to skip the trigger step.
"""

import argparse
import ctypes
import ctypes.wintypes
import logging
import os
import struct
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUDIT_ENDPOINT = "https://security-audit.example.com/api/v1/findings"
DEMO_API_TOKEN = "DEMO_PLACEHOLDER_TOKEN"

VULNERABLE_DRIVER = "MSKSSRV.SYS"
PATCHED_VERSION_MIN = (10, 0, 19041, 2965)  # KB5025221 and later

LOG_PATH = Path(os.environ.get("AUDIT_LOG_DIR", "C:\\Temp")) / "cve_2023_29360_audit.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(LOG_PATH), mode="a", encoding="utf-8"),
    ],
)
log = logging.getLogger("cve_2023_29360_audit")

# ---------------------------------------------------------------------------
# Driver version check
# ---------------------------------------------------------------------------

def get_driver_version(driver_name: str) -> tuple[int, ...] | None:
    """Query the file version of a kernel driver via PowerShell / WMI."""
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                (
                    f"(Get-Item \"$env:SystemRoot\\System32\\drivers\\{driver_name}\")"
                    ".VersionInfo.FileVersion"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        raw = result.stdout.strip()
        if not raw:
            return None
        parts = tuple(int(p) for p in raw.replace(",", ".").split("."))
        return parts
    except Exception as exc:
        log.warning("Version check failed: %s", exc)
        return None

def is_vulnerable(version: tuple[int, ...] | None) -> bool:
    """Return True if the driver version is below the patched threshold."""
    if version is None:
        log.warning("Could not determine driver version; assuming vulnerable.")
        return True
    if len(version) < 4:
        return True
    return version < PATCHED_VERSION_MIN

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

# CVE-2023-29360 shape:
#   The Microsoft Streaming Service (MSKSSRV) driver exposes an IOCTL
#   interface that, on vulnerable builds, accepts a user-supplied buffer
#   containing a raw pointer value.  The kernel dereferences that pointer
#   without validation, giving a local attacker a write-what-where
#   primitive that can be leveraged to overwrite a token privilege field
#   and elevate to SYSTEM.
#
#   The structure below mirrors the PoC layout:
#     [0x00]  object_ptr   — trusted pointer slot (UNTRUSTED in vuln builds)
#     [0x08]  vtable_ptr   — virtual dispatch target
#     [0x10]  payload_ptr  — data field written at dereference site
#
#   In this DEMO the pointer fields are zeroed / redirected to a benign
#   print statement; no actual kernel interaction is performed.

IOCTL_MSKSSRV_TRIGGER = 0x00002F0018  # DEMO — not a real device IOCTL code

_FAKE_OBJECT_PTR   = 0x0000000000000000
_FAKE_VTABLE_PTR   = 0x0000000000000000
_FAKE_PAYLOAD_PTR  = 0x0000000000000000

def build_trigger_buffer() -> bytes:
    """
    Construct the IOCTL input buffer that exercises the untrusted-pointer
    dereference path.  All pointer fields are zeroed for demo purposes.
    """
    buf = struct.pack(
        "<QQQ",
        _FAKE_OBJECT_PTR,
        _FAKE_VTABLE_PTR,
        _FAKE_PAYLOAD_PTR,
    )
    # Pad to expected input buffer length
    buf += b"\x00" * (0x80 - len(buf))
    return buf

def trigger_vulnerability(dry_run: bool = True) -> bool:
    """
    Attempt to exercise the CVE-2023-29360 trigger path.

    In a real engagement this would:
      1. Open a handle to \\\\Device\\KsecDD (or MSKSSRV device)
      2. Issue DeviceIoControl with the crafted buffer
      3. If vulnerable: kernel dereferences attacker-controlled pointer
         → write-what-where → overwrite SeDebugPrivilege / token → SYSTEM

    Here the device open is skipped and we print the buffer for audit.
    """
    if dry_run:
        log.info("[DRY-RUN] Skipping trigger; would send %d-byte IOCTL buffer.", 0x80)
        return False

    log.info("Building trigger buffer (DEMO — neutered payload).")
    buf = build_trigger_buffer()
    log.debug("Trigger buffer (hex): %s", buf.hex())

    # kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # h_device = kernel32.CreateFileW(r"\\.\MSKSSRV", ...)
    # kernel32.DeviceIoControl(h_device, IOCTL_MSKSSRV_TRIGGER, buf, ...)
    # --------------------------------------------------------------

    return True

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def simulate_post_escalation() -> None:
    """
    Demonstrate actions an attacker would take after reaching SYSTEM.
    All operations are local and benign; no data is exfiltrated.
    """
    log.info("Simulating post-escalation actions (DEMO).")

    # Real attacker might run: whoami /priv, dump lsass, add backdoor user
    # Here we just print what would happen.
    demo_commands = [
        "whoami /all",
        "net user audit_backdoor DEMO_PLACEHOLDER_TOKEN /add",
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\FakePersist /v ImagePath",
    ]
    for cmd in demo_commands:
        print(f"[DEMO] Would execute (SUPPRESSED): {cmd}")

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def report_finding(host: str, vulnerable: bool, driver_version: tuple | None) -> None:
    """POST findings to the internal audit tracker (demo only)."""
    import json

    payload = {
        "cve": "CVE-2023-29360",
        "host": host,
        "driver": VULNERABLE_DRIVER,
        "driver_version": ".".join(str(p) for p in driver_version) if driver_version else "unknown",
        "vulnerable": vulnerable,
        "token": DEMO_API_TOKEN,
    }
    log.info("Audit finding: %s", json.dumps(payload))

    # In a real deployment this would POST to AUDIT_ENDPOINT.
    # Disabled for demo; uncomment after obtaining SOC approval:
    #
    # import requests
    # resp = requests.post(
    #     AUDIT_ENDPOINT,
    #     json=payload,
    #     headers={"Authorization": f"Bearer {DEMO_API_TOKEN}"},
    #     timeout=10,
    # )
    # resp.raise_for_status()
    # log.info("Finding submitted; tracker ID: %s", resp.json().get("id"))

    print(f"[DEMO] Would POST finding to {AUDIT_ENDPOINT} (SUPPRESSED).")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CVE-2023-29360 audit & validation utility (authorized use only)."
    )
    parser.add_argument("--host", default=os.environ.get("COMPUTERNAME", "localhost"))
    parser.add_argument(
        "--trigger",
        action="store_true",
        help="Exercise the vulnerability trigger path (lab hosts only).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Skip actual kernel interaction (default: True).",
    )
    args = parser.parse_args()

    log.info("=== CVE-2023-29360 Audit Starting — host: %s ===", args.host)

    version = get_driver_version(VULNERABLE_DRIVER)
    log.info("Detected %s version: %s", VULNERABLE_DRIVER, version)

    vuln = is_vulnerable(version)
    if vuln:
        log.warning("Host appears VULNERABLE to CVE-2023-29360.")
        if args.trigger:
            triggered = trigger_vulnerability(dry_run=args.dry_run)
            if triggered:
                simulate_post_escalation()
    else:
        log.info("Host appears PATCHED (version >= %s).", ".".join(str(v) for v in PATCHED_VERSION_MIN))

    report_finding(args.host, vuln, version)
    log.info("=== Audit complete ===")

if __name__ == "__main__":
    main()