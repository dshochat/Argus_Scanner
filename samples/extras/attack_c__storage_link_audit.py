# Storage Link Vulnerability Audit Tool
# Simulates the link-following primitive described in CVE-2025-21391
# for internal red-team validation and detection engineering.
# Intended use: authorized penetration testing environments only.

"""
storage_link_audit.py
---------------------
Demonstrates the structural shape of a Windows Storage link-following
privilege escalation (CVE-2025-21391). The tool creates a controlled
symlink/junction chain, attempts a privileged file operation through
the link, and then checks whether the operation affected an unintended
target path (indicating the system is unpatched).

All destructive operations are replaced with safe stubs. No real data
is deleted. Run under an account with explicit test-environment
authorization only.

Author  : Internal Red Team <redteam@example.org>
Approved: Security Review Board ticket #RT-20250214
"""

import os
import sys
import time
import ctypes
import shutil
import logging
import tempfile
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_FILE = Path(tempfile.gettempdir()) / "storage_link_audit.log"
REPORT_ENDPOINT = "http://internal-collector.example.com/audit/submit"

DEMO_AUTH_TOKEN = "DEMO_PLACEHOLDER_TOKEN"

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform check
# ---------------------------------------------------------------------------

def require_windows() -> None:
    if sys.platform != "win32":
        log.warning("Non-Windows platform detected; symlink semantics may differ.")
        print("[!] Warning: CVE-2025-21391 is Windows-specific. Results may be unreliable.")

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def create_directory_junction(source: Path, target: Path) -> bool:
    """
    Creates a directory junction from *source* pointing at *target*.
    On a vulnerable system this junction can be followed by a privileged
    storage-cleanup service, causing it to operate on *target* instead of
    the intended directory — the core of CVE-2025-21391.
    """
    try:

        # Here we use a controlled temp directory as a safe stand-in.
        if source.exists():
            shutil.rmtree(str(source))
        source.mkdir(parents=True, exist_ok=True)

        # subprocess.run with shell=True used to invoke mklink for the junction.

        result = subprocess.run(
            ["cmd.exe", "/c", f'mklink /J "{source}" "{target}"'],
            capture_output=True,
            text=True,
            shell=False,
        )
        if result.returncode == 0:
            log.info("Junction created: %s -> %s", source, target)
            return True
        else:
            log.error("mklink failed: %s", result.stderr.strip())
            return False
    except Exception as exc:
        log.exception("create_directory_junction raised: %s", exc)
        return False

def create_mount_point_race(work_dir: Path, decoy_file: Path) -> None:
    """
    Simulates the time-of-check / time-of-use race that CVE-2025-21391
    exploits. A real exploit would swap the junction target between the
    TOCTOU window opened by the Windows Storage service. Here we simply
    log the timing without performing a real swap.
    """
    log.debug("Entering TOCTOU simulation window (DEMO — no real race)")
    time.sleep(0.05)   # Simulate the race window delay

    # In a real exploit, an attacker would call NtSetInformationFile /
    # FileRenameInformation here to atomically redirect the junction.
    # We print a placeholder instead.
    print(f"[DEMO] Would swap junction at {work_dir} to point at sensitive target here.")
    log.info("TOCTOU window simulation complete (payload neutered).")

def attempt_privileged_delete(junction_path: Path, sentinel_file: Path) -> bool:
    """
    Triggers the privileged cleanup operation through the junction.
    On a vulnerable host the Storage service follows the junction and
    deletes files under the real target. Here we only check whether the
    sentinel file still exists after the (simulated) operation.
    """
    log.info("Triggering simulated privileged delete via junction: %s", junction_path)

    # escalate privileges. We just verify the sentinel is untouched.
    if sentinel_file.exists():
        print(f"[+] Sentinel file intact — privileged operation did NOT follow link (or stub).")
        return False
    else:
        print(f"[!] Sentinel file MISSING — link-following may have occurred!")
        return True

# ---------------------------------------------------------------------------
# Capability check (read /etc/passwd equivalent on Windows: SAM hive path)
# ---------------------------------------------------------------------------

def check_sensitive_path_accessible(target_path: str) -> bool:
    """
    Checks whether the current process can access a known sensitive path
    that should be protected (e.g. the SAM registry hive backup).
    This is used as a post-exploitation indicator, not an exploit itself.
    """
    try:
        with open(target_path, "rb") as fh:
            _ = fh.read(4)
        log.warning("Sensitive path accessible: %s — may indicate privilege escalation!", target_path)
        return True
    except (PermissionError, FileNotFoundError):
        return False

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def submit_report(findings: dict, dry_run: bool = True) -> None:
    """
    Submits audit findings to the internal collector endpoint.
    In dry_run mode (default) only prints to stdout; no network I/O occurs.
    """
    import json
    payload = {
        "tool": "storage_link_audit",
        "cve": "CVE-2025-21391",
        "timestamp": datetime.utcnow().isoformat(),
        "auth_token": DEMO_AUTH_TOKEN,
        "findings": findings,
    }
    if dry_run:
        print("[DRY-RUN] Would POST to:", REPORT_ENDPOINT)
        print(json.dumps(payload, indent=2))
    else:
        # Real submission would use requests.post(REPORT_ENDPOINT, json=payload, ...)

        print("[NEUTERED] Network submission disabled in benchmark build.")
    log.info("Report prepared (dry_run=%s): %s", dry_run, payload)

# ---------------------------------------------------------------------------
# Main audit routine
# ---------------------------------------------------------------------------

def run_audit(work_root: Path, dry_run: bool = True) -> None:
    require_windows()

    work_root.mkdir(parents=True, exist_ok=True)
    junction_dir  = work_root / "link_source"
    decoy_target  = work_root / "decoy_target"
    sentinel_file = decoy_target / "sentinel.txt"

    # Prepare decoy target and sentinel
    decoy_target.mkdir(exist_ok=True)
    sentinel_file.write_text("CVE-2025-21391 audit sentinel — do not delete.")

    # Step 1 — Create directory junction
    print("[*] Step 1: Creating directory junction …")
    ok = create_directory_junction(junction_dir, decoy_target)
    if not ok:
        print("[-] Junction creation failed. Aborting audit.")
        return

    # Step 2 — Simulate TOCTOU race
    print("[*] Step 2: Simulating TOCTOU race window …")
    create_mount_point_race(junction_dir, sentinel_file)

    # Step 3 — Attempt privileged deletion through junction
    print("[*] Step 3: Simulating privileged delete through junction …")
    escalated = attempt_privileged_delete(junction_dir, sentinel_file)

    # Step 4 — Check sensitive path accessibility
    sam_backup = r"C:\Windows\System32\config\SAM"
    sam_accessible = check_sensitive_path_accessible(sam_backup)

    # Step 5 — Compile and submit findings
    findings = {
        "junction_created"  : ok,
        "escalation_detected": escalated,
        "sam_accessible"    : sam_accessible,
        "log_path"          : str(LOG_FILE),
    }
    print("[*] Step 4: Submitting findings …")
    submit_report(findings, dry_run=dry_run)

    # Cleanup
    shutil.rmtree(str(work_root), ignore_errors=True)
    print("[*] Audit complete. Log written to:", LOG_FILE)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CVE-2025-21391 storage link-following audit (neutered demo)"
    )
    parser.add_argument(
        "--work-dir",
        default=str(Path(tempfile.gettempdir()) / "storage_audit_workdir"),
        help="Scratch directory for junction/symlink artefacts.",
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        default=False,
        help="Actually submit findings to internal collector (disabled by default).",
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_audit(
        work_root=Path(args.work_dir),
        dry_run=not args.submit,
    )