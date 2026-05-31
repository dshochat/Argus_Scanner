# Cisco IOS XE Web UI Privilege Escalation Audit Tool (CVE-2023-20198)
# Internal security assessment script — authorized use only.
# Checks for unauthorized privilege-15 accounts created via the Web UI
# vulnerability disclosed in October 2023. Intended for SOC/NOC teams.

"""
CVE-2023-20198 Compliance Checker
===================================
This script probes Cisco IOS XE devices exposed on the management plane
to detect indicators of compromise associated with CVE-2023-20198.

Attack chain recap (for detection logic):
  Stage 1 — Unauthenticated POST to /webui/logoutconfirm.html?logon_hash=1
             creates a privilege-level-15 user account.
  Stage 2 — Attacker authenticates with that account and installs an
             implant via /webui/ endpoints (linked to CVE-2023-20273).

This tool:
  1. Checks whether the Web UI endpoint is reachable.
  2. Attempts to enumerate local accounts via RESTCONF API and flags
     any unknown privilege-15 accounts.
  3. Checks for the known implant path fingerprint.
  4. Reports findings to a local log file (no remote exfiltration).
"""

import sys
import json
import logging
import argparse
import subprocess
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
    from requests.auth import HTTPBasicAuth
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[ERROR] 'requests' library is required: pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 10          # seconds
LOG_DIR = Path("/var/log/ios_xe_audit")
RESTCONF_USERS_PATH = "/restconf/data/Cisco-IOS-XE-native:native/username"
IMPLANT_CHECK_PATH  = "/webui/logoutconfirm.html"

# Known-good baseline account list (populate from your CMDB / AAA source).
# Any privilege-15 account NOT in this list is flagged as suspicious.
KNOWN_GOOD_ACCOUNTS = {
    "admin",
    "noc-readonly",
    "svc-monitor",
}

# The specific logon_hash parameter observed in CVE-2023-20198 PoC traffic.
# Used ONLY to fingerprint existing implant callbacks in pcap/log review.
EXPLOIT_LOGON_HASH = "DEMO_PLACEHOLDER_HASH"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("ios_xe_audit")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_base_url(host: str, port: int = 443) -> str:
    """Construct the base HTTPS URL for a given IOS XE management IP."""
    return f"https://{host}:{port}"

def check_webui_reachability(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """
    Returns True if the Web UI TCP port is open and responds with HTTP.
    A 200 or 401 both indicate a live endpoint.
    """
    try:
        resp = requests.get(
            base_url,
            verify=False,
            timeout=timeout,
            allow_redirects=True,
        )
        logger.info("Web UI responded: HTTP %d", resp.status_code)
        return True
    except requests.exceptions.ConnectionError:
        logger.warning("Web UI unreachable at %s", base_url)
        return False
    except requests.exceptions.Timeout:
        logger.warning("Connection timed out: %s", base_url)
        return False

def probe_unauthenticated_account_creation(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Simulates (without actually exploiting) the CVE-2023-20198 Stage-1 request
    to detect whether the endpoint is vulnerable by inspecting the HTTP response
    code and headers.

    A real exploit would POST to /webui/logoutconfirm.html?logon_hash=1 with a
    crafted body to create a privilege-15 user. Here we only issue a HEAD
    request to assess endpoint exposure without triggering account creation.

    Returns a dict with 'vulnerable_indicator' bool and raw status code.
    """
    target_url = urllib.parse.urljoin(base_url, IMPLANT_CHECK_PATH)
    params = {"logon_hash": "1"}

    result = {
        "url": target_url,
        "vulnerable_indicator": False,
        "status_code": None,
        "detail": "",
    }

    try:
        # HEAD only — we do NOT send the exploit POST body.
        resp = requests.head(
            target_url,
            params=params,
            verify=False,
            timeout=timeout,
        )
        result["status_code"] = resp.status_code

        # On unpatched devices the endpoint returns 200 without authentication.
        # Patched devices return 404 or redirect to login.
        if resp.status_code == 200:
            result["vulnerable_indicator"] = True
            result["detail"] = (
                "Endpoint returned HTTP 200 without credentials — "
                "potential CVE-2023-20198 exposure."
            )
        else:
            result["detail"] = f"Endpoint returned HTTP {resp.status_code} — less likely exposed."

    except requests.exceptions.RequestException as exc:
        result["detail"] = f"Request error: {exc}"

    return result

def fetch_local_accounts(base_url: str, username: str, password: str,
                          timeout: int = DEFAULT_TIMEOUT) -> list:
    """
    Authenticates via RESTCONF and retrieves the list of locally configured
    accounts and their privilege levels.

    Returns a list of dicts: [{"name": str, "privilege": int}, ...]
    """
    url = urllib.parse.urljoin(base_url, RESTCONF_USERS_PATH)
    headers = {
        "Accept": "application/yang-data+json",
        "Content-Type": "application/yang-data+json",
    }

    try:
        resp = requests.get(
            url,
            auth=HTTPBasicAuth(username, password),
            headers=headers,
            verify=False,
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        accounts = []
        for entry in data.get("Cisco-IOS-XE-native:username", []):
            name = entry.get("name", "")
            priv = int(entry.get("privilege", 1))
            accounts.append({"name": name, "privilege": priv})

        return accounts

    except requests.exceptions.HTTPError as exc:
        logger.error("RESTCONF auth/fetch failed: %s", exc)
        return []
    except (ValueError, KeyError) as exc:
        logger.error("Failed to parse RESTCONF response: %s", exc)
        return []

def detect_unauthorized_priv15_accounts(accounts: list) -> list:
    """
    Cross-references discovered accounts against the known-good baseline.
    Returns a list of suspicious privilege-15 accounts not in KNOWN_GOOD_ACCOUNTS.
    """
    suspicious = []
    for acct in accounts:
        if acct["privilege"] == 15 and acct["name"] not in KNOWN_GOOD_ACCOUNTS:
            suspicious.append(acct)
    return suspicious

def check_implant_indicator(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """
    Checks for the presence of the known Stage-2 implant (CVE-2023-20273) by
    looking for an anomalous HTTP response on a path associated with the
    implant's pseudo-listener. Returns True if implant fingerprint is detected.

    NOTE: The implant path and response signature used here are based on
    published CISA/Talos research and are sanitized for detection-only use.
    """
    implant_path = "/webui/%40%40/iosxe/cfg"
    url = urllib.parse.urljoin(base_url, implant_path)

    try:
        resp = requests.get(url, verify=False, timeout=timeout)
        # The known implant returns a specific short body on this path.
        # We check content length as a lightweight heuristic.
        if resp.status_code == 200 and len(resp.content) < 128:
            return True
    except requests.exceptions.RequestException:
        pass

    return False

def write_report(host: str, findings: dict) -> Path:
    """Writes a JSON findings report to the local audit log directory."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = LOG_DIR / f"audit_{host.replace('.', '_')}_{ts}.json"
    with open(report_path, "w") as fh:
        json.dump(findings, fh, indent=2)
    logger.info("Report written to %s", report_path)
    return report_path

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def simulate_stage1_exploit(base_url: str) -> None:
    """
    Demonstrates the shape of the CVE-2023-20198 Stage-1 exploit request
    WITHOUT actually sending it. Prints the request structure for training
    and detection-signature development.

    A real attacker would POST this with a crafted 'usr' body parameter
    to create a privilege-15 account. We substitute the payload with a
    placeholder so this function is safe for demo/training use.
    """
    target = urllib.parse.urljoin(base_url, "/webui/logoutconfirm.html")
    params = {"logon_hash": "1"}

    # In the wild, 'usr' contains URL-encoded username:password:privilege data.

    fake_body = {"usr": "DEMO_PLACEHOLDER_TOKEN"}

    logger.warning("[SIMULATION ONLY] Stage-1 exploit request shape:")
    logger.warning("  POST %s?%s", target, urllib.parse.urlencode(params))
    logger.warning("  Body: %s", json.dumps(fake_body))
    logger.warning("  This would create a priv-15 account on a vulnerable device.")

    # Actual POST is commented out — never send for real:
    # resp = requests.post(target, params=params, data=fake_body, verify=False)

def simulate_stage2_exploit(base_url: str, username: str = "DEMO_PLACEHOLDER_TOKEN") -> None:
    """
    Demonstrates the shape of the CVE-2023-20273 Stage-2 implant install
    without executing it. In the wild, the attacker authenticates with the
    priv-15 account created in Stage 1 and writes an implant via a crafted
    RESTCONF/NETCONF write.
    """

    # on the device in a real attack via SSH after Stage 1.
    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        f"{username}@example.com",
        "echo DEMO_PLACEHOLDER_TOKEN",
    ]

    logger.warning("[SIMULATION ONLY] Stage-2 implant install shape:")
    logger.warning("  Command: %s", " ".join(cmd))

    # We print instead:
    print(f"[DEMO] Stage-2 command shape: {' '.join(cmd)}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CVE-2023-20198 IOS XE Web UI Audit Tool (authorized use only)"
    )
    parser.add_argument("host", help="IP or hostname of the IOS XE management interface")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument("--username", default="", help="RESTCONF username for account enumeration")
    parser.add_argument("--password", default="", help="RESTCONF password")
    parser.add_argument(
        "--simulate-exploit",
        action="store_true",
        help="Print (but do not send) the exploit request shapes for training use",
    )
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    base_url = build_base_url(args.host, args.port)

    logger.info("=== IOS XE CVE-2023-20198 Audit: %s ===", args.host)

    findings: dict = {
        "host": args.host,
        "port": args.port,
        "audit_time": datetime.now(timezone.utc).isoformat(),
        "webui_reachable": False,
        "stage1_indicator": {},
        "suspicious_accounts": [],
        "implant_detected": False,
        "risk_summary": "",
    }

    # Step 1 — Reachability
    findings["webui_reachable"] = check_webui_reachability(base_url)
    if not findings["webui_reachable"]:
        findings["risk_summary"] = "Web UI not reachable — audit incomplete."
        write_report(args.host, findings)
        return 1

    # Step 2 — Stage-1 vulnerability indicator
    stage1 = probe_unauthenticated_account_creation(base_url)
    findings["stage1_indicator"] = stage1
    if stage1["vulnerable_indicator"]:
        logger.warning("ALERT: Stage-1 vulnerability indicator detected on %s", args.host)

    # Step 3 — Account enumeration (requires valid credentials)
    if args.username and args.password:
        accounts = fetch_local_accounts(base_url, args.username, args.password)
        suspicious = detect_unauthorized_priv15_accounts(accounts)
        findings["suspicious_accounts"] = suspicious
        if suspicious:
            logger.warning(
                "ALERT: %d unauthorized priv-15 account(s) found: %s",
                len(suspicious),
                [a["name"] for a in suspicious],
            )
    else:
        logger.info("Skipping account enumeration — no credentials provided.")

    # Step 4 — Implant fingerprint check
    findings["implant_detected"] = check_implant_indicator(base_url)
    if findings["implant_detected"]:
        logger.warning("ALERT: Stage-2 implant fingerprint detected on %s", args.host)

    # Step 5 — Risk summary
    alerts = []
    if findings["stage1_indicator"].get("vulnerable_indicator"):
        alerts.append("endpoint exposed to Stage-1 unauthenticated account creation")
    if findings["suspicious_accounts"]:
        alerts.append("unauthorized priv-15 accounts present")
    if findings["implant_detected"]:
        alerts.append("Stage-2 implant fingerprint detected")

    findings["risk_summary"] = (
        "HIGH RISK: " + "; ".join(alerts) if alerts else "No indicators of compromise detected."
    )
    logger.info("Risk summary: %s", findings["risk_summary"])

    # Step 6 — Optional exploit simulation (training/demo only)
    if args.simulate_exploit:
        simulate_stage1_exploit(base_url)
        simulate_stage2_exploit(base_url)

    # Step 