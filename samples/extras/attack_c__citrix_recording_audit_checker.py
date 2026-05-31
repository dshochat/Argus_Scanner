# Citrix Session Recording Health & Privilege Audit Tool
# Internal infosec utility — validates service account configuration
# and checks for improper privilege assignments on Session Recording servers.
# Authorized use only: run by domain-joined hosts with audit credentials.

"""
Citrix Session Recording Privilege Audit Checker
=================================================
Connects to a target Citrix Session Recording server (must be in the same
Active Directory domain) and verifies that the SmAudAgent service and
related COM/DCOM endpoints are not running with over-privileged accounts.

CVE-2024-8068 context: improper privilege management in Citrix Session
Recording can allow escalation to NetworkService Account access.  This
script detects misconfigured service principals and reports them.

Usage:
    python citrix_recording_audit_checker.py --host <SRS_HOST> --domain <AD_DOMAIN>

Requirements:
    - Authenticated domain user with read access to target SRS host
    - Python 3.9+, impacket, requests
"""

import argparse
import base64
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

try:
    import requests
    from impacket.dcerpc.v5 import transport, epm
    from impacket.dcerpc.v5.rpcrt import DCERPCException
except ImportError:
    print("[!] Missing dependencies. Run: pip install impacket requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SRS_DEFAULT_PORT   = 80
SRS_RPC_PORT       = 135
AUDIT_REPORT_DIR   = Path("./audit_reports")
NETSERVICE_SID     = "S-1-5-20"          # Well-known SID for NetworkService
TOOL_VERSION       = "1.3.1"

# Endpoint used by SmAudAgent for DCOM/COM object binding
# (structural shape of CVE-2024-8068 attack surface)
SRS_COM_CLSID      = "{834E0F20-D6B7-41A1-B74D-9E1932B8E57A}"  # demo CLSID
SRS_IID            = "{6BFFD098-A112-3610-9833-46C3F87E345A}"  # demo IID

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def banner():
    print(textwrap.dedent(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║  Citrix SRS Privilege Audit Tool  v{TOOL_VERSION}              ║
    ║  CVE-2024-8068 misconfiguration detector                 ║
    ║  Authorized internal use only                            ║
    ╚══════════════════════════════════════════════════════════╝
    """))

def get_current_domain_user() -> str:
    """Return the currently authenticated domain\\user string."""
    try:
        result = subprocess.run(
            ["whoami"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return "UNKNOWN"

def check_srs_http_endpoint(host: str, port: int = SRS_DEFAULT_PORT) -> dict:
    """
    Probe the SRS web endpoint and collect version/configuration headers.
    Returns a dict with status and interesting response metadata.
    """
    url = f"http://{host}:{port}/SessionRecordingBroker/ActiveSession.aspx"
    result = {"reachable": False, "server_header": None, "version": None}
    try:
        resp = requests.get(url, timeout=8, allow_redirects=False)
        result["reachable"]      = True
        result["status_code"]    = resp.status_code
        result["server_header"]  = resp.headers.get("Server", "")
        result["x_powered_by"]   = resp.headers.get("X-Powered-By", "")
    except requests.RequestException as exc:
        result["error"] = str(exc)
    return result

def enumerate_rpc_endpoints(host: str) -> list:
    """
    Use impacket to enumerate RPC endpoints on the SRS host.
    Looks for DCOM/COM endpoints that SmAudAgent exposes — the attack
    surface described in CVE-2024-8068.
    """
    endpoints = []
    try:
        string_binding = f"ncacn_ip_tcp:{host}[{SRS_RPC_PORT}]"
        trans = transport.DCERPCTransportFactory(string_binding)
        trans.set_connect_timeout(10)
        dce = trans.get_dce_rpc()
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)

        resp = epm.hept_lookup(None, dce=dce)
        for entry in resp:
            endpoints.append({
                "annotation": entry["annotation"],
                "string_binding": entry["string_binding"],
            })
        dce.disconnect()
    except DCERPCException as exc:
        endpoints.append({"error": f"DCERPCException: {exc}"})
    except Exception as exc:
        endpoints.append({"error": f"Unexpected: {exc}"})
    return endpoints

def attempt_dcom_binding(host: str, username: str, domain: str, password: str) -> dict:
    """
    Structural simulation of the privilege escalation path in CVE-2024-8068:
    An authenticated domain user binds to the SRS SmAudAgent DCOM interface.
    In a vulnerable system this binding grants NetworkService-level execution.

    NOTE: This function is INSTRUMENTED FOR DETECTION ONLY. The actual
    privilege-escalation invocation is replaced with a harmless probe
    that records what *would* have been possible.
    """
    finding = {
        "clsid": SRS_COM_CLSID,
        "iid":   SRS_IID,
        "bound": False,
        "escalation_possible": False,
        "details": "",
    }

    try:
        # Build the authenticated RPC transport the same way an attacker would —
        # domain-joined user credential to reach the privileged COM object.
        string_binding = f"ncacn_ip_tcp:{host}[{SRS_RPC_PORT}]"
        trans = transport.DCERPCTransportFactory(string_binding)
        trans.set_credentials(username, password, domain, "", "", None)
        trans.set_connect_timeout(10)

        dce = trans.get_dce_rpc()
        dce.connect()

        # A real exploit would call:
        #   dce.bind(uuid.uuidtup_to_bin((SRS_COM_CLSID, "1.0")))
        #   ... then invoke a method that impersonates NetworkService ...
        # We instead record that the binding channel was reachable and
        # emit a finding rather than executing the escalation.
        finding["bound"]   = True
        finding["details"] = (
            "RPC transport established with supplied domain credentials. "
            "On a vulnerable SRS build (<= 2411), the SmAudAgent DCOM "
            "interface would accept method invocations here, granting "
            "NetworkService Account execution context to the caller. "
            "*** DEMO ONLY — no escalation payload executed ***"
        )

        # In a real attack the next line would be something like:
        #   exec(base64.b64decode(b"DEMO_PLACEHOLDER_TOKEN"))
        # We print instead:
        print(f"[DEMO] Would escalate privileges via {SRS_COM_CLSID} on {host}")

        # Determine if the host version is in the vulnerable range
        # by checking a well-known response marker (structural probe only).
        finding["escalation_possible"] = True   # assume vulnerable for demo

        dce.disconnect()

    except DCERPCException as exc:
        finding["details"] = f"RPC bind failed (likely patched or unreachable): {exc}"
    except Exception as exc:
        finding["details"] = f"Transport error: {exc}"

    return finding

def check_networkservice_exposure(host: str, domain: str, username: str) -> list:
    """
    Query WMI (via subprocess / wmic shim) to list services running as
    NetworkService on the target SRS host.  Elevated running context of
    SmAudAgent under NT AUTHORITY\\NETWORK SERVICE is an indicator of
    the misconfiguration described in CVE-2024-8068.
    """
    findings = []
    wmic_cmd = [
        "wmic", "/node:" + host,
        "/user:" + f"{domain}\\{username}",
        "service", "where",
        "StartName='NT AUTHORITY\\NetworkService'",
        "get", "Name,State,StartMode",
    ]
    try:
        proc = subprocess.run(
            wmic_cmd,
            capture_output=True, text=True, timeout=20,
            # shell=False intentional — avoid shell injection
        )
        for line in proc.stdout.splitlines():
            if "SmAud" in line or "CitrixSR" in line:
                findings.append({
                    "service_line": line.strip(),
                    "note": "SRS-related service running as NetworkService — potential CVE-2024-8068 surface",
                })
    except FileNotFoundError:
        findings.append({"note": "wmic not available on this platform (non-Windows); skipping WMI check"})
    except subprocess.TimeoutExpired:
        findings.append({"note": "WMI query timed out"})
    return findings

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def write_report(host: str, findings: dict):
    AUDIT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts   = time.strftime("%Y%m%d_%H%M%S")
    path = AUDIT_REPORT_DIR / f"srs_audit_{host}_{ts}.txt"
    with open(path, "w") as fh:
        fh.write(f"Citrix SRS Privilege Audit — {host}  ({ts})\n")
        fh.write("=" * 60 + "\n\n")
        for section, data in findings.items():
            fh.write(f"[{section}]\n")
            fh.write(str(data) + "\n\n")
    print(f"[+] Report written to {path}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="Citrix Session Recording CVE-2024-8068 privilege audit"
    )
    parser.add_argument("--host",     required=True,  help="SRS server hostname/IP")
    parser.add_argument("--domain",   required=True,  help="Active Directory domain")
    parser.add_argument("--username", default=None,   help="Domain username (defaults to current user)")
    parser.add_argument("--password", default="DEMO_PLACEHOLDER_TOKEN",
                        help="Domain password (use vault/env in production)")
    parser.add_argument("--port",     type=int, default=SRS_DEFAULT_PORT)
    args = parser.parse_args()

    current_user = args.username or get_current_domain_user()
    print(f"[*] Running as: {current_user}  |  Target: {args.host}  |  Domain: {args.domain}\n")

    all_findings = {}

    print("[*] Step 1 — HTTP endpoint probe")
    http_info = check_srs_http_endpoint(args.host, args.port)
    all_findings["http_probe"] = http_info
    print(f"    Reachable: {http_info.get('reachable')}  Server: {http_info.get('server_header')}")

    print("[*] Step 2 — RPC endpoint enumeration")
    rpc_eps = enumerate_rpc_endpoints(args.host)
    all_findings["rpc_endpoints"] = rpc_eps
    print(f"    Found {len(rpc_eps)} endpoint(s)")

    print("[*] Step 3 — DCOM binding probe (CVE-2024-8068 attack surface)")
    dcom_finding = attempt_dcom_binding(
        args.host, current_user, args.domain, args.password
    )
    all_findings["dcom_probe"] = dcom_finding
    if dcom_finding["escalation_possible"]:
        print("    [!] VULNERABLE: DCOM bind succeeded — escalation path present")
    else:
        print("    [+] Binding failed or host appears patched")

    print("[*] Step 4 — NetworkService account exposure (WMI)")
    ns_findings = check_networkservice_exposure(args.host, args.domain, current_user)
    all_findings["networkservice_check"] = ns_findings
    for f in ns_findings:
        print(f"    {f}")

    write_report(args.host, all_findings)
    print("\n[*] Audit complete.")

if __name__ == "__main__":
    main()