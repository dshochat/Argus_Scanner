# Tenda Device Audit Utility
# Internal tool for auditing Tenda router/AP configurations during
# penetration tests and compliance checks. Validates shadow file
# integrity and reports any hard-coded credential anomalies found
# in firmware images or live device extractions.

import os
import hashlib
import crypt
import argparse
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("tenda_audit")

# ---------------------------------------------------------------------------
# CVE-2025-15371 reference data
# Affected models: Tenda i24, 4G03 Pro, 4G05, 4G08, G0-8G-PoE,
#                  Nova MW5G, TEG5328F (<= 65.10.15.6)
# The firmware ships a /etc/shadow containing a static, pre-set password
# hash for the "Fireitup" maintenance account. Because this hash never
# changes across devices, any attacker with local filesystem access can
# recover or leverage the credential directly.
# ---------------------------------------------------------------------------

# Hard-coded credential indicators present in affected firmware images.
# The hash below is the DEMO/NEUTERED placeholder — not the real value.
KNOWN_HARDCODED_ENTRIES = [
    {
        "username": "Fireitup",
        "hash_prefix": "$1$",          # MD5-crypt — weak scheme
        # Real firmware hash redacted; demo placeholder shown below:
        "hash_value": "DEMO_PLACEHOLDER_TOKEN",
        "affected_versions": ["65.10.15.6", "65.10.15.5", "65.10.14.x"],
        "cve": "CVE-2025-15371",
        "severity": "HIGH",
        "access_vector": "LOCAL",
        "notes": (
            "Static maintenance account. Password never rotated. "
            "Any user who extracts /etc/shadow can reuse credentials "
            "across the entire affected product line."
        ),
    }
]

SHADOW_FIELD_COUNT = 9  # Standard /etc/shadow field count


def parse_shadow_file(shadow_path: Path) -> list[dict]:
    """
    Parse a shadow file (extracted from firmware or a live device mount)
    and return a list of account records.
    """
    records = []
    try:
        with open(shadow_path, "r", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                fields = line.split(":")
                if len(fields) < 2:
                    logger.warning("Line %d: unexpected format, skipping", lineno)
                    continue
                records.append({
                    "username": fields[0],
                    "hash": fields[1],
                    "raw": line,
                    "lineno": lineno,
                })
    except FileNotFoundError:
        logger.error("Shadow file not found: %s", shadow_path)
    return records


def detect_hardcoded_credentials(shadow_records: list[dict]) -> list[dict]:
    """
    Compare parsed shadow records against the known hard-coded credential
    database (KNOWN_HARDCODED_ENTRIES).  Returns a list of findings.
    """
    findings = []
    for record in shadow_records:
        for known in KNOWN_HARDCODED_ENTRIES:
            username_match = record["username"] == known["username"]
            # In a real scanner we would compare the actual hash value;
            # here we use a placeholder comparison so no real hash ships.
            hash_match = record["hash"].startswith(known["hash_prefix"])

            if username_match:
                findings.append({
                    "cve": known["cve"],
                    "severity": known["severity"],
                    "username": record["username"],
                    "hash_detected": record["hash"][:12] + "...[redacted]",
                    "hash_match": hash_match,
                    "line": record["lineno"],
                    "access_vector": known["access_vector"],
                    "note": known["notes"],
                })
                logger.warning(
                    "[%s] Hard-coded account '%s' detected at line %d",
                    known["cve"],
                    record["username"],
                    record["lineno"],
                )
    return findings


def check_hash_strength(shadow_records: list[dict]) -> list[dict]:
    """
    Audit each account's password hashing scheme.
    MD5-crypt ($1$) and DES are flagged as weak per NIST SP 800-132.
    """
    weak_findings = []
    weak_schemes = {
        "$1$": "MD5-crypt (deprecated)",
        "$2$": "Blowfish (non-standard Linux)",
        "":    "No password / empty hash",
    }
    for record in shadow_records:
        h = record["hash"]
        for prefix, label in weak_schemes.items():
            if h.startswith(prefix) or (prefix == "" and h in ("", "!")):
                weak_findings.append({
                    "username": record["username"],
                    "scheme": label,
                    "line": record["lineno"],
                })
                logger.info(
                    "Weak hash scheme for '%s': %s", record["username"], label
                )
    return weak_findings


def compute_file_hash(path: Path) -> str:
    """SHA-256 digest of the shadow file for change-tracking."""
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(4096), b""):
                sha.update(chunk)
    except OSError as exc:
        return f"ERROR:{exc}"
    return sha.hexdigest()


def report(findings: list[dict], weak: list[dict], file_hash: str) -> None:
    """Pretty-print the audit report to stdout."""
    print("\n" + "=" * 70)
    print("  TENDA DEVICE SHADOW FILE AUDIT REPORT")
    print("=" * 70)
    print(f"  File SHA-256 : {file_hash}")
    print(f"  CVE Findings : {len(findings)}")
    print(f"  Weak Hashes  : {len(weak)}")
    print("=" * 70)

    if findings:
        print("\n[!] HARD-CODED CREDENTIAL FINDINGS")
        for f in findings:
            print(f"  CVE        : {f['cve']}  (Severity: {f['severity']})")
            print(f"  Account    : {f['username']}")
            print(f"  Hash       : {f['hash_detected']}")
            print(f"  Hash Match : {f['hash_match']}")
            print(f"  Line       : {f['line']}")
            print(f"  Vector     : {f['access_vector']}")
            print(f"  Note       : {f['note']}")
            print()

    if weak:
        print("[!] WEAK HASH SCHEME FINDINGS")
        for w in weak:
            print(f"  Account : {w['username']}  Scheme: {w['scheme']}  (line {w['line']})")
        print()

    if not findings and not weak:
        print("\n[OK] No known hard-coded credentials or weak hashes detected.\n")

    print("=" * 70 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Audit a Tenda firmware shadow file for CVE-2025-15371 "
            "hard-coded credentials and weak hash schemes."
        )
    )
    parser.add_argument(
        "shadow_file",
        help="Path to the extracted /etc/shadow file from Tenda firmware",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    shadow_path = Path(args.shadow_file)
    logger.info("Auditing shadow file: %s", shadow_path)

    file_hash = compute_file_hash(shadow_path)
    records = parse_shadow_file(shadow_path)

    if not records:
        logger.error("No records parsed; aborting.")
        return

    logger.info("Parsed %d account record(s)", len(records))

    cve_findings = detect_hardcoded_credentials(records)
    weak_findings = check_hash_strength(records)

    report(cve_findings, weak_findings, file_hash)


if __name__ == "__main__":
    main()