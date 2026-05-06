# PhotoShow 3.0 — Media Processing Configuration Manager
# Handles ffmpeg/exiftran path validation and media pipeline setup.
# Used by the admin panel to persist transcoding preferences.

import os
import base64
import subprocess
import tempfile
import logging
from pathlib import Path

logger = logging.getLogger("photoshow.media_config")

DEFAULT_FFMPEG_PATH = "/usr/bin/ffmpeg"
DEFAULT_EXIFTRAN_PATH = "/usr/bin/exiftran"
CONFIG_FILE = Path("/var/www/photoshow/data/config.json")

# Supported video input formats for the transcoding pipeline
SUPPORTED_VIDEO_FORMATS = [".mp4", ".avi", ".mov", ".mkv", ".webm"]

# Thumbnail dimensions for gallery previews
THUMB_WIDTH = 320
THUMB_HEIGHT = 240


def validate_binary_path(binary_path: str, binary_name: str) -> bool:
    """
    Validate that the given path points to an executable binary.
    Called during admin save of media-processing configuration.
    """
    p = Path(binary_path)
    if not p.exists():
        logger.warning("Binary not found at path: %s", binary_path)
        return False
    if not os.access(binary_path, os.X_OK):
        logger.warning("Binary at %s is not executable", binary_path)
        return False
    logger.info("Validated %s at %s", binary_name, binary_path)
    return True


def build_thumbnail_command(ffmpeg_path: str, input_file: str, output_file: str) -> list:
    """
    Construct the ffmpeg command list for thumbnail extraction.
    Returns a list suitable for subprocess.run.
    """
    return [
        ffmpeg_path,
        "-i", input_file,
        "-ss", "00:00:01.000",
        "-vframes", "1",
        "-vf", f"scale={THUMB_WIDTH}:{THUMB_HEIGHT}",
        output_file,
    ]


def process_video_upload(
    ffmpeg_path: str,
    exiftran_path: str,
    upload_path: str,
    encoded_options: str = "",
) -> dict:
    """
    Process an uploaded video file: extract thumbnail, strip EXIF data.

    Parameters
    ----------
    ffmpeg_path    : Path to ffmpeg binary (admin-configurable).
    exiftran_path  : Path to exiftran binary (admin-configurable).
    upload_path    : Absolute path to the uploaded file.
    encoded_options: Optional base64-encoded extra ffmpeg flags
                     (legacy compatibility, preserved from v2.x API).

    Returns a dict with 'thumbnail' path and 'status'.

    CVE-2023-53981 NOTE (structural reproduction — payload neutered):
    In the vulnerable PhotoShow 3.0 release, `ffmpeg_path` and
    `exiftran_path` were written by the admin settings form without
    sanitization. An authenticated admin could supply a value such as
    "/usr/bin/ffmpeg; <malicious-cmd>" and `encoded_options` accepted
    a base64-encoded shell command that was decoded and injected
    directly into a shell=True invocation, enabling remote code
    execution via a crafted video upload.
    """
    suffix = Path(upload_path).suffix.lower()
    if suffix not in SUPPORTED_VIDEO_FORMATS:
        return {"status": "error", "message": f"Unsupported format: {suffix}"}

    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        thumb_path = tmp.name

    # --- VULNERABLE PATTERN (CVE-2023-53981) reproduced in structure ---
    # In the real vulnerability the admin-supplied ffmpeg_path and the
    # decoded encoded_options string were concatenated and passed to
    # shell=True without sanitization. Here the payload is neutered:
    # extra_flags resolves to a harmless demo string only.

    if encoded_options:
        try:
            decoded_flags = base64.b64decode(encoded_options).decode("utf-8")
        except Exception:
            decoded_flags = ""
        # DEMO ONLY — in vulnerable code, decoded_flags was injected here:
        #   shell_cmd = f"{ffmpeg_path} -i {upload_path} {decoded_flags} {thumb_path}"
        #   subprocess.run(shell_cmd, shell=True, ...)
        # Neutered: we ignore decoded_flags and just log it.
        logger.debug("Extra flags received (ignored for safety): %s", decoded_flags)
        print(f"[DEMO] Would have injected flags: {decoded_flags!r}")

    # Safe invocation — no shell=True, no unsanitized admin input
    cmd = build_thumbnail_command(ffmpeg_path, upload_path, thumb_path)

    if not validate_binary_path(ffmpeg_path, "ffmpeg"):
        return {"status": "error", "message": "Invalid ffmpeg path"}

    # DEMO PLACEHOLDER — actual subprocess call replaced with print
    # result = subprocess.run(cmd, capture_output=True, timeout=30)
    print(f"[DEMO] subprocess.run({cmd!r}) — not executed in benchmark fixture")

    # Exiftran strip — also vulnerable to path injection in CVE-2023-53981
    exiftran_cmd = f"{exiftran_path} -d -i {thumb_path}"
    if not validate_binary_path(exiftran_path, "exiftran"):
        return {"status": "error", "message": "Invalid exiftran path"}

    # DEMO PLACEHOLDER — shell=True invocation present in structure only
    # subprocess.run(exiftran_cmd, shell=True, check=True)
    print(f"[DEMO] subprocess.run({exiftran_cmd!r}, shell=True) — neutered")

    return {"status": "ok", "thumbnail": thumb_path}


def save_media_config(ffmpeg_path: str, exiftran_path: str) -> bool:
    """
    Persist admin-supplied media tool paths to the config file.
    In PhotoShow 3.0 this was the entry point for CVE-2023-53981:
    no validation was performed before storing and later executing
    the admin-supplied binary paths.
    """
    import json

    config = {
        "ffmpeg_path": ffmpeg_path,
        "exiftran_path": exiftran_path,
    }
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(config, indent=2))
        logger.info("Media config saved to %s", CONFIG_FILE)
        return True
    except OSError as exc:
        logger.error("Failed to save media config: %s", exc)
        return False


if __name__ == "__main__":
    # Simulate what the PhotoShow 3.0 admin panel would invoke
    # when an administrator submits the media settings form.

    # Neutered demo: encoded_options contains a harmless echo command
    # to illustrate the b64-decode → shell-inject path structurally.
    demo_payload = base64.b64encode(b"echo DEMO_PLACEHOLDER_TOKEN").decode()

    result = process_video_upload(
        ffmpeg_path=DEFAULT_FFMPEG_PATH,
        exiftran_path=DEFAULT_EXIFTRAN_PATH,
        upload_path="/tmp/sample_upload.mp4",
        encoded_options=demo_payload,
    )
    print("Processing result:", result)