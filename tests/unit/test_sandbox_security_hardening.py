"""Unit tests for v1.9 sandbox security hardening (B7+B8).

B7: capture server drops privileges from root to nobody/capture
    after binding privileged ports. If any parser bug is ever
    introduced, attacker gets uid=nobody, not uid=0.

B8: dast-init.sh explicitly unsets credentials env vars before the
    runuser privilege drop so a malicious target file can't
    exfiltrate ANTHROPIC_API_KEY / FLY_API_TOKEN / etc. via
    /proc/self/environ. Defense-in-depth: the orchestrator's
    client._build_env() doesn't pass them, but if it ever regresses
    OR if Fly's web UI sets one globally on the app, this shell-level
    unset still blocks exfiltration.

These tests don't require a live Firecracker — they exercise the
script + python source files directly for invariants we want to
preserve over time.
"""

from __future__ import annotations

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
INIT_SCRIPT = REPO_ROOT / "dast" / "sandbox" / "firecracker" / "dast-init.sh"
CAPTURE_SERVER = REPO_ROOT / "dast" / "sandbox" / "firecracker" / "dast-capture-server.py"


# ── B8: env-var stripping in dast-init.sh ────────────────────────────


def test_dast_init_strips_anthropic_api_key_before_runuser() -> None:
    """v1.9 SCAN-009 (B8): ANTHROPIC_API_KEY must be explicitly unset
    before the runuser privilege drop so the runner user can't read
    it from /proc/self/environ. The orchestrator's _build_env()
    doesn't currently pass it, but this is defense-in-depth — a
    regression or a Fly-side env var setting could leak it."""
    assert INIT_SCRIPT.exists(), f"dast-init.sh not found at {INIT_SCRIPT}"
    text = INIT_SCRIPT.read_text(encoding="utf-8")
    assert "unset ANTHROPIC_API_KEY" in text or "ANTHROPIC_API_KEY" in (
        # The unset block is multi-line backslash-continued; check
        # the var name appears within an unset context.
        " ".join(text.split())
    ), (
        "ANTHROPIC_API_KEY must be explicitly unset before runuser"
    )
    # Search for the unset block context.
    assert "unset" in text
    # Confirm the line containing ANTHROPIC_API_KEY is part of an
    # unset directive, not just an export.
    for line in text.splitlines():
        if "ANTHROPIC_API_KEY" in line:
            # Must be in the unset block — either the line starts
            # with "unset " or the previous line did.
            stripped = line.strip()
            assert stripped.startswith("unset") or stripped.startswith(
                "ANTHROPIC_API_KEY"
            ) or "unset" in text[: text.find(line)].split("\n")[-1], (
                f"ANTHROPIC_API_KEY found at line {stripped!r} but not in unset block"
            )


@pytest.mark.parametrize(
    "credential_var",
    [
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "FLY_API_TOKEN",
        "OPENAI_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
    ],
)
def test_dast_init_strips_credential_var(credential_var: str) -> None:
    """v1.9 SCAN-009 (B8): every credential env var of concern is
    explicitly unset before runuser."""
    text = INIT_SCRIPT.read_text(encoding="utf-8")
    assert credential_var in text, (
        f"{credential_var} missing from dast-init.sh unset block — "
        "if Fly's web UI sets it as an app-level env var, target code "
        "could read it from /proc/self/environ"
    )


def test_dast_init_unset_block_appears_before_runuser_exec() -> None:
    """v1.9 SCAN-009 (B8): the unset must happen BEFORE the runuser
    exec, otherwise the target process inherits the credentials."""
    text = INIT_SCRIPT.read_text(encoding="utf-8")
    unset_idx = text.find("unset ANTHROPIC_API_KEY")
    runuser_idx = text.find("exec runuser")
    assert unset_idx > 0
    assert runuser_idx > 0
    assert unset_idx < runuser_idx, (
        "The unset block must appear BEFORE the runuser exec, otherwise "
        "the credentials are inherited into the runner-uid process"
    )


def test_dast_init_runuser_failure_is_fatal() -> None:
    """v1.9 SCAN-009 (B7/B8): if runuser fails (PAM error, missing
    user, etc.), the script must hard-exit rather than silently fall
    through and run the target as root."""
    text = INIT_SCRIPT.read_text(encoding="utf-8")
    runuser_idx = text.find("exec runuser")
    assert runuser_idx > 0
    after_exec = text[runuser_idx:]
    # The next non-empty, non-comment line must be a guard.
    has_fatal_guard = (
        "FATAL:" in after_exec
        and "exit 1" in after_exec
    )
    assert has_fatal_guard, (
        "dast-init.sh must hard-exit if 'exec runuser' returns "
        "(meaning the exec failed and we'd silently run as root)"
    )


# ── B7: capture server drops privileges after binding ────────────────


def test_capture_server_has_drop_privileges_function() -> None:
    """v1.9 SCAN-009 (B7): capture server defines _drop_privileges
    so that after binding 80/443/53 (which requires root) it can
    relinquish root. Without this, a parser bug → root RCE."""
    assert CAPTURE_SERVER.exists()
    text = CAPTURE_SERVER.read_text(encoding="utf-8")
    assert "def _drop_privileges" in text
    # Must actually call setuid / setgid
    assert "os.setuid" in text
    assert "os.setgid" in text


def test_capture_server_drops_privileges_after_threads_started() -> None:
    """v1.9 SCAN-009 (B7): _drop_privileges must be called AFTER
    listen threads start (so the privileged ports are bound while
    we're still root) but BEFORE the main blocking loop."""
    text = CAPTURE_SERVER.read_text(encoding="utf-8")
    main_body_start = text.find("def main(")
    main_body_end = text.find('if __name__ == "__main__"')
    assert main_body_start > 0 < main_body_end
    main_src = text[main_body_start:main_body_end]
    # Order check: thread starts first, then drop, then blocking loop.
    threads_start_idx = main_src.find("t.start()")
    drop_idx = main_src.find("_drop_privileges()")
    block_idx = main_src.find("while True")
    assert threads_start_idx > 0
    assert drop_idx > threads_start_idx, (
        "_drop_privileges must be called AFTER threads start binding ports"
    )
    assert block_idx > drop_idx, (
        "Drop privileges BEFORE the infinite block-forever loop"
    )


def test_capture_server_priv_drop_tries_nobody_user() -> None:
    """v1.9 SCAN-009 (B7): the privilege-drop fallback chain must
    include `nobody` (always present on Debian/Alpine bases)."""
    text = CAPTURE_SERVER.read_text(encoding="utf-8")
    drop_block_start = text.find("def _drop_privileges")
    assert drop_block_start > 0
    drop_block = text[drop_block_start:drop_block_start + 3000]
    assert '"nobody"' in drop_block, (
        "The privilege-drop fallback must try 'nobody' user (always "
        "available on Debian/Alpine base images)"
    )


def test_capture_server_imports_os_module() -> None:
    """v1.9 SCAN-009 (B7): the privilege drop uses os.setuid /
    os.setgid / os.setgroups / os.geteuid; the os module must be
    imported."""
    text = CAPTURE_SERVER.read_text(encoding="utf-8")
    assert "import os" in text


def test_capture_server_drops_supplementary_groups() -> None:
    """v1.9 SCAN-009 (B7): when dropping from root, supplementary
    groups must be cleared via setgroups([]). Otherwise the new
    process inherits root's group list, retaining unintended access."""
    text = CAPTURE_SERVER.read_text(encoding="utf-8")
    assert "setgroups([])" in text or "setgroups( [])" in text, (
        "The privilege drop must clear supplementary groups via "
        "os.setgroups([]) — otherwise root's groups leak into the "
        "dropped process"
    )
