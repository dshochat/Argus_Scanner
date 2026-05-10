"""Test fixture for Phase B+ runtime exploit probing (v1.5).

Contains a deliberately vulnerable ``read_file_safely`` function that
LOOKS like it sanitizes paths but actually doesn't — it strips the leading
``../`` prefix but only once, so ``....//etc/passwd`` collapses back to
``../etc/passwd`` and the file read goes through.

This is the canonical "path-traversal that passes naive static review
but fails runtime testing" pattern. Phase B+ should:

1. Identify ``read_file_safely`` as a probe candidate.
2. Generate inputs like ``"../etc/passwd"`` and ``"....//etc/passwd"``.
3. Run each in the sandbox.
4. Observe that one of them returns sensitive content (Rule 1 fires) →
   CONFIRMED finding.

NOT a real CVE — synthetic, intentionally vulnerable for evaluation only.
"""
from __future__ import annotations

import os


def read_file_safely(path: str) -> str:
    """Read a file from the data directory.

    'Safely' (as the function name implies, but doesn't actually deliver):
    we strip one leading ``../`` prefix to prevent traversal. This is
    the textbook insufficient-sanitization bug — works against naive
    input, fails against ``....//`` and similar.
    """
    if path.startswith("../"):
        path = path[3:]
    # The intent was to constrain reads to a data dir, but the cleaning
    # is one-shot and easily bypassed.
    return open("/data/" + path).read()


def write_log_entry(message: str) -> None:
    """Append a log line to /tmp/app.log.

    This function is here as a NON-vulnerable comparison case — it takes
    user input but only writes it as a literal string to a fixed path.
    Probe candidate emission should pick the read function, not this one.
    """
    with open("/tmp/app.log", "a") as f:
        f.write(message + "\n")
