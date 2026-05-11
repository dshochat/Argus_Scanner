#!/bin/bash
# Test fixture for Phase B+ runtime exploit probing — shell edition.
#
# Contains a deliberately vulnerable file-read pattern that strips
# leading "../" once and then concatenates user input into a hard-coded
# /data/ prefix. A multi-segment traversal payload like ../../etc/passwd
# collapses to ../etc/passwd and the `cat` reads outside /data/.
#
# This is the canonical "path-traversal that passes naive static review
# but fails runtime testing" pattern, in shell form. Phase B+ should:
#
#   1. Identify this script as a probe candidate (script-level — no
#      separate function concept in shell).
#   2. Generate inputs like "../etc/passwd" and "../../etc/passwd".
#   3. Run each as $1 in the sandbox.
#   4. Observe that one of them returns sensitive content (Rule 1 fires
#      via exit-code-0 + stdout containing /etc/passwd-like content)
#      → CONFIRMED finding.
#
# NOT a real CVE — synthetic, intentionally vulnerable for evaluation only.

set -e

# Required-arg check
if [ -z "${1:-}" ]; then
    echo "Usage: $0 <path>" >&2
    exit 1
fi

path="$1"

# "Sanitize" by stripping one leading ../ — same bug as the .py and .js
# fixtures. Single-pass bash parameter expansion that's trivially bypassable.
path="${path#../}"

# Read from /data/ — fixed prefix, no further validation. Vulnerable.
cat "/data/${path}"
