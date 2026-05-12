"""JS string-array deobfuscation — wraps `webcrack` as a preprocessing stage.

obfuscator.io string-array obfuscation produces files where every literal
is rewritten as ``_0xNNNN(0xXXX)`` calls into a shared decoder table. The
result is huge (the table is bundled inline) and semantically opaque to
the LLM — and the 2.3 MB / 1.5 M-token payload from the Mini Shai-Hulud
TanStack compromise is a real example: every 1 M-context model rejected
it on size.

`webcrack` is a node-based static AST tool that unwinds this transform
into readable JS. It does NOT execute the input — it parses to AST,
inlines the decoder, and emits transformed source. Running it on
malicious JS is safe.

Resolution order for the binary: ``shutil.which("webcrack")`` first
(the standard install path: ``npm install -g webcrack`` after Node 22
LTS), then ``$ARGUS_WEBCRACK`` env var for non-PATH installs. We never
shell out to ``npx --yes`` — auto-install on every invocation can hang
the preprocessor on hosts where native deps fail to compile.

Triggering is gated by a marker regex: only files containing the
obfuscator.io fingerprint in their first 4 KB enter the subprocess
path. Every failure mode (webcrack missing, timeout, non-zero exit,
oversized output, no shrinkage) returns the original text with
``applied=False`` — the caller treats the original as canonical and
the downstream model stage's fail-closed verdict still flags the file.

Safety budgets:

* 60 s subprocess timeout — 2 MB input completes in ~10 s on a laptop.
* 5 MB output cap — webcrack shrinks; an expanding output indicates a
  pathological bundle and we bail.
* 20 % shrinkage threshold — if the "deobfuscated" output isn't at
  least a fifth smaller, treat it as a no-op (still likely over the
  model context budget).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from shared.utils.logging import get_logger

_log = get_logger(__name__)

#: Env var override for the webcrack binary path. The default lookup
#: is ``shutil.which("webcrack")`` (i.e. a global ``npm install -g
#: webcrack``); this override is for non-PATH installs such as a
#: project-local ``node_modules/.bin/webcrack``.
_WEBCRACK_ENV = "ARGUS_WEBCRACK"

#: Hard disable for the JS deobfuscation stage. Set by ``scanner/cli.py``
#: when the user passes ``--no-deobfuscation`` for restricted environments
#: (airgapped CI, locked-down hosts without Node). When set, the stage
#: short-circuits before the marker scan — webcrack is not called and
#: the original obfuscated bytes flow to the model unchanged.
_DISABLE_ENV = "ARGUS_NO_DEOBFUSCATION"

#: Env var override for the directory containing the node binary that
#: webcrack's shebang should resolve. Set this when the system default
#: node is too new/old (webcrack needs ≥18, isolated-vm builds best on
#: 22 LTS). The directory is prepended to PATH for the subprocess.
_NODE_DIR_ENV = "ARGUS_NODE_DIR"

_STRING_ARRAY_MARKER = re.compile(
    rb"_0x[0-9a-f]{4,}\s*=\s*_0x[0-9a-f]{4,}",
    re.IGNORECASE,
)

_MARKER_SCAN_BYTES = 4096

_WEBCRACK_TIMEOUT_S = 60

_MAX_OUTPUT_BYTES = 5 * 1024 * 1024

_SHRINKAGE_THRESHOLD = 0.8


@dataclass(frozen=True)
class JsDeobfResult:
    """Outcome of the JS deobfuscation pass.

    ``applied=False`` means the marker didn't fire OR webcrack couldn't
    run / didn't reduce the file; callers fall back to the original
    ``content``. ``technique`` is None unless a transform actually ran.
    """

    applied: bool
    content: str
    technique: str | None = None


def has_string_array_marker(raw_text: str) -> bool:
    """True if the obfuscator.io fingerprint is in the first 4 KB."""
    head = raw_text[:_MARKER_SCAN_BYTES].encode("utf-8", errors="ignore")
    return bool(_STRING_ARRAY_MARKER.search(head))


def _resolve_webcrack() -> str | None:
    """Return path to webcrack binary, or None if unavailable.

    Resolution order: ``shutil.which("webcrack")`` (the standard
    ``npm install -g webcrack`` install path), then the
    ``$ARGUS_WEBCRACK`` env var for non-PATH installs. We DO NOT shell
    out to ``npx --yes``: on hosts where webcrack's native deps fail
    to compile, auto-install can hang the preprocessor for minutes on
    every invocation. Operators install webcrack explicitly;
    preprocessing only consumes.
    """
    found = shutil.which("webcrack")
    if found:
        return found
    override = os.environ.get(_WEBCRACK_ENV, "").strip()
    if override and Path(override).exists():
        return override
    return None


def is_available() -> bool:
    """Return True if a usable webcrack binary is resolvable.

    Used by ``scanner/cli.py`` at startup to fail fast with a helpful
    install hint instead of silently degrading every JS-malware scan.
    """
    return _resolve_webcrack() is not None


def _subprocess_env() -> dict[str, str]:
    """Subprocess env, with ``ARGUS_NODE_DIR`` prepended to PATH if set.

    Lets operators pin a specific Node version (e.g. 22 LTS) for
    webcrack's ``#!/usr/bin/env node`` shebang without changing the
    system default.
    """
    env = os.environ.copy()
    node_dir = env.get(_NODE_DIR_ENV, "").strip()
    if node_dir and Path(node_dir).is_dir():
        env["PATH"] = f"{node_dir}{os.pathsep}{env.get('PATH', '')}"
    return env


def unwrap_js_string_array(raw_text: str) -> JsDeobfResult:
    """Run webcrack on ``raw_text`` if the string-array marker matches."""
    if os.environ.get(_DISABLE_ENV, "").strip():
        return JsDeobfResult(applied=False, content=raw_text)

    if not has_string_array_marker(raw_text):
        return JsDeobfResult(applied=False, content=raw_text)

    webcrack = _resolve_webcrack()
    if webcrack is None:
        _log.debug(
            "webcrack not on PATH and %s unset; skipping JS deobfuscation",
            _WEBCRACK_ENV,
        )
        return JsDeobfResult(applied=False, content=raw_text)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        input_file = tmp_path / "input.js"
        output_dir = tmp_path / "out"
        input_file.write_text(raw_text, encoding="utf-8")

        try:
            proc = subprocess.run(
                [webcrack, str(input_file), "-o", str(output_dir)],
                capture_output=True,
                timeout=_WEBCRACK_TIMEOUT_S,
                check=False,
                env=_subprocess_env(),
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            _log.debug("webcrack invocation failed: %s", exc)
            return JsDeobfResult(applied=False, content=raw_text)

        if proc.returncode != 0 or not output_dir.exists():
            stderr_preview = (
                proc.stderr.decode("utf-8", errors="replace")[:500]
                if proc.stderr
                else ""
            )
            _log.debug(
                "webcrack returned %s; stderr=%s",
                proc.returncode,
                stderr_preview,
            )
            return JsDeobfResult(applied=False, content=raw_text)

        parts: list[str] = []
        total = 0
        for f in sorted(output_dir.rglob("*.js")):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            total += len(text)
            if total > _MAX_OUTPUT_BYTES:
                _log.debug(
                    "webcrack output exceeded %s bytes; aborting",
                    _MAX_OUTPUT_BYTES,
                )
                return JsDeobfResult(applied=False, content=raw_text)
            rel = f.relative_to(output_dir)
            parts.append(f"// === {rel} ===\n{text}")

        if not parts:
            return JsDeobfResult(applied=False, content=raw_text)

        joined = "\n\n".join(parts)

        if len(joined) >= len(raw_text) * _SHRINKAGE_THRESHOLD:
            return JsDeobfResult(applied=False, content=raw_text)

        return JsDeobfResult(
            applied=True,
            content=joined,
            technique="js_string_array",
        )
