"""Synthetic exploit-laden module for end-to-end DAST flow verification (v1.9).

NOT REAL PRODUCTION CODE. Hand-crafted to exercise every stage of the
Argus scanner cascade so we can verify the v1.9 fixes — L1 split-mode
verdict aggregation, anti-undercall backstop, finding-based DAST
trigger, and Phase B+ HRP-finding surfacing — all flow through to
the user-facing output without anything getting dropped.

What this file is designed to trigger:

  * **Triage**: HIGH — pattern of subprocess + eval + user-controlled
    paths is the canonical malicious-or-vulnerable shape Gemini Flash-
    Lite flags as worth detailed analysis.

  * **L1 (Sonnet/Opus combined or split)**: should emit MULTIPLE
    findings with severity ≥ medium and confidence ≥ 0.6:
      - CWE-78 command injection (``run_user_command``)
      - CWE-22 path traversal (``read_user_file``)
      - CWE-95 code injection / dangerous eval (``compute_expression``)
      - CWE-502 insecure deserialization (``load_snapshot``)
      - CWE-918 SSRF (``fetch_remote_resource``)
    composite_risk should be in the 50-74 range (malicious) since
    the file is by design ATTACK-shaped, not vulnerable-but-legitimate.

  * **DAST trigger gate**: fires because final_verdict ∈
    {malicious, critical_malicious} hits the default trigger set
    (no need for the finding-confidence override).

  * **Phase A**: each L1 finding becomes a hypothesis. The harness
    builder synthesizes a minimal Python harness that imports the
    module, calls the vulnerable function with attacker input, and
    observes the runtime behavior. For ``run_user_command`` and
    ``compute_expression`` the harness should produce events
    (subprocess_call_captured, eval_invoked) that confirm exploits.

  * **Phase B+ runtime probe**: the model-driven probe generates
    additional attack inputs beyond L1's PoCs and might surface
    *latent_arbitrary_write* (the obfuscated open-with-attacker-path
    pattern below) as a NEW finding L1's prompt didn't pick. This
    is the path v1.9 fixed — the HRP_* finding should now show up
    in per_finding_validation with full evidence (CWE, severity,
    PoC, runtime_evidence) instead of just a bare ID.

  * **Phase 3 adversarial loop**: gets a second pass over the file's
    callables with the journal context from Phase A/B+. Might find
    chains like *user_input → compute_expression → arbitrary write
    via os.path* depending on the model's exploration.

  * **per_finding_validation**: should have one row PER L1 finding
    PLUS one row per HRP_* / HRP_AL_* finding that Phase B+ or
    Phase 3 confirmed at runtime. Each CONFIRMED row carries
    runtime_evidence + proof_of_concept.

WHY THIS DESIGN:
  * All functions are pure-Python with NO npm/pip dependencies —
    avoids the heavy-dependency denylist that would refuse-fast.
  * Each function is independently exploitable — Phase A can
    confirm them in isolation.
  * The "latent" path (``_helper_with_path``) is structurally
    reachable via ``compute_expression`` if the model thinks to
    chain them — exercises the Phase 3 chain-discovery path.
  * No real malicious payloads. The "attack" inputs are bog-standard
    demonstrative patterns (``; id``, ``../../etc/passwd``,
    ``__import__('os').system('whoami')``).
"""

from __future__ import annotations

import pickle
import subprocess
import urllib.request


# ── 1. Command injection (CWE-78) ─────────────────────────────────────


def run_user_command(filename: str) -> str:
    """Run ``ls`` against a user-provided path. Vulnerable to shell
    injection because we use ``shell=True`` with f-string interpolation.

    Attacker payload: ``filename = ". ; whoami"``. The semicolon escapes
    the ``ls`` command and ``whoami`` runs unconstrained.
    """
    cmd = f"ls {filename}"
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout


# ── 2. Code injection / dangerous eval (CWE-95) ───────────────────────


def compute_expression(expr: str) -> object:
    """Evaluate a math expression provided by the user.

    Intent: a tiny calculator. Actual behavior: passes the string to
    ``eval()`` with no sandboxing. Attacker payload:
    ``__import__('os').system('id')`` → arbitrary code execution.
    """
    return eval(expr)  # noqa: S307 — intentional for DAST verification


# ── 3. Path traversal (CWE-22) ────────────────────────────────────────


def read_user_file(filename: str) -> bytes:
    """Read a file from the data directory by user-supplied name.

    Intent: serve files from ``./data/``. Actual behavior: concatenates
    the user input without normalizing or anchoring, so attacker
    payload ``../../etc/passwd`` escapes the directory.
    """
    path = "data/" + filename
    with open(path, "rb") as f:
        return f.read()


# ── 4. Insecure deserialization (CWE-502) ─────────────────────────────


def load_snapshot(snapshot_bytes: bytes) -> object:
    """Restore an application snapshot. Uses ``pickle.loads`` on
    arbitrary attacker-controlled bytes. Attacker payload: a pickle
    blob whose ``__reduce__`` calls ``os.system`` → RCE on load.
    """
    return pickle.loads(snapshot_bytes)  # noqa: S301 — intentional


# ── 5. SSRF (CWE-918) ─────────────────────────────────────────────────


def fetch_remote_resource(url: str) -> bytes:
    """Fetch a URL via urllib.request.urlopen. No scheme allowlist, no
    host validation, no DNS rebinding guard. Attacker payload:
    ``http://169.254.169.254/latest/meta-data/iam/security-credentials/``
    on a cloud instance → IAM credential disclosure.
    """
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 — intentional
        return resp.read()


# ── 6. Latent path-write helper (Phase B+ / Phase 3 discovery target) ──
#
# This function is NOT directly called from any of the above. It's a
# "helper" left in module scope. The L1 prompt's intent-aware reasoning
# may or may not flag it (depends on calibration). The Phase B+
# runtime probe — which exercises every public callable with model-
# generated inputs — should reach it and surface a CWE-73 / CWE-22
# arbitrary-write finding if it probes with an absolute path or a
# path-traversal payload.
#
# This is the path that exercises the v1.9 HRP-finding surfacing fix:
# a DAST-DISCOVERED finding with no L1 hypothesis backing.


def write_user_log(filename: str, content: str) -> None:
    """Append a log entry. The file path is user-controlled.
    Attacker payload: ``filename='/etc/cron.d/backdoor'`` → root-owned
    cron entry write.
    """
    with open(filename, "a") as f:
        f.write(content + "\n")
