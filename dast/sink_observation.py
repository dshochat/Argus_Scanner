"""SCAN-018 Phase 3 — sandbox-syscall sink observation oracle.

For attack classes with a clear kernel-level signature, consult the
per-probe ``syscall_observations`` and downgrade ``CONFIRMED`` to
``SUPPRESSED`` when the expected sink syscall did NOT fire during the
probe run.

The principle: a CONFIRMED finding via the string-based oracles
("function returned ``/etc/passwd`` content", "URL.repr matched
``169.254.``") needs CORROBORATING EVIDENCE that the function
actually executed the exploit. The bpftrace sidecar (loaded by
``dast-init.sh`` BEFORE the privilege drop) observes every kernel
syscall in the sandbox. When a probe's string-evidence claims an
exploit fired but the syscall log shows no corresponding sink event,
the string match is almost certainly a content-overlap FP.

This is the lightweight version of Gemini's Fix #2-Full ("inject at
the trust boundary, intercept the sink") that uses infrastructure
ALREADY in place (per-probe bpftrace via dast/syscall_observability)
rather than rebuilding the sandbox harness.

── Attack-class coverage (v1) ──────────────────────────────────────

  * ssrf            — expects network_events to be non-empty. A
                       function that returns URL-shaped output but
                       never opened a socket didn't dispatch the
                       SSRF.
  * command_injection — expects ``exec_observed=True`` (an execve
                       fired). A function that returns ``uid=`` text
                       but spawned no process didn't actually run a
                       shell.
  * path_traversal   — expects openat on a path resembling the
                       attack input. A function whose output
                       contains ``root:x:0:0:`` but never opened a
                       file matched the class signature in-memory
                       content, not from a real read.

Other attack classes (code_injection, deserialization,
data_exfiltration, sql_injection, xxe, crypto_weakness, etc.) are
intentionally NOT gated here:

  * code_injection — Python ``exec()`` / ``eval()`` runs in-process
    bytecode; no execve fires for the legitimate-exploit case. The
    canary oracle already catches code_injection via /tmp file
    materialization.
  * deserialization — pickle / yaml RCE often resolves through
    in-process import machinery; no execve.
  * data_exfiltration — Phase 2's downstream-cap detector already
    handles the magnitude-amplification class. Network exfil is a
    sub-case of ssrf.
  * sql_injection — sandbox lacks a DB; the kernel sink is
    typically a write to a connected TCP socket, not distinctive
    enough to gate on.

── Fail-open posture ──────────────────────────────────────────────

The gate NEVER suppresses when it can't be sure:

  * Missing / None ``syscall_observations`` → fail-open.
  * ``total_events == 0`` → bpftrace likely didn't load (older
    Firecracker kernel without CONFIG_FTRACE_SYSCALLS). Fail-open
    so kernel-feature regressions don't cause silent suppression.
  * ``bpftrace_meta`` flags an error → fail-open.
  * Attack class not in the gated set → fail-open (no expectation,
    no suppression).

False suppression risk: a probe that REALLY exploits the function
but the sandbox blocks the underlying syscall (e.g., seccomp denial
of network for ssrf) would see no network_events. We'd suppress.
But: in that case, the string oracle wouldn't have fired either —
no connection means no remote content to return — so the suppression
is a no-op rather than a regression.

── Wired into ``dast/orchestrator.py`` as the 4th suppression
branch alongside ``purpose_aligned_return`` / ``no_network_io`` /
``downstream_cap_detected``. Always runs LAST so a finding that
passed all earlier precision gates still gets the syscall check
before landing as CONFIRMED.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MissingSinkInfo:
    """The expected kernel-level sink for an attack class that the
    sandbox did NOT observe during the probe run."""

    attack_class: str
    """e.g., ``"ssrf"``, ``"command_injection"``, ``"path_traversal"``."""

    expected_sink: str
    """Short label for the syscall that should have fired (used in
    the journal / suppression evidence string). E.g.,
    ``"network.connect"``, ``"execve"``, ``"openat on /etc/passwd"``."""

    rationale: str
    """Human-readable explanation of the missing-sink conclusion.
    Carried into the SUPPRESSED finding's ``runtime_evidence`` so
    operators can see why a string-oracle hit was overridden."""


#: Attack classes Phase 3 gates on syscall observations. The
#: orchestrator's lookup is by membership in this set — extending
#: coverage means adding to this set + the per-class check in
#: :func:`find_missing_expected_sink`.
_GATED_ATTACK_CLASSES: frozenset[str] = frozenset(
    {
        "ssrf",
        "command_injection",
        "path_traversal",
    }
)


def _bpftrace_observed_anything(syscall_observations: dict[str, Any]) -> bool:
    """True iff bpftrace actually captured at least one syscall AND
    didn't report a lifecycle error. Phase 3 fails OPEN when this
    returns False — kernel-feature limitation, not an exploit-absent
    signal."""
    total = int(syscall_observations.get("total_events") or 0)
    if total <= 0:
        return False
    meta = syscall_observations.get("bpftrace_meta") or {}
    if isinstance(meta, dict) and meta.get("error"):
        # bpftrace reported its own error (probe failed to attach,
        # tracepoint missing, etc.). Treat as unreliable.
        return False
    return True


def _extract_paths_from_input(args_json: str) -> list[str]:
    """Pull path-shaped strings out of an args_json blob so the
    path_traversal gate can compare against observed openat samples.

    Heuristic — looks for strings that contain ``/`` / ``\\`` or
    start with ``..``. Misses URL-encoded path traversals
    (``..%2F..%2Fetc%2Fpasswd``) — but those typically resolve to
    plain paths AFTER the function decodes them, so checking the raw
    input alone is conservative. Returns lowercased paths since the
    Linux openat tracepoint reports filenames as raw bytes (often
    lower-case for system paths)."""
    if not args_json:
        return []
    try:
        decoded = json.loads(args_json)
    except (json.JSONDecodeError, ValueError):
        return []

    paths: list[str] = []

    def _walk(v: Any) -> None:
        if isinstance(v, str):
            if "/" in v or "\\" in v or v.startswith(".."):
                paths.append(v.lower())
        elif isinstance(v, list):
            for x in v:
                _walk(x)
        elif isinstance(v, dict):
            for x in v.values():
                _walk(x)

    _walk(decoded)
    return paths


def find_missing_expected_sink(
    *,
    attack_class: str,
    syscall_observations: dict[str, Any] | None,
    args_json: str = "",
) -> MissingSinkInfo | None:
    """Inspect syscall_observations for the kernel-level sink that
    the declared ``attack_class`` would have fired in the sandbox.

    Returns :class:`MissingSinkInfo` describing the expected sink and
    why it's missing when the gate fires (the orchestrator turns this
    into a SUPPRESSED finding). Returns ``None`` when:

      * Attack class isn't gated by Phase 3.
      * No syscall data available (fail-open).
      * bpftrace didn't observe any events (fail-open).
      * The expected sink WAS observed (CONFIRMED stands).
    """
    if attack_class not in _GATED_ATTACK_CLASSES:
        return None
    if not syscall_observations or not isinstance(syscall_observations, dict):
        return None
    if not _bpftrace_observed_anything(syscall_observations):
        return None

    if attack_class == "ssrf":
        network_events = syscall_observations.get("network_events") or []
        if not network_events:
            return MissingSinkInfo(
                attack_class="ssrf",
                expected_sink="network.connect / socket",
                rationale=(
                    "ssrf probe CONFIRMED via string-oracle "
                    "(URL/IP-shaped output matched against the "
                    "attack-class signature library) BUT the sandbox "
                    "observed ZERO network syscalls (connect, socket, "
                    "sendto, etc.). The function returned URL-shaped "
                    "content but never opened a socket — the SSRF "
                    "primitive did not fire in this probe run. The "
                    "string-oracle hit is a content-overlap false "
                    "positive, not a real attack outcome."
                ),
            )
        return None

    if attack_class == "command_injection":
        if not bool(syscall_observations.get("exec_observed")):
            return MissingSinkInfo(
                attack_class="command_injection",
                expected_sink="execve / execveat",
                rationale=(
                    "command_injection probe CONFIRMED via "
                    "string-oracle (e.g., 'uid=' or 'gid=' in output) "
                    "BUT the sandbox observed ZERO execve/execveat "
                    "syscalls. The function did not spawn any "
                    "process — the command-shaped output was "
                    "synthesized in-process (e.g., string formatting, "
                    "cached fixture), not produced by an actual shell "
                    "running on the attack input."
                ),
            )
        return None

    if attack_class == "path_traversal":
        target_paths = _extract_paths_from_input(args_json)
        if not target_paths:
            # Couldn't recover a target from the args; can't verify
            # the openat. Fail-open rather than suppress on no info.
            return None

        # Collect every path-shaped string the sandbox observed via
        # openat samples + write_target_paths.
        samples = syscall_observations.get("samples_by_syscall") or {}
        openat_samples = samples.get("openat") or []
        write_paths = syscall_observations.get("write_target_paths") or []
        observed: list[str] = []
        for s in openat_samples:
            if isinstance(s, dict):
                p = s.get("filename") or s.get("path") or ""
                if p:
                    observed.append(str(p).lower())
        for p in write_paths:
            observed.append(str(p).lower())

        # Did the sandbox open ANY path resembling the attack target?
        # Match on either the full target or its tail two components
        # (so '/etc/passwd' attack input matches an openat sample of
        # ``/var/lib/foo/etc/passwd`` for a chrooted attempt — still
        # the exploit reaching for the sensitive file).
        for target in target_paths:
            tail_two = "/".join(target.rstrip("/").split("/")[-2:])
            for op in observed:
                if target in op or (tail_two and tail_two in op):
                    return None  # sink fired

        # No openat observed on the attack target -> string-oracle
        # hit was the file's BUILT-IN content (fixture string, cached
        # password file, etc.), not a fresh read.
        primary_target = target_paths[0]
        return MissingSinkInfo(
            attack_class="path_traversal",
            expected_sink=f"openat({primary_target})",
            rationale=(
                f"path_traversal probe CONFIRMED via string-oracle "
                f"(class signature like 'root:x:0:0:' matched in "
                f"function output) BUT the sandbox observed ZERO "
                f"openat syscalls on the attack target "
                f"({primary_target}). The function's output contained "
                f"the class signature, but the file at "
                f"{primary_target} was never actually opened during "
                f"this probe run. The string oracle hit on an "
                f"in-memory string (test fixture, hardcoded sample, "
                f"cached read) — not on content the function actually "
                f"exfiltrated via filesystem access."
            ),
        )

    return None


def extract_syscall_observations_from_events(
    events: list[Any],
) -> dict[str, Any] | None:
    """Pull the per-probe ``syscall_observations`` event payload out
    of a list of SandboxEvents. Each sandbox plan run emits exactly
    one such event when bpftrace loaded successfully. Returns
    ``None`` when:

      * No event of kind ``"syscall_observations"`` is present
        (kernel doesn't support the tracepoints — older Firecracker
        image, etc.).
      * The event payload doesn't parse into the expected dataclass
        (defensive — corruption, schema drift between sandbox image
        and parent).

    Importing :mod:`dast.syscall_observability` lazily so this
    module stays cheap to import for tests that don't need it.
    """
    if not events:
        return None
    try:
        from dast.syscall_observability import (  # noqa: PLC0415
            parse_syscall_observations,
        )
    except ImportError:
        return None
    from dataclasses import asdict as _asdict  # noqa: PLC0415

    for ev in events:
        if getattr(ev, "kind", None) != "syscall_observations":
            continue
        payload = getattr(ev, "payload", None)
        if payload is None:
            continue
        try:
            obs = parse_syscall_observations(payload)
            return _asdict(obs)
        except Exception:  # noqa: BLE001
            return None
    return None
