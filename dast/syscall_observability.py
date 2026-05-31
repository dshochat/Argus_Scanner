"""Parser for kernel-level syscall observability events.

Phase 2 of sandbox-observability-plan: the bpftrace sidecar (loaded
inside the sandbox by ``dast-init.sh``) emits one JSON object per
captured syscall to ``/tmp/syscalls.jsonl``. The sandbox entrypoint
drains the log at end-of-run and emits ONE :class:`SandboxEvent` of
kind ``syscall_observations`` containing the aggregated counts +
sampled detail records.

This module parses that event payload into typed observations that
feed into :class:`BehavioralProfile` (per-callable, when emitted by
the behavioral probe) or surface as standalone signals for Stage 2's
adversarial reasoning loop.

The schema is deliberately simple — counts and sampled records, no
inferred classifications. Stage 2's prompt does the classification
(e.g., "mprotect_exec_count > 0 → suspect JIT shellcode").

Closed gaps (per sandbox-observability-plan):
  * Gap 1: Raw-syscall bypass (ctypes.libc.execve)
  * Gap 2: Wide-filesystem writes
  * Gap 3: Non-standard ports + raw sockets
  * Gap 4: Memory-resident execution (mprotect_exec)
  * Gap 5: Process tree opacity
  * Gap 6: Capability + namespace deltas
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SyscallObservations:
    """Aggregated kernel-level syscall observations for one plan
    execution.

    Each field aggregates a class of malicious-behavior signal. Counts
    are bounded by what bpftrace observed in the 180-second window;
    samples are bounded by the entrypoint's emission caps.
    """

    #: Total syscalls observed (sum of all counts). Useful as a
    #: "did bpftrace actually run" sanity check.
    total_events: int = 0

    #: Per-syscall counts (e.g. ``{"execve": 3, "openat": 12, ...}``).
    counts_by_syscall: dict[str, int] = field(default_factory=dict)

    #: Up to SYSCALL_MAX_SAMPLES_PER_KIND sample records per syscall
    #: name, preserving args (filename for openat, target_uid for
    #: setuid, etc.). Stage 2 reads these for "what file did the
    #: target try to write" detail.
    samples_by_syscall: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    # ── Convenience flags (derived from counts, bool-typed for prompt
    # rendering simplicity) ─────────────────────────────────────────────

    #: True iff any ``execve`` or ``execveat`` fired. Catches raw-
    #: syscall command execution that bypasses the Python audit hook /
    #: JS child_process monkey patch.
    exec_observed: bool = False

    #: True iff ``mmap`` with PROT_EXEC OR ``mprotect`` setting
    #: PROT_EXEC fired. Classic shellcode pattern; legitimate JIT
    #: compilers (V8, JVM) also trigger this — Stage 2 prompt must
    #: account for context.
    memory_exec_observed: bool = False

    #: True iff any of setuid / setgid / capset / unshare fired —
    #: privilege-escalation or namespace-manipulation attempt.
    privilege_op_observed: bool = False

    #: True iff ``ptrace`` fired. Used by debuggers but ALSO classic
    #: sandbox-escape / anti-analysis primitive.
    ptrace_observed: bool = False

    #: True iff ``init_module`` or ``finit_module`` fired — kernel
    #: module loading. Extremely rare in normal code; strong signal of
    #: container escape attempt.
    kernel_module_load_observed: bool = False

    #: Distinct file paths that the target tried to open with
    #: O_WRONLY / O_RDWR / O_CREAT. Captures paths the runner uid
    #: lacks perms for (the openat tracepoint fires before EACCES is
    #: returned) — the key Gap-2 closure. Bounded to first 50 distinct.
    write_target_paths: list[str] = field(default_factory=list)

    #: Connect() / socket() events grouped by socket family/type when
    #: available. Bounded list of dicts.
    network_events: list[dict[str, Any]] = field(default_factory=list)

    #: bpftrace lifecycle / observability errors.
    bpftrace_meta: dict[str, Any] = field(default_factory=dict)


# Syscall names that fire the exec_observed flag.
_EXEC_SYSCALLS: frozenset[str] = frozenset({"execve", "execveat"})

# Syscall names that fire the memory_exec_observed flag.
_MEMORY_EXEC_SYSCALLS: frozenset[str] = frozenset({"mmap_exec", "mprotect_exec"})

# Syscall names that fire the privilege_op_observed flag.
_PRIVILEGE_SYSCALLS: frozenset[str] = frozenset(
    {"setuid", "setgid", "capset", "unshare"}
)

# Syscalls that count as filesystem-write attempts.
_WRITE_SYSCALLS: frozenset[str] = frozenset({"openat"})

# Syscalls that count as network events.
_NETWORK_SYSCALLS: frozenset[str] = frozenset({"connect", "socket"})

# Hard cap on write_target_paths length to bound event payload.
_MAX_WRITE_PATHS: int = 50

# Hard cap on network_events length.
_MAX_NETWORK_EVENTS: int = 50


def parse_syscall_observations(payload: dict[str, Any]) -> SyscallObservations:
    """Build a :class:`SyscallObservations` from the
    ``syscall_observations`` event payload emitted by the sandbox
    entrypoint.

    The payload shape (defined by the entrypoint emit):

      {
        "counts":  { "<syscall_name>": <count>, ... },
        "samples": { "<syscall_name>": [<record>, ...], ... },
        "meta":    { "start": <ts>, "end": <ts>, "lines_read": <n> },
      }

    Returns an empty observations object on malformed input — never
    raises. Stage 2's prompt rendering handles the empty case
    gracefully (no syscall section).
    """
    obs = SyscallObservations()
    if not isinstance(payload, dict):
        return obs

    counts_raw = payload.get("counts")
    samples_raw = payload.get("samples")
    meta_raw = payload.get("meta")

    if isinstance(counts_raw, dict):
        for sc_name, cnt in counts_raw.items():
            if not isinstance(sc_name, str) or not isinstance(cnt, int) or cnt < 0:
                continue
            obs.counts_by_syscall[sc_name] = cnt
            obs.total_events += cnt

    if isinstance(samples_raw, dict):
        for sc_name, samples in samples_raw.items():
            if not isinstance(sc_name, str) or not isinstance(samples, list):
                continue
            clean_samples = [s for s in samples if isinstance(s, dict)]
            if clean_samples:
                obs.samples_by_syscall[sc_name] = clean_samples

    if isinstance(meta_raw, dict):
        obs.bpftrace_meta = dict(meta_raw)

    # ── Derived flags + bounded lists ───────────────────────────────────
    obs.exec_observed = any(sc in obs.counts_by_syscall for sc in _EXEC_SYSCALLS)
    obs.memory_exec_observed = any(
        sc in obs.counts_by_syscall for sc in _MEMORY_EXEC_SYSCALLS
    )
    obs.privilege_op_observed = any(
        sc in obs.counts_by_syscall for sc in _PRIVILEGE_SYSCALLS
    )
    obs.ptrace_observed = "ptrace" in obs.counts_by_syscall
    obs.kernel_module_load_observed = (
        "init_module" in obs.counts_by_syscall
        or "finit_module" in obs.counts_by_syscall
    )

    # write_target_paths: distinct file paths from openat samples
    seen_paths: set[str] = set()
    for sc_name in _WRITE_SYSCALLS:
        for sample in obs.samples_by_syscall.get(sc_name, []):
            filename = sample.get("filename")
            if not isinstance(filename, str) or not filename:
                continue
            if filename in seen_paths:
                continue
            seen_paths.add(filename)
            obs.write_target_paths.append(filename)
            if len(obs.write_target_paths) >= _MAX_WRITE_PATHS:
                break
        if len(obs.write_target_paths) >= _MAX_WRITE_PATHS:
            break

    # network_events: connect + socket samples, lightly summarized
    for sc_name in _NETWORK_SYSCALLS:
        for sample in obs.samples_by_syscall.get(sc_name, []):
            # Drop bulky/uninteresting fields; keep only what Stage 2
            # benefits from seeing (syscall name + relevant args).
            event = {
                "syscall": sample.get("syscall", sc_name),
                "comm": sample.get("comm", ""),
            }
            for field_name in ("sockfd", "family", "type", "protocol"):
                if field_name in sample:
                    event[field_name] = sample[field_name]
            obs.network_events.append(event)
            if len(obs.network_events) >= _MAX_NETWORK_EVENTS:
                break
        if len(obs.network_events) >= _MAX_NETWORK_EVENTS:
            break

    return obs


def summarize_for_prompt(obs: SyscallObservations) -> str:
    """Render observations as a compact human-readable summary for
    embedding in Stage 2's adversarial-reasoning prompt.

    Empty observations render as a single line so the prompt template
    can include the section unconditionally without leaking "no data"
    boilerplate.

    Format (deterministic, bounded length):

        Kernel syscall observability (bpftrace):
          - exec: 2 (execve, execveat present)
          - memory_exec: PROT_EXEC mmap/mprotect observed
          - privilege_ops: setuid observed
          - openat write targets: /etc/cron.d/argus_persist_test, ...
          - network: 5 connect events
    """
    if obs.total_events == 0:
        return "Kernel syscall observability (bpftrace): no kernel events captured."

    lines = ["Kernel syscall observability (bpftrace):"]

    # Per-syscall counts (sorted for determinism)
    if obs.counts_by_syscall:
        sorted_counts = sorted(obs.counts_by_syscall.items(), key=lambda kv: (-kv[1], kv[0]))
        compact = ", ".join(f"{n}={c}" for n, c in sorted_counts[:10])
        lines.append(f"  - counts: {compact}")

    if obs.exec_observed:
        lines.append("  - exec: process exec syscall fired (closes V0 raw-syscall bypass gap)")
    if obs.memory_exec_observed:
        lines.append(
            "  - memory_exec: PROT_EXEC mmap/mprotect observed "
            "(possible JIT shellcode; legitimate in V8/JVM contexts)"
        )
    if obs.privilege_op_observed:
        lines.append(
            "  - privilege_ops: setuid/setgid/capset/unshare attempted "
            "(privilege-escalation or namespace manipulation signal)"
        )
    if obs.ptrace_observed:
        lines.append(
            "  - ptrace: PTRACE syscall fired (debugger or sandbox-escape primitive)"
        )
    if obs.kernel_module_load_observed:
        lines.append(
            "  - kernel_module_load: init_module / finit_module fired "
            "(extremely rare; strong container-escape signal)"
        )

    if obs.write_target_paths:
        # Truncate path list for prompt budget; first 10 paths.
        preview = obs.write_target_paths[:10]
        lines.append(
            "  - openat write targets (incl. EACCES attempts): "
            + ", ".join(preview)
        )
        if len(obs.write_target_paths) > 10:
            lines.append(f"    ... and {len(obs.write_target_paths) - 10} more")

    if obs.network_events:
        lines.append(
            f"  - network: {len(obs.network_events)} connect/socket events"
        )

    return "\n".join(lines)


__all__ = [
    "SyscallObservations",
    "parse_syscall_observations",
    "summarize_for_prompt",
]
