#!/usr/bin/env python3
"""DAST sandbox in-VM entrypoint.

Invoked as PID 1 in the Firecracker microvm (Fly.io machine). Reads
the plan + target file from environment variables (set by the orchestrator
when the machine is created), executes the plan in controlled
subprocesses, captures telemetry, and emits structured event JSON lines
on stdout. Each line is one event the orchestrator parses into a
:class:`SandboxEvent`.

ENV CONTRACT (set by FirecrackerSandboxClient when creating machine)
====================================================================

  PLAN_ID                str    Unique plan identifier
  FILE_ID                str    Logical file id (used for events)
  HYPOTHESIS_ID          str    L1 or Phase-B hypothesis id
  FILE_NAME              str    On-disk filename inside /workspace
  FILE_CONTENT_B64GZ     str    base64(gzip(file_bytes)) — file contents
  PLAN_COMMANDS          str    JSON list[str] of shell commands to run
  PLAN_TIMEOUT_SEC       str    Per-command wall-clock cap (default 30)
  EXPECTED_EVIDENCE      str    Free-text hint of what to look for
  EXPECTED_PATTERNS      str    JSON list[str] — patterns to search in source
                                 (drives `code_pattern_observed` events)

OUTPUT (stdout, one JSON object per line)
=========================================

  {"event_id": "...", "kind": "...", "payload": {...}}

Event kinds emitted (taxonomy mapped 1:1 to SandboxEvent kinds in
`firecracker_event_types.md`):

  process_spawn           A command in the plan started
  process_exit            A command exited (with stdout / stderr / code)
  process_timeout         A command exceeded PLAN_TIMEOUT_SEC
  network_call            Detected attempted network call (DNS fail / etc.)
  network_call_captured   Captured outbound HTTP/TLS attempt via the
                          iptables-redirected capture server. Includes
                          method/path/headers/body for HTTP, SNI host
                          for TLS handshakes.
  file_writes_observed    Set of new-or-changed files in /workspace
  code_pattern_observed   A pattern in EXPECTED_PATTERNS was found in source
  syscall_observations    Kernel-level syscall counts + samples captured
                          by bpftrace sidecar (Phase 2 observability).
                          Includes execve / openat / connect / mmap-exec
                          / setuid / unshare / etc. Closes V0 bypass
                          paths (raw libc, wide-fs writes, raw sockets).
  syscall_observability_error  bpftrace stderr if it died or failed to
                          attach. Diagnostic-only; orchestrator falls
                          back to language-instrumentation alone.
  syscall_drain_error     /tmp/syscalls.jsonl parse failed.
  env_error               Sandbox-side problem (decoding, etc.)
  execution_complete      Sentinel — terminal event, always last

The entrypoint always exits 0 regardless of the plan's exit codes;
plan-level success is communicated via the events. Non-zero entrypoint
exit means a sandbox-internal failure (env decode, etc.) and should be
flagged by the orchestrator.

Safety boundary
===============

* Plans run as user `runner`, not root.
* /workspace is the only writable directory the entrypoint touches.
* No outbound network is ALLOWED at the Fly app config level (no
  services declared); attempts to reach hosts surface as
  `network_call` events with `blocked: True`.
* Stdout from the plan is excerpted (1KB cap per command) before
  emission, to prevent leaking large samples back to the orchestrator.
* Machine auto-destroys after exit (set by the orchestrator when
  creating the machine).
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

WORKSPACE = Path("/workspace")
#: Cap on per-command stdout/stderr captured back to the orchestrator.
#:
#: Tuning history:
#:   * 1024 (initial): sized for single-function probe RESULT_JSON
#:     markers (one return value, value_preview up to 600 chars + framing).
#:     Adequate for v1.5 single-function probes; insufficient for the
#:     larger marker shapes that landed later.
#:   * 8192 (current, v1.6): bumped after Phase 3 Stage 1 behavioral
#:     probe and (earlier) Phase 2 v1.0 chain harness rewrite both hit
#:     silent-failure mode where the marker exceeded 1024 chars and
#:     got truncated mid-content. Truncated JSON failed parse →
#:     orchestrator returned empty profile / per_step=(no steps). The
#:     8x increase gives headroom for:
#:       * Behavioral probe profiles (up to MAX_CALLABLES_EXPLORED × 3
#:         invocations × ~250 chars per invocation entry) ≈ 6KB
#:       * Multi-step chain CHAIN_RESULT_JSON (3 steps × ~700 chars
#:         per_step + framing) ≈ 2.5KB
#:       * Future Phase 3 Stage 2 adversarial-loop trace summaries
#:     Pushing the cap further risks Fly log line truncation; 8192 is
#:     well within Fly's typical 64KB-per-line budget.
STDIO_EXCERPT_CAP = 8192  # chars per command, per stream

#: Path the harness writes its full structured result to. Bypasses
#: Fly's per-log-line size cap (≈ 4KB) which truncates large
#: ``process_exit.stdout_excerpt`` payloads mid-content. See
#: ``_drain_probe_result_file`` for the read + chunk-emit flow.
#:
#: All harnesses (behavioral probe, chain, single-function) that emit
#: large structured markers write the same JSON to this path in
#: addition to printing the inline marker to stdout. Backward compat:
#: small markers still emit on stdout for any reader that doesn't
#: support the chunk-event reassembly path yet.
PROBE_RESULT_FILE = "/workspace/argus_probe_result.json"

#: Maximum payload size per ``probe_result_chunk`` event. Sized so the
#: full event JSON (event_id + kind + payload framing + chunk content)
#: stays well below Fly's per-log-line cap (~4KB observed in practice).
#: 1500 bytes content + ~200 bytes framing = ~1700-byte log lines.
PROBE_CHUNK_BYTES = 1500

NETWORK_DETECT_PATTERNS = (
    r"name or service not known",
    r"nodename nor servname",
    r"no address associated with hostname",
    r"name resolution",
    r"connection refused",
    r"network is unreachable",
    r"urlopen error",
    r"failed to establish a new connection",
    r"getaddrinfo failed",
)
NETWORK_DETECT_RE = re.compile("|".join(NETWORK_DETECT_PATTERNS), re.IGNORECASE)

#: Caps on syscall-observation aggregation (Phase 2 v0.1).
#: Tuned for typical 60s plan + 180s bpftrace budget. A target firing
#: 10k+ syscalls/sec would produce a multi-MB jsonl; we read up to
#: SYSCALL_LOG_MAX_BYTES and bound the sample volume separately so
#: Stage 2's prompt doesn't see a wall of detail.
SYSCALL_MAX_SAMPLES_PER_KIND = 20
SYSCALL_MAX_TOTAL_SAMPLES = 200
SYSCALL_LOG_MAX_BYTES = 16 * 1024 * 1024  # 16 MB


def emit(kind: str, payload: dict, event_id: str | None = None) -> None:
    if event_id is None:
        h = hashlib.sha256(
            f"{kind}:{json.dumps(payload, sort_keys=True, default=str)}:{time.time_ns()}".encode()
        ).hexdigest()[:8]
        event_id = f"evt-{h}"
    print(json.dumps({"event_id": event_id, "kind": kind, "payload": payload}), flush=True)


def main() -> int:
    started = time.time()

    plan_id = os.environ.get("PLAN_ID", "unknown")
    file_id = os.environ.get("FILE_ID", "unknown")
    hypothesis_id = os.environ.get("HYPOTHESIS_ID", "unknown")
    # Strip any directory components — defends against the orchestrator
    # accidentally forwarding a path with separators.
    file_name = Path(os.environ.get("FILE_NAME", "target.bin")).name or "target.bin"
    file_b64 = os.environ.get("FILE_CONTENT_B64GZ", "")
    commands_json = os.environ.get("PLAN_COMMANDS", "[]")
    timeout_sec = int(os.environ.get("PLAN_TIMEOUT_SEC", "30") or "30")
    expected_evidence = os.environ.get("EXPECTED_EVIDENCE", "")
    expected_patterns_json = os.environ.get("EXPECTED_PATTERNS", "")

    emit(
        "execution_start",
        {
            "plan_id": plan_id,
            "file_id": file_id,
            "hypothesis_id": hypothesis_id,
            "file_name": file_name,
            "timeout_sec": timeout_sec,
        },
    )

    # 1. Materialize target file
    WORKSPACE.mkdir(exist_ok=True)
    target_path = WORKSPACE / file_name
    if file_b64:
        try:
            content = gzip.decompress(base64.b64decode(file_b64))
            target_path.write_bytes(content)
        except Exception as e:
            emit("env_error", {"reason": "file_decode_failed", "detail": str(e)[:200]})
            emit(
                "execution_complete",
                {"elapsed_ms": int((time.time() - started) * 1000), "halted_early": True},
                event_id="evt-final",
            )
            return 0

    # 2. Parse plan commands
    try:
        commands = json.loads(commands_json)
        if not isinstance(commands, list):
            raise ValueError("commands not a list")
    except Exception as e:
        emit("env_error", {"reason": "commands_parse_failed", "detail": str(e)[:200]})
        emit(
            "execution_complete",
            {"elapsed_ms": int((time.time() - started) * 1000), "halted_early": True},
            event_id="evt-final",
        )
        return 0

    # 3. Snapshot pre-execution filesystem
    files_before: dict[str, int] = {}
    for p in WORKSPACE.rglob("*"):
        if p.is_file():
            try:
                files_before[p.relative_to(WORKSPACE).as_posix()] = p.stat().st_size
            except OSError:
                pass

    # 4. Execute commands
    for i, cmd in enumerate(commands):
        if not isinstance(cmd, str) or not cmd.strip():
            continue

        # Defensive: detect bare Python source emitted as a shell command.
        # The planner occasionally drops a stray Python line (e.g.
        # ``import json``) as a standalone command — usually a heredoc
        # whose terminator got mis-quoted by the LLM. /bin/sh then
        # interprets ``import`` / ``from`` / ``def`` etc. as shell
        # builtins-not-found and emits ``exit_code=127 /bin/sh:
        # import: not found`` with no useful trace. Mark it as
        # ``env_error`` with a clear reason so the orchestrator's
        # rejection_reason text points at the planner bug instead of
        # the shell error, and skip execution (no point — would fail).
        first = cmd.lstrip().split(None, 1)[0] if cmd.lstrip() else ""
        _PY_LEADING_TOKENS = {
            "import", "from", "def", "class", "async", "await",
            "print(", "if", "elif", "else:", "for", "while", "try:",
            "except", "finally:", "with", "return", "yield", "raise",
            "lambda", "@",
        }
        looks_like_python = (
            first in _PY_LEADING_TOKENS
            or any(first.startswith(t) for t in (
                "print(", "@", "def ", "class ", "async ", "await ",
            ))
        )
        if looks_like_python and "python3" not in cmd[:50]:
            emit(
                "env_error",
                {
                    "reason": "plan_command_bare_python",
                    "step": i,
                    "detail": (
                        f"Plan command starts with Python token {first!r} "
                        f"but is not wrapped in `python3 -c '...'` or "
                        f"`python3 /path/script.py`. The sandbox launcher "
                        f"runs commands via /bin/sh, which would interpret "
                        f"this as a shell builtin and fail. Wrap multi-line "
                        f"Python in `python3 -c '...'` with proper "
                        f"single-quote escaping, or write the script to "
                        f"/workspace/<name>.py first and invoke it."
                    ),
                    "cmd_excerpt": cmd[:240],
                },
            )
            emit(
                "process_exit",
                {
                    "step": i,
                    "exit_code": 127,
                    "stdout_excerpt": "",
                    "stderr_excerpt": (
                        f"argus-entrypoint: refused bare-Python command "
                        f"(starts with {first!r}); wrap in python3 -c '...'."
                    ),
                },
            )
            continue

        emit("process_spawn", {"step": i, "cmd": cmd[:300]})
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                cwd=str(WORKSPACE),
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            emit("process_timeout", {"step": i, "limit_sec": timeout_sec})
            continue

        stdout_excerpt = (proc.stdout or "")[:STDIO_EXCERPT_CAP]
        stderr_excerpt = (proc.stderr or "")[:STDIO_EXCERPT_CAP]
        emit(
            "process_exit",
            {
                "step": i,
                "exit_code": proc.returncode,
                "stdout_excerpt": stdout_excerpt,
                "stderr_excerpt": stderr_excerpt,
            },
        )

        # 4a-bis. File-based transport drain. Bypasses Fly's per-log-
        # line ~4KB cap that silently truncates the ``stdout_excerpt``
        # field on ``process_exit`` for any probe whose marker output
        # exceeds the cap. Harnesses that produce structured markers
        # (behavioral probe, chain, single-function on large returns)
        # are instructed to ALSO write the full marker payload to
        # ``PROBE_RESULT_FILE``; the entrypoint reads + chunks it into
        # ``probe_result_chunk`` events sized to fit the log line cap.
        # The orchestrator-side parser reassembles chunks and prefers
        # this channel over stdout for structured-result parsing.
        try:
            result_path = Path(PROBE_RESULT_FILE)
            if result_path.exists() and result_path.is_file():
                try:
                    content = result_path.read_text(encoding="utf-8", errors="replace")
                except Exception as _read_err:
                    emit(
                        "probe_result_error",
                        {
                            "step": i,
                            "reason": "read_failed",
                            "detail": str(_read_err)[:200],
                        },
                    )
                    content = ""
                if content:
                    total = (len(content) + PROBE_CHUNK_BYTES - 1) // PROBE_CHUNK_BYTES
                    for idx in range(total):
                        chunk = content[idx * PROBE_CHUNK_BYTES : (idx + 1) * PROBE_CHUNK_BYTES]
                        emit(
                            "probe_result_chunk",
                            {
                                "step": i,
                                "chunk_index": idx,
                                "total_chunks": total,
                                "content": chunk,
                            },
                        )
                # Clean up for the next command so concurrent commands
                # don't see stale results.
                try:
                    result_path.unlink()
                except Exception:
                    pass
        except Exception as _drain_err:
            # Drain failure must not poison the main event stream —
            # journal it as a diagnostic and continue.
            emit(
                "probe_result_error",
                {
                    "step": i,
                    "reason": "drain_failed",
                    "detail": str(_drain_err)[:200],
                },
            )

        # 4b. Detect attempted-network signals from stderr
        for line in (proc.stderr or "").splitlines()[:80]:
            if NETWORK_DETECT_RE.search(line):
                emit(
                    "network_call",
                    {
                        "step": i,
                        "blocked": True,
                        "evidence_line": line[:200],
                    },
                )
                break  # one per command — don't spam

    # 5. Filesystem diff
    files_after: dict[str, int] = {}
    for p in WORKSPACE.rglob("*"):
        if p.is_file():
            try:
                files_after[p.relative_to(WORKSPACE).as_posix()] = p.stat().st_size
            except OSError:
                pass
    new_or_changed: list[dict] = []
    for path, size in files_after.items():
        before_size = files_before.get(path)
        if before_size is None:
            new_or_changed.append({"path": path, "size": size, "kind": "created"})
        elif before_size != size:
            new_or_changed.append({"path": path, "size": size, "kind": "modified"})
    if new_or_changed:
        emit("file_writes_observed", {"changes": new_or_changed[:50]})

    # 5b. Drain the capture server's log of redirected outbound calls.
    # iptables NAT (set up by dast-init.sh) redirects TCP 80/443 from
    # uid 1000 (runner) → 127.0.0.1:8000. The capture server logs each
    # connection to /tmp/captured.jsonl. We surface those as
    # `network_call_captured` events.
    capture_path = Path("/tmp/captured.jsonl")
    if capture_path.exists():
        try:
            for line in capture_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Skip server-internal sentinels — only emit actual captures.
                # tcp_server_start / dns_server_start = "server bound port X"
                # server_start = "all server threads launched"
                # accept_error / capture_error / bind_error / dns_error = capture-side issues
                if rec.get("kind") in (
                    "server_start",
                    "tcp_server_start",
                    "dns_server_start",
                    "accept_error",
                    "capture_error",
                    "bind_error",
                    "dns_error",
                    "dns_bind_error",
                ):
                    continue
                # Trim oversize fields before emission
                payload = {
                    "capture_kind": rec.get("kind"),
                    "peer": rec.get("peer"),
                    "size": rec.get("size"),
                    "timestamp": rec.get("timestamp"),
                }
                if rec.get("kind") == "http_request":
                    payload.update(
                        {
                            "method": rec.get("method"),
                            "path": rec.get("path"),
                            "headers": rec.get("headers"),
                            "body_excerpt": (rec.get("body_excerpt") or "")[:1500],
                        }
                    )
                elif rec.get("kind") == "tls_clienthello":
                    payload["sni"] = rec.get("sni")
                    payload["raw_excerpt_hex"] = (rec.get("raw_excerpt_hex") or "")[:128]
                elif rec.get("kind") == "dns_query":
                    payload.update(
                        {
                            "qname": rec.get("qname"),
                            "qtype": rec.get("qtype"),
                            "responded_with": rec.get("responded_with"),
                        }
                    )
                else:
                    payload["raw_excerpt_hex"] = (rec.get("raw_excerpt_hex") or "")[:256]
                emit("network_call_captured", payload)
        except Exception as e:
            emit(
                "env_error",
                {"reason": "captured_jsonl_read_failed", "detail": str(e)[:200]},
            )

    # 5c. Drain bpftrace syscall observability log (Phase 2 v0.1).
    # /tmp/syscalls.jsonl contains one JSON object per syscall captured
    # by argus-syscalls.bt (loaded by dast-init.sh as a root sidecar).
    # We aggregate counts + a bounded sample of detail records, then
    # emit ONE `syscall_observations` event per plan.
    #
    # Aggregation strategy:
    #   * count by syscall name
    #   * collect up to N sample records per syscall (preserves arg
    #     detail like filename for openat, target_uid for setuid)
    #   * total bounded — never emit > MAX_SYSCALL_SAMPLES regardless
    #     of stream volume
    syscall_path = Path("/tmp/syscalls.jsonl")
    if syscall_path.exists():
        try:
            syscall_counts: dict[str, int] = {}
            syscall_samples: dict[str, list[dict]] = {}
            total_samples = 0
            bpftrace_meta: dict = {"start": None, "end": None, "lines_read": 0}
            raw = syscall_path.read_text(encoding="utf-8", errors="replace")
            if len(raw) > SYSCALL_LOG_MAX_BYTES:
                raw = raw[:SYSCALL_LOG_MAX_BYTES]
            for line in raw.splitlines():
                bpftrace_meta["lines_read"] += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Meta records (bpftrace_start / bpftrace_timeout /
                # bpftrace_end) get tracked separately from syscall
                # records.
                kind = rec.get("kind", "")
                if kind == "bpftrace_start":
                    bpftrace_meta["start"] = rec.get("ts")
                    continue
                if kind in ("bpftrace_timeout", "bpftrace_end"):
                    bpftrace_meta["end"] = rec.get("ts")
                    continue
                sc = rec.get("syscall", "")
                if not sc:
                    continue
                syscall_counts[sc] = syscall_counts.get(sc, 0) + 1
                if total_samples < SYSCALL_MAX_TOTAL_SAMPLES:
                    per_sc = syscall_samples.setdefault(sc, [])
                    if len(per_sc) < SYSCALL_MAX_SAMPLES_PER_KIND:
                        # Drop the noisy ts field from samples (we have
                        # the start/end meta); keep the per-event details.
                        sample = {k: v for k, v in rec.items() if k != "ts"}
                        per_sc.append(sample)
                        total_samples += 1
            if syscall_counts or bpftrace_meta["lines_read"] > 0:
                emit(
                    "syscall_observations",
                    {
                        "counts": syscall_counts,
                        "samples": syscall_samples,
                        "meta": bpftrace_meta,
                    },
                )
        except Exception as _sc_err:
            # Syscall drain is best-effort — never poison the main
            # event stream. Emit diagnostic and continue.
            emit(
                "syscall_drain_error",
                {"detail": str(_sc_err)[:200]},
            )
        # Also emit bpftrace stderr if it died — helps debug "kernel
        # doesn't support BPF" failure mode in a fresh image.
        err_path = Path("/tmp/bpftrace.err")
        if err_path.exists():
            try:
                err_content = err_path.read_text(encoding="utf-8", errors="replace")
                if err_content.strip():
                    emit(
                        "syscall_observability_error",
                        {"stderr_excerpt": err_content[:1500]},
                    )
            except OSError:
                pass

    # 6. Pattern-presence (drives `code_pattern_observed` for Phase B)
    if expected_patterns_json:
        try:
            pats = json.loads(expected_patterns_json)
            if isinstance(pats, list) and target_path.exists():
                source_text = target_path.read_text(errors="replace")
                for pat in pats:
                    if isinstance(pat, str) and pat and pat in source_text:
                        emit(
                            "code_pattern_observed",
                            {
                                "pattern": pat[:120],
                                "file": file_name,
                                "exploit_demonstrated": False,
                            },
                        )
        except json.JSONDecodeError:
            pass

    elapsed_ms = int((time.time() - started) * 1000)
    emit(
        "execution_complete",
        {"elapsed_ms": elapsed_ms, "expected_evidence": expected_evidence[:200]},
        event_id="evt-final",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
