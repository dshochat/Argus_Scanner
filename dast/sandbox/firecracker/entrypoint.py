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
STDIO_EXCERPT_CAP = 1024  # chars per command, per stream
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
