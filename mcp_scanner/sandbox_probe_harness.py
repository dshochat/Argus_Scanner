#!/usr/bin/env python3
"""In-sandbox MCP probe harness.

This script runs INSIDE the Firecracker sandbox VM. The host (Argus
on the operator's machine) stages it into ``/workspace/`` along with
a probe-spec JSON file, then submits a SandboxPlan whose entrypoint
is ``python3 /workspace/mcp_probe_harness.py``.

What the harness does:

  1. Read the probe spec from the path passed via ``--probe-spec``.
  2. Spawn the user-supplied MCP launch command as a subprocess. Its
     network egress (during all subsequent probe payloads) is
     auto-intercepted by the in-sandbox capture-server.py — we don't
     have to touch that here.
  3. Run the MCP initialize handshake, then tools/list +
     resources/list + prompts/list to (re)build the surface map. The
     host already enumerated the server but the surface map can drift
     between runs and we want fresh evidence.
  4. For each probe in the spec, invoke ``tools/call`` with the
     supplied arguments. Record the response shape, the JSON-RPC
     ``isError`` flag, elapsed time, and any stderr the server
     emitted during that call.
  5. Write the aggregated result to the path passed via ``--result``.
     The host reads it back from the sandbox trace's
     ``probe_result_json`` field.

Stdlib-only — runs on any image tier (lean / rich_python / ml_tools)
without requiring pip-install of the official ``mcp`` SDK inside the
sandbox.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from typing import Any


def _read_line(stream: Any, timeout: float = 30.0) -> str:
    """Read one line from a non-blocking BufferedReader. We use
    ``select`` under the hood via ``stream.readline()`` which is
    blocking; the timeout is enforced by an outer wall-clock check.
    """
    deadline = time.monotonic() + timeout
    parts: list[bytes] = []
    while time.monotonic() < deadline:
        chunk = stream.readline()
        if not chunk:
            time.sleep(0.05)
            continue
        parts.append(chunk)
        if chunk.endswith(b"\n"):
            break
    return b"".join(parts).decode("utf-8", errors="replace")


def _send(proc: subprocess.Popen[bytes], msg: dict[str, Any]) -> None:
    data = (json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    assert proc.stdin is not None
    proc.stdin.write(data)
    proc.stdin.flush()


def _recv(
    proc: subprocess.Popen[bytes], expected_id: int | None, timeout: float = 10.0
) -> dict[str, Any]:
    """Loop until we see a response matching ``expected_id`` (or a
    notification if ``expected_id is None``). Skips intermediate
    notifications + mismatched ids — mirrors the host client's logic.
    """
    assert proc.stdout is not None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = _read_line(proc.stdout, timeout=max(deadline - time.monotonic(), 0.1))
        if not line.strip():
            raise TimeoutError("no response from MCP server")
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if expected_id is None:
            return obj
        # Notification — skip.
        if "method" in obj and "id" not in obj:
            continue
        if obj.get("id") == expected_id:
            return obj
        # Mismatched id — keep reading.
    raise TimeoutError(f"no response with id={expected_id} within {timeout}s")


# ── MCP discovery ────────────────────────────────────────────────────


def _initialize(proc: subprocess.Popen[bytes], request_id: int) -> dict[str, Any]:
    _send(
        proc,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "argus-mcp-harness", "version": "1.12"},
            },
        },
    )
    resp = _recv(proc, expected_id=request_id, timeout=10.0)
    # Notify initialized — fire-and-forget.
    _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    return resp


def _list(proc: subprocess.Popen[bytes], request_id: int, method: str) -> dict[str, Any]:
    _send(proc, {"jsonrpc": "2.0", "id": request_id, "method": method})
    try:
        return _recv(proc, expected_id=request_id, timeout=10.0)
    except TimeoutError:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -1, "message": "timeout"}}


def _classify_param(name: str, schema: dict[str, Any]) -> str:
    """Tiny self-contained classifier so the harness doesn't need to
    import the host's mcp_scanner.classifier module.

    The host re-classifies on parse-back too — this in-sandbox copy
    just produces a "best-effort" value the host uses if its own
    re-classification fails. Single source of truth is
    mcp_scanner.classifier on the host.
    """
    name_lower = name.lower()
    fmt = schema.get("format")
    if isinstance(fmt, str):
        f = fmt.lower()
        if f in ("uri", "url", "uri-reference", "iri"):
            return "url"
        if f in ("hostname", "idn-hostname", "ipv4", "ipv6"):
            return "host"
        if f in ("path", "file", "file-path"):
            return "path"
    for needle, cls in (
        ("endpoint", "url"), ("webhook", "url"), ("callback", "url"),
        ("uri", "url"), ("url", "url"), ("hostname", "host"),
        ("host", "host"), ("address", "host"), ("filename", "path"),
        ("file_path", "path"), ("file", "path"), ("path", "path"),
        ("command", "command"), ("cmd", "command"),
        ("query", "query"), ("sql", "query"),
    ):
        if needle in name_lower:
            return cls
    type_ = schema.get("type")
    if type_ == "string":
        return "fuzz"
    if type_ in ("integer", "number"):
        return "integer"
    if type_ == "boolean":
        return "boolean"
    return "unknown"


def _build_surface_dump(
    *,
    launch_command: str,
    init_result: dict[str, Any],
    tools_list: list[dict[str, Any]],
    resources_list: list[dict[str, Any]],
    prompts_list: list[dict[str, Any]],
    discovery_errors: list[str],
) -> dict[str, Any]:
    """Build a plain-dict version of MCPSurfaceMap. The host
    re-validates via Pydantic on parse-back."""
    init_data = init_result.get("result") or {}
    tools_out: list[dict[str, Any]] = []
    for t in tools_list:
        input_schema = t.get("inputSchema") or {}
        properties = input_schema.get("properties") if isinstance(input_schema, dict) else {}
        required_list = input_schema.get("required") or [] if isinstance(input_schema, dict) else []
        required_set = set(required_list) if isinstance(required_list, list) else set()
        params: list[dict[str, Any]] = []
        if isinstance(properties, dict):
            for pname, pschema in properties.items():
                if not isinstance(pschema, dict):
                    pschema = {}
                params.append(
                    {
                        "name": pname,
                        "param_class": _classify_param(pname, pschema),
                        "required": pname in required_set,
                        "json_schema": pschema,
                    }
                )
        tools_out.append(
            {
                "name": t.get("name") or "",
                "description": t.get("description") or "",
                "params": params,
                "raw_input_schema": input_schema if isinstance(input_schema, dict) else {},
            }
        )
    resources_out = [
        {
            "uri": r.get("uri") or "",
            "name": r.get("name") or "",
            "description": r.get("description") or "",
            "mime_type": r.get("mimeType"),
        }
        for r in resources_list
        if isinstance(r, dict)
    ]
    prompts_out = [
        {
            "name": p.get("name") or "",
            "description": p.get("description") or "",
            "arguments": p.get("arguments") or [],
        }
        for p in prompts_list
        if isinstance(p, dict)
    ]
    return {
        "target": launch_command,
        "transport": "stdio",
        "protocol_version": init_data.get("protocolVersion") or "",
        "server_info": init_data.get("serverInfo") or {},
        "capabilities": init_data.get("capabilities") or {},
        "tools": tools_out,
        "resources": resources_out,
        "prompts": prompts_out,
        "discovery_errors": discovery_errors,
    }


# ── Main loop ────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-spec", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args(argv)

    with open(args.probe_spec, encoding="utf-8") as f:
        spec = json.load(f)
    launch_command = spec.get("launch_command") or ""
    probes = spec.get("probes") or []
    if not launch_command:
        _write_result(args.result, error="empty launch_command")
        return 2

    # Spawn the MCP server. Stderr piped so we can attribute crashes
    # to specific probes. cwd /workspace to keep relative paths sane.
    proc = subprocess.Popen(
        shlex.split(launch_command, posix=os.name != "nt"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/workspace" if os.path.isdir("/workspace") else None,
    )

    request_id = 1
    diagnostics: list[str] = []
    discovery_errors: list[str] = []

    try:
        init_resp = _initialize(proc, request_id)
        request_id += 1
        if "error" in init_resp:
            diagnostics.append(
                f"initialize error: {init_resp['error']}"
            )

        tools_resp = _list(proc, request_id, "tools/list")
        request_id += 1
        tools_data = (tools_resp.get("result") or {}).get("tools") or []
        if "error" in tools_resp:
            discovery_errors.append(f"tools/list: {tools_resp['error']}")

        resources_resp = _list(proc, request_id, "resources/list")
        request_id += 1
        resources_data = (resources_resp.get("result") or {}).get("resources") or []
        if "error" in resources_resp:
            discovery_errors.append(f"resources/list: {resources_resp['error']}")

        prompts_resp = _list(proc, request_id, "prompts/list")
        request_id += 1
        prompts_data = (prompts_resp.get("result") or {}).get("prompts") or []
        if "error" in prompts_resp:
            discovery_errors.append(f"prompts/list: {prompts_resp['error']}")

        surface_dump = _build_surface_dump(
            launch_command=launch_command,
            init_result=init_resp,
            tools_list=tools_data,
            resources_list=resources_data,
            prompts_list=prompts_data,
            discovery_errors=discovery_errors,
        )

        responses: list[dict[str, Any]] = []
        for probe in probes:
            if not isinstance(probe, dict):
                continue
            tool_name = probe.get("tool_name") or ""
            arguments = probe.get("arguments") or {}
            t0 = time.monotonic()
            note = ""
            is_error = False
            resp: dict[str, Any] = {}
            try:
                _send(
                    proc,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "tools/call",
                        "params": {"name": tool_name, "arguments": arguments},
                    },
                )
                resp = _recv(proc, expected_id=request_id, timeout=15.0)
                request_id += 1
                if "error" in resp:
                    is_error = True
                else:
                    result_obj = resp.get("result") or {}
                    is_error = bool(result_obj.get("isError"))
            except TimeoutError:
                note = "timeout"
                is_error = True
                request_id += 1
            except (BrokenPipeError, ConnectionResetError) as e:
                note = f"transport closed: {e}"
                is_error = True
                break  # server gone — no point in further probes
            except Exception as e:  # noqa: BLE001
                note = f"{type(e).__name__}: {e}"
                is_error = True
                request_id += 1
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            responses.append(
                {
                    "probe_id": probe.get("probe_id") or "",
                    "probe_class": probe.get("probe_class") or "",
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "response": resp,
                    "is_error": is_error,
                    "elapsed_ms": elapsed_ms,
                    "stderr_excerpt": "",
                    "note": note,
                }
            )

        result_payload = {
            "surface": surface_dump,
            "responses": responses,
            "diagnostics": diagnostics,
        }
    finally:
        try:
            if proc.stdin is not None and not proc.stdin.closed:
                proc.stdin.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        except ProcessLookupError:
            pass

    _write_result(args.result, payload=result_payload)
    return 0


def _write_result(
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    out: dict[str, Any] = payload or {}
    if error is not None:
        out.setdefault("diagnostics", []).append(error)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, separators=(",", ":"))


if __name__ == "__main__":
    sys.exit(main())
