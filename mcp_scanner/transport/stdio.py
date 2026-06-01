"""Stdio MCP transport — subprocess + line-delimited JSON-RPC.

MCP-over-stdio sends one JSON object per line on stdout / stdin (no
LSP-style ``Content-Length`` headers). Argus uses ``asyncio`` subprocess
primitives so reads and writes don't block the event loop.

For Argus's threat model, stdio targets are ALWAYS launched inside the
Firecracker sandbox by ``mcp_scanner.sandbox_launcher`` — see that
module for the safety contract. This module just speaks the wire; it
doesn't care whether the subprocess is local or sandbox-relayed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
from typing import Any

from mcp_scanner.transport.base import (
    MCPTransportError,
    TransportClosed,
)

log = logging.getLogger("argus.mcp.transport.stdio")


class StdioTransport:
    """Run a local MCP server as a subprocess; speak JSON-RPC over its
    stdin / stdout.

    This is the LOCAL (host-process) implementation. The sandboxed
    variant in ``mcp_scanner.sandbox_launcher`` reuses the same
    JSON-RPC framing but routes the subprocess through Firecracker.
    Tests that don't need the sandbox use this directly with a fixture
    server binary.
    """

    def __init__(self, command: str | list[str], *, cwd: str | None = None) -> None:
        if isinstance(command, str):
            # On Windows, backslashes in paths (e.g. ``C:\Python\python.exe``)
            # would be eaten by POSIX-mode shlex which treats ``\`` as
            # an escape character. Use the platform-native posix mode:
            # posix=False on Windows (preserves backslashes), posix=True
            # elsewhere (handles ``'quoted args'`` correctly).
            posix = os.name != "nt"
            self._argv: list[str] = shlex.split(command, posix=posix)
        else:
            self._argv = list(command)
        if not self._argv:
            raise ValueError("StdioTransport: command must be non-empty")
        self._cwd = cwd
        self._proc: asyncio.subprocess.Process | None = None
        self._closed = False

    @property
    def argv(self) -> list[str]:
        return list(self._argv)

    async def start(self) -> None:
        """Spawn the subprocess. Idempotent — second call is a no-op."""
        if self._proc is not None:
            return
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *self._argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self._cwd,
            )
        except (FileNotFoundError, PermissionError, OSError) as e:
            raise MCPTransportError(
                f"failed to spawn MCP server {self._argv[0]!r}: {e}"
            ) from e
        log.debug("stdio-mcp spawned pid=%s argv=%s", self._proc.pid, self._argv)

    async def send(self, message: dict[str, Any]) -> None:
        if self._closed:
            raise TransportClosed("stdio transport closed")
        if self._proc is None or self._proc.stdin is None:
            raise MCPTransportError("stdio transport not started")
        try:
            line = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError) as e:
            raise MCPTransportError(f"json encode failed: {e}") from e
        data = (line + "\n").encode("utf-8")
        try:
            self._proc.stdin.write(data)
            await self._proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError) as e:
            self._closed = True
            raise TransportClosed(f"stdio transport: {e}") from e

    async def recv(self, timeout: float | None = None) -> dict[str, Any]:
        if self._closed:
            raise TransportClosed("stdio transport closed")
        if self._proc is None or self._proc.stdout is None:
            raise MCPTransportError("stdio transport not started")
        try:
            line = await asyncio.wait_for(
                self._proc.stdout.readline(), timeout=timeout
            )
        except TimeoutError as e:
            raise TimeoutError(
                f"stdio transport: no response within {timeout}s"
            ) from e
        if not line:
            # EOF — subprocess exited or closed stdout.
            self._closed = True
            raise TransportClosed("stdio transport: subprocess exited")
        try:
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                # Blank line — keep reading. MCP doesn't send blanks,
                # but some servers print log lines on stdout. Skip them.
                return await self.recv(timeout=timeout)
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            raise MCPTransportError(
                f"stdio transport: invalid JSON from server: {text[:200]!r}"
            ) from e
        if not isinstance(obj, dict):
            raise MCPTransportError(
                f"stdio transport: expected JSON object, got {type(obj).__name__}"
            )
        return obj

    async def read_stderr(self, max_bytes: int = 4096) -> bytes:
        """Drain the subprocess's stderr (non-blocking best-effort).

        Useful for fail-open probes: when a probe drives the server to
        crash, stderr often carries the traceback that pinpoints the
        bypass path.
        """
        if self._proc is None or self._proc.stderr is None:
            return b""
        try:
            # at_eof() avoids blocking when nothing's buffered
            if self._proc.stderr.at_eof():
                return b""
            return await asyncio.wait_for(
                self._proc.stderr.read(max_bytes), timeout=0.1
            )
        except (TimeoutError, ConnectionResetError):
            return b""

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._proc is None:
            return
        try:
            if self._proc.stdin is not None and not self._proc.stdin.is_closing():
                self._proc.stdin.close()
        except (BrokenPipeError, ConnectionResetError):
            pass
        if self._proc.returncode is None:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=2.0)
            except TimeoutError:
                self._proc.kill()
                await self._proc.wait()
            except ProcessLookupError:
                pass

    async def __aenter__(self) -> StdioTransport:
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()
