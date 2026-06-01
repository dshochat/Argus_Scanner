"""Unit tests for mcp_scanner.transport.stdio.

Uses a tiny Python "echo" fixture spawned as the subprocess. The
fixture reads a JSON-RPC request, returns a canned response (or echoes
the request back), then exits — perfect for testing the framing layer
without standing up a real MCP server.
"""

from __future__ import annotations

import sys

import pytest

from mcp_scanner.transport.base import MCPTransportError, TransportClosed
from mcp_scanner.transport.stdio import StdioTransport

pytestmark = pytest.mark.asyncio

# Python one-liners spawned as the subprocess. We use ``python -c`` so
# the test doesn't depend on any on-disk fixture script.
ECHO_SCRIPT = (
    "import sys, json\n"
    "line = sys.stdin.readline()\n"
    "if not line:\n"
    "    sys.exit(1)\n"
    "req = json.loads(line)\n"
    "resp = {'jsonrpc': '2.0', 'id': req.get('id'), 'result': {'echoed': req}}\n"
    "sys.stdout.write(json.dumps(resp) + '\\n')\n"
    "sys.stdout.flush()\n"
)

# Multi-message fixture: writes a log line on stdout (which the
# transport should skip), then the real response.
NOISY_SCRIPT = (
    "import sys, json\n"
    "line = sys.stdin.readline()\n"
    "if not line:\n"
    "    sys.exit(1)\n"
    "req = json.loads(line)\n"
    "sys.stdout.write('\\n')\n"  # blank — should be skipped
    "sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': req.get('id'), 'result': {}}) + '\\n')\n"
    "sys.stdout.flush()\n"
)

# Exit-immediately fixture for TransportClosed test.
EXIT_SCRIPT = "import sys\nsys.exit(0)\n"

# Invalid-JSON fixture for parse-error test.
GARBAGE_SCRIPT = (
    "import sys\n"
    "sys.stdout.write('not valid json\\n')\n"
    "sys.stdout.flush()\n"
)


def _py(script: str) -> list[str]:
    return [sys.executable, "-c", script]


async def test_send_recv_round_trip() -> None:
    t = StdioTransport(_py(ECHO_SCRIPT))
    await t.start()
    try:
        await t.send({"jsonrpc": "2.0", "id": 42, "method": "ping"})
        resp = await t.recv(timeout=5.0)
        assert resp["id"] == 42
        assert resp["result"]["echoed"]["method"] == "ping"
    finally:
        await t.aclose()


async def test_blank_line_skipped() -> None:
    """Servers occasionally write blank lines on stdout (especially
    Windows newline mangling). The transport should skip them and
    return the next valid message."""
    t = StdioTransport(_py(NOISY_SCRIPT))
    await t.start()
    try:
        await t.send({"jsonrpc": "2.0", "id": 1, "method": "x"})
        resp = await t.recv(timeout=5.0)
        assert resp["id"] == 1
    finally:
        await t.aclose()


async def test_subprocess_exit_raises_transport_closed() -> None:
    """When the subprocess exits before responding, ``recv`` raises
    TransportClosed — probes use this to detect a server crash, which
    is itself a finding."""
    t = StdioTransport(_py(EXIT_SCRIPT))
    await t.start()
    try:
        with pytest.raises(TransportClosed):
            await t.recv(timeout=5.0)
    finally:
        await t.aclose()


async def test_invalid_json_raises_transport_error() -> None:
    t = StdioTransport(_py(GARBAGE_SCRIPT))
    await t.start()
    try:
        with pytest.raises(MCPTransportError):
            await t.recv(timeout=5.0)
    finally:
        await t.aclose()


async def test_send_after_close_raises_transport_closed() -> None:
    t = StdioTransport(_py(ECHO_SCRIPT))
    await t.start()
    await t.aclose()
    with pytest.raises(TransportClosed):
        await t.send({"jsonrpc": "2.0", "id": 1, "method": "x"})


async def test_recv_after_close_raises_transport_closed() -> None:
    t = StdioTransport(_py(ECHO_SCRIPT))
    await t.start()
    await t.aclose()
    with pytest.raises(TransportClosed):
        await t.recv(timeout=1.0)


async def test_double_close_is_idempotent() -> None:
    t = StdioTransport(_py(ECHO_SCRIPT))
    await t.start()
    await t.aclose()
    # Should NOT raise.
    await t.aclose()


async def test_async_context_manager() -> None:
    """Common usage pattern: ``async with StdioTransport(...) as t:``."""
    async with StdioTransport(_py(ECHO_SCRIPT)) as t:
        await t.send({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        resp = await t.recv(timeout=5.0)
        assert resp["id"] == 1


async def test_empty_command_rejected() -> None:
    with pytest.raises(ValueError):
        StdioTransport("")


async def test_command_accepts_string_or_list() -> None:
    """Constructor accepts both ``"cmd arg"`` (shlex.split) and
    ``["cmd", "arg"]``. Both produce the same argv."""
    t1 = StdioTransport(f"{sys.executable} -c 'print(1)'")
    t2 = StdioTransport([sys.executable, "-c", "print(1)"])
    # The shlex-split form will have stripped the quotes; both should
    # end up with the same shape.
    assert t1.argv[0] == sys.executable
    assert t2.argv[0] == sys.executable
    assert "-c" in t1.argv
    assert "-c" in t2.argv


async def test_invalid_executable_raises_transport_error() -> None:
    t = StdioTransport(["/nonexistent/path/to/mcp-server-binary"])
    with pytest.raises(MCPTransportError):
        await t.start()


async def test_unserializable_payload_raises_transport_error() -> None:
    """Probe code that accidentally puts a non-JSON-serialisable value
    into the payload should get a clear error, not a cryptic crash."""

    class NotJsonable:
        pass

    t = StdioTransport(_py(ECHO_SCRIPT))
    await t.start()
    try:
        with pytest.raises(MCPTransportError):
            await t.send({"jsonrpc": "2.0", "id": 1, "params": NotJsonable()})
    finally:
        await t.aclose()


async def test_recv_timeout_raises_timeout_error() -> None:
    """When the server never responds within the timeout, ``recv``
    raises plain ``TimeoutError`` (not TransportClosed — distinguishing
    "hung" from "exited" matters for fail-open probes)."""
    # Hang fixture: read input but never reply.
    hang = "import sys\nsys.stdin.readline()\nimport time; time.sleep(60)\n"
    t = StdioTransport(_py(hang))
    await t.start()
    try:
        await t.send({"jsonrpc": "2.0", "id": 1, "method": "x"})
        with pytest.raises(TimeoutError):
            await t.recv(timeout=0.5)
    finally:
        await t.aclose()
