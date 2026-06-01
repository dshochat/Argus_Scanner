"""Unit tests for mcp_scanner.client.

Uses an in-memory FakeTransport that satisfies the MCPTransport
Protocol — no subprocess, no httpx. Each test enqueues canned
responses and asserts the client's parsing / state-machine logic.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from mcp_scanner.classifier import ParamClass
from mcp_scanner.client import MCPClient, MCPClientError
from mcp_scanner.transport.base import (
    MCPTransport,
    MCPTransportError,
    TransportClosed,
)

pytestmark = pytest.mark.asyncio


class FakeTransport:
    """In-memory transport. Tests enqueue ``next_response`` dicts; the
    transport returns them in FIFO order on each ``recv``. ``sent``
    captures every outbound message so tests can assert wire shape.
    """

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.responses: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.closed = False
        # When set, recv raises this instead of returning a response.
        self.raise_on_recv: Exception | None = None

    def enqueue(self, msg: dict[str, Any]) -> None:
        self.responses.put_nowait(msg)

    async def send(self, message: dict[str, Any]) -> None:
        if self.closed:
            raise TransportClosed("closed")
        self.sent.append(message)

    async def recv(self, timeout: float | None = None) -> dict[str, Any]:
        if self.closed:
            raise TransportClosed("closed")
        if self.raise_on_recv is not None:
            raise self.raise_on_recv
        try:
            return await asyncio.wait_for(self.responses.get(), timeout=timeout)
        except TimeoutError as e:
            raise TimeoutError(f"fake: no response within {timeout}s") from e

    async def aclose(self) -> None:
        self.closed = True


# Sanity: FakeTransport satisfies the Protocol. Async to match the
# module-level pytestmark (the body has no awaits — runtime_checkable
# isinstance check is the whole test).
async def test_fake_transport_implements_protocol() -> None:
    t = FakeTransport()
    assert isinstance(t, MCPTransport)


# ── initialize handshake ──────────────────────────────────────────────


async def test_initialize_sends_request_and_notification() -> None:
    """Initialize must send the ``initialize`` request AND, after a
    successful response, send the ``notifications/initialized``
    notification per spec."""
    t = FakeTransport()
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "test-server", "version": "0.1"},
            },
        }
    )
    c = MCPClient(t)
    await c.initialize()
    assert c.initialized is True
    assert c.protocol_version == "2025-03-26"
    assert c.server_info == {"name": "test-server", "version": "0.1"}
    assert c.server_capabilities == {"tools": {}}
    # Two messages sent: initialize request + initialized notification.
    assert len(t.sent) == 2
    assert t.sent[0]["method"] == "initialize"
    assert t.sent[0]["params"]["protocolVersion"] == "2025-03-26"
    assert t.sent[1]["method"] == "notifications/initialized"
    assert "id" not in t.sent[1]  # notifications have no id


async def test_initialize_is_idempotent() -> None:
    t = FakeTransport()
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"protocolVersion": "2025-03-26"},
        }
    )
    c = MCPClient(t)
    await c.initialize()
    await c.initialize()  # second call: no-op
    # Should have sent only one initialize.
    initialize_count = sum(1 for m in t.sent if m.get("method") == "initialize")
    assert initialize_count == 1


async def test_initialize_error_response_raises() -> None:
    t = FakeTransport()
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Invalid Request"},
        }
    )
    c = MCPClient(t)
    with pytest.raises(MCPClientError) as exc_info:
        await c.initialize()
    assert "-32600" in str(exc_info.value)


async def test_method_call_before_initialize_raises() -> None:
    t = FakeTransport()
    c = MCPClient(t)
    with pytest.raises(MCPClientError):
        await c.list_tools()


# ── raw_request — id matching + notification skipping ────────────────


async def test_raw_request_skips_notifications_then_returns_response() -> None:
    """Real servers interleave notifications (progress, logs) with
    responses. The client should skip notifications until it sees the
    response with the matching id."""
    t = FakeTransport()
    # First enqueue: initialize response.
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"protocolVersion": "2025-03-26"},
        }
    )
    # Then enqueue a notification (no id) followed by the actual response.
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"step": 1},
        }
    )
    t.enqueue({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})

    c = MCPClient(t)
    await c.initialize()
    tools = await c.list_tools()
    assert tools == []


async def test_raw_request_drops_mismatched_id_responses() -> None:
    """If the server replies with an id we didn't ask for (buggy server
    or probe-caused desync), we should drop it and keep reading."""
    t = FakeTransport()
    t.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    # Bogus response with wrong id, then the real response.
    t.enqueue({"jsonrpc": "2.0", "id": 999, "result": {"junk": True}})
    t.enqueue({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})

    c = MCPClient(t)
    await c.initialize()
    tools = await c.list_tools()
    assert tools == []


# ── tools/resources/prompts discovery ─────────────────────────────────


async def test_list_tools_returns_raw_tool_dicts() -> None:
    t = FakeTransport()
    t.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "fetch_url",
                        "description": "Fetch a URL",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "url": {"type": "string", "format": "uri"}
                            },
                            "required": ["url"],
                        },
                    }
                ]
            },
        }
    )
    c = MCPClient(t)
    await c.initialize()
    tools = await c.list_tools()
    assert len(tools) == 1
    assert tools[0]["name"] == "fetch_url"


async def test_list_tools_error_returns_empty_list() -> None:
    """A server without the ``tools`` capability may JSON-RPC-error on
    tools/list. The client should treat that as "no tools" rather than
    raising — discovery is best-effort."""
    t = FakeTransport()
    t.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "error": {"code": -32601, "message": "Method not found"},
        }
    )
    c = MCPClient(t)
    await c.initialize()
    tools = await c.list_tools()
    assert tools == []


async def test_list_resources_empty_on_error() -> None:
    t = FakeTransport()
    t.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "error": {"code": -32601, "message": "Method not found"},
        }
    )
    c = MCPClient(t)
    await c.initialize()
    assert await c.list_resources() == []


async def test_list_prompts_empty_on_error() -> None:
    t = FakeTransport()
    t.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "error": {"code": -32601, "message": "Method not found"},
        }
    )
    c = MCPClient(t)
    await c.initialize()
    assert await c.list_prompts() == []


# ── call_tool ────────────────────────────────────────────────────────


async def test_call_tool_passes_arguments() -> None:
    t = FakeTransport()
    t.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }
    )
    c = MCPClient(t)
    await c.initialize()
    resp = await c.call_tool("fetch_url", {"url": "https://example.com"})
    # The full JSON-RPC envelope, not just .result — probes inspect it.
    assert resp["result"]["content"][0]["text"] == "ok"
    # Outbound msg should carry method + name + arguments.
    call_msg = t.sent[-1]
    assert call_msg["method"] == "tools/call"
    assert call_msg["params"]["name"] == "fetch_url"
    assert call_msg["params"]["arguments"] == {"url": "https://example.com"}


async def test_call_tool_returns_error_response_to_caller() -> None:
    """Probes WANT to see error responses (e.g. fail-open probes
    treat ``{"error": {...}}`` differently from a 200 with ``isError:
    true``). The client returns the raw envelope; it doesn't raise."""
    t = FakeTransport()
    t.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "error": {"code": -32602, "message": "Invalid params"},
        }
    )
    c = MCPClient(t)
    await c.initialize()
    resp = await c.call_tool("fetch_url", {"oops": "wrong arg"})
    assert "error" in resp
    assert resp["error"]["code"] == -32602


# ── enumerate full flow ──────────────────────────────────────────────


async def test_enumerate_builds_surface_map() -> None:
    """End-to-end: initialize + 3x list-call → ``MCPSurfaceMap``."""
    t = FakeTransport()
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "vuln-server", "version": "0.1"},
            },
        }
    )
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "fetch_url",
                        "description": "naive fetch",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "url": {"type": "string"},
                                "timeout": {"type": "integer"},
                            },
                            "required": ["url"],
                        },
                    }
                ]
            },
        }
    )
    t.enqueue(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "resources": [
                    {
                        "uri": "file:///tmp/data.txt",
                        "name": "scratch",
                        "mimeType": "text/plain",
                    }
                ]
            },
        }
    )
    t.enqueue({"jsonrpc": "2.0", "id": 4, "result": {"prompts": []}})

    c = MCPClient(t)
    surface = await c.enumerate("test-target", "stdio")

    assert surface.target == "test-target"
    assert surface.transport == "stdio"
    assert surface.protocol_version == "2025-03-26"
    assert surface.server_info["name"] == "vuln-server"
    assert len(surface.tools) == 1
    assert surface.tools[0].name == "fetch_url"
    # Classifier wired in via enumerate.
    url_param = next(p for p in surface.tools[0].params if p.name == "url")
    assert url_param.param_class == ParamClass.URL
    assert url_param.required is True
    timeout_param = next(p for p in surface.tools[0].params if p.name == "timeout")
    assert timeout_param.param_class == ParamClass.INTEGER
    assert timeout_param.required is False
    assert len(surface.resources) == 1
    assert surface.resources[0].uri == "file:///tmp/data.txt"
    assert surface.prompts == []
    assert surface.discovery_errors == []


async def test_enumerate_records_discovery_errors_non_fatal() -> None:
    """A minimal server may only implement tools/list. Errors on the
    other discovery calls should land on ``discovery_errors``, not
    abort the enumeration."""
    t = FakeTransport()
    t.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    # tools/list — fine, empty.
    t.enqueue({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
    # resources/list — transport hangs up mid-call.
    # We model this by raising TransportClosed on the next recv.

    async def _make_recv_close():
        t.raise_on_recv = TransportClosed("server hung up")

    c = MCPClient(t)
    await c.initialize()
    await c.list_tools()
    # Switch transport to closed-mode AFTER tools/list completes.
    t.raise_on_recv = TransportClosed("server hung up")

    # enumerate doesn't re-initialize since we already did. Bypass by
    # calling the components manually to assert the error-capture path.
    # Or just use enumerate from a fresh client to validate end-to-end:
    t2 = FakeTransport()
    t2.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    t2.enqueue({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
    # Now resources/list — transport raises.
    t2.raise_on_recv_after_sends = 3  # not actually used; using callable below

    class FlakyTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.call_count = 0

        async def recv(self, timeout: float | None = None) -> dict[str, Any]:
            self.call_count += 1
            if self.call_count > 2:
                raise MCPTransportError("server unreachable mid-discovery")
            return await super().recv(timeout=timeout)

    flaky = FlakyTransport()
    flaky.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    flaky.enqueue({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
    c3 = MCPClient(flaky)
    surface = await c3.enumerate("flaky-target", "http")
    assert surface.tools == []
    # Two errors recorded (resources/list + prompts/list).
    assert len(surface.discovery_errors) == 2
    assert any("resources/list" in e for e in surface.discovery_errors)
    assert any("prompts/list" in e for e in surface.discovery_errors)


async def test_request_id_increments_per_call() -> None:
    t = FakeTransport()
    t.enqueue({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}})
    t.enqueue({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
    t.enqueue({"jsonrpc": "2.0", "id": 3, "result": {"resources": []}})

    c = MCPClient(t)
    await c.initialize()
    await c.list_tools()
    await c.list_resources()
    # Captured outbound ids: initialize=1, list_tools=2, list_resources=3.
    # (Plus the notification with no id.)
    ids = [m["id"] for m in t.sent if "id" in m]
    assert ids == [1, 2, 3]
