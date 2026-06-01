"""Unit tests for mcp_scanner.transport.http.

Uses ``respx`` (already a dev dep) to mock the httpx layer — no real
network calls. Validates streamable-HTTP (JSON body) + SSE parsing,
session-id propagation, and the half-duplex inbox queue.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from mcp_scanner.transport.base import MCPTransportError, TransportClosed
from mcp_scanner.transport.http import HttpTransport

pytestmark = pytest.mark.asyncio

TARGET = "https://example.test/mcp"


@respx.mock
async def test_json_response_single_message() -> None:
    """Server returns ``application/json`` with a single JSON-RPC body.
    Transport queues it; ``recv`` returns it."""
    respx.post(TARGET).mock(
        return_value=Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 7, "result": {"ok": True}},
        )
    )
    async with HttpTransport(TARGET) as t:
        await t.send({"jsonrpc": "2.0", "id": 7, "method": "ping"})
        resp = await t.recv(timeout=2.0)
        assert resp["id"] == 7
        assert resp["result"]["ok"] is True


@respx.mock
async def test_json_response_batch_pushes_each_message() -> None:
    """JSON-RPC batch response: each message lands in ``recv`` in
    order."""
    respx.post(TARGET).mock(
        return_value=Response(
            200,
            headers={"Content-Type": "application/json"},
            json=[
                {"jsonrpc": "2.0", "id": 1, "result": {"a": 1}},
                {"jsonrpc": "2.0", "id": 2, "result": {"b": 2}},
            ],
        )
    )
    async with HttpTransport(TARGET) as t:
        await t.send({"jsonrpc": "2.0", "id": 1, "method": "x"})
        msg1 = await t.recv(timeout=2.0)
        msg2 = await t.recv(timeout=2.0)
        assert msg1["id"] == 1
        assert msg2["id"] == 2


@respx.mock
async def test_sse_response_parses_multiple_events() -> None:
    """SSE body with three events; each ``data:`` payload should land
    in the inbox individually."""
    notif1 = '{"jsonrpc":"2.0","method":"notifications/progress","params":{"step":1}}'
    notif2 = '{"jsonrpc":"2.0","method":"notifications/progress","params":{"step":2}}'
    final = '{"jsonrpc":"2.0","id":3,"result":{"done":true}}'
    body = f"data: {notif1}\n\ndata: {notif2}\n\ndata: {final}\n\n"
    respx.post(TARGET).mock(
        return_value=Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=body,
        )
    )
    async with HttpTransport(TARGET) as t:
        await t.send({"jsonrpc": "2.0", "id": 3, "method": "compute"})
        m1 = await t.recv(timeout=2.0)
        m2 = await t.recv(timeout=2.0)
        m3 = await t.recv(timeout=2.0)
        assert m1["params"]["step"] == 1
        assert m2["params"]["step"] == 2
        assert m3["result"]["done"] is True


@respx.mock
async def test_sse_comment_line_skipped() -> None:
    """SSE allows ``:comment`` lines (often used as keepalives).
    They should be silently ignored."""
    body = (
        ": keepalive\n"
        "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n"
        "\n"
    )
    respx.post(TARGET).mock(
        return_value=Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=body,
        )
    )
    async with HttpTransport(TARGET) as t:
        await t.send({"jsonrpc": "2.0", "id": 1, "method": "x"})
        resp = await t.recv(timeout=2.0)
        assert resp["id"] == 1


@respx.mock
async def test_session_id_captured_and_echoed() -> None:
    """Server sets ``Mcp-Session-Id`` on the initialize response; the
    transport MUST echo it on every subsequent request."""
    # Track headers seen by the mock.
    seen_session_ids: list[str | None] = []

    def _handler(request):
        seen_session_ids.append(request.headers.get("Mcp-Session-Id"))
        if request.headers.get("Mcp-Session-Id") is None:
            # First call — set the session id.
            return Response(
                200,
                headers={
                    "Content-Type": "application/json",
                    "Mcp-Session-Id": "sess-abc-123",
                },
                json={"jsonrpc": "2.0", "id": 1, "result": {}},
            )
        # Subsequent calls — just echo OK.
        return Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 2, "result": {}},
        )

    respx.post(TARGET).mock(side_effect=_handler)

    async with HttpTransport(TARGET) as t:
        await t.send({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        await t.recv(timeout=2.0)
        assert t.session_id == "sess-abc-123"

        await t.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        await t.recv(timeout=2.0)

    assert seen_session_ids[0] is None  # initialize: no session yet
    assert seen_session_ids[1] == "sess-abc-123"


@respx.mock
async def test_bearer_token_attached() -> None:
    """``--auth token`` → ``Authorization: Bearer <token>`` on every
    request."""
    seen: list[str | None] = []

    def _handler(request):
        seen.append(request.headers.get("Authorization"))
        return Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "result": {}},
        )

    respx.post(TARGET).mock(side_effect=_handler)

    async with HttpTransport(TARGET, auth_token="my-token") as t:
        await t.send({"jsonrpc": "2.0", "id": 1, "method": "x"})
        await t.recv(timeout=2.0)

    assert seen == ["Bearer my-token"]


@respx.mock
async def test_invalid_json_body_raises_transport_error() -> None:
    respx.post(TARGET).mock(
        return_value=Response(
            200,
            headers={"Content-Type": "application/json"},
            content=b"not valid json",
        )
    )
    async with HttpTransport(TARGET) as t:
        with pytest.raises(MCPTransportError):
            await t.send({"jsonrpc": "2.0", "id": 1, "method": "x"})


@respx.mock
async def test_unknown_content_type_captured_as_non_jsonrpc() -> None:
    """Probes need to SEE error bodies (HTML error pages, etc.) rather
    than crash. The transport queues them under a sentinel key so
    callers can render evidence."""
    respx.post(TARGET).mock(
        return_value=Response(
            500,
            headers={"Content-Type": "text/html"},
            content=b"<html>500 internal error</html>",
        )
    )
    async with HttpTransport(TARGET) as t:
        await t.send({"jsonrpc": "2.0", "id": 1, "method": "x"})
        captured = await t.recv(timeout=2.0)
        assert captured["_argus_non_jsonrpc"] is True
        assert captured["status"] == 500
        assert "500 internal error" in captured["body_excerpt"]


@respx.mock
async def test_202_empty_body_is_silent_no_op() -> None:
    """Notifications (no id) get 202 Accepted + empty body per spec.
    The transport should NOT queue anything for ``recv``."""
    respx.post(TARGET).mock(return_value=Response(202, content=b""))
    async with HttpTransport(TARGET) as t:
        await t.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        # Should time out — nothing queued.
        with pytest.raises(TimeoutError):
            await t.recv(timeout=0.2)


@respx.mock
async def test_recv_after_close_raises_transport_closed() -> None:
    respx.post(TARGET).mock(
        return_value=Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "result": {}},
        )
    )
    t = HttpTransport(TARGET)
    await t.start()
    await t.aclose()
    with pytest.raises(TransportClosed):
        await t.recv(timeout=0.2)


async def test_invalid_scheme_rejected() -> None:
    """``ws://`` / ``stdio:`` are not valid for the HTTP transport."""
    with pytest.raises(ValueError):
        HttpTransport("ws://example.test/mcp")


async def test_send_after_close_raises_transport_closed() -> None:
    t = HttpTransport(TARGET)
    await t.start()
    await t.aclose()
    with pytest.raises(TransportClosed):
        await t.send({"jsonrpc": "2.0", "id": 1, "method": "x"})


async def test_double_close_idempotent() -> None:
    t = HttpTransport(TARGET)
    await t.start()
    await t.aclose()
    await t.aclose()  # must not raise


@respx.mock
async def test_post_failure_raises_transport_error() -> None:
    """httpx-level errors (connect refused, DNS failure, TLS errors)
    must surface as MCPTransportError so probes can record them as
    transport-level evidence."""
    import httpx as _httpx

    respx.post(TARGET).mock(side_effect=_httpx.ConnectError("connection refused"))
    async with HttpTransport(TARGET) as t:
        with pytest.raises(MCPTransportError):
            await t.send({"jsonrpc": "2.0", "id": 1, "method": "x"})
