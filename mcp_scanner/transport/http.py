"""HTTP MCP transport — streamable-HTTP + SSE.

Implements the 2025-03-26 MCP spec's streamable-HTTP transport:

  * Single POST endpoint (server-chosen URL, conventionally ``/mcp``).
  * Each POST body is a JSON-RPC request.
  * Response is one of:
      - ``application/json`` — single JSON-RPC response body.
      - ``text/event-stream`` — SSE channel; the server may stream
        multiple JSON-RPC messages (response + intermediate
        notifications) before closing the stream.
  * The server returns an ``Mcp-Session-Id`` header on the initialize
    response; the client MUST echo it on every subsequent request.

Argus uses ``httpx`` (already a core dep), no SDK needed. SSE parsing
is hand-rolled — the wire format is trivial (``data: <json>\\n\\n``).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

from mcp_scanner.transport.base import (
    MCPTransportError,
    TransportClosed,
)

log = logging.getLogger("argus.mcp.transport.http")

# Spec-defined: client MUST advertise both response types so the
# server can pick streaming or single-shot per its preference.
_ACCEPT_HEADER = "application/json, text/event-stream"

# Sane caps so a malicious / buggy server can't OOM us with an
# unterminated SSE stream.
_MAX_SSE_BYTES = 8 * 1024 * 1024
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class HttpTransport:
    """Streamable-HTTP MCP client.

    The transport is half-duplex: one POST per ``send`` / ``recv`` pair.
    Server-initiated notifications (the spec's optional SSE long-poll
    channel from server → client) are NOT supported in v1 — Argus's
    probe loops are request/response shaped, so we'd never observe a
    server-initiated push during a scan.
    """

    def __init__(
        self,
        url: str,
        *,
        auth_token: str | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"HttpTransport: url must be http(s); got {parsed.scheme!r}"
            )
        self._url = url
        self._auth_token = auth_token
        self._extra_headers = dict(extra_headers) if extra_headers else {}
        self._timeout = timeout
        self._verify_tls = verify_tls
        # Per-session ID from the server (initialize response).
        self._session_id: str | None = None
        # Pending responses queued for ``recv``. The transport stores a
        # FIFO of messages parsed from the most recent response body so
        # callers can drive a single send → multi-recv flow (SSE).
        self._inbox: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._client: httpx.AsyncClient | None = None
        self._closed = False

    @property
    def url(self) -> str:
        return self._url

    @property
    def session_id(self) -> str | None:
        return self._session_id

    async def start(self) -> None:
        """Open the underlying httpx AsyncClient. Idempotent."""
        if self._client is not None:
            return
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            verify=self._verify_tls,
            # No automatic redirects — the redirect probe wants to see
            # 30x responses raw.
            follow_redirects=False,
        )

    def _build_headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": _ACCEPT_HEADER,
        }
        if self._auth_token:
            h["Authorization"] = f"Bearer {self._auth_token}"
        if self._session_id is not None:
            h["Mcp-Session-Id"] = self._session_id
        h.update(self._extra_headers)
        return h

    async def send(self, message: dict[str, Any]) -> None:
        """POST one JSON-RPC message; queue the response(s) into ``_inbox``.

        This is unusual for a transport (send normally only writes), but
        HTTP is half-duplex by nature: we have to read the response in
        the same call to avoid losing it. ``recv`` then pops from the
        queue in FIFO order.
        """
        if self._closed:
            raise TransportClosed("http transport closed")
        if self._client is None:
            await self.start()
        assert self._client is not None

        try:
            body = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError) as e:
            raise MCPTransportError(f"json encode failed: {e}") from e

        try:
            resp = await self._client.post(
                self._url, content=body, headers=self._build_headers()
            )
        except httpx.HTTPError as e:
            raise MCPTransportError(f"http transport: POST failed: {e}") from e

        # Capture session id on the FIRST response that carries one
        # (typically the initialize response per spec).
        sid = resp.headers.get("Mcp-Session-Id")
        if sid and self._session_id is None:
            self._session_id = sid

        # Notifications (no ``id``) and ``initialized`` may legitimately
        # get 202 Accepted with empty body. Treat that as "nothing to
        # queue" rather than an error.
        if resp.status_code == 202 and not resp.content:
            return

        content_type = (resp.headers.get("Content-Type") or "").lower()
        if "text/event-stream" in content_type:
            await self._drain_sse(resp)
        elif "application/json" in content_type:
            await self._drain_json(resp)
        else:
            # Unknown content-type — store the raw response as evidence
            # rather than crash. Probes that drive error paths
            # (fail-open) want to SEE the body the server sent back.
            raw = resp.content[:_MAX_RESPONSE_BYTES]
            await self._inbox.put(
                {
                    "_argus_non_jsonrpc": True,
                    "status": resp.status_code,
                    "content_type": content_type,
                    "body_excerpt": raw.decode("utf-8", errors="replace"),
                }
            )

    async def _drain_json(self, resp: httpx.Response) -> None:
        """Single JSON-RPC body → push one message."""
        raw = resp.content[:_MAX_RESPONSE_BYTES]
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            raise MCPTransportError(
                f"http transport: invalid JSON from server "
                f"(status={resp.status_code}): {raw[:200]!r}"
            ) from e
        if isinstance(obj, list):
            # JSON-RPC batch — push each message individually so
            # ``recv`` sees them in order.
            for item in obj:
                if isinstance(item, dict):
                    await self._inbox.put(item)
        elif isinstance(obj, dict):
            await self._inbox.put(obj)
        else:
            raise MCPTransportError(
                f"http transport: expected JSON object or batch, got {type(obj).__name__}"
            )

    async def _drain_sse(self, resp: httpx.Response) -> None:
        """SSE body → parse each ``data:`` event and push.

        SSE is line-oriented: blank line terminates an event; the
        ``data:`` field carries the JSON-RPC payload. We ignore
        ``event:`` / ``id:`` / ``retry:`` fields for v1 — MCP servers
        don't use them for protocol semantics.
        """
        # Stream lazily so we don't load multi-MB SSE bodies into RAM.
        async for event in _iter_sse_events(resp.aiter_lines()):
            if not event:
                continue
            try:
                obj = json.loads(event)
            except json.JSONDecodeError:
                # Garbage SSE event — log + skip rather than abort the
                # whole stream. The probe layer reports this as a
                # protocol violation.
                log.debug("http transport: skipping non-JSON SSE event")
                continue
            if isinstance(obj, dict):
                await self._inbox.put(obj)

    async def recv(self, timeout: float | None = None) -> dict[str, Any]:
        if self._closed and self._inbox.empty():
            raise TransportClosed("http transport closed and inbox empty")
        try:
            return await asyncio.wait_for(self._inbox.get(), timeout=timeout)
        except TimeoutError as e:
            raise TimeoutError(
                f"http transport: no queued message within {timeout}s"
            ) from e

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> HttpTransport:
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()


async def _iter_sse_events(lines: AsyncIterator[str]) -> AsyncIterator[str]:
    """Reassemble SSE ``data:`` events from a line stream.

    Yields the concatenated payload of each event (one yield per
    blank-line-terminated event). Multi-line ``data:`` fields are
    joined with ``\\n`` per the SSE spec.
    """
    buf: list[str] = []
    bytes_seen = 0
    async for raw in lines:
        line = raw.rstrip("\r")
        bytes_seen += len(raw) + 1
        if bytes_seen > _MAX_SSE_BYTES:
            raise MCPTransportError(
                f"http transport: SSE stream exceeded {_MAX_SSE_BYTES} bytes"
            )
        if line == "":
            if buf:
                yield "\n".join(buf)
                buf = []
            continue
        if line.startswith(":"):
            # SSE comment line — ignore.
            continue
        if line.startswith("data:"):
            buf.append(line[5:].lstrip())
    # Drain any trailing event the server didn't terminate with a
    # blank line (some implementations close the stream mid-event).
    if buf:
        yield "\n".join(buf)
