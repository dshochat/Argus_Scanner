"""Out-of-band (OOB) callback listener for blind-SSRF confirmation
on REMOTE HTTP MCP servers.

Why this exists separately from the in-sandbox capture-server: the
sandbox owns its own egress interception via DNS hijack +
dast-capture-server.py — that handles stdio MCP targets cleanly. But
when the target is a REMOTE HTTP MCP server (somewhere on the public
Internet), Argus runs ON THE HOST, the probes go out OVER THE NET,
and any blind-SSRF the target performs lands on whatever URL we
include in the probe payload.

Two flavors share the ``OOBListener`` interface:

  * ``UserSuppliedOOB`` — operator runs an interactsh / dnslog /
    webhook.site listener themselves and passes the base URL via
    ``--oob <url>``. The listener doesn't do any work — it just
    knows how to build canary URLs containing per-probe tokens that
    point at the user's endpoint, and how to parse correlation
    tokens out of captures the operator manually inspects.

  * ``ArgusManagedOOB`` — Argus spawns a local HTTP listener on
    ``0.0.0.0:<random-port>`` and (optionally) the operator
    forwards the port via ngrok / cloudflared. Argus tells the
    operator the public URL via stdout. Every probe gets a unique
    correlation token in the canary URL; the listener records every
    inbound request and the scan handler reads back matched
    requests as evidence.

For v1.12, the listener does NOT persist captures across runs —
they're in-memory and reset per scan. Persistence ships in v1.13
when we add scan-history mode.

Security note: the Argus-managed listener binds to ``0.0.0.0``
because the whole POINT is to be reachable from the target. We
print a clear warning at startup and require ``--authorized`` to
have already been passed (the same gate that protects remote scans
generally).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import socket
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

log = logging.getLogger("argus.mcp.oob")


# Token alphabet: URL-safe, no characters that would need escaping in
# a path segment. 16 chars ≈ 96 bits of entropy — enough for per-probe
# uniqueness across a multi-million-probe campaign.
_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_TOKEN_LENGTH = 16


def _new_token() -> str:
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(_TOKEN_LENGTH))


@dataclass
class OOBHit:
    """One inbound callback recorded by the OOB listener.

    Captured fields mirror what most blind-SSRF probes care about:
    the path (containing the correlation token), HTTP method, request
    headers (X-Forwarded-For / Host can reveal the relay path), and
    body (some servers POST credentials back).
    """

    token: str
    method: str = ""
    path: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body_excerpt: str = ""
    source_ip: str = ""
    received_at_ms: int = 0


@runtime_checkable
class OOBListener(Protocol):
    """The contract the scan handler depends on.

    Two operations are needed:

      * ``build_callback_url(token)`` — embed a per-probe token into
        a URL the listener will receive. The scan handler injects the
        result into probe payloads (the URL becomes the SSRF canary
        that, when fetched by the target, hits the listener).

      * ``hits_for(token)`` — return every recorded callback whose
        path / body contained ``token``. The probe evaluator uses
        this to confirm blind SSRF.
    """

    def build_callback_url(self, token: str) -> str: ...
    def hits_for(self, token: str) -> list[OOBHit]: ...
    def all_hits(self) -> list[OOBHit]: ...


# ── user-supplied listener (no work; just URL construction) ──────────


class UserSuppliedOOB:
    """Operator brought their own OOB endpoint.

    Examples of valid base URLs:

      * ``https://abc123.oast.fun/`` (interactsh)
      * ``https://abc123.b32.io/`` (dnslog)
      * ``https://webhook.site/abc123/`` (webhook.site)

    Argus constructs ``<base>/argus/<token>`` URLs. The operator
    correlates callbacks themselves (interactsh's web UI or the
    service's webhook log) and can record hits manually via
    ``record_hit`` if they want them surfaced in the JSON report.
    """

    def __init__(self, base_url: str) -> None:
        self._base = base_url.rstrip("/")
        if not self._base.startswith(("http://", "https://")):
            raise ValueError(
                f"UserSuppliedOOB: base_url must be http(s); got {base_url!r}"
            )
        self._hits: list[OOBHit] = []

    @property
    def base_url(self) -> str:
        return self._base

    def build_callback_url(self, token: str) -> str:
        return f"{self._base}/argus/{token}"

    def record_hit(self, hit: OOBHit) -> None:
        """Manually record a hit. Operators paste interactsh / dnslog
        events into Argus via this for inclusion in the JSON report.
        Not used by the auto-listener flow."""
        self._hits.append(hit)

    def hits_for(self, token: str) -> list[OOBHit]:
        return [h for h in self._hits if token in h.path or token in h.body_excerpt]

    def all_hits(self) -> list[OOBHit]:
        return list(self._hits)


# ── Argus-managed listener (local HTTP server) ───────────────────────


class ArgusManagedOOB:
    """Argus spawns a local HTTP listener on a random port.

    Lifecycle:

      * ``start()`` — bind to ``host:port`` (default 0.0.0.0 + ephemeral),
        start the asyncio HTTP server. Returns the actual bound port.
      * ``build_callback_url(token)`` — formats
        ``http://<public_host>:<port>/argus/<token>``. ``public_host``
        defaults to the bound interface IP but can be overridden so the
        operator passes the ngrok / cloudflared tunnel URL.
      * ``hits_for(token)`` — returns the in-memory request log filtered
        to entries whose URL path or body contains ``token``.
      * ``stop()`` — graceful shutdown.

    The listener does NOT serve any real content — it always returns
    HTTP 204 No Content. The probe's intent is "the target fetched
    SOMETHING from this URL"; what we serve back doesn't matter.
    """

    def __init__(
        self,
        *,
        bind_host: str = "0.0.0.0",  # noqa: S104 — must be reachable from target
        bind_port: int = 0,  # 0 → OS-assigned ephemeral port
        public_host: str | None = None,
    ) -> None:
        self._bind_host = bind_host
        self._bind_port = bind_port
        self._public_host = public_host
        self._server: asyncio.base_events.Server | None = None
        self._hits: list[OOBHit] = []
        self._actual_port: int | None = None

    @property
    def actual_port(self) -> int | None:
        return self._actual_port

    @property
    def public_host(self) -> str:
        """Hostname / IP used in canary URLs. Defaults to the bound
        interface (NOT 0.0.0.0 since that would be unreachable as a
        URL). Operators with NAT / tunnels override via constructor."""
        if self._public_host is not None:
            return self._public_host
        if self._bind_host not in ("0.0.0.0", "::"):
            return self._bind_host
        # Best-effort: ask the OS what our outbound interface IP is.
        # This won't traverse NAT to a public IP — operators relying on
        # NAT pass `public_host=` explicitly.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # No actual packets sent.
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    async def start(self) -> int:
        """Bind + start. Returns the actually-bound port. Idempotent
        on the same instance."""
        if self._server is not None:
            assert self._actual_port is not None
            return self._actual_port
        self._server = await asyncio.start_server(
            self._handle_connection, self._bind_host, self._bind_port
        )
        sockets = self._server.sockets or ()
        if sockets:
            self._actual_port = sockets[0].getsockname()[1]
        else:
            raise RuntimeError("ArgusManagedOOB: server bound no sockets")
        log.info(
            "argus-managed OOB listener bound at %s:%s",
            self._bind_host,
            self._actual_port,
        )
        return self._actual_port

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    def build_callback_url(self, token: str) -> str:
        if self._actual_port is None:
            raise RuntimeError("ArgusManagedOOB: call start() before build_callback_url")
        return f"http://{self.public_host}:{self._actual_port}/argus/{token}"

    def hits_for(self, token: str) -> list[OOBHit]:
        return [h for h in self._hits if token in h.path or token in h.body_excerpt]

    def all_hits(self) -> list[OOBHit]:
        return list(self._hits)

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Per-connection handler. Parses an HTTP request, records it,
        sends back HTTP 204."""
        import time

        peer = writer.get_extra_info("peername") or ("", 0)
        source_ip = peer[0] if isinstance(peer, tuple) else ""
        request_line = b""
        headers_text = b""
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            # Read headers until blank line.
            buf: list[bytes] = []
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if not line or line in (b"\r\n", b"\n"):
                    break
                buf.append(line)
            headers_text = b"".join(buf)
        except (TimeoutError, ConnectionResetError):
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass
            return

        method, path, headers = _parse_request_head(request_line, headers_text)
        # Read body up to Content-Length (capped at 8 KiB).
        body_bytes = b""
        try:
            cl_raw = headers.get("content-length", "0")
            cl = max(0, min(8192, int(cl_raw)))
        except (TypeError, ValueError):
            cl = 0
        if cl > 0:
            with suppress(TimeoutError, asyncio.IncompleteReadError):
                body_bytes = await asyncio.wait_for(
                    reader.readexactly(cl), timeout=5.0
                )

        body_text = body_bytes.decode("utf-8", errors="replace")
        hit = OOBHit(
            token=_extract_token(path) or _extract_token(body_text),
            method=method,
            path=path,
            headers=headers,
            body_excerpt=body_text[:1024],
            source_ip=source_ip,
            received_at_ms=int(time.monotonic() * 1000),
        )
        self._hits.append(hit)
        log.info("oob hit: %s %s token=%r from=%s", method, path, hit.token, source_ip)

        # 204 No Content + close.
        writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        with suppress(BrokenPipeError, ConnectionResetError):
            await writer.drain()
        with suppress(OSError):
            writer.close()
            await writer.wait_closed()


# ── helpers ──────────────────────────────────────────────────────────


def _parse_request_head(
    request_line: bytes, headers_text: bytes
) -> tuple[str, str, dict[str, str]]:
    """Minimal HTTP request-line + headers parser.

    We tolerate junk — the OOB listener should NEVER crash on a
    malformed inbound (which could be the target probing us with
    weird payloads). Unparsed parts come back empty.
    """
    request_str = request_line.decode("latin-1", errors="replace").strip()
    parts = request_str.split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else ""
    headers: dict[str, str] = {}
    for line in headers_text.decode("latin-1", errors="replace").splitlines():
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return method, path, headers


def _extract_token(text: str) -> str:
    """Recover the 16-char Argus token from a URL path or body. We
    look for ``/argus/<token>`` first (canary URL shape), then fall
    back to any standalone 16-char alphanumeric string (catches
    operators who manually paste tokens into messages).
    """
    if "/argus/" in text:
        after = text.split("/argus/", 1)[1]
        # Token runs until next slash / query / whitespace / etc.
        tok = ""
        for ch in after:
            if ch in _TOKEN_ALPHABET:
                tok += ch
                if len(tok) >= _TOKEN_LENGTH:
                    return tok
            else:
                break
        if tok:
            return tok
    return ""


@asynccontextmanager
async def managed_listener(
    *,
    bind_host: str = "0.0.0.0",  # noqa: S104
    bind_port: int = 0,
    public_host: str | None = None,
) -> AsyncIterator[ArgusManagedOOB]:
    """Async context manager around ArgusManagedOOB. The scan handler
    uses this so the listener gets cleaned up no matter what."""
    listener = ArgusManagedOOB(
        bind_host=bind_host, bind_port=bind_port, public_host=public_host
    )
    await listener.start()
    try:
        yield listener
    finally:
        await listener.stop()


# Convenience export for the scan handler's "decide which listener" logic.
__all__ = [
    "ArgusManagedOOB",
    "OOBHit",
    "OOBListener",
    "UserSuppliedOOB",
    "managed_listener",
]
