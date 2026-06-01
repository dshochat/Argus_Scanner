"""MCPTransport Protocol — the contract every transport satisfies.

Transports speak line-delimited JSON-RPC 2.0. Argus's minimal client
operates ABOVE this layer; it doesn't care whether bytes flow over
subprocess pipes or HTTP.

Why minimal Protocol + raw dicts (not the SDK's typed shape):

  * Probe injection requires sending intentionally-malformed payloads
    (extra fields, wrong types, oversized strings). The official SDK's
    ClientSession validates against tool schemas client-side and
    refuses to send adversarial inputs — exactly the test we need to
    run. So Argus owns the wire.
  * Keeping the surface small (send / recv / call / aclose) makes it
    trivial to stub for unit tests — see ``tests/unit/test_mcp_client.py``.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


class MCPTransportError(Exception):
    """Generic transport-layer failure (connect, write, read, parse)."""


class TransportClosed(MCPTransportError):  # noqa: N818 — stdlib-style "is-state" name reads better
    """Raised on read/write after the transport has been closed.

    The client surfaces this distinctly from generic errors because
    the probes need to know "the server hung up" vs "we got a malformed
    response back" — the former is interesting evidence (a probe killed
    the server, which is itself a fail-open signal) while the latter is
    a protocol violation.
    """


@runtime_checkable
class MCPTransport(Protocol):
    """The contract every MCP transport implements.

    All methods are async because real transports do real I/O. Stubs
    in tests still implement the async signature; they just don't
    await anything.
    """

    async def send(self, message: dict[str, Any]) -> None:
        """Encode and write one JSON-RPC message to the wire.

        Raises ``TransportClosed`` if the connection is gone.
        ``MCPTransportError`` on encode / write failure.
        """
        ...

    async def recv(self, timeout: float | None = None) -> dict[str, Any]:
        """Read + decode the next JSON-RPC message from the wire.

        ``timeout`` is seconds; ``None`` means "wait forever". Raises
        ``TimeoutError`` when the timeout expires (caller decides
        whether that's a fail-open signal or a flake).
        """
        ...

    async def aclose(self) -> None:
        """Tear down the transport. Idempotent — safe to call twice."""
        ...
