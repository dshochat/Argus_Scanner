"""MCP transport primitives — stdio, HTTP, SSE, streamable-HTTP.

Every transport implements the ``MCPTransport`` Protocol so the upper
layer (``mcp_scanner.client``) is transport-agnostic.
"""

from __future__ import annotations

from mcp_scanner.transport.base import (
    MCPTransport,
    MCPTransportError,
    TransportClosed,
)

__all__ = [
    "MCPTransport",
    "MCPTransportError",
    "TransportClosed",
]
