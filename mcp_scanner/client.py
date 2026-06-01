"""Minimal MCP JSON-RPC client.

Wraps any ``MCPTransport`` (stdio or HTTP) with the four high-level
operations the rest of the scanner needs:

  * ``initialize`` — handshake + capabilities exchange.
  * ``list_tools`` / ``list_resources`` / ``list_prompts`` — discovery.
  * ``call_tool`` — typed-shape tool invocation.
  * ``raw_request`` — escape hatch for probes that need to send
    JSON-RPC the SDK would refuse (malformed input for fail-open,
    no-auth-token for auth-bypass diff, etc.).

Why minimal (not the official SDK):

The probe layer sends INTENTIONALLY-MALFORMED payloads. The official
``mcp`` Python SDK's ``ClientSession`` validates each ``tools/call``
against the tool's published schema client-side and refuses to send
the bad input — exactly what we need to TEST. So Argus owns the wire.

The official SDK is still listed as an optional extra (``[mcp]``) so
users who also build / test MCP servers can install it alongside; we
just don't depend on it for the scan path.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_scanner import MCP_PROTOCOL_VERSION
from mcp_scanner.classifier import classify_param
from mcp_scanner.surface import (
    MCPParam,
    MCPPrompt,
    MCPResource,
    MCPSurfaceMap,
    MCPTool,
)
from mcp_scanner.transport.base import (
    MCPTransport,
    MCPTransportError,
    TransportClosed,
)

log = logging.getLogger("argus.mcp.client")


class MCPClientError(Exception):
    """An MCP-level error — JSON-RPC error response, missing fields,
    initialize-refused, etc. Transport-level errors raise the
    transport's exception types instead."""


class MCPClient:
    """Stateful wrapper around an MCPTransport.

    The client owns:
      * The JSON-RPC request id counter.
      * The post-initialize state (capabilities + server info).
      * Sane request timeouts.

    Not thread-safe. One client per logical session — the probe layer
    builds a fresh client per probe so a probe that hangs the session
    can't poison subsequent probes.
    """

    def __init__(
        self,
        transport: MCPTransport,
        *,
        client_name: str = "argus-mcp-scanner",
        client_version: str = "1.12",
        default_timeout: float = 30.0,
    ) -> None:
        self._t = transport
        self._client_name = client_name
        self._client_version = client_version
        self._default_timeout = default_timeout
        self._next_id = 1
        self._initialized = False
        self._server_capabilities: dict[str, Any] = {}
        self._server_info: dict[str, Any] = {}
        self._protocol_version: str = ""

    @property
    def transport(self) -> MCPTransport:
        return self._t

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def server_capabilities(self) -> dict[str, Any]:
        return dict(self._server_capabilities)

    @property
    def server_info(self) -> dict[str, Any]:
        return dict(self._server_info)

    @property
    def protocol_version(self) -> str:
        return self._protocol_version

    # ── core JSON-RPC primitives ─────────────────────────────────────

    def _alloc_id(self) -> int:
        i = self._next_id
        self._next_id += 1
        return i

    async def raw_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
        skip_init_check: bool = False,
    ) -> dict[str, Any]:
        """Send one JSON-RPC request, wait for the matching response.

        ``skip_init_check`` lets the initialize call go through before
        ``self._initialized`` is True. All other calls require a
        completed initialize per the MCP spec.

        Returns the FULL response dict (``{jsonrpc, id, result OR error}``).
        Callers that only care about success unwrap ``.result`` after
        an ``_unwrap_result`` call. Probes that want to see error
        responses raw use this method.
        """
        if not skip_init_check and not self._initialized:
            raise MCPClientError(
                f"called {method!r} before initialize completed"
            )
        request_id = self._alloc_id()
        msg: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            msg["params"] = params
        await self._t.send(msg)
        # Loop until we see the response matching our id — server may
        # interleave notifications.
        deadline_timeout = timeout if timeout is not None else self._default_timeout
        while True:
            resp = await self._t.recv(timeout=deadline_timeout)
            # Notification (no id, has method) — ignore for v1.
            if "method" in resp and "id" not in resp:
                continue
            # Mismatched id — server sent a response we didn't ask for.
            # Could be a buggy server or a probe-caused desync. Log and
            # keep reading; probes that care will time out instead.
            if resp.get("id") != request_id:
                log.debug(
                    "mcp client: dropping unexpected response id=%r (waiting on %r)",
                    resp.get("id"),
                    request_id,
                )
                continue
            return resp

    async def send_notification(
        self, method: str, params: dict[str, Any] | None = None
    ) -> None:
        """JSON-RPC notification (no ``id``, no response expected).

        Per spec, ``notifications/initialized`` MUST be sent after a
        successful initialize. Other notifications (logging, cancelled)
        are optional.
        """
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        await self._t.send(msg)

    @staticmethod
    def _unwrap_result(resp: dict[str, Any], method: str) -> dict[str, Any]:
        """Pull ``.result`` out of a JSON-RPC response or raise
        ``MCPClientError`` if the response was an error.
        """
        if "error" in resp:
            err = resp["error"]
            code = err.get("code") if isinstance(err, dict) else None
            message = err.get("message") if isinstance(err, dict) else str(err)
            raise MCPClientError(
                f"{method!r} returned error: code={code} message={message!r}"
            )
        result = resp.get("result")
        if not isinstance(result, dict):
            raise MCPClientError(
                f"{method!r} returned malformed result (expected dict, got {type(result).__name__})"
            )
        return result

    # ── high-level operations ────────────────────────────────────────

    async def initialize(
        self,
        *,
        protocol_version: str = MCP_PROTOCOL_VERSION,
        capabilities: dict[str, Any] | None = None,
    ) -> None:
        """Run the handshake. Idempotent — second call is a no-op."""
        if self._initialized:
            return
        params: dict[str, Any] = {
            "protocolVersion": protocol_version,
            "capabilities": capabilities or {},
            "clientInfo": {
                "name": self._client_name,
                "version": self._client_version,
            },
        }
        resp = await self.raw_request(
            "initialize", params, skip_init_check=True
        )
        result = self._unwrap_result(resp, "initialize")
        self._protocol_version = (
            result.get("protocolVersion") or protocol_version
        )
        self._server_capabilities = dict(result.get("capabilities") or {})
        self._server_info = dict(result.get("serverInfo") or {})
        # Per spec: send ``notifications/initialized`` after the
        # response is parsed. Some servers refuse subsequent calls
        # until this notification arrives.
        await self.send_notification("notifications/initialized")
        self._initialized = True

    async def list_tools(self) -> list[dict[str, Any]]:
        """Return raw ``tools`` array from ``tools/list``. Empty list
        on a server that has no tools or doesn't expose the method."""
        resp = await self.raw_request("tools/list")
        try:
            result = self._unwrap_result(resp, "tools/list")
        except MCPClientError as e:
            log.info("tools/list refused: %s", e)
            return []
        tools = result.get("tools") or []
        return [t for t in tools if isinstance(t, dict)]

    async def list_resources(self) -> list[dict[str, Any]]:
        resp = await self.raw_request("resources/list")
        try:
            result = self._unwrap_result(resp, "resources/list")
        except MCPClientError as e:
            log.info("resources/list refused: %s", e)
            return []
        items = result.get("resources") or []
        return [r for r in items if isinstance(r, dict)]

    async def list_prompts(self) -> list[dict[str, Any]]:
        resp = await self.raw_request("prompts/list")
        try:
            result = self._unwrap_result(resp, "prompts/list")
        except MCPClientError as e:
            log.info("prompts/list refused: %s", e)
            return []
        items = result.get("prompts") or []
        return [p for p in items if isinstance(p, dict)]

    async def call_tool(
        self, name: str, arguments: dict[str, Any], *, timeout: float | None = None
    ) -> dict[str, Any]:
        """Invoke a tool. Returns the full JSON-RPC response so probes
        can inspect ``result``, ``error``, AND raw fields like
        ``isError`` flags on tool results."""
        return await self.raw_request(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout=timeout,
        )

    # ── full enumerate flow ──────────────────────────────────────────

    async def enumerate(self, target: str, transport_label: str) -> MCPSurfaceMap:
        """Drive a full handshake + discovery pass; return a typed
        surface map.

        ``transport_label`` is what the report renders; it's also what
        the scanner uses to route certain probes (e.g. SSE-specific
        chunked-response abuses).

        Errors during DISCOVERY (tools/list, resources/list, prompts/list)
        are recorded on the surface map's ``discovery_errors`` rather
        than raised — a minimal server that only implements tools/list
        still produces a useful surface map.

        Errors during INITIALIZE raise — without a successful handshake
        the server isn't really an MCP server.
        """
        await self.initialize()

        tools_models: list[MCPTool] = []
        resources_models: list[MCPResource] = []
        prompts_models: list[MCPPrompt] = []
        errors: list[str] = []

        # tools/list — gated by server capabilities. Per spec, a server
        # without ``capabilities.tools`` should not be asked. But many
        # implementations are loose with capabilities; try anyway.
        try:
            raw_tools = await self.list_tools()
            for t in raw_tools:
                tools_models.append(_build_tool_model(t))
        except (MCPTransportError, TransportClosed, TimeoutError) as e:
            errors.append(f"tools/list: {type(e).__name__}: {e}")

        try:
            raw_resources = await self.list_resources()
            for r in raw_resources:
                resources_models.append(
                    MCPResource(
                        uri=str(r.get("uri") or ""),
                        name=str(r.get("name") or ""),
                        description=str(r.get("description") or ""),
                        mime_type=r.get("mimeType"),
                    )
                )
        except (MCPTransportError, TransportClosed, TimeoutError) as e:
            errors.append(f"resources/list: {type(e).__name__}: {e}")

        try:
            raw_prompts = await self.list_prompts()
            for p in raw_prompts:
                args = p.get("arguments")
                prompts_models.append(
                    MCPPrompt(
                        name=str(p.get("name") or ""),
                        description=str(p.get("description") or ""),
                        arguments=list(args) if isinstance(args, list) else [],
                    )
                )
        except (MCPTransportError, TransportClosed, TimeoutError) as e:
            errors.append(f"prompts/list: {type(e).__name__}: {e}")

        return MCPSurfaceMap(
            target=target,
            transport=transport_label,
            protocol_version=self._protocol_version,
            server_info=dict(self._server_info),
            capabilities=dict(self._server_capabilities),
            tools=tools_models,
            resources=resources_models,
            prompts=prompts_models,
            discovery_errors=errors,
        )


def _build_tool_model(raw: dict[str, Any]) -> MCPTool:
    """Build an MCPTool from a raw tools/list entry.

    Handles the spec's ``inputSchema`` shape (object schema with
    ``properties`` + optional ``required``). Schemas that don't match
    that shape fall through as a single-param ``UNKNOWN`` so the probe
    layer at least has something to fuzz.
    """
    name = str(raw.get("name") or "").strip()
    description = str(raw.get("description") or "")
    input_schema = raw.get("inputSchema")
    if not isinstance(input_schema, dict):
        input_schema = {}

    params: list[MCPParam] = []
    properties = input_schema.get("properties")
    required_list = input_schema.get("required") or []
    required_set: set[str] = (
        {str(r) for r in required_list} if isinstance(required_list, list) else set()
    )

    if isinstance(properties, dict):
        for pname, pschema in properties.items():
            sub_schema = pschema if isinstance(pschema, dict) else {}
            params.append(
                MCPParam(
                    name=str(pname),
                    param_class=classify_param(str(pname), sub_schema),
                    required=str(pname) in required_set,
                    json_schema=sub_schema,
                )
            )

    return MCPTool(
        name=name,
        description=description,
        params=params,
        raw_input_schema=input_schema,
    )
