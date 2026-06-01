"""Tiny vulnerable MCP stdio server — for Argus's integration tests.

Speaks MCP-over-stdio using only the Python stdlib (no SDK dep) so
the test suite stays dep-light. Each tool below is intentionally
vulnerable to a specific class of bug the Argus probe catalog
targets:

  * ``fetch_url(url)`` — calls ``urllib.request.urlopen(url)`` with no
    scheme / host validation → SSRF (CWE-918). Probes target this.

  * ``read_url_with_redirects(url)`` — follows up to 5 redirects via
    urllib's default redirect handler → redirect-to-internal chain
    (CWE-601 + CWE-918). Hits IMDS even with a public-looking start.

  * ``safe_fetch(url)`` — validates ``url.startswith("https://")`` ONCE
    at top, then silently catches all exceptions and falls through to
    a "we tried, returning empty" path. Fail-open: a probe that drives
    the validator to raise (e.g. malformed UTF-8 in the URL) bypasses
    the check.

  * ``admin_lookup(user_id)`` — checks the ``MCP_AUTH_TOKEN`` env var
    against the ``Authorization`` header... in the description. The
    code itself NEVER reads any token — it always returns data. Auth
    bypass: same response unauthed vs authed.

  * ``echo(text)`` — harmless baseline tool. Should NEVER yield a
    finding; useful as a false-positive guard in tests.

Run standalone for manual exploration:

    python tests/fixtures/mcp/vulnerable_server.py

Connect via stdin/stdout with line-delimited JSON-RPC.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request

# ── Vulnerable tool implementations ───────────────────────────────────


def _fetch_url(url: str) -> str:
    """SSRF sink: pipes ``url`` straight into urlopen.

    Caps the read at 16 KiB so we can't accidentally exfil multi-MB
    responses in tests. The vulnerability is the lack of allowlist /
    private-IP filter, not the read cap.
    """
    try:
        with urllib.request.urlopen(url, timeout=2.0) as resp:  # noqa: S310 — intentional
            data = resp.read(16 * 1024)
            return data.decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return f"URLError: {e}"
    except Exception as e:  # noqa: BLE001 — fixture: surface all errors
        return f"error: {type(e).__name__}: {e}"


def _read_url_with_redirects(url: str) -> str:
    """Redirect-chain SSRF: uses the default handler so 30x → internal
    targets get followed without scheme / host re-validation."""
    try:
        # ``urlopen`` follows redirects by default (max ~10). A probe
        # canary that 302s to http://169.254.169.254/ lands in IMDS.
        with urllib.request.urlopen(url, timeout=2.0) as resp:  # noqa: S310
            data = resp.read(16 * 1024)
            return data.decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return f"URLError: {e}"
    except Exception as e:  # noqa: BLE001
        return f"error: {type(e).__name__}: {e}"


def _safe_fetch(url: str) -> str:
    """Fail-open: claims to enforce https-only.

    The validator runs FIRST, but the try/except is so broad it
    swallows the ValueError and falls through to the unrestricted
    fetch path. A probe that supplies a URL the validator can't even
    parse (raises before the scheme check) hits the bypass.
    """
    try:
        if not url.startswith("https://"):
            raise ValueError("only https:// allowed")
        # Re-check (paranoia). If we got here, scheme is https.
    except Exception:  # noqa: BLE001 — INTENTIONAL: this is the bug
        # "Be lenient on validator errors" — classic fail-open pattern.
        pass
    try:
        with urllib.request.urlopen(url, timeout=2.0) as resp:  # noqa: S310
            return resp.read(16 * 1024).decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return f"error: {type(e).__name__}: {e}"


def _admin_lookup(user_id: str) -> dict[str, object]:
    """Auth-bypass: description says "requires auth", code never checks.

    Returns the same shape whether the client is authed or not — the
    auth_bypass probe diffs these responses and flags identical
    payloads as evidence of missing enforcement.
    """
    # NB: ``MCP_AUTH_TOKEN`` is read here ONLY to print a debug line so
    # the fixture is observable; it does not gate the response.
    expected = os.environ.get("MCP_AUTH_TOKEN", "")
    if expected:
        print(f"[fixture] expected token={expected!r}", file=sys.stderr)
    return {
        "user_id": user_id,
        "role": "admin",
        "secrets": {"api_key": "AKIA-FIXTURE-DO-NOT-USE"},
    }


def _echo(text: str) -> str:
    """Baseline tool — no vulnerability. Probes should not flag this."""
    return text


# ── Schema definitions (returned by tools/list) ───────────────────────


_TOOL_SPECS: list[dict[str, object]] = [
    {
        "name": "fetch_url",
        "description": "Fetch the contents of a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "URL to fetch"}},
            "required": ["url"],
        },
    },
    {
        "name": "read_url_with_redirects",
        "description": "Fetch a URL, following any 30x redirects.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "safe_fetch",
        "description": "Fetch a URL. HTTPS-only (validated server-side).",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "admin_lookup",
        "description": (
            "Look up an admin user by id. Requires Authorization: Bearer "
            "$MCP_AUTH_TOKEN."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"user_id": {"type": "string"}},
            "required": ["user_id"],
        },
    },
    {
        "name": "echo",
        "description": "Echo the supplied text. Harmless.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
]

_TOOL_HANDLERS: dict[str, object] = {
    "fetch_url": _fetch_url,
    "read_url_with_redirects": _read_url_with_redirects,
    "safe_fetch": _safe_fetch,
    "admin_lookup": _admin_lookup,
    "echo": _echo,
}


# ── JSON-RPC dispatch ─────────────────────────────────────────────────


def _make_response(request_id: object, result: object | None = None,
                   error: dict[str, object] | None = None) -> dict[str, object]:
    msg: dict[str, object] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result if result is not None else {}
    return msg


def _handle_request(req: dict[str, object]) -> dict[str, object] | None:
    """Dispatch one JSON-RPC request → response dict (or None for
    notifications)."""
    method = req.get("method")
    request_id = req.get("id")
    params = req.get("params") if isinstance(req.get("params"), dict) else {}
    assert isinstance(params, dict)

    # Notification — no response.
    if request_id is None:
        return None

    if method == "initialize":
        return _make_response(
            request_id,
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "argus-fixture-vuln-server", "version": "0.1"},
            },
        )

    if method == "tools/list":
        return _make_response(request_id, {"tools": _TOOL_SPECS})

    if method == "resources/list":
        return _make_response(request_id, {"resources": []})

    if method == "prompts/list":
        return _make_response(request_id, {"prompts": []})

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(name, str) or name not in _TOOL_HANDLERS:
            return _make_response(
                request_id,
                error={"code": -32601, "message": f"unknown tool: {name!r}"},
            )
        if not isinstance(args, dict):
            return _make_response(
                request_id,
                error={"code": -32602, "message": "arguments must be an object"},
            )
        handler = _TOOL_HANDLERS[name]
        try:
            # Tools are positional-arg-free; each takes the dict's
            # values via keyword. Reflection here is a stand-in for
            # the SDK's schema-driven invocation.
            result = handler(**args)  # type: ignore[operator]
        except TypeError as e:
            return _make_response(
                request_id,
                error={"code": -32602, "message": f"bad args: {e}"},
            )
        # MCP tools return ``{content: [{type:text, text:...}], isError?}``.
        payload_text = (
            json.dumps(result, default=str) if isinstance(result, dict) else str(result)
        )
        return _make_response(
            request_id,
            {"content": [{"type": "text", "text": payload_text}]},
        )

    return _make_response(
        request_id,
        error={"code": -32601, "message": f"unknown method: {method!r}"},
    )


def main() -> int:
    """Read line-delimited JSON-RPC requests on stdin; write responses
    on stdout. Exits on EOF."""
    # Drain stderr in a daemon thread so callers don't deadlock if the
    # fixture writes noise there during a long scan.
    threading.Thread(
        target=lambda: sys.stderr.flush(), name="stderr-flusher", daemon=True
    ).start()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            # MCP doesn't define how to recover from garbage on the
            # wire; we just keep reading and let the client time out.
            continue
        if not isinstance(req, dict):
            continue
        resp = _handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
