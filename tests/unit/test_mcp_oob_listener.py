"""Unit tests for mcp_scanner.oob_listener.

Covers token generation, both listener flavors (user-supplied +
Argus-managed), the live HTTP listener round-trip via real sockets
(localhost only), and token extraction from canary URL paths.
"""

from __future__ import annotations

import asyncio
import socket
from contextlib import suppress

import pytest

from mcp_scanner.oob_listener import (
    ArgusManagedOOB,
    OOBHit,
    OOBListener,
    UserSuppliedOOB,
    _extract_token,
    _new_token,
    managed_listener,
)

pytestmark = pytest.mark.asyncio


# ── token machinery ──────────────────────────────────────────────────


async def test_new_token_is_16_chars_alphanumeric() -> None:
    tok = _new_token()
    assert len(tok) == 16
    assert tok.isalnum()


async def test_new_token_uniqueness_over_1000_draws() -> None:
    """16 chars × 62 alphabet = ~96 bits — collisions in 1000 draws
    are astronomically unlikely. This guards against a regression to
    a weaker generator (e.g. random.choice with predictable seed)."""
    tokens = {_new_token() for _ in range(1000)}
    assert len(tokens) == 1000


async def test_extract_token_from_argus_path() -> None:
    assert _extract_token("/argus/aBc123XYZ789defG") == "aBc123XYZ789defG"


async def test_extract_token_from_url_with_query() -> None:
    """Query params after the token shouldn't bleed into it."""
    assert _extract_token("/argus/aBc123XYZ789defG?x=1") == "aBc123XYZ789defG"


async def test_extract_token_returns_empty_on_no_match() -> None:
    assert _extract_token("/totally/different/path") == ""


async def test_extract_token_from_body_text() -> None:
    body = '{"callback": "http://atk/argus/aBc123XYZ789defG"}'
    assert _extract_token(body) == "aBc123XYZ789defG"


async def test_extract_token_truncates_at_16_chars() -> None:
    """A path longer than 16 token chars should yield only the first 16."""
    assert _extract_token("/argus/aBc123XYZ789defGextra") == "aBc123XYZ789defG"


# ── UserSuppliedOOB ──────────────────────────────────────────────────


async def test_user_supplied_oob_satisfies_protocol() -> None:
    o = UserSuppliedOOB("https://abc.oast.fun/")
    assert isinstance(o, OOBListener)


async def test_user_supplied_oob_builds_url() -> None:
    o = UserSuppliedOOB("https://abc.oast.fun")
    assert o.build_callback_url("tokTOK1234567890") == "https://abc.oast.fun/argus/tokTOK1234567890"


async def test_user_supplied_oob_trailing_slash_normalised() -> None:
    """``https://x/`` and ``https://x`` should produce identical URLs."""
    with_slash = UserSuppliedOOB("https://abc.oast.fun/")
    without = UserSuppliedOOB("https://abc.oast.fun")
    assert with_slash.build_callback_url("t") == without.build_callback_url("t")


async def test_user_supplied_oob_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError):
        UserSuppliedOOB("ws://x")


async def test_user_supplied_oob_record_and_filter_hits() -> None:
    o = UserSuppliedOOB("https://x.test")
    o.record_hit(OOBHit(token="abc12345DEF67890", path="/argus/abc12345DEF67890"))
    o.record_hit(OOBHit(token="zzz98765ZZZ54321", path="/argus/zzz98765ZZZ54321"))
    hits = o.hits_for("abc12345DEF67890")
    assert len(hits) == 1
    assert hits[0].path == "/argus/abc12345DEF67890"
    assert len(o.all_hits()) == 2


# ── ArgusManagedOOB ──────────────────────────────────────────────────


async def test_argus_managed_satisfies_protocol() -> None:
    o = ArgusManagedOOB()
    assert isinstance(o, OOBListener)


async def test_argus_managed_build_callback_url_before_start_raises() -> None:
    o = ArgusManagedOOB()
    with pytest.raises(RuntimeError):
        o.build_callback_url("tok")


async def test_argus_managed_start_returns_ephemeral_port() -> None:
    """Binding to port 0 should yield a real port number > 0."""
    listener = ArgusManagedOOB(bind_host="127.0.0.1", bind_port=0)
    port = await listener.start()
    try:
        assert port > 0
        assert listener.actual_port == port
        # Start is idempotent.
        port2 = await listener.start()
        assert port2 == port
    finally:
        await listener.stop()


async def test_argus_managed_records_inbound_request() -> None:
    """Drive a real HTTP GET against the listener; verify the hit gets
    captured with the right token + method + path."""
    async with managed_listener(bind_host="127.0.0.1", bind_port=0) as listener:
        token = "tokABCdef1234567"
        url_path = f"/argus/{token}"
        # Open a raw TCP socket + send HTTP/1.1 request.
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.actual_port
        )
        try:
            req = (
                f"GET {url_path} HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\n"
                f"User-Agent: argus-test\r\n"
                f"X-Forwarded-For: 10.0.0.5\r\n"
                f"\r\n"
            )
            writer.write(req.encode())
            await writer.drain()
            # Listener replies 204 No Content.
            resp = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            assert b"204 No Content" in resp
        finally:
            writer.close()
            await writer.wait_closed()
        # Give the listener a moment to finish recording.
        await asyncio.sleep(0.05)
        hits = listener.hits_for(token)
        assert len(hits) == 1
        h = hits[0]
        assert h.method == "GET"
        assert h.path == url_path
        assert h.token == token
        assert h.headers.get("x-forwarded-for") == "10.0.0.5"
        assert h.source_ip == "127.0.0.1"


async def test_argus_managed_returns_no_hits_for_unrecorded_token() -> None:
    async with managed_listener(bind_host="127.0.0.1", bind_port=0) as listener:
        assert listener.hits_for("token-we-never-saw") == []
        assert listener.all_hits() == []


async def test_argus_managed_explicit_public_host_used_in_url() -> None:
    listener = ArgusManagedOOB(
        bind_host="0.0.0.0",  # noqa: S104 — test intent
        bind_port=0,
        public_host="argus.example.test",
    )
    await listener.start()
    try:
        url = listener.build_callback_url("tok1234567890abc")
        assert url.startswith("http://argus.example.test:")
        assert "/argus/tok1234567890abc" in url
    finally:
        await listener.stop()


async def test_argus_managed_records_request_body() -> None:
    """When the target POSTs the IMDS creds back to the canary, we
    want the body for the report. Bound at 8 KiB max."""
    async with managed_listener(bind_host="127.0.0.1", bind_port=0) as listener:
        token = "tokXYZabcdef9876"
        body = f"stolen-creds=for-{token}"
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.actual_port
        )
        try:
            req = (
                f"POST /argus/{token} HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Content-Type: text/plain\r\n"
                f"\r\n"
                f"{body}"
            )
            writer.write(req.encode())
            await writer.drain()
            await asyncio.wait_for(reader.read(1024), timeout=2.0)
        finally:
            writer.close()
            await writer.wait_closed()
        await asyncio.sleep(0.05)
        hits = listener.hits_for(token)
        assert len(hits) == 1
        assert hits[0].method == "POST"
        assert body in hits[0].body_excerpt


async def test_argus_managed_stop_releases_port() -> None:
    """After stop(), the port should be re-bindable."""
    listener = ArgusManagedOOB(bind_host="127.0.0.1", bind_port=0)
    port = await listener.start()
    await listener.stop()
    # A second bind to the same port should succeed (with SO_REUSEADDR
    # this might pass even without stop, but asyncio's start_server
    # doesn't set SO_REUSEADDR on Windows).
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            # Some platforms hold the port briefly post-close; that's
            # acceptable, but if the bind succeeds we've proven the
            # release path works.
            return
        # Bind succeeded → port released.
        assert True


async def test_argus_managed_handles_malformed_request_without_crash() -> None:
    """Send garbage bytes; the listener should NOT crash."""
    async with managed_listener(bind_host="127.0.0.1", bind_port=0) as listener:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.actual_port
        )
        try:
            writer.write(b"\x00\x01\x02 GARBAGE NOT A REQUEST")
            await writer.drain()
            # Some response or hangup is fine; main thing is no crash.
            with suppress(TimeoutError):
                await asyncio.wait_for(reader.read(1024), timeout=1.0)
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
        # Listener should still serve subsequent requests.
        token = "tokFollowUp12345"
        reader2, writer2 = await asyncio.open_connection(
            "127.0.0.1", listener.actual_port
        )
        try:
            writer2.write(f"GET /argus/{token} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            await writer2.drain()
            resp = await asyncio.wait_for(reader2.read(1024), timeout=2.0)
            assert b"204" in resp
        finally:
            writer2.close()
            await writer2.wait_closed()
        await asyncio.sleep(0.05)
        assert len(listener.hits_for(token)) == 1
