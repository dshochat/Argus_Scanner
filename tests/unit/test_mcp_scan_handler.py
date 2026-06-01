"""Unit tests for the argus mcp scan handler — the in-memory bits.

End-to-end testing against the fixture vulnerable server lives in
tests/integration/test_mcp_scan_e2e.py.
"""

from __future__ import annotations

import argparse

import pytest

from mcp_scanner.cli import _apply_scope_deny, _run_mcp_scan
from mcp_scanner.sandbox_launcher import ProbeRequest

pytestmark = pytest.mark.asyncio


# ── _apply_scope_deny ────────────────────────────────────────────────


def _probe(url: str) -> ProbeRequest:
    return ProbeRequest(
        probe_id="x",
        probe_class="ssrf",
        tool_name="fetch_url",
        arguments={"url": url},
    )


async def test_scope_deny_drops_probes_targeting_denied_cidr() -> None:
    probes = [
        _probe("http://10.0.0.5/x"),
        _probe("http://192.168.1.1/y"),
        _probe("http://example.invalid/safe"),
    ]
    kept = _apply_scope_deny(probes, ["10.0.0.0/8"])
    # 10.0.0.5 dropped; 192.168.1.1 kept (not in 10/8); example.invalid kept.
    assert {p.arguments["url"] for p in kept} == {
        "http://192.168.1.1/y",
        "http://example.invalid/safe",
    }


async def test_scope_deny_multiple_cidrs() -> None:
    probes = [
        _probe("http://10.0.0.5/"),
        _probe("http://192.168.1.1/"),
        _probe("http://172.16.0.1/"),
        _probe("http://169.254.169.254/imds"),
        _probe("http://1.1.1.1/safe"),
    ]
    kept = _apply_scope_deny(probes, ["10.0.0.0/8", "192.168.0.0/16", "169.254.0.0/16"])
    assert {p.arguments["url"] for p in kept} == {
        "http://172.16.0.1/",
        "http://1.1.1.1/safe",
    }


async def test_scope_deny_hostname_targets_not_filtered() -> None:
    """The filter only applies to IP-literal URL hosts. Hostname canaries
    (metadata.google.internal etc.) aren't filtered here — they get
    blocked by the sandbox + OOB design instead."""
    probes = [_probe("http://metadata.google.internal/")]
    kept = _apply_scope_deny(probes, ["169.254.0.0/16"])
    assert len(kept) == 1


async def test_scope_deny_invalid_cidr_is_ignored() -> None:
    """A typo CIDR should be ignored (warning logged) rather than
    crash. The valid CIDRs in the list still apply."""
    probes = [
        _probe("http://169.254.169.254/imds"),
        _probe("http://1.1.1.1/safe"),
    ]
    kept = _apply_scope_deny(probes, ["bogus", "169.254.0.0/16"])
    assert {p.arguments["url"] for p in kept} == {"http://1.1.1.1/safe"}


async def test_scope_deny_no_cidrs_is_passthrough() -> None:
    probes = [_probe("http://10.0.0.5/")]
    assert _apply_scope_deny(probes, []) == probes


async def test_scope_deny_no_args_url_is_passthrough() -> None:
    """A probe whose arguments contain no URL strings shouldn't be
    affected by scope-deny."""
    p = ProbeRequest(
        probe_id="x",
        probe_class="auth_bypass",
        tool_name="admin_lookup",
        arguments={"user_id": "1"},
    )
    kept = _apply_scope_deny([p], ["10.0.0.0/8"])
    assert kept == [p]


# ── _run_mcp_scan — safety gate ─────────────────────────────────────


async def test_run_mcp_scan_remote_without_authorized_refuses(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Remote URL scan without --authorized → exit 2 + stderr message.
    The consent gate is a CRITICAL safety contract; the test pins it."""
    args = argparse.Namespace(
        url="https://example.test/mcp",
        stdio=None,
        transport=None,
        auth="none",
        auth_token=None,
        authorized=False,
        oob=None,
        scope_deny=[],
        tools=None,
        report="json",
        output_file=None,
    )
    rc = await _run_mcp_scan(args)
    assert rc == 2
    err = capsys.readouterr().err
    assert "--authorized" in err


async def test_run_mcp_scan_stdio_does_not_require_authorized() -> None:
    """Stdio targets are sandbox-protected (and per v1.12 wiring runs
    LocalMCPSession). They should NOT require --authorized."""
    # We don't actually drive a server here — just verify the consent
    # gate doesn't fire on stdio. A real handler invocation would need
    # a working binary; that's covered by the integration test.
    args = argparse.Namespace(
        url=None,
        stdio="/nonexistent/binary-9999",
        transport=None,
        auth="none",
        auth_token=None,
        authorized=False,  # NO --authorized flag set
        oob=None,
        scope_deny=[],
        tools=None,
        report="json",
        output_file=None,
    )
    # Should NOT exit 2 on the consent gate — should exit 1 from the
    # transport-error path (nonexistent binary). The point is that we
    # made it PAST the gate.
    rc = await _run_mcp_scan(args)
    assert rc == 1  # transport error, not consent denial
