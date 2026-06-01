"""MCP probe catalog.

Each probe is a self-contained module exposing:

  * A ``build_requests(surface) -> list[ProbeRequest]`` function that
    examines a surface map and returns the probe-spec payloads it
    wants the harness to fire.
  * An ``evaluate(surface, responses, network_captures) -> list[Finding]``
    function that converts harness output back into findings.

This split (build → fire-in-sandbox → evaluate) is what lets the
sandbox launcher batch ALL probes into a single SandboxPlan rather
than paying Fly cold-start cost per probe.
"""

from __future__ import annotations

# Import probe modules for the side effect of registering themselves.
from mcp_scanner.probes.auth_bypass import AuthBypassProbe  # noqa: F401 — registered
from mcp_scanner.probes.base import (
    PROBE_REGISTRY,
    Probe,
    register_probe,
)
from mcp_scanner.probes.fail_open import FailOpenProbe  # noqa: F401 — registered
from mcp_scanner.probes.redirect import RedirectProbe  # noqa: F401 — registered
from mcp_scanner.probes.ssrf import SSRFProbe  # noqa: F401 — registered

__all__ = [
    "PROBE_REGISTRY",
    "AuthBypassProbe",
    "FailOpenProbe",
    "Probe",
    "RedirectProbe",
    "SSRFProbe",
    "register_probe",
]
