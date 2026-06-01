"""Probe Protocol + registry.

A ``Probe`` is the contract every active-scan probe class implements.
Probes are pure logic — they generate ``ProbeRequest`` lists for the
sandbox harness, then evaluate the harness's responses into
``MCPFinding`` objects. The probes never speak directly to the MCP
server; that's the launcher / harness layer's job.

This split exists so that:

  1. Probes are trivial to unit-test (no async, no subprocess).
  2. Multiple probes can be batched into one sandbox run (cheap).
  3. Network-evidence attribution (from ``network_captures``) stays
     centralised — each probe specifies which ``host`` + ``path``
     pattern is its smoking gun, the evaluator matches.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from mcp_scanner.findings import MCPFinding
    from mcp_scanner.sandbox_launcher import ProbeRequest, ProbeResponse
    from mcp_scanner.surface import MCPSurfaceMap


@runtime_checkable
class Probe(Protocol):
    """The contract every MCP probe implements."""

    #: Stable string the registry + reports key off. Lower-case
    #: snake-case. Used as the ``probe_class`` on every ``ProbeRequest``
    #: this probe emits so attribution from response → probe works.
    probe_class: str

    def build_requests(self, surface: MCPSurfaceMap) -> list[ProbeRequest]:
        """Return the probe-spec payloads for this probe given the
        surface map. Empty list = "nothing to test here" (no eligible
        tool params)."""
        ...

    def evaluate(
        self,
        surface: MCPSurfaceMap,
        responses: list[ProbeResponse],
        network_captures: list[dict],
    ) -> list[MCPFinding]:
        """Turn the harness's responses (filtered to THIS probe's
        ``probe_class``) into findings. ``network_captures`` is the
        full sandbox observation set — probes attribute hits back to
        their own canary URLs / hostnames as evidence.
        """
        ...


#: Module-level registry. Each probe module appends to it via
#: ``register_probe`` at import time so the scan handler can iterate
#: probes without explicit imports of every concrete class.
PROBE_REGISTRY: list[Probe] = []


def register_probe(probe: Probe) -> Probe:
    """Add ``probe`` to the global registry. Idempotent — registering
    the same instance twice is a no-op so re-imports during testing
    don't double-fire probes."""
    if probe not in PROBE_REGISTRY:
        PROBE_REGISTRY.append(probe)
    return probe
