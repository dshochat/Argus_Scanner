"""MCP test fixtures.

Tiny vulnerable MCP servers + helpers used by integration tests under
``tests/integration/test_mcp_*.py``. The servers are intentionally
naive — each exposes a specific vulnerability class so the
corresponding Argus probe can validate end-to-end detection.
"""
