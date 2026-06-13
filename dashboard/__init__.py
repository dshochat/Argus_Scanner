"""Argus dashboard — self-hosted web UI for scan → validate → remediate.

This package is an OPTIONAL feature. Its web/DB dependencies (FastAPI,
SQLAlchemy, asyncpg, uvicorn) ship under the ``[dashboard]`` extra:

    pip install argus-ai-scanner[dashboard]

The base scanner never imports this package at runtime; the CLI lazy-
imports it only when ``argus dashboard ...`` runs or ``ARGUS_DB_URL`` is
set, so a plain ``pip install argus-ai-scanner`` stays DB-free.
"""

from __future__ import annotations

__all__ = ["__version__"]

# Tracks the dashboard schema/UI contract independently of the scanner.
__version__ = "0.1.0"
