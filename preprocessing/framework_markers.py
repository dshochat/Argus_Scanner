"""Framework marker heuristic — PREP-017 + PREP-019.

Scan the first 2 KB of decoded content for canonical web-framework
**import statements** (PREP-019) and emit a single framework name that
S1 can pre-seed its ``framework`` field from.

History:

* PREP-017 landed a bare-substring matcher on the 8 framework names
  (``flask``, ``fastapi``, ``django``, ``express``, ``gin``, ``echo``,
  ``fiber``, ``rails``). This matched the port from
  ``app/scanner/backend/scan_engine.py``, but substring matching on a
  3-character token (``gin``) produced systematic false positives:
  ``login``, ``begin``, ``engine``, ``engineering``, ``logging`` all
  contain ``gin`` as a substring. 7 of 11 files in the augmented
  benchmark corpus tripped the matcher on prose/variable names, none
  of which actually used the ``gin`` framework.
* PREP-019 switches from substring matching to language-aware
  import-statement regex. Asks "does this file use the framework?"
  instead of "does this file contain the letters of the framework
  name?" — directly answering the question the pre-pass is supposed
  to answer.

Scope notes:

* **Detects framework USE (import statements), not framework MENTIONS**
  in prose, variable names, or documentation. A ``README.md`` that
  says "we migrated from Flask to FastAPI" no longer matches; a
  Python file with ``from flask import Flask`` does.
* **Precedence: first match wins.** Order matches the PREP-017 tuple:
  ``flask > fastapi > django > express > gin > echo > fiber > rails``.
  When a file uses two frameworks at once (e.g., a test fixture that
  imports both), S1 sees a stable hint rather than a bag-of-matches.
* **Transitive framework detection is S1's responsibility.** A
  file that imports from a project-local module (which in turn
  imports Flask) does not get a framework hint from the pre-pass.
  S1's content inference handles the transitive case.
* **Scan window: first 2048 characters.** Files whose framework
  imports land deeper than 2 KB miss the hint. Framework imports
  overwhelmingly land near the top; we trade recall on pathological
  layouts for speed and precision.
* **No post-override.** Unlike ``imperative_install_detected`` and
  ``attack_vector_extension`` (safety nets that force
  ``priority_score >= 4``), ``framework_hint`` is purely informative.
  S1 may override from content evidence; the hint never forces.
"""

from __future__ import annotations

import re

# Scan window: first 2 KB of decoded content.
_SCAN_WINDOW_CHARS = 2048

# Per-framework regex tuples. Each framework's patterns cover the
# realistic forms of "this file uses framework X". Patterns are
# compiled at module load; first match wins; iteration order within
# a framework's tuple doesn't affect output.
#
# Pattern design:
#
# * Python frameworks — ``from <framework>(...) import ...`` plus
#   ``import <framework>``, anchored with ``\b`` so ``from flaskishly``
#   doesn't match. MULTILINE + ``^\s*`` means we only match imports
#   at the start of a line.
# * Node frameworks — ``require('framework')`` (CJS) plus the modern
#   ``from 'framework'`` (ES modules). Both quote styles accepted.
# * Go frameworks — the vendor import path in double quotes inside a
#   Go import block. Optional ``/vN`` suffix for frameworks that use
#   Go module semver tagging (echo/v4, fiber/v2, gin/v1).
# * Rails — ``require 'rails'`` plus the ``< Rails::Application``
#   declaration every Rails ``config/application.rb`` contains.
# * Django — also matches the ``DJANGO_SETTINGS_MODULE`` environment
#   flag, the canonical Django-project smoke signal in ``manage.py``,
#   ``wsgi.py``, ``asgi.py``, ``settings.py``.
_FRAMEWORK_IMPORT_PATTERNS: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = (
    (
        "flask",
        (
            re.compile(
                r"^\s*(?:from\s+flask(?:\.\w+)*\s+import\b|import\s+flask\b)",
                re.MULTILINE | re.IGNORECASE,
            ),
        ),
    ),
    (
        "fastapi",
        (
            re.compile(
                r"^\s*(?:from\s+fastapi(?:\.\w+)*\s+import\b|import\s+fastapi\b)",
                re.MULTILINE | re.IGNORECASE,
            ),
        ),
    ),
    (
        "django",
        (
            re.compile(
                r"^\s*(?:from\s+django(?:\.\w+)*\s+import\b|import\s+django\b)",
                re.MULTILINE | re.IGNORECASE,
            ),
            re.compile(r"\bDJANGO_SETTINGS_MODULE\b"),
        ),
    ),
    (
        "express",
        (
            # CJS: require('express') / require("express").
            re.compile(r"""require\s*\(\s*['"]express['"]\s*\)""", re.IGNORECASE),
            # ESM: import ... from 'express' / "express". Prefix is
            # MANDATORY (not optional) — the previous ``(?:...)?``
            # optional group degenerated to a bare quoted-string match,
            # firing on JSON/YAML configs (``{"mode": "express"}``) and
            # prose mentions (PR #34 review catch). Multiline-anchored
            # so the import statement must start a line.
            re.compile(
                r"""^\s*import\s+[\w{}\s,*]+\s+from\s+['"]express['"]""",
                re.MULTILINE | re.IGNORECASE,
            ),
        ),
    ),
    (
        "gin",
        (
            re.compile(r'"github\.com/gin-gonic/gin(?:/v\d+)?"'),
        ),
    ),
    (
        "echo",
        (
            re.compile(r'"github\.com/labstack/echo(?:/v\d+)?"'),
        ),
    ),
    (
        "fiber",
        (
            re.compile(r'"github\.com/gofiber/fiber(?:/v\d+)?"'),
        ),
    ),
    (
        "rails",
        (
            re.compile(r"""require\s+['"]rails(?:/all)?['"]""", re.IGNORECASE),
            re.compile(r"<\s*Rails::Application\b"),
        ),
    ),
)


def detect_framework(content: str) -> str | None:
    """Detect web-framework use via import-statement matching.

    PREP-019 semantics:

    * Detects framework **USE** (the file imports/requires the
      framework), not framework **MENTIONS** (prose, variable names,
      substring matches in unrelated identifiers).
    * Returns the **first** framework in the precedence order
      ``flask > fastapi > django > express > gin > echo > fiber >
      rails`` that has at least one pattern match in the first 2 KB.
      Stable hint for S1.
    * Transitive detection (a file imports from a project-local
      module which in turn imports Flask) is **S1's job**. The
      pre-pass only flags direct imports within the scan window.
    * Scan window is the first ``_SCAN_WINDOW_CHARS`` characters
      (2 KB). Files whose imports land deeper are not detected.
      Framework entry points overwhelmingly land near the top; we
      trade recall on pathological layouts for precision.

    Returns ``None`` when no framework-import pattern matches.
    """
    if not content:
        return None
    sample = content[:_SCAN_WINDOW_CHARS]
    for name, patterns in _FRAMEWORK_IMPORT_PATTERNS:
        for pattern in patterns:
            if pattern.search(sample):
                return name
    return None
