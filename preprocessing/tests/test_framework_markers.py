"""PREP-017 + PREP-019 tests: framework marker heuristic (import-anchored).

PREP-019 history: PREP-017 shipped with bare-substring matching, which
false-positived on English words containing short marker substrings
(``login``/``begin``/``engine``/``logging``/``engineering`` all contain
``gin``). PREP-019 switches to language-aware import-statement regex
so "does this file use framework X" is answered directly.

Tests below split into positive cases (the file actually imports the
framework), negative cases (prose/variable names that used to false-
positive), and the structural pins (scan window, precedence, marker
list).
"""

from __future__ import annotations

from preprocessing import detect_framework


# ── Positive: each framework is detected on its canonical import form ──


def test_detect_flask_from_import() -> None:
    content = "from flask import Flask\napp = Flask(__name__)\n"
    assert detect_framework(content) == "flask"


def test_detect_flask_bare_import() -> None:
    content = "import flask\napp = flask.Flask(__name__)\n"
    assert detect_framework(content) == "flask"


def test_detect_flask_submodule_import() -> None:
    content = "from flask.ext.sqlalchemy import SQLAlchemy\n"
    assert detect_framework(content) == "flask"


def test_detect_fastapi_from_import() -> None:
    content = "from fastapi import FastAPI\napp = FastAPI()\n"
    assert detect_framework(content) == "fastapi"


def test_detect_fastapi_submodule_import() -> None:
    content = "from fastapi.responses import JSONResponse\n"
    assert detect_framework(content) == "fastapi"


def test_detect_django_from_import() -> None:
    content = "from django.db import models\n"
    assert detect_framework(content) == "django"


def test_detect_django_settings_module_env_flag() -> None:
    # Canonical Django smoke signal in manage.py / wsgi.py / asgi.py.
    content = "DJANGO_SETTINGS_MODULE = 'myproject.settings'\n"
    assert detect_framework(content) == "django"


def test_detect_express_cjs_require() -> None:
    content = "const express = require('express');\nconst app = express();\n"
    assert detect_framework(content) == "express"


def test_detect_express_es_module_import() -> None:
    content = "import express from 'express';\nconst app = express();\n"
    assert detect_framework(content) == "express"


def test_detect_express_double_quotes() -> None:
    content = 'const express = require("express");\n'
    assert detect_framework(content) == "express"


def test_detect_gin_go_import() -> None:
    content = 'import (\n    "fmt"\n    "github.com/gin-gonic/gin"\n)\n'
    assert detect_framework(content) == "gin"


def test_detect_gin_go_import_with_version() -> None:
    content = 'import (\n    "github.com/gin-gonic/gin/v2"\n)\n'
    assert detect_framework(content) == "gin"


def test_detect_echo_go_import() -> None:
    content = 'import (\n    "github.com/labstack/echo/v4"\n)\n'
    assert detect_framework(content) == "echo"


def test_detect_fiber_go_import() -> None:
    content = 'import (\n    "github.com/gofiber/fiber/v2"\n)\n'
    assert detect_framework(content) == "fiber"


def test_detect_rails_require() -> None:
    content = "require 'rails/all'\n"
    assert detect_framework(content) == "rails"


def test_detect_rails_application_class() -> None:
    # Canonical config/application.rb shape.
    content = "module MyApp\n  class Application < Rails::Application\n  end\nend\n"
    assert detect_framework(content) == "rails"


# ── Case insensitivity preserved for language-case-insensitive matches ──


def test_case_insensitive_python_import() -> None:
    # Import statements are case-sensitive in Python, but some YAML/JSON
    # configs mention the framework with different casing. The Python
    # import pattern is case-insensitive for robustness.
    assert detect_framework("FROM FLASK IMPORT *") == "flask"


# ── NEGATIVE: PREP-019 regression pins against PREP-017's false positives ──


def test_no_match_login_in_comment() -> None:
    # "login" contains "gin" — was false-positive under PREP-017.
    assert detect_framework("# handle login flow\ndef login(user): pass\n") is None


def test_no_match_begin_in_docstring() -> None:
    assert (
        detect_framework('"""Begin with a short description of the module."""\n')
        is None
    )


def test_no_match_engine_in_text() -> None:
    assert detect_framework("# The engine processes records in batches\n") is None


def test_no_match_engineering_in_prose() -> None:
    assert detect_framework("# For engineering reports, see docs/\n") is None


def test_no_match_logging_import() -> None:
    # The stdlib 'logging' module imports must NOT trigger 'gin' false-positive.
    assert detect_framework("import logging\nlog = logging.getLogger(__name__)\n") is None


def test_no_match_framework_prose_mention() -> None:
    # A README that talks about Flask without importing it must not match.
    content = (
        "# Migration notes\n\n"
        "We migrated from Flask to FastAPI in 2024 to support async\n"
        "handlers. The migration took two sprints. See docs/migration.md.\n"
    )
    assert detect_framework(content) is None


def test_no_match_django_in_string_literal() -> None:
    # A mention inside a string literal without import/settings context
    # (e.g. a user-facing error message) must not match.
    content = 'raise ValueError("Unsupported django version")\n'
    assert detect_framework(content) is None


def test_no_match_express_prose() -> None:
    # "express" as an English word must not trigger the Express framework.
    content = "# This function expresses the transformation as a fold.\n"
    assert detect_framework(content) is None


def test_no_match_express_in_string_literal() -> None:
    # PR #34 review regression pin: the ESM pattern's prefix must be
    # MANDATORY, not optional. With an optional prefix the pattern
    # degenerated to a bare quoted-string match and fired on any
    # JSON/YAML config mentioning ``"express"`` — e.g. shipping modes,
    # rate-limit tiers, express-lane flags. None of these are the
    # framework.
    cases = [
        'config = {"shipping": "express"}\n',
        'RATE_TIER = "express"\n',
        "# We use \"express\" as the shipping mode label.\n",
        'data = {"mode": "express", "cost": 5}\n',
    ]
    for content in cases:
        assert detect_framework(content) is None, f"false positive on: {content!r}"


def test_no_match_echo_unix_command() -> None:
    # A shell-script docstring mentioning the Unix `echo` command must
    # not match the Echo Go framework.
    content = "# Equivalent to: echo 'done' | tee audit.log\n"
    assert detect_framework(content) is None


def test_no_match_gin_in_comment_or_variable() -> None:
    # Variable names and comments containing "gin" must not false-positive.
    content = "margin = 10\nbegin_at = compute_offset()\n# beginning of the dataset\n"
    assert detect_framework(content) is None


def test_no_match_rails_in_english() -> None:
    # "rails" as a mention in prose, not a Rails application file.
    content = "# This module is not on the happy-path rails; it handles errors.\n"
    assert detect_framework(content) is None


# ── Plain-file and empty-input baselines ──


def test_plain_python_no_framework() -> None:
    content = "def add(x, y):\n    return x + y\n"
    assert detect_framework(content) is None


def test_empty_content_none() -> None:
    assert detect_framework("") is None


# ── Scan-window semantics ──


def test_scan_window_limited_to_2048() -> None:
    # A flask import past the 2048-char window should NOT be detected.
    padding = "# " + ("padding " * 300)  # >2 KB of comments
    assert len(padding) > 2048
    content = padding + "\nfrom flask import Flask\n"
    assert detect_framework(content) is None


def test_import_within_2048_detected() -> None:
    # An import right at the edge but inside the window should match.
    padding = "# " + ("x " * 800)  # ~1600 chars
    assert len(padding) < 2048
    content = padding + "\nfrom flask import Flask\n"
    assert detect_framework(content) == "flask"


# ── Precedence ──


def test_precedence_flask_over_fastapi() -> None:
    content = "from flask import Flask\nfrom fastapi import FastAPI\n"
    assert detect_framework(content) == "flask"


def test_precedence_fastapi_over_django() -> None:
    content = "from fastapi import FastAPI\nimport django\n"
    assert detect_framework(content) == "fastapi"


def test_precedence_django_over_express() -> None:
    # Python + Node in same file (rare, but well-defined): Python wins.
    content = "from django.db import models\n// const express = require('express')\n"
    assert detect_framework(content) == "django"


# ── Regression pin: tuple contents haven't drifted ──


def test_framework_tuple_matches_ticket() -> None:
    # PREP-017 ticket listed 8 frameworks; PREP-019 keeps the same set
    # and precedence. If someone adds/removes a framework, this test
    # fails deliberately — bump the PREP ticket alongside the change.
    from preprocessing.framework_markers import _FRAMEWORK_IMPORT_PATTERNS  # noqa: PLC0415

    names = tuple(name for name, _ in _FRAMEWORK_IMPORT_PATTERNS)
    assert names == (
        "flask",
        "fastapi",
        "django",
        "express",
        "gin",
        "echo",
        "fiber",
        "rails",
    )


def test_scan_window_constant() -> None:
    # 2 KB scan window value pinned so it doesn't silently drift.
    from preprocessing.framework_markers import _SCAN_WINDOW_CHARS  # noqa: PLC0415

    assert _SCAN_WINDOW_CHARS == 2048
