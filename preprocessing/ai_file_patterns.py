"""AI-file filename pattern matching — PREP-016.

Recognize canonical AI-tooling files by filename alone, before any model
runs. Ported byte-for-byte from ``app/saas/ai_tool_scanner.py::27-62``.

A match means: "this file's *name* strongly suggests it's an AI tool
configuration / skill / system prompt / plugin manifest / …, regardless
of content". S1 can use the hint to force ``is_ai_component=true`` on
its triage output, overrideable when content evidence clearly
contradicts the name (e.g. a file named ``plugin.json`` that's actually
a VSCode plugin, not an AI-tool plugin).

The emitted category string is one of:

* ``skill_definition``
* ``agent_config``
* ``system_prompt``
* ``plugin_manifest``
* ``mcp_config``
* ``api_schema``
* ``tool_definition``

or ``None`` when no pattern matches.

Category selection is deterministic: exact filename matches checked
first, then regex globs. Both are defined below as ordered collections
so the first matching category wins.
"""

from __future__ import annotations

import re
from pathlib import Path

# ── Exact filename → category ────────────────────────────────────────────
# Ported verbatim from app/saas/ai_tool_scanner.py::AI_FILE_PATTERNS.
_AI_FILE_EXACT: dict[str, str] = {
    "SKILL.md": "skill_definition",
    "AGENTS.md": "agent_config",
    "CLAUDE.md": "system_prompt",
    ".cursorrules": "system_prompt",
    ".cursorrc": "system_prompt",
    "system_prompt.txt": "system_prompt",
    "system_prompt.md": "system_prompt",
    "plugin.json": "plugin_manifest",
    "mcp.json": "mcp_config",
    "ai-plugin.json": "plugin_manifest",
    "openapi.yaml": "api_schema",
    "openapi.json": "api_schema",
    ".github/copilot-instructions.md": "system_prompt",
}

# ── Regex globs by category ─────────────────────────────────────────────
# Ported verbatim from app/saas/ai_tool_scanner.py::AI_FILE_GLOBS.
_AI_FILE_GLOBS: dict[str, tuple[re.Pattern[str], ...]] = {
    "agent_config": (
        re.compile(r"agent[_-]?config\.(ya?ml|json|toml)$", re.IGNORECASE),
        re.compile(r"\.claude/agents/.*\.md$", re.IGNORECASE),
        re.compile(r"agents/.*\.(ya?ml|json|md)$", re.IGNORECASE),
    ),
    "system_prompt": (
        re.compile(r"system[_-]?prompt\.(txt|md|ya?ml)$", re.IGNORECASE),
        re.compile(r"prompt[_-]?template\.(txt|md|ya?ml|j2)$", re.IGNORECASE),
        # Cline AI assistant rules — same role as .cursorrules. Matches
        # both bare ``.clinerules`` and prefixed variants like
        # ``trivy-vscode-ext.clinerules`` that ship inside extensions.
        re.compile(r"(?:^|/|\.)clinerules$", re.IGNORECASE),
    ),
    "mcp_config": (re.compile(r"mcp[_-]?.*\.(json|ya?ml)$", re.IGNORECASE),),
    "tool_definition": (
        re.compile(r"tools?\.(json|ya?ml)$", re.IGNORECASE),
        re.compile(r"function[_-]?call.*\.(json|ya?ml)$", re.IGNORECASE),
    ),
}


def detect_ai_file(path: str | Path) -> str | None:
    """Classify a file path against AI-tooling filename patterns.

    Checks exact filenames first (e.g. ``SKILL.md``), then regex globs
    (e.g. ``agent-config.yaml`` matches the ``agent_config`` category).
    Returns ``None`` when no pattern matches.

    Matching operates on the full path string (including parent
    directories) so patterns like ``.claude/agents/*.md`` work
    correctly. Exact matches require the full path to equal one of the
    registered keys *or* the basename to equal it — ports the
    two-mode matching behaviour from ``ai_tool_scanner.py``.
    """
    p = Path(path)
    # Normalize path separators to forward slashes so globs that match
    # directory structure (``.github/copilot-instructions.md``,
    # ``.claude/agents/foo.md``) work on Windows too.
    full = str(p).replace("\\", "/")
    name = p.name

    # 1) Exact-name match — check both full path and basename
    for pattern, category in _AI_FILE_EXACT.items():
        if full == pattern or full.endswith("/" + pattern) or name == pattern:
            return category

    # 2) Regex-glob match
    for category, patterns in _AI_FILE_GLOBS.items():
        for regex in patterns:
            if regex.search(full):
                return category

    return None
