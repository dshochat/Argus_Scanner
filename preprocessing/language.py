"""Language detection — extension + shebang + content heuristics.

Cheap deterministic signal consumed by S1. S1 may re-confirm and override.
No models, no network. Returns a lowercase language identifier
(`python`, `javascript`, `go`, ...) or `unknown`.
"""

from __future__ import annotations

import re
from pathlib import Path

_EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".pyi": "python",
    ".pth": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".scala": "scala",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".lua": "lua",
    ".pl": "perl",
    ".r": "r",
    ".swift": "swift",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".hcl": "hcl",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".xml": "xml",
    ".html": "html",
    ".css": "css",
    ".md": "markdown",
    ".dockerfile": "dockerfile",
}

_MANIFEST_MAP: dict[str, str] = {
    "dockerfile": "dockerfile",
    "makefile": "makefile",
    "rakefile": "ruby",
    "gemfile": "ruby",
    "pipfile": "toml",
    "go.mod": "go",
    "go.sum": "go",
    "cargo.toml": "toml",
    "cargo.lock": "toml",
    "pom.xml": "xml",
    "package.json": "json",
    "package-lock.json": "json",
    "yarn.lock": "yaml",
}

_SHEBANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^#!.*\bpython[0-9.]*\b"), "python"),
    (re.compile(r"^#!.*\bnode\b"), "javascript"),
    (re.compile(r"^#!.*\b(bash|sh|zsh|ksh|dash)\b"), "shell"),
    (re.compile(r"^#!.*\bruby\b"), "ruby"),
    (re.compile(r"^#!.*\bperl\b"), "perl"),
    (re.compile(r"^#!.*\bpwsh\b"), "powershell"),
]


def detect_language(path: str | Path, content: str | bytes | None = None) -> str:
    """Return a language identifier (`python`, `javascript`, ...) or `unknown`.

    Priority: exact-filename manifests → extension → shebang line.
    """
    p = Path(path)
    name = p.name.lower()

    if name in _MANIFEST_MAP:
        return _MANIFEST_MAP[name]

    ext = p.suffix.lower()
    if ext in _EXTENSION_MAP:
        return _EXTENSION_MAP[ext]

    if content is not None:
        text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
        first_line = text.splitlines()[0] if text else ""
        for pattern, lang in _SHEBANG_PATTERNS:
            if pattern.match(first_line):
                return lang

    return "unknown"
