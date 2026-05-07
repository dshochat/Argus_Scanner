"""Ruby parsers — Gemfile, Gemfile.lock."""

from __future__ import annotations

import re
from pathlib import Path

from shared.types.enums import Ecosystem
from shared.types.preprocessing import Dependency

_GEM_LINE = re.compile(
    r"""^\s*gem\s+['"](?P<name>[^'"]+)['"](?:\s*,\s*['"](?P<version>[^'"]+)['"])?""",
    re.MULTILINE,
)
_LOCK_SPEC = re.compile(r"^\s{4}(?P<name>[\w\-]+)\s+\((?P<version>[^)]+)\)", re.MULTILINE)


def _dep(name: str, version: str, source: str) -> Dependency:
    return Dependency(
        name=name,
        version_spec=version or "*",
        ecosystem=Ecosystem.RUBYGEMS,
        source_file=source,
    )


def parse_gemfile(path: Path, content: str) -> list[Dependency]:
    source = path.name
    return [_dep(m.group("name"), m.group("version") or "*", source) for m in _GEM_LINE.finditer(content)]


def parse_gemfile_lock(path: Path, content: str) -> list[Dependency]:
    source = path.name
    seen: set[tuple[str, str]] = set()
    deps: list[Dependency] = []
    for m in _LOCK_SPEC.finditer(content):
        key = (m.group("name"), m.group("version"))
        if key in seen:
            continue
        seen.add(key)
        deps.append(_dep(*key, source))
    return deps
