"""Go module parsers — go.mod, go.sum."""

from __future__ import annotations

import re
from pathlib import Path

from shared.types.enums import Ecosystem
from shared.types.preprocessing import Dependency

_REQUIRE_LINE = re.compile(r"^\s*(?P<name>[\w./\-]+)\s+(?P<ver>v[^\s]+)")
_REQUIRE_BLOCK = re.compile(r"require\s*\((?P<body>.*?)\)", re.DOTALL)
_REQUIRE_SINGLE = re.compile(r"require\s+(?P<name>[\w./\-]+)\s+(?P<ver>v[^\s]+)")
_SUM_LINE = re.compile(r"^(?P<name>[\w./\-]+)\s+(?P<ver>v[^\s]+)")


def _dep(name: str, version: str, source: str) -> Dependency:
    return Dependency(
        name=name,
        version_spec=version,
        ecosystem=Ecosystem.GO,
        source_file=source,
    )


def parse_go_mod(path: Path, content: str) -> list[Dependency]:
    source = path.name
    deps: list[Dependency] = []

    for block in _REQUIRE_BLOCK.finditer(content):
        for line in block.group("body").splitlines():
            stripped = line.split("//", 1)[0].strip()
            if not stripped:
                continue
            if m := _REQUIRE_LINE.match(stripped):
                deps.append(_dep(m.group("name"), m.group("ver"), source))

    for m in _REQUIRE_SINGLE.finditer(content):
        deps.append(_dep(m.group("name"), m.group("ver"), source))

    return deps


def parse_go_sum(path: Path, content: str) -> list[Dependency]:
    source = path.name
    seen: set[tuple[str, str]] = set()
    deps: list[Dependency] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        if m := _SUM_LINE.match(line):
            version = m.group("ver").removesuffix("/go.mod")
            key = (m.group("name"), version)
            if key in seen:
                continue
            seen.add(key)
            deps.append(_dep(*key, source))
    return deps
