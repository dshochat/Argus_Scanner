"""Maven/Gradle parsers — pom.xml, build.gradle."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from shared.types.enums import Ecosystem
from shared.types.preprocessing import Dependency

_GRADLE_DEP = re.compile(
    r"""(?:implementation|api|compile|runtimeOnly|testImplementation|compileOnly)\s+"""
    r"""['"](?P<coord>[^'"\s]+)['"]""",
    re.MULTILINE,
)


def _dep(name: str, version: str, source: str) -> Dependency:
    return Dependency(
        name=name,
        version_spec=version or "*",
        ecosystem=Ecosystem.MAVEN,
        source_file=source,
    )


def parse_pom_xml(path: Path, content: str) -> list[Dependency]:
    source = path.name
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []

    tag = root.tag
    ns = ""
    if tag.startswith("{"):
        ns = tag[: tag.index("}") + 1]

    deps: list[Dependency] = []
    for dep in root.iter(f"{ns}dependency"):
        group = dep.findtext(f"{ns}groupId", default="").strip()
        artifact = dep.findtext(f"{ns}artifactId", default="").strip()
        version = dep.findtext(f"{ns}version", default="").strip()
        if not (group and artifact):
            continue
        deps.append(_dep(f"{group}:{artifact}", version, source))
    return deps


def parse_build_gradle(path: Path, content: str) -> list[Dependency]:
    source = path.name
    deps: list[Dependency] = []
    for m in _GRADLE_DEP.finditer(content):
        coord = m.group("coord")
        parts = coord.split(":")
        if len(parts) < 2:
            continue
        name = f"{parts[0]}:{parts[1]}"
        version = parts[2] if len(parts) > 2 else "*"
        deps.append(_dep(name, version, source))
    return deps
