"""NuGet parsers — *.csproj, packages.config."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from shared.types.enums import Ecosystem
from shared.types.preprocessing import Dependency


def _dep(name: str, version: str, source: str) -> Dependency:
    return Dependency(
        name=name,
        version_spec=version or "*",
        ecosystem=Ecosystem.NUGET,
        source_file=source,
    )


def parse_csproj(path: Path, content: str) -> list[Dependency]:
    source = path.name
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []
    deps: list[Dependency] = []
    for item in root.iter("PackageReference"):
        name = item.attrib.get("Include")
        version = item.attrib.get("Version") or (item.findtext("Version") or "*")
        if name:
            deps.append(_dep(name, str(version).strip(), source))
    return deps


def parse_packages_config(path: Path, content: str) -> list[Dependency]:
    source = path.name
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []
    deps: list[Dependency] = []
    for item in root.iter("package"):
        name = item.attrib.get("id")
        version = item.attrib.get("version", "*")
        if name:
            deps.append(_dep(name, version, source))
    return deps
