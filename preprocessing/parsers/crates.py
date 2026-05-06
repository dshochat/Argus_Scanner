"""Cargo parsers — Cargo.toml, Cargo.lock."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from shared.types.enums import Ecosystem
from shared.types.preprocessing import Dependency


def _dep(name: str, version: str, source: str) -> Dependency:
    return Dependency(
        name=name,
        version_spec=version or "*",
        ecosystem=Ecosystem.CRATES,
        source_file=source,
    )


def _spec_version(spec: Any) -> str:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        return str(spec.get("version", "*"))
    return "*"


def parse_cargo_toml(path: Path, content: str) -> list[Dependency]:
    try:
        data = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    source = path.name
    deps: list[Dependency] = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = data.get(section)
        if isinstance(value, dict):
            for name, spec in value.items():
                deps.append(_dep(name, _spec_version(spec), source))
    return deps


def parse_cargo_lock(path: Path, content: str) -> list[Dependency]:
    try:
        data = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    source = path.name
    deps: list[Dependency] = []
    packages = data.get("package") or []
    if not isinstance(packages, list):
        return []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version", "*")
        if name:
            deps.append(_dep(str(name), str(version), source))
    return deps
