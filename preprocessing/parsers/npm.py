"""npm dependency parsers — package.json, package-lock.json, yarn.lock, pnpm-lock.yaml."""

from __future__ import annotations

import json
import re
from pathlib import Path

from shared.types.enums import Ecosystem
from shared.types.preprocessing import Dependency

_YARN_ENTRY = re.compile(
    r"""^"?(?P<name>(?:@[^/]+/)?[^@"\s]+)@[^:]+:\s*$""",
    re.MULTILINE,
)
_YARN_VERSION = re.compile(r'^\s*version\s+"(?P<ver>[^"]+)"', re.MULTILINE)


def _dep(name: str, spec: str, source: str) -> Dependency:
    return Dependency(
        name=name,
        version_spec=spec or "*",
        ecosystem=Ecosystem.NPM,
        source_file=source,
    )


def parse_package_json(path: Path, content: str) -> list[Dependency]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    source = path.name
    deps: list[Dependency] = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        value = data.get(key)
        if isinstance(value, dict):
            for name, spec in value.items():
                deps.append(_dep(str(name), str(spec), source))
        elif isinstance(value, list):
            for name in value:
                deps.append(_dep(str(name), "*", source))

    bundled = data.get("bundledDependencies") or data.get("bundleDependencies")
    if isinstance(bundled, list):
        for name in bundled:
            deps.append(_dep(str(name), "*", source))
    elif isinstance(bundled, dict):
        for name, spec in bundled.items():
            deps.append(_dep(name, str(spec), source))

    return deps


def parse_package_lock_json(path: Path, content: str) -> list[Dependency]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    source = path.name
    deps: list[Dependency] = []

    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, info in packages.items():
            if not isinstance(info, dict):
                continue
            if pkg_path:
                name = info.get("name") or pkg_path.split("node_modules/")[-1]
                version = info.get("version", "*")
                if name:
                    deps.append(_dep(str(name), str(version), source))
            # Root package entry ("" path) lists direct dependencies declared
            # in the source package.json. These are the direct deps, not the
            # resolved install tree — still important signal.
            for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
                nested = info.get(dep_key)
                if isinstance(nested, dict):
                    for dname, dspec in nested.items():
                        deps.append(_dep(str(dname), str(dspec), source))

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        for name, info in dependencies.items():
            version = info.get("version", "*") if isinstance(info, dict) else "*"
            deps.append(_dep(str(name), str(version), source))

    return deps


_PNPM_PKG = re.compile(
    r"""^\s+'?/?(?P<name>(?:@[^/'"\s]+/)?[^@\s/:'"]+)@(?P<ver>[^:'\s]+)'?:""",
    re.MULTILINE,
)


def parse_pnpm_lock(path: Path, content: str) -> list[Dependency]:
    """pnpm-lock.yaml: extract packages via the `/name@version:` header format.

    Works across pnpm v5–v9. We use regex instead of a full YAML parser — pnpm lock
    files are easily 50k+ lines and PyYAML's C loader is still an optional dep we
    don't want to require for preprocessing.
    """
    source = path.name
    seen: set[tuple[str, str]] = set()
    deps: list[Dependency] = []
    for m in _PNPM_PKG.finditer(content):
        key = (m.group("name"), m.group("ver"))
        if key in seen:
            continue
        seen.add(key)
        deps.append(_dep(*key, source))
    return deps


def parse_yarn_lock(path: Path, content: str) -> list[Dependency]:
    source = path.name
    deps: list[Dependency] = []
    blocks = re.split(r"\n\n", content)
    for block in blocks:
        if not block.strip() or block.lstrip().startswith("#"):
            continue
        header_match = _YARN_ENTRY.search(block)
        version_match = _YARN_VERSION.search(block)
        if not header_match or not version_match:
            continue
        deps.append(_dep(header_match.group("name"), version_match.group("ver"), source))
    return deps
