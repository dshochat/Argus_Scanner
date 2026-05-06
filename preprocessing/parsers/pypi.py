"""PyPI dependency parsers — requirements.txt, pyproject.toml, setup.py, Pipfile, Pipfile.lock."""

from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path
from typing import Any

from shared.types.enums import Ecosystem
from shared.types.preprocessing import Dependency

_PEP508_SPLIT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]+\])?\s*(.*)$")


def _dep(name: str, spec: str, source: str) -> Dependency:
    return Dependency(
        name=name.strip().lower(),
        version_spec=spec.strip() or "*",
        ecosystem=Ecosystem.PYPI,
        source_file=source,
    )


def parse_requirements_txt(path: Path, content: str) -> list[Dependency]:
    deps: list[Dependency] = []
    source = path.name
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://", "file:")):
            continue
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        m = _PEP508_SPLIT.match(line)
        if not m:
            continue
        name, _extras, rest = m.groups()
        deps.append(_dep(name, rest or "*", source))
    return deps


def parse_pyproject_toml(path: Path, content: str) -> list[Dependency]:
    """Parse every common pyproject.toml backend — project/Poetry/PDM/Hatch/Flit/build-system."""
    try:
        data = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    source = path.name
    deps: list[Dependency] = []

    project = data.get("project", {}) or {}
    for entry in project.get("dependencies", []) or []:
        if parsed := _split_pep508(entry):
            deps.append(_dep(parsed[0], parsed[1], source))
    for group in (project.get("optional-dependencies") or {}).values():
        for entry in group or []:
            if parsed := _split_pep508(entry):
                deps.append(_dep(parsed[0], parsed[1], source))

    for entry in (data.get("build-system") or {}).get("requires", []) or []:
        if parsed := _split_pep508(entry):
            deps.append(_dep(parsed[0], parsed[1], source))

    tool = data.get("tool", {}) or {}

    poetry = tool.get("poetry", {}) or {}
    for name, spec in (poetry.get("dependencies") or {}).items():
        if name.lower() == "python":
            continue
        deps.append(_dep(name, _toml_spec_version(spec), source))
    for group in (poetry.get("group") or {}).values():
        for name, spec in (group.get("dependencies") or {}).items():
            deps.append(_dep(name, _toml_spec_version(spec), source))
    for name, spec in (poetry.get("dev-dependencies") or {}).items():
        deps.append(_dep(name, _toml_spec_version(spec), source))

    pdm = tool.get("pdm", {}) or {}
    for group in (pdm.get("dev-dependencies") or {}).values():
        for entry in group or []:
            if parsed := _split_pep508(entry):
                deps.append(_dep(parsed[0], parsed[1], source))

    hatch = tool.get("hatch", {}) or {}
    for env in (hatch.get("envs") or {}).values():
        for entry in env.get("dependencies", []) or []:
            if parsed := _split_pep508(entry):
                deps.append(_dep(parsed[0], parsed[1], source))
        for entry in env.get("extra-dependencies", []) or []:
            if parsed := _split_pep508(entry):
                deps.append(_dep(parsed[0], parsed[1], source))

    flit_meta = tool.get("flit", {}).get("metadata") or {}
    for entry in flit_meta.get("requires", []) or []:
        if parsed := _split_pep508(entry):
            deps.append(_dep(parsed[0], parsed[1], source))
    for reqs in (flit_meta.get("requires-extra") or {}).values():
        for entry in reqs or []:
            if parsed := _split_pep508(entry):
                deps.append(_dep(parsed[0], parsed[1], source))

    return _dedup(deps)


def parse_setup_py(path: Path, content: str) -> list[Dependency]:
    """Extract install_requires + friends, resolving name indirection recursively."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    source = path.name

    locals_: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                locals_[target.id] = node.value

    deps: list[Dependency] = []
    dep_keywords = {"install_requires", "setup_requires", "tests_require"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        func_name = getattr(func, "id", None) or getattr(func, "attr", None)
        if func_name != "setup":
            continue

        for kw in node.keywords:
            if kw.arg in dep_keywords:
                for item in _collect_strings(kw.value, locals_):
                    if parsed := _split_pep508(item):
                        deps.append(_dep(parsed[0], parsed[1], source))
            elif kw.arg == "extras_require":
                value = _resolve(kw.value, locals_)
                if isinstance(value, ast.Dict):
                    for v in value.values:
                        for item in _collect_strings(v, locals_):
                            if parsed := _split_pep508(item):
                                deps.append(_dep(parsed[0], parsed[1], source))
    return _dedup(deps)


def parse_pipfile(path: Path, content: str) -> list[Dependency]:
    try:
        data = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    source = path.name
    deps: list[Dependency] = []
    for section in ("packages", "dev-packages"):
        value = data.get(section)
        if isinstance(value, dict):
            for name, spec in value.items():
                deps.append(_dep(name, _toml_spec_version(spec), source))
    return deps


def parse_pipfile_lock(path: Path, content: str) -> list[Dependency]:
    """Pipfile.lock is JSON; top-level keys are 'default' and 'develop'."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    source = path.name
    deps: list[Dependency] = []
    for section in ("default", "develop"):
        value = data.get(section)
        if isinstance(value, dict):
            for name, spec in value.items():
                version = spec.get("version", "*") if isinstance(spec, dict) else str(spec)
                deps.append(_dep(name, str(version), source))
    return deps


def _toml_spec_version(spec: Any) -> str:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        return str(spec.get("version", "*"))
    return "*"


def _split_pep508(entry: str) -> tuple[str, str] | None:
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None
    entry = entry.split(";", 1)[0].strip()
    m = _PEP508_SPLIT.match(entry)
    if not m:
        return None
    name, _extras, rest = m.groups()
    return name, rest.strip() or "*"


def _resolve(node: ast.AST, locals_: dict[str, ast.AST], depth: int = 0) -> ast.AST:
    """Follow up to 5 levels of name indirection. Bounded to avoid cycles."""
    if depth >= 5 or not isinstance(node, ast.Name) or node.id not in locals_:
        return node
    return _resolve(locals_[node.id], locals_, depth + 1)


def _collect_strings(node: ast.AST, locals_: dict[str, ast.AST]) -> list[str]:
    """Recursive string collection: resolves names, concats lists and BinOp+."""
    node = _resolve(node, locals_)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        out: list[str] = []
        for elt in node.elts:
            out.extend(_collect_strings(elt, locals_))
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _collect_strings(node.left, locals_) + _collect_strings(node.right, locals_)
    return []


def _dedup(deps: list[Dependency]) -> list[Dependency]:
    seen: set[tuple[str, str]] = set()
    out: list[Dependency] = []
    for d in deps:
        key = (d.name, d.version_spec)
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out
