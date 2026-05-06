"""Ecosystem parser registry.

Each parser consumes `(path, content)` and returns `list[Dependency]`.
Dispatch is by exact filename first, then file suffix (for `*.csproj`).
"""

from __future__ import annotations

from pathlib import Path

from shared.types.preprocessing import Dependency

from ._base import ParserRegistry
from .crates import parse_cargo_lock, parse_cargo_toml
from .go import parse_go_mod, parse_go_sum
from .maven import parse_build_gradle, parse_pom_xml
from .npm import parse_package_json, parse_package_lock_json, parse_pnpm_lock, parse_yarn_lock
from .nuget import parse_csproj, parse_packages_config
from .pypi import (
    parse_pipfile,
    parse_pipfile_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
    parse_setup_py,
)
from .rubygems import parse_gemfile, parse_gemfile_lock

registry = ParserRegistry()
registry.register_name("requirements.txt")(parse_requirements_txt)
registry.register_name("pyproject.toml")(parse_pyproject_toml)
registry.register_name("setup.py")(parse_setup_py)
registry.register_name("pipfile")(parse_pipfile)
registry.register_name("pipfile.lock")(parse_pipfile_lock)
registry.register_name("package.json")(parse_package_json)
registry.register_name("package-lock.json")(parse_package_lock_json)
registry.register_name("yarn.lock")(parse_yarn_lock)
registry.register_name("pnpm-lock.yaml")(parse_pnpm_lock)
registry.register_name("go.mod")(parse_go_mod)
registry.register_name("go.sum")(parse_go_sum)
registry.register_name("pom.xml")(parse_pom_xml)
registry.register_name("build.gradle", "build.gradle.kts")(parse_build_gradle)
registry.register_name("gemfile")(parse_gemfile)
registry.register_name("gemfile.lock")(parse_gemfile_lock)
registry.register_name("cargo.toml")(parse_cargo_toml)
registry.register_name("cargo.lock")(parse_cargo_lock)
registry.register_name("packages.config")(parse_packages_config)
registry.register_suffix(".csproj")(parse_csproj)


def parse_manifest(path: str | Path, content: str) -> list[Dependency]:
    """Dispatch to the right parser by filename. Returns [] if no match."""
    p = Path(path)
    parser = registry.find(p)
    if parser is None:
        return []
    return parser(p, content)


def is_manifest(path: str | Path) -> bool:
    return registry.find(Path(path)) is not None


__all__ = [
    "Dependency",
    "is_manifest",
    "parse_build_gradle",
    "parse_cargo_lock",
    "parse_cargo_toml",
    "parse_csproj",
    "parse_gemfile",
    "parse_gemfile_lock",
    "parse_go_mod",
    "parse_go_sum",
    "parse_manifest",
    "parse_package_json",
    "parse_package_lock_json",
    "parse_packages_config",
    "parse_pipfile",
    "parse_pipfile_lock",
    "parse_pnpm_lock",
    "parse_pom_xml",
    "parse_pyproject_toml",
    "parse_requirements_txt",
    "parse_setup_py",
    "parse_yarn_lock",
    "registry",
]
