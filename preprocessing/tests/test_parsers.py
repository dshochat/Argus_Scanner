from __future__ import annotations

from pathlib import Path

from preprocessing.parsers import is_manifest, parse_manifest
from shared.types.enums import Ecosystem


def test_requirements_txt_parses_pep508() -> None:
    content = "\n".join(
        [
            "# comment",
            "requests==2.31.0",
            "django>=4.2,<5.0",
            "flask   # inline comment",
            "-e git+https://github.com/x/y.git#egg=y",
            "",
            "numpy ; python_version >= '3.11'",
        ]
    )
    deps = parse_manifest(Path("requirements.txt"), content)
    by_name = {d.name: d for d in deps}
    assert {"requests", "django", "flask", "numpy"} <= by_name.keys()
    assert by_name["requests"].version_spec == "==2.31.0"
    assert by_name["flask"].version_spec == "*"
    assert all(d.ecosystem is Ecosystem.PYPI for d in deps)


def test_pyproject_toml_project_deps() -> None:
    content = """
[project]
name = "x"
dependencies = ["httpx>=0.27", "pydantic>=2"]
optional-dependencies.dev = ["pytest>=8"]
"""
    deps = parse_manifest(Path("pyproject.toml"), content)
    names = {d.name for d in deps}
    assert {"httpx", "pydantic", "pytest"} <= names


def test_package_json_collects_all_dep_kinds() -> None:
    content = """
{
  "name": "x",
  "dependencies": {"react": "^18.0.0"},
  "devDependencies": {"typescript": "5.x"},
  "peerDependencies": {"vite": "*"}
}
"""
    deps = parse_manifest(Path("package.json"), content)
    names = {d.name for d in deps}
    assert names == {"react", "typescript", "vite"}
    assert all(d.ecosystem is Ecosystem.NPM for d in deps)


def test_go_mod_require_block() -> None:
    content = """\
module example.com/app

go 1.22

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/net v0.20.0 // indirect
)

require github.com/stretchr/testify v1.8.4
"""
    deps = parse_manifest(Path("go.mod"), content)
    names = {d.name for d in deps}
    assert "github.com/gin-gonic/gin" in names
    assert "github.com/stretchr/testify" in names
    assert all(d.ecosystem is Ecosystem.GO for d in deps)


def test_cargo_toml() -> None:
    content = """
[package]
name = "x"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1", features = ["full"] }
"""
    deps = parse_manifest(Path("Cargo.toml"), content)
    by_name = {d.name: d for d in deps}
    assert by_name["serde"].version_spec == "1.0"
    assert by_name["tokio"].version_spec == "1"


def test_is_manifest_dispatch() -> None:
    assert is_manifest(Path("requirements.txt"))
    assert is_manifest(Path("myapp.csproj"))
    assert is_manifest(Path("Pipfile.lock"))
    assert is_manifest(Path("pnpm-lock.yaml"))
    assert not is_manifest(Path("main.py"))


def test_pyproject_pdm_hatch_flit_buildsystem() -> None:
    content = """
[build-system]
requires = ["setuptools>=68", "wheel"]

[tool.pdm.dev-dependencies]
test = ["pytest>=8"]

[tool.hatch.envs.default]
dependencies = ["rich>=13"]

[tool.flit.metadata]
requires = ["typer>=0.9"]
"""
    deps = parse_manifest(Path("pyproject.toml"), content)
    names = {d.name for d in deps}
    assert {"setuptools", "wheel", "pytest", "rich", "typer"} <= names


def test_setup_py_multi_level_indirection() -> None:
    content = """
from setuptools import setup
BASE = ["httpx>=0.27"]
EXTRA = ["rich"]
REQS = BASE + EXTRA
setup(name="x", install_requires=REQS, extras_require={"test": ["pytest"]})
"""
    deps = parse_manifest(Path("setup.py"), content)
    names = {d.name for d in deps}
    assert {"httpx", "rich", "pytest"} <= names


def test_package_json_bundled_list_and_object() -> None:
    content_list = '{"name":"x","bundledDependencies":["react","left-pad"]}'
    content_obj = '{"name":"x","bundleDependencies":{"react":"^18","left-pad":"*"}}'
    names_list = {d.name for d in parse_manifest(Path("package.json"), content_list)}
    names_obj = {d.name for d in parse_manifest(Path("package.json"), content_obj)}
    assert {"react", "left-pad"} <= names_list
    assert {"react", "left-pad"} <= names_obj


def test_pipfile_lock_default_and_develop() -> None:
    content = """
{
  "default": {"requests": {"version": "==2.31.0"}},
  "develop": {"pytest": {"version": "==8.0.0"}}
}
"""
    deps = parse_manifest(Path("Pipfile.lock"), content)
    by_name = {d.name: d.version_spec for d in deps}
    assert by_name["requests"] == "==2.31.0"
    assert by_name["pytest"] == "==8.0.0"


def test_pnpm_lock_v6_format() -> None:
    content = """\
lockfileVersion: '6.0'

packages:

  /react@18.2.0:
    resolution: {integrity: sha512-...}
    dev: false

  /@types/node@20.10.0:
    resolution: {integrity: sha512-...}
    dev: true
"""
    deps = parse_manifest(Path("pnpm-lock.yaml"), content)
    by_name = {d.name: d.version_spec for d in deps}
    assert by_name["react"] == "18.2.0"
    assert by_name["@types/node"] == "20.10.0"


def test_pnpm_lock_v9_format() -> None:
    content = """\
lockfileVersion: '9.0'

packages:

  '@babel/helper-string-parser@7.27.1':
    resolution: {integrity: sha512-...}

  'axios@1.8.0':
    resolution: {integrity: sha512-...}
"""
    deps = parse_manifest(Path("pnpm-lock.yaml"), content)
    by_name = {d.name: d.version_spec for d in deps}
    assert by_name["@babel/helper-string-parser"] == "7.27.1"
    assert by_name["axios"] == "1.8.0"
