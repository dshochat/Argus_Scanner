"""PREP-018 tests: attack-vector extension flag."""

from __future__ import annotations

from pathlib import Path

from preprocessing import detect_attack_vector_extension


def test_detect_pth() -> None:
    assert detect_attack_vector_extension(Path("mypkg.pth")) == "pth"


def test_detect_egg() -> None:
    assert detect_attack_vector_extension(Path("legacy.egg")) == "egg"


def test_detect_whl() -> None:
    assert detect_attack_vector_extension(Path("wheel-1.0.0.whl")) == "whl"


def test_detect_spec() -> None:
    assert detect_attack_vector_extension(Path("build.spec")) == "spec"


def test_accepts_str_path() -> None:
    assert detect_attack_vector_extension("mypkg.pth") == "pth"


def test_case_insensitive_pth() -> None:
    # Windows-style uppercase still matches.
    assert detect_attack_vector_extension(Path("MYPKG.PTH")) == "pth"


def test_case_insensitive_whl() -> None:
    assert detect_attack_vector_extension(Path("pkg.Whl")) == "whl"


def test_plain_python_not_detected() -> None:
    assert detect_attack_vector_extension(Path("main.py")) is None


def test_config_files_not_detected() -> None:
    assert detect_attack_vector_extension(Path("config.yaml")) is None
    assert detect_attack_vector_extension(Path("README.md")) is None
    assert detect_attack_vector_extension(Path("requirements.txt")) is None


def test_no_extension_returns_none() -> None:
    assert detect_attack_vector_extension(Path("Dockerfile")) is None


def test_nested_path_matches_on_basename_suffix() -> None:
    # Match is on the last suffix, not on the full path string.
    assert detect_attack_vector_extension(Path("deep/nested/path/mypkg.whl")) == "whl"


def test_path_with_pth_in_name_not_extension_not_detected() -> None:
    # Only the EXTENSION counts. A file called "python.py" doesn't trip
    # "pth" substring matching because we only check the suffix.
    assert detect_attack_vector_extension(Path("python.py")) is None


def test_extension_set_matches_ticket() -> None:
    # Regression pin: PREP-018 ticket lists 4 extensions.
    from preprocessing.attack_vector_extensions import _ATTACK_VECTOR_EXTENSIONS  # noqa: PLC0415

    assert frozenset({".pth", ".egg", ".whl", ".spec"}) == _ATTACK_VECTOR_EXTENSIONS
