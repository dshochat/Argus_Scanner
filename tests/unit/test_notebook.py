"""Unit tests for the Jupyter notebook decomposer."""

from __future__ import annotations

import json
from pathlib import Path

from preprocessing.language import detect_language
from preprocessing.notebook import decompose_notebook


def _make_nb(cells: list[dict]) -> str:
    """Tiny .ipynb fabricator. Avoids string-concat fragility in tests."""
    return json.dumps(
        {
            "cells": cells,
            "metadata": {"kernelspec": {"name": "python3"}},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
    )


def test_extension_routes_to_jupyter() -> None:
    # Basic plumbing: .ipynb must be language-tagged, otherwise the
    # pipeline never calls decompose_notebook in the first place.
    assert detect_language(Path("foo.ipynb")) == "jupyter"


def test_decompose_basic_code_and_markdown() -> None:
    raw = _make_nb(
        [
            {"cell_type": "markdown", "source": ["# Title\n", "Some text\n"]},
            {"cell_type": "code", "source": ["import os\n", "print(os.getcwd())\n"]},
        ]
    )
    out = decompose_notebook(raw)
    assert out.is_valid
    assert out.parse_error is None
    assert out.n_markdown_cells == 1
    assert out.n_code_cells == 1
    # Code cell content survives verbatim
    assert "import os" in out.synthesized_source
    assert "print(os.getcwd())" in out.synthesized_source
    # Markdown is comment-prefixed (so the synth file is parseable Python)
    assert "# # Title" in out.synthesized_source
    # Banners present
    assert "NOTEBOOK CELL 1 (markdown)" in out.synthesized_source
    assert "NOTEBOOK CELL 2 (code)" in out.synthesized_source


def test_decompose_detects_pip_install_shell_magic() -> None:
    raw = _make_nb(
        [
            {"cell_type": "code", "source": "!pip install evil-pkg\n"},
        ]
    )
    out = decompose_notebook(raw)
    assert out.is_valid
    assert out.has_pip_install_magic
    assert "!pip install evil-pkg" in out.shell_magic_lines


def test_decompose_detects_load_ext_magic() -> None:
    raw = _make_nb(
        [
            {"cell_type": "code", "source": "%load_ext mal_ext\n"},
        ]
    )
    out = decompose_notebook(raw)
    assert out.is_valid
    assert out.has_load_ext_magic
    assert "%load_ext mal_ext" in out.ipython_magic_lines


def test_decompose_handles_pip_install_via_percent_magic() -> None:
    # %pip install is the IPython-magic equivalent — should also flag.
    raw = _make_nb(
        [
            {"cell_type": "code", "source": "%pip install evil-pkg\n"},
        ]
    )
    out = decompose_notebook(raw)
    assert out.is_valid
    assert out.has_pip_install_magic


def test_decompose_handles_string_source() -> None:
    # nbformat permits source as a plain string OR a list of strings.
    raw = _make_nb(
        [
            {"cell_type": "code", "source": "x = 1\n"},
        ]
    )
    out = decompose_notebook(raw)
    assert out.is_valid
    assert "x = 1" in out.synthesized_source


def test_decompose_invalid_json_returns_parse_error() -> None:
    out = decompose_notebook("not json at all {")
    assert not out.is_valid
    assert out.parse_error is not None
    assert out.synthesized_source == ""


def test_decompose_missing_cells_field() -> None:
    out = decompose_notebook(json.dumps({"metadata": {}, "nbformat": 4}))
    assert not out.is_valid
    assert out.parse_error == "missing or non-list `cells`"


def test_decompose_skips_non_dict_cells() -> None:
    # Pathological notebook: a non-dict in the cells array. Should be
    # skipped silently rather than crashing the parser — defensive
    # handling for fuzz-like inputs.
    raw = json.dumps(
        {
            "cells": [
                "not_a_dict",
                {"cell_type": "code", "source": "ok = True\n"},
            ],
            "metadata": {},
            "nbformat": 4,
        }
    )
    out = decompose_notebook(raw)
    assert out.is_valid
    assert out.n_code_cells == 1
    assert "ok = True" in out.synthesized_source


def test_decompose_unknown_cell_type_skipped() -> None:
    # Custom Jupyter-extension cell types should be skipped without
    # erroring or counting as code/markdown/raw.
    raw = _make_nb(
        [
            {"cell_type": "custom_extension", "source": "<rendered>"},
            {"cell_type": "code", "source": "y = 2\n"},
        ]
    )
    out = decompose_notebook(raw)
    assert out.is_valid
    assert out.n_code_cells == 1
    assert out.n_markdown_cells == 0
    assert out.n_raw_cells == 0


def test_decompose_real_malicious_fixture() -> None:
    # End-to-end: parse the fixture we ship in samples/regression_v1
    # and verify it's flagged on both magic axes.
    fixture = Path("samples/regression_v1/notebook_pip_malicious.ipynb")
    if not fixture.exists():
        # Test repo not running from the project root — skip rather
        # than fail.
        return
    raw = fixture.read_text(encoding="utf-8")
    out = decompose_notebook(raw)
    assert out.is_valid
    assert out.has_pip_install_magic
    assert out.has_load_ext_magic
    # Synthesized source preserves the malicious content verbatim
    assert "ml-trainer-helper" in out.synthesized_source
    assert "load_ext" in out.synthesized_source


def test_decompose_real_clean_fixture() -> None:
    fixture = Path("samples/regression_v1/notebook_clean.ipynb")
    if not fixture.exists():
        return
    raw = fixture.read_text(encoding="utf-8")
    out = decompose_notebook(raw)
    assert out.is_valid
    assert not out.has_pip_install_magic
    assert not out.has_load_ext_magic
    # Clean notebook still has cells
    assert out.n_code_cells >= 1
    assert out.n_markdown_cells >= 1
