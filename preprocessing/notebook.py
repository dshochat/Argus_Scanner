"""Jupyter notebook (.ipynb) decomposition — preprocessing step.

A .ipynb file is JSON with a list of cells (code / markdown / raw). For
security analysis we synthesize a single Python-with-comments blob where:

* Each code cell is rendered verbatim under a ``# === NOTEBOOK CELL N (code) ===``
  banner.
* Each markdown cell is rendered as Python comments under a
  ``# === NOTEBOOK CELL N (markdown) ===`` banner — preserves the
  prompt-injection surface for downstream detectors.
* Raw cells get the same treatment as markdown (comment-prefixed).

The synthesized blob then flows through the rest of the preprocessing
pipeline (deobfuscation, prompt-injection detection, dependency
parsing, manifest analysis) AS IF it were a ``.py`` file. This lets
every existing detector apply with no special-casing downstream.

Notebook-specific signals (shell magic, IPython magic, pip-install
calls in cells) are surfaced in the returned ``NotebookDecomposition``
so the orchestrator can use them — Argus's threat model for notebooks
includes ``!pip install <evil-pkg>`` shell magic and
``%load_ext <malicious_ext>`` IPython magic, both of which are
notebook-native attack vectors.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class NotebookDecomposition:
    """Result of parsing a .ipynb file."""

    is_valid: bool
    """True when the file parsed as JSON with a ``cells`` list."""

    synthesized_source: str
    """All cells flattened into one Python-with-comments blob.

    Empty string when ``is_valid`` is False.
    """

    n_code_cells: int = 0
    n_markdown_cells: int = 0
    n_raw_cells: int = 0

    shell_magic_lines: list[str] = field(default_factory=list)
    """Lines starting with ``!`` inside code cells (shell magic)."""

    ipython_magic_lines: list[str] = field(default_factory=list)
    """Lines starting with ``%`` inside code cells (IPython magic)."""

    has_pip_install_magic: bool = False
    """True when any shell-magic OR IPython-magic line installs a package."""

    has_load_ext_magic: bool = False
    """True when any IPython-magic line loads an extension via ``load_ext``."""

    parse_error: str | None = None


def _coerce_source(source: Any) -> str | None:
    """nbformat allows ``source`` to be a string OR a list of strings.
    Normalize to a single string. Anything else returns None (cell skipped)."""
    if isinstance(source, str):
        return source
    if isinstance(source, list):
        # Per nbformat the list is concatenated as-is (no separator inserted).
        return "".join(s for s in source if isinstance(s, str))
    return None


def decompose_notebook(raw_text: str) -> NotebookDecomposition:
    """Parse a .ipynb file's raw text and return a synthesized analysis target.

    The returned ``synthesized_source`` is what the rest of preprocessing
    operates on (deobfuscation, prompt-injection scan, etc.). Returns an
    invalid decomposition with ``parse_error`` populated when the file
    isn't a parseable Jupyter notebook — callers should fall back to
    raw-text analysis in that case.
    """
    try:
        nb = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return NotebookDecomposition(
            is_valid=False,
            synthesized_source="",
            parse_error=f"json: {exc.msg}",
        )

    if not isinstance(nb, dict):
        return NotebookDecomposition(
            is_valid=False,
            synthesized_source="",
            parse_error="root not an object",
        )

    cells = nb.get("cells")
    if not isinstance(cells, list):
        return NotebookDecomposition(
            is_valid=False,
            synthesized_source="",
            parse_error="missing or non-list `cells`",
        )

    parts: list[str] = []
    n_code = n_md = n_raw = 0
    shell_lines: list[str] = []
    magic_lines: list[str] = []

    for idx, cell in enumerate(cells, 1):
        if not isinstance(cell, dict):
            continue
        cell_type = cell.get("cell_type")
        text = _coerce_source(cell.get("source"))
        if text is None:
            continue

        if cell_type == "code":
            n_code += 1
            parts.append(f"# === NOTEBOOK CELL {idx} (code) ===\n{text}")
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("!"):
                    shell_lines.append(stripped)
                elif stripped.startswith("%"):
                    magic_lines.append(stripped)
        elif cell_type == "markdown":
            n_md += 1
            commented = "\n".join(
                f"# {ln}" if ln else "#" for ln in text.splitlines()
            )
            parts.append(f"# === NOTEBOOK CELL {idx} (markdown) ===\n{commented}")
        elif cell_type == "raw":
            n_raw += 1
            commented = "\n".join(
                f"# (raw) {ln}" if ln else "#" for ln in text.splitlines()
            )
            parts.append(f"# === NOTEBOOK CELL {idx} (raw) ===\n{commented}")
        # Unknown cell types are skipped silently — nbformat allows
        # extension cell types and we don't want to false-positive on
        # them.

    has_pip = any(
        ("pip install" in ln) or ("pip3 install" in ln) or ("uv pip install" in ln)
        for ln in shell_lines + magic_lines
    )
    has_load_ext = any("load_ext" in ln for ln in magic_lines)

    synth = "\n\n".join(parts)
    if synth:
        synth += "\n"

    return NotebookDecomposition(
        is_valid=True,
        synthesized_source=synth,
        n_code_cells=n_code,
        n_markdown_cells=n_md,
        n_raw_cells=n_raw,
        shell_magic_lines=shell_lines,
        ipython_magic_lines=magic_lines,
        has_pip_install_magic=has_pip,
        has_load_ext_magic=has_load_ext,
    )


__all__ = ["NotebookDecomposition", "decompose_notebook"]
