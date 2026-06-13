"""Hermetic tests for dashboard ingest file parsing."""

from __future__ import annotations

import json
from pathlib import Path

from dashboard.cli import _load_results


def test_load_results_single_dict(tmp_path: Path) -> None:
    f = tmp_path / "a.json"
    f.write_text(json.dumps({"filename": "x.py"}), encoding="utf-8")
    assert _load_results(f) == [{"filename": "x.py"}]


def test_load_results_json_array(tmp_path: Path) -> None:
    f = tmp_path / "b.json"
    f.write_text(json.dumps([{"filename": "a"}, {"filename": "b"}]), encoding="utf-8")
    assert len(_load_results(f)) == 2


def test_load_results_directory(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_text(json.dumps({"filename": "a"}), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps({"filename": "b"}), encoding="utf-8")
    assert len(_load_results(tmp_path)) == 2


def test_load_results_skips_invalid_json(tmp_path: Path) -> None:
    (tmp_path / "good.json").write_text(json.dumps({"filename": "a"}), encoding="utf-8")
    (tmp_path / "bad.json").write_text("{not valid json", encoding="utf-8")
    assert len(_load_results(tmp_path)) == 1


def test_load_results_missing_path_raises(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        _load_results(tmp_path / "nope.json")
