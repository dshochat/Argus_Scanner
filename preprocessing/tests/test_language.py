from __future__ import annotations

from pathlib import Path

from preprocessing.language import detect_language


def test_detect_language_python_by_extension() -> None:
    assert detect_language(Path("foo.py")) == "python"


def test_detect_language_manifest_overrides_extension() -> None:
    assert detect_language(Path("Dockerfile")) == "dockerfile"
    assert detect_language(Path("go.mod")) == "go"


def test_detect_language_shebang_fallback() -> None:
    assert detect_language(Path("unknown"), "#!/usr/bin/env node\nconsole.log(1)") == "javascript"
    assert detect_language(Path("unknown"), "#!/bin/bash\necho hi") == "shell"


def test_detect_language_unknown_without_hints() -> None:
    assert detect_language(Path("random.xyz"), "no shebang here") == "unknown"
