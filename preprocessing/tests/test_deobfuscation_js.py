from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from preprocessing.deobfuscation_js import (
    JsDeobfResult,
    has_string_array_marker,
    unwrap_js_string_array,
)

OBFUSCATED_HEAD = (
    "const _0x5b1880=_0x253b;(function(_0x4116b8,_0x2320bb){"
    "const _0x5f1a07=_0x253b,_0x5cdc04=_0x4116b8();"
    + ("var x=_0x5f1a07(0xf54);" * 200)
)

CLEAN_JS = """\
export function add(a, b) {
  return a + b;
}
"""


def test_marker_detected_in_obfuscator_io_preamble() -> None:
    assert has_string_array_marker(OBFUSCATED_HEAD) is True


def test_marker_not_present_in_clean_js() -> None:
    assert has_string_array_marker(CLEAN_JS) is False


def test_marker_only_scans_first_4k() -> None:
    # marker buried past the scan window should not trigger
    payload = ("// " + "x" * 80 + "\n") * 100 + OBFUSCATED_HEAD
    assert len(payload) > 4096
    assert has_string_array_marker(payload) is False


def test_unwrap_no_op_when_marker_absent() -> None:
    result = unwrap_js_string_array(CLEAN_JS)
    assert result == JsDeobfResult(applied=False, content=CLEAN_JS)


def test_disable_env_short_circuits_before_marker_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The disable gate must fire before webcrack resolution. If which
    # is reached when the disable env is set, that's a regression.
    monkeypatch.setenv("ARGUS_NO_DEOBFUSCATION", "1")

    def fail_which(name: str) -> str | None:
        raise AssertionError("which should not be called when disabled")

    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.shutil.which", fail_which
    )
    result = unwrap_js_string_array(OBFUSCATED_HEAD)
    assert result.applied is False
    assert result.content == OBFUSCATED_HEAD


def test_unwrap_no_op_when_webcrack_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUS_WEBCRACK", raising=False)
    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.shutil.which", lambda _: None
    )
    result = unwrap_js_string_array(OBFUSCATED_HEAD)
    assert result.applied is False
    assert result.content == OBFUSCATED_HEAD


def test_unwrap_no_op_on_webcrack_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARGUS_WEBCRACK", raising=False)
    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.shutil.which",
        lambda _: "/fake/webcrack",
    )
    fake = subprocess.CompletedProcess(
        args=[], returncode=1, stdout=b"", stderr=b"boom"
    )
    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.subprocess.run",
        lambda *a, **k: fake,
    )
    result = unwrap_js_string_array(OBFUSCATED_HEAD)
    assert result.applied is False
    assert result.content == OBFUSCATED_HEAD


def test_unwrap_no_op_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUS_WEBCRACK", raising=False)
    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.shutil.which",
        lambda _: "/fake/webcrack",
    )

    def raise_timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="webcrack", timeout=60)

    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.subprocess.run",
        raise_timeout,
    )
    result = unwrap_js_string_array(OBFUSCATED_HEAD)
    assert result.applied is False
    assert result.content == OBFUSCATED_HEAD


def test_unwrap_no_op_when_output_not_shrunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARGUS_WEBCRACK", raising=False)
    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.shutil.which",
        lambda _: "/fake/webcrack",
    )

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        out_dir_idx = cmd.index("-o") + 1
        out_dir = Path(cmd[out_dir_idx])
        out_dir.mkdir(parents=True, exist_ok=True)
        # Emit a file just as large as the input to fail the shrink gate.
        (out_dir / "deob.js").write_text(OBFUSCATED_HEAD, encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("preprocessing.deobfuscation_js.subprocess.run", fake_run)
    result = unwrap_js_string_array(OBFUSCATED_HEAD)
    assert result.applied is False
    assert result.content == OBFUSCATED_HEAD


def test_unwrap_applies_when_output_shrinks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARGUS_WEBCRACK", raising=False)
    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.shutil.which",
        lambda _: "/fake/webcrack",
    )
    shrunk = "function add(a, b) { return a + b; }\n"

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        out_dir_idx = cmd.index("-o") + 1
        out_dir = Path(cmd[out_dir_idx])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "deob.js").write_text(shrunk, encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("preprocessing.deobfuscation_js.subprocess.run", fake_run)
    result = unwrap_js_string_array(OBFUSCATED_HEAD)
    assert result.applied is True
    assert result.technique == "js_string_array"
    assert shrunk in result.content


def test_argus_webcrack_env_used_when_path_lookup_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # PATH lookup misses; env var supplies the binary for non-standard
    # installs (e.g. project-local node_modules/.bin/webcrack).
    fake_bin = tmp_path / "webcrack"
    fake_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("ARGUS_WEBCRACK", str(fake_bin))
    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.shutil.which", lambda _: None
    )

    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["cmd"] = list(cmd)
        out_dir_idx = cmd.index("-o") + 1
        out_dir = Path(cmd[out_dir_idx])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "deob.js").write_text("ok", encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("preprocessing.deobfuscation_js.subprocess.run", fake_run)
    result = unwrap_js_string_array(OBFUSCATED_HEAD)
    assert result.applied is True
    assert captured["cmd"][0] == str(fake_bin)


def test_path_lookup_wins_over_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # If both are set, the global install (shutil.which) takes precedence.
    path_bin = tmp_path / "path-webcrack"
    path_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    env_bin = tmp_path / "env-webcrack"
    env_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("ARGUS_WEBCRACK", str(env_bin))
    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.shutil.which", lambda _: str(path_bin)
    )

    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["cmd"] = list(cmd)
        out_dir_idx = cmd.index("-o") + 1
        out_dir = Path(cmd[out_dir_idx])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "deob.js").write_text("ok", encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("preprocessing.deobfuscation_js.subprocess.run", fake_run)
    unwrap_js_string_array(OBFUSCATED_HEAD)
    assert captured["cmd"][0] == str(path_bin)


def test_is_available_returns_true_when_resolvable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.shutil.which", lambda _: "/fake/webcrack"
    )
    monkeypatch.delenv("ARGUS_WEBCRACK", raising=False)
    from preprocessing.deobfuscation_js import is_available
    assert is_available() is True


def test_is_available_returns_false_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "preprocessing.deobfuscation_js.shutil.which", lambda _: None
    )
    monkeypatch.delenv("ARGUS_WEBCRACK", raising=False)
    from preprocessing.deobfuscation_js import is_available
    assert is_available() is False
