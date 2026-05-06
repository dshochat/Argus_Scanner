"""Preprocessing — deterministic, LLM-free stage 1.

Produces the `preprocessing{}` block of `LabelRecord`. See `CLAUDE.md` in
this directory for the full spec.
"""

from __future__ import annotations

from .ai_file_patterns import detect_ai_file
from .attack_vector_extensions import detect_attack_vector_extension
from .binary_detect import BinaryEmptyVerdict, classify_binary_or_empty
from .deobfuscation import DeobfuscationResult, deobfuscate
from .framework_markers import detect_framework
from .imperative_install import ImperativeInstallSignal
from .imperative_install import analyze_file as analyze_imperative_install
from .language import detect_language
from .malware_hash import (
    InMemoryMalwareHashBackend,
    MalwareHashBackend,
    default_backend,
    lookup,
    set_default_backend,
)
from .parsers import is_manifest, parse_manifest
from .pipeline import PreprocessingBundle, Preprocessor, preprocess_file
from .prompt_markers import wrap_decoded_for_prompt

__all__ = [
    "BinaryEmptyVerdict",
    "DeobfuscationResult",
    "ImperativeInstallSignal",
    "InMemoryMalwareHashBackend",
    "MalwareHashBackend",
    "Preprocessor",
    "PreprocessingBundle",
    "analyze_imperative_install",
    "classify_binary_or_empty",
    "default_backend",
    "deobfuscate",
    "detect_ai_file",
    "detect_attack_vector_extension",
    "detect_framework",
    "detect_language",
    "is_manifest",
    "lookup",
    "parse_manifest",
    "preprocess_file",
    "set_default_backend",
    "wrap_decoded_for_prompt",
]
