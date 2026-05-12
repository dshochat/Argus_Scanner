"""`Preprocessor` — deterministic pipeline producing the `preprocessing{}` block.

Order of operations:
  1. SHA-256 raw file bytes.
  2. Malware-hash lookup on the raw file hash (cheap, high-value, runs
     even on files we're about to skip).
  3. Size tiering (PREP-009). Files ≥ 5 MB short-circuit with
     ``skip_reason="too_large"``.
  4. Binary / empty probe (PREP-010). Files with no content or that look
     like binary blobs short-circuit with ``skip_reason="empty"`` or
     ``skip_reason="binary"``.
  5. Language detection (extension → shebang fallback).
  6. Deobfuscation (iterative unwrap; decoded content is what S1 sees).
  7. Token count over the decoded content.
  8. Dependency parsing if filename matches a known manifest.
  9. `imperative_install_detected` check (setup.py / package.json scripts / .pth).
  10. Prompt-injection indicator detection (PREP-011) over both raw and
      deobfuscated content.

Outputs a `shared.types.preprocessing.Preprocessing` record. No LLMs, no network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from shared.types.enums import ObfuscationTechnique
from shared.types.preprocessing import (
    Dependency,
    Preprocessing,
    SizeTier,
    classify_size,
)
from shared.utils.hashing import sha256_bytes
from shared.utils.tokens import approx_token_count

from .ai_file_patterns import detect_ai_file
from .attack_vector_extensions import detect_attack_vector_extension
from .binary_detect import classify_binary_or_empty
from .crypto_sensitivity import analyze_file as analyze_crypto_sensitivity
from .deobfuscation import deobfuscate
from .deobfuscation_js import unwrap_js_string_array
from .framework_markers import detect_framework
from .imperative_install import analyze_file as analyze_imperative_install
from .language import detect_language
from .malware_hash import MalwareHashBackend, lookup
from .parsers import parse_manifest
from .prompt_injection import detect_prompt_injection


@dataclass
class PreprocessingBundle:
    """Full preprocessing output: schema block + decoded content + provenance.

    ``obfuscation_attack_attempt`` carries a short label when the decoded
    content exhibits a marker-spoofing pattern (see
    ``prompt_markers.detect_marker_spoofing``). ``None`` = no attack
    signal observed. Propagated into ``Obfuscation.attack_attempt`` at
    extraction time.
    """

    preprocessing: Preprocessing
    decoded_content: str
    obfuscation_techniques: list[ObfuscationTechnique] = field(default_factory=list)
    imperative_install_reasons: list[str] = field(default_factory=list)
    # PREP-013: deobfuscation counters that surface through
    # ``extractions.obfuscation`` (``blob_count``, ``decoded_blob_count``,
    # ``failed_blob_count``, ``suspicion_score``, ``decoded_content_summary``).
    # Carried at the bundle level — the narrower ``Preprocessing`` Pydantic
    # model remains the S1/L1 context shape, unchanged.
    obfuscation_blob_count: int = 0
    obfuscation_decoded_blob_count: int = 0
    obfuscation_failed_blob_count: int = 0
    obfuscation_suspicion_score: float = 0.0
    obfuscation_decoded_content_summary: str | None = None
    # PREP-015: short label set when decoded content exhibits an attack
    # pattern (e.g. ``"marker_spoofing"``).
    obfuscation_attack_attempt: str | None = None


class Preprocessor:
    """Stateless (aside from injected backends) deterministic preprocessor."""

    def __init__(self, *, malware_backend: MalwareHashBackend | None = None) -> None:
        self._malware_backend = malware_backend

    def run(self, path: str | Path, content: bytes) -> PreprocessingBundle:
        p = Path(path)

        file_hash = sha256_bytes(content)
        file_size_bytes = len(content)
        size_tier = classify_size(file_size_bytes)

        # Always run the malware-hash lookup — cheap and high-value even
        # on oversized files. A known-malware hash hitting a 10 MB payload
        # is exactly the kind of signal we must surface regardless of
        # model-stage budgets.
        malware_match = lookup(file_hash, self._malware_backend)

        # PREP-009 oversize short-circuit: >5 MB files skip deobfuscation,
        # dependency parsing, imperative-install analysis. The bundle still
        # reports hash + size + tier + malware match per preservation
        # principle. Decoded content is an empty string so downstream
        # consumers see a deterministic no-op signal.
        if size_tier is SizeTier.OVERSIZED:
            pp = Preprocessing(
                dependencies=[],
                deobfuscation_applied=False,
                deobfuscation_layers=0,
                file_hash=file_hash,
                known_malware_match=malware_match,
                detected_language=None,
                token_count=None,
                imperative_install_detected=False,
                file_size_bytes=file_size_bytes,
                size_tier=size_tier,
                skip_reason="too_large",
            )
            return PreprocessingBundle(
                preprocessing=pp,
                decoded_content="",
                obfuscation_techniques=[],
                imperative_install_reasons=[],
            )

        # ML model files (.pkl, .pt, .bin, .safetensors, .h5, .onnx) are
        # binary by construction; classify_binary_or_empty would skip them.
        # Decompose first: extract a textual summary (suspicious globals,
        # REDUCE opcodes, safetensors metadata, …) WITHOUT executing any
        # callables, then feed that text through the rest of the pipeline.
        # The cascade then sees a Python-with-comments report describing
        # what's structurally inside the artifact.
        ml_lower = str(p).lower()
        ml_extensions = (
            ".pkl",
            ".pickle",
            ".pt",
            ".bin",
            ".safetensors",
            ".h5",
            ".hdf5",
            ".keras",
            ".onnx",
        )
        if ml_lower.endswith(ml_extensions):
            from .ml_model import decompose_ml_model  # noqa: PLC0415

            ml = decompose_ml_model(str(p), content)
            if ml.is_valid:
                synth_bytes = ml.synthesized_source.encode("utf-8")
                # Replace content for downstream stages — file_hash stays
                # the original-bytes hash (already computed above), so the
                # report tracks the real artifact even though analysis
                # operates on the synthesized text.
                content = synth_bytes

        # PREP-010 empty / binary skip. Runs after the oversize check so
        # the ordering of ``skip_reason`` values is deterministic:
        # too_large > binary > empty. Preservation principle: hash + size
        # + tier + malware match are still reported; model stages do not
        # fire. Decoded content is empty for downstream no-op.
        binary_empty = classify_binary_or_empty(content)
        if binary_empty.should_skip:
            pp = Preprocessing(
                dependencies=[],
                deobfuscation_applied=False,
                deobfuscation_layers=0,
                file_hash=file_hash,
                known_malware_match=malware_match,
                detected_language=None,
                token_count=None,
                imperative_install_detected=False,
                file_size_bytes=file_size_bytes,
                size_tier=size_tier,
                skip_reason=binary_empty.skip_reason,
            )
            return PreprocessingBundle(
                preprocessing=pp,
                decoded_content="",
                obfuscation_techniques=[],
                imperative_install_reasons=[],
            )

        raw_text = content.decode("utf-8", errors="replace")
        language = detect_language(p, raw_text)

        # GitHub Actions workflow files: a YAML at .github/workflows/*.yml
        # is a CI-supply-chain attack surface. Run the deterministic
        # sweep (pull_request_target, unpinned third-party actions,
        # ${{ }} injection, secrets-near-network-verb) and synthesize a
        # report that the cascade reads as Python-with-comments.
        from .github_actions import (  # noqa: PLC0415
            analyze_workflow,
            is_github_actions_workflow,
        )

        if language == "yaml" and is_github_actions_workflow(p):
            wfa = analyze_workflow(raw_text)
            if wfa.is_valid:
                raw_text = wfa.synthesized_source
                language = "github_actions"

        # Jupyter notebooks: decompose into a Python-with-comments blob so
        # all downstream detectors (deobfuscation, prompt-injection scan,
        # imperative-install analysis, model cascade) see the cells as
        # one synthesized source. Shell magic (``!pip install``) and
        # IPython magic (``%load_ext``) lines survive verbatim in the
        # synthesized text, so the model and existing detectors can
        # reason about them without notebook-specific machinery. Falls
        # back to raw text on parse failure (we don't want a malformed
        # notebook to skip cascade analysis entirely — a malicious
        # notebook with intentionally-corrupt JSON should still get
        # scanned).
        if language == "jupyter":
            from .notebook import decompose_notebook  # noqa: PLC0415

            decomp = decompose_notebook(raw_text)
            if decomp.is_valid:
                raw_text = decomp.synthesized_source

        # PREP-014: JS string-array deobfuscation. obfuscator.io-style
        # bundles often blow past every model's context window (the Mini
        # Shai-Hulud TanStack `router_init.js` is 1.5 M tokens). Unwrap
        # before the Python-targeted deobfuscate() runs so downstream
        # token counting, prompt-injection scan, and model stages see a
        # readable, shrunk source. Fail paths leave raw_text untouched.
        js_string_array_applied = False
        if language in ("javascript", "typescript"):
            js_result = unwrap_js_string_array(raw_text)
            if js_result.applied:
                raw_text = js_result.content
                js_string_array_applied = True

        deob = deobfuscate(raw_text)

        token_count = approx_token_count(deob.content)

        dependencies: list[Dependency] = parse_manifest(p, raw_text)

        signal = analyze_imperative_install(p, raw_text)

        prompt_injection_indicators = detect_prompt_injection(raw_text, decoded_content=deob.content)
        ai_file_match = detect_ai_file(p)
        framework_hint = detect_framework(deob.content)
        attack_vector_extension = detect_attack_vector_extension(p)
        crypto_signal = analyze_crypto_sensitivity(deob.content, language)

        pp = Preprocessing(
            dependencies=dependencies,
            deobfuscation_applied=deob.applied or js_string_array_applied,
            deobfuscation_layers=deob.layers + (1 if js_string_array_applied else 0),
            file_hash=file_hash,
            known_malware_match=malware_match,
            detected_language=language,
            token_count=token_count,
            imperative_install_detected=signal.detected,
            prompt_injection_indicators=prompt_injection_indicators,
            file_size_bytes=file_size_bytes,
            size_tier=size_tier,
            ai_file_match=ai_file_match,
            framework_hint=framework_hint,
            attack_vector_extension=attack_vector_extension,
            crypto_sensitivity_detected=crypto_signal.detected,
            crypto_sensitivity_reasons=crypto_signal.reasons,
        )

        # Marker-spoofing check: flag (do not reject) when decoded
        # content contains a literal close-marker substring. Rejecting
        # would hand attackers a DoS primitive; the signal is enough to
        # alert downstream stages. Import is lazy to avoid a cycle —
        # prompt_markers imports PreprocessingBundle from this module.
        from .prompt_markers import detect_marker_spoofing  # noqa: PLC0415

        attack_attempt: str | None = None
        if deob.applied and detect_marker_spoofing(deob.content):
            attack_attempt = "marker_spoofing"

        techniques = list(deob.techniques)
        if js_string_array_applied:
            techniques.append(ObfuscationTechnique.JS_STRING_ARRAY)

        return PreprocessingBundle(
            preprocessing=pp,
            decoded_content=deob.content,
            obfuscation_techniques=techniques,
            imperative_install_reasons=list(signal.reasons),
            obfuscation_blob_count=deob.blob_count,
            obfuscation_decoded_blob_count=deob.decoded_blob_count,
            obfuscation_failed_blob_count=deob.failed_blob_count,
            obfuscation_suspicion_score=deob.suspicion_score,
            obfuscation_decoded_content_summary=deob.decoded_content_summary,
            obfuscation_attack_attempt=attack_attempt,
        )


def preprocess_file(
    path: str | Path,
    content: bytes,
    *,
    malware_backend: MalwareHashBackend | None = None,
) -> PreprocessingBundle:
    """Convenience wrapper around a fresh `Preprocessor`."""
    return Preprocessor(malware_backend=malware_backend).run(path, content)
