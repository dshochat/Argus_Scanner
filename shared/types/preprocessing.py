"""Preprocessing block — deterministic outputs, no LLM.

Produced by language-specific parsers BEFORE any model runs. Feeds the
orchestrator for CVE lookups and is injected into L1 as context.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from shared.types.enums import Ecosystem, Severity


class PromptInjectionPatternType(str, Enum):
    """Classification of prompt-injection pattern classes detected pre-LLM."""

    ZERO_WIDTH_CHAR = "zero_width_char"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    ENCODED_SUSPICIOUS_KEYWORD = "encoded_suspicious_keyword"


class PromptInjectionIndicator(BaseModel):
    """Deterministic pre-pass finding for prompt-injection patterns.

    Emitted by ``preprocessing/prompt_injection.py``. These are guaranteed
    indicators: they are not gated on L1 pattern-matching and will appear
    in the preprocessing block whenever the pattern matches. L1 still sees
    the full content and can calibrate severity / add narrative, but the
    raw deterministic signal is preserved.
    """

    model_config = ConfigDict(extra="forbid")

    pattern_type: PromptInjectionPatternType
    pattern_label: str = Field(
        description=(
            "Short identifier for which specific pattern matched "
            "(e.g. 'ignore_previous_instructions', 'identity_override', "
            "'U+200B ZERO WIDTH SPACE')."
        ),
        max_length=80,
    )
    match_preview: str = Field(
        description=(
            "Truncated single-line preview of the matched text + local context. Never contains secret material."
        ),
        max_length=200,
    )
    line: int | None = Field(
        default=None,
        description=(
            "1-indexed line number of the match in the original content. "
            "None when the match was detected only in post-decode content."
        ),
    )
    severity: Severity = Field(description="Preprocessing-side severity; L1 can override later.")


# ── PREP-009 size tiering ─────────────────────────────────────────────────
#: Upper bound (exclusive) of the SMALL tier — files below run the full
#: pipeline unconditionally. Legacy 100 KB line from ``app/``.
SIZE_TIER_SMALL_MAX = 100_000
#: Upper bound (exclusive) of the MEDIUM tier — full pipeline with
#: token-budget monitoring.
SIZE_TIER_MEDIUM_MAX = 500_000
#: Upper bound (exclusive) of the LARGE tier — pre-pass runs fully; model
#: stages gated by orchestrator on per-stage token budgets.
SIZE_TIER_LARGE_MAX = 5_000_000
#: Files at or beyond this size are skipped entirely and
#: ``skip_reason="too_large"`` is emitted.
SIZE_TIER_OVERSIZED_AT = SIZE_TIER_LARGE_MAX


class SizeTier(str, Enum):
    """Size classification used to route a file through the pipeline.

    ``SMALL`` < 100 KB, ``MEDIUM`` 100 KB – 500 KB, ``LARGE`` 500 KB – 5 MB,
    ``OVERSIZED`` ≥ 5 MB (skipped). Boundaries match PREP-009; rationale
    in ``ROADMAP.md`` and ``scripts/prepass_consolidation_research.md``.
    """

    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    OVERSIZED = "oversized"


def classify_size(size_bytes: int) -> SizeTier:
    """Map a raw byte count to its :class:`SizeTier` bucket."""
    if size_bytes >= SIZE_TIER_OVERSIZED_AT:
        return SizeTier.OVERSIZED
    if size_bytes >= SIZE_TIER_MEDIUM_MAX:
        return SizeTier.LARGE
    if size_bytes >= SIZE_TIER_SMALL_MAX:
        return SizeTier.MEDIUM
    return SizeTier.SMALL


class Dependency(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version_spec: str = Field(description="E.g. '==3.1.2', '>=2.0,<3.0', '^4.17.21'")
    ecosystem: Ecosystem
    source_file: str | None = Field(
        default=None,
        description="Manifest file the dep was parsed from (requirements.txt, package.json, …).",
    )


class Preprocessing(BaseModel):
    """Deterministic preprocessing outputs. NOT model-generated."""

    model_config = ConfigDict(extra="forbid")

    dependencies: list[Dependency] = Field(
        description=(
            "Parsed by deterministic parsers from manifest files. "
            "Orchestrator queries the CVE DB against these before calling L1."
        ),
    )
    deobfuscation_applied: bool
    deobfuscation_layers: int = Field(default=0, ge=0)
    file_hash: str | None = Field(
        default=None,
        description="SHA-256 of raw file content, pre-deobfuscation.",
    )
    known_malware_match: str | None = None
    detected_language: str | None = None
    token_count: int | None = None
    imperative_install_detected: bool = Field(
        default=False,
        description=(
            "v3.1: True for setup.py/postinstall/.pth/build scripts that execute "
            "code during installation. When true, orchestrator forces priority_score>=4."
        ),
    )
    prompt_injection_indicators: list[PromptInjectionIndicator] = Field(
        default_factory=list,
        description=(
            "PREP-011: deterministic pre-pass matches for zero-width characters, "
            "hidden-instruction patterns, and encoded suspicious keywords. "
            "Guaranteed to appear when their pattern matches; not gated on "
            "L1 pattern-matching. L1 receives these as context."
        ),
    )
    file_size_bytes: int | None = Field(
        default=None,
        ge=0,
        description=(
            "PREP-009: raw byte count of the input file. Orchestrator uses "
            "this plus ``size_tier`` to route large files through reduced-"
            "depth model stages."
        ),
    )
    size_tier: SizeTier | None = Field(
        default=None,
        description=(
            "PREP-009: file-size classification. SMALL <100KB, MEDIUM "
            "100-500KB, LARGE 500KB-5MB, OVERSIZED ≥5MB (skipped). "
            'Complements ``skip_reason`` which is set to ``"too_large"`` '
            "on OVERSIZED files."
        ),
    )
    skip_reason: str | None = Field(
        default=None,
        max_length=40,
        description=(
            "When set, model stages do not fire on this file. Current "
            'values: ``"too_large"`` (>5MB, PREP-009), ``"empty"`` '
            '(zero-byte or whitespace-only, PREP-010), ``"binary"`` '
            "(NUL byte in first 1000 or >30% non-printable, PREP-010). "
            "Future: repo-mode skip-list matches. Preservation "
            "principle: the preprocessing block still reports hash + "
            "size so downstream stages know the file existed."
        ),
    )
    ai_file_match: str | None = Field(
        default=None,
        max_length=40,
        description=(
            "PREP-016: category label when the filename matches a canonical "
            "AI-tooling pattern (SKILL.md, CLAUDE.md, .cursorrules, plugin.json, "
            "mcp*.json, agent_config.yaml, tools.json, etc.). One of: "
            "skill_definition, agent_config, system_prompt, plugin_manifest, "
            "mcp_config, api_schema, tool_definition. ``None`` when no pattern "
            "matches. S1 uses this to force ``is_ai_component=true`` on its "
            "triage output, overrideable when content evidence clearly "
            "contradicts (e.g. a file literally named plugin.json that's "
            "actually an IDE plugin, not an AI plugin)."
        ),
    )
    framework_hint: str | None = Field(
        default=None,
        max_length=20,
        description=(
            "PREP-017: marker string (``flask``, ``fastapi``, ``django``, "
            "``express``, ``gin``, ``echo``, ``fiber``, ``rails``) when "
            "the first 2 KB of decoded content contains a canonical "
            "framework import. ``None`` when no marker matches. S1 "
            "pre-seeds its ``framework`` field from this; S1 may still "
            "infer a different framework from deeper content — the hint "
            "is additive, never subtractive."
        ),
    )
    attack_vector_extension: str | None = Field(
        default=None,
        max_length=10,
        description=(
            "PREP-018: Python packaging artifact extension (``pth``, ``egg``, "
            "``whl``, ``spec``) recognized on filename alone. Complements "
            "``imperative_install_detected`` which is content-based — this "
            "catches artifacts whose attack surface is structural (``.pth`` "
            "injects imports; ``.whl``/``.egg`` trigger installer hooks; "
            "``.spec`` runs during PyInstaller packaging). When non-null, "
            "orchestrator forces ``priority_score >= 4`` the same way "
            "``imperative_install_detected`` does."
        ),
    )
    crypto_sensitivity_detected: bool = Field(
        default=False,
        description=(
            "PREP-020: True when the file imports high-blast-radius "
            "cryptographic primitives (``cryptography.hazmat``, ``Crypto.*``, "
            "``Cryptodome.*``, ``OpenSSL.*``, ``nacl.*``, ``passlib.hash.*``) "
            "OR contains misuse-name identifiers (``legacy_iv``, "
            "``static_iv``, ``hardcoded_key``, ``insecure_mode``) OR has "
            "literal AES-key/IV-length bytes assigned to sensitive variables "
            "(``key`` / ``iv`` / ``salt``) OR matches the ``MODE_ECB`` "
            "content marker. When true, orchestrator forces "
            "``priority_score >= 4`` the same way "
            "``imperative_install_detected`` does — bringing the L1 "
            "attack-vector advisory into play (Fix 6 broadened it to all "
            "priority ≥ 4 files). The signal does NOT prove misuse; it "
            "marks the file as cryptographic attack-surface territory "
            "where L1's default cover-story-tolerance is risky."
        ),
    )
    crypto_sensitivity_reasons: list[str] = Field(
        default_factory=list,
        description=(
            "PREP-020: machine-readable reason tokens for the "
            "``crypto_sensitivity_detected`` signal. Stable strings such as "
            "``import:cryptography.hazmat.primitives.ciphers``, "
            "``misuse_name:legacy_iv_mode``, ``hardcoded_key_32b``, "
            "``MODE_ECB``. Empty when ``crypto_sensitivity_detected`` is "
            "False. Used by L1 prompt advisory + telemetry."
        ),
    )
