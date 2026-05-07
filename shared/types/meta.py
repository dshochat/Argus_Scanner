"""_meta block — provenance + scan intelligence cache (v3.1).

Includes the three-tier intelligence cache tracking and the pipeline
fingerprint. The composite file-level cache key is:

    SHA-256(file_hash + pipeline_fingerprint.fingerprint_hash)

Any component update (model, parser, prompt, policy) changes the
fingerprint → the key changes → files that actually used that component
miss the cache.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from shared.types.enums import (
    AttackCategory,
    CacheInvalidationReason,
    LabelModel,
    Origin,
    PatchStatus,
    TrainingDataType,
    VerdictLabel,
)


# ── Tier 0: file-level cache ───────────────────────────────────────────────────
class FileCacheInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    served_from_cache: bool = False
    cache_key: str | None = Field(
        default=None,
        description="SHA-256(file_hash + pipeline_fingerprint_hash).",
    )
    cached_at: datetime | None = None
    cache_ttl_sec: int | None = None
    hit_count: int | None = None
    invalidation_reason: CacheInvalidationReason | None = None
    previous_verdict: VerdictLabel | None = None
    invalidated_component: str | None = Field(
        default=None,
        description="E.g., 'models.s2', 'preprocessing.dependency_parsers.pypi'.",
    )
    ttl_rule_matched: str | None = Field(
        default=None,
        description="Name of the TTL rule from cache_policy.yaml.",
    )
    cache_eligible: bool = True
    ineligibility_reason: str | None = None


# ── Tier 1: dependency intelligence ────────────────────────────────────────────
class DependencyCacheHit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem: str
    package: str
    version_spec: str
    profile_age_hours: float
    cve_count: int | None = None
    capability_tags_injected: list[str] = Field(default_factory=list)
    tokens_saved_estimate: int | None = None


# ── Tier 2: entity intelligence ────────────────────────────────────────────────
class EntityCacheHit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str
    entity_type: str  # ip | domain | url | cloud_resource | other_indicator
    cached_context: str
    context_overridden: bool = Field(
        description=(
            "True if S3 overrode the cached classification for this file. Override = high-value anomaly signal."
        ),
    )
    override_context: str | None = None


# ── Tier 3: framework behavior baseline ────────────────────────────────────────
class FrameworkBaselineUsed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: str
    version: str | None = None
    baseline_age_hours: float
    expected_capabilities: list[str] = Field(default_factory=list)
    expected_network_patterns: list[str] = Field(default_factory=list)
    anomalies_detected: int = 0


# ── Pipeline fingerprint ───────────────────────────────────────────────────────
class ModelVersions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    s1: str | None = None
    s2: str | None = None
    s3: str | None = None
    s4: str | None = None
    l1: str | None = None
    orchestrator: str | None = None
    code_agent: str | None = None


class DependencyParserVersions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pypi: str | None = None
    npm: str | None = None
    go: str | None = None
    maven: str | None = None
    rubygems: str | None = None
    crates: str | None = None
    nuget: str | None = None


class PreprocessingVersions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deobfuscation_engine: str
    dependency_parsers: DependencyParserVersions = Field(default_factory=DependencyParserVersions)
    language_detector: str
    hash_engine: str
    pth_detector: str | None = None  # v3.1
    setup_script_analyzer: str | None = None  # v3.1


class IntelligenceCacheVersions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dependency_profiles_version: str | None = None
    entity_cache_version: str | None = None
    framework_baselines_version: str | None = None


class CachePolicyFingerprint(BaseModel):
    """v3.1: Policy snapshot at scan time. Detects drift."""

    model_config = ConfigDict(extra="forbid")

    policy_version: str
    deployment_profile: str = Field(
        description="'saas_free', 'saas_pro', 'onprem_small', 'onprem_large', 'govcloud', or 'default'.",
    )
    policy_hash: str = Field(description="SHA-256 of the resolved policy after all overrides.")
    customer_overrides_applied: bool = False
    runtime_flags: list[str] = Field(default_factory=list)


class PromptTemplateHashes(BaseModel):
    model_config = ConfigDict(extra="forbid")

    s1_prompt_hash: str | None = None
    s_extract_prompt_hash: str | None = None
    l1_prompt_hash: str | None = None
    verification_prompt_hash: str | None = None
    pass2_orchestrator_prompt_hash: str | None = None


class PipelineFingerprint(BaseModel):
    """Complete version fingerprint. Only components actually used for this file are populated."""

    model_config = ConfigDict(extra="forbid")

    fingerprint_hash: str
    scanner_version: str
    models: ModelVersions = Field(default_factory=ModelVersions)
    preprocessing: PreprocessingVersions
    schema_version: str
    policy_validator: str | None = None
    intelligence_cache: IntelligenceCacheVersions = Field(default_factory=IntelligenceCacheVersions)
    cve_db_cursor: str | None = None
    cache_policy: CachePolicyFingerprint
    prompt_templates: PromptTemplateHashes | None = None


class TokensSaved(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int | None = None
    from_dependency_profiles: int | None = None
    from_entity_cache: int | None = None
    from_framework_baseline: int | None = None


class ScanIntelligence(BaseModel):
    """v3.1: Tracks which pre-computed knowledge was injected into this scan."""

    model_config = ConfigDict(extra="forbid")

    file_cache: FileCacheInfo = Field(default_factory=FileCacheInfo)
    dependency_cache_hits: list[DependencyCacheHit] = Field(default_factory=list)
    entity_cache_hits: list[EntityCacheHit] = Field(default_factory=list)
    framework_baseline_used: FrameworkBaselineUsed | None = None
    pipeline_fingerprint: PipelineFingerprint
    tokens_saved: TokensSaved = Field(default_factory=TokensSaved)


# ── _meta (top-level) ─────────────────────────────────────────────────────────
class Meta(BaseModel):
    """Labeling provenance. NOT used for model training — for dataset management."""

    model_config = ConfigDict(extra="forbid")

    label_model: LabelModel
    label_timestamp: datetime
    filename: str
    file_hash: str
    origin: Origin
    synthetic_source: str | None = None
    attack_category: AttackCategory
    attack_subcategories: list[str] = Field(default_factory=list)
    known_vulns_provided: bool
    language: str
    content_was_decoded: bool = False
    decode_layers: int = 0
    token_count_input: int | None = None
    token_count_output: int | None = None
    patch_status: PatchStatus = PatchStatus.UNKNOWN
    known_cve_refs: list[str] = Field(default_factory=list)
    patch_diff_hash: str | None = None
    training_data_type: TrainingDataType | None = None
    scan_intelligence: ScanIntelligence | None = None
