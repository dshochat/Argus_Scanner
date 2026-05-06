"""Extractions block — S2 (secrets) + S3 (entities) + S4 (capabilities) + obfuscation."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from shared.types.enums import (
    CapabilityTag,
    DomainContext,
    EnvVarRiskCategory,
    FileOperation,
    HttpMethod,
    IpContext,
    ObfuscationTechnique,
    SecretContext,
    SecretType,
    Severity,
    SeverityExt,
)


# ── S2 ─────────────────────────────────────────────────────────────────────────
class SecretExtraction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: SecretType
    line: int
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    is_placeholder: bool = Field(
        description="True for template/example values. Hardest S2 judgment.",
    )
    context: SecretContext | None = None


# ── S3 ─────────────────────────────────────────────────────────────────────────
class IpEntity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str
    context: IpContext


class DomainEntity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str
    context: DomainContext


class UrlEntity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str
    context: str


class FilePathReferenced(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    operation: FileOperation
    sensitivity: SeverityExt
    description: str | None = Field(default=None, max_length=100)


class OtherIndicator(BaseModel):
    """v3.1: Free-text overflow bucket for indicator types not yet promoted to typed fields."""

    model_config = ConfigDict(extra="forbid")

    value: str
    indicator_type: str = Field(
        max_length=40,
        description="Free-text type label (container_image_digest, onion_address, ipfs_cid, …).",
    )
    context: str = Field(max_length=100)
    line: int | None = None
    severity_hint: SeverityExt | None = None


class Entities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ips: list[IpEntity] = Field(default_factory=list)
    domains: list[DomainEntity] = Field(default_factory=list)
    urls: list[UrlEntity] = Field(default_factory=list)
    cloud_resources: list[str] = Field(default_factory=list)
    file_paths_referenced: list[FilePathReferenced] = Field(default_factory=list)
    other_indicators: list[OtherIndicator] = Field(default_factory=list)


# ── S4 ─────────────────────────────────────────────────────────────────────────
class NetworkCall(BaseModel):
    """OUR MOAT: structured call enumeration with declared flag."""

    model_config = ConfigDict(extra="forbid")
    destination: str
    method: HttpMethod
    purpose: str = Field(max_length=200)
    declared: bool = Field(
        description="Whether this call is documented/expected for the file's stated purpose.",
    )


class CommandExecuted(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str
    method: str
    purpose: str = Field(max_length=150)


class EnvVarAccess(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    sensitivity: Severity
    risk_category: EnvVarRiskCategory | None = Field(
        default=None,
        description=(
            "v3.1: Risk domain. 'ai_orchestration' = LLM provider keys, base URLs, "
            "model routing. Critical for AI token theft detection."
        ),
    )


class CryptoOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: str
    purpose: str


class Capabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tags: list[CapabilityTag] = Field(default_factory=list)
    dangerous_apis: list[str] = Field(default_factory=list)
    network_calls: list[NetworkCall] = Field(default_factory=list)
    commands_executed: list[CommandExecuted] = Field(default_factory=list)
    env_vars_accessed: list[EnvVarAccess] = Field(default_factory=list)
    crypto_operations: list[CryptoOperation] = Field(default_factory=list)
    requires_elevated_privileges: bool = False
    modifies_system_state: bool = False


# ── Obfuscation (deterministic) ────────────────────────────────────────────────
class Obfuscation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected: bool
    techniques: list[ObfuscationTechnique] = Field(default_factory=list)
    layers: int = Field(default=0, ge=0)
    suspicion_score: float = Field(default=0.0, ge=0, le=1)
    decoded_content_summary: str | None = Field(default=None, max_length=300)
    # PREP-013: blob-count fields matching
    # ``data/labeling/deobfuscation/models.py:DecodeResult``. Populated by
    # ``preprocessing.deobfuscation.deobfuscate()`` and surfaced through
    # ``sast/extraction/extraction.py::_obfuscation_from_preprocessing``.
    # Fine-tuned models see this shape in training data; carrying the same
    # shape at inference avoids distribution shift on the obfuscation sub-block.
    blob_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Total number of encoded blobs the pre-pass attempted to decode. "
            "In preprocessing's layer-peeling model each successful peel "
            "corresponds to one blob; in labeling's match-then-splice model "
            "each long base64/hex/zlib blob found by pattern match is one "
            "blob. Semantics differ; the shape matches."
        ),
    )
    decoded_blob_count: int = Field(
        default=0,
        ge=0,
        description="Blobs that decoded to printable text.",
    )
    failed_blob_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Blobs that matched an obfuscation pattern but failed to decode "
            "(padding error, non-printable output, decompression bomb, "
            "etc.). Zero in the preprocessing backend until per-technique "
            "failure instrumentation lands; kept for schema parity with "
            "labeling's DecodeResult."
        ),
    )
    #: PREP-015: short label set by preprocessing when decoded content
    #: exhibits an attack pattern (e.g. ``"marker_spoofing"`` when the
    #: decoded payload contains a literal close-marker substring). ``None``
    #: = no attack signal.
    attack_attempt: str | None = Field(default=None, max_length=80)


# ── Top-level ──────────────────────────────────────────────────────────────────
class Extractions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secrets: list[SecretExtraction] = Field(default_factory=list)
    entities: Entities = Field(default_factory=Entities)
    capabilities: Capabilities
    obfuscation: Obfuscation
