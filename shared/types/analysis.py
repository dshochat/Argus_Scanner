"""Analysis block — L1 output.

Input: full file + all S-model outputs + optional CVE context.
MUST emit empty ``findings`` for clean files (anti-hallucination invariant).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from shared.types.enums import (
    AttackChainLikelihood,
    ConfidenceLabel,
    EnvironmentComplexity,
    FindingType,
    HypothesisType,
    OracleType,
    Severity,
    SeverityExt,
    ValidatedBy,
)


class CodeSnippet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str = Field(max_length=80)
    lines: list[int] = Field(min_length=2, max_length=2)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^F[0-9]{3}$")
    type: FindingType
    severity: Severity
    confidence_label: ConfidenceLabel = Field(
        description=(
            "v3.1: Model's categorical confidence. The float `confidence` is "
            "PIPELINE-COMPUTED from logprob distribution over this token."
        ),
    )
    confidence: float = Field(
        ge=0,
        le=1,
        description="v3.1: Pipeline-computed from logprobs over confidence_label. Not model-generated.",
    )
    title: str = Field(max_length=120)
    cwe: str | None = None
    cvss_estimate: float | None = Field(default=None, ge=0, le=10)
    code_snippet: CodeSnippet | None = None
    explanation: str = Field(max_length=500)
    data_flow: str | None = Field(default=None, max_length=400)
    fix: str = Field(max_length=500)
    proof_of_concept: str | None = Field(default=None, max_length=400)
    mitre_attack: list[str] = Field(default_factory=list)
    known_cve: str | None = None
    patch_available: bool | None = None
    validated_by: ValidatedBy | None = None


class TrustBoundaryUserToAgent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sanitization: str | None = None  # none | partial | full
    injection_surface: str | None = None  # none | low | medium | high


class TrustBoundaryAgentToTools(BaseModel):
    model_config = ConfigDict(extra="forbid")
    validation: str | None = None
    privilege_level: str | None = None  # minimal | scoped | broad | unrestricted
    tools_accessible: list[str] = Field(default_factory=list)


class TrustBoundaryToolToSystem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sandboxed: bool | None = None
    network_scope: str | None = None  # none | restricted | unrestricted
    filesystem_scope: str | None = None


class TrustBoundaries(BaseModel):
    """Only populated when triage.is_ai_component = true."""

    model_config = ConfigDict(extra="forbid")
    user_to_agent: TrustBoundaryUserToAgent | None = None
    agent_to_tools: TrustBoundaryAgentToTools | None = None
    tool_to_system: TrustBoundaryToolToSystem | None = None


class DataFlow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str
    sink: str
    risk: str = Field(max_length=200)
    transforms: list[str] = Field(default_factory=list)


class DeclaredVsActual(BaseModel):
    """OUR MOAT: mismatch between declared and actual behavior."""

    model_config = ConfigDict(extra="forbid")
    has_declaration: bool
    declaration_source: str  # docstring | readme | package_json | comments | manifest | none
    mismatch_severity: str  # none | low | medium | high | critical
    description: str = Field(max_length=400)
    undeclared_capabilities: list[str] = Field(default_factory=list)


class ExfiltrationRisk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    external_network_calls: list[str] = Field(default_factory=list)
    encoding_before_sending: str | None = Field(default=None, max_length=200)
    data_in_logs: str | None = None
    data_in_errors: str | None = None


class ObfuscationSignals(BaseModel):
    model_config = ConfigDict(extra="forbid")
    encoded_strings: list[str] = Field(default_factory=list)
    dynamic_url_construction: bool = False
    conditional_behavior: str | None = None
    comment_code_mismatch: str | None = None
    hidden_instructions: str | None = None
    fetches_remote_instructions: bool = False


class Behavior(BaseModel):
    """Full behavioral & semantic profile. Echo's primary differentiator."""

    model_config = ConfigDict(extra="forbid")

    purpose: str = Field(max_length=300)
    risk_narrative: str = Field(max_length=500)
    sensitivity: SeverityExt
    data_types: list[str] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    trust_boundaries: TrustBoundaries | None = None
    declared_vs_actual: DeclaredVsActual | None = None
    exfiltration_risk: ExfiltrationRisk | None = None
    obfuscation_signals: ObfuscationSignals | None = None


class AttackChain(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(max_length=120)
    likelihood: AttackChainLikelihood
    entry_point: str
    impact: str
    steps: list[str] = Field(max_length=8)
    mitre_attack: list[str] = Field(default_factory=list)
    findings_used: list[str] = Field(default_factory=list)


class TestStep(BaseModel):
    """v3.1: One step in a stateful multi-step test plan."""

    model_config = ConfigDict(extra="forbid")

    step_number: int = Field(ge=1)
    action: str = Field(max_length=200)
    expected_state: str = Field(max_length=200)
    depends_on_step: int | None = None


class Hypothesis(BaseModel):
    """Testable prediction for Pass 2 sandbox execution."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^H[0-9]{3}$")
    finding_ref: str = Field(description="Finding ID this hypothesis validates. E.g., 'F001'.")
    type: HypothesisType
    description: str = Field(max_length=300)
    test_approach: str = Field(max_length=400)
    suggested_payload: str | None = Field(default=None, max_length=300)
    environment_needs: list[str] = Field(default_factory=list)
    oracle_type: OracleType | None = None
    estimated_complexity: str | None = None  # low | medium | high
    poc_feasible: bool
    test_steps: list[TestStep] = Field(
        default_factory=list,
        description="v3.1: Multi-step plan for stateful exploits.",
    )
    environment_complexity: EnvironmentComplexity | None = Field(
        default=None,
        description="v3.1: Code Agent handles single_process and some multi_process.",
    )
    estimated_sandbox_time_sec: int | None = Field(
        default=None,
        ge=1,
        description="v3.1: L1 estimate used by orchestrator for Pass 2 budget allocation.",
    )


class Analysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[Finding] = Field(
        default_factory=list,
        description="MUST be empty [] for clean files. Anti-hallucination invariant.",
    )
    behavior: Behavior
    attack_chains: list[AttackChain] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
