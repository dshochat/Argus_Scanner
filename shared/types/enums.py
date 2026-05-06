"""Canonical enums derived from docs/label_schema_v3.1.json.

The label schema is the contract. Any change here must match the schema JSON.
"""

from __future__ import annotations

from enum import Enum


class LabelModel(str, Enum):
    HAIKU = "haiku"
    SONNET = "sonnet"
    OPUS = "opus"


class Origin(str, Enum):
    REAL_SCRAPED = "real_scraped"
    SYNTHETIC_GENERATED = "synthetic_generated"


class AttackCategory(str, Enum):
    CLEAN = "clean"
    ADVERSARIAL_CLEAN = "adversarial_clean"
    ADVERSARIAL_VULNERABLE = "adversarial_vulnerable"  # v3.1
    VULNERABLE = "vulnerable"
    ATTACK_CHAIN = "attack_chain"
    AI_TOOL = "ai_tool"
    SUPPLY_CHAIN = "supply_chain"
    MALWARE = "malware"


class PatchStatus(str, Enum):
    UNPATCHED = "unpatched"
    PATCHED = "patched"
    PARTIALLY_PATCHED = "partially_patched"
    UNKNOWN = "unknown"


class TrainingDataType(str, Enum):
    TYPE_A_STANDARD = "type_a_standard"
    TYPE_B_CVE_ENRICHED = "type_b_cve_enriched"
    TYPE_C_VULN_PAIR = "type_c_vuln_pair"
    TYPE_C_PATCHED_PAIR = "type_c_patched_pair"
    TYPE_C_REFACTOR_PAIR = "type_c_refactor_pair"  # v3.1 anti-bias
    TYPE_D_HARD_NEGATIVE = "type_d_hard_negative"
    TYPE_E_ADVERSARIAL_VULNERABLE = "type_e_adversarial_vulnerable"  # v3.1


class Ecosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"
    GO = "go"
    MAVEN = "maven"
    RUBYGEMS = "rubygems"
    CRATES = "crates"
    NUGET = "nuget"
    OTHER = "other"


class FileType(str, Enum):
    SCRIPT = "script"
    LIBRARY = "library"
    CONFIG = "config"
    IAC = "iac"
    DOCKERFILE = "dockerfile"
    CI_PIPELINE = "ci_pipeline"
    MCP_CONFIG = "mcp_config"
    AGENT_CONFIG = "agent_config"
    AI_MODEL_FILE = "ai_model_file"
    PACKAGE_MANIFEST = "package_manifest"
    DATA_FILE = "data_file"
    DOCUMENTATION = "documentation"
    SHELL_SCRIPT = "shell_script"
    PATH_CONFIG = "path_config"
    POSTINSTALL_HOOK = "postinstall_hook"
    SETUP_SCRIPT = "setup_script"  # v3.1
    UNKNOWN = "unknown"


class ScanDepth(str, Enum):
    FULL = "full"
    EXTRACTION_ONLY = "extraction_only"
    CLASSIFICATION_ONLY = "classification_only"
    SKIP = "skip"


class Pass2Reason(str, Enum):
    OBFUSCATED_PAYLOAD = "obfuscated_payload"
    DYNAMIC_EXECUTION = "dynamic_execution"
    NETWORK_BEHAVIOR = "network_behavior"
    COMPLEX_DATA_FLOW = "complex_data_flow"
    AI_TOOL_INTERACTION = "ai_tool_interaction"
    MEMORY_UNSAFE_WITH_EXTERNAL_INPUT = "memory_unsafe_with_external_input"
    NONE = "none"


class SecretType(str, Enum):
    API_KEY = "api_key"
    AWS_CREDENTIALS = "aws_credentials"
    GCP_CREDENTIALS = "gcp_credentials"
    AZURE_CREDENTIALS = "azure_credentials"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"
    CONNECTION_STRING = "connection_string"
    OAUTH_SECRET = "oauth_secret"
    JWT_TOKEN = "jwt_token"
    SSH_KEY = "ssh_key"
    CRYPTO_WALLET_KEY = "crypto_wallet_key"
    WEBHOOK_URL = "webhook_url"
    GENERIC_SECRET = "generic_secret"
    AI_PLATFORM_CREDENTIAL = "ai_platform_credential"  # v3.1


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SeverityExt(str, Enum):
    """Severity including 'informational' used by findings/behavior.sensitivity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    NONE = "none"


class SecretContext(str, Enum):
    ENV_VAR_IN_CONFIG = "env_var_in_config"
    HARDCODED_IN_SOURCE = "hardcoded_in_source"
    COMMENT = "comment"
    ENV_FILE = "env_file"
    CI_PIPELINE_VAR = "ci_pipeline_var"
    PACKAGE_METADATA = "package_metadata"


class IpContext(str, Enum):
    TARGET = "target"
    SOURCE = "source"
    CONFIG = "config"
    SUSPICIOUS = "suspicious"
    METADATA_ENDPOINT = "metadata_endpoint"
    C2 = "c2"
    INTERNAL = "internal"


class DomainContext(str, Enum):
    API_ENDPOINT = "api_endpoint"
    C2_SUSPECT = "c2_suspect"
    EXFILTRATION_TARGET = "exfiltration_target"
    CDN = "cdn"
    INTERNAL = "internal"
    PACKAGE_REGISTRY = "package_registry"
    CLOUD_SERVICE = "cloud_service"
    UNKNOWN = "unknown"


class EntityType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    CLOUD_RESOURCE = "cloud_resource"
    OTHER_INDICATOR = "other_indicator"


class FileOperation(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    LIST = "list"


class CapabilityTag(str, Enum):
    NETWORK_OUTBOUND = "network_outbound"
    NETWORK_LISTEN = "network_listen"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    PROCESS_SPAWN = "process_spawn"
    PROCESS_INJECT = "process_inject"
    ENV_ACCESS = "env_access"
    REGISTRY_ACCESS = "registry_access"
    CRYPTO_OPERATIONS = "crypto_operations"
    DYNAMIC_EXECUTION = "dynamic_execution"
    CODE_GENERATION = "code_generation"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_ACCESS = "credential_access"
    SYSTEM_RECONNAISSANCE = "system_reconnaissance"
    DATA_COLLECTION = "data_collection"
    DATA_ENCODING = "data_encoding"
    DATA_EXFILTRATION = "data_exfiltration"
    CONTAINER_ESCAPE = "container_escape"
    CLOUD_API_ACCESS = "cloud_api_access"
    C2_COMMUNICATION = "c2_communication"
    LATERAL_MOVEMENT = "lateral_movement"
    DEFENSE_EVASION = "defense_evasion"
    AI_TOOL_INTERACTION = "ai_tool_interaction"
    AI_PROVIDER_REDIRECT = "ai_provider_redirect"  # v3.1


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    CONNECT = "CONNECT"
    WEBSOCKET = "WEBSOCKET"
    UNKNOWN = "unknown"


class EnvVarRiskCategory(str, Enum):
    """v3.1: Risk-domain classification for environment variables."""

    CREDENTIAL = "credential"
    AI_ORCHESTRATION = "ai_orchestration"
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    UNKNOWN = "unknown"


class ObfuscationTechnique(str, Enum):
    BASE64 = "base64"
    HEX = "hex"
    ROT13 = "rot13"
    XOR = "xor"
    EXEC_CHAIN = "exec_chain"
    EVAL_CHAIN = "eval_chain"
    STRING_CONCAT = "string_concat"
    UNICODE_ESCAPE = "unicode_escape"
    ZLIB_COMPRESS = "zlib_compress"
    MARSHAL = "marshal"
    CUSTOM_ENCODING = "custom_encoding"


class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    MALWARE_BEHAVIOR = "malware_behavior"
    MISCONFIGURATION = "misconfiguration"
    SECRET_EXPOSURE = "secret_exposure"
    SUPPLY_CHAIN_RISK = "supply_chain_risk"
    PRIVILEGE_ISSUE = "privilege_issue"
    DATA_EXPOSURE = "data_exposure"
    AI_SAFETY_ISSUE = "ai_safety_issue"
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    DATA_EXFILTRATION = "data_exfiltration"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    RACE_CONDITION = "race_condition"
    DESERIALIZATION = "deserialization"


class ConfidenceLabel(str, Enum):
    """v3.1: Model's categorical confidence. Float is pipeline-computed from logprobs."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ValidatedBy(str, Enum):
    STATIC_ONLY = "static_only"
    EXECUTION_CONFIRMED = "execution_confirmed"
    EXECUTION_REJECTED = "execution_rejected"
    DETERMINISTIC_ORACLE = "deterministic_oracle"


class VerdictLabel(str, Enum):
    """Maliciousness anchors. The system computes 0-100 score via logprob expectation."""

    CLEAN = "clean"
    INFORMATIONAL = "informational"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL_MALICIOUS = "critical_malicious"


class RecommendedAction(str, Enum):
    NO_ACTION = "no_action"
    REVIEW_FINDINGS = "review_findings"
    FIX_BEFORE_DEPLOY = "fix_before_deploy"
    QUARANTINE = "quarantine"
    DELETE_AND_ROTATE_CREDENTIALS = "delete_and_rotate_credentials"


class ValidationStatus(str, Enum):
    STATIC_ONLY = "static_only"
    EXECUTION_VALIDATED = "execution_validated"
    EXECUTION_PARTIAL = "execution_partial"


class HypothesisType(str, Enum):
    EXPLOITABILITY_TEST = "exploitability_test"
    REACHABILITY_TEST = "reachability_test"
    CHAIN_VALIDATION = "chain_validation"
    CRASH_TEST = "crash_test"
    STATEFUL_MULTI_STEP = "stateful_multi_step"  # v3.1


class OracleType(str, Enum):
    ASAN = "asan"
    UBSAN = "ubsan"
    TSAN = "tsan"
    LSAN = "lsan"
    EXECUTION_OUTPUT = "execution_output"
    MOCK_SERVER = "mock_server"
    FILE_ACCESS = "file_access"
    DETERMINISTIC = "deterministic"


class EnvironmentComplexity(str, Enum):
    """v3.1: Code Agent supports single_process + some multi_process."""

    SINGLE_PROCESS = "single_process"
    MULTI_PROCESS = "multi_process"
    MULTI_SERVICE = "multi_service"
    DISTRIBUTED = "distributed"


class AttackChainLikelihood(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SandboxType(str, Enum):
    FIRECRACKER = "firecracker"
    GVISOR = "gvisor"
    KATA = "kata"
    DOCKER_SECCOMP = "docker_seccomp"


class HypothesisResult(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTABLE = "not_testable"
    POLICY_BLOCKED = "policy_blocked"


class CveFeedSourceType(str, Enum):
    LIVE_SCRAPER = "live_scraper"
    ECHOFEED_BUNDLE = "echofeed_bundle"
    MANUAL_IMPORT = "manual_import"


class CacheInvalidationReason(str, Enum):
    TTL_EXPIRED = "ttl_expired"
    CVE_UPDATE = "cve_update"
    MODEL_UPDATE = "model_update"
    PARSER_UPDATE = "parser_update"
    SCHEMA_VERSION_CHANGE = "schema_version_change"
    SCANNER_VERSION_CHANGE = "scanner_version_change"
    POLICY_RULES_UPDATE = "policy_rules_update"
    INTELLIGENCE_CACHE_REFRESH = "intelligence_cache_refresh"
    MANUAL_RESCAN = "manual_rescan"
    PASS2_BUDGET_RETRY = "pass2_budget_retry"


class DetectionSource(str, Enum):
    REGEX_CONFIRMED = "regex_confirmed"
    REGEX_FLAGGED_LLM_REJECTED = "regex_flagged_llm_rejected"
    REGEX_FLAGGED_LLM_CONFIRMED = "regex_flagged_llm_confirmed"
    SCANNER_MISSED_LLM_FOUND = "scanner_missed_llm_found"


# Maliciousness score anchors — see shared/utils/scoring.py for derivation.
VERDICT_ANCHORS: dict[str, int] = {
    VerdictLabel.CLEAN.value: 0,
    VerdictLabel.INFORMATIONAL.value: 25,
    VerdictLabel.SUSPICIOUS.value: 50,
    VerdictLabel.MALICIOUS.value: 75,
    VerdictLabel.CRITICAL_MALICIOUS.value: 100,
}
