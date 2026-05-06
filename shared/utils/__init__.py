"""Cross-directory utilities used by every pipeline stage."""

from shared.utils.hashing import (
    compute_cache_key,
    compute_pipeline_fingerprint_hash,
    sha256_bytes,
    sha256_file,
    sha256_text,
)
from shared.utils.logging import get_logger, setup_logging
from shared.utils.policy import (
    DEFAULT_POLICY_PATH,
    CachePolicy,
    load_cache_policy,
    resolve_policy,
)
from shared.utils.schema import load_label_schema
from shared.utils.scoring import (
    PASS2_UNCERTAINTY_THRESHOLD,
    MaliciousnessResult,
    compute_verdict,
    finding_confidence_from_logprobs,
    should_escalate_to_pass2,
)
from shared.utils.tokens import approx_token_count

__all__ = [
    "DEFAULT_POLICY_PATH",
    "PASS2_UNCERTAINTY_THRESHOLD",
    "CachePolicy",
    "MaliciousnessResult",
    "approx_token_count",
    "compute_cache_key",
    "compute_pipeline_fingerprint_hash",
    "compute_verdict",
    "finding_confidence_from_logprobs",
    "get_logger",
    "load_cache_policy",
    "load_label_schema",
    "resolve_policy",
    "setup_logging",
    "sha256_bytes",
    "sha256_file",
    "sha256_text",
    "should_escalate_to_pass2",
]
