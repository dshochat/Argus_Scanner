"""Cache policy loader and four-layer resolver.

Resolution order (highest priority last):

    default → deployment_profile → customer_overrides → runtime_flags

The resolved policy is deep-merged, then hashed; that hash is stored in
``pipeline_fingerprint.cache_policy.policy_hash`` so policy drift is auditable.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import yaml

from shared.utils.hashing import sha256_text

# docs/cache_policy.yaml is the source of truth.
DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "docs" / "cache_policy.yaml"

CachePolicy = dict[str, Any]


def load_cache_policy(path: str | Path | None = None) -> CachePolicy:
    """Load the cache policy YAML. Returns the full dict (default + profiles)."""
    p = Path(path) if path is not None else DEFAULT_POLICY_PATH
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursive dict merge. Overlay wins. Lists are replaced, not concatenated."""
    out = copy.deepcopy(base)
    for k, v in overlay.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def resolve_policy(
    policy: CachePolicy,
    *,
    deployment_profile: str = "default",
    customer_overrides: dict[str, Any] | None = None,
    runtime_flags: dict[str, Any] | None = None,
) -> tuple[CachePolicy, str]:
    """Resolve the four-layer policy stack for a single scan.

    Returns the merged policy plus its SHA-256 hash (stored in the pipeline
    fingerprint for audit).
    """
    # Extract the "default" base — everything at top-level except the
    # profile/override/runtime sections.
    base_keys = {
        "global",
        "file_cache",
        "dependency_cache",
        "entity_cache",
        "framework_baselines",
    }
    base: dict[str, Any] = {k: policy[k] for k in base_keys if k in policy}

    # Layer 2: deployment profile overrides
    profiles = policy.get("deployment_profiles", {})
    if deployment_profile != "default" and deployment_profile in profiles:
        base = _deep_merge(base, profiles[deployment_profile])

    # Layer 3: customer overrides (boundaries enforced by caller per allowed_overrides)
    if customer_overrides:
        base = _deep_merge(base, customer_overrides)

    # Layer 4: runtime flags (one-off CLI/API overrides for a single scan)
    if runtime_flags:
        base = _deep_merge(base, {"_runtime_flags": runtime_flags})

    policy_hash = sha256_text(json.dumps(base, sort_keys=True, separators=(",", ":"), default=str))
    return base, policy_hash
