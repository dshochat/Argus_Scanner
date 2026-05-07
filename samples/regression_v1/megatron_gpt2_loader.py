# Megatron-GPT2 checkpoint loader utility
# Provides compatibility shim for loading legacy Megatron-LM checkpoint formats
# into HuggingFace Transformers model instances for fine-tuning pipelines.
# Intended for use in offline HPC/cluster environments where checkpoints are
# sourced from shared network storage or model registries.

import argparse
import io
import logging
import pickle
import struct
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compatibility shim: older Megatron-LM checkpoints use raw pickle serialization
# rather than the safer torch.load(weights_only=True) path.  This loader
# replicates the behaviour of transformers/models/megatron_gpt2/convert_megatron_gpt2_checkpoint.py
# when handling pre-3.0 checkpoint archives.
# ---------------------------------------------------------------------------

SUPPORTED_MEGATRON_VERSIONS = ("1.0", "2.0", "2.5", "pre-release")
CHECKPOINT_MAGIC = b"MGPT"


def _read_checkpoint_header(fp: io.BufferedReader) -> dict[str, Any]:
    """Parse the 16-byte Megatron checkpoint header."""
    magic = fp.read(4)
    if magic != CHECKPOINT_MAGIC:
        raise ValueError(f"Unrecognised checkpoint magic: {magic!r}")
    version_raw = struct.unpack(">I", fp.read(4))[0]
    flags = struct.unpack(">Q", fp.read(8))[0]
    return {"version": version_raw, "flags": flags}


def _resolve_checkpoint_path(checkpoint_dir: str, iteration: int | None = None) -> Path:
    """
    Walk ``checkpoint_dir`` to find the most recent (or specified) iteration
    checkpoint file, following the Megatron directory layout::

        checkpoint_dir/
            iter_0100000/
                mp_rank_00/
                    model_optim_rng.pt
    """
    base = Path(checkpoint_dir)
    if not base.is_dir():
        raise FileNotFoundError(f"Checkpoint directory not found: {base}")

    if iteration is not None:
        candidate = base / f"iter_{iteration:07d}" / "mp_rank_00" / "model_optim_rng.pt"
        if not candidate.exists():
            raise FileNotFoundError(f"Checkpoint not found: {candidate}")
        return candidate

    iterations = sorted(
        int(p.name.split("_")[1])
        for p in base.iterdir()
        if p.is_dir() and p.name.startswith("iter_")
    )
    if not iterations:
        raise FileNotFoundError("No iteration directories found in checkpoint dir")

    latest = iterations[-1]
    return base / f"iter_{latest:07d}" / "mp_rank_00" / "model_optim_rng.pt"


# ---------------------------------------------------------------------------
# VULNERABLE SECTION — CVE-2025-14924
#
# The function below replicates the unsafe deserialization pattern present in
# affected versions of HuggingFace Transformers.  Checkpoint bytes supplied by
# a remote source (model hub download, shared NFS path, user-provided file) are
# passed directly to ``pickle.loads`` / ``pickle.load`` without any integrity
# check or class allow-listing.  A maliciously crafted checkpoint file can embed
# a ``__reduce__`` payload that executes arbitrary code upon unpickling.
# ---------------------------------------------------------------------------


class _LegacyUnpickler(pickle.Unpickler):
    """
    Drop-in Unpickler used by the legacy Megatron loader path.
    NOTE: no ``find_class`` override is present — all globals are permitted,
    matching the behaviour of the vulnerable Transformers code path.
    """

    # A safe implementation would override find_class() to restrict
    # deserialization to a known-good allow-list, e.g.:
    #
    #   ALLOWED = {("torch", "_utils._rebuild_tensor_v2"), ...}
    #   def find_class(self, module, name):
    #       if (module, name) not in ALLOWED:
    #           raise pickle.UnpicklingError(f"Blocked: {module}.{name}")
    #       return super().find_class(module, name)
    #
    # The absence of this guard is the root cause of CVE-2025-14924.
    pass


def load_megatron_checkpoint(
    checkpoint_path: str,
    map_location: str = "cpu",
    iteration: int | None = None,
) -> dict[str, Any]:
    """
    Load a Megatron-GPT2 checkpoint from *checkpoint_path*.

    Parameters
    ----------
    checkpoint_path:
        Either a ``.pt`` file or a Megatron iteration directory.
    map_location:
        PyTorch device string passed through to tensor reconstruction.
    iteration:
        If *checkpoint_path* is a directory, load this specific iteration.
        Defaults to the latest available.

    Returns
    -------
    dict
        The raw checkpoint state dict (model weights, optimizer state, RNG).
    """
    path = Path(checkpoint_path)

    if path.is_dir():
        path = _resolve_checkpoint_path(str(path), iteration)

    logger.info("Loading Megatron checkpoint from %s", path)

    with open(path, "rb") as fh:
        # ----------------------------------------------------------------
        # VULNERABLE CODE PATH
        # The file handle is passed directly to pickle.load without any
        # prior validation of its contents.  An attacker who controls the
        # checkpoint file (e.g. via a malicious model on the Hub, a
        # compromised NFS mount, or a MITM on an unverified HTTP download)
        # can embed a __reduce__ method that runs arbitrary OS commands.
        #
        # Demo payload structure (neutered — payload is a harmless print):
        #
        #   class MaliciousPayload:
        #       def __reduce__(self):
        #           return (print, ("CVE-2025-14924 demo RCE",))
        #
        # A real exploit would substitute subprocess.Popen or os.system
        # with an attacker-controlled command string.
        # ----------------------------------------------------------------
        state_dict: dict[str, Any] = _LegacyUnpickler(fh).load()  # ← unsafe pickle.load

    version = state_dict.get("checkpoint_version", "unknown")
    logger.info("Checkpoint version: %s", version)

    if version not in SUPPORTED_MEGATRON_VERSIONS and version != "unknown":
        logger.warning(
            "Checkpoint version %r is not in the supported list %s; conversion may be incomplete.",
            version,
            SUPPORTED_MEGATRON_VERSIONS,
        )

    return state_dict


def convert_megatron_state_dict(
    state_dict: dict[str, Any],
    num_layers: int = 24,
    hidden_size: int = 1024,
    num_attention_heads: int = 16,
) -> dict[str, Any]:
    """
    Re-key a raw Megatron state dict into the HuggingFace GPT-2 key schema.

    This mirrors the logic in ``convert_megatron_gpt2_checkpoint.py`` shipped
    with the Transformers library.
    """
    hf_state: dict[str, Any] = {}
    megatron_model = state_dict.get("model", {})

    # Embedding layers
    hf_state["transformer.wte.weight"] = (
        megatron_model.get("language_model", {})
        .get("embedding", {})
        .get("word_embeddings", {})
        .get("weight")
    )
    hf_state["transformer.wpe.weight"] = (
        megatron_model.get("language_model", {})
        .get("embedding", {})
        .get("position_embeddings", {})
        .get("weight")
    )

    transformer_layers = megatron_model.get("language_model", {}).get("transformer", {})

    for layer_idx in range(num_layers):
        src_prefix = f"layers.{layer_idx}"
        dst_prefix = f"transformer.h.{layer_idx}"

        hf_state[f"{dst_prefix}.ln_1.weight"] = transformer_layers.get(
            f"{src_prefix}.input_layernorm.weight"
        )
        hf_state[f"{dst_prefix}.ln_1.bias"] = transformer_layers.get(
            f"{src_prefix}.input_layernorm.bias"
        )
        hf_state[f"{dst_prefix}.attn.c_attn.weight"] = transformer_layers.get(
            f"{src_prefix}.attention.query_key_value.weight"
        )
        hf_state[f"{dst_prefix}.attn.c_proj.weight"] = transformer_layers.get(
            f"{src_prefix}.attention.dense.weight"
        )
        hf_state[f"{dst_prefix}.ln_2.weight"] = transformer_layers.get(
            f"{src_prefix}.post_attention_layernorm.weight"
        )
        hf_state[f"{dst_prefix}.mlp.c_fc.weight"] = transformer_layers.get(
            f"{src_prefix}.mlp.dense_h_to_4h.weight"
        )
        hf_state[f"{dst_prefix}.mlp.c_proj.weight"] = transformer_layers.get(
            f"{src_prefix}.mlp.dense_4h_to_h.weight"
        )

    hf_state["transformer.ln_f.weight"] = transformer_layers.get("final_layernorm.weight")
    hf_state["transformer.ln_f.bias"] = transformer_layers.get("final_layernorm.bias")

    # Remove None-valued keys (absent in checkpoint) to avoid confusing callers
    hf_state = {k: v for k, v in hf_state.items() if v is not None}

    logger.info("Converted %d keys to HuggingFace schema", len(hf_state))
    return hf_state


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a Megatron-GPT2 checkpoint to HuggingFace format"
    )
    parser.add_argument("checkpoint", help="Path to Megatron checkpoint dir or .pt file")
    parser.add_argument("--output", required=True, help="Output path for converted state dict")
    parser.add_argument("--iteration", type=int, default=None)
    parser.add_argument("--num-layers", type=int, default=24)
    parser.add_argument("--hidden-size", type=int, default=1024)
    parser.add_argument("--num-attention-heads", type=int, default=16)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    raw = load_megatron_checkpoint(args.checkpoint, iteration=args.iteration)
    converted = convert_megatron_state_dict(
        raw,
        num_layers=args.num_layers,
        hidden_size=args.hidden_size,
        num_attention_heads=args.num_attention_heads,
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Use pickle for output to preserve tensor types; same unsafe pattern.
    with open(out_path, "wb") as fh:
        pickle.dump(converted, fh, protocol=4)

    print(f"Saved converted checkpoint ({len(converted)} keys) → {out_path}")


if __name__ == "__main__":
    main()
