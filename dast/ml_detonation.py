"""DAST detonation plan templates for ML model artifacts.

The point of pickle / PyTorch model security is that *loading is execution*:
``pickle.load()`` and ``torch.load()`` evaluate ``__reduce__`` opcodes the
moment the file is parsed, which is why a malicious ``.pkl`` is RCE on
the victim's machine the second they call ``torch.load(model.pt)``.

This module builds a deterministic Phase-A-shaped plan dict — the same
shape the model-driven Phase A planner emits — that loads the artifact
in a sandbox and watches what happens. The cascade's static report
already flagged the suspicious globals; DAST is what upgrades the
verdict from "looks like ``os.system`` is in there" to **"loading
this file caused ``os.system('echo pwned')`` to actually fire in the
sandbox."**

Plans built here are deterministic — no model call is needed to generate
the command. The orchestrator can prepend them to the model's plan list
on iter 1 for any file the engine recognized as an ML model artifact.

Supported formats / loaders:

==================  ============================================
extension / format  loader command (run in sandbox)
==================  ============================================
``.pkl``/``.pickle`` ``python -c "import sys, pickle; pickle.load(open(sys.argv[1],'rb'))"``
``.pt``              ``python -c "import sys, torch; torch.load(sys.argv[1], map_location='cpu', weights_only=False)"``
``.bin``             same as ``.pt`` (Hugging Face's pickle-shaped weight blobs)
``.safetensors``     ``python -c "import sys; from safetensors import safe_open; f = safe_open(sys.argv[1],'pt'); print(list(f.keys()))"``
``.h5``/``.hdf5``    ``python -c "import sys, h5py; print(list(h5py.File(sys.argv[1]).keys()))"``
``.onnx``            ``python -c "import sys, onnx; onnx.load(sys.argv[1])"``
==================  ============================================

The pickle / pytorch / bin loaders are deliberately UNSAFE
(``weights_only=False``, raw ``pickle.load``) — that's the whole point.
A safe loader would not detonate the payload, which means it would not
prove exploitability. The sandbox is the containment boundary, not the
loader.
"""

from __future__ import annotations

import base64
from typing import Any

# ── Format → loader command ────────────────────────────────────────────────


def _python_oneliner(body: str) -> str:
    """Wrap a one-line Python expression in ``python -c "..."`` with the
    workspace path interpolated. Single quotes inside the body are
    escaped to avoid shell-quoting collisions."""
    escaped = body.replace('"', r"\"")
    return f'python -c "{escaped}"'


_LOADER_TEMPLATES: dict[str, str] = {
    "pickle": _python_oneliner(
        "import sys, pickle; "
        "obj = pickle.load(open(sys.argv[1], 'rb')); "
        "print('PICKLE_LOAD_COMPLETED', type(obj).__name__)"
    )
    + " /workspace/{file_name}",
    "pytorch": _python_oneliner(
        "import sys, torch; "
        "obj = torch.load(sys.argv[1], map_location='cpu', weights_only=False); "
        "print('TORCH_LOAD_COMPLETED', type(obj).__name__)"
    )
    + " /workspace/{file_name}",
    "safetensors": _python_oneliner(
        "import sys; from safetensors import safe_open; "
        "f = safe_open(sys.argv[1], 'pt'); "
        "ks = list(f.keys()); meta = f.metadata() or {}; "
        "print('SAFETENSORS_OPENED tensors=' + str(len(ks)) + ' metadata_keys=' + str(list(meta.keys())))"
    )
    + " /workspace/{file_name}",
    "hdf5": _python_oneliner(
        "import sys, h5py; with h5py.File(sys.argv[1], 'r') as f: print('H5_OPENED keys=' + str(list(f.keys())[:10]))"
    )
    + " /workspace/{file_name}",
    "onnx": _python_oneliner(
        "import sys, onnx; "
        "m = onnx.load(sys.argv[1]); "
        "print('ONNX_LOADED producer=' + str(m.producer_name) + ' opset=' + str([o.version for o in m.opset_import]))"
    )
    + " /workspace/{file_name}",
}


# ── Format detection ───────────────────────────────────────────────────────

_ZIP_MAGIC = b"PK\x03\x04"
_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_PICKLE_PROTO_MAGIC = bytes([0x80])


def detect_format(file_name: str, head_bytes: bytes) -> str | None:
    """Return one of ``pickle`` / ``pytorch`` / ``safetensors`` / ``hdf5``
    / ``onnx`` based on extension + magic-byte sniff. Returns ``None``
    when the file isn't a recognized ML artifact."""
    name = file_name.lower()
    head = head_bytes[:8] if head_bytes else b""

    if head.startswith(_ZIP_MAGIC):
        # PyTorch saves >= 1.6 are zipfiles. Some HuggingFace .bin files
        # are too. We treat all zip-shaped ML artifacts as pytorch.
        if name.endswith((".pt", ".bin", ".pickle", ".pkl")):
            return "pytorch"
        return None
    if head.startswith(_HDF5_MAGIC) or name.endswith((".h5", ".hdf5", ".keras")):
        return "hdf5"
    if name.endswith(".safetensors"):
        return "safetensors"
    if name.endswith(".onnx"):
        return "onnx"
    if head.startswith(_PICKLE_PROTO_MAGIC):
        return "pickle"
    if name.endswith((".pkl", ".pickle")):
        return "pickle"
    if name.endswith((".pt", ".bin")):
        # Old PyTorch saves were raw pickle, not zip
        return "pytorch"
    return None


# ── Plan construction ──────────────────────────────────────────────────────


def build_ml_load_plan(
    *,
    file_name: str,
    file_id: str,
    hypothesis_id: str,
    original_bytes: bytes,
) -> dict[str, Any] | None:
    """Build a Phase-A-shaped plan dict that loads the artifact in the
    sandbox.

    Returns ``None`` when the file isn't a recognized ML artifact —
    callers should fall back to the model-driven plan path.

    The returned dict is the same shape ``build_phase_a_plan_prompt``'s
    ``plans[]`` array carries:
    * ``hypothesis_id`` — the L1 finding being verified
    * ``plan_status`` — always ``"executable"`` for ML detonations
    * ``commands`` — list of shell commands the sandbox runs
    * ``oracle`` — what kind of side-effect would prove exploitability
    * ``payload`` — base64-encoded original bytes (sandbox stages this
      at ``/workspace/<file_name>``)
    * ``timeout_sec`` — generous (60s) because some torch.load calls do
      a lot of I/O before the malicious __reduce__ fires
    * ``image_hint`` — ``ml_tools`` because we need torch / safetensors
      / h5py / onnx pre-installed
    * ``rationale`` — human-readable explanation of why this plan exists
    """
    fmt = detect_format(file_name, original_bytes[:32])
    if fmt is None:
        return None

    loader_template = _LOADER_TEMPLATES[fmt]
    # Use str.replace, NOT str.format — the python -c body contains
    # literal {} (e.g. ``meta = f.metadata() or {}``) that .format()
    # would mis-interpret as positional placeholders.
    command = loader_template.replace("{file_name}", file_name)

    # Oracle: the strongest signal for a malicious load is a side-effect
    # the loader's documented behavior would NOT produce — a syscall to
    # ``execve`` / ``socket`` / unexpected file write, etc. The cascade
    # already knows the format-expected behavior; the verdict prompt
    # treats everything else as evidence of exploit.
    oracle = "execution_output_with_side_effect_observation"

    payload_b64 = base64.b64encode(original_bytes).decode("ascii")

    return {
        "hypothesis_id": hypothesis_id,
        "plan_status": "executable",
        "commands": [command],
        "oracle": oracle,
        "payload": payload_b64,
        "payload_encoding": "base64",
        "timeout_sec": 60,
        "image_hint": "ml_tools",
        "rationale": (
            f"ML artifact detonation ({fmt}). Loading the file is the "
            f"primary attack surface: pickle/torch.load() runs __reduce__ "
            f"opcodes, h5py.File() reads attribute strings, etc. Watch "
            f"the trace for syscalls / network egress / process spawns "
            f"during the load — the documented loader does not produce "
            f"those, so any such event upgrades the verdict to CONFIRMED."
        ),
    }


def synthesize_ml_load_hypothesis(
    *,
    hypothesis_id: str = "HML_LOAD",
    file_format: str,
) -> dict[str, Any]:
    """Build a synthetic L1-style hypothesis the orchestrator can plan
    against. Used when the engine reaches DAST with NO model-emitted
    findings on an ML artifact — we still want to detonate the load
    in the sandbox to surface any latent payload.

    Shape mirrors what ``_scan_result_to_l1_output`` produces from a
    real ``ScanResult.vulnerabilities[i]``."""
    return {
        "id": hypothesis_id,
        "finding_ref": hypothesis_id,
        "finding_type": "ml_artifact_load_rce",
        "severity": "critical",
        "explanation": (
            f"Loading a {file_format} artifact is the canonical RCE primitive "
            "for that format. The model file's own bytecode-level "
            "instructions execute during deserialization. Argus builds a "
            "deterministic load plan and watches for side effects."
        ),
        "code_snippet": "(binary artifact — see preprocessing report)",
        "line": None,
        "data_flow_trace": "load_call -> __reduce__ -> arbitrary callable",
        "proof_of_concept": (
            "import pickle; pickle.load(open('artifact', 'rb'))  # OR torch.load('artifact', weights_only=False)"
        ),
        "cwe": "CWE-502",
        "confidence": 1.0,
    }


__all__ = [
    "build_ml_load_plan",
    "detect_format",
    "synthesize_ml_load_hypothesis",
]
