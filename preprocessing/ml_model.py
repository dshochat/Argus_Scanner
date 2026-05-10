"""ML model file inspection — pickle / PyTorch / safetensors / ONNX / HDF5.

Argus's threat model includes hostile model artifacts: an attacker uploads
a ``.pkl`` / ``.pt`` / ``.bin`` to a model registry, a victim calls
``torch.load(...)`` or ``pickle.load(...)``, and arbitrary code runs.
Pickle's ``REDUCE`` / ``BUILD`` / ``NEWOBJ`` opcodes can reference any
importable callable — ``posix.system``, ``subprocess.Popen``,
``__builtin__.eval`` — so the malicious payload is the bytecode itself,
not the tensor data.

This module disassembles model artifacts WITHOUT executing them. We use
the stdlib ``pickletools.genops`` (and ``pickletools.dis``) which only
parses the opcode stream — no callable is ever resolved or invoked.
The output is a textual summary of suspicious findings that the rest
of the preprocessing pipeline can route into the cascade as if it were
a flat Python source.

Supported formats:
* ``.pkl``, ``.pickle`` — raw Python pickle
* ``.pt`` — PyTorch checkpoints (zipfile of pickles, plus tensors)
* ``.bin`` — Hugging Face's pickle-shaped weight blobs (zipfile or raw pickle)
* ``.safetensors`` — JSON-prefixed binary; parse the metadata header
* ``.h5``, ``.hdf5`` — HDF5 magic-byte recognition (deep inspection
  requires h5py; flagged as recognized but not deeply parsed in v1)
* ``.onnx`` — Protocol Buffer header recognition (no proto parsing in v1)
"""

from __future__ import annotations

import io
import json
import pickletools
import zipfile
from dataclasses import dataclass, field

# ── Suspicious-globals catalog ──────────────────────────────────────────────
# A pickle can call ANY importable callable via REDUCE. The set below is
# the canonical "what malware reaches for" vocabulary. We surface every
# match so the model cascade has explicit evidence.

_SUSPICIOUS_MODULES: frozenset[str] = frozenset(
    {
        # Code execution
        "os",
        "posix",
        "nt",
        "subprocess",
        "commands",
        "pty",
        "platform",
        # Network
        "socket",
        "urllib",
        "urllib2",
        "urllib3",
        "requests",
        "http.client",
        "httplib",
        "ftplib",
        # Code loading
        "builtins",
        "__builtin__",
        "importlib",
        "imp",
        # Filesystem
        "shutil",
        "tempfile",
        # Eval primitives (named globals)
        "compile",
    }
)

#: Tighter list of (module, name) pairs that are unambiguous code-exec
#: primitives. Hits here are P0 critical regardless of any context.
_SUSPICIOUS_GLOBALS: frozenset[tuple[str, str]] = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("os", "execv"),
        ("os", "execve"),
        ("os", "execvp"),
        ("os", "execvpe"),
        ("os", "exec"),
        ("os", "spawnv"),
        ("os", "spawnve"),
        ("posix", "system"),
        ("posix", "exec"),
        ("nt", "system"),
        ("subprocess", "Popen"),
        ("subprocess", "call"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("subprocess", "run"),
        ("subprocess", "getoutput"),
        ("subprocess", "getstatusoutput"),
        ("pty", "spawn"),
        ("commands", "getoutput"),
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("builtins", "compile"),
        ("builtins", "__import__"),
        ("__builtin__", "eval"),
        ("__builtin__", "exec"),
        ("__builtin__", "compile"),
        ("__builtin__", "__import__"),
        ("importlib", "import_module"),
        ("imp", "load_source"),
        ("imp", "load_module"),
        ("socket", "socket"),
        ("urllib.request", "urlopen"),
        ("urllib", "urlopen"),
        ("requests", "get"),
        ("requests", "post"),
        ("requests", "request"),
        ("httplib", "HTTPConnection"),
        ("http.client", "HTTPConnection"),
    }
)


@dataclass
class MLModelDecomposition:
    """Result of inspecting an ML model artifact."""

    is_valid: bool
    """True when the format was parseable."""

    format: str
    """One of: ``pickle`` / ``pytorch_zip`` / ``safetensors`` / ``onnx`` /
    ``hdf5`` / ``unknown``."""

    synthesized_source: str
    """Textual summary the cascade can read as Python-with-comments.

    Always populated, even when no suspicious findings — the cascade gets
    enough context to render a verdict."""

    suspicious_globals: list[str] = field(default_factory=list)
    """Sorted, deduplicated ``module.name`` strings — every GLOBAL/STACK_GLOBAL
    opcode whose target is in the suspicious catalog."""

    code_exec_primitives: list[str] = field(default_factory=list)
    """Subset of ``suspicious_globals`` that hits ``_SUSPICIOUS_GLOBALS`` —
    unambiguous RCE primitives (``os.system``, ``subprocess.Popen``, etc.)."""

    has_reduce_op: bool = False
    """True when the pickle stream contains a ``REDUCE`` / ``BUILD`` /
    ``NEWOBJ`` / ``INST`` / ``OBJ`` opcode — the constructs that turn a
    pickled global into a callable invocation."""

    n_opcodes: int = 0

    metadata: dict[str, str] = field(default_factory=dict)
    """Format-specific metadata (e.g., safetensors ``__metadata__`` block,
    pytorch model archive listing). Stringified for safe display."""

    parse_error: str | None = None


# ── Pickle disassembly ──────────────────────────────────────────────────────


def _disassemble_pickle(data: bytes) -> tuple[list[str], list[str], bool, int]:
    """Walk a pickle stream's opcodes WITHOUT executing it.

    Returns ``(suspicious_globals, code_exec_primitives, has_reduce_op,
    n_opcodes)`` where:
    * ``suspicious_globals`` is sorted ``module.name`` for every GLOBAL
      whose module is in the suspicious catalog.
    * ``code_exec_primitives`` is the subset that hit the unambiguous
      RCE list.
    * ``has_reduce_op`` is True when at least one REDUCE-shape opcode
      appears (REDUCE / BUILD / NEWOBJ / NEWOBJ_EX / INST / OBJ).
    """
    susp: set[str] = set()
    rce: set[str] = set()
    has_reduce = False
    n_ops = 0

    last_module: str | None = None
    last_name: str | None = None

    try:
        for opcode, arg, _pos in pickletools.genops(io.BytesIO(data)):
            n_ops += 1
            name = opcode.name
            if name in {"GLOBAL", "STACK_GLOBAL"}:
                # GLOBAL pushes "module name" pair (single bytestring with
                # newline separator); STACK_GLOBAL takes them off the stack
                # so we can't see the args directly here. For STACK_GLOBAL
                # we fall back on the last short_strings we saw.
                if name == "GLOBAL" and isinstance(arg, str) and "\n" in arg:
                    mod, n = arg.split("\n", 1)
                    susp_hit = mod in _SUSPICIOUS_MODULES
                    if susp_hit:
                        susp.add(f"{mod}.{n}")
                    if (mod, n) in _SUSPICIOUS_GLOBALS:
                        rce.add(f"{mod}.{n}")
                elif name == "STACK_GLOBAL":
                    # Use the last two SHORT_BINUNICODE / BINUNICODE we saw.
                    if last_module and last_name:
                        if last_module in _SUSPICIOUS_MODULES:
                            susp.add(f"{last_module}.{last_name}")
                        if (last_module, last_name) in _SUSPICIOUS_GLOBALS:
                            rce.add(f"{last_module}.{last_name}")
            elif name in {"REDUCE", "BUILD", "NEWOBJ", "NEWOBJ_EX", "INST", "OBJ"}:
                has_reduce = True
            elif name in {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE"} and isinstance(arg, str):
                # Track the rolling window for STACK_GLOBAL resolution.
                # STACK_GLOBAL pulls (module, name) off the stack — the
                # two most recent string pushes are the candidates.
                last_module = last_name
                last_name = arg
    except Exception as exc:  # noqa: BLE001
        # Truncated / corrupt pickle — return what we got so far rather
        # than raising. The cascade still gets the partial signal plus
        # a parse-warning marker via metadata in the caller.
        susp.add(f"__parse_error__:{type(exc).__name__}")

    return sorted(susp), sorted(rce), has_reduce, n_ops


def _decompose_raw_pickle(content: bytes) -> MLModelDecomposition:
    susp, rce, has_red, nops = _disassemble_pickle(content)
    parts: list[str] = [
        "# === ML MODEL FILE: pickle ===",
        f"# total_opcodes: {nops}",
        f"# has_reduce_or_build_op: {has_red}",
    ]
    if rce:
        parts.append("# CODE-EXECUTION PRIMITIVES OBSERVED IN PICKLE STREAM:")
        for g in rce:
            parts.append(f"#   ! {g}")
    if susp:
        parts.append("# SUSPICIOUS GLOBALS REFERENCED (module in catalog):")
        for g in susp:
            parts.append(f"#   . {g}")
    if not (rce or susp):
        parts.append("# (no globals matched the suspicious catalog)")
    return MLModelDecomposition(
        is_valid=True,
        format="pickle",
        synthesized_source="\n".join(parts) + "\n",
        suspicious_globals=susp,
        code_exec_primitives=rce,
        has_reduce_op=has_red,
        n_opcodes=nops,
    )


def _decompose_pytorch_zip(content: bytes) -> MLModelDecomposition:
    """``.pt`` files are zipfiles containing ``data.pkl`` (the metadata
    pickle) plus tensor blobs. Walk every member that looks like a
    pickle and aggregate findings."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except (zipfile.BadZipFile, OSError):
        # Not a zip — assume raw pickle (older PyTorch format)
        return _decompose_raw_pickle(content)

    all_susp: set[str] = set()
    all_rce: set[str] = set()
    has_red = False
    nops_total = 0
    files_inspected: list[str] = []

    try:
        for name in zf.namelist():
            if not (name.endswith(".pkl") or name.endswith("/data.pkl") or name.endswith("data.pkl")):
                continue
            try:
                blob = zf.read(name)
            except (zipfile.BadZipFile, OSError):
                continue
            susp, rce, hred, nops = _disassemble_pickle(blob)
            all_susp.update(susp)
            all_rce.update(rce)
            has_red = has_red or hred
            nops_total += nops
            files_inspected.append(name)
    finally:
        zf.close()

    parts: list[str] = [
        "# === ML MODEL FILE: pytorch (zip-of-pickles) ===",
        f"# pickled_members_inspected: {len(files_inspected)} ({', '.join(files_inspected[:5])})",
        f"# total_opcodes_across_members: {nops_total}",
        f"# any_member_has_reduce_or_build_op: {has_red}",
    ]
    susp_sorted = sorted(all_susp)
    rce_sorted = sorted(all_rce)
    if rce_sorted:
        parts.append("# CODE-EXECUTION PRIMITIVES OBSERVED ACROSS PICKLE MEMBERS:")
        for g in rce_sorted:
            parts.append(f"#   ! {g}")
    if susp_sorted:
        parts.append("# SUSPICIOUS GLOBALS REFERENCED:")
        for g in susp_sorted:
            parts.append(f"#   . {g}")
    if not (rce_sorted or susp_sorted):
        parts.append("# (no globals matched the suspicious catalog)")
    return MLModelDecomposition(
        is_valid=True,
        format="pytorch_zip",
        synthesized_source="\n".join(parts) + "\n",
        suspicious_globals=susp_sorted,
        code_exec_primitives=rce_sorted,
        has_reduce_op=has_red,
        n_opcodes=nops_total,
        metadata={"members": ",".join(files_inspected)},
    )


def _decompose_safetensors(content: bytes) -> MLModelDecomposition:
    """``.safetensors`` is intentionally safe (no pickle). The format:
    8-byte little-endian header length, then a JSON header with tensor
    metadata + an optional ``__metadata__`` block. We surface the
    metadata so the cascade can spot embedded prompt-injection or
    suspicious URLs."""
    if len(content) < 8:
        return MLModelDecomposition(
            is_valid=False,
            format="safetensors",
            synthesized_source="",
            parse_error="too_short_for_header",
        )
    try:
        header_len = int.from_bytes(content[:8], "little", signed=False)
    except Exception as exc:  # noqa: BLE001
        return MLModelDecomposition(
            is_valid=False,
            format="safetensors",
            synthesized_source="",
            parse_error=f"header_len_decode: {exc!r}",
        )
    if header_len == 0 or header_len > len(content) - 8 or header_len > 100_000_000:
        return MLModelDecomposition(
            is_valid=False,
            format="safetensors",
            synthesized_source="",
            parse_error=f"implausible_header_len: {header_len}",
        )
    try:
        header_bytes = content[8 : 8 + header_len]
        header = json.loads(header_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return MLModelDecomposition(
            is_valid=False,
            format="safetensors",
            synthesized_source="",
            parse_error=f"json: {exc!r}",
        )
    if not isinstance(header, dict):
        return MLModelDecomposition(
            is_valid=False,
            format="safetensors",
            synthesized_source="",
            parse_error="header_not_object",
        )
    user_metadata = header.get("__metadata__")
    if isinstance(user_metadata, dict):
        meta_str = json.dumps(user_metadata, indent=2, default=str)[:2000]
    else:
        meta_str = "(no __metadata__ block)"
    n_tensors = sum(1 for k in header.keys() if isinstance(k, str) and k != "__metadata__")
    parts = [
        "# === ML MODEL FILE: safetensors ===",
        f"# n_tensor_entries: {n_tensors}",
        "# user-supplied __metadata__ block:",
        *[f"# {ln}" for ln in meta_str.splitlines()],
    ]
    return MLModelDecomposition(
        is_valid=True,
        format="safetensors",
        synthesized_source="\n".join(parts) + "\n",
        metadata={"n_tensors": str(n_tensors)},
    )


def _decompose_onnx(content: bytes) -> MLModelDecomposition:
    """ONNX is a Protocol Buffer model. We don't deeply parse the proto
    in v1 — we surface structural facts so the cascade has context.
    Future work: extract opset / producer / metadata_props (which CAN
    contain attacker-controlled strings)."""
    parts = [
        "# === ML MODEL FILE: onnx (protocol buffer) ===",
        f"# size_bytes: {len(content)}",
        "# (deep ONNX proto parsing not implemented — flagged as recognized)",
    ]
    return MLModelDecomposition(
        is_valid=True,
        format="onnx",
        synthesized_source="\n".join(parts) + "\n",
    )


def _decompose_hdf5(content: bytes) -> MLModelDecomposition:
    parts = [
        "# === ML MODEL FILE: hdf5 ===",
        f"# size_bytes: {len(content)}",
        "# (deep HDF5 inspection requires h5py — flagged as recognized)",
    ]
    return MLModelDecomposition(
        is_valid=True,
        format="hdf5",
        synthesized_source="\n".join(parts) + "\n",
    )


# ── Format dispatch ─────────────────────────────────────────────────────────

#: Magic-byte signatures we care about.
_PICKLE_PROTO_BYTES: bytes = bytes([0x80])  # PROTO opcode (proto >= 2)
_OLD_PICKLE_OPS: frozenset[bytes] = frozenset({b"(", b"]", b"}", b"c"})  # proto 0/1 starts
_ZIP_MAGIC: bytes = b"PK\x03\x04"
_HDF5_MAGIC: bytes = b"\x89HDF\r\n\x1a\n"


def decompose_ml_model(filename: str, content: bytes) -> MLModelDecomposition:
    """Inspect a model artifact based on its extension and magic bytes.

    Magic-byte sniffing is authoritative when the extension and the
    bytes disagree (e.g., a ``.bin`` that's actually a zipfile of
    pickles). The extension is a hint, not a contract.
    """
    name = filename.lower()
    head = content[:8] if content else b""

    # 1) Zip-like containers (PyTorch ``.pt``, sometimes ``.bin``)
    if head.startswith(_ZIP_MAGIC):
        return _decompose_pytorch_zip(content)

    # 2) HDF5
    if head.startswith(_HDF5_MAGIC) or name.endswith((".h5", ".hdf5", ".keras")):
        return _decompose_hdf5(content)

    # 3) safetensors — recognized by extension only (no fixed magic)
    if name.endswith(".safetensors"):
        return _decompose_safetensors(content)

    # 4) ONNX
    if name.endswith(".onnx"):
        return _decompose_onnx(content)

    # 5) Raw pickle (proto >= 2 starts with 0x80; proto 0/1 starts with
    # one of (/]/}/c — but those collide with arbitrary text, so we
    # only treat-as-pickle when the extension also matches).
    if head.startswith(_PICKLE_PROTO_BYTES):
        return _decompose_raw_pickle(content)
    if name.endswith((".pkl", ".pickle", ".pt", ".bin")):
        return _decompose_raw_pickle(content)

    return MLModelDecomposition(
        is_valid=False,
        format="unknown",
        synthesized_source="",
        parse_error=f"no_recognized_signature_for: {filename}",
    )


__all__ = [
    "MLModelDecomposition",
    "decompose_ml_model",
]
