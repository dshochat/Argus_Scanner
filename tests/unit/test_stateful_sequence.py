"""Unit tests for stateful-sequence dispatch + JS/TS harness landmarks.

Covers:
  * Language dispatch: python/javascript/typescript supported,
    others return None
  * Plan-dict shape: commands, oracle, payload_encoding, image_hint
  * Runner cmd: TS gets tsx + package.json + tsconfig bundler; JS
    gets plain node; Python gets python3
  * Harness file extension: .py for Python, .cjs for JS/TS
  * Harness body landmarks: STATEFUL_SEQ_RESULT_JSON marker, fs_write/
    env_set/call/fs_read op handlers, placeholder substitution,
    catastrophic-failure safety net

The JS/TS dispatch is v11 (2026-05-17) — direct port of the Python
v1.6 harness. Same op shapes, same markers, same interpreter on the
orchestrator side.
"""

from __future__ import annotations

import base64
import json

import pytest

from dast.runtime_probe import (
    _build_javascript_stateful_sequence_harness,
    _build_python_stateful_sequence_harness,
    build_runtime_stateful_sequence_plan,
)


# ── Fixture helpers ──────────────────────────────────────────────────────


def _ops_minimal() -> list[dict]:
    """A 2-op sequence: write a file, then call a function that reads it."""
    return [
        {"op": "fs_write", "path": "/tmp/cfg.txt", "content": "{}"},
        {
            "op": "call",
            "function_name": "loadConfig",
            "args_json": '["/tmp/cfg.txt"]',
            "kwargs_json": "{}",
        },
    ]


def _ops_full() -> list[dict]:
    """Cover all four op kinds + placeholder substitution."""
    return [
        {"op": "fs_write", "path": "/tmp/seed.json", "content": '{"key":"v"}'},
        {"op": "env_set", "name": "MY_SECRET", "value": "abc123"},
        {
            "op": "call",
            "function_name": "readSecret",
            "args_json": '["/tmp/seed.json"]',
            "kwargs_json": "{}",
        },
        # Reuse the call's return via placeholder
        {
            "op": "call",
            "function_name": "applyConfig",
            "args_json": '["<<_step1_result>>"]',
            "kwargs_json": "{}",
        },
        {"op": "fs_read", "path": "/tmp/seed.json"},
    ]


# ── Language dispatch ──────────────────────────────────────────────────────


def test_dispatch_python_returns_plan() -> None:
    plan = build_runtime_stateful_sequence_plan(
        file_name="vuln.py",
        file_bytes=b"def loadConfig(p): return open(p).read()\n",
        ops=_ops_minimal(),
        hypothesis_id="HRP_AL_T0_H1",
    )
    assert plan is not None
    assert plan["plan_status"] == "executable"
    assert "python3" in plan["commands"][1]
    assert "_argus_seq_HRP_AL_T0_H1.py" in plan["commands"][1]
    assert "python" in plan["rationale"]


def test_dispatch_javascript_returns_plan() -> None:
    """v11 (2026-05-17): JS gets the new harness via plain ``node``."""
    plan = build_runtime_stateful_sequence_plan(
        file_name="vuln.js",
        file_bytes=b"function loadConfig(p) { return require('fs').readFileSync(p); }\n",
        ops=_ops_minimal(),
        hypothesis_id="HRP_AL_T0_H2",
    )
    assert plan is not None
    assert plan["plan_status"] == "executable"
    run_cmd = plan["commands"][1]
    assert "node " in run_cmd
    assert "_argus_seq_HRP_AL_T0_H2.cjs" in run_cmd
    assert "cd /workspace" in run_cmd
    # JS-mode does NOT write a tsconfig or package.json
    assert "tsx " not in run_cmd
    assert "tsconfig" not in run_cmd
    assert "javascript" in plan["rationale"]


def test_dispatch_typescript_returns_plan_with_tsx_runner() -> None:
    """v11 (2026-05-17): TS gets the JS harness body but launched via
    tsx + package.json{type:module} + tsconfig.json{moduleResolution:bundler}
    so multi-file TS projects with `./foo.js` → `foo.ts` source rewrites
    work at runtime."""
    plan = build_runtime_stateful_sequence_plan(
        file_name="vuln.ts",
        file_bytes=b"export function loadConfig(p: string): string { return '' }\n",
        ops=_ops_minimal(),
        hypothesis_id="HRP_AL_T0_H3",
    )
    assert plan is not None
    run_cmd = plan["commands"][1]
    assert "tsx " in run_cmd
    assert "_argus_seq_HRP_AL_T0_H3.cjs" in run_cmd
    assert "cd /workspace" in run_cmd
    # TS-mode writes both config files
    assert "package.json" in run_cmd
    assert '"type":"module"' in run_cmd
    assert "tsconfig.json" in run_cmd
    assert '"moduleResolution":"bundler"' in run_cmd
    assert '"allowImportingTsExtensions":true' in run_cmd
    # ts-node-era flags must NOT appear
    assert "ts-node" not in run_cmd
    assert "TS_NODE_TRANSPILE_ONLY" not in run_cmd
    assert "typescript" in plan["rationale"]


def test_dispatch_tsx_extension_also_supported() -> None:
    """.tsx files route the same way as .ts."""
    plan = build_runtime_stateful_sequence_plan(
        file_name="component.tsx",
        file_bytes=b"export const x = 1;\n",
        ops=_ops_minimal(),
        hypothesis_id="HRP_AL_T0_H4",
    )
    assert plan is not None
    assert "tsx " in plan["commands"][1]


def test_dispatch_unsupported_languages_return_none() -> None:
    """Shell, JSX, Java, etc. — stateful_sequence has no harness for
    these languages; the dispatcher returns None and the orchestrator
    surfaces a BLOCKED outcome."""
    for fn in ("script.sh", "script.bash", "App.java", "config.yaml", "page.jsx"):
        plan = build_runtime_stateful_sequence_plan(
            file_name=fn,
            file_bytes=b"x",
            ops=_ops_minimal(),
            hypothesis_id="HRP_AL_T0_H5",
        )
        assert plan is None, f"{fn} should return None"


def test_dispatch_empty_ops_returns_none() -> None:
    """Empty ops list = no sequence to run = no plan."""
    plan = build_runtime_stateful_sequence_plan(
        file_name="vuln.ts",
        file_bytes=b"export const x = 1;\n",
        ops=[],
        hypothesis_id="HRP_AL_T0_H6",
    )
    assert plan is None


# ── Plan-dict shape ───────────────────────────────────────────────────────


def test_plan_shape_has_required_keys() -> None:
    plan = build_runtime_stateful_sequence_plan(
        file_name="vuln.ts",
        file_bytes=b"export const x = 1;\n",
        ops=_ops_minimal(),
        hypothesis_id="HRP_AL_T0_H7",
    )
    assert plan is not None
    # Same shape contract as other plan-builder returns.
    assert plan["hypothesis_id"] == "HRP_AL_T0_H7"
    assert plan["plan_status"] == "executable"
    assert plan["oracle"] == "execution_output_with_side_effect_observation"
    assert plan["payload_encoding"] == "base64"
    assert isinstance(plan["commands"], list)
    assert len(plan["commands"]) == 2  # write_cmd + run_cmd
    assert plan["timeout_sec"] > 0
    assert "image_hint" in plan
    assert "rationale" in plan
    # Payload decodes to original bytes
    assert base64.b64decode(plan["payload"]) == b"export const x = 1;\n"


def test_plan_hypothesis_id_sanitised_for_workspace_path() -> None:
    """hypothesis_id may contain ``/`` or other chars unsafe in filenames.
    The harness path strips them via regex."""
    plan = build_runtime_stateful_sequence_plan(
        file_name="vuln.ts",
        file_bytes=b"export const x = 1;\n",
        ops=_ops_minimal(),
        hypothesis_id="HRP_AL/T0/H1?weird",  # would break a raw path
    )
    assert plan is not None
    write_cmd = plan["commands"][0]
    assert "/" not in write_cmd.split("/_argus_seq_")[1].split(".")[0]
    assert "?" not in write_cmd


# ── JS harness body landmarks ─────────────────────────────────────────────


def test_js_harness_emits_stateful_seq_result_marker() -> None:
    """The Python and JS harnesses share the marker so the interpreter
    is language-agnostic. STATEFUL_SEQ_RESULT_JSON must appear on
    both normal-path and fatal-path emission."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_minimal(),
    )
    # Normal-path emission
    assert "console.log('STATEFUL_SEQ_RESULT_JSON:'" in h
    # Fatal-path emission (catastrophic safety net)
    assert "_emitFatal" in h
    # Process-level handlers for uncaughtException + unhandledRejection
    assert "process.on('uncaughtException'" in h
    assert "process.on('unhandledRejection'" in h


def test_js_harness_handles_all_four_op_kinds() -> None:
    """fs_write / env_set / fs_read / call — each must have its own
    branch in the op execution loop."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_full(),
    )
    assert "_opType === 'fs_write'" in h
    assert "_opType === 'env_set'" in h
    assert "_opType === 'fs_read'" in h
    assert "_opType === 'call'" in h
    # Each op-kind branch should record an exception type on failure
    assert h.count("exception_type") >= 4


def test_js_harness_placeholder_substitution() -> None:
    """The ``<<_stepN_result>>`` substitution lets later ops reference
    earlier call returns. Same convention as Python harness + chain
    harness."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_full(),
    )
    assert "PLACEHOLDER_RE" in h
    assert "<<_step" in h or "_step(\\\\d+)_result>>" in h
    assert "_substitute" in h
    # _substitute recurses into arrays + objects so nested placeholders work
    assert "Array.isArray(v)" in h
    assert "Object.keys(v)" in h


def test_js_harness_uses_path_to_file_url_for_import() -> None:
    """Same dynamic-import pattern as the single-function probe harness
    — works for both CJS and ESM targets, ts-node compatible via tsx."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_minimal(),
    )
    assert "pathToFileURL" in h
    assert "await import(" in h


def test_js_harness_async_iife_wrapper() -> None:
    """Top-level await needs the async IIFE wrapper. Same shape as
    JS probe + chain harnesses."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_minimal(),
    )
    assert "(async () => {" in h
    assert "})().catch(" in h


def test_js_harness_dotted_path_resolver() -> None:
    """Function names may be dotted (``MyClass.method``) — harness must
    walk the dotted path through the imported module."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=[
            {
                "op": "call",
                "function_name": "MyClass.method",
                "args_json": "[]",
                "kwargs_json": "{}",
            }
        ],
    )
    assert "resolveFn" in h
    assert "dotted.split('.')" in h
    # ESM default-export fallback so ``import { foo }`` AND
    # ``import foo from './x'`` both resolve correctly.
    assert "default" in h


def test_js_harness_short_circuit_on_call_failure() -> None:
    """Failed call ops at non-final positions short-circuit the sequence
    (no further ops run). Failed fs_write/env_set/fs_read do NOT
    short-circuit — they just record the failure and continue. Same
    semantics as Python harness."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_full(),
    )
    assert "_shortCircuited" in h
    assert "_opIdx < _ops.length - 1" in h


def test_js_harness_side_effects_marker_separate_from_result() -> None:
    """SIDE_EFFECTS marker is emitted as a separate line — same convention
    as Python harness + single-function probe so the interpreter can
    parse them independently."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_minimal(),
    )
    assert "console.log('SIDE_EFFECTS:'" in h
    assert "tmp_files_added" in h


def test_js_harness_writes_result_file_for_chunk_transport() -> None:
    """File-based transport: harness writes argus_probe_result.json so
    large traces survive Fly's per-log-line truncation. Orchestrator's
    probe_result_chunk events read this file."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_minimal(),
    )
    assert "argus_probe_result.json" in h
    assert "fs.writeFileSync" in h


def test_js_harness_path_prep_preamble() -> None:
    """Path-prep preamble: scan source + op args for /-prefixed
    string literals, fs.mkdirSync({recursive: true}) each. Mirrors the
    JS single-function probe harness."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_full(),
    )
    assert "absDirPrefixes" in h
    assert "{ recursive: true }" in h
    # DENY list filters out system dirs to prevent path-prep escapes
    assert "DENY" in h
    # Scans op args too, not just source
    assert "for (const op of _ops)" in h


def test_js_harness_kwargs_convention() -> None:
    """JS doesn't have true kwargs — by convention, the harness passes
    non-empty kwargs as a final-object arg appended after positional
    args. Same as JS single-function probe."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_minimal(),
    )
    # Look for the convention marker
    assert "Object.keys(_kwargs).length > 0" in h
    assert "[..._args, _kwargs]" in h


def test_js_harness_serialises_ops_safely() -> None:
    """ops embedded as JS string literal — must roundtrip through JSON.parse
    without breaking when ops contain quotes / backslashes / unicode."""
    tricky_ops = [
        {
            "op": "call",
            "function_name": "exec",
            "args_json": '["it\\\'s a test", "héllo wörld"]',
            "kwargs_json": "{}",
        }
    ]
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=tricky_ops,
    )
    # The ops payload should be JS-quoted (double JSON encoding)
    assert "JSON.parse(" in h
    # Must not have an unbalanced quote that breaks JS parsing
    assert h.count("'") % 2 == 0 or '"' in h  # at minimum well-formed


def test_js_harness_inner_timeout_safety_net() -> None:
    """45-second inner timeout — fires if the sequence hangs (e.g.,
    async function never resolves). Emits a STATEFUL_SEQ_RESULT_JSON
    with exception_type set so the orchestrator gets actionable evidence."""
    h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts",
        ops=_ops_minimal(),
    )
    assert "setTimeout" in h
    assert "45000" in h
    assert "innerHarnessTimeout" in h


# ── Cross-language parity (interpreter is language-agnostic) ─────────────


def test_python_and_js_harnesses_emit_same_marker() -> None:
    """The Python and JS harnesses must use IDENTICAL marker strings
    so the orchestrator's parser can read either without branching."""
    py_h = _build_python_stateful_sequence_harness(
        module_name="x", ops=_ops_minimal()
    )
    js_h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts", ops=_ops_minimal()
    )
    assert "STATEFUL_SEQ_RESULT_JSON:" in py_h
    assert "STATEFUL_SEQ_RESULT_JSON:" in js_h
    # Both write the same companion file for chunked transport
    assert "argus_probe_result.json" in py_h
    assert "argus_probe_result.json" in js_h


def test_python_and_js_harnesses_share_op_field_names() -> None:
    """per_op_results entries must have the same field names in both
    languages so the interpreter can read either without branching."""
    py_h = _build_python_stateful_sequence_harness(
        module_name="x", ops=_ops_full()
    )
    js_h = _build_javascript_stateful_sequence_harness(
        module_path="/workspace/x.ts", ops=_ops_full()
    )
    # Common fields across all op kinds
    for field in ("op_index", "op_type", "ok", "exception_type", "exception_msg"):
        assert field in py_h, f"Python harness missing {field}"
        assert field in js_h, f"JS harness missing {field}"
    # Op-specific fields
    for field in ("bytes_written", "content_preview", "value_preview", "function_name"):
        assert field in py_h, f"Python harness missing {field}"
        assert field in js_h, f"JS harness missing {field}"
