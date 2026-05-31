"""Unit tests for dast/behavioral_probe.py — Phase 3 Stage 1.

Covers:
* Data types (BehavioralProfile, CallableObservation, CallableInvocation,
  DataflowHint) construct cleanly with defaults
* Plan builder — Python-only gate, distinct ``BP_<file_id>`` hypothesis
  namespace, embedded base64 payload, valid command structure
* Probe-script generator — produces valid Python, contains the
  expected instrumentation (sys.addaudithook, /tmp baseline, callable
  enumeration, signal.alarm timeout, AST dataflow analysis, marker
  emission)
* Trace parser — defensive on empty stdout, broken JSON, partial
  fields; roundtrips a synthetic marker
* Orchestrator stage — skipped when flag disabled, runs once when
  enabled, surfaces profile on DastResult, journals an informational
  record (verdict=inconclusive)

No live API; no real sandbox. Uses synthetic SandboxTrace-shape
objects and stub sandbox clients.
"""

from __future__ import annotations

import ast
import base64
import json
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path

import pytest

from dast.behavioral_probe import (
    DEFAULT_BEHAVIORAL_PROBE_TIMEOUT_SEC,
    MAX_CALLABLES_EXPLORED,
    MAX_INVOCATIONS_PER_CALLABLE,
    BehavioralProfile,
    CallableInvocation,
    CallableObservation,
    DataflowHint,
    _build_python_behavioral_probe_script,
    build_behavioral_probe_plan,
    parse_behavioral_probe_trace,
)
from dast.orchestrator import run_dast  # noqa: E402
from dast.sandbox.client import SandboxEvent, SandboxPlan, SandboxTrace
from dast.validator import HypothesisValidator

# ── Data types ─────────────────────────────────────────────────────────────


def test_callable_invocation_defaults() -> None:
    """Construct with required args only; rest have safe defaults."""
    inv = CallableInvocation(args_repr="['x']", ok=True)
    assert inv.args_repr == "['x']"
    assert inv.ok is True
    assert inv.return_type == ""
    assert inv.exception_type == ""
    assert inv.elapsed_ms == 0


def test_callable_observation_defaults() -> None:
    """Per-callable observation defaults to no dangerous-builtin reach,
    no opens, no network attempts."""
    obs = CallableObservation(name="parse_config")
    assert obs.name == "parse_config"
    assert obs.signature == ""
    assert obs.invocations == []
    # All danger flags default False
    assert obs.calls_eval is False
    assert obs.calls_exec is False
    assert obs.calls_compile is False
    assert obs.calls_subprocess is False
    assert obs.calls_pickle_loads is False
    assert obs.calls_marshal_loads is False
    assert obs.calls_dynamic_import is False
    assert obs.opens_files == []
    assert obs.writes_files_in_tmp == []
    assert obs.network_attempts == []
    assert obs.returns_callable_field is False


def test_dataflow_hint_defaults() -> None:
    h = DataflowHint(source_function="parse", sink_function="apply")
    assert h.source_function == "parse"
    assert h.sink_function == "apply"
    assert h.callsite_line == 0
    assert h.flow_kind == "return_to_arg"


def test_behavioral_profile_defaults() -> None:
    """Profile with required file metadata + empty observations."""
    p = BehavioralProfile(file_id="abc", file_name="x.py")
    assert p.file_id == "abc"
    assert p.file_name == "x.py"
    assert p.callables == []
    assert p.dataflow_hints == []
    assert p.import_error == ""
    assert p.callables_total == 0
    assert p.callables_explored == 0
    assert p.elapsed_ms == 0


# ── Tunables sanity ────────────────────────────────────────────────────────


def test_tunables_are_bounded() -> None:
    """Cost-control constants stay in reasonable ranges."""
    assert 5 <= MAX_CALLABLES_EXPLORED <= 50
    assert 1 <= MAX_INVOCATIONS_PER_CALLABLE <= 5
    assert 30 <= DEFAULT_BEHAVIORAL_PROBE_TIMEOUT_SEC <= 300


# ── Plan builder ───────────────────────────────────────────────────────────


def test_plan_builder_returns_none_for_unsupported_language() -> None:
    """Stage 1 supports Python (v1.6) and JS (v1.8 JS DAST parity).
    Shell + everything else still returns None — Stage 1 needs a
    per-language harness to produce a profile."""
    # JS supported as of v1.8 — gets a plan, NOT None.
    js_plan = build_behavioral_probe_plan(
        file_name="x.js", file_bytes=b"function f() { return 1; }\n", file_id="abc"
    )
    assert js_plan is not None
    assert js_plan["hypothesis_id"].startswith("BP_")
    # Shell still unsupported in Stage 1.
    assert build_behavioral_probe_plan(file_name="x.sh", file_bytes=b"", file_id="abc") is None
    assert build_behavioral_probe_plan(file_name="x.bash", file_bytes=b"", file_id="abc") is None
    # Unknown extensions skipped.
    assert build_behavioral_probe_plan(file_name="x.go", file_bytes=b"", file_id="abc") is None


def test_plan_builder_js_dispatches_to_node_harness() -> None:
    """JS plan uses .cjs harness extension + `node` runner. Harness
    runs in /workspace cwd so npm-installed deps resolve via
    Node's standard module lookup."""
    plan = build_behavioral_probe_plan(
        file_name="x.js",
        file_bytes=b"function greet() { return 'hi'; }\nmodule.exports = { greet };\n",
        file_id="abc",
    )
    assert plan is not None
    assert len(plan["commands"]) == 2
    assert "_argus_behavioral_probe.cjs" in plan["commands"][0]
    # Run command must cd to /workspace for node_modules resolution.
    assert plan["commands"][1] == "cd /workspace && node /workspace/_argus_behavioral_probe.cjs"


def test_plan_builder_mjs_and_cjs_dispatches_to_node() -> None:
    """``.mjs`` and ``.cjs`` both route through the JS harness."""
    for ext in (".mjs", ".cjs"):
        plan = build_behavioral_probe_plan(
            file_name=f"x{ext}",
            file_bytes=b"export function f() { return 1; }\n",
            file_id="abc",
        )
        assert plan is not None, f"{ext} should produce a plan"
        assert "node /workspace/_argus_behavioral_probe.cjs" in plan["commands"][1]


def test_plan_builder_typescript_dispatches_via_tsx() -> None:
    """TS support (v10, 2026-05-16): ``.ts`` / ``.tsx`` files route
    through the JS behavioral-probe harness body but are launched via
    ``tsx``. The harness's dynamic ``import()`` of the user's TS
    target transpiles on-the-fly. tsx skips type-check by default so
    type errors in user code don't block probing.

    v9 originally shipped with ``node --loader ts-node/esm`` but had
    100% TS-file Stage 1 failure due to a CJS-entry+ESM-dynamic-import
    cycle bug in ts-node's loader hook. tsx is the production runner.
    """
    for ext in (".ts", ".tsx"):
        plan = build_behavioral_probe_plan(
            file_name=f"x{ext}",
            file_bytes=(
                b"export function greet(name: string): string { return 'hi ' + name }\n"
            ),
            file_id="abcdef12",
        )
        assert plan is not None, f"{ext} should produce a plan"
        assert plan["hypothesis_id"].startswith("BP_")
        # Harness file stays .cjs (CJS-mode harness body — reused from JS path)
        assert "_argus_behavioral_probe.cjs" in plan["commands"][0]
        run_cmd = plan["commands"][1]
        # tsx launches the harness; ts-node-era flags must NOT appear.
        assert "tsx " in run_cmd
        assert "ts-node" not in run_cmd
        assert "TS_NODE_TRANSPILE_ONLY" not in run_cmd
        assert "--loader" not in run_cmd
        # cwd must be /workspace so npm-installed deps + the staged
        # TS target resolve correctly.
        assert "cd /workspace" in run_cmd
        # The exact harness path is the same as the JS dispatch.
        assert "/workspace/_argus_behavioral_probe.cjs" in run_cmd
        # /workspace/package.json gets written with type=module so
        # tsx transpiles user .ts files as ESM (top-level await etc.).
        assert "package.json" in run_cmd
        assert '"type":"module"' in run_cmd
        # /workspace/tsconfig.json with moduleResolution=bundler so
        # tsx resolves modern TS ``import './foo.js'`` to ``./foo.ts``
        # source on disk (standard TS-ecosystem pattern). Without this,
        # multi-file TS projects fail to import siblings at runtime.
        assert "tsconfig.json" in run_cmd
        assert '"moduleResolution":"bundler"' in run_cmd
        assert '"allowImportingTsExtensions":true' in run_cmd


def test_plan_builder_typescript_reuses_js_harness_body() -> None:
    """The TS dispatch reuses ``_build_javascript_behavioral_probe_script``
    verbatim — our harness is plain JS; ts-node only transpiles the
    user's target on ``import()``. Confirm by structural-equivalence:
    the harness body emitted for a .ts target is character-identical
    to the harness body for an equivalent .js target after substituting
    the file_name field (the only piece of the script that legitimately
    differs between the two)."""
    import base64

    js_plan = build_behavioral_probe_plan(
        file_name="x.js",
        file_bytes=b"module.exports = { f: () => 1 };\n",
        file_id="abcdef12",
    )
    ts_plan = build_behavioral_probe_plan(
        file_name="x.ts",
        file_bytes=b"export function f(): number { return 1 }\n",
        file_id="abcdef12",
    )
    assert js_plan is not None and ts_plan is not None
    js_harness_b64 = js_plan["commands"][0].split()[-1]
    ts_harness_b64 = ts_plan["commands"][0].split()[-1]
    js_script = base64.b64decode(js_harness_b64).decode("utf-8")
    ts_script = base64.b64decode(ts_harness_b64).decode("utf-8")
    # The only legitimate difference is the embedded file_name string.
    # Normalize and assert structural equality.
    js_normalized = js_script.replace('"x.js"', '"FILE"')
    ts_normalized = ts_script.replace('"x.ts"', '"FILE"')
    assert js_normalized == ts_normalized, (
        "TS dispatch should reuse the JS harness body verbatim "
        "(after normalizing file_name)"
    )
    # Sanity: actually contains the marker the orchestrator parses.
    assert "BEHAVIORAL_PROFILE_JSON:" in ts_script


def test_plan_builder_emits_bp_hypothesis_id() -> None:
    """Plans use a distinct ``BP_<file_id_prefix>`` namespace to avoid
    collision with chain probes (``HRP_C<n>``) and single-function
    probes (``HRP_<c>_<i>``)."""
    plan = build_behavioral_probe_plan(
        file_name="x.py", file_bytes=b"def f(): pass\n", file_id="1234567890abcdef"
    )
    assert plan is not None
    assert plan["hypothesis_id"].startswith("BP_")
    assert plan["hypothesis_id"] == "BP_12345678"


def test_plan_builder_has_two_commands_write_then_run() -> None:
    """Stage 1 plan: write the probe script via base64, then exec it."""
    plan = build_behavioral_probe_plan(
        file_name="x.py", file_bytes=b"def f(): pass\n", file_id="abc"
    )
    assert plan is not None
    assert len(plan["commands"]) == 2
    assert "_argus_behavioral_probe.py" in plan["commands"][0]
    assert plan["commands"][1].startswith("python3 /workspace/_argus_behavioral_probe.py")


def test_plan_builder_embeds_file_bytes_as_base64() -> None:
    plan = build_behavioral_probe_plan(
        file_name="x.py",
        file_bytes=b"def f(): return 1\n",
        file_id="abc",
    )
    assert plan is not None
    assert plan["payload_encoding"] == "base64"
    assert base64.b64decode(plan["payload"]) == b"def f(): return 1\n"


def test_plan_builder_timeout_at_least_60s() -> None:
    """Plan timeout big enough to cover MAX_CALLABLES_EXPLORED ×
    MAX_INVOCATIONS_PER_CALLABLE × per-call timeout, with headroom."""
    plan = build_behavioral_probe_plan(
        file_name="x.py", file_bytes=b"def f(): pass\n", file_id="abc"
    )
    assert plan is not None
    assert plan["timeout_sec"] >= 60


def test_plan_oracle_is_distinct_from_other_probes() -> None:
    """Behavioral probe uses its own oracle string so the orchestrator
    + trace pipeline can route it distinctly."""
    plan = build_behavioral_probe_plan(
        file_name="x.py", file_bytes=b"def f(): pass\n", file_id="abc"
    )
    assert plan is not None
    assert plan["oracle"] == "behavioral_profile_observation"


# ── Probe-script generator ─────────────────────────────────────────────────


def test_probe_script_parses_as_valid_python() -> None:
    """The embedded probe script must be syntactically valid Python —
    otherwise the harness crashes before any marker emits and the
    orchestrator sees a silent failure."""
    script = _build_python_behavioral_probe_script(
        module_name="some_target", file_name="some_target.py", file_id="abc"
    )
    ast.parse(script)  # raises SyntaxError on failure


def test_probe_script_installs_audit_hook() -> None:
    """Audit hook is the load-bearing capture mechanism for
    eval/exec/subprocess/pickle/open/socket events."""
    script = _build_python_behavioral_probe_script(module_name="m", file_name="m.py", file_id="abc")
    assert "sys.addaudithook" in script
    # Must observe at least the danger-class events
    assert "'subprocess.Popen'" in script
    assert "'pickle.find_class'" in script
    assert "'marshal.loads'" in script
    assert "'open'" in script
    assert "'socket.connect'" in script


def test_probe_script_enumerates_public_callables() -> None:
    """Probe enumerates via inspect.getmembers, skipping private names."""
    script = _build_python_behavioral_probe_script(module_name="m", file_name="m.py", file_id="abc")
    assert "inspect.getmembers" in script
    assert "_name.startswith('_')" in script
    # Bounded by MAX_CALLABLES_EXPLORED
    assert str(MAX_CALLABLES_EXPLORED) in script


def test_probe_script_filters_inherited_methods_via_qualname() -> None:
    """B#4 (2026-05-16): Stage 1 callable scoping must filter out
    methods inherited from base classes (e.g., Pydantic's BaseModel
    methods like model_dump, model_copy, dict, copy, json, from_orm).

    Empirically motivated by the mcp-server-fetch eval where Fetch
    inherits ~16 methods from Pydantic BaseModel. Pre-fix all 16 ate
    Stage 1's budget; post-fix only Fetch's own methods do.

    Mechanism: check __qualname__ — for inherited methods it retains
    the DEFINING class's name (e.g., 'BaseModel.model_dump' even when
    accessed via Fetch). Own methods qualname starts with the current
    class name (e.g., 'Fetch.process_url')."""
    script = _build_python_behavioral_probe_script(
        module_name="m", file_name="m.py", file_id="abc"
    )
    # The qualname check must appear in the generated script
    assert "__qualname__" in script
    # The filter condition itself
    assert "_mqual.startswith(_cname + '.')" in script
    # The "inherited from base class" exit comment
    assert "inherited" in script.lower()


def test_probe_script_inherited_filter_has_module_fallback() -> None:
    """Some method-descriptor objects (classmethod / staticmethod
    wrappers) don't expose __qualname__ cleanly. The filter accepts
    those via the __module__ fallback when qualname is unavailable —
    avoids spurious exclusions of legitimate own-class methods."""
    script = _build_python_behavioral_probe_script(
        module_name="m", file_name="m.py", file_id="abc"
    )
    # Fallback path: __module__ check when qualname empty
    assert "_mmod == _target_module_name and not _mqual" in script


def test_probe_script_filter_skips_pydantic_basemodel_methods_by_name() -> None:
    """Quick sanity check on the most common case: any of the
    Pydantic auto-generated method names that motivated this fix
    appear as test fodder in the assertion below, and the qualname
    mechanism handles them all uniformly. This test doesn't run the
    sandbox; it just asserts the filter mechanism is in place."""
    script = _build_python_behavioral_probe_script(
        module_name="my_module", file_name="my_module.py", file_id="abc"
    )
    # The script must have BOTH the qualname filter AND the docstring
    # explanation referencing Pydantic — future readers should see
    # WHY the filter was added.
    assert "Pydantic" in script or "BaseModel" in script
    assert "model_dump" in script or "model_copy" in script


# ── v15.2: namespace-distribution re-export tolerance ──────────────────


def test_probe_script_computes_target_dist_prefix() -> None:
    """v15.2 (2026-05-20): the harness MUST compute a distribution
    prefix from the target module name so re-exported classes from
    sibling submodules of the same distribution are accepted.

    For module_name='ruamel.yaml.loader' the harness should compute
    _target_dist_prefix='ruamel.yaml.' (drop the last segment +
    re-add the dot). Empty string for single-segment names
    (preserves the strict-equality fallback for traditional flat
    packages)."""
    script = _build_python_behavioral_probe_script(
        module_name="ruamel.yaml.loader",
        file_name="loader.py",
        file_id="abc",
    )
    # The prefix computation must be present
    assert "_target_dist_prefix" in script
    # Single-segment fallback: 'if . in _target_module_name'
    assert "'.' in _target_module_name" in script
    # The .rsplit('.', 1)[0] + '.' construction
    assert "rsplit('.', 1)[0]" in script


def test_probe_script_class_filter_accepts_dist_prefix() -> None:
    """The class-acceptance check must allow classes whose
    __module__ starts with the target's distribution prefix —
    pip-installed ``ruamel.yaml.loader`` does ``from .main import
    Loader, SafeLoader, …`` so the classes have
    ``__module__='ruamel.yaml.main'`` not the target module name.
    Pre-v15.2 these were silently rejected → 0 callables enumerated.
    """
    script = _build_python_behavioral_probe_script(
        module_name="ruamel.yaml.loader",
        file_name="loader.py",
        file_id="abc",
    )
    # The relaxed accept rule on the class itself
    assert "_target_dist_prefix and _cmod.startswith(_target_dist_prefix)" in script
    # Comment trail explains the intent
    assert "outside our distribution" in script.lower() or "noise filter" in script.lower()


def test_probe_script_method_filter_accepts_dist_prefix() -> None:
    """Symmetric to the class filter: methods inherited from a
    sibling submodule of the same distribution are accepted as
    own-class methods, while methods from foreign distributions
    (Pydantic BaseModel.model_dump from pydantic.main) are still
    rejected as inherited noise."""
    script = _build_python_behavioral_probe_script(
        module_name="ruamel.yaml.loader",
        file_name="loader.py",
        file_id="abc",
    )
    # Method-level relaxation: _is_own_method now also accepts
    # cross-submodule-same-distribution methods.
    assert "_mmod.startswith(_target_dist_prefix)" in script


def test_probe_script_single_segment_target_module_keeps_strict_filter() -> None:
    """For traditional single-segment target modules (e.g., a flat
    .py file scanned standalone), the v15.2 distribution-prefix
    relaxation MUST NOT kick in — otherwise classes from arbitrary
    other modules would suddenly be accepted. The
    ``if '.' in _target_module_name`` guard preserves the strict
    behavior for these cases."""
    script = _build_python_behavioral_probe_script(
        module_name="myfile",  # no dot
        file_name="myfile.py",
        file_id="abc",
    )
    # The guard is present — _target_dist_prefix only populated when
    # the target has at least one dot.
    assert "_target_dist_prefix = ''" in script
    # And gets reassigned only conditionally
    assert "if '.' in _target_module_name" in script


def test_probe_script_has_per_call_timeout() -> None:
    """SIGALRM-based per-call timeout prevents one slow callable from
    consuming the whole probe budget."""
    script = _build_python_behavioral_probe_script(module_name="m", file_name="m.py", file_id="abc")
    assert "signal.alarm" in script
    assert "TimeoutError('per_call_timeout')" in script


def test_probe_script_has_defensive_sandboxing() -> None:
    """Probe must set short socket timeout + disable proxy lookups so
    benign discovery inputs can't accidentally hang on network calls."""
    script = _build_python_behavioral_probe_script(module_name="m", file_name="m.py", file_id="abc")
    assert "socket.setdefaulttimeout" in script
    assert "no_proxy" in script or "NO_PROXY" in script


def test_probe_script_extracts_dataflow_hints_via_ast() -> None:
    """Static AST analysis surfaces cross-function flows (e.g.,
    ``apply_config(parse_config(x))``) that pure behavioral observation
    can't see. Stage 2 uses these hints for chain hypothesis design."""
    script = _build_python_behavioral_probe_script(module_name="m", file_name="m.py", file_id="abc")
    assert "ast.parse" in script
    assert "ast.Call" in script
    assert "source_function" in script
    assert "sink_function" in script


def test_probe_script_emits_marker_line() -> None:
    """Probe must emit ``BEHAVIORAL_PROFILE_JSON:`` marker so the
    orchestrator's trace parser can find it."""
    script = _build_python_behavioral_probe_script(module_name="m", file_name="m.py", file_id="abc")
    assert "BEHAVIORAL_PROFILE_JSON:" in script
    assert "sys.stdout.flush()" in script


def test_probe_script_wraps_module_import_in_try() -> None:
    """ImportError on the target module must not crash the probe —
    Stage 2 can still reason from source if behavioral observations
    are empty, but only if the probe emits a profile with
    ``import_error`` populated rather than dying silently."""
    script = _build_python_behavioral_probe_script(
        module_name="missing_xyz", file_name="missing_xyz.py", file_id="abc"
    )
    assert "import missing_xyz as _target" in script
    assert "_import_error" in script
    # The except must catch BaseException so SystemExit / KeyboardInterrupt
    # from import-time code don't kill the probe silently.
    assert "except BaseException as _imp_e" in script


# ── JS harness content (v1.8 — JS DAST parity) ────────────────────────────


def _build_js_script() -> str:
    """Helper: build a JS behavioral probe script for content assertions."""
    from dast.behavioral_probe import _build_javascript_behavioral_probe_script

    return _build_javascript_behavioral_probe_script(file_name="m.js", file_id="abc123def456")


def test_js_script_emits_marker_line() -> None:
    """JS probe must emit the same ``BEHAVIORAL_PROFILE_JSON:`` marker
    as the Python probe — parser is language-agnostic."""
    script = _build_js_script()
    assert "BEHAVIORAL_PROFILE_JSON:" in script


def test_js_script_installs_fatal_handlers() -> None:
    """Uncaught exceptions + unhandled promise rejections must still
    produce a marker, not a silent exit-1 (the empirical failure mode
    we saw on the Python harness pre-fatal-handler hardening)."""
    script = _build_js_script()
    assert "process.on('uncaughtException'" in script
    assert "process.on('unhandledRejection'" in script
    assert "_emitFatal" in script


def test_js_script_inner_timeout_45s() -> None:
    """A 45s inner setTimeout must fire if the harness hangs (e.g.,
    a target's exported function awaits something that never resolves).
    45s ≈ Python's per-callable budget × MAX_CALLABLES_EXPLORED with
    headroom under the overall probe timeout."""
    script = _build_js_script()
    assert "45000" in script  # ms
    assert "innerHarnessTimeout" in script


def test_js_script_monkey_patches_eval_and_function() -> None:
    """eval() and `new Function(...)` are eval-equivalents in JS. Both
    must be wrapped so calls_eval fires regardless of which the target
    uses."""
    script = _build_js_script()
    assert "global.eval" in script
    assert "global.Function" in script
    assert "_markEval" in script


def test_js_script_monkey_patches_vm_module() -> None:
    """vm.runInNewContext / runInContext / runInThisContext are exec
    equivalents. The patch must wrap them for calls_exec signal."""
    script = _build_js_script()
    assert "runInNewContext" in script
    assert "runInContext" in script
    assert "runInThisContext" in script
    assert "_markExec" in script


# ── v13 Stage 1 production-grade fix: adversarial seed bank + name-aware hints ──


def test_max_invocations_bumped_to_five_for_v13() -> None:
    """v13: MAX_INVOCATIONS_PER_CALLABLE bumped 3 → 5 to fit benign +
    adversarial inputs in same per-callable budget."""
    from dast.behavioral_probe import MAX_INVOCATIONS_PER_CALLABLE

    assert MAX_INVOCATIONS_PER_CALLABLE >= 5, (
        "Stage 1 needs ≥5 invocations per callable to interleave benign "
        "canary + name-hint adversarial + per-type adversarial fallbacks. "
        "Anything less starves the adversarial seed bank."
    )


def test_adversarial_input_templates_exists_and_has_attack_seeds() -> None:
    """v13: adversarial seed bank populated per-type with attack-shaped
    values. Required for Stage 1 signals_observed to populate during
    discovery (production-grade fix for the empty-signals bottleneck)."""
    from dast.behavioral_probe import _ADVERSARIAL_INPUT_TEMPLATES

    # str seeds must include SSRF, path traversal, SQL-i, command-i.
    str_seeds = _ADVERSARIAL_INPUT_TEMPLATES["str"]
    assert any(
        "169.254.169.254" in s for s in str_seeds
    ), "AWS IMDS SSRF seed missing — Stage 1 won't fire network signal on fetch_*"
    assert any(
        "../" in s and "etc/passwd" in s for s in str_seeds
    ), "path-traversal seed missing — Stage 1 won't fire fs signal on read_*"
    assert any(
        "UNION SELECT" in s for s in str_seeds
    ), "SQL injection seed missing — Stage 1 won't fire DB signal on query_*"
    assert any(
        "__import__" in s for s in str_seeds
    ), "code-injection seed missing — Stage 1 won't fire exec signal on eval/exec"


def test_name_to_adversarial_hint_covers_common_attack_surfaces() -> None:
    """v13: name-hint table maps function-name keywords to priority
    seeds. Verifies all the major attack-class buckets are covered so
    e.g. fetch_url() gets the IMDS URL on its first adversarial slot."""
    from dast.behavioral_probe import _NAME_TO_ADVERSARIAL_HINT

    # Coverage of major attack-class buckets:
    network_keys = {"fetch", "request", "url", "download", "crawl"}
    fs_keys = {"read_file", "load_file", "open_file"}
    sql_keys = {"query", "sql", "execute_query"}
    eval_keys = {"eval", "exec"}
    llm_keys = {"prompt", "complete", "invoke"}
    template_keys = {"render", "template"}

    for bucket_name, keys in (
        ("network", network_keys),
        ("fs", fs_keys),
        ("sql", sql_keys),
        ("eval", eval_keys),
        ("llm", llm_keys),
        ("template", template_keys),
    ):
        present = keys & _NAME_TO_ADVERSARIAL_HINT.keys()
        assert present, (
            f"name-hint bucket {bucket_name!r} has zero coverage — "
            f"expected at least one of {keys}, got intersection {present}"
        )


def test_probe_script_embeds_adversarial_bank_and_name_hints() -> None:
    """v13: probe script (Python harness) must embed both the
    adversarial bank and the name-hint mapping as Python literals.
    Without these, the in-sandbox _derive_args() can't apply
    name-aware seeding and Stage 1 reverts to benign-only discovery."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    # Adversarial bank
    assert "_adversarial_inputs" in script
    assert "169.254.169.254" in script
    assert "etc/passwd" in script
    # Name-hint table
    assert "_name_hints" in script
    assert "'fetch'" in script or '"fetch"' in script  # one of the keys
    # The dispatch helper
    assert "_name_hint_for" in script
    # _derive_args now accepts fn_name
    assert "def _derive_args(fn, fn_name=" in script


def test_probe_script_passes_fn_name_to_derive_args() -> None:
    """v13: the per-callable invocation loop must thread the function
    name into _derive_args so name-hint seed selection actually fires.
    Without this thread-through, the seed bank exists but is unused."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    # The new call signature passes both _fn_obj and _fn_name.
    assert "_derive_args(_fn_obj, _fn_name" in script


def test_probe_script_with_v13_changes_parses_as_valid_python() -> None:
    """Belt-and-suspenders: the regenerated script with all v13
    additions must still parse cleanly. Catches escape/quoting bugs
    in the new constant embeddings."""
    script = _build_python_behavioral_probe_script(
        module_name="some_mod", file_name="some_mod.py", file_id="xyz"
    )
    try:
        ast.parse(script)
    except SyntaxError as exc:
        raise AssertionError(
            f"Probe script failed to parse: line {exc.lineno}: {exc.msg}"
        ) from exc


# ── v13 Change B (class-aware probing) ──


def test_probe_script_defines_argusmock_for_class_instantiation() -> None:
    """v13: probe must define _ArgusMock — duck-typed stub used as
    constructor dependency when the target class takes complex args
    (LangChain BaseTool with model/embeddings, MCP server with config).
    Without this, classes whose constructors take real deps stay
    unreachable and Stage 1 enumerates only inert class-method
    descriptors."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    assert "_ArgusMock" in script
    assert "def __getattr__" in script
    assert "def __call__" in script
    # Async context manager protocol for async classes
    assert "__aenter__" in script
    assert "__aexit__" in script


def test_probe_script_defines_try_instantiate_helper() -> None:
    """v13: _try_instantiate(cls) tries zero-arg, then kwargs-with-
    mocks, then positional-mocks. Required for the agentic-tool
    constructor pattern (LangChain Tool(model=..., embeddings=...))."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    assert "def _try_instantiate(cls)" in script
    # All three strategies should be present
    assert "Strategy 1: zero-arg" in script
    assert "Strategy 2:" in script
    assert "Strategy 3:" in script


def test_probe_script_candidate_tuples_carry_instance_slot() -> None:
    """v13: _candidates is a list of 3-tuples (name, fn_obj, instance).
    The instance is the cached class instance (or None for module-
    level functions). Per-callable invoker uses it to bind the method."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    # 3-tuple form in the enumeration
    assert "_candidates.append((_name, _obj, None))" in script
    assert "(f'{_cname}.{_mname}', _mobj, _instance)" in script
    # Loop unpacks 3-tuple
    assert "for _fn_name, _fn_obj, _instance in _candidates" in script


def test_probe_script_binds_method_to_instance_for_class_calls() -> None:
    """v13: when an instance is available, the per-callable invoker
    rebinds via getattr(_instance, method_name) so 'self' resolves
    correctly. Without this we'd pass the discovery URL string as
    self and get only TypeErrors."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    assert "_bound = getattr(_instance, _bare_mname)" in script
    # Argument self-stripping for bound calls
    assert "_strip_self" in script
    assert "_args[1:]" in script
    # Invocation target picks bound method when instance present
    assert "_invoke_target = _bound" in script


def test_probe_script_v14_resets_alarm_before_async_drive() -> None:
    """v14-A: the coroutine drive must reset the SIGALRM with a fresh
    per-call budget before run_until_complete fires. Without this,
    the alarm set at slot-start has already eaten into the budget
    by the time _invoke_target returns its coroutine, leaving the
    async drive < 4 sec to complete — too short for httpx.connect
    to a non-routable IP. fetch_url() returning a coroutine without
    a network signal was the v13 follow-on we're closing here."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    # Reset alarm before drive
    assert "signal.alarm(0)" in script
    # Fresh alarm with int(per_call_timeout) + 2 (full budget for async)
    assert "signal.alarm(int(" in script
    assert "+ 2)" in script


def test_probe_script_v14_records_coroutine_drive_diagnostics() -> None:
    """v14-A: invocations dict must surface coroutine_awaited (bool)
    and coroutine_drive_err (str) so Stage 2 can distinguish
    'function returned a real value' from 'we awaited and got the
    value' from 'we tried to await and got TimeoutError'."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    assert "_coroutine_awaited" in script
    assert "_coroutine_drive_err" in script
    assert "'coroutine_awaited': _coroutine_awaited" in script
    assert "'coroutine_drive_err': _coroutine_drive_err" in script


def test_probe_script_drives_coroutines_to_completion() -> None:
    """v13: when a method returns a coroutine (async invoke pattern),
    the probe must await it so audit hooks fire on the actual network/
    fs work, not just the coroutine object creation. LangChain's
    async methods (ainvoke/arun) and MCP's async handlers depend on
    this."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    assert "iscoroutine" in script
    assert "run_until_complete" in script


def test_probe_script_enumerates_agentic_method_names_including_underscored() -> None:
    """v13: _call is the canonical LangChain BaseTool method (single
    underscore prefix). The legacy filter at line ~747 skipped EVERY
    underscored name; v13 allowlists agentic conventions so _call /
    __call__ / invoke / ainvoke / run / arun are reachable."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    assert "_AGENTIC_METHOD_NAMES" in script
    for name in ("'_call'", "'call'", "'invoke'", "'ainvoke'", "'run'", "'arun'"):
        assert name in script, f"agentic method {name} missing from allowlist"


def test_js_script_embeds_adversarial_bank_and_name_hints() -> None:
    """v13 JS parity: the Node.js probe script must embed the
    adversarial bank + name-hint table as JSON literals (no Python-
    specific repr() shapes leak in). _pickInputs must accept the
    callable name so seed selection works."""
    script = _build_js_script()
    # Embedded constants by name
    assert "ADVERSARIAL" in script
    assert "NAME_HINTS" in script
    # Attack-shaped values present
    assert "169.254.169.254" in script
    assert "etc/passwd" in script
    assert "UNION SELECT" in script
    # The dispatch helper + updated signature
    assert "_nameHintFor" in script
    assert "_pickInputs(name, arity)" in script or "_pickInputs(c.name, c.arity)" in script
    # The longest-match-wins sort happens in script
    assert "NAME_HINT_KEYS" in script


def test_probe_script_v14_records_mock_calls() -> None:
    """v14-B: _ArgusMock is a RECORDING mock — it appends every
    getattr access + every __call__ into a module-level
    _argus_mock_journal list. Stage 2 reads the journal to reason
    about data flow through class methods even when the underlying
    real dep (model.invoke, db.execute) returns a mock.
    """
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    # Journal is module-level
    assert "_argus_mock_journal" in script
    assert "_ARGUS_MOCK_JOURNAL_CAP" in script
    # Records both getattr and call ops
    assert "'op': 'getattr'" in script
    assert "'op': 'call'" in script
    # Records args + kwargs
    assert "'args_repr':" in script
    assert "'kwargs_repr':" in script


def test_probe_script_v14_mock_journal_per_callable_slice() -> None:
    """v14-B: per-callable observation must include the journal slice
    contributed by THIS callable's invocations. Without slicing, all
    callables would see the cumulative journal and Stage 2 couldn't
    attribute behavior to a specific method."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    assert "_mock_journal_pre_len" in script
    assert "_mock_journal_slice" in script
    assert "'mock_journal_slice': _mock_journal_slice" in script


def test_probe_script_v14c_distinguishes_subprocess_shell_modes() -> None:
    """v14-C: static AST scan detects subprocess.run(shell=True) vs
    subprocess.run(shell=False) per function, and the per-callable
    observation carries subprocess_shell_mode_static so Stage 2 can
    distinguish 'real cmd-injection surface' from 'legitimate
    process spawn'. Saves Stage 2 hypothesis budget on functions
    like extract_content_from_html (uses subprocess.run with shell=
    False to invoke node) that were burning Stage 2 cycles on
    refuted cmd-injection hypotheses pre-v14."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    # AST scanner tracks per-function subprocess shell mode
    assert "subprocess_shell_by_fn" in script
    # Detects the standard subprocess fn names
    for name in ("'run'", "'Popen'", "'call'", "'check_call'", "'check_output'"):
        assert name in script, f"subprocess fn {name} missing from detector"
    # Three-state classification surfaces in the observation
    assert "'shell_true'" in script
    assert "'shell_false_only'" in script
    assert "subprocess_shell_mode_static" in script


def test_probe_script_v14_mock_journal_capped() -> None:
    """v14-B: the journal cap (200 module-level, 30 per-callable slice)
    keeps the profile size sane even when class methods spam attribute
    chains. Without caps a recursive mock could OOM the probe."""
    script = _build_python_behavioral_probe_script(
        module_name="t", file_name="t.py", file_id="abc"
    )
    # 200 is the global cap
    assert "_ARGUS_MOCK_JOURNAL_CAP = 200" in script
    # 30 is the per-callable slice cap
    assert "_mock_journal_slice[:30]" in script


def test_js_script_defines_argusmockjs_proxy() -> None:
    """v13 JS: _ArgusMockJS is a Proxy-based duck mock used for class
    constructor dependencies. Without it, classes that take complex
    objects (LangChain WebBrowser({model, embeddings, ...})) can't be
    instantiated and their methods stay unreachable."""
    script = _build_js_script()
    assert "_ArgusMockJS" in script
    assert "new Proxy" in script
    # Promise-interop guards (must not return mock for 'then')
    assert "'then'" in script
    assert "'catch'" in script


def test_js_script_v14_argusmockjs_records_to_journal() -> None:
    """v14-B JS parity: _ArgusMockJS records every get + apply into
    _argusMockJournalJS so Stage 2 sees data flow through mocked
    class constructor dependencies (model.invoke, db.execute, etc.)."""
    script = _build_js_script()
    assert "_argusMockJournalJS" in script
    assert "_ARGUS_MOCK_JOURNAL_CAP_JS" in script
    # Records on get + apply
    assert "op: 'getattr'" in script
    assert "op: 'call'" in script
    # Per-callable journal slice is surfaced
    assert "mock_journal_slice" in script


def test_js_script_defines_try_instantiate_with_multiple_strategies() -> None:
    """v13 JS: _tryInstantiate walks through zero-arg → kwargs-object
    → single-mock-arg → bag-of-mocks strategies (same shape as the
    Python _try_instantiate). Handles the LangChain-style ctor pattern."""
    script = _build_js_script()
    assert "_tryInstantiate" in script
    assert "new Cls()" in script
    # Strategy 2: kwargs object with mock-stuffed common keys
    assert "model: _ArgusMockJS()" in script
    assert "embeddings: _ArgusMockJS()" in script


def test_js_script_detects_es6_classes_and_enumerates_methods() -> None:
    """v13 JS: when an export is a class, the harness must instantiate
    it and enumerate its prototype methods (one tier deep). Otherwise
    LangChain's WebBrowser stays a single 'function' callable instead
    of expanding to WebBrowser.invoke / WebBrowser._call etc."""
    script = _build_js_script()
    assert "_isLikelyClass" in script
    assert "_enumerateClassMethods" in script
    assert "Object.getPrototypeOf" in script
    # ES6 class detection via Function.prototype.toString
    assert "class " in script


def test_js_script_dispatches_class_methods_through_instance() -> None:
    """v13 JS: when a callable has an associated instance (it's a
    class method), the per-call loop must invoke as instance.method(...)
    so 'this' resolves correctly. Without this binding the call would
    run with this=null and methods that touch this.* fields error."""
    script = _build_js_script()
    # Callable shape carries an instance slot
    assert "instance: instance || null" in script
    # Per-call dispatch checks for instance
    assert "if (c.instance !== null" in script
    assert "bound.apply(c.instance" in script


def test_js_script_pickinputs_call_site_passes_callable_name() -> None:
    """v13 JS parity: the per-callable invocation loop must thread the
    callable's name into _pickInputs so the name-hint selector fires
    on functions like fetch_url, query, etc."""
    script = _build_js_script()
    # Old call: _pickInputs(c.arity).  v13 call: _pickInputs(c.name, c.arity).
    assert "_pickInputs(c.name, c.arity)" in script
    # Old single-arg call must be gone (regression guard).
    assert "_pickInputs(c.arity)" not in script.replace(
        "_pickInputs(c.name, c.arity)", ""
    )


def test_name_hint_longest_match_wins_for_specificity() -> None:
    """v13 contract: when both 'fetch' and 'fetch_url' are present in
    the name-hint table, the longer keyword wins for functions named
    'fetch_url'. Prevents shorter generic keys from shadowing more
    specific ones. The probe-script side does the sorting; we test the
    constants admit the right precedence."""
    from dast.behavioral_probe import _NAME_TO_ADVERSARIAL_HINT

    if "fetch_url" in _NAME_TO_ADVERSARIAL_HINT and "fetch" in _NAME_TO_ADVERSARIAL_HINT:
        # If both exist, they should map to compatible adversarial
        # values (both URL-shaped). This is a sanity check that
        # specific patterns don't accidentally point to wrong
        # attack class.
        fetch_url_seed = _NAME_TO_ADVERSARIAL_HINT["fetch_url"]
        fetch_seed = _NAME_TO_ADVERSARIAL_HINT["fetch"]
        # Both should be URL-shaped strings.
        assert "http" in fetch_url_seed and "http" in fetch_seed


def test_js_script_monkey_patches_child_process() -> None:
    """child_process.exec/spawn/etc. surface for subprocess signal."""
    script = _build_js_script()
    for fn in ("exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"):
        assert f"'{fn}'" in script, f"child_process.{fn} should be wrapped"
    assert "_markSubprocess" in script


def test_js_script_monkey_patches_fs_module() -> None:
    """fs.readFile/writeFile/etc. surface for file I/O signal."""
    script = _build_js_script()
    for fn in (
        "readFile",
        "readFileSync",
        "writeFile",
        "writeFileSync",
        "createReadStream",
        "createWriteStream",
    ):
        assert f"'{fn}'" in script, f"fs.{fn} should be wrapped"
    assert "_markFile" in script


def test_js_script_monkey_patches_network() -> None:
    """http / https / net surfaces for network-attempt signal."""
    script = _build_js_script()
    assert "http.request" in script or "_wrapReq(http, 'request')" in script
    assert "https.request" in script or "_wrapReq(https, 'request')" in script
    assert "net.connect" in script or "_wrapReq(net, 'connect')" in script
    assert "_markNetwork" in script


def test_js_script_monkey_patches_require_for_module_reach() -> None:
    """Module.prototype.require must be wrapped so we see what modules
    the target loads (calls_dynamic_import signal)."""
    script = _build_js_script()
    assert "Module.prototype.require" in script
    assert "_markDynImport" in script


def test_js_script_uses_dynamic_import_for_target() -> None:
    """Target loaded via dynamic ``import()`` so both CJS and ESM
    targets work. ``pathToFileURL`` required for absolute paths on
    Node 14+."""
    script = _build_js_script()
    assert "await import(" in script
    assert "pathToFileURL" in script


def test_js_script_enumerates_named_and_default_exports() -> None:
    """Callable enumeration must cover both ESM-style named exports
    and default export (function OR object with method keys)."""
    script = _build_js_script()
    assert "Object.keys(mod" in script  # named exports walk
    assert "mod.default" in script  # default export check
    assert "_addCallable" in script


def test_js_script_static_regex_scan_for_eval_exec_static() -> None:
    """Static regex scan complements monkey patches — catches direct
    callsites in the target source even if the target intercepts our
    patches (defense in depth). Same role as Python's AST pass."""
    script = _build_js_script()
    assert "_staticScan" in script
    assert "calls_eval_static" in script
    assert "calls_exec_static" in script


def test_js_script_emits_schema_matching_python_profile() -> None:
    """JS profile JSON must use the SAME field names as Python's
    BehavioralProfile so ``parse_behavioral_probe_trace`` works
    uniformly. Critical for Stage 2 reasoning consistency."""
    script = _build_js_script()
    # Required top-level fields
    for field in (
        "file_id",
        "file_name",
        "callables",
        "dataflow_hints",
        "import_error",
        "callables_total",
        "callables_explored",
        "elapsed_ms",
    ):
        assert field in script, f"profile field '{field}' must appear in JS script"


def test_js_script_writes_to_workspace_result_file() -> None:
    """File-based transport fallback — bypasses Fly's per-log-line ~4KB
    stdout cap that truncates large markers. Same approach the Python
    harness uses."""
    script = _build_js_script()
    assert "/workspace/argus_probe_result.json" in script


def test_js_script_embeds_file_id_for_traceability() -> None:
    """The profile must echo the orchestrator-provided file_id back so
    the parser can verify identity."""
    script = _build_js_script()
    assert '"abc123def456"' in script  # JSON-encoded file_id literal


# ── Trace parser ───────────────────────────────────────────────────────────


def test_parse_trace_empty_stdout_returns_empty_profile() -> None:
    """No marker in stdout → empty profile, not raise. Caller treats
    empty profile as "probe failed to produce usable output".

    F-A1 (2026-05-21): now also populates ``harness_error`` with a
    structured ``marker_missing:`` diagnostic so callers can tell apart
    "probe didn't run / nothing came back" from "probe ran cleanly and
    found nothing to enumerate"."""
    p = parse_behavioral_probe_trace(file_id="abc", file_name="x.py", stdout="")
    assert isinstance(p, BehavioralProfile)
    assert p.callables == []
    assert p.dataflow_hints == []
    assert p.import_error == ""
    assert p.callables_explored == 0
    # F-A1: both channels empty → structured diagnostic.
    assert p.harness_error == (
        "marker_missing:no_probe_result_file_and_no_stdout_marker"
    )


def test_parse_trace_propagates_harness_error_field() -> None:
    """v15.6 (2026-05-20): the harness's top-level ``excepthook``
    writes a partial profile with ``harness_error`` populated when
    the script crashes mid-enumeration. The parser must propagate
    that field onto the typed profile so the orchestrator can
    surface the traceback for debugging.

    Pre-v15.6 these crashes were silent (empty profile,
    ``elapsed_ms=0``) and impossible to diagnose without rebuilding
    the sandbox image.
    """
    marker_payload = {
        "file_id": "abc",
        "file_name": "x.py",
        "callables": [],
        "dataflow_hints": [],
        "import_error": "",
        "harness_error": (
            'Traceback (most recent call last):\n'
            '  File "<string>", line 412, in <module>\n'
            "TypeError: descriptor 'foo' for 'Bar' objects doesn't apply\n"
        ),
        "callables_total": 0,
        "callables_explored": 0,
        "elapsed_ms": 42,
    }
    marker = "BEHAVIORAL_PROFILE_JSON:" + json.dumps(marker_payload) + "\n"
    p = parse_behavioral_probe_trace(file_id="abc", file_name="x.py", stdout=marker)
    assert p.import_error == ""
    assert "TypeError" in p.harness_error
    assert p.elapsed_ms == 42


def test_parse_trace_broken_json_skipped() -> None:
    """A marker line with malformed JSON is ignored — probe stays empty
    rather than raising.

    F-A1: harness_error now identifies that a marker WAS seen but its
    JSON couldn't be decoded (typical cause: log-line truncation)."""
    bad = "BEHAVIORAL_PROFILE_JSON:{not valid json\n"
    p = parse_behavioral_probe_trace(file_id="abc", file_name="x.py", stdout=bad)
    assert p.callables == []
    assert p.harness_error == (
        "marker_missing:stdout_marker_present_but_unparseable_json"
    )


# ─── F-A1 (SCAN-015) — marker-missing diagnostic ─────────────────────────


def test_parse_trace_fa1_both_channels_silent() -> None:
    """No probe_result_json AND no stdout marker → diagnostic surfaces
    the most common case: sandbox SIGKILL before emit.

    Pre-F-A1 this was the exact pattern observed on openai-python's
    ``_base_client.py`` and ~30/33 campaign files: heavy-import file
    enters the sandbox, runs out of time / mem before reaching the
    BEHAVIORAL_PROFILE_JSON emit, parser returns an all-zeros profile
    with both error fields empty. Operators read this as "Stage 1 ran
    and found nothing" — the actual cause was Stage 1 dying mid-
    enumeration. F-A1 makes the failure mode loud."""
    p = parse_behavioral_probe_trace(
        file_id="abc", file_name="x.py", stdout="some other unrelated output\n"
    )
    assert p.harness_error == (
        "marker_missing:no_probe_result_file_and_no_stdout_marker"
    )
    assert p.callables_total == 0


def test_parse_trace_fa1_file_unparseable_no_stdout() -> None:
    """File channel present but invalid JSON, no stdout marker. This
    happens when the sandbox entrypoint drain delivered a partial file
    (interrupted write) and the harness's stdout was suppressed by
    the runner's log capture."""
    p = parse_behavioral_probe_trace(
        file_id="abc",
        file_name="x.py",
        stdout="",
        probe_result_json='{"partial": tru',  # invalid
    )
    assert p.harness_error == (
        "marker_missing:probe_result_file_unparseable_no_stdout_marker"
    )


def test_parse_trace_fa1_both_channels_unparseable() -> None:
    """Belt-and-suspenders failure: both channels have content, neither
    parses. Should surface the most-specific diagnostic."""
    p = parse_behavioral_probe_trace(
        file_id="abc",
        file_name="x.py",
        stdout="BEHAVIORAL_PROFILE_JSON:{trunc",  # invalid stdout marker
        probe_result_json="{partial",  # invalid file
    )
    assert p.harness_error == (
        "marker_missing:probe_result_file_unparseable_stdout_marker_unparseable"
    )


def test_parse_trace_fa1_clean_empty_callables_no_diagnostic() -> None:
    """When the harness ran successfully and emitted a valid profile
    that just happens to have 0 callables (e.g., a constants-only
    module), the diagnostic must NOT fire — that's a real clean run.

    Distinguishes "Stage 1 ran cleanly, file has no public callables"
    from "Stage 1 died before emitting anything"."""
    marker = "BEHAVIORAL_PROFILE_JSON:" + json.dumps(
        {
            "file_id": "abc",
            "file_name": "x.py",
            "callables": [],
            "callables_total": 0,
            "callables_explored": 0,
            "elapsed_ms": 42,
            "import_error": "",
            "harness_error": "",
        }
    )
    p = parse_behavioral_probe_trace(
        file_id="abc", file_name="x.py", stdout=marker
    )
    assert p.harness_error == ""  # no diagnostic — this was a clean run
    assert p.elapsed_ms == 42
    assert p.callables_total == 0


def test_parse_trace_fa1_does_not_clobber_harness_error_from_payload() -> None:
    """When the harness emits a marker WITH harness_error already set
    (its own try/except caught an enumeration crash), the parser must
    NOT overwrite that field with the marker-missing diagnostic.
    The harness's own traceback is more useful than the channel
    diagnostic."""
    marker = "BEHAVIORAL_PROFILE_JSON:" + json.dumps(
        {
            "file_id": "abc",
            "file_name": "x.py",
            "harness_error": (
                "Traceback: TypeError descriptor 'foo' not applicable"
            ),
            "callables_total": 0,
            "callables_explored": 0,
            "elapsed_ms": 100,
        }
    )
    p = parse_behavioral_probe_trace(
        file_id="abc", file_name="x.py", stdout=marker
    )
    assert "TypeError" in p.harness_error
    assert "marker_missing" not in p.harness_error


def test_parse_trace_roundtrips_synthetic_marker() -> None:
    """Construct a synthetic marker line, parse it, verify fields land
    on the typed profile structure."""
    marker_payload = {
        "file_id": "abc",
        "file_name": "x.py",
        "callables": [
            {
                "name": "parse_config",
                "signature": "(s: str) -> dict",
                "invocations": [
                    {
                        "args_repr": "['x']",
                        "ok": True,
                        "return_type": "dict",
                        "value_preview": "{'hook': 'x'}",
                        "elapsed_ms": 1,
                    }
                ],
                "calls_eval": False,
                "calls_exec": False,
                "calls_compile": False,
                "calls_subprocess": False,
                "calls_pickle_loads": False,
                "calls_marshal_loads": False,
                "calls_dynamic_import": False,
                "opens_files": [],
                "writes_files_in_tmp": [],
                "network_attempts": [],
            },
            {
                "name": "apply_config",
                "signature": "(cfg: dict) -> str",
                "invocations": [
                    {
                        "args_repr": "[{}]",
                        "ok": False,
                        "exception_type": "KeyError",
                        "exception_msg": "'hook'",
                        "elapsed_ms": 1,
                    }
                ],
                "calls_eval": True,  # apply_config evals the hook
                "calls_exec": False,
                "calls_compile": False,
                "calls_subprocess": False,
                "calls_pickle_loads": False,
                "calls_marshal_loads": False,
                "calls_dynamic_import": False,
                "opens_files": [],
                "writes_files_in_tmp": [],
                "network_attempts": [],
            },
        ],
        "dataflow_hints": [
            {
                "source_function": "parse_config",
                "sink_function": "apply_config",
                "callsite_line": 42,
                "flow_kind": "return_to_arg",
            }
        ],
        "import_error": "",
        "callables_total": 2,
        "callables_explored": 2,
        "elapsed_ms": 250,
    }
    stdout = "BEHAVIORAL_PROFILE_JSON:" + json.dumps(marker_payload) + "\n"
    p = parse_behavioral_probe_trace(file_id="abc", file_name="x.py", stdout=stdout)
    assert len(p.callables) == 2
    assert p.callables[0].name == "parse_config"
    assert p.callables[1].calls_eval is True
    assert len(p.dataflow_hints) == 1
    assert p.dataflow_hints[0].source_function == "parse_config"
    assert p.dataflow_hints[0].sink_function == "apply_config"
    assert p.dataflow_hints[0].callsite_line == 42
    assert p.callables_explored == 2
    assert p.elapsed_ms == 250


def test_parse_trace_recovers_marker_with_other_stdout_lines() -> None:
    """Other lines in stdout (log noise, print()s from the target
    module) don't prevent marker recovery."""
    marker = "BEHAVIORAL_PROFILE_JSON:" + json.dumps(
        {
            "file_id": "abc",
            "file_name": "x.py",
            "callables": [],
            "dataflow_hints": [],
            "import_error": "",
            "callables_total": 0,
            "callables_explored": 0,
            "elapsed_ms": 100,
        }
    )
    stdout = "[INFO] starting up\nsome stdout line\n" + marker + "\n[INFO] done\n"
    p = parse_behavioral_probe_trace(file_id="abc", file_name="x.py", stdout=stdout)
    assert p.elapsed_ms == 100


def test_parse_trace_captures_import_error() -> None:
    """When the target module fails to import, the probe emits a marker
    with ``import_error`` set; the parser surfaces that as a diagnostic
    field on the profile."""
    marker = "BEHAVIORAL_PROFILE_JSON:" + json.dumps(
        {
            "file_id": "abc",
            "file_name": "x.py",
            "callables": [],
            "dataflow_hints": [],
            "import_error": "ModuleNotFoundError: No module named 'lxml'",
            "callables_total": 0,
            "callables_explored": 0,
            "elapsed_ms": 50,
        }
    )
    p = parse_behavioral_probe_trace(file_id="abc", file_name="x.py", stdout=marker)
    assert p.import_error.startswith("ModuleNotFoundError")


# ── Orchestrator integration ───────────────────────────────────────────────


@dataclass
class _CapturingBehavioralSandbox:
    """Stub sandbox that delivers a canned BEHAVIORAL_PROFILE_JSON
    marker for the first BP_<...> plan it sees, plus benign defaults
    for everything else (so the rest of the orchestrator doesn't
    crash)."""

    submitted_plans: list[SandboxPlan] = dc_field(default_factory=list)
    file_content_map: dict[str, bytes] = dc_field(default_factory=dict)
    canned_profile_stdout: str = ""

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        self.submitted_plans.append(plan)
        is_behavioral = plan.hypothesis_id.startswith("BP_")
        stdout = self.canned_profile_stdout if is_behavioral else ""
        evt = SandboxEvent(
            event_id=f"evt-{plan.hypothesis_id}",
            kind="execution_output",
            payload={"hypothesis_id": plan.hypothesis_id},
        )
        return SandboxTrace(
            plan_id=plan.plan_id,
            file_id=plan.file_id,
            hypothesis_id=plan.hypothesis_id,
            events=[evt],
            exit_code=0,
            stdout_excerpt=stdout,
            stderr_excerpt="",
            elapsed_ms=10,
        )


def _minimal_phase_a_response() -> str:
    """Phase A verdict — the orchestrator runs Phase A as part of the
    main iter loop. Return a minimal valid response so the rest of the
    flow doesn't crash."""
    return json.dumps(
        {
            "verdict_label": "suspicious",
            "log_summary": "stub",
            "validated_findings": [],
            "confirmed_categories": [],
        }
    )


def _empty_phase_b_response() -> str:
    return json.dumps(
        {
            "stop_reason": "no_new_hypotheses",
            "non_code_regions_inspected": [],
            "new_hypotheses": [],
        }
    )


@pytest.mark.asyncio
async def test_behavioral_probe_skipped_when_flag_disabled(tmp_path) -> None:
    """``enable_phase_3_discovery=False`` (default) → no BP_<...> plan
    is submitted. Sanity guard so existing users don't start paying
    the probe cost unintentionally even with --enable-runtime-probe."""
    sandbox = _CapturingBehavioralSandbox()

    async def fake_inference(prompt, options, schema):
        return {
            "text": _minimal_phase_a_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "def f(p): return p\n",
        "file_name": "v.py",
        "original_bytes": b"def f(p): return p\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
        enable_phase_3_discovery=False,  # OFF
    )

    bp_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id.startswith("BP_")]
    assert bp_plans == [], "behavioral probe must not run when flag disabled"
    assert result.runtime_behavioral_profile is None


@pytest.mark.asyncio
async def test_behavioral_probe_runs_for_javascript(tmp_path) -> None:
    """JS DAST parity (v1.8): JavaScript files now produce a Stage 1 plan.

    Pre-v1.8 the orchestrator gate fenced non-Python files off entirely.
    With JS parity wiring (a8dffe2..6e8dd01) the orchestrator admits JS
    and the behavioral_probe builder dispatches to the Node harness.
    This test pins the new behavior — a JS file with phase_3_discovery
    enabled produces a BP_<...> plan submitted to the sandbox."""
    sandbox = _CapturingBehavioralSandbox()

    async def fake_inference(prompt, options, schema):
        return {
            "text": _minimal_phase_a_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "module.exports = { f: () => 1 };\n",
        "file_name": "v.js",
        "original_bytes": b"module.exports = { f: () => 1 };\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
        enable_phase_3_discovery=True,
    )

    bp_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id.startswith("BP_")]
    assert len(bp_plans) == 1, f"JS Stage 1 should submit 1 BP plan, got {len(bp_plans)}"
    # Plan dispatched to Node harness (cjs extension).
    assert ".cjs" in bp_plans[0].commands[0]
    # Result may or may not have a profile depending on whether the
    # capturing sandbox stubs a usable profile — what we care about
    # here is that the PLAN was submitted (the orchestrator gate
    # admitted JS). Result-population is exercised in the next test.
    _ = result


@pytest.mark.asyncio
async def test_behavioral_probe_plan_wires_runtime_packages_for_own_dist(
    tmp_path,
) -> None:
    """v15.5 (2026-05-20): the BP plan submitted to the sandbox must
    carry ``runtime_packages=[<own_dist>]`` when ``project_root``
    points at a Python sdist (PKG-INFO present) AND
    ``enable_per_scan_dep_install=True``.

    Pre-v15.5 bug: the BP plan construction path in
    ``_run_phase_3_behavioral_probe`` was the only DAST plan site
    that didn't call ``runtime_packages_for_plan``. Net effect:
    BP harnesses shipped with ``runtime_packages=[]`` regardless of
    project_root, dast-init never pip-installed the target's
    distribution, and ``import <pkg>.<module>`` failed silently
    inside the sandbox -> callables_total=0 on every package-internal
    Python file.

    This test pins the wiring: a synthetic project_root with a
    PKG-INFO declaring ``Mako`` must produce a BP plan whose
    ``runtime_packages`` field contains ``Mako``.
    """
    proj = tmp_path / "Mako-1.3.12"
    proj.mkdir()
    (proj / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: Mako\n")

    sandbox = _CapturingBehavioralSandbox()

    async def fake_inference(prompt, options, schema):
        return {
            "text": _minimal_phase_a_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "fid",
        "source_text": "def f(p): return p\n",
        "file_name": "template.py",
        "original_bytes": b"def f(p): return p\n",
        "project_root": str(proj),
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
        enable_phase_3_discovery=True,
        enable_per_scan_dep_install=True,
    )

    bp_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id.startswith("BP_")]
    assert len(bp_plans) == 1, "expected exactly one BP_<...> plan"
    bp_plan = bp_plans[0]
    assert bp_plan.runtime_packages == ["Mako"], (
        f"BP plan must carry own_dist install — got {bp_plan.runtime_packages!r}"
    )


@pytest.mark.asyncio
async def test_behavioral_probe_plan_empty_runtime_packages_when_dep_install_off(
    tmp_path,
) -> None:
    """v15.5 boundary: when ``enable_per_scan_dep_install=False``,
    even with a PKG-INFO project_root the BP plan stays with
    ``runtime_packages=[]``. Respects the operator opt-out."""
    proj = tmp_path / "Mako-1.3.12"
    proj.mkdir()
    (proj / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: Mako\n")

    sandbox = _CapturingBehavioralSandbox()

    async def fake_inference(prompt, options, schema):
        return {
            "text": _minimal_phase_a_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "fid",
        "source_text": "def f(p): return p\n",
        "file_name": "template.py",
        "original_bytes": b"def f(p): return p\n",
        "project_root": str(proj),
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
        enable_phase_3_discovery=True,
        enable_per_scan_dep_install=False,  # OFF
    )

    bp_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id.startswith("BP_")]
    assert len(bp_plans) == 1
    assert bp_plans[0].runtime_packages == []


@pytest.mark.asyncio
async def test_behavioral_probe_skipped_for_unsupported_language(tmp_path) -> None:
    """Languages with no Stage 1 harness (shell, etc.) still get
    skipped at the orchestrator level. JS now goes through (test above);
    shell and unknown extensions still no-op."""
    sandbox = _CapturingBehavioralSandbox()

    async def fake_inference(prompt, options, schema):
        return {
            "text": _minimal_phase_a_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "#!/bin/bash\necho hi\n",
        "file_name": "v.sh",  # shell — no Stage 1 harness
        "original_bytes": b"#!/bin/bash\necho hi\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
        enable_phase_3_discovery=True,
    )

    bp_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id.startswith("BP_")]
    assert bp_plans == [], "behavioral probe must skip files without a per-language harness"
    assert result.runtime_behavioral_profile is None


@pytest.mark.asyncio
async def test_behavioral_probe_runs_and_surfaces_profile(tmp_path) -> None:
    """End-to-end: flag ON + Python file → BP_<...> plan submitted,
    canned profile delivered, parsed, surfaced on DastResult."""
    profile_payload = {
        "file_id": "h",
        "file_name": "v.py",
        "callables": [
            {
                "name": "parse_config",
                "signature": "(s)",
                "invocations": [
                    {
                        "args_repr": "['x']",
                        "ok": True,
                        "return_type": "dict",
                        "value_preview": "{'hook': 'x'}",
                        "elapsed_ms": 1,
                    }
                ],
                "calls_eval": False,
                "calls_exec": False,
                "calls_compile": False,
                "calls_subprocess": False,
                "calls_pickle_loads": False,
                "calls_marshal_loads": False,
                "calls_dynamic_import": False,
                "opens_files": [],
                "writes_files_in_tmp": [],
                "network_attempts": [],
            }
        ],
        "dataflow_hints": [],
        "import_error": "",
        "callables_total": 1,
        "callables_explored": 1,
        "elapsed_ms": 120,
    }
    canned_stdout = "BEHAVIORAL_PROFILE_JSON:" + json.dumps(profile_payload) + "\n"
    sandbox = _CapturingBehavioralSandbox(canned_profile_stdout=canned_stdout)

    async def fake_inference(prompt, options, schema):
        return {
            "text": _minimal_phase_a_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "def parse_config(s): return {'hook': s}\n",
        "file_name": "v.py",
        "original_bytes": b"def parse_config(s): return {'hook': s}\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
        enable_phase_3_discovery=True,
    )

    # BP plan was submitted exactly once
    bp_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id.startswith("BP_")]
    assert len(bp_plans) == 1
    # Profile flowed through to DastResult
    assert result.runtime_behavioral_profile is not None
    assert result.runtime_behavioral_profile["callables_explored"] == 1
    assert result.runtime_behavioral_profile["callables"][0]["name"] == "parse_config"


@pytest.mark.asyncio
async def test_behavioral_probe_journals_inconclusive_record(tmp_path) -> None:
    """Stage 1 is non-destructive: journals one inconclusive record for
    traceability, does NOT generate confirmed/rejected findings."""
    profile_payload = {
        "file_id": "h",
        "file_name": "v.py",
        "callables": [],
        "dataflow_hints": [],
        "import_error": "",
        "callables_total": 3,
        "callables_explored": 3,
        "elapsed_ms": 200,
    }
    sandbox = _CapturingBehavioralSandbox(
        canned_profile_stdout="BEHAVIORAL_PROFILE_JSON:" + json.dumps(profile_payload)
    )

    async def fake_inference(prompt, options, schema):
        return {
            "text": _minimal_phase_a_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "def f(): pass\n",
        "file_name": "v.py",
        "original_bytes": b"def f(): pass\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
        enable_phase_3_discovery=True,
    )

    # One BP_<...> journal record exists with verdict=inconclusive
    bp_records = [r for r in result.journal_records if str(r.get("claim_id", "")).startswith("BP_")]
    assert len(bp_records) >= 1
    assert all(r.get("verdict") == "inconclusive" for r in bp_records)
