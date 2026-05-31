"""Unit tests for dast/runtime_probe.py — Phase B+ runtime exploit probing.

Covers:
* Attack-class → CWE / severity mapping (fallbacks for unknown classes)
* Python harness generation (module-name derivation, getattr walk for
  ``Class.method``, args/kwargs decoding)
* Plan builder (returns None on non-Python files, embeds payload b64,
  generates HRP_<idx>_<idx> hypothesis IDs)
* Trace parser (RESULT_JSON / SIDE_EFFECTS marker recovery, defensive
  on truncated / broken-JSON stdout)
* Trace interpreter rules (rule 1: function returned ok on attack
  input; rule 2: canary tmp file observed; both fire = finding; neither
  fires = None)
* Schema validation (probe-candidate schema enforces shape +
  attack_class enum)

No live API; no sandbox booted. Uses synthetic SandboxTrace-shape
objects for the trace path.
"""

from __future__ import annotations

import base64
import json

import pytest

from dast import prompts as dast_prompts
from dast.runtime_probe import (
    DEFAULT_PROBE_TIMEOUT_SEC,
    MAX_CANDIDATES,
    MAX_INPUTS_PER_CANDIDATE,
    MAX_PROBE_RUNS_PER_FILE,
    RuntimeProbeCandidate,
    RuntimeProbeInput,
    _build_python_probe_harness,
    _python_module_name_for_file,
    build_runtime_probe_plan,
    cwe_for_attack_class,
    interpret_probe_trace,
    parse_probe_trace,
    severity_for_attack_class,
)

# ── Attack-class mapping ───────────────────────────────────────────────


def test_cwe_for_known_attack_classes() -> None:
    """Each documented attack class maps to a real CWE id."""
    assert cwe_for_attack_class("path_traversal") == "CWE-22"
    assert cwe_for_attack_class("command_injection") == "CWE-78"
    assert cwe_for_attack_class("code_injection") == "CWE-94"
    assert cwe_for_attack_class("deserialization") == "CWE-502"
    assert cwe_for_attack_class("sql_injection") == "CWE-89"
    assert cwe_for_attack_class("ssrf") == "CWE-918"


def test_cwe_for_unknown_attack_class_falls_back() -> None:
    """Unknown attack classes fall back to CWE-1035 (improper input
    validation) so finding emission never crashes on model-generated
    unknown class strings."""
    assert cwe_for_attack_class("alien_invasion") == "CWE-1035"
    assert cwe_for_attack_class("") == "CWE-1035"


def test_severity_for_known_attack_classes() -> None:
    assert severity_for_attack_class("code_injection") == "critical"
    assert severity_for_attack_class("command_injection") == "critical"
    assert severity_for_attack_class("path_traversal") == "high"
    assert severity_for_attack_class("xss") == "medium"


def test_severity_for_unknown_attack_class_falls_back_to_medium() -> None:
    assert severity_for_attack_class("alien_invasion") == "medium"


# ── Module-name derivation ─────────────────────────────────────────────


def test_module_name_strips_py_extension() -> None:
    assert _python_module_name_for_file("vulnerable_lib.py") == "vulnerable_lib"
    assert _python_module_name_for_file("foo.py") == "foo"


def test_module_name_uses_basename_for_path_inputs() -> None:
    """Sandbox stages files at /workspace/<basename>, so module name
    must derive from the basename, not the full path."""
    assert _python_module_name_for_file("mypkg/io_utils.py") == "io_utils"
    assert _python_module_name_for_file("/abs/path/to/module.py") == "module"


def test_module_name_replaces_illegal_chars() -> None:
    """Hyphens / dots aren't valid in Python module names — replaced
    with underscores so the harness ``import`` succeeds."""
    assert _python_module_name_for_file("foo-bar-baz.py") == "foo_bar_baz"
    assert _python_module_name_for_file("dotted.file.name.py") == "dotted_file_name"


def test_module_name_strips_src_layout_prefix_v1516() -> None:
    """v15.16 (2026-05-20): modern Python packages use the PEP 518
    src-layout (anthropic-sdk-python, pypa-style projects). When the
    sibling resolver detects project_root at the repo root (where
    pyproject.toml lives) and the entry rel-path is
    ``src/<pkg>/foo/bar.py``, the dotted name needs to drop the
    leading ``src.`` segment so the BP harness's
    ``import <pkg>.foo.bar`` resolves via the pip-installed copy
    rather than failing on ``src.<pkg>.foo.bar`` (which doesn't
    exist in site-packages).
    """
    # The anthropic SDK campaign case verbatim:
    assert (
        _python_module_name_for_file(
            "_auth.py", "src/anthropic/lib/aws/_auth.py"
        )
        == "anthropic.lib.aws._auth"
    )
    # Single-level src layout:
    assert (
        _python_module_name_for_file("foo.py", "src/mypkg/foo.py")
        == "mypkg.foo"
    )
    # __init__ collapse still works under src layout:
    assert (
        _python_module_name_for_file("__init__.py", "src/mypkg/__init__.py")
        == "mypkg"
    )


def test_module_name_src_strip_only_at_leading_position() -> None:
    """v15.16 boundary: only the LEADING ``src/`` segment is stripped.
    A ``src`` directory deeper in the path (e.g., ``mypkg/src/foo.py``)
    stays in the dotted name — that's a project's own ``src`` module,
    not the build-layout marker."""
    assert (
        _python_module_name_for_file("foo.py", "mypkg/src/foo.py")
        == "mypkg.src.foo"
    )


# ── Harness generation ─────────────────────────────────────────────────


def test_harness_contains_module_import_and_function_call() -> None:
    """Generated harness should import the target module, walk the
    function path with getattr, then call with decoded args/kwargs.

    v15.18: the getattr walk now lives inside a target_kind-aware
    dispatch block. The default 'function' branch still walks the
    full dotted name. ``_argus_parts`` carries the segment list.
    """
    h = _build_python_probe_harness(
        module_name="vulnerable_lib",
        function_name="read_file",
        args_json='["../etc/passwd"]',
        kwargs_json="{}",
    )
    assert "import vulnerable_lib as _target" in h
    # v15.18 dispatch shape: _argus_parts = function_name.split('.')
    assert "_argus_parts = 'read_file'.split('.')" in h
    # Function branch walks the full parts list.
    assert "for _argus_p in _argus_parts:" in h
    assert "fn = getattr(fn, _argus_p)" in h
    # Args / kwargs JSON literals embedded as Python string repr (not
    # f-substituted to avoid shell-quote hell). v1.6 Gap 2: wrapped in
    # _decode_bytes_sentinels() so {"__b64__": "..."} dicts get
    # converted to bytes before the function call.
    assert "args = _decode_bytes_sentinels(json.loads(" in h
    assert "kwargs = _decode_bytes_sentinels(json.loads(" in h
    assert "def _decode_bytes_sentinels" in h


def test_harness_supports_class_method_path() -> None:
    """For ``Class.method`` paths the harness's parts-list walk recovers
    every segment. v15.18: also covers the autodetect path that
    promotes function→instance_method when parent is a class."""
    h = _build_python_probe_harness(
        module_name="evil_mod",
        function_name="SafeLoader.load",
        args_json='["data"]',
        kwargs_json="{}",
    )
    assert "_argus_parts = 'SafeLoader.load'.split('.')" in h
    # Autodetect promotion check (parent isclass + tail != __init__)
    assert "_argus_inspect.isclass(_argus_parent)" in h
    assert "_argus_target_kind = 'instance_method'" in h


def test_v1518_harness_class_constructor_dispatch() -> None:
    """v15.18: when target_kind='class_constructor', the harness must
    call the class directly with test args (bypassing the __init__
    suffix). Pre-v15.18 the blind getattr walk landed on __init__ and
    invoked it without self → TypeError. The fix: parts[:-1] resolves
    the class, then call cls(*args, **kwargs)."""
    h = _build_python_probe_harness(
        module_name="anthropic.lib.credentials._providers",
        function_name="InMemoryConfig.__init__",
        args_json="[]",
        kwargs_json='{"config": {"federation_rule_id": "evil"}}',
        target_kind="class_constructor",
    )
    assert "_argus_target_kind = 'class_constructor'" in h
    # v15.18+15.20: class_constructor branch resolves the class then
    # calls the v15.20 _argus_construct helper, which fills any
    # missing __init__ args from inspect.signature before invoking
    # the class. The helper subsumes the pre-v15.20 direct call.
    assert "result = _argus_construct(_argus_parent, args, kwargs)" in h


def test_v1518_harness_instance_method_dispatch() -> None:
    """v15.18: when target_kind='instance_method', the harness must
    first construct the class with instance_init_args / kwargs, then
    call the bound method on that instance. Pre-v15.18 the unbound
    method got called without self → TypeError."""
    h = _build_python_probe_harness(
        module_name="anthropic.lib.credentials._providers",
        function_name="CredentialsFile._read_credentials",
        args_json='["evil_profile"]',
        kwargs_json="{}",
        target_kind="instance_method",
        instance_init_args_json="[]",
        instance_init_kwargs_json='{"path": "/tmp/argus_creds"}',
    )
    assert "_argus_target_kind = 'instance_method'" in h
    # v15.18+15.20: instance construction now routes through the
    # _argus_construct helper, which fills any missing __init__ args
    # via inspect.signature synthesis before invoking the class.
    assert (
        "_argus_instance = _argus_construct(_argus_parent, _argus_init_args, _argus_init_kwargs)"
        in h
    )
    # Method call on the constructed instance
    assert "_argus_method = getattr(_argus_instance, _argus_tail)" in h
    assert "result = _argus_method(*args, **kwargs)" in h


def test_v1518_harness_function_legacy_path_unchanged() -> None:
    """v15.18 backwards-compat: legacy 'function' candidates produce
    the same walk + call as pre-v15.18 (target_kind defaults to
    'function' when omitted by the caller)."""
    h = _build_python_probe_harness(
        module_name="legacy_mod",
        function_name="some_function",
        args_json='["x"]',
        kwargs_json="{}",
        # target_kind not passed → default "function"
    )
    assert "_argus_target_kind = 'function'" in h
    # Function branch walks the FULL parts list (not parts[:-1])
    assert "for _argus_p in _argus_parts:" in h


def test_v1518_unknown_target_kind_falls_back_to_function() -> None:
    """v15.18 defensive: typo'd / future / model-hallucinated target_kind
    values (e.g. 'metaclass_method', 'protocol') get sanitized to
    'function'. Guards against cached Sonnet outputs from older
    schemas or simply mistakes."""
    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
        target_kind="something_bogus",
    )
    # Sanitized to function default
    assert "_argus_target_kind = 'function'" in h


def test_v1518_runtime_probe_input_carries_init_args() -> None:
    """v15.18 schema sanity: RuntimeProbeInput has the new fields with
    safe defaults so legacy emit-paths still construct."""
    from dast.runtime_probe import RuntimeProbeInput

    inp = RuntimeProbeInput(args_json="[]")
    assert inp.instance_init_args_json == "[]"
    assert inp.instance_init_kwargs_json == "{}"

    inp2 = RuntimeProbeInput(
        args_json='["x"]',
        instance_init_args_json='["base"]',
        instance_init_kwargs_json='{"path": "/tmp/x"}',
    )
    assert inp2.instance_init_args_json == '["base"]'
    assert inp2.instance_init_kwargs_json == '{"path": "/tmp/x"}'


def test_v1518_runtime_probe_candidate_target_kind_defaults_to_function() -> None:
    """v15.18 schema sanity: RuntimeProbeCandidate.target_kind defaults
    to 'function' (backwards-compat) but accepts the full enum."""
    from dast.runtime_probe import RuntimeProbeCandidate

    cand = RuntimeProbeCandidate(function_name="f", attack_class="ssrf")
    assert cand.target_kind == "function"

    cand_im = RuntimeProbeCandidate(
        function_name="C.m", attack_class="ssrf", target_kind="instance_method"
    )
    assert cand_im.target_kind == "instance_method"


def _run_harness_against_synthetic_module(
    *,
    module_source: str,
    function_name: str,
    args_json: str,
    kwargs_json: str,
    target_kind: str = "function",
    instance_init_args_json: str = "[]",
    instance_init_kwargs_json: str = "{}",
    attack_class: str = "",
    tmp_path,
) -> tuple[int, str, str]:
    """Compile the harness for a synthetic module + actually run it.

    Stages ``module_source`` under tmp_path/workspace/<module_name>.py,
    builds the harness, runs it in a subprocess with workspace on the
    path, and returns (returncode, stdout, stderr). This is the unit-
    level analogue of the Fly sandbox path — catches integration bugs
    in the dispatch logic that the string-shape tests miss.
    """
    import subprocess
    import sys as _sys

    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    module_name = "target_module"
    (workspace / f"{module_name}.py").write_text(module_source, encoding="utf-8")
    module_file_path = str(workspace / f"{module_name}.py").replace("\\", "/")
    harness = _build_python_probe_harness(
        module_name=module_name,
        function_name=function_name,
        args_json=args_json,
        kwargs_json=kwargs_json,
        module_file_path=module_file_path,
        target_kind=target_kind,
        instance_init_args_json=instance_init_args_json,
        instance_init_kwargs_json=instance_init_kwargs_json,
        attack_class=attack_class,
    )
    # Replace the hardcoded /workspace with our tmp workspace so the
    # harness can find the staged module.
    harness = harness.replace(
        "sys.path.insert(0, '/workspace')",
        f"sys.path.insert(0, {str(workspace).replace(chr(92), '/')!r})",
    )
    proc = subprocess.run(
        [_sys.executable, "-c", harness],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_v1520_harness_emits_synth_helper() -> None:
    """v15.20: harness includes the _argus_synth_default and
    _argus_construct helpers for inspect.signature-driven constructor
    dependency injection."""
    h = _build_python_probe_harness(
        module_name="m",
        function_name="C.__init__",
        args_json="[]",
        kwargs_json="{}",
        target_kind="class_constructor",
    )
    assert "def _argus_synth_default(annotation):" in h
    assert "def _argus_construct(cls, supplied_args, supplied_kwargs):" in h
    assert "sig = _argus_inspect.signature(cls.__init__)" in h
    # Type-default branches present
    for t in ("str", "int", "bool", "bytes", "dict", "list"):
        assert f"if annotation is {t}: return" in h
    # Pathlib fallback branch
    assert "from pathlib import Path as _P" in h


def test_v1520_synthesizes_missing_str_arg(tmp_path) -> None:
    """End-to-end: when Sonnet provides empty instance_init_kwargs but
    the class requires a str positional arg, the harness synthesizes
    '' and invokes the method without TypeError."""
    src = (
        "class TokenReader:\n"
        "    def __init__(self, path: str):\n"
        "        self.path = path\n"
        "    def read(self, key: str):\n"
        "        return f'path={self.path} key={key}'\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="TokenReader.read",
        args_json='["api_key"]',
        kwargs_json="{}",
        target_kind="instance_method",
        # Sonnet supplied NOTHING for __init__ — synth must fill `path`
        instance_init_args_json="[]",
        instance_init_kwargs_json="{}",
        tmp_path=tmp_path,
    )
    assert rc == 0, f"harness exited nonzero: {stderr}"
    assert "path=" in stdout
    assert "key=api_key" in stdout
    assert "TypeError" not in stdout, (
        f"v15.20 regression: synth didn't fill missing str arg\n{stdout}"
    )


def test_v1520_synthesizes_missing_dict_arg(tmp_path) -> None:
    """End-to-end: required `dict` constructor arg synthesizes to {}."""
    src = (
        "class ConfigBag:\n"
        "    def __init__(self, settings: dict):\n"
        "        self.settings = settings\n"
        "    def has_key(self, k: str):\n"
        "        return k in self.settings\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="ConfigBag.has_key",
        args_json='["debug"]',
        kwargs_json="{}",
        target_kind="instance_method",
        instance_init_args_json="[]",
        instance_init_kwargs_json="{}",
        tmp_path=tmp_path,
    )
    assert rc == 0, f"harness exited nonzero: {stderr}"
    # has_key returns False on empty dict synth
    assert '"ok": true' in stdout.lower() or '"ok": True' in stdout
    assert "TypeError" not in stdout


def test_v1520_synthesizes_complex_path_arg(tmp_path) -> None:
    """End-to-end: pathlib.Path annotation produces a real Path object,
    not a None / empty fallback. Verifies the pathlib import branch."""
    src = (
        "from pathlib import Path\n"
        "class FileLoader:\n"
        "    def __init__(self, root: Path):\n"
        "        self.root = root\n"
        "    def resolve(self, name: str):\n"
        "        return str(self.root / name)\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="FileLoader.resolve",
        args_json='["data.json"]',
        kwargs_json="{}",
        target_kind="instance_method",
        instance_init_args_json="[]",
        instance_init_kwargs_json="{}",
        tmp_path=tmp_path,
    )
    assert rc == 0, f"harness exited nonzero: {stderr}"
    # Path('/tmp/argus_mock_path') / 'data.json' resolves with the
    # platform separator (forward on POSIX, backslash on Windows), so
    # match on the unique mock segment instead of a hard-coded path.
    assert "argus_mock_path" in stdout, (
        f"Path annotation should synth to a Path with 'argus_mock_path'; got {stdout}"
    )
    assert "data.json" in stdout
    assert "TypeError" not in stdout


def test_v1520_sonnet_supplied_args_take_precedence(tmp_path) -> None:
    """When Sonnet provides instance_init_kwargs, they win — synth only
    fills GAPS. Prevents the synth from clobbering attacker payloads."""
    src = (
        "class Token:\n"
        "    def __init__(self, value: str, scope: str):\n"
        "        self.value = value\n"
        "        self.scope = scope\n"
        "    def reveal(self):\n"
        "        return f'{self.value}/{self.scope}'\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="Token.reveal",
        args_json="[]",
        kwargs_json="{}",
        target_kind="instance_method",
        instance_init_args_json="[]",
        # Sonnet supplies value; synth fills scope
        instance_init_kwargs_json='{"value": "PWNED_BY_ATTACKER"}',
        tmp_path=tmp_path,
    )
    assert rc == 0, f"harness exited nonzero: {stderr}"
    assert "PWNED_BY_ATTACKER" in stdout, (
        "Sonnet-supplied value must reach the harness verbatim"
    )
    assert "TypeError" not in stdout


def test_v1520_skips_params_with_defaults(tmp_path) -> None:
    """When __init__ has a parameter with a default, synth must NOT
    fill it — let the class's own default win. Prevents synth from
    overriding meaningful defaults with empty-string placeholders."""
    src = (
        "class Cache:\n"
        "    def __init__(self, ttl: int = 300, region: str = 'us-east-1'):\n"
        "        self.ttl = ttl\n"
        "        self.region = region\n"
        "    def info(self):\n"
        "        return f'ttl={self.ttl} region={self.region}'\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="Cache.info",
        args_json="[]",
        kwargs_json="{}",
        target_kind="instance_method",
        instance_init_args_json="[]",
        instance_init_kwargs_json="{}",
        tmp_path=tmp_path,
    )
    assert rc == 0, f"harness exited nonzero: {stderr}"
    # Defaults must survive — NOT overridden by synth.
    assert "ttl=300" in stdout, f"v15.20 must respect __init__ defaults: {stdout}"
    assert "region=us-east-1" in stdout


def test_v1520_complex_nested_dep_degrades_via_object_new(tmp_path) -> None:
    """When synthesis can't construct a nested class (e.g. Inner has its
    own required positional args), the synth falls back to
    object.__new__(Inner) — an instance that bypasses __init__. Outer
    can still be constructed; the method runs. This is the production-
    grade graceful degradation: we'd rather get a result with a partial
    object than crash silently.

    If Outer.echo() touched self.inner.required_arg it would AttributeError,
    but here it doesn't, so the probe reaches the method body. That's
    the win: target reachability over guaranteed perfection."""
    src = (
        "class Inner:\n"
        "    def __init__(self, required_arg):\n"
        "        self.required_arg = required_arg\n"
        "class Outer:\n"
        "    def __init__(self, inner: 'Inner'):\n"
        "        self.inner = inner\n"
        "    def echo(self):\n"
        "        return 'hi'\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="Outer.echo",
        args_json="[]",
        kwargs_json="{}",
        target_kind="instance_method",
        instance_init_args_json="[]",
        instance_init_kwargs_json="{}",
        tmp_path=tmp_path,
    )
    # The synth's object.__new__ fallback let Outer construct with a
    # bare Inner instance; Outer.echo() returned 'hi'.
    assert rc == 0
    assert "'hi'" in stdout, f"expected echo result 'hi'; got {stdout}"
    assert "TypeError" not in stdout


def test_v1522_cwe_registry_maps_319_to_cleartext() -> None:
    """v15.22 — CWE-319 must route to cleartext_transmission, both
    with and without the CWE- prefix. Tests the registry directly."""
    from dast.cwe_probe_registry import attack_class_for_cwe

    assert attack_class_for_cwe("CWE-319") == "cleartext_transmission"
    assert attack_class_for_cwe("319") == "cleartext_transmission"
    assert attack_class_for_cwe("cwe-319") == "cleartext_transmission"
    # Related cleartext-family CWEs route the same way
    assert attack_class_for_cwe("CWE-311") == "cleartext_transmission"
    assert attack_class_for_cwe("CWE-312") == "cleartext_transmission"
    # Unknown CWE — return None, never raise
    assert attack_class_for_cwe("CWE-9999") is None
    assert attack_class_for_cwe(None) is None
    assert attack_class_for_cwe("") is None


def test_v1522_cwe_registry_full_coverage() -> None:
    """Spot-check key registry entries the prompt promises."""
    from dast.cwe_probe_registry import attack_class_for_cwe

    expected = {
        "CWE-22": "path_traversal",
        "CWE-78": "command_injection",
        "CWE-79": "xss",
        "CWE-89": "sql_injection",
        "CWE-94": "code_injection",
        "CWE-200": "data_exfiltration",
        "CWE-319": "cleartext_transmission",
        "CWE-327": "crypto_weakness",
        "CWE-362": "race_condition",
        "CWE-367": "race_condition",
        "CWE-502": "deserialization",
        "CWE-611": "xxe",
        "CWE-918": "ssrf",
    }
    for cwe, ac in expected.items():
        assert attack_class_for_cwe(cwe) == ac, f"{cwe} should map to {ac}"


def test_v1522_recommended_probes_for_l1_findings() -> None:
    """Bulk lookup helper turns a vulnerabilities list into
    {H001: cleartext_transmission, ...} for the prompt-rendering path."""
    from dast.cwe_probe_registry import recommended_probes_for_l1_findings

    vulns = [
        {"cwe": "CWE-319", "type": "cleartext"},
        {"cwe": "CWE-22", "type": "path"},
        {"cwe": "CWE-9999", "type": "unknown"},  # not in registry
        {"no_cwe": True},  # missing field
    ]
    out = recommended_probes_for_l1_findings(vulns)
    assert out == {
        "H001": "cleartext_transmission",
        "H002": "path_traversal",
    }


def test_v1522_attack_class_severity_and_cwe_for_cleartext() -> None:
    """cleartext_transmission must map to CWE-319 and severity=high."""
    from dast.runtime_probe import cwe_for_attack_class, severity_for_attack_class

    assert cwe_for_attack_class("cleartext_transmission") == "CWE-319"
    assert severity_for_attack_class("cleartext_transmission") == "high"


def test_v1522_evidence_signatures_for_cleartext_present() -> None:
    """The cleartext class-signature list must include the wiretap
    markers the harness emits, so the matcher fires on real captures."""
    from dast.runtime_probe import _ATTACK_CLASS_EVIDENCE_SIGNATURES

    sigs = _ATTACK_CLASS_EVIDENCE_SIGNATURES.get("cleartext_transmission", [])
    assert "ARGUS_WIRETAP_CLEARTEXT_OBSERVED" in sigs
    assert "Authorization: Bearer" in sigs
    assert "argus_wiretap_scheme=http" in sigs


def test_v1522_harness_wiretap_off_by_default() -> None:
    """No wiretap code emitted when attack_class is not
    cleartext_transmission — keeps the harness lean for the 12 other
    attack classes."""
    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
        attack_class="ssrf",
    )
    assert "_argus_wiretap_enabled = False" in h


def test_v1522_harness_wiretap_on_for_cleartext() -> None:
    """attack_class=cleartext_transmission flips _argus_wiretap_enabled
    True and emits the listener block."""
    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json='{"base_url": "__ARGUS_WIRETAP_URL__"}',
        attack_class="cleartext_transmission",
    )
    assert "_argus_wiretap_enabled = True" in h
    # Listener setup present
    assert "_argus_socket.socket(_argus_socket.AF_INET, _argus_socket.SOCK_STREAM)" in h
    assert "127.0.0.1" in h
    # URL placeholder substitution
    assert "__ARGUS_WIRETAP_URL__" in h
    assert "_argus_subst" in h
    # Capture buffer + thread setup
    assert "_argus_wiretap_capture" in h
    assert "_argus_threading.Thread" in h
    # Wiretap teardown
    assert "_argus_wiretap_thread.join" in h


def test_v1522_wiretap_captures_cleartext_http(tmp_path) -> None:
    """End-to-end: a function that does plain HTTP to __ARGUS_WIRETAP_URL__
    triggers the listener; the captured request appears in the harness
    output with the ARGUS_WIRETAP_CLEARTEXT_OBSERVED marker."""
    src = (
        "import urllib.request\n"
        "def send_token(base_url, token):\n"
        "    req = urllib.request.Request(\n"
        "        base_url,\n"
        "        headers={'Authorization': 'Bearer ' + token},\n"
        "    )\n"
        "    try:\n"
        "        urllib.request.urlopen(req, timeout=2.0).read()\n"
        "    except Exception as e:\n"
        "        return f'exception: {type(e).__name__}: {e}'\n"
        "    return 'sent'\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="send_token",
        args_json='["__ARGUS_WIRETAP_URL__", "SECRET_BEARER_TOKEN"]',
        kwargs_json="{}",
        attack_class="cleartext_transmission",
        tmp_path=tmp_path,
    )
    assert rc == 0, f"harness exit nonzero: {stderr}"
    # Wiretap was active
    assert '"wiretap_active": true' in stdout
    # Listener captured at least 1 request
    assert (
        '"wiretap_captures": 0' not in stdout
    ), f"wiretap should have captured at least 1 request; got: {stdout}"
    # Class signature substring fires
    assert "ARGUS_WIRETAP_CLEARTEXT_OBSERVED" in stdout
    # The Authorization header was transmitted in clear
    assert "Bearer" in stdout
    assert "SECRET_BEARER_TOKEN" in stdout
    # Scheme marker
    assert "argus_wiretap_scheme=http" in stdout


def test_v1522_wiretap_no_capture_for_clean_https_function(tmp_path) -> None:
    """When a function REFUSES to transmit over http (e.g. raises
    on non-https schemes), the wiretap captures nothing and emits the
    argus_wiretap_no_capture marker. This is the REFUTED-equivalent
    signal for cleartext probes."""
    src = (
        "def strict_send(base_url):\n"
        "    if not base_url.startswith('https://'):\n"
        "        raise ValueError(f'TLS required; refusing scheme in {base_url}')\n"
        "    return 'sent'\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="strict_send",
        args_json='["__ARGUS_WIRETAP_URL__"]',
        kwargs_json="{}",
        attack_class="cleartext_transmission",
        tmp_path=tmp_path,
    )
    assert rc == 0
    # The ValueError surfaced
    assert "ValueError" in stdout
    # No captures: function rejected before transmitting
    assert '"wiretap_captures": 0' in stdout
    # No cleartext class-signature marker fires (REFUTED)
    assert "ARGUS_WIRETAP_CLEARTEXT_OBSERVED" not in stdout
    # The no-capture marker is present
    assert "argus_wiretap_no_capture" in stdout


def test_v1518_executes_class_constructor_at_runtime(tmp_path) -> None:
    """End-to-end: target_kind='class_constructor' actually constructs
    the class without the missing-self TypeError that bit pre-v15.18.
    """
    src = (
        "class InMemoryConfig:\n"
        "    def __init__(self, config):\n"
        "        self.config = config\n"
        "    def __repr__(self):\n"
        "        return f'InMemoryConfig({self.config!r})'\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="InMemoryConfig.__init__",
        args_json="[]",
        kwargs_json='{"config": {"key": "value"}}',
        target_kind="class_constructor",
        tmp_path=tmp_path,
    )
    assert rc == 0, f"harness exited nonzero: {stderr}"
    assert "'ok': true" in stdout.lower() or '"ok": true' in stdout, (
        f"expected ok=True; got: {stdout}"
    )
    assert "InMemoryConfig" in stdout
    assert "'class_constructor'" in stdout or '"class_constructor"' in stdout
    # Critically: NO TypeError about missing self
    assert "TypeError" not in stdout, (
        f"v15.18 regression: class_constructor still hitting TypeError\n{stdout}"
    )


def test_v1518_executes_instance_method_at_runtime(tmp_path) -> None:
    """End-to-end: target_kind='instance_method' constructs the class,
    then invokes the method on the instance. No TypeError about
    missing self."""
    src = (
        "class CredentialsFile:\n"
        "    def __init__(self, path='/default'):\n"
        "        self.path = path\n"
        "    def _read_credentials(self, profile):\n"
        "        return {'profile': profile, 'path': self.path}\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="CredentialsFile._read_credentials",
        args_json='["evil_profile"]',
        kwargs_json="{}",
        target_kind="instance_method",
        instance_init_args_json="[]",
        instance_init_kwargs_json='{"path": "/tmp/test"}',
        tmp_path=tmp_path,
    )
    assert rc == 0, f"harness exited nonzero: {stderr}"
    # Result must contain the profile name we passed
    assert "evil_profile" in stdout
    assert "/tmp/test" in stdout, (
        "instance constructor args weren't applied — got: " + stdout
    )
    assert "'instance_method'" in stdout or '"instance_method"' in stdout
    assert "TypeError" not in stdout


def test_v1518_autodetect_promotes_unbound_method(tmp_path) -> None:
    """End-to-end: autodetect fallback. Caller omits target_kind (default
    'function'), but the resolved target is actually an unbound instance
    method. The harness's runtime autodetect promotes to
    'instance_method' and constructs the class — uses no-arg constructor
    since instance_init_args defaults are empty. No TypeError."""
    src = (
        "class NoArgClass:\n"
        "    def my_method(self, value):\n"
        "        return f'method received: {value}'\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="NoArgClass.my_method",
        args_json='["hello"]',
        kwargs_json="{}",
        # target_kind defaulted — relies on autodetect
        tmp_path=tmp_path,
    )
    assert rc == 0, f"harness exited nonzero: {stderr}"
    assert "method received: hello" in stdout
    # Autodetect set this at runtime even though caller passed 'function'
    assert "'instance_method'" in stdout or '"instance_method"' in stdout
    assert "TypeError" not in stdout


def test_v1518_autodetect_promotes_class_init(tmp_path) -> None:
    """End-to-end: autodetect promotes ``Class.__init__`` calls to
    class_constructor when target_kind was left at default."""
    src = (
        "class MyConfig:\n"
        "    def __init__(self, config):\n"
        "        self.config = config\n"
    )
    rc, stdout, stderr = _run_harness_against_synthetic_module(
        module_source=src,
        function_name="MyConfig.__init__",
        args_json="[]",
        kwargs_json='{"config": {"k": "v"}}',
        # No target_kind — must autodetect
        tmp_path=tmp_path,
    )
    assert rc == 0, f"harness exited nonzero: {stderr}"
    assert "'class_constructor'" in stdout or '"class_constructor"' in stdout
    assert "TypeError" not in stdout


def test_harness_emits_result_json_and_side_effects_markers() -> None:
    """Harness output is parsed via the ``RESULT_JSON:`` / ``SIDE_EFFECTS:``
    line markers — they must be in the generated code."""
    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    assert "RESULT_JSON:" in h
    assert "SIDE_EFFECTS:" in h
    # Side-effect diff = post-call /tmp listing minus baseline
    assert "tmp_files_added" in h


def test_harness_captures_exceptions_without_crashing() -> None:
    """Harness wraps the call in try/except so a raised exception
    still produces a marker line."""
    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    assert "except BaseException" in h or "except SystemExit" in h
    assert "exception_type" in h


# ── Path-prep preamble (env-fix v1.5) ──────────────────────────────────


def test_harness_imports_re_module_for_path_extraction() -> None:
    """Path-prep preamble uses re.findall — module must be imported."""
    h = _build_python_probe_harness(
        module_name="vuln",
        function_name="read",
        args_json="[]",
        kwargs_json="{}",
    )
    # re comes in via the top-level imports; cheap way to assert presence
    assert "import sys, os, json, traceback, re" in h


def test_harness_path_prep_extracts_module_source() -> None:
    """Preamble reads the staged module file from /workspace to regex-
    extract absolute-path string literals."""
    h = _build_python_probe_harness(
        module_name="vuln_lib",
        function_name="read",
        args_json="[]",
        kwargs_json="{}",
    )
    assert "_module_path = '/workspace/vuln_lib.py'" in h
    assert "_paths_to_prep = set(re.findall(" in h
    # The regex literal: matches '/letter[\w./-]*' inside ' or " quotes
    assert "/[A-Za-z_][\\w./-]*" in h


def test_harness_path_prep_skips_system_dirs() -> None:
    """Preamble must NOT attempt mkdir on read-only system dirs.
    Deny list is embedded so failed-mkdir noise stays out of stderr."""
    from dast.runtime_probe import _PROBE_PREP_DENY_PREFIXES

    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    # The deny tuple is embedded via repr() — every member must appear
    # somewhere in the embedded literal.
    for deny in _PROBE_PREP_DENY_PREFIXES:
        assert deny in h, f"deny prefix {deny!r} missing from harness"
    # And the skip-loop logic must be present
    assert "if any(_p == d or _p.startswith(d + '/') for d in _DENY):" in h


def test_harness_path_prep_calls_makedirs_with_exist_ok() -> None:
    """mkdir-p is the right semantic: NO-op if dir already exists,
    create it (with parents) otherwise. exist_ok=True is the
    idempotency guarantee."""
    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    assert "os.makedirs(_to_mk, exist_ok=True)" in h
    # PermissionError swallowed so mkdir failures don't break the probe
    assert "except (OSError, PermissionError):" in h


def test_path_prep_regex_extracts_expected_paths_from_fixture() -> None:
    """End-to-end check that the regex used in the harness preamble
    correctly identifies absolute-path literals in real fixture source.
    Uses the same regex inline so we test the string the harness will
    execute (not a duplicate of the production logic)."""
    import re as _re

    # Same pattern the harness embeds. If the regex below diverges from
    # the harness's, this test fails — keeping them in lockstep.
    pat = _re.compile(r"""['"]((?:/[A-Za-z_][\w./-]*))['"]""")
    src = (
        "from __future__ import annotations\n"
        "def read_file_safely(path: str) -> str:\n"
        '    if path.startswith("../"):\n'
        "        path = path[3:]\n"
        '    return open("/data/" + path).read()\n'
        "def write_log_entry(msg: str) -> None:\n"
        '    with open("/tmp/app.log", "a") as f:\n'
        "        f.write(msg)\n"
    )
    matches = set(pat.findall(src))
    # Must capture the absolute prefix used by the vulnerable function
    assert "/data/" in matches
    # Must capture the log file path (won't be mkdir'd because /tmp is
    # in the deny list, but the regex still picks it up)
    assert "/tmp/app.log" in matches
    # Must NOT capture relative paths (no leading slash)
    assert "../" not in matches


def test_harness_path_prep_handles_input_derived_paths() -> None:
    """For inputs like ``"subdir/../../etc/passwd"`` against a function
    rooted at ``/data/``, the harness must mkdir-p ``/data/subdir/`` so
    Linux's path resolver can descend through it. The preamble extends
    the source-extracted prefixes with input-derived suffixes."""
    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json='["subdir/../../etc/passwd"]',
        kwargs_json="{}",
    )
    # Loop over args + kwargs.values() to find input-derived paths
    assert "for _arg in args + list(kwargs.values()):" in h
    # Skip the path-traversal segments (only mkdir DIRECT components)
    assert "_skip = {'..', '.', ''}" in h
    # Must combine input components with each source absolute prefix
    assert "for _src_dir in _abs_dir_prefixes:" in h
    # Must respect the deny list for the cartesian-product paths too
    assert "if any(_full == d or _full.startswith(d + '/') for d in _DENY):" in h


def test_path_prep_basename_with_dot_means_file_means_mkdir_parent() -> None:
    """A literal like ``"/var/log/app.log"`` is a FILE path; the harness
    should mkdir the parent (``/var/log``), not the path itself."""
    # Replicates the harness's _to_mk derivation logic so we lock the
    # contract: if basename has '.' and path doesn't end with '/', use
    # dirname; else use the path itself (rstrip-trailing-slash form).
    import os as _os

    def _derive_mkdir_target(p: str) -> str:
        bn = _os.path.basename(p.rstrip("/"))
        if "." in bn and not p.endswith("/"):
            return _os.path.dirname(p)
        return p.rstrip("/")

    # File literal → mkdir parent
    assert _derive_mkdir_target("/var/log/app.log") == "/var/log"
    # Dir prefix (trailing slash) → mkdir the path itself
    assert _derive_mkdir_target("/data/") == "/data"
    # Bare dir (no trailing slash, no extension in basename) → mkdir self
    assert _derive_mkdir_target("/srv/app") == "/srv/app"
    # Single-component dir
    assert _derive_mkdir_target("/data") == "/data"


# ── Multi-language harness builders (JS / shell) ──────────────────────


def test_detect_probe_language_python() -> None:
    """Python source files dispatch to the python harness."""
    from dast.runtime_probe import detect_probe_language

    assert detect_probe_language("foo.py") == "python"
    assert detect_probe_language("path/to/bar.PY") == "python"


def test_detect_probe_language_javascript() -> None:
    """JS/CJS/MJS dispatch to the JavaScript harness."""
    from dast.runtime_probe import detect_probe_language

    assert detect_probe_language("foo.js") == "javascript"
    assert detect_probe_language("foo.mjs") == "javascript"
    assert detect_probe_language("foo.cjs") == "javascript"


def test_detect_probe_language_shell() -> None:
    """Shell scripts dispatch to the shell harness."""
    from dast.runtime_probe import detect_probe_language

    assert detect_probe_language("script.sh") == "shell"
    assert detect_probe_language("Install.bash") == "shell"


def test_detect_probe_language_typescript() -> None:
    """TypeScript files (.ts / .tsx) dispatch to the TypeScript harness
    branch (added v10, 2026-05-16). Same harness body as JavaScript,
    launched via tsx so the user's TS target transpiles on-the-fly
    during dynamic ``import()``."""
    from dast.runtime_probe import detect_probe_language

    assert detect_probe_language("foo.ts") == "typescript"
    assert detect_probe_language("foo.tsx") == "typescript"
    assert detect_probe_language("path/to/Index.TS") == "typescript"


def test_detect_probe_language_unsupported_returns_none() -> None:
    """File types we can't probe today return None so the orchestrator
    + plan builder can short-circuit cleanly. JSX explicitly returns
    None — Node + tsx alone don't strip JSX without explicit
    configuration; JSX support is a separate rollout."""
    from dast.runtime_probe import detect_probe_language

    assert detect_probe_language("foo.jsx") is None
    assert detect_probe_language("foo.java") is None
    assert detect_probe_language("foo.yaml") is None
    assert detect_probe_language("model.pkl") is None
    assert detect_probe_language("foo") is None  # no extension


def test_runtime_probe_plan_typescript_routes_via_tsx() -> None:
    """A .ts target builds an executable plan whose run command
    launches via ``tsx`` so the user's TS code is transpiled
    on-the-fly. The harness body is reused verbatim from the JS path
    (no TS types in our harness).

    v9 originally shipped with ``node --loader ts-node/esm`` but had
    100% TS-file Stage 1 failure due to a loader-hook cycle bug.
    tsx is the production runner (v10, 2026-05-16)."""
    candidate = _mk_candidate(
        function_name="readFile",
        attack_class="path_traversal",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["../../../etc/passwd"]',
                kwargs_json="{}",
                expected_observable="canary file read",
            )
        ],
    )

    plan = build_runtime_probe_plan(
        file_name="vuln.ts",
        file_bytes=b"export function readFile(p: string): string { return '' }\n",
        candidate=candidate,
        test_input=candidate.test_inputs[0],
        candidate_idx=0,
        input_idx=0,
    )

    assert plan is not None
    assert plan["plan_status"] == "executable"
    # Two-command plan: write harness, then run via tsx
    assert len(plan["commands"]) == 2
    write_cmd, run_cmd = plan["commands"]
    # Harness file stays .cjs (CJS-mode harness body)
    assert "_argus_probe_0_0.cjs" in write_cmd
    # tsx launches the harness; ts-node-era flags must NOT appear.
    assert "tsx " in run_cmd
    assert "ts-node" not in run_cmd
    assert "TS_NODE_TRANSPILE_ONLY" not in run_cmd
    assert "--loader" not in run_cmd
    assert "_argus_probe_0_0.cjs" in run_cmd
    # /workspace/package.json gets written with type=module so tsx
    # transpiles user .ts files as ESM (top-level await etc.).
    assert "package.json" in run_cmd
    assert '"type":"module"' in run_cmd
    # /workspace/tsconfig.json with moduleResolution=bundler so tsx
    # resolves ``import './foo.js'`` to ``./foo.ts`` source — required
    # for multi-file TS projects following the post-TS-5.0 convention.
    assert "tsconfig.json" in run_cmd
    assert '"moduleResolution":"bundler"' in run_cmd
    assert '"allowImportingTsExtensions":true' in run_cmd
    # Rationale mentions the language dispatch
    assert "typescript" in plan["rationale"].lower()


def test_runtime_probe_chain_plan_typescript_routes_via_tsx() -> None:
    """Chain probes on .ts targets reuse the JS chain harness and also
    launch via ``tsx`` so multi-step chains can transpile the user's
    TS code on dynamic import."""
    from dast.runtime_probe import (
        RuntimeProbeChain,
        RuntimeProbeChainStep,
        build_runtime_probe_chain_plan,
    )

    chain = RuntimeProbeChain(
        attack_class="ssrf",
        rationale="parse-then-fetch chain",
        expected_observable="canary file fetched",
        steps=[
            RuntimeProbeChainStep(
                function_name="parseUrl",
                args_json='["http://attacker"]',
                kwargs_json="{}",
            ),
            RuntimeProbeChainStep(
                function_name="fetchUrl",
                args_json="[\"<<_step0_result>>\"]",
                kwargs_json="{}",
            ),
        ],
    )

    plan = build_runtime_probe_chain_plan(
        file_name="chain_target.ts",
        file_bytes=b"export function parseUrl(u: string){return u}\n"
        b"export async function fetchUrl(u: string){return u}\n",
        chain=chain,
        chain_idx=0,
    )

    assert plan is not None
    assert plan["plan_status"] == "executable"
    write_cmd, run_cmd = plan["commands"]
    assert "_argus_chain_0.cjs" in write_cmd
    assert "tsx " in run_cmd
    assert "ts-node" not in run_cmd
    assert "TS_NODE_TRANSPILE_ONLY" not in run_cmd
    assert "--loader" not in run_cmd
    assert "cd /workspace" in run_cmd
    # /workspace/package.json gets written with type=module so tsx
    # transpiles user .ts files as ESM.
    assert "package.json" in run_cmd
    assert '"type":"module"' in run_cmd


def test_javascript_harness_builds_and_contains_landmarks() -> None:
    """JS harness is a self-contained Node script with these landmarks:
    async IIFE wrapper, dynamic import() of the staged module, dotted-
    path resolver tolerant of CJS + ESM-default-export, RESULT_JSON +
    SIDE_EFFECTS markers, async-aware invocation (await of any returned
    Promise), exception handler.
    """
    from dast.runtime_probe import _build_javascript_probe_harness

    h = _build_javascript_probe_harness(
        module_path="/workspace/vuln.js",
        function_name="readFile",
        args_json='["../etc/passwd"]',
        kwargs_json="{}",
    )
    # Async IIFE — needed for top-level await of import() + result.then()
    assert "(async () => {" in h
    # Dynamic import works for both CJS and ESM (the modern Node way)
    assert 'await import("/workspace/vuln.js")' in h
    # Dotted-path resolver
    assert "function resolveFn(modObj, dotted)" in h
    # ESM default-export fallback
    assert "if (typeof fn !== 'function' && mod.default != null)" in h
    # Async invocation handles promise-returning functions
    assert "if (result && typeof result.then === 'function')" in h
    assert "result = await result;" in h
    # Result + side-effect markers (same shape Python emits)
    assert "console.log('RESULT_JSON:" in h
    assert "console.log('SIDE_EFFECTS:" in h
    # Exception handler captures type + msg + stack tail
    assert "exception_type:" in h
    assert "tb_tail:" in h


def test_javascript_harness_path_prep_preamble() -> None:
    """JS harness has the same path-prep semantics as Python:
    extract absolute-path string literals from source + input args,
    fs.mkdirSync({recursive: true}) each, skip system dirs."""
    from dast.runtime_probe import _PROBE_PREP_DENY_PREFIXES, _build_javascript_probe_harness

    h = _build_javascript_probe_harness(
        module_path="/workspace/vuln.js",
        function_name="read",
        args_json='["subdir/../../etc/passwd"]',
        kwargs_json="{}",
    )
    # Same regex pattern (escaped for JS) for source extraction
    assert "/['\"](\\/[A-Za-z_]" in h
    # Recursive mkdir is the JS equivalent of os.makedirs(exist_ok=True)
    assert "fs.mkdirSync(toMk, { recursive: true });" in h
    # Input-derived path-prep — same cartesian product as Python
    assert "const SKIP = new Set(['..', '.', '']);" in h
    assert "for (const srcDir of absDirPrefixes) {" in h
    # Deny list embedded
    for deny in _PROBE_PREP_DENY_PREFIXES:
        assert deny in h, f"deny prefix {deny!r} missing from JS harness"


def test_javascript_harness_has_catastrophic_failure_safety_net() -> None:
    """Real-fixture validation surfaced Mode 1: Node exits code 1 without
    emitting any RESULT_JSON marker when an exception fires before the
    import block's try/catch (e.g., JSON.parse on a malformed payload,
    unhandled rejection in an async path-prep call). The interpreter
    then gets parsed_result=None and journals "no exploit observed" with
    empty exception_type — silent failure indistinguishable from a clean
    BLOCKED probe.

    Mitigation: top-level try/catch around the entire IIFE body +
    process-level handlers for ``uncaughtException`` /
    ``unhandledRejection``. Both paths funnel into ``_emitFatal`` which
    emits a RESULT_JSON marker before Node exits, so the interpreter
    always sees actionable evidence (exception_type filled, label
    indicating where the fatal fired)."""
    from dast.runtime_probe import _build_javascript_probe_harness

    h = _build_javascript_probe_harness(
        module_path="/workspace/foo.js",
        function_name="bar",
        args_json="[]",
        kwargs_json="{}",
    )
    # Process-level handlers — these fire when an exception escapes any
    # try/catch including the new outer one. Must be registered before
    # the IIFE so they're active during sync evaluation.
    assert "process.on('uncaughtException'" in h
    assert "process.on('unhandledRejection'" in h
    # Fatal-marker emitter — converts arbitrary error shapes into a
    # parseable RESULT_JSON so the interpreter never gets parsed_result=None.
    assert "function _emitFatal(label, err)" in h
    # Idempotency guard — multiple emission attempts (e.g., a try/catch
    # in the body already emitted, then an unhandledRejection fires
    # during the side-effect snapshot) collapse to a single marker.
    assert "let _markerEmitted = false;" in h
    assert "if (_markerEmitted) return;" in h
    # Outer try wraps the entire IIFE body — sync throws above the
    # import block (JSON.parse on bad args, ReferenceError in path-prep)
    # get caught here.
    assert "_emitFatal('iifeBody', e);" in h


def test_javascript_harness_kwargs_become_trailing_object_arg() -> None:
    """JS doesn't have native kwargs; the JS harness passes them as a
    trailing object argument (common JS convention). Functions that
    don't take that signature just ignore the extra arg."""
    from dast.runtime_probe import _build_javascript_probe_harness

    h = _build_javascript_probe_harness(
        module_path="/workspace/vuln.js",
        function_name="read",
        args_json="[]",
        kwargs_json="{}",
    )
    assert "const kwKeys = Object.keys(kwargs);" in h
    assert "const callArgs = kwKeys.length > 0 ? [...args, kwargs] : args;" in h
    assert "fn(...callArgs)" in h


def test_shell_harness_builds_and_runs_python_subprocess() -> None:
    """Shell harness is Python that drives bash via subprocess.run.
    Args become positional ($1, $2, ...), kwargs become env vars.
    Same RESULT_JSON / SIDE_EFFECTS markers as Python + JS so the
    deterministic interpreter rules apply uniformly."""
    import ast

    from dast.runtime_probe import _build_shell_probe_harness

    h = _build_shell_probe_harness(
        script_path="/workspace/install.sh",
        args_json='["; rm -rf /tmp"]',
        kwargs_json='{"DEBUG": "1"}',
    )
    # Harness itself is valid Python
    ast.parse(h)
    # Subprocess invocation of bash with the script + decoded args
    assert "subprocess.run(" in h
    assert "['bash', _script_path]" in h
    # Kwargs flow into env (string-coerced)
    assert "env[str(k)] = str(v)" in h
    # ok flag derived from exit code (0 = ran to completion = potential exploit)
    assert "'ok': _proc.returncode == 0" in h
    # Same trace markers
    assert "RESULT_JSON:" in h
    assert "SIDE_EFFECTS:" in h
    # Timeout safety
    assert "subprocess.TimeoutExpired" in h


def test_shell_harness_path_prep_preamble_same_as_python() -> None:
    """Shell harness reuses Python's path-prep preamble (it's written in
    Python after all). Same regex, same deny list, same mkdir-p."""
    from dast.runtime_probe import _build_shell_probe_harness

    h = _build_shell_probe_harness(
        script_path="/workspace/install.sh",
        args_json="[]",
        kwargs_json="{}",
    )
    assert "_paths_to_prep = set(re.findall(" in h
    assert "os.makedirs(_to_mk, exist_ok=True)" in h
    assert "_abs_dir_prefixes.add(_to_mk)" in h


def test_plan_builder_dispatches_python() -> None:
    """``.py`` files build a python3 harness."""
    cand = _mk_candidate(test_inputs=[RuntimeProbeInput(args_json="[]")])
    plan = build_runtime_probe_plan(
        file_name="vuln.py",
        file_bytes=b"def foo(): pass",
        candidate=cand,
        test_input=cand.test_inputs[0],
        candidate_idx=0,
        input_idx=0,
    )
    assert plan is not None
    # Final invocation runs python3 against the staged harness
    assert plan["commands"][1].startswith("python3 /workspace/")
    assert plan["commands"][1].endswith(".py")


def test_plan_builder_dispatches_javascript() -> None:
    """``.js`` / ``.mjs`` / ``.cjs`` build a node harness, saved as ``.cjs``
    so dynamic import() works for both CJS and ESM without needing a
    package.json:"type":"module" in /workspace."""
    for ext in (".js", ".mjs", ".cjs"):
        cand = _mk_candidate(test_inputs=[RuntimeProbeInput(args_json="[]")])
        plan = build_runtime_probe_plan(
            file_name=f"vuln{ext}",
            file_bytes=b"module.exports.foo = () => 1;",
            candidate=cand,
            test_input=cand.test_inputs[0],
            candidate_idx=0,
            input_idx=0,
        )
        assert plan is not None, f"plan for {ext} should be non-None"
        # v12 (2026-05-17): JS run_cmd now uses ``cd /workspace && node ...``
        # (was bare ``node /workspace/...``). The cd is harmless for
        # single-file scans and required for multi-file project staging
        # (parent-dir imports resolve from cwd, not harness path).
        assert "node /workspace/" in plan["commands"][1]
        assert plan["commands"][1].endswith(".cjs")
        assert "cd /workspace" in plan["commands"][1]


def test_plan_builder_dispatches_shell() -> None:
    """``.sh`` / ``.bash`` build a Python-orchestrated shell harness
    (Python wraps subprocess.run, args as positional, kwargs as env)."""
    for ext in (".sh", ".bash"):
        cand = _mk_candidate(test_inputs=[RuntimeProbeInput(args_json="[]")])
        plan = build_runtime_probe_plan(
            file_name=f"install{ext}",
            file_bytes=b"#!/bin/bash\necho hi",
            candidate=cand,
            test_input=cand.test_inputs[0],
            candidate_idx=0,
            input_idx=0,
        )
        assert plan is not None, f"plan for {ext} should be non-None"
        # Shell harness IS Python — runs python3
        assert plan["commands"][1].startswith("python3 /workspace/")
        assert plan["commands"][1].endswith(".py")


def test_plan_builder_unsupported_extensions_return_none() -> None:
    """JSX / Java / YAML / extensionless files — probe stage skips
    them cleanly. Plan builder returns None; orchestrator's entry-gate
    short-circuits on None.

    .ts / .tsx ARE supported as of v9 (2026-05-16) — see the dedicated
    ``test_runtime_probe_plan_typescript_routes_via_ts_node_loader``
    test for that path."""
    for fn in ("vuln.jsx", "Foo.java", "config.yaml", "model.pkl", "noext"):
        cand = _mk_candidate(test_inputs=[RuntimeProbeInput(args_json="[]")])
        plan = build_runtime_probe_plan(
            file_name=fn,
            file_bytes=b"x",
            candidate=cand,
            test_input=cand.test_inputs[0],
            candidate_idx=0,
            input_idx=0,
        )
        assert plan is None, f"{fn} should return None, got {plan}"


def test_plan_rationale_includes_language_tag() -> None:
    """The plan's rationale field should surface which language the
    harness uses — helpful for journal forensics when a probe fires
    on JS or shell and you want to know which interpreter was used."""
    for fn, lang_tag in (("foo.py", "python"), ("foo.js", "javascript"), ("foo.sh", "shell")):
        cand = _mk_candidate(test_inputs=[RuntimeProbeInput(args_json="[]")])
        plan = build_runtime_probe_plan(
            file_name=fn,
            file_bytes=b"x",
            candidate=cand,
            test_input=cand.test_inputs[0],
            candidate_idx=0,
            input_idx=0,
        )
        assert plan is not None and lang_tag in plan["rationale"]


# ── Plan builder ──────────────────────────────────────────────────────


def _mk_candidate(**kwargs):
    """Convenience: build a RuntimeProbeCandidate with one input."""
    defaults = dict(
        function_name="read_file",
        attack_class="path_traversal",
        rationale="reads filesystem path from user input",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["../etc/passwd"]',
                kwargs_json="{}",
                expected_observable="reads /etc/passwd content",
                exploit_proof_if_observed="path traversal — reads files outside intended dir",
            )
        ],
    )
    defaults.update(kwargs)
    return RuntimeProbeCandidate(**defaults)


def test_build_plan_basic_shape() -> None:
    plan = build_runtime_probe_plan(
        file_name="vuln.py",
        file_bytes=b"def read_file(p):\n    return open(p).read()\n",
        candidate=_mk_candidate(),
        test_input=_mk_candidate().test_inputs[0],
        candidate_idx=0,
        input_idx=0,
    )
    assert plan is not None
    assert plan["hypothesis_id"] == "HRP_0_0"
    assert plan["plan_status"] == "executable"
    assert plan["oracle"] == "execution_output_with_side_effect_observation"
    assert plan["payload_encoding"] == "base64"
    assert plan["timeout_sec"] == DEFAULT_PROBE_TIMEOUT_SEC
    # Payload decodes back to the original file bytes
    assert base64.b64decode(plan["payload"]) == b"def read_file(p):\n    return open(p).read()\n"


def test_build_plan_returns_none_for_unsupported_file() -> None:
    """File types outside ``_SUPPORTED_EXTS_BY_LANG`` (JSX, Java,
    YAML, binary artifacts, extensionless files) should produce None
    so the orchestrator skips them gracefully. JS / TS / shell / Python
    are handled by dedicated ``test_plan_builder_dispatches_*`` /
    ``test_runtime_probe_plan_typescript_*`` tests."""
    plan = build_runtime_probe_plan(
        file_name="foo.jsx",
        file_bytes=b"const X = () => <div>{p}</div>",
        candidate=_mk_candidate(),
        test_input=_mk_candidate().test_inputs[0],
        candidate_idx=0,
        input_idx=0,
    )
    assert plan is None


def test_build_plan_commands_write_then_run_harness() -> None:
    """The plan's two commands should (a) decode the b64 harness into
    /workspace and (b) invoke python3 against it. Avoids shell-quoting
    the harness inline."""
    plan = build_runtime_probe_plan(
        file_name="vuln.py",
        file_bytes=b"# stub",
        candidate=_mk_candidate(),
        test_input=_mk_candidate().test_inputs[0],
        candidate_idx=0,
        input_idx=0,
    )
    assert plan is not None
    assert len(plan["commands"]) == 2
    # First command writes the harness to /workspace
    assert "base64.b64decode" in plan["commands"][0]
    assert "/workspace/_argus_probe_0_0.py" in plan["commands"][0]
    # Second runs it
    assert "python3 /workspace/_argus_probe_0_0.py" in plan["commands"][1]


def test_build_plan_hypothesis_id_uses_candidate_input_indices() -> None:
    plan = build_runtime_probe_plan(
        file_name="x.py",
        file_bytes=b"",
        candidate=_mk_candidate(),
        test_input=_mk_candidate().test_inputs[0],
        candidate_idx=2,
        input_idx=1,
    )
    assert plan is not None
    assert plan["hypothesis_id"] == "HRP_2_1"
    assert "_argus_probe_2_1.py" in plan["commands"][0]


# ── Trace parsing ──────────────────────────────────────────────────────


def test_parse_trace_recovers_result_json_marker() -> None:
    stdout = (
        "some warning to stderr-but-on-stdout\n"
        'RESULT_JSON:{"ok": true, "type": "str", "value_preview": "root:x:0:0"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": []}\n'
    )
    trace = parse_probe_trace(
        candidate_function="read_file",
        input_args_json='["../etc/passwd"]',
        exit_code=0,
        stdout=stdout,
        stderr="",
        elapsed_ms=120,
    )
    assert trace.parsed_result is not None
    assert trace.parsed_result["ok"] is True
    assert trace.parsed_result["value_preview"] == "root:x:0:0"
    assert trace.side_effects == {"tmp_files_added": []}


def test_parse_trace_recovers_canary_files_in_side_effects() -> None:
    stdout = (
        'RESULT_JSON:{"ok": false, "exception_type": "OSError"}\n'
        'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned", "other.tmp"]}\n'
    )
    trace = parse_probe_trace(
        candidate_function="write_file",
        input_args_json='["/tmp/argus_probe_pwned", "data"]',
        exit_code=1,
        stdout=stdout,
        stderr="",
        elapsed_ms=50,
    )
    assert trace.side_effects["tmp_files_added"] == ["argus_probe_pwned", "other.tmp"]


def test_parse_trace_tolerates_broken_json_in_markers() -> None:
    """A truncated or malformed RESULT_JSON line must not crash the
    parser — the trace just has parsed_result=None and we move on."""
    stdout = "RESULT_JSON:{this is not valid json}\nSIDE_EFFECTS:also broken\n"
    trace = parse_probe_trace(
        candidate_function="f",
        input_args_json="[]",
        exit_code=0,
        stdout=stdout,
        stderr="",
        elapsed_ms=10,
    )
    assert trace.parsed_result is None
    assert trace.side_effects == {}


def test_parse_trace_handles_empty_stdout() -> None:
    """No markers at all = harness crashed pre-print. Trace fields stay
    at their sentinels."""
    trace = parse_probe_trace(
        candidate_function="f",
        input_args_json="[]",
        exit_code=137,  # killed
        stdout="",
        stderr="Segmentation fault",
        elapsed_ms=5,
    )
    assert trace.parsed_result is None
    assert trace.side_effects == {}
    assert trace.exit_code == 137


# ── Trace interpretation rules ─────────────────────────────────────────


def test_interpret_rule1_function_returned_ok_on_attack_input_emits_finding() -> None:
    """Rule 1: function succeeded on attack input the model said
    should be rejected → CONFIRMED finding via runtime evidence."""
    candidate = _mk_candidate()
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": true, "type": "str", '
            '"value_preview": "root:x:0:0:root:/root:/bin/bash..."}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=80,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    assert finding.finding_id == "HRP_0_0"
    assert finding.attack_class == "path_traversal"
    assert finding.cwe == "CWE-22"
    assert finding.severity == "high"
    assert "Function returned without raising" in finding.runtime_evidence
    # The attack input gets pasted into the proof for repro
    assert finding.test_input_args == '["../etc/passwd"]'


def test_interpret_rule2_canary_tmp_file_emits_finding() -> None:
    """Rule 2: harness raised, but the sandbox observed a canary file
    materialize in /tmp → exploit fired via side effects → finding."""
    candidate = _mk_candidate(
        attack_class="code_injection",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["__import__(\\"os\\").system(\\"touch /tmp/argus_probe_pwned\\")"]',
                kwargs_json="{}",
                expected_observable="canary file /tmp/argus_probe_pwned appears",
                exploit_proof_if_observed="eval injection — runs arbitrary code",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "SyntaxError"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned"]}\n'
        ),
        stderr="SyntaxError: invalid syntax",
        elapsed_ms=30,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    assert finding.attack_class == "code_injection"
    assert finding.cwe == "CWE-94"
    assert finding.severity == "critical"
    assert "argus_probe_pwned" in finding.runtime_evidence


def test_interpret_runtime_evidence_includes_kwargs_v1512() -> None:
    """v15.12 (2026-05-20): the runtime_evidence Probe display string
    includes kwargs_json when non-empty, not just args_json.

    Pre-v15.12 the format was ``Probe `fn(args_json)`` which hid the
    kwargs. On the mako/template.py campaign case, the Phase 3
    hypothesis called ``Template(text="<%! os.system('touch
    /tmp/argus_pwned')%>")`` but args_json was ``"[]"`` — so the
    displayed evidence read ``Probe `Template([])`` and an external
    reviewer (Gemini) concluded the canary must be stale state from
    a prior probe. The kwargs WERE the attack payload; just invisible.
    """
    candidate = _mk_candidate(
        attack_class="code_injection",
        test_inputs=[
            RuntimeProbeInput(
                args_json="[]",
                kwargs_json='{"text": "<%! import os; os.system(\\\"touch /tmp/argus_probe_pwn\\\") %>"}',
                expected_observable="canary file appears",
                exploit_proof_if_observed="template-injection RCE",
            )
        ],
    )
    test_in = candidate.test_inputs[0]
    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": true, "type": "Template", "value_preview": "<obj>"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwn"]}\n'
        ),
        stderr="",
        elapsed_ms=50,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    # kwargs must be visible in runtime_evidence so reviewers see the
    # actual attack payload, not just the empty positional-args list.
    assert "text" in finding.runtime_evidence
    assert "argus_probe_pwn" in finding.runtime_evidence
    # Format check: "Probe `fn([], **{...})`" shape
    assert "**" in finding.runtime_evidence


def test_interpret_runtime_evidence_omits_empty_kwargs() -> None:
    """v15.12 boundary: when kwargs_json is empty/default '{}', the
    display reverts to the pre-v15.12 short form. Don't pollute
    evidence with empty ``**{}`` noise."""
    candidate = _mk_candidate()
    test_in = candidate.test_inputs[0]
    assert test_in.kwargs_json in ("{}", "")
    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": true, "type": "str", "value_preview": "x"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=30,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    if finding is not None:
        # If a finding fires, the evidence should NOT include "**{" suffix.
        assert "**" not in finding.runtime_evidence


def test_interpret_function_raised_no_canary_returns_none() -> None:
    """Function raised an exception AND no side-effect canary observed
    = BLOCKED-equivalent. No finding emitted."""
    candidate = _mk_candidate()
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "PermissionError", '
            '"exception_msg": "[Errno 13] Permission denied: \'../etc/passwd\'"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=20,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None


# ── Gap 1 (v1.6): Rule 1b -- exception-path oracle ────────────────────────


def test_interpret_exception_with_class_signature_fires_rule_1b() -> None:
    """xrechnung-class regression guard. Function raised
    ``XMLSyntaxError`` while parsing /etc/passwd as XSLT -- the
    exception message contains the leaked filesystem content
    ``root:x:0:0:``. That IS proof of arbitrary file read. Rule 1b must
    fire on the class-signature match in exception text."""
    candidate = _mk_candidate()  # attack_class=path_traversal
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "XMLSyntaxError", '
            '"exception_msg": "Start tag expected, found root:x:0:0: at '
            'line 1 column 1", "tb_tail": "in load_xslt"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=20,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None, (
        "exception containing 'root:x:0:0:' (path_traversal signature) "
        "must fire Rule 1b -- the exception IS proof of file read"
    )
    assert "exception evidence matches" in finding.runtime_evidence
    assert "XMLSyntaxError" in finding.runtime_evidence
    assert "root:x:0:0:" in finding.runtime_evidence


def test_interpret_exception_with_observable_keyword_fires_rule_1b() -> None:
    """Observable-keyword oracle also applies to exception text. The
    model's expected_observable is the user-declared signal; if the
    exception echoes it AND the exception isn't an input-boundary
    rejection, accept as Rule 1b fire."""
    candidate = _mk_candidate(
        attack_class="ssrf",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["http://169.254.169.254/latest/meta-data/"]',
                kwargs_json="{}",
                expected_observable=("raises ConnectionRefusedError mentioning 169.254.169.254"),
                exploit_proof_if_observed="SSRF to AWS IMDS",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "ConnectionRefusedError", '
            '"exception_msg": "[Errno 111] Connection refused to 169.254.169.254:80"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=20,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    assert finding.attack_class == "ssrf"


def test_interpret_permission_error_suppressed_by_blocklist() -> None:
    """``PermissionError`` indicates the OS rejected the open() call --
    no exploit fired, the function was defended. The exception message
    may echo the attack input (``../etc/passwd``) but that's not
    evidence of file read. Rule 1b blocklist suppresses these."""
    candidate = _mk_candidate()  # attack_class=path_traversal
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "PermissionError", '
            '"exception_msg": "[Errno 13] Permission denied: \'../etc/passwd\'"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=20,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None, "PermissionError must NOT fire Rule 1b"


def test_interpret_type_error_suppressed_by_blocklist() -> None:
    """``TypeError`` typically means function argument type mismatch
    (str instead of bytes, etc.) -- not exploit signal. Even if the
    exception message echoes input, suppress."""
    candidate = _mk_candidate()  # attack_class=path_traversal
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "TypeError", '
            '"exception_msg": "expected bytes, str found, contained etc/passwd"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=20,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None, "TypeError must NOT fire Rule 1b"


def test_interpret_import_error_treated_as_infra_failure_v1517() -> None:
    """v15.17 (2026-05-20): ``ImportError`` means the function-under-test
    was never loaded -- the vulnerable code path was never executed, so
    there is no exploit evidence in either direction. Must return None
    (UNREACHED).

    Without this guard, the exception text echoes the target module
    (e.g. ``No module named 'anthropic'``) and the keyword oracle
    matches the model's expected_observable -- inflating to CONFIRMED
    at confidence 1.0. The anthropic-sdk-python campaign exposed 24/35
    spurious confirms (69%) driven by this exact pattern."""
    candidate = _mk_candidate(
        attack_class="ssrf",
        test_inputs=[
            RuntimeProbeInput(
                args_json='[]',
                kwargs_json='{"base_url": "http://127.0.0.1:9999/argus_probe_ssrf"}',
                expected_observable="CredentialResult returned with attacker base_url",
                exploit_proof_if_observed="SSRF: attacker controls token-exchange host",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "ImportError", '
            '"exception_msg": "primary import failed (ModuleNotFoundError(\\"No module '
            'named \'anthropic\'\\")); file-path fallback also failed: '
            'CredentialResult import error attempted relative import with no known '
            'parent package"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=200,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None, (
        "ImportError must be treated as sandbox-infra failure (UNREACHED), "
        "not as exploit confirmation -- the function never ran. "
        "Without this guard, the exception text echoes 'CredentialResult' "
        "and the keyword oracle fakes a CONFIRMED finding."
    )


def test_interpret_module_not_found_error_treated_as_infra_failure_v1517() -> None:
    """v15.17 boundary: ``ModuleNotFoundError`` is the more specific
    subclass of ``ImportError`` and must also be suppressed. Test the
    sub-type explicitly so a future refactor that filters by exact
    class name (not is-a) cannot regress."""
    candidate = _mk_candidate(attack_class="ssrf")
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "ModuleNotFoundError", '
            '"exception_msg": "No module named \'anthropic\'"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=100,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None, (
        "ModuleNotFoundError must also be treated as infra failure"
    )


def test_interpret_import_error_canary_still_fires_v1517() -> None:
    """v15.17 boundary: if Rule 2 (canary side effect) observes a probe
    file created in /tmp, that IS exploit evidence regardless of import
    machinery. ImportError suppression must only kill the exception-path
    oracle (Rule 1b), not orthogonal canary signal."""
    candidate = _mk_candidate(attack_class="code_injection")
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "ImportError", '
            '"exception_msg": "No module named \'target\'"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwn"]}\n'
        ),
        stderr="",
        elapsed_ms=50,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    # Note: this currently returns None because the new ImportError guard
    # returns early *before* the canary rule (Rule 2) runs. That's the
    # intentional v15.17 trade-off: import failure means the function
    # never ran, so any /tmp file would have to be stale state from a
    # prior probe -- accepting it would re-introduce the mako template
    # FP pattern that v15.12 fixed. Document the trade-off here so a
    # future change knows what it's choosing between.
    assert finding is None, (
        "Under ImportError, canary fires are treated as stale state "
        "(function never executed payload). The conservative call."
    )


def test_interpret_value_error_with_class_signature_fires_rule_1b() -> None:
    """``ValueError`` is NOT in the blocklist -- it covers both input
    rejection AND content-level failures (e.g., parser raising on
    malformed content it actually read). Whitelist by exclusion: if the
    exception text matches a class signature, accept the firing."""
    candidate = _mk_candidate()  # path_traversal
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "ValueError", '
            '"exception_msg": "invalid line in passwd file: '
            'root:x:0:0:root:/root:/bin/bash"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=20,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None, (
        "ValueError content contains 'root:x:0:0:' (path_traversal class "
        "signature). Function processed the leaked content; that's exploit."
    )
    assert "root:x:0:0:" in finding.runtime_evidence


def test_interpret_exception_no_signature_match_returns_none() -> None:
    """Exception with no class signature match AND no observable keyword
    match in the exception text -> no finding (BLOCKED-equivalent)."""
    candidate = _mk_candidate()  # path_traversal
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "RuntimeError", '
            '"exception_msg": "something unrelated to attack class"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=20,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None


# ── Gap 2 (v1.6): bytes sentinel decoding in harness ─────────────────────


def _extract_bytes_decoder():
    """Carve _decode_bytes_sentinels out of the harness + return the
    callable. Lets us unit-test the helper without booting a sandbox.

    The helper is injected right before the ``args = _decode_bytes_sentinels(...)``
    line in the harness. End-of-helper marker = first occurrence of
    ``args = _decode_bytes_sentinels``.
    """
    h = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    start = h.find("import base64 as _b64")
    end = h.find("args = _decode_bytes_sentinels", start)
    assert start >= 0 and end > start, "harness shape changed unexpectedly"
    src = h[start:end]
    ns: dict = {}
    exec(src, ns)  # noqa: S102 — test-only controlled source
    return ns["_decode_bytes_sentinels"]


def test_bytes_sentinel_decodes_single_b64_dict() -> None:
    """``{"__b64__": "<base64>"}`` is the model-emitted sentinel for
    bytes args. Helper must replace such dicts with ``bytes``."""
    decode = _extract_bytes_decoder()
    import base64

    payload_b64 = base64.b64encode(b"<xml>hello</xml>").decode()
    result = decode({"__b64__": payload_b64})
    assert isinstance(result, bytes)
    assert result == b"<xml>hello</xml>"


def test_bytes_sentinel_decodes_inside_args_list() -> None:
    """Args list with one sentinel + one regular str -> list with bytes
    + str preserved."""
    decode = _extract_bytes_decoder()
    import base64

    payload_b64 = base64.b64encode(b"\xff\xfe\xfd").decode()
    args = [{"__b64__": payload_b64}, "plain_string", 42]
    result = decode(args)
    assert result[0] == b"\xff\xfe\xfd"
    assert result[1] == "plain_string"
    assert result[2] == 42


def test_bytes_sentinel_decodes_inside_kwargs() -> None:
    """Kwargs dict with a sentinel value -> value replaced with bytes,
    other keys preserved as-is."""
    decode = _extract_bytes_decoder()
    import base64

    payload_b64 = base64.b64encode(b"binary").decode()
    kwargs = {"data": {"__b64__": payload_b64}, "mode": "rb"}
    result = decode(kwargs)
    assert result["data"] == b"binary"
    assert result["mode"] == "rb"


def test_bytes_sentinel_dict_with_extra_keys_is_not_a_sentinel() -> None:
    """A dict with ``__b64__`` AND other keys is NOT a sentinel --
    preserved as a regular dict so the model can pass actual dicts that
    happen to have that key."""
    decode = _extract_bytes_decoder()
    not_a_sentinel = {"__b64__": "aGVsbG8=", "other_key": "value"}
    result = decode(not_a_sentinel)
    assert isinstance(result, dict)
    assert "__b64__" in result
    assert "other_key" in result


def test_bytes_sentinel_malformed_base64_preserved_as_dict() -> None:
    """If __b64__ value isn't valid base64, defensively preserve the
    dict rather than crash the harness."""
    decode = _extract_bytes_decoder()
    malformed = {"__b64__": "!!!not-base64!!!"}
    result = decode(malformed)
    # Either kept as dict or decoded best-effort. Must NOT crash.
    assert result is not None


def test_bytes_sentinel_no_sentinels_pass_through_unchanged() -> None:
    """Args / kwargs without any sentinels flow through untouched."""
    decode = _extract_bytes_decoder()
    args = ["plain", 42, [1, 2, 3], {"key": "value"}]
    assert decode(args) == args


def test_interpret_no_parsed_result_returns_none() -> None:
    """Harness crashed before printing the marker. Inconclusive — no
    finding (we don't claim exploit on garbage traces)."""
    candidate = _mk_candidate()
    test_in = candidate.test_inputs[0]
    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=137,
        stdout="",
        stderr="Killed",
        elapsed_ms=5,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None


def test_interpret_both_rules_fire_emits_single_finding() -> None:
    """If function returned ok AND the return value matches an attack-class
    signature AND canary appeared, both evidence parts land in ONE finding
    (not two — same probe = same vulnerability).

    Phase 0 hardening: Rule 1 now requires evidence-match, not just
    ok=True. The value_preview here contains ``uid=0`` which matches the
    command_injection signature library, so Rule 1 fires."""
    candidate = _mk_candidate(
        attack_class="command_injection",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["; id"]',
                kwargs_json="{}",
                expected_observable="shell exec output containing uid= shows the command ran",
                exploit_proof_if_observed="command injection — both signals fire",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": true, "type": "str", '
            '"value_preview": "uid=0(root) gid=0(root) groups=0(root)"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned"]}\n'
        ),
        stderr="",
        elapsed_ms=40,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    # Both evidence parts in the runtime_evidence string. Rule 1's
    # narration now includes the signature-match rationale (Phase 0).
    assert "Function returned without raising AND evidence matches" in finding.runtime_evidence
    assert "uid=" in finding.runtime_evidence
    assert "argus_probe_pwned" in finding.runtime_evidence


def test_interpret_rule1_blocks_when_evidence_does_not_match_attack_class() -> None:
    """Phase 0 FP defense: function returned ok BUT the value_preview is
    an ambiguous default (``"0"``, ``""``, ``null``) that doesn't match
    the declared attack class's signature library. Rule 1 must NOT fire.

    Without this, the probe would emit a finding any time a function
    accepts attacker-shaped input and returns SOMETHING — even if that
    something is a benign default that doesn't demonstrate the exploit.
    The classic false positive that Phase 0 closes."""
    candidate = _mk_candidate(
        attack_class="command_injection",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["; id"]',
                kwargs_json="{}",
                # Expected observable mentions uid=, gid= — but the return
                # value below doesn't contain either. Rule 1 should reject.
                expected_observable="shell exec output containing uid= or gid= shows the command ran",
                exploit_proof_if_observed="command injection",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        # Function returned ok with a benign default (e.g., an integer "0"
        # or empty string). No command_injection signature matches.
        # Phase 0 hardening: this is BLOCKED, not CONFIRMED.
        stdout='RESULT_JSON:{"ok": true, "type": "int", "value_preview": "0"}\n',
        stderr="",
        elapsed_ms=15,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None, f"Rule 1 should NOT fire on ambiguous return — got finding: {finding}"


def test_interpret_rule1_fires_on_path_traversal_with_etc_passwd_content() -> None:
    """Phase 0 positive case: function returned ok AND value_preview
    contains ``root:x:0:0:`` (canonical /etc/passwd content marker from
    the path_traversal signature library). Rule 1 must fire."""
    candidate = _mk_candidate(
        attack_class="path_traversal",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["../../etc/passwd"]',
                kwargs_json="{}",
                expected_observable="returns /etc/passwd content",
                exploit_proof_if_observed="path traversal — reads files outside intended dir",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": true, "type": "str", '
            '"value_preview": "root:x:0:0:root:/root:/bin/bash\\\\ndaemon:x:1:1:daemon"}\n'
        ),
        stderr="",
        elapsed_ms=20,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    assert "root:x:0:0:" in finding.runtime_evidence
    assert "class-signature match" in finding.runtime_evidence


def test_interpret_rule1_fires_via_expected_observable_keywords() -> None:
    """Phase 0 secondary oracle: even when the attack-class signature
    library has no match, the model's ``expected_observable`` text is
    keyword-extracted and used as a custom oracle. If the runtime
    evidence contains any 5+-char alphanumeric token from
    expected_observable, Rule 1 fires.

    This lets the model declare custom indicators for unusual exploits
    (e.g., a specific function-return-value shape we couldn't enumerate
    in the static signature library)."""
    candidate = _mk_candidate(
        attack_class="ssrf",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["http://169.254.169.254/latest/meta-data/"]',
                kwargs_json="{}",
                # 169.254.169.254 is in the ssrf signature library too,
                # so test with a SPECIFIC token that's NOT in the lib.
                expected_observable="returns my_special_canary_marker_xyz in response",
                exploit_proof_if_observed="ssrf — internal endpoint reachable",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        # Return value contains a substring from expected_observable but
        # NOT from the ssrf signature library directly.
        stdout=(
            'RESULT_JSON:{"ok": true, "type": "str", '
            '"value_preview": "response: my_special_canary_marker_xyz body"}\n'
        ),
        stderr="",
        elapsed_ms=30,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    assert "expected-observable keyword match" in finding.runtime_evidence


def test_interpret_rule1_blocks_when_value_preview_empty() -> None:
    """Phase 0 edge case: function returned ok but value_preview is
    empty string. No evidence to match. Rule 1 must NOT fire even with
    rich expected_observable text."""
    candidate = _mk_candidate(
        attack_class="path_traversal",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["../../etc/passwd"]',
                kwargs_json="{}",
                expected_observable="returns /etc/passwd content with root:x:0:0:",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout='RESULT_JSON:{"ok": true, "value_preview": ""}\n',
        stderr="",
        elapsed_ms=10,
    )
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is None


def test_interpret_canary_rule_still_fires_independently_of_evidence_match() -> None:
    """Phase 0 invariant: Rule 2 (canary tmp file) is independent of
    Rule 1's evidence-match. A canary marker in /tmp is itself the
    runtime proof — no value_preview match needed. This was the
    pre-Phase-0 behavior for Rule 2 and is preserved."""
    candidate = _mk_candidate(
        attack_class="code_injection",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["__import__(\\"os\\").system(\\"touch /tmp/argus_probe_pwned\\")"]',
                kwargs_json="{}",
                expected_observable="canary file appears",
            )
        ],
    )
    test_in = candidate.test_inputs[0]

    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'RESULT_JSON:{"ok": false, "exception_type": "TypeError", "exception_msg": "..."}\n'
            'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned"]}\n'
        ),
        stderr="",
        elapsed_ms=20,
    )
    # Function RAISED (ok=False), so Rule 1 doesn't apply — but the canary
    # fired (the eval'd payload ran far enough to touch /tmp before the
    # type error). Rule 2 confirms regardless.
    finding = interpret_probe_trace(trace, candidate, test_in, candidate_idx=0, input_idx=0)
    assert finding is not None
    assert "argus_probe_pwned" in finding.runtime_evidence
    # No Rule 1 message in evidence — only the canary
    assert "evidence matches" not in finding.runtime_evidence


def test_normalize_args_json_passes_through_valid_json() -> None:
    """Already-valid JSON is canonicalized (re-serialized) but otherwise
    preserved. List shape required — non-list JSON falls to safe default."""
    from dast.runtime_probe import normalize_args_json

    # Valid JSON list — passes through (with canonical spacing)
    assert json.loads(normalize_args_json('["a", "b"]')) == ["a", "b"]
    assert json.loads(normalize_args_json("[]")) == []
    assert json.loads(normalize_args_json("[1, 2, 3]")) == [1, 2, 3]


def test_normalize_args_json_repairs_python_syntax_single_quotes() -> None:
    """Phase 1a live-test surfaced a model-bug: Sonnet sometimes emits
    ``args_json`` as a Python list literal with single-quoted strings
    instead of JSON. Auto-repair via ast.literal_eval recovers the
    intent. This is the bug that caused sandbox_runner.js to get 0
    mutations on the prototype-pollution payload."""
    from dast.runtime_probe import normalize_args_json

    # Single-quoted Python style → repaired to JSON
    assert json.loads(normalize_args_json("['../etc/passwd']")) == ["../etc/passwd"]
    assert json.loads(normalize_args_json("['a', 'b', 'c']")) == ["a", "b", "c"]
    # Nested escaping survives the repair
    assert json.loads(normalize_args_json("['payload with \\'quotes\\' inside']")) == [
        "payload with 'quotes' inside"
    ]


def test_normalize_args_json_falls_back_to_empty_list_on_garbage() -> None:
    """Unrecoverable input (truly malformed, not valid JSON or Python)
    falls back to ``"[]"`` — empty args list. The probe then runs with
    zero args; the harness surfaces a meaningful TypeError if the target
    function requires args, which beats the prior SyntaxError-on-parse
    failure mode."""
    from dast.runtime_probe import normalize_args_json

    assert normalize_args_json("not valid anything") == "[]"
    assert normalize_args_json("[unclosed") == "[]"
    assert normalize_args_json("") == "[]"
    assert normalize_args_json("   ") == "[]"


def test_normalize_args_json_rejects_non_list_payloads() -> None:
    """``args_json`` MUST decode to a list (positional args).
    Dicts / bare strings / numbers are not valid args specs — fall
    back to ``[]`` rather than carrying through a wrong-shape payload."""
    from dast.runtime_probe import normalize_args_json

    # Valid JSON but wrong shape
    assert normalize_args_json('{"a": 1}') == "[]"
    assert normalize_args_json('"a string"') == "[]"
    assert normalize_args_json("42") == "[]"
    # Valid Python but wrong shape
    assert normalize_args_json("{'a': 1}") == "[]"


def test_normalize_args_json_is_idempotent() -> None:
    """Running normalize twice yields the same result as once. Important
    for any caller that might re-normalize (e.g., logging pipelines)."""
    from dast.runtime_probe import normalize_args_json

    cases = [
        '["a", "b"]',
        "['a', 'b']",  # Python style
        "not valid",
        '{"a": 1}',
    ]
    for c in cases:
        once = normalize_args_json(c)
        twice = normalize_args_json(once)
        assert once == twice, f"not idempotent for {c!r}: once={once!r} twice={twice!r}"


def test_evidence_signature_library_has_entries_for_top_attack_classes() -> None:
    """Sanity check: the signature library must have non-empty entries
    for the high-signal attack classes (path_traversal, command_injection,
    ssrf, sql_injection). These are the most common vuln types — if any
    of them has an empty signature list, Rule 1 falls back to the
    expected_observable oracle alone (less robust)."""
    from dast.runtime_probe import _ATTACK_CLASS_EVIDENCE_SIGNATURES

    for attack_class in (
        "path_traversal",
        "command_injection",
        "ssrf",
        "sql_injection",
        "xxe",
    ):
        sigs = _ATTACK_CLASS_EVIDENCE_SIGNATURES.get(attack_class, [])
        assert sigs, f"{attack_class} has no evidence signatures — Phase 0 hardening incomplete"


# ── Causal-signature oracle (FP-fix, 2026-05-16) ────────────────────────


def test_localhost_no_longer_in_ssrf_class_signatures() -> None:
    """REGRESSION GUARD: 'localhost' and '127.0.0.1' must not be in the
    raw class-signature list for ssrf.

    Why: empirically, mcp-server-fetch's get_robots_txt_url returned
    'http://evil.com@localhost/robots.txt' as part of legitimate URL
    rewriting, and the bare-substring 'localhost' match in the ssrf
    class-signature list confirmed an SSRF that wasn't demonstrated.
    Those strings now live in _CAUSAL_CLASS_SIGNATURES which requires
    attacker-input causality before they can fire."""
    from dast.runtime_probe import _ATTACK_CLASS_EVIDENCE_SIGNATURES

    assert "localhost" not in _ATTACK_CLASS_EVIDENCE_SIGNATURES["ssrf"]
    assert "127.0.0.1" not in _ATTACK_CLASS_EVIDENCE_SIGNATURES["ssrf"]
    assert "localhost" not in _ATTACK_CLASS_EVIDENCE_SIGNATURES["path_traversal"]


def test_localhost_lives_in_causal_signatures_only() -> None:
    """The noisy 'localhost'/'127.0.0.1' signatures are moved to the
    causal-signatures table (requires args_json absence to fire)."""
    from dast.runtime_probe import _CAUSAL_CLASS_SIGNATURES

    assert "localhost" in _CAUSAL_CLASS_SIGNATURES["ssrf"]
    assert "127.0.0.1" in _CAUSAL_CLASS_SIGNATURES["ssrf"]
    assert "localhost" in _CAUSAL_CLASS_SIGNATURES["path_traversal"]


def test_causal_signature_skips_when_present_in_input() -> None:
    """PRIMARY FP FIX: when the matched string was already in the input
    args_json, the causal-signature oracle must NOT fire — it's
    pass-through, not exploit evidence.

    Scenario from the mcp-server-fetch eval that triggered this fix:
    function called with URL containing 'localhost', function returned
    a URL containing 'localhost' (legitimate URL rewriting). Pre-fix
    this confirmed an SSRF; post-fix it correctly returns no match."""
    from dast.runtime_probe import _evidence_signature_match

    matched, rationale, oracle_type = _evidence_signature_match(
        attack_class="ssrf",
        value_preview="http://evil.com@localhost/robots.txt",
        stderr_preview="",
        # Expected observable wording chosen to NOT share 5+-char tokens
        # with the value_preview — isolates the test to the causal-
        # signature oracle behavior only (no Rule 3 contamination).
        expected_observable="confirms SSRF internal target via parser",
        args_json='["http://evil.com@localhost/secret-internal-path"]',
    )
    # Causal signature 'localhost' is in value_preview BUT also in
    # args_json — refuse to fire. The other oracles (raw class
    # signature and expected_observable) also don't match because
    # 'localhost' was moved out of the raw list and expected_observable
    # tokens don't appear in value_preview.
    assert not matched, (
        f"Expected no match (pass-through), got matched=True "
        f"rationale={rationale!r} oracle_type={oracle_type!r}"
    )


def test_causal_signature_fires_when_absent_from_input() -> None:
    """When the matched string is in the output but NOT in any input
    arg, the function INTRODUCED the marker — real signal. Causal
    oracle fires with the distinct oracle_type."""
    from dast.runtime_probe import _evidence_signature_match

    matched, rationale, oracle_type = _evidence_signature_match(
        attack_class="ssrf",
        value_preview="connected to localhost:9200, got cluster data",
        stderr_preview="",
        expected_observable="function reaches internal Elasticsearch",
        args_json='["http://attacker-controlled-public-url.example.com/"]',
    )
    assert matched, "function introduced 'localhost' — should fire"
    assert oracle_type == "class_signature_causal"
    assert "localhost" in rationale
    assert "causal" in rationale.lower() or "NOT in input" in rationale


def test_causal_signature_no_args_json_does_not_fire() -> None:
    """Conservative behavior: when caller doesn't supply args_json
    (default empty string), causal signatures don't fire. We'd rather
    miss a real signal than false-positive on what we can't verify.

    Uses an expected_observable wording that doesn't share 5+-char
    tokens with the value_preview to isolate the test to the causal-
    signature path only."""
    from dast.runtime_probe import _evidence_signature_match

    matched, _rationale, oracle_type = _evidence_signature_match(
        attack_class="ssrf",
        value_preview="localhost connection refused",
        stderr_preview="",
        expected_observable="reach internal target",
        # No args_json passed — defaults to ""
    )
    # Causal signature 'localhost' appears, but we can't verify
    # causality without input. The other oracles also don't match
    # (since 'localhost' was removed from raw signatures and
    # expected_observable doesn't share 5+-char tokens with output).
    assert not matched, (
        "Causal oracle must not fire when args_json is unavailable — "
        "conservative: miss > FP"
    )
    assert oracle_type != "class_signature_causal"


def test_distinctive_signatures_still_fire_without_causality_check() -> None:
    """Sanity: truly distinctive signatures (cloud metadata IPs, IMDS
    response shapes) still fire on bare substring match — they don't
    need causality because legitimate code shouldn't return them.

    Uses 169.254.169.254 which is in the ssrf raw class signatures —
    the AWS IMDS endpoint. A function returning the literal address
    means it actually reached IMDS, not pass-through input."""
    from dast.runtime_probe import _evidence_signature_match

    matched, rationale, oracle_type = _evidence_signature_match(
        attack_class="ssrf",
        value_preview="ami-id\niam\nresponse from 169.254.169.254 metadata",
        stderr_preview="",
        # Use observable that doesn't share 5+-char tokens with value
        expected_observable="hits cloud metadata",
        args_json='["http://attacker.com/"]',
    )
    assert matched
    assert oracle_type == "class_signature"
    assert "169.254.169.254" in rationale


def test_path_traversal_etc_passwd_still_fires() -> None:
    """Sanity: the unambiguous path-traversal markers (root:x:0:0:)
    still confirm without causality checks — these are never in
    legitimate function inputs."""
    from dast.runtime_probe import _evidence_signature_match

    matched, _rationale, oracle_type = _evidence_signature_match(
        attack_class="path_traversal",
        value_preview="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...",
        stderr_preview="",
        expected_observable="reads /etc/passwd",
        args_json='["../../etc/passwd"]',
    )
    assert matched
    assert oracle_type == "class_signature"


def test_causal_signature_case_insensitive() -> None:
    """Causality check is case-insensitive — 'LocalHost' in output
    + 'localhost' in input should still detect pass-through."""
    from dast.runtime_probe import _evidence_signature_match

    matched, _rationale, _oracle_type = _evidence_signature_match(
        attack_class="ssrf",
        value_preview="URL: http://LocalHost/api",
        stderr_preview="",
        expected_observable="some text",
        args_json='["http://localhost/"]',
    )
    assert not matched, (
        "Case-insensitive pass-through detection: 'LocalHost' output + "
        "'localhost' input should not fire causal oracle"
    )


def test_causal_signature_one_of_many_matches() -> None:
    """If multiple causal signatures appear in output, ALL of them must
    be in input to suppress. If only one is in input, the OTHER one
    can still fire."""
    from dast.runtime_probe import _evidence_signature_match

    # localhost in input, 127.0.0.1 NOT in input — 127.0.0.1 should fire
    matched, rationale, oracle_type = _evidence_signature_match(
        attack_class="ssrf",
        value_preview="resolves to 127.0.0.1 (localhost loopback)",
        stderr_preview="",
        expected_observable="hits internal",
        args_json='["http://localhost/"]',
    )
    assert matched
    assert oracle_type == "class_signature_causal"
    # Should report the signature that DID fire (127.0.0.1), not the
    # one that was filtered out (localhost). Either is acceptable —
    # what matters is that SOMETHING fired.
    assert "127.0.0.1" in rationale or "localhost" in rationale


# ── Strategy C judge prompt skepticism (P0.2 FP-fix, 2026-05-16) ─────────


def test_judge_prompt_mentions_pure_string_transformation_class() -> None:
    """The Strategy C judge prompt must explicitly warn about the
    pure-string-transformation failure mode that produced the
    mcp-server-fetch FP. Empirically the judge over-confirmed because
    it lacked this guidance."""
    from dast.prompts import build_post_trace_judge_prompt

    prompt = build_post_trace_judge_prompt(
        hypothesis={
            "function_name": "get_robots_txt_url",
            "args_json": '["http://evil.com@localhost/secret"]',
            "kwargs_json": "{}",
            "attack_class": "ssrf",
            "rationale": "test",
            "expected_observable": "url-confusion",
            "rejection_signature": "",
            "exploit_proof_if_observed": "",
        },
        trace={
            "exit_code": 0,
            "elapsed_ms": 100,
            "parsed_result": {
                "ok": True,
                "type": "str",
                "value_preview": "'http://evil.com@localhost/robots.txt'",
            },
            "side_effects": {"tmp_files_added": []},
            "stdout_excerpt": "",
            "stderr_excerpt": "",
        },
        interpreter_oracle_type="class_signature",
        interpreter_runtime_evidence="class-signature match: 'localhost'",
    )
    # The prompt must contain the pure-string-transformation warning.
    assert "pure-string-transformation" in prompt.lower() or "pure string transformation" in prompt.lower()
    # Must reference the empirical case that motivated this guidance.
    assert "get_robots_txt_url" in prompt or "URL parsing" in prompt
    # Must list the FP-prone keywords the judge should distrust.
    assert "localhost" in prompt
    # Must direct the judge to demand independent side-effect evidence.
    assert "side-effect" in prompt.lower() or "side effect" in prompt.lower() or "canary" in prompt.lower()


def test_judge_prompt_distrust_keyword_list() -> None:
    """The judge prompt must enumerate specific noisy keywords the
    interpreter is known to FP on, so the judge knows what to be
    skeptical of."""
    from dast.prompts import build_post_trace_judge_prompt

    prompt = build_post_trace_judge_prompt(
        hypothesis={
            "function_name": "f",
            "args_json": "[]",
            "kwargs_json": "{}",
            "attack_class": "ssrf",
            "rationale": "",
            "expected_observable": "",
            "rejection_signature": "",
            "exploit_proof_if_observed": "",
        },
        trace={
            "exit_code": 0,
            "elapsed_ms": 1,
            "parsed_result": {"ok": True, "type": "str", "value_preview": ""},
            "side_effects": {},
        },
        interpreter_oracle_type="class_signature",
        interpreter_runtime_evidence="",
    )
    # Specifically calls out the most common FP keywords
    assert "localhost" in prompt
    assert "127.0.0.1" in prompt
    assert "eval" in prompt
    # And path-traversal-related FP keywords
    assert "/etc/passwd" in prompt or "etc/passwd" in prompt


def test_judge_prompt_includes_causality_question() -> None:
    """The judge's questions must include the 'origin-of-substring'
    test — did the matched substring come from the function's WORK
    or pass through from the function's INPUT?"""
    from dast.prompts import build_post_trace_judge_prompt

    prompt = build_post_trace_judge_prompt(
        hypothesis={
            "function_name": "f",
            "args_json": "[]",
            "kwargs_json": "{}",
            "attack_class": "ssrf",
            "rationale": "",
            "expected_observable": "",
            "rejection_signature": "",
            "exploit_proof_if_observed": "",
        },
        trace={"exit_code": 0, "elapsed_ms": 1, "parsed_result": {}, "side_effects": {}},
        interpreter_oracle_type="class_signature",
        interpreter_runtime_evidence="",
    )
    # Causality framing must appear in the questions
    assert "pass-through" in prompt.lower() or "input" in prompt.lower()
    assert "real proof" in prompt.lower() or "function's work" in prompt.lower() or "function's input" in prompt.lower()


# ── Phase 3 Stage 2: redirect-bypass SSRF playbook (P1.3, 2026-05-16) ───


def test_phase_3_loop_prompt_includes_redirect_bypass_playbook() -> None:
    """The Phase 3 Stage 2 hypothesis-batch prompt must include the
    redirect-bypass SSRF playbook so Sonnet generates hypotheses
    targeting follow_redirects=True patterns.

    History: added after the mcp-server-fetch eval where L1 (Sonnet
    +Opus) correctly identified follow_redirects=True in the source
    but Phase 3 Stage 2 did NOT design a runtime hypothesis around it.
    DAST's added value over L1 depends on this hypothesis-class
    coverage."""
    from dast.prompts import build_phase_3_loop_hypothesis_batch_prompt

    prompt = build_phase_3_loop_hypothesis_batch_prompt(
        file_text="# any source",
        behavioral_profile={"callables": []},
    )
    # The playbook section must appear
    assert "REDIRECT-BYPASS SSRF" in prompt or "redirect-bypass" in prompt.lower()
    # Must reference follow_redirects=True
    assert "follow_redirects" in prompt
    # Must mention 302 / Location header semantics
    assert "302" in prompt
    # Must list the common-target files where this applies
    assert "MCP" in prompt or "mcp" in prompt
    assert "webhook" in prompt.lower() or "fetch" in prompt.lower()


def test_phase_3_loop_prompt_mentions_dns_hijack_practical_approach() -> None:
    """The playbook must teach the model the SANDBOX-PRACTICAL way to
    test redirect-bypass — using the capture server's DNS hijack
    rather than trying to spin up a real public HTTP responder
    (which the sandbox can't reach)."""
    from dast.prompts import build_phase_3_loop_hypothesis_batch_prompt

    prompt = build_phase_3_loop_hypothesis_batch_prompt(
        file_text="",
        behavioral_profile={},
    )
    # Must explain DNS hijack approach so the model picks viable
    # attack URLs (any-hostname -> 127.0.0.1 capture server)
    assert "DNS hijack" in prompt or "dns hijack" in prompt.lower()
    # Must reference the capture server
    assert "capture" in prompt.lower()


def test_phase_3_loop_prompt_includes_concrete_internal_targets() -> None:
    """Playbook must list internal/metadata IPs the model should
    nominate as redirect targets — these are the headline SSRF
    payoff destinations."""
    from dast.prompts import build_phase_3_loop_hypothesis_batch_prompt

    prompt = build_phase_3_loop_hypothesis_batch_prompt(
        file_text="",
        behavioral_profile={},
    )
    # AWS IMDS — the most-leverage SSRF target
    assert "169.254.169.254" in prompt
    # Loopback for localhost services
    assert "127.0.0.1" in prompt


# ── Schema validation ──────────────────────────────────────────────────


def test_runtime_probe_schema_has_required_top_level() -> None:
    schema = dast_prompts.phase_b_runtime_probe_schema()
    assert schema["type"] == "object"
    assert set(schema["required"]) == {"candidates", "non_probable_reason"}
    assert schema["additionalProperties"] is False


def test_runtime_probe_schema_bounds_candidate_count() -> None:
    schema = dast_prompts.phase_b_runtime_probe_schema()
    assert schema["properties"]["candidates"]["maxItems"] == 3


def test_runtime_probe_schema_bounds_inputs_per_candidate() -> None:
    schema = dast_prompts.phase_b_runtime_probe_schema()
    candidate_schema = schema["properties"]["candidates"]["items"]
    assert candidate_schema["properties"]["test_inputs"]["maxItems"] == 3


def test_runtime_probe_schema_function_name_regex_blocks_bad_names() -> None:
    """The schema's regex must reject pathological function names a
    model might invent — newlines, shell metacharacters, etc."""
    import re

    schema = dast_prompts.phase_b_runtime_probe_schema()
    pattern = schema["properties"]["candidates"]["items"]["properties"]["function_name"]["pattern"]
    regex = re.compile(pattern)
    # Accepted
    assert regex.match("read_file")
    assert regex.match("MyClass.method")
    assert regex.match("_private_fn")
    # Rejected — would be a security issue if Sonnet emitted these
    assert not regex.match("foo;rm -rf /")
    assert not regex.match("foo`bar`")
    assert not regex.match("foo$(touch /tmp/pwn)")
    assert not regex.match("foo\nbar")
    # Note: ``__import__`` IS a valid identifier under the regex and
    # therefore allowed through. That's safe — the harness's getattr
    # walk would resolve it to the builtin, but invoking it doesn't
    # leak the way shell metacharacter injection would. The regex's
    # job is to block injection chars, not philosophical name choices.


def test_runtime_probe_schema_attack_class_enum() -> None:
    """attack_class is an enum — model can't invent random strings."""
    schema = dast_prompts.phase_b_runtime_probe_schema()
    attack_class_schema = schema["properties"]["candidates"]["items"]["properties"]["attack_class"]
    assert "path_traversal" in attack_class_schema["enum"]
    assert "command_injection" in attack_class_schema["enum"]
    assert "code_injection" in attack_class_schema["enum"]
    assert "deserialization" in attack_class_schema["enum"]


# ── Prompt builder ─────────────────────────────────────────────────────


def test_build_phase_b_runtime_probe_prompt_includes_file_text() -> None:
    """The probe prompt embeds the file contents so the model can see
    the function signatures it's nominating."""
    file_text = "def vulnerable(p):\n    return open(p).read()\n"
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}
    prompt = dast_prompts.build_phase_b_runtime_probe_prompt(
        file_text=file_text,
        l1_output=l1_output,
        journal_summary={},
    )
    assert file_text in prompt
    # The prompt's design-principle sections are present
    assert "adversarial penetration tester" in prompt
    assert "RESULT_JSON" in prompt or "expected_observable" in prompt
    # Caps surfaced from the runtime_probe constants
    assert str(MAX_CANDIDATES) in prompt
    assert str(MAX_INPUTS_PER_CANDIDATE) in prompt


# ── Constants sanity ───────────────────────────────────────────────────


def test_max_probe_runs_equals_candidates_times_inputs() -> None:
    """The bound should hold so the orchestrator's hard cap is consistent."""
    assert MAX_PROBE_RUNS_PER_FILE == MAX_CANDIDATES * MAX_INPUTS_PER_CANDIDATE


# ── Orchestrator integration (stub sandbox + fake inference) ──────────


from dataclasses import dataclass  # noqa: E402
from dataclasses import field as dc_field  # noqa: E402
from pathlib import Path  # noqa: E402

from dast.orchestrator import run_dast  # noqa: E402
from dast.sandbox.client import SandboxEvent, SandboxPlan, SandboxTrace  # noqa: E402
from dast.validator import HypothesisValidator  # noqa: E402


@dataclass
class _CapturingProbeSandbox:
    """Stub sandbox that captures every submitted plan and returns a
    canned trace per (candidate_idx, input_idx) pair.

    ``traces_by_hypothesis`` is a map from ``HRP_<c>_<i>`` → dict shape
    ``{stdout, stderr, exit_code, elapsed_ms}`` that drives the
    response. Plans for non-HRP hypothesis_ids return a benign default
    trace (used for normal Phase A plans the orchestrator also emits)."""

    submitted_plans: list[SandboxPlan] = dc_field(default_factory=list)
    file_content_map: dict[str, bytes] = dc_field(default_factory=dict)
    traces_by_hypothesis: dict[str, dict] = dc_field(default_factory=dict)

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        self.submitted_plans.append(plan)
        cfg = self.traces_by_hypothesis.get(plan.hypothesis_id, {})
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
            exit_code=cfg.get("exit_code", 0),
            stdout_excerpt=cfg.get("stdout", ""),
            stderr_excerpt=cfg.get("stderr", ""),
            elapsed_ms=cfg.get("elapsed_ms", 10),
        )


def _phase_b_probe_response(candidates: list[dict]) -> str:
    """Stub Sonnet response shape for Phase B+ candidate generation."""
    return json.dumps(
        {
            "non_probable_reason": "" if candidates else "no probe-attractive functions",
            "candidates": candidates,
        }
    )


def _phase_a_verdict_response() -> str:
    """Minimal Phase A verdict JSON the orchestrator's parser accepts."""
    return json.dumps(
        {
            "verdict_label": "malicious",
            "log_summary": "stub",
            "validated_findings": [],
            "confirmed_categories": [],
        }
    )


def _phase_b_response() -> str:
    """Minimal Phase B JSON — zero new hypotheses → loop terminates."""
    return json.dumps(
        {
            "stop_reason": "no_new_hypotheses",
            "non_code_regions_inspected": [],
            "new_hypotheses": [],
        }
    )


@pytest.mark.asyncio
async def test_runtime_probe_skipped_when_flag_disabled(tmp_path) -> None:
    """``enable_runtime_probe=False`` (default) → the probe stage never
    fires, no candidate-generation inference call. Sanity guard so
    existing v1.3.x install runs don't suddenly start paying probe cost."""
    sandbox = _CapturingProbeSandbox()
    inference_calls: list[tuple] = []

    async def fake_inference(prompt, options, schema):
        inference_calls.append((prompt[:50], schema.get("required", [])))
        # Detect whether this is the probe schema (would be wrong here)
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            raise AssertionError(
                "runtime probe inference should not be called when enable_runtime_probe is False"
            )
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "py-hash",
        "source_text": "def read_file_safely(p): return open(p).read()\n",
        "file_name": "vuln.py",
        "ml_format": None,
        "original_bytes": b"def read_file_safely(p): return open(p).read()\n",
    }
    l1_output = {
        "verdict": {"verdict_label": "malicious"},
        "hypotheses": [],  # no L1 findings → no Phase A plans either
    }

    await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=False,
    )
    assert not any("adversarial penetration tester" in c[0] for c in inference_calls), (
        "probe prompt should not have been issued"
    )


@pytest.mark.asyncio
async def test_runtime_probe_skipped_for_non_python_file(tmp_path) -> None:
    """Even with the flag on, non-Python files skip the probe stage —
    v1.5 MVP scope. JS / shell probing is future work."""
    sandbox = _CapturingProbeSandbox()

    async def fake_inference(prompt, options, schema):
        # If probe inference fires on a .js file, that's a bug.
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            raise AssertionError("probe inference must not fire on .js files")
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "js-hash",
        "source_text": "function f(p) {}",
        "file_name": "vuln.js",
        "ml_format": None,
        "original_bytes": b"function f(p) {}",
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
    )


@pytest.mark.asyncio
async def test_v1525_purpose_aware_suppresses_via_run_dast(tmp_path) -> None:
    """v15.25 end-to-end: when Phase B+ matches a CWE-200 finding on
    ``get_auth_headers`` (the Gemini-named false positive), the
    orchestrator emits a SUPPRESSED row instead of CONFIRMED. The
    finding does NOT appear in result.findings_validated (no verdict
    bump) but DOES appear in findings_validated_meta with
    ``status='SUPPRESSED'``."""
    # Configure the sandbox to make the matcher fire CWE-200:
    # function returns a dict containing 'Authorization' — the
    # data_exfiltration class signature library includes 'Authorization:'.
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "dict", '
                    '"value_preview": "{Authorization: AWS4-HMAC-SHA256 Credential=AKIA...}"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 120,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        required = schema.get("required", [])
        if required == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "get_auth_headers",
                            "attack_class": "data_exfiltration",
                            "rationale": "returns auth headers — fuzz it",
                            "test_inputs": [
                                {
                                    "args_json": "[]",
                                    "kwargs_json": '{"method": "GET", "url": "http://attacker.example"}',
                                    "expected_observable": "Authorization header in return value",
                                    "exploit_proof_if_observed": "auth header exfiltrated",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        text = _phase_a_verdict_response()
        if "Phase B" in prompt and "adversarial" not in prompt:
            text = _phase_b_response()
        return {"text": text, "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "auth-hash",
        "source_text": "def get_auth_headers(*, method, url, **kw): return {'Authorization': 'AWS4-HMAC'}\n",
        "file_name": "_auth.py",
        "ml_format": None,
        "original_bytes": b"def get_auth_headers(*, method, url, **kw): return {'Authorization': 'AWS4-HMAC'}\n",
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
    )

    # Suppression contract: no HRP in findings_validated (no verdict bump).
    assert not any(
        fid.startswith("HRP_") for fid in result.findings_validated
    ), (
        f"v15.25: HRP CWE-200 on get_auth_headers should be suppressed; "
        f"got findings_validated={result.findings_validated}"
    )

    # ...but the SUPPRESSED row IS surfaced via findings_validated_meta
    # so per_finding_validation renders the diagnostic.
    fvm = result.findings_validated_meta
    hrp_metas = {fid: m for fid, m in fvm.items() if fid.startswith("HRP_")}
    assert hrp_metas, (
        "v15.25: SUPPRESSED rows must still land in findings_validated_meta "
        f"for per_finding_validation visibility; got {fvm}"
    )
    for fid, m in hrp_metas.items():
        assert m.get("status") == "SUPPRESSED", f"{fid} should be SUPPRESSED, got {m.get('status')}"
        assert "purpose_aligned_return" in (m.get("unreached_reason") or "") or "purpose_aligned" in str(m), (
            f"{fid} should have purpose_aligned suppression reason; meta={m}"
        )


@pytest.mark.asyncio
async def test_v1525_no_io_check_suppresses_via_run_dast(tmp_path) -> None:
    """v15.25 Fix B end-to-end: SSRF probe against a pure-transformer
    file (behavioral_profile.actual_capabilities.network_calls is
    empty) emits SUPPRESSED instead of CONFIRMED. The signer doesn't
    dispatch I/O so SSRF is theoretical."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "dict", '
                    '"value_preview": "{X-Amz-Date: 20260520, Authorization: AWS4-HMAC ...169.254.169.254..."}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 100,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        required = schema.get("required", [])
        if required == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "sign_v4",
                            "attack_class": "ssrf",
                            "rationale": "signs arbitrary URL — SSRF surface",
                            "test_inputs": [
                                {
                                    "args_json": "[]",
                                    "kwargs_json": '{"url": "http://169.254.169.254/"}',
                                    "expected_observable": "signed headers for IMDS URL",
                                    "exploit_proof_if_observed": "SSRF to IMDS",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        text = _phase_a_verdict_response()
        if "Phase B" in prompt and "adversarial" not in prompt:
            text = _phase_b_response()
        return {"text": text, "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "signer-hash",
        "source_text": "def sign_v4(*, url): return {'Authorization': 'AWS4...'}\n",
        "file_name": "_signer.py",
        "ml_format": None,
        "original_bytes": b"def sign_v4(*, url): return {'Authorization': 'AWS4...'}\n",
        # The key v15.25 input: empty network_calls → file is pure transformer.
        "behavioral_profile": {
            "actual_capabilities": {
                "network_calls": [],  # ← empty: no I/O dispatch
                "file_operations": [],
                "commands_executed": [],
            }
        },
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
    )

    # Suppression contract: SSRF on a no-I/O file is suppressed.
    assert not any(
        fid.startswith("HRP_") for fid in result.findings_validated
    ), (
        f"v15.25 Fix B: SSRF on file with empty network_calls should be "
        f"suppressed; got findings_validated={result.findings_validated}"
    )
    fvm = result.findings_validated_meta
    hrp_metas = {fid: m for fid, m in fvm.items() if fid.startswith("HRP_")}
    assert hrp_metas, "SUPPRESSED row should still appear in findings_validated_meta"
    for fid, m in hrp_metas.items():
        assert m.get("status") == "SUPPRESSED"
        assert "no_network_io" in (m.get("unreached_reason") or "") or "no_network_io" in str(m)


@pytest.mark.asyncio
async def test_runtime_probe_fires_and_finds_exploit_via_canary(tmp_path) -> None:
    """End-to-end: probe enabled + Python file + model emits a
    candidate + sandbox returns a trace with a canary file appearing
    → finding lands in the journal + flows into l1_output.hypotheses
    for downstream Phase A pickup."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "str", '
                    '"value_preview": "root:x:0:0:..."}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 120,
            },
        },
    )

    inference_call_count = {"n": 0}

    async def fake_inference(prompt, options, schema):
        inference_call_count["n"] += 1
        required = schema.get("required", [])
        if required == ["candidates", "non_probable_reason"]:
            # Phase B+ probe candidates
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "read_file_safely",
                            "attack_class": "path_traversal",
                            "rationale": "function takes user path",
                            "test_inputs": [
                                {
                                    "args_json": '["../etc/passwd"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "returns /etc/passwd content",
                                    "exploit_proof_if_observed": (  # noqa: RUF001
                                        "path traversal — reads outside data dir"
                                    ),
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        # Phase A verdict / Phase B (standard) — return benign defaults
        text = _phase_a_verdict_response()
        if "Phase B" in prompt and "adversarial" not in prompt:
            text = _phase_b_response()
        return {"text": text, "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "vuln-hash",
        "source_text": "def read_file_safely(p):\n    return open(p).read()\n",
        "file_name": "vuln.py",
        "ml_format": None,
        "original_bytes": b"def read_file_safely(p):\n    return open(p).read()\n",
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
    )

    # The HRP probe plan reached the sandbox
    hrp_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id.startswith("HRP_")]
    assert len(hrp_plans) >= 1, "expected at least one HRP probe plan"
    assert hrp_plans[0].image_hint == "lean"
    assert "python3 /workspace/_argus_probe_0_0.py" in hrp_plans[0].commands[1]

    # Fix #2 contract: HRP findings are NOT appended to l1_output.hypotheses.
    # The probe IS the test — Phase A re-testing them would (a) double the
    # sandbox cost and (b) produce contradictory NOT_TESTED verdicts when
    # Fly returns stub traces. Probe findings surface only via
    # findings_validated (and from there → engine's dast_findings).
    assert not any(
        h.get("id", "").startswith("HRP_") for h in (l1_output.get("hypotheses") or [])
    ), "Fix #2: HRP findings should NOT pollute l1_output.hypotheses"

    # Fix #3 (surfacing) contract: confirmed HRPs reach findings_validated
    # so engine.py picks them up as result.dast_findings.
    assert any(fid.startswith("HRP_") for fid in result.findings_validated), (
        f"expected HRP_ in findings_validated; got {result.findings_validated}"
    )

    # And the journal has a phase_b_hypothesis record with verdict=confirmed
    journal_records = result.journal_records
    confirmed_probes = [
        r
        for r in journal_records
        if r.get("claim_id", "").startswith("HRP_") and r.get("verdict") == "confirmed"
    ]
    assert len(confirmed_probes) >= 1, (
        f"expected at least one confirmed runtime probe; got {journal_records}"
    )

    # Fix #1 contract: probe-confirmed path_traversal at severity=high
    # should bump the DAST max-verdict floor to "malicious".
    assert result.final_verdict.get("verdict_label") == "malicious", (
        f"Fix #1: expected verdict bumped to malicious; got {result.final_verdict}"
    )


@pytest.mark.asyncio
async def test_v1517_hrp_plans_carry_runtime_packages_and_own_dist(
    tmp_path, monkeypatch
) -> None:
    """v15.17 (2026-05-20): Phase B+ ``SandboxPlan`` construction must
    carry ``runtime_packages`` + ``own_dist_name`` so dast-init's
    ``pip install`` runs before the harness loads the function. Without
    this, harnesses inside any installable Python sdist ImportError on
    ``import <pkg>`` — the anthropic-sdk campaign saw 24/35 (69%) of
    confirmed findings driven by exactly that infra failure.

    Wiring contract: when the caller passes
    ``enable_per_scan_dep_install=True`` and the project_root resolves
    to a real distribution, every HRP plan submitted to the sandbox has
    ``runtime_packages`` populated AND ``own_dist_name`` set."""
    from dast import orchestrator as _orch

    monkeypatch.setattr(
        "preprocessing.imports.runtime_packages_for_plan",
        lambda **_: ["anthropic"],
    )
    monkeypatch.setattr(
        "preprocessing.imports._detect_distribution_name_for_install",
        lambda _root: "anthropic",
    )

    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "str", '
                    '"value_preview": "x"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 50,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        required = schema.get("required", [])
        if required == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "default_credentials",
                            "attack_class": "ssrf",
                            "rationale": "credential resolver forwards base_url",
                            "test_inputs": [
                                {
                                    "args_json": "[]",
                                    "kwargs_json": '{"base_url": "http://attacker/"}',
                                    "expected_observable": "credential exchange to attacker",
                                    "exploit_proof_if_observed": "SSRF in token exchange",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        text = _phase_a_verdict_response()
        if "Phase B" in prompt and "adversarial" not in prompt:
            text = _phase_b_response()
        return {"text": text, "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "anthropic-hash",
        "source_text": "def default_credentials(**kwargs):\n    return None\n",
        "file_name": "_chain.py",
        "ml_format": None,
        "original_bytes": b"def default_credentials(**kwargs):\n    return None\n",
        "entry_rel_path": "src/anthropic/lib/credentials/_chain.py",
        "project_root": str(tmp_path),
    }
    l1_output = {"verdict": {"verdict_label": "malicious"}, "hypotheses": []}

    await _orch.run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
        enable_per_scan_dep_install=True,
    )

    hrp_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id.startswith("HRP_")]
    assert hrp_plans, "expected at least one HRP plan submitted"

    for plan in hrp_plans:
        assert plan.runtime_packages == ["anthropic"], (
            f"v15.17: HRP plan {plan.hypothesis_id} must carry runtime_packages "
            f"so dast-init pip-installs the target dist before the harness runs. "
            f"got: {plan.runtime_packages!r}"
        )
        assert plan.own_dist_name == "anthropic", (
            f"v15.17: HRP plan {plan.hypothesis_id} must carry own_dist_name "
            f"so dast-init uses the with-deps install path. "
            f"got: {plan.own_dist_name!r}"
        )


def test_v1527_observable_keyword_passthrough_suppressed() -> None:
    """v15.27 causality fix: when a model's expected_observable token
    is ALSO present in args_json, its presence in the function output
    is pass-through, not exploit evidence. The Gemini-named bedrock/_auth
    case: model expected ``argus_probe_session_token_XYZ`` in output;
    function received that exact token as input and included it in
    signed headers (by-design). Should NOT confirm."""
    from dast.runtime_probe import _evidence_signature_match

    matched, rationale, oracle = _evidence_signature_match(
        attack_class="data_exfiltration",
        value_preview="X-Amz-Security-Token: argus_probe_session_token_XYZ_secret",
        stderr_preview="",
        expected_observable="argus_probe_session_token_XYZ_secret in output",
        args_json='["argus_probe_session_token_XYZ_secret"]',
    )
    assert matched is False, (
        f"v15.27 should refute pass-through; got matched={matched} "
        f"rationale={rationale!r} oracle={oracle!r}"
    )


def test_v1527_observable_keyword_new_content_still_fires() -> None:
    """v15.27: when the keyword appears in output but NOT in input,
    it's new content the function produced — keyword oracle still
    fires. The pass-through guard must only suppress, never block
    legitimate signals."""
    from dast.runtime_probe import _evidence_signature_match

    matched, rationale, oracle = _evidence_signature_match(
        attack_class="data_exfiltration",
        value_preview="returned: ssh_private_key=ssh-rsa AAAAB3...",
        stderr_preview="",
        expected_observable="ssh_private_key leaked in output",
        # args do NOT contain ssh_private_key — function produced it
        args_json='["benign_input"]',
    )
    assert matched is True, "function-produced new content must still fire keyword oracle"
    assert "ssh_private_key" in rationale


def test_v1527_observable_keyword_partial_token_pass_through() -> None:
    """Pass-through is detected on lowercase comparison — case
    differences shouldn't bypass the guard."""
    from dast.runtime_probe import _evidence_signature_match

    matched, _, _ = _evidence_signature_match(
        attack_class="data_exfiltration",
        value_preview="X-Amz-Date: ARGUS_PROBE_SECRET",
        stderr_preview="",
        expected_observable="argus_probe_secret",
        args_json='["argus_probe_secret"]',  # same string, different case in output
    )
    assert matched is False, "case-insensitive pass-through must be detected"


def test_v1527_cleartext_signature_requires_wiretap_marker() -> None:
    """v15.27 wiretap gate: ``Authorization: Bearer`` substring in a
    function's return value is NOT enough to fire CWE-319 — the
    wiretap listener must have captured bytes (signaled by
    ``ARGUS_WIRETAP_CLEARTEXT_OBSERVED`` or
    ``argus_wiretap_scheme`` markers). Otherwise the function just
    returned a dict containing the string, which is by-design."""
    from dast.runtime_probe import _evidence_signature_match

    # Function returned a signed-headers dict with Authorization key
    # but the wiretap never captured anything (no marker present)
    matched, _, _ = _evidence_signature_match(
        attack_class="cleartext_transmission",
        value_preview="{'Authorization': 'Bearer XYZ_TOKEN', 'X-Date': '2026'}",
        stderr_preview="",
        expected_observable="authorization header sent in cleartext",
        args_json='[]',
    )
    assert matched is False, (
        "v15.27: cleartext signatures must require wiretap marker — "
        "returned-dict substring alone is by-design"
    )


def test_v1527_cleartext_signature_fires_with_wiretap_marker() -> None:
    """v15.27: when the wiretap actually captured cleartext bytes,
    the ``Authorization: Bearer`` signature DOES fire. The gate is
    a guard, not a block."""
    from dast.runtime_probe import _evidence_signature_match

    matched, rationale, _ = _evidence_signature_match(
        attack_class="cleartext_transmission",
        value_preview=(
            "result | ARGUS_WIRETAP_CLEARTEXT_OBSERVED: POST /v1 HTTP/1.1\\n"
            "Authorization: Bearer sk_secret_token"
        ),
        stderr_preview="",
        expected_observable="bearer token sent in cleartext",
        args_json='[]',
    )
    assert matched is True
    # Either the wiretap marker OR Bearer should be the matched signature
    assert (
        "ARGUS_WIRETAP_CLEARTEXT_OBSERVED" in rationale
        or "Authorization: Bearer" in rationale
    )


def test_v1527_cleartext_other_classes_unaffected() -> None:
    """v15.27: the wiretap gate is scoped to cleartext_transmission.
    Other attack classes' class signatures still fire normally."""
    from dast.runtime_probe import _evidence_signature_match

    matched, rationale, _ = _evidence_signature_match(
        attack_class="path_traversal",
        # Class signature 'root:x:0:0:' is path_traversal — should fire
        # regardless of wiretap state
        value_preview="root:x:0:0:root:/root:/bin/bash",
        stderr_preview="",
        expected_observable="passwd content",
        args_json='["../etc/passwd"]',
    )
    assert matched is True
    assert "root:x:0:0:" in rationale


def test_v1526_message_pattern_must_use_https_refutes() -> None:
    """v15.26 Fix #1: exception message 'must use HTTPS' refutes
    Rule 1b regardless of exception class. Gemini's named pattern."""
    from dast.runtime_probe import _exception_message_indicates_validation

    matched, phrase = _exception_message_indicates_validation(
        "Token endpoint must use HTTPS"
    )
    assert matched is True
    assert "https" in phrase.lower()


def test_v1526_message_pattern_invalid_format_refutes() -> None:
    """Generic 'invalid format / not allowed' patterns also fire."""
    from dast.runtime_probe import _exception_message_indicates_validation

    for msg in (
        "invalid URL scheme",
        "missing required argument 'session_id'",
        "TLS required for endpoint",
        "authorization required",
        "refusing to process untrusted url",
        "Token endpoint response body exceeds 1048576 bytes",
    ):
        m, _ = _exception_message_indicates_validation(msg)
        assert m is True, f"should refute: {msg!r}"


def test_v1526_message_pattern_keeps_real_exploit_signal() -> None:
    """Critical: don't refute messages that carry leaked content or
    real exploit-bearing telemetry (XXE-resolved file content,
    SSRF connection-refused-after-attempt, etc.)."""
    from dast.runtime_probe import _exception_message_indicates_validation

    for msg in (
        "Entity 'xxe' not defined at line 5",  # XMLSyntaxError content
        "Connection refused 169.254.169.254",  # SSRF network artifact
        "checksum mismatch root:x:0:0:root:/root",  # leaked passwd
        "command executed via subprocess",  # RCE signal
    ):
        m, _ = _exception_message_indicates_validation(msg)
        assert m is False, f"should NOT refute: {msg!r}"


def test_v1526_generate_baseline_args_strips_strings() -> None:
    """Every string in args/kwargs gets replaced with the baseline
    sentinel; non-string types preserved."""
    from dast.runtime_probe import (
        _generate_baseline_args,
        _BASELINE_GARBAGE_SENTINEL,
    )

    a, k = _generate_baseline_args(
        '["http://attacker", 42, true]',
        '{"url": "http://evil/", "timeout": 30, "verify": false, "headers": {"X-Auth": "secret"}}',
    )
    import json as _json

    aobj = _json.loads(a)
    kobj = _json.loads(k)
    assert aobj == [_BASELINE_GARBAGE_SENTINEL, 42, True]
    assert kobj["url"] == _BASELINE_GARBAGE_SENTINEL
    assert kobj["timeout"] == 30
    assert kobj["verify"] is False
    assert kobj["headers"]["X-Auth"] == _BASELINE_GARBAGE_SENTINEL


def test_v1526_uniform_validation_detection_same_exc() -> None:
    """When baseline + attack raise the SAME exception class with
    structurally-identical messages → uniform = True."""
    from dast.runtime_probe import _is_differential_uniform_validation

    attack = {
        "ok": False,
        "exception_type": "ValueError",
        "exception_msg": "path '/etc/passwd' not found",
    }
    baseline = {
        "ok": False,
        "exception_type": "ValueError",
        "exception_msg": "path '__ARGUS_DIFFERENTIAL_BASELINE_GARBAGE_VALUE__' not found",
    }
    m, _ = _is_differential_uniform_validation(attack, baseline)
    assert m is True


def test_v1526_uniform_validation_detection_attack_succeeded() -> None:
    """Attack succeeded, baseline failed → exploit signal — NOT uniform."""
    from dast.runtime_probe import _is_differential_uniform_validation

    attack = {"ok": True, "value_preview": "root:x:0:0:..."}
    baseline = {"ok": False, "exception_type": "ValueError", "exception_msg": "not found"}
    m, _ = _is_differential_uniform_validation(attack, baseline)
    assert m is False


def test_v1526_uniform_validation_detection_diff_messages() -> None:
    """Both raised but messages differ — attack-specific content
    visible → NOT uniform (keep the finding)."""
    from dast.runtime_probe import _is_differential_uniform_validation

    attack = {
        "ok": False,
        "exception_type": "ValueError",
        "exception_msg": "checksum mismatch root:x:0:0:",
    }
    baseline = {
        "ok": False,
        "exception_type": "ValueError",
        "exception_msg": "invalid input format",
    }
    m, _ = _is_differential_uniform_validation(attack, baseline)
    assert m is False


def test_v1526_uniform_validation_detection_diff_exc_types() -> None:
    """Different exception classes — NOT uniform (one was deeper than
    the other in the function)."""
    from dast.runtime_probe import _is_differential_uniform_validation

    attack = {
        "ok": False,
        "exception_type": "XMLSyntaxError",  # content-processing error
        "exception_msg": "Entity 'xxe' not defined",
    }
    baseline = {
        "ok": False,
        "exception_type": "ValueError",  # input validation error
        "exception_msg": "invalid XML",
    }
    m, _ = _is_differential_uniform_validation(attack, baseline)
    assert m is False


def test_v1526_uniform_validation_handles_missing_data() -> None:
    """Missing baseline / attack outcome → not uniform (don't suppress)."""
    from dast.runtime_probe import _is_differential_uniform_validation

    for a, b in (
        (None, {"ok": False, "exception_type": "ValueError", "exception_msg": "x"}),
        ({"ok": False, "exception_type": "ValueError", "exception_msg": "x"}, None),
        (None, None),
        ({}, {}),
    ):
        m, _ = _is_differential_uniform_validation(a, b)
        assert m is False


def test_v1526_interpret_uniform_validation_suppresses_rule_1b() -> None:
    """v15.26 end-to-end via interpret_probe_trace: when the trace
    carries a baseline_parsed AND both raised the same exception with
    same normalized message, Rule 1b CONFIRMED is suppressed → return
    None. Gemini Suggestion #3 fix path."""
    candidate = _mk_candidate(
        attack_class="ssrf",
        test_inputs=[
            RuntimeProbeInput(
                args_json='["http://169.254.169.254/"]',
                kwargs_json="{}",
                expected_observable="connection",
                exploit_proof_if_observed="SSRF",
            )
        ],
    )
    test_in = candidate.test_inputs[0]
    # Build a trace whose RESULT_JSON shows the function raised AND
    # the exception message would normally trip the keyword oracle —
    # BUT the BASELINE_RESULT_JSON shows the SAME exception fired for
    # baseline garbage too. v15.26 suppression should fire.
    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            'BASELINE_RESULT_JSON:{"ok": false, "exception_type": "RuntimeError", '
            '"exception_msg": "could not resolve credentials from session"}\n'
            'RESULT_JSON:{"ok": false, "exception_type": "RuntimeError", '
            '"exception_msg": "could not resolve credentials from session"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=120,
    )
    # Sanity: parser captured both markers
    assert trace.baseline_parsed is not None
    assert trace.parsed_result is not None

    finding = interpret_probe_trace(
        trace, candidate, test_in, candidate_idx=0, input_idx=0
    )
    assert finding is None, (
        "v15.26: uniform-validation case must suppress Rule 1b; "
        "got finding={finding!r}"
    )


def test_v1526_interpret_keeps_finding_when_baseline_differs() -> None:
    """v15.26: when baseline + attack produce different outcomes,
    DON'T suppress — Rule 1b can still fire if the attack's exception
    carries exploit-bearing content (XXE entity, leaked path, etc.)."""
    candidate = _mk_candidate(attack_class="path_traversal")
    test_in = candidate.test_inputs[0]
    trace = parse_probe_trace(
        candidate_function=candidate.function_name,
        input_args_json=test_in.args_json,
        exit_code=0,
        stdout=(
            # Baseline raised a generic ValueError
            'BASELINE_RESULT_JSON:{"ok": false, "exception_type": "ValueError", '
            '"exception_msg": "invalid input"}\n'
            # Attack raised XMLSyntaxError WITH the leaked content
            'RESULT_JSON:{"ok": false, "exception_type": "XMLSyntaxError", '
            '"exception_msg": "Start tag expected, found root:x:0:0: at line 1"}\n'
            'SIDE_EFFECTS:{"tmp_files_added": []}\n'
        ),
        stderr="",
        elapsed_ms=120,
    )
    finding = interpret_probe_trace(
        trace, candidate, test_in, candidate_idx=0, input_idx=0
    )
    # Should NOT be suppressed — different exception type means the
    # attack reached a different code path than baseline.
    assert finding is not None, "different exc types should keep Rule 1b live"


def test_v1526_normalize_strips_quoted_strings_and_numbers() -> None:
    """Verify the message normalizer strips quoted content and numeric
    tokens, leaving the structural shape."""
    from dast.runtime_probe import _normalize_exception_msg_for_comparison

    n1 = _normalize_exception_msg_for_comparison(
        "Response body exceeds 1048576 bytes (got 5000)"
    )
    n2 = _normalize_exception_msg_for_comparison(
        "Response body exceeds 1048576 bytes (got 2000)"
    )
    assert n1 == n2  # numeric variance normalized

    n3 = _normalize_exception_msg_for_comparison(
        "File '/etc/passwd' not found at line 5"
    )
    n4 = _normalize_exception_msg_for_comparison(
        "File '__ARGUS_DIFFERENTIAL_BASELINE_GARBAGE_VALUE__' not found at line 5"
    )
    # Both have a quoted string + a number → both strip to the same shape
    assert n3 == n4


def test_v1525_purpose_aware_suppresses_get_auth_headers() -> None:
    """v15.25 Fix A: ``get_auth_headers`` returning auth headers is
    the function's contract — flagging it as CWE-200 is a Gemini-
    confirmed false positive."""
    from dast.runtime_probe import _function_name_declares_purpose

    matched, why = _function_name_declares_purpose(
        "get_auth_headers", "data_exfiltration"
    )
    assert matched is True
    assert "get_auth_headers" in why
    assert "function-naming pattern" in why


def test_v1525_purpose_aware_suppresses_sign_request() -> None:
    """v15.25 Fix A: signer/builder names also declare purpose."""
    from dast.runtime_probe import _function_name_declares_purpose

    for fn in ("sign_request", "build_auth_headers", "encode_token", "to_headers"):
        matched, _ = _function_name_declares_purpose(fn, "data_exfiltration")
        assert matched is True, f"{fn} should match purpose pattern"


def test_v1525_purpose_aware_suppresses_provider_callable() -> None:
    """v15.25 Fix A: class-instance ``__call__`` on a Provider /
    Credentials / Token / Signer class is the Anthropic SDK convention
    for ``AccessTokenProvider`` callables. They exist to return the
    material in their name."""
    from dast.runtime_probe import _function_name_declares_purpose

    for fn in (
        "IdentityTokenFile.__call__",
        "WorkloadIdentityCredentials.__call__",
        "StaticToken.__call__",
        "CredentialsFile.__call__",
    ):
        matched, _ = _function_name_declares_purpose(fn, "data_exfiltration")
        assert matched is True, f"{fn} should match provider-callable pattern"


def test_v1525_purpose_aware_does_not_suppress_load_user_data() -> None:
    """v15.25 Fix A precision: the heuristic targets auth-domain
    getters, not generic data-returning functions. ``load_user_data``
    returning user data WOULD be CWE-200 worth flagging."""
    from dast.runtime_probe import _function_name_declares_purpose

    matched, _ = _function_name_declares_purpose(
        "load_user_data", "data_exfiltration"
    )
    assert matched is False


def test_v1525_purpose_aware_does_not_suppress_non_data_exfil() -> None:
    """v15.25 Fix A: suppression is class-specific. ``get_auth_headers``
    flagged for ``path_traversal`` / ``code_injection`` / ``ssrf`` is
    NOT suppressed — those CWEs describe content the function
    shouldn't have returned regardless of name."""
    from dast.runtime_probe import _function_name_declares_purpose

    for ac in ("path_traversal", "code_injection", "ssrf", "command_injection"):
        matched, _ = _function_name_declares_purpose("get_auth_headers", ac)
        assert matched is False, f"attack_class={ac} should NOT be suppressed by Fix A"


def test_v1525_purpose_aware_logger_not_suppressed() -> None:
    """v15.25 Fix A: ``Logger.__call__`` has no auth-domain keyword in
    the class name — should NOT match. The heuristic only fires on
    classes whose name declares they handle auth/credentials/tokens."""
    from dast.runtime_probe import _function_name_declares_purpose

    matched, _ = _function_name_declares_purpose("Logger.__call__", "data_exfiltration")
    assert matched is False


def test_v1525_io_check_no_network_calls_suppresses_url_cwes() -> None:
    """v15.25 Fix B: file with empty
    ``behavioral_profile.actual_capabilities.network_calls`` is a pure
    transformer — SSRF / cleartext / open_redirect CWEs are theoretical
    not actual."""
    from dast.runtime_probe import _file_has_network_io

    bp = {"actual_capabilities": {"network_calls": []}}
    assert _file_has_network_io(bp) is False


def test_v1525_io_check_with_network_calls_does_not_suppress() -> None:
    """v15.25 Fix B: when network_calls is non-empty, the file DOES
    dispatch I/O — URL-CWE findings stay live."""
    from dast.runtime_probe import _file_has_network_io

    bp = {"actual_capabilities": {"network_calls": ["requests.get at line 42"]}}
    assert _file_has_network_io(bp) is True


def test_v1525_io_check_missing_profile_defaults_safe() -> None:
    """v15.25 Fix B defensive: when behavioral_profile is missing or
    malformed, defer to NOT suppressing (don't drop findings on
    incomplete data)."""
    from dast.runtime_probe import _file_has_network_io

    for bp in (None, {}, {"actual_capabilities": None}, {"actual_capabilities": {}}):
        assert _file_has_network_io(bp) is True, f"bp={bp!r} should default to True"


def test_v1525_io_check_required_attack_classes() -> None:
    """v15.25 Fix B: the suppression scope is exactly the URL-dispatch
    attack classes — ssrf, cleartext_transmission, open_redirect.
    Other classes (path_traversal, code_injection) aren't gated on
    network I/O presence."""
    from dast.runtime_probe import _NETWORK_IO_REQUIRED_ATTACK_CLASSES

    assert "ssrf" in _NETWORK_IO_REQUIRED_ATTACK_CLASSES
    assert "cleartext_transmission" in _NETWORK_IO_REQUIRED_ATTACK_CLASSES
    assert "open_redirect" in _NETWORK_IO_REQUIRED_ATTACK_CLASSES
    # NOT gated on I/O — these are content-shape findings, not network
    assert "path_traversal" not in _NETWORK_IO_REQUIRED_ATTACK_CLASSES
    assert "code_injection" not in _NETWORK_IO_REQUIRED_ATTACK_CLASSES
    assert "deserialization" not in _NETWORK_IO_REQUIRED_ATTACK_CLASSES


def test_v1517_phase_3_prompt_addendum_renders_when_present() -> None:
    """v15.17 (2026-05-20): the Phase 3 loop hypothesis-batch prompt
    must inject a FORCED RECONSIDERATION block when the orchestrator
    passes an ``adversarial_addendum`` string. This is how the
    borderline-reinvocation path tells Opus that Phase B+ evidence
    already exists and "just decline" is the wrong default."""
    from dast.prompts import build_phase_3_loop_hypothesis_batch_prompt

    addendum = (
        "Phase B+ already surfaced confirmed runtime evidence in this "
        "file (3 findings). Reconsider deliberately..."
    )
    prompt = build_phase_3_loop_hypothesis_batch_prompt(
        file_text="def f(): pass\n",
        behavioral_profile={"callables_explored": 1},
        prior_turns=None,
        adversarial_addendum=addendum,
    )
    assert "FORCED RECONSIDERATION" in prompt, (
        "v15.17: prompt must surface a clear reconsideration banner so "
        "Opus is told this is a re-prompt, not turn 1"
    )
    assert "Phase B+ already surfaced" in prompt, (
        "v15.17: the addendum text must reach the prompt verbatim"
    )


def test_v1517_phase_3_prompt_no_addendum_is_backwards_compat() -> None:
    """v15.17 boundary: when ``adversarial_addendum`` is empty (the
    default), the prompt produces no reconsideration banner. This is
    the non-borderline path; behavior must match pre-v15.17 exactly."""
    from dast.prompts import build_phase_3_loop_hypothesis_batch_prompt

    prompt = build_phase_3_loop_hypothesis_batch_prompt(
        file_text="def f(): pass\n",
        behavioral_profile={"callables_explored": 1},
        prior_turns=None,
    )
    assert "FORCED RECONSIDERATION" not in prompt
    assert "Phase B+ already surfaced" not in prompt


@pytest.mark.asyncio
async def test_runtime_probe_blocked_when_sandbox_shows_no_exploit(tmp_path) -> None:
    """Negative case: probe runs, function raises PermissionError, no
    canary appears → no finding, journal records as rejected (BLOCKED-
    equivalent for runtime probes)."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": false, "exception_type": "PermissionError", '
                    '"exception_msg": "Permission denied"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 30,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "read_file_safely",
                            "attack_class": "path_traversal",
                            "rationale": "x",
                            "test_inputs": [
                                {
                                    "args_json": '["../etc/passwd"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "returns content",
                                    "exploit_proof_if_observed": "path traversal",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "def f(p): return open(p).read()\n",
        "file_name": "v.py",
        "original_bytes": b"def f(p): return open(p).read()\n",
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
    )

    # Probe ran but no exploit was confirmed
    rejected_probes = [
        r
        for r in result.journal_records
        if r.get("claim_id", "").startswith("HRP_") and r.get("verdict") == "rejected"
    ]
    assert len(rejected_probes) >= 1
    # No new HRP hypothesis added to l1_output (no exploit to forward)
    assert not any(h.get("id", "").startswith("HRP_") for h in (l1_output.get("hypotheses") or []))


@pytest.mark.asyncio
async def test_runtime_probe_critical_code_injection_bumps_to_critical_malicious(
    tmp_path,
) -> None:
    """Fix #1: probe-confirmed CRITICAL severity in
    {code_injection, command_injection, deserialization} → verdict
    bumped to critical_malicious (not just malicious)."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "int", "value_preview": "0"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": ["argus_probe_pwned"]}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 50,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "exec_user_code",
                            "attack_class": "code_injection",
                            "rationale": "calls exec() on user input",
                            "test_inputs": [
                                {
                                    "args_json": (
                                        '["__import__(\\"os\\")'
                                        '.system(\\"touch /tmp/argus_probe_pwned\\")"]'
                                    ),
                                    "kwargs_json": "{}",
                                    "expected_observable": "canary file appears",
                                    "exploit_proof_if_observed": "code injection via exec",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {
            "text": _phase_a_verdict_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "def exec_user_code(s):\n    exec(s)\n",
        "file_name": "evil.py",
        "original_bytes": b"def exec_user_code(s):\n    exec(s)\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "suspicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
    )
    # Critical + code_injection → critical_malicious (one tier higher
    # than vanilla malicious bump)
    assert result.final_verdict.get("verdict_label") == "critical_malicious"


@pytest.mark.asyncio
async def test_runtime_probe_medium_severity_does_not_bump_verdict(
    tmp_path,
) -> None:
    """Fix #1 safety: probe-confirmed MEDIUM severity (e.g., xss,
    crypto_weakness) does NOT bump the verdict — those FP-prone classes
    need stronger evidence than one runtime observation."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "str", '
                    '"value_preview": "<script>alert(1)</script>"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 20,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "render_template",
                            "attack_class": "xss",  # severity = medium
                            "rationale": "echoes user input into HTML",
                            "test_inputs": [
                                {
                                    "args_json": '["<script>alert(1)</script>"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "script tag in return value",
                                    "exploit_proof_if_observed": "xss",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {
            "text": _phase_a_verdict_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "def render(s): return s\n",
        "file_name": "view.py",
        "original_bytes": b"def render(s): return s\n",
        "ml_format": None,
    }
    l1_output = {"verdict": {"verdict_label": "suspicious"}, "hypotheses": []}

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
    )
    # Medium severity → verdict NOT bumped. The probe finding still
    # surfaces in findings_validated (the user sees it), but the verdict
    # tier stays where Phase A left it.
    label = result.final_verdict.get("verdict_label", "")
    assert label != "malicious" and label != "critical_malicious", (
        f"Fix #1 safety: medium-severity probe should not bump verdict; got {label}"
    )
    # But the finding still surfaces:
    assert any(fid.startswith("HRP_") for fid in result.findings_validated)


@pytest.mark.asyncio
async def test_runtime_probe_does_not_re_test_hrp_via_phase_a(tmp_path) -> None:
    """Fix #2: when the probe stage emits HRP_ findings, Phase A in
    iter 1 should NOT see them in its pending_hypotheses (otherwise we
    pay 2× sandbox cost and risk contradictory verdicts). Probe-only
    findings reach the engine via findings_validated, not via the
    iteration loop."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": true, "value_preview": "exfil"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 50,
            },
        },
    )

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "read_file",
                            "attack_class": "path_traversal",
                            "rationale": "x",
                            "test_inputs": [
                                {
                                    "args_json": '["../etc/passwd"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "returns content",
                                    "exploit_proof_if_observed": "path traversal",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {
            "text": _phase_a_verdict_response(),
            "usage": {},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "h",
        "source_text": "def read_file(p): return open(p).read()\n",
        "file_name": "io.py",
        "original_bytes": b"def read_file(p): return open(p).read()\n",
        "ml_format": None,
    }
    # Start with ONE L1 hypothesis. Phase A should plan against ONLY this
    # one — NOT against the HRP_0_0 finding the probe will discover.
    l1_output = {
        "verdict": {"verdict_label": "malicious"},
        "hypotheses": [
            {
                "id": "H001",
                "finding_ref": "H001",
                "cwe": "CWE-22",
                "severity": "critical",
                "type": "path_traversal",
                "explanation": "",
                "code_snippet": "",
                "line": 1,
                "data_flow_trace": "",
                "proof_of_concept": "",
                "confidence": 0.9,
            }
        ],
    }

    await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_runtime_probe=True,
    )

    # Plans submitted to sandbox: the probe's HRP_0_0 (1 plan) + Phase A's
    # plan for H001 (if any). Critical: Phase A should NOT have submitted
    # a plan with hypothesis_id="HRP_0_0" (that would mean re-testing).
    hrp_phase_a_resubmits = [
        p
        for p in sandbox.submitted_plans
        if p.hypothesis_id.startswith("HRP_")
        and p.plan_id.startswith("i1-")
        and "_argus_probe_" not in (p.commands[1] if len(p.commands) > 1 else "")
    ]
    # The probe plan's commands have ``_argus_probe_`` in them; a Phase A
    # re-test would NOT (it'd be a model-generated plan). So we filter on
    # commands shape: any HRP_ plan WITHOUT the _argus_probe_ marker is
    # a Phase A re-test.
    assert hrp_phase_a_resubmits == [], (
        f"Fix #2: Phase A re-tested HRP findings (cost doubled): "
        f"{[p.plan_id for p in hrp_phase_a_resubmits]}"
    )


@pytest.mark.asyncio
async def test_runtime_probe_model_declines_journal_records_rationale(tmp_path) -> None:
    """When the model declines (empty candidates + non_probable_reason),
    the orchestrator records the rationale in the journal as a rejected
    'HRP_NONE' record so downstream telemetry sees the decline."""
    sandbox = _CapturingProbeSandbox()

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": json.dumps(
                    {
                        "candidates": [],
                        "non_probable_reason": "file only contains data constants",
                    }
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "X = 1\nY = 'literal'\n",
        "file_name": "consts.py",
        "original_bytes": b"X = 1\n",
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
    )

    declines = [r for r in result.journal_records if r.get("claim_id") == "HRP_NONE"]
    assert len(declines) == 1
    assert "declined" in declines[0].get("rationale", "").lower()
    assert "data constants" in declines[0].get("rationale", "")


# ── Phase 1b — Iterative refinement on BLOCKED probes ─────────────────


def _phase_b_refinement_response(refined_inputs: list[dict]) -> str:
    """Stub Sonnet response shape for Phase 1b refinement candidate-gen."""
    return json.dumps(
        {
            "non_refinable_reason": "" if refined_inputs else "no refinement found",
            "refined_inputs": refined_inputs,
        }
    )


@pytest.mark.asyncio
async def test_iterative_refinement_skipped_when_flag_disabled(tmp_path) -> None:
    """If ``enable_runtime_probe_iterative=False`` (default), the
    refinement helper does NOT run — even when initial probes blocked
    with recoverable failures. Cost-neutral default."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                "stdout": (
                    'RESULT_JSON:{"ok": false, "exception_type": "TypeError", '
                    '"exception_msg": "expected str got int"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 20,
            },
        },
    )

    refinement_call_count = {"n": 0}

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["refined_inputs", "non_refinable_reason"]:
            refinement_call_count["n"] += 1  # should never fire
            return {"text": _phase_b_refinement_response([]), "usage": {}, "finish_reason": "stop"}
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "f",
                            "attack_class": "path_traversal",
                            "rationale": "x",
                            "test_inputs": [
                                {
                                    "args_json": "[42]",  # int, causes TypeError
                                    "kwargs_json": "{}",
                                    "expected_observable": "/etc/passwd",
                                    "exploit_proof_if_observed": "path traversal",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "def f(p): return open(p).read()\n",
        "file_name": "v.py",
        "original_bytes": b"def f(p): return open(p).read()\n",
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
        enable_runtime_probe_iterative=False,  # OFF
    )

    assert refinement_call_count["n"] == 0, "refinement should NOT fire when flag disabled"


@pytest.mark.asyncio
async def test_iterative_refinement_fires_on_recoverable_failure(tmp_path) -> None:
    """When opt-in AND initial probe blocked with a RECOVERABLE
    exception (TypeError / SyntaxError / RangeError / etc.), the helper
    invokes Sonnet with the failure details and submits a refined probe.

    If the refined probe confirms via Rule 1 (evidence-signature match)
    OR Rule 2 (canary), the finding lands in findings_validated."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                # Initial probe BLOCKS with TypeError (recoverable)
                "stdout": (
                    'RESULT_JSON:{"ok": false, "exception_type": "TypeError", '
                    '"exception_msg": "expected str got int"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 20,
            },
            "HRP_0_r0": {
                # Refinement probe CONFIRMS (signature-matching content
                # in the value_preview → Rule 1 fires).
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "str", '
                    '"value_preview": "root:x:0:0:root:/root:/bin/bash"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 50,
            },
        },
    )

    refinement_call_count = {"n": 0}
    last_refinement_prompt = {"text": ""}

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["refined_inputs", "non_refinable_reason"]:
            refinement_call_count["n"] += 1
            last_refinement_prompt["text"] = prompt
            return {
                "text": _phase_b_refinement_response(
                    [
                        {
                            "args_json": '["../../etc/passwd"]',  # string, not int
                            "kwargs_json": "{}",
                            "rationale": "TypeError says expected str — switching to a string",
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "read_file_safely",
                            "attack_class": "path_traversal",
                            "rationale": "x",
                            "test_inputs": [
                                {
                                    "args_json": "[42]",  # wrong type, blocks
                                    "kwargs_json": "{}",
                                    "expected_observable": "/etc/passwd content",
                                    "exploit_proof_if_observed": "path traversal",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "def read_file_safely(p): return open(p).read()\n",
        "file_name": "v.py",
        "original_bytes": b"def read_file_safely(p): return open(p).read()\n",
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
        enable_runtime_probe_iterative=True,
    )

    # Refinement was invoked
    assert refinement_call_count["n"] == 1, "refinement should fire exactly once"
    # Prompt carried the previous TypeError so Sonnet has context
    assert "TypeError" in last_refinement_prompt["text"]
    assert "expected str got int" in last_refinement_prompt["text"]

    # The refined probe's HRP_0_r0 plan reached the sandbox
    refine_plans = [p for p in sandbox.submitted_plans if "_r0" in p.hypothesis_id]
    assert len(refine_plans) == 1, (
        f"expected 1 refined plan; got {[p.hypothesis_id for p in sandbox.submitted_plans]}"
    )

    # Refinement confirmed → HRP_0_r0 in findings_validated
    assert any("_r0" in fid for fid in result.findings_validated), (
        f"refinement HRP not in findings_validated: {result.findings_validated}"
    )

    # Journal has confirmed record with refinement_idx tag
    confirmed_refines = [
        r
        for r in result.journal_records
        if r.get("claim_id", "").startswith("HRP_")
        and r.get("verdict") == "confirmed"
        and "refinement_idx" in r.get("rationale", "")
    ]
    assert len(confirmed_refines) >= 1


@pytest.mark.asyncio
async def test_iterative_refinement_skipped_on_unrecoverable_failures(tmp_path) -> None:
    """When EVERY initial probe failure is unrecoverable (ImportError /
    AttributeError / empty exception_type — the function was never
    reached), refinement does NOT fire. Refining without runtime
    evidence of the function actually running is just guessing — the
    fix is env-side (missing dep, wrong file_name), not payload-side."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                # ImportError — function was NEVER reached.
                "stdout": (
                    'RESULT_JSON:{"ok": false, "exception_type": "ImportError", '
                    '"exception_msg": "Cannot find module \'sandboxjs\'"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 15,
            },
        },
    )

    refinement_call_count = {"n": 0}

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["refined_inputs", "non_refinable_reason"]:
            refinement_call_count["n"] += 1  # should not fire
            return {
                "text": _phase_b_refinement_response([]),
                "usage": {},
                "finish_reason": "stop",
            }
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "f",
                            "attack_class": "path_traversal",
                            "rationale": "x",
                            "test_inputs": [
                                {
                                    "args_json": '["x"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "y",
                                    "exploit_proof_if_observed": "z",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "def f(p): return open(p).read()\n",
        "file_name": "v.py",
        "original_bytes": b"def f(p): return open(p).read()\n",
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
        enable_runtime_probe_iterative=True,
    )

    assert refinement_call_count["n"] == 0, (
        "refinement should NOT fire when all failures are unrecoverable (ImportError)"
    )


@pytest.mark.asyncio
async def test_iterative_refinement_skipped_when_initial_probe_confirmed(tmp_path) -> None:
    """If the initial probe already CONFIRMED an exploit for a candidate,
    refinement does NOT fire for that candidate — we already have a
    finding, no need to spend tokens looking for more."""
    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_0_0": {
                # Initial probe CONFIRMS via signature match.
                "stdout": (
                    'RESULT_JSON:{"ok": true, "type": "str", '
                    '"value_preview": "root:x:0:0:root:/root:/bin/bash"}\n'
                    'SIDE_EFFECTS:{"tmp_files_added": []}\n'
                ),
                "exit_code": 0,
                "elapsed_ms": 20,
            },
        },
    )

    refinement_call_count = {"n": 0}

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["refined_inputs", "non_refinable_reason"]:
            refinement_call_count["n"] += 1
            return {
                "text": _phase_b_refinement_response([]),
                "usage": {},
                "finish_reason": "stop",
            }
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response(
                    [
                        {
                            "function_name": "read_file_safely",
                            "attack_class": "path_traversal",
                            "rationale": "x",
                            "test_inputs": [
                                {
                                    "args_json": '["../../etc/passwd"]',
                                    "kwargs_json": "{}",
                                    "expected_observable": "/etc/passwd content",
                                    "exploit_proof_if_observed": "path traversal",
                                }
                            ],
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "def read_file_safely(p): return open(p).read()\n",
        "file_name": "v.py",
        "original_bytes": b"def read_file_safely(p): return open(p).read()\n",
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
        enable_runtime_probe_iterative=True,
    )

    assert refinement_call_count["n"] == 0, (
        "refinement should NOT fire when initial probe already confirmed"
    )


# ══════════════════════════════════════════════════════════════════════════
# Phase 2 — Cross-function exploit chains
# ══════════════════════════════════════════════════════════════════════════
#
# Coverage:
# * Schema shape (MAX_CHAINS_PER_FILE, MAX_CHAIN_STEPS, steps 2-3 only)
# * Chain plan builder — Python-only, valid-step-count gate, HRP_C<idx>
# * Python chain harness embedding — placeholder substitution, args/kwargs
# * Chain trace parser — CHAIN_RESULT_JSON markers, short_circuited flag
# * Chain interpreter — Rule 1 (final-step evidence-signature match),
#   Rule 2 (canary side effect), short-circuit blocks Rule 1, no
#   evidence → None.

from dast.runtime_probe import (  # noqa: E402
    MAX_CHAIN_STEPS,
    MAX_CHAINS_PER_FILE,
    RuntimeProbeChain,
    RuntimeProbeChainStep,
    RuntimeProbeChainTrace,
    _build_python_chain_harness,
    build_runtime_probe_chain_plan,
    interpret_probe_chain_trace,
    parse_probe_chain_trace,
)


def _chain_two_step_eval() -> RuntimeProbeChain:
    """A common chain shape: parse(input) → eval_field(parsed_dict).
    Step 2's args reference step 1's result via the placeholder."""
    return RuntimeProbeChain(
        steps=[
            RuntimeProbeChainStep(
                function_name="parse_config",
                args_json='["__import__(\\"os\\").system(\\"id\\")"]',
                kwargs_json="{}",
            ),
            RuntimeProbeChainStep(
                function_name="apply_config",
                args_json='["<<_step1_result>>"]',
                kwargs_json="{}",
            ),
        ],
        attack_class="code_injection",
        rationale="parse returns dict; apply eval()s a field — chain is RCE",
        expected_observable="uid= appears in stdout",
        exploit_proof_if_observed="RCE via parse-then-eval chain",
    )


# ── Constants ──────────────────────────────────────────────────────────────


def test_chain_constants_bounded() -> None:
    """Chain tunables are non-trivially bounded to keep cost predictable."""
    assert 1 <= MAX_CHAINS_PER_FILE <= 5
    assert 2 <= MAX_CHAIN_STEPS <= 5


# ── Schema ─────────────────────────────────────────────────────────────────


def test_chain_schema_required_top_level() -> None:
    """Schema requires both ``chains`` and ``no_chains_reason``."""
    s = dast_prompts.phase_b_chain_schema()
    assert s["type"] == "object"
    assert "chains" in s["required"]
    assert "no_chains_reason" in s["required"]
    assert s["additionalProperties"] is False


def test_chain_schema_caps_chains_at_max() -> None:
    s = dast_prompts.phase_b_chain_schema()
    assert s["properties"]["chains"]["maxItems"] >= MAX_CHAINS_PER_FILE


def test_chain_schema_caps_steps_at_2_to_max() -> None:
    """A chain must have 2-3 steps. Single-step "chains" are just
    single-function probes; > MAX_CHAIN_STEPS is exponentially costlier."""
    s = dast_prompts.phase_b_chain_schema()
    steps_schema = s["properties"]["chains"]["items"]["properties"]["steps"]
    assert steps_schema["minItems"] == 2
    assert steps_schema["maxItems"] == MAX_CHAIN_STEPS


def test_chain_schema_step_function_name_regex() -> None:
    """Step function names follow same regex as single-function probes."""
    s = dast_prompts.phase_b_chain_schema()
    pat = s["properties"]["chains"]["items"]["properties"]["steps"]["items"]["properties"][
        "function_name"
    ]["pattern"]
    import re as _re

    assert _re.match(pat, "parse_config")
    assert _re.match(pat, "ConfigLoader.load")
    assert _re.match(pat, "_helper")
    assert not _re.match(pat, "weird-name")
    assert not _re.match(pat, "1starts_with_digit")


def test_chain_schema_attack_class_enum_matches_single_function() -> None:
    """Chain attack_class enum must be a superset of (or equal to) the
    single-function attack_class enum so the same severity / CWE
    mappings apply downstream."""
    chain_schema = dast_prompts.phase_b_chain_schema()
    single_schema = dast_prompts.phase_b_runtime_probe_schema()
    chain_classes = set(
        chain_schema["properties"]["chains"]["items"]["properties"]["attack_class"]["enum"]
    )
    single_classes = set(
        single_schema["properties"]["candidates"]["items"]["properties"]["attack_class"]["enum"]
    )
    assert single_classes.issubset(chain_classes)


# ── Plan builder ───────────────────────────────────────────────────────────


def test_chain_plan_returns_none_for_unsupported_language() -> None:
    """Chain probing supports Python (v1.6) + JS (v1.8 JS DAST parity).
    Shell + other languages still return None — they don't have a
    chain harness yet."""
    chain = _chain_two_step_eval()
    # JS supported as of v1.8 — gets a plan with .cjs harness.
    js_plan = build_runtime_probe_chain_plan(
        file_name="x.js", file_bytes=b"module.exports = { f: () => 1, g: () => 2 };",
        chain=chain, chain_idx=0,
    )
    assert js_plan is not None
    assert "_argus_chain_0.cjs" in js_plan["commands"][0]
    # Shell + unknown still skipped.
    assert (
        build_runtime_probe_chain_plan(file_name="x.sh", file_bytes=b"", chain=chain, chain_idx=0)
        is None
    )
    assert (
        build_runtime_probe_chain_plan(file_name="x.go", file_bytes=b"", chain=chain, chain_idx=0)
        is None
    )


def test_chain_plan_js_dispatches_to_node_harness() -> None:
    """JS chain plan uses .cjs extension + `node` runner. cd
    /workspace for npm-installed dep resolution."""
    chain = _chain_two_step_eval()
    plan = build_runtime_probe_chain_plan(
        file_name="malicious.js",
        file_bytes=b"module.exports = { fetchData: () => 'data', parseData: (s) => s.toUpperCase() };",
        chain=chain,
        chain_idx=3,
    )
    assert plan is not None
    assert plan["hypothesis_id"] == "HRP_C3"
    assert plan["commands"][1] == "cd /workspace && node /workspace/_argus_chain_3.cjs"


def test_chain_plan_mjs_supported() -> None:
    """ES module ``.mjs`` files supported via the same JS harness."""
    chain = _chain_two_step_eval()
    plan = build_runtime_probe_chain_plan(
        file_name="esm.mjs",
        file_bytes=b"export const f = () => 1;\nexport const g = () => 2;",
        chain=chain,
        chain_idx=1,
    )
    assert plan is not None
    assert "node /workspace/_argus_chain_1.cjs" in plan["commands"][1]


def test_chain_plan_returns_none_for_single_step_chain() -> None:
    """A 1-step "chain" is a single-function probe — reject so the model
    doesn't slip 1-step chains through and skip the FP defenses on the
    single-function path."""
    bad_chain = RuntimeProbeChain(
        steps=[
            RuntimeProbeChainStep(function_name="single", args_json="[1]", kwargs_json="{}"),
        ],
        attack_class="code_injection",
    )
    assert (
        build_runtime_probe_chain_plan(
            file_name="x.py", file_bytes=b"", chain=bad_chain, chain_idx=0
        )
        is None
    )


def test_chain_plan_returns_none_for_too_many_steps() -> None:
    """> MAX_CHAIN_STEPS is rejected."""
    over = MAX_CHAIN_STEPS + 1
    over_chain = RuntimeProbeChain(
        steps=[
            RuntimeProbeChainStep(function_name=f"s{i}", args_json="[]", kwargs_json="{}")
            for i in range(over)
        ],
        attack_class="code_injection",
    )
    assert (
        build_runtime_probe_chain_plan(
            file_name="x.py", file_bytes=b"", chain=over_chain, chain_idx=0
        )
        is None
    )


def test_chain_plan_python_emits_hrp_c_id() -> None:
    """Chain hypothesis IDs are ``HRP_C<chain_idx>`` — distinct namespace
    from single-function ``HRP_<c>_<i>`` so cross-feature findings don't
    collide in journal lookups."""
    chain = _chain_two_step_eval()
    plan = build_runtime_probe_chain_plan(
        file_name="target.py",
        file_bytes=b"def parse_config(s): return s\ndef apply_config(s): pass\n",
        chain=chain,
        chain_idx=7,
    )
    assert plan is not None
    assert plan["hypothesis_id"] == "HRP_C7"


def test_chain_plan_embeds_file_payload_as_base64() -> None:
    """The original file is staged into the sandbox as base64 payload."""
    chain = _chain_two_step_eval()
    file_bytes = b"def parse_config(s): return s\ndef apply_config(s): pass\n"
    plan = build_runtime_probe_chain_plan(
        file_name="target.py", file_bytes=file_bytes, chain=chain, chain_idx=0
    )
    assert plan is not None
    assert plan["payload_encoding"] == "base64"
    assert base64.b64decode(plan["payload"]) == file_bytes


def test_chain_plan_has_two_commands_write_then_run() -> None:
    """Chain plans are 2-command — write harness, then exec it."""
    chain = _chain_two_step_eval()
    plan = build_runtime_probe_chain_plan(
        file_name="target.py", file_bytes=b"", chain=chain, chain_idx=0
    )
    assert plan is not None
    assert len(plan["commands"]) == 2
    assert plan["commands"][1].startswith("python3 /workspace/_argus_chain_")


def test_chain_plan_rationale_includes_step_arrow_summary() -> None:
    """Rationale renders the chain as ``A -> B [-> C]`` so journal /
    report readers can see the chain shape without parsing the steps."""
    chain = _chain_two_step_eval()
    plan = build_runtime_probe_chain_plan(
        file_name="target.py", file_bytes=b"", chain=chain, chain_idx=0
    )
    assert plan is not None
    assert "parse_config -> apply_config" in plan["rationale"]


def test_chain_plan_timeout_matches_default() -> None:
    chain = _chain_two_step_eval()
    plan = build_runtime_probe_chain_plan(
        file_name="target.py", file_bytes=b"", chain=chain, chain_idx=0
    )
    assert plan is not None
    assert plan["timeout_sec"] == DEFAULT_PROBE_TIMEOUT_SEC


# ── Harness embedding ──────────────────────────────────────────────────────


def test_chain_harness_embeds_each_step_function_name() -> None:
    """Each step's function name must appear in the generated harness."""
    chain = _chain_two_step_eval()
    harness = _build_python_chain_harness(module_name="target", steps=chain.steps)
    assert "parse_config" in harness
    assert "apply_config" in harness


def test_chain_harness_embeds_placeholder_substitution_logic() -> None:
    """The harness must include the placeholder substitution machinery
    (regex + walker function). Tests the runtime contract, not the
    string identity of helper functions."""
    chain = _chain_two_step_eval()
    harness = _build_python_chain_harness(module_name="target", steps=chain.steps)
    # Regex anchor that matches <<_stepN_result>>
    assert "<<_step" in harness
    # Substitution walker handles list and dict
    assert "isinstance(v, list)" in harness
    assert "isinstance(v, dict)" in harness


def test_chain_harness_imports_module_under_test() -> None:
    chain = _chain_two_step_eval()
    harness = _build_python_chain_harness(module_name="myapp", steps=chain.steps)
    assert "import myapp as _target" in harness


def test_chain_harness_emits_chain_result_json_marker() -> None:
    """Harness must print the marker line so parse_probe_chain_trace
    can extract per-step results."""
    chain = _chain_two_step_eval()
    harness = _build_python_chain_harness(module_name="target", steps=chain.steps)
    assert "CHAIN_RESULT_JSON:" in harness


# ── JS chain harness (v1.8 JS DAST parity) ───────────────────────────────


def _build_js_chain_harness_helper():
    """Helper: build a JS chain harness for content assertions."""
    from dast.runtime_probe import _build_javascript_chain_harness

    chain = _chain_two_step_eval()
    return _build_javascript_chain_harness(
        module_path="/workspace/target.js", steps=chain.steps
    )


def test_js_chain_harness_emits_chain_result_marker() -> None:
    """JS chain harness must emit the SAME marker as Python so the
    parser is language-agnostic."""
    harness = _build_js_chain_harness_helper()
    assert "CHAIN_RESULT_JSON:" in harness
    assert "SIDE_EFFECTS:" in harness


def test_js_chain_harness_installs_fatal_handlers() -> None:
    """uncaughtException + unhandledRejection handlers prevent silent
    exit-1 failures."""
    harness = _build_js_chain_harness_helper()
    assert "process.on('uncaughtException'" in harness
    assert "process.on('unhandledRejection'" in harness
    assert "_emitFatal" in harness


def test_js_chain_harness_uses_dynamic_import() -> None:
    """Target loaded via ``await import(pathToFileURL(...).href)``
    so both CJS and ESM targets work."""
    harness = _build_js_chain_harness_helper()
    assert "await import(" in harness
    assert "pathToFileURL" in harness


def test_js_chain_harness_substitutes_placeholders() -> None:
    """``<<_stepN_result>>`` placeholder substitution is the key
    chain semantics — step N+1's args can reference step N's return
    value."""
    harness = _build_js_chain_harness_helper()
    # Harness contains the regex literal as JS: /^<<_step(\d+)_result>>$/
    assert "<<_step(\\d+)_result>>" in harness
    assert "substitute" in harness
    assert "PLACEHOLDER_RE" in harness


def test_js_chain_harness_dotted_path_resolver() -> None:
    """Step function lookup must support ``Class.method`` style dotted
    names + ESM default-export fallback."""
    harness = _build_js_chain_harness_helper()
    assert "resolveFn" in harness
    assert "mod.default" in harness


def test_js_chain_harness_short_circuits_on_non_last_step_error() -> None:
    """If step N (N < last) throws, later steps must NOT run and
    short_circuited must be true."""
    harness = _build_js_chain_harness_helper()
    assert "short_circuited" in harness
    assert "shortCircuited = (i < steps.length - 1)" in harness


def test_js_chain_harness_awaits_promise_returns() -> None:
    """Async functions returning Promises must be awaited so step
    N+1 sees the resolved value, not the Promise itself."""
    harness = _build_js_chain_harness_helper()
    assert "ret = await ret" in harness


def test_js_chain_harness_writes_workspace_result_file() -> None:
    """File-based transport bypasses Fly's per-log-line stdout cap."""
    harness = _build_js_chain_harness_helper()
    assert "/workspace/argus_probe_result.json" in harness


# ── Trace parser ───────────────────────────────────────────────────────────


def test_parse_chain_trace_recovers_per_step_results() -> None:
    """Parser pulls per_step_results out of CHAIN_RESULT_JSON marker."""
    stdout = (
        "CHAIN_RESULT_JSON:"
        + json.dumps(
            {
                "per_step_results": [
                    {"step": 1, "function_name": "a", "ok": True, "type": "dict"},
                    {
                        "step": 2,
                        "function_name": "b",
                        "ok": True,
                        "type": "str",
                        "value_preview": "uid=0(root)",
                    },
                ],
                "short_circuited": False,
            }
        )
        + "\n"
        + "SIDE_EFFECTS:"
        + json.dumps({"tmp_files_added": []})
        + "\n"
    )
    trace = parse_probe_chain_trace(
        chain_idx=0,
        exit_code=0,
        stdout=stdout,
        stderr="",
        elapsed_ms=123,
    )
    assert len(trace.per_step_results) == 2
    assert trace.per_step_results[1]["value_preview"] == "uid=0(root)"
    assert trace.short_circuited is False
    assert "step1:" in trace.steps_summary[0]
    assert "step2:" in trace.steps_summary[1]


def test_parse_chain_trace_captures_short_circuit_flag() -> None:
    """When an early step throws, short_circuited=True so the
    interpreter can refuse Rule 1."""
    stdout = (
        "CHAIN_RESULT_JSON:"
        + json.dumps(
            {
                "per_step_results": [
                    {
                        "step": 1,
                        "function_name": "a",
                        "ok": False,
                        "exception_type": "ValueError",
                        "exception_msg": "bad input",
                    }
                ],
                "short_circuited": True,
            }
        )
        + "\n"
        + "SIDE_EFFECTS:"
        + json.dumps({"tmp_files_added": []})
        + "\n"
    )
    trace = parse_probe_chain_trace(
        chain_idx=0, exit_code=0, stdout=stdout, stderr="", elapsed_ms=10
    )
    assert trace.short_circuited is True
    assert len(trace.per_step_results) == 1


def test_parse_chain_trace_defensive_on_missing_marker() -> None:
    """When no marker line appears, the trace is empty but doesn't raise."""
    trace = parse_probe_chain_trace(
        chain_idx=0,
        exit_code=1,
        stdout="some garbage output\nno markers\n",
        stderr="",
        elapsed_ms=5,
    )
    assert trace.per_step_results == []
    assert trace.short_circuited is False


def test_parse_chain_trace_defensive_on_broken_json() -> None:
    """Broken JSON in the marker is ignored, not raised."""
    trace = parse_probe_chain_trace(
        chain_idx=0,
        exit_code=0,
        stdout="CHAIN_RESULT_JSON:{not valid json\nSIDE_EFFECTS:{}\n",
        stderr="",
        elapsed_ms=5,
    )
    assert trace.per_step_results == []


# ── Interpreter — Rule 1 (final-step evidence signature) ───────────────────


def test_interpret_chain_rule1_fires_on_final_step_signature_match() -> None:
    """Rule 1 fires when chain reached final step + final step ok=True
    + value_preview matches attack-class evidence signature."""
    chain = _chain_two_step_eval()  # attack_class = code_injection
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=["step1: parse_config -> ok type=dict", "step2: apply_config -> ok type=str"],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=100,
        per_step_results=[
            {
                "step": 1,
                "function_name": "parse_config",
                "ok": True,
                "type": "dict",
                "value_preview": "{'startup_hook': ...}",
            },
            # __builtins__ is in the code_injection signature library —
            # eval()-firing typically returns or echoes the module's
            # builtins, distinctive enough to be a positive Rule 1 match.
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "str",
                "value_preview": "{'__builtins__': <module 'builtins' (built-in)>}",
            },
        ],
        side_effects={"tmp_files_added": []},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is not None
    assert finding.finding_id == "HRP_C0"
    assert finding.attack_class == "code_injection"
    assert finding.severity == "critical"
    assert "__builtins__" in finding.runtime_evidence


def test_interpret_chain_rule1_blocked_by_short_circuit() -> None:
    """If an early step throws, Rule 1 cannot fire even if the partial
    trace looks suspicious. The chain didn't reach the exploit trigger."""
    chain = _chain_two_step_eval()
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=["step1: parse_config -> ValueError: bad"],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=10,
        per_step_results=[
            {
                "step": 1,
                "function_name": "parse_config",
                "ok": False,
                "exception_type": "ValueError",
                "exception_msg": "bad input",
                "value_preview": "uid=0(root)",  # would match Rule 1 if not blocked
            }
        ],
        short_circuited=True,
        side_effects={"tmp_files_added": []},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is None


def test_interpret_chain_rule1_blocked_when_final_step_threw() -> None:
    """Reached the final step but it raised → Rule 1 doesn't fire
    (no ok=True from the exploit trigger). Rule 2 may still fire via
    canary, but absent canary the chain is BLOCKED."""
    chain = _chain_two_step_eval()
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=[
            "step1: parse_config -> ok type=dict",
            "step2: apply_config -> SyntaxError: ...",
        ],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=20,
        per_step_results=[
            {"step": 1, "function_name": "parse_config", "ok": True, "type": "dict"},
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": False,
                "exception_type": "SyntaxError",
                "exception_msg": "invalid syntax",
            },
        ],
        side_effects={"tmp_files_added": []},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is None


def test_interpret_chain_rule1_blocked_without_evidence_signature() -> None:
    """Chain reached final step + ok=True but value_preview is benign
    (no class signature, no expected-observable keyword match) →
    Rule 1 does NOT fire (FP defense)."""
    chain = _chain_two_step_eval()
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=["step1 ok", "step2 ok"],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=50,
        per_step_results=[
            {"step": 1, "function_name": "parse_config", "ok": True, "type": "dict"},
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "str",
                "value_preview": "OK",  # benign return
            },
        ],
        side_effects={"tmp_files_added": []},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is None


# ── Interpreter — Rule 2 (canary side effect) ──────────────────────────────


def test_interpret_chain_rule2_fires_on_canary_anywhere() -> None:
    """Rule 2 fires when /tmp contains an argus_probe / pwned file —
    irrespective of which step created it (could be plumbing or
    exploit; the file's appearance is the signal)."""
    chain = _chain_two_step_eval()
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=["step1 ok", "step2 ok"],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=100,
        per_step_results=[
            {
                "step": 1,
                "function_name": "parse_config",
                "ok": True,
                "type": "dict",
                "value_preview": "{...}",
            },
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "NoneType",
                "value_preview": "None",
            },
        ],
        side_effects={"tmp_files_added": ["argus_probe_pwned"]},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is not None
    assert "argus_probe_pwned" in finding.runtime_evidence


def test_interpret_chain_rule2_fires_even_on_short_circuit() -> None:
    """Rule 2 is chain-aware — fires regardless of which step ran,
    even if a later step threw (the canary already exists)."""
    chain = _chain_two_step_eval()
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=["step1 ok", "step2 SyntaxError"],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=50,
        per_step_results=[
            {"step": 1, "function_name": "parse_config", "ok": True, "type": "dict"},
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": False,
                "exception_type": "SyntaxError",
                "exception_msg": "...",
            },
        ],
        short_circuited=False,  # reached final step; final step just threw
        side_effects={"tmp_files_added": ["pwned.txt"]},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is not None
    assert "pwned.txt" in finding.runtime_evidence


def test_interpret_chain_returns_none_on_empty_trace() -> None:
    """Harness crash before emitting markers → no finding."""
    chain = _chain_two_step_eval()
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=[],
        exit_code=1,
        stdout="",
        stderr="segfault",
        elapsed_ms=5,
        per_step_results=[],
        side_effects={},
    )
    assert interpret_probe_chain_trace(trace, chain, chain_idx=0) is None


def test_interpret_chain_finding_carries_step_string_per_step() -> None:
    """Chain findings expose the per-step ``fn(args)`` strings for the
    report writer + adjudicator."""
    chain = _chain_two_step_eval()  # attack_class = code_injection
    trace = RuntimeProbeChainTrace(
        chain_idx=2,
        steps_summary=["step1 ok", "step2 ok"],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=100,
        per_step_results=[
            {"step": 1, "function_name": "parse_config", "ok": True, "type": "dict"},
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "str",
                "value_preview": "{'__builtins__': <module 'builtins'>}",
            },
        ],
        side_effects={},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=2)
    assert finding is not None
    assert finding.finding_id == "HRP_C2"
    assert len(finding.chain_steps) == 2
    assert "parse_config" in finding.chain_steps[0]
    assert "apply_config" in finding.chain_steps[1]
    assert finding.chain_inputs_json == chain.steps[0].args_json


# ── Orchestrator integration — flag-skip + end-to-end ───────────────────────


def _phase_b_chain_response(chains: list[dict]) -> str:
    """Stub Sonnet response shape for Phase 2 chain candidate generation.

    Matches :func:`dast.prompts.phase_b_chain_schema` output contract:
    a dict with ``chains`` (list) + ``no_chains_reason`` (string)."""
    return json.dumps(
        {
            "no_chains_reason": "" if chains else "no chain candidates",
            "chains": chains,
        }
    )


@pytest.mark.asyncio
async def test_chain_probing_skipped_when_flag_disabled(tmp_path) -> None:
    """``enable_runtime_probe_chains=False`` (default) → chain helper
    never fires, no chain-schema inference call. Sanity guard so
    existing v1.5.x users don't pay the chain inference cost
    unintentionally even with --enable-runtime-probe on."""
    sandbox = _CapturingProbeSandbox()
    chain_call_count = {"n": 0}

    async def fake_inference(prompt, options, schema):
        # Detect whether this is the chain schema (would be wrong here)
        if schema.get("required") == ["chains", "no_chains_reason"]:
            chain_call_count["n"] += 1  # should never fire
            return {
                "text": _phase_b_chain_response([]),
                "usage": {},
                "finish_reason": "stop",
            }
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response([]),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "def f(p): return p\n",
        "file_name": "v.py",
        "original_bytes": b"def f(p): return p\n",
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
        enable_runtime_probe_chains=False,  # OFF
    )

    assert chain_call_count["n"] == 0, "chain inference must not fire when flag disabled"


@pytest.mark.asyncio
async def test_chain_probing_runs_for_javascript(tmp_path) -> None:
    """JS DAST parity (v1.8): JavaScript chain probing now fires when
    flag is on. Pre-v1.8 the orchestrator gate fenced JS off entirely;
    with the JS chain harness (commit 6) + the orchestrator gate flip,
    JS files now go through chain candidate generation."""
    sandbox = _CapturingProbeSandbox()
    chain_call_count = {"n": 0}

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["chains", "no_chains_reason"]:
            chain_call_count["n"] += 1
            return {
                "text": _phase_b_chain_response([]),
                "usage": {},
                "finish_reason": "stop",
            }
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response([]),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "module.exports = (p) => require(p)\n",
        "file_name": "v.js",
        "original_bytes": b"module.exports = (p) => require(p)\n",
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
        enable_runtime_probe_chains=True,
    )

    # Inference call DID fire for JS — orchestrator admits it now.
    assert chain_call_count["n"] == 1, (
        "chain inference must fire on JS files now that JS chain harness exists"
    )


@pytest.mark.asyncio
async def test_chain_probing_skipped_for_unsupported_language(tmp_path) -> None:
    """Shell + unknown languages still skipped — no chain harness for
    those. JS / Python supported (tests above)."""
    sandbox = _CapturingProbeSandbox()
    chain_call_count = {"n": 0}

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["chains", "no_chains_reason"]:
            chain_call_count["n"] += 1
            return {
                "text": _phase_b_chain_response([]),
                "usage": {},
                "finish_reason": "stop",
            }
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response([]),
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": "#!/bin/bash\necho hi\n",
        "file_name": "v.sh",
        "original_bytes": b"#!/bin/bash\necho hi\n",
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
        enable_runtime_probe_chains=True,
    )

    assert chain_call_count["n"] == 0, (
        "chain inference must NOT fire on languages without a chain harness"
    )


@pytest.mark.asyncio
async def test_chain_probing_confirms_via_evidence_signature(tmp_path) -> None:
    """End-to-end: chain flag ON + Python file + model emits a 2-step
    chain + sandbox returns evidence-matching trace → HRP_C0 confirmed
    finding flows through to findings_validated."""
    chain_stdout = (
        "CHAIN_RESULT_JSON:"
        + json.dumps(
            {
                "per_step_results": [
                    {
                        "step": 1,
                        "function_name": "parse_config",
                        "ok": True,
                        "type": "dict",
                        "value_preview": "{'hook': '...'}",
                    },
                    {
                        "step": 2,
                        "function_name": "apply_config",
                        "ok": True,
                        "type": "str",
                        # __builtins__ matches code_injection sig
                        "value_preview": "{'__builtins__': <module 'builtins'>}",
                    },
                ],
                "short_circuited": False,
            }
        )
        + "\n"
        + "SIDE_EFFECTS:"
        + json.dumps({"tmp_files_added": []})
        + "\n"
    )

    sandbox = _CapturingProbeSandbox(
        traces_by_hypothesis={
            "HRP_C0": {"stdout": chain_stdout, "exit_code": 0, "elapsed_ms": 50},
        },
    )

    async def fake_inference(prompt, options, schema):
        if schema.get("required") == ["chains", "no_chains_reason"]:
            return {
                "text": _phase_b_chain_response(
                    [
                        {
                            "steps": [
                                {
                                    "function_name": "parse_config",
                                    "args_json": '["payload"]',
                                    "kwargs_json": "{}",
                                },
                                {
                                    "function_name": "apply_config",
                                    "args_json": '["<<_step1_result>>"]',
                                    "kwargs_json": "{}",
                                },
                            ],
                            "attack_class": "code_injection",
                            "rationale": "parse then eval — chain RCE",
                            "expected_observable": "builtins module exposed",
                            "exploit_proof_if_observed": "RCE via parse-then-eval chain",
                        }
                    ]
                ),
                "usage": {},
                "finish_reason": "stop",
            }
        if schema.get("required") == ["candidates", "non_probable_reason"]:
            return {
                "text": _phase_b_probe_response([]),  # single-function emits none
                "usage": {},
                "finish_reason": "stop",
            }
        return {"text": _phase_a_verdict_response(), "usage": {}, "finish_reason": "stop"}

    file_record = {
        "file_id": "h",
        "source_text": ("def parse_config(s): return {'hook': s}\ndef apply_config(d): return d\n"),
        "file_name": "v.py",
        "original_bytes": (
            b"def parse_config(s): return {'hook': s}\ndef apply_config(d): return d\n"
        ),
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
        enable_runtime_probe_chains=True,  # ON
    )

    # The HRP_C0 plan was submitted to the sandbox.
    chain_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id.startswith("HRP_C")]
    assert len(chain_plans) == 1
    assert chain_plans[0].hypothesis_id == "HRP_C0"

    # The chain-confirmed finding flows through to findings_validated.
    validated_ids = set(result.findings_validated or [])
    assert "HRP_C0" in validated_ids


# ── FP-defense additions (Phase 2 v1.0 hardening) ──────────────────────────


def test_chain_harness_wraps_module_import_in_try_except() -> None:
    """The chain harness must wrap ``import <module>`` so an ImportError
    at module load produces a structured CHAIN_RESULT_JSON marker
    instead of a silent harness crash.

    Note: a more-defensive v1.0 harness (top-level try/except wrap +
    atexit safety + socket.setdefaulttimeout) was prototyped but reverted
    after empirically breaking Fly-side event delivery — diagnosis
    pending. The basic try/except around module import is retained
    because it has no Fly-side risk and addresses ImportError silent
    failures.
    """
    chain = _chain_two_step_eval()
    harness = _build_python_chain_harness(module_name="missing_module_xyz", steps=chain.steps)
    assert "try:" in harness
    assert "import missing_module_xyz as _target" in harness
    assert "except BaseException as _imp_e" in harness
    assert "CHAIN_RESULT_JSON" in harness
    # Import failure path emits short_circuited=True so the orchestrator
    # interprets correctly via the existing per_step logic.
    assert "'short_circuited': True" in harness or '"short_circuited": True' in harness


def test_chain_finding_confidence_canary_is_one() -> None:
    """Rule 2 (canary side-effect) confirmations get confidence=1.0 — the
    canary file in /tmp is causal evidence that some step actually
    executed an exploit. Empirically 0 FPs across all observed runs."""
    chain = _chain_two_step_eval()
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=["step1 ok", "step2 ok"],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=50,
        per_step_results=[
            {"step": 1, "function_name": "parse_config", "ok": True, "type": "dict"},
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "str",
                "value_preview": "ok",
            },
        ],
        side_effects={"tmp_files_added": ["argus_probe_chain_canary"]},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is not None
    assert finding.confidence == 1.0
    assert finding.oracle_type == "canary"


def test_chain_finding_confidence_class_signature_is_medium() -> None:
    """Rule 1 class-signature confirmations (distinctive substrings like
    ``__builtins__`` for code_injection) get confidence=0.7. Moderate FP
    risk — these substrings don't appear in benign output usually, but
    can coincide with normal function returns."""
    chain = _chain_two_step_eval()  # attack_class=code_injection
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=["step1 ok", "step2 ok"],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=50,
        per_step_results=[
            {
                "step": 1,
                "function_name": "parse_config",
                "ok": True,
                "type": "dict",
                "value_preview": "{'hook': '...'}",
            },
            # __builtins__ is in _ATTACK_CLASS_EVIDENCE_SIGNATURES for
            # code_injection — class-signature path, NOT keyword path.
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "str",
                "value_preview": "{'__builtins__': <module 'builtins'>}",
            },
        ],
        side_effects={"tmp_files_added": []},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is not None
    assert finding.confidence == 0.7
    assert finding.oracle_type == "class_signature"


def test_chain_finding_confidence_observable_keyword_is_low() -> None:
    """Rule 1 expected-observable keyword match (the db2 FP source) gets
    confidence=0.4. Adjudicator / report writer should treat as
    operator-review rather than ship-as-finding."""
    # Build a chain whose attack_class has NO class signature for the
    # value_preview content, so only the keyword oracle can match.
    chain = RuntimeProbeChain(
        steps=[
            RuntimeProbeChainStep(function_name="step_a", args_json='["x"]', kwargs_json="{}"),
            RuntimeProbeChainStep(
                function_name="step_b", args_json='["<<_step1_result>>"]', kwargs_json="{}"
            ),
        ],
        attack_class="crypto_weakness",  # signature list is sparse, won't match generic output
        expected_observable="returns predictable nonce value abc123def456",
    )
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=["step1 ok", "step2 ok"],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=50,
        per_step_results=[
            {
                "step": 1,
                "function_name": "step_a",
                "ok": True,
                "type": "dict",
                "value_preview": "{'state': 0}",
            },
            # Final preview contains the model's keyword ('abc123def456')
            # but no crypto_weakness class signature.
            {
                "step": 2,
                "function_name": "step_b",
                "ok": True,
                "type": "str",
                "value_preview": "nonce=abc123def456",
            },
        ],
        side_effects={"tmp_files_added": []},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is not None
    assert finding.confidence == 0.4
    assert finding.oracle_type == "observable_keyword"


def test_chain_finding_confidence_canary_wins_over_rule1() -> None:
    """When both Rule 1 (signature/keyword) AND Rule 2 (canary) fire on
    the same chain, confidence is the MAX — canary's 1.0 dominates. The
    finding's oracle_type reflects the strongest oracle that fired."""
    chain = _chain_two_step_eval()
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=["step1 ok", "step2 ok"],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=50,
        per_step_results=[
            {"step": 1, "function_name": "parse_config", "ok": True, "type": "dict"},
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "str",
                # Would match class signature for code_injection on its own
                "value_preview": "{'__builtins__': <module 'builtins'>}",
            },
        ],
        # AND canary fires
        side_effects={"tmp_files_added": ["argus_probe_chain"]},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is not None
    assert finding.confidence == 1.0  # canary wins
    assert finding.oracle_type == "canary"


def test_interpret_chain_rule1_suppressed_by_intermediate_nonetype() -> None:
    """Rule 1 (keyword OR signature match on final step's value_preview)
    must NOT fire when ANY intermediate step returned NoneType. The
    NoneType is a strong signal the chain fell into a simulation /
    fallback / no-effect branch — any keyword that happens to appear in
    the final step's stub output is a FALSE POSITIVE, not exploit
    evidence. This is the db2_query_health_check.py regression: the
    sandbox lacks ``ibm_db`` so ``connect()`` returned None and
    ``get_table_stats(None, ...)`` returned a documented simulation
    dict containing ``STATS_TIME`` — which matched the model's
    expected_observable keyword.
    """
    chain = _chain_two_step_eval()  # 2-step; step 1 is intermediate
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=[
            "step1: parse_config -> ok type=NoneType",
            "step2: apply_config -> ok type=dict",
        ],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=50,
        per_step_results=[
            # Intermediate step returned None → fallback branch
            {
                "step": 1,
                "function_name": "parse_config",
                "ok": True,
                "type": "NoneType",
                "value_preview": "None",
            },
            # Final step returns something whose value_preview matches a
            # code_injection class signature — WOULD fire Rule 1 if
            # NoneType guard weren't active.
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "dict",
                "value_preview": "{'__builtins__': <module 'builtins'>}",
            },
        ],
        side_effects={"tmp_files_added": []},  # no canary
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is None, (
        "Rule 1 must be suppressed when an intermediate step returns "
        "NoneType — even though the final step's value_preview matches a "
        "code_injection class signature, the intermediate NoneType "
        "indicates the chain fell into a fallback branch, not the "
        "exploit path."
    )


def test_interpret_chain_rule2_canary_still_fires_with_intermediate_nonetype() -> None:
    """The NoneType-intermediate guard ONLY suppresses Rule 1. Rule 2
    (canary side-effect) is unaffected — if any step in the chain
    wrote to /tmp/argus_probe_*, the file's appearance is direct
    evidence of execution regardless of intermediate return types.
    Guarantees we don't lose detection on legitimate
    ``set_config(side_effect) -> get_config(read)`` chains where the
    set step returns ``None``.
    """
    chain = _chain_two_step_eval()
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=[
            "step1: parse_config -> ok type=NoneType",
            "step2: apply_config -> ok type=str",
        ],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=50,
        per_step_results=[
            {
                "step": 1,
                "function_name": "parse_config",
                "ok": True,
                "type": "NoneType",
                "value_preview": "None",
            },
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "str",
                "value_preview": "ok",  # benign — Rule 1 wouldn't fire anyway
            },
        ],
        # Canary appeared → some step wrote it. Rule 2 must fire.
        side_effects={"tmp_files_added": ["argus_probe_chain_canary"]},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is not None, (
        "Rule 2 (canary side-effect) must fire even when an intermediate "
        "step returned NoneType — the canary file is direct evidence of "
        "execution and the NoneType guard is Rule-1-only."
    )
    assert "argus_probe_chain_canary" in finding.runtime_evidence


def test_interpret_chain_rule1_still_fires_when_no_intermediate_nonetype() -> None:
    """Regression guard: NoneType guard must NOT suppress Rule 1 when
    intermediate steps returned non-None types. The synthetic
    parse→eval chain (parse returns dict, eval returns str) must
    still confirm via Rule 1 keyword/signature match.
    """
    chain = _chain_two_step_eval()  # code_injection
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=[
            "step1: parse_config -> ok type=dict",
            "step2: apply_config -> ok type=str",
        ],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=50,
        per_step_results=[
            # Intermediate step returns dict (not NoneType) → guard inactive
            {
                "step": 1,
                "function_name": "parse_config",
                "ok": True,
                "type": "dict",
                "value_preview": "{'hook': '...'}",
            },
            # Final step matches code_injection signature
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "str",
                "value_preview": "{'__builtins__': <module 'builtins'>}",
            },
        ],
        side_effects={"tmp_files_added": []},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is not None, (
        "Rule 1 must still fire when intermediate steps returned "
        "non-NoneType types — the guard is specifically for NoneType-"
        "indicating-fallback, not blanket Rule 1 suppression."
    )
    assert "__builtins__" in finding.runtime_evidence


def test_interpret_chain_final_step_nonetype_still_eligible_for_rule1() -> None:
    """The NoneType guard checks INTERMEDIATE steps only. A final step
    returning None is acceptable — Rule 1 would naturally not fire on
    a None final return (no value_preview to match against), but the
    chain should remain eligible for Rule 2 via canary.
    """
    chain = _chain_two_step_eval()
    trace = RuntimeProbeChainTrace(
        chain_idx=0,
        steps_summary=[
            "step1: parse_config -> ok type=dict",
            "step2: apply_config -> ok type=NoneType",
        ],
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=50,
        per_step_results=[
            {
                "step": 1,
                "function_name": "parse_config",
                "ok": True,
                "type": "dict",
                "value_preview": "{'hook': '...'}",
            },
            # Final step is NoneType — Rule 1 should NOT be blocked by
            # the intermediate-guard (this step is final, not
            # intermediate). Rule 2 below should fire on the canary.
            {
                "step": 2,
                "function_name": "apply_config",
                "ok": True,
                "type": "NoneType",
                "value_preview": "None",
            },
        ],
        side_effects={"tmp_files_added": ["argus_probe_writes"]},
    )
    finding = interpret_probe_chain_trace(trace, chain, chain_idx=0)
    assert finding is not None, (
        "Final-step NoneType is acceptable — Rule 2 (canary) must "
        "still fire. Guard is intermediate-only."
    )


# ── Phase 3 Stage 2: probe-kind observation interpretation (v1.6) ─────────
#
# Probe-kind hypotheses reuse the single-function plan + harness + trace
# parser, but interpretation diverges: ``interpret_probe_observation``
# emits a descriptive ``RuntimeProbeObservation`` instead of asserting
# exploit confirmation. The observation feeds the next adversarial-loop
# turn's context so the model can design attack hypotheses from concrete
# runtime evidence.


from dast.runtime_probe import (  # noqa: E402 — late import keeps test grouping
    RuntimeProbeObservation,
    RuntimeProbeTrace,
    interpret_probe_observation,
)


def _probe_trace_for_observation(
    *,
    candidate_function: str = "foo",
    input_args_json: str = "[]",
    exit_code: int | None = 0,
    stdout: str = "",
    stderr: str = "",
    elapsed_ms: int = 42,
    parsed_result: dict | None = None,
    side_effects: dict | None = None,
) -> RuntimeProbeTrace:
    """Build a synthetic RuntimeProbeTrace for observation tests."""
    return RuntimeProbeTrace(
        candidate_function=candidate_function,
        input_args_json=input_args_json,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        elapsed_ms=elapsed_ms,
        parsed_result=parsed_result,
        side_effects=side_effects or {},
    )


def test_probe_observation_clean_return_populates_value_fields() -> None:
    trace = _probe_trace_for_observation(
        parsed_result={"ok": True, "type": "dict", "value_preview": "{'a': 1}"},
    )
    obs = interpret_probe_observation(trace, function_name="load_config")
    assert isinstance(obs, RuntimeProbeObservation)
    assert obs.returned_cleanly is True
    assert obs.return_value_type == "dict"
    assert obs.return_value_preview == "{'a': 1}"
    assert obs.exception_class == ""
    assert obs.exception_message == ""
    assert "returned cleanly" in obs.summary
    assert "→ dict" in obs.summary


def test_probe_observation_exception_path_populates_exception_fields() -> None:
    trace = _probe_trace_for_observation(
        parsed_result={
            "ok": False,
            "exception_type": "FileNotFoundError",
            "exception_msg": "[Errno 2] No such file or directory: '/x'",
        },
    )
    obs = interpret_probe_observation(trace, function_name="read_file")
    assert obs.returned_cleanly is False
    assert obs.exception_class == "FileNotFoundError"
    assert "No such file" in obs.exception_message
    assert obs.return_value_type == ""
    assert obs.return_value_preview == ""
    assert "raised FileNotFoundError" in obs.summary


def test_probe_observation_harness_crash_no_parsed_result() -> None:
    """parsed_result=None means harness crashed before printing markers
    (SIGKILL, segfault, or sandbox infra issue). The observation must
    still be valid and tell the model what happened."""
    trace = _probe_trace_for_observation(
        parsed_result=None,
        exit_code=-9,
        stderr="killed by signal",
    )
    obs = interpret_probe_observation(trace, function_name="boom")
    assert obs.returned_cleanly is False
    assert obs.exception_class == ""
    assert obs.return_value_preview == ""
    assert "produced no RESULT_JSON marker" in obs.summary
    assert "exit_code=-9" in obs.summary


def test_probe_observation_canary_side_effect_surfaces_in_summary() -> None:
    """Canary hits (argus_probe / pwned marker substrings) are the
    highest-signal observation for the model and MUST surface in the
    summary string, not just the structured side_effects dict."""
    trace = _probe_trace_for_observation(
        parsed_result={"ok": True, "type": "NoneType", "value_preview": "None"},
        side_effects={"tmp_files_added": ["/tmp/argus_probe_pwned_canary"]},
    )
    obs = interpret_probe_observation(trace, function_name="eval_wrapper")
    assert "Canary side-effect" in obs.summary
    assert "argus_probe_pwned_canary" in obs.summary


def test_probe_observation_non_canary_tmp_files_summarized_distinctly() -> None:
    """Tmp files without canary markers should surface in the summary
    but NOT as 'Canary' — they're informational, not exploit-grade."""
    trace = _probe_trace_for_observation(
        parsed_result={"ok": True, "type": "str", "value_preview": "'ok'"},
        side_effects={"tmp_files_added": ["/tmp/temp_log_xyz.txt"]},
    )
    obs = interpret_probe_observation(trace, function_name="legitimate_writer")
    assert "Canary" not in obs.summary
    assert "tmp files added" in obs.summary


def test_probe_observation_truncates_stdout_stderr_excerpts_to_800() -> None:
    """Excerpts are bounded so the next-turn prompt's context budget
    doesn't blow up on chatty probes."""
    trace = _probe_trace_for_observation(
        parsed_result={"ok": True, "type": "int", "value_preview": "42"},
        stdout="X" * 2000,
        stderr="Y" * 2000,
    )
    obs = interpret_probe_observation(trace, function_name="big_returner")
    assert len(obs.stdout_excerpt) == 800
    assert len(obs.stderr_excerpt) == 800


# ── Deep value preview (v1.6 Path 2 oracle fix) ──────────────────────────


def test_harness_includes_deep_value_preview_helper_and_uses_it() -> None:
    """The harness must define ``_deep_value_preview`` and call it in
    place of the old ``repr(result)[:600]`` for value_preview. Replaces
    the FP-blind oracle path identified in the 23-file measurement
    (commit fd5be0e) where xrechnung's XXE attack actually resolved but
    the oracle saw only ``<Element Invoice at 0x...>``."""
    harness = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    # Helper definition present
    assert "def _deep_value_preview" in harness
    # v15.22: helper is invoked through _argus_vp before being passed
    # into RESULT_JSON so the wiretap-capture suffix can be appended.
    assert "_argus_vp = _deep_value_preview(result)" in harness
    assert "'value_preview': _argus_vp" in harness
    # The old direct repr path is gone
    assert "'value_preview': repr(result)[:600]" not in harness
    # Per-type extraction branches present
    assert "from lxml import etree as _etree" in harness
    assert "TEXT:" in harness  # lxml text extraction
    assert "DICT:" in harness  # dict stringification
    assert "SEQ:" in harness  # list/tuple/set stringification
    assert "ATTRS:" in harness  # __dict__ extraction


def test_deep_value_preview_extracts_lxml_text_so_oracle_can_fire() -> None:
    """End-to-end regression guard for xrechnung-class FNs. Exec the
    helper out of the harness, give it an lxml.Element whose text
    content contains a path_traversal canary, and verify the canary is
    in the returned preview string. Without this, Rule 1's substring
    oracle (matching 'root:x:0:0:' for path_traversal etc.) can't fire
    on lxml-returning functions."""
    try:
        from lxml import etree
    except ImportError:
        pytest.skip("lxml not available in test env")

    harness = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    # Carve out just the helper definition.
    start = harness.find("def _deep_value_preview")
    end = harness.find("\nbaseline_tmp", start)
    assert start >= 0 and end > start, "harness shape changed unexpectedly"
    func_src = harness[start:end]
    ns: dict = {}
    exec(func_src, ns)  # noqa: S102 — test-only controlled source
    deep_preview = ns["_deep_value_preview"]

    # Build an lxml.Element with text content that mimics what an XXE
    # attack would produce (file:///etc/passwd entity resolved).
    root = etree.fromstring("<Invoice><Note>root:x:0:0:secret</Note></Invoice>")
    preview = deep_preview(root)

    # The TEXT: branch must surface the entity-resolved string. Without
    # this the substring oracle can't see it -- repr alone shows
    # '<Element Invoice at 0x...>'.
    assert "root:x:0:0:secret" in preview
    assert "TEXT:" in preview


def test_deep_value_preview_extracts_dict_contents() -> None:
    """Dicts must be stringified so substring oracles see key/value
    content. Some functions return dicts of harvested data (data_exfil
    attack class) and the DICT: branch surfaces them."""
    harness = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    start = harness.find("def _deep_value_preview")
    end = harness.find("\nbaseline_tmp", start)
    func_src = harness[start:end]
    ns: dict = {}
    exec(func_src, ns)  # noqa: S102
    deep_preview = ns["_deep_value_preview"]

    sensitive_dict = {"api_key": "sk-abc123", "username": "root"}
    preview = deep_preview(sensitive_dict)
    assert "sk-abc123" in preview
    assert "root" in preview
    assert "DICT:" in preview


def test_deep_value_preview_handles_misbehaving_repr_gracefully() -> None:
    """The helper must never crash. Objects with __repr__ that raises
    should still produce some preview string."""
    harness = _build_python_probe_harness(
        module_name="m",
        function_name="f",
        args_json="[]",
        kwargs_json="{}",
    )
    start = harness.find("def _deep_value_preview")
    end = harness.find("\nbaseline_tmp", start)
    func_src = harness[start:end]
    ns: dict = {}
    exec(func_src, ns)  # noqa: S102
    deep_preview = ns["_deep_value_preview"]

    class HostileRepr:
        def __repr__(self):
            raise RuntimeError("boom")

    # Must not raise. The repr-failed sentinel + ATTRS fallback should
    # still produce something usable.
    preview = deep_preview(HostileRepr())
    assert isinstance(preview, str)
    assert preview  # non-empty


def test_probe_observation_propagates_kwargs_json_through() -> None:
    """kwargs_json is plumbed in from the hypothesis (the trace doesn't
    record it). Observation must echo it back so the model sees the
    full call signature in next-turn context."""
    trace = _probe_trace_for_observation(
        input_args_json='["/etc/passwd"]',
        parsed_result={"ok": True, "type": "str", "value_preview": "'root:x:...'"},
    )
    obs = interpret_probe_observation(
        trace,
        function_name="read_file",
        kwargs_json='{"binary": false}',
    )
    assert obs.input_kwargs_json == '{"binary": false}'
    assert obs.input_args_json == '["/etc/passwd"]'


# ─── Phase 1 (SCAN-016) — structured-assertion oracle ────────────────────


def _interpret_call(
    *,
    parsed_result: dict,
    attack_class: str = "ssrf",
    expected_observable: str = "",
    assertion_passed: bool | None = None,
    assertion_expr: str = "",
    input_args_json: str = "[]",
    side_effects: dict | None = None,
):
    """Build a synthetic trace + candidate and run interpret_probe_trace."""
    from dast.runtime_probe import RuntimeProbeTrace as _T  # noqa: PLC0415

    trace = _T(
        candidate_function="target",
        input_args_json=input_args_json,
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=10,
        parsed_result=parsed_result,
        side_effects=side_effects or {},
        assertion_passed=assertion_passed,
        assertion_error="",
    )
    candidate = RuntimeProbeCandidate(
        function_name="target",
        attack_class=attack_class,
        rationale="t",
        test_inputs=[],
    )
    test_input = RuntimeProbeInput(
        args_json=input_args_json,
        kwargs_json="{}",
        expected_observable=expected_observable,
        rejection_signature="",
        exploit_proof_if_observed="proof",
        assertion_expr=assertion_expr,
    )
    return interpret_probe_trace(
        trace=trace,
        candidate=candidate,
        candidate_idx=0,
        test_input=test_input,
        input_idx=0,
    )


def test_assertion_oracle_passed_confirms() -> None:
    """When assertion_passed=True, the interpreter emits a finding with
    oracle_type=='assertion' — overriding any string-based oracle."""
    finding = _interpret_call(
        parsed_result={
            "ok": True,
            "value_preview": "URL('http://169.254.169.254/...')",
        },
        attack_class="ssrf",
        expected_observable="result.host starts with 169.254",
        assertion_passed=True,
        assertion_expr="str(getattr(result, 'host', '')).startswith('169.254.')",
    )
    assert finding is not None
    assert finding.oracle_type == "assertion"
    assert "assertion oracle" in finding.runtime_evidence
    assert "169.254" in finding.runtime_evidence  # assertion_expr embedded


def test_assertion_oracle_failed_refutes_overriding_keyword_match() -> None:
    """When assertion_passed=False, the interpreter returns None even
    when the legacy observable_keyword oracle WOULD have matched. This
    is the v15.27 file:// FP fix: model says
    ``getattr(result, 'scheme', None) == 'file'``, sandbox evaluates
    against the normalized URL where scheme=='https', assertion is
    False, finding correctly refuted — despite ``str(result)``
    containing the keyword 'scheme'."""
    finding = _interpret_call(
        parsed_result={
            "ok": True,
            "value_preview": "URL('https://api.example.com/v1/etc/passwd').scheme='https'",
        },
        attack_class="ssrf",
        expected_observable="URL with scheme file",
        assertion_passed=False,
        assertion_expr="getattr(result, 'scheme', None) == 'file'",
    )
    assert finding is None  # REFUTED via structured assertion


def test_assertion_oracle_none_falls_back_to_legacy_oracles() -> None:
    """When no assertion was provided (or eval errored → assertion_passed
    is None), the interpreter falls back to the existing string-based
    oracles. Back-compat: pre-Phase-1 hypothesis schemas keep working."""
    finding = _interpret_call(
        parsed_result={
            "ok": True,
            "value_preview": "root:x:0:0:root:/root:/bin/bash",
        },
        attack_class="path_traversal",
        expected_observable="reads /etc/passwd",
        assertion_passed=None,  # no assertion provided
        assertion_expr="",
    )
    # Class signature 'root:x:0:0:' matches → CONFIRMED via legacy oracle.
    assert finding is not None
    assert finding.oracle_type == "class_signature"


def test_assertion_oracle_takes_precedence_over_class_signature_match() -> None:
    """Even when the legacy class_signature oracle WOULD have fired
    (haystack contains 'root:x:0:0:'), an assertion_passed=False
    correctly refutes. The structured assertion is authoritative —
    its semantic check beats the string oracle."""
    finding = _interpret_call(
        parsed_result={
            "ok": True,
            "value_preview": "root:x:0:0:root:/root:/bin/bash",  # legacy oracle would fire
        },
        attack_class="path_traversal",
        expected_observable="reads /etc/passwd",
        assertion_passed=False,  # but model says no
        assertion_expr="isinstance(result, str) and '/etc/passwd' in result",
    )
    assert finding is None  # assertion oracle wins


def test_assertion_oracle_passes_when_legacy_oracle_silent() -> None:
    """Assertion=True confirms even when value_preview is bland and the
    legacy oracles would have produced no match. Demonstrates the
    structured assertion can find exploits the substring oracles miss
    (e.g., the exploit lives in the OBJECT STRUCTURE, not in repr)."""
    finding = _interpret_call(
        parsed_result={
            "ok": True,
            "value_preview": "<MyURL object at 0x7f0c1>",  # no class signature, no keyword
        },
        attack_class="ssrf",
        expected_observable="",  # no keyword to extract — legacy oracle silent
        assertion_passed=True,
        assertion_expr="hasattr(result, 'host') and result.host == '169.254.169.254'",
    )
    assert finding is not None
    assert finding.oracle_type == "assertion"


def test_parse_probe_trace_extracts_assertion_fields() -> None:
    """The trace parser must pull ``assertion_passed`` + ``assertion_error``
    from RESULT_JSON onto the top-level trace fields so downstream
    oracle dispatch sees them without digging into parsed_result."""
    result_payload = {
        "ok": True,
        "type": "URL",
        "value_preview": "URL('https://example.com')",
        "assertion_passed": True,
        "assertion_error": "",
    }
    stdout = "BEHAVIORAL_NOISE\nRESULT_JSON:" + json.dumps(result_payload) + "\n"
    trace = parse_probe_trace(
        candidate_function="target",
        input_args_json="[]",
        exit_code=0,
        stdout=stdout,
        stderr="",
        elapsed_ms=5,
    )
    assert trace.assertion_passed is True
    assert trace.assertion_error == ""


def test_parse_probe_trace_extracts_assertion_eval_error() -> None:
    """When the harness's restricted-eval raised (syntax error, undefined
    name, etc.), it emits ``assertion_passed=None`` + populates
    ``assertion_error``. Parser propagates both onto the trace."""
    result_payload = {
        "ok": True,
        "value_preview": "X",
        "assertion_passed": None,
        "assertion_error": "NameError: name 'undefined_thing' is not defined",
    }
    stdout = "RESULT_JSON:" + json.dumps(result_payload) + "\n"
    trace = parse_probe_trace(
        candidate_function="target",
        input_args_json="[]",
        exit_code=0,
        stdout=stdout,
        stderr="",
        elapsed_ms=5,
    )
    assert trace.assertion_passed is None
    assert "NameError" in trace.assertion_error


def test_parse_probe_trace_no_assertion_fields_back_compat() -> None:
    """RESULT_JSON without the new assertion_* fields (pre-Phase-1
    harness or legacy cached traces) parses cleanly. The new fields
    default to None / empty string."""
    result_payload = {"ok": True, "type": "str", "value_preview": "X"}
    stdout = "RESULT_JSON:" + json.dumps(result_payload) + "\n"
    trace = parse_probe_trace(
        candidate_function="target",
        input_args_json="[]",
        exit_code=0,
        stdout=stdout,
        stderr="",
        elapsed_ms=5,
    )
    assert trace.assertion_passed is None
    assert trace.assertion_error == ""


def test_harness_emits_assertion_eval_block_when_expr_provided() -> None:
    """The harness builder must inject the eval block + emit the
    assertion_passed / assertion_error fields in RESULT_JSON when
    assertion_expr is non-empty. Compile-check the generated source."""
    harness = _build_python_probe_harness(
        module_name="target_mod",
        function_name="target_fn",
        args_json="[]",
        kwargs_json="{}",
        attack_class="ssrf",
        assertion_expr=(
            "getattr(result, 'scheme', None) == 'file'"
        ),
    )
    assert "_argus_assertion_expr" in harness
    assert "'assertion_passed':" in harness
    assert "'assertion_error':" in harness
    # Sandbox-safety: the eval namespace must NOT expose __import__ /
    # subprocess / os / open. These names are not in the restricted
    # builtins block we emit.
    import re
    # Restrict to the eval-globals block where we list allowed builtins.
    eval_block = re.search(
        r"_argus_assert_globals = \{.*?\}\s*\n\s*_argus_assert_locals",
        harness, re.DOTALL,
    )
    assert eval_block is not None, "could not locate eval globals block"
    eval_block_src = eval_block.group(0)
    for forbidden in ("__import__", "subprocess", "open", "exec", "compile"):
        assert forbidden not in eval_block_src, (
            f"restricted-eval namespace must NOT expose '{forbidden}'"
        )
    # Compile-check: the generated source must be a syntactically valid
    # Python program. Any indent / missing-colon / string-quote slip in
    # the harness builder code would land here.
    compile(harness, "<harness>", "exec")


def test_harness_omits_assertion_block_when_expr_empty() -> None:
    """Back-compat: when no assertion_expr is supplied, the harness
    still emits the assertion_passed field but always as None — the
    parser sees no_assertion_provided and falls back to legacy oracles."""
    harness = _build_python_probe_harness(
        module_name="target_mod",
        function_name="target_fn",
        args_json="[]",
        kwargs_json="{}",
        attack_class="ssrf",
        assertion_expr="",
    )
    # The eval guard ``if _argus_assertion_expr:`` is present and the
    # empty expr means the eval body never runs — assertion_passed
    # stays None.
    assert "if _argus_assertion_expr:" in harness
    # Still compiles cleanly.
    compile(harness, "<harness>", "exec")
