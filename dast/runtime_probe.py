"""Runtime exploit probing — Phase B+ runtime-guided exploit discovery.

Phase B as it ships in v1.3.x asks Sonnet/Opus to brainstorm new
vulnerabilities by re-reading the file + Phase A's journal evidence.
That's still **model-driven static analysis with runtime context**, not
runtime discovery: the sandbox is used only to TEST hypotheses, never
to GENERATE them.

v1.5 adds Phase B+ runtime probing. The flow:

1. Sonnet identifies 1-3 candidate functions in the file that have
   attack-attractive signatures (take user-controlled input, call a
   sink, manipulate filesystem / network / process).
2. For each candidate, Sonnet generates 2-3 concrete attack inputs
   (e.g., for a ``read_file(path)`` function: ``"../etc/passwd"``,
   ``"/etc/shadow"``, ``"|cat /etc/passwd"``) — paired with an
   ``expected_observable`` describing what the sandbox would see if
   the exploit fires.
3. Argus builds a Python harness per (candidate × input), runs it in
   the microVM, captures stdout / stderr / exit_code / side-effect
   markers (new files in /tmp, environment leaks).
4. Sonnet interprets each trace: did the observed behavior match
   ``expected_observable``? If yes, it's a CONFIRMED finding via
   runtime evidence, NOT static analysis. The finding flows back into
   the journal as a new Phase A-ready hypothesis (and naturally
   reaches CONFIRMED status because the runtime evidence is already
   in the trace).

Scope (v1.5 MVP):

* Python only — the harness uses ``import target_module; target.fn(*args)``.
  JS/TS / shell probing comes in v1.5.1.
* Opt-in via ``ScanConfig.enable_runtime_probe = True``; off by default
  because (a) it adds ~$0.20-0.50/file in API cost on top of Phase A
  and (b) the FP rate on first-party code with legitimate filesystem /
  network behavior will be non-trivial early on.
* Single iter — runtime probe runs ONCE in iter 1 after Phase A. We do
  not iterate probe-discovery (multi-iter probing is a future feature
  once we have observability data on how this performs).
* Bounded — at most ``MAX_CANDIDATES`` × ``MAX_INPUTS_PER_CANDIDATE``
  sandbox runs per file. Hard cap on cost.

What this does NOT do:

* Coverage-guided fuzzing (no instrumentation, no AFL-style mutation).
* Symbolic execution (no path constraint solving).
* Native-binary probing (Python only).
* Multi-step exploit chains (one function per probe).

The right framing: **AI-driven adversarial pen-testing automation**,
scoped to be tractable + cheap. Model writes targeted attack inputs;
sandbox runs them; model interprets results.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Tunables ──────────────────────────────────────────────────────────────

#: Maximum number of probing candidates Sonnet is allowed to nominate
#: per file. Keeps cost bounded; if more functions look interesting, the
#: model picks the highest-yield ones.
MAX_CANDIDATES: int = 3

#: Maximum test inputs Sonnet generates per candidate. Each input = one
#: sandbox detonation.
MAX_INPUTS_PER_CANDIDATE: int = 3

#: Hard upper bound on total sandbox runs per file. With defaults this
#: is 3 × 3 = 9 sandbox runs ≈ ~5 min at 30s cold start each. In
#: practice the inference layer also caps via the probe schema itself.
MAX_PROBE_RUNS_PER_FILE: int = MAX_CANDIDATES * MAX_INPUTS_PER_CANDIDATE

#: Default per-probe timeout in the sandbox. 30s is enough for a Python
#: import + a single function call + side-effect snapshot, even on
#: filesystem-heavy probes.
DEFAULT_PROBE_TIMEOUT_SEC: int = 30


# ── Data types ────────────────────────────────────────────────────────────


@dataclass
class RuntimeProbeInput:
    """One attack-shaped input for a candidate function.

    The model emits these as part of the probe-candidate schema:
    positional args + keyword args + a description of what the sandbox
    should expect to observe if the exploit fires.
    """

    args_json: str
    """JSON-encoded list of positional args, e.g. ``'["../etc/passwd"]'``.
    Decoded inside the sandbox harness — keeps the wire format
    language-agnostic."""

    kwargs_json: str = "{}"
    """JSON-encoded dict of keyword args."""

    expected_observable: str = ""
    """Human-readable description of the runtime signal that proves
    the exploit fired. E.g., ``"reads /etc/passwd content into the
    return value"``, ``"writes file /tmp/pwned"``, ``"spawns subprocess
    that runs 'whoami'"``. The trace interpreter compares the observed
    runtime evidence against this."""

    exploit_proof_if_observed: str = ""
    """The vulnerability claim that lands as a finding IF the observed
    signal matches. E.g., ``"path traversal — reads files outside the
    intended directory via ../"``."""


@dataclass
class RuntimeProbeCandidate:
    """One function-under-test, identified by Sonnet via static analysis
    as a probing-attractive target."""

    function_name: str
    """Bare function / method name as it appears in the module's top-level
    namespace. Composite paths like ``MyClass.method`` are allowed; the
    harness uses ``getattr`` walks for them."""

    attack_class: str
    """Classification — ``path_traversal``, ``code_injection``,
    ``command_injection``, ``deserialization``, ``ssrf``,
    ``data_exfiltration``, etc. Drives the prompt that interprets
    traces and the CWE attached to any finding."""

    rationale: str = ""
    """Why the model picked this function — for journal traceability."""

    test_inputs: list[RuntimeProbeInput] = field(default_factory=list)


@dataclass
class RuntimeProbeTrace:
    """The result of running one probe (one candidate × one input)
    in the sandbox. Mirrors the SandboxTrace shape but typed for the
    probe interpretation layer."""

    candidate_function: str
    input_args_json: str
    exit_code: int | None
    stdout: str
    stderr: str
    elapsed_ms: int
    parsed_result: dict[str, Any] | None = None
    """If the harness emitted a ``RESULT_JSON:{...}`` marker line on
    stdout, this is the decoded dict. ``None`` when the harness
    crashed before printing the marker (segfault, kill, etc.)."""

    side_effects: dict[str, Any] = field(default_factory=dict)
    """Decoded ``SIDE_EFFECTS:{...}`` marker — files added to /tmp,
    new processes spawned, network connections opened. Used by the
    interpreter to detect runtime exploit signals."""


@dataclass
class RuntimeProbeFinding:
    """A finding emitted when a probe's trace matches its expected
    observable. Flows back into the journal as a CONFIRMED hypothesis."""

    finding_id: str
    """``HRP_<candidate_idx>_<input_idx>`` — stable per-scan identifier."""

    candidate_function: str
    attack_class: str
    severity: str
    """``critical`` / ``high`` / ``medium`` — derived from attack_class
    via :data:`_ATTACK_CLASS_SEVERITY`."""

    cwe: str
    """CWE id derived from attack_class. ``CWE-22`` for path traversal,
    ``CWE-78`` for command injection, etc."""

    description: str
    """Plain-language summary of the exploit, derived from
    ``exploit_proof_if_observed`` + observed runtime evidence."""

    runtime_evidence: str
    """The specific bytes / lines from the sandbox trace that prove
    the exploit fired. Verbatim where possible — this is what makes
    the finding sandbox-grounded rather than model-speculated."""

    test_input_args: str
    """The exact JSON-encoded args that triggered the exploit. Pasted
    into ``proof_of_concept`` so a developer can reproduce."""


# ── Attack-class → CWE + severity mapping ────────────────────────────────


_ATTACK_CLASS_CWE: dict[str, str] = {
    "path_traversal": "CWE-22",
    "code_injection": "CWE-94",
    "command_injection": "CWE-78",
    "deserialization": "CWE-502",
    "data_exfiltration": "CWE-200",
    "ssrf": "CWE-918",
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "xxe": "CWE-611",
    "crypto_weakness": "CWE-327",
    "prompt_injection": "CWE-1389",  # provisional
    "open_redirect": "CWE-601",
    "race_condition": "CWE-362",
}

_ATTACK_CLASS_SEVERITY: dict[str, str] = {
    "path_traversal": "high",
    "code_injection": "critical",
    "command_injection": "critical",
    "deserialization": "critical",
    "data_exfiltration": "high",
    "ssrf": "high",
    "sql_injection": "critical",
    "xss": "medium",
    "xxe": "high",
    "crypto_weakness": "medium",
    "prompt_injection": "medium",
    "open_redirect": "medium",
    "race_condition": "medium",
}


def cwe_for_attack_class(attack_class: str) -> str:
    """Return the CWE id mapped to a probe's attack class.

    Falls back to ``CWE-1035`` ("Improper Input Validation") for
    unrecognized classes so finding emission never crashes on a
    model-generated unknown class string."""
    return _ATTACK_CLASS_CWE.get(attack_class, "CWE-1035")


def severity_for_attack_class(attack_class: str) -> str:
    """Return ``critical`` / ``high`` / ``medium`` / ``low`` for a probe's
    attack class. Falls back to ``medium`` for unknown classes."""
    return _ATTACK_CLASS_SEVERITY.get(attack_class, "medium")


# ── Python harness generation ─────────────────────────────────────────────


def _python_module_name_for_file(file_name: str) -> str:
    """Derive an import-safe module name from a wheel filename or path.

    ``vulnerable_lib.py`` → ``vulnerable_lib``
    ``mypkg/io_utils.py`` → ``io_utils`` (we strip parent dirs and rely
    on the sandbox staging the file at ``/workspace/<basename>``).

    We deliberately use the BASENAME so the harness import path is
    deterministic. The sandbox guarantees the file lives at
    ``/workspace/<basename>`` (see ``SandboxPlan.file_name``)."""
    base = Path(file_name).name
    if base.endswith(".py"):
        base = base[: -len(".py")]
    # Replace any python-illegal chars with underscores
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in base)


# ── Path-prep preamble (v1.5 env fix) ────────────────────────────────────
#
# Functions rooted at hard-coded directory prefixes (e.g.,
# ``open("/data/" + user_input)``) need that prefix dir to EXIST in the
# sandbox before path-traversal exploits can fire. Linux's pathname
# resolver requires every intermediate component to exist (and be
# searchable) before it will resolve ``..`` traversals — so an attack
# input like ``../../etc/passwd`` against ``open("/data/" + path)``
# raises ``FileNotFoundError`` BEFORE the traversal can resolve to
# ``/etc/passwd`` if ``/data`` doesn't exist.
#
# Layered defense:
#   * Sandbox Dockerfile pre-creates a curated set of common prefixes
#     (``/data``, ``/srv/app``, ``/var/lib/app``, …) at mode 1777.
#   * This harness preamble auto-detects ANY absolute-path string
#     literal in the target module's source and ``mkdir -p``'s the
#     corresponding parent dir (or the path itself if it looks like a
#     dir prefix). Catches unusual prefixes the Dockerfile list misses.
#
# The deny-list skips well-known read-only/system dirs so we never
# attempt to mkdir at e.g. ``/etc`` (would fail anyway as non-root,
# but explicit skip is safer + cheaper). All exceptions are swallowed
# — a failed mkdir is a no-op, never blocks the probe call itself.

#: Directory prefixes the harness will NOT attempt to create or mutate.
#: System dirs (read-only at runtime, owned by root, sometimes read-only
#: filesystem mounts) — we don't want noise in stderr from PermissionError.
_PROBE_PREP_DENY_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/dev",
    "/proc",
    "/sys",
    "/root",
    "/boot",
    "/run",
    "/tmp",  # already exists + canary detection mutates here
)


def _build_python_probe_harness(
    *,
    module_name: str,
    function_name: str,
    args_json: str,
    kwargs_json: str,
) -> str:
    """Generate the Python harness that runs ONE probe inside the sandbox.

    Layout:
    1. Snapshot baseline (env, /tmp contents, network log if accessible).
    2. Path-prep preamble: regex-extract absolute-path string literals
       from the target module's source and ``mkdir -p`` the prefix dirs
       so path-traversal exploits can resolve through them.
    3. Import the target module from /workspace.
    4. Resolve the function (supports ``Class.method`` via getattr walk).
    5. Call it with the decoded args / kwargs.
    6. Print ``RESULT_JSON:{...}`` (outcome) + ``SIDE_EFFECTS:{...}``
       (diff of observable side effects).

    The harness is a single-line python -c invocation so it can be
    dropped into a SandboxPlan's ``commands`` list with no shell quoting
    surprises (we ``shlex.quote`` the whole thing at submit time).
    """
    # Use a heredoc-style string we'll embed via stdin. Keeping it
    # raw-string-friendly: triple-quoted, no escapes that f-strings or
    # shells would mangle. The args / kwargs JSON is embedded as a
    # Python literal string so the harness can json.loads() it without
    # shell quoting hell.
    args_repr = repr(args_json)
    kwargs_repr = repr(kwargs_json)
    safe_function = function_name  # Pre-validated by the schema regex
    deny_repr = repr(_PROBE_PREP_DENY_PREFIXES)
    return (
        "import sys, os, json, traceback, re\n"
        "sys.path.insert(0, '/workspace')\n"
        "baseline_tmp = set()\n"
        "try:\n"
        "    baseline_tmp = set(os.listdir('/tmp'))\n"
        "except Exception:\n"
        "    pass\n"
        # ── Path-prep preamble ─────────────────────────────────────────────
        # Regex picks up '/letter[\\w./-]*' string literals from source.
        # For each, mkdir-p the dirname (or the path itself if it ends in '/'
        # or has no extension — i.e., looks like a dir prefix not a file).
        # Skips system prefixes; swallows OSError/PermissionError silently.
        f"_DENY = {deny_repr}\n"
        f"_module_path = '/workspace/{module_name}.py'\n"
        "_paths_to_prep = set()\n"
        "try:\n"
        "    _src = open(_module_path).read()\n"
        "    _paths_to_prep = set(re.findall("
        "r'''[\"\\']((?:/[A-Za-z_][\\w./-]*))[\"\\']''', _src))\n"
        "except Exception:\n"
        "    pass\n"
        "_abs_dir_prefixes = set()\n"
        "for _p in _paths_to_prep:\n"
        "    if any(_p == d or _p.startswith(d + '/') for d in _DENY):\n"
        "        continue\n"
        "    try:\n"
        "        _bn = os.path.basename(_p.rstrip('/'))\n"
        "        # If it looks like a file (basename has '.'), mkdir parent;\n"
        "        # else (looks like a dir prefix), mkdir the path itself.\n"
        "        _looks_like_file = '.' in _bn and not _p.endswith('/')\n"
        "        _to_mk = os.path.dirname(_p) if _looks_like_file else _p.rstrip('/')\n"
        "        if _to_mk and _to_mk != '/':\n"
        "            os.makedirs(_to_mk, exist_ok=True)\n"
        "            _abs_dir_prefixes.add(_to_mk)\n"
        "    except (OSError, PermissionError):\n"
        "        pass\n"
        # ── End source path-prep ──────────────────────────────────────────
        f"args = json.loads({args_repr})\n"
        f"kwargs = json.loads({kwargs_repr})\n"
        # ── Input-derived path-prep ───────────────────────────────────────
        # When the function is rooted at hard-coded prefix dirs (e.g.
        # ``open("/data/" + path)``) and the attack input contains DIRECT
        # path components (not just ``..``/``.``), Linux's path resolver
        # needs ``<prefix>/<components>/...`` to exist before traversal
        # can resolve through it. Example: input ``subdir/../../etc/passwd``
        # against ``open("/data/" + path)`` resolves only when
        # ``/data/subdir/`` exists. mkdir-p the cartesian product of
        # source prefixes × input direct-component prefixes.
        "_skip = {'..', '.', ''}\n"
        "for _arg in args + list(kwargs.values()):\n"
        "    if not (isinstance(_arg, str) and '/' in _arg):\n"
        "        continue\n"
        "    _comps = [c for c in _arg.split('/') if c not in _skip]\n"
        "    if not _comps:\n"
        "        continue\n"
        # last component assumed to be the target file; build under
        # progressively-deeper prefixes for each preceding component.
        "    for _depth in range(1, len(_comps)):\n"
        "        _rel = '/'.join(_comps[:_depth])\n"
        "        for _src_dir in _abs_dir_prefixes:\n"
        "            try:\n"
        "                _full = _src_dir.rstrip('/') + '/' + _rel\n"
        "                if any(_full == d or _full.startswith(d + '/') for d in _DENY):\n"
        "                    continue\n"
        "                os.makedirs(_full, exist_ok=True)\n"
        "            except (OSError, PermissionError):\n"
        "                pass\n"
        # ── End input path-prep ───────────────────────────────────────────

        f"import {module_name} as _target\n"
        "fn = _target\n"
        f"for part in '{safe_function}'.split('.'):\n"
        "    fn = getattr(fn, part)\n"
        "try:\n"
        "    result = fn(*args, **kwargs)\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': True,\n"
        "        'type': type(result).__name__,\n"
        "        'value_preview': repr(result)[:600],\n"
        "    }))\n"
        "except SystemExit as e:\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': False,\n"
        "        'exception_type': 'SystemExit',\n"
        "        'exception_msg': str(e)[:300],\n"
        "    }))\n"
        "except BaseException as e:\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': False,\n"
        "        'exception_type': type(e).__name__,\n"
        "        'exception_msg': str(e)[:300],\n"
        "        'tb_tail': traceback.format_exc()[-1500:],\n"
        "    }))\n"
        "added_tmp = []\n"
        "try:\n"
        "    added_tmp = sorted(set(os.listdir('/tmp')) - baseline_tmp)\n"
        "except Exception:\n"
        "    pass\n"
        "print('SIDE_EFFECTS:' + json.dumps({\n"
        "    'tmp_files_added': added_tmp[:20],\n"
        "}))\n"
    )


# ── JavaScript harness generation ────────────────────────────────────────


def _javascript_module_path_for_file(file_name: str) -> str:
    """The absolute path Node should ``import()`` to load the staged
    module. Sandbox guarantees the file lives at ``/workspace/<basename>``.

    Unlike Python (where we strip the extension and rely on the import
    machinery), Node's dynamic ``import()`` takes a path — extension
    included — and figures out the loader from there. Trailing chars
    that would break a path import are not legal in Node module specifiers
    anyway, so we just pass the basename verbatim.
    """
    return f"/workspace/{Path(file_name).name}"


def _build_javascript_probe_harness(
    *,
    module_path: str,
    function_name: str,
    args_json: str,
    kwargs_json: str,
) -> str:
    """Generate the Node.js harness that runs ONE probe inside the sandbox.

    Layout (mirrors the Python harness for symmetry):
    1. Snapshot baseline (/tmp listing).
    2. Path-prep preamble — extract absolute-path string literals from
       source and from input args, ``fs.mkdirSync(..., {recursive: true})``
       each.
    3. Dynamic ``import()`` the target module.
    4. Resolve the function with a dotted-path walk supporting both
       CommonJS (``module.exports``) and ES-module (``export default``)
       layouts.
    5. Call with decoded args / kwargs. Async functions are awaited.
    6. Print ``RESULT_JSON:{...}`` + ``SIDE_EFFECTS:{...}`` markers — the
       deterministic interpreter rules then run on these the same way
       they do for Python.

    Wrapped in an async IIFE so top-level ``await`` works on Node 18+.
    """
    # Embed args/kwargs as JSON-in-JS-string-literal — JSON.parse handles
    # the unwrap. Use JSON.stringify to safely encode the args_json /
    # kwargs_json strings into JS string literals.
    args_json_lit = json.dumps(args_json)
    kwargs_json_lit = json.dumps(kwargs_json)
    function_name_lit = json.dumps(function_name)
    module_path_lit = json.dumps(module_path)
    deny_lit = json.dumps(list(_PROBE_PREP_DENY_PREFIXES))
    return (
        # ── Catastrophic-failure safety net ─────────────────────────────────
        # Real-fixture runs surfaced a class of failure where Node exited
        # code 1 without emitting any RESULT_JSON marker — the harness
        # crashed before its try/catch around the import block could fire
        # (e.g., JSON.parse on a malformed payload, or an unhandled
        # rejection from an async path-prep call). The interpreter then
        # got parsed_result=None and journaled "no exploit observed" with
        # an empty exception_type — a silent failure that looks identical
        # to "probe ran cleanly, no exploit found".
        #
        # Fix: install process-level handlers FIRST so any exception or
        # unhandled rejection is converted into a RESULT_JSON marker
        # before Node exits. Idempotency-safe: the markers are emitted by
        # the normal-path code below when execution reaches it.
        "let _markerEmitted = false;\n"
        "function _emitFatal(label, err) {\n"
        "  if (_markerEmitted) return;\n"
        "  _markerEmitted = true;\n"
        "  const msg = err && (err.message || err.toString) "
        "? String(err.message || err).slice(0, 300) : String(err).slice(0, 300);\n"
        "  const stack = err && err.stack ? String(err.stack).slice(-1500) : '';\n"
        "  const ctor = err && err.constructor && err.constructor.name "
        "? err.constructor.name : 'Error';\n"
        "  try {\n"
        "    console.log('RESULT_JSON:' + JSON.stringify({\n"
        "      ok: false,\n"
        "      exception_type: ctor,\n"
        "      exception_msg: '[' + label + '] ' + msg,\n"
        "      tb_tail: stack,\n"
        "    }));\n"
        "    console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: [] }));\n"
        "  } catch (e) {}\n"
        "}\n"
        "process.on('uncaughtException', (e) => _emitFatal('uncaughtException', e));\n"
        "process.on('unhandledRejection', (e) => _emitFatal('unhandledRejection', e));\n"
        "(async () => {\n"
        # Wrap the entire body in try/catch so SYNC throws at the IIFE
        # top level (JSON.parse failures, ReferenceErrors before the
        # import block, etc.) still get reported as RESULT_JSON. The
        # individual try/catch blocks below remain — they emit more
        # specific exception_type labels for the common cases.
        "  try {\n"
        "  const fs = require('fs');\n"
        "  const path = require('path');\n"
        "  let baselineTmp = new Set();\n"
        "  try {\n"
        "    baselineTmp = new Set(fs.readdirSync('/tmp'));\n"
        "  } catch (e) {}\n"
        "  const args = JSON.parse(" + args_json_lit + ");\n"
        "  const kwargs = JSON.parse(" + kwargs_json_lit + ");\n"
        "  const fnName = " + function_name_lit + ";\n"
        # ── Path-prep preamble ──────────────────────────────────────────
        "  const DENY = " + deny_lit + ";\n"
        "  const absDirPrefixes = new Set();\n"
        "  try {\n"
        "    const src = fs.readFileSync(" + module_path_lit + ", 'utf8');\n"
        "    const re = /['\"](\\/[A-Za-z_][\\w./-]*)['\"]/g;\n"
        "    const matches = new Set();\n"
        "    let m;\n"
        "    while ((m = re.exec(src)) !== null) matches.add(m[1]);\n"
        "    for (const p of matches) {\n"
        "      if (DENY.some(d => p === d || p.startsWith(d + '/'))) continue;\n"
        "      try {\n"
        "        const bn = path.basename(p.replace(/\\/$/, ''));\n"
        "        const looksLikeFile = bn.includes('.') && !p.endsWith('/');\n"
        "        const toMk = looksLikeFile ? path.dirname(p) : p.replace(/\\/$/, '');\n"
        "        if (toMk && toMk !== '/') {\n"
        "          fs.mkdirSync(toMk, { recursive: true });\n"
        "          absDirPrefixes.add(toMk);\n"
        "        }\n"
        "      } catch (e) {}\n"
        "    }\n"
        "  } catch (e) {}\n"
        # ── Input-derived path-prep ─────────────────────────────────────
        "  const SKIP = new Set(['..', '.', '']);\n"
        "  const allInputs = [...args, ...Object.values(kwargs)];\n"
        "  for (const a of allInputs) {\n"
        "    if (typeof a !== 'string' || !a.includes('/')) continue;\n"
        "    const comps = a.split('/').filter(c => !SKIP.has(c));\n"
        "    if (comps.length === 0) continue;\n"
        "    for (let depth = 1; depth < comps.length; depth++) {\n"
        "      const rel = comps.slice(0, depth).join('/');\n"
        "      for (const srcDir of absDirPrefixes) {\n"
        "        try {\n"
        "          const full = srcDir.replace(/\\/$/, '') + '/' + rel;\n"
        "          if (DENY.some(d => full === d || full.startsWith(d + '/'))) continue;\n"
        "          fs.mkdirSync(full, { recursive: true });\n"
        "        } catch (e) {}\n"
        "      }\n"
        "    }\n"
        "  }\n"
        # ── Module resolution ───────────────────────────────────────────
        # Dynamic import() supports both CJS and ESM. For CJS modules
        # the named exports appear directly on the module namespace;
        # for ESM-default-export they appear on .default.
        "  let mod;\n"
        "  try {\n"
        "    mod = await import(" + module_path_lit + ");\n"
        "  } catch (e) {\n"
        "    _markerEmitted = true;\n"
        "    console.log('RESULT_JSON:' + JSON.stringify({\n"
        "      ok: false,\n"
        "      exception_type: 'ImportError',\n"
        "      exception_msg: String(e.message || e).slice(0, 300),\n"
        "    }));\n"
        "    console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: [] }));\n"
        "    return;\n"
        "  }\n"
        # Dotted-path resolver — try direct attr walk, then .default.
        "  function resolveFn(modObj, dotted) {\n"
        "    const parts = dotted.split('.');\n"
        "    let cur = modObj;\n"
        "    for (const p of parts) {\n"
        "      if (cur != null && typeof cur === 'object' && p in cur) {\n"
        "        cur = cur[p];\n"
        "      } else {\n"
        "        return undefined;\n"
        "      }\n"
        "    }\n"
        "    return cur;\n"
        "  }\n"
        "  let fn = resolveFn(mod, fnName);\n"
        "  if (typeof fn !== 'function' && mod.default != null) {\n"
        "    fn = resolveFn(mod.default, fnName);\n"
        "  }\n"
        "  if (typeof fn !== 'function') {\n"
        "    _markerEmitted = true;\n"
        "    console.log('RESULT_JSON:' + JSON.stringify({\n"
        "      ok: false,\n"
        "      exception_type: 'AttributeError',\n"
        "      exception_msg: 'function not found: ' + fnName,\n"
        "    }));\n"
        "    console.log('SIDE_EFFECTS:' + JSON.stringify({ tmp_files_added: [] }));\n"
        "    return;\n"
        "  }\n"
        # ── Invocation + result capture ─────────────────────────────────
        # Pass kwargs as a trailing object arg if non-empty — common JS
        # convention. If the function doesn't accept that signature it
        # just ignores the extra arg.
        "  const kwKeys = Object.keys(kwargs);\n"
        "  const callArgs = kwKeys.length > 0 ? [...args, kwargs] : args;\n"
        "  try {\n"
        "    let result = fn(...callArgs);\n"
        "    if (result && typeof result.then === 'function') {\n"
        "      result = await result;\n"
        "    }\n"
        "    let preview;\n"
        "    try {\n"
        "      preview = (typeof result === 'string' ? result : JSON.stringify(result));\n"
        "      preview = String(preview).slice(0, 600);\n"
        "    } catch (e) {\n"
        "      preview = String(result).slice(0, 600);\n"
        "    }\n"
        "    _markerEmitted = true;\n"
        "    console.log('RESULT_JSON:' + JSON.stringify({\n"
        "      ok: true,\n"
        "      type: typeof result,\n"
        "      value_preview: preview,\n"
        "    }));\n"
        "  } catch (e) {\n"
        "    const stack = e && e.stack ? String(e.stack).slice(-1500) : '';\n"
        "    _markerEmitted = true;\n"
        "    console.log('RESULT_JSON:' + JSON.stringify({\n"
        "      ok: false,\n"
        "      exception_type: e && e.constructor ? e.constructor.name : 'Error',\n"
        "      exception_msg: String((e && e.message) || e).slice(0, 300),\n"
        "      tb_tail: stack,\n"
        "    }));\n"
        "  }\n"
        # ── Side-effect snapshot ───────────────────────────────────────
        "  let added = [];\n"
        "  try {\n"
        "    added = fs.readdirSync('/tmp').filter(f => !baselineTmp.has(f)).sort();\n"
        "  } catch (e) {}\n"
        "  console.log('SIDE_EFFECTS:' + JSON.stringify({\n"
        "    tmp_files_added: added.slice(0, 20),\n"
        "  }));\n"
        # Close the outer try that wraps the entire IIFE body. Sync
        # throws (e.g., JSON.parse on a malformed payload, ReferenceError
        # in path-prep, TypeError in input enumeration) bubble here and
        # get reported as a fatal marker. _markerEmitted guards against
        # double-emission if a partial-success path already reported.
        "  } catch (e) {\n"
        "    _emitFatal('iifeBody', e);\n"
        "  }\n"
        "})();\n"
    )


# ── Shell harness generation ─────────────────────────────────────────────


def _build_shell_probe_harness(
    *,
    script_path: str,
    args_json: str,
    kwargs_json: str,
) -> str:
    """Generate the Python harness that drives ONE shell-script probe.

    Shell scripts are entry-points, not function libraries — the
    ``function_name`` field is conceptually "the script itself" for
    shell. We invoke ``bash <script_path> <args...>`` with:

    * ``args_json`` decoded as POSITIONAL ARGS ($1, $2, ...)
    * ``kwargs_json`` decoded as ENVIRONMENT VARS (exported before exec)

    The harness is written in Python (not bash) because pure-bash JSON
    parsing is treacherous and Python is already in every sandbox image.
    Same RESULT_JSON / SIDE_EFFECTS markers as Python + JS so the
    deterministic interpreter rules apply uniformly.

    Path-prep preamble runs the same way as Python — regex-extract
    absolute-path string literals from the shell source and from input
    args, ``mkdir -p`` each. The shell deny list is identical to
    Python's (no ``/etc``, ``/usr``, etc.).
    """
    args_repr = repr(args_json)
    kwargs_repr = repr(kwargs_json)
    deny_repr = repr(_PROBE_PREP_DENY_PREFIXES)
    script_path_repr = repr(script_path)
    return (
        "import sys, os, json, traceback, re, subprocess\n"
        "baseline_tmp = set()\n"
        "try:\n"
        "    baseline_tmp = set(os.listdir('/tmp'))\n"
        "except Exception:\n"
        "    pass\n"
        f"args = json.loads({args_repr})\n"
        f"kwargs = json.loads({kwargs_repr})\n"
        f"_DENY = {deny_repr}\n"
        f"_script_path = {script_path_repr}\n"
        "_paths_to_prep = set()\n"
        "try:\n"
        "    _src = open(_script_path).read()\n"
        "    _paths_to_prep = set(re.findall("
        "r'''[\"\\']((?:/[A-Za-z_][\\w./-]*))[\"\\']''', _src))\n"
        "except Exception:\n"
        "    pass\n"
        "_abs_dir_prefixes = set()\n"
        "for _p in _paths_to_prep:\n"
        "    if any(_p == d or _p.startswith(d + '/') for d in _DENY):\n"
        "        continue\n"
        "    try:\n"
        "        _bn = os.path.basename(_p.rstrip('/'))\n"
        "        _looks_like_file = '.' in _bn and not _p.endswith('/')\n"
        "        _to_mk = os.path.dirname(_p) if _looks_like_file else _p.rstrip('/')\n"
        "        if _to_mk and _to_mk != '/':\n"
        "            os.makedirs(_to_mk, exist_ok=True)\n"
        "            _abs_dir_prefixes.add(_to_mk)\n"
        "    except (OSError, PermissionError):\n"
        "        pass\n"
        "_skip = {'..', '.', ''}\n"
        "for _arg in args + list(kwargs.values()):\n"
        "    if not (isinstance(_arg, str) and '/' in _arg):\n"
        "        continue\n"
        "    _comps = [c for c in _arg.split('/') if c not in _skip]\n"
        "    if not _comps:\n"
        "        continue\n"
        "    for _depth in range(1, len(_comps)):\n"
        "        _rel = '/'.join(_comps[:_depth])\n"
        "        for _src_dir in _abs_dir_prefixes:\n"
        "            try:\n"
        "                _full = _src_dir.rstrip('/') + '/' + _rel\n"
        "                if any(_full == d or _full.startswith(d + '/') for d in _DENY):\n"
        "                    continue\n"
        "                os.makedirs(_full, exist_ok=True)\n"
        "            except (OSError, PermissionError):\n"
        "                pass\n"
        # Build env from kwargs (string-coerced), prepend the existing env.
        "env = os.environ.copy()\n"
        "for k, v in kwargs.items():\n"
        "    env[str(k)] = str(v)\n"
        # Invoke bash <script> <args...>. Shell scripts return their own
        # exit code; we map that to ok = (returncode == 0). Vulnerable
        # behavior on attack input usually = exit 0 (the script ran the
        # attack to completion) rather than the defensive exit != 0.
        f"_argv = ['bash', _script_path] + [str(a) for a in args]\n"
        "try:\n"
        "    _proc = subprocess.run(\n"
        "        _argv,\n"
        "        env=env,\n"
        "        capture_output=True,\n"
        "        text=True,\n"
        "        timeout=20,\n"
        "    )\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': _proc.returncode == 0,\n"
        "        'exit_code': _proc.returncode,\n"
        "        'type': 'shell_exit',\n"
        "        'value_preview': (_proc.stdout or '')[:600],\n"
        "        'stderr_preview': (_proc.stderr or '')[:300],\n"
        "    }))\n"
        "except subprocess.TimeoutExpired:\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': False,\n"
        "        'exception_type': 'TimeoutExpired',\n"
        "        'exception_msg': 'shell script exceeded timeout',\n"
        "    }))\n"
        "except BaseException as e:\n"
        "    print('RESULT_JSON:' + json.dumps({\n"
        "        'ok': False,\n"
        "        'exception_type': type(e).__name__,\n"
        "        'exception_msg': str(e)[:300],\n"
        "        'tb_tail': traceback.format_exc()[-1500:],\n"
        "    }))\n"
        "added_tmp = []\n"
        "try:\n"
        "    added_tmp = sorted(set(os.listdir('/tmp')) - baseline_tmp)\n"
        "except Exception:\n"
        "    pass\n"
        "print('SIDE_EFFECTS:' + json.dumps({\n"
        "    'tmp_files_added': added_tmp[:20],\n"
        "}))\n"
    )


# ── Language detection + plan dispatch ───────────────────────────────────


#: Map of probe-supported languages to file extensions. The plan builder
#: dispatches harness generation by walking this table.
_SUPPORTED_EXTS_BY_LANG: dict[str, tuple[str, ...]] = {
    "python": (".py",),
    "javascript": (".js", ".mjs", ".cjs"),
    "shell": (".sh", ".bash"),
}


def detect_probe_language(file_name: str) -> str | None:
    """Return the probe language for ``file_name`` based on its extension,
    or ``None`` if the file isn't probe-supported.

    Returns one of: ``"python"``, ``"javascript"``, ``"shell"``, or
    ``None``. Used by both the plan builder (to dispatch harness
    generation) and the orchestrator's probe-stage entry gate (to skip
    files we can't probe).

    TypeScript / JSX is intentionally NOT included — Node 18 doesn't
    strip TS type annotations natively, and probing a .ts file through
    the JS harness would fail at parse time. Add ts-node to the
    sandbox image and split the harness to enable.
    """
    fn_lower = file_name.lower()
    for lang, exts in _SUPPORTED_EXTS_BY_LANG.items():
        if any(fn_lower.endswith(e) for e in exts):
            return lang
    return None


# ── Plan builder ──────────────────────────────────────────────────────────


def build_runtime_probe_plan(
    *,
    file_name: str,
    file_bytes: bytes,
    candidate: RuntimeProbeCandidate,
    test_input: RuntimeProbeInput,
    candidate_idx: int,
    input_idx: int,
    image_hint: str = "minimal",
) -> dict[str, Any] | None:
    """Build a Phase-A-shaped plan dict that runs one probe.

    Returns ``None`` when the file's extension isn't in
    :data:`_SUPPORTED_EXTS_BY_LANG` (probe is a no-op for that file).
    The plan's ``hypothesis_id`` follows the pattern
    ``HRP_<candidate_idx>_<input_idx>`` (HRP = "harness runtime probe")
    for stable identifiers across iterations.

    Dispatches harness construction by file extension:

    * ``.py`` → Python harness (import + getattr walk + call)
    * ``.js`` / ``.mjs`` / ``.cjs`` → Node harness (dynamic import +
      CJS/ESM-tolerant function resolver + async-await invocation)
    * ``.sh`` / ``.bash`` → Python-orchestrated shell harness
      (subprocess.run with args as positional and kwargs as env vars;
      script-level probing, not function-level, since shell scripts
      are usually entry points)

    All three harnesses emit the same ``RESULT_JSON:`` / ``SIDE_EFFECTS:``
    markers and route through :func:`interpret_probe_trace` identically.
    """
    lang = detect_probe_language(file_name)
    if lang is None:
        return None

    file_base = Path(file_name).name
    if lang == "python":
        module_name = _python_module_name_for_file(file_name)
        harness = _build_python_probe_harness(
            module_name=module_name,
            function_name=candidate.function_name,
            args_json=test_input.args_json,
            kwargs_json=test_input.kwargs_json,
        )
        runner = "python3"
        harness_ext = "py"
    elif lang == "javascript":
        module_path = _javascript_module_path_for_file(file_name)
        harness = _build_javascript_probe_harness(
            module_path=module_path,
            function_name=candidate.function_name,
            args_json=test_input.args_json,
            kwargs_json=test_input.kwargs_json,
        )
        runner = "node"
        # Use .cjs so dynamic import() of either CJS or ESM works
        # without "type":"module" gymnastics in /workspace.
        harness_ext = "cjs"
    elif lang == "shell":
        script_path = f"/workspace/{file_base}"
        harness = _build_shell_probe_harness(
            script_path=script_path,
            args_json=test_input.args_json,
            kwargs_json=test_input.kwargs_json,
        )
        runner = "python3"
        harness_ext = "py"
    else:  # pragma: no cover — detect_probe_language guarantees coverage
        return None

    # Encode the original file as base64 so the sandbox stages it at
    # /workspace/<file_name>. Same pattern ml_detonation.py uses for
    # binary artifacts; reuses the staging infra.
    payload_b64 = base64.b64encode(file_bytes).decode("ascii")

    # Wrap harness in a python -c invocation. The sandbox runner will
    # shell-quote this safely; we just deliver the harness source.
    # SandboxPlan.commands is a list of shell strings, so the cleanest
    # path is to write the harness to a temp file in /workspace first,
    # then invoke it. Two-command plan. The bootstrap is always python3
    # (always present in every sandbox image) — only the harness runner
    # varies by language.
    harness_path = f"/workspace/_argus_probe_{candidate_idx}_{input_idx}.{harness_ext}"
    write_cmd = (
        f'python3 -c "import base64,sys; '
        f"open({harness_path!r},'wb').write("
        f'base64.b64decode(sys.argv[1]))" '
        f"{base64.b64encode(harness.encode('utf-8')).decode('ascii')}"
    )
    run_cmd = f"{runner} {harness_path}"

    return {
        "hypothesis_id": f"HRP_{candidate_idx}_{input_idx}",
        "plan_status": "executable",
        "commands": [write_cmd, run_cmd],
        "oracle": "execution_output_with_side_effect_observation",
        "payload": payload_b64,
        "payload_encoding": "base64",
        "timeout_sec": DEFAULT_PROBE_TIMEOUT_SEC,
        "image_hint": image_hint,
        "rationale": (
            f"Runtime probe ({lang}): testing {candidate.function_name} with attack "
            f"input for {candidate.attack_class}. Expected if vulnerable: "
            f"{test_input.expected_observable[:150]}"
        ),
    }


# ── Trace interpretation ─────────────────────────────────────────────────


def parse_probe_trace(
    *,
    candidate_function: str,
    input_args_json: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    elapsed_ms: int,
) -> RuntimeProbeTrace:
    """Pull the structured markers (``RESULT_JSON:`` and ``SIDE_EFFECTS:``)
    out of the harness's stdout and build a typed trace record.

    Defensive against (a) truncated stdout, (b) harness crash before
    markers, (c) markers with broken JSON. Any parse failure leaves the
    relevant field at its sentinel (``parsed_result=None`` or empty
    ``side_effects={}``) so callers don't have to handle exceptions."""
    trace = RuntimeProbeTrace(
        candidate_function=candidate_function,
        input_args_json=input_args_json,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        elapsed_ms=elapsed_ms,
    )

    # Walk stdout line-by-line to find the markers. We accept the LAST
    # occurrence of each marker (harness emits one of each near the end).
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("RESULT_JSON:"):
            payload = line[len("RESULT_JSON:") :].strip()
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    trace.parsed_result = parsed
            except (json.JSONDecodeError, ValueError):
                continue
        elif line.startswith("SIDE_EFFECTS:"):
            payload = line[len("SIDE_EFFECTS:") :].strip()
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    trace.side_effects = parsed
            except (json.JSONDecodeError, ValueError):
                continue

    return trace


# ── Phase 0: attack-class evidence signatures (FP defense) ───────────────
#
# Rule 1 ("function returned ok on attack input") used to fire on any
# parsed_result.ok == True. That's too broad — a function that returns
# empty string / null / an error code on attack input also produces
# ok=True. Real-world fixture validation surfaced this: a probe could
# emit a finding without the return value actually demonstrating the
# claimed exploit (e.g., path_traversal "confirmed" with value_preview
# being a benign string that happens to not be /etc/passwd content).
#
# Fix: each attack class declares a list of POSITIVE-MATCH SIGNATURES
# that the runtime evidence (value_preview + stderr_preview) MUST
# contain for Rule 1 to fire. The model's `expected_observable` field
# is additionally extracted into a per-input oracle: any expected-
# observable-keyword found in the runtime evidence is a confirming
# match. If neither hits, the probe is BLOCKED — runtime evidence
# didn't concretely demonstrate the exploit.
#
# Substring match, not regex. Case-insensitive. Cheap, deterministic,
# evidence-grounded. Same shape as Rule 2's canary-marker matching
# already in place for /tmp file emergence.

#: Per-attack-class signature library. Each entry is a list of
#: case-insensitive substrings the runtime evidence MUST contain for
#: Rule 1 to confirm an exploit of that class. Multiple substrings =
#: OR (any one match is enough). Empty list means Rule 1 is gated
#: ENTIRELY on the per-input ``expected_observable`` oracle for that
#: attack class.
#:
#: Signatures err toward distinctive runtime artifacts — file-system
#: layout markers, command-output identifiers, version banners — that
#: don't appear in benign return values.
_ATTACK_CLASS_EVIDENCE_SIGNATURES: dict[str, list[str]] = {
    "path_traversal": [
        # Sensitive-file content markers — passwd/shadow line shapes
        "root:x:0:0:",
        "root:x:0:",
        "daemon:x:",
        # SSH key markers
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN DSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        # Known sensitive-path content
        "[client]",  # /etc/mysql/my.cnf style
        "[mysqld]",
        # /etc/hosts line shape
        "localhost",  # in conjunction with returning content
        # /proc artifacts
        "Linux version ",
        "MemTotal:",
        # Sensitive AWS/cloud secrets
        "AKIA",
        "aws_access_key_id",
    ],
    "command_injection": [
        # uid output from `id`
        "uid=",
        "gid=",
        "groups=",
        # `whoami` returns root/runner; not distinctive on its own — pair
        # with shell-pipe markers via canary instead. Listed for
        # completeness when the model targets whoami specifically.
        "uname",
        # `pwd` output marker — distinctive when subshell fires
        "/workspace",
        # Common shell-exec stdout
        "Linux ",
        # `env` exfil
        "PATH=/",
        "HOME=/",
        # `ls /` style markers
        "bin\nboot\ndev\n",
    ],
    "code_injection": [
        # eval / exec firing typically produces canary tmp files (Rule 2)
        # or returns a value embedded with marker strings. Keep narrow.
        "__builtins__",
        "<module '",
        "/proc/self",
    ],
    "deserialization": [
        # pickle.__reduce__ / yaml.unsafe_load typically fire via canary
        # (Rule 2). Distinctive return markers when payload echos back:
        "Reduce executed",
        "<class 'os.system'>",
        "command executed via",
    ],
    "ssrf": [
        # Internal-only address echoes
        "169.254.169.254",  # AWS IMDS
        "metadata.google.internal",
        "metadata.google",
        "metadata.azure.com",
        "127.0.0.1",  # in the returned content
        "localhost",
        # IMDS response shape
        "iam/security-credentials",
        "AccessKeyId",
    ],
    "sql_injection": [
        # Distinctive db-introspection output
        "version()",
        "@@version",
        "sqlite_master",
        "information_schema",
        "PostgreSQL",
        "MariaDB",
        "MySQL",
        # Union-injection telltale: error containing SQL keywords
        "SQL syntax",
        "syntax error",
        "ORA-",  # Oracle
    ],
    "data_exfiltration": [
        # HTTP/network artifacts in return value indicating outbound
        "HTTP/1",
        "200 OK",
        "Set-Cookie:",
        "Authorization:",
        # Base64 of common secret prefixes (rough heuristic)
        "ZWNyZXQ",  # base64 of "ecret"
    ],
    "xxe": [
        # File-content disclosure via XML external entity
        "root:x:0:",
        "<?xml",
        "<!DOCTYPE",
        "SYSTEM \"file:",
    ],
    "xss": [
        "<script",
        "alert(",
        "onerror=",
        "javascript:",
    ],
    "crypto_weakness": [
        # MD5/SHA1 collisions, predictable PRNG — these often surface as
        # specific known-bad output strings. Keep narrow until we see
        # concrete cases.
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty string
    ],
    "open_redirect": [
        "Location: http",
        "Location: //",
    ],
    "prompt_injection": [
        # Hard to gate purely on substrings — typically caught via canary
        "ignore previous",
        "ignore all",
        "system prompt:",
    ],
    "race_condition": [
        # Timing-based; defer to model-loop interpretation for v1.5.
    ],
}


def _evidence_signature_match(
    *,
    attack_class: str,
    value_preview: str,
    stderr_preview: str,
    expected_observable: str,
) -> tuple[bool, str]:
    """Check whether the runtime evidence concretely demonstrates an
    exploit of the declared attack class.

    Two oracles, OR-combined:

    1. **Class signature**: the evidence contains any of the
       attack-class-specific positive-match substrings (e.g., ``root:x:0:0:``
       for path_traversal — distinctive sensitive-file content).
    2. **Expected-observable keyword**: extracted from the model's
       ``expected_observable`` text, any 5+ char alphanumeric token appears
       in the evidence (e.g., model said "returns /etc/passwd content" →
       extract ``etc/passwd`` and ``passwd`` → check if value_preview
       contains either).

    Returns ``(matched, rationale)`` — the rationale is journaled into
    the finding's runtime_evidence so we can audit which oracle confirmed.

    Case-insensitive substring match. If both haystacks are empty,
    return False to avoid false-positive on a no-content return.
    """
    haystack = (value_preview + " " + stderr_preview).lower()
    if not haystack.strip():
        return False, "empty runtime evidence"

    # Oracle 1: class signature
    class_sigs = _ATTACK_CLASS_EVIDENCE_SIGNATURES.get(attack_class, [])
    for sig in class_sigs:
        if sig.lower() in haystack:
            return True, f"class-signature match: '{sig}'"

    # Oracle 2: expected_observable keyword extraction. Pull 5+-char
    # alphanumeric tokens from the model's expected_observable text,
    # strip noise words, and see if any appear in the haystack.
    _NOISE_WORDS = {
        "function",
        "returns",
        "returned",
        "contains",
        "value",
        "string",
        "should",
        "would",
        "exploit",
        "attack",
        "input",
        "output",
        "passes",
        "fails",
    }
    tokens: list[str] = []
    for raw_token in re.findall(r"[A-Za-z0-9_/.\-]{5,}", expected_observable):
        t = raw_token.strip("/.-_")
        if not t or t.lower() in _NOISE_WORDS:
            continue
        tokens.append(t)
    for t in tokens:
        if t.lower() in haystack:
            return True, f"expected-observable keyword match: '{t}'"

    return False, "no evidence-signature match"


def interpret_probe_trace(
    trace: RuntimeProbeTrace,
    candidate: RuntimeProbeCandidate,
    test_input: RuntimeProbeInput,
    *,
    candidate_idx: int,
    input_idx: int,
) -> RuntimeProbeFinding | None:
    """Decide whether the trace constitutes a runtime-confirmed exploit.

    Two complementary rules:

    **Rule 1 (FP-hardened, Phase 0):** ``parsed_result.ok == True`` AND
    the runtime evidence (value_preview + stderr_preview) matches at
    least one of:

      * The attack-class signature library
        (:data:`_ATTACK_CLASS_EVIDENCE_SIGNATURES`) — distinctive runtime
        artifacts that don't appear in benign return values (e.g.,
        ``root:x:0:0:`` for path_traversal, ``uid=`` for
        command_injection, ``200 OK`` for ssrf).
      * Keywords extracted from the model's ``expected_observable`` text
        — substrings 5+ chars that appear verbatim in the evidence.

    Without the evidence match, Rule 1 does NOT fire — even if the
    function returned ok. This kills the class of FPs where a function
    legitimately returned an empty string / null / error code on attack
    input and the probe used to report it as an exploit anyway.

    **Rule 2 (unchanged):** ``side_effects.tmp_files_added`` contains
    files matching the canary marker pattern (``argus_probe`` / ``pwned``
    substrings). This rule was already evidence-gated by the marker
    requirement, no FP exposure.

    Returns ``None`` when no rule fires (probe ran but observed no
    exploit signal — that's the BLOCKED-equivalent for runtime probes).
    """
    if trace.parsed_result is None:
        # Harness crashed before printing the marker — can't interpret.
        return None

    parsed = trace.parsed_result
    side_effects = trace.side_effects or {}

    # Rule 1: function returned successfully on an attack input AND the
    # runtime evidence concretely matches the declared attack class.
    # Without the evidence match, ok=True alone is not enough — the
    # function might be returning a no-op default that doesn't represent
    # an exploit.
    ok = bool(parsed.get("ok"))
    value_preview = str(parsed.get("value_preview", "") or "")
    stderr_preview = str(parsed.get("stderr_preview", "") or "")
    rule1_match = False
    rule1_rationale = ""
    if ok:
        rule1_match, rule1_rationale = _evidence_signature_match(
            attack_class=candidate.attack_class,
            value_preview=value_preview,
            stderr_preview=stderr_preview,
            expected_observable=test_input.expected_observable,
        )

    # Rule 2: canary side effects. The model is encouraged to include
    # markers in attack inputs (e.g., write to /tmp/argus_probe_*) that
    # the sandbox can observe. Tmp files appearing post-call = exploit.
    tmp_added: list[str] = (
        side_effects.get("tmp_files_added")
        if isinstance(side_effects.get("tmp_files_added"), list)
        else []
    )
    canary_hit = any(
        isinstance(f, str) and ("argus_probe" in f.lower() or "pwned" in f.lower())
        for f in tmp_added
    )

    # Build the finding when ANY rule fires.
    evidence_parts: list[str] = []
    if rule1_match:
        evidence_parts.append(
            f"Function returned without raising AND evidence matches: {rule1_rationale}. "
            f"Value preview: {value_preview[:200]}"
        )
    if canary_hit:
        evidence_parts.append(f"Sandbox observed canary file(s) created in /tmp: {tmp_added[:5]}")
    if not evidence_parts:
        # Probe ran cleanly — either exception raised, OR ok=True but the
        # runtime evidence didn't match any expected oracle (FP defense).
        # That's BLOCKED/UNREACHED-equivalent: no exploit observed.
        return None

    runtime_evidence = (
        f"Probe `{candidate.function_name}({test_input.args_json})`: "
        + "; ".join(evidence_parts)
        + f" (exit_code={trace.exit_code}, elapsed={trace.elapsed_ms}ms)"
    )

    return RuntimeProbeFinding(
        finding_id=f"HRP_{candidate_idx}_{input_idx}",
        candidate_function=candidate.function_name,
        attack_class=candidate.attack_class,
        severity=severity_for_attack_class(candidate.attack_class),
        cwe=cwe_for_attack_class(candidate.attack_class),
        description=(
            test_input.exploit_proof_if_observed
            or f"{candidate.attack_class} in {candidate.function_name}"
        ),
        runtime_evidence=runtime_evidence,
        test_input_args=test_input.args_json,
    )


__all__ = [
    "DEFAULT_PROBE_TIMEOUT_SEC",
    "MAX_CANDIDATES",
    "MAX_INPUTS_PER_CANDIDATE",
    "MAX_PROBE_RUNS_PER_FILE",
    "RuntimeProbeCandidate",
    "RuntimeProbeFinding",
    "RuntimeProbeInput",
    "RuntimeProbeTrace",
    "build_runtime_probe_plan",
    "cwe_for_attack_class",
    "detect_probe_language",
    "interpret_probe_trace",
    "parse_probe_trace",
    "severity_for_attack_class",
]
