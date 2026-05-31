"""SCAN-017 Phase 2 — static AST detector for downstream-capped functions.

The Gemini-flagged FP class this addresses:

    The HRP probe for ``_parse_retry_after_header`` confirmed because
    the function returned 3600.0 when fed ``retry-after-ms: 3600000``.
    But the immediate downstream consumer ``_calculate_retry_timeout``
    contains ``if retry_after is not None and 0 < retry_after <= 60:``
    — the 3600 value is silently bounded to a 60-second cap when the
    SDK actually USES the parser's output. The unit-level CONFIRMED
    is misleading: the exploit chain is broken at the sink.

Phase 2 detects this purely statically. For each function defined in
the file, the visitor inspects its body for patterns that bound the
return value of ANOTHER function defined in the same file:

  * ``min(<call>, N)`` / ``max(<call>, N)``           — min/max wrap
  * ``var = <call>; ... var <= N / var < N``          — compare-bound
  * ``var = <call>; ... 0 < var <= N``                — range-bound
  * ``var = <call>; return min(var, N)``              — return-wrap

When a probe's candidate function is recorded as ``capped_function``
in any in-file caller AND the cap value is below the attack-relevant
threshold, the orchestrator suppresses the finding with reason
``downstream_cap_detected``. The behaviour mirrors v15.25's
purpose-aligned-return suppression — both fire as the LAST step before
a finding is committed, with audit trails preserved in the journal.

Conservative scope (v1):

* Same-file only. Cross-file caps (parser in module X, consumer in
  module Y) would require import resolution + multi-file source
  access. F-3 (syscall_observations) catches those at runtime.

* Numeric cap values only (int / float literals). Non-numeric caps
  (e.g., enum guards) are out of scope for now.

* Attack-class gate. Caps only suppress for ATTACK CLASSES whose
  exploit story REQUIRES unbounded magnitude (DoS amplification,
  resource exhaustion, business-logic abuse). They DO NOT suppress
  for ssrf / open_redirect / code_injection / path_traversal —
  those exploits don't depend on the magnitude of a numeric return
  value, so a cap doesn't invalidate them.

* AST-only — no dataflow tracing beyond direct assignment +
  same-function bound. A cap that's three calls deep through helpers
  won't be detected. That's fine: precision > recall here, missing
  a cap means we false-positive (current behaviour), detecting a
  cap that doesn't apply is a false-suppression risk we want to
  avoid.

Stand-alone module to keep the AST visitor + helpers separately
testable from runtime_probe.py and behavioral_probe.py — both of
which are already large.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class DownstreamCap:
    """One detected cap in a same-file caller."""

    capped_function: str
    """Bare name of the function whose return value the caller bounds.
    e.g., ``"_parse_retry_after_header"``."""

    capper_function: str
    """Bare name of the function whose body contains the bound. e.g.,
    ``"_calculate_retry_timeout"``."""

    capper_line: int
    """1-indexed line of the bounding expression in the source file."""

    pattern: str
    """Which pattern matched:
       * ``"min_call"``      — ``min(<call>, N)``
       * ``"max_call"``      — ``max(<call>, N)``
       * ``"compare_le"``    — ``var <= N``
       * ``"compare_lt"``    — ``var < N``
       * ``"compare_ge"``    — ``var >= N``  (lower bound; less interesting
                                              but recorded)
       * ``"compare_range"`` — ``0 < var <= N`` (the retry-after exact pattern)
    """

    cap_value: float
    """The numeric literal that bounds the value. For min/max:
    the literal argument. For compares: the literal on the
    non-variable side. Cap values are unbound on top — a cap at
    int.MAX_SIZE wouldn't be a real cap, but we don't filter here;
    the consumer (orchestrator suppression block) does the
    attack-class-aware threshold check.
    """


#: Attack classes whose exploit story REQUIRES unbounded magnitude.
#: A downstream cap that bounds the value invalidates the exploit
#: claim for these classes — suppression applies.
#:
#: Classes NOT in this set are exempt from cap-based suppression
#: because their exploit doesn't depend on numeric magnitude:
#:
#:   * ssrf / open_redirect   — about WHERE we connect, not how big
#:   * path_traversal         — about WHICH file, not size
#:   * code_injection         — about WHAT runs, not magnitude
#:   * deserialization        — about parser confusion, not value bounds
#:   * sql_injection          — about WHICH query, not size
#:   * command_injection      — about WHAT command, not magnitude
_CAP_RELEVANT_ATTACK_CLASSES: frozenset[str] = frozenset(
    {
        "data_exfiltration",        # CWE-200 amplification (the retry-after class)
        "business_logic_flaw",      # CWE-840 abuse via amplification
        "denial_of_service",        # CWE-400 unbounded growth
        "race_condition",           # CWE-362 amplification window
        # crypto_weakness — usually about algorithm not magnitude;
        # NOT included.
    }
)


#: Attack-class-specific minimum cap thresholds. A cap BELOW this
#: value is meaningful (it kills the amplification potential); a cap
#: AT or ABOVE this value isn't really a cap for the purpose of the
#: exploit.
#:
#: Numbers calibrated to the attack class:
#:   * data_exfiltration (CWE-200): retry / sleep amplification —
#:     anything ≤ 120 seconds bounds the exploit usefully.
#:   * business_logic_flaw / denial_of_service: 600 seconds (10 min)
#:     — beyond that you're effectively unbounded for most operator
#:     concerns. Tunable in production.
_ATTACK_CLASS_CAP_THRESHOLDS: dict[str, float] = {
    "data_exfiltration": 120.0,
    "business_logic_flaw": 600.0,
    "denial_of_service": 600.0,
    "race_condition": 600.0,
}


def _numeric_literal(node: ast.AST) -> float | None:
    """Return the numeric value of an AST node iff it's an int / float
    / negated int-float literal. Otherwise None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return float(node.value)
    # Unary minus on a literal: -60
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, (int, float))
        and not isinstance(node.operand.value, bool)
    ):
        return -float(node.operand.value)
    return None


def _ast_call_name(call: ast.Call) -> str | None:
    """Bare callable name from a ``Call`` node. ``f()`` → ``"f"``.
    ``self.f()`` / ``a.b.c.f()`` → ``"f"`` (we match on tail name only;
    method-vs-function isn't important for cap matching). Returns None
    for indirect/computed calls (``getattr(...)()``, ``(lambda ...)()``).
    """
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def find_downstream_caps(source: str) -> list[DownstreamCap]:
    """Scan ``source`` (a Python file's text) and return every same-file
    downstream cap detected.

    Robust against partial / unparseable sources — returns ``[]`` on
    SyntaxError so callers never have to wrap in try/except.

    Walks each top-level FunctionDef / AsyncFunctionDef (including
    those nested in classes) and looks for two pattern families:

      A. **Inline bound:** ``min(call(), N)`` / ``max(call(), N)``.
         Doesn't require the call's return to be assigned anywhere —
         the bound is right there in the expression.

      B. **Assign + compare bound:** ``var = call(); ... <compare on
         var with literal>``. The visitor stitches the two together
         within a single function body. Used for the retry-after
         pattern: ``retry_after = self._parse_retry_after_header(...)``
         + ``if retry_after is not None and 0 < retry_after <= 60:``.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    caps: list[DownstreamCap] = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        caps.extend(_find_caps_in_function(func))
    return caps


def _find_caps_in_function(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[DownstreamCap]:
    caps: list[DownstreamCap] = []
    capper_name = func.name

    # ── Pattern A: inline min/max wrap ───────────────────────────────────
    for node in ast.walk(func):
        # Skip nested function defs so the visitor's scope is THIS function.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not func:
            continue
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("min", "max")
            and len(node.args) >= 2
        ):
            wrap_pattern = "min_call" if node.func.id == "min" else "max_call"
            # For each call-argument inside min/max, find a sibling
            # literal — that pairing constitutes a cap.
            for arg_idx, arg in enumerate(node.args):
                if not isinstance(arg, ast.Call):
                    continue
                called = _ast_call_name(arg)
                if not called:
                    continue
                for other_idx, other in enumerate(node.args):
                    if other_idx == arg_idx:
                        continue
                    cap_val = _numeric_literal(other)
                    if cap_val is None:
                        continue
                    caps.append(
                        DownstreamCap(
                            capped_function=called,
                            capper_function=capper_name,
                            capper_line=node.lineno,
                            pattern=wrap_pattern,
                            cap_value=cap_val,
                        )
                    )

    # ── Pattern B: assign + compare bound ────────────────────────────────
    # Build a var → called-function map from same-function assignments.
    var_to_called: dict[str, tuple[str, int]] = {}
    for node in ast.walk(func):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not func:
            continue
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
        ):
            called = _ast_call_name(node.value)
            if called:
                var_to_called[node.targets[0].id] = (called, node.lineno)

    if not var_to_called:
        return caps

    # Scan Compare nodes for ``var <op> literal`` or ``literal <op> var
    # <op> literal`` (range).
    for node in ast.walk(func):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not func:
            continue
        if not isinstance(node, ast.Compare):
            continue
        # Collect (operand, position) pairs.
        operands = [node.left] + list(node.comparators)
        # Match operators (the comparison chain has len(comparators) ops).
        ops = list(node.ops)

        # Find vars present in the chain.
        for var_idx, var_op in enumerate(operands):
            if not (isinstance(var_op, ast.Name) and var_op.id in var_to_called):
                continue
            called, _ = var_to_called[var_op.id]

            # Walk neighbouring positions for literal bounds.
            for other_idx, other in enumerate(operands):
                if other_idx == var_idx:
                    continue
                cap_val = _numeric_literal(other)
                if cap_val is None:
                    continue
                # Identify the operator between var and the literal.
                # The chain shape: operands[i] ops[i] operands[i+1].
                if var_idx < other_idx:
                    rel_op = ops[var_idx]
                else:
                    rel_op = ops[other_idx]

                if isinstance(rel_op, ast.LtE):
                    pattern = "compare_le"
                elif isinstance(rel_op, ast.Lt):
                    pattern = "compare_lt"
                elif isinstance(rel_op, ast.GtE):
                    pattern = "compare_ge"
                elif isinstance(rel_op, ast.Gt):
                    # var > literal (literal is lower bound; not a cap on top).
                    # Still useful info but we don't suppress on it.
                    pattern = "compare_gt"
                else:
                    continue  # not a magnitude bound (Eq / NotEq / Is / etc.)

                # Range pattern: 0 < var <= 60 — both bounds present.
                if len(operands) == 3 and isinstance(operands[1], ast.Name) and operands[1].id == var_op.id:
                    lower = _numeric_literal(operands[0])
                    upper = _numeric_literal(operands[2])
                    if lower is not None and upper is not None:
                        # Use the upper bound as the cap.
                        caps.append(
                            DownstreamCap(
                                capped_function=called,
                                capper_function=capper_name,
                                capper_line=node.lineno,
                                pattern="compare_range",
                                cap_value=upper,
                            )
                        )
                        break  # don't double-record this Compare
                caps.append(
                    DownstreamCap(
                        capped_function=called,
                        capper_function=capper_name,
                        capper_line=node.lineno,
                        pattern=pattern,
                        cap_value=cap_val,
                    )
                )
    return caps


def find_capping_for_function(
    function_name: str,
    attack_class: str,
    caps: list[DownstreamCap],
) -> DownstreamCap | None:
    """Return the most-restrictive cap that should suppress a probe
    finding on ``function_name`` of ``attack_class``, or None if no
    cap applies.

    Logic:

      1. Attack-class gate: if ``attack_class`` is not in
         :data:`_CAP_RELEVANT_ATTACK_CLASSES`, return None. The
         exploit doesn't depend on magnitude.
      2. Function-name match: skip caps where ``capped_function`` !=
         ``function_name`` (tail-name comparison; supports
         ``self.f()``, ``ClassName.f()``).
      3. Pattern gate: only ``min_call``, ``max_call``, ``compare_le``,
         ``compare_lt``, ``compare_range`` patterns are real
         magnitude caps (skip ``compare_ge`` / ``compare_gt`` —
         those are lower bounds, not upper).
      4. Threshold check: if cap_value is at or above the attack-
         class threshold, the "cap" doesn't bound enough to
         invalidate the exploit. Return None.
      5. Return the most-restrictive (lowest cap_value) cap that
         survives all gates.
    """
    if attack_class not in _CAP_RELEVANT_ATTACK_CLASSES:
        return None
    threshold = _ATTACK_CLASS_CAP_THRESHOLDS.get(attack_class)
    if threshold is None:
        return None

    # Tail-name match: "self._parse_x" / "_parse_x" / "Foo._parse_x"
    # all resolve to "_parse_x" via _ast_call_name. We match on the
    # tail of the dotted function_name supplied by the probe candidate.
    tail = function_name.rsplit(".", 1)[-1]

    candidates = [
        c
        for c in caps
        if c.capped_function == tail
        and c.pattern in ("min_call", "max_call", "compare_le", "compare_lt", "compare_range")
        and c.cap_value < threshold
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda c: c.cap_value)
