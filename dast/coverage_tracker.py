"""DAST coverage tracker (v1.9.1) — dedupe Phase B+ / Phase 3 / Phase A
probes against (function, attack_class) pairs that earlier stages have
already claimed or confirmed.

Motivation (the e2e scan that surfaced this):

  Stage order inside ``run_dast``:
      1. Phase B+ runtime probe  (model-driven, generates own inputs)
      2. Phase 3 adversarial loop (model-driven, has B+ context)
      3. Phase B chain probes     (multi-step chain hypotheses)
      4. Phase A iter loop        (verifies L1 hypotheses one-by-one)

  Pre-v1.9.1 each stage worked in isolation:
    * Phase B+ probed every public callable it saw — including
      functions L1 had already flagged with high confidence.
    * Phase 3 then re-probed the same functions, getting independent
      confirmation but no new information.
    * Phase A verified L1's hypotheses against the same functions yet
      again, paying for the sandbox call even when B+ / 3 had already
      produced grounded runtime evidence.

  The e2e validation scan (samples/v1_9_dast_e2e_verification.py)
  showed 11 HRP confirmations across 3 functions: 9 of them were
  redundant against L1's findings (Phase B+ probed run_user_command
  three times for CWE-78 right after L1 said CWE-78 at run_user_command
  with conf=0.97). Same story for compute_expression and write_user_log.
  Phase 3 then re-confirmed two of those for the third time.

Production behavior (default ON):

  * **Pre-Phase B+**: tracker is populated from L1 vulnerabilities with
    confidence ≥ ``L1_TRUST_THRESHOLD`` (0.6 by default). When Phase B+'s
    candidate generator returns probe candidates, any candidate matching
    a tracker entry is filtered out BEFORE the sandbox call. Phase B+'s
    fixed budget (MAX_CANDIDATES × MAX_INPUTS_PER_CANDIDATE) then goes
    to NEW callables / NEW attack classes — directly answering the
    "more chances to find new exploits" goal.

  * **After Phase B+ confirms**: each confirmed HRP_* adds its
    ``(function, attack_class)`` to the tracker with source=phase_b.
    Phase 3's candidate generator then filters against the enlarged
    tracker.

  * **After Phase 3 confirms**: same — HRP_AL_* entries flow back.
    Phase A's iter loop then checks each L1 hypothesis: if a tracker
    entry covers it via a B+/3 confirmation, Phase A writes a
    synthetic ``confirmed`` journal record citing the runtime
    evidence + skips the sandbox call.

  * **Skip telemetry**: every suppression is counted into
    ``IterationStats.coverage_dedupe_suppressed`` and surfaced in the
    operator-facing iteration summary. Operators can see "Phase B+
    skipped 5 probes already covered by L1, Phase 3 skipped 3 already
    covered by B+, Phase A skipped 2 already covered by B+/3."

Failure modes / fail-soft posture:

  * **Function-name extraction fails**: L1 hypothesis dicts don't have
    a clean ``function_name`` field — we extract it best-effort from
    ``code_snippet`` / ``data_flow_trace``. If extraction returns no
    name, the hypothesis is recorded with ``function="?"`` and never
    matches a candidate — equivalent to "no dedupe for this finding."
    Safer than aggressive matching by attack_class alone (which would
    block Phase B+ from probing OTHER functions for the same CWE).

  * **Attack class mismatch**: L1 uses ``type`` strings like
    ``command_injection``; Phase B+ candidates use ``attack_class``
    strings of the same shape — we normalize both via
    :func:`_normalize_attack_class`. Unknown values pass through
    unchanged so future-added attack classes don't silently break.

  * **Operator override**: ``--disable-coverage-dedupe`` (config
    ``enable_coverage_dedupe=False``) restores the v1.9.0 behavior of
    every stage running unfiltered. Use when investigating a
    suspected dedupe false-positive.

The tracker is process-local — one instance per ``run_dast`` call.
Never persisted across scans.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("argus.dast.coverage_tracker")


#: L1 findings with confidence below this threshold are NOT pre-loaded
#: into the tracker. We only dedupe against L1 claims the model itself
#: was confident about; low-confidence findings benefit from Phase B+'s
#: independent confirmation. Conservative default — operators wanting
#: more dedupe (and more new-exploit budget) can lower this.
L1_TRUST_THRESHOLD: float = 0.6


#: Aliases for attack-class normalization. L1's ``type`` strings and
#: Phase B+'s ``attack_class`` strings mostly match, but a few synonyms
#: appear in the wild. Map them to a canonical form here so dedupe
#: matches them correctly.
_ATTACK_CLASS_ALIASES: dict[str, str] = {
    # CWE-94 vs CWE-95 — both are "code injection" in our taxonomy
    "code_injection": "code_injection",
    "dynamic_code_eval": "code_injection",
    # CWE-77 / CWE-78 — command injection family
    "command_injection": "command_injection",
    "os_command_injection": "command_injection",
    "shell_injection": "command_injection",
    # CWE-22 / CWE-73 — path family
    "path_traversal": "path_traversal",
    "arbitrary_file_write": "path_traversal",
    "directory_traversal": "path_traversal",
    # CWE-918 — SSRF
    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    # CWE-502 — deserialization
    "insecure_deserialization": "insecure_deserialization",
    "deserialization": "insecure_deserialization",
    "pickle_loads": "insecure_deserialization",
    # CWE-79 — XSS
    "xss": "xss",
    "cross_site_scripting": "xss",
}


def _normalize_attack_class(value: str | None) -> str:
    """Map a raw attack-class string (from L1's ``type``, Phase B+'s
    ``attack_class``, or any other source) to its canonical form.

    Unknown values pass through lower-cased so future-added classes
    don't break dedupe — they just match themselves.
    """
    if not value:
        return ""
    lower = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    return _ATTACK_CLASS_ALIASES.get(lower, lower)


# Regex patterns for extracting function names from L1 finding code
# snippets / data flow traces. Best-effort — covers the common cases
# the test corpus surfaces. When none match we return "" and skip
# dedupe for that finding.
_FUNC_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
_FUNC_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]+)\s*\(")
_ARROW_FLOW_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]+)\s*(?:\(|→|->)")


def _extract_function_name(hypothesis_or_finding: dict[str, Any]) -> str:
    """Best-effort extraction of a function name from an L1 hypothesis
    or DAST finding dict. Returns ``""`` when no usable name found.

    Search order (most reliable first):
      1. ``function_name`` field if present (Phase B+ findings carry it
         explicitly; some L1 hypotheses might too).
      2. ``code_snippet`` — look for ``def <name>(`` at the start of a
         line (definition site).
      3. ``code_snippet`` — look for the first ``<name>(`` call
         pattern. Less reliable; identifies the called function not
         the enclosing one.
      4. ``data_flow_trace`` — look for ``<name>(`` or ``<name> →``
         tokens (the trace string often names sink callees).
      5. ``code_snippet`` — if it's a single bare identifier, treat it
         as the function name.

    Output is the bare name without parens / args. We don't try to
    distinguish bound methods from free functions — the dedupe key
    is just the name as Phase B+ would also see it.
    """
    if not isinstance(hypothesis_or_finding, dict):
        return ""

    # Source 1: explicit field — Phase B+ probe findings always have it
    explicit = hypothesis_or_finding.get("function_name")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    snippet = str(hypothesis_or_finding.get("code_snippet") or "")
    flow = str(hypothesis_or_finding.get("data_flow_trace") or "")

    # Source 2: def-site match in the code snippet
    m = _FUNC_DEF_RE.search(snippet)
    if m:
        return m.group(1)

    # Source 3: first function-call pattern in the code snippet
    # Filter to skip common shell-builtin-style words that would
    # match the regex but aren't function names.
    _SKIP_TOKENS = {
        "if", "else", "elif", "for", "while", "return", "with", "try",
        "except", "lambda", "yield", "await", "async", "def", "class",
        "import", "from", "as", "in", "is", "not", "and", "or", "self",
        "True", "False", "None", "print",
    }
    for cand in _FUNC_CALL_RE.findall(snippet):
        if cand and cand not in _SKIP_TOKENS:
            return cand

    # Source 4: data flow trace — use the same call-pattern regex
    # (not the arrow form, which picks up variable names on the left
    # of ``url → urlopen(url)``). The call-with-parens form is the
    # most reliable signal of a function name in the trace text.
    for cand in _FUNC_CALL_RE.findall(flow):
        if cand and cand not in _SKIP_TOKENS:
            return cand

    # Source 5: bare identifier
    s = snippet.strip()
    if s and s.isidentifier():
        return s

    return ""


@dataclass(frozen=True)
class CoverageEntry:
    """One ``(function, attack_class)`` coverage record."""

    function: str
    attack_class: str
    # Where the confirmation came from. One of:
    #   * "l1"        — L1 finding pre-loaded into the tracker
    #   * "phase_b"   — Phase B+ runtime probe HRP_* confirmation
    #   * "phase_3"   — Phase 3 adversarial-loop HRP_AL_* confirmation
    #   * "phase_b_chain" — Phase B chain HRP_C* confirmation
    source: str
    #: The originating finding's ID (H001, HRP_0_0, etc.) so synthetic
    #: journal entries we generate during dedupe can cite it.
    finding_id: str
    #: Optional CWE for human-readable telemetry. Not used in matching
    #: (matching is on ``attack_class`` only after normalization).
    cwe: str = ""
    #: Optional runtime evidence summary, copied from the source
    #: finding. Lets Phase A synthesize a confirmed journal entry
    #: that cites real evidence rather than fabricating one.
    runtime_evidence: str = ""


@dataclass
class CoverageTracker:
    """Per-scan dedupe tracker. Maps ``(function, attack_class)`` →
    :class:`CoverageEntry`. Lookup is O(1) on the canonical
    (lower-cased + alias-normalized) attack class string.
    """

    #: Underlying storage. Keyed by tuple ``(function, normalized_attack_class)``.
    _entries: dict[tuple[str, str], CoverageEntry] = field(default_factory=dict)
    #: Telemetry: number of probe-candidate suppressions, by source
    #: stage. Phase B+ counts go up when L1 entries suppress B+ probes;
    #: Phase 3 counts go up when L1/B+ entries suppress 3 probes; and
    #: so on. Exposed via ``stats()`` for the iteration summary.
    _suppressions_by_stage: dict[str, int] = field(default_factory=dict)
    #: Operator-visible flag. When False, all dedupe operations no-op
    #: and ``is_covered`` always returns None. Lets ``--disable-
    #: coverage-dedupe`` restore the v1.9.0 baseline behavior.
    enabled: bool = True

    def add(
        self,
        *,
        function: str,
        attack_class: str,
        source: str,
        finding_id: str,
        cwe: str = "",
        runtime_evidence: str = "",
    ) -> bool:
        """Record a coverage entry. Returns True if newly added,
        False if the key already existed (no overwrite). No-op when
        ``function`` is empty (failed extraction → can't dedupe).
        """
        if not function or not attack_class:
            return False
        key = (function, _normalize_attack_class(attack_class))
        if key in self._entries:
            return False
        self._entries[key] = CoverageEntry(
            function=function,
            attack_class=_normalize_attack_class(attack_class),
            source=source,
            finding_id=finding_id,
            cwe=cwe,
            runtime_evidence=runtime_evidence,
        )
        return True

    def is_covered(
        self, *, function: str, attack_class: str
    ) -> CoverageEntry | None:
        """Return the matching :class:`CoverageEntry` if this
        ``(function, attack_class)`` is already covered. Returns
        ``None`` when not covered, when dedupe is disabled, or when
        inputs are empty.
        """
        if not self.enabled or not function or not attack_class:
            return None
        key = (function, _normalize_attack_class(attack_class))
        return self._entries.get(key)

    def record_suppression(self, stage: str) -> None:
        """Increment the suppression counter for a stage. Called by
        the candidate-filter sites when they skip a probe."""
        self._suppressions_by_stage[stage] = (
            self._suppressions_by_stage.get(stage, 0) + 1
        )

    def populate_from_l1_findings(
        self,
        l1_vulnerabilities: list[dict[str, Any]] | None,
        *,
        min_confidence: float = L1_TRUST_THRESHOLD,
    ) -> int:
        """Seed the tracker from L1's high-confidence findings.

        Called once at ``run_dast`` entry, BEFORE Phase B+ fires.
        Phase B+ then sees an already-populated tracker and skips
        candidates matching L1's claims, directing its budget at
        new exploits.

        Returns the number of entries added. Failure modes:
          * confidence < threshold → skip silently
          * function name extraction fails → skip silently
          * empty / missing attack class → skip silently

        Conservative on purpose: anything that fails to extract
        cleanly just doesn't dedupe (= Phase B+ runs unconstrained
        for that finding).
        """
        if not l1_vulnerabilities or not self.enabled:
            return 0
        added = 0
        for i, v in enumerate(l1_vulnerabilities):
            if not isinstance(v, dict):
                continue
            conf_raw = v.get("confidence", 0)
            try:
                conf = float(conf_raw or 0)
            except (TypeError, ValueError):
                conf = 0.0
            if conf < min_confidence:
                continue
            # Hypothesis dicts produced by dast.runner.
            # _scan_result_to_l1_output use ``finding_type``;
            # ScanResult.vulnerabilities entries use ``type``. Read
            # either so the same populator handles both call sites.
            attack = v.get("finding_type") or v.get("type") or ""
            if not attack:
                continue
            func = _extract_function_name(v)
            if not func:
                continue
            finding_id = f"H{i + 1:03d}"
            if self.add(
                function=func,
                attack_class=attack,
                source="l1",
                finding_id=finding_id,
                cwe=str(v.get("cwe") or ""),
                runtime_evidence="",
            ):
                added += 1
        if added:
            log.info(
                "CoverageTracker: pre-populated %d entries from L1 "
                "findings (conf >= %.2f)",
                added,
                min_confidence,
            )
        return added

    def stats(self) -> dict[str, Any]:
        """Operator-facing telemetry dict. Surface in iteration
        summary so users see WHY DAST cost less / found more.
        """
        entries_by_source: dict[str, int] = {}
        for entry in self._entries.values():
            entries_by_source[entry.source] = (
                entries_by_source.get(entry.source, 0) + 1
            )
        return {
            "enabled": self.enabled,
            "n_entries": len(self._entries),
            "entries_by_source": entries_by_source,
            "suppressions_by_stage": dict(self._suppressions_by_stage),
        }

    def entries(self) -> list[CoverageEntry]:
        """List of all coverage entries — for debugging / inspection.
        Returned in insertion order (Python 3.7+ dict guarantee)."""
        return list(self._entries.values())


__all__ = [
    "L1_TRUST_THRESHOLD",
    "CoverageEntry",
    "CoverageTracker",
    "_extract_function_name",
    "_normalize_attack_class",
]
