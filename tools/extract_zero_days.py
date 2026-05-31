"""Extract Phase 3 zero-day findings + generate copy-pasteable Gemini
cross-validation prompts.

After an ``argus scan-repo`` run, this tool reads the output JSON,
filters every file's findings to the **zero-day class** (Phase 3
Stage 2 CONFIRMED hypotheses whose attack_class is NOT in L1's
findings for that file), and writes one ``.txt`` file per zero-day
into ``<output-dir>/`` ready for copy-paste into Gemini 3.1 Pro.

Each emitted ``.txt`` contains:
  * The target file's full source code (truncated at MAX_SOURCE_BYTES
    if necessary)
  * The Phase 3 hypothesis details — function_name, attack_class,
    rationale, args/kwargs, expected_observable, rejection_signature
  * Sandbox trace summary — oracle, judge verdict + reasoning, runtime
    evidence (the why-it-was-confirmed signal)
  * The exact "evaluate this claim" task framing used by Argus's
    internal cross-validation (mirrors ``dast/cross_validation.py``)

The prompt is non-leading — Gemini is asked to refute, refine, or
confirm with reasoning, NOT rubber-stamp.

Usage::

    uv run python -m tools.extract_zero_days \\
        .argus_local/mcp_eval_v11.json \\
        --output-dir .argus_local/zero_day_prompts/

Output: one ``<filename>_<finding_id>.txt`` per zero-day, plus a
``_summary.md`` index listing what was extracted from where.

Behavior:
  * If a file has NO Phase 3 confirmed outcomes, skip silently.
  * If a confirmed outcome's attack_class IS already in L1's
    vulnerabilities for that file, skip (not a zero-day — DAST just
    re-confirmed an L1 finding).
  * If the scan output is a repo-scan with multiple files, iterate
    them all.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dast.cross_validation import (
    MAX_SOURCE_BYTES,
    build_cross_validation_prompt,
)


def _l1_attack_classes_for_file(file_result: dict[str, Any]) -> set[str]:
    """Return the set of attack-class signals already covered by L1
    for one file.

    L1 emits findings keyed by CWE; Phase 3 emits hypotheses keyed by
    attack_class. To correlate, we normalise both sides to the
    lowercased free-text attack-class label that Phase 3 uses and
    that Argus's prompts also embed in L1 finding descriptions.
    """
    covered: set[str] = set()
    for v in file_result.get("vulnerabilities") or []:
        # Argus L1 emits attack_class explicitly on Phase 3-emitted
        # findings; for pure L1 findings we fall back to the CWE
        # number which Phase 3 also references.
        ac = str(v.get("attack_class") or "").lower().strip()
        if ac:
            covered.add(ac)
        cwe = str(v.get("cwe") or v.get("cwe_id") or "").lower().strip()
        if cwe:
            covered.add(cwe)
            # Also store the bare number (e.g., "918" without "cwe-")
            if cwe.startswith("cwe-"):
                covered.add(cwe[len("cwe-") :])
        # The L1 schema uses ``type`` for the bug-class label (e.g.,
        # type="ssrf"); older schemas used ``title``. Capture both.
        type_field = str(v.get("type") or "").lower().strip()
        if type_field:
            covered.add(type_field)
            covered.add(type_field.replace("-", "_"))
        # Bug-class keywords from the finding's title / description so
        # an L1 finding worded as "SSRF" still suppresses a Phase 3
        # hypothesis with attack_class="ssrf".
        title = str(v.get("title") or v.get("type") or "").lower()
        for kw in (
            "ssrf",
            "path_traversal",
            "path-traversal",
            "command_injection",
            "command-injection",
            "code_injection",
            "code-injection",
            "sql_injection",
            "sql-injection",
            "deserialization",
            "prompt_injection",
            "prompt-injection",
            "race_condition",
            "race-condition",
            "data_exfiltration",
            "data-exfiltration",
        ):
            if kw in title:
                covered.add(kw.replace("-", "_"))
    return covered


def _is_zero_day(outcome: dict[str, Any], l1_covered: set[str]) -> bool:
    """A zero-day class outcome is one that:
      * Has Phase 3 verdict == CONFIRMED (not refuted, blocked, probe_observed)
      * Has an attack_class that's NOT already covered by L1's findings
    """
    if str(outcome.get("verdict", "")).lower() != "confirmed":
        return False
    hyp = outcome.get("hypothesis") or {}
    ac = str(hyp.get("attack_class") or "").lower().strip()
    if not ac:
        return False
    # Normalise dashes/underscores for matching
    ac_norm = ac.replace("-", "_")
    if ac in l1_covered or ac_norm in l1_covered:
        return False
    return True


def _is_disclosure_worthy_l1(
    vuln: dict[str, Any],
    pf_status: str,
    min_sev_rank: int = 3,
) -> bool:
    """A L1 finding worth flagging for Gemini cross-validation.

    Criteria:
      * severity ``high`` or ``critical`` (we don't want medium / low
        noise drowning the disclosure backlog)
      * CWE present (without a CWE we can't tell what bug class —
        skip to keep prompts targeted)
      * Phase A per-finding status is ``CONFIRMED`` — i.e., the L1
        claim was RUNTIME-CONFIRMED by Argus's Phase A. That's the
        primary zero-day signal: a finding that L1 emitted AND
        Phase A validated against the running code. NOT_TESTED /
        BLOCKED / UNREACHED don't qualify — those are L1 claims
        without runtime grounding (still real bugs sometimes, but
        not the "Argus caught it" disclosure framing).

    L1 + Phase A CONFIRMED = the headline class of finding for
    disclosure pipelines. Phase 3 Stage 2 confirmations on NEW
    attack classes (not in L1) are a separate, bonus signal —
    handled by ``_is_zero_day`` elsewhere in this module.
    """
    sev = str(vuln.get("severity") or "").lower().strip()
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if sev_rank.get(sev, 0) < min_sev_rank:
        return False
    cwe = vuln.get("cwe") or vuln.get("cwe_id") or ""
    if not cwe:
        return False
    if str(pf_status or "").strip().upper() != "CONFIRMED":
        return False
    return True


def _outcomes_iter(file_result: dict[str, Any]):
    """Yield Phase 3 Stage 2 outcomes (dict form) from a file's scan
    result. Tolerant of the various places the field can live across
    Argus versions."""
    p3 = file_result.get("phase_3_loop") or {}
    # v1.8+ schema: outcomes at top level
    for o in p3.get("outcomes") or []:
        if isinstance(o, dict):
            yield o
    # Older schema: outcomes nested under turns
    for t in p3.get("turns") or []:
        if isinstance(t, dict):
            for o in t.get("outcomes") or []:
                if isinstance(o, dict):
                    yield o


def _safe_filename(s: str) -> str:
    """Sanitise a string for use as a filename component."""
    keep = []
    for ch in s:
        if ch.isalnum() or ch in ("-", "_", "."):
            keep.append(ch)
        else:
            keep.append("_")
    return "".join(keep).strip("_") or "unnamed"


def _normalise_file_results(scan_output: Any) -> list[dict[str, Any]]:
    """Yield per-file result dicts from either a single-file scan JSON
    or a scan-repo JSON envelope. Returns a list (not a generator) so
    we can count + sort upstream.
    """
    if isinstance(scan_output, list):
        return [x for x in scan_output if isinstance(x, dict)]
    if not isinstance(scan_output, dict):
        return []
    # scan-repo envelope shapes we've seen across versions:
    for key in ("files", "results", "file_results", "scans"):
        v = scan_output.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    # Single-file scan: the dict IS the file result.
    if "vulnerabilities" in scan_output or "phase_3_loop" in scan_output:
        return [scan_output]
    return []


def _emit_prompt(
    *,
    file_result: dict[str, Any],
    outcome: dict[str, Any],
    output_dir: Path,
) -> Path:
    """Build the Gemini prompt for one zero-day outcome and write it
    to disk. Returns the written path."""
    hypothesis = outcome.get("hypothesis") or {}
    file_name = str(file_result.get("filename") or "unknown")
    # File source — prefer raw source_text if present, else decode
    # original_bytes, else empty string.
    source = (
        file_result.get("source_text")
        or file_result.get("source")
        or ""
    )
    if not source and isinstance(file_result.get("original_bytes"), str):
        import base64  # noqa: PLC0415

        try:
            source = base64.b64decode(file_result["original_bytes"]).decode(
                "utf-8", errors="replace"
            )
        except Exception:  # noqa: BLE001
            source = ""

    # File purpose — Argus's L1 emits ``file_intent_analysis.purpose``
    # which is exactly the human-readable framing Gemini needs.
    fia = file_result.get("file_intent_analysis") or {}
    file_purpose = str(fia.get("purpose") or "")

    # Build the trace summary — same shape cross_validation.py uses.
    trace_summary = {
        "exit_code": 0 if outcome.get("verdict") == "confirmed" else 1,
        "elapsed_ms": outcome.get("elapsed_ms", 0),
        "parsed_result": outcome.get("parsed_result") or {},
        "side_effects": outcome.get("side_effects") or {},
    }

    prompt = build_cross_validation_prompt(
        hypothesis=hypothesis,
        trace=trace_summary,
        interpreter_oracle_type=str(outcome.get("oracle_type") or ""),
        interpreter_runtime_evidence=str(outcome.get("runtime_evidence") or ""),
        judge_verdict=str(outcome.get("judge_verdict") or ""),
        judge_reasoning=str(outcome.get("judge_reasoning") or ""),
        file_source=source,
        file_name=file_name,
        file_purpose=file_purpose,
    )

    # Filename: <file>_<function>_<attack_class>.txt
    fn_part = _safe_filename(Path(file_name).stem)[:40]
    fun_part = _safe_filename(str(hypothesis.get("function_name") or "anon"))[:30]
    cls_part = _safe_filename(str(hypothesis.get("attack_class") or "unk"))[:24]
    out_path = output_dir / f"{fn_part}__{fun_part}__{cls_part}.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(prompt, encoding="utf-8")
    return out_path


def _emit_l1_prompt(
    *,
    file_result: dict[str, Any],
    vuln: dict[str, Any],
    output_dir: Path,
) -> Path:
    """Build a Gemini cross-validation prompt for a high/critical L1
    finding that Phase 3 didn't runtime-confirm.

    Format mirrors ``_emit_prompt`` but the "hypothesis" is the L1
    finding (no runtime trace), and the prompt frames the task as
    "Argus's L1 cascade flagged this static — Phase 3 couldn't reach
    it at runtime due to Stage 1 discovery depth — independently
    judge if it's real."

    These prompts are the DISCLOSURE-READY signal for files where
    Stage 1 doesn't reach the attack surface (e.g., LangChain.js's
    class-based tools where the constructor takes complex args and
    the actual exec path is in instance methods called post-
    construction). Gemini reads the source + L1's claim + the
    static-analysis context and renders an independent verdict.
    """
    file_name = str(file_result.get("filename") or "unknown")
    source = file_result.get("source_text") or file_result.get("source") or ""
    if not source and isinstance(file_result.get("original_bytes"), str):
        import base64  # noqa: PLC0415

        try:
            source = base64.b64decode(file_result["original_bytes"]).decode(
                "utf-8", errors="replace"
            )
        except Exception:  # noqa: BLE001
            source = ""

    fia = file_result.get("file_intent_analysis") or {}
    file_purpose = str(fia.get("purpose") or "")

    cwe = str(vuln.get("cwe") or vuln.get("cwe_id") or "")
    sev = str(vuln.get("severity") or "")
    line = str(vuln.get("line") or vuln.get("line_number") or "")
    title = str(vuln.get("title") or "")
    description = str(vuln.get("description") or vuln.get("reason") or "")
    code_snippet = str(vuln.get("code") or "")
    impact = str(vuln.get("impact") or "")
    attack_class = str(vuln.get("attack_class") or "")
    poc = str(vuln.get("proof_of_concept") or "")
    runtime_evidence = str(vuln.get("runtime_evidence") or "")
    confidence = vuln.get("confidence")

    # Truncate file source if oversized — bound prompt cost.
    src_bytes = source.encode("utf-8", errors="replace")
    truncated = False
    if len(src_bytes) > MAX_SOURCE_BYTES:
        source = src_bytes[:MAX_SOURCE_BYTES].decode("utf-8", errors="replace")
        truncated = True

    truncation_note = ""
    if truncated:
        truncation_note = (
            f"\n[...source truncated at {MAX_SOURCE_BYTES} bytes — "
            f"full file is {len(src_bytes)} bytes total]\n"
        )

    purpose_block = ""
    if file_purpose:
        purpose_block = f"\n## File purpose (Argus's analysis)\n\n{file_purpose}\n"

    poc_block = ""
    if poc:
        poc_block = (
            "\n## Phase A runtime proof-of-concept (the input pattern that "
            "triggered the bug)\n\n"
            f"{poc}\n"
        )
    evidence_block = ""
    if runtime_evidence:
        evidence_block = (
            "\n## Phase A runtime evidence (what the sandbox observed)\n\n"
            f"{runtime_evidence}\n"
        )
    confidence_str = f"{confidence}" if confidence is not None else "(not set)"

    prompt = (
        "You are a senior application-security engineer doing independent\n"
        "second-opinion review on a finding produced by an automated\n"
        "code-scanning tool (Argus). The tool's L1 cascade (Sonnet 4.6 +\n"
        "Opus 4.6 with deep-thinking) flagged this as a real vulnerability\n"
        "via static analysis. The tool's Phase A runtime layer then\n"
        "RECONSTRUCTED the data-flow path in a microVM sandbox and\n"
        "OBSERVED the bug execute end-to-end (status: CONFIRMED).\n"
        "\n"
        "Your job is to either:\n"
        "  (a) confirm the finding is real and explain the concrete\n"
        "      exploit chain in your own words;\n"
        "  (b) refute it — explain why it's a false positive despite the\n"
        "      runtime evidence (e.g., the harness is unrealistic, the\n"
        "      attack requires misconfiguration the operator wouldn't do,\n"
        "      etc.);\n"
        "  (c) refine it — same root cause but different impact/severity\n"
        "      than what Argus claims.\n"
        "\n"
        "DO NOT pre-judge. Read the code, evaluate the claim, give your\n"
        "honest assessment. If the answer is 'this is the documented\n"
        "behavior and not a bug,' say so directly. Phase A's runtime\n"
        "evidence is strong but not infallible — the harness reconstructs\n"
        "the data path, which is closer to reality than pure static\n"
        "analysis but still synthetic.\n"
        "\n"
        f"## Target file: {file_name}\n"
        f"{purpose_block}"
        "\n"
        "## Full source code\n"
        "\n"
        "```\n"
        f"{source}\n"
        f"{truncation_note}"
        "```\n"
        "\n"
        "## Argus L1 finding (the static claim)\n"
        "\n"
        f"  cwe:           {cwe}\n"
        f"  severity:      {sev}\n"
        f"  line:          {line}\n"
        f"  attack_class:  {attack_class or '(not specified)'}\n"
        f"  title:         {title}\n"
        f"  confidence:    {confidence_str}\n"
        f"  description:   {description}\n"
        f"  impact:        {impact}\n"
        f"  code snippet:  {code_snippet[:240]}\n"
        f"{poc_block}"
        f"{evidence_block}"
        "\n"
        "## Your task\n"
        "\n"
        "Output structured JSON conforming to this shape:\n"
        "\n"
        "{\n"
        '  "gemini_verdict": "CONFIRMED" | "REFUTED" | "INCONCLUSIVE",\n'
        '  "gemini_reasoning": "<1-2 paragraphs explaining your verdict>",\n'
        '  "related_issues_surfaced": [<short paragraphs describing OTHER\n'
        '    vulnerabilities you noticed in the source while evaluating\n'
        '    this finding — these are NEW bugs Argus may have missed>],\n'
        '  "suggested_fix": "<concrete code-level fix if the finding\n'
        '    is real, empty if refuted>"\n'
        "}\n"
        "\n"
        "Reasoning principles:\n"
        "  * Read the actual code — don't trust the static-analysis\n"
        "    framing if it doesn't match what you see.\n"
        "  * For SSRF claims: is there URL validation? Does an attacker\n"
        "    control the URL? Can the response be exfiltrated back?\n"
        "  * For SQL-injection claims: is input sanitized? Are queries\n"
        "    parameterized? Can attacker-controlled string segments\n"
        "    reach the SQL execution path?\n"
        "  * For credential-exposure claims: is the secret actually\n"
        "    reachable in normal flow, or only via misuse the operator\n"
        "    would have to explicitly configure?\n"
        "  * For path-traversal claims: is the path validated against\n"
        "    a whitelist / canonicalised / restricted via chroot-style\n"
        "    bounding?\n"
        "  * If you see ADDITIONAL bugs the tool didn't surface, list\n"
        "    each in related_issues_surfaced — net-new contributions.\n"
    )

    # Filename: <file>__l1__<cwe>__<line>.txt
    fn_part = _safe_filename(Path(file_name).stem)[:40]
    cwe_part = _safe_filename(cwe)[:20]
    line_part = _safe_filename(line)[:8] or "L0"
    out_path = output_dir / f"{fn_part}__l1__{cwe_part}__L{line_part}.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(prompt, encoding="utf-8")
    return out_path


def _emit_summary(
    *,
    output_dir: Path,
    extracted: list[dict[str, Any]],
    extracted_l1: list[dict[str, Any]] | None = None,
    scanned_files: int,
    files_with_phase_3: int,
) -> Path:
    """Write a Markdown index of what was extracted, where, and from
    which target. Makes the output dir self-describing.

    Covers two disclosure classes:
      * Phase 3 Stage 2 zero-day class — runtime-confirmed NEW attack
        classes Argus surfaced that L1 missed.
      * L1 + Phase A CONFIRMED — high/critical L1 findings that Phase A
        runtime-confirmed against the running code. This is typically
        the PRIMARY disclosure signal — Phase 3 Stage 2 produces few/
        no NEW classes on mature codebases because Stage 1's discovery
        depth doesn't reach class-method attack surfaces.
    """
    extracted_l1 = extracted_l1 or []

    # mkdir even in the no-findings case so the summary lands
    # somewhere (caller can confirm "ran but nothing matched").
    output_dir.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# Argus disclosure prompts — Gemini cross-validation")
    lines.append("")
    lines.append(
        "Each ``.txt`` file in this directory is a copy-pasteable prompt "
        "for Gemini 3.1 Pro. Two classes are emitted:"
    )
    lines.append("")
    lines.append(
        "* **Phase 3 zero-day class** — Stage 2 runtime-CONFIRMED "
        "hypothesis on a NEW attack class L1 didn't surface. Rare on "
        "mature codebases, high signal when present."
    )
    lines.append(
        "* **L1 + Phase A CONFIRMED** — high/critical static finding from "
        "the L1 cascade (Sonnet + Opus deep-thinking) that Phase A "
        "runtime-confirmed. This is the primary disclosure-ready signal."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total files scanned: **{scanned_files}**")
    lines.append(f"- Files with Phase 3 outcomes: **{files_with_phase_3}**")
    lines.append(f"- Phase 3 zero-day class prompts: **{len(extracted)}**")
    lines.append(
        f"- L1 + Phase A CONFIRMED prompts: **{len(extracted_l1)}**"
    )
    lines.append("")
    if not extracted and not extracted_l1:
        lines.append("**No disclosure-worthy findings to validate.** L1 emitted")
        lines.append("no high/critical findings that Phase A runtime-confirmed,")
        lines.append("and Phase 3 Stage 2 found no NEW attack classes.")
        out = output_dir / "_summary.md"
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out

    if extracted_l1:
        lines.append("## L1 + Phase A CONFIRMED findings")
        lines.append("")
        lines.append(
            "These are the headline disclosures: L1 flagged them statically, "
            "Phase A runtime-confirmed them against actual code execution."
        )
        lines.append("")
        lines.append("| File | CWE | Severity | Title | Phase A | Prompt |")
        lines.append("|---|---|---|---|---|---|")
        for e in extracted_l1:
            title = str(e.get("title") or "")[:60]
            lines.append(
                f"| `{e['file_name']}` "
                f"| `{e['cwe']}` "
                f"| {e['severity']} "
                f"| {title} "
                f"| {e['phase_a_status']} "
                f"| [`{e['prompt_path']}`]({e['prompt_path']}) |"
            )
        lines.append("")

    if extracted:
        lines.append("## Phase 3 zero-day class findings")
        lines.append("")
        lines.append(
            "Stage 2 runtime-confirmed hypotheses on NEW attack classes "
            "L1 didn't surface."
        )
        lines.append("")
        lines.append(
            "| File | Function | Attack class | Judge verdict | Prompt file |"
        )
        lines.append("|---|---|---|---|---|")
        for e in extracted:
            lines.append(
                f"| `{e['file_name']}` "
                f"| `{e['function_name']}` "
                f"| `{e['attack_class']}` "
                f"| {e.get('judge_verdict', '-') or '-'} "
                f"| [`{e['prompt_path']}`]({e['prompt_path']}) |"
            )
        lines.append("")

    lines.append("## How to use")
    lines.append("")
    lines.append("1. Open one of the ``.txt`` files in this directory.")
    lines.append("2. Paste the full contents into a fresh Gemini 3.1 Pro chat.")
    lines.append("3. Gemini will return a JSON verdict — CONFIRMED / REFUTED / ")
    lines.append("   INCONCLUSIVE — with reasoning + suggested fix + any")
    lines.append("   related issues it noticed.")
    lines.append(
        "4. If Gemini REFUTES, the finding is likely a false positive. "
        "Add it to the FP-hardening backlog."
    )
    lines.append(
        "5. If Gemini CONFIRMS, the finding is disclosure-ready. "
        "Capture the chain-of-thought + the suggested-fix into a "
        "GHSA / CVE draft."
    )

    out = output_dir / "_summary.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="extract_zero_days",
        description=(
            "Extract Phase 3 zero-day findings from an argus scan output "
            "and emit copy-pasteable Gemini cross-validation prompts."
        ),
    )
    parser.add_argument(
        "scan_output",
        type=Path,
        help="Path to argus scan output JSON (single-file or scan-repo).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Directory to write prompt .txt files to. "
            "Defaults to <scan_output>.zero_days/ next to the input."
        ),
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=None,
        help=(
            "Optional directory containing the original source files "
            "(matched by ``filename`` from the scan JSON, searched "
            "recursively). When set, the source code is embedded into "
            "the prompt so Gemini can review without a separate paste."
        ),
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help=(
            "Minimum L1 severity to emit a disclosure prompt for. "
            "Default 'high' (only high/critical). Set 'medium' to also "
            "emit medium-severity findings — useful when a CONFIRMED "
            "medium represents a distinct bug class not covered by an "
            "existing high/critical advisory."
        ),
    )
    args = parser.parse_args(argv)
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    min_sev_rank = sev_rank[args.min_severity]

    if not args.scan_output.is_file():
        print(f"ERROR: scan output not found: {args.scan_output}", file=sys.stderr)
        return 2

    try:
        scan_output = json.loads(args.scan_output.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: cannot parse {args.scan_output}: {exc}", file=sys.stderr)
        return 2

    out_dir = (
        args.output_dir
        if args.output_dir is not None
        else args.scan_output.with_suffix("").with_name(
            args.scan_output.stem + ".zero_days"
        )
    )

    file_results = _normalise_file_results(scan_output)
    if not file_results:
        print(
            f"ERROR: no per-file results found in {args.scan_output} "
            "(unrecognised schema?)",
            file=sys.stderr,
        )
        return 2

    # Optional: hydrate ``source_text`` from disk so the emitter embeds
    # the actual file contents in the prompt. The scan JSON itself
    # doesn't store source.
    if args.source_root is not None:
        if not args.source_root.is_dir():
            print(
                f"ERROR: --source-root not a directory: {args.source_root}",
                file=sys.stderr,
            )
            return 2
        for fr in file_results:
            fname = str(fr.get("filename") or "")
            if not fname or fr.get("source_text"):
                continue
            matches = list(args.source_root.rglob(fname))
            if not matches:
                continue

            # Heuristic ranking — pick the most likely "real source"
            # match when a filename appears in multiple subtrees (e.g.,
            # `libs/.../src/tools/foo.ts` vs `examples/.../foo.ts`):
            #   1. Penalise paths under examples/ / test/ / __tests__/.
            #   2. Prefer the longest file (real source is usually
            #      larger than an example or test stub).
            #   3. Prefer paths that contain `/src/` over those that
            #      don't (TS/JS canonical layout).
            def _score(p: Path) -> tuple[int, int, int]:
                parts_lower = {x.lower() for x in p.parts}
                in_examples = any(
                    x in parts_lower
                    for x in ("examples", "example", "demo", "demos")
                )
                in_tests = any(
                    x in parts_lower
                    for x in ("test", "tests", "__tests__", "spec", "specs")
                )
                in_src = "src" in parts_lower
                try:
                    size = p.stat().st_size
                except OSError:
                    size = 0
                # Lower tuple is worse; we sort descending and take [0].
                return (
                    -1 if in_examples or in_tests else 0,
                    1 if in_src else 0,
                    size,
                )

            matches.sort(key=_score, reverse=True)
            try:
                fr["source_text"] = matches[0].read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                pass

    extracted: list[dict[str, Any]] = []
    extracted_l1: list[dict[str, Any]] = []
    files_with_phase_3 = 0

    for file_result in file_results:
        outcomes = list(_outcomes_iter(file_result))
        if outcomes:
            files_with_phase_3 += 1
        l1_covered = _l1_attack_classes_for_file(file_result)

        # ---- Phase 3 Stage 2 zero-day class (NEW attack classes) ----
        for outcome in outcomes:
            if not _is_zero_day(outcome, l1_covered):
                continue
            prompt_path = _emit_prompt(
                file_result=file_result,
                outcome=outcome,
                output_dir=out_dir,
            )
            hypothesis = outcome.get("hypothesis") or {}
            extracted.append(
                {
                    "file_name": file_result.get("filename") or "unknown",
                    "function_name": hypothesis.get("function_name") or "anon",
                    "attack_class": hypothesis.get("attack_class") or "unknown",
                    "judge_verdict": outcome.get("judge_verdict") or "",
                    "prompt_path": prompt_path.name,
                }
            )

        # ---- L1 + Phase A CONFIRMED (the primary disclosure signal) ----
        # Argus emits Phase A per-finding outcomes in
        # ``per_finding_validation`` — a list of dicts with finding_id,
        # cwe, severity, line, status, proof_of_concept, runtime_evidence.
        # The corresponding L1 vuln (with description / code / fix) lives
        # in ``vulnerabilities``, ordered to match by (cwe, line).
        pfv_list = file_result.get("per_finding_validation") or []
        l1_vulns = file_result.get("vulnerabilities") or []

        # Build a lookup of L1 vulns by (cwe, line) so we can enrich
        # the Phase A entry with description / code / fix context.
        l1_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        for v in l1_vulns:
            if not isinstance(v, dict):
                continue
            k = (
                str(v.get("cwe") or v.get("cwe_id") or "").upper(),
                str(v.get("line") or v.get("line_number") or ""),
            )
            l1_by_key[k] = v

        for pfv in pfv_list:
            if not isinstance(pfv, dict):
                continue
            pa_status = str(pfv.get("status") or "")
            # Build a "merged" vuln view that the emitter can render.
            cwe = str(pfv.get("cwe") or "")
            line = str(pfv.get("line") or "")
            l1_match = l1_by_key.get((cwe.upper(), line)) or {}
            merged_vuln: dict[str, Any] = {
                "cwe": cwe,
                "severity": pfv.get("severity"),
                "line": pfv.get("line"),
                "title": pfv.get("type") or l1_match.get("type") or "",
                "attack_class": pfv.get("type") or l1_match.get("type") or "",
                "description": l1_match.get("explanation")
                or l1_match.get("description")
                or "",
                "code": l1_match.get("code") or "",
                "fix": l1_match.get("fix") or "",
                "impact": l1_match.get("impact") or "",
                "confidence": pfv.get("confidence")
                or l1_match.get("confidence"),
                "proof_of_concept": pfv.get("proof_of_concept")
                or l1_match.get("proof_of_concept")
                or "",
                "runtime_evidence": pfv.get("runtime_evidence") or "",
                "finding_id": pfv.get("finding_id") or "",
            }
            if not _is_disclosure_worthy_l1(
                merged_vuln, pa_status, min_sev_rank=min_sev_rank
            ):
                continue
            prompt_path = _emit_l1_prompt(
                file_result=file_result,
                vuln=merged_vuln,
                output_dir=out_dir,
            )
            extracted_l1.append(
                {
                    "file_name": file_result.get("filename") or "unknown",
                    "cwe": cwe,
                    "severity": merged_vuln["severity"] or "",
                    "title": merged_vuln["title"] or "",
                    "phase_a_status": pa_status,
                    "prompt_path": prompt_path.name,
                }
            )

    summary_path = _emit_summary(
        output_dir=out_dir,
        extracted=extracted,
        extracted_l1=extracted_l1,
        scanned_files=len(file_results),
        files_with_phase_3=files_with_phase_3,
    )

    total = len(extracted) + len(extracted_l1)
    if total:
        print(
            f"Extracted {total} disclosure prompts into {out_dir}/  "
            f"(L1+PhaseA: {len(extracted_l1)}, Phase3 zero-day: {len(extracted)})"
        )
        print(f"  - Summary: {summary_path}")
        for e in extracted_l1:
            print(
                f"  - [L1+PhaseA] {e['file_name']} :: {e['cwe']} "
                f"{e['severity']} ({e['title']}) -> {e['prompt_path']}"
            )
        for e in extracted:
            print(
                f"  - [Phase3 zero-day] {e['file_name']} :: "
                f"{e['function_name']} ({e['attack_class']}) "
                f"-> {e['prompt_path']}"
            )
    else:
        print(
            f"No disclosure-worthy findings to extract. "
            f"({files_with_phase_3}/{len(file_results)} files had Phase 3 outcomes.)"
        )
        print(f"  - Summary: {summary_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
