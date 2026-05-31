"""Gemini 3.1 Pro adjudicator for Argus's per-finding zero-day claims
and file-level disagreements.

Two adjudication modes in one tool:

1. **Per-finding (W1 candidates)** — for each Argus DAST-confirmed
   finding that the 3-LLM consensus oracle and Opus both missed, send
   to Gemini: source code + the specific finding (CWE, severity,
   explanation, code snippet) + Argus's runtime evidence + DAST
   proof-of-concept. Ask: "Is this a real exploitable vulnerability,
   or did the scanner over-claim?" Gemini returns is_real + severity
   + reasoning + confidence.

   Resolves the strategic decision: of the W1 candidates surfaced by
   :mod:`methodology.phase_3_proof_analyzer`, how many are genuine
   zero-day discoveries vs scanner hallucinations.

2. **File-level disagreement** — for files where Argus and Opus
   disagreed on the verdict, blinded A/B presentation (random which
   is which), Gemini picks which scanner is right. Same shape as the
   existing GPT-5 judge (:mod:`methodology.judge`) but Gemini-native
   instead of OpenAI.

Output: a single markdown report + JSON sidecar:
  - Headline: of N W1 candidates, K confirmed real (zero-day count)
  - Per-finding details: each W1 with Gemini's verdict + reasoning
  - File-level adjudication results
  - Updated lift math (proof-grounded wins counted only when adjudicated)

Why Gemini 3.1 Pro: requested by user; also Gemini 3.1 Pro is one of
the 3 voters that produced the consensus oracle, but it's a separate
"independent senior researcher" call here -- different prompt, no
context about the prior vote.

Cost: ~$0.05/finding × 18 W1 + ~$0.10/disagreement × 7 = ~$1.60 total.

Usage::

    uv run python -m methodology.finding_adjudicator \\
        --proof-analysis bench_results/argus_phase3_<ts>/proof_analysis.json \\
        --suite-dir samples/regression_v1 \\
        --output bench_results/argus_phase3_<ts>/adjudication.md
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
log = logging.getLogger("argus.finding_adjudicator")

# Pricing for cost estimation (Gemini 3.1 Pro Preview).
GEMINI_31_PRO_COST_IN = 1.25
GEMINI_31_PRO_COST_OUT = 10.0

MAX_FILE_CONTENT_CHARS = 60_000

JUDGE_PER_FINDING_SYSTEM_PROMPT = """\
You are an independent senior security researcher. An automated scanner \
has analyzed a source file and produced a specific finding it claims is \
a real exploitable vulnerability, backed by sandbox runtime evidence. \
Your job is to independently judge whether the finding describes an \
ACTUAL exploitable vulnerability in this file, or whether the scanner \
over-claimed.

You will receive:
  1. The source file content.
  2. The scanner's specific finding (CWE, type, severity, line, code \
     snippet, explanation).
  3. The sandbox runtime evidence (what the sandbox observed when \
     testing the finding).
  4. The scanner's proof-of-concept description.

Apply the integrity rule: a finding is REAL when:
  * the CODE in the file actually contains the vulnerable pattern, AND
  * the runtime evidence demonstrates the exploit actually fires (not \
    just that the scanner reached the function or saw the keyword), AND
  * the impact described matches what the code can plausibly do.

A finding is OVER-CLAIMED when:
  * the runtime evidence is keyword-matched rather than \
    behavior-confirming, OR
  * the scanner's described impact exceeds what the code can do, OR
  * the file is a test/demo/fixture and the "exploit" is intentional \
    illustration not a real production vulnerability.

Be especially careful about:
  * Files explicitly named or commented as TEST / FIXTURE / DEMO / \
    REGRESSION — these may intentionally contain vulnerable patterns \
    for testing purposes. Real exploitability still applies if the \
    code runs in production-like contexts.
  * "Defense evasion" CWEs claimed because a file contains \
    encoded/compressed data — encoding alone is not exploit; the \
    DECODED behavior is what matters.

Return JSON only, in this exact shape:

  {
    "is_real": true | false,
    "severity_assessment": "critical" | "high" | "medium" | "low" | "none",
    "confidence": <float 0.0 to 1.0>,
    "reasoning": "<3-6 sentences grounded in the actual code + evidence>",
    "notes": "<optional, e.g., 'context-dependent: only exploitable when X' or empty>"
  }
"""


JUDGE_FILE_LEVEL_SYSTEM_PROMPT = """\
You are an independent senior security researcher adjudicating a \
disagreement between two automated code scanners. The scanners have \
analyzed a file and reached different verdicts. Your job is to \
evaluate which scanner is correct based on the actual code evidence \
- not on which scanner's findings sound more confident.

You will receive:
  1. The file's source code.
  2. An "oracle" verdict label from a prior labeling pass. The oracle \
     may be wrong; treat it as a prior, not as ground truth.
  3. Two unlabeled positions, "A" and "B". Each position contains a \
     verdict and a list of structured findings. You do NOT know which \
     scanner produced which position.

Verdict scale (most-severe -> least-severe):
  critical_malicious - clear active attack (RCE, exfil, persistent backdoor)
  malicious          - high-confidence malicious behavior
  suspicious         - anomalous patterns, ambiguous intent
  clean              - no security concerns

Return JSON only, in this exact shape:

  {
    "verdict": "<one of: critical_malicious | malicious | suspicious | clean>",
    "agree_with": "<one of: A | B | both | neither>",
    "reasoning": "<2-4 sentence justification grounded in the actual code>",
    "confidence": <float 0.0 to 1.0>
  }
"""


@dataclass
class PerFindingJudgment:
    file_name: str
    cwe: str
    is_real: bool | None
    severity_assessment: str
    confidence: float
    reasoning: str
    notes: str
    tokens_in: int
    tokens_out: int
    cost_usd: float
    duration_ms: int
    error: str | None = None
    # Original finding context preserved for the report
    argus_status: str = ""
    argus_severity: str = ""
    argus_confidence: float = 0.0
    proof_text: str = ""


@dataclass
class FileLevelJudgment:
    file_name: str
    judge_verdict: str
    agree_with: str  # "A" | "B" | "both" | "neither" | "argus" | "opus"
    judge_reasoning: str
    judge_confidence: float
    ab_mapping: dict[str, str] = field(default_factory=dict)
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    duration_ms: int = 0
    error: str | None = None


# ── Gemini call ───────────────────────────────────────────────────────────


async def _call_gemini(
    *,
    api_key: str,
    system_prompt: str,
    user_message: str,
    model: str = "gemini-3.1-pro-preview",
    thinking_budget: int = 24576,
    max_output_tokens: int = 8192,
) -> tuple[dict[str, Any], int, int, str]:
    """One Gemini call. Returns (parsed_json_or_empty, in_tokens, out_tokens, raw_text).

    Uses the google-genai SDK directly. Safety filters disabled --
    security analysis prompts hit content filters otherwise.
    """
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=api_key)
    config = types.GenerateContentConfig(
        system_instruction=system_prompt,
        max_output_tokens=max_output_tokens,
        thinking_config=types.ThinkingConfig(thinking_budget=thinking_budget)
        if thinking_budget
        else None,
        safety_settings=[
            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="OFF"),
        ],
        response_mime_type="application/json",
    )
    response = await client.aio.models.generate_content(
        model=model,
        contents=user_message,
        config=config,
    )
    # Extract text from non-thought parts
    text_parts: list[str] = []
    if response.candidates and response.candidates[0].content:
        for part in response.candidates[0].content.parts or []:
            if hasattr(part, "thought") and part.thought:
                continue
            if part.text:
                text_parts.append(part.text)
    raw_text = "\n".join(text_parts) if text_parts else (response.text or "")

    parsed: dict[str, Any] = {}
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        # Try to extract JSON from a possibly markdown-wrapped response
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start >= 0 and end > start:
            try:
                parsed = json.loads(raw_text[start : end + 1])
            except json.JSONDecodeError:
                parsed = {}

    usage = response.usage_metadata
    in_tokens = int(getattr(usage, "prompt_token_count", 0) or 0)
    out_candidates = int(getattr(usage, "candidates_token_count", 0) or 0)
    out_thoughts = int(getattr(usage, "thoughts_token_count", 0) or 0)
    out_tokens = out_candidates + out_thoughts
    return parsed, in_tokens, out_tokens, raw_text


# ── Per-finding adjudication ─────────────────────────────────────────────


def _build_per_finding_message(
    file_name: str,
    file_source: str,
    finding: dict,
    runtime_evidence: str,
    proof_of_concept: str,
) -> str:
    """Construct the user prompt for one (file, finding) adjudication."""
    src = file_source[:MAX_FILE_CONTENT_CHARS]
    if len(file_source) > MAX_FILE_CONTENT_CHARS:
        omitted = len(file_source) - MAX_FILE_CONTENT_CHARS
        src += f"\n... [file truncated: {omitted} more chars omitted]"

    cwe = finding.get("cwe", "?")
    type_ = finding.get("type", "?")
    sev = finding.get("severity", "?")
    line = finding.get("line", "?")
    explanation = (finding.get("explanation") or finding.get("title") or "")[:1500]
    code_snippet = (finding.get("code") or "")[:500]

    return (
        f"File: {file_name}\n\n"
        f"=== Source code ===\n```\n{src}\n```\n\n"
        f"=== Scanner's finding ===\n"
        f"CWE: {cwe}\n"
        f"Type: {type_}\n"
        f"Severity claimed: {sev}\n"
        f"Line: {line}\n"
        f"Explanation:\n{explanation}\n\n"
        f"Code snippet at finding location:\n```\n{code_snippet}\n```\n\n"
        f"=== Sandbox runtime evidence ===\n{runtime_evidence[:1500]}\n\n"
        f"=== Scanner's proof-of-concept description ===\n{proof_of_concept[:800]}\n\n"
        f"Judge whether this finding describes a REAL exploitable vulnerability "
        f"in this file. Return the JSON described in the system prompt."
    )


async def adjudicate_finding(
    *,
    api_key: str,
    file_name: str,
    file_source: str,
    finding: dict,
    runtime_evidence: str,
    proof_of_concept: str,
    extra_context: dict | None = None,
) -> PerFindingJudgment:
    t0 = time.time()
    user_message = _build_per_finding_message(
        file_name=file_name,
        file_source=file_source,
        finding=finding,
        runtime_evidence=runtime_evidence,
        proof_of_concept=proof_of_concept,
    )
    try:
        parsed, tin, tout, _ = await _call_gemini(
            api_key=api_key,
            system_prompt=JUDGE_PER_FINDING_SYSTEM_PROMPT,
            user_message=user_message,
        )
    except Exception as exc:  # noqa: BLE001
        elapsed = int((time.time() - t0) * 1000)
        return PerFindingJudgment(
            file_name=file_name,
            cwe=str(finding.get("cwe") or "?"),
            is_real=None,
            severity_assessment="",
            confidence=0.0,
            reasoning="",
            notes="",
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            duration_ms=elapsed,
            error=f"{type(exc).__name__}: {str(exc)[:200]}",
            **(extra_context or {}),
        )
    elapsed = int((time.time() - t0) * 1000)
    cost = tin / 1_000_000 * GEMINI_31_PRO_COST_IN + tout / 1_000_000 * GEMINI_31_PRO_COST_OUT
    return PerFindingJudgment(
        file_name=file_name,
        cwe=str(finding.get("cwe") or "?"),
        is_real=bool(parsed.get("is_real")) if "is_real" in parsed else None,
        severity_assessment=str(parsed.get("severity_assessment") or ""),
        confidence=float(parsed.get("confidence") or 0.0),
        reasoning=str(parsed.get("reasoning") or "")[:1000],
        notes=str(parsed.get("notes") or "")[:500],
        tokens_in=tin,
        tokens_out=tout,
        cost_usd=cost,
        duration_ms=elapsed,
        error=None if parsed else "empty_response",
        **(extra_context or {}),
    )


# ── File-level adjudication ──────────────────────────────────────────────


def _build_file_level_message(
    file_name: str,
    file_source: str,
    oracle_verdict: str,
    pos_a: dict,
    pos_b: dict,
) -> str:
    src = file_source[:MAX_FILE_CONTENT_CHARS]
    if len(file_source) > MAX_FILE_CONTENT_CHARS:
        src += "\n... [file truncated]"

    lines = [
        f"File: {file_name}",
        f"Oracle verdict (prior, may be wrong): {oracle_verdict or '<no oracle label>'}",
        "",
        "=== Source code ===",
        "```",
        src,
        "```",
        "",
        "=== Competing positions ===",
    ]
    for ab, pos in (("A", pos_a), ("B", pos_b)):
        verdict = pos.get("verdict") or "<no verdict>"
        findings = pos.get("findings") or []
        lines.extend(["", f"### Position {ab}", f"verdict: {verdict}", "findings:"])
        for f in findings[:20]:
            cwe = f.get("cwe") or ""
            ftype = f.get("type") or ""
            sev = f.get("severity") or ""
            ln = f.get("line")
            title = (f.get("title") or f.get("explanation") or "")[:120]
            lines.append(f"  - [{cwe}] {ftype} ({sev}) line={ln} - {title}")
        if len(findings) > 20:
            lines.append(f"  ... ({len(findings) - 20} more findings omitted)")
    lines.extend(["", "Return your judgment as JSON per the system prompt."])
    return "\n".join(lines)


async def adjudicate_file_disagreement(
    *,
    api_key: str,
    file_name: str,
    file_source: str,
    oracle_verdict: str,
    argus_position: dict,
    opus_position: dict,
    seed: int | None = None,
) -> FileLevelJudgment:
    rng = random.Random(seed if seed is not None else file_name)
    if rng.random() < 0.5:
        pos_a, pos_b = argus_position, opus_position
        mapping = {"A": "argus", "B": "opus"}
    else:
        pos_a, pos_b = opus_position, argus_position
        mapping = {"A": "opus", "B": "argus"}
    t0 = time.time()
    user_message = _build_file_level_message(
        file_name=file_name,
        file_source=file_source,
        oracle_verdict=oracle_verdict,
        pos_a=pos_a,
        pos_b=pos_b,
    )
    try:
        parsed, tin, tout, _ = await _call_gemini(
            api_key=api_key,
            system_prompt=JUDGE_FILE_LEVEL_SYSTEM_PROMPT,
            user_message=user_message,
        )
    except Exception as exc:  # noqa: BLE001
        elapsed = int((time.time() - t0) * 1000)
        return FileLevelJudgment(
            file_name=file_name,
            judge_verdict="",
            agree_with="",
            judge_reasoning="",
            judge_confidence=0.0,
            ab_mapping=mapping,
            duration_ms=elapsed,
            error=f"{type(exc).__name__}: {str(exc)[:200]}",
        )
    elapsed = int((time.time() - t0) * 1000)
    cost = tin / 1_000_000 * GEMINI_31_PRO_COST_IN + tout / 1_000_000 * GEMINI_31_PRO_COST_OUT
    raw_agree = str(parsed.get("agree_with") or "").upper()
    decoded_agree = mapping.get(raw_agree, raw_agree.lower())
    return FileLevelJudgment(
        file_name=file_name,
        judge_verdict=str(parsed.get("verdict") or ""),
        agree_with=decoded_agree,
        judge_reasoning=str(parsed.get("reasoning") or "")[:1000],
        judge_confidence=float(parsed.get("confidence") or 0.0),
        ab_mapping=mapping,
        tokens_in=tin,
        tokens_out=tout,
        cost_usd=cost,
        duration_ms=elapsed,
        error=None if parsed else "empty_response",
    )


# ── Driver ────────────────────────────────────────────────────────────────


def _load_argus_rows(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def _row_finding_with_evidence(row: dict, cwe: str) -> tuple[dict, str, str]:
    """For a given file row + CWE, return (vuln_dict, runtime_evidence, poc)."""
    cwe_up = cwe.upper().strip()
    vuln: dict = {}
    runtime_evidence = ""
    poc = ""
    for v in row.get("vulnerabilities") or []:
        if str(v.get("cwe") or "").upper().strip() == cwe_up:
            vuln = v
            break
    for p in row.get("per_finding_validation") or []:
        if str(p.get("cwe") or "").upper().strip() == cwe_up:
            runtime_evidence = str(p.get("runtime_evidence") or "")
            poc = str(p.get("proof_of_concept") or "")
            if not vuln:
                vuln = {
                    "cwe": cwe,
                    "type": p.get("type", ""),
                    "severity": p.get("severity", ""),
                    "line": p.get("line"),
                    "code": "",
                    "explanation": "",
                }
            break
    return vuln, runtime_evidence, poc


async def run_adjudication(
    *,
    api_key: str,
    proof_analysis: dict,
    argus_rows: list[dict],
    opus_rows: list[dict],
    suite_dir: Path,
    skip_per_finding: bool = False,
    skip_file_level: bool = False,
) -> tuple[list[PerFindingJudgment], list[FileLevelJudgment]]:
    """Adjudicate the W1 candidates + the file-level disagreements."""
    argus_by_file = {r["file_name"]: r for r in argus_rows if r.get("file_name")}
    opus_by_file = {r["file_name"]: r for r in opus_rows if r.get("file_name")}

    per_finding_judgments: list[PerFindingJudgment] = []
    file_level_judgments: list[FileLevelJudgment] = []

    # Per-finding adjudication on W1 candidates
    if not skip_per_finding:
        w1_jobs: list[tuple[str, str]] = []
        for f in proof_analysis.get("files") or []:
            file_name = f["file_name"]
            for c in f.get("classifications") or []:
                if c.get("category") == "W1_WIN_ZERO_DAY":
                    w1_jobs.append((file_name, c.get("cwe", "")))
        log.info("per-finding adjudication: %d W1 candidates", len(w1_jobs))
        for i, (file_name, cwe) in enumerate(w1_jobs, start=1):
            row = argus_by_file.get(file_name) or {}
            vuln, runtime_evidence, poc = _row_finding_with_evidence(row, cwe)
            src_path = suite_dir / file_name
            try:
                src = src_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                log.warning("could not read %s: %s", src_path, exc)
                src = ""
            judgment = await adjudicate_finding(
                api_key=api_key,
                file_name=file_name,
                file_source=src,
                finding=vuln,
                runtime_evidence=runtime_evidence,
                proof_of_concept=poc,
                extra_context={
                    "argus_status": vuln.get("dast_status") or "",
                    "argus_severity": vuln.get("severity") or "",
                    "argus_confidence": float(vuln.get("confidence") or 0.0),
                    "proof_text": (runtime_evidence or "")[:400],
                },
            )
            per_finding_judgments.append(judgment)
            label = (
                "REAL"
                if judgment.is_real is True
                else "OVER-CLAIMED"
                if judgment.is_real is False
                else "ERR"
            )
            print(
                f"  [{i}/{len(w1_jobs)}] {file_name:35s} {cwe:10s} -> {label:13s} "
                f"sev={judgment.severity_assessment:8s} conf={judgment.confidence:.2f} "
                f"${judgment.cost_usd:.4f}",
                flush=True,
            )

    # File-level adjudication on disagreement files
    if not skip_file_level:
        disagreement_files: list[str] = []
        for f in proof_analysis.get("files") or []:
            cats = {c.get("category") for c in (f.get("classifications") or [])}
            if cats & {"A1_ARGUS_CLAIMS_ALONE", "A2_ORACLE_VS_ARGUS_HIGH_COV"}:
                disagreement_files.append(f["file_name"])
        log.info("file-level adjudication: %d disagreements", len(disagreement_files))
        for i, file_name in enumerate(disagreement_files, start=1):
            arow = argus_by_file.get(file_name) or {}
            orow = opus_by_file.get(file_name) or {}
            src_path = suite_dir / file_name
            try:
                src = src_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                src = ""
            argus_pos = {
                "verdict": arow.get("predicted_verdict"),
                "findings": arow.get("vulnerabilities") or [],
            }
            opus_pos = {
                "verdict": orow.get("predicted_verdict"),
                "findings": orow.get("vulnerabilities") or [],
            }
            judgment = await adjudicate_file_disagreement(
                api_key=api_key,
                file_name=file_name,
                file_source=src,
                oracle_verdict=arow.get("oracle_verdict") or "",
                argus_position=argus_pos,
                opus_position=opus_pos,
            )
            file_level_judgments.append(judgment)
            n_total = len(disagreement_files)
            print(
                f"  [{i}/{n_total}] {file_name:35s} "
                f"verdict={judgment.judge_verdict:18s} "
                f"agree_with={judgment.agree_with:8s} ${judgment.cost_usd:.4f}",
                flush=True,
            )

    return per_finding_judgments, file_level_judgments


# ── Reporting ─────────────────────────────────────────────────────────────


def render_report(
    per_finding: list[PerFindingJudgment],
    file_level: list[FileLevelJudgment],
) -> str:
    lines: list[str] = []
    lines.append("# Gemini 3.1 Pro adjudication report")
    lines.append("")
    lines.append("## Per-finding adjudication (W1 zero-day candidates)")
    lines.append("")
    n = len(per_finding)
    n_real = sum(1 for j in per_finding if j.is_real is True)
    n_over = sum(1 for j in per_finding if j.is_real is False)
    n_err = sum(1 for j in per_finding if j.error)
    real_pct = (100.0 * n_real / n) if n else 0.0
    lines.append(f"- Total W1 candidates adjudicated: **{n}**")
    lines.append(
        f"- 🏆 **Confirmed REAL** (Gemini says exploit is genuine): **{n_real}** ({real_pct:.1f}%)"
    )
    lines.append(f"- ❌ **Over-claimed** (scanner exaggerated proof): {n_over}")
    lines.append(f"- ⚠️ Error / inconclusive: {n_err}")
    cost = sum(j.cost_usd for j in per_finding) + sum(j.cost_usd for j in file_level)
    lines.append(f"- **Adjudication cost**: ${cost:.4f}")
    lines.append("")
    lines.append("### Per-finding verdicts")
    lines.append("")
    lines.append("| File | CWE | Gemini verdict | Severity | Conf | Reasoning (snippet) |")
    lines.append("|---|---|---|---|---|---|")
    for j in per_finding:
        label = (
            "✅ REAL" if j.is_real is True else "❌ over-claimed" if j.is_real is False else "⚠️ err"
        )
        reasoning = (j.reasoning or j.error or "").replace("|", "\\|").replace("\n", " ")[:160]
        lines.append(
            f"| `{j.file_name}` | {j.cwe} | {label} | "
            f"{j.severity_assessment} | {j.confidence:.2f} | {reasoning} |"
        )
    lines.append("")

    if file_level:
        lines.append("## File-level disagreement adjudication")
        lines.append("")
        n_fl = len(file_level)
        n_argus = sum(1 for j in file_level if j.agree_with == "argus")
        n_opus = sum(1 for j in file_level if j.agree_with == "opus")
        n_both = sum(1 for j in file_level if j.agree_with == "both")
        n_neither = sum(1 for j in file_level if j.agree_with == "neither")
        lines.append(f"- Disagreement files adjudicated: {n_fl}")
        lines.append(f"- Gemini sides with **Argus**: {n_argus}")
        lines.append(f"- Gemini sides with **Opus**: {n_opus}")
        lines.append(f"- Both: {n_both}, Neither: {n_neither}")
        lines.append("")
        lines.append("| File | Gemini verdict | Agree with | Confidence | Reasoning |")
        lines.append("|---|---|---|---|---|")
        for j in file_level:
            raw = j.judge_reasoning or j.error or ""
            reasoning = raw.replace("|", "\\|").replace("\n", " ")[:160]
            lines.append(
                f"| `{j.file_name}` | {j.judge_verdict} | {j.agree_with} | "
                f"{j.judge_confidence:.2f} | {reasoning} |"
            )
        lines.append("")

    return "\n".join(lines)


def to_json_records(
    per_finding: list[PerFindingJudgment],
    file_level: list[FileLevelJudgment],
) -> dict[str, Any]:
    return {
        "summary": {
            "n_per_finding": len(per_finding),
            "n_real": sum(1 for j in per_finding if j.is_real is True),
            "n_over_claimed": sum(1 for j in per_finding if j.is_real is False),
            "n_err": sum(1 for j in per_finding if j.error),
            "n_file_level": len(file_level),
            "file_level_agree_argus": sum(1 for j in file_level if j.agree_with == "argus"),
            "file_level_agree_opus": sum(1 for j in file_level if j.agree_with == "opus"),
            "total_cost_usd": sum(j.cost_usd for j in per_finding)
            + sum(j.cost_usd for j in file_level),
        },
        "per_finding": [
            {
                "file_name": j.file_name,
                "cwe": j.cwe,
                "is_real": j.is_real,
                "severity_assessment": j.severity_assessment,
                "confidence": j.confidence,
                "reasoning": j.reasoning,
                "notes": j.notes,
                "argus_status": j.argus_status,
                "argus_severity": j.argus_severity,
                "argus_confidence": j.argus_confidence,
                "proof_text": j.proof_text,
                "tokens_in": j.tokens_in,
                "tokens_out": j.tokens_out,
                "cost_usd": j.cost_usd,
                "duration_ms": j.duration_ms,
                "error": j.error,
            }
            for j in per_finding
        ],
        "file_level": [
            {
                "file_name": j.file_name,
                "judge_verdict": j.judge_verdict,
                "agree_with": j.agree_with,
                "judge_reasoning": j.judge_reasoning,
                "judge_confidence": j.judge_confidence,
                "ab_mapping": j.ab_mapping,
                "tokens_in": j.tokens_in,
                "tokens_out": j.tokens_out,
                "cost_usd": j.cost_usd,
                "duration_ms": j.duration_ms,
                "error": j.error,
            }
            for j in file_level
        ],
    }


# ── CLI ───────────────────────────────────────────────────────────────────


async def _run(args: argparse.Namespace) -> int:
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        log.error("GEMINI_API_KEY not set in environment")
        return 2

    proof_analysis = json.loads(Path(args.proof_analysis).read_text(encoding="utf-8"))
    argus_rows = _load_argus_rows(Path(args.argus_bench))
    opus_rows = _load_argus_rows(Path(args.opus_bench))

    per_finding, file_level = await run_adjudication(
        api_key=api_key,
        proof_analysis=proof_analysis,
        argus_rows=argus_rows,
        opus_rows=opus_rows,
        suite_dir=Path(args.suite_dir),
        skip_per_finding=args.skip_per_finding,
        skip_file_level=args.skip_file_level,
    )

    md = render_report(per_finding, file_level)
    Path(args.output).write_text(md, encoding="utf-8")
    json_path = Path(args.output).with_suffix(".json")
    json_path.write_text(
        json.dumps(to_json_records(per_finding, file_level), indent=2),
        encoding="utf-8",
    )
    log.info("wrote markdown report: %s", args.output)
    log.info("wrote JSON sidecar: %s", json_path)

    # Headline
    n = len(per_finding)
    n_real = sum(1 for j in per_finding if j.is_real is True)
    n_over = sum(1 for j in per_finding if j.is_real is False)
    total_cost = sum(j.cost_usd for j in per_finding) + sum(j.cost_usd for j in file_level)
    print()
    print("=== ADJUDICATION HEADLINE ===")
    print(f"  W1 candidates adjudicated: {n}")
    print(f"  Gemini confirms REAL exploits: {n_real} ({100.0 * n_real / max(n, 1):.1f}%)")
    print(f"  Gemini says OVER-CLAIMED: {n_over}")
    print(f"  File-level disagreements judged: {len(file_level)}")
    print(f"  Total cost: ${total_cost:.4f}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="finding_adjudicator")
    parser.add_argument(
        "--proof-analysis",
        type=str,
        required=True,
        help="Path to proof_analysis.json from phase_3_proof_analyzer",
    )
    parser.add_argument("--argus-bench", type=str, required=True)
    parser.add_argument("--opus-bench", type=str, required=True)
    parser.add_argument(
        "--suite-dir",
        type=str,
        default=str(REPO_ROOT / "samples" / "regression_v1"),
    )
    parser.add_argument("--output", type=str, required=True, help="Output markdown path")
    parser.add_argument("--skip-per-finding", action="store_true")
    parser.add_argument("--skip-file-level", action="store_true")
    args = parser.parse_args()
    load_dotenv(REPO_ROOT / ".env", override=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
