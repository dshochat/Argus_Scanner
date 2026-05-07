import json

SYSTEM_PROMPT = """You are a senior security researcher with 15 years of experience \
in vulnerability analysis, malware reverse engineering, and code auditing.

You are reviewing a disagreement between AI security scanners. Multiple frontier AI models \
scanned the same file and produced different findings. Your job is to read the actual source \
code and determine which model is correct.

RULES:
- Read the actual code carefully. Do NOT trust any scanner's explanation blindly — \
  verify every claim against the actual code.
- If a scanner claims a vulnerability exists, check:
  * Is the vulnerable code pattern actually present?
  * Is there input sanitization or validation upstream that prevents exploitation?
  * Is this code reachable? Could it be dead code or behind a feature flag?
  * Is the CWE classification correct?
  * Is the severity appropriate?
- If a scanner claims code is clean, check:
  * Did it miss a pattern the other scanners caught?
  * Is there a subtle vulnerability it overlooked?
- If scanners disagree on severity, check the actual exploitability and realistic impact.
- For behavioral profile disagreements, trace what the code ACTUALLY does.
- For attack chain disagreements, verify each step references real code.

RETURN ONLY THIS JSON — no other text:
{
  "verdict": "CONFIRMED|REJECTED|MODIFIED",
  "confidence": <float 0.0 to 1.0>,
  "reasoning": "<your detailed analysis — cite specific line numbers and code>",
  "corrected_finding": <null if CONFIRMED or REJECTED, corrected JSON object if MODIFIED>
}"""


def _extract_code_snippet(source_code: str, finding_details: dict, context_lines: int = 25) -> str:
    """Extract a relevant code snippet around the finding, not the entire file."""
    if not source_code:
        return "[no source code available]"

    lines = source_code.split("\n")

    # Try to find a line number reference in the finding
    line_num = None
    if isinstance(finding_details, dict):
        line_num = finding_details.get("line_number") or finding_details.get("line")
        # Also check nested structures
        if not line_num:
            for val in finding_details.values():
                if isinstance(val, dict):
                    line_num = val.get("line_number") or val.get("line")
                    if line_num:
                        break

    if line_num and isinstance(line_num, (int, str)):
        try:
            ln = int(line_num)
            start = max(0, ln - context_lines)
            end = min(len(lines), ln + context_lines)
            snippet_lines = []
            for i in range(start, end):
                marker = " >>> " if i + 1 == ln else "     "
                snippet_lines.append(f"{i + 1:4d}{marker}{lines[i]}")
            return "\n".join(snippet_lines)
        except (ValueError, TypeError):
            pass

    # If file is small enough, include it all
    if len(lines) <= 100:
        return "\n".join(f"{i + 1:4d}     {line}" for i, line in enumerate(lines))

    # Otherwise, return first 50 + last 20 lines with a truncation notice
    head = "\n".join(f"{i + 1:4d}     {line}" for i, line in enumerate(lines[:50]))
    tail = "\n".join(f"{i + 1:4d}     {line}" for i, line in enumerate(lines[-20:], start=len(lines) - 20))
    return f"{head}\n\n... [{len(lines) - 70} lines truncated] ...\n\n{tail}"


def _extract_relevant_findings(model_findings: list, review_type: str) -> str:
    """Extract only the relevant section from each model's findings, kept compact."""
    sections = []
    for finding in model_findings:
        model_name = finding.get("model_name", "Unknown Model")
        parts = [f"--- {model_name} ---"]

        rt = review_type.lower()

        if "vuln" in rt:
            vulns = finding.get("vulnerabilities")
            if vulns and isinstance(vulns, list):
                # Compact: just CWE, severity, line, description
                for v in vulns:
                    desc = v.get("description", v.get("explanation", ""))[:150]
                    parts.append(
                        f"  VULN: {v.get('cwe_id', '?')} sev={v.get('severity', '?')} line={v.get('line_number', '?')} — {desc}"
                    )
            else:
                parts.append("  [no vulnerabilities found]")

        elif "profile" in rt or "behavioral" in rt:
            profile = finding.get("behavioral_profile")
            if profile and isinstance(profile, dict):
                # Only include the specific subsection that's in dispute
                parts.append(f"  Profile: {json.dumps(profile, separators=(',', ':'))[:500]}")
            else:
                parts.append("  [no behavioral profile]")

        elif "chain" in rt or "attack" in rt:
            chains = finding.get("attack_chains")
            if chains and isinstance(chains, list):
                for c in chains:
                    entry = c.get("entry_point", "?")
                    impact = c.get("final_impact", "?")
                    parts.append(f"  CHAIN: {entry} → {impact}")
            else:
                parts.append("  [no attack chains]")

        elif "ai_tool" in rt:
            ai = finding.get("ai_tool_analysis")
            if ai:
                parts.append(f"  AI Tool: {json.dumps(ai, separators=(',', ':'))[:400]}")
            else:
                parts.append("  [no AI tool analysis]")

        else:
            # Unknown type — include compact summaries of everything
            for key in (
                "vulnerabilities",
                "behavioral_profile",
                "attack_chains",
                "ai_tool_analysis",
            ):
                val = finding.get(key)
                if val:
                    parts.append(f"  {key}: {json.dumps(val, separators=(',', ':'))[:300]}")

        sections.append("\n".join(parts))

    return "\n\n".join(sections)


BATCH_SYSTEM_PROMPT = """You are a senior security researcher reviewing multiple \
disagreements about the SAME file. You will see the source code ONCE, \
then multiple specific disagreements to resolve.

For EACH disagreement, provide a verdict.

If the file contains obfuscated/encoded content (base64, hex, etc), \
decode it ONCE mentally, then reference the decoded content for all verdicts.

RULES:
- Read the actual code carefully. Verify every claim against the actual code.
- For vulnerability claims: check if the pattern is actually present and exploitable.
- For behavioral claims: trace what the code ACTUALLY does.
- For attack chains: verify each step references real code.
- If the file is encoded/obfuscated, note what it decodes to, then judge all findings against the decoded content.

RETURN ONLY THIS JSON — no other text:
{
  "decoded_summary": "if file was obfuscated, brief summary of what it decodes to. null if not obfuscated.",
  "verdicts": [
    {
      "review_id": "<id from the disagreement>",
      "verdict": "CONFIRMED|REJECTED|MODIFIED",
      "confidence": 0.0-1.0,
      "reasoning": "your analysis for this specific disagreement",
      "corrected_finding": null
    }
  ]
}"""


def _format_model_findings_compact(model_findings: list) -> str:
    """Format all model findings compactly for batch prompt."""
    sections = []
    for finding in model_findings:
        model_name = finding.get("model_name", "Unknown")
        parts = [f"--- {model_name} ---"]
        for key in ("vulnerabilities", "behavioral_profile", "attack_chains", "ai_tool_analysis"):
            val = finding.get(key)
            if val:
                parts.append(f"  {key}: {json.dumps(val, separators=(',', ':'))[:400]}")
        sections.append("\n".join(parts))
    return "\n\n".join(sections)


def _smart_code_snippet(source_code: str, review_items: list) -> str:
    """Smart code extraction for batch — if encoded, send minimal + note."""
    if not source_code:
        return "[no source code available]"

    lines = source_code.split("\n")

    # Detect if file is mostly encoded/obfuscated
    has_long_base64 = any(len(line) > 200 and not line.strip().startswith("#") for line in lines)

    if has_long_base64 and len(source_code) > 3000:
        # Encoded file — send first 500 chars + note
        snippet = source_code[:500]
        return (
            f"{snippet}\n\n"
            f"[FILE TRUNCATED — {len(lines)} lines, {len(source_code)} chars total. "
            f"Contains base64/encoded payload. Scanner models already decoded it — "
            f"judge based on their decoded findings below, not raw encoded content.]"
        )

    # Small file — send all with line numbers
    if len(lines) <= 100:
        return "\n".join(f"{i + 1:4d}  {line}" for i, line in enumerate(lines))

    # Large but not encoded — send relevant snippets around each finding
    target_lines = set()
    for item in review_items:
        fd = item.get("finding_details") or {}
        ln = fd.get("line_number") or fd.get("line")
        if ln:
            try:
                ln = int(ln)
                for i in range(max(0, ln - 10), min(len(lines), ln + 10)):
                    target_lines.add(i)
            except (ValueError, TypeError):
                pass

    if target_lines:
        sorted_lines = sorted(target_lines)
        result = []
        prev = -2
        for i in sorted_lines:
            if i > prev + 1:
                result.append("  ...")
            result.append(f"{i + 1:4d}  {lines[i]}")
            prev = i
        return "\n".join(result)

    # Fallback: head + tail
    head = "\n".join(f"{i + 1:4d}  {line}" for i, line in enumerate(lines[:50]))
    tail = "\n".join(f"{i + 1:4d}  {line}" for i, line in enumerate(lines[-20:], start=len(lines) - 20))
    return f"{head}\n\n... [{len(lines) - 70} lines truncated] ...\n\n{tail}"


def build_batch_verdict_prompt(file_data: dict, model_findings: list, review_items: list) -> tuple:
    """
    Build a single prompt for ALL disagreements on one file.
    Source code and model findings included ONCE.
    """
    source_code = file_data.get("content", "")
    code_snippet = _smart_code_snippet(source_code, review_items)
    model_section = _format_model_findings_compact(model_findings)

    disagreements = ""
    for i, item in enumerate(review_items):
        disagreements += f"""
--- DISAGREEMENT {i + 1} (review_id: {item["id"]}) ---
Type: {item.get("review_type", "?")}
Description: {item.get("description", "")}
Agree: {json.dumps(item.get("models_agree", []), separators=(",", ":"))}
Disagree: {json.dumps(item.get("models_disagree", []), separators=(",", ":"))}
Finding: {json.dumps(item.get("finding_details", {}), separators=(",", ":"))}
"""

    user_message = f"""## Source Code (analyze ONCE, reference for all disagreements)
Filename: {file_data.get("filename", "unknown")}
```
{code_snippet}
```

## Model Findings
{model_section}

## Disagreements to Resolve ({len(review_items)} total)
{disagreements}

Resolve EACH disagreement. Return one verdict per disagreement in the JSON array."""

    return BATCH_SYSTEM_PROMPT, user_message


def build_verdict_prompt(review_item: dict, source_code: str, model_findings: list) -> tuple:
    """
    Build a focused prompt for Grok — only the relevant code snippet and findings.
    """
    finding_details = review_item.get("finding_details") or {}
    models_agree = review_item.get("models_agree") or []
    models_disagree = review_item.get("models_disagree") or []
    review_type = review_item.get("review_type", "unknown")

    # Extract focused code snippet around the finding
    code_snippet = _extract_code_snippet(source_code, finding_details)

    # Extract only relevant model findings, kept compact
    model_section = _extract_relevant_findings(model_findings, review_type)

    user_message = f"""## Disagreement: {review_type}
{review_item.get("description", "No description")}

## Code ({review_item.get("filename", "unknown")})
```
{code_snippet}
```

## Model Findings
{model_section}

## Agree: {json.dumps(models_agree, separators=(",", ":"))}
## Disagree: {json.dumps(models_disagree, separators=(",", ":"))}

## Finding In Question
{json.dumps(finding_details, indent=2)}

Verdict?"""

    return SYSTEM_PROMPT, user_message
