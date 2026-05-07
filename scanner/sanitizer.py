"""
saas/response_sanitizer.py — Shared AI response leak protection.

Detects and sanitizes any AI provider identity leakage from LLM responses.
Used by scan_engine.py and the API layer to ensure no model identity
is ever exposed to users.

IMPORTANT: Do NOT redact security domain terms like "AI", "LLM", "agent",
"AI agent", "LLM agent" — these are legitimate findings in scan output.
Only redact self-identification patterns where the model reveals its own identity.
"""

import json
import logging
import re

log = logging.getLogger("ed-api")

# ── HARD identity leaks — the model is revealing its own identity.
# Always trigger retry regardless of context.
IDENTITY_PHRASES = [
    "as a language model",
    "large language model",
    "as an ai assistant",
    "i am an ai assistant",
    "i'm an ai assistant",
    "i was trained",
    "my training data",
    "my training",
    "i was created by",
    "i was built by",
    "i was made by",
    "i cannot",
    "i can't help",
    "i cannot help",
    "i'm not able to",
    "i must decline",
    "i can't help with",
    "i don't have personal",
    "as an assistant",
    "i'm a helpful",
    "as a helpful assistant",
    "i'm a helpful assistant",
    "i'm a chatbot",
    "my instructions say",
    "my system prompt",
    "i was instructed to",
    "my instructions",
]

# ── SOFT provider names — specific model/company names that should not
# appear in AI-generated analysis fields. Legitimate in user-quoted code
# (e.g., code that imports openai library).
PROVIDER_NAMES = [
    "claude",
    "anthropic",
    "openai",
    "gpt-4",
    "gpt-3",
    "gpt4",
    "gpt3",
    "opus",
    "sonnet",
    "haiku",
    "gemini",
    "google ai",
    "mistral",
]

# Deduplicated and lowercased for matching
_IDENTITY_LOWER = list(dict.fromkeys(s.lower() for s in IDENTITY_PHRASES))
_PROVIDER_LOWER = list(dict.fromkeys(s.lower() for s in PROVIDER_NAMES))

# For the full leak check (identity + provider)
_ALL_LEAK_LOWER = _IDENTITY_LOWER + _PROVIDER_LOWER

# Sanitization patterns — ONLY for provider names (not security terms)
_SANITIZE_PATTERNS = [re.compile(re.escape(s), re.IGNORECASE) for s in _PROVIDER_LOWER]


def check_for_leaks(text: str) -> tuple[bool, str | None]:
    """
    Check if text contains any identity or provider strings.

    Returns:
        (has_leak, matched_string) — True + the matched string if leaked,
        (False, None) if clean.
    """
    lower = text.lower()
    for s in _ALL_LEAK_LOWER:
        if s in lower:
            return True, s
    return False, None


def sanitize_text(text: str) -> str:
    """Replace only provider name strings with [redacted]. Does NOT touch
    security domain terms like AI, LLM, agent."""
    for pattern in _SANITIZE_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


def sanitize_response(response_dict: dict) -> tuple[dict | None, bool]:
    """
    Check every string value in the response for forbidden strings.

    Returns:
        (sanitized_dict, had_leak)
        - If had_leak is True and leak is in AI-generated fields: returns (None, True)
          signaling the caller should retry the scan.
        - If leak is only in user-quoted code snippets: sanitizes and returns (dict, True)
        - If clean: returns (response_dict, False)
    """
    # Serialize to check all nested fields
    text = json.dumps(response_dict)
    has_leak, matched = check_for_leaks(text)

    if not has_leak:
        return response_dict, False

    # ── Check for HARD identity leaks (always retry) ──
    def _has_identity_leak(val: str) -> bool:
        lower = val.lower()
        return any(s in lower for s in _IDENTITY_LOWER)

    # Check all fields for hard identity phrases
    for vuln in response_dict.get("vulnerabilities", []):
        for field in ("explanation", "fix", "reasoning", "mismatch_detail"):
            val = vuln.get(field, "")
            if isinstance(val, str) and _has_identity_leak(val):
                log.warning("IDENTITY_LEAK in vuln field=%s", field)
                return None, True

    composite = response_dict.get("composite_risk", {})
    if isinstance(composite, dict):
        reasoning = composite.get("reasoning", "")
        if isinstance(reasoning, str) and _has_identity_leak(reasoning):
            log.warning("IDENTITY_LEAK in composite_risk.reasoning")
            return None, True

    ai_tool = response_dict.get("ai_tool_analysis", {})
    if isinstance(ai_tool, dict):
        detail = ai_tool.get("mismatch_detail", "")
        if isinstance(detail, str) and _has_identity_leak(detail):
            log.warning("IDENTITY_LEAK in ai_tool_analysis.mismatch_detail")
            return None, True

    # Check behavioral profile fields for identity leaks
    bp = response_dict.get("behavioral_profile", {})
    if isinstance(bp, dict):
        for field in ("purpose_summary", "mismatch_detail"):
            val = bp.get(field, "")
            if isinstance(val, str) and _has_identity_leak(val):
                log.warning("IDENTITY_LEAK in behavioral_profile.%s", field)
                return None, True
        dva = bp.get("declared_vs_actual", {})
        if isinstance(dva, dict):
            md = dva.get("mismatch_detail", "")
            if isinstance(md, str) and _has_identity_leak(md):
                log.warning("IDENTITY_LEAK in behavioral_profile.declared_vs_actual.mismatch_detail")
                return None, True

    # ── SOFT provider name matches ──
    # Sanitize only provider names, leave everything else intact
    log.info("SOFT_LEAK_SANITIZED matched=%s (provider name, not identity)", matched)
    sanitized_text = sanitize_text(text)
    try:
        sanitized = json.loads(sanitized_text)
        return sanitized, True
    except json.JSONDecodeError:
        log.error("SANITIZE_JSON_ERROR — sanitization broke JSON structure")
        return None, True
