"""Argus inference adapters — Anthropic + Google.

Each adapter wraps a provider's API and exposes the uniform ``scan(content,
filename, system_prompt)`` interface used by the cascade runners. Phase 1
needs only Anthropic (Sonnet 4.6 / Opus 4.6) and Google (Gemini Flash-Lite
triage); other providers will be reintroduced for v2 benchmark mode (ARG-007).
"""

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

log = logging.getLogger("ed-bm-adapters")


class BaseModelAdapter(ABC):
    """Base class for all model adapters."""

    def __init__(self, model_config: dict):
        self.name = model_config["name"]
        self.model_id = model_config["model_id"]
        self.api_key = model_config.get("api_key_encrypted", "")
        self.provider = model_config["provider"]
        self.config = model_config.get("config", {}) or {}

    async def scan(self, content: str, filename: str, system_prompt: str) -> dict:
        """
        Scan a file and return structured results.

        Returns:
            {
                "raw_response": <raw API response>,
                "parsed": <parsed JSON from model>,
                "input_tokens": int,
                "output_tokens": int,
                "response_time_ms": int,
                "json_valid": bool,
                "error": str or None,
            }
        """
        user_message = f"Filename: {filename}\nLanguage: {self._detect_language(filename)}\n\n```{self._detect_language(filename)}\n{content}\n```"

        start = time.time()
        try:
            result = await self._call_api(system_prompt, user_message)
            elapsed_ms = int((time.time() - start) * 1000)
            result["response_time_ms"] = elapsed_ms
            return result
        except Exception as e:
            elapsed_ms = int((time.time() - start) * 1000)
            log.error("Model %s failed on %s: %s", self.name, filename, e)
            return {
                "raw_response": None,
                "parsed": None,
                "input_tokens": 0,
                "output_tokens": 0,
                "response_time_ms": elapsed_ms,
                "json_valid": False,
                "error": str(e),
            }

    @abstractmethod
    async def _call_api(self, system_prompt: str, user_message: str) -> dict:
        """Provider-specific API call. Must return standardized result dict."""
        raise NotImplementedError

    async def test_connection(self) -> dict:
        """Test model connection with a simple prompt."""
        start = time.time()
        try:
            result = await self._call_api(
                "You are a helpful assistant.",
                "Say 'hello' in one word."
            )
            elapsed_ms = int((time.time() - start) * 1000)
            return {"success": True, "response_time_ms": elapsed_ms, "model": self.model_id}
        except Exception as e:
            elapsed_ms = int((time.time() - start) * 1000)
            return {"success": False, "error": str(e), "response_time_ms": elapsed_ms, "model": self.model_id}

    def parse_response(self, raw_text: str) -> Tuple[Optional[dict], bool]:
        """Parse model response text into structured JSON."""
        if not raw_text:
            return None, False
        # Try to extract JSON from response — models may wrap it in markdown
        text = raw_text.strip()
        # Remove markdown code fences if present
        if text.startswith("```"):
            first_newline = text.index("\n") if "\n" in text else 3
            text = text[first_newline + 1:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        try:
            parsed = json.loads(text)
            return parsed, True
        except json.JSONDecodeError:
            # Try to find JSON object in the text
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    parsed = json.loads(text[start:end + 1])
                    return parsed, True
                except json.JSONDecodeError:
                    pass
            return None, False

    @staticmethod
    def _detect_language(filename: str) -> str:
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "jsx", ".tsx": "tsx", ".java": "java", ".go": "go",
            ".rs": "rust", ".rb": "ruby", ".php": "php", ".c": "c",
            ".cpp": "cpp", ".cs": "csharp", ".swift": "swift",
            ".kt": "kotlin", ".scala": "scala", ".sh": "bash",
            ".yaml": "yaml", ".yml": "yaml", ".json": "json",
            ".xml": "xml", ".html": "html", ".css": "css",
            ".sql": "sql", ".r": "r", ".m": "matlab",
            ".toml": "toml", ".ini": "ini", ".cfg": "ini",
        }
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
        return "text"


class AnthropicAdapter(BaseModelAdapter):
    """Adapter for Anthropic Claude models."""

    async def _call_api(self, system_prompt: str, user_message: str) -> dict:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self.api_key)

        # Argus uses claude-opus-4-6 + claude-sonnet-4-6 with the LEGACY
        # extended-thinking API: ``thinking.type=enabled`` + explicit
        # ``budget_tokens``. Reasons:
        #   * 4.6 is materially less refusal-prone on live-payload code
        #     (4.7 returned stop_reason=refusal on litellm-style fixtures
        #     even with the Senior-Security-Researcher system prompt).
        #   * Legacy ``enabled`` mode lets us pin budget_tokens explicitly
        #     (default 24000 — "extra high"), where 4.7's ``adaptive`` mode
        #     allocates internally and gives no direct knob.
        # Anthropic emits a deprecation warning for enabled-on-4.6;
        # informational, the call still works and gives us the budget knob
        # we want. Migrate to adaptive only if 4.6 stops accepting enabled.
        thinking_budget = self.config.get("thinking_budget", 24000)

        # Opt-in prompt caching on the system block (90% read discount on hits).
        # Off by default so smoke tests with tiny prompts don't trip the
        # 1024-token cache minimum; analysis runners enable it explicitly.
        if self.config.get("enable_system_cache", False):
            system_arg: Any = [
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        else:
            system_arg = system_prompt

        kwargs = {
            "model": self.model_id,
            "max_tokens": self.config.get("max_tokens", 16384) + thinking_budget,
            "system": system_arg,
            "messages": [{"role": "user", "content": user_message}],
            "thinking": {"type": "enabled", "budget_tokens": thinking_budget},
        }

        # Use streaming to avoid SDK timeout for long thinking requests
        text_parts = []
        input_tokens = 0
        output_tokens = 0

        async with client.messages.stream(**kwargs) as stream:
            response = await stream.get_final_message()

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)

        raw_text = "\n".join(text_parts)
        parsed, json_valid = self.parse_response(raw_text)
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens

        return {
            "raw_response": raw_text,
            "parsed": parsed,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "json_valid": json_valid,
            "error": None,
        }


class GoogleAdapter(BaseModelAdapter):
    """Adapter for Google Gemini models (uses google-genai SDK)."""

    async def _call_api(self, system_prompt: str, user_message: str) -> dict:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=self.api_key)

        # Build config — Deep Think ON: use max thinking budget by default
        thinking_budget = self.config.get("thinking_budget", 24576)
        config = types.GenerateContentConfig(
            system_instruction=system_prompt,
            max_output_tokens=self.config.get("max_tokens", 16384),
            thinking_config=types.ThinkingConfig(thinking_budget=thinking_budget) if thinking_budget else None,
            safety_settings=[
                types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="OFF"),
                types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="OFF"),
                types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="OFF"),
                types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="OFF"),
            ],
        )

        response = await client.aio.models.generate_content(
            model=self.model_id,
            contents=user_message,
            config=config,
        )

        # Extract text parts, filtering out thinking blocks
        text_parts = []
        if response.candidates and response.candidates[0].content:
            for part in response.candidates[0].content.parts:
                if hasattr(part, "thought") and part.thought:
                    continue
                if part.text:
                    text_parts.append(part.text)
        raw_text = "\n".join(text_parts) if text_parts else (response.text or "")
        parsed, json_valid = self.parse_response(raw_text)

        usage = response.usage_metadata
        # Gemini reports thinking tokens separately as ``thoughts_token_count``.
        # When thinking is enabled (thinking_config set), the API still
        # bills these at the output rate. To get an accurate cost
        # estimate AND visibility into thinking depth, fold them into
        # output_tokens. Falls back to 0 on older SDK versions or
        # non-thinking models that don't emit the field.
        candidates = (usage.candidates_token_count if usage else 0) or 0
        thoughts = 0
        if usage is not None:
            thoughts = getattr(usage, "thoughts_token_count", 0) or 0
        return {
            "raw_response": raw_text,
            "parsed": parsed,
            "input_tokens": usage.prompt_token_count if usage else 0,
            "output_tokens": candidates + thoughts,
            "thoughts_tokens": thoughts,
            "json_valid": json_valid,
            "error": None,
        }


# ── Factory ─────────────────────────────────────────────────────────────────

_ADAPTERS = {
    "anthropic": AnthropicAdapter,
    "google": GoogleAdapter,
}


def get_adapter(model_config: dict) -> BaseModelAdapter:
    """Factory: create the right adapter for a model's provider."""
    provider = model_config.get("provider", "").lower()
    adapter_cls = _ADAPTERS.get(provider)
    if not adapter_cls:
        raise ValueError(f"Unknown provider: {provider}. Supported: {', '.join(_ADAPTERS.keys())}")
    return adapter_cls(model_config)
