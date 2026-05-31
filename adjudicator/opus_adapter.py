"""
opus_verdict_adapter.py — Opus 4.6 adapter for the Verdict Agent.

Uses Claude Opus 4.6 with thinking DISABLED for fast, focused verdicts.
"""

import anthropic
import json
import time
import logging

log = logging.getLogger("verdict-agent")


class OpusVerdictAdapter:
    def __init__(self, api_key, model="claude-opus-4-6"):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def get_verdict(self, system_prompt, user_message, max_retries=2, max_tokens=1024):
        """
        Send to Opus with thinking DISABLED for fast verdict.
        Returns: {verdict, confidence, reasoning, corrected_finding} or None
        """
        for attempt in range(max_retries + 1):
            try:
                start = time.time()

                message = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=0,
                    thinking={"type": "disabled"},
                    system=system_prompt,
                    messages=[
                        {"role": "user", "content": user_message}
                    ],
                )

                elapsed_ms = int((time.time() - start) * 1000)

                # Extract text — no thinking blocks with thinking disabled
                raw_text = "".join(
                    block.text for block in message.content
                    if block.type == "text"
                )

                # Parse JSON
                clean = raw_text.strip()
                if clean.startswith("```"):
                    clean = clean.split("\n", 1)[1]
                    clean = clean.rsplit("```", 1)[0]
                clean = clean.strip()

                verdict = json.loads(clean)

                # Validate
                assert verdict["verdict"] in ("CONFIRMED", "REJECTED", "MODIFIED")
                assert 0.0 <= verdict["confidence"] <= 1.0
                assert "reasoning" in verdict

                # Track usage
                verdict["_input_tokens"] = message.usage.input_tokens
                verdict["_output_tokens"] = message.usage.output_tokens
                verdict["_response_time_ms"] = elapsed_ms

                log.info(
                    "Verdict: %s | Confidence: %.2f | %dms | %din/%dout",
                    verdict["verdict"], verdict["confidence"], elapsed_ms,
                    message.usage.input_tokens, message.usage.output_tokens,
                )

                return verdict

            except anthropic.RateLimitError:
                wait = (attempt + 1) * 15
                log.warning("Rate limited, waiting %ds", wait)
                time.sleep(wait)
                continue
            except json.JSONDecodeError as e:
                log.error("JSON parse error (attempt %d/%d): %s", attempt + 1, max_retries + 1, e)
                if attempt < max_retries:
                    time.sleep(3)
                    continue
                return None
            except Exception as e:
                log.error("Opus API error (attempt %d/%d): %s", attempt + 1, max_retries + 1, e)
                if attempt < max_retries:
                    time.sleep(5)
                    continue
                return None

        return None
