"""Multi-vendor consensus oracle voters (BENCH-014).

To replace the single-vendor / FT-SLM-derived regression oracle, we
run three frontier models from three different vendors against the
same regression suite using ``SECURITY_SCAN_PROMPT``, then compute
a per-file consensus verdict via ordinal-median tie-breaking. The
result becomes the new ground truth for Argus evaluation, eliminating
single-vendor circularity.

Voters:

  * Anthropic Opus 4.6 (``claude-opus-4-6``, thinking_budget=24000)
    Already produced by BENCH-002 — typically reused, no re-run needed.
  * Google Gemini 3.1 Pro (``gemini-3.1-pro-preview``, thinking_budget=24576)
  * OpenAI GPT-5.5 (``gpt-5.5``, reasoning_effort=high)

All voters consume the same ``SECURITY_SCAN_PROMPT``, all produce a
``predicted_verdict`` from ``composite_risk.score`` via the same
``score_to_verdict`` mapping. Per-file output shape:

    VoterRecord(
        file_name=str,
        voter_name="opus_4_6" | "gemini_3_1_pro" | "gpt_5_5",
        predicted_verdict=str | None,  # 4-tier oracle vocab
        composite_score=int | None,
        cost_usd=float,
        ...
    )

Cost budget: ~$15-25 for a full 23-file pass on Gemini + GPT-5.5
(Opus reused from BENCH-002 at $0).

The consensus computation is in :mod:`methodology.oracle_builder`.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from inference.adapters import AnthropicAdapter, GoogleAdapter
from prompts.scanner import SECURITY_SCAN_PROMPT
from scanner.runners import (
    GEMINI_FLASH_LITE_COST_IN,
    GEMINI_FLASH_LITE_COST_OUT,
    OPUS_46_COST_IN,
    OPUS_46_COST_OUT,
    score_to_verdict,
)

log = logging.getLogger("argus.voters")

# ── Voter cost constants (per 1M tokens) ─────────────────────────────────────

# Reuse Opus rates from scanner.runners.
# Gemini 3.1 Pro pricing differs from Flash-Lite; use the Pro tier rates.
# As of 2026-05, Gemini 3.1 Pro is $1.25 / $10 per 1M tokens (input/output).
GEMINI_31_PRO_COST_IN = 1.25
GEMINI_31_PRO_COST_OUT = 10.0

# GPT-5.5 pricing — same rates we use in methodology.judge.
GPT_55_COST_IN = 3.0
GPT_55_COST_OUT = 15.0

# xAI Grok 4.3 pricing (per 1M tokens). Approximate — verify against
# xAI pricing page when needed.
GROK_43_COST_IN = 3.0
GROK_43_COST_OUT = 15.0


# ── Voter record shape ───────────────────────────────────────────────────────


@dataclass
class VoterRecord:
    """One voter's verdict on one file. Compatible with BenchRow shape
    where it overlaps; doesn't carry oracle_verdict (voters BUILD the
    oracle, they don't read from one).

    ``raw_output`` carries the FULL parsed JSON from the model — every
    schema field (vulnerabilities, behavioral_profile, ai_tool_analysis,
    attack_chains, composite_risk, shield_policy). Persisted so future
    analysis (CWE consensus, capability-tag overlap, finding-quality
    judging) doesn't have to re-call the API. Excluded from repr() to
    keep ``str(record)`` readable.
    """

    file_name: str
    voter_name: str
    predicted_verdict: str | None
    composite_score: int | None
    cost_usd: float
    duration_ms: int
    input_tokens: int = 0
    output_tokens: int = 0
    error: str | None = None
    raw_findings: list[dict[str, Any]] = field(default_factory=list)
    raw_output: dict[str, Any] = field(default_factory=dict, repr=False)
    raw_response: str | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_name": self.file_name,
            "voter_name": self.voter_name,
            "predicted_verdict": self.predicted_verdict,
            "composite_score": self.composite_score,
            "cost_usd": round(self.cost_usd, 6),
            "duration_ms": self.duration_ms,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "error": self.error,
            "raw_findings": list(self.raw_findings),
            "raw_output": dict(self.raw_output),
        }


VoterCallable = Callable[[str, bytes], Awaitable[VoterRecord]]


# ── Anthropic Opus 4.6 voter (matches BENCH-002 baseline) ────────────────────


def make_opus_voter(api_key: str) -> VoterCallable:
    """Anthropic Opus 4.6, thinking_budget=24000, max_tokens=32768.

    Output shape mirrors :func:`methodology.bench.make_raw_opus_baseline_runner`
    so existing BENCH-002 runs can be replayed via this voter without
    re-running the API calls (see :func:`load_opus_voter_from_bench_rows`)."""
    adapter = AnthropicAdapter(
        {
            "name": "argus-voter-opus",
            "model_id": "claude-opus-4-6",
            "api_key_encrypted": api_key,
            "provider": "anthropic",
            "config": {
                "thinking_budget": 24000,
                "max_tokens": 32768,
                "enable_system_cache": True,
            },
        }
    )
    return _make_anthropic_or_google_voter(adapter, "opus_4_6", OPUS_46_COST_IN, OPUS_46_COST_OUT)


# ── Google Gemini 3.1 Pro voter ─────────────────────────────────────────────


def make_gemini_voter(
    api_key: str,
    *,
    thinking_budget: int = -1,
) -> VoterCallable:
    """Google Gemini 3.1 Pro Preview with configurable thinking budget.

    ``thinking_budget=-1`` (default) tells Gemini "dynamic / no cap" —
    the model decides how many thinking tokens to spend per file with
    no upper limit. A positive integer caps the budget. ``0`` disables
    thinking entirely.

    Switched default to -1 after observing the 24576 cap led to ~1.7K
    thinking tokens / file (small) — Gemini under-spent the cap on
    typical files. With -1, the model is free to think as deeply as
    needed, particularly on hard cases.
    """
    adapter = GoogleAdapter(
        {
            "name": "argus-voter-gemini",
            "model_id": "gemini-3.1-pro-preview",
            "api_key_encrypted": api_key,
            "provider": "google",
            "config": {
                "thinking_budget": thinking_budget,
                "max_tokens": 32768,
            },
        }
    )
    return _make_anthropic_or_google_voter(
        adapter, "gemini_3_1_pro", GEMINI_31_PRO_COST_IN, GEMINI_31_PRO_COST_OUT
    )


def _make_anthropic_or_google_voter(
    adapter: Any,
    voter_name: str,
    cost_in_per_m: float,
    cost_out_per_m: float,
) -> VoterCallable:
    """Shared runner for Anthropic / Google adapters.

    Adapters expose a uniform ``adapter.scan(content, filename, system_prompt)``
    that returns ``{parsed, json_valid, input_tokens, output_tokens, error}``.
    """

    async def voter(filename: str, content: bytes) -> VoterRecord:
        text = content.decode("utf-8", errors="replace")
        t0 = time.time()
        result = await adapter.scan(text, filename, SECURITY_SCAN_PROMPT)
        elapsed_ms = int((time.time() - t0) * 1000)

        parsed = result.get("parsed") or {}
        json_valid = result.get("json_valid", False)
        composite = (parsed.get("composite_risk") or {}) if isinstance(parsed, dict) else {}
        score = composite.get("score") if isinstance(composite, dict) else None
        verdict = score_to_verdict(score) if json_valid else "suspicious"

        in_tokens = int(result.get("input_tokens", 0))
        out_tokens = int(result.get("output_tokens", 0))
        cost = in_tokens / 1_000_000 * cost_in_per_m + out_tokens / 1_000_000 * cost_out_per_m

        runner_error = result.get("error")
        if runner_error is None and not json_valid:
            runner_error = "json_parse_failed"

        findings: list[dict[str, Any]] = []
        if isinstance(parsed, dict):
            v_list = parsed.get("vulnerabilities") or []
            if isinstance(v_list, list):
                findings = [v for v in v_list if isinstance(v, dict)]

        return VoterRecord(
            file_name=filename,
            voter_name=voter_name,
            predicted_verdict=verdict if json_valid else None,
            composite_score=int(score) if isinstance(score, (int, float)) else None,
            cost_usd=cost,
            duration_ms=elapsed_ms,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            error=runner_error,
            raw_findings=findings,
            raw_output=parsed if isinstance(parsed, dict) else {},
        )

    return voter


# ── OpenAI GPT-5.5 voter (httpx, no SDK) ─────────────────────────────────────


_OPENAI_BASE_URL = "https://api.openai.com/v1"


def make_gpt5_voter(api_key: str, *, model: str = "gpt-5.4") -> VoterCallable:
    """OpenAI voter (defaults to gpt-5.4).

    NOTE: ``gpt-5.5`` returns HTTP 400 (``cyber_policy``) on direct
    vulnerability-analysis prompts unless the account is enrolled in
    OpenAI's "Trusted Access for Cyber" program. ``gpt-5.4`` accepts
    the same prompt without the policy block — verified empirically
    on 2026-05-05. Both are reasoning-class models accepting
    ``reasoning_effort=high``.

    Older fallbacks: ``gpt-4.1``, ``gpt-4o`` also work but lack
    reasoning_effort (regular chat models, not reasoning-class).

    Uses httpx directly (no openai SDK dep) to match the judge's
    plumbing. ``response_format=json_object`` forces parseable output.
    """

    async def voter(filename: str, content: bytes) -> VoterRecord:
        text = content.decode("utf-8", errors="replace")
        user_message = (
            f"Filename: {filename}\nLanguage: {_detect_language(filename)}\n\n```\n{text}\n```"
        )
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": SECURITY_SCAN_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "response_format": {"type": "json_object"},
        }
        # Reasoning models (gpt-5.x) accept reasoning_effort. Older chat
        # models (gpt-4o, gpt-4.1) reject it — only set when applicable.
        if model.startswith("gpt-5"):
            payload["reasoning_effort"] = "high"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        t0 = time.time()
        verdict: str | None = None
        composite: int | None = None
        in_tokens = 0
        out_tokens = 0
        error: str | None = None
        findings: list[dict[str, Any]] = []
        raw_text: str | None = None
        parsed: dict[str, Any] = {}

        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                resp = await client.post(
                    f"{_OPENAI_BASE_URL}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                raise ValueError("no choices in OpenAI response")
            raw_text = (choices[0].get("message") or {}).get("content") or ""
            if not raw_text:
                raise ValueError("empty content in OpenAI response")
            parsed_obj = json.loads(raw_text)
            if isinstance(parsed_obj, dict):
                parsed = parsed_obj
                cr = parsed.get("composite_risk") or {}
                score = cr.get("score") if isinstance(cr, dict) else None
                verdict = score_to_verdict(score)
                if isinstance(score, (int, float)):
                    composite = int(score)
                v_list = parsed.get("vulnerabilities") or []
                if isinstance(v_list, list):
                    findings = [v for v in v_list if isinstance(v, dict)]
            usage = data.get("usage") or {}
            in_tokens = int(usage.get("prompt_tokens") or 0)
            out_tokens = int(usage.get("completion_tokens") or 0)
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as e:
            error = f"{type(e).__name__}: {e}"

        elapsed_ms = int((time.time() - t0) * 1000)
        # Cost rates depend on the model — use GPT-5.5 rates for gpt-5.x,
        # gpt-4o rates ($2.50/$10) for gpt-4o, and gpt-4.1 rates ($2/$8)
        # for gpt-4.1. Approximate; OpenAI publishes the canonical figures.
        if model.startswith("gpt-5"):
            cost_in_per_m, cost_out_per_m = GPT_55_COST_IN, GPT_55_COST_OUT
        elif model.startswith("gpt-4o"):
            cost_in_per_m, cost_out_per_m = 2.5, 10.0
        elif model.startswith("gpt-4.1"):
            cost_in_per_m, cost_out_per_m = 2.0, 8.0
        else:
            cost_in_per_m, cost_out_per_m = GPT_55_COST_IN, GPT_55_COST_OUT
        cost = in_tokens / 1_000_000 * cost_in_per_m + out_tokens / 1_000_000 * cost_out_per_m

        # Voter name reflects the actual model used. Examples:
        #   gpt-5.4   -> gpt_5_4
        #   gpt-5.5   -> gpt_5_5
        #   gpt-4.1   -> gpt_4_1
        #   gpt-4o    -> gpt_4o
        voter_name = "gpt_" + (model.replace("gpt-", "").replace("-", "_").replace(".", "_"))

        return VoterRecord(
            file_name=filename,
            voter_name=voter_name,
            predicted_verdict=verdict,
            composite_score=composite,
            cost_usd=cost,
            duration_ms=elapsed_ms,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            error=error,
            raw_findings=findings,
            raw_output=parsed,
            raw_response=raw_text,
        )

    return voter


# ── xAI Grok 4.3 voter (OpenAI-compatible API) ───────────────────────────────


_XAI_BASE_URL = "https://api.x.ai/v1"


def make_grok_voter(api_key: str, *, model: str = "grok-4.3") -> VoterCallable:
    """xAI Grok voter (defaults to Grok 4.3 with reasoning_effort=high).

    xAI exposes an OpenAI-compatible chat-completions endpoint at
    ``api.x.ai/v1`` so the call shape is identical to the GPT voter.
    Only Grok 4.3 (current reasoning model) accepts ``reasoning_effort``;
    older Grok variants reject the parameter (HTTP 400).
    """

    async def voter(filename: str, content: bytes) -> VoterRecord:
        text = content.decode("utf-8", errors="replace")
        user_message = (
            f"Filename: {filename}\nLanguage: {_detect_language(filename)}\n\n```\n{text}\n```"
        )
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": SECURITY_SCAN_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "response_format": {"type": "json_object"},
        }
        # Grok 4.3 (and later) accept reasoning_effort. Older variants reject it.
        if "4.3" in model or "5" in model:
            payload["reasoning_effort"] = "high"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        t0 = time.time()
        verdict: str | None = None
        composite: int | None = None
        in_tokens = 0
        out_tokens = 0
        error: str | None = None
        findings: list[dict[str, Any]] = []
        raw_text: str | None = None
        parsed: dict[str, Any] = {}

        try:
            async with httpx.AsyncClient(timeout=600.0) as client:
                resp = await client.post(
                    f"{_XAI_BASE_URL}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                raise ValueError("no choices in xAI response")
            raw_text = (choices[0].get("message") or {}).get("content") or ""
            if not raw_text:
                raise ValueError("empty content in xAI response")
            parsed_obj = json.loads(raw_text)
            if isinstance(parsed_obj, dict):
                parsed = parsed_obj
                cr = parsed.get("composite_risk") or {}
                score = cr.get("score") if isinstance(cr, dict) else None
                verdict = score_to_verdict(score)
                if isinstance(score, (int, float)):
                    composite = int(score)
                v_list = parsed.get("vulnerabilities") or []
                if isinstance(v_list, list):
                    findings = [v for v in v_list if isinstance(v, dict)]
            usage = data.get("usage") or {}
            in_tokens = int(usage.get("prompt_tokens") or 0)
            out_tokens = int(usage.get("completion_tokens") or 0)
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as e:
            error = f"{type(e).__name__}: {e}"

        elapsed_ms = int((time.time() - t0) * 1000)
        cost = in_tokens / 1_000_000 * GROK_43_COST_IN + out_tokens / 1_000_000 * GROK_43_COST_OUT

        # Voter name normalises model id ("grok-4.3" -> "grok_4_3").
        voter_name = "grok_" + model.replace("grok-", "").replace("-", "_").replace(".", "_")

        return VoterRecord(
            file_name=filename,
            voter_name=voter_name,
            predicted_verdict=verdict,
            composite_score=composite,
            cost_usd=cost,
            duration_ms=elapsed_ms,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            error=error,
            raw_findings=findings,
            raw_output=parsed,
            raw_response=raw_text,
        )

    return voter


def _detect_language(filename: str) -> str:
    """Lightweight extension-based language label for the prompt user message."""
    fn = filename.lower()
    for ext, lang in (
        (".py", "python"),
        (".js", "javascript"),
        (".ts", "typescript"),
        (".jsx", "jsx"),
        (".tsx", "tsx"),
        (".go", "go"),
        (".rs", "rust"),
        (".java", "java"),
        (".sh", "bash"),
        (".pth", "python"),
        (".json", "json"),
        (".yaml", "yaml"),
        (".yml", "yaml"),
    ):
        if fn.endswith(ext):
            return lang
    return "text"


# ── Reusing existing BENCH-002 data for the Opus voter ───────────────────────


def load_opus_voter_from_bench_rows(bench_rows_path: Path) -> list[VoterRecord]:
    """Convert a saved ``raw_opus_run1.json`` into ``VoterRecord``\\s
    so we can reuse BENCH-002 data without re-paying API cost.

    Reconstructs ``raw_output`` from the typed BenchRow fields when the
    saved row pre-dates the BenchRow.raw_output addition (older runs
    don't have it). This ensures rich-dimension extractors
    (capability tags, dangerous APIs, behavioral categories) work on
    the materialised opus voter records.
    """
    if not bench_rows_path.exists():
        return []
    try:
        data = json.loads(bench_rows_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    out: list[VoterRecord] = []
    if not isinstance(data, list):
        return out
    for d in data:
        if not isinstance(d, dict):
            continue
        # Prefer the row's saved raw_output (newer runs); fall back to
        # reconstructing from typed fields (older runs).
        raw_output: dict[str, Any] = dict(d.get("raw_output") or {})
        if not raw_output:
            raw_output = {
                "vulnerabilities": list(d.get("vulnerabilities") or []),
                "behavioral_profile": dict(d.get("behavioral_profile") or {}),
                "attack_chains": list(d.get("attack_chains") or []),
            }
        out.append(
            VoterRecord(
                file_name=d.get("file_name", ""),
                voter_name="opus_4_6",
                predicted_verdict=d.get("predicted_verdict"),
                composite_score=None,  # not serialized in BenchRow
                cost_usd=float(d.get("cost_usd", 0.0)),
                duration_ms=int(d.get("duration_ms", 0)),
                input_tokens=int(d.get("input_tokens", 0)),
                output_tokens=int(d.get("output_tokens", 0)),
                error=d.get("error"),
                raw_findings=list(d.get("vulnerabilities") or []),
                raw_output=raw_output,
            )
        )
    return out


# ── Batch runner ─────────────────────────────────────────────────────────────


def _atomic_write_json(path: Path, payload: list[dict[str, Any]]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    try:
        tmp.replace(path)
    except OSError:
        path.write_text(json.dumps(payload, indent=2))
        try:
            tmp.unlink()
        except OSError:
            pass


def _load_existing_voter_records(path: Path) -> list[VoterRecord]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    out: list[VoterRecord] = []
    for d in data:
        if not isinstance(d, dict):
            continue
        out.append(
            VoterRecord(
                file_name=d.get("file_name", ""),
                voter_name=d.get("voter_name", ""),
                predicted_verdict=d.get("predicted_verdict"),
                composite_score=d.get("composite_score"),
                cost_usd=float(d.get("cost_usd", 0.0)),
                duration_ms=int(d.get("duration_ms", 0)),
                input_tokens=int(d.get("input_tokens", 0)),
                output_tokens=int(d.get("output_tokens", 0)),
                error=d.get("error"),
                raw_findings=list(d.get("raw_findings") or []),
                raw_output=dict(d.get("raw_output") or {}),
            )
        )
    return out


async def run_voter(
    voter: VoterCallable,
    files: list[tuple[str, bytes]],
    *,
    output_path: Path,
    progress_callback: Any = None,
    resume: bool = True,
) -> list[VoterRecord]:
    """Run a voter on a list of (filename, content) pairs.

    Streams to ``output_path`` after each file (atomic tmp+rename) so a
    mid-run crash doesn't lose prior records. ``resume=True`` skips
    files whose record is already saved.
    """
    existing = _load_existing_voter_records(output_path) if resume else []
    done_names = {r.file_name for r in existing}
    rows = list(existing)

    todo = [(fn, content) for fn, content in files if fn not in done_names]
    log.info("voter run: %d files (%d resumed, %d to do)", len(files), len(rows), len(todo))

    for i, (filename, content) in enumerate(todo, 1):
        record = await voter(filename, content)
        rows.append(record)
        _atomic_write_json(output_path, [r.to_dict() for r in rows])
        if progress_callback is not None:
            progress_callback(i, len(todo), record)

    return rows


def get_api_keys_from_env() -> dict[str, str | None]:
    """Read voter API keys from environment. Caller decides what to do
    when one is missing."""
    return {
        "anthropic": os.environ.get("ANTHROPIC_API_KEY") or None,
        "gemini": os.environ.get("GEMINI_API_KEY") or None,
        "openai": os.environ.get("OPENAI_API_KEY") or None,
        "grok": os.environ.get("GROK_API_KEY") or None,
    }


__all__ = [
    "GEMINI_31_PRO_COST_IN",
    "GEMINI_31_PRO_COST_OUT",
    "GPT_55_COST_IN",
    "GPT_55_COST_OUT",
    "GROK_43_COST_IN",
    "GROK_43_COST_OUT",
    "VoterRecord",
    "get_api_keys_from_env",
    "load_opus_voter_from_bench_rows",
    "make_gemini_voter",
    "make_gpt5_voter",
    "make_grok_voter",
    "make_opus_voter",
    "run_voter",
]
