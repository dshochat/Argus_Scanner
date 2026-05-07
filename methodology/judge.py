"""BENCH-011 — GPT-5.5 independent judge on Argus / vanilla Opus disagreements.

For each file where Argus and vanilla Opus disagree (and the oracle
verdict may also disagree), feed GPT-5.5:

  * the file's source code (so it can reason from primary evidence)
  * two BLINDED positions A and B — one is Argus's, one is vanilla
    Opus's, but the judge doesn't know which
  * the oracle verdict label (with a caveat that the oracle is itself
    fallible — variance_characterization for 18/23 files, opus_confirmed
    for 5/23)

GPT-5.5 returns ``{verdict, agree_with: "A"|"B"|"both"|"neither",
reasoning, confidence}``. We decode A/B back to argus/opus using the
randomization mapping we kept.

Why blinded: if the judge knew "the cascade product" was producing one
position, it might bias toward us (we built the question). Blinding +
random A/B order eliminates that.

Why GPT-5.5 (not Opus, not Sonnet): same-family circularity. Argus's
own Opus 4.6 produces position A on most disagreements; using Opus to
judge Opus-vs-Opus is just measuring effort variance within the
family. A different vendor's frontier model is an honest tiebreaker.

Cost: ~$5-10 per full run on the 23-file suite (typically 5-10
disagreements × ~$1 per judgment with thinking).

Output schema (one record per disagreement):

    {
      "file_name": "litellm_obfuscated.py",
      "judge_model": "gpt-5.5",
      "oracle_verdict": "critical_malicious",
      "argus_verdict": "critical_malicious",
      "opus_verdict": "suspicious",
      "judgment": {
        "verdict": "critical_malicious",
        "agree_with": "argus",          # decoded from A/B
        "agree_with_blinded": "A",       # what GPT actually returned
        "reasoning": "...",
        "confidence": 0.85
      },
      "ab_mapping": {"A": "argus", "B": "opus"},
      "tokens_in": 1234, "tokens_out": 567,
      "cost_usd": 0.0234,
      "duration_ms": 4321,
      "error": null
    }

The runner is gated by ``OPENAI_API_KEY`` in ``.env``. Without it, no
judgments are produced — BENCH-012 still runs and notes "no judge
output" in the launch report.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger("argus.judge")

# OpenAI pricing for GPT-5.5 (per 1M tokens). Update these if Anthropic /
# OpenAI publish revised rates. Bench cost is reported using these
# constants; mismatch with actual billed cost is the only consequence.
GPT_55_COST_IN = 3.0
GPT_55_COST_OUT = 15.0

DEFAULT_JUDGE_MODEL = "gpt-5.5"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
MAX_FILE_CONTENT_CHARS = 60_000  # ~15k tokens — keeps cost reasonable

JUDGE_SYSTEM_PROMPT = """\
You are an independent senior security researcher adjudicating a \
disagreement between two automated code scanners. The scanners have \
analyzed a file and reached different verdicts. Your job is to \
evaluate which scanner is correct based on the actual code evidence \
— not on which scanner's findings sound more confident.

You will receive:
  1. The file's source code.
  2. An "oracle" verdict label from a prior labeling pass. The oracle \
     may be wrong; treat it as a prior, not as ground truth.
  3. Two unlabeled positions, "A" and "B". Each position contains a \
     verdict and a list of structured findings. You do NOT know which \
     scanner produced which position.

Verdict scale (most-severe → least-severe):
  critical_malicious — clear active attack (RCE, exfil, persistent backdoor)
  malicious          — high-confidence malicious behavior
  suspicious         — anomalous patterns, ambiguous intent
  low_concern        — minor issues, likely benign
  clean              — no security concerns

Return JSON only, in this exact shape:

  {
    "verdict": "<one of: critical_malicious | malicious | suspicious | low_concern | clean>",
    "agree_with": "<one of: A | B | both | neither>",
    "reasoning": "<2-4 sentence justification grounded in the actual code>",
    "confidence": <float in [0.0, 1.0]>
  }

Rules:
  * "agree_with": A or B if exactly one position matches your verdict; \
    "both" if both positions match; "neither" if neither matches.
  * Ground reasoning in specific code locations / behaviors. Don't \
    parrot the scanner's findings — verify them against the source.
  * If the file is truncated (you'll see "[file truncated]"), reason \
    only from what you saw and lower your confidence accordingly.
  * No prose outside the JSON object."""


# ── Data shape ────────────────────────────────────────────────────────────────


@dataclass
class JudgmentRecord:
    """One judgment on one disagreement."""

    file_name: str
    judge_model: str
    oracle_verdict: str | None
    argus_verdict: str | None
    opus_verdict: str | None
    judgment: dict[str, Any]
    ab_mapping: dict[str, str]  # {"A": "argus", "B": "opus"} or vice-versa
    tokens_in: int
    tokens_out: int
    cost_usd: float
    duration_ms: int
    error: str | None = None
    raw_response: str | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_name": self.file_name,
            "judge_model": self.judge_model,
            "oracle_verdict": self.oracle_verdict,
            "argus_verdict": self.argus_verdict,
            "opus_verdict": self.opus_verdict,
            "judgment": self.judgment,
            "ab_mapping": dict(self.ab_mapping),
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "cost_usd": round(self.cost_usd, 6),
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


# ── Position randomization (A/B blinding) ─────────────────────────────────────


def randomize_positions(
    payload: dict[str, Any],
    *,
    seed: str | int | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Shuffle the (argus, opus) pair into (A, B) and return the mapping.

    ``seed`` makes the randomization deterministic per file (use the
    file_name) — important for reproducibility: re-running the judge
    on the same input yields the same blinding. ``None`` → fresh
    randomness each call.

    Returns ``(payload_with_AB_positions, {"A": <internal_label>, "B": <internal_label>})``.
    Strips ``_label_internal`` from the position dicts in the returned
    payload — the judge never sees those.
    """
    positions = list(payload.get("positions") or [])
    if len(positions) != 2:
        raise ValueError(f"expected 2 positions, got {len(positions)} for {payload.get('file_name')!r}")
    rng = random.Random(seed)
    indices = [0, 1]
    rng.shuffle(indices)
    ab_keys = ["A", "B"]
    mapping: dict[str, str] = {}
    blinded_positions: list[dict[str, Any]] = []
    for ab, idx in zip(ab_keys, indices, strict=True):
        pos = dict(positions[idx])
        internal = pos.pop("_label_internal", "unknown")
        mapping[ab] = internal
        pos["_ab"] = ab  # purely for the prompt's structure
        blinded_positions.append(pos)
    blinded_payload = {
        "file_name": payload.get("file_name"),
        "file_content": payload.get("file_content"),
        "oracle_verdict": payload.get("oracle_verdict"),
        "positions_AB": blinded_positions,
    }
    return blinded_payload, mapping


# ── Prompt construction ───────────────────────────────────────────────────────


def _truncate_file_content(content: str | None, max_chars: int = MAX_FILE_CONTENT_CHARS) -> str:
    if not content:
        return "[file content unavailable]"
    if len(content) <= max_chars:
        return content
    return content[:max_chars] + "\n\n[file truncated]"


def build_user_message(blinded_payload: dict[str, Any]) -> str:
    """Render the user message GPT-5.5 sees for one disagreement."""
    file_name = blinded_payload.get("file_name") or "<unknown>"
    oracle = blinded_payload.get("oracle_verdict") or "<no oracle label>"
    content = _truncate_file_content(blinded_payload.get("file_content"))
    positions = blinded_payload.get("positions_AB") or []

    lines: list[str] = [
        f"File: {file_name}",
        f"Oracle verdict (prior, may be wrong): {oracle}",
        "",
        "─── Source code ───",
        "```",
        content,
        "```",
        "",
        "─── Competing positions ───",
    ]
    for pos in positions:
        ab = pos.get("_ab") or "?"
        verdict = pos.get("verdict") or "<no verdict>"
        n_findings = pos.get("n_findings", 0)
        refused = pos.get("refused", False)
        findings = pos.get("findings") or []
        lines.append("")
        lines.append(f"### Position {ab}")
        lines.append(f"verdict: {verdict}")
        lines.append(f"refused: {refused}")
        lines.append(f"n_findings: {n_findings}")
        if findings:
            lines.append("findings:")
            for f in findings[:20]:  # cap to avoid prompt bloat
                cwe = f.get("cwe") or ""
                ftype = f.get("type") or ""
                sev = f.get("severity") or ""
                line = f.get("line")
                title = f.get("title") or ""
                lines.append(f"  - [{cwe}] {ftype} ({sev}) line={line} — {title}")
            if len(findings) > 20:
                lines.append(f"  ... ({len(findings) - 20} more findings omitted)")
    lines.append("")
    lines.append("Return your judgment as JSON per the system prompt.")
    return "\n".join(lines)


# ── OpenAI HTTP call ──────────────────────────────────────────────────────────


async def _call_openai(
    *,
    api_key: str,
    model: str,
    system_prompt: str,
    user_message: str,
    base_url: str = DEFAULT_OPENAI_BASE_URL,
    http_client: httpx.AsyncClient | None = None,
    timeout_s: float = 300.0,
    reasoning_effort: str | None = "high",
) -> dict[str, Any]:
    """Single chat-completion call. Returns the raw OpenAI response dict.

    Uses ``response_format={"type": "json_object"}`` to force valid JSON;
    GPT-5.5 still emits a string we have to ``json.loads`` — but the API
    guarantees the string parses.

    Notes:
      * GPT-5.5 (reasoning-class) rejects ``temperature`` overrides —
        only the default value is supported, so we omit the parameter.
      * ``reasoning_effort`` defaults to ``"high"`` because the judge is
        a load-bearing decision (security verdict adjudication). Setting
        it explicitly produces deeper reasoning; the default ``"medium"``
        underspends thinking tokens on adversarial security reasoning.
        Pass ``None`` to omit the parameter (uses model default).
    """
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "response_format": {"type": "json_object"},
    }
    if reasoning_effort is not None:
        payload["reasoning_effort"] = reasoning_effort
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    url = f"{base_url}/chat/completions"

    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=timeout_s)
    try:
        resp = await client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]
    finally:
        if own_client:
            await client.aclose()


def parse_judgment(api_response: dict[str, Any]) -> tuple[dict[str, Any], int, int, str]:
    """Extract the structured judgment + token counts from an OpenAI response.

    Returns ``(judgment, in_tokens, out_tokens, raw_text)``. Raises
    ``ValueError`` if the response shape is unexpected or the JSON is
    invalid.
    """
    choices = api_response.get("choices") or []
    if not choices:
        raise ValueError("no choices in OpenAI response")
    msg = (choices[0] or {}).get("message") or {}
    raw_text = msg.get("content") or ""
    if not raw_text:
        raise ValueError("empty content in OpenAI response")
    try:
        judgment = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"judge returned invalid JSON: {e}") from e
    usage = api_response.get("usage") or {}
    in_tokens = int(usage.get("prompt_tokens") or 0)
    out_tokens = int(usage.get("completion_tokens") or 0)
    return judgment, in_tokens, out_tokens, raw_text


def _decode_agree_with(blinded: str | None, mapping: dict[str, str]) -> str | None:
    """Translate ``"A"|"B"|"both"|"neither"`` from the judge into the
    underlying scanner label (``"argus"|"opus"|"both"|"neither"``).
    Unknown values pass through unchanged."""
    if not blinded:
        return None
    if blinded in ("both", "neither"):
        return blinded
    return mapping.get(blinded, blinded)


# ── Single judgment ───────────────────────────────────────────────────────────


async def judge_one(
    diff_record: dict[str, Any],
    *,
    api_key: str,
    model: str = DEFAULT_JUDGE_MODEL,
    base_url: str = DEFAULT_OPENAI_BASE_URL,
    http_client: httpx.AsyncClient | None = None,
    seed: str | int | None = None,
) -> JudgmentRecord:
    """Run the judge on a single diff record. The record must have a
    non-None ``judge_payload``; if not, raises ``ValueError``."""
    payload = diff_record.get("judge_payload")
    if payload is None:
        raise ValueError(f"no judge_payload on record for {diff_record.get('file_name')!r}")
    file_name = diff_record.get("file_name") or payload.get("file_name") or "<unknown>"
    seed_to_use = seed if seed is not None else file_name
    blinded_payload, mapping = randomize_positions(payload, seed=seed_to_use)
    user_message = build_user_message(blinded_payload)
    vm = diff_record.get("verdict_match") or {}

    t0 = time.time()
    error: str | None = None
    judgment_decoded: dict[str, Any] = {}
    in_tokens = 0
    out_tokens = 0
    raw_text: str | None = None
    try:
        api_response = await _call_openai(
            api_key=api_key,
            model=model,
            system_prompt=JUDGE_SYSTEM_PROMPT,
            user_message=user_message,
            base_url=base_url,
            http_client=http_client,
        )
        judgment, in_tokens, out_tokens, raw_text = parse_judgment(api_response)
        judgment_decoded = {
            "verdict": judgment.get("verdict"),
            "agree_with_blinded": judgment.get("agree_with"),
            "agree_with": _decode_agree_with(judgment.get("agree_with"), mapping),
            "reasoning": judgment.get("reasoning"),
            "confidence": judgment.get("confidence"),
        }
    except (httpx.HTTPError, ValueError) as e:
        error = f"{type(e).__name__}: {e}"
        log.warning("judge failed on %s: %s", file_name, error)
    duration_ms = int((time.time() - t0) * 1000)

    cost = in_tokens / 1_000_000 * GPT_55_COST_IN + out_tokens / 1_000_000 * GPT_55_COST_OUT
    return JudgmentRecord(
        file_name=file_name,
        judge_model=model,
        oracle_verdict=vm.get("oracle"),
        argus_verdict=vm.get("argus"),
        opus_verdict=vm.get("opus"),
        judgment=judgment_decoded,
        ab_mapping=mapping,
        tokens_in=in_tokens,
        tokens_out=out_tokens,
        cost_usd=cost,
        duration_ms=duration_ms,
        error=error,
        raw_response=raw_text,
    )


# ── Batch runner ──────────────────────────────────────────────────────────────


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


def disagreement_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Subset of diff records that have a non-None ``judge_payload``.

    BENCH-010 already computes this — files with all three sources
    matching (or with the missing-source case being unanimous) get a
    ``None`` judge_payload and are skipped here.
    """
    return [r for r in records if r.get("judge_payload") is not None]


async def run_judge(
    records: list[dict[str, Any]],
    *,
    api_key: str,
    model: str = DEFAULT_JUDGE_MODEL,
    output_path: Path | None = None,
    base_url: str = DEFAULT_OPENAI_BASE_URL,
    http_client: httpx.AsyncClient | None = None,
    progress_callback: Any = None,
) -> list[JudgmentRecord]:
    """Run the judge on every disagreement and (optionally) save results.

    Streams to ``output_path`` after each judgment so a mid-run crash
    doesn't lose prior judgments.
    """
    targets = disagreement_records(records)
    log.info("judge: %d disagreements to adjudicate", len(targets))

    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=180.0)
    out: list[JudgmentRecord] = []
    try:
        for i, rec in enumerate(targets, 1):
            judgment = await judge_one(
                rec,
                api_key=api_key,
                model=model,
                base_url=base_url,
                http_client=client,
            )
            out.append(judgment)
            if output_path is not None:
                _atomic_write_json(output_path, [j.to_dict() for j in out])
            if progress_callback is not None:
                progress_callback(i, len(targets), judgment)
    finally:
        if own_client:
            await client.aclose()
    return out


# ── Aggregation helpers (consumed by BENCH-012) ───────────────────────────────


def summarize_judgments(judgments: list[JudgmentRecord]) -> dict[str, Any]:
    """Tally judge outcomes across a run.

    Returns counts per ``agree_with`` bucket plus mean confidence and
    total cost. BENCH-012's launch report renders this directly.
    """
    n = len(judgments)
    if n == 0:
        return {
            "n_disagreements": 0,
            "judge_picked_argus": 0,
            "judge_picked_opus": 0,
            "judge_picked_both": 0,
            "judge_picked_neither": 0,
            "judge_errors": 0,
            "mean_confidence": None,
            "total_cost_usd": 0.0,
        }
    counts = {"argus": 0, "opus": 0, "both": 0, "neither": 0, "unknown": 0}
    confidences: list[float] = []
    errors = 0
    total_cost = 0.0
    for j in judgments:
        if j.error:
            errors += 1
            continue
        bucket = j.judgment.get("agree_with") or "unknown"
        counts[bucket] = counts.get(bucket, 0) + 1
        c = j.judgment.get("confidence")
        if isinstance(c, (int, float)):
            confidences.append(float(c))
        total_cost += j.cost_usd
    return {
        "n_disagreements": n,
        "judge_picked_argus": counts.get("argus", 0),
        "judge_picked_opus": counts.get("opus", 0),
        "judge_picked_both": counts.get("both", 0),
        "judge_picked_neither": counts.get("neither", 0),
        "judge_errors": errors,
        "mean_confidence": (round(sum(confidences) / len(confidences), 3) if confidences else None),
        "total_cost_usd": round(total_cost, 4),
    }


# ── Module entry point ────────────────────────────────────────────────────────


def load_diff_report(path: Path) -> list[dict[str, Any]]:
    """Load a saved diff report (BENCH-010 output)."""
    with path.open() as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"expected list of diff records at {path}, got {type(data)}")
    return data


def get_api_key_from_env() -> str | None:
    """Read OPENAI_API_KEY from the environment. Caller decides what to
    do if it's missing — the bench harness skips the judge gracefully."""
    return os.environ.get("OPENAI_API_KEY") or None


__all__ = [
    "DEFAULT_JUDGE_MODEL",
    "GPT_55_COST_IN",
    "GPT_55_COST_OUT",
    "JUDGE_SYSTEM_PROMPT",
    "JudgmentRecord",
    "build_user_message",
    "disagreement_records",
    "get_api_key_from_env",
    "judge_one",
    "load_diff_report",
    "parse_judgment",
    "randomize_positions",
    "run_judge",
    "summarize_judgments",
]
