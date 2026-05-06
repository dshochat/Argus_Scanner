"""Statistical confidence engine — logprobs → scores.

Directly implements §9 of docs/echo_scanner_architecture_v3.html.

LLMs are poorly calibrated at generating numbers but well-calibrated at
classification. The model emits a categorical verdict_label under structured
output; the system computes the continuous 0–100 maliciousness score from
the probability distribution over that token.

    score       = Σ prob_i · anchor_i          (weighted expectation)
    uncertainty = entropy(probs) / log2(|categories|)   (normalized 0-1)

If uncertainty > 0.6 → escalate to Pass 2 regardless of label.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from shared.types.enums import VERDICT_ANCHORS, VerdictLabel

PASS2_UNCERTAINTY_THRESHOLD = 0.6


@dataclass
class MaliciousnessResult:
    maliciousness_score: int
    selected_label: str
    label_confidence: float
    model_uncertainty: float
    distribution: dict[str, float]
    pass2_escalated: bool
    anchors: dict[str, int] = field(default_factory=lambda: dict(VERDICT_ANCHORS))


def _normalize_logprobs(token_logprobs: dict[str, float]) -> dict[str, float]:
    """Convert logprobs over verdict tokens into a normalized probability dist."""
    probs = {k: math.exp(v) for k, v in token_logprobs.items()}
    total = sum(probs.values())
    if total <= 0:
        raise ValueError("empty logprob distribution")
    return {k: v / total for k, v in probs.items()}


def compute_verdict(token_logprobs: dict[str, float]) -> MaliciousnessResult:
    """Compute maliciousness score + uncertainty from verdict-label logprobs.

    token_logprobs: raw logprobs over the 5 verdict_label tokens, as extracted
    from vLLM. Extra / unknown keys are ignored. Missing categories are assumed
    to have probability 0.
    """
    raw = {k: v for k, v in token_logprobs.items() if k in VERDICT_ANCHORS}
    if not raw:
        raise ValueError("no verdict_label tokens present in logprobs")

    probs = _normalize_logprobs(raw)
    score = sum(probs[k] * VERDICT_ANCHORS[k] for k in probs)

    entropy = -sum(p * math.log2(p) for p in probs.values() if p > 0)
    denom = math.log2(len(probs)) if len(probs) > 1 else 1.0
    uncertainty = entropy / denom

    selected = max(probs, key=probs.get)  # type: ignore[arg-type]

    return MaliciousnessResult(
        maliciousness_score=round(score),
        selected_label=selected,
        label_confidence=round(probs[selected], 3),
        model_uncertainty=round(uncertainty, 3),
        distribution={k: round(v, 4) for k, v in probs.items()},
        pass2_escalated=uncertainty > PASS2_UNCERTAINTY_THRESHOLD,
    )


def finding_confidence_from_logprobs(label_logprobs: dict[str, float]) -> float:
    """Compute a per-finding confidence (0.0-1.0) from logprobs over confidence_label.

    Anchors: high=1.0, medium=0.6, low=0.25. Same expectation pattern as verdict.
    """
    anchors = {"high": 1.0, "medium": 0.6, "low": 0.25}
    raw = {k: v for k, v in label_logprobs.items() if k in anchors}
    if not raw:
        raise ValueError("no confidence_label tokens present in logprobs")
    probs = _normalize_logprobs(raw)
    return round(sum(probs[k] * anchors[k] for k in probs), 3)


def should_escalate_to_pass2(
    *,
    priority_score: int,
    result: MaliciousnessResult,
    poc_feasible: bool,
    customer_policy: str = "critical_and_high_only",
) -> bool:
    """Apply the Pass 2 gate from §6 / v3.1 changelog Gap 3.1.

    Gate (tightened per v3.1):
      - priority_score == 5         → always (budget permitting)
      - priority_score == 4 + poc_feasible → yes
      - uncertainty > 0.6 + priority_score >= 3 → yes
      - customer policy override     → yes
    """
    if customer_policy == "off":
        return False
    if priority_score >= 5:
        return True
    if priority_score == 4 and poc_feasible:
        return True
    if result.pass2_escalated and priority_score >= 3:
        return True
    if customer_policy == "confirm_all":
        return True
    return False


_ALL_VERDICT_LABELS = [v.value for v in VerdictLabel]
"""Handy list for vLLM guided decoding over the full 5-category enum."""
