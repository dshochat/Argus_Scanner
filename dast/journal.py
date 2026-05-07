"""Disk-backed JSONL journal for DAST iterations.

Each iteration appends structured records to ``journals/<file_id>.jsonl``.
Subsequent iterations read a model-friendly *summary* derived from the
journal; raw records never re-enter the model context. This is how the
prototype tests its central efficiency claim against unstructured
frontier+journal approaches (10M Opus, 27M GLM-5.1 per investigation).

Journal-compression contract (measured in smoke):
    token_count_at_iter(N+1) <= 0.6 * token_count_at_iter(N)

If the ratio approaches 1.0 the pattern is failing — flag for prompt
adjustment in Step 3 review. Empirically we expect compression around
0.05 because the rule-based summarizer collapses raw events into a
short paragraph keyed on counts + IDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict


class JournalPhase(str, Enum):
    PHASE_A_PLAN = "phase_a_plan"
    PHASE_A_VERDICT = "phase_a_verdict"
    PHASE_B_HYPOTHESIS = "phase_b_hypothesis"
    SANDBOX_EXEC = "sandbox_exec"


ClaimVerdict = Literal["confirmed", "refuted", "inconclusive", "rejected"]


class JournalRecord(BaseModel):
    """One iteration event. Append-only."""

    model_config = ConfigDict(extra="forbid")

    iter: int
    phase: JournalPhase
    claim_id: str | None = None
    verdict: ClaimVerdict | None = None
    rationale: str = ""
    evidence_refs: list[str] = []
    sandbox_event_id: str | None = None
    model_tokens_in: int = 0
    model_tokens_out: int = 0


@dataclass
class JournalSummary:
    """Compressed iteration history that goes into the next prompt."""

    up_to_iter: int
    confirmed_findings: list[str] = field(default_factory=list)
    refuted_findings: list[str] = field(default_factory=list)
    inconclusive_findings: list[str] = field(default_factory=list)
    accepted_hypotheses: list[str] = field(default_factory=list)
    rejected_hypotheses: list[str] = field(default_factory=list)
    open_threads: list[str] = field(default_factory=list)
    summary_text: str = ""
    token_count: int = 0

    def to_dict(self) -> dict:
        return {
            "up_to_iter": self.up_to_iter,
            "confirmed_findings": self.confirmed_findings,
            "refuted_findings": self.refuted_findings,
            "inconclusive_findings": self.inconclusive_findings,
            "accepted_hypotheses": self.accepted_hypotheses,
            "rejected_hypotheses": self.rejected_hypotheses,
            "open_threads": self.open_threads,
            "summary_text": self.summary_text,
            "token_count": self.token_count,
        }


def _approx_tokens(s: str) -> int:
    """Cheap token count: ~4 chars per token. Good enough for compression
    measurement, where the question is order-of-magnitude not exact."""
    return max(1, len(s) // 4)


def _safe_filename(file_id: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in file_id)


class Journal:
    """Read/write interface to ``journals/<file_id>.jsonl``."""

    def __init__(self, file_id: str, base_dir: Path) -> None:
        self.file_id = file_id
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.base_dir / f"{_safe_filename(file_id)}.jsonl"
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def append(self, record: JournalRecord) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")

    def read_all(self) -> list[JournalRecord]:
        if not self.path.exists():
            return []
        records: list[JournalRecord] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            records.append(JournalRecord.model_validate_json(line))
        return records

    def summarize(self, *, up_to_iter: int) -> JournalSummary:
        recs = [r for r in self.read_all() if r.iter <= up_to_iter]
        confirmed: list[str] = []
        refuted: list[str] = []
        inconclusive: list[str] = []
        accepted_hyps: list[str] = []
        rejected_hyps: list[str] = []

        for r in recs:
            cid = r.claim_id or ""
            if r.phase == JournalPhase.PHASE_A_VERDICT and cid:
                if r.verdict == "confirmed" and cid not in confirmed:
                    confirmed.append(cid)
                elif r.verdict == "refuted" and cid not in refuted:
                    refuted.append(cid)
                elif r.verdict == "inconclusive" and cid not in inconclusive:
                    inconclusive.append(cid)
            elif r.phase == JournalPhase.PHASE_B_HYPOTHESIS and cid:
                if r.verdict == "rejected" and cid not in rejected_hyps:
                    rejected_hyps.append(cid)
                elif r.verdict != "rejected" and cid not in accepted_hyps:
                    accepted_hyps.append(cid)

        # Findings IDs collected from Phase A verdict records' evidence_refs
        finding_set: list[str] = []
        for r in recs:
            if r.phase == JournalPhase.PHASE_A_VERDICT and r.verdict == "confirmed":
                for f in r.evidence_refs:
                    if f.startswith("F") and f not in finding_set:
                        finding_set.append(f)

        if up_to_iter == 0:
            text = "No prior iterations. This is iter 1."
        else:
            parts: list[str] = []
            for it in range(1, up_to_iter + 1):
                it_recs = [r for r in recs if r.iter == it]
                it_conf = [
                    r.claim_id for r in it_recs if r.phase == JournalPhase.PHASE_A_VERDICT and r.verdict == "confirmed"
                ]
                it_ref = [
                    r.claim_id for r in it_recs if r.phase == JournalPhase.PHASE_A_VERDICT and r.verdict == "refuted"
                ]
                it_inc = [
                    r.claim_id
                    for r in it_recs
                    if r.phase == JournalPhase.PHASE_A_VERDICT and r.verdict == "inconclusive"
                ]
                it_acc = [
                    r.claim_id
                    for r in it_recs
                    if r.phase == JournalPhase.PHASE_B_HYPOTHESIS and r.verdict != "rejected"
                ]
                it_rej = [
                    r.claim_id
                    for r in it_recs
                    if r.phase == JournalPhase.PHASE_B_HYPOTHESIS and r.verdict == "rejected"
                ]
                bits = [f"Iter {it}:"]
                if it_conf:
                    bits.append(f"confirmed={it_conf}")
                if it_ref:
                    bits.append(f"refuted={it_ref}")
                if it_inc:
                    bits.append(f"inconclusive={it_inc}")
                if it_acc:
                    bits.append(f"accepted_hyps={it_acc}")
                if it_rej:
                    bits.append(f"rejected_hyps={it_rej}")
                parts.append(" ".join(bits))
            text = " | ".join(parts)

        # findings list deduped from confirmed claim_ids' evidence_refs
        token_count = _approx_tokens(
            text + " ".join(confirmed + refuted + inconclusive + accepted_hyps + rejected_hyps)
        )

        return JournalSummary(
            up_to_iter=up_to_iter,
            confirmed_findings=finding_set,
            refuted_findings=[],
            inconclusive_findings=inconclusive,
            accepted_hypotheses=accepted_hyps,
            rejected_hypotheses=rejected_hyps,
            open_threads=[],
            summary_text=text,
            token_count=token_count,
        )

    def token_count_at_iter(self, iter_n: int) -> int:
        return self.summarize(up_to_iter=iter_n).token_count
