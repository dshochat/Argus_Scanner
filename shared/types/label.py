"""Top-level LabelRecord — one JSON per file.

This is the data contract between every pipeline stage. Producers
(S1, S-Extract, L1, verification, Pass 2, statistical engine) each
populate a specific block and leave the others untouched.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from shared.types.analysis import Analysis
from shared.types.extractions import Extractions
from shared.types.meta import Meta
from shared.types.preprocessing import Preprocessing
from shared.types.triage import Triage
from shared.types.verdict import ExecutionResults, SecretFound, Verdict


class LabelRecord(BaseModel):
    """Universal label schema v3.1. Mirrors docs/label_schema_v3.1.json."""

    model_config = ConfigDict(extra="forbid")

    meta: Meta = Field(alias="_meta")
    preprocessing: Preprocessing
    triage: Triage
    extractions: Extractions
    analysis: Analysis
    verdict: Verdict
    secrets_found: list[SecretFound] = Field(default_factory=list)
    execution_results: ExecutionResults | None = None
