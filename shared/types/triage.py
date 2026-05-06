"""Triage block — S1 model output.

S1 input: first 2048 tokens of raw file. Output: this block.
Priority score drives the scan-depth routing table:

    5 → Full Pass 1 + Pass 2 always
    4 → Full Pass 1 + Pass 2 if budget
    3 → Full Pass 1, no Pass 2
    2 → S1 + S-Extract only (no L1)
    1 → S1 only (classify and skip)
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from shared.types.enums import FileType, Pass2Reason, ScanDepth


class Triage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_type: FileType
    language: str | None = None
    framework: str | None = Field(
        default=None,
        description="flask, django, express, fastapi, langchain, crewai, autogen, …",
    )
    ecosystem: str | None = None
    is_ai_component: bool = Field(
        description=(
            "True for AI/MCP/agent configs, model defs, prompt templates, "
            ".cursorrules, CLAUDE.md, or AI tool integrations."
        ),
    )
    priority_score: int = Field(ge=1, le=5)
    scan_depth: ScanDepth
    pass2_candidate: bool = False
    pass2_reason: Pass2Reason | None = None
