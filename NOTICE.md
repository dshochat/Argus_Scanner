# Notice — Code Origins

Argus is a new project, but it builds on two prior codebases authored by the same
team. This file records that lineage for code provenance and license tracking.

## Source: CNAPPPOC (github.com/dshochat/CNAPPPOC, archived)

Lifted components:

| Path in Argus | Origin path |
|---|---|
| `scanner/engine.py` | `scanner/backend/scan_engine.py` (refactored) |
| `scanner/sanitizer.py` | `scanner/backend/response_sanitizer.py` |
| `scanner/router.py` | `scanner/backend/scanner.py` (refactored) |
| `prompts/scanner.py` | `shared/scanner_prompt.py` |
| `inference/adapters.py` | `benchmark/backend/bm_model_adapters.py` (Anthropic + Gemini only) |
| `adjudicator/` | `agents/verdict_agent/` |
| `samples/` | `samples/` |
| `db/schema.sql` | `schema.sql` (simplified) |
| `frontend/` | `frontend/` |
| `.claude/skills/` | `.claude/skills/` |

Original commit attribution preserved in `git log` entries that re-import these
files. Architectural patterns (combined-prompt design, cascade routing,
multi-provider adapter, verdict adjudication) are CNAPPPOC contributions.

## Source: echoDefense (github.com/EchoSecurityLabs/echoDefense)

Lifted components:

| Path in Argus | Origin path |
|---|---|
| `preprocessing/` | `preprocessing/` (entire module) |
| `shared/types/` | `shared/types/` (Pydantic schemas) |
| `shared/utils/` | `shared/utils/` (deobfuscation, scoring helpers, JSON recovery) |
| `dast/sandbox/client.py` | `scripts/dast_prototype/sandbox_client.py` (promoted from prototype) |
| `dast/orchestrator.py` | `scripts/dast_prototype/dast_orchestrator.py` |
| `dast/prompts.py` | `scripts/dast_prototype/dast_prompts.py` |
| `dast/validator.py` | `scripts/dast_prototype/hypothesis_validator.py` |
| `dast/journal.py` | `scripts/dast_prototype/evidence_journal.py` |
| `dast/sandbox/firecracker/` | `scripts/dast_prototype/firecracker/` (Dockerfiles + scripts + fly.toml × 3) |
| `methodology/scoring.py` | `scripts/dast_prototype/scoring.py` |
| `methodology/baseline.py` | `scripts/dast_prototype/_run_baseline_characterization.py` (refactored as module) |
| `methodology/per_fix.py` | `scripts/dast_prototype/_run_per_fix_evaluation.py` (refactored as module) |
| `analysis/ensemble.py` | `sast/analysis/l1/ensemble.py` |

Architectural contributions: deterministic preprocessing pipeline, multi-image
sandbox dispatcher, DAST iter-erosion guard, verdict-distance methodology,
N-sample ensemble pattern.

## What is NEW in Argus (not lifted)

- The integration glue: `scanner/engine.py` rewriting of CNAPPPOC's
  `scan_file_routed` to consume preprocessing output and route to Sonnet/Opus
  cascade
- Anthropic-specific cascade gating (high-stakes-category routing,
  ensemble-disagreement adjudication, DAST trigger logic)
- Repurposed prompt set tuned for Sonnet 4.6 / Opus 4.6 verdicts
- Cost-aware orchestration (model selection per file based on
  preprocessing flags + triage classification)

## License

Argus is licensed under the [Apache License 2.0](LICENSE). The lifted
code from CNAPPPOC was authored by the Argus author (Dudy Shochat). The
lifted code from echoDefense was co-authored with the EchoSecurityLabs
team; that lift is performed with explicit author rights to those
contributions, with attribution preserved.

The Apache 2.0 grant extends to the project as a whole. Specific
contributor copyright notices on individual files (where present)
are preserved.
