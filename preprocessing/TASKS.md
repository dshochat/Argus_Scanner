# preprocessing — TASKS

Source of truth for tasks scoped to `preprocessing/`. Format is fixed — see
root `CLAUDE.md` §"Parallel session task workflow" for the protocol.
Task IDs use the `PREP-NNN` prefix so they are unique across the
repo. `scripts/board.py` aggregates this file into root `BOARD.md`.

## Backlog

### Deferred (not Phase 0, or blocked on other work)

- **Secret pre-triage** — PENDING Path 1 validation (CONFIRM/REJECT
  prompt methodology). Validation 2 showed zero F1 lift via
  append-block approach; task-reframed variant must be tested before
  committing.
- **Repo-level skip lists** (node_modules, .git, vendor, lockfiles)
  — BLOCKED on `api/` repo-scan mode (API-007).
- **CVE lookup + L1 `cve_context`** — scope of SAST-ANALYSIS-005
  (N-day); Pass 2 DAST handles exploitability separately (see
  research doc §3.5).
- **Known-benign hash allowlist** — needs dataset; future P2.
- **AST import/call/export graph** — future P2, feeds L1
  `declared_vs_actual`.
- **LABELING-NONCE-001** (cross-repo) — Port the per-call
  nonce-suffixed marker format from
  `preprocessing/prompt_markers.py` into
  `data/labeling/deobfuscation/decoder.py` so training and inference
  use the same marker shape. Until this lands, FT models trained on
  labeling-shape data see literal (nonce-less) markers at training
  and nonce-bearing markers at inference — a small distribution
  shift we expect the prose-prefix match to tolerate, but parity
  removes the risk entirely. Surfaced by PR #26 review.
  Not blocking Phase-0 close. size:S

## In Progress

_none_

## Blocked

_none_

## Done

- [x] **PREP-001** — Scaffold preprocessing package entry point (`Preprocessor`, `preprocess_file`) size:S owner:phase0-session started:2026-04-17 finished:2026-04-17
- [x] **PREP-002** — Language detection (extension + shebang + heuristics) size:S owner:phase0-session started:2026-04-17 finished:2026-04-17
- [x] **PREP-003** — Deobfuscation engine (base64/hex/zlib/marshal/rot13/exec-chain iterative unwrap) size:M owner:phase0-session started:2026-04-17 finished:2026-04-17
- [x] **PREP-004** — Malware hash lookup (protocol + in-memory default backend) size:S owner:phase0-session started:2026-04-17 finished:2026-04-17
- [x] **PREP-005** — Per-ecosystem dependency parsers (pypi, npm, go, maven, rubygems, crates, nuget) + dispatcher size:L owner:phase0-session started:2026-04-17 finished:2026-04-17
- [x] **PREP-006** — setup.py AST walker, `.pth` detector, postinstall hook detector (`imperative_install_detected`) size:M owner:phase0-session started:2026-04-17 finished:2026-04-17
- [x] **PREP-007** — Unit tests with golden fixtures (parsers, deobfuscation, imperative-install) size:M owner:phase0-session started:2026-04-17 finished:2026-04-17
- [x] **PREP-008** — Decompression-bomb guard on zlib decodes (`MAX_ZLIB_DECOMPRESSED = 100_000` bytes cap matching `data/labeling/deobfuscation/safety.py`; overruns rejected and surfaced as `failed_blob_count`) size:S owner:phase0-priority1 started:2026-04-21 finished:2026-04-21 commit:6e43fd6
- [x] **PREP-009** — Tiered file-size handling (<100KB full pipeline; 100KB–500KB full with token-budget monitoring; 500KB–5MB pre-pass full + model stages budget-gated; >5MB skip with `skip_reason=too_large`) size:M owner:phase0-priority1 started:2026-04-21 finished:2026-04-21 commit:40c3c71
- [x] **PREP-010** — Binary / empty content skip (null-byte density + non-printable ratio detection; emits `skip_reason=binary` or `skip_reason=empty`; no model stages fire on non-null skip_reason) size:S owner:phase0-priority1 started:2026-04-21 finished:2026-04-21 commit:1c6b121
- [x] **PREP-011** — Prompt-injection pattern detection (zero-width U+200B/200C/200D/FEFF + hidden-instruction regex set + encoded-suspicious-keyword check; emits direct findings that bypass L1 but still flow through for narrative calibration) size:M owner:phase0-priority1 started:2026-04-21 finished:2026-04-21 commit:44fd96c
- [x] **PREP-012** — Deobfuscation trigger discipline (firing criteria switched from bare-base64 to exec-chain-paired per `data/labeling/deobfuscation/patterns.py`; JWTs / PEM keys / embedded images no longer trigger decode) size:S owner:phase0-priority2 started:2026-04-21 finished:2026-04-21 commit:0e0b584
- [x] **PREP-013** — Deobfuscation output-shape alignment with labeling (`techniques`, `blob_count`, `decoded_blob_count`, `failed_blob_count`, `suspicion_score`, `decoded_content_summary` extended onto `preprocessing.obfuscation` sub-block) size:M owner:phase0-priority2 started:2026-04-21 finished:2026-04-21 commit:68e8010
- [x] **PREP-014** — Printability filter on decoded output (`PRINTABILITY_THRESHOLD = 0.80`; decoded bytes below threshold rejected, original encoded content preserved) size:S owner:phase0-priority2 started:2026-04-21 finished:2026-04-21 commit:35a1cc4
- [x] **PREP-015** — Decoded-content prompt markers (`# === DECODED ... PAYLOAD ===` / `# === END DECODED PAYLOAD ===` wrapping; `sast/extraction/prompts.py` + `sast/analysis/l1/prompt.py` consumers updated; matches labeling convention) size:S owner:phase0-priority2 started:2026-04-21 finished:2026-04-21 commit:7560b23
- [x] **PREP-016** — AI-file filename pattern matching (`SKILL.md`, `CLAUDE.md`, `.cursorrules`, `plugin.json`, `mcp*.json`, `agent_config.yaml`, `tools.json` → `ai_file_match`; S1 forces `is_ai_component=true` on match, overrideable on content evidence) size:S owner:phase0-priority3 started:2026-04-22 finished:2026-04-22 commit:e95e7a6
- [x] **PREP-017** — Framework marker heuristic (first-2K-char scan for flask/fastapi/django/express/gin/echo/fiber/rails → `framework_hint`; S1 pre-seeds its `framework` field) size:S owner:phase0-priority3 started:2026-04-22 finished:2026-04-22 commit:fbbea0a
- [x] **PREP-018** — Attack-vector extension flag (`.pth`, `.egg`, `.whl`, `.spec` → `attack_vector_extension`; orchestrator forces `priority_score >= 4` the same way `imperative_install_detected` does) size:XS owner:phase0-priority3 started:2026-04-22 finished:2026-04-22 commit:ea5d85d
- [x] **PREP-019** — Framework markers switched from bare-substring to language-aware import-anchor regex after Checkpoint 1 corpus surfaced a 7/11 false-positive rate on `gin` matching `login`/`begin`/`engine`/`engineering`/`logging` substrings. Covers Python `from X import …`/`import X`, Node `require('X')`/`from 'X'`, Go `"github.com/vendor/X/vN"`, Ruby `require 'rails'` + `< Rails::Application`, Django `DJANGO_SETTINGS_MODULE`. 37 unit tests including negative regression pins. size:S owner:feat-benchmark-augmented-corpus started:2026-04-22 finished:2026-04-22 commit:d6a5e1a
