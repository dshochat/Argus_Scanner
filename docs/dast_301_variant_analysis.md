# DAST-301 — Variant Analysis (Phase D)

**Status**: v1 MVP, scoped to same-file variants. Cross-file + multi-repo
is v1.1 (DAST-302).

**Owner**: Argus DAST engine.

**Motivation**: today Argus stops after Phase A confirms one finding.
A human security researcher's next thought is *"if the developer made
this mistake here, where else?"* — variant analysis is that intuition
automated at machine speed.

---

## The pipeline (4 steps)

```
[Phase A confirms finding F]
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 1 — Semantic Signature Extraction                      │
│   Opus call: F.proof_of_concept + F.runtime_evidence        │
│              + F.code → ``SemanticSignature``               │
│   Output: structured dict {                                 │
│     "source": <untrusted-input shape>,                      │
│     "transformations": [<each transform applied>],          │
│     "sink": <dangerous operation>,                          │
│     "attack_class": <SSRF / SQLi / RCE / ...>,              │
│     "guard_predicates_missing": [<validation NOT present>], │
│   }                                                          │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 2 — Code Graph + Candidate Hunting (AST-driven for v1) │
│   Enumerate every callable in the SAME file (v1 scope).     │
│   For each candidate, compute the same source→sink shape    │
│   from local AST. Filter to candidates whose sink-call       │
│   matches the signature's sink class.                        │
│   Output: list[VariantCandidate]                            │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 3 — LLM-Guided Ranking + Pruning                       │
│   Opus call: signature + each candidate's source snippet    │
│              → semantic-similarity score (0.0–1.0).         │
│   Keep candidates above similarity threshold (default 0.7). │
│   Bounded to MAX_VARIANT_CANDIDATES_PER_SEED = 5.           │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 4 — Autonomous Harness Generation + Verification       │
│   For each ranked candidate:                                │
│     a) Re-target the seed finding's Phase A harness to the  │
│        candidate's function name + arg signature.           │
│     b) Submit to sandbox (re-uses existing SandboxClient).  │
│     c) Apply seed finding's oracle (signature-driven).      │
│     d) Classify CONFIRMED / REFUTED / INCONCLUSIVE.         │
│   Output: list[VariantOutcome]                              │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
[Phase D result attached to DastResult.variant_analysis]
[Confirmed variants become L1+PhaseA-shaped findings in
 findings_validated → flow through Phase C remediation]
```

## Cost model

Per-seed Phase D budget caps (enforced explicitly):

| Step | Model call | Avg cost |
|---|---|---|
| 1 — Signature extraction | 1 Opus call, ~$0.05 |
| 2 — AST hunting | 0 model calls (deterministic) |
| 3 — Variant ranking | 1 Opus call (batched), ~$0.10 |
| 4 — Per-variant harness + verify | 5 × ($0.02 inference + $0.05 sandbox) = $0.35 |
| **Total** | **~$0.50 per seed** |

A scan with 3 confirmed L1 findings → ~$1.50 Phase D budget. This is
enforced via `PHASE_D_MAX_COST_PER_SEED_USD = 0.50` and a per-scan cap
via the existing `ScanConfig.max_cost_per_scan_usd` (SCAN-007).

## Failure modes + degradation

* **Signature extraction fails (schema violation, API error)** →
  Phase D records `skipped_reason: signature_extraction_failed` and
  continues to Phase B+ without variants. Non-blocking.
* **AST parse fails (malformed file)** → Phase D skips this seed,
  logs to journal as `phase_d_ast_parse_failed`.
* **No candidates above similarity threshold** → Phase D records
  empty result; expected outcome on isolated bugs.
* **Sandbox replay fails on all variants** → records errors in
  `variant_errors`; existing variants stay UNVERIFIED.
* **Cost cap hit mid-seed** → Phase D aborts after current variant
  completes; remaining variants stay UNVERIFIED.

## Trust model

Phase D's signature extraction receives:
* The L1 finding's `code` snippet (untrusted source).
* The L1 finding's `proof_of_concept` + `runtime_evidence` strings
  (Argus-generated, trusted).

Source-content interpolation uses `wrap_untrusted_source()` (SCAN-006)
just like every other Argus prompt.

## Data flow into Phase C (v1.1)

When Phase D confirms variant `V` on function `f2` (with seed `F`
on function `f1`):
* `V` is added to `findings_validated` with a synthetic finding_ref
  `D-<seed_id>-<f2>`.
* Phase C's existing v14 `dast_findings` wiring picks it up.
* The PATCH generated by Phase C considers all of (F, V1, V2, ...)
  together — single coherent fix touches every variant.
* v1.1 follow-on: multi-file patch propagation. v1 punts to "Phase C
  patches each file independently with the same signature-shaped fix."

## Integration

* Phase D fires **only when**: `enable_phase_d=True` (default False
  for v1 MVP; flip to True in v1.1 after measurement) AND Phase A
  confirmed ≥ 1 finding.
* Located in orchestrator between Phase A iteration end and Phase B+
  trigger so downstream phases see the full finding set.

## What v1 ships (MVP, this commit)

* Same-file variant analysis (no cross-file graphing).
* Python + TS/JS via the same AST helpers used elsewhere.
* Feature-flagged off-by-default.
* Full unit-test coverage on data model + signature parsing + AST
  candidate enumeration + harness retargeting.
* Production-grade cost gate (`PHASE_D_MAX_COST_PER_SEED_USD`).
* No-op when Phase A produced 0 confirmed findings (the common case
  for clean files).

## What v1.1 adds (DAST-302) — IMPLEMENTED

* **Cross-file code graph** (Python `ast` for v1.1; tree-sitter for
  TS/JS deferred to v1.2). The graph enumerates every function in
  every Python file under the project root and indexes each function's
  callsites. Project root resolves via the existing v12 sibling-file
  marker walk (``tsconfig.json``, ``pyproject.toml``, ``.git``, etc.).
* **Bounded enumeration**: file count cap (200), per-file size cap
  (256 KB), per-graph node cap (5000). Excludes ``node_modules``,
  ``__pycache__``, ``.git``, ``.venv``, ``venv``, ``site-packages``.
* **Cross-file harness retargeting**: when a variant lives in
  ``lib/helper.py`` rather than the entry file, the harness updates
  the import path (e.g. ``import lib.helper`` plus
  ``lib.helper.variant_fn(...)``) instead of just substituting the
  function name. Works because the v12 sibling-staging tarball
  already places sibling files at ``/workspace/<rel-from-root>``.
* **Same-file fallback**: when ``project_root`` is unknown (e.g.
  single-file scan via ``argus scan path/to/file.py``), the runner
  falls back to v1's same-file behavior.
* **Multi-file patch propagation in Phase C**: ⚠️ STILL v2 work
  (DAST-303). Phase D surfaces variants across files; Phase C v14
  patches the entry file's source only. v1.1's cross-file Phase D
  surfaces variant findings with their ``file_path`` so the operator
  can manually apply the same patch logic; automated multi-file
  patching is the v2 milestone.

## What v2 adds

### DAST-303 — Cross-repo Phase D variant hunting

* Cross-repo variant hunting against curated mirror corpora
  ("WebBrowser SSRF in LangChain — where else does this pattern
  appear in the npm/pip ecosystem?").
* Active monitoring: re-run variant hunt when a confirmed CVE is
  filed for a known-vulnerable function.
* Requires a curated mirror index (Argus doesn't build one — uses
  off-the-shelf indices like GitHub's package corpus + npm's
  top-100k by downloads).

### DAST-304 — Multi-file Phase C patch propagation

**NOTE: This is Phase C extension work, NOT Phase D.** Phase D's job
is to FIND variants. Phase C's job is to FIX them. When Phase D
v1.1 (DAST-302) surfaces variants across multiple files, Phase C
today (v14) can only patch the entry file. DAST-304 extends Phase C
to:

* Generate ONE patch template grounded in the seed finding +
  signature.
* Apply the template to every confirmed variant's file with
  locally-scoped rebinding.
* Verify each patched variant independently in the sandbox.
* Produce one coherent PR with N file changes.

This is the "automated relentless security researcher" outcome.
Without it, Phase D v1.1 surfaces cross-file variants but the
operator has to manually apply the same patch logic to each one —
which defeats half the value of variant analysis.

**Sequence**: ship DAST-304 BEFORE DAST-303. Multi-file patching
within one repo is higher-leverage than cross-repo hunting until
the patch story is solid.

---

**Acceptance gate for v1**: re-scan `webbrowser.ts` (the LangChain
finding). Phase A confirms the L99 SSRF. Phase D should:
1. Extract signature: source=LLM-supplied URL string, sink=fetch()
   call, missing-guards=[URL.protocol, IP-validation, redirect].
2. Hunt same-file candidates → identify `getRequestUrl()` /
   `_call()` / any other function passing user-controlled URL into
   `fetch()`.
3. Retarget harness → submit → classify.

If Phase D surfaces even ONE same-file variant L1 missed, the v1 MVP
has paid for itself.
