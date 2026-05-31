# DAST-303 — Cross-repo Phase D variant hunting

**Status:** Design / scoping
**Estimated work:** 2–3 weeks
**Priority:** HIGH (post-v1.0 Cloudflare-comparison batch)
**Blocked by:** DAST-302 + DAST-304 (both shipped 2026-05-18) + variant-judge oracle rewrite (in flight in a separate session — its accuracy is the load-bearing assumption for cross-repo to amplify the right signal)

---

## 1. Problem

DAST-302 (same-project cross-file Blast Radius) ships today. When Phase A confirms a vulnerability — say SSRF in `webbrowser.ts` line 99 — DAST-302 hunts variants in **sibling files within the same project** (`getHtml`, `cached_fetch`, etc.) and verifies each in the sandbox.

But the **highest-value disclosure case** is broader: when we confirm SSRF in LangChain's WebBrowser tool, the question becomes "where ELSE in the npm ecosystem does this pattern exist?" That's cross-REPO variant hunting — exactly what Cloudflare's published Trace + Feedback stage does for their security harness (their tracer agent fans out across "consumer repositories" of a shared library after each confirmed finding).

DAST-303 extends Phase D's reach from one project to a curated corpus of relevant projects. The same retargeter + sandbox harness + variant judge pipeline DAST-302 ships fires against external code, finding instances of the same vulnerability class in different codebases.

## 2. Why this is high-priority now

The Argus go-to-market story has three components:

1. **Confirmed vulnerabilities** (Phase A) — sandbox-proven, disclosure-ready findings.
2. **Same-project blast radius** (DAST-302) — when one bug is found, surface every other place in the same project it exists.
3. **Cross-repo blast radius** (DAST-303) — when one bug is found, surface every other place in the SECURITY ECOSYSTEM (other npm packages using the same vulnerable pattern) it exists.

Component 3 is the killer feature for security disclosure work. When Argus confirms one CVE-worthy bug, DAST-303 turns that into N bug reports across the ecosystem. The LangChain disclosures already drafted are the seed for this — once we have the SSRF confirmed in LangChain's `webbrowser.ts`, DAST-303 hunts for the same pattern in `langchain-community`, `langchain-experimental`, every other npm AI-tool package that fetches URLs from LLM output, etc.

Cloudflare's blog explicitly describes this as the highest-leverage capability in their harness:

> "For each confirmed finding in a shared library, a tracer agent fans out (one instance per consumer repository) [...] decides whether attacker-controlled input actually reaches the bug from outside the system."

DAST-303 is the same capability built on Argus's stack.

## 3. Non-goals (explicit)

1. **NOT building our own search index from scratch.** Sourcegraph / GitHub code search / npm registry / pypi already index code. DAST-303 uses one of them as the candidate-retrieval layer; we don't ingest 100M files into our own ElasticSearch cluster.
2. **NOT cross-language at v1.** Start with the language that ships first — same-language as the seed file. Python seed → Python ecosystem. JS seed → npm. Polyglot is v1.1+.
3. **NOT scanning the entire ecosystem on every confirmed finding.** Bounded candidate set per seed (default 20 candidate repos, max 50). Beyond that the operator opts in explicitly with `--dast-303-max-candidates N`.
4. **NOT running candidate repos' full test suites.** Sandbox verification reuses the seed's retargeted harness pattern (DAST-302 already proved this works). We need to load just the function under analysis + its direct dependencies into the sandbox, not the whole repo's test environment.
5. **NOT touching the Phase D variant-judge oracle.** That's the spawned session's deliverable — DAST-303 consumes its output (CONFIRMED / REFUTED / INCONCLUSIVE / NOT_TESTABLE) verbatim.

## 4. Architecture

### 4.1 Pipeline

```
DAST-303 fires AFTER:
  Phase A confirms a vulnerability    (variant_judge.verdict=CONFIRMED)
  AND DAST-302 ran                    (same-project Blast Radius complete)
  AND ScanConfig.enable_dast_303=True (opt-in for v1)

Pipeline stages:

[Stage 1] Signature lift
  Reuse Phase D's existing SemanticSignature from DAST-301:
    {attack_class, cwe, source_shape, sink_kind, sink_callee,
     transformations, missing_guards}

[Stage 2] Candidate retrieval
  Search code-index backend (Sourcegraph / GitHub / npm) for files
  matching the signature's sink + transformation shape. Bounded
  candidate set: default 20, max 50.

[Stage 3] Candidate triage
  Run the L1 cascade (with SCAN-010 split mode default-enabled)
  against each candidate file. CLEAN classifications drop out
  cheaply; LOW / HIGH proceed to Stage 4.

[Stage 4] Harness retargeting
  Reuse the cross-file retargeter from DAST-302 (Bug #6 fix —
  AST-aware Python -c body rewriter). Generate variant harness
  per candidate function.

[Stage 5] Sandbox verification
  Per-candidate sandbox plan, same shape as DAST-302's. Variant
  judge (the spawned session's deliverable) decides verdict.
  Cost-gated at $0.20/candidate (vs DAST-302's $0.50/seed budget
  because cross-repo runs at higher volume).

[Stage 6] Disclosure report
  CONFIRMED candidates surface as
  ``DastResult.cross_repo_variants[]``. Each carries:
    - Source repo + path + line
    - Sandbox verification trace
    - Confidence + Phase A-style proof_of_concept
  Direct input to disclosure tooling (GHSA drafts, npm advisory
  reports, etc.).
```

### 4.2 Code-index backend choice

Three viable backends:

| Backend | API cost | Coverage | Latency | Pros | Cons |
|---|---|---|---|---|---|
| **Sourcegraph public search** | Free tier 100 req/day, paid tier ~$300/mo | All public GitHub + popular registries | ~500ms/query | Best query language; regex + structural search; understands code | Free tier limits; paid is real $$ |
| **GitHub code search (REST)** | Free with token (60 req/min); paid GitHub usage tier higher | GitHub public repos only | ~1s/query | Free, no contract; baked-in for GitHub-hosted projects | Misses GitLab / Bitbucket; rate-limited |
| **npm registry + tarball download** | Free | npm only | High latency (download per package) | True coverage of npm — picks up unpublished / private mirrors | npm-only; volume requires local caching |

**v1 choice: GitHub code search** — free, broad, sufficient for disclosure use case. v2 adds Sourcegraph for queries the GH search syntax can't express. v3 adds npm-direct for npm-only ecosystem coverage.

### 4.3 Search query construction

Given a `SemanticSignature` for a confirmed SSRF in webbrowser.ts:

```python
sig = SemanticSignature(
    attack_class="ssrf",
    sink_kind="network_fetch",
    sink_callee="fetch",
    missing_guards=[
        "URL.protocol allowlist",
        "IP filter",
        "DNS resolution check",
    ],
)
```

Query construction maps signature fields → search expressions:

```
GitHub code search query (constructed):
  language:typescript
  path:*.ts
  /\bfetch\s*\(\s*\w+\s*\)/   # bare fetch(varname), no validation
  -path:test/* -path:**/test/**  # exclude tests
  -path:node_modules/**
  -path:dist/** -path:build/**

Optional refinements:
  + "tool" + "agent"           # AI-tool context boost
  + langchain                  # Direct ecosystem search
```

Each signature carries a `_build_search_query(signature, backend)` mapping. The mapping table is **a code module, not config** — search-query construction is signature-class-specific and version-controlled with the signature schema.

### 4.4 Bounded resource budget

Per DAST-303 fan-out:

| Resource | Default | Max |
|---|---|---|
| Candidate repos enumerated | 50 | 200 |
| Candidate repos triaged (L1) | 20 | 50 |
| Candidate files sandbox-verified | 5 | 15 |
| Cost (verification phase) | $1.50 | $5.00 |
| Wall-clock | ~10 min | ~30 min |

Cost-gated: each stage has its own cap. Triage budget hits → drop bottom-confidence candidates. Sandbox budget hits → drop tail; report partial confirmed set. Default conservative because the disclosure case wants HIGH precision (a few solid confirmed cross-repo bugs > many speculative reports).

### 4.5 Active monitoring (v2)

Cloudflare's blog mentions their Feedback stage re-runs the hunt when a CVE is filed against a known-vulnerable callable signature. v2 adds:

* Argus subscribes to GitHub security advisories + npm advisory database
* When a new CVE is filed against a callable in `SemanticSignature.sink_callee`, DAST-303 re-runs the hunt across the corpus
* Net: continuous variant discovery without operator intervention

v1 ships manual-trigger only — DAST-303 fires on explicit `argus dast-303 --seed-finding-id F` invocations or on scan completion when `enable_dast_303=True`.

## 5. Schema additions

```python
# dast/variant_analysis.py — extend
@dataclass
class CrossRepoVariant:
    """Single confirmed (or not) cross-repo variant from DAST-303."""
    source_repo: str          # e.g. "facebook/react"
    source_ref: str           # commit SHA or branch
    file_path: str            # relative to repo root
    function_name: str
    line_start: int
    verdict: str              # "confirmed" / "refuted" / "inconclusive" / "not_testable"
    sandbox_plan_id: str
    runtime_evidence: str
    similarity_score: float
    rationale: str

# DastResult — extend
@dataclass
class DastResult:
    ...existing fields...
    cross_repo_variants: list[dict] = field(default_factory=list)
    cross_repo_skipped_reason: str = ""  # populated when DAST-303 skipped
```

## 6. Acceptance gate

DAST-303 ships when ALL of:

1. **Cross-repo hunt finds the LangChain SSRF in `langchain-community`.** Manually-verified that the same SSRF pattern exists in the variant repo; DAST-303 must surface it as CONFIRMED.
2. **Bounded resource budgets hold.** No scan exceeds 50 candidate-files enumerated, 15 sandbox runs, $5 total spend.
3. **GitHub code search rate-limit handled gracefully.** Exponential backoff + circuit breaker. Test: hammer the search until 429 → confirm scan completes with partial results + clear telemetry.
4. **Zero false positives on `tenda_device_audit.py` (the clean fixture).** When the seed is a real bug, DAST-303 must not confuse "looks similar" with "actually vulnerable." Variant judge gates this — but DAST-303's candidate retrieval can also pre-filter via signature similarity score.
5. **Path-safety + sandbox isolation hold.** Cross-repo content is by definition UNTRUSTED. The sandbox already isolates execution (Firecracker microVMs per DAST-106); DAST-303 just feeds it third-party code. Test: feed deliberately-hostile candidate → confirm sandbox contains the blast.

## 7. Failure modes

| Failure | Behavior |
|---|---|
| Code-index backend down / rate-limited | DAST-303 skips with `cross_repo_skipped_reason="search_backend_unavailable"`. Phase D + DAST-302 still complete. |
| Candidate repo's source not accessible (private / deleted) | Skip that candidate; log + continue. |
| Sandbox can't build candidate repo's deps | Mark candidate as INCONCLUSIVE; don't count as REFUTED. |
| Variant judge returns NOT_TESTABLE | Same — candidate stays as NOT_TESTABLE in the report. |
| Budget exhausted mid-fanout | Cancel remaining candidates; report partial confirmed set with `cross_repo_budget_exhausted=True` flag. |
| Hostile candidate file (malicious payload) | Sandbox contains via existing Firecracker isolation. Variant judge sees suspicious behavior + reports — no exfil possible. |

## 8. Rollback story

`ScanConfig.enable_dast_303=False` is the default. Operators who hit unexpected behavior:
1. Don't pass `--enable-dast-303` → DAST-303 doesn't fire
2. Or set `enable_dast_303=False` programmatically
3. No code reverts needed

For operators in the middle of a `scan-repo` invocation that hit issues, the per-file `enable_dast_303` flag (passed through `ScanConfig`) gates DAST-303 fan-out per file. They can disable mid-run by killing the process and re-running with the flag off — no in-flight state to clean up.

## 9. Implementation plan (slices)

**Slice 1 — code-index backend + signature search-query construction (~3-5 days)**:
- `dast/code_index/github_search.py` — GitHub code search client with backoff + rate-limit handling
- `dast/cross_repo_query.py` — signature → search query mapping for SSRF / RCE / SQLi (the 3 attack classes we have the most data on)
- Tests: synthetic signatures → expected queries; rate-limit simulation; back-off correctness
- No engine wiring yet — pure infrastructure

**Slice 2 — Candidate retrieval + L1 triage fan-out (~3-5 days)**:
- `dast/cross_repo_retrieval.py` — given a signature, fetch candidate files from GitHub
- Bounded retrieval (50 max), in-memory caching per scan
- Reuse the existing L1 cascade (SCAN-010 split mode) to triage candidates
- Tests: synthetic candidate set → expected triage outcomes

**Slice 3 — Sandbox verification fan-out + variant judge integration (~3-5 days)**:
- `dast/cross_repo_verifier.py` — per-candidate retargeter + sandbox plan submission
- Wait for variant-judge oracle rewrite to land (spawned session)
- Reuse Fix #6 AST harness retargeter for cross-repo bodies
- Aggregate per-candidate results into `cross_repo_variants[]`
- Tests: stubbed sandbox + judge; end-to-end with synthetic candidates

**Slice 4 — engine integration + CLI + acceptance gate validation (~2-3 days)**:
- `dast/orchestrator.py` — DAST-303 stage between DAST-302 and Phase C
- `ScanConfig.enable_dast_303` + `dast_303_max_candidates`
- CLI flag `--enable-dast-303 [--dast-303-max-candidates N]`
- Acceptance-gate end-to-end run on the LangChain disclosure target

**Slice 5 — Active monitoring (v2 follow-up, NOT this scope)**:
- Subscribe to GitHub Security Advisories / npm advisory DB
- Auto-trigger DAST-303 re-runs on CVE filings against known sink callables
- Cron / webhook integration

## 10. Open questions

1. **Code-index choice empirical validation.** The design picks GitHub code search for v1. We should spike all three options against a known query (the SSRF-in-LangChain pattern) and measure: result quality, latency, rate-limit headroom, false-positive rate. 1-day spike before Slice 1.
2. **Candidate diff: forks vs originals.** GitHub indexes forks separately, which can return 10+ near-identical files for popular libraries. Need a dedup heuristic (file content hash + path normalization) before triage spend.
3. **Disclosure attribution.** When DAST-303 confirms a cross-repo bug, who do we credit / who gets the GHSA report? "Argus found it" is fine for first-party; v2 / hosted-tier may need disclosure-coordination infrastructure.
4. **Cost model for hosted tier.** DAST-303 against an unbounded corpus could be expensive. v2 / hosted-tier likely caps per-customer monthly variant-hunt budget.
