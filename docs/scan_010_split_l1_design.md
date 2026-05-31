# SCAN-010 — Split L1 into VULNS / BEHAVIORAL / CHAINS specialized prompts

**Status:** Design / scoping (no code committed)
**Owner:** TBD
**Estimated work:** 3–5 days
**Priority:** HIGH (post-v1.0 launch; first item in the Cloudflare-comparison lifts batch)
**Blocked by:** v1.0 launch ships
**Related tickets:** SCAN-011 (per-attack-class hunters) depends on SCAN-010 landing first

---

## 1. Problem

Today the L1 cascade (`scanner/engine.py:704-728`) calls a single runner with the **combined** `SECURITY_SCAN_PROMPT` ([`prompts/scanner.py:360`](../prompts/scanner.py)), which asks ONE prompt to answer three different questions in one shot:

* **Vulnerabilities** (CWE-typed findings + composite risk)
* **Behavioral profile** (capabilities, deviations, shield policy)
* **Attack chains** (multi-step combinations + AI-tool issues)

Cloudflare's published security harness ([blog.cloudflare.com/cyber-frontier-models](https://blog.cloudflare.com/cyber-frontier-models/), May 2026) crystallizes a design insight: **the model is better at each question when asked them separately**, because each prompt is narrower than the combined version. Internal evidence aligns — Argus's combined prompt frequently produces hedged findings ("possibly", "potentially") that survive Phase A's filter at a lower rate than focused findings would.

The good news: **the three specialized prompts already exist** in `prompts/scanner.py` (`SCAN_PROMPT_VULNS`, `SCAN_PROMPT_BEHAVIORAL`, `SCAN_PROMPT_CHAINS`) from the original CNAPPPOC lift, but were never wired into production. SCAN-010 is mostly a **wiring + routing** problem, not prompt engineering.

## 2. Current state (as of 2026-05-18)

```
preprocessing → triage (Gemini Flash-Lite, ~$0.001/file)
  ├─ CLEAN → return (no L1)
  ├─ LOW   → sonnet_runner(SECURITY_SCAN_PROMPT)  ~$0.02/file (Flash) or $0.07 (Sonnet)
  └─ HIGH  → sonnet_runner(SECURITY_SCAN_PROMPT)  ~$0.07/file
            └─ high_stakes → opus_runner(SECURITY_SCAN_PROMPT)  ~$0.15/file
```

All HIGH-triage files get the combined prompt. Three questions, one model call, one schema response.

## 3. Proposed change

```
preprocessing → triage
  ├─ CLEAN → return
  ├─ LOW   → sonnet_runner(SECURITY_SCAN_PROMPT)        ← unchanged
  └─ HIGH  → SPLIT MODE:
              ├─ vulns_runner(SCAN_PROMPT_VULNS)        ┐ parallel
              ├─ behavioral_runner(SCAN_PROMPT_BEHAVIORAL) ├─ asyncio.gather
              └─ chains_runner(SCAN_PROMPT_CHAINS)       ┘
              → merge 3 disjoint sub-schemas into engine dict
              → existing borderline/Opus escalation logic unchanged
```

**Gate:** split mode fires ONLY on HIGH-triage routings. CLEAN and LOW paths keep the cheap combined prompt — preserves the cost amortization on the long tail.

## 4. Non-goals (explicit)

1. NOT changing the prompts' content. The three specialized prompts in `prompts/scanner.py` are taken as-is for v1 of SCAN-010. Prompt tuning is a follow-on if the regression suite reveals gaps.
2. NOT changing the triage routing logic. CLEAN/LOW/HIGH classifications stay deterministic.
3. NOT touching `SECURITY_SCAN_PROMPT`. It remains the LOW-path default and a fallback for split-mode failures.
4. NOT changing Phase 3 (runtime probe + adversarial loop), Phase D (Blast Radius), or Phase C (remediation). Those operate downstream of L1 and consume the same engine-shape dict.

## 5. Schemas

Each specialized prompt has its own JSON schema. The three are **disjoint partitions** of the combined schema:

| Specialized prompt | Schema slice |
|---|---|
| `SCAN_PROMPT_VULNS` | `file_intent_analysis` + `vulnerabilities[]` + `composite_risk` |
| `SCAN_PROMPT_BEHAVIORAL` | `behavioral_profile` (actual_capabilities + deviations + shield_policy) |
| `SCAN_PROMPT_CHAINS` | `ai_tool_analysis` + `attack_chains[]` |

Each schema is jsonschema-validatable per SCAN-008 (the existing fail-open + retry-once pattern from SCAN-009 applies unchanged).

**Merge contract** — the three responses combine into the existing engine dict by trivial key union:

```python
merged = {
    "file_intent_analysis": vulns["file_intent_analysis"],
    "vulnerabilities":      vulns["vulnerabilities"],
    "composite_risk":       vulns["composite_risk"],
    "behavioral_profile":   behavioral["behavioral_profile"],
    "ai_tool_analysis":     chains["ai_tool_analysis"],
    "attack_chains":        chains["attack_chains"],
    "verdict_label":        _derive_verdict_from_split(vulns, behavioral, chains),
}
```

`_derive_verdict_from_split` reproduces the verdict logic the combined prompt does internally — composite_risk score + behavioral deviation severity + chain presence — using the same thresholds. Reference implementation source: the verdict-derivation block at the end of `SECURITY_SCAN_PROMPT`.

## 6. Concurrency + cost

**Concurrency:** the three specialized calls fire in parallel via `asyncio.gather`. Wall-clock latency stays at ~1 model call (gated by the slowest of the three). Token cost is the sum.

**Cost math (Sonnet 4.6 at $3/M in + $15/M out):**

| Mode | Calls | Effective input tokens | Notes |
|---|---|---|---|
| Combined (today) | 1 | ~8k | One prompt, one full system message |
| Split — raw | 3 | ~24k | Each specialized prompt re-sends the system message |
| Split — with prompt cache | 3 | ~10k effective | 90% read discount on the shared `SCAN_PROMPT_SYSTEM` portion across the 2nd + 3rd calls |

Net cost increase: ~1.3× per HIGH-triage file (with caching), not 3×. Real number depends on cache hit rate; first call in a scan pays full system-prompt cost, the subsequent two get the discount. The existing `enable_system_cache=True` flag in `make_sonnet_runner`/`make_opus_runner` (`scanner/runners.py:292`) handles this transparently.

**SCAN-007 enforcement:** `ScanConfig.max_cost_per_file_usd` (current default $0.50) gates per-file spend. Split mode's higher cost is bounded by the same cap. If the cumulative cost of the three calls would exceed the cap mid-flight, the engine aborts further calls and falls back to whatever sub-responses have already returned (vulns is the critical-path prompt — partial output with only vulns is still useful; missing behavioral / chains degrades gracefully).

## 7. Failure modes (production-grade)

| Failure | Behavior |
|---|---|
| Schema validation fails on ONE specialized call | SCAN-009 retry-once. If retry also fails: fall back to combined `SECURITY_SCAN_PROMPT` for this file (don't ship partial output). Log + telemetry. |
| Schema validation fails on TWO+ specialized calls | Fall back to combined immediately (likely model-quality issue; retrying each isn't going to help). |
| One call returns empty / null sub-section | Accept; merge with the empty section blank. Don't fail the scan. |
| One call's `verdict_label` disagrees with the merged-verdict derivation | Use the merged derivation. Specialized prompts shouldn't emit `verdict_label` at all — strip it from each schema. |
| Cost cap hits mid-fanout | Cancel remaining calls. Use whatever returned. Verdict derivation uses available signals. Mark scan as cost-capped in telemetry. |
| Anthropic API rate-limit on the 3-way fanout | Existing adapter retry handles this. If it persists, fall back to combined. |
| Specialized prompt missing a schema field the engine expects | The merger fills in defaults (empty arrays, empty dicts). Engine downstream never sees missing keys. |

## 8. Routing decision

Where the split fires in `scanner/engine.py`:

* Today: line 686 — `if classification == "LOW": chosen_runner = sonnet_runner`; `else (HIGH): chosen_runner = sonnet_runner / opus_runner` based on `high_stakes`.
* After SCAN-010: same LOW branch unchanged. HIGH branch dispatches to either the split runner (default for HIGH) or the combined runner (fallback when split fails or cost-capped). The `high_stakes → Opus` escalation applies to ALL three specialized calls when triggered.

**Decision matrix:**

| Triage | `high_stakes` flag | Mode | Prompt(s) | Model |
|---|---|---|---|---|
| CLEAN | n/a | (no L1) | n/a | n/a |
| LOW | n/a | combined | `SECURITY_SCAN_PROMPT` | Sonnet (or Flash via separate runner) |
| HIGH | False | **split** | 3 specialized | Sonnet × 3 in parallel |
| HIGH | True | **split** | 3 specialized | Opus × 3 in parallel |

The borderline ensemble (`scanner/engine.py:738-770`) operates on the merged output, unchanged.

## 9. Implementation plan (post-launch)

1. **`prompts/scanner.py`** — confirm each specialized prompt has its `verdict_label` removed from its schema and from the prompt body. Add jsonschema definitions for each (`SCAN_PROMPT_VULNS_SCHEMA`, etc.) co-located with the prompt strings.
2. **`scanner/runners.py`** — add `make_sonnet_runner_split(api_key)` and `make_opus_runner_split(api_key)`. Each returns a single async callable that internally fans out to three adapter calls + merges. Same return shape as the combined runner so `engine.py` doesn't have to know which mode ran.
3. **`scanner/engine.py`** — line 689 region. Replace the single `chosen_runner` selection with a mode-aware dispatcher: HIGH classification → split runner; everything else → combined. The dispatcher tracks which mode was used in `scan_path` for observability.
4. **`scanner/cli.py`** — add `--l1-mode {auto,split,combined}` flag, default `auto` (the routing table above). `--l1-mode combined` forces the old behavior for A/B benchmarking; `--l1-mode split` forces split mode even on LOW for diagnostics.
5. **`scanner/config.py`** — add `ScanConfig.l1_split_enabled: bool = True` and `ScanConfig.l1_split_on_triage: tuple[str, ...] = ("HIGH",)` so the gate is configurable.
6. **`tests/unit/test_runners_split_l1.py`** — new test module:
   * Three specialized prompts each produce valid schema output (with stubbed adapter)
   * Merge logic combines disjoint schemas correctly
   * One specialized call failing schema → falls back to combined
   * Cost-cap mid-fanout → cancels remaining, uses partial output
   * `--l1-mode combined` forces single-call path
   * `--l1-mode split` forces split path on LOW
   * Verdict derivation produces the same label as the combined prompt would (within ±1 label class on the 23-file regression suite)
7. **`bench/scan_010_validation.py`** — new benchmark script:
   * Run the 23-file regression suite in `--l1-mode combined` (baseline)
   * Run again in `--l1-mode split` (treatment)
   * Compare verdict-exact (must be ≥ baseline) AND hedged-finding rate (must drop ≥30%)
   * Output table comparing per-file deltas

## 10. Acceptance criteria

SCAN-010 ships when ALL of:

1. **Verdict-exact stays ≥ baseline** on the 23-file regression suite. No "we made it cleaner-prompted but lost recall" regression.
2. **Hedged-finding rate drops ≥30%** measured by counting `vulnerabilities[].explanation` containing literal "possibly|potentially|could in theory|might|may be" tokens (case-insensitive). The Cloudflare-cited improvement should be empirically measurable.
3. **Per-file cost increase ≤ 1.5×** the combined baseline on the regression suite. Within SCAN-007 caps. Telemetry confirms prompt cache is working as expected.
4. **All 7 unit-test categories above pass.** Including the regression-suite verdict-exact equivalence.
5. **End-to-end smoke** on the LangChain disclosure target (`samples/webbrowser.ts` or equivalent) produces a verdict + findings consistent with the combined-prompt baseline. Per CLAUDE.md's "wire end-to-end before declaring done" rule.

## 11. Rollback plan

The change is fully gated behind `ScanConfig.l1_split_enabled` (default True for new code, but can be flipped at runtime). If post-deploy telemetry shows verdict-exact regression or unexpected cost overruns:

1. Operator sets `enable_l1_split=False` in their `~/.argus/config.toml` → next scan uses combined mode immediately
2. No rebuild / re-deploy required
3. Telemetry continues collecting both modes during the rollback so we can diagnose the regression without re-flipping

## 12. Open questions

1. **Should LOW-triage files ever get split mode?** Today's design says no (preserves cost). But if the 23-file suite reveals LOW-classified files where the combined prompt is missing findings the split would catch, we may want a `--l1-mode auto-aggressive` that splits LOW too. Defer to post-launch measurement.
2. **Should the three specialized prompts share fewer system-prompt bytes to reduce token cost?** Today they all prepend `SCAN_PROMPT_SYSTEM`. Could move shared instructions into a thinner shared prelude per prompt. Defer — premature optimization without measurement.
3. **Should SCAN-011 (per-attack-class parallel hunters) replace SCAN_PROMPT_VULNS, or layer on top?** SCAN-011's design is to fan out N attack-class hunters within the HIGH-triage routing — orthogonal to SCAN-010's three-question split. Likely layered: SCAN-010 first (split the WHY-types of questions), SCAN-011 second (split VULNS further into per-attack-class hunters). Confirm during SCAN-011 design.
4. **Caching boundary** — does the Anthropic adapter's `enable_system_cache=True` cache survive when three different specialized prompts are sent in the same scan? Anthropic prompt caching uses a per-system-message cache key. The three specialized prompts share `SCAN_PROMPT_SYSTEM` as prefix; if the cache is keyed on the FULL system message (system_prompt + first user-message prefix), each specialized prompt has a different cache key and we don't get the discount. Need to verify empirically against the live API before assuming 1.3× cost; could be 3× in the worst case. Spike: send three specialized prompts back-to-back and inspect `cache_creation_input_tokens` / `cache_read_input_tokens` in the response. Resolve before implementation.

## 13. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Specialized prompts produce DIFFERENT verdicts than combined on the regression suite | Medium | Medium | Acceptance gate (#10.1) catches it; rollback flag (#11) lets us revert per-scan |
| Caching doesn't apply (open question #12.4) → real cost is 3×, not 1.3× | Medium | High | Verify before implementation; if 3×, gate split mode behind explicit `--enable-l1-split` opt-in instead of default-on |
| Verdict-derivation reproduction misses an edge case the combined prompt handled internally | Medium | Medium | Comprehensive test fixtures + 23-file regression. If a regression is found, prefer fixing the derivation over reverting the split. |
| Three parallel calls trigger Anthropic per-key rate limits | Low | Low | Existing adapter exponential backoff handles it; gate `asyncio.gather` with a `Semaphore(N=2)` if observed in production |
| Prompt drift: future edits to one specialized prompt break the merge | Low | Medium | Schema validation catches structural drift. Regression suite catches behavioral drift. |
