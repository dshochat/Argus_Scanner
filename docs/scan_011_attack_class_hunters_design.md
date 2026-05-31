# SCAN-011 — Per-attack-class parallel hunters within HIGH-triage scans

**Status:** Design / scoping
**Estimated work:** 1–2 weeks
**Priority:** HIGH (post-v1.0 Cloudflare-comparison batch)
**Blocked by:** SCAN-010 + SCAN-010.1 — both shipped 2026-05-18

---

## 1. Problem

SCAN-010 split the L1 cascade into three specialized prompts (`VULNS` / `BEHAVIORAL` / `CHAINS`) along the **question-type axis** ("what bugs exist" vs "what does it do" vs "how do they chain"). That delivered ~16% fewer hedged findings and parallelism wins.

But the `VULNS` prompt itself still asks **one broad question** ("find ALL vulnerabilities") across 21 distinct CWE categories: `command_injection | sql_injection | path_traversal | ssrf | xss | xxe | hardcoded_credentials | prompt_injection | insecure_deserialization | idor | auth_bypass | race_condition | crypto_weakness | data_exfiltration | privilege_escalation | code_injection | csrf | file_upload | open_redirect | missing_authorization | business_logic_flaw`.

Cloudflare's published security harness ran **~50 parallel hunter agents per scan**, each looking for a **specific attack class**. Their stated insight (which matches our combined-L1 audit and SCAN-010 results): **narrower prompts produce less hedging and more precise findings**.

SCAN-011 takes that insight one level deeper than SCAN-010 — splitting the `VULNS` prompt along the **attack-class axis** for HIGH-triage routings.

## 2. What "narrower" means at this level

Compared with the current `VULNS` prompt asking the model to consider 21 attack classes:

| Hunter | Asks one focused question |
|---|---|
| `INJECTION_HUNTER` | "Does user input flow into a code-execution or query sink?" (cmd/sql/code/eval injection family) |
| `SSRF_HUNTER` | "Does user-controlled URL flow into a network primitive?" |
| `PATH_TRAVERSAL_HUNTER` | "Does user-controlled path flow into filesystem access?" |
| `DESERIALIZATION_HUNTER` | "Does untrusted bytes flow into pickle / yaml.load / unmarshal?" |
| `PROMPT_INJECTION_HUNTER` | "Does untrusted text reach an LLM call's prompt parameter?" (with the strict precondition rules already in `SCAN_REASONING_RULES`) |
| `CREDENTIAL_HUNTER` | "Are credentials hardcoded, leaked, or exfiltrated?" |
| `AUTHZ_HUNTER` | "Is access control missing, bypassable, or IDOR-vulnerable?" |
| `CRYPTO_HUNTER` | "Are crypto primitives weak, misused, or insecurely configured?" |
| `EXFIL_HUNTER` | "Does sensitive data leave the system via network / logs / errors?" |
| `MALICIOUS_INTENT_HUNTER` | "Is the file itself the attack (CWE-506 territory) — embedded malware, backdoor, supply-chain payload?" |

10 hunters, not 21. The CWE families collapse: `command_injection` / `sql_injection` / `code_injection` / `eval` all share the same "user-input → sink" reasoning so they live in one `INJECTION_HUNTER`. `xss` / `xxe` / `csrf` / `open_redirect` / `file_upload` / `race_condition` / `business_logic_flaw` / `privilege_escalation` either fold into existing hunters or live in a catch-all `MISC_VULN_HUNTER` that's narrow enough to still beat the 21-way prompt.

Each hunter sees the same `SCAN_PROMPT_SYSTEM` prefix (already cacheable post-SCAN-010.1) + its own short specialized body (~500-1500 chars).

## 3. Non-goals (explicit)

1. **NOT replacing the SCAN-010 split.** SCAN-011 layers ON TOP of SCAN-010's split — the `VULNS` slot is replaced by N parallel hunters. `BEHAVIORAL` and `CHAINS` are unchanged.
2. **NOT changing the engine cascade / triage routing.** CLEAN / LOW paths are completely unaffected. SCAN-011 fires only when SCAN-010's split mode fires (i.e., HIGH-triage + `l1_split_enabled=True`).
3. **NOT 50-way fan-out.** Cloudflare's 50-way pattern doesn't apply at our cost level — they have unlimited internal budget; we have BYOK customers. 10 hunters bounded by `ScanConfig.max_parallel_hunters_per_file` (default 10, max 20) keeps cost predictable.
4. **NOT building a hunter framework from scratch.** Each hunter is just another specialized prompt + body in `prompts/scanner.py`. The fan-out machinery from SCAN-010's split runner is reused directly.

## 4. Architecture

### 4.1 Prompt structure

```
prompts/scanner.py adds:

  ATTACK_CLASS_HUNTERS: dict[str, str] = {
      "injection":         SCAN_PROMPT_INJECTION_HUNTER_BODY,
      "ssrf":              SCAN_PROMPT_SSRF_HUNTER_BODY,
      "path_traversal":    SCAN_PROMPT_PATH_TRAVERSAL_HUNTER_BODY,
      "deserialization":   SCAN_PROMPT_DESERIALIZATION_HUNTER_BODY,
      "prompt_injection":  SCAN_PROMPT_PROMPT_INJECTION_HUNTER_BODY,
      "credentials":       SCAN_PROMPT_CREDENTIAL_HUNTER_BODY,
      "authz":             SCAN_PROMPT_AUTHZ_HUNTER_BODY,
      "crypto":            SCAN_PROMPT_CRYPTO_HUNTER_BODY,
      "exfiltration":      SCAN_PROMPT_EXFIL_HUNTER_BODY,
      "malicious_intent":  SCAN_PROMPT_MALICIOUS_INTENT_HUNTER_BODY,
  }

Each hunter body shares schema fields (file_intent_analysis +
vulnerabilities[] + composite_risk) but the prompt narrates the
search criteria specific to its attack class. The vulnerability
type taxonomy in vulnerabilities[].type stays the existing
21-value enum (no migration needed downstream).
```

### 4.2 Runner

```
scanner/runners.py adds:

  make_anthropic_hunter_runner_from_adapter(
      adapter,
      *,
      hunter_set: tuple[str, ...] | None = None,
      max_concurrent_hunters: int = 10,
      model_label: str,
      cost_per_m_input: float,
      cost_per_m_output: float,
  ) -> Callable[..., Awaitable[dict]]

  make_sonnet_runner_hunter(api_key, *, ...) -> ...
  make_opus_runner_hunter(api_key, *, ...) -> ...
```

The hunter runner:
1. Selects `hunter_set` (default = all 10).
2. Sequentializes the first hunter call (writes the SCAN_PROMPT_SYSTEM cache, per SCAN-010.1) — `injection` chosen as first because it's the most-common-finding hunter, so it warms the cache for the others.
3. Fans out the remaining N-1 hunters via `asyncio.gather` bounded by `Semaphore(max_concurrent_hunters)`.
4. Merges results: union of `vulnerabilities[]` across hunters (dedup by `(type, line, code)` triple), max of `composite_risk.score`, max of uncertainty.
5. Emits `hunter_telemetry` block on the returned dict:
   - per-hunter: validity, n_findings_emitted, input_tokens, output_tokens, cost_usd, cache_read_input_tokens
   - aggregate: n_total_findings, n_dedupe_collisions, cost_usd_total

### 4.3 Dispatch

The split runner (SCAN-010) currently calls `make_anthropic_split_runner_from_adapter`. SCAN-011 adds an alternative wiring:

```
scanner/engine.py:ScanConfig adds:

  l1_hunter_enabled: bool = False  # opt-in for v1; flip default after Gate validation
  l1_hunter_max_concurrent: int = 10
  l1_hunter_set: tuple[str, ...] = ()  # empty = all 10; subset for targeted scans

scanner/cli.py adds:

  --l1-hunters {all|<comma-list>}     # default unset = SCAN-010 split-mode behavior
  --l1-hunter-max-concurrent N        # advanced; default 10
```

When `l1_hunter_enabled=True` AND triage routes HIGH, the engine dispatches to the hunter runner. The hunter runner internally still calls BEHAVIORAL + CHAINS via the SCAN-010 split (those slots are unchanged); it just replaces the single VULNS slot with N parallel hunters.

## 5. Cost math

Per HIGH-triage file with `max_concurrent_hunters=10`:

| Component | Tokens | Cost (Sonnet 4.6) |
|---|---|---|
| 1× cache-write of SCAN_PROMPT_SYSTEM (~2500 tokens, 2.0× input rate) | 5000 | $0.015 |
| 9× cache-read of SCAN_PROMPT_SYSTEM (0.1× input rate) | 2250 | $0.007 |
| 10× hunter body (~500-1500 chars each, ~300-500 tokens) input | ~4000 | $0.012 |
| 10× output × ~1500 tokens (narrower prompts → smaller outputs each) | ~15000 | $0.225 |
| BEHAVIORAL + CHAINS (unchanged from SCAN-010, +2 calls) | ~4000 in / ~3500 out | $0.065 |
| **Total** | **~33000** | **~$0.32 per HIGH-triage file** |

vs SCAN-010 baseline: ~$0.16 per HIGH-triage file.

**SCAN-011 ~2× cost of SCAN-010 on HIGH-triage files.** This is the BIG cost increase — operators need to opt in deliberately. Default OFF is the right v1 posture.

Cost gate: SCAN-007's per-file cap (default $0.50) bounds this. If `max_cost_per_file_usd` is set tight (e.g., $0.20), the runner aborts further hunter calls mid-fanout and ships partial output. Same pattern as SCAN-010's mid-fanout cancellation.

## 6. Quality story — why this trade is worth it

Cloudflare's published claim: narrower prompts produce less hedged findings + better recall on specific attack classes.

Argus-specific argument:

1. The current `VULNS` prompt is a 21-CWE-class catch-all. The model's attention is spread thin — when it scans an SSRF-shaped function, it's also half-thinking about XSS / SQL injection / authn-bypass / etc.
2. A focused `SSRF_HUNTER` prompt asks ONE question: "does user-controlled URL flow into a network primitive?" The model can drill deep on the specific data-flow pattern.
3. On files where one CWE class dominates (typical real-world case), 9 of 10 hunters return empty findings cheaply and 1 hunter produces a thorough analysis. Cost is bounded by the 1 hunter doing real work.
4. On multi-vulnerability files (rare but high-value — e.g., the LangChain GHSA disclosures), multiple hunters fire and the dedup'd union surfaces MORE findings than a single VULNS prompt would catch.

**Acceptance gate (Gate 2 equivalent — 23-file regression suite):**

* Per-finding precision stays ≥ baseline (no FP explosion)
* Per-finding recall ≥ baseline on files where the oracle has multiple CWE classes
* Verdict-exact rate ≥ baseline (composite_risk derivation is the same; verdict shouldn't shift)
* Hedging-rate drop ≥ 30% (the Cloudflare-cited improvement)
* Mean per-file cost increase ≤ 2.5× SCAN-010 baseline (matches our cost-math estimate)

## 7. Failure modes

| Failure | Behavior |
|---|---|
| 1-2 hunters JSON-fail | Merged result with their findings missing; rest ship. Telemetry surfaces which hunters failed. |
| 5+ hunters JSON-fail | Systemic — surface `hunter_systemic_failure` runner error; fall back to SCAN-010 split mode for this file. |
| One hunter raises | `asyncio.gather(return_exceptions=True)` catches; that hunter's slot empty; rest ship. |
| Cost cap hit mid-fanout | Cancel remaining hunters; ship partial output with `hunter_telemetry.cost_capped=True`. Verdict derives from whatever returned. |
| Dedup collision (e.g., two hunters flag same `(injection, line 47)`) | Keep the highest-confidence variant; collision counted in telemetry. |
| Empty `hunter_set` config | Falls through to SCAN-010 split mode (combined VULNS, no hunter fan-out). |

## 8. Rollback story

`ScanConfig.l1_hunter_enabled=False` is the default. Operators who hit unexpected cost or quality regressions:
1. Remove `--l1-hunters` from CLI invocation → revert to SCAN-010 behavior
2. No redeploy, no config-file edit

The CLI flag IS the rollback. Telemetry's `hunter_telemetry` block makes A/B comparison possible without redeploys.

## 9. Implementation plan

Slice 1 — Foundation (this PR / "today" first slice):

* Hunter taxonomy + first 3 prompts (`injection`, `ssrf`, `malicious_intent`) drafted in `prompts/scanner.py`
* `ATTACK_CLASS_HUNTERS` dict + `SCAN_PROMPT_INJECTION_HUNTER_BODY` etc.
* `scanner/runners.py:make_anthropic_hunter_runner_from_adapter` scaffolding (single hunter call works; multi-hunter fan-out stubbed)
* `ScanConfig.l1_hunter_enabled` + `l1_hunter_max_concurrent` fields
* Unit tests for: hunter dispatch when flag on / off / split-fallback when no hunter wired
* No CLI flag yet — flag in slice 2

Slice 2 — Complete the hunter set (next PR):

* Remaining 7 hunters in `prompts/scanner.py`
* Multi-hunter fan-out logic in the runner with sequentialize-first-call pattern
* Dedup of `vulnerabilities[]` across hunters
* `--l1-hunters` CLI flag
* Cost-cap-aware mid-fanout cancellation

Slice 3 — Validation + default flip (separate session, ~1 day):

* 23-file regression audit (Gate 2 equivalent)
* Hedging-rate measurement vs SCAN-010 baseline
* Cost telemetry analysis
* Default flip decision

## 10. Open questions

1. **Should hunters be order-dependent?** Today's plan: parallel except for the first call (sequentialize for cache write). Alternative: chain dependent hunters (e.g., `malicious_intent` reads first, gates whether the file-attack-suite hunters even fire). Costs less but adds latency. Defer to slice 3 measurement.
2. **Should `BEHAVIORAL` + `CHAINS` calls fire in parallel with the hunter fan-out or sequentially?** Today's plan: parallel (with the rest of the hunters). Adds 2 calls but they're cheap (single specialized prompts each).
3. **Schema unification.** Each hunter emits `vulnerabilities[]` shaped like the existing SCAN-010 VULNS prompt. Merging is trivial (union + dedup). But individual hunter findings will have a narrower scope per call — operators might want a `hunter_origin` field per finding to trace which hunter emitted it. Add to slice 2 if requested.
