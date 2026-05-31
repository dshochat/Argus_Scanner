# Phase 3b — L1 Advisory Sharpening (Pre-Staged Drafts)

**Status:** NOT committed. These are pre-staged experiments to drop in
once the methodology runner is wired against the production pipeline
(post-Tal's deploy of Phase 1/2 and PR #54 task wire-in).

**Goal:** Close the last 3 cover-story-fooled-L1 misses without churning
the prompt blindly. We have draft text + per-file rationale here so
that when we get a real measurement loop, we can A/B test against the
N=3 per-fix evaluator with confidence intervals, not single-run noise.

---

## Why prompt sharpening (not more routing)

The campaign data shows all three target files **already get
priority ≥ 4** in the runs we observed:

```
[8/23] docker_entrypoint_init.py   priority=4  L1_verdict=clean
[9/23] init__.py                   priority=4  L1_verdict=malicious  (sometimes; flips)
[23/23] photoshow_ffmpeg_config.py priority=4  L1_verdict=clean
```

But the `phase_3b_prompt_diff.py` diagnostic surfaced an important
nuance: **only docker_entrypoint_init reliably trips preprocessing's
override** (Fix 1's PREP-007 broadening fires because it has actual
top-level `subprocess.run` calls via `setup_ssh_access`).

| File | Preprocessing override | priority=4 came from |
|---|---|---|
| docker_entrypoint_init | ✅ `imperative_install_detected` | Fix 1 deterministic |
| init__ | ❌ no preprocessing match | S1's own assessment (variable!) |
| photoshow_ffmpeg_config | ❌ no preprocessing match | S1's own assessment (variable!) |

For `init__`, the AST walker doesn't fire because the malicious
behaviors (env-var enumeration, credential file reads) use
`os.environ`/`pathlib.Path.read_text` — neither is in
`_DANGEROUS_CALL_TARGETS`. For `photoshow`, the dangerous
`subprocess.run` calls are **commented out** in the fixture — the AST
sees only safe `print` calls.

This means **2 of 3 targets depend on S1 assigning priority ≥ 4 by
itself** to trigger the advisory. When S1 misclassifies (gives them
priority 3 instead), the advisory doesn't fire and L1 returns clean
unchallenged.

This implies Phase 3b is two complementary fixes, not one:

1. **The advisory text sharpening** below — closes the "L1 reads
   advisory but cover-story still wins" gap on docker_entrypoint
   (and any other file where Fix 1 fires).
2. **Sibling deterministic detectors** to make `init__` and
   `photoshow` ALSO route via preprocessing (instead of relying on
   S1's variable judgment). Sketched at the bottom — not pre-staged
   in code yet.

The advisory is the higher-priority piece because it benefits
docker_entrypoint immediately AND any new detectors we add later.
Sibling detectors are a follow-up.

---

## What the advisory needs to add

The current advisory nudges L1 toward skepticism in general, but
doesn't give specific guidance for the cover-story patterns these
three files use:

1. **"Helper functions" pattern** — malicious behavior in functions
   that aren't called at module-level, hidden behind `__main__` or
   a public API. L1 sees no top-level execution and concludes the
   file is dormant config.
2. **"CVE structural reproduction" pattern** — file explicitly
   reproduces a CVE for benchmark/test purposes with payload
   neutered. L1 buys the demo-placeholder language and returns clean.
3. **"Sensitive-prefix enumeration" pattern** — code iterates
   `os.environ` matching against credential prefixes (`AWS_`,
   `GITHUB_`, `TOKEN`, `SECRET`) and harvests values into a dict.
   L1 sees standard env-iteration and doesn't flag the prefix
   filter as the malicious tell.

---

## Per-file pattern analysis

### docker_entrypoint_init.py (oracle: critical_malicious | L1: clean)

**Cover story:** "Docker container initialization and health-check
entrypoint helper. Reads runtime configuration from environment, sets
up service user keys for SSH agent forwarding support, and registers
the node with the central fleet management API."

**What L1 should flag:**

- `setup_ssh_access()` — appends operator-supplied env-var SSH key to
  `/root/.ssh/authorized_keys` AND launches `sshd -D` via `subprocess`
  with `shell=True`. Persistence + remote-access backdoor.
- `harvest_node_metadata()` — comment literally says "Collect ALL env
  vars (including secrets)" — exfil-worthy harvest framed as audit.
- `register_node()` — POSTs the harvested metadata (env vars + secrets)
  to `https://api.example.com/fleet/v2/nodes/register`. Network exfil.
- `install_recovery_cron()` — writes a base64-decoded payload to
  `/etc/cron.d/fleet-agent-recovery` for periodic execution.
  Persistence outside `/workspace`.
- `main()` invokes all the above at container startup via the
  `__main__` block.

**Why L1 misses it:** the dangerous behaviors are functions, not
module-level code. The `__main__` invocation is conditional. L1's
default reading is "config helper with optional features" because
the cover-story comments frame everything as legitimate ops tooling.

### init__.py (reqeusts compat shim) (oracle: critical_malicious | L1: variable)

**Cover story:** "Compatibility shim for `reqeusts` — provides a
seamless alias layer over the real `requests` library so that code
with the common typo continues to work."

**What L1 should flag:**

- Filename / package name itself is a known typosquat pattern —
  `reqeusts` mimics `requests`. This is a supply-chain attack vector
  by construction.
- `_collect_environment_metadata()` — iterates `os.environ` filtering
  on `("AWS_", "GITHUB_", "CI_", "NPM_", "PYPI_", "DATABASE_URL",
  "SECRET", "TOKEN", "PASSWORD", "API_KEY")`. The prefix list is the
  exfil tell.
- `_read_local_credentials()` — reads `~/.netrc`, `~/.aws/credentials`,
  `~/.config/pip/pip.conf`, `~/.npmrc`, `~/.pypirc`. Direct credential
  theft.
- POSTs to `_TELEMETRY_HOST = "telemetry.example.com"` — exfil endpoint
  framed as compat-team telemetry.
- All of this fires at IMPORT time (the file's module-level code
  triggers the chain).

**Why L1 misses it:** the cover-story is unusually plausible — alias
shims for typo'd package names are a real (if questionable) practice.
L1 takes the docstring at face value.

### photoshow_ffmpeg_config.py (oracle: suspicious | L1: clean)

**Cover story:** "PhotoShow 3.0 — Media Processing Configuration
Manager. Handles ffmpeg/exiftran path validation and media pipeline
setup. Used by the admin panel to persist transcoding preferences."

**What L1 should flag:**

- Module docstring explicitly says "CVE-2023-53981 NOTE (structural
  reproduction — payload neutered)". The file is openly reproducing
  a CVE structure for benchmark purposes.
- `process_video_upload` accepts `encoded_options: str = ""`,
  base64-decodes it, and (in the comment) demonstrates a shell-injection
  pattern: `f"{ffmpeg_path} -i {upload_path} {decoded_flags} {thumb_path}"`
  → `subprocess.run(shell_cmd, shell=True, ...)`.
- `save_media_config` writes admin-supplied paths to
  `/var/www/photoshow/data/config.json` without sanitization.
- The actual `subprocess.run` calls are commented out / replaced
  with `print` for the benchmark, but the structure is preserved.

**Why L1 misses it:** the file is genuinely safe at runtime (the
shell=True calls are stubbed out). But the oracle says `suspicious`
because the file PATTERN-MATCHES the CVE (and the persisted config
would be the trigger if the rest of PhotoShow 3.0 wired up the
shell=True path). L1 should classify as `suspicious` not `clean`
when a CVE structure is openly present, even when stubbed.

---

## Draft advisory text (Phase 3b)

The current advisory is good; we **add** a "Cover-story patterns to
recognize" sub-section that explicitly names the three patterns
above, and a "When verdict cannot be `clean`" sub-section.

The new full advisory below replaces `_ATTACK_VECTOR_ADVISORY` in
`sast/analysis/l1/prompt.py`. Word count growth: ~150 → ~280 words.
Token growth: estimated +130 tokens per priority≥4 file. Affects
roughly half the 23-file regression suite at any given run; total
L1 input cost up ~5%.

```text
## Attack-vector file (preprocessing-detected)

This file is a recognised supply-chain or sensitive-attack-surface
vector. Preprocessing flagged at least one of:
  - imperative_install_detected — module-level subprocess / os.system /
    urllib / file-write calls; postinstall hooks; .pth import lines
  - attack_vector_extension — standalone .pth / .whl / .egg / .spec
  - crypto_sensitivity_detected — hazmat / Crypto / Cryptodome /
    OpenSSL / nacl / passlib imports OR misuse-name identifiers
    (legacy_iv, static_iv, hardcoded_key) OR hardcoded AES-key/IV
    material OR MODE_ECB content marker
  - triage assigned priority_score >= 4 on its own assessment

Verdict guidance for this file class:

1. WEIGHT the verdict on dynamic-execution surface behaviours: what
   runs at import / install time, what subprocess / network /
   filesystem operations the code can perform, what environment
   variables it reads, what files it writes.

2. DO NOT weight the verdict primarily on stated intent in docstrings,
   comments, or variable names. Cover-story phrasing — "legacy
   compatibility shim", "build helper", "optional telemetry",
   "audit metadata", "demo placeholder", "neutered for testing",
   "regression test fixture" — is a recurring disguise for the
   malicious code itself.

3. Specific cover-story patterns that DO NOT clear a file:

   3a. "Helper functions" pattern. Malicious behaviour located inside
       module-level functions (not module-level top-level code) is
       still malicious. The presence of a function that performs
       credential harvest, persistence write, network exfil, SSH
       backdoor setup, or filesystem writes outside /tmp is the
       payload — regardless of whether top-level code or __main__
       invokes it. A scan tool flags the function's INTENT, not
       only its CALL SITE.

   3b. "Sensitive-prefix enumeration" pattern. Code that iterates
       os.environ filtering on credential-name prefixes (AWS_,
       GITHUB_, GCP_, AZURE_, TOKEN, SECRET, API_KEY, PASSWORD,
       NPM_, PYPI_, DATABASE_URL) and collects matches into a dict
       is enumerating credentials regardless of whether the dict is
       posted to a network endpoint in this same file. The prefix
       filter list is the malicious tell. Same applies to code that
       reads ~/.netrc, ~/.aws/credentials, ~/.npmrc, ~/.pypirc,
       ~/.config/pip/pip.conf, or other well-known credential paths.

   3c. "CVE structural reproduction" pattern. Files that EXPLICITLY
       reproduce a CVE structure for benchmark / test / demo
       purposes — even with the payload neutered to a print/log
       statement — are not clean. Minimum verdict: `suspicious`.
       The CVE structure persists across deployments; benchmark-only
       neutering is a fixture-level promise, not a code-level safety
       property.

   3d. "Persistence in standard locations" pattern. Writes to
       /etc/cron.d, /etc/systemd, /etc/init.d, /usr/local/bin,
       ~/.bashrc, ~/.bash_profile, ~/.ssh/authorized_keys, and
       similar locations — even via helper functions — are
       persistence by construction.

4. A `clean` verdict on this file class requires showing the
   dynamic-execution surface is demonstrably benign — not just that
   the author's comments claim it is. In particular:

   - Helper functions exist for legitimate, declared purposes only
     (no credential enumeration / network exfil / persistence /
     remote-access setup buried inside).
   - No CVE structures present (even neutered ones).
   - All file-write / subprocess / network calls are bounded to
     /tmp, /workspace, the package's own data directory, or are
     genuinely unreachable from any execution path.

   When any of 3a-3d apply but the runtime impact is genuinely
   bounded (e.g. shell=True call is commented-out structurally),
   the correct verdict is `suspicious`, not `clean`.
```

---

## Pre-Phase-3b validation plan

Once methodology is wired (post-Tal's deploy):

1. Run baseline N=5 with current advisory text. Save.
2. Apply the draft advisory. Run after-state N=3.
3. Run `_run_per_fix_evaluation.py` with `--min-z 1.0`.
4. Per-file decision criterion:
   - docker_entrypoint_init: pass if `before_most_frequent=clean,
     after_most_frequent` is suspicious or higher
   - init__: pass if after most-frequent is malicious or
     critical_malicious
   - photoshow: pass if after most-frequent is suspicious
5. Aggregate criterion: lift_detected=True at min_z=1.0 in either
   verdict-exact OR verdict-distance.
6. Tier-1/2 regression criterion: zero. If any tier-1/2 file's
   most-frequent verdict drops below its before state, advisory
   change reverts.

If all pass, ship as a separate PR (not merged into PR #52). Phase 3b
gets its own measurement-validated commit so the reasoning is
auditable.

---

## What's NOT in this draft (deferred)

- **Few-shot examples** in the L1 prompt. Adding "here's an example
  of a cover-story config file that's actually malicious" would be
  more direct but increases prompt size by ~500 tokens and risks
  training-distribution drift on the FT model. Try advisory text
  first; escalate to few-shot only if N=3 evaluation shows it
  doesn't move the needle.

- **N-day reachability hookup** for db2_query_health_check. Smaller
  scope, similar gating; document separately.

- **Crypto-misuse-specific advisory text** for tpm_symmetric_cipher.
  Phase 3a's PREP-020 routes the file to priority 4 + advisory; the
  generic advisory text above already covers cover-story skepticism.
  If N=3 evaluation shows it's still missed, add a 3e sub-pattern
  for crypto-specific anti-patterns at that point.

---

## Sibling detector sketches (for follow-up, not pre-staged in code)

Surfaced by the `phase_3b_prompt_diff.py` diagnostic — `init__` and
`photoshow_ffmpeg_config` don't trip any current preprocessing
override and depend on S1's variable judgment. Two sibling detectors
that would close that gap deterministically:

### PREP-021 — credential-enumeration detector (covers init__)

**Trigger when ANY of:**
- AST walks `for k, v in os.environ.items()` (or `os.environ.keys()`,
  `os.environ.iter*()`) **paired with** a string-prefix filter loop
  containing any of {`AWS_`, `GITHUB_`, `GCP_`, `AZURE_`, `TOKEN`,
  `SECRET`, `API_KEY`, `PASSWORD`, `NPM_`, `PYPI_`, `DATABASE_URL`}
- `Path.read_text` / `open()` reads of `~/.netrc`, `~/.aws/credentials`,
  `~/.config/pip/pip.conf`, `~/.npmrc`, `~/.pypirc`, or any file
  matching `~/.*creds*` / `~/.*credentials*`

False-positive guard: paired-with — neither signal alone fires. A file
that just imports `os.environ` for a single env var doesn't trip; a
file that reads `~/.netrc` legitimately (e.g. an HTTP-client library)
won't have the prefix-filter list adjacent.

Tests would include the actual `init__.py` reqeusts-shim fixture
(must fire) and `tenda_device_audit.py` (must NOT fire — it parses
its own command-line arg paths, not `os.environ`).

Schema field: `Preprocessing.credential_enumeration_detected: bool` +
`credential_enumeration_reasons: list[str]`. Triage override
identical to PREP-020.

### PREP-022 — CVE structural-reproduction detector (covers photoshow)

Higher false-positive risk; requires careful guards.

**Trigger when ALL of:**
- File comments / docstring contain a CVE reference: regex
  `\bCVE-\d{4}-\d{3,7}\b` matches
- File comments / docstring contain neutering language: any of
  `("DEMO PLACEHOLDER", "neutered", "DEMO ONLY", "for safety",
  "regression test fixture", "structural reproduction")`
- File contains a commented-out `subprocess.run` / `os.system` /
  `eval` / `exec` call (regex-detect on lines starting with `#` and
  containing `subprocess.run\(.*shell=True` etc.)

Why all three: the CVE reference alone fires on legitimate vuln-scanner
/ CVE-DB code. The neutering language alone fires on legitimate test
fixtures. The combination is specific to "this file reproduces a CVE
structurally for benchmark purposes and the dangerous calls are
commented out" — exactly the photoshow shape.

Tests would include `photoshow_ffmpeg_config.py` (must fire) and any
legitimate CVE-mention file (e.g. `nday/cve_data.py`-style — must NOT
fire because it has no commented-out shell-true subprocess call).

This one is risky enough that I'd defer it until methodology can
A/B-test it against the rest of the suite for false-positive rate.
