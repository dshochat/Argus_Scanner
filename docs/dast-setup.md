# DAST setup

DAST verification is **optional**. If you skip it, Argus runs the L1 cascade and returns verdicts without sandbox-confirmed evidence.

## What DAST does for you (v1.1)

When enabled, DAST runs in a Firecracker microVM (Fly.io managed) and gives you four classes of per-finding outcome:

| Status | What it means |
|---|---|
| `CONFIRMED` | Sandbox observed the vulnerability actually being exploited at runtime. PoC payload + runtime evidence are surfaced. |
| `BLOCKED` | DAST tested the attack; the file's own code defended against it (sanitization, escaping, allowlist, etc.). |
| `UNREACHED` | Attack tested; the code path can't be triggered from any tested input. |
| `NOT_TESTED` | DAST didn't fully validate (with sub-reason: `infra_stub` / `inconclusive` / `not_planned`). |

Plus DAST-204 v0.5 **Discovery** mode (opt-in via `--enable-discovery`): proactive payload sweep that finds CWEs L1 missed entirely.

## Language coverage matrix (DAST-206)

The Argus DAST sandbox image (`minimal-v2`, `networked-v2`, `ml_tools-v2`) ships with multi-language runtimes pre-installed. Discovery commands auto-dispatch by file extension:

| File extension | Runtime | Use case |
|---|---|---|
| `.py`, `.pth` | Python 3.13 | Python supply-chain (PyPI, sitecustomize, postinstall) |
| `.js`, `.mjs`, `.cjs` | Node.js (Debian default — currently 18.x) | npm postinstall, malicious packages, AI tooling |
| `.ts`, `.jsx`, `.tsx` | Node.js (no transpile — runs as JS for behavior testing) | TypeScript supply-chain (security analysis is on runtime behavior, not type-checks) |
| `.sh`, `.bash` | bash | Shell installer scripts |
| `.class`, `.jar` | OpenJDK 17 JRE headless (already in image) | Java/Kotlin/Scala — pre-compiled bytecode analysis. Class invocation: `java -cp /workspace ClassName`. |
| `.java` (source) | **Not yet** — needs JDK image rebuild (v1.2 task) | Java source files require `javac` for compilation. JRE-only image can't compile. |
| Other | python3 (default fallback) | — |

**Not yet supported in DAST**: Go, Rust, C/C++ (compile-required), .NET, Java source files. These get **L1 cascade analysis** (verdict accuracy unaffected) but no runtime DAST validation. Planned for v1.2+.

## What you need

- A Fly.io account ([fly.io](https://fly.io))
- `flyctl` CLI installed locally — installation:
  - macOS / Linux: `curl -L https://fly.io/install.sh | sh`
  - Windows PowerShell: `iwr https://fly.io/install.ps1 -useb | iex`
- A payment method on file at [fly.io/dashboard/billing](https://fly.io/dashboard/billing) (the free tier covers DAST sandbox usage but Fly requires a card)

## One-time setup

The full runbook with explanations is in [`dast/sandbox/firecracker/MULTI_IMAGE.md`](https://github.com/dshochat/Argus_Scanner/blob/main/dast/sandbox/firecracker/MULTI_IMAGE.md). Short version:

```bash
# 1. Authenticate
flyctl auth login

# 2. Create the sandbox app + deploy initial image
cd dast/sandbox/firecracker
bash preflight.sh    # macOS / Linux / WSL
# or on Windows:
$env:ARGUS_DAST_FLY_ORG = "personal"  # or your org slug
./preflight.ps1

# 3. Generate a deploy-scoped token for Argus
flyctl tokens create deploy --app argus-dast-sandbox --expiry 720h

# 4. Save the token in your .env (replace any existing value)
# FLY_API_TOKEN=<paste here>

# 5. Build + push the three sandbox images (~10-90 min, mostly cached)
#    IMAGE_VERSION=v2 ships v1.5's /data pre-create fix needed for
#    runtime-probe path-traversal detection. Bumping the tag prevents
#    stale-cache confusion for users upgrading from v1.x.
IMAGE_VERSION=v2 bash build_and_push_multi.sh

# 6. Set the image refs in .env
# ECHO_DAST_IMAGE_MINIMAL=registry.fly.io/argus-dast-sandbox:minimal-v2
# ECHO_DAST_IMAGE_NETWORKED=registry.fly.io/argus-dast-sandbox:networked-v2
# ECHO_DAST_IMAGE_ML_TOOLS=registry.fly.io/argus-dast-sandbox:ml_tools-v2
```

After step 6, `argus scan` automatically invokes DAST on confirmed-malicious files. Use `--no-dast` to suppress per scan.

## Per-scan flags (v1.1)

```bash
# Default: DAST runs on malicious / critical_malicious verdicts only
argus scan path/to/file.py

# Opt-in to DAST-204 discovery — proactive payload sweep for new CWEs
argus scan path/to/file.py --enable-discovery

# Tunable DAST coverage (DAST-207 lite, v1.1)
# Default trigger:  malicious + critical_malicious
# Broader coverage (also DAST suspicious files, ~30-50% more API spend):
argus scan path/to/file.py --dast-trigger-verdicts suspicious,malicious,critical_malicious

# Strictest cost-controlled mode:
argus scan path/to/file.py --dast-trigger-verdicts critical_malicious

# Hard cost cap per file (any verdict)
argus scan path/to/file.py --max-cost 0.50

# Skip DAST entirely (no Fly required)
argus scan path/to/file.py --no-dast
```

## The three sandbox images

| Image | Contents | Use cases |
|---|---|---|
| `minimal-v2` | Python 3.13 + Node.js + npm + JRE + bash + coreutils + curl + pre-created app dirs (`/data`, `/srv/app`, `/var/lib/app`, …) at mode 1777 | Default for most plans. Pickle exploits, file I/O, subprocess, basic crypto, Node modules, runtime-probe path-traversal. |
| `networked-v2` | minimal + curl / wget / nc / dnsutils / openssl | Exfiltration confirmation: real curl-to-attacker-domain calls observable via DNS / network captures. |
| `ml_tools-v2` | networked + torch CPU + transformers + safetensors | Model-loader exploits: malicious safetensors, pickled `__reduce__` payloads in `torch.load()`. |

> **Upgrading from v1.x?** Existing `*-v1` images don't include the common app directories pre-created at mode 1777 that v1.5's runtime probe needs to detect path-traversal exploits against hard-coded prefix dirs like `open("/data/" + user_input)`. Rebuild + retag with `IMAGE_VERSION=v2 bash build_and_push_multi.sh` and update your `.env` to point at the `-v2` tags.

The orchestrator's plan generator picks `image_hint` per hypothesis. The MultiImageSandboxClient routes accordingly; if the model picks an unsupported hint (or omits one), it falls back to `minimal`.

## Cost notes

- **Image storage + push**: $0.
- **Per-scan machine cost**: $0.05-0.20. Each plan creates one ephemeral microVM that runs for ~10-60 seconds, billed per second.
- **Anthropic inference**: dominates DAST cost (~$0.20-0.80 per scan, depends on iteration count).
- **Discovery additional cost** (if `--enable-discovery`): ~$0.25/file (5-7 sandbox plans run in series).

## Privacy / data flow

When DAST is enabled, your file content is shipped (gzip + base64) to your own Fly app via the env-var protocol. The file is materialised at `/workspace/<filename>` inside an ephemeral Firecracker microVM, executed, observed via DNS hijack + capture server, and the VM is auto-destroyed after the plan completes.

**Your code never leaves your Fly account.** Argus's SandboxClient talks directly to your Fly machines API; nothing is routed through Argus infrastructure.

For users without Fly accounts, run with `--no-dast` — Argus ships meaningful verdicts via the L1 cascade alone.

## Troubleshooting

**`flyctl: command not found` from Argus.** flyctl is needed only for log retrieval. If your Python process can't see it, set `flyctl_path` explicitly when constructing `FirecrackerSandboxClient`, or add flyctl's install dir to PATH.

**`organization <X> not found`** during `preflight.ps1`. Your Fly org slug might not be `personal`. Run `flyctl orgs list` and pass the right slug via `$env:ARGUS_DAST_FLY_ORG = "your-slug"`.

**`is_stub_no_trace=True` / "no events captured from machine"** in the DAST journal. The init script likely failed before the entrypoint ran. Most common cause: CRLF line endings in `dast-init.sh` (Linux bash chokes on `\r`). The repo's `.gitattributes` enforces LF on `*.sh` to prevent this; if you've edited the script locally, verify with `file dast-init.sh` (should NOT say "with CRLF line terminators"). You'll see this status in the launch report as `NOT_TESTED:infra_stub`.

**Verdict downgrade after DAST**. The DAST-105 v2 engine guard (v1.1) allows DAST to downgrade L1's verdict ONLY when every L1 finding has Tier 1.5 status `BLOCKED` or `UNREACHED` — sandbox-grounded refutation. Without that, L1's verdict is kept and you'll see `dast_keep_l1:N/M_findings_grounded` in `scan_path`.

**Discovery (CWE-204) finds 0 things on supply-chain malware files.** Expected — Discovery v0.5's payload library targets web/app vulnerabilities (CWE-78/89/22/79/502/918/611/94) plus malware patterns (CWE-201/506). Pure data-exfil malware that doesn't take user input may not match any CLI-injection pattern. The CWE-201 (any outbound network call) and CWE-506 (persistence file writes) payloads will fire on most active malware. If your file is benign-looking and no discovery payloads fire, that's a correct outcome.

## Languages without DAST today

L1 cascade analysis works on any language Argus encounters. DAST per-finding validation requires the file's runtime to be available in the sandbox image. For files in unsupported languages:

- L1 verdict accuracy is unaffected
- `result.dast_attempted` will be `False` (gate didn't fire) or DAST runs but produces few traces
- `result.per_finding_validation` will mostly be `NOT_TESTED:not_planned`

Planned for v1.2+:
- Go runtime
- Rust runtime
- .NET / C#

For these languages today, treat L1 verdicts as the primary signal; consult per-finding metadata for severity/confidence.
