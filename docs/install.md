# Install

Get from zero to your first scan in 60 seconds.

## Prereqs

- Python 3.12+
- An [Anthropic API key](https://console.anthropic.com/settings/keys) (`sk-ant-...`)

That's it for the default install. DAST sandbox verification is optional
and runs on either **Docker + gVisor** (self-hosted, no cloud account) or
a **Fly.io** account — see [dast-setup.md](dast-setup.md).

## Install

```bash
pip install argus-ai-scanner
```

Or from source:

```bash
git clone git@github.com:dshochat/Argus_Scanner.git
cd Argus_Scanner
uv sync
```

## Configure

Argus reads `ANTHROPIC_API_KEY` from your environment or a `.env` file
in the current directory (or any parent). The minimum `.env`:

```env
ANTHROPIC_API_KEY=sk-ant-...
```

That's all you need for the default v1.11 cascade (L1 + Finding
Validation + Remediation). Argus's `load_dotenv` uses `override=True`,
so values in `.env` always win over stale shell env vars.

## First scan

A clean file:

```bash
argus scan samples/regression_v1/clean.py
```

Expected: verdict `clean`, cost ~$0.0001, finishes in seconds.

A known-vulnerable file:

```bash
argus scan samples/regression_v1/high_with_vuln.py
```

Expected: verdict `suspicious`, 2 CONFIRMED CWE-78 command-injection
findings. If a DAST sandbox is configured (gVisor or Fly; see DAST
setup), Argus also generates a patch and replays the exploit against it.

## What gets enabled by default (v1.11)

| Stage | Default |
|---|:---:|
| Triage + L1 (Sonnet 4.6 → Opus 4.6 escalation) | ✅ ON |
| **Finding Validation** (sandbox re-runs each L1 finding) | ✅ ON (needs a DAST sandbox) |
| **Remediation** (auto-patch + exploit replay) | ✅ ON (needs a DAST sandbox) |
| Exploit Discovery / Behavioral Profiling / Adversarial Reasoning | Opt-in via flags |

Without a DAST sandbox configured, Argus gracefully degrades to
cascade-only verdicts (L1 only). With one (self-hosted gVisor or Fly),
Validation + Remediation fire on every suspicious / malicious verdict.

## Optional: DAST sandbox

To enable Finding Validation + Remediation, stand up a sandbox — a
**local gVisor container** (recommended; no cloud — set
`ARGUS_DAST_RUNTIME=gvisor`) or a **managed Fly.io** app. **One-time
setup.** Full guide: [dast-setup.md](dast-setup.md).

## Optional: cheaper triage

By default Argus uses Sonnet 4.6 for triage (~$0.02/file, deterministic).
For cost-sensitive batch scans, switch to Gemini Flash-Lite triage
(~$0.001/file, slightly higher variance):

```bash
export GEMINI_API_KEY=AIza...
argus scan FILE --triage-model gemini-flash-lite
```

Get a [Google AI Studio key](https://aistudio.google.com/app/apikey).

## Troubleshooting

**`ANTHROPIC_API_KEY not set`.** Either no `.env` was found in your
current directory or its parents, or your key isn't exported in the
OS environment. Fix: `cp .env.example .env` and fill in the key, then
re-run from the same directory.

**`DAST runner not configured`** (info log, not an error). You're
running without a DAST sandbox set up — for gVisor:
`ARGUS_DAST_RUNTIME=gvisor` + Docker/`runsc` + the local image; for Fly:
`FLY_API_TOKEN` + the image vars. Argus skips DAST gracefully and
returns L1-only verdicts. To enable it, follow
[dast-setup.md](dast-setup.md).

**`Cost cap exceeded: $X > $1.00`**. A pathological file hit the per-
file cap. Raise with `--max-cost 2.00` for that run, or `--max-cost 0`
to disable.

## What's next

- **[`argus scan --help`](#)** — full CLI reference for the `scan`
  subcommand. Also `argus scan-repo --help` and `argus install --help`.
- **[dast-setup.md](dast-setup.md)** — turn on sandbox verification.
- **[architecture.md](architecture.md)** — the full cascade flow.
- **[cost-guide.md](cost-guide.md)** — per-file pricing breakdown.
