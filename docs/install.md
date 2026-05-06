# Install & first scan

## Prerequisites

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) (the dependency manager Argus uses)
- An Anthropic API key — [console.anthropic.com](https://console.anthropic.com/settings/keys)
- A Google AI Studio key — [aistudio.google.com](https://aistudio.google.com/app/apikey)
- *(Optional)* a Fly.io account if you want DAST sandbox verification

## 1. Clone + install

```bash
git clone git@github.com:dshochat/Argus_Scanner.git
cd Argus_Scanner
uv sync --extra dev
```

This installs runtime deps (`anthropic`, `google-genai`, `pydantic`, `httpx`, `tiktoken`, etc.) plus dev deps (pytest, ruff, mypy).

## 2. Configure API keys

```bash
cp .env.example .env
```

Then edit `.env` and fill in:

```env
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=AIza...
```

Argus reads `.env` with `override=True` — local file values always win over OS environment.

## 3. Verify with a sanity scan

A clean file should short-circuit at triage and cost ~$0.0001:

```bash
uv run argus scan samples/regression_v1/clean.py --output markdown
```

Expected output:

```
**Verdict:** `clean`
**Risk:** 0/100 (none)
**Triage:** CLEAN — Pure utility functions...
**Cost:** $0.0001  **Time:** ~2s
**Scan path:** preprocessing → high_stakes=False → triage:CLEAN → clean_short_circuit
```

## 4. Scan a real file

```bash
uv run argus scan path/to/your/code.py --output markdown
```

Common flags:

| Flag | Effect |
|---|---|
| `--output json` | structured JSON instead of markdown |
| `--no-dast` | skip DAST verification (default: enabled if Fly is configured) |
| `--max-cost 0.25` | abort the scan if it exceeds $0.25 ([Cost guide](cost-guide.md)) |

## 5. (Optional) DAST sandbox setup

DAST runs in Firecracker microvms on Fly.io. If you don't configure it, Argus runs L1-only and skips the verification stage. To enable:

→ [DAST setup runbook](dast-setup.md)

## What's next

- [Architecture overview](architecture.md) — what each cascade tier does
- [Cost guide](cost-guide.md) — per-file pricing + the `--max-cost` cap
- [Contributing](contributing.md) — running the test suite + PR process

## Troubleshooting

**`KeyError: 'ANTHROPIC_API_KEY'` on first run.** Most often: `.env` exists but `ANTHROPIC_API_KEY` is also set as an empty string in your shell environment, which shadows the file. Fix by unsetting the OS-level var (`unset ANTHROPIC_API_KEY` on bash, `Remove-Item env:ANTHROPIC_API_KEY` on PowerShell) and re-running.

**`flyctl: command not found` during DAST.** DAST is optional. If Fly env vars aren't set, the runner returns `None` and Argus skips DAST silently with a log line. Force-disable with `--no-dast` to suppress the log.

**Test failures referencing `samples/regression_v1/`.** The regression suite is committed to the repo. If `git status` shows the directory untracked, run `git fetch && git reset --hard origin/main`.
