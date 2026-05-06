# Argus

**An AI-native code security scanner that proves exploitability at runtime.**

Argus combines a cost-graduated LLM cascade (Gemini Flash-Lite triage → Sonnet 4.6 → Opus 4.6) with a Firecracker-microVM sandbox tier that *executes* suspect code and observes what it does. Static-analysis findings get promoted to **CONFIRMED** only when the sandbox captures concrete runtime evidence — a network call, a file write, a process spawn. Findings that cannot be triggered are marked **UNREACHED**; findings the file's own defenses block are **BLOCKED**.

Open source, Apache 2.0, BYOK. Argus collects nothing — you pay Anthropic and Google directly on your own keys.

## What you get per finding

| Status | Meaning |
|---|---|
| `CONFIRMED` | Sandbox observed the exploit firing. PoC + event trace are surfaced with the finding. |
| `BLOCKED` | Attack tested; the file's own code defended (sanitization, escaping, allowlist). |
| `UNREACHED` | Attack tested; the code path is genuinely unreachable. |
| `NOT_TESTED` | Sandbox couldn't fully validate (sub-reason: `infra_stub` / `inconclusive` / `not_planned`). |

## How the cascade works

```
File
  ↓
[$0]  Preprocessing       hash, deobfuscation, deps, attack-vector flags
  ↓
[Gemini Flash-Lite]  Triage  CLEAN | LOW | HIGH (~$0.0001/file)
  ↓
  ├─ CLEAN → return
  ├─ LOW   → Gemini Flash combined  (~$0.02/file)
  └─ HIGH  → Sonnet 4.6 combined    (~$0.07/file, default)
              └─ borderline / high-stakes → Opus 4.6 deep  (~$0.15/file, ~20%)
  ↓
[N=3 Sonnet ensemble]  borderline-uncertainty path
  ↓
[DAST sandbox]         Sonnet orchestrator + Firecracker microVM
                        (minimal / networked / ml_tools images)
                        → Opus iter-3 escalation if stuck after 2 iterations
  ↓
[Engine guard]         DAST never lowers L1's verdict without sandbox-grounded
                        refutation (DAST-105)
```

The cascade is built around the observation that most files are clean: spend $0.0001 to dispatch a clean file in under a second, $0.07 to deep-analyze a suspicious one, and only invoke the sandbox tier on the small subset where runtime confirmation actually matters.

## Install in a minute

```bash
git clone git@github.com:dshochat/Argus_Scanner.git && cd Argus_Scanner
uv sync --extra dev
cp .env.example .env       # add ANTHROPIC_API_KEY + GEMINI_API_KEY
uv run argus scan path/to/your/file.py
```

Full instructions: [Install & first scan](install.md). DAST sandbox setup: [DAST setup](dast-setup.md).

## License

Apache 2.0. See [LICENSE](https://github.com/dshochat/Argus_Scanner/blob/main/LICENSE).

Copyright © 2026 Dudy Shochat and contributors.
