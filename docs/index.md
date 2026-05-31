# Argus

**AI-native code security scanner.** Open source (Apache 2.0). Multi-stage
cascade analysis (Gemini Flash-Lite triage → Sonnet 4.6 → Opus 4.6) plus
runtime DAST verification in Firecracker microVMs. Bring your own API keys.

!!! note "v1.7+ status"
    Production. Beat-Opus benchmark target (≥15pp verdict-exact lift over
    single-call Opus 4.6 on the 23-file regression suite) met in v1.1 and
    re-validated on v1.5 / v1.6 / v1.7 cycles. Public release at
    [`dshochat/Argus_Scanner`](https://github.com/dshochat/Argus_Scanner)
    (snapshot of this private dev repo at release boundaries).

## Why Argus

Most open-source scanners (Semgrep, deepsec, GitHub Advanced Security)
pattern-match. Few reason about *runtime behavior* or chain findings into
*exploits*. Mythos charges $50-200/scan for what amounts to
expert-replacement assessment.

**Argus targets Mythos-class verdict quality at ~$5-15 in API spend per
100 files**, with sandbox-confirmed exploitability as the differentiator.
You bring API keys; Argus collects nothing.

## How it works (one diagram)

```
File
  ↓
[$0]  Preprocessing      hash, deobfuscation (incl. webcrack), deps,
                          attack-vector flags, file-type expansion
                          (Jupyter, ML models, GitHub Actions)
  ↓
[Gemini Flash-Lite]  Triage   CLEAN | LOW | HIGH   (~$0.0001/file)
  ↓
  ├─ CLEAN → return
  ├─ LOW   → Gemini Flash combined            (~$0.02/file)
  └─ HIGH  → Sonnet 4.6 combined              (~$0.05-0.30/file, default)
              └─ borderline OR high-stakes → Opus 4.6 deep
  ↓
[N=3 Sonnet ensemble]    on borderline files (uncertainty > 0.4)
  ↓
[DAST Phase A]           per-finding validation (multi-image: lean |
                          rich_python | ml_tools)
  ↓
[DAST Phase B+]          runtime exploit probing (default ON, v1.8)
[Phase 3 Stage 1 + 2]    behavioral probe + adversarial reasoning loop
                          + Strategy B (rejection_signature)
                          + Strategy C (post-trace LLM judge)
                          (default ON, v1.8)
[Phase C]                fix-and-verify (opt-in via --enable-remediation, v1.8)
  ↓
[Report-layer policy]    downgrade_cap (default) | strict (v1.8)
```

Most files terminate before DAST. DAST runs only on
`malicious` / `critical_malicious` verdicts by default. Phase B+, Phase 3,
and Phase C are opt-in.

## Install in one minute

```bash
git clone git@github.com:dshochat/Argus.git && cd Argus
uv sync --extra dev
cp .env.example .env  # add ANTHROPIC_API_KEY + GEMINI_API_KEY
uv run argus scan path/to/your/file.py
```

Full instructions: [Install & first scan](install.md).

## CLI commands

| Command | Purpose |
|---|---|
| `argus scan FILE` | Single file scan |
| `argus scan-repo PATH` | Whole repo (markdown / JSON / SARIF v2.1.0) |
| `argus install PACKAGE` | Pre-install gate for PyPI packages |
| `argus bench` | Beat-Opus benchmark (release validation) |

## Documentation

- [Install & first scan](install.md)
- [Architecture](architecture.md)
- [DAST setup](dast-setup.md)
- [API keys](api-keys.md)
- [Cost guide](cost-guide.md)
- [Contributing](contributing.md)

## License

Apache 2.0. See [LICENSE](https://github.com/dshochat/Argus/blob/main/LICENSE).

Copyright © 2026 Dudy Shochat and contributors.
