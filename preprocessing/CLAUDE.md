# preprocessing/ — CLAUDE.md

**Architecture sections:** §4 (File Prioritization), §5 (Pass 1 — CVE Context
Fetch), v3.1 changelog Gap 1.1 (dependency blind spots).

## What this directory does

Everything deterministic that happens **before any model runs**. NO LLMs.
Hand-written, testable, fast. Its outputs feed both the orchestrator (for
CVE lookups) and L1 (as context), and can force priority-score overrides.

Produces the `preprocessing{}` block of the label schema:

```
preprocessing = {
  dependencies: [{name, version_spec, ecosystem, source_file}],
  deobfuscation_applied: bool,
  deobfuscation_layers: int,
  file_hash: sha256,
  known_malware_match: str | null,
  detected_language: str,
  token_count: int,
  imperative_install_detected: bool,   # v3.1
}
```

## Subdirectories

- `parsers/` — per-ecosystem dependency parsers: `pypi/`, `npm/`, `go/`,
  `maven/`, `rubygems/`, `crates/`, `nuget/`. Each parser consumes a specific
  manifest filename and emits `list[Dependency]`. Plain Python — no models,
  no network.

## What preprocessing must do

1. **SHA-256 the raw file** (`shared.utils.sha256_file`).
1. **Language detection** by extension + content heuristics. Cheap signal —
   S1 re-confirms and may override.
1. **Token count** via `shared.utils.approx_token_count` (tiktoken w/
   `cl100k_base`).
1. **Deobfuscation**: unwrap base64 / hex / zlib / marshal / exec chains /
   rot13 / custom encodings iteratively. Record every layer. Decoded content
   is what the models see downstream.
1. **Malware hash lookup**: check `file_hash` against known-bad hashes (from
   external scraper's malware table). If matched, short-circuit with a critical
   verdict.
1. **Dependency parsing** (the v3.1 blind-spot fix):
   - `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` → `pypi`
   - `package.json`, `package-lock.json`, `yarn.lock` → `npm`
   - `go.mod`, `go.sum` → `go`
   - `pom.xml`, `build.gradle` → `maven`
   - `Gemfile`, `Gemfile.lock` → `rubygems`
   - `Cargo.toml`, `Cargo.lock` → `crates`
   - `*.csproj`, `packages.config` → `nuget`
1. **`setup.py` AST walker**: extract `install_requires`, `dependency_links`,
   and flag any `subprocess`/`os.system`/`urllib` calls → set
   `imperative_install_detected = True`.
1. **`.pth` detector**: if any line starts with `import`, immediate
   priority-5 signal.
1. **Postinstall / build hook detection**: `postinstall` scripts in
   `package.json`, `install` / `build` targets in build files.

## The v3.1 guarantee

When `preprocessing.imperative_install_detected == True`, the orchestrator
**forces** `triage.priority_score >= 4` regardless of what S1 output. This
is enforced in the pipeline orchestrator (`api/`), not in S1 training —
S1 is free to guess; preprocessing is the safety net.

Rationale: setup.py / postinstall / .pth are classic supply-chain payload
vectors. A malicious package hides its payload behind a dynamic install
script and S1's 2048-token triage can miss it. Deterministic detection
catches the pattern with zero false negatives.

## Integration points

- **Inputs:** raw file bytes, repo root path for manifest discovery.
- **Outputs:** `Preprocessing` Pydantic model (`shared.types.Preprocessing`).
- **Downstream consumers:**
  - `sast/triage/` (S1 reads `preprocessing.detected_language`, deobfuscated content).
  - `sast/analysis/l1` (receives full block as context).
  - `sast/analysis/nday` (reads `dependencies[]` for CVE lookups).
  - `cache/` (uses `file_hash` + parser versions for the composite key).
- **Postgres:** writes nothing directly. The orchestrator joins
  `preprocessing.dependencies` against `cves` for N-day lookups.

## Cache interactions

- **Writes to:** Tier 0 pipeline_fingerprint (via versions reported for
  `deobfuscation_engine`, `language_detector`, `hash_engine`, `pth_detector`,
  `setup_script_analyzer`, per-ecosystem `dependency_parsers`).
- **Invalidation scope:** when a parser updates, only entries for files in
  that ecosystem miss (see `cache_policy.yaml` →
  `file_cache.invalidation.on_parser_update: ecosystem_scoped`).
- **Tier 1 writes** are downstream: the orchestrator populates dependency
  profiles using our parsed `dependencies[]` as the key.

## Testing notes

- Golden fixtures for every parser (real `requirements.txt`, real
  `package.json`, real `go.mod`).
- Adversarial `setup.py` with obfuscated `os.system('curl … | sh')` — must
  set `imperative_install_detected=True`.
- `.pth` fixture — must immediately surface as priority-5 candidate.
- Deobfuscation fuzz tests: 5-layer base64-wrapped marshal blob, unicode
  escape chains, exec chain obfuscation.
- Parsers must be **idempotent** and **deterministic** — same input →
  byte-identical output.

## Task workflow

This component uses the repo-wide parallel-session task protocol.
See root `CLAUDE.md` §11 "Parallel session task workflow" for the full
rules. Day-to-day: read `preprocessing/TASKS.md` for backlog, claim items by
moving them to `## In Progress`, commit `TASKS.md` alongside code
changes, and run `uv run python scripts/board.py` at root to refresh
`BOARD.md`.
