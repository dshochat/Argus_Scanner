# Contributing to Argus

Thanks for considering a contribution. Argus is an AI-native code security scanner; the things we care most about are detection quality, cost discipline, and DAST verification fidelity. PRs are welcome.

## Quick start

```bash
git clone git@github.com:dshochat/Argus_Scanner.git
cd Argus_Scanner
uv sync --extra dev
cp .env.example .env       # add ANTHROPIC_API_KEY + GEMINI_API_KEY
uv run pytest tests/unit -v
uv run argus scan path/to/file.py
```

You'll need:

- Python 3.12+
- An Anthropic API key (Sonnet 4.6 / Opus 4.6 cascade tiers)
- A Google AI Studio key (Gemini Flash-Lite triage)
- Optionally, a Fly.io token for the DAST sandbox tier — not required for most contributions

## Where to start

- **Good first issues** are tagged in [GitHub Issues](https://github.com/dshochat/Argus_Scanner/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). They're scoped, clearly described, and reviewable in a sitting.
- **The architecture overview is [`docs/architecture.md`](docs/architecture.md).** Read this before touching `scanner/engine.py` or `dast/orchestrator.py` — both are integration glue with non-obvious invariants.

## Style

- **Python 3.12+, mypy `--strict`, ruff for lint + format.** No flake8 or black; please don't introduce them.
- **Pydantic v2** for every cross-boundary structure.
- **`structlog`** for logging; never `print()` outside the CLI.
- **Type everything.** `Any` is allowed at runner-injection seams (engine.py uses `Any` for `*_runner` parameters by design — duck typing is the testability story); elsewhere prefer concrete types.

```bash
uv run ruff check . && uv run ruff format .
uv run mypy --strict .
```

CI runs both on every PR.

## Tests

Two tiers, kept strictly separate:

- **`tests/unit/`** — no live API. Stubs all model calls. Must pass on every PR. Several hundred tests; fast (<3s for the full suite).
- **`tests/integration/`** — live API calls. Marked with `@pytest.mark.integration`. Skips if API keys aren't set. Costs API credits on every run. **CI does not run these** — run them locally before submitting cascade or runner changes.

```bash
uv run pytest tests/unit -v                  # always
uv run pytest tests/integration -v -s        # before runner / engine changes
```

Don't add live API calls to `tests/unit/`. The rule has no exceptions: it's the difference between "dev iteration is fast" and "every contributor needs to fund their own scan budget."

## What we welcome

- **New deterministic detectors** in `preprocessing/` — fast, free, well-tested. Mirror existing detectors (`crypto_sensitivity.py`, `imperative_install.py`) for shape.
- **Prompt tuning** that improves verdict-distance on the regression suite (`samples/regression_v1/`). Show the before/after numbers in the PR.
- **DAST coverage extensions** — new sandbox image variants, new payload templates for Discovery mode, new oracle types.
- **Cost guardrails** — anything that makes per-scan cost more predictable or transparent.
- **Bug reports + reproductions** — issues with a reduced test case land fastest.

## What's out of scope right now

- Adding new model providers beyond Anthropic + Google — defer until v2 benchmark mode resurrects.
- Architectural pivots without prior discussion in an issue.
- Frontend work — `frontend/` is dormant for the deferred hosted tier.

## Architecture invariants (non-negotiable)

If your change touches one of these, expect a longer review:

1. **Preprocessing is deterministic and free.** Never call models in `preprocessing/`. If you're tempted, the change probably belongs in `analysis/`.
2. **The cascade short-circuits cheap files cheap.** Clean files cost $0.0001 (triage only); don't add expensive defaults.
3. **All runners are injectable.** `scan_file(triage_runner=, sonnet_runner=, opus_runner=, dast_runner=)`. Never hard-code provider calls in the engine.
4. **DAST never silently lowers an L1 verdict.** A `malicious` → `suspicious` downgrade only fires when *every* L1 finding is sandbox-grounded as `BLOCKED` or `UNREACHED`. Without that, L1's verdict stands.
5. **Methodology before lift claims.** Don't publish a verdict-exact number from a single regression run. N=2 minimum for cross-config comparisons.

## Pull request process

1. **Open an issue first** if the change is non-trivial. Saves rework on both sides.
2. **Branch from `main`.** Keep PRs focused — one task ID per PR is the norm.
3. **Tests pass.** `uv run pytest tests/unit -v && uv run ruff check . && uv run mypy --strict .`
4. **Live integration smoke** for runner / engine changes — paste the resulting verdict + cost in the PR description.
5. **Squash-merge by default.** Multi-commit PRs are fine if the commits tell a coherent story.

## Security disclosures

Please do not file public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the private disclosure path.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
