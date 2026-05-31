# Contributing

The full contribution guide lives at [CONTRIBUTING.md](https://github.com/dshochat/Argus/blob/main/CONTRIBUTING.md) in the repo root. Short version below.

## Quick start

```bash
git clone git@github.com:dshochat/Argus.git
cd Argus
uv sync --extra dev
cp .env.example .env   # add ANTHROPIC_API_KEY + GEMINI_API_KEY
uv run pytest tests/unit -v
```

## Style

- **Python 3.12+, mypy `--strict`, ruff for lint + format.** No flake8 / black.
- **Pydantic v2** for cross-boundary structures.
- **`structlog`** for logging; never `print()` outside the CLI.
- **Type everything.** `Any` is allowed at runner-injection seams.

```bash
uv run ruff check . && uv run ruff format .
uv run mypy --strict .
```

CI runs both on every PR (see [`.github/workflows/ci.yml`](https://github.com/dshochat/Argus/blob/main/.github/workflows/ci.yml)).

## Tests

- **`tests/unit/`** — no live API. Stubs all model calls. Must pass on every PR. ~94 tests; growing.
- **`tests/integration/`** — live API calls. Marked with `@pytest.mark.integration`. Skips if API keys aren't set. CI does **not** run these. Run them locally before submitting cascade or runner changes.

## What we welcome

- New deterministic detectors in `preprocessing/`
- Better prompt tuning (with verdict-distance improvement on the regression suite)
- DAST sandbox image extensions (per-language / per-framework)
- Cost guardrails / cost transparency
- Bug reports with reduced reproductions

## What's out of scope right now

- New model providers beyond Anthropic + Google (defer to v2)
- Architectural pivots without prior issue discussion
- Frontend work (the `frontend/` directory is dormant)

## Architecture invariants

If your change touches one of these, expect a longer review:

1. Preprocessing is deterministic and free.
2. Cascade short-circuits cheap files cheap.
3. Single-provider per agentic DAST loop.
4. All runners injectable.
5. Methodology before lift claims.

See [Architecture](architecture.md) for the full list.

## Security disclosures

Don't file public issues for security vulnerabilities. See [SECURITY.md](https://github.com/dshochat/Argus/blob/main/SECURITY.md).

## License

By contributing you agree that your contributions will be licensed under [Apache 2.0](https://github.com/dshochat/Argus/blob/main/LICENSE).
