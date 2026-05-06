# API keys

Argus calls real Anthropic + Google APIs. You need keys for both.

## Required keys

### Anthropic

Used for Sonnet 4.6 + Opus 4.6 cascade analysis + DAST inference.

1. Go to [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys).
2. Create a new API key.
3. Save to `.env`:

```env
ANTHROPIC_API_KEY=sk-ant-api03-...
```

**Cost note**: Anthropic prepaid balance only. Sonnet 4.6 = $3/M input + $15/M output; Opus 4.6 = $15/M input + $75/M output. A single Sonnet scan typically uses ~5K-10K output tokens. See [Cost guide](cost-guide.md) for per-file projections.

### Google AI Studio

Used for Gemini Flash-Lite triage (the cheapest cascade tier).

1. Go to [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey).
2. Create a new API key (link to a Google Cloud project if prompted; standard tier is fine).
3. Save to `.env`:

```env
GEMINI_API_KEY=AIzaSy...
```

**Cost note**: Gemini 3.1 Flash-Lite preview is essentially free at scanning volumes (~$0.0001 per file).

## Optional keys

### Fly.io (for DAST)

Only needed if you want DAST sandbox verification.

→ See [DAST setup](dast-setup.md) for the full procedure.

## Where Argus reads keys from

Argus uses `python-dotenv` with `override=True` — values in `.env` always win over OS environment variables. This is intentional: a stale empty `ANTHROPIC_API_KEY` in your shell won't silently shadow the .env file.

If you'd rather use OS env vars exclusively, simply don't create `.env`; Argus falls back to `os.environ` for each lookup.

## Security

`.env` is in `.gitignore`. Never commit API keys.

If you accidentally commit a key, **rotate it immediately**:
- Anthropic: revoke at [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys)
- Google: revoke at [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
- Fly: `flyctl tokens revoke <token-name>`

`git rm --cached .env && git commit` doesn't help — the key is in repo history. Rotation is the only fix.

For production deployments, use a secrets manager (AWS Secrets Manager / HashiCorp Vault / GCP Secret Manager / etc.) and inject env vars at runtime instead of using `.env`.

## Rate limits

Anthropic + Google both rate-limit by tokens-per-minute. For benchmark runs (`argus bench`), rate limits can throttle the run. The CLI runs files sequentially specifically to avoid hitting the per-key concurrency cap.
