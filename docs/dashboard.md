# Web dashboard

A self-hosted web UI that visualizes the **scan → validate → remediate** flow
for every file Argus scans. Three audiences, one view:

- **Developers** — the vulnerable code and the generated fix.
- **Security engineers** — the sandbox exploit evidence and adversarial variants.
- **Management** — how many findings are *real* (DAST-confirmed) and how many
  were *auto-fixed and verified*.

Stack: **React + Vite** (TypeScript, Tailwind) front end, **FastAPI +
SQLAlchemy 2.0 (async)** back end, **Postgres** store. The compiled UI ships
pre-built inside the wheel, so running the dashboard needs no Node toolchain.

## Install

The dashboard is an optional extra so the base scanner stays dependency-light:

```bash
pip install "argus-ai-scanner[dashboard]"
```

This adds `fastapi`, `uvicorn`, `sqlalchemy`, and `asyncpg`.

## Quick start

```bash
# 1. Postgres (or point ARGUS_DB_URL at any Postgres you already run)
docker compose -f dashboard/docker-compose.yml up -d
export ARGUS_DB_URL=postgresql://argus:argus@localhost:5432/argus

# 2. Create tables (idempotent)
argus dashboard init-db

# 3. Get data in (pick either / both)
argus scan path/to/file.py          # auto-persists when ARGUS_DB_URL is set
argus dashboard ingest ./results/   # back-fill existing JSON outputs

# 4. Serve
argus dashboard serve               # http://127.0.0.1:8000
```

## How data gets in

- **Auto-persist** — whenever `ARGUS_DB_URL` is set, `argus scan` and
  `argus scan-repo` write each result to Postgres after the scan completes. This
  is best-effort: a DB outage or a missing extra prints a one-line hint and
  **never changes the scan's outcome or exit code**. A `scan-repo` run stamps all
  its files with one `run_id` so they group under **Runs**.
- **Ingest** — `argus dashboard ingest <path>` loads existing
  `argus scan --output json` results. `<path>` may be a single `.json` file, a
  directory of `*.json`, or a file containing a JSON array of results.

## Commands

| Command | Purpose |
|---|---|
| `argus dashboard init-db [--db-url URL]` | Create the `scans` table + indexes. |
| `argus dashboard ingest <path> [--db-url URL]` | Import existing result JSON. |
| `argus dashboard serve [--host H] [--port P] [--db-url URL]` | Run the web server. |

`--db-url` falls back to `$ARGUS_DB_URL` (loaded from `.env` like the rest of
the CLI). Default bind is `127.0.0.1:8000`.

## What you see

- **Overview** — KPI cards (scans, files at risk, confirmed-exploitable,
  auto-remediated HIGH, API spend) and charts (verdict mix, remediation
  confidence, scans over time, findings by severity, top vulnerability types).
- **Scans** — a filterable, sortable table (verdict, risk, language, filename).
- **Scan detail** — a management-readable summary band plus the three-stage
  flow: **Scan** (SAST findings with code, CWE, PoC) → **Validation** (DAST
  disposition per finding: CONFIRMED / BLOCKED / REJECTED / UNREACHED /
  NOT_TESTED, with runtime evidence) → **Remediation** (fix summary, the
  verification gates — functional preservation + blocked adversarial variants —
  and a HIGH / MEDIUM / LOW / FAILED confidence), plus a cost/telemetry panel.
- **Runs** — repository scans grouped by run.

The UI auto-refreshes, so new results appear without a manual reload.

## Data model

One table, `scans`: summary columns (filename, verdict, risk, finding counts,
remediation confidence, cost, timestamp) for fast list/filter/sort, plus a JSONB
`raw` column holding the full `ScanResult.to_dict()` for the detail view. A GIN
index on `raw` powers the severity / vulnerability-type aggregates. Schema
creation is idempotent (`create_all`); there are no destructive migrations.

## Security

There is **no authentication** in v1 — the server binds to `127.0.0.1` and is
meant for self-hosted, single-operator use. If you expose it on a network, put
it behind your own authenticating reverse proxy. The dashboard is read-only over
the database; it never runs scans or mutates results.

## Rebuilding the UI (contributors only)

End users never need this — the wheel ships the compiled SPA. To hack on the
front end:

```bash
cd dashboard/frontend
npm install
npm run dev      # Vite dev server on :5173, proxies /api → :8000
npm run build    # compiles into dashboard/server/static/ (committed)
```

`npm run build` output (`dashboard/server/static/`) is committed and
force-included in the wheel; rebuild and commit it when you change the UI.
