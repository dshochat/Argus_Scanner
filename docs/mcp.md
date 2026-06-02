# MCP scanning mode

Argus v1.12 adds dynamic security testing for Model Context Protocol servers. Speaks MCP over stdio (sandboxed) and Streamable-HTTP / SSE (remote, opt-in). Reuses the existing DAST sandbox + SSRF payload catalog + CWE→probe registry + findings schema — it's a self-contained plug-in to the engine, not a re-implementation.

## Two subcommands

```bash
argus mcp enumerate   # recon only — list tools/resources/prompts + classify params
argus mcp scan        # active scan — run the probe catalog
```

`enumerate` is always safe to run. `scan` against a remote URL requires `--authorized`.

## Quick start

### Against a local MCP server (stdio)

```bash
# Enumerate (no attacks) — runs the server directly on your host, recon only:
argus mcp enumerate --stdio "python3 -m my_mcp_server" --report md

# Active scan — runs the (untrusted) server INSIDE the Firecracker sandbox.
# Declare the server's install package so the sandbox can launch it:
argus mcp scan --stdio "python3 -m my_mcp_server" \
               --sandbox-pip my-mcp-server-package \
               --report md
```

`enumerate` runs the server directly on your host (recon only — no attack payloads). `scan` runs the server **inside the Firecracker sandbox** so SSRF/redirect probes hit the in-sandbox capture-server instead of real infrastructure. That requires the DAST Fly config (`FLY_API_TOKEN` + `ECHO_DAST_IMAGE_LEAN` — see [dast-setup.md](dast-setup.md)); the server's launch dependencies are installed in the VM via `--sandbox-pip` (Python, first package installs with deps) / `--sandbox-npm` (Node).

If `FLY_API_TOKEN` is **not** set, `scan` warns and falls back to running the server as a direct host subprocess (probe traffic then originates from your machine). Pass `--unsafe-direct-stdio` to opt into that explicitly for servers you fully trust. The fixture vulnerable server (`tests/fixtures/mcp/vulnerable_server.py`) is a handy way to see what a finding-rich scan looks like.

### Against a remote MCP server (HTTP)

```bash
# Enumerate (still safe):
argus mcp enumerate --url https://mcp.example.com/mcp \
                    --auth token --auth-token "$MCP_TOKEN"

# Active scan — REQUIRES --authorized:
argus mcp scan --url https://mcp.example.com/mcp \
               --auth token --auth-token "$MCP_TOKEN" \
               --authorized \
               --scope-deny 10.0.0.0/8 --scope-deny 192.168.0.0/16 \
               --report md
```

## Probe catalog (v1.12)

| Probe | CWE | What it tests |
|---|---|---|
| **SSRF** | CWE-918 | URL/HOST params get 8 canary payloads: AWS IMDSv1 + IMDSv2 token endpoint, GCP / Azure metadata, alt IP encodings (decimal + hex), loopback variants. |
| **Redirect-to-internal** | CWE-601 → CWE-918 | External-looking URLs that 30x-redirect to AWS IMDS / loopback. Catches missing post-redirect re-validation. |
| **Fail-open** | CWE-755 | Adversarial URL inputs (NUL bytes, oversize, CRLF, garbage, wrong types) probe whether validation silently bypasses on exception. |
| **Authorization bypass** | CWE-862 | Paired authed-vs-unauthed calls per tool; Jaccard-overlap diff confirms when the unauthed response carries the same data. |

Each finding carries `confirmed: true/false` — confirmed requires evidence (sandbox network capture OR OOB callback). Heuristic findings ship at lower CVSS for triage.

## Reports

`--report json` (default) emits the stable schema:

```json
{
  "schema": "argus.mcp.scan-report",
  "schema_version": 1,
  "argus_version": "1.12.0",
  "scanned_at_utc": "2026-06-01T...",
  "target": "...",
  "transport": "stdio",
  "surface": { ... },
  "findings": [ ... ],
  "session_metadata": { ... }
}
```

`--report md` emits a human-readable summary with severity icons, per-finding sections, and a session telemetry block.

## Out-of-band (OOB) callbacks

Blind-SSRF confirmation needs the target to actually fetch a URL we control:

- **Local stdio scan (sandboxed)** — uses the in-sandbox capture-server (DNS-hijacked, records HTTP/HTTPS/TCP egress to hostnames). Requires the DAST Fly config (`FLY_API_TOKEN` + `ECHO_DAST_IMAGE_LEAN`); no per-scan external setup beyond that. Direct-IP egress to link-local ranges (e.g. a literal `169.254.169.254`) has no route inside the VM, so those land as heuristic findings (the server's "connection failed" response is still evidence it attempted the fetch).

- **Remote HTTP scan** — two options:
  - `--oob https://abc.interact.sh` — operator brings their own interactsh / dnslog / webhook.site endpoint.
  - No flag → Argus spawns a local listener on an ephemeral port. Tunnel via ngrok / cloudflared if you need a public URL.

## Safety contract

- Remote URL scans **refuse to attack** without `--authorized`. Stdio scans skip the gate because the (untrusted) server runs inside the Firecracker sandbox with isolated egress — provided `FLY_API_TOKEN` is configured. Without it, Argus warns and falls back to a direct host subprocess (or pass `--unsafe-direct-stdio` to opt in explicitly).
- `--scope-deny <cidr>` (repeatable) drops any probe whose canary URL targets a denied IP range. Defense in depth on top of the sandbox / OOB isolation.
- Argus-managed OOB listener binds to `0.0.0.0` (must be reachable from target); stderr-prints a warning at startup.

## Exit codes

- `0` — no findings (or only heuristic findings).
- `1` — at least one **confirmed** finding (active exploitation proven). CI gates can branch on this.
- `2` — usage / consent-gate error (missing flag, refused remote scan without `--authorized`).

## Common flags

| Flag | Default | Notes |
|---|---|---|
| `--stdio "<cmd>"` / `--url <url>` | (required, exclusive) | Target selection. |
| `--transport` | streamable-http | For `--url`. Auto-inferred. |
| `--auth none\|token` | `none` | Token sent as `Authorization: Bearer`. |
| `--auth-token` | — | Read from env, not shell history. |
| `--authorized` | off | **Required** for remote scans. |
| `--oob <url>` | — | User-supplied OOB endpoint. |
| `--scope-deny <cidr>` | — | Repeatable. Filter outbound probe URLs. |
| `--tools <list>` | all | Comma-separated tool name filter. |
| `--report json\|md` | json | Output format. |
| `--output-file <path>` | stdout | Where to write the report. |

## Out of scope for v1.12

These are clean extension points — not yet implemented:

- Prompt injection / LLM testing
- Static MCP code analysis
- Continuous monitoring / scheduled scans
- Advisory auto-generation

## Architecture

```
CLI (scanner/cli.py)            ─┐
   mcp subparser                 │
   dispatches → mcp_scanner.cli  │
                                  │
mcp_scanner/                       │
├── transport/                     │
│   ├── stdio.py        ──┐         │
│   └── http.py        ──┤          │
├── client.py             │← MCPClient.enumerate
├── classifier.py         │   → MCPSurfaceMap
├── surface.py            │
├── sandbox_launcher.py   │← LocalMCPSession.drive(probes)
├── sandbox_probe_harness.py  (runs INSIDE sandbox for stdio scan)
├── probes/                │← PROBE_REGISTRY.build_requests + evaluate
│   ├── ssrf.py            │
│   ├── redirect.py        │
│   ├── fail_open.py       │
│   └── auth_bypass.py     │
├── oob_listener.py        │← OOB callbacks for blind SSRF on remote scans
├── findings.py            │← MCPFinding (Pydantic)
└── report.py              │← render_json / render_markdown
                            ▼
                       stdout / --output-file
```

The change to `scanner/cli.py` is one subparser block (~120 lines including help text) + one dispatch branch. The rest is the self-contained `mcp_scanner/` package.

## Reusing existing Argus infrastructure

- **SSRF payloads**: lifted from `dast/behavioral_probe.py`'s curated keyword map.
- **CWE → attack class**: `dast/cwe_probe_registry.py` mapping.
- **Sandbox**: `dast/sandbox/client.py::SandboxClient` Protocol + `MultiImageSandboxClient` (lean / rich_python / ml_tools tiers).
- **In-sandbox OOB / canary**: `dast/sandbox/firecracker/dast-capture-server.py` (DNS hijack + egress capture → `network_call_captured` events).
- **Findings schema**: `MCPFinding` wraps the existing `shared/types/analysis.py::Finding` shape with MCP-specific provenance fields.
