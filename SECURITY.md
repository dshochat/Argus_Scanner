# Security policy

## Reporting a vulnerability

If you've found a security issue in Argus, **please don't open a public GitHub issue.** Report it privately so we can investigate and ship a fix before disclosure.

**How to report:**

- GitHub Security Advisories (preferred): [github.com/dshochat/Argus_Scanner/security/advisories/new](https://github.com/dshochat/Argus_Scanner/security/advisories/new)
- Email: davidsho1131@gmail.com — please use "Argus security" in the subject

Include:
- A description of the issue and its impact
- Steps to reproduce (a minimal POC if possible)
- The Argus version / commit hash you tested against
- Your name / handle for credit, or a request for anonymity

## Disclosure timeline

We aim to:

- Acknowledge your report within **3 business days**
- Provide a meaningful update within **14 days**
- Ship a fix and coordinate disclosure within **90 days** of the initial report (sooner for critical issues)

Coordinated disclosure is the norm. We'll credit you in release notes unless you request otherwise.

---

## Security model of Argus itself

Argus is a tool that intentionally executes untrusted source code. Understanding its trust boundaries matters before deploying it.

### What runs where

| Tier | Where it runs | Trust assumption |
|---|---|---|
| Preprocessing | Locally on your machine | Pure-deterministic Python over file bytes. No execution. |
| L1 cascade (triage / Sonnet / Opus) | Your machine + Anthropic + Google APIs | Sends file bytes to the model providers under your API keys. No code execution. |
| DAST sandbox | Ephemeral Firecracker microVM in your Fly.io account | **The file's code runs here.** This is the security boundary. |
| Argus orchestrator (the agentic DAST loop) | Your machine | Sends sandbox traces and L1 findings to Anthropic; never runs the file's code itself. |

The DAST sandbox is the security boundary. The orchestrator never `exec`s file content; the only place file code actually runs is inside the microVM.

### Sandbox guarantees

When DAST is enabled:

- Each plan creates one ephemeral Firecracker microVM (1 vCPU / 512 MB / no public IP) and destroys it after execution.
- Network egress is captured via DNS hijack to a local capture server in the VM. Outbound connections are observed but not actually delivered to the listed peer.
- File materialization, command execution, event capture, and teardown are wrapped in a per-machine timeout enforced by Fly's API. A misbehaving plan cannot run indefinitely.
- The host running Argus never executes the scanned file's code.

### What's NOT in scope

These are out of Argus's threat model — important to be clear about so you can layer additional controls if you need them.

- **Files you scan.** Argus reads untrusted source code; that's its job. Findings about malicious behavior in scanned files are scanner *output*, not scanner vulnerabilities.
- **Third-party dependencies.** Report those upstream (Anthropic SDK, google-genai, etc.). We'll consider requests to bump pinned versions if a transitive vulnerability is exploitable through Argus's own code paths.
- **DAST sandbox guest images.** Those are intentionally permissive — the sandbox is the security boundary, not the guest.
- **Self-hosted infrastructure choices.** If you deploy Argus in a way that exposes API keys or file contents (e.g., logging the plain text of `.env`, running on a shared host), that's a deployment concern, not an Argus vulnerability.
- **API key handling outside Argus's process.** Your Anthropic / Google / Fly keys live in your environment; how you provision and rotate them is up to you. Argus reads them via `python-dotenv` and never writes them to disk or stdout.

### Issues we consider security-relevant

- Prompt injection that causes the scanner to silently skip findings or alter its verdict
- DAST sandbox escape (guest → host)
- API key leakage in logs, output, or error messages
- Path traversal during file ingestion
- Crashes or denial of service on adversarial inputs that a scanner is expected to handle

### Issues that are not vulnerabilities

These are still welcome as regular issues, just not under the security-disclosure path:

- False positives or false negatives on benign code
- Cost overruns or unexpected API charges (see [cost guide](docs/cost-guide.md) for the controls available)
- Performance issues on large files

## Bug bounty

There's no formal bounty program right now. Public credit + a sincere thank-you is what we have to offer. If you're a researcher who needs something more formal in advance, get in touch before reporting.
