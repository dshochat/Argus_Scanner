"""Phase C verified-remediation gates (Stage 2 + Stage 3 — live wiring).

The original-PoC replay in :func:`dast.orchestrator._run_phase_c_fix_verify`
answers *"does the reported exploit still fire against the patch?"* — a
necessary but weak signal. A patch can pass that and still be a bad fix:

  * **shallow** — it blocks the one reported payload but not the
    vulnerability *class* (a sibling encoding of the same attack walks
    right through);
  * **over-restrictive** — it "fixes" the bug by breaking legitimate
    traffic (the worst false NEUTRALIZED: the exploit is gone because the
    function now rejects everything).

This module supplies the two live gates that turn a replayed patch into a
*verified* one, plus the plumbing the orchestrator needs to run them:

  * **Stage 2 — functional preservation.** Generate a benign request that
    SHOULD succeed, run the PATCHED code against it, confirm it still
    works. Because the DAST sandbox DNS-hijacks every hostname to
    127.0.0.1 (so a real benign fetch would be blocked by any correct
    SSRF patch), the functional probe MOCKS name resolution to a public
    address + mocks the network egress — it tests "does the patch still
    admit a legitimate public host?" without real traffic.

  * **Stage 3 — adversarial variants.** Generate novel payloads of the
    SAME class (alternate IP encodings, cloud-metadata endpoints, IPv6,
    userinfo confusion, …) and replay each against the PATCHED code. The
    hijacked sandbox is the ideal oracle here: a variant "fired" iff its
    request actually reached the capture server, i.e. the patch let it
    through. Any fire ⇒ the patch is shallow.

The confidence math + budget policy live in
:mod:`dast.remediation_verify`; this module is the *live closures* that
feed it. Generation (LLM) is split from replay (sandbox) so the caller
can do all inference OUTSIDE the per-sandbox content-lock window and only
hold the lock for the fast replay step.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from dast.inference import InferenceFn
from dast.remediation_verify import VerifyBudget, VerifyOutcome, verify_patch
from dast.sandbox.client import SandboxPlan

log = logging.getLogger("argus.dast.phase_c_verify_gates")

# Oracle markers the generated harnesses must print. Kept Argus-namespaced
# so a substring match can't collide with arbitrary app output.
REACH_ORACLE = "ARGUS_VARIANT_REACHED"
BLOCK_MARKER = "ARGUS_VARIANT_BLOCKED"
FUNC_OK = "ARGUS_FUNC_OK"
FUNC_BROKEN = "ARGUS_FUNC_BROKEN"
# Printed when the harness's OWN setup (mocks / import) failed — i.e. the
# test couldn't even reach the entrypoint. This is NOT evidence the patch
# over-blocks; it maps to functional_ok=None (unknown), never to False,
# so a flaky mock can't fabricate a "patch broke the app" retry.
FUNC_SETUP_ERROR = "ARGUS_FUNC_SETUP_ERROR"

# A submit-against-patched callback: the orchestrator injects the patched
# bytes into the sandbox content map, then hands us this to replay a plan
# against them and return the trace (or raise).
SubmitPatched = Callable[[SandboxPlan], Awaitable[Any]]


@dataclass
class GateVariant:
    """One adversarial payload variant + its self-classifying harness."""

    description: str
    payload: str
    commands: list[str]


@dataclass
class FunctionalProbe:
    """One benign, mock-backed request the patched code should still serve."""

    description: str
    benign_url: str
    commands: list[str]


@dataclass
class GatePlans:
    """Pre-generated (LLM, lock-free) gate plans + generation telemetry."""

    functional: FunctionalProbe | None
    variants: list[GateVariant] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    notes: list[str] = field(default_factory=list)


# ── JSON helpers ─────────────────────────────────────────────────────


def _json_loads_safe(text: str) -> dict[str, Any]:
    """Best-effort parse of a model tool/text response into a dict."""
    if not text:
        return {}
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {}
    except (json.JSONDecodeError, TypeError):
        # Tolerate a ```json fence or leading prose.
        start = text.find("{")
        end = text.rfind("}")
        if 0 <= start < end:
            try:
                obj = json.loads(text[start : end + 1])
                return obj if isinstance(obj, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}


def _trace_excerpt(trace: Any, limit: int = 240) -> str:
    """Short stdout/stderr excerpt from a trace — for gate diagnostics
    (why a functional probe was judged broken / a variant fired)."""
    out = str(getattr(trace, "stdout_excerpt", "") or "")
    err = str(getattr(trace, "stderr_excerpt", "") or "")
    combined = (out + (" | ERR: " + err if err else "")).strip()
    return combined[:limit]


def oracle_in_trace(trace: Any, oracle: str) -> bool:
    """True if ``oracle`` appears in the trace's stdout/stderr/events.

    Mirrors the Phase A / Phase D literal-substring oracle so the gate
    classification is consistent with the rest of DAST.
    """
    if not oracle:
        return False
    needle = oracle.lower()
    for field_name in ("stdout_excerpt", "stderr_excerpt"):
        val = getattr(trace, field_name, None)
        if isinstance(val, str) and needle in val.lower():
            return True
    for ev in getattr(trace, "events", None) or []:
        payload_str = str(getattr(ev, "payload", "") or "")
        if needle in payload_str.lower():
            return True
    return False


# ── prompt + schema builders ─────────────────────────────────────────


def _vuln_summary_text(confirmed_findings: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for h in confirmed_findings[:4]:
        if not isinstance(h, dict):
            continue
        cwe = h.get("cwe") or h.get("type") or "vuln"
        desc = (h.get("description") or h.get("explanation") or h.get("rationale") or "")[:240]
        fn = h.get("_function_name") or h.get("function_name") or ""
        parts.append(f"- [{cwe}]{(' ' + fn) if fn else ''}: {desc}")
    return "\n".join(parts) or "- (no structured finding metadata)"


def build_adversarial_prompt(
    *,
    file_name: str,
    confirmed_findings: list[dict[str, Any]],
    original_source: str,
    patched_source: str,
    seed_commands: list[str],
    seed_payload: str,
    n: int,
) -> str:
    """Prompt: generate ``n`` same-class payload variants + harnesses.

    The harness must be self-classifying: print ``REACH_ORACLE`` iff the
    request actually went through (the patch let it reach the network),
    else ``BLOCK_MARKER``. The DAST sandbox hijacks all DNS to
    127.0.0.1, so "reached the network" == "reached the capture server".
    """
    seed_cmd_block = "\n".join(seed_commands) if seed_commands else "(no seed harness available)"
    return f"""You are Argus's remediation verifier, Stage 3 (adversarial).

A patch was generated for confirmed vulnerabilities in `{file_name}`. Your
job is to decide whether the patch fixes the vulnerability CLASS or only
the one reported payload. You do this by crafting {n} NOVEL exploit
payloads of the SAME class that use DIFFERENT techniques/encodings than
the original, then having each one self-report whether it got through.

CONFIRMED VULNERABILITIES:
{_vuln_summary_text(confirmed_findings)}

ORIGINAL (vulnerable) SOURCE:
```
{original_source[:2400]}
```

PATCHED SOURCE (this is what your payloads must defeat):
```
{patched_source[:3200]}
```

ORIGINAL proof-of-concept payload that confirmed the bug:
  {seed_payload or "(n/a)"}

ORIGINAL sandbox harness (use as a TEMPLATE for imports / how the
entrypoint is invoked — keep the same import + call shape):
```
{seed_cmd_block}
```

RUNTIME ENVIRONMENT (critical):
- The sandbox resolves EVERY hostname to 127.0.0.1 and runs a capture
  server there. So any request your variant actually sends will "reach"
  an internal host. A variant therefore tests: does the patch still let
  the request leave the function?
- For an SSRF-class bug, use techniques the original payload did NOT:
  decimal IP (e.g. 2130706433), hex/octal IP, IPv6 (`[::1]`, `[::ffff:127.0.0.1]`),
  cloud metadata (169.254.169.254), userinfo confusion
  (`http://allowed.example@169.254.169.254/`), trailing-dot / case /
  added-port host forms, and alternate schemes if the patch allowlists
  schemes. Pick the {n} STRONGEST distinct techniques for THIS patch.

HARNESS CONTRACT for each variant (so we can classify deterministically):
- A list of shell commands that import the module exactly as the seed
  harness does and call the SAME entrypoint with your variant URL.
- Wrap the call so it prints `{REACH_ORACLE}` if the call returns
  normally (request went through), and `{BLOCK_MARKER}` if it raises
  (validation rejected it). Example shape (adapt imports to the seed):
    python -c "import sys; \\
    <import module as in seed>; \\
    try:\\n  <entrypoint>('<VARIANT_URL>'); print('{REACH_ORACLE}')\\n except Exception as e:\\n  print('{BLOCK_MARKER}', type(e).__name__)"
- Keep each harness to a single `python -c` (or `python3 -c`) command.

Return STRICT JSON:
{{"variants": [{{"description": "<technique, one line>", "payload": "<the variant URL/value>", "commands": ["<harness cmd>"]}}]}}
Exactly {n} variants. No prose outside the JSON."""


def adversarial_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "variants": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "description": {"type": "string"},
                        "payload": {"type": "string"},
                        "commands": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["description", "payload", "commands"],
                },
            }
        },
        "required": ["variants"],
    }


def build_functional_prompt(
    *,
    file_name: str,
    confirmed_findings: list[dict[str, Any]],
    original_source: str,
    patched_source: str,
    seed_commands: list[str],
) -> str:
    """Prompt: generate ONE benign, mock-backed functional probe.

    Verifies the patch did not over-block legitimate traffic. Because the
    sandbox hijacks DNS, the probe MUST mock resolution to a public IP and
    mock the network egress so the patched validation sees a legitimate
    public host and proceeds.
    """
    seed_cmd_block = "\n".join(seed_commands) if seed_commands else "(no seed harness available)"
    return f"""You are Argus's remediation verifier, Stage 2 (functional preservation).

A patch was generated for `{file_name}`. A patch that "fixes" a bug by
breaking legitimate functionality is a FAILED patch (the worst case: the
exploit is gone only because the function now rejects everything). Your
job: prove the patched code still serves a LEGITIMATE request.

ORIGINAL SOURCE:
```
{original_source[:2000]}
```

PATCHED SOURCE:
```
{patched_source[:3000]}
```

ORIGINAL sandbox harness (TEMPLATE for imports / entrypoint call shape):
```
{seed_cmd_block}
```

RUNTIME ENVIRONMENT (critical):
- The sandbox hijacks ALL DNS to 127.0.0.1, so a real benign fetch would
  be (correctly) blocked by any sound SSRF patch. You therefore MUST
  MOCK so the patched validation sees a PUBLIC address and NO real
  network call happens:
    * Monkeypatch `socket.getaddrinfo` to return a PUBLIC IP
      (e.g. 93.184.216.34) for the benign host, so the patch's
      resolve-and-check logic passes it.
    * Mock the egress call the code uses (e.g. `requests.get` /
      `urllib.request.urlopen`) to return a dummy successful response
      (status 200, small body) — no real traffic.
  Install the mocks BEFORE importing/calling the entrypoint.
- Then call the SAME entrypoint as the seed harness with a LEGITIMATE
  public URL (e.g. https://example.com/image.png).

HARNESS CONTRACT (deterministic classification — TWO distinct phases):
- Phase A (setup): install the mocks + import the module inside their OWN
  try/except. If THIS fails (mock target missing, import error, etc.),
  print `{FUNC_SETUP_ERROR}` and exit — this is a test-harness problem,
  NOT evidence about the patch, so don't conflate it with a regression.
- Phase B (the actual test): call the entrypoint with the legitimate URL
  in a SEPARATE try/except. Print `{FUNC_OK}` if it returns successfully
  (legitimate request preserved); print `{FUNC_BROKEN}` ONLY if the
  ENTRYPOINT itself raises (the patch over-blocked a valid input).
- Keep it to a single `python -c` command.

Return STRICT JSON:
{{"description": "<one line>", "benign_url": "<the legit URL>", "commands": ["<harness cmd>"]}}
No prose outside the JSON."""


def functional_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "description": {"type": "string"},
            "benign_url": {"type": "string"},
            "commands": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["description", "commands"],
    }


# ── generation (LLM; call OUTSIDE the sandbox lock) ──────────────────


async def prepare_gate_plans(
    *,
    inference: InferenceFn,
    file_name: str,
    confirmed_findings: list[dict[str, Any]],
    original_source: str,
    patched_source: str,
    seed_commands: list[str],
    seed_payload: str,
    budget: VerifyBudget,
) -> GatePlans:
    """Generate the functional probe + adversarial variants up front.

    Pure inference — no sandbox calls — so the caller runs this BEFORE
    acquiring the per-sandbox content lock. Returns whatever it could
    generate; partial failures degrade gracefully (a missing gate just
    means that signal is absent, which the confidence model handles).
    """
    plans = GatePlans(functional=None)

    # Stage 2 plan
    if budget.functional > 0:
        try:
            resp = await inference(
                build_functional_prompt(
                    file_name=file_name,
                    confirmed_findings=confirmed_findings,
                    original_source=original_source,
                    patched_source=patched_source,
                    seed_commands=seed_commands,
                ),
                {"temperature": 0.0, "max_tokens": 1536, "seed": 0},
                functional_schema(),
            )
            plans.tokens_in += (resp.get("usage") or {}).get("prompt_tokens", 0) or 0
            plans.tokens_out += (resp.get("usage") or {}).get("completion_tokens", 0) or 0
            obj = _json_loads_safe(resp.get("text", ""))
            cmds = [c for c in (obj.get("commands") or []) if isinstance(c, str) and c.strip()]
            if cmds:
                plans.functional = FunctionalProbe(
                    description=str(obj.get("description") or "benign request preserved"),
                    benign_url=str(obj.get("benign_url") or ""),
                    commands=cmds,
                )
            else:
                plans.notes.append("functional probe generation returned no commands")
        except Exception as exc:  # noqa: BLE001
            plans.notes.append(f"functional probe generation failed: {type(exc).__name__}")

    # Stage 3 plans
    if budget.variants > 0:
        try:
            resp = await inference(
                build_adversarial_prompt(
                    file_name=file_name,
                    confirmed_findings=confirmed_findings,
                    original_source=original_source,
                    patched_source=patched_source,
                    seed_commands=seed_commands,
                    seed_payload=seed_payload,
                    n=budget.variants,
                ),
                {"temperature": 0.0, "max_tokens": 3072, "seed": 0},
                adversarial_schema(),
            )
            plans.tokens_in += (resp.get("usage") or {}).get("prompt_tokens", 0) or 0
            plans.tokens_out += (resp.get("usage") or {}).get("completion_tokens", 0) or 0
            obj = _json_loads_safe(resp.get("text", ""))
            for v in (obj.get("variants") or [])[: budget.variants]:
                if not isinstance(v, dict):
                    continue
                cmds = [c for c in (v.get("commands") or []) if isinstance(c, str) and c.strip()]
                if not cmds:
                    continue
                plans.variants.append(
                    GateVariant(
                        description=str(v.get("description") or "same-class variant"),
                        payload=str(v.get("payload") or ""),
                        commands=cmds,
                    )
                )
            if not plans.variants:
                plans.notes.append("adversarial generation returned no usable variants")
        except Exception as exc:  # noqa: BLE001
            plans.notes.append(f"adversarial generation failed: {type(exc).__name__}")

    return plans


# ── plan construction + execution (sandbox; INSIDE the lock) ─────────


def make_gate_plan(
    *,
    commands: list[str],
    payload: str,
    oracle: str,
    file_id: str,
    file_name: str,
    image_hint: str,
    timeout_sec: int,
    purpose: str,
) -> SandboxPlan:
    """Build a SandboxPlan for a gate harness against the patched file."""
    return SandboxPlan(
        plan_id=f"phaseC-{purpose}-{uuid.uuid4().hex[:8]}",
        file_id=file_id,
        hypothesis_id=f"verify-{purpose}-{uuid.uuid4().hex[:6]}",
        commands=commands,
        expected_oracle=oracle,
        payload=payload,
        timeout_sec=timeout_sec,
        image_hint=image_hint or "lean",
        file_name=file_name,
        synthesis_context={"phase": "C", "purpose": f"verify_{purpose}", "patched": True},
    )


async def execute_gates(
    *,
    plans: GatePlans,
    submit_patched: SubmitPatched,
    file_id: str,
    file_name: str,
    image_hint: str,
    timeout_sec: int,
    severity: str | None,
    poc_refuted: bool,
    budget: VerifyBudget,
) -> tuple[VerifyOutcome, dict[str, Any]]:
    """Replay the pre-generated gate plans against the injected patched
    source and fold the results into a :class:`VerifyOutcome`.

    ``submit_patched`` MUST already be bound to a sandbox whose content
    map holds the patched bytes (the orchestrator owns the inject/restore
    + lock). Replays here are fast; no inference happens.

    Returns ``(outcome, details)`` where ``details`` carries the
    per-variant fire results + functional result for the report.
    """
    details: dict[str, Any] = {
        "functional": None,
        "variants": [],
        "errors": [],
        "n_sandbox_calls": 0,
    }

    async def run_functional() -> bool | None:
        probe = plans.functional
        if probe is None:
            return None
        plan = make_gate_plan(
            commands=probe.commands,
            payload=probe.benign_url,
            oracle=FUNC_OK,
            file_id=file_id,
            file_name=file_name,
            image_hint=image_hint,
            timeout_sec=timeout_sec,
            purpose="functional",
        )
        try:
            trace = await submit_patched(plan)
            details["n_sandbox_calls"] += 1
        except Exception as exc:  # noqa: BLE001
            details["errors"].append(f"functional replay failed: {type(exc).__name__}")
            # Sandbox failure ≠ patch broke the app. Report "unknown" (None)
            # so confidence stays MEDIUM, not a false FAILED.
            details["functional"] = {"ok": None, "reason": "sandbox_error"}
            return None
        ok = oracle_in_trace(trace, FUNC_OK)
        broke = oracle_in_trace(trace, FUNC_BROKEN)
        setup_err = oracle_in_trace(trace, FUNC_SETUP_ERROR)
        # A harness setup failure (mock/import) is NOT evidence the patch
        # over-blocks — map it to unknown so a flaky mock can't fabricate a
        # "patch broke the app" retry. Decisive pass/fail only when exactly
        # one of the entrypoint markers shows; anything else → unknown.
        result: bool | None
        if setup_err:
            result = None
        elif ok and not broke:
            result = True
        elif broke and not ok:
            result = False
        else:
            result = None
        details["functional"] = {
            "ok": result,
            "description": probe.description,
            "benign_url": probe.benign_url,
            "stdout": _trace_excerpt(trace),
            "commands": probe.commands,
        }
        return result

    async def run_adversarial(n: int) -> tuple[int, int]:
        chosen = plans.variants[:n]
        tested = 0
        fired = 0
        for v in chosen:
            plan = make_gate_plan(
                commands=v.commands,
                payload=v.payload,
                oracle=REACH_ORACLE,
                file_id=file_id,
                file_name=file_name,
                image_hint=image_hint,
                timeout_sec=timeout_sec,
                purpose="variant",
            )
            try:
                trace = await submit_patched(plan)
                details["n_sandbox_calls"] += 1
            except Exception as exc:  # noqa: BLE001
                details["errors"].append(f"variant replay failed: {type(exc).__name__}")
                # A replay that didn't run is not evidence the variant was
                # blocked — record it but don't count it as tested.
                details["variants"].append(
                    {"description": v.description, "payload": v.payload, "result": "error"}
                )
                continue
            tested += 1
            did_fire = oracle_in_trace(trace, REACH_ORACLE)
            if did_fire:
                fired += 1
            details["variants"].append(
                {
                    "description": v.description,
                    "payload": v.payload,
                    "result": "FIRED" if did_fire else "blocked",
                    "stdout": _trace_excerpt(trace),
                }
            )
        return tested, fired

    outcome = await verify_patch(
        poc_refuted=poc_refuted,
        severity=severity,
        run_functional=run_functional,
        run_adversarial=run_adversarial,
        budget=budget,
    )
    return outcome, details
