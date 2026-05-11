"""Sandbox client — Protocol + stub + Firecracker (Fly.io) implementations.

Production target is Firecracker (primary) / gVisor (fallback) per
``dast/CLAUDE.md``. The stub keeps the prototype's architecture-
validation runs decoupled from sandbox infrastructure. The Firecracker
client (Path C — Fly.io managed Firecracker substrate) is the real-
sandbox path for verdict-accuracy validation against the same corpus.

Both implementations satisfy the ``SandboxClient`` Protocol; the
orchestrator code is unchanged regardless of which is wired in.

Stub design
-----------
The stub takes a per-file ``ScenarioMap`` at construction time. The map
encodes, for each (file_id, hypothesis_id) pair, what the sandbox would
observe IF the corresponding L1 finding is real per the Opus oracle:

    ScenarioMap[file_id][hypothesis_id] = ScenarioEntry(
        ground_truth_status: "confirmed" | "refuted" | "inconclusive",
        events: list[SandboxEvent],
        exit_code: int,
        elapsed_ms: int,
    )

Phase B (upstream-reasoning) hypotheses are typically not in the map —
they're synthesized at runtime. The stub handles those by inspecting
the plan's ``hypothesis_id`` / oracle and returning a "code_pattern_
observed" event when the upstream condition is real (i.e., when the
hypothesis's ``upstream_chain.confirmed_finding_ref`` points to an L1
finding the oracle confirmed). This mirrors what a real sandbox would
report: the upstream condition is observable in code regardless of
runtime behavior.

The orchestrator passes the runtime context (the hypothesis dict) on
the plan via ``SandboxPlan.synthesis_context`` so the stub can decide
deterministically. This is a stub-only field; real sandboxes don't see
it.

Cost: $0. Latency: ~1 ms per call. Stub-driven latency numbers are NOT
representative of production.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ConfigDict

SANDBOX_IMAGE_HINTS: tuple[str, ...] = ("minimal", "networked", "ml_tools")
"""Allowed values for ``SandboxPlan.image_hint`` (DAST-005).

  * ``minimal`` — Python + stdlib + base shell utilities. Default.
  * ``networked`` — superset of minimal: + curl, wget, netcat, dnsutils.
  * ``ml_tools`` — superset of networked: + transformers, torch (CPU),
    safetensors, huggingface_hub.

The orchestrator passes the plan's hint to ``MultiImageSandboxClient``
which dispatches to the matching inner client. Single-image callers
(stub or single Firecracker image) ignore the hint.
"""


class SandboxPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: str
    file_id: str
    hypothesis_id: str
    commands: list[str]
    expected_oracle: str
    payload: str
    timeout_sec: int
    # DAST-005: which sandbox image this plan needs. Defaults to
    # ``minimal`` so existing callers and plans without an explicit
    # hint route to the existing single-image behavior.
    image_hint: str = "minimal"
    # Stub-only context: lets the stub synthesize traces for Phase B
    # hypotheses that aren't in the canned ScenarioMap. Real sandbox
    # ignores this.
    synthesis_context: dict[str, Any] = {}
    # On-disk basename (with extension) used when staging the file at
    # /workspace/<file_name> in the sandbox. Empty falls back to file_id
    # for legacy callers / stub fixtures. Node `require()`, Java class
    # loader, and any extension-routed runtime need the right suffix.
    file_name: str = ""


class SandboxEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    kind: str
    payload: dict[str, Any]


class SandboxTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: str
    file_id: str
    hypothesis_id: str
    events: list[SandboxEvent]
    exit_code: int | None
    stdout_excerpt: str
    stderr_excerpt: str
    elapsed_ms: int
    is_stub_no_trace: bool = False
    stub_synthesis_note: str = ""


class SandboxClient(Protocol):
    async def submit(self, plan: SandboxPlan) -> SandboxTrace: ...


@dataclass
class ScenarioEntry:
    """What the stub returns for a known (file_id, hypothesis_id) pair."""

    ground_truth_status: str  # "confirmed" | "refuted" | "inconclusive"
    events: list[dict] = field(default_factory=list)
    exit_code: int = 0
    elapsed_ms: int = 100
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""


@dataclass
class StubSandboxClient:
    """Deterministic stub. See module docstring."""

    scenario: dict[str, dict[str, ScenarioEntry]] = field(default_factory=dict)
    # file_id -> set of L1 finding IDs the oracle confirmed
    oracle_confirmed_findings: dict[str, set[str]] = field(default_factory=dict)

    @staticmethod
    def trace_key(plan: SandboxPlan) -> str:
        h = hashlib.sha256()
        h.update(plan.file_id.encode())
        h.update(b"|")
        h.update(plan.hypothesis_id.encode())
        h.update(b"|")
        h.update(plan.payload.encode())
        h.update(b"|")
        for cmd in sorted(plan.commands):
            h.update(cmd.encode())
            h.update(b"\n")
        return h.hexdigest()[:16]

    def _next_event_id(self, plan: SandboxPlan, idx: int) -> str:
        # Deterministic per-plan event IDs
        digest = hashlib.sha256(f"{plan.plan_id}|{plan.hypothesis_id}|{idx}".encode()).hexdigest()[:6]
        return f"evt-{digest}"

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        # 1. Canned scenario lookup
        per_file = self.scenario.get(plan.file_id) or {}
        entry = per_file.get(plan.hypothesis_id)
        if entry is not None:
            evs = [
                SandboxEvent(**dict(e, event_id=e.get("event_id") or self._next_event_id(plan, i)))
                for i, e in enumerate(entry.events)
            ]
            return SandboxTrace(
                plan_id=plan.plan_id,
                file_id=plan.file_id,
                hypothesis_id=plan.hypothesis_id,
                events=evs,
                exit_code=entry.exit_code,
                stdout_excerpt=entry.stdout_excerpt,
                stderr_excerpt=entry.stderr_excerpt,
                elapsed_ms=entry.elapsed_ms,
            )

        # 2. Phase B synthesis path: ALWAYS return ONLY a
        # ``code_pattern_observed`` event. Never an exploit_demonstrated
        # event. See stub_design.md for the rationale: a real sandbox
        # CAN observe whether a pattern is present in code (statically
        # readable from the file) but only sees an exploit if a runtime
        # path actually triggers it. The stub has no runtime-behavior
        # data for Phase B upstream conditions, so it must report the
        # weaker signal and let the model decide whether pattern-presence
        # alone justifies a confirmed verdict (per the v0.2 prompt
        # rules, the answer is no — pattern-only is "inconclusive").
        #
        # IMPORTANT: this branch deliberately does NOT consult
        # ``oracle_confirmed_findings`` — peeking at the oracle to
        # decide event content is a form of cheating that would mask
        # real architecture problems. The decision to anchor only on
        # the file's static contents is independent of oracle.
        ctx = plan.synthesis_context or {}
        uc = ctx.get("upstream_chain") or {}
        upstream_finding = (uc.get("confirmed_finding_ref") or "").strip()
        evid_loc = (uc.get("evidence_location") or "").strip()
        cond = (uc.get("upstream_condition") or "").strip()
        if upstream_finding and evid_loc:
            evt = SandboxEvent(
                event_id=self._next_event_id(plan, 0),
                kind="code_pattern_observed",
                payload={
                    "upstream_finding_ref": upstream_finding,
                    "upstream_condition": cond,
                    "evidence_location": evid_loc,
                    "synthesized_from": "stub_sandbox",
                    "exploit_demonstrated": False,
                    "note": (
                        "Pattern is present in source. Stub does not "
                        "have runtime-behavior data so cannot demonstrate "
                        "exploit. Per Verdict Rule 1, treat this as "
                        "pattern-only evidence."
                    ),
                },
            )
            return SandboxTrace(
                plan_id=plan.plan_id,
                file_id=plan.file_id,
                hypothesis_id=plan.hypothesis_id,
                events=[evt],
                exit_code=0,
                stdout_excerpt="",
                stderr_excerpt="",
                elapsed_ms=2,
                stub_synthesis_note=(
                    f"Pattern observed: {cond} at {evid_loc}. Exploit NOT demonstrated. (Stub has no runtime data.)"
                ),
            )

        # 3. No-trace sentinel — orchestrator should mark inconclusive
        return SandboxTrace(
            plan_id=plan.plan_id,
            file_id=plan.file_id,
            hypothesis_id=plan.hypothesis_id,
            events=[],
            exit_code=None,
            stdout_excerpt="",
            stderr_excerpt="",
            elapsed_ms=1,
            is_stub_no_trace=True,
            stub_synthesis_note=("no canned scenario and no oracle-confirmed upstream anchor"),
        )

    def to_jsonable_scenario(self) -> dict:
        """Serialize scenario for fixture write — diagnostic only."""
        out = {}
        for fid, hmap in self.scenario.items():
            out[fid] = {
                hid: {
                    "ground_truth_status": e.ground_truth_status,
                    "events": e.events,
                    "exit_code": e.exit_code,
                    "elapsed_ms": e.elapsed_ms,
                }
                for hid, e in hmap.items()
            }
        return out


def build_scenario_from_l1_and_oracle(
    file_id: str,
    l1_record: dict,
    oracle_record: dict,
) -> tuple[dict[str, ScenarioEntry], set[str]]:
    """Build per-file ScenarioMap entries from L1 hypotheses + oracle findings.

    Approach:
      * For each L1 hypothesis Hxxx referencing finding Fyyy:
          - if oracle confirms Fyyy (i.e., oracle.findings contains Fyyy
            with type/severity matching L1's claim), status=confirmed and
            we synthesize an event that observes the expected_evidence
            implied by the hypothesis's oracle_type
          - if oracle has no matching finding, status=inconclusive
          - if oracle classifies the file as clean and L1 over-fires,
            status=refuted
      * The set of oracle-confirmed F### IDs is also returned so the stub
        can resolve Phase B upstream-chain references.
    """
    sr = l1_record.get("scan_report") or {}
    l1_findings = (sr.get("analysis") or {}).get("findings") or []
    l1_hyps = (sr.get("analysis") or {}).get("hypotheses") or []
    oracle_findings = ((oracle_record.get("full_label") or {}).get("analysis") or {}).get("findings") or []
    oracle_verdict = ((oracle_record.get("full_label") or {}).get("verdict") or {}).get("verdict_label") or "clean"

    # Two views of the oracle: by L1-style finding ID (sometimes oracles
    # re-emit F### with different numbering), and by CWE+type fingerprint.
    oracle_cwe_set = {(f.get("cwe") or "").strip().upper() for f in oracle_findings if isinstance(f, dict)}
    oracle_type_set = {(f.get("type") or "").strip() for f in oracle_findings if isinstance(f, dict)}

    confirmed_l1_finding_ids: set[str] = set()
    for f in l1_findings:
        cwe = (f.get("cwe") or "").strip().upper()
        ftype = (f.get("type") or "").strip()
        if cwe and cwe in oracle_cwe_set:
            confirmed_l1_finding_ids.add(f.get("id", ""))
        elif ftype and ftype in oracle_type_set:
            confirmed_l1_finding_ids.add(f.get("id", ""))

    # Oracle disagreement gates (see stub_design.md):
    #   * If oracle says clean or informational, L1's findings are
    #     over-fires; the stub returns "no_expected_event" (refuted).
    #   * If oracle says suspicious, the file is genuinely on the
    #     borderline; the stub returns "ambiguous_observation"
    #     (inconclusive) for L1's findings — pattern likely present
    #     but exploit not demonstrated by oracle.
    #   * Only when oracle says malicious or critical_malicious do we
    #     promote CWE/type-matched L1 findings to confirmed status with
    #     a runtime side-effect event.
    if oracle_verdict in {"clean", "informational", "suspicious"}:
        confirmed_l1_finding_ids = set()

    scenarios: dict[str, ScenarioEntry] = {}
    for h in l1_hyps:
        hid = h.get("id", "")
        fid = h.get("finding_ref", "")
        oracle_type = h.get("oracle_type") or "execution_output"
        evidence = h.get("test_steps") or []
        if fid in confirmed_l1_finding_ids:
            # Oracle agrees with L1 → emit BOTH a runtime side-effect
            # event (exploit_demonstrated, named per oracle_type) AND a
            # code_pattern_observed event. The runtime event is what
            # the model needs to confirm per Verdict Rule 1.
            ev_runtime = {
                "event_id": "",
                "kind": _kind_for_oracle(oracle_type),
                "payload": {
                    "hypothesis_id": hid,
                    "finding_ref": fid,
                    "synth_status": "exploit_demonstrated",
                    "expected_test_steps": [
                        {"action": s.get("action"), "expected_state": s.get("expected_state")} for s in evidence
                    ],
                    "note": ("Runtime side-effect observed; exploit demonstrated."),
                },
            }
            ev_pattern = {
                "event_id": "",
                "kind": "code_pattern_observed",
                "payload": {
                    "hypothesis_id": hid,
                    "finding_ref": fid,
                    "exploit_demonstrated": True,
                },
            }
            entry = ScenarioEntry(
                ground_truth_status="confirmed",
                events=[ev_runtime, ev_pattern],
                exit_code=0,
                elapsed_ms=80,
                stdout_excerpt="[stub] runtime exploit demonstrated",
            )
        elif oracle_verdict in {"clean", "informational"}:
            # Oracle disagrees: file is genuinely benign, L1 over-fired.
            # Real sandbox would observe NO exploit chain. Return
            # `no_expected_event` so model verdicts to "refuted".
            entry = ScenarioEntry(
                ground_truth_status="refuted",
                events=[
                    {
                        "event_id": "",
                        "kind": "no_expected_event",
                        "payload": {
                            "hypothesis_id": hid,
                            "finding_ref": fid,
                            "exploit_demonstrated": False,
                            "note": (
                                "Sandbox executed the plan; no expected "
                                "side effect occurred. Oracle considers "
                                "file benign."
                            ),
                        },
                    }
                ],
                exit_code=0,
                elapsed_ms=20,
            )
        elif oracle_verdict == "suspicious":
            # Oracle is genuinely on the borderline. Real sandbox would
            # observe the pattern is present but couldn't trigger a
            # full exploit chain. Pattern-only event → inconclusive.
            entry = ScenarioEntry(
                ground_truth_status="inconclusive",
                events=[
                    {
                        "event_id": "",
                        "kind": "code_pattern_observed",
                        "payload": {
                            "hypothesis_id": hid,
                            "finding_ref": fid,
                            "exploit_demonstrated": False,
                            "note": (
                                "Pattern present in source. Sandbox "
                                "could not demonstrate full exploit "
                                "chain (oracle classifies file as "
                                "suspicious, not malicious)."
                            ),
                        },
                    }
                ],
                exit_code=0,
                elapsed_ms=20,
            )
        else:
            # CWE/type mismatch on a malicious file: L1's hypothesis
            # targets a finding shape that oracle didn't enumerate.
            # Real sandbox might observe ambiguous behavior. Inconclusive.
            entry = ScenarioEntry(
                ground_truth_status="inconclusive",
                events=[
                    {
                        "event_id": "",
                        "kind": "ambiguous_observation",
                        "payload": {
                            "hypothesis_id": hid,
                            "finding_ref": fid,
                            "exploit_demonstrated": False,
                            "note": (
                                "Oracle confirms file is malicious but "
                                "did not enumerate this finding shape; "
                                "sandbox observation is ambiguous."
                            ),
                        },
                    }
                ],
                exit_code=0,
                elapsed_ms=30,
            )
        scenarios[hid] = entry
    return scenarios, confirmed_l1_finding_ids


def _kind_for_oracle(oracle_type: str) -> str:
    return {
        "execution_output": "exec_marker",
        "file_access": "file_write",
        "mock_server": "http_request",
        "network_capture": "http_request",
        "asan": "memory_violation",
        "ubsan": "integer_overflow",
        "tsan": "data_race",
    }.get(oracle_type, "generic_observation")


# ---------------------------------------------------------------------------
# Firecracker (Fly.io) sandbox client
# ---------------------------------------------------------------------------


class FlyMachinesError(RuntimeError):
    """Raised when the Fly Machines API returns an unexpected response."""


@dataclass
class FlyMachinesClient:
    """Low-level Fly Machines REST API client.

    Handles machine create / wait / destroy. Logs retrieval is the
    caller's responsibility (see :meth:`FirecrackerSandboxClient._get_logs`).
    """

    app_name: str
    api_token: str
    region: str = "iad"
    base_url: str = "https://api.machines.dev/v1"
    request_timeout_s: float = 60.0

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

    async def create_machine(
        self,
        *,
        image: str,
        env: dict[str, str],
        cpus: int = 1,
        memory_mb: int = 512,
        cpu_kind: str = "shared",
        auto_destroy: bool = False,
        name: str | None = None,
    ) -> dict[str, Any]:
        body = {
            "name": name,
            "region": self.region,
            "config": {
                "image": image,
                "env": env,
                "guest": {
                    "cpu_kind": cpu_kind,
                    "cpus": cpus,
                    "memory_mb": memory_mb,
                },
                "auto_destroy": auto_destroy,
                "restart": {"policy": "no"},
            },
        }
        async with httpx.AsyncClient(timeout=self.request_timeout_s) as client:
            r = await client.post(
                f"{self.base_url}/apps/{self.app_name}/machines",
                json=body,
                headers=self._headers,
            )
            if r.status_code >= 400:
                raise FlyMachinesError(f"create_machine {r.status_code}: {r.text[:500]}")
            return r.json()

    async def wait_for_state(
        self,
        machine_id: str,
        instance_id: str,
        target_state: str = "stopped",
        timeout_s: int = 120,
    ) -> dict[str, Any]:
        url = f"{self.base_url}/apps/{self.app_name}/machines/{machine_id}/wait"
        params = {
            "state": target_state,
            "timeout": timeout_s,
            "instance_id": instance_id,
        }
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_s + 30, connect=15.0)) as client:
            r = await client.get(url, params=params, headers=self._headers)
            if r.status_code >= 400:
                raise FlyMachinesError(f"wait_for_state {r.status_code}: {r.text[:500]}")
            return r.json()

    async def get_machine(self, machine_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.request_timeout_s) as client:
            r = await client.get(
                f"{self.base_url}/apps/{self.app_name}/machines/{machine_id}",
                headers=self._headers,
            )
            if r.status_code >= 400:
                raise FlyMachinesError(f"get_machine {r.status_code}: {r.text[:300]}")
            return r.json()

    async def destroy_machine(self, machine_id: str, force: bool = True) -> None:
        async with httpx.AsyncClient(timeout=self.request_timeout_s) as client:
            r = await client.delete(
                f"{self.base_url}/apps/{self.app_name}/machines/{machine_id}",
                params={"force": "true" if force else "false"},
                headers=self._headers,
            )
            # 200 / 404 both acceptable (404 = already gone)
            if r.status_code not in (200, 204, 404):
                raise FlyMachinesError(f"destroy_machine {r.status_code}: {r.text[:300]}")


def _find_flyctl() -> str | None:
    """Locate flyctl binary. Falls back to typical Windows / POSIX install
    paths if not on PATH (since this session's PATH may differ from the
    user's interactive shell).
    """
    on_path = shutil.which("flyctl") or shutil.which("flyctl.exe")
    if on_path:
        return on_path
    candidates = [
        Path.home() / ".fly" / "bin" / "flyctl.exe",
        Path.home() / ".fly" / "bin" / "flyctl",
        Path("/usr/local/bin/flyctl"),
        Path("/c/Users") / os.environ.get("USERNAME", "user") / ".fly" / "bin" / "flyctl.exe",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


@dataclass
class FirecrackerSandboxClient:
    """Real sandbox via Fly.io machines (Firecracker substrate).

    Per plan: creates one ephemeral microvm with the plan's commands and
    target file passed via env vars, waits for it to stop, retrieves
    logs (which contain JSON event lines emitted by the in-VM
    entrypoint), parses them into :class:`SandboxEvent` objects, and
    destroys the machine.

    Construction:
        ``file_content_map`` is ``{file_id → bytes}``. The orchestrator
        wires this up with the corpus contents at run start.
        ``flyctl_path`` is auto-detected if not provided; the binary is
        used for log retrieval (Fly's REST logs endpoint is not
        documented for arbitrary historical machine stdout, so we
        subprocess flyctl for this one operation — see
        ``firecracker_event_types.md``).

    Safety:
        * ``auto_destroy=False`` on machine creation so we have time to
          retrieve logs after the entrypoint exits. Manual destroy in
          a ``finally`` block.
        * Per-call timeout caps wall clock at ``timeout_sec + boot_overhead_s``.
        * Per-machine resources hardcoded to 1 vCPU / 512 MB / no public IP.
    """

    fly_client: FlyMachinesClient
    image: str
    file_content_map: dict[str, bytes] = field(default_factory=dict)
    flyctl_path: str | None = None
    # Boot overhead is the headroom we add to plan.timeout_sec when
    # asking Fly to wait for state=stopped. Fly's API caps wait at 60s
    # total, so we cap the request internally; if a plan genuinely
    # needs longer than 60s, fall back to polling get_machine.
    boot_overhead_s: int = 15
    fly_wait_max_s: int = 60  # API hard cap
    # Logs are written by the entrypoint to stdout. Fly's NATS-backed
    # log pipeline takes a few seconds to flush; we retry with
    # increasing delays until we see the entrypoint's "execution_complete"
    # sentinel or run out of attempts.
    log_retrieval_retries: int = 6
    log_retrieval_initial_delay_s: float = 5.0
    _resolved_image: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.flyctl_path is None:
            self.flyctl_path = _find_flyctl()

    async def _resolve_image(self) -> str:
        """Resolve `:latest` to the actual deployment tag.

        Fly does not always auto-tag deployments as `:latest` — depends on
        account / deploy strategy. To stay robust, we subprocess
        ``flyctl image show --json`` to get the current image reference
        for our app. Cached after first resolution.
        """
        if self._resolved_image is not None:
            return self._resolved_image
        if not self.image.endswith(":latest"):
            self._resolved_image = self.image
            return self._resolved_image
        if not self.flyctl_path:
            raise FlyMachinesError(
                "flyctl not available; cannot resolve `:latest` tag. "
                "Pass an explicit image like 'registry.fly.io/argus-dast-sandbox:deployment-XXX'."
            )
        # `flyctl releases --json --image` returns the deployment image
        # ref reliably even when no machines are running. `flyctl image
        # show` requires a running machine and returns `null` otherwise,
        # so it's not usable for our preflight pattern.
        proc = await asyncio.create_subprocess_exec(
            self.flyctl_path,
            "releases",
            "--app",
            self.fly_client.app_name,
            "--json",
            "--image",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "FLY_API_TOKEN": self.fly_client.api_token},
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=20.0)
        except asyncio.TimeoutError:
            proc.kill()
            raise FlyMachinesError("flyctl releases timed out") from None
        if proc.returncode != 0:
            err = stderr_b.decode("utf-8", errors="replace")[:400]
            raise FlyMachinesError(f"flyctl releases failed: {err}")
        try:
            data = json.loads(stdout_b.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as e:
            raise FlyMachinesError(f"flyctl releases JSON parse: {e}") from e
        if not isinstance(data, list) or not data:
            raise FlyMachinesError(
                f"flyctl releases returned no rows for app {self.fly_client.app_name!r} — has it ever been deployed?"
            )
        # First record is the most recent release.
        latest = data[0] if isinstance(data[0], dict) else {}
        ref = latest.get("ImageRef") or latest.get("imageRef") or ""
        if not ref or ":" not in ref:
            raise FlyMachinesError(f"flyctl releases returned no usable ImageRef: {latest!r}")
        self._resolved_image = ref
        return self._resolved_image

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        env = self._build_env(plan)
        machine_name = f"plan-{StubSandboxClient.trace_key(plan)}"
        machine: dict[str, Any] | None = None
        try:
            image = await self._resolve_image()
            machine = await self.fly_client.create_machine(
                image=image,
                env=env,
                name=machine_name,
                cpus=1,
                memory_mb=512,
                auto_destroy=False,
            )
            machine_id = machine["id"]
            instance_id = machine.get("instance_id") or machine.get("nonce") or ""

            # Wait for the entrypoint to finish executing. Fly's API
            # caps wait at 60s; if the plan needs longer, we'd fall back
            # to polling get_machine (not yet implemented since our
            # plans are typically ≤30s).
            requested = plan.timeout_sec + self.boot_overhead_s
            wait_s = min(requested, self.fly_wait_max_s)
            try:
                await self.fly_client.wait_for_state(
                    machine_id=machine_id,
                    instance_id=instance_id,
                    target_state="stopped",
                    timeout_s=wait_s,
                )
            except FlyMachinesError as e:
                # If the wait timed out (machine still running), poll
                # once via get_machine — it may have just finished.
                # Otherwise propagate.
                if "timeout" not in str(e).lower():
                    raise
                state_info = await self.fly_client.get_machine(machine_id)
                if state_info.get("state") not in {"stopped", "destroyed"}:
                    # Still running past our budget — give up; logs may be partial.
                    pass

            # Retrieve stdout (which contains JSON event lines from entrypoint.py)
            log_lines = await self._get_logs(machine_id)
            events, exit_code, stdout_excerpt, stderr_excerpt, elapsed_ms = self._parse_log_lines(log_lines, plan)
            return SandboxTrace(
                plan_id=plan.plan_id,
                file_id=plan.file_id,
                hypothesis_id=plan.hypothesis_id,
                events=events,
                exit_code=exit_code,
                stdout_excerpt=stdout_excerpt,
                stderr_excerpt=stderr_excerpt,
                elapsed_ms=elapsed_ms,
                is_stub_no_trace=(not events),
                stub_synthesis_note="" if events else "no events captured from machine",
            )
        except Exception as e:
            return SandboxTrace(
                plan_id=plan.plan_id,
                file_id=plan.file_id,
                hypothesis_id=plan.hypothesis_id,
                events=[],
                exit_code=None,
                stdout_excerpt="",
                stderr_excerpt=f"firecracker_error: {type(e).__name__}: {str(e)[:300]}",
                elapsed_ms=0,
                is_stub_no_trace=True,
                stub_synthesis_note=f"sandbox call failed: {type(e).__name__}",
            )
        finally:
            if machine is not None:
                # Best-effort destroy. If it's already gone or the
                # destroy fails we don't want to mask the original
                # error; just swallow.
                try:
                    await self.fly_client.destroy_machine(machine["id"])
                except Exception:
                    pass

    # ---- helpers ---------------------------------------------------------

    def _build_env(self, plan: SandboxPlan) -> dict[str, str]:
        # Locate the file's content from the registered map
        content = self.file_content_map.get(plan.file_id, b"")
        encoded = base64.b64encode(gzip.compress(content)).decode("ascii") if content else ""

        # Pattern list for code_pattern_observed events. Phase B
        # hypotheses have an upstream_chain.upstream_condition that
        # serves as the pattern target.
        ctx = plan.synthesis_context or {}
        uc = ctx.get("upstream_chain") or {}
        cond = (uc.get("upstream_condition") or "").strip()
        patterns: list[str] = []
        if cond and len(cond) >= 5 and len(cond) <= 100:
            # Use the upstream condition itself as a pattern string.
            # Crude but effective for the common cases observed in the
            # 7-file run (e.g., "user: root", "uses: actions/setup-node@v3").
            patterns.append(cond)

        # Strip any directory components and reject empty / traversal
        # attempts. Falls back to file_id (the SHA256) so unauthored
        # callers keep a non-empty value, but extension-routed
        # languages (Node `require`, Java class loader, etc.) only
        # work when callers populate plan.file_name with the real
        # basename.
        raw_name = (plan.file_name or "").strip()
        safe_name = Path(raw_name).name if raw_name else ""
        file_name = safe_name or plan.file_id

        env = {
            "PLAN_ID": plan.plan_id,
            "FILE_ID": plan.file_id,
            "HYPOTHESIS_ID": plan.hypothesis_id,
            "FILE_NAME": file_name,
            "FILE_CONTENT_B64GZ": encoded,
            "PLAN_COMMANDS": json.dumps(plan.commands),
            "PLAN_TIMEOUT_SEC": str(plan.timeout_sec),
            "EXPECTED_EVIDENCE": (ctx.get("expected_evidence") if isinstance(ctx, dict) else "") or "",
            "EXPECTED_PATTERNS": json.dumps(patterns) if patterns else "",
        }
        # Fly env values must be strings; drop empty values to keep
        # config compact (Fly accepts but the ENV becomes implicit "").
        return {k: v for k, v in env.items() if v != ""}

    async def _get_logs(self, machine_id: str) -> list[str]:
        """Retrieve machine stdout via flyctl subprocess.

        Fly's HTTP API does not expose a documented endpoint for
        historical per-machine stdout retrieval; flyctl uses an
        internal NATS-backed API. Subprocess is the simplest reliable
        path. Retries once on transient empty result (logs sometimes
        take a moment to flush after machine stops).
        """
        if not self.flyctl_path:
            raise FlyMachinesError(
                "flyctl binary not found on PATH or in standard locations. "
                "Install it (https://fly.io/docs/flyctl/install/) and ensure "
                "it's accessible to this Python process."
            )

        # NOTE: ``flyctl logs --machine X`` returns EMPTY for already-
        # destroyed machines (Fly behavior — the per-machine log filter
        # apparently can't resolve a deleted instance). The log entries
        # ARE in the central app log store and ARE retrievable via
        # ``flyctl logs --app X`` (no machine filter); we then
        # post-filter by ``instance`` field (== machine_id).
        #
        # flyctl logs --json emits concatenated JSON objects (NOT a JSON
        # array). We use json.JSONDecoder.raw_decode in a loop to parse.
        last_messages: list[str] = []
        delay = self.log_retrieval_initial_delay_s
        for _attempt in range(self.log_retrieval_retries):
            await asyncio.sleep(delay)
            proc = await asyncio.create_subprocess_exec(
                self.flyctl_path,
                "logs",
                "--no-tail",
                "--json",
                "--app",
                self.fly_client.app_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "FLY_API_TOKEN": self.fly_client.api_token},
            )
            try:
                stdout_b, _stderr_b = await asyncio.wait_for(proc.communicate(), timeout=45.0)
            except asyncio.TimeoutError:
                proc.kill()
                delay *= 1.3
                continue
            stdout = stdout_b.decode("utf-8", errors="replace")
            messages: list[str] = []
            decoder = json.JSONDecoder()
            idx = 0
            text_len = len(stdout)
            while idx < text_len:
                while idx < text_len and stdout[idx] in " \t\n\r":
                    idx += 1
                if idx >= text_len:
                    break
                try:
                    obj, end = decoder.raw_decode(stdout, idx)
                except json.JSONDecodeError:
                    idx += 1
                    continue
                idx = end
                if not isinstance(obj, dict):
                    continue
                # Filter by instance == machine_id
                if obj.get("instance") != machine_id:
                    continue
                msg = obj.get("message")
                if isinstance(msg, str):
                    messages.append(msg)
            if messages:
                last_messages = messages
                # Sentinel check
                if any('"event_id": "evt-final"' in m or '"kind": "execution_complete"' in m for m in messages):
                    return messages
            delay *= 1.3
        return last_messages

    def _parse_log_lines(
        self, log_messages: list[str], plan: SandboxPlan
    ) -> tuple[list[SandboxEvent], int | None, str, str, int]:
        """Parse the per-message strings returned by :meth:`_get_logs`.

        Each ``log_messages[i]`` is the ``message`` field from a flyctl
        log JSON entry — one stdout line from the entrypoint. Most are
        JSON-encoded events; some are Fly init noise (e.g. "Machine
        created and started in 4.487s") which we skip silently.

        Returns: (events, exit_code, stdout_excerpt, stderr_excerpt, elapsed_ms)
        """
        events: list[SandboxEvent] = []
        stdout_pieces: list[str] = []
        stderr_pieces: list[str] = []
        exit_code: int | None = None
        elapsed_ms: int = 0

        for msg in log_messages:
            if not msg or not msg.strip().startswith("{"):
                continue
            try:
                ev = json.loads(msg)
            except json.JSONDecodeError:
                continue
            if not isinstance(ev, dict) or "kind" not in ev:
                continue
            kind = ev.get("kind")
            payload = ev.get("payload") or {}
            event_id = ev.get("event_id") or _hash_event_id(kind, payload)
            events.append(SandboxEvent(event_id=event_id, kind=kind, payload=payload))

            if kind == "process_exit":
                so = payload.get("stdout_excerpt") or ""
                se = payload.get("stderr_excerpt") or ""
                if so:
                    stdout_pieces.append(so)
                if se:
                    stderr_pieces.append(se)
                if exit_code is None or (payload.get("exit_code") and exit_code == 0):
                    exit_code = payload.get("exit_code")
            if kind == "execution_complete":
                elapsed_ms = int(payload.get("elapsed_ms") or 0)

        return (
            events,
            exit_code,
            "\n".join(stdout_pieces)[:2000],
            "\n".join(stderr_pieces)[:2000],
            elapsed_ms,
        )


def _hash_event_id(kind: str, payload: dict) -> str:
    h = hashlib.sha256(
        f"{kind}:{json.dumps(payload, sort_keys=True, default=str)}:{time.time_ns()}".encode()
    ).hexdigest()[:8]
    return f"evt-{h}"


# ---------------------------------------------------------------------------
# DAST-005: Multi-image sandbox dispatcher
# ---------------------------------------------------------------------------


@dataclass
class MultiImageSandboxClient:
    """Routes plans to per-image inner sandbox clients by ``plan.image_hint``.

    Composition pattern: this client IS a :class:`SandboxClient` (satisfies
    the Protocol) but holds N inner clients keyed by image hint and
    dispatches per call. Existing single-image code paths are unaffected.

    Construction expects a dict mapping each supported hint
    (``minimal`` / ``networked`` / ``ml_tools``) to a fully-constructed
    inner ``SandboxClient``. A plan whose hint isn't in the map is
    routed to ``fallback_hint`` (default ``minimal``); a plan whose hint
    is the empty string or missing also falls through to fallback. This
    keeps the orchestrator decoupled from how inner clients are built —
    callers can register a single client under multiple keys to share
    images, or omit hints they don't support yet.

    Usage::

        client = MultiImageSandboxClient(
            inner_by_hint={
                "minimal":   FirecrackerSandboxClient(image="...:minimal-v1"),
                "networked": FirecrackerSandboxClient(image="...:networked-v1"),
                "ml_tools":  FirecrackerSandboxClient(image="...:ml-tools-v1"),
            },
        )

    Tests can compose stub clients per hint to verify dispatch:

        client = MultiImageSandboxClient(
            inner_by_hint={
                "minimal":   StubSandboxClient(...),
                "networked": StubSandboxClient(...),
            },
        )
    """

    inner_by_hint: dict[str, "SandboxClient"]
    fallback_hint: str = "minimal"

    def __post_init__(self) -> None:
        if self.fallback_hint not in self.inner_by_hint:
            raise ValueError(
                f"fallback_hint={self.fallback_hint!r} is not in inner_by_hint "
                f"keys ({sorted(self.inner_by_hint)!r}); a fallback must always "
                "resolve to a registered client."
            )

    def resolve_hint(self, requested: str) -> str:
        """Return the hint that ``submit`` would actually dispatch on.

        Useful for telemetry / journal annotation: callers can record
        whether the orchestrator honored the planner's request or fell
        back to a different image.
        """
        if requested in self.inner_by_hint:
            return requested
        return self.fallback_hint

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        hint = self.resolve_hint(plan.image_hint)
        return await self.inner_by_hint[hint].submit(plan)


# ---------------------------------------------------------------------------
# Trace logging wrapper — captures (plan, trace) pairs for analysis
# ---------------------------------------------------------------------------


@dataclass
class TraceLoggingSandboxWrapper:
    """Wraps a :class:`SandboxClient` and persists every (plan, trace)
    pair to disk as JSONL. Used for post-hoc fidelity comparison
    between stub and real-sandbox runs (Step 3 deliverable).

    The wrapper does not modify the underlying client's behavior; it
    only observes the trace and writes a record. The orchestrator
    receives the unmodified trace.
    """

    inner: Any  # SandboxClient
    log_path: Path
    sandbox_label: str = "unknown"

    def __post_init__(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.write_text("", encoding="utf-8")

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        started = time.time()
        trace = await self.inner.submit(plan)
        elapsed_s = round(time.time() - started, 3)
        record = {
            "sandbox_label": self.sandbox_label,
            "elapsed_s": elapsed_s,
            "plan": plan.model_dump(),
            "trace": trace.model_dump(),
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
        return trace
