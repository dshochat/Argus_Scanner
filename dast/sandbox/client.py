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
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ConfigDict

log = logging.getLogger("argus.dast.sandbox.client")


SANDBOX_IMAGE_HINTS: tuple[str, ...] = ("lean", "rich_python", "ml_tools")
"""Allowed values for ``SandboxPlan.image_hint`` (DAST-005).

v1.8 P2b — image tier rebalance (was ``minimal/networked/ml_tools``):

  * ``lean`` (DEFAULT) — Python 3.13 stdlib + Node.js + Java JRE +
    bash + coreutils + curl + wget + nc + dnsutils + openssl.
    Network tools are NOT image-gated anymore (network egress is
    a policy-layer concern). Use lean for anything that doesn't
    need a specific Python package preinstalled.
  * ``rich_python`` — superset of lean + commonly-imported Python
    packages preinstalled (requests, numpy, pandas, pillow,
    cryptography, pyyaml, lxml, beautifulsoup4, pycryptodome,
    python-dateutil, chardet). Cuts ``ModuleNotFoundError:infra_stub``
    on the most common imports. Use when the target file imports
    popular third-party libs.
  * ``ml_tools`` — superset of rich_python + transformers, torch
    (CPU), safetensors, huggingface_hub. Use for model-loader
    exploits, pickled ``__reduce__`` payloads in ``torch.load()``,
    malicious safetensors.

The orchestrator passes the plan's hint to ``MultiImageSandboxClient``
which dispatches to the matching inner client. Single-image callers
(stub or single Firecracker image) ignore the hint.
"""


# v1.8 P2b: per-tier memory allocation for Fly Machines. Pre-v1.8 used
# a flat 2048 MB for every plan regardless of image, which was overkill
# for lean (~80 MB idle) and risky for ml_tools (torch.load() on a real
# checkpoint can peak at 1.8-2.2 GB RSS — right on the edge at 2 GB).
#
# The mapping below right-sizes per tier:
#
#   * lean:        1024 MB — Python + Node + shell utilities. Idle RSS
#                  ~50-80 MB; worst-case malicious file ~200-400 MB.
#                  1 GB gives 2-5x headroom while halving the
#                  per-second cost vs the old flat 2 GB.
#   * rich_python: 2048 MB — adds scipy/sklearn/pandas/numpy on top of
#                  lean's content. These have ~200-400 MB import-time
#                  footprint; with file execution it lands in the
#                  600-1200 MB range. 2 GB is the right Goldilocks tier.
#   * ml_tools:    4096 MB — torch + transformers + safetensors are
#                  heavy. torch.load() on a 200 MB checkpoint + the
#                  malicious __reduce__ payload commonly peaks at
#                  1.8-2.5 GB RSS. 4 GB eliminates OOM risk for
#                  legitimate model-loader exploits.
#
# Net cost impact across an average scan (~3-5 plans): roughly zero —
# lean savings offset ml_tools increase. The win is eliminated OOM on
# real torch payloads.
SANDBOX_MEMORY_MB_BY_TIER: dict[str, int] = {
    "lean": 1024,
    "rich_python": 2048,
    "ml_tools": 4096,
}
"""Per-image memory allocation in MB for Fly Machines. Used by
``FirecrackerSandboxClient.submit()`` to right-size each plan's VM."""


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
    # ``lean`` (v1.8 P2b — was ``minimal`` in v1.7) so callers and
    # plans without an explicit hint route to the cheapest tier.
    image_hint: str = "lean"
    # Stub-only context: lets the stub synthesize traces for Phase B
    # hypotheses that aren't in the canned ScenarioMap. Real sandbox
    # ignores this.
    synthesis_context: dict[str, Any] = {}
    # On-disk basename (with extension) used when staging the file at
    # /workspace/<file_name> in the sandbox. Empty falls back to file_id
    # for legacy callers / stub fixtures. Node `require()`, Java class
    # loader, and any extension-routed runtime need the right suffix.
    file_name: str = ""
    # P2a v0.1 (v1.8): list of pip distribution names to pip-install
    # inside the sandbox BEFORE plan commands run. Populated by the
    # orchestrator from the target file's parsed imports (see
    # ``preprocessing.imports.compute_runtime_packages``). Empty list
    # means "no per-scan installs" — the v1.7 / pre-P2a behavior.
    #
    # Security contract: only names extracted from ``import X`` AST
    # nodes flow here; the dast-init.sh hook runs
    # ``pip install --no-deps`` to refuse transitive installs.
    # Stdlib + image-preinstalled names are filtered out before this
    # field is populated, so the list contains only "actual gaps" for
    # the target tier.
    runtime_packages: list[str] = []
    # JS DAST parity (v1.8): list of npm package names to install
    # inside the sandbox BEFORE plan commands run. JS analogue of
    # ``runtime_packages`` — populated by the orchestrator from the
    # target ``.js``/``.mjs``/``.cjs`` file's parsed require() / import
    # statements (see ``preprocessing.js_imports.compute_npm_packages``).
    # Empty list means "no per-scan installs."
    #
    # Security contract: the dast-init.sh hook runs ``npm install
    # --ignore-scripts`` which kills the primary npm RCE vector
    # (postinstall lifecycle hooks). Unlike pip, transitive deps ARE
    # installed — the npm threat model differs from pip's.
    runtime_npm_packages: list[str] = []
    # v15.10 (2026-05-20): when the file under scan belongs to a Python
    # sdist with a PKG-INFO / pyproject.toml declaring its distribution
    # name, set this to that name (e.g., "readme_renderer", "rich_rst").
    # The sandbox client's _partition_env reads this and routes the
    # own-dist install into RUNTIME_PACKAGES_ALLOWLISTED (with-deps)
    # rather than RUNTIME_PACKAGES (no-deps). Fixes the failure mode
    # where readme-renderer / rich-rst BP harness died on
    # ModuleNotFoundError because their transitive deps (pygments,
    # rich_rst._vendor) didn't get installed under --no-deps. The
    # own_dist name is manifest-declared (not attacker input), so
    # installing its declared deps is in-scope and sandbox-contained.
    own_dist_name: str = ""
    # NOTE: Multi-file project staging (v11, 2026-05-17) does NOT live
    # on SandboxPlan. The sibling files don't vary per-plan (every plan
    # for one entry file uses the same siblings), so they ride on the
    # sandbox client's ``additional_files_map`` (keyed by file_id) —
    # same pattern as ``file_content_map``. The runner populates the
    # map once per scan; _build_env looks up plan.file_id at send-time.
    # Keeps the plan self-contained at the schema level + avoids a
    # 9-callsite spread of ``additional_files=...`` across plan-builder
    # constructions.


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
    # File-based transport result. Populated by the orchestrator's
    # ``_parse_log_lines`` when the sandbox entrypoint emits
    # ``probe_result_chunk`` events (one or more) carrying the contents
    # of ``/workspace/argus_probe_result.json``. Chunks are reassembled
    # in order. Trace parsers (parse_behavioral_probe_trace,
    # parse_probe_chain_trace, etc.) prefer this field over
    # ``stdout_excerpt`` for structured-result parsing because stdout
    # is subject to Fly's per-log-line ~4KB truncation cap which
    # silently drops large probe markers. Empty when no chunk events
    # were emitted (sandbox didn't run a probe, harness didn't write
    # to the result file, or running an older image without the
    # file-based transport). Callers fall back to stdout_excerpt in
    # that case for backward compat.
    probe_result_json: str = ""


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
        digest = hashlib.sha256(f"{plan.plan_id}|{plan.hypothesis_id}|{idx}".encode()).hexdigest()[
            :6
        ]
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
                    f"Pattern observed: {cond} at {evid_loc}. "
                    f"Exploit NOT demonstrated. (Stub has no runtime data.)"
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
    oracle_findings = ((oracle_record.get("full_label") or {}).get("analysis") or {}).get(
        "findings"
    ) or []
    oracle_verdict = ((oracle_record.get("full_label") or {}).get("verdict") or {}).get(
        "verdict_label"
    ) or "clean"

    # Two views of the oracle: by L1-style finding ID (sometimes oracles
    # re-emit F### with different numbering), and by CWE+type fingerprint.
    oracle_cwe_set = {
        (f.get("cwe") or "").strip().upper() for f in oracle_findings if isinstance(f, dict)
    }
    oracle_type_set = {
        (f.get("type") or "").strip() for f in oracle_findings if isinstance(f, dict)
    }

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
                        {"action": s.get("action"), "expected_state": s.get("expected_state")}
                        for s in evidence
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


def _partition_env(
    pkgs: list[str], *, own_dist_name: str = ""
) -> dict[str, str]:
    """Partition ``plan.runtime_packages`` into the two env vars
    consumed by ``dast-init.sh`` (P2a v0.3 + v15.10 own_dist routing).

    Splits the input list:
      * names matching ``own_dist_name`` (manifest-declared) →
        ``RUNTIME_PACKAGES_ALLOWLISTED`` (with-deps install). v15.10
        rationale: the own_dist's declared dependencies are part of
        the file's known dependency set, sandbox-contained.
      * names in PYPI_TOP_ALLOWLIST → also ``RUNTIME_PACKAGES_ALLOWLISTED``
      * everything else → ``RUNTIME_PACKAGES`` (no-deps, safe default
        for attacker-controllable import names)

    Returns a dict suitable for spreading into the env block, with
    empty values for groups that have no packages (caller's existing
    filter drops empty values).
    """
    if not pkgs:
        return {"RUNTIME_PACKAGES": "", "RUNTIME_PACKAGES_ALLOWLISTED": ""}
    from preprocessing.imports import partition_runtime_packages

    no_deps, with_deps = partition_runtime_packages(
        pkgs, own_dist_name=own_dist_name or None
    )
    return {
        "RUNTIME_PACKAGES": " ".join(no_deps),
        "RUNTIME_PACKAGES_ALLOWLISTED": " ".join(with_deps),
    }


def _npm_env(pkgs: list[str]) -> dict[str, str]:
    """Build the ``RUNTIME_NPM_PACKAGES`` env var for JS DAST parity.

    Unlike the pip partition, there's no allowlist split for npm —
    the security model is different (postinstall scripts are the
    attack vector, not transitive deps), and ``--ignore-scripts`` in
    the dast-init.sh hook covers it.

    Returns a single-key dict so the caller can spread it into the env
    block; empty value when the list is empty (caller's filter drops
    empty values).
    """
    return {"RUNTIME_NPM_PACKAGES": " ".join(pkgs) if pkgs else ""}


def _derive_python_module_name(entry_rel_path: str) -> str:
    """Convert a sibling-resolver entry-rel path into a Python dotted
    module name suitable for ``import`` statements.

    Examples::

        jsonpickle/unpickler.py        -> jsonpickle.unpickler
        jsonpickle/ext/yaml.py         -> jsonpickle.ext.yaml
        flat_module.py                 -> ""    (no package context — caller
                                                 falls back to file path)
        src/pkg/sub/mod.py             -> src.pkg.sub.mod  (rare: tracked
                                                 from project root, but
                                                 reflects on-disk layout
                                                 after staging)

    Returns the empty string when the input is empty, doesn't end in
    ``.py``, or contains no path separator (the entry is a flat file
    at the workspace root — no package import needed).

    Defensive: Python's import system rejects identifiers that start
    with a digit, contain hyphens, or are reserved keywords. When the
    derived dotted name has any invalid segment we return empty to
    let the planner fall back to file-path execution rather than emit
    an obviously-broken ``import`` statement.
    """
    if not entry_rel_path or not entry_rel_path.endswith(".py"):
        return ""
    # POSIX normalize — runner.py already replaces "\\" with "/" but
    # be defensive.
    posix = entry_rel_path.replace("\\", "/").lstrip("./")
    if "/" not in posix:
        # Flat file at workspace root — no package context, planner
        # uses python3 /workspace/$FILE_NAME pattern instead.
        return ""
    stem = posix[:-3]  # strip .py
    # ``pkg/__init__.py`` → ``pkg`` (importing the package directly is
    # the idiomatic form; ``import pkg.__init__`` works but is unusual
    # and may confuse the planner LLM into thinking ``__init__`` is a
    # submodule).
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    parts = stem.split("/")
    if not parts:
        return ""
    # Validate every segment as a Python identifier. Use a conservative
    # check: ASCII letters, digits (not first char), underscore.
    for seg in parts:
        if not seg or seg[0].isdigit():
            return ""
        for ch in seg:
            if not (ch.isalnum() or ch == "_"):
                return ""
    return ".".join(parts)


def _pack_additional_files(additional_files: dict[str, bytes]) -> str:
    """Pack sibling project files into a single base64-encoded tar.gz.

    Multi-file project staging (v10, 2026-05-17). When the orchestrator
    resolves sibling files via ``preprocessing.sibling_files`` and
    attaches them to ``SandboxPlan.additional_files``, this helper
    serialises them into the single env var Fly machines accept
    (``ADDITIONAL_FILES_TARGZ_B64``).

    Returns ``""`` when ``additional_files`` is empty so the caller's
    ``v != ""`` filter drops the env var entirely (back-compatible with
    pre-v10 dast-init.sh that doesn't know about this var).

    Tar format chosen over per-file env vars for three reasons:
      1. **Cardinality**: Fly env vars have a per-machine count limit;
         packing N files into one var dodges that ceiling.
      2. **Path preservation**: tar stores the relative path natively
         so dast-init.sh just runs ``tar xzf`` — no per-file ``mkdir
         -p && echo $base64 | base64 -d > path`` loop on the shell
         side.
      3. **Atomicity**: extraction is one step; either all files land
         or none. Avoids half-staged states.

    The tar is created in-memory (no temp file) and bounded by the
    upstream resolver's MAX_SIBLING_FILES + MAX_SIBLING_BYTES caps —
    we don't need to re-validate sizes here.
    """
    if not additional_files:
        return ""
    import io  # noqa: PLC0415
    import tarfile  # noqa: PLC0415
    import time  # noqa: PLC0415

    buf = io.BytesIO()
    mtime = int(time.time())
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tf:
        for rel_path, content in additional_files.items():
            info = tarfile.TarInfo(name=rel_path)
            info.size = len(content)
            info.mtime = mtime
            info.mode = 0o644
            info.type = tarfile.REGTYPE
            tf.addfile(info, io.BytesIO(content))
    return base64.b64encode(buf.getvalue()).decode("ascii")


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
    # Multi-file project staging map (v11, 2026-05-17). Mirrors
    # file_content_map's pattern: keyed by file_id, value is the dict
    # of sibling project files (relative_path → bytes) the runner
    # resolved via ``preprocessing.sibling_files.resolve_sibling_files``.
    # _build_env packs them into ADDITIONAL_FILES_TARGZ_B64 env var;
    # dast-init.sh (v11+) extracts to /workspace preserving structure.
    #
    # Empty dict for a given file_id (the default lookup result via
    # .get(..., {})) means single-file mode — back-compat preserved.
    additional_files_map: dict[str, dict[str, bytes]] = field(default_factory=dict)
    # Entry-rel-path map (v12, 2026-05-17). Companion to
    # additional_files_map: for multi-file projects, the entry file
    # itself needs to be staged under its rel-from-project-root path
    # (not just /workspace/<basename>) so parent-dir imports
    # (``import "../chains/foo.js"``) resolve correctly at runtime
    # — the entry's parent in the sandbox must be a real subdir of
    # /workspace so ``..`` doesn't escape.
    #
    # Keyed by file_id. Value is the entry's rel-from-root path as
    # a forward-slash string (e.g., ``"src/tools/sql.ts"``).
    # Absent / empty for single-file scans → dast-init falls back to
    # /workspace/<FILE_NAME> (v11 behavior).
    entry_rel_path_map: dict[str, str] = field(default_factory=dict)
    flyctl_path: str | None = None
    # Boot overhead is the headroom we add to plan.timeout_sec when
    # asking Fly to wait for state=stopped. Fly's API caps wait at 60s
    # total, so we cap the request internally; if a plan genuinely
    # needs longer than 60s, fall back to polling get_machine.
    boot_overhead_s: int = 15
    fly_wait_max_s: int = 60  # API hard cap
    # When Fly's wait_for_state hits its 60s API cap, fall back to
    # polling get_machine for up to this many EXTRA seconds. Needed
    # for plans whose dast-init.sh step exceeds 60s — typically large
    # ``--enable-per-scan-dep-install`` invocations (e.g.,
    # ``flowise-components`` pulls a heavy transitive npm tree).
    # Without this, large-dep scans deterministically came back as
    # ``is_stub_no_trace=true`` with rejection_reason
    # ``FlyMachinesError(deadline_exceeded)``. 240s extra = 5 minutes
    # total budget for the slowest plans.
    long_poll_extra_s: int = 240
    # Interval between get_machine polls during the extra-budget
    # fallback. 5s = 48 polls over 240s, well under Fly's per-minute
    # rate limit but tight enough to catch a finish within 5s of
    # completion.
    long_poll_interval_s: float = 5.0
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
            raise FlyMachinesError("flyctl releases timed out")
        if proc.returncode != 0:
            err = stderr_b.decode("utf-8", errors="replace")[:400]
            raise FlyMachinesError(f"flyctl releases failed: {err}")
        try:
            data = json.loads(stdout_b.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as e:
            raise FlyMachinesError(f"flyctl releases JSON parse: {e}")
        if not isinstance(data, list) or not data:
            raise FlyMachinesError(
                f"flyctl releases returned no rows for app "
                f"{self.fly_client.app_name!r} — has it ever been deployed?"
            )
        # First record is the most recent release.
        latest = data[0] if isinstance(data[0], dict) else {}
        ref = latest.get("ImageRef") or latest.get("imageRef") or ""
        if not ref or ":" not in ref:
            raise FlyMachinesError(f"flyctl releases returned no usable ImageRef: {latest!r}")
        self._resolved_image = ref
        return self._resolved_image

    async def _wait_for_machine_terminal(
        self,
        *,
        machine_id: str,
        instance_id: str,
        plan_timeout_sec: int,
    ) -> None:
        """Wait for a Fly machine to reach state ∈ {stopped, destroyed}.

        Fly's ``wait_for_state`` REST endpoint caps the timeout
        parameter at 60s (server-side hard limit). For plans that
        need longer — typically ``--enable-per-scan-dep-install``
        with a large npm tree (`flowise-components` etc.) — we fall
        back to polling ``get_machine`` every
        :data:`long_poll_interval_s` seconds until the machine
        reaches a terminal state OR the extended budget exhausts.

        The total wait budget is::

            plan_timeout_sec + boot_overhead_s + long_poll_extra_s

        The first ``min(requested, 60)`` seconds go through Fly's
        wait endpoint (single API call). After it returns "still
        running," we shift to polling for the remainder. Worst-
        case latency: ``long_poll_interval_s`` (the poll cadence).

        Raises:
          FlyMachinesError when the machine enters a failed state
          OR when the full budget exhausts without reaching a
          terminal state. The caller (``submit``) catches this and
          surfaces it as ``stderr_excerpt="firecracker_error: ..."``
          on the returned :class:`SandboxTrace`.
        """
        requested = plan_timeout_sec + self.boot_overhead_s
        wait_s = min(requested, self.fly_wait_max_s)
        try:
            await self.fly_client.wait_for_state(
                machine_id=machine_id,
                instance_id=instance_id,
                target_state="stopped",
                timeout_s=wait_s,
            )
            return
        except FlyMachinesError as e:
            # Non-timeout failures (network, 5xx, etc.) propagate
            # immediately. Only "still-running" / timeout errors fall
            # through to the long-poll path. Fly returns several
            # equivalent phrasings — match all of them.
            msg = str(e).lower()
            timeout_markers = (
                "timeout",
                "deadline",          # "deadline_exceeded" / "deadline exceeded"
                "still has not reached",
                "did not reach",
                "still running",
            )
            if not any(m in msg for m in timeout_markers):
                raise

        # Long-poll fallback: keep polling get_machine until terminal
        # state or the extended budget exhausts. We've already burned
        # ``wait_s`` seconds on the API wait; the remaining budget is
        # the operator-configurable ``long_poll_extra_s``.
        budget_end = time.monotonic() + self.long_poll_extra_s
        while time.monotonic() < budget_end:
            await asyncio.sleep(self.long_poll_interval_s)
            try:
                state_info = await self.fly_client.get_machine(machine_id)
            except FlyMachinesError as e:
                # Transient API errors during poll shouldn't abort —
                # log and retry the next tick. A persistent failure
                # will surface when budget exhausts.
                # log import lives at module level; use it via name.
                # Defensive: bail if the error indicates the machine
                # is permanently gone (404).
                if "404" in str(e):
                    raise
                continue
            state = state_info.get("state")
            if state in {"stopped", "destroyed"}:
                return
            if state == "failed":
                raise FlyMachinesError(
                    f"machine {machine_id} entered failed state during "
                    f"long-poll: {state_info!r}"
                )
            # Other states (created, starting, started, stopping) →
            # keep polling.

        raise FlyMachinesError(
            f"machine {machine_id} did not reach stopped within "
            f"{self.fly_wait_max_s + self.long_poll_extra_s}s "
            f"(plan_timeout={plan_timeout_sec}s); per-scan dep "
            f"install or harness execution likely exceeded the "
            f"per-plan budget."
        )

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        env = self._build_env(plan)
        machine_name = f"plan-{StubSandboxClient.trace_key(plan)}"
        machine: dict[str, Any] | None = None
        try:
            image = await self._resolve_image()
            # v1.8 P2b: per-tier memory allocation. See
            # SANDBOX_MEMORY_MB_BY_TIER for the rationale. Falls back to
            # 2048 (the v1.7 flat default) if the plan's hint isn't in
            # the table — defensive against future tier additions that
            # forget to update the map.
            memory_mb = SANDBOX_MEMORY_MB_BY_TIER.get(plan.image_hint, 2048)
            machine = await self.fly_client.create_machine(
                image=image,
                env=env,
                name=machine_name,
                cpus=1,
                memory_mb=memory_mb,
                auto_destroy=False,
            )
            machine_id = machine["id"]
            instance_id = machine.get("instance_id") or machine.get("nonce") or ""

            # Wait for the entrypoint to finish executing. Fly's API
            # caps wait at 60s. If the plan needs longer (typically
            # large per-scan dep installs — see
            # ``long_poll_extra_s`` docstring), fall back to polling
            # get_machine until state=stopped/destroyed or the
            # extended budget elapses.
            await self._wait_for_machine_terminal(
                machine_id=machine_id,
                instance_id=instance_id,
                plan_timeout_sec=plan.timeout_sec,
            )

            # Retrieve stdout (which contains JSON event lines from entrypoint.py)
            log_lines = await self._get_logs(machine_id)
            (
                events,
                exit_code,
                stdout_excerpt,
                stderr_excerpt,
                elapsed_ms,
                probe_result_json,
            ) = self._parse_log_lines(log_lines, plan)
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
                probe_result_json=probe_result_json,
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

        # v1.9.2 debug: log multi-file staging state per plan so we can
        # verify the sibling tarball + entry-rel-path are actually being
        # shipped to the sandbox. Costs nothing — env_build is per-plan
        # not per-event. Remove once smoke confirms.
        try:
            import sys as _sys  # noqa: PLC0415
            _siblings = self.additional_files_map.get(plan.file_id) or {}
            _erp = self.entry_rel_path_map.get(plan.file_id, "")
            _mod = _derive_python_module_name(_erp)
            print(
                f"[argus.dast.sandbox.debug] build_env "
                f"file_id={plan.file_id[:16]} plan={plan.plan_id} "
                f"siblings={len(_siblings)} entry_rel={_erp!r} "
                f"module_name={_mod!r}",
                file=_sys.stderr,
            )
        except Exception:
            pass

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
            "EXPECTED_EVIDENCE": (ctx.get("expected_evidence") if isinstance(ctx, dict) else "")
            or "",
            "EXPECTED_PATTERNS": json.dumps(patterns) if patterns else "",
            # P2a (v1.8): list of pip packages to install in the
            # sandbox before plan commands run. Empty (= no install) on
            # plans where the orchestrator chose not to populate
            # runtime_packages — typically lean tier or
            # ``enable_per_scan_dep_install=False``.
            #
            # v0.3 split: ``runtime_packages`` is partitioned by the
            # top-PyPI allowlist into two groups before being shipped
            # to dast-init.sh:
            #   * ``RUNTIME_PACKAGES`` — names NOT in the allowlist;
            #     installed with ``pip install --no-deps`` (v0.1
            #     contract — safe default for attacker-named packages).
            #   * ``RUNTIME_PACKAGES_ALLOWLISTED`` — names in the
            #     curated allowlist; installed with full transitive
            #     resolution, since we trust those packages'
            #     maintainer-declared dep graphs.
            #
            # Old images without the v0.3 init.sh hook ignore the
            # ``_ALLOWLISTED`` var and behave like v0.1 (everything
            # goes through ``RUNTIME_PACKAGES``+ --no-deps), so the
            # rollout is back-compatible. Names are validated shell-
            # safe before they reach here (see
            # ``preprocessing.imports._is_safe_pkg_name``).
            **_partition_env(
                plan.runtime_packages,
                own_dist_name=getattr(plan, "own_dist_name", "") or "",
            ),
            # JS DAST parity (v1.8): npm packages for .js/.mjs/.cjs
            # targets. dast-init.sh installs with --ignore-scripts to
            # neutralize the primary npm threat (postinstall hooks).
            # Old images ignore this env var; the dast-init.sh update
            # rolls in the same image rebuild as the v0.3 pip split.
            **_npm_env(plan.runtime_npm_packages),
            # Multi-file project staging (v11, 2026-05-17): tar.gz of
            # sibling project files keyed by path relative to entry
            # file's directory. dast-init.sh extracts to /workspace
            # (preserving structure) so the entry's relative imports
            # resolve at runtime. Old images without the v11 dast-init.sh
            # update ignore this env var; the staged single file at
            # /workspace/<FILE_NAME> still works (v10 single-file flow
            # unchanged). Empty when no siblings — caller's filter drops.
            #
            # additional_files_map is keyed by plan.file_id (same
            # pattern as file_content_map above) and populated by the
            # runner once per scan; every plan for that file_id sees
            # the same sibling set.
            "ADDITIONAL_FILES_TARGZ_B64": _pack_additional_files(
                self.additional_files_map.get(plan.file_id, {})
            ),
            # v12 (2026-05-17): entry-rel-path. When set, dast-init.sh
            # stages the entry file at /workspace/<ENTRY_REL_PATH>
            # instead of /workspace/<FILE_NAME>. Empty / unset →
            # v11 behavior (entry at /workspace/<FILE_NAME>). Honored
            # only by v12+ dast-init; older images ignore the var.
            "ENTRY_REL_PATH": self.entry_rel_path_map.get(plan.file_id, ""),
            # v1.9.2: package-qualified Python module name derived from
            # ENTRY_REL_PATH. Set whenever the entry file lives in a
            # Python package subdir (e.g. ``jsonpickle/unpickler.py``)
            # — derived as ``jsonpickle.unpickler``. Plans that import
            # a package member MUST use this dotted form, not the bare
            # basename, otherwise relative-import statements
            # (``from . import ...``) inside the entry file fail with
            # ImportError. Empty when entry is a flat file at /workspace
            # root or the sibling resolver didn't run.
            "MODULE_NAME": _derive_python_module_name(
                self.entry_rel_path_map.get(plan.file_id, "")
            ),
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
        for attempt in range(self.log_retrieval_retries):
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
                if any(
                    '"event_id": "evt-final"' in m or '"kind": "execution_complete"' in m
                    for m in messages
                ):
                    return messages
            delay *= 1.3
        return last_messages

    def _parse_log_lines(
        self, log_messages: list[str], plan: SandboxPlan
    ) -> tuple[list[SandboxEvent], int | None, str, str, int, str]:
        """Parse the per-message strings returned by :meth:`_get_logs`.

        Each ``log_messages[i]`` is the ``message`` field from a flyctl
        log JSON entry — one stdout line from the entrypoint. Most are
        JSON-encoded events; some are Fly init noise (e.g. "Machine
        created and started in 4.487s") which we skip silently.

        Returns: (events, exit_code, stdout_excerpt, stderr_excerpt,
        elapsed_ms, probe_result_json).

        ``probe_result_json`` is the reassembled contents of
        ``/workspace/argus_probe_result.json`` from the sandbox,
        delivered via ``probe_result_chunk`` events. Bypasses Fly's
        per-log-line truncation that silently clips large
        ``process_exit.stdout_excerpt`` payloads. Empty string when no
        chunk events were emitted (older image without the file-based
        transport, or harness didn't write to the result file).
        """
        events: list[SandboxEvent] = []
        stdout_pieces: list[str] = []
        stderr_pieces: list[str] = []
        exit_code: int | None = None
        elapsed_ms: int = 0
        # Step-keyed chunks: {(step_idx) -> {chunk_idx -> content, total: N}}
        # Most plans have a single step (or two: write + exec). We
        # reassemble per-step then concat in step order. In practice
        # only the EXEC step writes a probe result file, so this is
        # almost always a single contiguous payload.
        probe_chunks_by_step: dict[int, dict[int, str]] = {}
        probe_total_by_step: dict[int, int] = {}

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
            elif kind == "probe_result_chunk":
                step = int(payload.get("step") or 0)
                idx = int(payload.get("chunk_index") or 0)
                total = int(payload.get("total_chunks") or 0)
                content = str(payload.get("content") or "")
                probe_chunks_by_step.setdefault(step, {})[idx] = content
                if total:
                    probe_total_by_step[step] = total
            elif kind == "execution_complete":
                elapsed_ms = int(payload.get("elapsed_ms") or 0)

        # Reassemble probe result. Concat in step order; within each
        # step, concat chunks in index order. Missing chunks (e.g.,
        # one of the events was lost) leave a gap — log a diagnostic
        # but emit what we have so the trace parser can still attempt
        # to recover. JSON loads from the parser side will fail on
        # truncated content, which is the correct downstream signal
        # (the parser returns an empty profile).
        probe_result_parts: list[str] = []
        for step in sorted(probe_chunks_by_step.keys()):
            chunks = probe_chunks_by_step[step]
            total = probe_total_by_step.get(step, len(chunks))
            for idx in range(total):
                if idx in chunks:
                    probe_result_parts.append(chunks[idx])
                # Missing chunk: skip — parser will fail to load and
                # caller falls back to stdout. Diagnostic is the
                # discrepancy between received and expected chunk
                # counts which downstream operators can spot.
        probe_result_json = "".join(probe_result_parts)

        return (
            events,
            exit_code,
            "\n".join(stdout_pieces)[:2000],
            "\n".join(stderr_pieces)[:2000],
            elapsed_ms,
            probe_result_json,
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
    # P2a v0.2 (v1.8): when True, ``submit()`` populates
    # ``plan.runtime_packages`` for plans whose builder didn't set it
    # AND whose ``image_hint`` is in {rich_python, ml_tools}. Orchestrator
    # mutates this at run_dast entry from cfg.enable_per_scan_dep_install.
    # Default False keeps tests / stub callers unaffected.
    enable_per_scan_dep_install: bool = False

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
        # P2a v0.2: centralized fallback + tier auto-bump.
        #
        # The flow is two-step:
        #   1. If dep install is enabled AND plan-builder didn't already
        #      populate runtime_packages, compute it for ALL tiers (lean
        #      included). lean's preinstalled-filter inside
        #      runtime_packages_for_plan returns [] for it pre-hotfix;
        #      we run the full compute here regardless so we can decide
        #      whether to bump.
        #   2. If runtime_packages comes back non-empty AND plan was
        #      going to lean tier, AUTO-BUMP to rich_python. Rationale:
        #      Sonnet's plan-time tier selection isn't reliable (the
        #      Fly logs from a P2a v0.2 e2e scan showed Sonnet picking
        #      lean for a file with `import selenium` → install never
        #      fires → ModuleNotFoundError). Auto-bumping preserves
        #      lean's "minimal" identity in the common case while
        #      fixing the under-classification corner.
        #
        # This single instrumentation point covers EVERY plan path:
        # Phase A iter, Phase B+ runtime probe (incl. mutation +
        # iterative + chains variants), Phase 3 Stage 1 behavioral
        # probe, Phase 3 Stage 2 (single_function / stateful_sequence /
        # probe kinds), and any future plan-builder we add.
        if self.enable_per_scan_dep_install and (
            not plan.runtime_packages and not plan.runtime_npm_packages
        ):
            # Inner FirecrackerSandboxClient holds file_content_map.
            # Pull from the inner client that would actually serve this
            # plan (matches plan.image_hint, falls back same way submit
            # would).
            hint_for_lookup = self.resolve_hint(plan.image_hint)
            inner_for_lookup = self.inner_by_hint[hint_for_lookup]
            content_map = getattr(inner_for_lookup, "file_content_map", {})
            file_bytes = (
                content_map.get(plan.file_id, b"") if isinstance(content_map, dict) else b""
            )
            if file_bytes:
                # Dual-language dispatch: detect by extension and route
                # to the appropriate dep-extraction helper. Python and
                # JS share the same auto-bump pattern (lean targets with
                # non-empty install lists graduate to rich_python so
                # the install hook actually runs against a tier that
                # supports it).
                fn_lower = (plan.file_name or "").lower()
                is_python = fn_lower.endswith((".py", ".pth"))
                # v10 (2026-05-16): TS extensions added so the same npm
                # dep extractor runs against TypeScript files. TS uses
                # the same ``import`` syntax as JS, so
                # ``extract_js_imports`` works as-is on .ts/.tsx source.
                # Note: we deliberately do NOT auto-bump TS plans from
                # lean → rich_python below (unlike the JS branch).
                # rich_python lacks the lean tier's pre-installed npm
                # package block AND the tsx binary, so bumping would
                # strand TS files with no transpiler. lean is the right
                # tier for TS; npm install hook still runs there.
                is_js = fn_lower.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx"))

                if is_python:
                    from preprocessing.imports import runtime_packages_for_plan

                    # Compute against rich_python's preinstalled set so
                    # the filter is consistent regardless of the plan's
                    # original tier (otherwise lean plans always return
                    # [] because the helper bails on lean). If we end up
                    # bumping, the tier we bump TO is rich_python, so
                    # its preinstalled set is the right filter to apply.
                    computed_pkgs = runtime_packages_for_plan(
                        file_bytes=file_bytes,
                        file_name=plan.file_name,
                        image_hint="rich_python"
                        if plan.image_hint == "lean"
                        else plan.image_hint,
                        enabled=True,
                    )
                    if computed_pkgs:
                        plan.runtime_packages = computed_pkgs
                        # Auto-bump: lean plans with real install needs
                        # graduate to rich_python.
                        if plan.image_hint == "lean":
                            plan.image_hint = "rich_python"
                elif is_js:
                    from preprocessing.js_imports import (
                        HeavyDepRefused,
                        compute_npm_packages,
                        npm_packages_for_plan,
                    )

                    # npm helper has no tier-gate — Node/npm are in
                    # ``lean`` already, install works on any tier. But
                    # we still auto-bump lean → rich_python for
                    # consistency with the Python path and to give JS
                    # targets the larger memory budget (rich_python =
                    # 2GB vs lean = 1GB) when they actually exercise
                    # npm-installed code paths.
                    #
                    # v1.9 — heavy-denylist: if the entry file OR any
                    # staged sibling imports a known-too-heavy package
                    # (flowise-components, @n8n/*, etc.), refuse fast
                    # by returning a stub trace with a clear rationale.
                    # Before: machines would burn the full 300s wait
                    # budget mid-npm-install, then get killed → 5-10
                    # min wasted per refused plan. After: ~50ms refusal
                    # with the offending package names surfaced.
                    refused_packages: list[str] = []
                    try:
                        computed_npm_set: set[str] = set(
                            npm_packages_for_plan(
                                file_bytes=file_bytes,
                                file_name=plan.file_name,
                                enabled=True,
                            )
                        )
                    except HeavyDepRefused as exc:
                        refused_packages = list(exc.packages)
                        computed_npm_set = set()

                    # v11 (2026-05-17): also extract npm imports from
                    # SIBLING project files staged via
                    # additional_files_map. mcp-server-filesystem's
                    # ``lib.ts`` imports ``diff`` which the entry file
                    # never references — without sibling extraction
                    # tsx fails at ``Cannot find package 'diff'`` even
                    # though sibling staging itself worked.
                    addl_map = getattr(inner_for_lookup, "additional_files_map", {})
                    siblings = (
                        addl_map.get(plan.file_id, {})
                        if isinstance(addl_map, dict)
                        else {}
                    )
                    for sibling_rel, sibling_bytes in siblings.items():
                        sib_lower = sibling_rel.lower()
                        if not (
                            sib_lower.endswith(".js")
                            or sib_lower.endswith(".mjs")
                            or sib_lower.endswith(".cjs")
                            or sib_lower.endswith(".ts")
                            or sib_lower.endswith(".tsx")
                        ):
                            continue
                        try:
                            sib_source = sibling_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            continue
                        try:
                            for pkg in compute_npm_packages(sib_source):
                                computed_npm_set.add(pkg)
                        except HeavyDepRefused as exc:
                            # Sibling files can also pull heavy
                            # transitives. Refuse for the whole plan;
                            # surface every package found across entry
                            # + siblings.
                            for p in exc.packages:
                                if p not in refused_packages:
                                    refused_packages.append(p)

                    # If any heavy package was refused (entry or
                    # sibling), short-circuit with a clear stub trace
                    # BEFORE we hand off to the underlying sandbox
                    # client. The trace's ``stderr_excerpt`` carries
                    # the structured refusal reason so downstream
                    # per_finding_validation can render it as
                    # ``not_tested_reason='heavy_dependency_refused'``
                    # with the offending packages in the rationale.
                    if refused_packages:
                        log.info(
                            "DAST refusing plan %s for %s: imports "
                            "heavy package(s) %s exceeding 180s npm "
                            "install budget",
                            plan.plan_id,
                            plan.file_name,
                            refused_packages,
                        )
                        return SandboxTrace(
                            plan_id=plan.plan_id,
                            file_id=plan.file_id,
                            hypothesis_id=plan.hypothesis_id,
                            events=[],
                            exit_code=None,
                            stdout_excerpt="",
                            stderr_excerpt=(
                                f"heavy_dependency_refused: file imports "
                                f"{refused_packages} which exceed the "
                                f"180s npm install budget. Override "
                                f"with ARGUS_NPM_HEAVY_DENYLIST_DISABLE="
                                f"true or ARGUS_NPM_HEAVY_DENYLIST_"
                                f"REMOVE={','.join(refused_packages)}."
                            ),
                            elapsed_ms=0,
                            is_stub_no_trace=True,
                            stub_synthesis_note=(
                                f"refused fast — heavy npm deps "
                                f"{refused_packages}"
                            ),
                        )
                    computed_npm = sorted(computed_npm_set)
                    if computed_npm:
                        plan.runtime_npm_packages = computed_npm
                        # Auto-bump rule. For JS targets, we bump lean
                        # → rich_python to get more memory. For TS, we
                        # MUST NOT bump — rich_python doesn't have tsx
                        # installed (the v10 npm install block only
                        # runs in Dockerfile.lean) and lacks the
                        # pre-installed npm packages too. Bumping a TS
                        # plan strands it with no transpiler. Future
                        # follow-up: replicate the npm install block
                        # + tsx symlink to rich_python's Dockerfile so
                        # the bump is safe across both languages.
                        is_ts = fn_lower.endswith((".ts", ".tsx"))
                        if plan.image_hint == "lean" and not is_ts:
                            plan.image_hint = "rich_python"

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
