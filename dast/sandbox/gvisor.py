"""Sandbox client — gVisor (local Docker + ``runsc``) implementation.

Self-hosted DAST substrate. This is the recommended default when Argus
runs in a customer's own environment (no Fly.io dependency, no egress to
a managed cloud). It satisfies the same :class:`SandboxClient` Protocol
as :class:`~dast.sandbox.client.FirecrackerSandboxClient`, so the
orchestrator, the multi-image dispatcher, and every trace parser are
unchanged regardless of which substrate is wired in.

Why gVisor
----------
``runsc`` (gVisor) is a user-space kernel that intercepts the container's
syscalls and services them in a sandboxed process, so a sandbox escape
must defeat gVisor's netstack + sentry rather than the host kernel
directly. It needs no nested virtualisation (KVM optional via the
``systrap`` platform), installs as an apt package, and registers as an
OCI runtime Docker dispatches to with ``--runtime=runsc``. That makes it
deployable on a stock Kubernetes node (via a ``RuntimeClass``) or a plain
Docker host — the two environments customers actually have.

Same image, same contract
-------------------------
The sandbox **image** is byte-for-byte the one the Firecracker path uses
(``dast/sandbox/firecracker/Dockerfile.*``): a normal OCI image whose
``ENTRYPOINT`` runs ``dast-init.sh`` → capture server → privilege drop →
``entrypoint.py``. The in-VM **env contract** (:func:`build_sandbox_env`)
and the **event-log parser** (:func:`parse_sandbox_log_lines`) are shared
verbatim with the Fly client, so verdicts cannot drift between the hosted
and self-hosted runtimes. The only thing that changes here is the launch
mechanism: instead of the Fly Machines API (create → wait → flyctl logs →
destroy) we ``docker run`` the container and read its stdout directly —
which is strictly simpler, because Docker hands us the entrypoint's stdout
with no NATS-flush retries or per-machine log filtering.

Egress control
--------------
The default network mode is ``none``: the container gets only a loopback
interface, so there is **no real egress at all**. That dovetails with the
sandbox's DNS-hijack design — ``dast-init.sh`` rewrites
``/etc/resolv.conf`` to ``127.0.0.1`` and the capture server binds
``127.0.0.1:53/80/443``, so every outbound hostname the target resolves
goes to the in-VM capture server (logged, never sent), and any attempt to
reach a raw routable IP simply fails with "network unreachable" (surfaced
as a ``network_call`` blocked event). This is the same observable
behaviour as the Fly app (which declares no services), with a stronger
guarantee: the kernel-level interface is genuinely absent. The mode is
configurable (``network=``) for operators who want an allowlisted egress
bridge, but ``none`` is the secure production default.

Isolation note
--------------
``runsc`` is the trust boundary here, so this client does **not** strip
the container's Linux capabilities or set ``no-new-privileges``:
``dast-init.sh`` legitimately needs ``CAP_NET_BIND_SERVICE`` (bind the
privileged capture ports) and ``CAP_SETUID``/``CAP_SETGID`` (the
``runuser`` privilege drop to the ``runner`` user). Even if a target
escalated back to root *inside* the container, it would still be confined
by gVisor and by ``--network=none``. Resource bounds (``--memory``,
``--cpus``, ``--pids-limit``, swap disabled) are applied as
defence-in-depth against local DoS.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .client import (
    SANDBOX_MEMORY_MB_BY_TIER,
    SandboxPlan,
    SandboxTrace,
    StubSandboxClient,
    build_sandbox_env,
    parse_sandbox_log_lines,
)

log = logging.getLogger("argus.dast.sandbox.gvisor")


class DockerError(RuntimeError):
    """Raised when the docker CLI is unavailable or returns unexpectedly."""


def find_docker() -> str | None:
    """Locate the ``docker`` binary on PATH (None if absent)."""
    return shutil.which("docker")


def _last_unfinished_step(events: list[Any]) -> int | None:
    """The plan step that was running when the container hung: the highest
    ``process_spawn`` step with no matching ``process_exit`` /
    ``process_timeout``. Lets a timeout trace name the offending command."""
    spawned: set[int] = set()
    finished: set[int] = set()
    for e in events:
        payload = getattr(e, "payload", {}) or {}
        step = payload.get("step")
        if not isinstance(step, int):
            continue
        kind = getattr(e, "kind", None)
        if kind == "process_spawn":
            spawned.add(step)
        elif kind in ("process_exit", "process_timeout"):
            finished.add(step)
    unfinished = spawned - finished
    return max(unfinished) if unfinished else None


async def gvisor_preflight(
    *, docker_path: str | None = None, runtime: str = "runsc", timeout_s: float = 20.0
) -> tuple[bool, str]:
    """Cheap one-shot check that Docker is up and ``runtime`` is registered.

    Returns ``(ok, detail)``. ``detail`` is a human-readable reason on
    failure (surfaced by the runner so a misconfigured host fails fast
    with an actionable message instead of every plan erroring opaquely).
    Does NOT pull or run an image — it only parses ``docker info``.
    """
    docker = docker_path or find_docker()
    if not docker:
        return False, "docker binary not found on PATH"
    try:
        proc = await asyncio.create_subprocess_exec(
            docker,
            "info",
            "--format",
            "{{json .Runtimes}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        return False, f"`docker info` timed out after {timeout_s}s (daemon not responding?)"
    except OSError as e:
        return False, f"failed to exec docker: {e}"
    if proc.returncode != 0:
        return False, f"`docker info` failed: {err_b.decode('utf-8', 'replace')[:200]}"
    runtimes_json = out_b.decode("utf-8", "replace")
    if runtime not in runtimes_json:
        return (
            False,
            f"docker runtime {runtime!r} not registered (found: {runtimes_json.strip()}). "
            f"Install gVisor and run `runsc install` + restart docker.",
        )
    return True, f"docker ok; runtime {runtime!r} registered"


@dataclass
class DockerGvisorSandboxClient:
    """Real sandbox via local Docker + a gVisor (``runsc``) runtime.

    Per plan: ``docker run --rm --runtime=<runtime> --network=<network>``
    the sandbox image with the plan's env, wait for it to exit, parse its
    stdout into :class:`SandboxEvent` objects. No managed-cloud calls.

    Construction mirrors :class:`FirecrackerSandboxClient`:
        * ``image`` — a LOCAL docker image tag (e.g.
          ``argus-dast-sandbox:lean``) built from
          ``dast/sandbox/firecracker/Dockerfile.lean``. Unlike the Fly
          client there is no ``:latest`` registry resolution — the image
          is whatever the customer built/pulled locally.
        * ``file_content_map`` / ``additional_files_map`` /
          ``entry_rel_path_map`` — populated once per scan by the runner,
          keyed by ``file_id`` (identical semantics to the Fly client).

    Safety / resources:
        * ``--rm`` so the container is removed on exit; a ``finally``
          force-removes by name as a backstop after a kill.
        * Per-plan wall-clock cap = ``plan.timeout_sec + boot_overhead_s
          + long_poll_extra_s`` (the extra budget covers per-scan pip/npm
          installs in ``dast-init.sh``, mirroring the Fly long-poll).
        * Memory right-sized per image tier; swap disabled
          (``--memory-swap`` == ``--memory``); ``--pids-limit`` caps forks.
    """

    image: str
    docker_path: str | None = None
    runtime: str = "runsc"
    network: str = "none"
    file_content_map: dict[str, bytes] = field(default_factory=dict)
    additional_files_map: dict[str, dict[str, bytes]] = field(default_factory=dict)
    entry_rel_path_map: dict[str, str] = field(default_factory=dict)
    cpus: float = 1.0
    pids_limit: int = 512
    # Wall-clock headroom for container start + capture-server bind before
    # the entrypoint begins executing plan commands. gVisor containers
    # start in ~1-2s (no microVM boot), so this is generous.
    boot_overhead_s: int = 20
    # Per-plan deadline is COMPUTED, not flat (unlike the Fly client's
    # long_poll_extra_s). The entrypoint runs each command sequentially
    # capped at plan.timeout_sec, so the legitimate execution ceiling is
    # len(commands) * timeout_sec. The dep-install budget is added ONLY for
    # plans that actually install packages (dast-init.sh runs pip/npm
    # BEFORE the entrypoint). This means a hung NO-install plan is killed in
    # ~boot + n*timeout + drain instead of waiting a flat 240s — see
    # ``_deadline_s``.
    #
    # dep_install_budget_s covers the in-container pip (--no-deps, 60s cap)
    # + npm (--ignore-scripts, 180s cap) installs dast-init.sh performs.
    dep_install_budget_s: int = 200
    # Slack above the command-execution ceiling for the entrypoint's
    # own setup/teardown (file staging, capture-log + probe-result drain).
    drain_headroom_s: int = 30
    # Operator escape hatch: extra `docker run` args injected verbatim
    # before the image (e.g. ("--cpuset-cpus", "0-1") or an egress
    # allowlist setup). Empty by default.
    extra_run_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.docker_path is None:
            self.docker_path = find_docker()

    # ---- helpers ---------------------------------------------------------

    def _build_env(self, plan: SandboxPlan) -> dict[str, str]:
        # Shared with the Fly client — single source of truth for the
        # in-VM env contract (see dast/sandbox/client.build_sandbox_env).
        return build_sandbox_env(
            plan,
            file_content_map=self.file_content_map,
            additional_files_map=self.additional_files_map,
            entry_rel_path_map=self.entry_rel_path_map,
        )

    def _deadline_s(self, plan: SandboxPlan) -> float:
        """Per-plan wall-clock cap for the whole ``docker run``.

        Scales with the plan instead of a flat budget: the entrypoint runs
        each command sequentially under ``plan.timeout_sec``, so the
        legitimate execution ceiling is ``len(commands) * timeout_sec``.
        The dep-install budget is added ONLY when the plan installs
        packages. Net effect: a hung no-install plan is killed promptly
        (≈ boot + n*timeout + drain) rather than after a flat 240s.
        """
        n_cmds = max(1, len(plan.commands))
        exec_budget = n_cmds * plan.timeout_sec
        needs_install = bool(plan.runtime_packages or plan.runtime_npm_packages)
        install_budget = self.dep_install_budget_s if needs_install else 0
        return float(self.boot_overhead_s + exec_budget + install_budget + self.drain_headroom_s)

    def _build_run_argv(self, plan: SandboxPlan, *, container_name: str, env_keys: list[str]) -> list[str]:
        memory_mb = SANDBOX_MEMORY_MB_BY_TIER.get(plan.image_hint, 2048)
        argv: list[str] = [
            self.docker_path or "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            f"--runtime={self.runtime}",
            f"--network={self.network}",
            f"--memory={memory_mb}m",
            # Disable swap by pinning memory-swap to the memory limit, so
            # a target can't evade the RSS cap by swapping.
            f"--memory-swap={memory_mb}m",
            f"--cpus={self.cpus}",
            f"--pids-limit={self.pids_limit}",
        ]
        argv.extend(self.extra_run_args)
        # Pass each env var BY NAME (`-e KEY`, no value). Docker then
        # inherits the value from THIS process's environment, which we
        # set on the subprocess below. This keeps large values
        # (FILE_CONTENT_B64GZ) and JSON values (PLAN_COMMANDS) out of
        # argv entirely — no "Argument list too long", no shell-quoting
        # hazards. Only the named keys cross into the container; the
        # orchestrator's own secrets in os.environ never get a `-e`.
        for key in env_keys:
            argv.extend(["-e", key])
        argv.append(self.image)
        return argv

    async def _docker_force_remove(self, container_name: str) -> None:
        """Best-effort ``docker rm -f`` (backstop after a kill / crash)."""
        if not self.docker_path:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                self.docker_path,
                "rm",
                "-f",
                container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=15.0)
        except Exception:
            pass

    async def _docker_logs(self, container_name: str) -> str:
        """Fetch a (still-running or stopped) container's stdout+stderr.

        Used on timeout to salvage the entrypoint's partial output BEFORE
        the container is killed — the entrypoint emits JSON events to
        stdout, so this recovers whatever fired before the hang. stderr is
        merged in (dast-init diagnostics). Best-effort; '' on any error.
        """
        if not self.docker_path:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.docker_path,
                "logs",
                container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=20.0)
            return out_b.decode("utf-8", errors="replace")
        except Exception:
            return ""

    # ---- Protocol --------------------------------------------------------

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        if not self.docker_path:
            return self._failure_trace(plan, "docker binary not found on PATH (is Docker installed?)")

        env = self._build_env(plan)
        # Unique per submission so concurrent / retried identical plans
        # never collide on the container name (trace_key is deterministic
        # per plan content, so add a random suffix).
        container_name = f"argus-plan-{StubSandboxClient.trace_key(plan)}-{uuid.uuid4().hex[:8]}"
        argv = self._build_run_argv(plan, container_name=container_name, env_keys=list(env))

        # The docker CLI process inherits our env (so it can read PATH,
        # DOCKER_HOST, etc.) PLUS the plan env (so `-e KEY` resolves).
        # Only the keys named in argv via `-e` are forwarded into the
        # container — the rest of os.environ (API keys) is not.
        child_env = {**os.environ, **env}
        deadline_s = self._deadline_s(plan)

        started = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_env,
            )
        except OSError as e:
            return self._failure_trace(plan, f"failed to exec docker: {e}")

        try:
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=deadline_s)
            except asyncio.TimeoutError:
                # The container is STILL RUNNING (it hung) — so grab its
                # output-so-far via `docker logs` BEFORE killing it. A plain
                # kill + empty trace discards everything the entrypoint
                # emitted, which (a) blinds us to WHICH command hung and
                # (b) throws away events that may already prove the finding.
                # Salvaging the partial log turns a blind zero-event timeout
                # into a debuggable, possibly-still-useful trace.
                partial = await self._docker_logs(container_name)
                await self._docker_force_remove(container_name)
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                (
                    ev,
                    exit_code,
                    so,
                    se,
                    elapsed_ms,
                    probe_json,
                ) = parse_sandbox_log_lines(partial.splitlines(), plan)
                if not elapsed_ms:
                    elapsed_ms = int((time.monotonic() - started) * 1000)
                last_cmd = _last_unfinished_step(ev)
                note = (
                    f"gvisor_timeout after {deadline_s:.0f}s "
                    f"(plan_timeout={plan.timeout_sec}s x {len(plan.commands)} cmds"
                    f"{', +dep-install' if (plan.runtime_packages or plan.runtime_npm_packages) else ''}); "
                    f"{len(ev)} partial event(s) salvaged"
                    f"{f'; hung at step {last_cmd}' if last_cmd is not None else ''}"
                )
                return SandboxTrace(
                    plan_id=plan.plan_id,
                    file_id=plan.file_id,
                    hypothesis_id=plan.hypothesis_id,
                    events=ev,
                    exit_code=exit_code,
                    stdout_excerpt=so,
                    stderr_excerpt=(note + (" | " + se if se else ""))[:2000],
                    elapsed_ms=elapsed_ms,
                    is_stub_no_trace=(not ev),
                    stub_synthesis_note=note[:200],
                    probe_result_json=probe_json,
                )

            stdout = stdout_b.decode("utf-8", errors="replace")
            stderr = stderr_b.decode("utf-8", errors="replace")
            rc = proc.returncode

            # The entrypoint prints one JSON event per stdout line; split
            # and hand to the shared parser (identical to the Fly path).
            stdout_lines = stdout.splitlines()
            (
                events,
                exit_code,
                stdout_excerpt,
                stderr_excerpt,
                elapsed_ms,
                probe_result_json,
            ) = parse_sandbox_log_lines(stdout_lines, plan)

            if not elapsed_ms:
                elapsed_ms = int((time.monotonic() - started) * 1000)

            if not events:
                # No events parsed → sandbox-internal failure (init crash,
                # OOM kill rc=137, image missing, runtime not registered).
                # Carry the container's stderr so the operator can debug.
                detail = (stderr or stdout).strip()[:1600]
                stderr_excerpt = (f"gvisor_no_events: docker_rc={rc}\n{detail}").strip()[:2000]

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
                stub_synthesis_note="" if events else "no events captured from container",
                probe_result_json=probe_result_json,
            )
        except Exception as e:  # noqa: BLE001 — mirror Fly client's catch-all
            return self._failure_trace(plan, f"{type(e).__name__}: {str(e)[:300]}")
        finally:
            # Backstop: --rm + kill usually clean up, but force-remove by
            # name in case the container lingered (e.g. daemon hiccup).
            await self._docker_force_remove(container_name)

    def _failure_trace(self, plan: SandboxPlan, reason: str) -> SandboxTrace:
        return SandboxTrace(
            plan_id=plan.plan_id,
            file_id=plan.file_id,
            hypothesis_id=plan.hypothesis_id,
            events=[],
            exit_code=None,
            stdout_excerpt="",
            stderr_excerpt=f"gvisor_error: {reason}",
            elapsed_ms=0,
            is_stub_no_trace=True,
            stub_synthesis_note=f"sandbox call failed: {reason[:120]}",
        )


__all__ = [
    "DockerError",
    "DockerGvisorSandboxClient",
    "find_docker",
    "gvisor_preflight",
]
