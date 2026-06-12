"""Unit tests for the gVisor (local Docker + ``runsc``) sandbox client.

No live Docker: ``asyncio.create_subprocess_exec`` is faked so we assert
on the exact ``docker run`` argv, the env-passthrough isolation property,
stdout→event parsing, the no-events failure path, and the timeout→kill
path. The make-or-break "does gVisor actually run the image" check lives
in the host smoke test, not here — these pin the adapter's contract.
"""

from __future__ import annotations

import asyncio

import pytest

from dast.sandbox.client import SandboxPlan, SandboxTrace
from dast.sandbox.gvisor import DockerGvisorSandboxClient, gvisor_preflight

# ── builders ────────────────────────────────────────────────────────────────


def _plan(**over: object) -> SandboxPlan:
    base: dict[str, object] = dict(
        plan_id="p1",
        file_id="f1",
        hypothesis_id="h1",
        commands=["echo hi"],
        expected_oracle="reached",
        payload="x",
        timeout_sec=30,
        image_hint="lean",
        file_name="t.py",
    )
    base.update(over)
    return SandboxPlan(**base)  # type: ignore[arg-type]


def _client(**over: object) -> DockerGvisorSandboxClient:
    base: dict[str, object] = dict(
        image="argus-dast-sandbox:lean",
        docker_path="/usr/bin/docker",
        file_content_map={"f1": b"print('hi')\n"},
    )
    base.update(over)
    return DockerGvisorSandboxClient(**base)  # type: ignore[arg-type]


# ── fake subprocess plumbing ──────────────────────────────────────────────────


class _FakeProc:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0, hang: bool = False) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self._hang = hang
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        if self._hang:
            await asyncio.sleep(3600)  # force the wait_for timeout
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True


class _DockerSpy:
    """Stand-in for ``asyncio.create_subprocess_exec`` that dispatches on
    the docker subcommand (argv[1]) and records every call."""

    def __init__(self, *, run_proc: _FakeProc | None = None, info_proc: _FakeProc | None = None) -> None:
        self.run_proc = run_proc or _FakeProc()
        self.info_proc = info_proc or _FakeProc(b"{}", b"", 0)
        self.calls: list[tuple[list[str], dict[str, str] | None]] = []

    async def __call__(
        self,
        *argv: str,
        stdout: object = None,
        stderr: object = None,
        env: dict[str, str] | None = None,
    ) -> _FakeProc:
        self.calls.append((list(argv), env))
        sub = argv[1] if len(argv) > 1 else ""
        if sub == "run":
            return self.run_proc
        if sub == "info":
            return self.info_proc
        return _FakeProc(b"", b"", 0)  # rm / kill / anything else

    def run_call(self) -> tuple[list[str], dict[str, str] | None]:
        for argv, env in self.calls:
            if len(argv) > 1 and argv[1] == "run":
                return argv, env
        raise AssertionError("no `docker run` call was recorded")

    def subcommands(self) -> list[str]:
        return [argv[1] for argv, _ in self.calls if len(argv) > 1]


# ── argv shape ────────────────────────────────────────────────────────────────


def test_build_run_argv_core_flags() -> None:
    c = _client()
    argv = c._build_run_argv(_plan(), container_name="cn", env_keys=["PLAN_ID", "FILE_CONTENT_B64GZ"])
    assert argv[:3] == ["/usr/bin/docker", "run", "--rm"]
    assert "--runtime=runsc" in argv
    assert "--network=none" in argv
    assert "--memory=1024m" in argv  # lean tier
    assert "--memory-swap=1024m" in argv  # swap disabled
    assert "--cpus=1.0" in argv
    assert "--pids-limit=512" in argv
    assert argv[-1] == "argus-dast-sandbox:lean"  # image last
    # env passed BY NAME (no value on argv)
    assert "-e" in argv
    assert "PLAN_ID" in argv
    assert "FILE_CONTENT_B64GZ" in argv


def test_build_run_argv_memory_scales_with_tier() -> None:
    c = _client()
    ml = c._build_run_argv(_plan(image_hint="ml_tools"), container_name="cn", env_keys=[])
    rp = c._build_run_argv(_plan(image_hint="rich_python"), container_name="cn", env_keys=[])
    assert "--memory=4096m" in ml and "--memory-swap=4096m" in ml
    assert "--memory=2048m" in rp and "--memory-swap=2048m" in rp


def test_build_run_argv_honors_runtime_network_overrides() -> None:
    c = _client(runtime="runc", network="argus-egress")
    argv = c._build_run_argv(_plan(), container_name="cn", env_keys=[])
    assert "--runtime=runc" in argv
    assert "--network=argus-egress" in argv


def test_extra_run_args_injected_before_image() -> None:
    c = _client(extra_run_args=("--cpuset-cpus", "0-1"))
    argv = c._build_run_argv(_plan(), container_name="cn", env_keys=[])
    assert "--cpuset-cpus" in argv and "0-1" in argv
    assert argv.index("--cpuset-cpus") < argv.index("argus-dast-sandbox:lean")


# ── submit: happy path ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_parses_stdout_events(monkeypatch: pytest.MonkeyPatch) -> None:
    stdout = (
        b'{"event_id":"e1","kind":"execution_start","payload":{"plan_id":"p1"}}\n'
        b'{"event_id":"e2","kind":"process_exit","payload":'
        b'{"step":0,"exit_code":0,"stdout_excerpt":"hello-from-sandbox","stderr_excerpt":""}}\n'
        b"[dast-init] noise that is not json and must be skipped\n"
        b'{"event_id":"evt-final","kind":"execution_complete","payload":{"elapsed_ms":4242}}\n'
    )
    spy = _DockerSpy(run_proc=_FakeProc(stdout=stdout, stderr=b"[dast-init] up", returncode=0))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)

    trace = await _client().submit(_plan())
    assert isinstance(trace, SandboxTrace)
    assert trace.is_stub_no_trace is False
    kinds = [e.kind for e in trace.events]
    assert kinds == ["execution_start", "process_exit", "execution_complete"]
    assert trace.exit_code == 0
    assert trace.elapsed_ms == 4242
    assert "hello-from-sandbox" in trace.stdout_excerpt


@pytest.mark.asyncio
async def test_submit_passes_env_by_name_and_isolates_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An API key in the orchestrator's env must NEVER be forwarded into
    # the container via `-e`, even though the docker CLI inherits it.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    spy = _DockerSpy(run_proc=_FakeProc(stdout=b'{"kind":"execution_complete","payload":{}}\n'))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)

    await _client().submit(_plan())
    argv, env = spy.run_call()

    # The `-e` flags name only the sandbox contract vars.
    e_flag_targets = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
    assert "PLAN_ID" in e_flag_targets
    assert "FILE_CONTENT_B64GZ" in e_flag_targets
    assert "ANTHROPIC_API_KEY" not in e_flag_targets  # the security property

    # The child process env carries the sandbox vars (so `-e KEY` resolves)
    # AND inherits the secret (harmless — it's just not forwarded).
    assert env is not None
    assert env.get("PLAN_ID") == "p1"
    assert env.get("FILE_CONTENT_B64GZ", "")  # non-empty gz payload
    assert env.get("ANTHROPIC_API_KEY") == "sk-ant-secret"


# ── submit: failure paths ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_no_events_is_failure_with_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    spy = _DockerSpy(run_proc=_FakeProc(stdout=b"", stderr=b'Unknown runtime specified "runsc"', returncode=125))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)

    trace = await _client().submit(_plan())
    assert trace.is_stub_no_trace is True
    assert trace.events == []
    assert "gvisor_no_events" in trace.stderr_excerpt
    assert "docker_rc=125" in trace.stderr_excerpt
    assert "Unknown runtime" in trace.stderr_excerpt


@pytest.mark.asyncio
async def test_submit_missing_docker_returns_failure_trace() -> None:
    # docker_path=None → no subprocess attempted, clean failure trace.
    c = _client(docker_path=None)
    trace = await c.submit(_plan())
    assert trace.is_stub_no_trace is True
    assert "docker binary not found" in trace.stderr_excerpt


@pytest.mark.asyncio
async def test_submit_timeout_kills_container(monkeypatch: pytest.MonkeyPatch) -> None:
    # deadline = timeout_sec(0) + boot_overhead_s(0) + long_poll_extra_s(0) = 0
    # → the hanging fake never completes → TimeoutError → kill + rm.
    run_proc = _FakeProc(hang=True)
    spy = _DockerSpy(run_proc=run_proc)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)

    c = _client(boot_overhead_s=0, long_poll_extra_s=0)
    trace = await c.submit(_plan(timeout_sec=0))

    assert trace.is_stub_no_trace is True
    assert "timeout" in trace.stderr_excerpt.lower()
    assert run_proc.killed is True  # the run container process was killed
    assert "rm" in spy.subcommands()  # force-remove backstop fired


# ── preflight ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_preflight_ok_when_runtime_registered(monkeypatch: pytest.MonkeyPatch) -> None:
    spy = _DockerSpy(info_proc=_FakeProc(stdout=b'{"runc":{},"runsc":{}}', returncode=0))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
    ok, detail = await gvisor_preflight(docker_path="/usr/bin/docker", runtime="runsc")
    assert ok is True
    assert "runsc" in detail


@pytest.mark.asyncio
async def test_preflight_fails_when_runtime_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    spy = _DockerSpy(info_proc=_FakeProc(stdout=b'{"runc":{}}', returncode=0))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
    ok, detail = await gvisor_preflight(docker_path="/usr/bin/docker", runtime="runsc")
    assert ok is False
    assert "not registered" in detail


@pytest.mark.asyncio
async def test_preflight_fails_without_docker() -> None:
    ok, detail = await gvisor_preflight(docker_path=None, runtime="runsc")
    assert ok is False
    assert "not found" in detail
