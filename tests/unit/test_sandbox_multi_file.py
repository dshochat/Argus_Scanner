"""Unit tests for multi-file project staging at the sandbox layer.

Covers:
  * ``_pack_additional_files`` — tar.gz + base64 serialisation
  * ``FirecrackerSandboxClient._build_env`` — additional_files_map lookup
    + env var presence/absence
  * Roundtrip: pack → b64 decode → tar extract → verify file contents
"""

from __future__ import annotations

import base64
import gzip
import io
import tarfile

import pytest

from dast.sandbox.client import (
    FirecrackerSandboxClient,
    FlyMachinesClient,
    SandboxPlan,
    _pack_additional_files,
)


def _client(additional_files_map: dict[str, dict[str, bytes]] | None = None) -> FirecrackerSandboxClient:
    """Build a minimal client for env-build tests; Fly state irrelevant."""
    return FirecrackerSandboxClient(
        fly_client=FlyMachinesClient(api_token="dummy", app_name="argus-test"),  # type: ignore[call-arg]
        image="registry.fly.io/argus-dast-sandbox:lean-v11",
        additional_files_map=additional_files_map or {},
    )


def _plan(file_id: str = "test_fid") -> SandboxPlan:
    return SandboxPlan(
        plan_id="p1",
        file_id=file_id,
        hypothesis_id="h1",
        commands=["echo hi"],
        expected_oracle="test",
        payload="",
        timeout_sec=30,
        file_name="entry.ts",
    )


# ── _pack_additional_files ─────────────────────────────────────────────────


def test_pack_empty_returns_empty_string() -> None:
    """Back-compat: no sibling files → empty env var (caller filters)."""
    assert _pack_additional_files({}) == ""


def test_pack_single_file_roundtrips() -> None:
    """Packed bytes decode back to the original file via tar.gz."""
    files = {"utils.ts": b"export const x = 1\n"}
    encoded = _pack_additional_files(files)
    assert encoded != ""

    # Decode + extract.
    raw = base64.b64decode(encoded)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        members = tf.getnames()
        assert members == ["utils.ts"]
        extracted = tf.extractfile("utils.ts")
        assert extracted is not None
        assert extracted.read() == b"export const x = 1\n"


def test_pack_multiple_files_preserves_paths() -> None:
    """Nested relative paths roundtrip — pack/extract preserves structure."""
    files = {
        "utils.ts": b"a\n",
        "lib/inner.ts": b"b\n",
        "deeper/nested/path.ts": b"c\n",
    }
    encoded = _pack_additional_files(files)
    raw = base64.b64decode(encoded)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        names = set(tf.getnames())
        assert names == {"utils.ts", "lib/inner.ts", "deeper/nested/path.ts"}
        assert tf.extractfile("lib/inner.ts").read() == b"b\n"  # type: ignore[union-attr]
        assert tf.extractfile("deeper/nested/path.ts").read() == b"c\n"  # type: ignore[union-attr]


def test_pack_is_gzip_compressed() -> None:
    """The encoded blob is real gzip — verify magic bytes after b64 decode."""
    files = {"x.ts": b"y" * 200}
    raw = base64.b64decode(_pack_additional_files(files))
    # gzip magic bytes
    assert raw[:2] == b"\x1f\x8b"
    # gunzip-able
    decompressed = gzip.decompress(raw)
    assert decompressed[:4] != b""  # tar header present


def test_pack_handles_binary_bytes() -> None:
    """Non-utf8 bytes in file content roundtrip cleanly."""
    files = {"blob.bin": b"\x00\xff\x01\xfe binary data\n"}
    encoded = _pack_additional_files(files)
    raw = base64.b64decode(encoded)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        extracted = tf.extractfile("blob.bin")
        assert extracted is not None
        assert extracted.read() == b"\x00\xff\x01\xfe binary data\n"


# ── FirecrackerSandboxClient._build_env ────────────────────────────────────


def test_build_env_no_siblings_omits_env_var() -> None:
    """No siblings registered for this file_id → env var dropped from
    the dict (back-compat with pre-v11 images that don't know about
    ADDITIONAL_FILES_TARGZ_B64)."""
    client = _client(additional_files_map={})
    env = client._build_env(_plan(file_id="abc"))
    assert "ADDITIONAL_FILES_TARGZ_B64" not in env


def test_build_env_unregistered_file_id_omits_env_var() -> None:
    """Other file_id in the map but not this one → still omitted."""
    client = _client(additional_files_map={"other_fid": {"x.ts": b"y\n"}})
    env = client._build_env(_plan(file_id="this_fid"))
    assert "ADDITIONAL_FILES_TARGZ_B64" not in env


def test_build_env_with_siblings_ships_packed_var() -> None:
    """When siblings are registered for this file_id, the packed env
    var is set and decodes to the same files."""
    siblings = {"utils.ts": b"export const x = 1\n", "lib.ts": b"export const y = 2\n"}
    client = _client(additional_files_map={"test_fid": siblings})
    env = client._build_env(_plan(file_id="test_fid"))

    assert "ADDITIONAL_FILES_TARGZ_B64" in env
    raw = base64.b64decode(env["ADDITIONAL_FILES_TARGZ_B64"])
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        names = set(tf.getnames())
        assert names == {"utils.ts", "lib.ts"}


def test_build_env_packing_is_deterministic() -> None:
    """Same input → same encoded output. Important for reproducible
    plans + cache hashing."""
    siblings = {"utils.ts": b"a\n", "lib.ts": b"b\n"}
    client = _client(additional_files_map={"test_fid": siblings})
    env1 = client._build_env(_plan(file_id="test_fid"))
    env2 = client._build_env(_plan(file_id="test_fid"))
    assert env1["ADDITIONAL_FILES_TARGZ_B64"] == env2["ADDITIONAL_FILES_TARGZ_B64"]


# ── SandboxPlan schema unchanged ───────────────────────────────────────────


def test_sandbox_plan_has_no_additional_files_field() -> None:
    """v11 design decision: additional_files rides on the client's map,
    NOT on the plan, to keep the schema slim and avoid 9 plan-builder
    callsite edits. Verify the field stays off the schema."""
    plan = _plan()
    # Pydantic's model_fields gives us the declared field set
    assert "additional_files" not in type(plan).model_fields


# ── Bounded cost: pack output size sanity ─────────────────────────────────


def test_pack_compresses_reasonably() -> None:
    """For highly compressible content (repeated lines), the encoded
    blob should be well under the raw byte count."""
    # 100 KB of repeated content compresses to <1 KB.
    repetitive = b"export const x = 1\n" * 5000
    files = {"big.ts": repetitive}
    encoded = _pack_additional_files(files)
    # Original is ~95 KB; encoded should be much less.
    assert len(encoded) < len(repetitive) // 5


def test_pack_unicode_filename_roundtrip() -> None:
    """Unicode in relative path roundtrips (tar uses utf-8 by default
    in PAX format, which is Python tarfile's default for mode='w:gz')."""
    files = {"éutils.ts": b"export const x = 1\n"}
    encoded = _pack_additional_files(files)
    raw = base64.b64decode(encoded)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        names = tf.getnames()
        assert names == ["éutils.ts"]


# ── v1.9 _wait_for_machine_terminal long-poll fallback ──────────────────


@pytest.mark.asyncio
async def test_long_poll_fires_on_deadline_exceeded_phrasing() -> None:
    """The real Fly API returns ``"deadline_exceeded"`` (or
    ``"still has not reached..."``) without the literal word
    ``"timeout"``. Previous match logic checked only for "timeout"
    and the long-poll never fired — large-npm scans came back
    NOT_TESTED with no runtime trace. Confirm the widened marker
    set catches Fly's actual error phrasings."""
    from dast.sandbox.client import FlyMachinesError, FlyMachinesClient

    client = _client()
    # Override the fly client with a stub that raises the same error
    # shape Fly returns from /machines/{id}/wait when the machine
    # didn't reach state=stopped within the API's timeout.
    call_log: list[str] = []

    class _StubFlyClient(FlyMachinesClient):  # type: ignore[misc]
        def __init__(self) -> None:
            self.app_name = "argus-test"

        async def wait_for_state(self, **kw) -> dict:  # type: ignore[override]
            call_log.append("wait_for_state")
            raise FlyMachinesError(
                "wait_for_state 408: {\"error\":\"machine still has "
                "not reached the desired state, deadline_exceeded\"}"
            )

        async def get_machine(self, machine_id: str) -> dict:  # type: ignore[override]
            call_log.append("get_machine")
            # Simulate the machine reaching stopped on the FIRST
            # long-poll iteration — so the long-poll path succeeds.
            return {"state": "stopped"}

    client.fly_client = _StubFlyClient()
    # Shorten the long-poll interval so the test doesn't wait 5s.
    client.long_poll_interval_s = 0.01
    client.long_poll_extra_s = 5

    # Should NOT raise — long-poll triggered by "deadline_exceeded"
    # phrasing, then get_machine returned stopped.
    await client._wait_for_machine_terminal(
        machine_id="m1",
        instance_id="inst",
        plan_timeout_sec=30,
    )
    assert "wait_for_state" in call_log
    assert "get_machine" in call_log


@pytest.mark.asyncio
async def test_long_poll_fires_on_timeout_phrasing() -> None:
    """Back-compat: the original "timeout" phrasing also triggers
    long-poll. Both must work."""
    from dast.sandbox.client import FlyMachinesError, FlyMachinesClient

    client = _client()
    polls: list[str] = []

    class _StubFlyClient(FlyMachinesClient):  # type: ignore[misc]
        def __init__(self) -> None:
            self.app_name = "argus-test"

        async def wait_for_state(self, **kw) -> dict:  # type: ignore[override]
            raise FlyMachinesError("wait_for_state 504: request timeout")

        async def get_machine(self, machine_id: str) -> dict:  # type: ignore[override]
            polls.append("poll")
            return {"state": "stopped"}

    client.fly_client = _StubFlyClient()
    client.long_poll_interval_s = 0.01
    client.long_poll_extra_s = 5

    await client._wait_for_machine_terminal(
        machine_id="m1", instance_id="inst", plan_timeout_sec=30,
    )
    assert polls == ["poll"]


@pytest.mark.asyncio
async def test_long_poll_does_not_fire_on_non_timeout_error() -> None:
    """Auth failures, 5xx, network errors should propagate
    immediately — NOT fall through to long-poll, which would just
    waste minutes polling on a permanently-failed call."""
    from dast.sandbox.client import FlyMachinesError, FlyMachinesClient

    client = _client()

    class _StubFlyClient(FlyMachinesClient):  # type: ignore[misc]
        def __init__(self) -> None:
            self.app_name = "argus-test"

        async def wait_for_state(self, **kw) -> dict:  # type: ignore[override]
            raise FlyMachinesError(
                "wait_for_state 401: {\"error\":\"unauthorized\"}"
            )

        async def get_machine(self, machine_id: str) -> dict:  # type: ignore[override]
            raise AssertionError("get_machine should not be called")

    client.fly_client = _StubFlyClient()
    client.long_poll_interval_s = 0.01

    with pytest.raises(FlyMachinesError, match="401"):
        await client._wait_for_machine_terminal(
            machine_id="m1", instance_id="inst", plan_timeout_sec=30,
        )


@pytest.mark.asyncio
async def test_long_poll_polls_until_terminal_state() -> None:
    """When the machine takes several polls to reach stopped, the
    long-poll keeps polling until it does. Mirrors the real case
    where a 100-150s npm install + harness execution lands well
    past the 60s API wait cap."""
    from dast.sandbox.client import FlyMachinesError, FlyMachinesClient

    client = _client()
    poll_counter = {"n": 0}

    class _StubFlyClient(FlyMachinesClient):  # type: ignore[misc]
        def __init__(self) -> None:
            self.app_name = "argus-test"

        async def wait_for_state(self, **kw) -> dict:  # type: ignore[override]
            raise FlyMachinesError("deadline_exceeded after 60s")

        async def get_machine(self, machine_id: str) -> dict:  # type: ignore[override]
            poll_counter["n"] += 1
            # Stay "started" for first 3 polls, then "stopped".
            if poll_counter["n"] < 4:
                return {"state": "started"}
            return {"state": "stopped"}

    client.fly_client = _StubFlyClient()
    client.long_poll_interval_s = 0.01
    client.long_poll_extra_s = 5

    await client._wait_for_machine_terminal(
        machine_id="m1", instance_id="inst", plan_timeout_sec=30,
    )
    assert poll_counter["n"] == 4


@pytest.mark.asyncio
async def test_long_poll_raises_on_failed_state() -> None:
    """If the machine enters ``failed`` state during the long-poll,
    abort immediately with a clear error — don't waste budget
    polling something that's already terminally broken."""
    from dast.sandbox.client import FlyMachinesError, FlyMachinesClient

    client = _client()

    class _StubFlyClient(FlyMachinesClient):  # type: ignore[misc]
        def __init__(self) -> None:
            self.app_name = "argus-test"

        async def wait_for_state(self, **kw) -> dict:  # type: ignore[override]
            raise FlyMachinesError("deadline_exceeded")

        async def get_machine(self, machine_id: str) -> dict:  # type: ignore[override]
            return {"state": "failed", "error": "OOM"}

    client.fly_client = _StubFlyClient()
    client.long_poll_interval_s = 0.01
    client.long_poll_extra_s = 5

    with pytest.raises(FlyMachinesError, match="failed state"):
        await client._wait_for_machine_terminal(
            machine_id="m1", instance_id="inst", plan_timeout_sec=30,
        )


@pytest.mark.asyncio
async def test_long_poll_raises_when_budget_exhausted() -> None:
    """If the machine stays in ``started`` for the entire long-poll
    budget, raise a clear timeout error — don't poll forever."""
    from dast.sandbox.client import FlyMachinesError, FlyMachinesClient

    client = _client()
    poll_counter = {"n": 0}

    class _StubFlyClient(FlyMachinesClient):  # type: ignore[misc]
        def __init__(self) -> None:
            self.app_name = "argus-test"

        async def wait_for_state(self, **kw) -> dict:  # type: ignore[override]
            raise FlyMachinesError("deadline_exceeded")

        async def get_machine(self, machine_id: str) -> dict:  # type: ignore[override]
            poll_counter["n"] += 1
            return {"state": "started"}  # never reaches stopped

    client.fly_client = _StubFlyClient()
    client.long_poll_interval_s = 0.01
    # Tight budget so the test finishes fast.
    client.long_poll_extra_s = 0.05

    with pytest.raises(FlyMachinesError, match="did not reach stopped"):
        await client._wait_for_machine_terminal(
            machine_id="m1", instance_id="inst", plan_timeout_sec=30,
        )
    # Sanity: poll loop ran at least once before bailing.
    assert poll_counter["n"] >= 1
