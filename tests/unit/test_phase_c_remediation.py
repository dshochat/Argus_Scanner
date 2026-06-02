"""Unit tests for ``dast.orchestrator._run_phase_c_fix_verify``.

v14 (2026-05-17): hardening tests for the Phase C remediation path.
Previously the function had ZERO direct unit-test coverage; the only
tests around Phase C touched config flags + the binary-artifact guard.
This file covers the v14 hardening additions:

* **Fix #1** — DAST-discovered findings (Phase 3 Stage 2 + Phase 2
  chains + Phase B+ probes) are no longer silently dropped from
  ``hyp_by_ref``; they participate in patch generation alongside L1
  findings. Per-finding status for unverified DAST findings reports
  UNVERIFIABLE (correct) instead of falsely NEUTRALIZED.
* **Fix #2** — ``patched_source`` syntax validation (``ast.parse``
  for Python, ``node --check`` for JS) fail-fast before sandbox
  replay so we surface ``patch_syntax_invalid`` distinctly from
  sandbox infra failures.
* **Fix #3** — diff-size sanity: reject byte-identical patches
  (model returned no change) and rejection patches that shrink to
  <20% or grow to >300% of original.
* **Fix #4** — empty ``source_text`` fail-fast.

All tests stub the inference + sandbox interfaces; no live API calls.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from dast.orchestrator import _post_patch_status, _run_phase_c_fix_verify
from dast.sandbox.client import SandboxTrace

# ── post-patch verdict → status mapping (regression for the inverted map) ──


def test_post_patch_status_refuted_is_neutralized() -> None:
    """`refuted` = the trace affirmatively shows the exploit no longer
    fires = a VERIFIED fix. Prior bug mapped it to UNVERIFIABLE."""
    assert _post_patch_status("refuted") == "NEUTRALIZED"


def test_post_patch_status_confirmed_is_still_exploitable() -> None:
    assert _post_patch_status("confirmed") == "STILL_EXPLOITABLE"


def test_post_patch_status_inconclusive_is_unverifiable() -> None:
    """`inconclusive` = no decisive evidence → UNVERIFIABLE. Prior bug
    wrongly reported this as NEUTRALIZED (a false 'fixed' claim)."""
    assert _post_patch_status("inconclusive") == "UNVERIFIABLE"


def test_post_patch_status_missing_or_unknown_is_unverifiable() -> None:
    assert _post_patch_status(None) == "UNVERIFIABLE"
    assert _post_patch_status("unknown") == "UNVERIFIABLE"
    # The phantom value the old code matched must NOT be a fix signal.
    assert _post_patch_status("rejected") == "UNVERIFIABLE"


def _make_inference_stub(
    patched_source: str,
    fix_summary: str = "fixed",
    verdict_label: str = "clean",
    claim_verdicts: list[dict] | None = None,
) -> Any:
    """Build an inference callable that returns:
      * patch JSON on the FIRST call (Step 1 — generate patch)
      * verdict JSON on the SECOND call (Step 3 — re-judge)
    """
    import json

    claim_verdicts = claim_verdicts or []
    patch_json = json.dumps(
        {
            "patched_source": patched_source,
            "fix_summary": fix_summary,
            "per_finding_fixes": [],
        }
    )
    verdict_json = json.dumps(
        {
            "current_verdict": {"verdict_label": verdict_label},
            "claim_verdicts": claim_verdicts,
        }
    )
    responses = [
        {"text": patch_json, "usage": {"prompt_tokens": 100, "completion_tokens": 50}},
        {"text": verdict_json, "usage": {"prompt_tokens": 80, "completion_tokens": 40}},
    ]
    state = {"i": 0}

    async def _inf(prompt: str, params: dict, schema: dict) -> dict[str, Any]:
        r = responses[min(state["i"], len(responses) - 1)]
        state["i"] += 1
        return r

    return _inf


class _StubSandbox:
    """Sandbox stub for Phase C replay.

    Exposes ``file_content_map`` (a dict) so Phase C's content injection
    finds something mutable; the ``submit`` coroutine returns a
    SandboxTrace with a configurable event set.
    """

    def __init__(self) -> None:
        self.file_content_map: dict[str, bytes] = {}
        self.submit_calls: list[Any] = []

    async def submit(self, plan: Any) -> SandboxTrace:
        self.submit_calls.append(plan)
        return SandboxTrace(
            plan_id=plan.plan_id,
            file_id=plan.file_id,
            hypothesis_id=plan.hypothesis_id,
            events=[],
            exit_code=0,
            stdout_excerpt="",
            stderr_excerpt="",
            elapsed_ms=10,
        )


class _StubJournal:
    """Phase C only writes if explicitly enabled; this stub captures
    any append calls so tests can assert no journal writes happen."""

    def __init__(self) -> None:
        self.records: list[Any] = []

    def append(self, rec: Any) -> None:
        self.records.append(rec)


# ── Fix #4: empty source_text ────────────────────────────────────────


@pytest.mark.asyncio
async def test_phase_c_fails_fast_on_empty_source_text() -> None:
    """v14 Fix #4: if source_text is empty/whitespace, Phase C must
    fail-fast with ``attempted=False, skipped_reason=no_source_text``.
    Generating a patch against an empty file is unrecoverable."""
    file_record = {"file_id": "abc", "file_name": "x.py", "source_text": ""}
    inf = AsyncMock()  # must never be called
    sandbox = _StubSandbox()
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001"}]},
        iter1_plans=[],
        inference=inf,
        sandbox=sandbox,
        journal=_StubJournal(),
    )
    assert result["attempted"] is False
    assert result["skipped_reason"] == "no_source_text"
    inf.assert_not_called()
    assert sandbox.submit_calls == []


@pytest.mark.asyncio
async def test_phase_c_fails_fast_on_whitespace_only_source_text() -> None:
    """Whitespace-only source should also fail-fast — same rationale
    as empty source."""
    file_record = {"file_id": "abc", "file_name": "x.py", "source_text": "   \n\n  "}
    inf = AsyncMock()
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001"}]},
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    assert result["skipped_reason"] == "no_source_text"
    inf.assert_not_called()


# ── Fix #3: diff-size sanity ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_phase_c_rejects_byte_identical_patch() -> None:
    """v14 Fix #3: when the model returns the original source
    unchanged, Phase C must reject with skipped_reason=
    patch_byte_identical_to_original instead of replaying and
    falsely reporting NEUTRALIZED."""
    original = (
        "def fetch(url):\n"
        "    import urllib.request\n"
        "    return urllib.request.urlopen(url).read()\n"
    )
    file_record = {
        "file_id": "abc",
        "file_name": "x.py",
        "source_text": original,
    }
    inf = _make_inference_stub(patched_source=original)  # model returns same
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={
            "hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]
        },
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    assert result["skipped_reason"] == "patch_byte_identical_to_original"
    assert result["attempted"] is True


@pytest.mark.asyncio
async def test_phase_c_rejects_suspiciously_small_patch() -> None:
    """v14 Fix #3: model returning a tiny stub (e.g. ``# safe``) when
    the original was 500+ chars indicates a truncation / hallucination
    failure. Reject before replay."""
    original = "def fetch(url):\n" + "    pass\n" * 200  # ~1700 chars
    file_record = {
        "file_id": "abc",
        "file_name": "x.py",
        "source_text": original,
    }
    inf = _make_inference_stub(patched_source="# fixed\n")  # 8 chars
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={
            "hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]
        },
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    assert result["skipped_reason"] == "patch_size_suspicious"
    assert "size_delta" in result


@pytest.mark.asyncio
async def test_phase_c_rejects_suspiciously_large_patch() -> None:
    """v14 Fix #3: 4× growth indicates the model hallucinated a
    different file or padded with junk. Reject."""
    original = "def fetch(url):\n    return urlopen(url)\n"  # ~40 chars
    bloat = "# bloat\n" * 200  # ~1600 chars
    file_record = {
        "file_id": "abc",
        "file_name": "x.py",
        "source_text": original,
    }
    inf = _make_inference_stub(patched_source=original + bloat)
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={
            "hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]
        },
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    # original < 100 chars → strict bounds don't fire on short files;
    # rewrite with longer original to trigger the >300% bound.
    if result["skipped_reason"] != "patch_size_suspicious":
        # Re-run with a sufficiently long original to exercise the 3x cap.
        bigger_orig = "def fetch(url):\n    return urlopen(url)\n" * 10
        file_record["source_text"] = bigger_orig
        inf = _make_inference_stub(patched_source=bigger_orig + bloat * 5)
        result = await _run_phase_c_fix_verify(
            file_record=file_record,
            findings_validated=["H001"],
            l1_output={
                "hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]
            },
            iter1_plans=[],
            inference=inf,
            sandbox=_StubSandbox(),
            journal=_StubJournal(),
        )
    assert result["skipped_reason"] == "patch_size_suspicious"


@pytest.mark.asyncio
async def test_phase_c_accepts_short_function_with_legitimate_growth() -> None:
    """Regression for the synthetic_phase_d_v10 production bug
    (2026-05-18): a 411-char ``fetch_url`` body fixed with a correct
    SSRF mitigation (scheme allowlist + IP-private-block + DNS check)
    grew to ~2442 chars (~5.9×). The pure 3× ratio bound rejected the
    fix even though it was objectively correct. Compound bound
    ``max(3×, +2 KB)`` permits legitimate growth on short attack-
    attractive functions while still rejecting whole-file hallucinations
    on larger originals (covered by the suspiciously_large test above).
    """
    original = (
        "import urllib.request\n\n\n"
        "def fetch_url(url):\n"
        "    # Naive: no scheme allowlist, no IP allowlist, no DNS\n"
        "    # rebinding protection. Vulnerable to SSRF against\n"
        "    # internal metadata endpoints (169.254.169.254) and\n"
        "    # loopback (127.0.0.1) services.\n"
        "    resp = urllib.request.urlopen(url, timeout=5)\n"
        "    return resp.read()\n"
    )
    # ~2400-char patched body: scheme allowlist + ipaddress checks +
    # DNS resolution loop. Stand-in for the real Phase C v14 output.
    patched = (
        "import ipaddress\n"
        "import socket\n"
        "import urllib.parse\n"
        "import urllib.request\n\n\n"
        "_BLOCKED_HOSTS = {'localhost', 'metadata.google.internal'}\n\n\n"
        "def fetch_url(url):\n"
        "    parsed = urllib.parse.urlparse(url)\n"
        "    if parsed.scheme != 'https':\n"
        "        raise ValueError('only https URLs are accepted')\n"
        "    host = (parsed.hostname or '').lower()\n"
        "    if not host:\n"
        "        raise ValueError('url has no hostname')\n"
        "    if host in _BLOCKED_HOSTS:\n"
        "        raise ValueError(f'host {host!r} is blocked')\n"
        "    try:\n"
        "        infos = socket.getaddrinfo(host, parsed.port or 443)\n"
        "    except socket.gaierror as exc:\n"
        "        raise ValueError(f'dns lookup failed: {exc}') from exc\n"
        "    for info in infos:\n"
        "        ip_str = info[4][0]\n"
        "        try:\n"
        "            ip = ipaddress.ip_address(ip_str)\n"
        "        except ValueError as exc:\n"
        "            raise ValueError(f'bad ip {ip_str!r}') from exc\n"
        "        if (\n"
        "            ip.is_private\n"
        "            or ip.is_loopback\n"
        "            or ip.is_link_local\n"
        "            or ip.is_reserved\n"
        "            or ip.is_multicast\n"
        "            or ip.is_unspecified\n"
        "        ):\n"
        "            raise ValueError(\n"
        "                f'resolved ip {ip_str!r} is in a blocked range'\n"
        "            )\n"
        "    resp = urllib.request.urlopen(url, timeout=5)\n"
        "    return resp.read()\n"
    )
    # Assert the case actually exercises the compound-bound branch:
    # patched > 3× original AND patched < original + 2 KB.
    assert len(patched) > len(original) * 3.0
    assert len(patched) < len(original) + 2048
    file_record = {
        "file_id": "abc",
        "file_name": "fetch.py",
        "source_text": original,
    }
    inf = _make_inference_stub(patched_source=patched, verdict_label="clean")
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={
            "hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]
        },
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    assert (
        result.get("skipped_reason") != "patch_size_suspicious"
    ), f"compound size bound should accept short-function SSRF fix; got {result!r}"


# ── Fix #2: syntax validation ────────────────────────────────────────


@pytest.mark.asyncio
async def test_phase_c_rejects_python_patch_with_syntax_error() -> None:
    """v14 Fix #2: invalid Python syntax in patched_source must
    fail-fast with skipped_reason=patch_syntax_invalid + the
    error message surfaced. Without this, every replay errors with
    SyntaxError and the function returns all_replays_failed —
    misclassifying garbage as sandbox infra failure."""
    original = (
        "def fetch(url):\n"
        "    import urllib.request\n"
        "    return urllib.request.urlopen(url).read()\n"
    )
    broken_patch = "def fetch(url):\n    return\n    INVALID PYTHON\n)) syntax error\n"
    file_record = {
        "file_id": "abc",
        "file_name": "fetch.py",
        "source_text": original,
    }
    inf = _make_inference_stub(patched_source=broken_patch)
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={
            "hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]
        },
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    assert result["skipped_reason"] == "patch_syntax_invalid"
    assert "syntax_error" in result
    assert "SyntaxError" in result["syntax_error"]


@pytest.mark.asyncio
async def test_phase_c_accepts_python_patch_with_valid_syntax() -> None:
    """Sanity: a syntactically-valid patch proceeds to Step 2 replay.
    With no iter1_plans, replay yields all_replays_failed which is the
    expected path — not the syntax-invalid path."""
    original = "def fetch(url):\n    return urlopen(url)\n" * 5  # ~200 chars
    valid_patch = (
        "from urllib.parse import urlparse\n"
        "def fetch(url):\n"
        "    parsed = urlparse(url)\n"
        "    if parsed.hostname == '169.254.169.254':\n"
        "        raise ValueError('blocked')\n"
        "    return urlopen(url)\n" * 3
    )
    file_record = {
        "file_id": "abc",
        "file_name": "fetch.py",
        "source_text": original,
    }
    inf = _make_inference_stub(patched_source=valid_patch)
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={
            "hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]
        },
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    # Must NOT be rejected as syntax-invalid — bytes are valid Python.
    assert result.get("skipped_reason") != "patch_syntax_invalid"
    # With empty iter1_plans, replay yields all_replays_failed.
    assert result.get("skipped_reason") == "all_replays_failed"


# ── Fix #1: DAST findings included in hyp_by_ref ─────────────────────


@pytest.mark.asyncio
async def test_phase_c_includes_dast_findings_in_confirmed() -> None:
    """v14 Fix #1: when ``dast_findings`` is passed, those finding_refs
    are added to ``hyp_by_ref`` and reach Step 1's patcher prompt.
    Without this, Phase 3 Stage 2 zero-day-class findings would be
    silently dropped from ``confirmed`` and never patched."""
    original = "def fetch_url(url):\n    return urlopen(url)\n" * 5
    file_record = {
        "file_id": "abc",
        "file_name": "x.py",
        "source_text": original,
    }
    valid_patch = original.replace("urlopen(url)", "urlopen(validate(url))")

    # Record what the patcher inference receives.
    seen_prompts: list[str] = []

    async def _capture_inf(prompt: str, params: dict, schema: dict) -> dict[str, Any]:
        import json as _json

        seen_prompts.append(prompt)
        if len(seen_prompts) == 1:
            return {
                "text": _json.dumps(
                    {
                        "patched_source": valid_patch,
                        "fix_summary": "fixed both findings",
                    }
                ),
                "usage": {"prompt_tokens": 0, "completion_tokens": 0},
            }
        return {
            "text": _json.dumps(
                {
                    "current_verdict": {"verdict_label": "clean"},
                    "claim_verdicts": [],
                }
            ),
            "usage": {"prompt_tokens": 0, "completion_tokens": 0},
        }

    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001", "P3-fetch_url"],
        l1_output={
            "hypotheses": [
                {"id": "H001", "finding_ref": "H001", "type": "ssrf"}
            ]
        },
        iter1_plans=[],
        inference=_capture_inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
        dast_findings=[
            {
                "id": "P3-fetch_url",
                "finding_ref": "P3-fetch_url",
                "type": "ssrf",
                "severity": "critical",
                "description": "Phase 3 Stage 2 confirmed SSRF via fetch_url",
                "_source": "phase_3_stage_2",
            }
        ],
    )

    # Patcher must have been called (DAST finding wasn't dropped)
    assert len(seen_prompts) >= 1
    # Both findings should appear in the prompt
    first_prompt = seen_prompts[0]
    assert "H001" in first_prompt
    assert "P3-fetch_url" in first_prompt


# ── v14 B5: replay failure surfacing ─────────────────────────────────


class _FailingSandbox:
    """Sandbox stub that raises on every submit — exercises the
    replay-exception capture path."""

    def __init__(self) -> None:
        self.file_content_map: dict[str, bytes] = {}

    async def submit(self, plan: Any) -> Any:
        raise RuntimeError(f"simulated sandbox failure for {plan.plan_id}")


@pytest.mark.asyncio
async def test_phase_c_replay_failures_surface_in_result() -> None:
    """v14 B5: when a sandbox replay raises (timeout, Fly 403, network
    error), the failure must surface in ``replay_errors`` rather than
    being silently swallowed. Without this, the per-finding loop sees
    zero re-traces and marks findings NEUTRALIZED even though the
    patched plan never actually executed."""
    original = "def fetch(url):\n    return urlopen(url)\n" * 5
    valid_patch = original.replace("urlopen(url)", "urlopen(validate(url))")
    file_record = {
        "file_id": "abc",
        "file_name": "fetch.py",
        "source_text": original,
    }

    # Provide an executable iter-1 plan so the replay loop attempts
    # submission (which will then raise).
    iter1 = [
        {
            "plan_id": "iter1-H001",
            "hypothesis_id": "H001",
            "plan_status": "executable",
            "commands": ["echo test"],
            "oracle": "marker",
            "timeout_sec": 5,
        }
    ]
    inf = _make_inference_stub(patched_source=valid_patch)
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={
            "hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]
        },
        iter1_plans=iter1,
        inference=inf,
        sandbox=_FailingSandbox(),
        journal=_StubJournal(),
    )

    # All replays failed → no traces produced, but the failures are
    # captured with diagnostic info.
    assert result.get("skipped_reason") == "all_replays_failed" or (
        "replay_errors" in result and len(result["replay_errors"]) >= 1
    )


@pytest.mark.asyncio
async def test_phase_c_partial_replay_failure_captures_error_details() -> None:
    """v14 B5: when SOME replays succeed and others fail, the
    successful traces still drive verdict re-judgment AND the failures
    are surfaced for diagnostics. Operators can correlate NEUTRALIZED
    claims with the underlying sandbox health."""

    class _FlakeSandbox:
        def __init__(self) -> None:
            self.file_content_map: dict[str, bytes] = {}
            self._n = 0

        async def submit(self, plan: Any) -> Any:
            self._n += 1
            if self._n % 2 == 0:
                raise RuntimeError(f"flake on plan {plan.plan_id}")
            # Return a minimal trace dict-like object
            from dast.sandbox.client import SandboxTrace

            return SandboxTrace(
                plan_id=plan.plan_id,
                file_id=plan.file_id,
                hypothesis_id=plan.hypothesis_id,
                events=[],
                exit_code=0,
                stdout_excerpt="",
                stderr_excerpt="",
                elapsed_ms=10,
            )

    original = "def fetch(url):\n    return urlopen(url)\n" * 5
    valid_patch = original.replace("urlopen(url)", "urlopen(validate(url))")
    file_record = {
        "file_id": "abc",
        "file_name": "fetch.py",
        "source_text": original,
    }
    iter1 = [
        {
            "plan_id": f"iter1-H{i}",
            "hypothesis_id": f"H{i:03d}",
            "plan_status": "executable",
            "commands": ["echo"],
            "oracle": "",
            "timeout_sec": 5,
        }
        for i in range(4)
    ]
    inf = _make_inference_stub(patched_source=valid_patch)
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H000"],
        l1_output={
            "hypotheses": [
                {"id": f"H{i:03d}", "finding_ref": f"H{i:03d}", "type": "ssrf"}
                for i in range(4)
            ]
        },
        iter1_plans=iter1,
        inference=inf,
        sandbox=_FlakeSandbox(),
        journal=_StubJournal(),
    )

    # Some replays succeeded, some failed. Errors surface.
    assert result.get("n_replays", 0) >= 1
    assert "replay_errors" in result
    assert result["n_replay_errors"] >= 1
    # Each error carries diagnostic info
    err = result["replay_errors"][0]
    assert "hypothesis_id" in err
    assert "exception_type" in err
    assert err["exception_type"] == "RuntimeError"


# ── v14 B4: concurrent file_content_map locking ──────────────────────


@pytest.mark.asyncio
async def test_phase_c_acquires_content_map_lock() -> None:
    """v14 B4: Phase C must acquire an asyncio.Lock on the sandbox
    client's file_content_map before mutating it. Without serialization,
    a concurrent scan on file_id=X mid-Phase-C-on-Y could see Y's
    patched bytes incorrectly attributed to X."""
    import asyncio

    original = "def x(): pass\n" * 5
    valid_patch = "def x():\n    return 1\n" * 5
    file_record = {
        "file_id": "abc",
        "file_name": "x.py",
        "source_text": original,
    }

    sandbox = _StubSandbox()
    inf = _make_inference_stub(patched_source=valid_patch)
    await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={
            "hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]
        },
        iter1_plans=[],
        inference=inf,
        sandbox=sandbox,
        journal=_StubJournal(),
    )
    # After the call, the sandbox client should have the lock attached.
    lock = getattr(sandbox, "_phase_c_content_lock", None)
    assert lock is not None, (
        "Phase C must attach an asyncio.Lock to the sandbox client to "
        "serialize file_content_map mutation"
    )
    assert isinstance(lock, asyncio.Lock)
    # Lock should NOT be held at exit (released in finally block).
    assert not lock.locked()


@pytest.mark.asyncio
async def test_phase_c_dast_only_findings_still_drive_patch() -> None:
    """v14 Fix #1: even when L1 emits zero hypotheses, if DAST
    confirmed findings exist (e.g., Phase 3 discovered a vuln L1
    entirely missed), Phase C should still attempt remediation."""
    original = "def x():\n    return eval(input('?'))\n"
    file_record = {
        "file_id": "abc",
        "file_name": "x.py",
        "source_text": original,
    }
    valid_patch = "def x():\n    return ast.literal_eval(input('?'))\n"
    inf = _make_inference_stub(patched_source=valid_patch)
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["P3-eval"],
        l1_output={"hypotheses": []},  # L1 had nothing
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
        dast_findings=[
            {
                "id": "P3-eval",
                "finding_ref": "P3-eval",
                "type": "code_injection",
                "severity": "critical",
                "description": "Phase 3 confirmed eval of user input",
            }
        ],
    )
    # Must NOT report no_confirmed_findings — the DAST finding qualifies.
    assert result.get("skipped_reason") != "no_confirmed_findings_with_finding_ref"
