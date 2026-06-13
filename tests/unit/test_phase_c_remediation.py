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

from dast.orchestrator import (
    _confirmation_is_grounded,
    _post_patch_status,
    _run_phase_c_fix_verify,
)
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


# ── T19: CONFIRMED must cite a REAL sandbox event (anti-fabrication) ──


def test_confirmation_grounded_when_cited_event_exists() -> None:
    real = {"evt-aaa", "evt-bbb"}
    assert _confirmation_is_grounded(["evt-bbb"], real) is True
    # one real + one fabricated still counts as grounded.
    assert _confirmation_is_grounded(["evt-nope", "evt-aaa"], real) is True


def test_confirmation_ungrounded_when_citation_fabricated_or_empty() -> None:
    real = {"evt-aaa"}
    assert _confirmation_is_grounded(["evt-ghost"], real) is False  # fabricated id
    assert _confirmation_is_grounded([], real) is False  # cites nothing
    assert _confirmation_is_grounded(None, real) is False  # malformed
    assert _confirmation_is_grounded(["evt-aaa"], set()) is False  # no real events at all


def test_confirmation_grounded_coerces_non_str_ids() -> None:
    # event ids compared as strings (defensive against int/None in the list).
    assert _confirmation_is_grounded([123], {"123"}) is True


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
    original = "def fetch(url):\n    import urllib.request\n    return urllib.request.urlopen(url).read()\n"
    file_record = {
        "file_id": "abc",
        "file_name": "x.py",
        "source_text": original,
    }
    inf = _make_inference_stub(patched_source=original)  # model returns same
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
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
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    assert result["skipped_reason"] == "patch_size_suspicious"
    assert "size_delta" in result


@pytest.mark.asyncio
async def test_phase_c_rejects_suspiciously_large_patch() -> None:
    """v14 Fix #3: whole-file hallucination / junk-padding still gets
    rejected. The absolute headroom is generous (+24 KB) so a thorough
    real fix to a small file passes (see the SSRF test below) — but an
    egregious blow-up beyond ``max(3×, +24 KB)`` is still caught before
    we waste a sandbox replay on it."""
    # ~400-char original (>100 so the size guard is active).
    original = "def fetch(url):\n    return urlopen(url)\n" * 10
    bloat = "# bloat\n" * 3600  # ~28.8 KB — well past the +24 KB headroom
    file_record = {
        "file_id": "abc",
        "file_name": "x.py",
        "source_text": original,
    }
    inf = _make_inference_stub(patched_source=original + bloat)
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    assert result["skipped_reason"] == "patch_size_suspicious"
    assert "size_delta" in result


@pytest.mark.asyncio
async def test_phase_c_accepts_short_function_with_legitimate_growth() -> None:
    """Regression for the synthetic_phase_d_v10 production bug
    (2026-05-18): a 411-char ``fetch_url`` body fixed with a correct
    SSRF mitigation (scheme allowlist + IP-private-block + DNS check)
    grew to ~2442 chars (~5.9×). The pure 3× ratio bound rejected the
    fix even though it was objectively correct. Compound bound
    ``max(3×, +24 KB)`` permits legitimate growth on short attack-
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
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    assert result.get("skipped_reason") != "patch_size_suspicious", (
        f"compound size bound should accept short-function SSRF fix; got {result!r}"
    )


@pytest.mark.asyncio
async def test_phase_c_accepts_thorough_fix_to_tiny_file() -> None:
    """Regression for the CVE-2026-24779 demo bug (2026-06-01): a
    471-char loader fixed with a class-complete SSRF mitigation
    (resolve host→IP + ipaddress private/loopback/link-local/reserved/
    multicast checks + a helper + docstrings) grew to ~4.9 KB (~10×).
    The old ``+2 KB`` absolute headroom rejected this *airtight* patch as
    ``patch_size_suspicious`` — the patch never replayed, so the headline
    remediation reported UNVERIFIABLE. A thorough fix to a tiny file is
    large in absolute terms by nature; the ``+24 KB`` headroom admits it
    while syntax/replay/gates remain the real correctness check.
    """
    original = (
        "import requests\n"
        "from urllib.parse import urlparse\n\n\n"
        "def load_remote_media(url):\n"
        "    p = urlparse(url)\n"
        "    if p.hostname in ('localhost', '127.0.0.1'):\n"
        "        raise ValueError('blocked')\n"
        "    return requests.get(url).content\n"
    )
    # ~4.9 KB stand-in for the real Phase C airtight patch: lands in the
    # band the OLD +2 KB bound wrongly rejected and the +24 KB bound accepts.
    body = (
        "import ipaddress\n"
        "import socket\n"
        "import requests\n"
        "from urllib.parse import urlparse\n\n\n"
        "_ALLOWED_SCHEMES = {'http', 'https'}\n\n\n"
        "def _resolve_and_check_host(host):\n"
        '    """Resolve host to every IP and reject internal ranges.\n'
        "    Defeats decimal/hex/octal/IPv6-mapped encodings and DNS-to-\n"
        '    internal rebinding by checking the RESOLVED address."""\n'
        "    for info in socket.getaddrinfo(host, None):\n"
        "        addr = ipaddress.ip_address(info[4][0])\n"
        "        if (addr.is_private or addr.is_loopback\n"
        "                or addr.is_link_local or addr.is_reserved\n"
        "                or addr.is_multicast or addr.is_unspecified):\n"
        "            raise ValueError(f'blocked internal address: {addr}')\n"
    )
    # Pad with real-looking guard logic to ~4.9 KB (still < orig + 24 KB).
    body += "    # defense-in-depth: re-validate on each call path\n" * 70
    body += (
        "\n\ndef load_remote_media(url):\n"
        "    p = urlparse(url.replace(chr(92), '/'))\n"
        "    if p.scheme not in _ALLOWED_SCHEMES:\n"
        "        raise ValueError('scheme not allowed')\n"
        "    _resolve_and_check_host(p.hostname or '')\n"
        "    return requests.get(url, allow_redirects=False).content\n"
    )
    patched = body
    # The case must land in the headroom band the regression is about:
    # past 3× AND past the old +2 KB, but within the current +24 KB.
    assert len(patched) > len(original) * 3.0
    assert len(patched) > len(original) + 2048  # old bound would reject
    assert len(patched) < len(original) + 24576  # current bound admits
    file_record = {
        "file_id": "abc",
        "file_name": "_demo_media_loader.py",
        "source_text": original,
    }
    inf = _make_inference_stub(patched_source=patched, verdict_label="clean")
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    assert result.get("skipped_reason") != "patch_size_suspicious", (
        f"the +24 KB headroom must admit a thorough fix to a tiny file; got {result.get('skipped_reason')!r}"
    )


# ── Fix #2: syntax validation ────────────────────────────────────────


@pytest.mark.asyncio
async def test_phase_c_rejects_python_patch_with_syntax_error() -> None:
    """v14 Fix #2: invalid Python syntax in patched_source must
    fail-fast with skipped_reason=patch_syntax_invalid + the
    error message surfaced. Without this, every replay errors with
    SyntaxError and the function returns all_replays_failed —
    misclassifying garbage as sandbox infra failure."""
    original = "def fetch(url):\n    import urllib.request\n    return urllib.request.urlopen(url).read()\n"
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
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
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
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    # Must NOT be rejected as syntax-invalid — bytes are valid Python.
    assert result.get("skipped_reason") != "patch_syntax_invalid"
    # With empty iter1_plans, replay yields all_replays_failed.
    assert result.get("skipped_reason") == "all_replays_failed"


@pytest.mark.asyncio
async def test_phase_c_ts_patch_not_rejected_by_node_check() -> None:
    """REGRESSION: a .ts patch with TYPE ANNOTATIONS must NOT be rejected
    as patch_syntax_invalid. node --check parses TS as plain JS and
    false-fails on `: string` etc. — which silently skipped the replay
    for EVERY TS patch (remediation never earned a confidence). TS/TSX
    must bypass node --check and defer to the tsx sandbox replay."""
    original = "export function fetchResource(url: string): string {\n  return get(url);\n}\n" * 3
    ts_patch = (
        "function isPrivate(addr: string): boolean {\n"
        "  return addr.startsWith('127.') || addr === '::1';\n"
        "}\n"
        "export async function fetchResource(url: string): Promise<string> {\n"
        "  const u = new URL(url);\n"
        "  if (isPrivate(u.hostname)) throw new Error('blocked');\n"
        "  return String(await get(url));\n"
        "}\n"
    )
    file_record = {"file_id": "abc", "file_name": "fetch.ts", "source_text": original}
    inf = _make_inference_stub(patched_source=ts_patch)
    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
        iter1_plans=[],
        inference=inf,
        sandbox=_StubSandbox(),
        journal=_StubJournal(),
    )
    # The TS type annotations must NOT trip the (JS-only) node --check.
    assert result.get("skipped_reason") != "patch_syntax_invalid"
    assert "syntax_error" not in result or not result.get("syntax_error")


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
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
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
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
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
        l1_output={"hypotheses": [{"id": f"H{i:03d}", "finding_ref": f"H{i:03d}", "type": "ssrf"} for i in range(4)]},
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
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
        iter1_plans=[],
        inference=inf,
        sandbox=sandbox,
        journal=_StubJournal(),
    )
    # After the call, the sandbox client should have the lock attached.
    lock = getattr(sandbox, "_phase_c_content_lock", None)
    assert lock is not None, (
        "Phase C must attach an asyncio.Lock to the sandbox client to serialize file_content_map mutation"
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


# ── v15: verified-remediation gate wiring (Stage 2 + 3) ──────────────


_GATE_PATCH = (
    "import requests\n"
    "import ipaddress\n"
    "import socket\n"
    "from urllib.parse import urlparse\n\n\n"
    "def load_media_from_url(url):\n"
    "    p = urlparse(url)\n"
    "    for info in socket.getaddrinfo(p.hostname or '', None):\n"
    "        if ipaddress.ip_address(info[4][0]).is_private:\n"
    "            raise ValueError('blocked')\n"
    "    return requests.get(url).content\n"
)


def _gate_inference_stub(*, n_variants: int):
    """Inference stub for the full Phase C + gates path. Routes by prompt:
    Stage-2/Stage-3 gate prompts return functional/adversarial JSON; the
    first two non-gate calls return the patch then the (refuted) verdict."""
    import json

    func_json = json.dumps(
        {
            "description": "benign public host",
            "benign_url": "https://example.com/img.png",
            "commands": ["python -c \"print('ARGUS_FUNC_OK')\""],
        }
    )
    adv_json = json.dumps(
        {
            "variants": [
                {
                    "description": f"technique {i}",
                    "payload": f"http://variant{i}/",
                    "commands": [f'python -c "print({i})"'],
                }
                for i in range(n_variants)
            ]
        }
    )
    patch_json = json.dumps({"patched_source": _GATE_PATCH, "fix_summary": "resolve-to-IP", "per_finding_fixes": []})
    verdict_json = json.dumps(
        {
            "current_verdict": {"verdict_label": "clean"},
            "claim_verdicts": [{"hypothesis_id": "H001", "verdict": "refuted"}],
        }
    )
    state = {"non_gate": 0}

    async def _inf(prompt: str, params: dict, schema: Any) -> dict[str, Any]:
        if "Stage 2 (functional" in prompt:
            txt = func_json
        elif "Stage 3 (adversarial" in prompt:
            txt = adv_json
        else:
            txt = patch_json if state["non_gate"] == 0 else verdict_json
            state["non_gate"] += 1
        return {"text": txt, "usage": {"prompt_tokens": 10, "completion_tokens": 5}}

    return _inf


class _GateSandbox(_StubSandbox):
    """Sandbox stub that self-classifies gate harnesses by oracle: the
    functional plan always 'passes'; a variant 'fires' only if its
    payload is in ``fire_payloads``."""

    def __init__(self, *, fire_payloads: tuple[str, ...] = ()) -> None:
        super().__init__()
        self.fire_payloads = set(fire_payloads)

    async def submit(self, plan: Any) -> SandboxTrace:
        from dast.phase_c_verify_gates import FUNC_OK, REACH_ORACLE

        self.submit_calls.append(plan)
        out = ""
        oracle = getattr(plan, "expected_oracle", "")
        if oracle == FUNC_OK:
            out = FUNC_OK
        elif oracle == REACH_ORACLE and (plan.payload in self.fire_payloads):
            out = REACH_ORACLE
        return SandboxTrace(
            plan_id=plan.plan_id,
            file_id=plan.file_id,
            hypothesis_id=plan.hypothesis_id,
            events=[],
            exit_code=0,
            stdout_excerpt=out,
            stderr_excerpt="",
            elapsed_ms=10,
        )


def _gate_call(inference: Any, sandbox: Any, severity: str = "critical"):
    return _run_phase_c_fix_verify(
        file_record={
            "file_id": "abc",
            "file_name": "loader.py",
            "source_text": (
                "import requests\n"
                "from urllib.parse import urlparse\n\n\n"
                "def load_media_from_url(url):\n"
                "    if urlparse(url).hostname == 'localhost':\n"
                "        raise ValueError('no')\n"
                "    return requests.get(url).content\n"
            ),
        },
        findings_validated=["H001"],
        l1_output={
            "hypotheses": [
                {
                    "id": "H001",
                    "finding_ref": "H001",
                    "type": "ssrf",
                    "severity": severity,
                }
            ]
        },
        iter1_plans=[
            {
                "hypothesis_id": "H001",
                "plan_status": "executable",
                "commands": ["python -c 'pass'"],
                "payload": "http://localhost",
                "oracle": "x",
                "image_hint": "lean",
                "timeout_sec": 30,
            }
        ],
        inference=inference,
        sandbox=sandbox,
        journal=_StubJournal(),
        enable_verify_gates=True,
    )


@pytest.mark.asyncio
async def test_phase_c_gates_high_confidence_when_class_complete() -> None:
    """Patch refutes the PoC, preserves a benign request, and blocks all
    5 novel same-class variants → HIGH confidence, stamped onto the
    NEUTRALIZED finding."""
    sandbox = _GateSandbox()  # no variant fires
    result = await _gate_call(_gate_inference_stub(n_variants=5), sandbox)
    ver = result["verification"]
    assert ver is not None
    assert ver["confidence"] == "HIGH"
    assert ver["functional_ok"] is True
    # 5 LLM encoding variants + 1 deterministic DNS-rebinding probe (SSRF).
    assert ver["variants_total"] == 6 and ver["variants_fired"] == 0
    assert any("rebind" in (v.get("description") or "").lower() for v in ver["variants"])
    assert result["needs_retry"] is False
    pf = result["per_finding"][0]
    assert pf["post_patch_status"] == "NEUTRALIZED"
    assert pf["confidence"] == "HIGH"


@pytest.mark.asyncio
async def test_phase_c_gates_failed_signals_retry_when_variant_fires() -> None:
    """A surviving same-class variant ⇒ FAILED confidence + a retry
    signal carrying concrete bypass evidence for patch regeneration."""
    sandbox = _GateSandbox(fire_payloads=("http://variant2/",))
    result = await _gate_call(_gate_inference_stub(n_variants=5), sandbox)
    ver = result["verification"]
    assert ver["confidence"] == "FAILED"
    assert ver["variants_fired"] == 1
    assert result["needs_retry"] is True
    assert "BYPASS STILL WORKS" in result["failure_evidence"]
    assert "http://variant2/" in result["failure_evidence"]
    # The PoC was still refuted, so status stays NEUTRALIZED but the
    # confidence is honestly FAILED (shallow patch).
    assert result["per_finding"][0]["confidence"] == "FAILED"


@pytest.mark.asyncio
async def test_phase_c_gates_absent_when_disabled() -> None:
    """Default (gates disabled) leaves verification=None and never calls
    the Stage-2/3 generators."""
    sandbox = _GateSandbox()
    result = await _run_phase_c_fix_verify(
        file_record={
            "file_id": "abc",
            "file_name": "loader.py",
            "source_text": "import x\ndef f(u):\n    return x.get(u)\n",
        },
        findings_validated=["H001"],
        l1_output={"hypotheses": [{"id": "H001", "finding_ref": "H001", "type": "ssrf"}]},
        iter1_plans=[
            {
                "hypothesis_id": "H001",
                "plan_status": "executable",
                "commands": ["python -c 'pass'"],
                "payload": "http://localhost",
                "oracle": "x",
                "image_hint": "lean",
                "timeout_sec": 30,
            }
        ],
        inference=_gate_inference_stub(n_variants=5),
        sandbox=sandbox,
        journal=_StubJournal(),
        # enable_verify_gates defaults False
    )
    assert result["verification"] is None
    assert result["needs_retry"] is False
