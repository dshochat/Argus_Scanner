"""DAST-303 Slice 2 — unit tests for cross_repo_retrieval (tarball
flow).

Covers pure-function pieces (sink-line finder, import-near-sink
extraction, judge-input projection, binary detection, workspace
import resolution) plus end-to-end ``fetch_and_triage`` orchestration
with workspaces materialized on a tmp_path."""

from __future__ import annotations

import json
import tarfile
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from dast.code_index import CandidateFile
from dast.cross_repo_retrieval import (
    DEFAULT_MAX_FILE_BYTES,
    MAX_IMPORTS_PER_CANDIDATE,
    CrossRepoFetched,
    RepoWorkspace,
    _build_judge_candidates,
    _build_judge_context,
    _extract_imports_near_sink,
    _find_first_sink_line,
    _invoke_variant_judge,
    _is_likely_binary,
    download_repo_tarball,
    fetch_and_triage,
)
from dast.variant_analysis import SemanticSignature

if TYPE_CHECKING:
    from pathlib import Path


def _sig(**kwargs: Any) -> SemanticSignature:
    defaults = dict(
        attack_class="ssrf",
        cwe="CWE-918",
        source_shape="LLM-supplied URL",
        sink_kind="network_fetch",
        sink_callee="fetch",
        missing_guards=["URL scheme allowlist"],
        seed_function="webbrowserCall",
        seed_finding_id="H001",
    )
    defaults.update(kwargs)
    return SemanticSignature(**defaults)


def _cand(
    repo: str = "owner/repo",
    path: str = "src/tool.ts",
    *,
    ref: str = "deadbeefcafe",
) -> CandidateFile:
    return CandidateFile(
        repo_full_name=repo,
        file_path=path,
        ref=ref,
        html_url=f"https://github.com/{repo}/blob/{ref}/{path}",
        raw_url=f"https://raw.githubusercontent.com/{repo}/{ref}/{path}",
        repo_stargazers=15000,
        repo_is_fork=False,
        repo_description="",
    )


def _make_workspace(
    tmp_path: Path, repo: str, ref: str, files: dict[str, str]
) -> RepoWorkspace:
    """Materialize a fake repo workspace on disk for tests that need
    a real RepoWorkspace. Keys in ``files`` are repo-relative paths."""
    root = tmp_path / "ws" / f"{repo.replace('/', '__')}__{ref}"
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return RepoWorkspace(repo_full_name=repo, ref=ref, root=root)


# ── _is_likely_binary ───────────────────────────────────────────────


def test_is_likely_binary_returns_false_for_plain_text() -> None:
    assert _is_likely_binary(b"const fetch = require('node-fetch');") is False


def test_is_likely_binary_returns_true_for_nul_bytes() -> None:
    assert _is_likely_binary(b"PK\x03\x04\x00\x00") is True


def test_is_likely_binary_returns_true_for_high_nontext_ratio() -> None:
    sample = bytes([0xFF, 0xD8, 0xFF, 0xE0]) * 100 + b"some text"
    assert _is_likely_binary(sample) is True


def test_is_likely_binary_empty_returns_false() -> None:
    assert _is_likely_binary(b"") is False


# ── _find_first_sink_line ────────────────────────────────────────────


def test_find_first_sink_line_one_indexed() -> None:
    content = "first\nsecond\nthird with fetch\nfourth"
    assert _find_first_sink_line(content, "fetch") == 3


def test_find_first_sink_line_first_occurrence_when_multiple() -> None:
    content = "alpha\nfetch(a)\nbeta\nfetch(b)\ngamma"
    assert _find_first_sink_line(content, "fetch") == 2


def test_find_first_sink_line_returns_zero_when_absent() -> None:
    content = "no sink here\njust regular code\nreturn 0"
    assert _find_first_sink_line(content, "fetch") == 0


def test_find_first_sink_line_handles_empty_sink() -> None:
    assert _find_first_sink_line("anything", "") == 0
    assert _find_first_sink_line("anything", "   ") == 0


# ── _extract_imports_near_sink ───────────────────────────────────────


def test_extract_imports_near_sink_returns_imports_in_proximity_order() -> None:
    """Imports near the sink line should rank higher than imports
    at the top of the file."""
    content = "\n".join([
        "import { faraway } from './unrelated-module'",     # line 1
        "import express from 'express'",                     # line 2
        "",                                                  # line 3
        "function before() { return 1 }",                   # line 4
        "",                                                  # line 5
        "import { checkDenyList } from './httpSecurity'",   # line 6 (close)
        "function vulnerable(url) {",                        # line 7
        "    fetch(url)",                                    # line 8 <- sink
        "}",                                                 # line 9
    ])
    out = _extract_imports_near_sink(content, sink_line=8, max_imports=3)
    # ``./httpSecurity`` (line 6) is closest to sink_line 8.
    assert out[0] == "./httpSecurity"
    # Remaining imports follow, ordered by distance.
    assert len(out) <= 3
    assert set(out).issubset({"./httpSecurity", "express", "./unrelated-module"})


def test_extract_imports_near_sink_dedupes() -> None:
    """The same specifier appearing twice → only one entry in the
    output."""
    content = (
        "import a from 'shared'\n"
        "import b from 'shared'\n"
        "fetch(url)\n"
    )
    out = _extract_imports_near_sink(content, sink_line=3, max_imports=5)
    assert out.count("shared") == 1


def test_extract_imports_near_sink_handles_require_and_dynamic() -> None:
    """``require()`` + dynamic ``import()`` both match."""
    content = (
        "const x = require('cjs-mod')\n"
        "const y = await import('esm-mod')\n"
        "fetch(url)\n"
    )
    out = _extract_imports_near_sink(content, sink_line=3, max_imports=5)
    assert "cjs-mod" in out
    assert "esm-mod" in out


def test_extract_imports_near_sink_returns_empty_on_no_imports() -> None:
    content = "function x() { fetch(url) }"
    assert _extract_imports_near_sink(content, sink_line=1) == []


def test_extract_imports_near_sink_caps_at_max_imports() -> None:
    """``max_imports=N`` enforced regardless of how many specifiers
    exist in the file."""
    lines = [f"import x{i} from 'mod-{i}'" for i in range(10)]
    lines.append("fetch(url)")
    content = "\n".join(lines)
    out = _extract_imports_near_sink(content, sink_line=11, max_imports=3)
    assert len(out) == 3


# ── RepoWorkspace.read_file ──────────────────────────────────────────


def test_workspace_read_file_returns_decoded_text(tmp_path: Path) -> None:
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {"src/x.ts": "const fetch = require('node-fetch');"}
    )
    assert ws.read_file("src/x.ts") == "const fetch = require('node-fetch');"


def test_workspace_read_file_returns_none_for_missing(tmp_path: Path) -> None:
    ws = _make_workspace(tmp_path, "o/r", "abc", {})
    assert ws.read_file("nope.ts") is None


def test_workspace_read_file_skips_oversize(tmp_path: Path) -> None:
    big = "x" * (DEFAULT_MAX_FILE_BYTES + 1)
    ws = _make_workspace(tmp_path, "o/r", "abc", {"big.ts": big})
    assert ws.read_file("big.ts") is None
    # But with a higher cap it works.
    assert ws.read_file("big.ts", max_bytes=DEFAULT_MAX_FILE_BYTES * 2) == big


def test_workspace_read_file_rejects_binary(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    target = root / "blob.bin"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)
    ws = RepoWorkspace(repo_full_name="o/r", ref="abc", root=root)
    assert ws.read_file("blob.bin") is None


# ── RepoWorkspace.resolve_import ─────────────────────────────────────


def test_resolve_relative_import_with_ts_extension(tmp_path: Path) -> None:
    """``./httpSecurity`` from ``src/foo.ts`` resolves to
    ``src/httpSecurity.ts``."""
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {
            "src/foo.ts": "import { x } from './httpSecurity'",
            "src/httpSecurity.ts": "export const x = 1",
        },
    )
    assert ws.resolve_import("src/foo.ts", "./httpSecurity") == "src/httpSecurity.ts"


def test_resolve_relative_import_with_parent_dir(tmp_path: Path) -> None:
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {
            "src/controllers/foo.ts": "",
            "src/services/bar.ts": "",
        },
    )
    out = ws.resolve_import("src/controllers/foo.ts", "../services/bar")
    assert out == "src/services/bar.ts"


def test_resolve_relative_import_directory_index(tmp_path: Path) -> None:
    """``./services`` → ``./services/index.ts``."""
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {
            "src/foo.ts": "",
            "src/services/index.ts": "export {}",
        },
    )
    assert ws.resolve_import("src/foo.ts", "./services") == "src/services/index.ts"


def test_resolve_relative_import_refuses_escape(tmp_path: Path) -> None:
    """``../../../etc/passwd`` style escape is refused even when the
    target somehow exists (defense-in-depth)."""
    ws = _make_workspace(tmp_path, "o/r", "abc", {"src/foo.ts": ""})
    # Even if we ask for something outside the workspace root, the
    # function returns None instead of leaking a non-workspace path.
    assert ws.resolve_import("src/foo.ts", "../../../escape") is None


def test_resolve_workspace_package_by_name_field(tmp_path: Path) -> None:
    """A monorepo with ``packages/flowise-components/`` and
    ``packages/flowise-components/package.json`` declaring
    ``"name": "flowise-components"`` should be resolved when
    something imports ``from 'flowise-components'``."""
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {
            "packages/flowise-components/package.json": json.dumps(
                {
                    "name": "flowise-components",
                    "main": "dist/index.js",
                }
            ),
            "packages/flowise-components/src/index.ts": "export {}",
        },
    )
    out = ws.resolve_import("apps/api/x.ts", "flowise-components")
    # We prefer ``src/index.<ext>`` since the main path doesn't exist
    # in the test workspace.
    assert out == "packages/flowise-components/src/index.ts"


def test_resolve_workspace_package_with_scoped_name(tmp_path: Path) -> None:
    """Scoped names like ``@n8n/computer-use`` should resolve."""
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {
            "packages/computer-use/package.json": json.dumps(
                {"name": "@n8n/computer-use"}
            ),
            "packages/computer-use/src/index.ts": "export {}",
        },
    )
    out = ws.resolve_import("apps/x.ts", "@n8n/computer-use")
    assert out == "packages/computer-use/src/index.ts"


def test_resolve_bare_external_import_returns_none(tmp_path: Path) -> None:
    """Bare imports for third-party packages (no internal workspace
    match) return None — we don't want to suck in node_modules."""
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {"src/foo.ts": "import axios from 'axios'"},
    )
    assert ws.resolve_import("src/foo.ts", "axios") is None


# ── _build_judge_context ─────────────────────────────────────────────


def test_build_judge_context_includes_candidate_and_resolved_imports(
    tmp_path: Path,
) -> None:
    """The composed text must include both the candidate file's
    sink-windowed body AND each resolved import's source."""
    controller_src = (
        "import service from '../services/foo'\n"
        "function getAllLinks(req) {\n"
        "  return service(req.query.url)\n"
        "}\n"
    )
    service_src = (
        "import { checkDenyList } from '../../components/httpSecurity'\n"
        "export default async function service(url) {\n"
        "  await checkDenyList(url)\n"
        "  return fetch(url)\n"
        "}\n"
    )
    security_src = (
        "export async function checkDenyList(url) { /* real guard */ }\n"
    )
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {
            "src/controllers/foo.ts": controller_src,
            "src/services/foo.ts": service_src,
            "components/httpSecurity.ts": security_src,
        },
    )
    composed, resolved = _build_judge_context(
        candidate_file_path="src/services/foo.ts",
        candidate_content=service_src,
        sink_line=4,
        workspace=ws,
        sink_callee="fetch",
    )
    # Candidate file section is present.
    assert "src/services/foo.ts" in composed
    # The imported httpSecurity content was resolved + inlined.
    assert "src/services/foo.ts" in composed or "httpSecurity" in composed
    assert "components/httpSecurity.ts" in resolved
    assert "real guard" in composed


def test_build_judge_context_no_imports_when_sink_missing(
    tmp_path: Path,
) -> None:
    """sink_line=0 → skip the import-resolution step; only candidate
    file is included."""
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {
            "src/foo.ts": "import x from './y'\n",
            "src/y.ts": "export const x = 1\n",
        },
    )
    composed, resolved = _build_judge_context(
        candidate_file_path="src/foo.ts",
        candidate_content="import x from './y'\n",
        sink_line=0,
        workspace=ws,
        sink_callee="fetch",
    )
    assert resolved == []
    # Candidate content still present.
    assert "import x from './y'" in composed


# ── _build_judge_candidates ──────────────────────────────────────────


def test_build_judge_candidates_includes_only_fetched_with_snippet() -> None:
    sig = _sig(sink_callee="fetch")
    f_ok = CrossRepoFetched(
        candidate=_cand("a/b", "x.ts"),
        content="...",
        snippet="fetch(url)",
        first_sink_line=42,
    )
    f_skipped = CrossRepoFetched(
        candidate=_cand("c/d", "y.ts"),
        skipped_reason="download_failed",
    )
    f_no_snippet = CrossRepoFetched(
        candidate=_cand("e/f", "z.ts"),
        content="some content",
        snippet="",
    )

    out = _build_judge_candidates([f_ok, f_skipped, f_no_snippet], sig)
    assert len(out) == 1
    assert out[0]["function_name"] == "a/b/x.ts"
    assert out[0]["line_number"] == 42
    assert out[0]["sink_callees_observed"] == ["fetch"]


def test_build_judge_candidates_uses_repo_path_as_identifier() -> None:
    sig = _sig(sink_callee="fetch")
    fs = [
        CrossRepoFetched(
            candidate=_cand("a/b", "x.ts"),
            snippet="fetch(...)", first_sink_line=1,
        ),
        CrossRepoFetched(
            candidate=_cand("c/d", "x.ts"),  # same path, different repo
            snippet="fetch(...)", first_sink_line=1,
        ),
    ]
    out = _build_judge_candidates(fs, sig)
    identifiers = [c["function_name"] for c in out]
    assert identifiers == ["a/b/x.ts", "c/d/x.ts"]
    assert len(set(identifiers)) == 2


# ── _invoke_variant_judge ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_invoke_variant_judge_parses_rankings() -> None:
    sig = _sig(sink_callee="fetch")
    inputs = [
        {
            "function_name": "a/b/x.ts",
            "line_number": 42,
            "source_snippet": "fetch(url)",
            "sink_callees_observed": ["fetch"],
        },
    ]

    async def fake_inference(prompt, options, schema):
        return {
            "schema_valid": True,
            "text": json.dumps(
                {
                    "rankings": [
                        {
                            "function_name": "a/b/x.ts",
                            "similarity_score": 0.85,
                            "rationale": "fetch on untrusted URL with no guards",
                        }
                    ]
                }
            ),
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        }

    out = await _invoke_variant_judge(
        signature=sig, judge_inputs=inputs, inference=fake_inference
    )
    assert out["a/b/x.ts"][0] == 0.85


@pytest.mark.asyncio
async def test_invoke_variant_judge_returns_empty_on_invalid_schema() -> None:
    async def fake_inference(prompt, options, schema):
        return {
            "schema_valid": False,
            "schema_error": "missing required field",
            "text": "{}",
        }
    out = await _invoke_variant_judge(
        signature=_sig(),
        judge_inputs=[
            {"function_name": "x/y/z.ts", "line_number": 1,
             "source_snippet": "...", "sink_callees_observed": ["fetch"]}
        ],
        inference=fake_inference,
    )
    assert out == {}


@pytest.mark.asyncio
async def test_invoke_variant_judge_handles_json_decode_failure() -> None:
    async def fake_inference(prompt, options, schema):
        return {"schema_valid": True, "text": "not valid json{{{"}
    out = await _invoke_variant_judge(
        signature=_sig(),
        judge_inputs=[
            {"function_name": "a/b.ts", "line_number": 1,
             "source_snippet": "...", "sink_callees_observed": ["fetch"]}
        ],
        inference=fake_inference,
    )
    assert out == {}


@pytest.mark.asyncio
async def test_invoke_variant_judge_clamps_scores() -> None:
    async def fake_inference(prompt, options, schema):
        return {
            "schema_valid": True,
            "text": json.dumps({
                "rankings": [
                    {"function_name": "x/y.ts", "similarity_score": 1.7, "rationale": "high"},
                    {"function_name": "p/q.ts", "similarity_score": -0.3, "rationale": "low"},
                ]
            }),
        }
    out = await _invoke_variant_judge(
        signature=_sig(),
        judge_inputs=[
            {"function_name": "x/y.ts", "line_number": 1,
             "source_snippet": "...", "sink_callees_observed": ["fetch"]},
            {"function_name": "p/q.ts", "line_number": 1,
             "source_snippet": "...", "sink_callees_observed": ["fetch"]},
        ],
        inference=fake_inference,
    )
    assert out["x/y.ts"][0] == 1.0
    assert out["p/q.ts"][0] == 0.0


@pytest.mark.asyncio
async def test_invoke_variant_judge_skips_call_on_empty_inputs() -> None:
    called = []

    async def fake_inference(prompt, options, schema):
        called.append(1)
        return {}
    out = await _invoke_variant_judge(
        signature=_sig(),
        judge_inputs=[],
        inference=fake_inference,
    )
    assert out == {}
    assert called == []


@pytest.mark.asyncio
async def test_invoke_variant_judge_scales_max_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Batch of 30 candidates should request more than the default
    2048 max_tokens — protects against truncated-rankings bug."""
    captured: dict[str, Any] = {}

    async def fake_inference(prompt, options, schema):
        captured["max_tokens"] = options["max_tokens"]
        return {"schema_valid": True, "text": '{"rankings": []}'}

    big_inputs = [
        {
            "function_name": f"o/r/file_{i}.ts",
            "line_number": 1,
            "source_snippet": "...",
            "sink_callees_observed": ["fetch"],
        }
        for i in range(30)
    ]
    await _invoke_variant_judge(
        signature=_sig(), judge_inputs=big_inputs, inference=fake_inference,
    )
    assert captured["max_tokens"] > 2048
    assert captured["max_tokens"] <= 8192


# ── download_repo_tarball ────────────────────────────────────────────


def _make_fake_tarball(
    tmp_path: Path, files: dict[str, str], top_dir: str
) -> bytes:
    """Build a gzipped tar bytestring with GitHub's top-level
    directory naming convention."""
    staging = tmp_path / "staging"
    staging.mkdir()
    tar_path = tmp_path / "out.tar.gz"
    for rel, content in files.items():
        full = staging / top_dir / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(staging / top_dir, arcname=top_dir)
    return tar_path.read_bytes()


@pytest.mark.asyncio
async def test_download_repo_tarball_extracts_and_strips_top(
    tmp_path: Path,
) -> None:
    """Happy path: download a tarball, extract stripping the GitHub
    top-level dir, candidate files become accessible at their normal
    repo paths."""
    tarball = _make_fake_tarball(
        tmp_path,
        {
            "src/x.ts": "const a = 1",
            "package.json": '{"name": "test-pkg"}',
        },
        top_dir="owner-repo-abcdef",
    )

    def handler(req: httpx.Request) -> httpx.Response:
        assert "tarball/abc123" in str(req.url)
        return httpx.Response(200, content=tarball)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    ) as client:
        ws = await download_repo_tarball(
            "owner/repo", "abc123",
            client=client, cache_dir=tmp_path / "cache",
            github_token="ghp_test",
        )
    assert ws is not None
    # Top-level dir stripped — paths land at workspace root.
    assert (ws.root / "src" / "x.ts").is_file()
    assert ws.read_file("src/x.ts") == "const a = 1"


@pytest.mark.asyncio
async def test_download_repo_tarball_uses_cache_on_second_call(
    tmp_path: Path,
) -> None:
    """Second call with the same (repo, ref) should hit the cache and
    skip the HTTP request entirely."""
    tarball = _make_fake_tarball(
        tmp_path,
        {"x.ts": "hello"},
        top_dir="owner-repo-abc",
    )
    call_count = [0]

    def handler(req: httpx.Request) -> httpx.Response:
        call_count[0] += 1
        return httpx.Response(200, content=tarball)

    cache = tmp_path / "cache"
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    ) as client:
        ws1 = await download_repo_tarball(
            "o/r", "abc", client=client, cache_dir=cache
        )
        ws2 = await download_repo_tarball(
            "o/r", "abc", client=client, cache_dir=cache
        )

    assert ws1 is not None and ws2 is not None
    assert ws1.root == ws2.root
    assert call_count[0] == 1  # second call hit cache


@pytest.mark.asyncio
async def test_download_repo_tarball_handles_404(tmp_path: Path) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"Not Found")

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    ) as client:
        ws = await download_repo_tarball(
            "o/r", "abc",
            client=client, cache_dir=tmp_path / "cache",
        )
    assert ws is None


@pytest.mark.asyncio
async def test_download_repo_tarball_aborts_on_oversize(tmp_path: Path) -> None:
    """A tarball larger than max_bytes is rejected mid-stream."""
    huge_tarball = b"x" * 100_000

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=huge_tarball)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    ) as client:
        ws = await download_repo_tarball(
            "o/r", "abc",
            client=client, cache_dir=tmp_path / "cache",
            max_bytes=1024,  # tiny
        )
    assert ws is None


@pytest.mark.asyncio
async def test_download_repo_tarball_refuses_empty_inputs(tmp_path: Path) -> None:
    async with httpx.AsyncClient() as client:
        assert await download_repo_tarball(
            "", "abc", client=client, cache_dir=tmp_path
        ) is None
        assert await download_repo_tarball(
            "o/r", "", client=client, cache_dir=tmp_path
        ) is None


@pytest.mark.asyncio
async def test_download_repo_tarball_sends_bearer_when_token_provided(
    tmp_path: Path,
) -> None:
    captured_headers: dict[str, str] = {}
    tarball = _make_fake_tarball(tmp_path, {"x.ts": ""}, top_dir="t-d-1")

    def handler(req: httpx.Request) -> httpx.Response:
        for k, v in req.headers.items():
            captured_headers[k.lower()] = v
        return httpx.Response(200, content=tarball)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    ) as client:
        await download_repo_tarball(
            "o/r", "abc",
            client=client,
            cache_dir=tmp_path / "cache",
            github_token="ghp_real_token",
        )
    assert captured_headers.get("authorization") == "Bearer ghp_real_token"


# ── fetch_and_triage (end-to-end with workspace) ─────────────────────


@pytest.mark.asyncio
async def test_fetch_and_triage_full_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end with a mocked download that returns pre-built
    workspaces. Verifies the full pipeline runs and propagates judge
    scores onto the right candidates."""
    sig = _sig(sink_callee="fetch")

    # Two repos, one candidate each — different sinks, different
    # snippets.
    vuln_ws = _make_workspace(
        tmp_path, "vuln/repo", "abc",
        {"x.ts": "function f(u) {\n  fetch(u)\n}\n"},
    )
    safe_ws = _make_workspace(
        tmp_path, "safe/repo", "def",
        {"x.ts": "function g(u) {\n  fetch('https://example')\n}\n"},
    )

    async def fake_download(repo, ref, **kw):
        if repo == "vuln/repo":
            return vuln_ws
        if repo == "safe/repo":
            return safe_ws
        return None

    monkeypatch.setattr(
        "dast.cross_repo_retrieval.download_repo_tarball",
        fake_download,
    )

    async def fake_inference(prompt, options, schema):
        return {
            "schema_valid": True,
            "text": json.dumps({
                "rankings": [
                    {"function_name": "vuln/repo/x.ts",
                     "similarity_score": 0.9, "rationale": "untrusted URL"},
                    {"function_name": "safe/repo/x.ts",
                     "similarity_score": 0.2, "rationale": "hardcoded URL"},
                ]
            }),
        }

    candidates = [
        _cand("vuln/repo", "x.ts", ref="abc"),
        _cand("safe/repo", "x.ts", ref="def"),
    ]
    results = await fetch_and_triage(
        sig, candidates, inference=fake_inference,
        cache_dir=tmp_path / "cache",
        triage_threshold=0.5,
    )
    by_repo = {r.fetched.candidate.repo_full_name: r for r in results}
    assert by_repo["vuln/repo"].similarity_score == 0.9
    assert by_repo["vuln/repo"].is_match is True
    assert by_repo["safe/repo"].similarity_score == 0.2
    assert by_repo["safe/repo"].is_match is False


@pytest.mark.asyncio
async def test_fetch_and_triage_groups_by_repo_one_download_per_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple candidates from the same (repo, ref) → ONE tarball
    download. Critical for cost — 10 candidates from 1 repo should
    not trigger 10 downloads."""
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {
            "a.ts": "fetch(x)",
            "b.ts": "fetch(y)",
            "c.ts": "fetch(z)",
        },
    )
    download_calls = []

    async def fake_download(repo, ref, **kw):
        download_calls.append((repo, ref))
        return ws

    monkeypatch.setattr(
        "dast.cross_repo_retrieval.download_repo_tarball",
        fake_download,
    )

    async def fake_inference(prompt, options, schema):
        rankings = [
            {"function_name": f"o/r/{p}", "similarity_score": 0.3,
             "rationale": "ok"}
            for p in ("a.ts", "b.ts", "c.ts")
        ]
        return {"schema_valid": True, "text": json.dumps({"rankings": rankings})}

    candidates = [
        _cand("o/r", "a.ts", ref="abc"),
        _cand("o/r", "b.ts", ref="abc"),
        _cand("o/r", "c.ts", ref="abc"),
    ]
    await fetch_and_triage(
        _sig(), candidates, inference=fake_inference,
        cache_dir=tmp_path / "cache",
    )
    assert download_calls == [("o/r", "abc")]


@pytest.mark.asyncio
async def test_fetch_and_triage_propagates_download_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One repo's download fails → those candidates get
    skipped_reason='download_failed', other repos still get judged."""
    good_ws = _make_workspace(
        tmp_path, "good/repo", "abc",
        {"x.ts": "fetch(u)"},
    )

    async def fake_download(repo, ref, **kw):
        if repo == "bad/repo":
            return None
        return good_ws

    monkeypatch.setattr(
        "dast.cross_repo_retrieval.download_repo_tarball",
        fake_download,
    )

    async def fake_inference(prompt, options, schema):
        return {
            "schema_valid": True,
            "text": json.dumps({
                "rankings": [
                    {"function_name": "good/repo/x.ts",
                     "similarity_score": 0.7, "rationale": "match"}
                ]
            }),
        }
    candidates = [
        _cand("bad/repo", "x.ts", ref="abc"),
        _cand("good/repo", "x.ts", ref="abc"),
    ]
    results = await fetch_and_triage(
        _sig(), candidates, inference=fake_inference,
        cache_dir=tmp_path / "cache",
    )
    by_repo = {r.fetched.candidate.repo_full_name: r for r in results}
    assert by_repo["bad/repo"].skipped_reason == "download_failed"
    assert by_repo["good/repo"].similarity_score == 0.7
    assert by_repo["good/repo"].is_match is True


@pytest.mark.asyncio
async def test_fetch_and_triage_handles_missing_file_in_tarball(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Candidate file path doesn't exist in the downloaded tarball
    (renamed since search indexed). Skipped, doesn't crash."""
    ws = _make_workspace(tmp_path, "o/r", "abc", {"actual.ts": "fetch(x)"})

    async def fake_download(repo, ref, **kw):
        return ws
    monkeypatch.setattr(
        "dast.cross_repo_retrieval.download_repo_tarball", fake_download,
    )

    async def fake_inference(prompt, options, schema):
        return {"schema_valid": True, "text": '{"rankings": []}'}

    results = await fetch_and_triage(
        _sig(),
        [_cand("o/r", "nonexistent.ts", ref="abc")],
        inference=fake_inference,
        cache_dir=tmp_path / "cache",
    )
    assert results[0].skipped_reason == "file_not_in_tarball"


@pytest.mark.asyncio
async def test_fetch_and_triage_marks_sink_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    ws = _make_workspace(
        tmp_path, "o/r", "abc",
        {"x.ts": "function g() { return 1 }"},
    )

    async def fake_download(repo, ref, **kw):
        return ws
    monkeypatch.setattr(
        "dast.cross_repo_retrieval.download_repo_tarball", fake_download,
    )

    called = []

    async def fake_inference(prompt, options, schema):
        called.append(1)
        return {"schema_valid": True, "text": '{"rankings": []}'}

    results = await fetch_and_triage(
        _sig(),
        [_cand("o/r", "x.ts", ref="abc")],
        inference=fake_inference,
        cache_dir=tmp_path / "cache",
    )
    assert results[0].skipped_reason == "sink_not_found"
    # No surviving candidates → no judge call.
    assert called == []


@pytest.mark.asyncio
async def test_fetch_and_triage_threshold_inclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """score == triage_threshold → is_match=True."""
    ws = _make_workspace(tmp_path, "o/r", "abc", {"x.ts": "fetch(x)"})

    async def fake_download(repo, ref, **kw):
        return ws
    monkeypatch.setattr(
        "dast.cross_repo_retrieval.download_repo_tarball", fake_download,
    )

    async def fake_inference(prompt, options, schema):
        return {
            "schema_valid": True,
            "text": json.dumps({"rankings": [
                {"function_name": "o/r/x.ts",
                 "similarity_score": 0.5, "rationale": "borderline"}
            ]}),
        }

    results = await fetch_and_triage(
        _sig(),
        [_cand("o/r", "x.ts", ref="abc")],
        inference=fake_inference,
        cache_dir=tmp_path / "cache",
        triage_threshold=0.5,
    )
    assert results[0].is_match is True


@pytest.mark.asyncio
async def test_fetch_and_triage_empty_input_short_circuits(
    tmp_path: Path,
) -> None:
    async def fake_inference(prompt, options, schema):
        return {}
    out = await fetch_and_triage(
        _sig(), [], inference=fake_inference,
        cache_dir=tmp_path / "cache",
    )
    assert out == []


@pytest.mark.asyncio
async def test_fetch_and_triage_marks_judge_failed_when_schema_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    ws = _make_workspace(tmp_path, "o/r", "abc", {"x.ts": "fetch(x)"})

    async def fake_download(repo, ref, **kw):
        return ws
    monkeypatch.setattr(
        "dast.cross_repo_retrieval.download_repo_tarball", fake_download,
    )

    async def broken_inference(prompt, options, schema):
        return {"schema_valid": False, "schema_error": "boom"}

    results = await fetch_and_triage(
        _sig(),
        [_cand("o/r", "x.ts", ref="abc")],
        inference=broken_inference,
        cache_dir=tmp_path / "cache",
    )
    assert results[0].skipped_reason == "judge_failed"
    assert results[0].similarity_score == 0.0


def test_max_imports_constant_is_sensible() -> None:
    """Smoke test that the constant is in a reasonable range — too
    low means we miss guards; too high blows the prompt budget."""
    assert 2 <= MAX_IMPORTS_PER_CANDIDATE <= 8
