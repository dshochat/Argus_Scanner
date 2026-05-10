"""GitHub Actions workflow inspection — supply-chain CI attack surface.

A workflow YAML at ``.github/workflows/*.yml`` defines what runs against
your code on every push or PR. The CI surface is exactly where
``pip install`` / ``npm install`` / ``go get`` happen, so a compromised
workflow IS a supply-chain attack — the code you wrote stays the same;
the *machinery executing it* gets owned.

Specific patterns this module flags (Argus's threat model for CI):

1. **``pull_request_target`` trigger** combined with checkout of the
   PR's HEAD ref (the ``GITHUB_HEAD_REF`` / ``github.event.pull_request.head.sha``
   pattern). This trigger runs in the *target* repo's context with full
   secrets, while the code being checked out comes from the attacker's
   fork — the canonical pwn-request pattern (CWE-863-adjacent).
2. **Third-party actions without SHA pinning.** ``uses: foo/bar@v1`` or
   ``uses: foo/bar@main`` re-runs whatever HEAD points at on each
   workflow execution. SHA pinning (``uses: foo/bar@<40-char hex>``)
   removes that drift surface.
3. **``${{ ... }}`` interpolation inside ``run:`` blocks.** Direct shell
   interpolation of ``github.event.*`` or ``github.head_ref`` etc. is
   the GHSL-2024-style command-injection class — issue/PR titles can
   contain ``$()`` / backticks.
4. **Over-permissive ``permissions:`` block.** ``permissions: write-all``
   or absence of any explicit permissions block (which means the workflow
   inherits the repo default). At minimum we surface what's declared.
5. **Plain ``secrets.*`` references inside ``run:`` blocks.** Often
   benign, but any pattern like ``run: curl ... -d "${{ secrets.X }}"``
   to an attacker-influenced URL is exfiltration.

We do not parse the YAML deeply — we use a permissive regex sweep over
the raw text, then synthesize a Python-with-comments report so the
cascade can render a verdict on top of the deterministic signals.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# ── Path matching ──────────────────────────────────────────────────────────


def is_github_actions_workflow(path: str | Path) -> bool:
    """Return True when the path looks like ``.github/workflows/*.yml``.

    Matches normalized forward-slash paths (Windows-friendly). Composite
    actions (``action.yml`` at repo root or ``actions/*/action.yml``)
    are NOT covered by this v1 — that's a separate file shape.
    """
    p = str(path).replace("\\", "/").lower()
    if not (p.endswith(".yml") or p.endswith(".yaml")):
        return False
    # Tolerate paths that include the prefix anywhere in the chain
    # (e.g. ``my-repo/.github/workflows/ci.yml``).
    return "/.github/workflows/" in p or p.startswith(".github/workflows/")


# ── Patterns ───────────────────────────────────────────────────────────────

# Triggers: top-level ``on: pull_request_target`` OR mapping form
# (``on:\n  pull_request_target:`` etc.)
_PR_TARGET_RE = re.compile(r"\bpull_request_target\b")
_WORKFLOW_RUN_RE = re.compile(r"\bworkflow_run\b")
_REPO_DISPATCH_RE = re.compile(r"\brepository_dispatch\b")

# ``uses: <owner>/<repo>[/<path>]@<ref>`` — captures the full ref string.
# YAML list items prefix the line with ``- ``, so we tolerate an optional
# leading ``- `` after any indent.
_USES_RE = re.compile(
    r"^\s*-?\s*uses:\s*([A-Za-z0-9_.\-/]+)@([A-Za-z0-9._\-]+)\s*$",
    re.MULTILINE,
)

# 40-char lowercase hex SHA (the secure pin form). Tolerate uppercase
# but warn — git refs are lowercase.
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")

# ``permissions:`` block presence + the dangerous shorthand forms
_PERMISSIONS_BLOCK_RE = re.compile(r"^\s*permissions:\s*", re.MULTILINE)
_PERMISSIONS_WRITE_ALL_RE = re.compile(r"^\s*permissions:\s*write-all\b", re.MULTILINE)

# ``${{ ... }}`` expressions, focused on the injection-prone sources
_DANGEROUS_INTERP_SOURCES = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.head_ref",
    "github.event.head_commit.message",
    "github.event.commits",
)
_INTERP_RE = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")

# ``run: ... ${{ ... }} ...`` — line starts with ``run:`` and contains
# an interpolation. ``run:`` can also be a multi-line literal block
# (``run: |\n  ...``); we handle both by scanning every line that follows
# a ``run:`` block until indent decreases.
_RUN_LINE_RE = re.compile(r"^\s*run:\s*\|\s*$", re.MULTILINE)

# Suspicious shell verbs in workflow ``run:`` blocks
_EXFIL_VERBS_RE = re.compile(
    r"\b(curl|wget|http\.client|requests\.|fetch\b|nc\s|openssl\s+s_client)\b",
    re.IGNORECASE,
)


# ── Result type ────────────────────────────────────────────────────────────


@dataclass
class WorkflowAnalysis:
    is_valid: bool
    synthesized_source: str

    triggers: list[str] = field(default_factory=list)
    has_pull_request_target: bool = False
    has_workflow_run: bool = False

    third_party_actions: list[dict[str, str]] = field(default_factory=list)
    """Each entry: ``{action: 'foo/bar', ref: 'v1', sha_pinned: 'true'/'false'}``."""

    n_unpinned_third_party: int = 0

    permissions_block_present: bool = False
    permissions_write_all: bool = False

    dangerous_interpolations: list[str] = field(default_factory=list)
    """The full ``${{ ... }}`` strings whose source is a known
    injection-prone field (issue title, PR body, etc.)."""

    run_blocks_with_interp: int = 0

    has_exfil_verbs_with_secrets: bool = False
    """True when at least one line contains both a network verb (curl /
    wget / etc.) AND a ``secrets.*`` interpolation. Heuristic — the
    cascade decides whether it's actually exfiltration."""

    parse_error: str | None = None


# ── Implementation ─────────────────────────────────────────────────────────


def _extract_triggers(text: str) -> list[str]:
    """Return the set of triggers declared. Tolerates both the inline
    list form (``on: [push, pull_request]``) and the mapping form
    (``on:\\n  push:\\n  pull_request:``)."""
    triggers: set[str] = set()
    for keyword in (
        "push",
        "pull_request",
        "pull_request_target",
        "workflow_run",
        "workflow_dispatch",
        "schedule",
        "release",
        "issue_comment",
        "issues",
        "discussion",
        "discussion_comment",
        "fork",
        "repository_dispatch",
        "deployment",
        "deployment_status",
        "page_build",
        "watch",
        "create",
        "delete",
        "label",
    ):
        if re.search(rf"\b{re.escape(keyword)}\b", text):
            triggers.add(keyword)
    return sorted(triggers)


def _is_third_party(action_path: str) -> bool:
    """``actions/*`` and ``github/*`` are first-party (GitHub-published).
    Everything else with at least one slash is third-party. Local actions
    (``./.github/actions/foo``) start with ``.``."""
    if action_path.startswith(".") or action_path.startswith("docker://"):
        return False
    if "/" not in action_path:
        return False
    owner = action_path.split("/", 1)[0]
    return owner not in ("actions", "github")


def _scan_run_blocks(text: str) -> tuple[int, bool]:
    """Walk the raw text line-by-line; for each ``run: |`` literal-block
    or single-line ``run: ...`` entry, count interpolations and check
    whether any line combines a network verb with ``secrets.*``.

    Returns ``(n_run_blocks_with_any_interp, has_exfil_verbs_with_secrets)``."""
    lines = text.splitlines()
    n_with_interp = 0
    exfil = False

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        run_match = re.match(r"run:\s*(\|[\-+]?)?\s*(.*)$", stripped)
        if run_match:
            block_lines: list[str] = []
            inline = run_match.group(2)
            if inline:
                block_lines.append(inline)
            # Determine indent level for continuation
            base_indent = len(line) - len(line.lstrip())
            j = i + 1
            while j < len(lines):
                cur = lines[j]
                if not cur.strip():
                    j += 1
                    continue
                cur_indent = len(cur) - len(cur.lstrip())
                if cur_indent <= base_indent:
                    break
                block_lines.append(cur)
                j += 1
            block = "\n".join(block_lines)
            if "${{" in block:
                n_with_interp += 1
            if "${{" in block and "secrets." in block and _EXFIL_VERBS_RE.search(block):
                exfil = True
            i = j
        else:
            i += 1
    return n_with_interp, exfil


def analyze_workflow(text: str) -> WorkflowAnalysis:
    """Run the deterministic sweep and synthesize a textual report.

    Always returns ``is_valid=True`` when the text is non-empty — we
    don't try to YAML-parse the file because YAML strictness would
    refuse adversarial workflows that pass GHA's looser parser. The
    textual report carries every detected signal.
    """
    if not text.strip():
        return WorkflowAnalysis(
            is_valid=False,
            synthesized_source="",
            parse_error="empty_text",
        )

    triggers = _extract_triggers(text)
    has_prt = bool(_PR_TARGET_RE.search(text))
    has_wfr = bool(_WORKFLOW_RUN_RE.search(text))

    actions: list[dict[str, str]] = []
    n_unpinned = 0
    for m in _USES_RE.finditer(text):
        action = m.group(1)
        ref = m.group(2)
        third = _is_third_party(action)
        sha_pinned = bool(_SHA_RE.match(ref))
        if third:
            actions.append(
                {
                    "action": action,
                    "ref": ref,
                    "sha_pinned": str(sha_pinned).lower(),
                }
            )
            if not sha_pinned:
                n_unpinned += 1

    perms_present = bool(_PERMISSIONS_BLOCK_RE.search(text))
    perms_wa = bool(_PERMISSIONS_WRITE_ALL_RE.search(text))

    dangerous: list[str] = []
    for m in _INTERP_RE.finditer(text):
        inner = m.group(1).strip()
        for src in _DANGEROUS_INTERP_SOURCES:
            if src in inner:
                dangerous.append(m.group(0))
                break

    n_run_with_interp, exfil = _scan_run_blocks(text)

    # ── Synthesize the Python-with-comments report ─────────────────────────
    parts: list[str] = ["# === GITHUB ACTIONS WORKFLOW ==="]
    parts.append(f"# triggers: {', '.join(triggers) if triggers else '(none detected)'}")
    if has_prt:
        parts.append("# ! pull_request_target detected — runs with secrets in target context")
    if has_wfr:
        parts.append("# ! workflow_run trigger — chained execution from another workflow")
    parts.append(f"# permissions block: {'declared' if perms_present else 'NOT DECLARED (uses repo default)'}")
    if perms_wa:
        parts.append("# ! permissions: write-all — no scope reduction")

    parts.append(f"# third-party actions: {len(actions)} (unpinned: {n_unpinned})")
    for a in actions:
        flag = "" if a["sha_pinned"] == "true" else "  ! NOT SHA-PINNED"
        parts.append(f"#   uses: {a['action']}@{a['ref']}{flag}")

    parts.append(f"# run-blocks with ${{...}}: {n_run_with_interp}")
    if dangerous:
        parts.append("# ! dangerous interpolations into shell context:")
        for d in dangerous:
            parts.append(f"#   {d}")
    if exfil:
        parts.append("# ! at least one run-block combines a network verb (curl/wget/etc.)")
        parts.append("#   with a `secrets.*` interpolation — possible exfiltration vector")

    parts.append("")
    parts.append("# === RAW WORKFLOW SOURCE FOLLOWS (cascade re-analyzes the YAML directly) ===")
    parts.append(text)

    return WorkflowAnalysis(
        is_valid=True,
        synthesized_source="\n".join(parts) + "\n",
        triggers=triggers,
        has_pull_request_target=has_prt,
        has_workflow_run=has_wfr,
        third_party_actions=actions,
        n_unpinned_third_party=n_unpinned,
        permissions_block_present=perms_present,
        permissions_write_all=perms_wa,
        dangerous_interpolations=dangerous,
        run_blocks_with_interp=n_run_with_interp,
        has_exfil_verbs_with_secrets=exfil,
    )


__all__ = [
    "WorkflowAnalysis",
    "analyze_workflow",
    "is_github_actions_workflow",
]
