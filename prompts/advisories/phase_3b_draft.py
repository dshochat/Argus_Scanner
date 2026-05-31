"""Phase 3b — draft of the enhanced ``_ATTACK_VECTOR_ADVISORY`` text.

NOT WIRED IN. Pre-staged for the methodology-validated rollout.

Drop-in replacement for the constant currently defined in
``sast/analysis/l1/prompt.py``. The replacement procedure once we have
methodology measurement:

    1. Run N=5 baseline with current text (save as `_eval_before_*.json`)
    2. Edit `sast/analysis/l1/prompt.py` to use this constant
    3. Run N=3 with new text (save as `_eval_after_*.json`)
    4. `uv run python scripts/dast_prototype/_run_per_fix_evaluation.py
        --before _eval_before_*.json --after _eval_after_*.json
        --min-z 1.0`
    5. If lift_detected=True AND zero tier-1/2 regressions, ship as a
       separate PR (not bundled with anything else, so the lift
       attribution is clean).

Sized: 277 words, ~360 tokens. Replaces the 116-word current advisory.
Net cost: ~+260 tokens per priority≥4 file. Affects roughly half the
23-file regression suite at any given run; total L1 input cost ~+5%.

See ``phase_3b_advisory_drafts.md`` for per-file pattern analysis and
the rationale for each new sub-pattern (3a-3d).
"""

from __future__ import annotations


_ATTACK_VECTOR_ADVISORY_PHASE_3B_DRAFT = (
    "## Attack-vector file (preprocessing-detected)\n\n"
    "This file is a recognised supply-chain or sensitive-attack-surface "
    "vector. Preprocessing flagged at least one of:\n"
    "- ``imperative_install_detected`` — module-level subprocess / "
    "os.system / urllib / file-write calls; postinstall hooks; "
    "``.pth`` import lines\n"
    "- ``attack_vector_extension`` — standalone ``.pth`` / ``.whl`` / "
    "``.egg`` / ``.spec``\n"
    "- ``crypto_sensitivity_detected`` — hazmat / Crypto / Cryptodome / "
    "OpenSSL / nacl / passlib imports OR misuse-name identifiers "
    "(``legacy_iv``, ``static_iv``, ``hardcoded_key``) OR hardcoded "
    "AES-key/IV material OR ``MODE_ECB`` content marker\n"
    "- triage assigned ``priority_score >= 4`` on its own assessment\n\n"
    "**Verdict guidance for this file class:**\n\n"
    "1. **Weight** the verdict on dynamic-execution surface behaviours: "
    "what runs at import / install time, what subprocess / network / "
    "filesystem operations the code can perform, what environment "
    "variables it reads, what files it writes.\n\n"
    "2. **Do not** weight the verdict primarily on stated intent in "
    "docstrings, comments, or variable names. Cover-story phrasing — "
    '"legacy compatibility shim", "build helper", "optional telemetry", '
    '"audit metadata", "demo placeholder", "neutered for testing", '
    '"regression test fixture" — is a recurring disguise for the '
    "malicious code itself.\n\n"
    "3. **Specific cover-story patterns that DO NOT clear a file:**\n\n"
    "   - **3a. Helper functions pattern.** Malicious behaviour located "
    "inside module-level functions (not module-level top-level code) "
    "is still malicious. The presence of a function that performs "
    "credential harvest, persistence write, network exfil, SSH backdoor "
    "setup, or filesystem writes outside ``/tmp`` is the payload — "
    "regardless of whether top-level code or ``__main__`` invokes it. "
    "Flag the function's intent, not only its call site.\n\n"
    "   - **3b. Sensitive-prefix enumeration pattern.** Code that "
    "iterates ``os.environ`` filtering on credential-name prefixes "
    "(``AWS_``, ``GITHUB_``, ``GCP_``, ``AZURE_``, ``TOKEN``, "
    "``SECRET``, ``API_KEY``, ``PASSWORD``, ``NPM_``, ``PYPI_``, "
    "``DATABASE_URL``) and collects matches into a dict is "
    "enumerating credentials regardless of whether the dict is posted "
    "to a network endpoint in this same file. The prefix-filter list "
    "is the malicious tell. Same applies to code that reads "
    "``~/.netrc``, ``~/.aws/credentials``, ``~/.npmrc``, ``~/.pypirc``, "
    "``~/.config/pip/pip.conf``, or other well-known credential "
    "locations.\n\n"
    "   - **3c. CVE structural reproduction pattern.** Files that "
    "explicitly reproduce a CVE structure for benchmark / test / demo "
    "purposes — even with the payload neutered to a ``print`` / log "
    "statement — are not clean. Minimum verdict: ``suspicious``. The "
    "CVE structure persists across deployments; benchmark-only "
    "neutering is a fixture-level promise, not a code-level safety "
    "property.\n\n"
    "   - **3d. Persistence in standard locations pattern.** Writes "
    "to ``/etc/cron.d``, ``/etc/systemd``, ``/etc/init.d``, "
    "``/usr/local/bin``, ``~/.bashrc``, ``~/.bash_profile``, "
    "``~/.ssh/authorized_keys``, and similar locations — even via "
    "helper functions — are persistence by construction.\n\n"
    "4. A ``clean`` verdict on this file class requires showing the "
    "dynamic-execution surface is demonstrably benign — not just "
    "that the author's comments claim it is. Specifically:\n"
    "   - Helper functions exist for legitimate, declared purposes "
    "only (no credential enumeration, network exfil, persistence, "
    "or remote-access setup buried inside).\n"
    "   - No CVE structures present (even neutered ones).\n"
    "   - All file-write / subprocess / network calls are bounded to "
    "``/tmp``, ``/workspace``, the package's own data directory, or "
    "are genuinely unreachable from any execution path.\n\n"
    "When any of 3a-3d apply but the runtime impact is genuinely "
    "bounded (e.g. ``shell=True`` call is commented-out structurally), "
    "the correct verdict is ``suspicious``, not ``clean``.\n\n"
)


if __name__ == "__main__":
    # Sanity check: print the constant + report token estimate so we
    # can confirm cost projection before the methodology run.
    import sys
    sys.path.insert(0, "C:/WEB/echo/echoDefense")

    print(_ATTACK_VECTOR_ADVISORY_PHASE_3B_DRAFT)
    print("=" * 60)

    # Cheap token-count approximation: chars / 4
    chars = len(_ATTACK_VECTOR_ADVISORY_PHASE_3B_DRAFT)
    rough_tokens = chars // 4
    print(f"chars={chars}  ~tokens={rough_tokens}")

    try:
        from shared.utils.tokenize import approx_token_count
        print(
            "approx_token_count="
            f"{approx_token_count(_ATTACK_VECTOR_ADVISORY_PHASE_3B_DRAFT)}"
        )
    except Exception as e:  # noqa: BLE001
        print(f"(approx_token_count unavailable: {e})")
