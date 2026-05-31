"""Build a multi-vendor consensus oracle from voter outputs (BENCH-014).

Takes ``VoterRecord``\\s from N voters (typically Opus 4.6 + Gemini 3.1 Pro
+ GPT-5.5) and produces a per-file consensus verdict via ordinal-median
tie-breaking.

Why median (not naive majority): with 3 ordinal verdicts, the median
handles all three split patterns cleanly:

  * 3-way agreement (all "suspicious") -> "suspicious"
  * 2-1 split (suspicious / suspicious / malicious) -> "suspicious" (majority + median agree)
  * 3-way split (clean / suspicious / malicious) -> "suspicious" (median is the
    most defensible single answer; a naive "majority" rule would have
    no winner)

The 4-tier ordinal scale matches the regression-suite oracle:
``clean=0, suspicious=1, malicious=2, critical_malicious=3``.

Output schema (mirrors regression_baseline.json):

    {
      "files": [
        {
          "file_name": "litellm_obfuscated.py",
          "oracle_verdict": "critical_malicious",
          "voter_verdicts": {
            "opus_4_6": "critical_malicious",
            "gemini_3_1_pro": "critical_malicious",
            "gpt_5_5": "critical_malicious"
          },
          "n_voters": 3,
          "is_unanimous": true,
          "is_majority": true,
          "median_rank": 3,
          "min_rank": 3,
          "max_rank": 3,
          "spread": 0,
          "source": "consensus_3_vendor"
        }
      ],
      "metadata": {
        "voters": ["opus_4_6", "gemini_3_1_pro", "gpt_5_5"],
        "tie_break": "ordinal_median",
        "n_files": 23
      }
    }

The launch report consumes this directly via ``baseline_oracle_path``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from methodology.voters import VoterRecord, _load_existing_voter_records

# 4-tier ordinal scale (matches regression-suite oracle vocabulary).
VERDICT_RANK: dict[str, int] = {
    "clean": 0,
    "suspicious": 1,
    "malicious": 2,
    "critical_malicious": 3,
}
RANK_TO_VERDICT: dict[int, str] = {v: k for k, v in VERDICT_RANK.items()}


# ── Per-file consensus ───────────────────────────────────────────────────────


def median_verdict(verdicts: Iterable[str]) -> str | None:
    """Compute the ordinal median of a sequence of verdict labels.

    Unknown labels are dropped (don't pollute the median). Returns
    ``None`` when no usable verdicts remain.

    For an even count, ties are broken DOWNWARD (toward the lower-
    severity verdict) — conservative bias in oracle construction.
    """
    ranks = sorted(VERDICT_RANK[v] for v in verdicts if v in VERDICT_RANK)
    if not ranks:
        return None
    n = len(ranks)
    if n % 2 == 1:
        return RANK_TO_VERDICT[ranks[n // 2]]
    # Even count: take the lower of the two middle values (conservative).
    return RANK_TO_VERDICT[ranks[n // 2 - 1]]


def _consensus_string_set(
    voter_records: list[VoterRecord],
    extract: Any,
    *,
    min_voters: int = 2,
    normalize: Any = None,
) -> dict[str, Any]:
    """Compute majority-vote consensus on a set of strings extracted from
    each voter's raw_output.

    ``extract`` is a callable ``(voter_record) -> Iterable[str]`` that
    returns the strings that voter cast a vote for (e.g., set of CWEs
    mentioned, set of capability tags, set of dangerous APIs).
    ``normalize`` (optional) post-processes each string before voting.
    Returns ``{consensus: list, votes_per: dict[str, int], n_voters: int}``.

    A string is in the consensus if at least ``min_voters`` voters
    listed it. With 4 voters and ``min_voters=2`` that's the natural
    "≥half" majority rule.
    """
    if normalize is None:
        normalize = lambda s: s.strip().upper() if isinstance(s, str) else None

    votes: dict[str, int] = {}
    n_voters = 0
    for r in voter_records:
        if r.error:
            continue
        items = extract(r) or []
        normalized = {normalize(x) for x in items if x is not None}
        normalized.discard(None)
        normalized.discard("")
        if not normalized:
            # Voter ran successfully but had no items in this category —
            # they still "vote zero", so count them as a voter.
            n_voters += 1
            continue
        n_voters += 1
        for s in normalized:
            votes[s] = votes.get(s, 0) + 1

    consensus = sorted(s for s, c in votes.items() if c >= min_voters)
    return {
        "consensus": consensus,
        "votes_per": dict(sorted(votes.items())),
        "n_voters": n_voters,
        "min_voters_for_consensus": min_voters,
    }


def _extract_cwes(r: VoterRecord) -> list[str]:
    out: list[str] = []
    for v in r.raw_findings or []:
        if isinstance(v, dict):
            cwe = v.get("cwe")
            if isinstance(cwe, str) and cwe:
                out.append(cwe)
    return out


def _extract_capability_tags(r: VoterRecord) -> list[str]:
    """Capability tag set, derived from ``behavioral_profile.actual_capabilities``.

    The SECURITY_SCAN_PROMPT schema doesn't emit a top-level
    ``extractions.capabilities.tags`` — that was specific to
    echoDefense's augmented oracle. The same information lives at
    ``behavioral_profile.actual_capabilities.{network_calls,
    commands_executed, ...}`` on every model's output.
    """
    if not r.raw_output or not isinstance(r.raw_output, dict):
        return []
    bp = r.raw_output.get("behavioral_profile") or {}
    if not isinstance(bp, dict):
        return []
    actual = bp.get("actual_capabilities") or {}
    if not isinstance(actual, dict):
        return []
    tags: list[str] = []
    if actual.get("network_calls"):
        tags.append("NETWORK_OUTBOUND")
    if actual.get("commands_executed"):
        tags.append("PROCESS_SPAWN")
    if actual.get("dynamic_imports"):
        tags.append("DYNAMIC_EXECUTION")
    if actual.get("crypto_operations"):
        tags.append("CRYPTO_USE")
    if actual.get("env_vars_accessed"):
        tags.append("ENV_ACCESS")
    if actual.get("serialization"):
        tags.append("SERIALIZATION")
    file_ops = actual.get("file_operations") or []
    if isinstance(file_ops, list) and file_ops:
        tags.append("FILE_IO")
    exfil = bp.get("exfiltration_risk") or {}
    if isinstance(exfil, dict) and exfil.get("external_network_calls"):
        tags.append("DATA_EXFILTRATION")
    return tags


def _extract_dangerous_apis(r: VoterRecord) -> list[str]:
    """Concrete API/command/library names from
    ``behavioral_profile.actual_capabilities.{commands_executed, dynamic_imports,
    serialization, network_calls.destination}``. These are model-extracted
    string identifiers (e.g., ``subprocess.run``, ``urllib.urlopen``,
    ``pickle.loads``) that we treat as the "dangerous_apis" axis even though
    the SECURITY_SCAN_PROMPT doesn't use that exact field name.
    """
    if not r.raw_output or not isinstance(r.raw_output, dict):
        return []
    bp = r.raw_output.get("behavioral_profile") or {}
    if not isinstance(bp, dict):
        return []
    actual = bp.get("actual_capabilities") or {}
    if not isinstance(actual, dict):
        return []
    out: list[str] = []
    for key in ("commands_executed", "dynamic_imports", "serialization"):
        items = actual.get(key) or []
        if isinstance(items, list):
            out.extend(str(x) for x in items if isinstance(x, str))
    network = actual.get("network_calls") or []
    if isinstance(network, list):
        for n in network:
            if isinstance(n, dict):
                dest = n.get("destination")
                if isinstance(dest, str) and dest:
                    out.append(dest)
    return out


def _extract_behavioral_categories(r: VoterRecord) -> list[str]:
    """Coarse behavioral signals from the scanner output's
    ``behavioral_profile``. Looks for the high-signal categories:
    network calls, exfil risk, dynamic execution, obfuscation."""
    if not r.raw_output or not isinstance(r.raw_output, dict):
        return []
    bp = r.raw_output.get("behavioral_profile") or {}
    if not isinstance(bp, dict):
        return []
    out: list[str] = []
    actual = bp.get("actual_capabilities") or {}
    if isinstance(actual, dict):
        if actual.get("network_calls"):
            out.append("NETWORK_OUTBOUND")
        if actual.get("commands_executed"):
            out.append("PROCESS_SPAWN")
        if actual.get("dynamic_imports"):
            out.append("DYNAMIC_EXECUTION")
        if actual.get("crypto_operations"):
            out.append("CRYPTO_USE")
    exfil = bp.get("exfiltration_risk") or {}
    if isinstance(exfil, dict) and exfil.get("external_network_calls"):
        out.append("DATA_EXFILTRATION")
    obf = bp.get("obfuscation_signals") or {}
    if isinstance(obf, dict):
        if obf.get("encoded_strings") or obf.get("dynamic_url_construction"):
            out.append("DEFENSE_EVASION")
        if obf.get("fetches_remote_instructions"):
            out.append("REMOTE_FETCH")
    return out


def build_consensus_record(
    file_name: str,
    voter_records: list[VoterRecord],
) -> dict[str, Any]:
    """Per-file consensus on verdict, CWEs, capability tags, dangerous
    APIs, and behavioral categories. Plus diagnostic metadata.

    Each voter contributes one vote per category. Per-string consensus
    is built via ``min_voters=2`` (i.e., ≥2 of N voters must mention
    a string for it to be in the consensus). For 3 voters that means
    "majority"; for 4 voters that's "at least half".
    """
    verdicts: dict[str, str] = {}
    valid_verdicts: list[str] = []
    for r in voter_records:
        if r.error:
            continue
        v = r.predicted_verdict
        if v not in VERDICT_RANK:
            continue
        verdicts[r.voter_name] = v
        valid_verdicts.append(v)

    consensus = median_verdict(valid_verdicts)
    ranks = [VERDICT_RANK[v] for v in valid_verdicts]
    is_unanimous = len(set(valid_verdicts)) == 1 if valid_verdicts else False
    counts: dict[str, int] = {}
    for v in valid_verdicts:
        counts[v] = counts.get(v, 0) + 1
    is_majority = (
        any(c > len(valid_verdicts) / 2 for c in counts.values()) if valid_verdicts else False
    )

    # Rich consensus: CWE / capability / dangerous-API / behavioral.
    cwe_consensus = _consensus_string_set(voter_records, _extract_cwes)
    cap_consensus = _consensus_string_set(voter_records, _extract_capability_tags)
    api_consensus = _consensus_string_set(voter_records, _extract_dangerous_apis)
    beh_consensus = _consensus_string_set(voter_records, _extract_behavioral_categories)

    return {
        "file_name": file_name,
        "oracle_verdict": consensus,
        "voter_verdicts": verdicts,
        "n_voters": len(valid_verdicts),
        "is_unanimous": is_unanimous,
        "is_majority": is_majority,
        "median_rank": ranks[len(ranks) // 2] if ranks else None,
        "min_rank": min(ranks) if ranks else None,
        "max_rank": max(ranks) if ranks else None,
        "spread": (max(ranks) - min(ranks)) if ranks else 0,
        "source": "consensus_multi_vendor",
        # Rich consensus: each is a list of strings + a per-string vote
        # tally so future callers can compute precision/recall against
        # the per-voter outputs.
        "cwe_consensus": cwe_consensus,
        "capability_tag_consensus": cap_consensus,
        "dangerous_api_consensus": api_consensus,
        "behavioral_category_consensus": beh_consensus,
    }


# ── Aggregator over multiple voter files ─────────────────────────────────────


def build_consensus_oracle(
    voter_files: dict[str, Path],
    file_list: list[str],
) -> dict[str, Any]:
    """Build the full consensus oracle.

    ``voter_files`` maps voter_name -> path to the voter's output JSON
    (produced by :func:`methodology.voters.run_voter`). ``file_list``
    is the canonical list of file_names — typically every file in the
    regression suite. Files with no voter records get ``oracle_verdict``
    = ``None`` and ``n_voters`` = 0.

    Returns the full oracle dict ready to be written to disk.
    """
    # Load and index each voter's records.
    by_voter: dict[str, dict[str, VoterRecord]] = {}
    for voter_name, path in voter_files.items():
        records = _load_existing_voter_records(path)
        by_voter[voter_name] = {r.file_name: r for r in records}

    out_files: list[dict[str, Any]] = []
    for fn in file_list:
        per_file: list[VoterRecord] = []
        for voter_name, recs in by_voter.items():
            r = recs.get(fn)
            if r is not None:
                per_file.append(r)
        out_files.append(build_consensus_record(fn, per_file))

    return {
        "files": out_files,
        "metadata": {
            "voters": list(voter_files.keys()),
            "tie_break": "ordinal_median",
            "n_files": len(file_list),
        },
    }


def write_consensus_oracle(oracle: dict[str, Any], path: Path) -> None:
    """Atomic-write oracle to ``path``."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(oracle, indent=2), encoding="utf-8")
    try:
        tmp.replace(path)
    except OSError:
        path.write_text(json.dumps(oracle, indent=2), encoding="utf-8")
        try:
            tmp.unlink()
        except OSError:
            pass


# ── Diagnostics: compare two oracles ─────────────────────────────────────────


def compare_oracles(
    old_oracle_path: Path,
    new_oracle_path: Path,
) -> dict[str, Any]:
    """Side-by-side diff of two oracles. Useful to see which files
    changed verdict between the old (variance + opus_confirmed) and
    new (multi-vendor consensus) oracles.

    Returns ``{shared, changed, only_old, only_new}`` summary plus a
    per-file breakdown of changed labels.
    """
    if not old_oracle_path.exists():
        old: dict[str, Any] = {"files": []}
    else:
        old = json.loads(old_oracle_path.read_text())
    if not new_oracle_path.exists():
        new: dict[str, Any] = {"files": []}
    else:
        new = json.loads(new_oracle_path.read_text())

    old_by = {f.get("file_name"): f for f in (old.get("files") or [])}
    new_by = {f.get("file_name"): f for f in (new.get("files") or [])}

    shared = set(old_by) & set(new_by)
    only_old = set(old_by) - set(new_by)
    only_new = set(new_by) - set(old_by)

    changed: list[dict[str, Any]] = []
    for fn in sorted(shared):
        ov = old_by[fn].get("oracle_verdict")
        nv = new_by[fn].get("oracle_verdict")
        if ov != nv:
            changed.append(
                {
                    "file_name": fn,
                    "old_verdict": ov,
                    "new_verdict": nv,
                    "voter_verdicts": new_by[fn].get("voter_verdicts") or {},
                }
            )

    return {
        "n_shared": len(shared),
        "n_changed": len(changed),
        "n_only_old": len(only_old),
        "n_only_new": len(only_new),
        "changed_files": changed,
        "only_in_old": sorted(only_old),
        "only_in_new": sorted(only_new),
    }


__all__ = [
    "RANK_TO_VERDICT",
    "VERDICT_RANK",
    "build_consensus_oracle",
    "build_consensus_record",
    "compare_oracles",
    "median_verdict",
    "write_consensus_oracle",
]
