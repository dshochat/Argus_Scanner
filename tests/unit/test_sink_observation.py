"""Unit tests for dast/sink_observation.py — SCAN-018 Phase 3.

Covers the kernel-syscall sink-observation oracle:

* Per-attack-class gating logic (ssrf, command_injection,
  path_traversal — the three classes Phase 3 covers in v1).
* Fail-open posture across every "we don't know" branch
  (missing observations, bpftrace_meta error, no events, attack
  class not gated).
* False-positive defense ON THE SUPPRESSOR (the syscall-sink check
  must not silently drop real findings).
* SandboxEvent extraction helper.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from dast.sink_observation import (
    MissingSinkInfo,
    _bpftrace_observed_anything,
    _extract_paths_from_input,
    extract_syscall_observations_from_events,
    find_missing_expected_sink,
)


# ─── Fail-open posture ──────────────────────────────────────────────────


def test_attack_class_not_gated_returns_none() -> None:
    """Classes outside the gated set (sql_injection, code_injection,
    xss, etc.) return None unconditionally — Phase 3 doesn't have a
    sink signal for them, so it must not interfere."""
    obs = {"total_events": 100, "network_events": []}
    for cls in ("sql_injection", "code_injection", "xss", "deserialization",
                "data_exfiltration", "crypto_weakness"):
        assert find_missing_expected_sink(
            attack_class=cls, syscall_observations=obs, args_json="[]"
        ) is None


def test_no_syscall_observations_returns_none() -> None:
    """Missing observation dict → fail-open. Kernel doesn't support
    bpftrace, sandbox image old, etc."""
    for obs in (None, {}, {"total_events": 0}):
        assert find_missing_expected_sink(
            attack_class="ssrf",
            syscall_observations=obs,
            args_json='["http://x.com"]',
        ) is None


def test_bpftrace_error_meta_returns_none() -> None:
    """bpftrace itself reported a lifecycle error → fail-open."""
    obs = {
        "total_events": 50,
        "bpftrace_meta": {"error": "tracepoint not found"},
        "network_events": [],
    }
    assert find_missing_expected_sink(
        attack_class="ssrf", syscall_observations=obs, args_json='["http://x"]'
    ) is None


# ─── ssrf gate ──────────────────────────────────────────────────────────


def test_ssrf_no_network_events_fires_suppression() -> None:
    """SSRF claimed but bpftrace observed zero network syscalls →
    string-oracle FP, suppress."""
    obs = {
        "total_events": 80,
        "network_events": [],
        "counts_by_syscall": {"openat": 12, "read": 30},
    }
    info = find_missing_expected_sink(
        attack_class="ssrf",
        syscall_observations=obs,
        args_json='["http://169.254.169.254/"]',
    )
    assert info is not None
    assert info.attack_class == "ssrf"
    assert "network_events" not in info.rationale.lower() or "zero" in info.rationale.lower()


def test_ssrf_with_observed_network_events_does_not_suppress() -> None:
    """SSRF probe DID open a socket — connection observed in bpftrace
    log. Don't suppress; the exploit primitive actually fired."""
    obs = {
        "total_events": 80,
        "network_events": [
            {"family": "AF_INET", "addr": "169.254.169.254", "port": 80}
        ],
    }
    info = find_missing_expected_sink(
        attack_class="ssrf",
        syscall_observations=obs,
        args_json='["http://169.254.169.254/"]',
    )
    assert info is None


# ─── command_injection gate ─────────────────────────────────────────────


def test_command_injection_no_execve_fires_suppression() -> None:
    obs = {
        "total_events": 100,
        "exec_observed": False,
        "counts_by_syscall": {"openat": 8},
    }
    info = find_missing_expected_sink(
        attack_class="command_injection",
        syscall_observations=obs,
        args_json='["whoami"]',
    )
    assert info is not None
    assert "execve" in info.expected_sink.lower()
    assert "exec" in info.rationale.lower()


def test_command_injection_execve_observed_does_not_suppress() -> None:
    """A real command-injection probe that actually spawned a shell —
    execve_observed is True. Don't suppress; the sink fired."""
    obs = {
        "total_events": 100,
        "exec_observed": True,
        "counts_by_syscall": {"execve": 1, "openat": 5},
    }
    info = find_missing_expected_sink(
        attack_class="command_injection",
        syscall_observations=obs,
        args_json='["whoami"]',
    )
    assert info is None


# ─── path_traversal gate ────────────────────────────────────────────────


def test_path_traversal_no_matching_openat_fires_suppression() -> None:
    """Probe matched class signature 'root:x:0:0:' in output but the
    sandbox didn't openat anything resembling /etc/passwd → the
    matcher hit an in-memory fixture string, suppress."""
    obs = {
        "total_events": 50,
        "samples_by_syscall": {
            "openat": [
                {"filename": "/tmp/argus_probe_workspace.py"},
                {"filename": "/usr/lib/python3.12/json/__init__.py"},
            ]
        },
        "write_target_paths": [],
    }
    info = find_missing_expected_sink(
        attack_class="path_traversal",
        syscall_observations=obs,
        args_json='["/etc/passwd"]',
    )
    assert info is not None
    assert "/etc/passwd" in info.rationale
    assert "openat" in info.rationale.lower()


def test_path_traversal_openat_on_target_does_not_suppress() -> None:
    """Probe really opened /etc/passwd in the sandbox — openat
    sample includes the target. Don't suppress; the exploit fired."""
    obs = {
        "total_events": 50,
        "samples_by_syscall": {
            "openat": [
                {"filename": "/etc/passwd"},
                {"filename": "/usr/lib/python3.12/encoding.py"},
            ]
        },
    }
    info = find_missing_expected_sink(
        attack_class="path_traversal",
        syscall_observations=obs,
        args_json='["/etc/passwd"]',
    )
    assert info is None


def test_path_traversal_no_target_path_in_args_returns_none() -> None:
    """The args_json doesn't contain anything path-shaped → can't
    verify which file the probe was targeting. Fail-open."""
    obs = {
        "total_events": 50,
        "samples_by_syscall": {"openat": []},
    }
    info = find_missing_expected_sink(
        attack_class="path_traversal",
        syscall_observations=obs,
        args_json='["benign-string"]',
    )
    assert info is None


def test_path_traversal_tail_match_handles_chroot_observation() -> None:
    """Sandbox observed openat under a chroot-prefixed path
    (``/var/lib/foo/etc/passwd``) — still represents the exploit
    reaching for the sensitive file. Don't suppress."""
    obs = {
        "total_events": 50,
        "samples_by_syscall": {
            "openat": [{"filename": "/var/lib/sandbox/etc/passwd"}]
        },
    }
    info = find_missing_expected_sink(
        attack_class="path_traversal",
        syscall_observations=obs,
        args_json='["/etc/passwd"]',
    )
    assert info is None


def test_path_traversal_write_target_paths_count_as_observed() -> None:
    """``write_target_paths`` is the Gap-2 closure for write probes —
    if openat samples are empty but write_target_paths has the
    target, don't suppress (the openat fired with O_CREAT)."""
    obs = {
        "total_events": 50,
        "samples_by_syscall": {"openat": []},
        "write_target_paths": ["/etc/passwd"],
    }
    info = find_missing_expected_sink(
        attack_class="path_traversal",
        syscall_observations=obs,
        args_json='["/etc/passwd"]',
    )
    assert info is None


def test_path_traversal_url_encoded_target_picked_up_via_dotdot_prefix() -> None:
    """``..%2F..%2Fetc%2Fpasswd`` starts with ``..`` so the extractor
    DOES recognise it as a path-shaped target. With no observed
    openat on a matching path, the suppression fires — operators can
    treat this as a string-oracle FP just like the literal-path
    variant."""
    obs = {
        "total_events": 50,
        "samples_by_syscall": {"openat": []},
    }
    info = find_missing_expected_sink(
        attack_class="path_traversal",
        syscall_observations=obs,
        args_json='["..%2F..%2Fetc%2Fpasswd"]',
    )
    # Path WAS extracted (via .. prefix) → suppress because no openat
    # observed.
    assert info is not None
    assert info.attack_class == "path_traversal"


# ─── _extract_paths_from_input helper ───────────────────────────────────


def test_extract_paths_finds_unix_paths() -> None:
    paths = _extract_paths_from_input('["/etc/passwd", "x"]')
    assert "/etc/passwd" in paths
    assert "x" not in paths  # no path indicator


def test_extract_paths_finds_dotdot_prefix() -> None:
    paths = _extract_paths_from_input('["../etc/passwd"]')
    assert "../etc/passwd" in paths


def test_extract_paths_walks_nested_dicts() -> None:
    paths = _extract_paths_from_input(
        '{"options": {"file": "/etc/shadow"}, "n": 1}'
    )
    assert "/etc/shadow" in paths


def test_extract_paths_handles_invalid_json() -> None:
    assert _extract_paths_from_input("not json") == []
    assert _extract_paths_from_input("") == []


def test_extract_paths_lowercases_for_case_insensitive_match() -> None:
    """Linux openat reports lowercased paths typically. Normalize."""
    paths = _extract_paths_from_input('["/Etc/Passwd"]')
    assert "/etc/passwd" in paths


# ─── _bpftrace_observed_anything ────────────────────────────────────────


def test_bpftrace_observed_false_on_zero_events() -> None:
    assert not _bpftrace_observed_anything({"total_events": 0})


def test_bpftrace_observed_false_on_lifecycle_error() -> None:
    assert not _bpftrace_observed_anything(
        {"total_events": 100, "bpftrace_meta": {"error": "x"}}
    )


def test_bpftrace_observed_true_normal_case() -> None:
    assert _bpftrace_observed_anything({"total_events": 100})


# ─── extract_syscall_observations_from_events helper ────────────────────


@dataclass
class _FakeEvent:
    kind: str
    event_id: str = "e1"
    payload: Any = None


def test_extract_from_events_finds_kind_match() -> None:
    """Helper finds the first ``syscall_observations`` event and
    parses it through dast.syscall_observability. The entrypoint emit
    shape is ``{"counts": {...}, "samples": {...}, "meta": {...}}``
    (see :mod:`dast.syscall_observability.parse_syscall_observations`
    for the parser); ``total_events`` is derived by summing the
    counts dict, not provided as a top-level field."""
    payload = {
        "counts": {"openat": 5},
        "samples": {"openat": []},
        "meta": {"start": 0, "end": 1, "lines_read": 5},
    }
    events = [
        _FakeEvent(kind="other"),
        _FakeEvent(kind="syscall_observations", payload=payload),
    ]
    obs = extract_syscall_observations_from_events(events)
    assert obs is not None
    assert obs["total_events"] == 5  # summed from counts.openat=5


def test_extract_from_events_returns_none_when_absent() -> None:
    events = [_FakeEvent(kind="other"), _FakeEvent(kind="stdout")]
    assert extract_syscall_observations_from_events(events) is None


def test_extract_from_events_handles_empty_list() -> None:
    assert extract_syscall_observations_from_events([]) is None
    assert extract_syscall_observations_from_events(None) is None  # type: ignore


def test_extract_from_events_corrupt_payload_yields_empty_observations() -> None:
    """The parser is defensive — non-dict input yields an empty
    :class:`SyscallObservations` (all-zero counts, no events). The
    extractor returns the empty obs as a dict; downstream
    ``_bpftrace_observed_anything`` correctly treats total_events=0
    as fail-open."""
    events = [_FakeEvent(kind="syscall_observations", payload="not a dict")]
    obs = extract_syscall_observations_from_events(events)
    assert obs is not None
    assert obs["total_events"] == 0
    # Downstream gate correctly fails open on the empty obs:
    assert _bpftrace_observed_anything(obs) is False
