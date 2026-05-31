"""Unit tests for dast.syscall_observability.

Covers parsing the ``syscall_observations`` event payload emitted by
the sandbox entrypoint into typed :class:`SyscallObservations`, plus
the prompt-rendering helper.
"""

from __future__ import annotations

from dast.syscall_observability import (
    SyscallObservations,
    parse_syscall_observations,
    summarize_for_prompt,
)


# ── parse_syscall_observations — basics ───────────────────────────────────


def test_parse_empty_payload() -> None:
    """Missing/empty payload → empty observations, no crash."""
    obs = parse_syscall_observations({})
    assert obs.total_events == 0
    assert obs.counts_by_syscall == {}
    assert obs.exec_observed is False


def test_parse_non_dict_payload_safe() -> None:
    """Defensive — non-dict payload returns empty observations
    instead of raising."""
    obs = parse_syscall_observations(None)  # type: ignore[arg-type]
    assert isinstance(obs, SyscallObservations)
    assert obs.total_events == 0


def test_parse_counts_only() -> None:
    """Counts populate total_events + counts_by_syscall."""
    obs = parse_syscall_observations(
        {"counts": {"execve": 2, "openat": 5}, "samples": {}, "meta": {}}
    )
    assert obs.total_events == 7
    assert obs.counts_by_syscall == {"execve": 2, "openat": 5}


def test_parse_rejects_malformed_count_entries() -> None:
    """Non-int counts and non-str keys are silently dropped."""
    obs = parse_syscall_observations(
        {
            "counts": {
                "execve": 2,
                "bad_value": "not_an_int",
                "bad_neg": -1,
                123: 5,  # non-string key
            }
        }
    )
    assert obs.counts_by_syscall == {"execve": 2}


# ── Derived flags ─────────────────────────────────────────────────────────


def test_exec_flag_fires_on_execve() -> None:
    obs = parse_syscall_observations({"counts": {"execve": 1}})
    assert obs.exec_observed is True


def test_exec_flag_fires_on_execveat() -> None:
    obs = parse_syscall_observations({"counts": {"execveat": 1}})
    assert obs.exec_observed is True


def test_exec_flag_silent_on_other_syscalls() -> None:
    obs = parse_syscall_observations({"counts": {"openat": 5, "connect": 2}})
    assert obs.exec_observed is False


def test_memory_exec_flag_mmap_exec() -> None:
    obs = parse_syscall_observations({"counts": {"mmap_exec": 1}})
    assert obs.memory_exec_observed is True


def test_memory_exec_flag_mprotect_exec() -> None:
    obs = parse_syscall_observations({"counts": {"mprotect_exec": 1}})
    assert obs.memory_exec_observed is True


def test_memory_exec_flag_silent_on_plain_mmap() -> None:
    """``mmap`` without PROT_EXEC doesn't fire the flag — the script
    only emits ``mmap_exec`` when PROT_EXEC is in the prot flags."""
    obs = parse_syscall_observations({"counts": {"mmap": 100}})
    assert obs.memory_exec_observed is False


def test_privilege_op_flag_setuid() -> None:
    obs = parse_syscall_observations({"counts": {"setuid": 1}})
    assert obs.privilege_op_observed is True


def test_privilege_op_flag_capset() -> None:
    obs = parse_syscall_observations({"counts": {"capset": 1}})
    assert obs.privilege_op_observed is True


def test_privilege_op_flag_unshare() -> None:
    obs = parse_syscall_observations({"counts": {"unshare": 1}})
    assert obs.privilege_op_observed is True


def test_ptrace_flag() -> None:
    obs = parse_syscall_observations({"counts": {"ptrace": 1}})
    assert obs.ptrace_observed is True


def test_kernel_module_load_flag_init_module() -> None:
    obs = parse_syscall_observations({"counts": {"init_module": 1}})
    assert obs.kernel_module_load_observed is True


def test_kernel_module_load_flag_finit_module() -> None:
    obs = parse_syscall_observations({"counts": {"finit_module": 1}})
    assert obs.kernel_module_load_observed is True


# ── Samples + bounded lists ───────────────────────────────────────────────


def test_samples_preserved() -> None:
    """Sample records preserved verbatim (modulo dict-instance filter)."""
    obs = parse_syscall_observations(
        {
            "counts": {"openat": 2},
            "samples": {
                "openat": [
                    {"syscall": "openat", "filename": "/etc/passwd", "flags": "1"},
                    {"syscall": "openat", "filename": "/tmp/foo", "flags": "401"},
                ]
            },
        }
    )
    assert len(obs.samples_by_syscall["openat"]) == 2
    assert obs.samples_by_syscall["openat"][0]["filename"] == "/etc/passwd"


def test_samples_rejects_non_dict_entries() -> None:
    """Malformed (non-dict) sample entries silently dropped."""
    obs = parse_syscall_observations(
        {
            "counts": {"execve": 3},
            "samples": {
                "execve": [
                    {"syscall": "execve", "filename": "/bin/sh"},
                    "malformed_string",  # not a dict
                    None,  # not a dict
                    {"syscall": "execve", "filename": "/bin/bash"},
                ]
            },
        }
    )
    assert len(obs.samples_by_syscall["execve"]) == 2


def test_write_target_paths_extracted_from_openat_samples() -> None:
    """openat samples' filenames flow into write_target_paths."""
    obs = parse_syscall_observations(
        {
            "counts": {"openat": 3},
            "samples": {
                "openat": [
                    {"syscall": "openat", "filename": "/etc/cron.d/evil"},
                    {"syscall": "openat", "filename": "/root/.ssh/authorized_keys"},
                    {"syscall": "openat", "filename": "/var/log/wtmp"},
                ]
            },
        }
    )
    assert obs.write_target_paths == [
        "/etc/cron.d/evil",
        "/root/.ssh/authorized_keys",
        "/var/log/wtmp",
    ]


def test_write_target_paths_deduplicated() -> None:
    """Same path appearing multiple times only listed once."""
    obs = parse_syscall_observations(
        {
            "counts": {"openat": 5},
            "samples": {
                "openat": [
                    {"syscall": "openat", "filename": "/etc/passwd"},
                    {"syscall": "openat", "filename": "/etc/passwd"},
                    {"syscall": "openat", "filename": "/etc/passwd"},
                ]
            },
        }
    )
    assert obs.write_target_paths == ["/etc/passwd"]


def test_write_target_paths_capped_at_50() -> None:
    """Defensive: pathological sample volume → list bounded at 50."""
    samples = [
        {"syscall": "openat", "filename": f"/tmp/file_{i}"} for i in range(100)
    ]
    obs = parse_syscall_observations(
        {"counts": {"openat": 100}, "samples": {"openat": samples}}
    )
    assert len(obs.write_target_paths) == 50


def test_network_events_from_connect_and_socket() -> None:
    """connect + socket samples flow into network_events with the
    relevant fields preserved."""
    obs = parse_syscall_observations(
        {
            "counts": {"connect": 1, "socket": 1},
            "samples": {
                "connect": [
                    {"syscall": "connect", "comm": "python3", "sockfd": 5},
                ],
                "socket": [
                    {
                        "syscall": "socket",
                        "comm": "python3",
                        "family": 2,
                        "type": 1,
                        "protocol": 0,
                    },
                ],
            },
        }
    )
    assert len(obs.network_events) == 2
    connect_ev = next(e for e in obs.network_events if e["syscall"] == "connect")
    assert connect_ev["sockfd"] == 5
    socket_ev = next(e for e in obs.network_events if e["syscall"] == "socket")
    assert socket_ev["family"] == 2


def test_bpftrace_meta_passthrough() -> None:
    """Meta dict (start / end / lines_read) preserved as-is."""
    obs = parse_syscall_observations(
        {
            "counts": {"execve": 1},
            "meta": {"start": 123456789, "end": 123456999, "lines_read": 42},
        }
    )
    assert obs.bpftrace_meta == {
        "start": 123456789,
        "end": 123456999,
        "lines_read": 42,
    }


# ── summarize_for_prompt ──────────────────────────────────────────────────


def test_summary_empty() -> None:
    """Empty observations → single placeholder line, no boilerplate."""
    obs = SyscallObservations()
    text = summarize_for_prompt(obs)
    assert "no kernel events captured" in text
    assert text.count("\n") == 0  # single line


def test_summary_with_counts() -> None:
    """Counts render as compact `name=count` list, descending by count."""
    obs = parse_syscall_observations(
        {"counts": {"execve": 2, "openat": 10, "connect": 1}}
    )
    text = summarize_for_prompt(obs)
    assert "counts:" in text
    # Sort by count desc → openat appears first
    assert text.index("openat=10") < text.index("execve=2")


def test_summary_renders_exec_signal() -> None:
    obs = parse_syscall_observations({"counts": {"execve": 1}})
    text = summarize_for_prompt(obs)
    assert "exec" in text.lower()
    assert "raw-syscall bypass" in text.lower() or "process exec" in text.lower()


def test_summary_renders_memory_exec_signal() -> None:
    obs = parse_syscall_observations({"counts": {"mprotect_exec": 1}})
    text = summarize_for_prompt(obs)
    assert "PROT_EXEC" in text or "memory_exec" in text


def test_summary_renders_privilege_op_signal() -> None:
    obs = parse_syscall_observations({"counts": {"setuid": 1}})
    text = summarize_for_prompt(obs)
    assert "setuid" in text or "privilege" in text.lower()


def test_summary_renders_write_paths() -> None:
    obs = parse_syscall_observations(
        {
            "counts": {"openat": 1},
            "samples": {
                "openat": [{"syscall": "openat", "filename": "/etc/cron.d/evil"}]
            },
        }
    )
    text = summarize_for_prompt(obs)
    assert "/etc/cron.d/evil" in text
    assert "EACCES" in text  # documents the failed-attempt capture


def test_summary_truncates_long_write_path_list() -> None:
    """When > 10 distinct paths, summary shows first 10 + '... and N more'."""
    samples = [{"syscall": "openat", "filename": f"/p/{i}"} for i in range(15)]
    obs = parse_syscall_observations(
        {"counts": {"openat": 15}, "samples": {"openat": samples}}
    )
    text = summarize_for_prompt(obs)
    assert "/p/0" in text
    assert "and 5 more" in text


# ── Integration: realistic syscall scenarios ──────────────────────────────


def test_scenario_command_injection_via_ctypes_libc() -> None:
    """Simulates a target using ctypes to bypass subprocess.Popen
    audit hook: raw libc.execve fires execve syscall, would have
    been invisible to the V0 stack.

    This is the headline Gap-1 closure — verify exec_observed fires
    AND the summary mentions the bypass closure."""
    obs = parse_syscall_observations(
        {
            "counts": {"execve": 1, "openat": 4},
            "samples": {
                "execve": [
                    {
                        "syscall": "execve",
                        "filename": "/bin/sh",
                        "comm": "python3",
                    }
                ],
            },
        }
    )
    assert obs.exec_observed is True
    text = summarize_for_prompt(obs)
    assert "raw-syscall bypass" in text.lower() or "exec" in text


def test_scenario_persistence_via_eacces_attempt() -> None:
    """Simulates a target trying to write to /etc/cron.d (EACCES at
    runner uid, but tracepoint fires anyway since we hook sys_enter).

    This is the headline Gap-2 closure — verify the path appears in
    write_target_paths even though the write would have failed."""
    obs = parse_syscall_observations(
        {
            "counts": {"openat": 1},
            "samples": {
                "openat": [
                    {
                        "syscall": "openat",
                        "filename": "/etc/cron.d/argus_persist",
                        "flags": "441",  # O_WRONLY | O_CREAT | O_TRUNC
                        "comm": "python3",
                    }
                ],
            },
        }
    )
    assert "/etc/cron.d/argus_persist" in obs.write_target_paths
    text = summarize_for_prompt(obs)
    assert "/etc/cron.d/argus_persist" in text


def test_scenario_jit_shellcode_pattern() -> None:
    """Simulates the classic shellcode injection pattern: mmap with
    PROT_EXEC, then jump to it. Stage 2 prompt should see this signal
    and consider JIT-shellcode hypotheses (with V8/JVM context as the
    legitimate-use disclaimer)."""
    obs = parse_syscall_observations(
        {
            "counts": {"mmap_exec": 2, "mprotect_exec": 3},
            "samples": {
                "mmap_exec": [
                    {"syscall": "mmap_exec", "prot": "5", "len": 4096}
                ],
            },
        }
    )
    assert obs.memory_exec_observed is True
    text = summarize_for_prompt(obs)
    assert "PROT_EXEC" in text
