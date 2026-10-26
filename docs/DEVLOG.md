
## 2026-09-16 - L1 kernel sensor, session 1
- Phase 0 done: kernel 6.8.0-138-generic, BTF present at /sys/kernel/btf/vmlinux (6099393 bytes),
  toolchain installed (clang 14, bpftool v7.4.0 / libbpf v1.4).
- Generated bpf/vmlinux.h from BTF, 150673 lines, gitignored since it is machine-specific.
- Repo initialised, .gitattributes committed first (LF enforced), then .gitignore.
- Wrote hello.bpf.c, execve tracepoint + bpf_printk. Compiles clean to eBPF bytecode
  (file reports "ELF 64-bit LSB relocatable, eBPF, with debug_info, not stripped").
- Disassembled it: 10 instructions. "call 6" is bpf_trace_printk called by helper ID,
  which is also why bpf_printk takes only three format args (r1 and r2 are taken).
- Not loaded into the kernel yet. Loader is next session.

## 2026-10-14 - L1 kernel sensor, session 2
- Wrote loader/hello_loader.c with libbpf: open, load, attach, then wait for a signal.
- Loaded hello.bpf.o and attached it to the execve tracepoint. libbpf printed a harmless note about the .rodata.str1.1 section.
- trace_pipe showed an "exec" line for each new program started, including a burst when a new terminal opened. comm showed the parent name (bash) because the hook fires at syscall entry.
- pwd produced no event because it is a shell builtin and does not call execve.
- Verifier exercise: a map lookup dereferenced without a NULL check compiled fine but was rejected at load with "R0 invalid mem access 'map_value_or_null'" after 7 instructions, error -13. Adding "if (!val) return 0;" made it load (xlated 152B, jited 93B). Lesson files not committed.
- Wrote common.h (struct event, 168 bytes, checked with clang and gcc), execve_monitor.bpf.c (ring buffer, 256KB) and loader.c (JSON lines on stdout).
- First load failed with "libbpf: failed to find valid kernel BTF", error -3. The apt libbpf (0.5.0) could not parse the 6.8 kernel's BTF. Built libbpf v1.4.0 as a static library, linked the loader against it, and the load worked.
- Piped loader output through jq. EXEC lines appeared for terminal shell startup and for ls. comm is cut at 15 characters. A program named /tmp/a"b came through as valid JSON with the quote escaped.

## 2026-10-26 - L1 kernel sensor, session 3
- Added file_monitor (OPEN, write intent only), net_monitor (CONNECT, BIND), privesc_monitor (PTRACE, SETUID), file_lifecycle (UNLINK, RENAME), mem_monitor (MPROTECT), module_monitor (MODULE), perm_monitor (CHMOD). 8 monitors, 22 programs, one shared ring buffer.
- strace on this VM: os.rename -> rename, mv -> renameat2, os.unlink -> unlink, rm -> unlinkat, os.chmod -> chmod, chmod(1) -> fchmodat, os.fchmod -> fchmod. Hooking only the *at forms would have seen 2 of 4 file ops and 1 of 3 chmods. Whole families hooked, all seen. fchmodat2 is not used by glibc 2.35, proved it fires with raw syscall 452.
- First setuid version missed calls that change only the real uid (sudo's first switch never showed up). Now falls back to the real uid when euid is -1.
- Idle minute with Firefox open: 72 and 254 events. The 254 was mostly apt-check (104 EXEC, 52 OPEN).
- Port 0 connects were 3 of 8 CONNECT in that minute, now dropped in the kernel. IPv4-mapped and pure IPv6 connects were invisible, now reported. Firefox :443 connects only started showing after that fix.
- mem_monitor rate limit: 514 exec remaps in an idle minute, 21 events emitted, 493 carried in suppressed=. Mostly gnome-shell.
- Firefox renamed 8 files in about 25 ms during normal browsing.
- Event loss: 0 with the reader keeping up. 48019 of a 50000 open flood with the reader stalled 30 s. Now counted in a per-cpu drops map and printed on exit.
- Per-event cost from kernel.bpf_stats_enabled: filtered read-only open 60 ns. Emitted event waking the reader every time 65200 ns. Never waking 128 ns but 48557 dropped. Waking only when 64 KB is pending 1159 ns, 0 dropped.
- My batched wakeup broke quiet events: ring_buffer__poll does not read on timeout, so a lone ls never showed. Added ring_buffer__consume in the loop and at exit.
- correlate.bpf.c (off by default, --correlate): connect stamps the pid, exec checks self then parent within 10 s, exit clears it. Child and same-process cases fire, no-connect and 11 s cases don't. 2 stamps left after the test.
- Still open: no L2 engine yet to pipe into. One OPEN with empty detail at bash startup. *at syscalls can give relative paths. RENAME paths over 59 chars get cut.
