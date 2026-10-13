
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
