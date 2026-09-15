// hello.bpf.c - smallest possible eBPF program.
// Attaches to the execve syscall entry tracepoint and writes one line to
// the kernel trace pipe every time any process on this machine starts a
// new program. Exists only to prove the toolchain works end to end.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
	bpf_printk("exec\n");
	return 0;
}
