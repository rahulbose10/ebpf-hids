#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define WRITE_FLAGS 0x643

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int emit_open(const char *filename, long flags)
{
	struct task_struct *task;
	struct event *e;

	if (!(flags & WRITE_FLAGS))
		return 0;

	e = RESERVE_EVENT();
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();

	e->kts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->type = EVT_OPEN;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->detail, sizeof(e->detail), filename);

	SUBMIT_EVENT(e);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_open((const char *)ctx->args[1], (long)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_open")
int handle_open(struct trace_event_raw_sys_enter *ctx)
{
	return emit_open((const char *)ctx->args[0], (long)ctx->args[1]);
}
