#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define PTRACE_ATTACH 16
#define PTRACE_SEIZE 0x4206

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static const char ptrace_fmt[] = "target_pid=%u";
static const char setuid_fmt[] = "old_uid=%u new_uid=%u";

static __always_inline struct event *new_event(__u32 type)
{
	struct task_struct *task;
	struct event *e;

	e = RESERVE_EVENT();
	if (!e)
		return e;

	task = (struct task_struct *)bpf_get_current_task();

	e->kts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->type = type;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	long request = ctx->args[0];
	struct event *e;
	__u64 args[1];

	if (request != PTRACE_ATTACH && request != PTRACE_SEIZE)
		return 0;

	e = new_event(EVT_PTRACE);
	if (!e)
		return 0;

	args[0] = (__u32)ctx->args[1];
	bpf_snprintf(e->detail, sizeof(e->detail), ptrace_fmt, args, sizeof(args));
	SUBMIT_EVENT(e);
	return 0;
}

static __always_inline int emit_setuid(__u32 ruid, __u32 euid)
{
	__u32 new_uid = euid != (__u32)-1 ? euid : ruid;
	struct event *e;
	__u64 args[2];

	if (new_uid == (__u32)-1)
		return 0;

	e = new_event(EVT_SETUID);
	if (!e)
		return 0;

	args[0] = e->uid;
	args[1] = new_uid;
	bpf_snprintf(e->detail, sizeof(e->detail), setuid_fmt, args, sizeof(args));
	SUBMIT_EVENT(e);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_setuid((__u32)ctx->args[0], (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int handle_setreuid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_setuid((__u32)ctx->args[0], (__u32)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int handle_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_setuid((__u32)ctx->args[0], (__u32)ctx->args[1]);
}
