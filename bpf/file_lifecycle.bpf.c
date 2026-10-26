#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define PATH_PART 60

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static const char rename_fmt[] = "%s -> %s";

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

static __always_inline int emit_unlink(const char *path)
{
	struct event *e;

	e = new_event(EVT_UNLINK);
	if (!e)
		return 0;

	bpf_probe_read_user_str(&e->detail, sizeof(e->detail), path);
	SUBMIT_EVENT(e);
	return 0;
}

static __always_inline int emit_rename(const char *oldpath, const char *newpath)
{
	char oldbuf[PATH_PART];
	char newbuf[PATH_PART];
	struct event *e;
	__u64 args[2];

	e = new_event(EVT_RENAME);
	if (!e)
		return 0;

	bpf_probe_read_user_str(oldbuf, sizeof(oldbuf), oldpath);
	bpf_probe_read_user_str(newbuf, sizeof(newbuf), newpath);
	args[0] = (__u64)oldbuf;
	args[1] = (__u64)newbuf;
	bpf_snprintf(e->detail, sizeof(e->detail), rename_fmt, args, sizeof(args));
	SUBMIT_EVENT(e);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int handle_unlink(struct trace_event_raw_sys_enter *ctx)
{
	return emit_unlink((const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_unlink((const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter *ctx)
{
	return emit_rename((const char *)ctx->args[0], (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_rename((const char *)ctx->args[1], (const char *)ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	return emit_rename((const char *)ctx->args[1], (const char *)ctx->args[3]);
}
