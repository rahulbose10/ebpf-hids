#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "path.h"

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

static __always_inline int emit_unlink(int dfd, const char *path)
{
	struct path_scratch *s;
	const char *p;
	struct event *e;

	s = get_scratch();
	if (!s)
		return 0;
	p = abs_path(s, dfd, path);
	if (!p)
		return 0;

	e = new_event(EVT_UNLINK);
	if (!e)
		return 0;

	bpf_probe_read_kernel_str(&e->detail, sizeof(e->detail), p);
	SUBMIT_EVENT(e);
	return 0;
}

static __always_inline int emit_rename(int olddfd, const char *oldpath,
				       int newdfd, const char *newpath)
{
	char oldbuf[PATH_PART] = {};
	char newbuf[PATH_PART] = {};
	struct path_scratch *s;
	const char *p;
	struct event *e;
	__u64 args[2];

	s = get_scratch();
	if (!s)
		return 0;

	p = abs_path(s, olddfd, oldpath);
	if (p)
		bpf_probe_read_kernel_str(oldbuf, sizeof(oldbuf), p);
	p = abs_path(s, newdfd, newpath);
	if (p)
		bpf_probe_read_kernel_str(newbuf, sizeof(newbuf), p);

	e = new_event(EVT_RENAME);
	if (!e)
		return 0;

	args[0] = (__u64)oldbuf;
	args[1] = (__u64)newbuf;
	bpf_snprintf(e->detail, sizeof(e->detail), rename_fmt, args, sizeof(args));
	SUBMIT_EVENT(e);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int handle_unlink(struct trace_event_raw_sys_enter *ctx)
{
	return emit_unlink(AT_FDCWD_VAL, (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_unlink((int)ctx->args[0], (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter *ctx)
{
	return emit_rename(AT_FDCWD_VAL, (const char *)ctx->args[0],
			   AT_FDCWD_VAL, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_rename((int)ctx->args[0], (const char *)ctx->args[1],
			   (int)ctx->args[2], (const char *)ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	return emit_rename((int)ctx->args[0], (const char *)ctx->args[1],
			   (int)ctx->args[2], (const char *)ctx->args[3]);
}
