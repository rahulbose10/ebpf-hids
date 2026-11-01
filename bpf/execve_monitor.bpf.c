#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct event);
} pending SEC(".maps");

static __always_inline int save_pending(const char *filename)
{
	struct event p = {};
	struct task_struct *task;
	__u32 tgid;

	task = (struct task_struct *)bpf_get_current_task();
	tgid = bpf_get_current_pid_tgid() >> 32;

	p.kts = bpf_ktime_get_ns();
	p.pid = tgid;
	p.ppid = BPF_CORE_READ(task, real_parent, tgid);
	p.uid = (__u32)bpf_get_current_uid_gid();
	p.type = EVT_EXEC;
	bpf_get_current_comm(&p.comm, sizeof(p.comm));
	bpf_probe_read_user_str(&p.detail, sizeof(p.detail), filename);

	bpf_map_update_elem(&pending, &tgid, &p, BPF_ANY);
	return 0;
}

static __always_inline int emit_pending(long ret)
{
	struct event *p;
	struct event *e;
	__u32 tgid;

	tgid = bpf_get_current_pid_tgid() >> 32;
	p = bpf_map_lookup_elem(&pending, &tgid);
	if (!p)
		return 0;

	if (ret == 0) {
		e = RESERVE_EVENT();
		if (e) {
			__builtin_memcpy(e, p, sizeof(*e));
			SUBMIT_EVENT(e);
		}
	}

	bpf_map_delete_elem(&pending, &tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
	return save_pending((const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx)
{
	return save_pending((const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
	return emit_pending(ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int handle_execveat_exit(struct trace_event_raw_sys_exit *ctx)
{
	return emit_pending(ctx->ret);
}
