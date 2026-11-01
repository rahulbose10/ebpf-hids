#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define WRITE_FLAGS 0x643

char LICENSE[] SEC("license") = "GPL";

struct path_key {
	char path[DETAIL_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct path_key);
	__type(value, __u8);
} sensitive SEC(".maps");

static __always_inline void fill_header(struct event *e, __u32 type)
{
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task();

	e->kts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->type = type;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline int emit_read(const char *filename)
{
	struct path_key k = {};
	struct event *e;

	if (bpf_probe_read_user_str(k.path, sizeof(k.path), filename) <= 0)
		return 0;
	if (!bpf_map_lookup_elem(&sensitive, &k))
		return 0;

	e = RESERVE_EVENT();
	if (!e)
		return 0;

	fill_header(e, EVT_READ);
	__builtin_memcpy(e->detail, k.path, sizeof(e->detail));

	SUBMIT_EVENT(e);
	return 0;
}

static __always_inline int emit_open(const char *filename, long flags)
{
	struct event *e;

	if (!(flags & WRITE_FLAGS))
		return emit_read(filename);

	e = RESERVE_EVENT();
	if (!e)
		return 0;

	fill_header(e, EVT_OPEN);
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
