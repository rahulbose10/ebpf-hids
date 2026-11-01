#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "path.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct rename_buf {
	char buf[LONG_DETAIL_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rename_buf);
} rename_buf SEC(".maps");

static __always_inline void *new_record(__u64 size, __u32 type)
{
	struct task_struct *task;
	struct event *e;

	e = bpf_ringbuf_reserve(&events, size, 0);
	if (!e) {
		count_drop();
		return 0;
	}

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

	e = new_record(sizeof(*e), EVT_UNLINK);
	if (!e)
		return 0;

	bpf_probe_read_kernel_str(&e->detail, sizeof(e->detail), p);
	SUBMIT_EVENT(e);
	return 0;
}

static __always_inline int emit_rename(int olddfd, const char *oldpath,
				       int newdfd, const char *newpath)
{
	struct path_scratch *s;
	struct rename_buf *r;
	struct event_long *e;
	const char *p;
	__u32 key = 0;
	__u64 n = 0;
	long len;

	s = get_scratch();
	r = bpf_map_lookup_elem(&rename_buf, &key);
	if (!s || !r)
		return 0;

	p = abs_path(s, olddfd, oldpath);
	if (p) {
		len = bpf_probe_read_kernel_str(r->buf, PATH_BUF, p);
		if (len > 1)
			n = len - 1;
	}
	n &= PATH_MASK;
	r->buf[n] = ' ';
	r->buf[n + 1] = '-';
	r->buf[n + 2] = '>';
	r->buf[n + 3] = ' ';
	r->buf[n + 4] = 0;

	p = abs_path(s, newdfd, newpath);
	if (p)
		bpf_probe_read_kernel_str(&r->buf[n + 4], PATH_BUF, p);

	e = new_record(sizeof(*e), EVT_RENAME);
	if (!e)
		return 0;

	bpf_probe_read_kernel(e->detail, sizeof(e->detail), r->buf);
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
