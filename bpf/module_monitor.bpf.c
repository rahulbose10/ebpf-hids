#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static const char image_fmt[] = "memory_image len=%lu";

static __always_inline struct event *new_event(void)
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
	e->type = EVT_MODULE;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_init_module(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	__u64 args[1];

	e = new_event();
	if (!e)
		return 0;

	args[0] = ctx->args[1];
	bpf_snprintf(e->detail, sizeof(e->detail), image_fmt, args, sizeof(args));
	SUBMIT_EVENT(e);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_finit_module(struct trace_event_raw_sys_enter *ctx)
{
	int fdnum = (int)ctx->args[0];
	const unsigned char *name;
	struct task_struct *task;
	struct file *f = 0;
	struct file **fds;
	unsigned int max_fds;
	struct event *e;

	e = new_event();
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	fds = BPF_CORE_READ(task, files, fdt, fd);
	max_fds = BPF_CORE_READ(task, files, fdt, max_fds);
	if (fdnum >= 0 && (unsigned int)fdnum < max_fds)
		bpf_probe_read_kernel(&f, sizeof(f), &fds[fdnum]);

	e->detail[0] = '\0';
	if (f) {
		name = BPF_CORE_READ(f, f_path.dentry, d_name.name);
		bpf_probe_read_kernel_str(e->detail, sizeof(e->detail), name);
	}
	SUBMIT_EVENT(e);
	return 0;
}
