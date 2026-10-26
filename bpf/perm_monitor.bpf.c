#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define PATH_LEN 112

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static const char chmod_fmt[] = "%s mode=%u%u%u%u";

static __always_inline const unsigned char *fd_name(int fdnum)
{
	struct task_struct *task;
	struct file *f = 0;
	struct file **fds;
	unsigned int max_fds;

	task = (struct task_struct *)bpf_get_current_task();
	fds = BPF_CORE_READ(task, files, fdt, fd);
	max_fds = BPF_CORE_READ(task, files, fdt, max_fds);
	if (fdnum < 0 || (unsigned int)fdnum >= max_fds)
		return 0;
	bpf_probe_read_kernel(&f, sizeof(f), &fds[fdnum]);
	if (!f)
		return 0;
	return BPF_CORE_READ(f, f_path.dentry, d_name.name);
}

static __always_inline int emit_chmod(const void *path, bool from_user, __u64 mode)
{
	char buf[PATH_LEN];
	struct task_struct *task;
	struct event *e;
	__u64 args[5];

	e = RESERVE_EVENT();
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();

	e->kts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->type = EVT_CHMOD;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	if (from_user)
		bpf_probe_read_user_str(buf, sizeof(buf), path);
	else
		bpf_probe_read_kernel_str(buf, sizeof(buf), path);

	args[0] = (__u64)buf;
	args[1] = (mode >> 9) & 7;
	args[2] = (mode >> 6) & 7;
	args[3] = (mode >> 3) & 7;
	args[4] = mode & 7;
	bpf_snprintf(e->detail, sizeof(e->detail), chmod_fmt, args, sizeof(args));
	SUBMIT_EVENT(e);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int handle_chmod(struct trace_event_raw_sys_enter *ctx)
{
	return emit_chmod((const void *)ctx->args[0], true, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_chmod((const void *)ctx->args[1], true, ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int handle_fchmodat2(struct trace_event_raw_sys_enter *ctx)
{
	return emit_chmod((const void *)ctx->args[1], true, ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int handle_fchmod(struct trace_event_raw_sys_enter *ctx)
{
	return emit_chmod(fd_name((int)ctx->args[0]), false, ctx->args[1]);
}
