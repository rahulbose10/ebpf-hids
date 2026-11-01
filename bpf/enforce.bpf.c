#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

struct config {
	__u32 protected_pid;
	__u32 blocked_dev;
	__u64 blocked_ino;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} enforce_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static const char blk_fmt[] = "BLOCKED ptrace target_pid=%u";
static const char exec_fmt[] = "BLOCKED exec path=%s";

static __always_inline struct event *new_block(__u32 type)
{
	struct task_struct *task;
	struct event *e;

	e = RESERVE_EVENT();
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	e->kts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->type = type;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(enforce_ptrace, struct task_struct *child, unsigned int mode, int ret)
{
	struct config *cfg;
	struct event *e;
	__u64 args[1];
	__u32 key = 0;
	__u32 target;

	cfg = bpf_map_lookup_elem(&enforce_cfg, &key);
	if (!cfg)
		return ret;
	if (cfg->protected_pid == 0)
		return ret;

	target = BPF_CORE_READ(child, tgid);
	if (target != cfg->protected_pid)
		return ret;

	e = new_block(EVT_PTRACE);
	if (e) {
		args[0] = target;
		bpf_snprintf(e->detail, sizeof(e->detail), blk_fmt, args, sizeof(args));
		SUBMIT_EVENT(e);
	}

	return -EPERM;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_exec, struct linux_binprm *bprm, int ret)
{
	struct inode *inode;
	struct config *cfg;
	struct event *e;
	__u64 args[1];
	__u32 key = 0;

	if (ret)
		return ret;

	cfg = bpf_map_lookup_elem(&enforce_cfg, &key);
	if (!cfg || cfg->blocked_ino == 0)
		return ret;

	inode = BPF_CORE_READ(bprm, file, f_inode);
	if (!inode)
		return ret;
	if (BPF_CORE_READ(inode, i_ino) != cfg->blocked_ino)
		return ret;
	if (BPF_CORE_READ(inode, i_sb, s_dev) != cfg->blocked_dev)
		return ret;

	e = new_block(EVT_EXEC);
	if (e) {
		args[0] = (__u64)BPF_CORE_READ(bprm, filename);
		bpf_snprintf(e->detail, sizeof(e->detail), exec_fmt, args, sizeof(args));
		SUBMIT_EVENT(e);
	}

	return -EPERM;
}
