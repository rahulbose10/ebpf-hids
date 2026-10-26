#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define WINDOW_NS 1000000000ULL

char LICENSE[] SEC("license") = "GPL";

struct rate_state {
	__u64 window_start;
	__u32 suppressed;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct rate_state);
} ptrace_rate SEC(".maps");

static const char check_fmt[] = "target_pid=%u mode=0x%x suppressed=%u";

SEC("lsm/ptrace_access_check")
int BPF_PROG(on_ptrace_check, struct task_struct *child, unsigned int mode, int ret)
{
	struct rate_state fresh = {};
	struct rate_state *st;
	struct task_struct *task;
	struct event *e;
	__u32 suppressed = 0;
	__u64 args[3];
	__u64 now;
	__u32 pid;
	__u32 target;

	pid = bpf_get_current_pid_tgid() >> 32;
	now = bpf_ktime_get_ns();

	st = bpf_map_lookup_elem(&ptrace_rate, &pid);
	if (st) {
		if (now - st->window_start < WINDOW_NS) {
			__sync_fetch_and_add(&st->suppressed, 1);
			return ret;
		}
		suppressed = st->suppressed;
		st->window_start = now;
		st->suppressed = 0;
	} else {
		fresh.window_start = now;
		bpf_map_update_elem(&ptrace_rate, &pid, &fresh, BPF_ANY);
	}

	target = BPF_CORE_READ(child, tgid);

	e = RESERVE_EVENT();
	if (!e) {
		return ret;
	}

	task = (struct task_struct *)bpf_get_current_task();
	e->kts = now;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->type = EVT_PTRACE_CHECK;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	args[0] = target;
	args[1] = mode;
	args[2] = suppressed;
	bpf_snprintf(e->detail, sizeof(e->detail), check_fmt, args, sizeof(args));
	SUBMIT_EVENT(e);

	return ret;
}
