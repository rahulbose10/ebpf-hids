#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
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
} rate SEC(".maps");

static const char mprotect_fmt[] = "addr=0x%lx prot=%c%c%c suppressed=%u";

static __always_inline int emit_mprotect(__u64 addr, __u64 prot)
{
	struct rate_state fresh = {};
	struct rate_state *st;
	struct task_struct *task;
	struct event *e;
	__u32 suppressed = 0;
	__u64 args[5];
	__u64 now;
	__u32 pid;

	if (!(prot & PROT_EXEC))
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	now = bpf_ktime_get_ns();

	st = bpf_map_lookup_elem(&rate, &pid);
	if (st) {
		if (now - st->window_start < WINDOW_NS) {
			__sync_fetch_and_add(&st->suppressed, 1);
			return 0;
		}
		suppressed = st->suppressed;
		st->window_start = now;
		st->suppressed = 0;
	} else {
		fresh.window_start = now;
		bpf_map_update_elem(&rate, &pid, &fresh, BPF_ANY);
	}

	e = RESERVE_EVENT();
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();

	e->kts = now;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->type = EVT_MPROTECT;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	args[0] = addr;
	args[1] = (prot & PROT_READ) ? 'r' : '-';
	args[2] = (prot & PROT_WRITE) ? 'w' : '-';
	args[3] = 'x';
	args[4] = suppressed;
	bpf_snprintf(e->detail, sizeof(e->detail), mprotect_fmt, args, sizeof(args));
	SUBMIT_EVENT(e);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int handle_mprotect(struct trace_event_raw_sys_enter *ctx)
{
	return emit_mprotect(ctx->args[0], ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_pkey_mprotect")
int handle_pkey_mprotect(struct trace_event_raw_sys_enter *ctx)
{
	return emit_mprotect(ctx->args[0], ctx->args[2]);
}
