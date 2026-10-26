#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define AF_INET 2
#define AF_INET6 10
#define MARK_WINDOW_NS (10ULL * 1000000000ULL)
#define EXEC_LEN 64

char LICENSE[] SEC("license") = "GPL";

struct mark {
	__u64 ts;
	__u8 addr[16];
	__be16 port;
	__u16 pad1;
	__u32 pad2;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct mark);
} marks SEC(".maps");

static const char v4_fmt[] = "dst=%u.%u.%u.%u:%u exec=%s";
static const char v6_fmt[] = "dst=[%x:%x:%x:%x:%x:%x:%x:%x]:%u exec=%s";

static __always_inline bool is_v4(const __u8 *a)
{
	int i;

	for (i = 0; i < 10; i++)
		if (a[i])
			return false;
	return a[10] == 0xff && a[11] == 0xff;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int mark_connect(struct trace_event_raw_sys_enter *ctx)
{
	void *uaddr = (void *)ctx->args[1];
	struct sockaddr_in6 sa6 = {};
	struct sockaddr_in sa = {};
	struct mark m = {};
	__u16 family;
	__u32 tgid;

	if (bpf_probe_read_user(&family, sizeof(family), uaddr))
		return 0;

	if (family == AF_INET) {
		if (bpf_probe_read_user(&sa, sizeof(sa), uaddr))
			return 0;
		m.addr[10] = 0xff;
		m.addr[11] = 0xff;
		__builtin_memcpy(&m.addr[12], &sa.sin_addr.s_addr, 4);
		m.port = sa.sin_port;
	} else if (family == AF_INET6) {
		if (bpf_probe_read_user(&sa6, sizeof(sa6), uaddr))
			return 0;
		__builtin_memcpy(m.addr, &sa6.sin6_addr, 16);
		m.port = sa6.sin6_port;
	} else {
		return 0;
	}

	if (m.port == 0)
		return 0;

	tgid = bpf_get_current_pid_tgid() >> 32;
	m.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&marks, &tgid, &m, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int check_exec(struct trace_event_raw_sys_enter *ctx)
{
	char exec_path[EXEC_LEN];
	struct task_struct *task;
	struct mark *mp;
	struct event *e;
	struct mark m;
	__u64 a4[6];
	__u64 a6[10];
	__u32 self;
	__u32 parent;
	int i;

	task = (struct task_struct *)bpf_get_current_task();
	self = bpf_get_current_pid_tgid() >> 32;
	parent = BPF_CORE_READ(task, real_parent, tgid);

	mp = bpf_map_lookup_elem(&marks, &self);
	if (!mp)
		mp = bpf_map_lookup_elem(&marks, &parent);
	if (!mp)
		return 0;
	m = *mp;

	if (bpf_ktime_get_ns() - m.ts > MARK_WINDOW_NS)
		return 0;

	e = RESERVE_EVENT();
	if (!e)
		return 0;

	e->kts = bpf_ktime_get_ns();
	e->pid = self;
	e->ppid = parent;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->type = EVT_CORRELATED;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(exec_path, sizeof(exec_path), (const char *)ctx->args[0]);

	if (is_v4(m.addr)) {
		a4[0] = m.addr[12];
		a4[1] = m.addr[13];
		a4[2] = m.addr[14];
		a4[3] = m.addr[15];
		a4[4] = bpf_ntohs(m.port);
		a4[5] = (__u64)exec_path;
		bpf_snprintf(e->detail, sizeof(e->detail), v4_fmt, a4, sizeof(a4));
	} else {
		for (i = 0; i < 8; i++)
			a6[i] = (m.addr[2 * i] << 8) | m.addr[2 * i + 1];
		a6[8] = bpf_ntohs(m.port);
		a6[9] = (__u64)exec_path;
		bpf_snprintf(e->detail, sizeof(e->detail), v6_fmt, a6, sizeof(a6));
	}
	SUBMIT_EVENT(e);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int clear_mark(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;

	if ((__u32)id != tgid)
		return 0;
	bpf_map_delete_elem(&marks, &tgid);
	return 0;
}
