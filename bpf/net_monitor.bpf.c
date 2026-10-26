#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static const char v4_fmt[] = "%u.%u.%u.%u:%u";
static const char v6_fmt[] = "[%x:%x:%x:%x:%x:%x:%x:%x]:%u";

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

static __always_inline int emit_v4(__u32 type, const __u8 *ip, __be16 port)
{
	struct event *e;
	__u64 args[5];

	if (port == 0)
		return 0;

	e = new_event(type);
	if (!e)
		return 0;

	args[0] = ip[0];
	args[1] = ip[1];
	args[2] = ip[2];
	args[3] = ip[3];
	args[4] = bpf_ntohs(port);
	bpf_snprintf(e->detail, sizeof(e->detail), v4_fmt, args, sizeof(args));
	SUBMIT_EVENT(e);
	return 0;
}

static __always_inline int emit_v6(__u32 type, const struct in6_addr *addr, __be16 port)
{
	struct event *e;
	__u64 args[9];
	int i;

	if (port == 0)
		return 0;

	e = new_event(type);
	if (!e)
		return 0;

	for (i = 0; i < 8; i++)
		args[i] = bpf_ntohs(addr->in6_u.u6_addr16[i]);
	args[8] = bpf_ntohs(port);
	bpf_snprintf(e->detail, sizeof(e->detail), v6_fmt, args, sizeof(args));
	SUBMIT_EVENT(e);
	return 0;
}

static __always_inline int emit_sockaddr(__u32 type, void *uaddr)
{
	struct sockaddr_in6 sa6 = {};
	struct sockaddr_in sa = {};
	__u16 family;

	if (bpf_probe_read_user(&family, sizeof(family), uaddr))
		return 0;

	if (family == AF_INET) {
		if (bpf_probe_read_user(&sa, sizeof(sa), uaddr))
			return 0;
		return emit_v4(type, (const __u8 *)&sa.sin_addr.s_addr, sa.sin_port);
	}

	if (family == AF_INET6) {
		if (bpf_probe_read_user(&sa6, sizeof(sa6), uaddr))
			return 0;
		if (sa6.sin6_addr.in6_u.u6_addr32[0] == 0 &&
		    sa6.sin6_addr.in6_u.u6_addr32[1] == 0 &&
		    sa6.sin6_addr.in6_u.u6_addr32[2] == bpf_htonl(0xffff))
			return emit_v4(type, &sa6.sin6_addr.in6_u.u6_addr8[12], sa6.sin6_port);
		return emit_v6(type, &sa6.sin6_addr, sa6.sin6_port);
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	return emit_sockaddr(EVT_CONNECT, (void *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int handle_bind(struct trace_event_raw_sys_enter *ctx)
{
	return emit_sockaddr(EVT_BIND, (void *)ctx->args[1]);
}
