#ifndef EBPF_HIDS_COMMON_H
#define EBPF_HIDS_COMMON_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define COMM_LEN 16
#define DETAIL_LEN 128

enum event_type {
	EVT_EXEC = 1,
	EVT_OPEN,
	EVT_CONNECT,
	EVT_PTRACE,
	EVT_SETUID,
	EVT_UNLINK,
	EVT_RENAME,
	EVT_MPROTECT,
	EVT_MODULE,
	EVT_BIND,
	EVT_CHMOD,
	EVT_CORRELATED,
	EVT_PTRACE_CHECK,
};

struct event {
	__u64 kts;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 type;
	char comm[COMM_LEN];
	char detail[DETAIL_LEN];
};

_Static_assert(sizeof(struct event) == 168, "struct event size changed");

#ifdef __VMLINUX_H__
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *n;

	n = bpf_map_lookup_elem(&drops, &key);
	if (n)
		*n += 1;
}

#define RESERVE_EVENT() ({ \
	struct event *__e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0); \
	if (!__e) \
		count_drop(); \
	__e; \
})

#define WAKEUP_BYTES (64 * 1024)

#define SUBMIT_EVENT(e) bpf_ringbuf_submit((e), \
	bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) >= WAKEUP_BYTES ? \
	BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP)
#endif

#endif
