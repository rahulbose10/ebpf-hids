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

#endif
