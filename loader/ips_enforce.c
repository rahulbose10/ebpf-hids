#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/common.h"

struct config {
	__u32 protected_pid;
	__u32 pad;
};

static volatile sig_atomic_t stop = 0;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct event *e = data;

	(void)ctx;
	if (size < sizeof(*e))
		return 0;
	printf("{\"ts\":%.6f,\"pid\":%u,\"comm\":\"%.16s\",\"action\":\"BLOCK\",\"detail\":\"%.128s\"}\n",
	       e->kts / 1e9, e->pid, e->comm, e->detail);
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct ring_buffer *rb = NULL;
	struct bpf_program *prog;
	struct bpf_map *cfg_map, *ev_map;
	struct config cfg = {};
	__u32 key = 0;
	long pid;
	long err;
	int ret = 1;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <pid-to-protect>\n", argv[0]);
		return 1;
	}
	pid = strtol(argv[1], NULL, 10);
	if (pid <= 0) {
		fprintf(stderr, "bad pid: %s\n", argv[1]);
		return 1;
	}
	cfg.protected_pid = (__u32)pid;

	setvbuf(stdout, NULL, _IOLBF, 0);

	obj = bpf_object__open_file("bpf/enforce.bpf.o", NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open failed: %s\n", strerror(-err));
		obj = NULL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		goto out;
	}

	cfg_map = bpf_object__find_map_by_name(obj, "enforce_cfg");
	ev_map = bpf_object__find_map_by_name(obj, "events");
	prog = bpf_object__find_program_by_name(obj, "enforce_ptrace");
	if (!cfg_map || !ev_map || !prog) {
		fprintf(stderr, "object is missing a map or program\n");
		goto out;
	}

	err = bpf_map__update_elem(cfg_map, &key, sizeof(key), &cfg, sizeof(cfg), BPF_ANY);
	if (err) {
		fprintf(stderr, "writing config failed: %s\n", strerror(-err));
		goto out;
	}

	rb = ring_buffer__new(bpf_map__fd(ev_map), handle_event, NULL, NULL);
	err = libbpf_get_error(rb);
	if (!rb || err) {
		fprintf(stderr, "ring buffer setup failed: %s\n", strerror(err ? -err : ENOMEM));
		rb = NULL;
		goto out;
	}

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(-err));
		link = NULL;
		goto out;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	fprintf(stderr, "IPS ACTIVE: ptrace against pid %ld will be denied. Ctrl+C to disable.\n", pid);
	while (!stop) {
		ring_buffer__consume(rb);
		int n = ring_buffer__poll(rb, 100);
		if (n < 0 && n != -EINTR) {
			fprintf(stderr, "poll failed: %s\n", strerror(-n));
			break;
		}
	}
	ring_buffer__consume(rb);
	ret = 0;

out:
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	bpf_object__close(obj);
	fprintf(stderr, "IPS disabled.\n");
	return ret;
}
