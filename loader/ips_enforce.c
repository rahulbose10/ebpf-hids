#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/common.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define KERNEL_DEV(d) ((major(d) << 20) | minor(d))

struct config {
	__u32 protected_pid;
	__u32 blocked_dev;
	__u64 blocked_ino;
};

static const char *const prog_names[] = {
	"enforce_ptrace",
	"enforce_exec",
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
	struct bpf_link *links[ARRAY_SIZE(prog_names)] = { NULL };
	struct bpf_object *obj = NULL;
	struct ring_buffer *rb = NULL;
	struct bpf_program *prog;
	struct bpf_map *cfg_map, *ev_map;
	struct config cfg = {};
	struct stat st;
	__u32 key = 0;
	size_t i;
	long pid;
	long err;
	int ret = 1;

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: %s <pid-to-protect> [path-to-block-exec]\n", argv[0]);
		return 1;
	}
	pid = strtol(argv[1], NULL, 10);
	if (pid <= 0) {
		fprintf(stderr, "bad pid: %s\n", argv[1]);
		return 1;
	}
	cfg.protected_pid = (__u32)pid;

	if (argc == 3) {
		if (stat(argv[2], &st) != 0) {
			fprintf(stderr, "cannot stat %s: %s\n", argv[2], strerror(errno));
			return 1;
		}
		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "not a regular file: %s\n", argv[2]);
			return 1;
		}
		cfg.blocked_dev = KERNEL_DEV(st.st_dev);
		cfg.blocked_ino = st.st_ino;
	}

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
	if (!cfg_map || !ev_map) {
		fprintf(stderr, "object is missing a map\n");
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

	for (i = 0; i < ARRAY_SIZE(prog_names); i++) {
		prog = bpf_object__find_program_by_name(obj, prog_names[i]);
		if (!prog) {
			fprintf(stderr, "object is missing %s\n", prog_names[i]);
			goto out;
		}
		links[i] = bpf_program__attach(prog);
		err = libbpf_get_error(links[i]);
		if (err) {
			fprintf(stderr, "attach %s failed: %s\n", prog_names[i], strerror(-err));
			links[i] = NULL;
			goto out;
		}
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	fprintf(stderr, "IPS ACTIVE: ptrace against pid %ld will be denied. Ctrl+C to disable.\n", pid);
	if (cfg.blocked_ino)
		fprintf(stderr, "IPS ACTIVE: exec of %s (dev %u, inode %llu) will be denied.\n",
			argv[2], cfg.blocked_dev, (unsigned long long)cfg.blocked_ino);
	else
		fprintf(stderr, "IPS: no exec path given, exec blocking off.\n");

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
	for (i = 0; i < ARRAY_SIZE(links); i++)
		bpf_link__destroy(links[i]);
	bpf_object__close(obj);
	fprintf(stderr, "IPS disabled.\n");
	return ret;
}
