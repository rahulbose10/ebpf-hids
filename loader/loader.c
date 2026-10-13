#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "../bpf/common.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static volatile sig_atomic_t stop = 0;

static const char *const type_names[] = {
	[EVT_EXEC] = "EXEC",
	[EVT_OPEN] = "OPEN",
	[EVT_CONNECT] = "CONNECT",
	[EVT_PTRACE] = "PTRACE",
	[EVT_SETUID] = "SETUID",
	[EVT_UNLINK] = "UNLINK",
	[EVT_RENAME] = "RENAME",
	[EVT_MPROTECT] = "MPROTECT",
	[EVT_MODULE] = "MODULE",
	[EVT_BIND] = "BIND",
	[EVT_CHMOD] = "CHMOD",
	[EVT_CORRELATED] = "CORRELATED",
	[EVT_PTRACE_CHECK] = "PTRACE_CHECK",
};

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static void print_json_string(const char *s, size_t max)
{
	size_t i;

	putchar('"');
	for (i = 0; i < max && s[i]; i++) {
		unsigned char c = (unsigned char)s[i];

		if (c == '"' || c == '\\')
			printf("\\%c", c);
		else if (c < 0x20 || c >= 0x7f)
			printf("\\u%04x", c);
		else
			putchar(c);
	}
	putchar('"');
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct event *e = data;
	const char *type_name;

	(void)ctx;
	if (size < sizeof(*e))
		return 0;
	if (e->type >= ARRAY_SIZE(type_names))
		return 0;
	type_name = type_names[e->type];
	if (!type_name)
		return 0;

	printf("{\"ts\":%.6f,\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":",
	       e->kts / 1e9, e->pid, e->ppid, e->uid);
	print_json_string(e->comm, sizeof(e->comm));
	printf(",\"type\":\"%s\",\"detail\":", type_name);
	print_json_string(e->detail, sizeof(e->detail));
	printf("}\n");
	return 0;
}

int main(void)
{
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct ring_buffer *rb = NULL;
	struct bpf_program *prog;
	struct bpf_map *map;
	long err;
	int n;
	int ret = 1;

	setvbuf(stdout, NULL, _IOLBF, 0);

	obj = bpf_object__open_file("bpf/execve_monitor.bpf.o", NULL);
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

	prog = bpf_object__find_program_by_name(obj, "handle_execve");
	map = bpf_object__find_map_by_name(obj, "events");
	if (!prog || !map) {
		fprintf(stderr, "handle_execve or events map not found in object\n");
		goto out;
	}

	rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
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

	fprintf(stderr, "sensor up: execve streaming, Ctrl+C to stop\n");
	while (!stop) {
		n = ring_buffer__poll(rb, 100);
		if (n < 0 && n != -EINTR) {
			fprintf(stderr, "poll failed: %s\n", strerror(-n));
			break;
		}
	}
	ret = 0;

out:
	ring_buffer__free(rb);
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return ret;
}
