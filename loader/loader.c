#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/common.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MAX_LINKS 32
#define CORRELATE_PATH "bpf/correlate.bpf.o"

static volatile sig_atomic_t stop = 0;

static const char *const object_paths[] = {
	"bpf/execve_monitor.bpf.o",
	"bpf/file_monitor.bpf.o",
	"bpf/net_monitor.bpf.o",
	"bpf/privesc_monitor.bpf.o",
	"bpf/file_lifecycle.bpf.o",
	"bpf/mem_monitor.bpf.o",
	"bpf/module_monitor.bpf.o",
	"bpf/perm_monitor.bpf.o",
};

#define NUM_OBJS (ARRAY_SIZE(object_paths) + 1)

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

static int share_map(struct bpf_object *obj, const char *name, int fd)
{
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, name);
	if (!map) {
		fprintf(stderr, "warn: no %s map in %s\n", name, bpf_object__name(obj));
		return -1;
	}
	if (fd >= 0 && bpf_map__reuse_fd(map, fd)) {
		fprintf(stderr, "warn: %s cannot share the %s map\n", bpf_object__name(obj), name);
		return -1;
	}
	return 0;
}

static struct bpf_object *try_load(const char *path, int *events_fd, int *drops_fd)
{
	struct bpf_object *obj;
	long err;

	obj = bpf_object__open_file(path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "warn: open %s failed: %s\n", path, strerror(-err));
		return NULL;
	}

	if (share_map(obj, "events", *events_fd) || share_map(obj, "drops", *drops_fd))
		goto fail;

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "warn: load %s failed: %s\n", path, strerror(-err));
		goto fail;
	}
	if (*events_fd < 0)
		*events_fd = bpf_object__find_map_fd_by_name(obj, "events");
	if (*drops_fd < 0)
		*drops_fd = bpf_object__find_map_fd_by_name(obj, "drops");
	return obj;

fail:
	bpf_object__close(obj);
	return NULL;
}

static int try_attach(struct bpf_object *obj, struct bpf_link **links, int *nlinks)
{
	struct bpf_program *prog;
	struct bpf_link *link;
	int attached = 0;
	long err;

	bpf_object__for_each_program(prog, obj) {
		if (*nlinks == MAX_LINKS) {
			fprintf(stderr, "warn: MAX_LINKS reached, %s not attached\n",
				bpf_program__name(prog));
			break;
		}
		link = bpf_program__attach(prog);
		err = libbpf_get_error(link);
		if (err) {
			fprintf(stderr, "warn: attach %s failed: %s\n",
				bpf_program__name(prog), strerror(-err));
			continue;
		}
		links[(*nlinks)++] = link;
		attached++;
	}
	return attached;
}

static long long read_drops(int drops_fd)
{
	__u32 key = 0;
	long long total = 0;
	__u64 *vals;
	int ncpus, i;

	if (drops_fd < 0)
		return -1;
	ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0)
		return -1;
	vals = calloc(ncpus, sizeof(*vals));
	if (!vals)
		return -1;
	if (bpf_map_lookup_elem(drops_fd, &key, vals) == 0) {
		for (i = 0; i < ncpus; i++)
			total += vals[i];
	} else {
		total = -1;
	}
	free(vals);
	return total;
}

int main(int argc, char **argv)
{
	struct bpf_object *objs[NUM_OBJS] = { NULL };
	struct bpf_link *links[MAX_LINKS] = { NULL };
	struct ring_buffer *rb = NULL;
	int correlate = argc > 1 && strcmp(argv[1], "--correlate") == 0;
	size_t wanted = ARRAY_SIZE(object_paths) + (correlate ? 1 : 0);
	int events_fd = -1;
	int drops_fd = -1;
	int nlinks = 0;
	int up = 0;
	size_t i;
	long err;
	int n;
	int ret = 1;

	setvbuf(stdout, NULL, _IOLBF, 0);

	for (i = 0; i < ARRAY_SIZE(object_paths); i++)
		objs[i] = try_load(object_paths[i], &events_fd, &drops_fd);
	if (correlate)
		objs[NUM_OBJS - 1] = try_load(CORRELATE_PATH, &events_fd, &drops_fd);

	if (events_fd < 0) {
		fprintf(stderr, "no monitor could be loaded, giving up\n");
		goto out;
	}

	rb = ring_buffer__new(events_fd, handle_event, NULL, NULL);
	err = libbpf_get_error(rb);
	if (!rb || err) {
		fprintf(stderr, "ring buffer setup failed: %s\n", strerror(err ? -err : ENOMEM));
		rb = NULL;
		goto out;
	}

	for (i = 0; i < NUM_OBJS; i++) {
		if (objs[i] && try_attach(objs[i], links, &nlinks) > 0)
			up++;
	}

	if (up == 0) {
		fprintf(stderr, "no monitor could be attached, giving up\n");
		goto out;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	fprintf(stderr, "sensor up: %d/%zu monitors streaming, Ctrl+C to stop\n",
		up, wanted);
	while (!stop) {
		ring_buffer__consume(rb);
		n = ring_buffer__poll(rb, 100);
		if (n < 0 && n != -EINTR) {
			fprintf(stderr, "poll failed: %s\n", strerror(-n));
			break;
		}
	}
	ring_buffer__consume(rb);
	ret = 0;

out:
	if (drops_fd >= 0)
		fprintf(stderr, "dropped events: %lld\n", read_drops(drops_fd));
	ring_buffer__free(rb);
	while (nlinks > 0)
		bpf_link__destroy(links[--nlinks]);
	for (i = 0; i < NUM_OBJS; i++)
		bpf_object__close(objs[i]);
	return ret;
}
