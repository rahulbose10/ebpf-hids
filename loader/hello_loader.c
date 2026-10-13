#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t stop = 0;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

int main(void)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	long err;

	obj = bpf_object__open_file("bpf/hello.bpf.o", NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open failed: %s\n", strerror(-err));
		return 1;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		bpf_object__close(obj);
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "handle_execve");
	if (!prog) {
		fprintf(stderr, "program handle_execve not found in object\n");
		bpf_object__close(obj);
		return 1;
	}

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(-err));
		bpf_object__close(obj);
		return 1;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	printf("attached. run commands in another terminal, Ctrl+C here to stop.\n");
	while (!stop)
		sleep(1);

	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
