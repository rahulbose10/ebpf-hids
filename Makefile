CLANG ?= clang
CC := gcc
BPFTOOL ?= bpftool
LIBBPF_DIR ?= $(HOME)/libbpf-install
LIBBPF_INC := $(LIBBPF_DIR)/usr/include
LIBBPF_LIB := $(firstword $(wildcard $(LIBBPF_DIR)/usr/lib64/libbpf.a $(LIBBPF_DIR)/usr/lib/libbpf.a))

ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

BPF_SRCS := $(wildcard bpf/*.bpf.c)
BPF_OBJS := $(BPF_SRCS:.c=.o)

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I bpf -I $(LIBBPF_INC)
CFLAGS := -O2 -Wall -I $(LIBBPF_INC)

.PHONY: all clean

all: $(BPF_OBJS) loader/loader

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp && mv $@.tmp $@

bpf/%.bpf.o: bpf/%.bpf.c bpf/common.h bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

loader/loader: loader/loader.c bpf/common.h
	@test -n "$(LIBBPF_LIB)" || { echo "libbpf.a not found under $(LIBBPF_DIR), see README"; exit 1; }
	$(CC) $(CFLAGS) $< -o $@ $(LIBBPF_LIB) -lelf -lz

clean:
	rm -f bpf/*.bpf.o loader/loader
