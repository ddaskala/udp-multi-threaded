BPFTOOL=bpftool
CC=gcc
CFLAGS=-std=gnu11 -O3 -Wall -Wextra -fstack-protector-strong
ARCH=$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

all: udp_multi_thread client

udp_multi_thread: udp_multi_thread.c reuseport_cpu.skel.h
	$(CC) $(CFLAGS) -lbpf -lpthread udp_multi_thread.c reuseport_cpu.skel.h -o udp_multi_thread

client: client.c
	$(CC) $(CFLAGS) client.c reuseport_cpu.skel.h -o client

reuseport_cpu.skel.h: reuseport_cpu_bpf.o
	$(BPFTOOL) gen skeleton reuseport_cpu_bpf.o > reuseport_cpu.skel.h

reuseport_cpu_bpf.o: reuseport_cpu.bpf.c vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c reuseport_cpu.bpf.c -o reuseport_cpu_bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm udp_multi_thread client reuseport_cpu.skel.h reuseport_cpu_bpf.o vmlinux.h