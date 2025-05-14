## Overview
This project demonstrates how to build a high performance UDP echo server by utilizing eBPF to maintain CPU cache affinity. The server creates a thread for each CPU, and each thread binds a socket on the same port via `SO_REUSEPORT`. Each thread is pinned to a CPU, and the thread stores its socket fd in a bpf map. Whenever a packet is received on a CPU, the kernel will forward it to the corresponding socket that's pinned to that CPU.

In general, kernel threads receive packets from a NIC then forward it to one or more sockets. If these sockets are not located on the same CPU, then there's a performance penalty to copy the packet data to a different CPU. This approach attempts to boost system performance by avoiding unnecessary cross CPU copies of packet data.

## Setup
You'll need to install gcc, clang, bpftool, and libbpf-devel.

Mount the bpf file system so we can pin eBPF maps.  
`sudo mount -t bpf bpf /sys/fs/bpf`

## Build
`make`

## Run
From one terminal run the server.  
`sudo ./udp_multi_thread`

## Test
Send some packets to the server.  
`./client`

## Acknowledgments

This project was heavily inspired by https://github.com/q2ven/reuseport_cpu. Where the author created a multi-process server, and each process has multiple sockets for the same set of ports.
