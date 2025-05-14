// Heavily influenced by https://github.com/q2ven/reuseport_cpu
// But we adapted this approach to be multi-threaded instead of multi-process.
// You'll need to install gcc, clang, bpftool, and libbpf-devel
// sudo mount -t bpf bpf /sys/fs/bpf
// run with `sudo ./udp_multi_thread`
//
// Use the following command to see the CPU which the application threads are pinned to
// ps -mo pid,tid,%cpu,psr -p <pid>

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "reuseport_cpu.skel.h"

#define PORT 2048
#define BUFFER_SIZE 1024

#define PATH_LEN    128
#define PATH_MAP    "/sys/fs/bpf/reuseport_map_%05d"
#define PATH_PROG   "/sys/fs/bpf/reuseport_prog_%05d"

// Structure to pass data to threads
typedef struct {
    // thread_id is overloaded, it's also the cpu id
    // that we will pin the thread to.
    int thread_id;
} thread_data_t;

static int pin_thread_to_cpu(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    // Set the CPU affinity for the current thread
    int result = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (result != 0) {
        // Handle error
        return -1;
    }

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level __attribute__((unused)), const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static int attach_reuseport_prog(thread_data_t *data, int sockfd, int port)
{
    char path[PATH_LEN];
    int prog_fd, err;

    snprintf(path, PATH_LEN, PATH_PROG, port);

    prog_fd = bpf_obj_get(path);
    if (prog_fd < 0)
        return prog_fd;

    err = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
             &prog_fd, sizeof(prog_fd));
    if (err)
        fprintf(stderr, "CPU[%02d]: Failed to attach BPF prog\n", data->thread_id);

    close(prog_fd);

    return err;
}

static int update_reuseport_map(thread_data_t *data, int sockfd)
{
    char path[PATH_LEN];
    int map_fd, err;

    // This picks the map of sockfds for a port
    snprintf(path, PATH_LEN, PATH_MAP, PORT);

    /* Load pinned BPF map */
    map_fd = bpf_obj_get(path);
    if (map_fd < 0) {
        fprintf(stderr, "CPU[%02d]: Failed to open BPF map %s\n", data->thread_id, path);
    }

    err = bpf_map_update_elem(map_fd, &data->thread_id, &sockfd, BPF_NOEXIST);
    if (err) {
        fprintf(stderr, "CPU[%02d]: Failed to update BPF map for sockfd %d\n", data->thread_id, sockfd);
    }

    close(map_fd);

    return err;
}

void *socket_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    int thread_id = data->thread_id;
    int sockfd = -1;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    int opt = 1;

    if (pin_thread_to_cpu(thread_id) < 0) {
        perror("Failed to pin thread to CPU");
        goto close;
    }

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        goto close;
    }

    // Set SO_REUSEPORT option
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEPORT failed");
        goto close;
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket to address and port
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        goto close;
    }
    printf("Thread %d: Socket bound to port %d with SO_REUSEPORT\n", thread_id, PORT);

    /* Update BPF map like: map[cpu_id] = socket_fd */
    if (update_reuseport_map(data, sockfd) != 0) {
        perror("update_reuseport_map failed");
        goto close;
    }

    /* Attach BPF program to reuseport group. We only need to attach to one of the sockets,
     * so restrict this to thread 0. */
    if (thread_id == 0) {
        if (attach_reuseport_prog(data, sockfd, PORT) != 0) {
            perror("attach_reuseport_prog failed");
            goto close;
        }
    }
    
    // Main receive loop
    while (1) {
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, 
                        (struct sockaddr *)&client_addr, &client_len);
        
        if (n < 0) {
            perror("recvfrom failed");
            continue;
        }
        
        buffer[n] = '\0';
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        
        printf("Thread %d received from %s:%d: %s\n", 
               thread_id, client_ip, ntohs(client_addr.sin_port), buffer);
        
        // Echo back to client
        sendto(sockfd, buffer, n, 0, (struct sockaddr *)&client_addr, client_len);
    }

close:
    if (sockfd != -1) {
        close(sockfd);
    }
    pthread_exit(NULL);
}

static int pin_bpf_obj(int port)
{
    struct reuseport_cpu_bpf *skel;
    char path[PATH_LEN];
    int err;

    /* Open BPF skeleton */
    skel = reuseport_cpu_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }

    /* Load & verify BPF programs */
    err = reuseport_cpu_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    snprintf(path, PATH_LEN, PATH_MAP, port);

    /* Unpin already pinned BPF map */
    unlink(path);

    /* Pin BPF map */
    err = bpf_map__pin(skel->maps.reuseport_map, path);
    if (err) {
        fprintf(stderr, "Failed to pin BPF map at %s\n", path);
        goto cleanup;
    }

    snprintf(path, PATH_LEN, PATH_PROG, port);

    /* Unpin already pinned BPF prog */
    unlink(path);

    /* Pin BPF prog */
    err = bpf_program__pin(skel->progs.migrate_reuseport, path);
    if (err) {
        fprintf(stderr, "Failed to pin BPF prog at %s\n", path);
    }

cleanup:
    reuseport_cpu_bpf__destroy(skel);

    return err;
}

static int setup_bpf_map(void)
{

    libbpf_set_print(libbpf_print_fn);

    return pin_bpf_obj(PORT);
}

int main() {
    int num_cpus = libbpf_num_possible_cpus();
    pthread_t threads[num_cpus];
    thread_data_t thread_data[num_cpus];
    
    printf("Starting UDP server with %d threads on port %d\n", num_cpus, PORT);

    if (setup_bpf_map() != 0) {
        perror("setup_bpf_map failed");
        exit(1);
    }
    
    // Create threads
    for (int i = 0; i < num_cpus; i++) {
        thread_data[i].thread_id = i;
        
        if (pthread_create(&threads[i], NULL, socket_thread, &thread_data[i]) != 0) {
            perror("Failed to create thread");
            return 1;
        }
        
        printf("Thread %d created\n", i);
    }
    
    // Wait for all threads to complete (which won't happen in this example)
    for (int i = 0; i < num_cpus; i++) {
        pthread_join(threads[i], NULL);
    }
    
    return 0;
}
