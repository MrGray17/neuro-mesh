// ==============================================================================
// NEURO-MESH SOVEREIGN CELL : eBPF KERNEL PROBE (CO-RE)
// ==============================================================================
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EVENT_TYPE_EXEC 1
#define EVENT_TYPE_CONNECT 2

// Strict Data Contract with C++ User-Space
struct event_t {
    u32 pid;
    u32 ppid;
    u32 event_type;
    char comm[16];
    char payload[256];
};

// High-Performance Memory Bridge to User-Space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB Ring Buffer
} telemetry_ringbuf SEC(".maps");

// ------------------------------------------------------------------------------
// HOOK 1: sys_enter_execve (Catches every process start, including hidden ones)
// ------------------------------------------------------------------------------
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;

    // Zero-allocation memory reservation directly in the ring buffer
    e = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*e), 0);
    if (!e) return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->event_type = EVENT_TYPE_EXEC;
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Safely extract the binary path from user-space memory
    const char *arg_ptr = (const char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->payload, sizeof(e->payload), arg_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ------------------------------------------------------------------------------
// HOOK 2: sys_enter_connect (Catches every outbound network attempt)
// ------------------------------------------------------------------------------
SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;

    e = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->event_type = EVENT_TYPE_CONNECT;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Extracting socket struct (Simplified string identifier for C++ parser)
    struct sockaddr *addr = (struct sockaddr *)BPF_CORE_READ(ctx, args[1]);
    short family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    
    // Tag payload with address family (AF_INET = 2)
    e->payload[0] = (char)family;
    e->payload[1] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
