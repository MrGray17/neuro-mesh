// ============================================================
// NEURO-MESH : KERNEL eBPF SENSOR & XDP DROPPER
// ============================================================
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// 1. DATA STRUCTURES
struct KernelEvent {
    unsigned int pid;
    int event_type;
    char comm[16];
    char payload[256];
};

// 2. KERNEL TO USERSPACE RING BUFFER (The Eyes)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} telemetry_ringbuf SEC(".maps");

// 3. THE HARDWARE BLACKLIST MAP (The Shield)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);   // IP Address
    __type(value, __u8);   // Status (1 = Blocked)
} xdp_blacklist SEC(".maps");

// ============================================================
// XDP PROGRAM: HARDWARE-LEVEL PACKET DROPPER
// Runs directly on the Network Interface Card driver
// ============================================================
SEC("xdp")
int xdp_neuro_mesh_dropper(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // We only care about IP traffic
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    // Check if the Source IP is in our "COMPROMISED" hash map
    __be32 src_ip = iph->saddr;
    __u8 *banned = bpf_map_lookup_elem(&xdp_blacklist, &src_ip);
    if (banned && *banned == 1) {
        // Instant hardware-level drop. No CPU usage for the kernel stack.
        return XDP_DROP;
    }

    return XDP_PASS;
}

// ============================================================
// TRACEPOINT: PROCESS EXECUTION MONITORING
// Feeds the local AI Inference Engine via Ring Buffer
// ============================================================
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    struct KernelEvent *event;
    
    // Reserve memory in the ring buffer
    event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->event_type = 1; // 1 = EXEC
    
    // Grab the command name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Submit to user-space SovereignCell
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
