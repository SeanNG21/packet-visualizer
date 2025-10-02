/* bpf/tag_kern_xdp.c - XDP version for better packet capture */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define TOOL_TAG          0xABC
#define TAG_SHIFT         20
#define ID_MASK           ((1U << TAG_SHIFT) - 1)

enum hook_type {
    HOOK_XDP = 1,
};

struct flow_event {
    u64 ts_ns;
    u32 id;
    u32 mark;
    u32 hook;
    u8  proto;
    u16 sport;
    u16 dport;
    u32 src_ip;
    u32 dst_ip;
} __attribute__((packed));

/* Per-CPU counter */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} percpu_ctr SEC(".maps");

/* Ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} rb SEC(".maps");

/* Parse packet */
static __always_inline int parse_pkt(void *data, void *data_end,
                                     u32 *src_ip, u32 *dst_ip,
                                     u16 *sport, u16 *dport, u8 *proto)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    *proto = iph->protocol;
    *src_ip = iph->saddr;
    *dst_ip = iph->daddr;

    if (*proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return 0;
        *sport = bpf_ntohs(tcph->source);
        *dport = bpf_ntohs(tcph->dest);
    } else if (*proto == IPPROTO_UDP) {
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return 0;
        *sport = bpf_ntohs(udph->source);
        *dport = bpf_ntohs(udph->dest);
    }

    return 0;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    u32 src_ip = 0, dst_ip = 0;
    u16 sport = 0, dport = 0;
    u8 proto = 0;

    /* Parse packet */
    if (parse_pkt(data, data_end, &src_ip, &dst_ip, &sport, &dport, &proto) < 0)
        return XDP_PASS;

    /* Generate packet ID */
    u32 idx = 0;
    u64 *ctr = bpf_map_lookup_elem(&percpu_ctr, &idx);
    if (!ctr)
        return XDP_PASS;

    u64 count = __sync_fetch_and_add(ctr, 1);
    u32 id = (u32)(count & ID_MASK);
    u32 mark = (TOOL_TAG << TAG_SHIFT) | id;

    /* Reserve ring buffer */
    struct flow_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return XDP_PASS;

    /* Fill event */
    e->ts_ns = bpf_ktime_get_ns();
    e->id = id;
    e->mark = mark;
    e->hook = HOOK_XDP;
    e->proto = proto;
    e->sport = sport;
    e->dport = dport;
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";