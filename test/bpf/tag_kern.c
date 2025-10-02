/* bpf/tag_kern.c - Complete eBPF TC program */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Type definitions */
typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

/* Constants */
#define TOOL_TAG          0xABC
#define TAG_SHIFT         20
#define TOOL_TAG_MASK     (0xFFFU << TAG_SHIFT)
#define ID_MASK           ((1U << TAG_SHIFT) - 1)

#define ETH_P_IP          0x0800
#define IPPROTO_TCP       6
#define IPPROTO_UDP       17
#define IPPROTO_ICMP      1

enum hook_type {
    HOOK_TC_INGRESS = 1,
    HOOK_TC_EGRESS  = 2,
};

/* Event structure */
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

/* Per-CPU counter for packet IDs */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} percpu_ctr SEC(".maps");

/* Packet fingerprint storage */
struct packet_fingerprint {
    u32 src_ip;
    u32 dst_ip;
    u16 sport;
    u16 dport;
    u8  proto;
    u8  pad[3];
    u64 ts_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct packet_fingerprint);
} id_to_fp SEC(".maps");

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4MB */
} rb SEC(".maps");

/* Helper to extract packet info */
static __always_inline void extract_fingerprint(struct __sk_buff *skb,
                                                struct packet_fingerprint *fp)
{
    __builtin_memset(fp, 0, sizeof(*fp));
    fp->ts_ns = bpf_ktime_get_ns();

    /* Load Ethernet header */
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return;

    /* Only process IPv4 */
    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return;

    /* Load IP header */
    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, sizeof(eth), &iph, sizeof(iph)) < 0)
        return;

    if (iph.version != 4)
        return;

    int ihl = iph.ihl * 4;
    if (ihl < (int)sizeof(struct iphdr))
        return;

    fp->proto  = iph.protocol;
    fp->src_ip = iph.saddr;
    fp->dst_ip = iph.daddr;

    /* Parse ports for TCP/UDP */
    if (fp->proto == IPPROTO_TCP || fp->proto == IPPROTO_UDP) {
        u8 ports[4];
        if (bpf_skb_load_bytes(skb, sizeof(eth) + ihl, ports, 4) == 0) {
            fp->sport = ((u16)ports[0] << 8) | ports[1];
            fp->dport = ((u16)ports[2] << 8) | ports[3];
        }
    }
}

/* Helper to emit event to ring buffer */
static __always_inline void emit_event(u32 hook, u32 mark,
                                       const struct packet_fingerprint *fp)
{
    u32 id = mark & ID_MASK;
    struct flow_event *e;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        /* Ring buffer full */
        return;
    }

    e->ts_ns = bpf_ktime_get_ns();
    e->id    = id;
    e->mark  = mark;
    e->hook  = hook;
    e->proto = fp ? fp->proto : 0;
    e->sport = fp ? fp->sport : 0;
    e->dport = fp ? fp->dport : 0;
    e->src_ip = fp ? fp->src_ip : 0;
    e->dst_ip = fp ? fp->dst_ip : 0;

    bpf_ringbuf_submit(e, 0);
}

/* TC Ingress program */
SEC("tc/ingress")
int tag_ingress(struct __sk_buff *skb)
{
    u32 idx = 0;
    u64 *ctr = bpf_map_lookup_elem(&percpu_ctr, &idx);
    if (!ctr)
        return TC_ACT_OK;

    /* Generate unique packet ID */
    u64 prev = __sync_fetch_and_add(ctr, 1);
    u32 id20 = (u32)(prev & ID_MASK);

    /* Build and set mark */
    u32 new_mark = (TOOL_TAG << TAG_SHIFT) | id20;
    skb->mark = new_mark;

    /* Extract packet info */
    struct packet_fingerprint fp = {};
    extract_fingerprint(skb, &fp);

    /* Store fingerprint */
    bpf_map_update_elem(&id_to_fp, &id20, &fp, BPF_ANY);

    /* Emit event */
    emit_event(HOOK_TC_INGRESS, new_mark, &fp);

    return TC_ACT_OK;
}

/* TC Egress program */
SEC("tc/egress")
int tag_egress(struct __sk_buff *skb)
{
    u32 mark = skb->mark;
    
    /* Check if packet has our tool tag */
    if ((mark & TOOL_TAG_MASK) != (TOOL_TAG << TAG_SHIFT))
        return TC_ACT_OK;

    /* Extract packet info */
    struct packet_fingerprint fp = {};
    extract_fingerprint(skb, &fp);

    /* Emit event */
    emit_event(HOOK_TC_EGRESS, mark, &fp);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";