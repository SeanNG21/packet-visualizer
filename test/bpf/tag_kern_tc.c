/* bpf/tag_kern_tc.c - TC-BPF program with mark + log */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>   // 🔥 thêm cái này để có IPPROTO_TCP, IPPROTO_UDP
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TOOL_TAG          0xABC
#define TAG_SHIFT         20
#define ID_MASK           ((1U << TAG_SHIFT) - 1)

enum hook_type {
    HOOK_TC_INGRESS = 1,
    HOOK_TC_EGRESS  = 2,
};

struct flow_event {
    __u64 ts_ns;
    __u32 id;
    __u32 mark;
    __u32 hook;
    __u8  proto;
    __u16 sport;
    __u16 dport;
    __u32 src_ip;
    __u32 dst_ip;
} __attribute__((packed));

/* Counter per-CPU */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} percpu_ctr SEC(".maps");

/* Ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} rb SEC(".maps");

/* Parse IPv4 packet */
static __always_inline int parse_pkt(void *data, void *data_end,
                                     __u32 *src_ip, __u32 *dst_ip,
                                     __u16 *sport, __u16 *dport, __u8 *proto)
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

/* Common logic for ingress/egress */
static __always_inline int handle_tc(struct __sk_buff *skb, __u32 hook)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    __u32 src_ip = 0, dst_ip = 0;
    __u16 sport = 0, dport = 0;
    __u8 proto = 0;

    if (parse_pkt(data, data_end, &src_ip, &dst_ip, &sport, &dport, &proto) < 0)
        return TC_ACT_OK;

    /* Generate ID */
    __u32 idx = 0;
    __u64 *ctr = bpf_map_lookup_elem(&percpu_ctr, &idx);
    if (!ctr)
        return TC_ACT_OK;

    __u64 count = __sync_fetch_and_add(ctr, 1);
    __u32 id = (__u32)(count & ID_MASK);
    __u32 mark = (TOOL_TAG << TAG_SHIFT) | id;

    /* Gắn mark thật vào skb */
    skb->mark = mark;

    /* Gửi log ra ring buffer */
    struct flow_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    e->ts_ns = bpf_ktime_get_ns();
    e->id = id;
    e->mark = mark;
    e->hook = hook;
    e->proto = proto;
    e->sport = sport;
    e->dport = dport;
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;

    bpf_ringbuf_submit(e, 0);

    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    return handle_tc(skb, HOOK_TC_INGRESS);
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    return handle_tc(skb, HOOK_TC_EGRESS);
}


char LICENSE[] SEC("license") = "GPL";
