/* bpf/tag_kern.c
 * CO-RE eBPF program for TC ingress/egress: tag skb->mark and emit events
 */

// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "vmlinux.h"

/* ===== constants ===== */
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned short __u16;
typedef unsigned char __u8;

#define ETH_P_IP      0x0800
#define ETH_P_IPV6    0x86DD
#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8

#define IPPROTO_TCP   6
#define IPPROTO_UDP   17

/* ===== maps ===== */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} percpu_ctr SEC(".maps");

struct packet_fingerprint {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
    __u64 ts_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct packet_fingerprint);
} id_to_fp SEC(".maps");

struct flow_event {
    __u64 ts_ns;
    __u32 id;
    __u32 mark;
    __u32 hook;
    __u8  proto;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} rb SEC(".maps");

/* ===== mark layout ===== */
#define TOOL_TAG          0xABCULL
#define TAG_SHIFT         20
#define TOOL_TAG_MASK     (0xFFFULL << TAG_SHIFT)
#define ID_MASK           ((1ULL << TAG_SHIFT) - 1)
#define PRESERVE_LOW_MASK 0x0000FFFFU

enum {
    HOOK_TC_INGRESS = 1,
    HOOK_TC_EGRESS  = 2,
};

/* ===== helpers ===== */
static __always_inline void extract_fingerprint(struct __sk_buff *skb,
                                                struct packet_fingerprint *fp)
{
    __builtin_memset(fp, 0, sizeof(*fp));
    fp->ts_ns = bpf_ktime_get_ns();

    __u16 proto = 0;
    if (bpf_skb_load_bytes(skb, 12, &proto, sizeof(proto)) < 0)
        return;

    if (proto == bpf_htons(ETH_P_IP) || proto == ETH_P_IP) {
        struct iphdr iph;
        if (bpf_skb_load_bytes(skb, 14, &iph, sizeof(iph)) < 0)
            return;
        int ihl = iph.ihl * 4;
        if (ihl < (int)sizeof(struct iphdr))
            return;

        fp->proto  = iph.protocol;
        fp->src_ip = iph.saddr;
        fp->dst_ip = iph.daddr;

        if (fp->proto == IPPROTO_TCP || fp->proto == IPPROTO_UDP) {
            __u8 ports[4];
            if (bpf_skb_load_bytes(skb, 14 + ihl, ports, 4) == 0) {
                fp->sport = ((__u16)ports[0] << 8) | ports[1];
                fp->dport = ((__u16)ports[2] << 8) | ports[3];
            }
        }
    }
}

static __always_inline void emit_event(__u32 hook, __u32 mark,
                                       const struct packet_fingerprint *fp)
{
    __u32 id = (mark >> TAG_SHIFT) & ID_MASK;
    struct flow_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return;
    e->ts_ns = bpf_ktime_get_ns();
    e->id    = id;
    e->mark  = mark;
    e->hook  = hook;
    e->proto = fp ? fp->proto : 0;
    e->sport = fp ? fp->sport : 0;
    e->dport = fp ? fp->dport : 0;
    bpf_ringbuf_submit(e, 0);
}

/* ===== tc programs ===== */
SEC("tc/ingress")
int tag_ingress(struct __sk_buff *skb)
{
    __u32 old_mark = skb->mark;
    __u32 want_tag = ((__u32)TOOL_TAG << TAG_SHIFT);

    if ((old_mark & ((__u32)TOOL_TAG_MASK)) == want_tag)
        return BPF_OK;

    __u32 idx = 0;
    __u64 *ctr = bpf_map_lookup_elem(&percpu_ctr, &idx);
    if (!ctr)
        return BPF_OK;

    __u64 prev = __sync_fetch_and_add(ctr, 1);
    __u32 id20 = (__u32)(prev & ID_MASK);

    __u32 low16 = old_mark & PRESERVE_LOW_MASK;
    __u32 new_mark = low16 | want_tag | (id20 & (__u32)ID_MASK);
    skb->mark = new_mark;

    struct packet_fingerprint fp = {};
    extract_fingerprint(skb, &fp);
    bpf_map_update_elem(&id_to_fp, &id20, &fp, BPF_ANY);

    emit_event(HOOK_TC_INGRESS, new_mark, &fp);
    return BPF_OK;
}

SEC("tc/egress")
int tag_egress(struct __sk_buff *skb)
{
    __u32 mark = skb->mark;
    __u32 want_tag = ((__u32)TOOL_TAG << TAG_SHIFT);

    if ((mark & ((__u32)TOOL_TAG_MASK)) != want_tag)
        return BPF_OK;

    struct packet_fingerprint fp = {};
    extract_fingerprint(skb, &fp);
    emit_event(HOOK_TC_EGRESS, mark, &fp);
    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
