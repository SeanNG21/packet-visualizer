// ebpf/bpf/callpath.bpf.c
#include "prog.h"

/* Ringbuf riêng cho callpath */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22);
} events_call SEC(".maps");

static __always_inline __u16 bpf_ntohs16(__u16 x){ return __builtin_bswap16(x); }

/* Đọc IPv4 + TCP/UDP ports từ skb KHÔNG dùng helper skb_* */
static __always_inline void fill_tuple_from_skb(struct event_call_t *e, struct sk_buff *skb)
{
    /* network_header là offset từ head */
    void *head = (void *)(unsigned long)BPF_CORE_READ(skb, head);
    __u16 nhoff = BPF_CORE_READ(skb, network_header);
    __u32 len   = BPF_CORE_READ(skb, len);

    if (!head || (__u32)nhoff + sizeof(struct iphdr) > len) {
        e->l4proto = 0; e->sport = 0; e->dport = 0; e->saddr_v4 = 0; e->daddr_v4 = 0;
        return;
    }

    char *nh = (char *)head + nhoff;

    struct iphdr iph = {};
    if (bpf_probe_read_kernel(&iph, sizeof(iph), nh) < 0 || iph.version != 4) {
        e->l4proto = 0; e->sport = 0; e->dport = 0; e->saddr_v4 = 0; e->daddr_v4 = 0;
        return;
    }

    /* packet-id mềm + hash/mark có sẵn trong skb */
    e->skb_addr = (unsigned long long)skb;
    {
        __u32 h = 0;
        BPF_CORE_READ_INTO(&h, skb, hash);
        e->skb_hash = h;
    }
    e->mark = BPF_CORE_READ(skb, mark);

    e->l4proto  = iph.protocol;
    e->saddr_v4 = iph.saddr;     /* BE32, convert ở user-space nếu cần */
    e->daddr_v4 = iph.daddr;

    __u32 ihl_bytes = (__u32)iph.ihl * 4;
    if ((__u32)nhoff + ihl_bytes > len) { e->sport = 0; e->dport = 0; return; }

    if (iph.protocol == IPPROTO_TCP) {
        struct tcphdr th = {};
        if ((__u32)nhoff + ihl_bytes + sizeof(th) <= len &&
            bpf_probe_read_kernel(&th, sizeof(th), nh + ihl_bytes) == 0) {
            e->sport = bpf_ntohs16(th.source);
            e->dport = bpf_ntohs16(th.dest);
        } else { e->sport = 0; e->dport = 0; }
    } else if (iph.protocol == IPPROTO_UDP) {
        struct udphdr uh = {};
        if ((__u32)nhoff + ihl_bytes + sizeof(uh) <= len &&
            bpf_probe_read_kernel(&uh, sizeof(uh), nh + ihl_bytes) == 0) {
            e->sport = bpf_ntohs16(uh.source);
            e->dport = bpf_ntohs16(uh.dest);
        } else { e->sport = 0; e->dport = 0; }
    } else {
        e->sport = 0; e->dport = 0;
    }
}

/* Emit một sự kiện callpath */
static __always_inline int emit_call(__u8 func_id, __u8 hook_hint, struct sk_buff *skb)
{
    struct event_call_t *e = bpf_ringbuf_reserve(&events_call, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->etype     = EVT_CALL;
    e->ts_ns     = bpf_ktime_get_ns();
    e->func_id   = func_id;
    e->hook_hint = hook_hint;
    e->pkt_len   = (__u16)BPF_CORE_READ(skb, len);

    /* ifindex RX: từ skb->dev nếu có */
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (dev) e->ifindex = BPF_CORE_READ(dev, ifindex);

    fill_tuple_from_skb(e, skb);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Kprobes đại diện một số điểm trong đường đi */
SEC("kprobe/ip_rcv")
int BPF_KPROBE(kp_ip_rcv, struct sk_buff *skb)
{
    return emit_call(CF_IP_RCV, NFH_PREROUTING, skb);
}

SEC("kprobe/ip_local_deliver")
int BPF_KPROBE(kp_ip_local_deliver, struct sk_buff *skb)
{
    return emit_call(CF_IP_LOCAL_DELIVER, NFH_LOCAL_IN, skb);
}

SEC("kprobe/ip_local_out")
int BPF_KPROBE(kp_ip_local_out, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return emit_call(CF_IP_LOCAL_OUT, NFH_LOCAL_OUT, skb);
}

SEC("kprobe/ip_output")
int BPF_KPROBE(kp_ip_output, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return emit_call(CF_IP_OUTPUT, NFH_POSTROUTING, skb);
}

char LICENSE[] SEC("license") = "GPL";
