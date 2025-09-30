// ebpf/src/bpf/hooks.bpf.c
// fentry/fexit for nf_hook_slow() -> capture hook + verdict (+ IPv4 5-tuple)
// CO-RE friendly (requires BTF), outputs events via a ring buffer.

// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/udp.h>
// #include <linux/tcp.h>
#define DEFINE_BPF_MAPS
#include "prog.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22);
} events_hooks SEC(".maps"); 

// ====== config / helpers ======
char LICENSE[] SEC("license") = "GPL";

// convert BE<->LE helpers (no libc in eBPF)
static __always_inline __u16 bpf_ntohs(__u16 x) { return __builtin_bswap16(x); }
static __always_inline __u32 bpf_ntohl(__u32 x) { return __builtin_bswap32(x); }

// Event type
enum {
    EVT_HOOK_ENTER = 0,
    EVT_HOOK_EXIT  = 1,
};

// Keep it compact; extend later if needed
struct event_t {
    __u64 ts_ns;

    __u8  etype;        // enter/exit
    __u8  pf;           // nf proto family (NFPROTO_*)
    __u8  hook;         // 0..4  (PREROUTING..POSTROUTING)
    __u8  l4proto;      // IPPROTO_*

    __u32 ifindex_in;   // from nf_hook_state->in (if any)
    __u32 ifindex_out;  // from nf_hook_state->out (if any)

    __s32 verdict;      // only valid for EXIT (retval), -1 for ENTER

    __u16 pkt_len;      // skb->len (truncated to 16-bit)
    __u16 reserved;

    // IPv4 5-tuple (host order where meaningful)
    __u32 saddr_v4;
    __u32 daddr_v4;
    __u16 sport;
    __u16 dport;
    __u64 skb_addr;   // pointer của skb (làm packet-id mềm)
    __u32 skb_hash;   // bpf_get_hash_recalc()
    __u32 mark;
};

// Ring buffer for events
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1 << 22); // 4MB buffer
// } events SEC(".maps");

// Safely read IPv4 + (optional) TCP/UDP header starting from NET header.
// Returns 0 on success and fills event fields.
static __always_inline int parse_ipv4(struct sk_buff *skb, struct event_t *e)
{
    // Lấy offset L3 chuẩn từ skb->network_header - skb->head
    __u32 nh_off = BPF_CORE_READ(skb, network_header);

    struct iphdr iph = {};
    if (bpf_skb_load_bytes(skb, nh_off, &iph, sizeof(iph)) < 0)
        return -1;
    if (iph.version != 4)
        return -1;

    e->l4proto  = iph.protocol;
    e->saddr_v4 = iph.saddr;  // giữ nguyên be32, convert ở user-space
    e->daddr_v4 = iph.daddr;

    __u32 ihl_bytes = (__u32)iph.ihl * 4;
    __u32 l4_off = nh_off + ihl_bytes;

    if (iph.protocol == IPPROTO_TCP) {
        struct tcphdr th = {};
        if (bpf_skb_load_bytes(skb, l4_off, &th, sizeof(th)) == 0) {
            e->sport = bpf_ntohs(th.source);
            e->dport = bpf_ntohs(th.dest);
        }
    } else if (iph.protocol == IPPROTO_UDP) {
        struct udphdr uh = {};
        if (bpf_skb_load_bytes(skb, l4_off, &uh, sizeof(uh)) == 0) {
            e->sport = bpf_ntohs(uh.source);
            e->dport = bpf_ntohs(uh.dest);
        }
    } else {
        e->sport = 0; e->dport = 0;
    }
    return 0;
}


// Fill common fields from skb/state; parse L3/L4 if IPv4.
static __always_inline void fill_common(struct sk_buff *skb,
                                        struct nf_hook_state *st,
                                        struct event_t *e)
{
    e->ts_ns  = bpf_ktime_get_ns();
    e->pf     = st ? st->pf   : 0;
    e->hook   = st ? st->hook : 0;
    e->pkt_len = (__u16)BPF_CORE_READ(skb, len);
    e->verdict = -1;

        /* packet-id mềm */
    e->skb_addr = (unsigned long long)skb;
    /* hash flow sẵn có của skb (0 nếu kernel chưa tính) */
    {
        __u32 h = 0;
        BPF_CORE_READ_INTO(&h, skb, hash);
        e->skb_hash = h;
    }
    e->mark = BPF_CORE_READ(skb, mark);

    // ifindex in/out
    e->ifindex_in  = 0;
    e->ifindex_out = 0;
    if (st) {
        struct net_device *in  = BPF_CORE_READ(st, in);
        struct net_device *out = BPF_CORE_READ(st, out);
        if (in)  e->ifindex_in  = BPF_CORE_READ(in, ifindex);
        if (out) e->ifindex_out = BPF_CORE_READ(out, ifindex);
    }
    if (st && st->pf == NFPROTO_IPV4) {
        (void)parse_ipv4(skb, e);
    } else {
        e->l4proto = 0;
        e->sport = e->dport = 0;
        e->saddr_v4 = e->daddr_v4 = 0;
    }

    // Try IPv4 parse; ignore failures silently (could be IPv6/ARP/etc.)
    // (void)parse_ipv4(skb, e);
}

// ===================== fentry: nf_hook_slow =====================
SEC("fentry/nf_hook_slow")
int BPF_PROG(hook_enter, struct sk_buff *skb, struct nf_hook_state *state)
{
    struct event_t *e = bpf_ringbuf_reserve(&events_hooks, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->etype = EVT_HOOK_ENTER;
    fill_common(skb, state, e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ===================== fexit: nf_hook_slow ======================
SEC("fexit/nf_hook_slow")
int BPF_PROG(hook_exit, struct sk_buff *skb, struct nf_hook_state *state, int ret)
{
    struct event_t *e = bpf_ringbuf_reserve(&events_hooks, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->etype   = EVT_HOOK_EXIT;
    e->verdict = ret;                 // NF_ACCEPT=1, NF_DROP=0, ...
    fill_common(skb, state, e);       // (overwrites verdict to -1, so set it again)
    e->verdict = ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}


