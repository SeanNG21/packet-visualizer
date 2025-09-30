#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
#include <inttypes.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../ebpf/bpf/hooks.skel.h"
#include "../ebpf/bpf/callpath.skel.h"

#include "nft_trace.h"

/* ===== struct event: khớp với eBPF ===== */
struct event_hook_t {
    __u64 ts_ns;
    __u8  etype, pf, hook, l4proto;
    __u32 ifindex_in, ifindex_out;
    __s32 verdict;
    __u16 pkt_len, _pad0;
    __u32 saddr_v4, daddr_v4; // be32
    __u16 sport, dport;
    __u64 skb_addr;
    __u32 skb_hash;
    __u32 mark;
};

struct event_call_t {
    __u64 ts_ns;
    __u8  etype, func_id, l4proto, hook_hint;
    __u32 ifindex;
    __u16 pkt_len, _pad1;
    __u32 saddr_v4, daddr_v4; // be32
    __u16 sport, dport;
    __u64 skb_addr;
    __u32 skb_hash;
    __u32 mark;
};

struct pv_event {
    __u32 id;
    __u32 ifindex;
    __u16 proto;
    __u32 len;
};

/* ===== trạng thái ===== */
static struct ring_buffer *rb_hooks, *rb_call, *rb_tc;
static volatile int stop_flag = 0;

/* ===== correlator: lưu event gần nhất ===== */
#define EV_RING 256
struct last_ev {
    __u64 ts_ns;
    __u8  l4;
    __u8  hook;
    __s32 verdict;
    __u32 saddr, daddr; // be32
    __u16 sport, dport;
    __u8  src;          // 1=hooks, 2=callpath, 3=tc
    __u32 mark;
};
static struct last_ev ev_ring[EV_RING];
static int ev_idx = 0;

/* ===== helpers ===== */
static inline const char* be32_to_str(__u32 be, char out[16]) {
    struct in_addr a = { .s_addr = be };
    return inet_ntop(AF_INET, &a, out, 16);
}
static inline __u64 now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}
static inline void push_last(__u8 src, __u8 l4, __u32 s, __u16 sp, __u32 d, __u16 dp,
                      __s32 verdict, __u8 hook, __u64 ts, __u32 mark) {
    int i = ev_idx++ % EV_RING;
    ev_ring[i] = (struct last_ev){ .ts_ns=ts,.l4=l4,.hook=hook,.verdict=verdict,
                                   .saddr=s,.daddr=d,.sport=sp,.dport=dp,.src=src,.mark=mark };
}
static inline struct last_ev* find_near(__u8 l4, __u32 s, __u16 sp,
                                        __u32 d, __u16 dp, __u64 ts, __u32 mark) {
    struct last_ev *best = NULL; __u64 best_dt = ~0ull;
    for (int i=0;i<EV_RING;i++) {
        struct last_ev *E=&ev_ring[i];
        bool match = false;
        if (mark && E->mark == mark) match = true;
        else if (!mark && E->l4==l4 && E->saddr==s && E->sport==sp && E->daddr==d && E->dport==dp)
            match = true;
        if (match) {
            __u64 dt = (ts > E->ts_ns) ? (ts - E->ts_ns) : (E->ts_ns - ts);
            if (dt < best_dt) { best_dt=dt; best=E; }
        }
    }
    return (best && best_dt <= 20*1000*1000ull) ? best : NULL; // ≤ 20ms
}
static inline __u32 ip4_be32_from_str(const char *s) {
    struct in_addr a; return inet_pton(AF_INET, s, &a)==1 ? a.s_addr : 0;
}

/* Fallback: được nft_fallback.c gọi khi parse "nft monitor trace" */
void correlator_on_nft_packet(int hook, unsigned char l4proto,
                              const char *saddr, unsigned short sport,
                              const char *daddr, unsigned short dport)
{
    printf("[nft][pkt] hook=%d proto=%u %s:%u -> %s:%u\n",
           hook, l4proto, saddr, sport, daddr, dport);

    __u32 s_be = ip4_be32_from_str(saddr);
    __u32 d_be = ip4_be32_from_str(daddr);
    __u64 ts   = now_ns();

    struct last_ev *m = find_near(l4proto, s_be, sport, d_be, dport, ts, 0);
    if (m) {
        char sa[16], da[16];
        printf("[merge-fb] ebpf(src=%u) hook=%u verdict=%d %s:%u -> %s:%u\n",
               m->src, m->hook, m->verdict,
               be32_to_str(m->saddr, sa), m->sport,
               be32_to_str(m->daddr, da), m->dport);
    }
}

/* map id -> tên hàm cho log callpath */
static const char* func_name(unsigned id) {
    switch (id) {
        case 1: return "ip_rcv";
        case 2: return "netif_receive_skb";
        case 3: return "ip_local_deliver";
        case 4: return "nf_hook_slow";
        case 5: return "ip_local_out";
        case 6: return "ip_output";
        case 7: return "__dev_queue_xmit";
        case 8: return "dev_hard_start_xmit";
        case 9: return "loopback_xmit";
        default: return "?";
    }
}

/* ===== ringbuf callbacks ===== */
static int on_hook_event(void *ctx, void *data, size_t len) {
    (void)ctx; (void)len;
    struct event_hook_t *e = data;
    char s[16], d[16]; be32_to_str(e->saddr_v4, s); be32_to_str(e->daddr_v4, d);

    if (e->verdict >= 0)
        printf("[ebpf][hook-exit] hook=%u verdict=%d l4=%u %s:%u -> %s:%u len=%u mark=%u\n",
               e->hook, e->verdict, e->l4proto, s, e->sport, d, e->dport,
               e->pkt_len, e->mark);
    else
        printf("[ebpf][hook-enter] hook=%u l4=%u %s:%u -> %s:%u len=%u mark=%u\n",
               e->hook, e->l4proto, s, e->sport, d, e->dport, e->pkt_len, e->mark);

    push_last(1, e->l4proto, e->saddr_v4, e->sport, e->daddr_v4, e->dport,
              e->verdict, e->hook, e->ts_ns, e->mark);
    return 0;
}

static int on_call_event(void *ctx, void *data, size_t len) {
    (void)ctx; (void)len;
    struct event_call_t *e = data;
    char s[16], d[16]; be32_to_str(e->saddr_v4, s); be32_to_str(e->daddr_v4, d);

    printf("[ebpf][call] func=%s (id=%u) hint=%u l4=%u %s:%u -> %s:%u len=%u mark=%u\n",
           func_name(e->func_id), e->func_id, e->hook_hint, e->l4proto,
           s, e->sport, d, e->dport, e->pkt_len, e->mark);

    push_last(2, e->l4proto, e->saddr_v4, e->sport, e->daddr_v4, e->dport,
              -1, e->hook_hint, e->ts_ns, e->mark);
    return 0;
}

static int on_tc_event(void *ctx, void *data, size_t len) {
    (void)ctx; (void)len;
    struct pv_event *e = data;
    printf("[tc] id=%u ifindex=%u proto=0x%x len=%u\n",
           e->id, e->ifindex, e->proto, e->len);

    push_last(3, 0, 0, 0, 0, 0, -1, 0, now_ns(), e->id);
    return 0;
}

/* ===== callback từ nft_trace.c ===== */
static void on_nft_evt(uint32_t mark, const char* fam, const char* hookname,
                       const char* table, const char* chain,
                       uint64_t rule, const char* verdict)
{
    printf("[nft][trace] mark=%u %s %s %s/%s rule=%" PRIu64 " verdict=%s\n",
           mark, fam, hookname, table, chain, rule, verdict);

    if (!mark) return;

    __u64 ts = now_ns();
    struct last_ev *m = find_near(0, 0,0,0,0, ts, mark);
    if (m) {
        char sa[16], da[16];
        printf("[merge] mark=%u -> ebpf(src=%u) hook=%u verdict=%d %s:%u -> %s:%u\n",
               mark, m->src, m->hook, m->verdict,
               be32_to_str(m->saddr, sa), m->sport,
               be32_to_str(m->daddr, da), m->dport);
    }
}

/* ===== signal ===== */
static void on_sigint(int signo){ (void)signo; stop_flag=1; }

/* ===== main ===== */
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, on_sigint);

    /* 1) eBPF: hooks */
    struct hooks_bpf *hooks = hooks_bpf__open_and_load();
    if (!hooks) fprintf(stderr, "hooks open/load fail\n");
    else if (hooks_bpf__attach(hooks)) fprintf(stderr, "hooks attach fail\n");

    /* 2) eBPF: callpath */
    struct callpath_bpf *cp = callpath_bpf__open_and_load();
    if (!cp) fprintf(stderr, "callpath open/load fail\n");
    else if (callpath_bpf__attach(cp)) fprintf(stderr, "callpath attach fail\n");

    /* 3) tc_ingress: chỉ mở map từ pinning */
    int fd_tc = bpf_obj_get("/sys/fs/bpf/tc/globals/rb_tc");
    if (fd_tc < 0) {
        perror("bpf_obj_get rb_tc");
    } else {
        rb_tc = ring_buffer__new(fd_tc, on_tc_event, NULL, NULL);
        if (!rb_tc) fprintf(stderr, "ringbuf tc open fail\n");
    }

    /* 4) ringbuffers */
    int fd_hooks=-1, fd_call=-1;
    if (hooks && hooks->maps.events_hooks) fd_hooks = bpf_map__fd(hooks->maps.events_hooks);
    if (cp && cp->maps.events_call)        fd_call  = bpf_map__fd(cp->maps.events_call);

    rb_hooks = (fd_hooks>=0) ? ring_buffer__new(fd_hooks, on_hook_event, NULL, NULL) : NULL;
    rb_call  = (fd_call >=0) ? ring_buffer__new(fd_call,  on_call_event, NULL, NULL) : NULL;

    if (!rb_hooks && fd_hooks>=0) fprintf(stderr, "ringbuf hooks open fail\n");
    if (!rb_call  && fd_call >=0) fprintf(stderr, "ringbuf call open fail\n");

    /* 5) thread nft trace */
    pthread_t t_nft;
    pthread_create(&t_nft, NULL, (void*(*)(void*))nft_trace_start, (void*)on_nft_evt);

    /* 6) poll */
    while (!stop_flag) {
        if (rb_hooks) ring_buffer__poll(rb_hooks, 100);
        if (rb_call)  ring_buffer__poll(rb_call,  100);
        if (rb_tc)    ring_buffer__poll(rb_tc,    100);
        if (!rb_hooks && !rb_call && !rb_tc) usleep(200*1000);
    }

    ring_buffer__free(rb_hooks);
    ring_buffer__free(rb_call);
    ring_buffer__free(rb_tc);
    if (hooks) hooks_bpf__destroy(hooks);
    if (cp)    callpath_bpf__destroy(cp);
    return 0;
}
