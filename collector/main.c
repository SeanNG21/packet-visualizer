// collector/main.c
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

#include <netinet/in.h>
#include <bpf/libbpf.h>

#include "../ebpf/bpf/hooks.skel.h"
#include "../ebpf/bpf/callpath.skel.h"
#include "nft_fallback.h"

/* ===== struct event: phải khớp với eBPF (prog.h / *.bpf.c) ===== */
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

/* ===== trạng thái ===== */
static struct ring_buffer *rb_hooks, *rb_call;
static volatile int stop_flag = 0;

/* ===== correlator: nhớ sự kiện gần nhất để ghép theo 5-tuple + thời gian ===== */
#define EV_RING 256
struct last_ev {
  __u64 ts_ns;
  __u8  l4;
  __u8  hook;
  __s32 verdict;
  __u32 saddr, daddr; // be32
  __u16 sport, dport;
  __u8  src;          // 1=hooks, 2=callpath
};
static struct last_ev ev_ring[EV_RING];
static int ev_idx = 0;

/* ===== helpers ===== */
static inline const char* be32_to_str(__u32 be, char out[16]) {
  struct in_addr a = { .s_addr = be };
  return inet_ntop(AF_INET, &a, out, 16);
}
static inline __u32 ip4_be32_from_str(const char *s) {
  struct in_addr a; return inet_pton(AF_INET, s, &a)==1 ? a.s_addr : 0;
}
static inline __u64 now_ns(void) {
  struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
  return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}
static inline void push_last(__u8 src, __u8 l4, __u32 s, __u16 sp, __u32 d, __u16 dp,
                      __s32 verdict, __u8 hook, __u64 ts) {
  int i = ev_idx++ % EV_RING;
  ev_ring[i] = (struct last_ev){ .ts_ns=ts,.l4=l4,.hook=hook,.verdict=verdict,
                                 .saddr=s,.daddr=d,.sport=sp,.dport=dp,.src=src };
}
static inline struct last_ev* find_near(__u8 l4, __u32 s, __u16 sp, __u32 d, __u16 dp, __u64 ts) {
  struct last_ev *best = NULL; __u64 best_dt = ~0ull;
  for (int i=0;i<EV_RING;i++) {
    struct last_ev *E=&ev_ring[i];
    if (E->l4==l4 && E->saddr==s && E->sport==sp && E->daddr==d && E->dport==dp) {
      __u64 dt = (ts > E->ts_ns) ? (ts - E->ts_ns) : (E->ts_ns - ts);
      if (dt < best_dt) { best_dt=dt; best=E; }
    }
  }
  return (best && best_dt <= 20*1000*1000ull) ? best : NULL; // ≤ 20ms
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
    printf("[ebpf][hook-exit] hook=%u verdict=%d l4=%u %s:%u -> %s:%u len=%u pid=%llx hash=%u mark=%u\n",
           e->hook, e->verdict, e->l4proto, s, e->sport, d, e->dport, e->pkt_len,
           (unsigned long long)e->skb_addr, e->skb_hash, e->mark);
  else
    printf("[ebpf][hook-enter] hook=%u l4=%u %s:%u -> %s:%u len=%u pid=%llx hash=%u mark=%u\n",
           e->hook, e->l4proto, s, e->sport, d, e->dport, e->pkt_len,
           (unsigned long long)e->skb_addr, e->skb_hash, e->mark);

  /* ghép theo 5-tuple + ts */
  push_last(1, e->l4proto, e->saddr_v4, e->sport, e->daddr_v4, e->dport,
            e->verdict, e->hook, e->ts_ns);
  return 0;
}

static int on_call_event(void *ctx, void *data, size_t len) {
  (void)ctx; (void)len;
  struct event_call_t *e = data;
  char s[16], d[16]; be32_to_str(e->saddr_v4, s); be32_to_str(e->daddr_v4, d);

  printf("[ebpf][call] func=%s (id=%u) hint=%u l4=%u %s:%u -> %s:%u len=%u pid=%llx hash=%u mark=%u\n",
         func_name(e->func_id), e->func_id, e->hook_hint, e->l4proto,
         s, e->sport, d, e->dport, e->pkt_len,
         (unsigned long long)e->skb_addr, e->skb_hash, e->mark);

  push_last(2, e->l4proto, e->saddr_v4, e->sport, e->daddr_v4, e->dport,
            -1, e->hook_hint, e->ts_ns);
  return 0;
}

/* ===== được gọi từ thread fallback nft mỗi khi parse ra 1 dòng "packet" ===== */
void correlator_on_nft_packet(int hook, unsigned char l4proto,
                              const char *saddr, unsigned short sport,
                              const char *daddr, unsigned short dport)
{
  printf("[nft][pkt] hook=%d proto=%u %s:%u -> %s:%u\n",
         hook, l4proto, saddr, sport, daddr, dport);

  __u32 s_be = ip4_be32_from_str(saddr);
  __u32 d_be = ip4_be32_from_str(daddr);
  __u64 ts   = now_ns();

  struct last_ev *m = find_near(l4proto, s_be, sport, d_be, dport, ts);
  if (m) {
    char sa[16], da[16];
    printf("[merge] ebpf: src=%u hook=%u verdict=%d %s:%u -> %s:%u (Δ<=20ms)\n",
           m->src, m->hook, m->verdict,
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

  /* 3) ringbuffers */
  int fd_hooks=-1, fd_call=-1;
  if (hooks && hooks->maps.events_hooks) fd_hooks = bpf_map__fd(hooks->maps.events_hooks);
  if (cp && cp->maps.events_call)       fd_call  = bpf_map__fd(cp->maps.events_call);

  rb_hooks = (fd_hooks>=0) ? ring_buffer__new(fd_hooks, on_hook_event, NULL, NULL) : NULL;
  rb_call  = (fd_call >=0) ? ring_buffer__new(fd_call,  on_call_event, NULL, NULL) : NULL;
  if (!rb_hooks && fd_hooks>=0) fprintf(stderr, "ringbuf hooks open fail\n");
  if (!rb_call  && fd_call >=0) fprintf(stderr, "ringbuf call open fail\n");

  /* 4) bật thread fallback đọc `nft monitor trace` */
  nft_start_fallback_async();

  /* 5) poll song song với thread nft */
  while (!stop_flag) {
    if (rb_hooks) ring_buffer__poll(rb_hooks, 100);
    if (rb_call)  ring_buffer__poll(rb_call,  100);
    if (!rb_hooks && !rb_call) usleep(200*1000);
  }

  ring_buffer__free(rb_hooks);
  ring_buffer__free(rb_call);
  if (hooks) hooks_bpf__destroy(hooks);
  if (cp)    callpath_bpf__destroy(cp);
  return 0;
}
