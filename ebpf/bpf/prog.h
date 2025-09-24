#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ---- fallback macro (không kéo uapi headers) ---- */
#ifndef BPF_HDR_START_MAC
#define BPF_HDR_START_MAC 0
#endif
#ifndef BPF_HDR_START_NET
#define BPF_HDR_START_NET 1
#endif

/* ---- IPPROTO_* tự định nghĩa để tránh include <linux/in.h> ---- */
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* ===================== enums ===================== */
enum event_type { EVT_HOOK=0, EVT_RULE=1, EVT_CALL=2 };

enum nf_hook_num_min {
  NFH_PREROUTING=0, NFH_LOCAL_IN=1, NFH_FORWARD=2, NFH_LOCAL_OUT=3, NFH_POSTROUTING=4,
};

enum call_func_id {
  CF_IP_RCV=1, CF_NETIF_RECEIVE_SKB, CF_IP_LOCAL_DELIVER, CF_NF_HOOK_SLOW,
  CF_IP_LOCAL_OUT, CF_IP_OUTPUT, CF_DEV_QUEUE_XMIT, CF_DEV_HARD_START_XMIT, CF_LOOPBACK_XMIT,
};

/* ===================== events ===================== */
struct event_hook_t {
  __u64 ts_ns;
  __u8  etype, pf, hook, l4proto;
  __u32 ifindex_in, ifindex_out;
  __s32 verdict;
  __u16 pkt_len, _pad0;
  __u32 saddr_v4, daddr_v4;
  __u16 sport, dport;

  __u64 skb_addr;   // NEW: pointer của skb
  __u32 skb_hash;   // NEW: bpf_get_hash_recalc()
  __u32 mark;       // NEW: skb->mark
};

struct event_call_t {
  __u64 ts_ns;
  __u8  etype, func_id, l4proto, hook_hint;
  __u32 ifindex;
  __u16 pkt_len, _pad1;
  __u32 saddr_v4, daddr_v4;
  __u16 sport, dport;

  __u64 skb_addr;   // NEW
  __u32 skb_hash;   // NEW
  __u32 mark;       // NEW
};


struct event_rule_t {
  __u64 ts_ns;
  __u8  etype, hook, family, verdict;
  __u64 rule_handle;
  char  table[32], chain[32];
};


/* ===================== maps ===================== */
// #ifdef DEFINE_BPF_MAPS
// // struct {
// //   __uint(type, BPF_MAP_TYPE_RINGBUF);
// //   __uint(max_entries, 1 << 22);
// // } events SEC(".maps");

// struct {
//   __uint(type, BPF_MAP_TYPE_ARRAY);
//   __uint(max_entries, 3);
//   __type(key, __u32);
//   __type(value, __u64);
// } ev_counters SEC(".maps");
// #else
// extern struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<22); } events;
// extern struct { __uint(type, BPF_MAP_TYPE_ARRAY);  __uint(max_entries, 3);     __type(key, __u32); __type(value, __u64);} ev_counters;
// #endif

static __always_inline void incr_counter(__u32 idx) { (void)idx; }


/* safe copy str */
static __always_inline void safe_read_str(char *dst, const void *src, __u32 dst_sz) {
  if (!dst || !dst_sz) return;
  long n = bpf_core_read_str(dst, dst_sz, src);
  if (n < 0 && dst_sz > 0) dst[0] = '\0';
}
