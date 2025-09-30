// ebpf/bpf/nft_trace.bpf.c
#include "prog.h"
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22);
} events_trace SEC(".maps");
char LICENSE[] SEC("license") = "GPL";

/* Dummy ctx cho tracepoint nftables:nft_trace.
 * Khai báo tất cả các tên field có thể có giữa các phiên bản kernel.
 * CO-RE sẽ relocate field nào thực sự tồn tại, còn lại bỏ qua.
 */
struct tp_nft_trace_ctx {
    __u8  hook;           // NF_INET_* (0..4)
    __u8  family;         // NFPROTO_*
    const char *table;    // "inet"/"ip"/...
    const char *chain;    // "input"/"output"/...

    /* các biến thể tên/kiểu của rule handle */
    __u64 rule_handle;    // biến thể A
    __u64 handle;         // biến thể B
    __u64 rule_id;        // biến thể C

    /* các biến thể tên verdict/type */
    __u8  verdict;        // biến thể A
    __u8  type;           // biến thể B
} __attribute__((preserve_access_index));

static __always_inline __u8 read_verdict(const struct tp_nft_trace_ctx *ctx)
{
    __u8 v = 0;
    if (bpf_core_field_exists(ctx->verdict))
        v = BPF_CORE_READ(ctx, verdict);
    else if (bpf_core_field_exists(ctx->type))
        v = BPF_CORE_READ(ctx, type);
    return v;
}

static __always_inline __u64 read_rule_handle(const struct tp_nft_trace_ctx *ctx)
{
    __u64 h = 0;
    if (bpf_core_field_exists(ctx->rule_handle))
        h = BPF_CORE_READ(ctx, rule_handle);
    else if (bpf_core_field_exists(ctx->handle))
        h = BPF_CORE_READ(ctx, handle);
    else if (bpf_core_field_exists(ctx->rule_id))
        h = BPF_CORE_READ(ctx, rule_id);
    return h;
}

SEC("tracepoint/nftables/nft_trace")
int on_nft_trace(const struct tp_nft_trace_ctx *ctx)
{
    struct event_rule_t *e = bpf_ringbuf_reserve(&events_trace, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->etype = EVT_RULE;

    if (bpf_core_field_exists(ctx->hook))
        e->hook = BPF_CORE_READ(ctx, hook);
    if (bpf_core_field_exists(ctx->family))
        e->family = BPF_CORE_READ(ctx, family);

    e->rule_handle = read_rule_handle(ctx);
    e->verdict     = read_verdict(ctx);

    const char *tbl = NULL, *chn = NULL;
    if (bpf_core_field_exists(ctx->table))
        tbl = BPF_CORE_READ(ctx, table);
    if (bpf_core_field_exists(ctx->chain))
        chn = BPF_CORE_READ(ctx, chain);

    safe_read_str(e->table, tbl, sizeof(e->table));
    safe_read_str(e->chain, chn, sizeof(e->chain));

    incr_counter(EVT_RULE);
    bpf_ringbuf_submit(e, 0);
    return 0;
}


