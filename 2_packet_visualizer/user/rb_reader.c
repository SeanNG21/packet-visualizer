#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct flow_event {
    __u64 ts_ns;
    __u32 id;
    __u32 mark;
    __u32 hook;
    __u8  proto;
    __u16 sport;
    __u16 dport;
};

static const char* hook_name(__u32 h) {
    switch (h) {
        case 1: return "TC_INGRESS";
        case 2: return "TC_EGRESS";
        case 3: return "NFT_CHAIN";
        default: return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t len) {
    struct flow_event *e = data;
    printf("[%s] ts=%" PRIu64 " id=%u mark=0x%08x proto=%u sport=%u dport=%u\n",
           hook_name(e->hook), (uint64_t)e->ts_ns, e->id, e->mark, e->proto,
           ntohs(e->sport), ntohs(e->dport));
    return 0;
}

int main(int argc, char **argv) {
    const char *rb_path = "/sys/fs/bpf/retis_rb";
    if (argc > 1)
        rb_path = argv[1];

    int rb_map = bpf_obj_get(rb_path);
    if (rb_map < 0) {
        fprintf(stderr, "open ringbuf map failed at %s: %s\n", rb_path, strerror(errno));
        fprintf(stderr, "did you pin it? (see run.sh)\n");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(rb_map, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        return 1;
    }

    while (1) {
        int err = ring_buffer__poll(rb, 250);
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    return 0;
}
