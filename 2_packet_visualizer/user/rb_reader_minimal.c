#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h> 

struct flow_event {
    uint64_t ts_ns;
    uint32_t id;
    uint32_t mark;
    uint32_t hook;
    uint8_t  proto;
    uint16_t sport;
    uint16_t dport;
};

static int handle_event(void *ctx, void *data, size_t size) {
    struct flow_event *e = data;
    printf("ts=%llu id=%u mark=0x%x hook=%u proto=%u sport=%u dport=%u\n",
           (unsigned long long)e->ts_ns,
           e->id, e->mark, e->hook,
           e->proto, e->sport, e->dport);
    return 0;
}

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/retis_rb");
    if (map_fd < 0) {
        perror("bpf_obj_get retis_rb");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for events...\n");
    while (1) {
        int err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    return 0;
}
