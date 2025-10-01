// user/rb_reader.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

static volatile int exiting = 0;

struct flow_event {
    __u64 ts_ns;
    __u32 id;
    __u32 mark;
    __u32 hook;
    __u8  proto;
    __u16 sport;
    __u16 dport;
};

static void handle_sigint(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    const struct flow_event *e = data;

    printf("[EVENT] ts=%llu id=%u mark=0x%x hook=%u proto=%u sport=%u dport=%u\n",
           (unsigned long long)e->ts_ns,
           e->id,
           e->mark,
           e->hook,
           e->proto,
           e->sport,
           e->dport);
    return 0;
}

int main(int argc, char **argv)
{
    const char *path = "/sys/fs/bpf/retis_rb";
    int rb_fd;
    struct ring_buffer *rb = NULL;

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    rb_fd = bpf_obj_get(path);
    if (rb_fd < 0) {
        fprintf(stderr, "Failed to open ringbuf at %s: %s\n",
                path, strerror(errno));
        return 1;
    }

    rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer: %s\n",
                strerror(errno));
        return 1;
    }

    printf("Listening on ringbuf %s ... (Ctrl-C to stop)\n", path);

    while (!exiting) {
        int err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err < 0 && errno != EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    close(rb_fd);
    printf("Exiting.\n");
    return 0;
}
