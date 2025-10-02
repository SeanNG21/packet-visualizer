/* user/rb_reader.c - Complete reader program */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Match BPF program definitions */
#define TOOL_TAG          0xABC
#define TAG_SHIFT         20
#define ID_MASK           ((1U << TAG_SHIFT) - 1)

enum hook_type {
    HOOK_TC_INGRESS = 1,
    HOOK_TC_EGRESS  = 2,
};

struct flow_event {
    __u64 ts_ns;
    __u32 id;
    __u32 mark;
    __u32 hook;
    __u8  proto;
    __u16 sport;
    __u16 dport;
    __u32 src_ip;
    __u32 dst_ip;
} __attribute__((packed));

static volatile int exiting = 0;
static unsigned long long event_count = 0;
static unsigned long long ingress_count = 0;
static unsigned long long egress_count = 0;

static void handle_sigint(int sig)
{
    exiting = 1;
}

static const char* proto_name(__u8 proto)
{
    switch (proto) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "OTHER";
    }
}

static int handle_event(void *ctx, void *data, size_t len)
{
    const struct flow_event *e = data;
    char ts_buf[32];
    char src_ip[INET_ADDRSTRLEN] = "0.0.0.0";
    char dst_ip[INET_ADDRSTRLEN] = "0.0.0.0";
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm_info);
    event_count++;
    
    if (e->hook == HOOK_TC_INGRESS)
        ingress_count++;
    else if (e->hook == HOOK_TC_EGRESS)
        egress_count++;

    /* Convert IPs */
    if (e->src_ip) {
        struct in_addr addr = { .s_addr = e->src_ip };
        inet_ntop(AF_INET, &addr, src_ip, sizeof(src_ip));
    }
    if (e->dst_ip) {
        struct in_addr addr = { .s_addr = e->dst_ip };
        inet_ntop(AF_INET, &addr, dst_ip, sizeof(dst_ip));
    }

    /* Print event */
    const char *emoji = (e->hook == HOOK_TC_INGRESS) ? "📥" : "📤";
    const char *hook_name = (e->hook == HOOK_TC_INGRESS) ? "INGRESS" : "EGRESS";
    
    printf("%s [%s] EVENT #%llu - TC_%s\n", 
           emoji, ts_buf, event_count, hook_name);
    printf("  Packet ID  : %u\n", e->id);
    printf("  Mark       : 0x%08x\n", e->mark);
    printf("  Protocol   : %s (%u)\n", proto_name(e->proto), e->proto);
    
    if (e->src_ip && e->dst_ip) {
        printf("  Flow       : %s", src_ip);
        if (e->sport) printf(":%u", e->sport);
        printf(" → %s", dst_ip);
        if (e->dport) printf(":%u", e->dport);
        printf("\n");
    }
    
    printf("  Timestamp  : %llu ns\n", e->ts_ns);
    printf("─────────────────────────────────────────\n");
    fflush(stdout);
    
    return 0;
}

int main(int argc, char **argv)
{
    const char *path = "/sys/fs/bpf/retis_rb";
    int rb_fd;
    struct ring_buffer *rb = NULL;
    int timeout_ms = 100;

    if (argc > 1) {
        path = argv[1];
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    printf("═══════════════════════════════════════════\n");
    printf("  Packet Visualizer - Ring Buffer Reader\n");
    printf("═══════════════════════════════════════════\n");
    printf("Ring buffer: %s\n", path);
    printf("Tool tag   : 0x%03x\n", TOOL_TAG);
    printf("───────────────────────────────────────────\n");

    /* Check if file exists */
    if (access(path, F_OK) != 0) {
        fprintf(stderr, "❌ Ring buffer not found at %s\n\n", path);
        fprintf(stderr, "Make sure eBPF programs are loaded and ring buffer is pinned.\n");
        fprintf(stderr, "Run: sudo ./setup.sh <interface>\n");
        return 1;
    }

    printf("✅ Ring buffer file exists\n");

    /* Open ring buffer */
    rb_fd = bpf_obj_get(path);
    if (rb_fd < 0) {
        fprintf(stderr, "❌ Failed to open ring buffer: %s\n", strerror(errno));
        fprintf(stderr, "   Make sure you're running as root\n");
        return 1;
    }

    printf("✅ Ring buffer opened (fd=%d)\n", rb_fd);

    /* Create consumer */
    rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "❌ Failed to create ring buffer consumer: %s\n",
                strerror(errno));
        close(rb_fd);
        return 1;
    }

    printf("✅ Consumer created\n");
    printf("───────────────────────────────────────────\n");
    printf("🎧 Listening for packet events...\n");
    printf("   📥 = TC Ingress (packets entering)\n");
    printf("   📤 = TC Egress (packets leaving)\n");
    printf("   Press Ctrl-C to stop\n");
    printf("═══════════════════════════════════════════\n\n");

    unsigned long long poll_count = 0;
    time_t last_status = time(NULL);

    while (!exiting) {
        int err = ring_buffer__poll(rb, timeout_ms);
        poll_count++;
        
        if (err < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "\n❌ Error polling: %d (%s)\n", 
                    err, strerror(errno));
            break;
        }

        /* Print status if no events */
        time_t now = time(NULL);
        if (now - last_status >= 30 && event_count == 0) {
            printf("[STATUS] Polls: %llu | No events yet\n", poll_count);
            printf("         Generate traffic: ping -c 5 8.8.8.8\n\n");
            last_status = now;
        }
    }

    printf("\n═══════════════════════════════════════════\n");
    printf("📊 Statistics:\n");
    printf("  Total events   : %llu\n", event_count);
    printf("  Ingress events : %llu\n", ingress_count);
    printf("  Egress events  : %llu\n", egress_count);
    printf("  Total polls    : %llu\n", poll_count);
    printf("═══════════════════════════════════════════\n");

    ring_buffer__free(rb);
    close(rb_fd);
    printf("✅ Exiting cleanly.\n");
    return 0;
}