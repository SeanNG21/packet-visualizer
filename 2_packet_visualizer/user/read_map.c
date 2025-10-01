#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <inttypes.h>
#include <stdint.h>
#include <arpa/inet.h>

struct packet_fingerprint {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
    __u64 ts_ns;
};

static void ip_print(__u32 ip) {
    printf("%u.%u.%u.%u",
           (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);
}

int main(int argc, char **argv) {
    const char *map_path = "/sys/fs/bpf/retis_id_to_fp";
    if (argc > 1)
        map_path = argv[1];

    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "failed to open pinned map %s: %s\n", map_path, strerror(errno));
        return 1;
    }

    printf("Opened map at %s (fd=%d)\n", map_path, map_fd);

    while (1) {
        __u32 key, next;
        int err = bpf_map_get_next_key(map_fd, NULL, &key);
        if (err) {
            printf("map empty or get_next_key failed (err=%d)\n", err);
            sleep(1);
            continue;
        }

        while (1) {
            struct packet_fingerprint fp;
            if (bpf_map_lookup_elem(map_fd, &key, &fp) == 0) {
                printf("ID: %u  ts_ns:%" PRIu64 " proto:%u ",
                       key, (uint64_t)fp.ts_ns, fp.proto);
                ip_print(fp.src_ip);
                printf(":%u -> ", ntohs(fp.sport));
                ip_print(fp.dst_ip);
                printf(":%u\n", ntohs(fp.dport));
            }
            int rc = bpf_map_get_next_key(map_fd, &key, &next);
            if (rc) break;
            key = next;
        }
        sleep(1);
    }
    return 0;
}
