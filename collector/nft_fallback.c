// collector/nft_fallback.c
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct nft_tuple {
    int hook;               // 0..4 hoặc -1 nếu không biết
    unsigned char l4proto;  // 6=tcp, 17=udp, 1=icmp, 0=unknown
    char saddr[64], daddr[64];
    unsigned short sport, dport;
};

// map hook name -> số
static int map_hook_from_line(const char *line) {
    if (strstr(line, " hook prerouting"))  return 0;
    if (strstr(line, " hook input"))       return 1;
    if (strstr(line, " hook forward"))     return 2;
    if (strstr(line, " hook output"))      return 3;
    if (strstr(line, " hook postrouting")) return 4;
    // một số bản nft không in "hook ..." ở dòng packet; trả về -1
    return -1;
}

static unsigned char guess_l4proto(const char *line) {
    if (strstr(line, " ip protocol tcp") || strstr(line, " tcp ")) return 6;
    if (strstr(line, " ip protocol udp") || strstr(line, " udp ")) return 17;
    if (strstr(line, " icmp ")) return 1;
    return 0;
}

static void parse_addrs(const char *line, char *sa, size_t saz, char *da, size_t daz) {
    const char *p;
    *sa = *da = '\0';
    if ((p = strstr(line, "ip saddr "))) { p += 9; sscanf(p, "%63s", sa); }
    if ((p = strstr(line, "ip daddr "))) { p += 9; sscanf(p, "%63s", da); }
}

static void parse_ports_any(const char *line, unsigned char l4, unsigned short *sp, unsigned short *dp) {
    *sp = *dp = 0;
    const char *p;
    if (l4 == 6 && (p = strstr(line, "tcp sport "))) { p += 10; *sp = (unsigned short)atoi(p); }
    if (l4 == 6 && (p = strstr(line, "tcp dport "))) { p += 10; *dp = (unsigned short)atoi(p); }
    if (l4 == 17 && (p = strstr(line, "udp sport "))) { p += 10; *sp = (unsigned short)atoi(p); }
    if (l4 == 17 && (p = strstr(line, "udp dport "))) { p += 10; *dp = (unsigned short)atoi(p); }
}

static int is_packet_line(const char *line) {
    // Dòng có “packet:” là dòng chứa tuple (saddr/daddr/ports)
    return strstr(line, " packet: ") != NULL;
}

// do main.c export (đã khai báo trong nft_fallback.h)
extern void correlator_on_nft_packet(int hook, unsigned char l4proto,
                                     const char *saddr, unsigned short sport,
                                     const char *daddr, unsigned short dport);

static void *nft_thread(void *arg) {
    (void)arg;
    FILE *fp = popen("nft monitor trace", "r");
    if (!fp) { perror("popen nft monitor trace"); return NULL; }

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        if (is_packet_line(line)) {
            struct nft_tuple t = {0};
            t.hook    = map_hook_from_line(line);
            t.l4proto = guess_l4proto(line);
            parse_addrs(line, t.saddr, sizeof t.saddr, t.daddr, sizeof t.daddr);
            parse_ports_any(line, t.l4proto, &t.sport, &t.dport);

            // In nhanh (debug)
            printf("[nft] hook=%d proto=%u %s:%u -> %s:%u\n",
                   t.hook, t.l4proto, t.saddr, t.sport, t.daddr, t.dport);

            // Gửi tuple sang main để “ghép” với eBPF
            correlator_on_nft_packet(t.hook, t.l4proto,
                                     t.saddr, t.sport, t.daddr, t.dport);
        } else {
            // rule/policy line (không đủ tuple) — vẫn in thô để tham khảo
            printf("[nft] %s", line);
        }
    }
    pclose(fp);
    return NULL;
}

void nft_start_fallback_async(void) {
    pthread_t th;
    if (pthread_create(&th, NULL, nft_thread, NULL) == 0)
        pthread_detach(th);
    else
        perror("pthread_create nft_thread");
}
