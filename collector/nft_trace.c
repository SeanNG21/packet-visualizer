// collector/nft_trace.c
// build:  gcc -O2 -g -o nft-trace.o -c nft_trace.c
// link :  gcc -o pv-collector ... nft_trace.o -lmnl
//
// Yêu cầu: libmnl + headers kernel (nf_tables uapi).
// Ubuntu/Debian: sudo apt-get install -y libmnl-dev linux-libc-dev

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include "nft_trace.h"

#include <linux/netfilter.h>       // NFPROTO_IPV4, NF_ACCEPT,...
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>  // NFTA_TRACE_HOOK,...
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

#include <linux/netfilter/nf_tables.h>

#ifndef NFTA_TRACE_HOOK
#define NFTA_TRACE_HOOK 7
#endif

// ---- helpers ---------------------------------------------------------------

static const char* family_name(uint8_t fam) {
    switch (fam) {
        case NFPROTO_IPV4: return "ip";
        case NFPROTO_IPV6: return "ip6";
        case NFPROTO_INET: return "inet";
        case NFPROTO_BRIDGE: return "bridge";
        case NFPROTO_NETDEV: return "netdev";
        default: return "unknown";
    }
}

static const char* hook_name(uint32_t hooknum) {
    // Theo family inet/ip: PREROUTING=0, INPUT=1, FORWARD=2, OUTPUT=3, POSTROUTING=4
    switch (hooknum) {
        case 0: return "PREROUTING";
        case 1: return "INPUT";
        case 2: return "FORWARD";
        case 3: return "OUTPUT";
        case 4: return "POSTROUTING";
        default: return "HOOK?";
    }
}

static const char* verdict_name(int32_t v) {
    // Giá trị âm đặc biệt trong netfilter verdicts
    switch (v) {
        case NF_ACCEPT: return "ACCEPT";
        case NF_DROP:   return "DROP";
        case NF_STOLEN: return "STOLEN";
        case NF_QUEUE:  return "QUEUE";
        case NF_REPEAT: return "REPEAT";
        case NF_STOP:   return "STOP";
        default:        return "?";
    }
}

// ---- parse NFT_MSG_TRACE ---------------------------------------------------
//
// uapi linux/netfilter/nf_tables.h:
// enum nft_trace_attributes {
//   NFTA_TRACE_UNSPEC,
//   NFTA_TRACE_TABLE,        (NLA_NUL_STRING)
//   NFTA_TRACE_CHAIN,        (NLA_NUL_STRING)
//   NFTA_TRACE_RULE_HANDLE,  (NLA_U64)
//   NFTA_TRACE_TYPE,         (NLA_U32)  -- loại event
//   NFTA_TRACE_VERDICT,      (NLA_S32)  -- verdict nếu có
//   NFTA_TRACE_FAMILY,       (NLA_U32)
//   NFTA_TRACE_HOOK,         (NLA_U32)
//   NFTA_TRACE_ID,           (NLA_U32)  -- trace-id nội bộ của nft
//   NFTA_TRACE_MARK,         (NLA_U32)  -- skb mark (có thể có nếu kernel/new enough)
//   ... (các attr khác tùy phiên bản kernel)
//
// Lưu ý: một số kernel cũ có thể CHƯA có NFTA_TRACE_MARK.
// Trong trường hợp đó ta vẫn chạy bình thường (mark = 0).
//

struct trace_ctx {
    nft_trace_cb on_evt; // callback người dùng truyền vào
};

static int attr_cb(const struct nlattr *attr, void *data) {
    // libmnl yêu cầu callback attribute, nhưng ở đây ta parse theo kiểu "thu gom"
    (void)attr; (void)data;
    return MNL_CB_OK;
}

static int nl_cb(const struct nlmsghdr *nlh, void *data) {
    struct trace_ctx *ctx = (struct trace_ctx*)data;

    if ((nlh->nlmsg_type & 0xFF) != NFT_MSG_TRACE) {
        return MNL_CB_OK;
    }

    // payload của NFT_MSG_TRACE là 1 nhóm TLV attributes
    struct nlattr *tb[NFTA_TRACE_MAX + 1];
    memset(tb, 0, sizeof(tb));

    // Header chuẩn nfnetlink
    const struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
    size_t len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*nfg));

    // parse attributes
    mnl_attr_parse(nlh, sizeof(*nfg), (mnl_attr_cb_t)attr_cb, tb);

    // Trích thông tin
    uint8_t  fam   = nfg->nfgen_family;
    uint32_t hook  = tb[NFTA_TRACE_HOOK] ? mnl_attr_get_u32(tb[NFTA_TRACE_HOOK]) : 0;
    const char *table = tb[NFTA_TRACE_TABLE] ? mnl_attr_get_str(tb[NFTA_TRACE_TABLE]) : "";
    const char *chain = tb[NFTA_TRACE_CHAIN] ? mnl_attr_get_str(tb[NFTA_TRACE_CHAIN]) : "";
    uint64_t rule = tb[NFTA_TRACE_RULE_HANDLE] ? mnl_attr_get_u64(tb[NFTA_TRACE_RULE_HANDLE]) : 0;
    int32_t verdict = tb[NFTA_TRACE_VERDICT] ? (int32_t)mnl_attr_get_u32(tb[NFTA_TRACE_VERDICT]) : 0;
    uint32_t mark = tb[NFTA_TRACE_MARK] ? mnl_attr_get_u32(tb[NFTA_TRACE_MARK]) : 0; // có thể 0 nếu kernel không gửi

    // Gọi callback người dùng
    if (ctx->on_evt) {
        ctx->on_evt(mark, family_name(fam), hook_name(hook), table, chain, rule, verdict_name(verdict));
    }

    return MNL_CB_OK;
}

// ---- public API ------------------------------------------------------------

int nft_trace_start(nft_trace_cb on_evt)
{
    int ret = -1;
    struct mnl_socket *nl = NULL;

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl) {
        perror("mnl_socket_open");
        return -1;
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        goto out;
    }

    // Join multicast group NFTABLES để nhận mọi sự kiện (bao gồm trace)
    // Lưu ý: group id tính bằng (1 << (group_number - 1)). libmnl hỗ trợ theo raw setsockopt:
    {
        unsigned int group = NFNLGRP_NFTABLES;
        if (mnl_socket_setsockopt(nl, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
            perror("setsockopt NETLINK_ADD_MEMBERSHIP");
            goto out;
        }
    }

    // Loop nhận bản tin
    struct trace_ctx ctx = {.on_evt = on_evt};

    char buf[8192];
    for (;;) {
        int n = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("mnl_socket_recvfrom");
            break;
        }
        ret = mnl_cb_run(buf, n, 0, 0, nl_cb, &ctx);
        if (ret < 0) {
            perror("mnl_cb_run");
            break;
        }
    }

out:
    if (nl) mnl_socket_close(nl);
    return ret;
}
