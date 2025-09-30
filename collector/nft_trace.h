// collector/nft_trace.h
#pragma once
#include <stdint.h>

// Callback khi nhận 1 event trace từ nftables.
// mark     : skb->mark (trace-id bạn gán ở tc); có thể =0 nếu kernel không gửi attr này.
// family   : "ip"/"ip6"/"inet"/...
// hook     : "PREROUTING"/"INPUT"/"FORWARD"/"OUTPUT"/"POSTROUTING"
// table    : tên bảng
// chain    : tên chain
// rule     : rule handle (u64)
// verdict  : "ACCEPT"/"DROP"/...
typedef void (*nft_trace_cb)(uint32_t mark,
                             const char* family,
                             const char* hook,
                             const char* table,
                             const char* chain,
                             uint64_t rule,
                             const char* verdict);

// Bắt đầu lắng nghe NFT_MSG_TRACE (blocking loop).
int nft_trace_start(nft_trace_cb on_evt);
