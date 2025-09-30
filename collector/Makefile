CC ?= cc
CFLAGS := -O2 -g -Wall -I../ebpf/bpf
# libbpf, libelf, zlib, pthread, và thêm libmnl để đọc netlink
LDFLAGS := -lbpf -lelf -lz -lpthread -lmnl -lnftnl


all: pv-collector

# thêm nft_trace.c vào danh sách source
pv-collector: main.c nft_fallback.c nft_trace.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f pv-collector
