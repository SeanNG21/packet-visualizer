CC ?= cc
CFLAGS := -O2 -g -Wall -I../ebpf/bpf
LDFLAGS := -lbpf -lelf -lz -lpthread

all: pv-collector
pv-collector: main.c nft_fallback.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f pv-collector
