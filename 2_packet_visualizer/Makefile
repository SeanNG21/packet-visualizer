# Makefile cho packet_visualizer

CLANG   ?= clang
LLVMS   ?= llvm-strip
CC      ?= gcc

BPF_SRC   = bpf/tag_kern.c
BPF_OBJ   = bpf/tag_kern.o
USER_PROGS = user/read_map user/rb_reader

CFLAGS_USER  = -O2 -g -Wall
LDFLAGS_USER = -lbpf
CFLAGS_BPF   = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I bpf

all: $(BPF_OBJ) $(USER_PROGS)

# ===== Generate vmlinux.h =====
bpf/vmlinux.h:
	@echo "[*] Generating vmlinux.h from kernel BTF..."
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "Error: /sys/kernel/btf/vmlinux not found. Kernel must support BTF (CONFIG_DEBUG_INFO_BTF=y)."; \
		exit 1; \
	fi
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

gen_vmlinux_h: bpf/vmlinux.h

# ===== Build BPF object =====
$(BPF_OBJ): $(BPF_SRC) bpf/vmlinux.h
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@
	$(LLVMS) -g $@

# ===== Build user-space programs =====
user/%: user/%.c
	$(CC) $(CFLAGS_USER) $< -o $@ $(LDFLAGS_USER)

clean:
	rm -f $(BPF_OBJ) $(USER_PROGS) bpf/vmlinux.h

.PHONY: all clean gen_vmlinux_h
