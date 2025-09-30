# ebpf/Makefile
BPF_CLANG ?= clang
ARCH ?= x86    # nếu máy arm64 thì đặt ARCH=arm64

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
  -I$(PWD)/include -I$(PWD)/bpf

BPF_DIR := bpf
INC_DIR := include

BPF_OBJS := \
  $(BPF_DIR)/hooks.bpf.o \
  $(BPF_DIR)/nft_trace.bpf.o \
  $(BPF_DIR)/callpath.bpf.o

.PHONY: all clean vmlinux

all: $(BPF_OBJS)

# build từng .bpf.o từ .bpf.c
$(BPF_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(INC_DIR)/vmlinux.h $(BPF_DIR)/prog.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# sinh vmlinux.h nếu chưa có
vmlinux:
	mkdir -p $(INC_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(INC_DIR)/vmlinux.h

clean:
	rm -f $(BPF_OBJS)
